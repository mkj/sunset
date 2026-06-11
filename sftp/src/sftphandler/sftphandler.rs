use crate::error::SftpError;
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    self, InitVersionClient, InitVersionLowest, LStat, MAX_REQUEST_LEN, ReqId,
    SFTP_VERSION, SftpNum, SftpPacket, Stat, StatusCode,
};
use crate::server::DirReadHeaderReply;
use crate::sftperror::SftpResult;
use crate::sftphandler::requestholder::{RequestHolder, RequestHolderError};
use crate::sftphandler::sftpoutputchannelhandler::{
    SftpOutputPipe, SftpOutputProducer,
};
use crate::sftpserver::{ReadHeaderReply, SftpServer};
use crate::sftpsource::SftpSource;

use embassy_futures::select::{Either3, select3};
use sunset::Error as SunsetError;
use sunset::sshwire::{SSHSource, WireError};

use core::u32;
use embedded_io_async::Error;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

// Platforms like thumbv6m-none-eabi can't atomics, so instead
// use critical-section.
type SFTPCoord = cfg_select! {
    target_has_atomic = "ptr" => bbqueue::traits::coordination::cas::AtomicCoord,
    _ => bbqueue::traits::coordination::cs::CsCoord,
};

/// An async bbqueue with inline storage
type SFTPBBQueue<const N: usize> = bbqueue::BBQueue<
    bbqueue::traits::storage::Inline<N>,
    SFTPCoord,
    bbqueue::traits::notifier::maitake::MaiNotSpsc,
>;

/// FSM for handling sftp requests during [`SftpHandler::process`]
#[derive(Default, Debug, PartialEq, Eq)]
enum HandlerState {
    /// The handle is not been initialized.
    /// if the client receivs an Init packet it will process it.
    #[default]
    Uninitialized,
    /// The handle is ready to process requests. No request pending
    /// A new packet will be evaluated to be process as:
    /// - a regular request
    /// - fragment (More data is needed)
    /// - long request (It does not fit in the buffers and segmenting
    /// strategies are used)
    Idle,
    /// The client has received a request and will decide how to process it.
    /// Use the self.incomplete_request_holder
    ProcessRequest { sftp_num: SftpNum },
    /// There is a fragmented request and more bytes are needed
    /// Use the self.incomplete_request_holder
    ProcessFragment,
    /// A request, with a length over the incoming buffer capacity is being
    /// processed.
    ///
    /// E.g. a write request with size exceeding the
    /// buffer size: Processing this request will require to be split
    /// into multiple write actions
    ProcessWriteRequest { offset: u64, remaining_data: u32 },

    /// Used to clear an invalid buffer in cases where there is still
    /// data to be process but no longer required
    ClearBuffer { data: usize },
}

/// Process the raw buffers in and out from a subsystem channel decoding
/// request and encoding responses
///
/// Parameter (S): It will delegate request to an [`crate::sftpserver::SftpServer`]
/// implemented by the library user taking into account the local system details.
///
/// Parameter (T): Is a type that implements [`crate::handles::OpaqueFileHandle`] that **must** match the type used in the [`crate::sftpserver::SftpServer`] provided in (S)
///
/// The compiler time constant `BUFFER_OUT_SIZE` is used to define the
/// size of the output buffer for the subsystem [`embassy_sync::pipe::Pipe`] used
/// to send responses safely across the instantiated structure.
///
pub struct SftpHandler<'a, T, S, const BUFFER_OUT_SIZE: usize>
where
    T: OpaqueFileHandle,
    S: SftpServer<T>,
{
    /// Holds the internal state if the SFTP handle
    state: HandlerState,

    /// The local SFTP File server implementing the basic SFTP requests
    /// defined by [`crate::sftpserver::SftpServer`]
    file_server: &'a mut S,

    // /// Use to process SFTP Write packets that have been received
    // /// partially and the remaining is expected in successive buffers
    // partial_write_request_tracker: Option<PartialWriteRequestTracker<T>>,
    /// Used to handle received buffers that do not hold a complete request [`SftpPacket`]
    request_holder: RequestHolder<'a>,

    /// Marker to keep track of the OpaqueFileHandle type
    _marker: core::marker::PhantomData<T>,
}

impl<'a, T, S, const BUFFER_OUT_SIZE: usize> SftpHandler<'a, T, S, BUFFER_OUT_SIZE>
where
    T: OpaqueFileHandle,
    S: SftpServer<T>,
{
    /// Creates a new instance of the structure.
    ///
    /// Requires:
    ///
    /// - `file_server` (implementing [`crate::sftpserver::SftpServer`] ): to execute
    /// the request in the local system
    /// - `request_buffer`: used to deal with fragmented
    /// packets during [`SftpHandler::process_loop`]
    pub fn new(file_server: &'a mut S, request_buffer: &'a mut [u8]) -> Self {
        SftpHandler {
            file_server,
            state: HandlerState::default(),
            request_holder: RequestHolder::new(request_buffer),
            _marker: core::marker::PhantomData,
        }
    }

    /// Runs the SFTP server loop.
    ///
    /// Takes an [`embedded_io_async::Read`] and [`embedded_io_async::Write`].
    /// Processes all the request from `chan_in` until an EOF is received.
    pub async fn process_loop(
        &mut self,
        mut chan_in: impl embedded_io_async::Read,
        chan_out: impl embedded_io_async::Write,
    ) -> SftpResult<()> {
        // A single request should be adequate for progress.
        const INPUT_BUF: usize = MAX_REQUEST_LEN;

        let mut sftp_output_pipe = SftpOutputPipe::<BUFFER_OUT_SIZE>::new();

        let (mut output_consumer, output_producer) =
            sftp_output_pipe.split(chan_out)?;

        let output_consumer_loop = output_consumer.receive_task();

        let buf = SFTPBBQueue::<INPUT_BUF>::new();

        let read_loop = async {
            let prod = buf.stream_producer();
            loop {
                let mut input = prod.wait_grant_max_remaining(usize::MAX).await;
                trace!("SFTP: About to read bytes from SSH Channel");

                let lr = chan_in
                    .read(&mut input)
                    .await
                    .map_err(|e| SunsetError::from(e.kind()))?;

                debug!("SFTP <---- received: {:?} bytes", lr);
                trace!("SFTP <---- received: {:?}", &input[0..lr]);
                if lr == 0 {
                    debug!("client disconnected");
                    return Err(SftpError::ClientDisconnected);
                }

                input.commit(lr);
            }
            #[allow(unreachable_code)]
            SftpResult::Ok(())
        };

        let processing_loop = async {
            let cons = buf.stream_consumer();
            loop {
                let input = cons.wait_read().await;
                trace!("SFTP: About to read bytes from SSH Channel");

                let consumed = self.process(&input, &output_producer).await?;
                input.release(consumed);
            }
        };
        match select3(read_loop, processing_loop, output_consumer_loop).await {
            Either3::First(r) => {
                error!("Read returned: {:?}", r);
                r
            }
            Either3::Second(r) => {
                error!("Processing returned: {:?}", r);
                r
            }
            Either3::Third(r) => {
                error!("Output consumer returned: {:?}", r);
                r
            }
        }
    }

    async fn process_validated_request(
        &mut self,
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
    ) -> SftpResult<()> {
        let Some(sftp_packet) = self.request_holder.valid_request() else {
            return Err(SunsetError::bug().into());
        };
        match sftp_packet {
            SftpPacket::Read(req_id, ref read) => {
                debug!("Read request: {:?}", sftp_packet);

                let reply = ReadHeaderReply::new(req_id, output_producer);
                if let Err(error) = self
                    .file_server
                    .read(&T::try_from(&read.handle)?, read.offset, read.len, reply)
                    .await
                {
                    error!("Error reading data: {:?}", error);
                    if let SftpError::FileServerError(status) = error {
                        output_producer
                            .send_status(req_id, status, "Could not list attributes")
                            .await?;
                    } else {
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Could not list attributes",
                            )
                            .await?;
                    }
                };

                self.state = HandlerState::Idle;
            }
            SftpPacket::LStat(req_id, LStat { file_path: path }) => {
                match self.file_server.attrs(false, path.to_str()?).await {
                    Ok(attrs) => {
                        debug!("List stats for {} is {:?}", path, attrs);

                        output_producer
                            .send_packet(&SftpPacket::Attrs(req_id, attrs))
                            .await?;
                    }
                    Err(status) => {
                        error!("Error listing stats for {}: {:?}", path, status);
                        output_producer
                            .send_status(req_id, status, "Could not list attributes")
                            .await?;
                    }
                };
                self.state = HandlerState::Idle;
            }
            SftpPacket::Stat(req_id, Stat { file_path: path }) => {
                match self.file_server.attrs(true, path.to_str()?).await {
                    Ok(attrs) => {
                        debug!("List stats for {} is {:?}", path, attrs);

                        output_producer
                            .send_packet(&SftpPacket::Attrs(req_id, attrs))
                            .await?;
                    }
                    Err(status) => {
                        error!("Error listing stats for {}: {:?}", path, status);
                        output_producer
                            .send_status(req_id, status, "Could not list attributes")
                            .await?;
                    }
                };
                self.state = HandlerState::Idle;
            }
            SftpPacket::ReadDir(req_id, read_dir) => {
                let dir_read_header_reply =
                    DirReadHeaderReply::new(req_id, output_producer);
                if let Err(status) = self
                    .file_server
                    .readdir(&T::try_from(&read_dir.handle)?, dir_read_header_reply)
                    .await
                {
                    error!("Open failed: {:?}", status);

                    output_producer
                        .send_status(req_id, status, "Error Reading Directory")
                        .await?;
                };
                self.state = HandlerState::Idle;
            }
            SftpPacket::OpenDir(req_id, open_dir) => {
                match self.file_server.opendir(open_dir.dirname.as_str()?).await {
                    Ok(opaque_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: opaque_file_handle.into_file_handle(),
                            },
                        );
                        output_producer.send_packet(&response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
                self.state = HandlerState::Idle;
            }
            SftpPacket::Close(req_id, close) => {
                match self.file_server.close(&T::try_from(&close.handle)?).await {
                    Ok(_) => {
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_OK, "")
                            .await?;
                    }
                    Err(e) => {
                        error!("SFTP Close thrown: {:?}", e);
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "Could not Close the handle",
                            )
                            .await?;
                    }
                }
                self.state = HandlerState::Idle;
            }
            SftpPacket::Write(_, write) => {
                debug!("Got write: {:?}", write);
                self.state = HandlerState::ProcessWriteRequest {
                    offset: write.offset,
                    remaining_data: write.data_len,
                };
            }
            SftpPacket::Open(req_id, open) => {
                match self
                    .file_server
                    .open(open.filename.as_str()?, &open.pflags)
                    .await
                {
                    Ok(opaque_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: opaque_file_handle.into_file_handle(),
                            },
                        );
                        output_producer.send_packet(&response).await?;
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_FAILURE, "")
                            .await?;
                    }
                };
                self.state = HandlerState::Idle;
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                match self.file_server.realpath(path_info.path.to_str()?).await {
                    Ok(name_entry) => {
                        let dir_read_header_reply =
                            DirReadHeaderReply::new(req_id, output_producer);
                        let encoded_len =
                            crate::sftpserver::helpers::get_name_entry_len(
                                &name_entry,
                            )?;
                        debug!("PathInfo encoded length: {:?}", encoded_len);
                        trace!("PathInfo Response content: {:?}", encoded_len);
                        let dir_read_data_reply = dir_read_header_reply
                            .send_header(encoded_len, 1)
                            .await?;
                        dir_read_data_reply
                            .send_data(|mut sender| async move {
                                sender.send_item(&name_entry).await?;
                                sender
                                    .completed()
                                    .ok_or(SftpError::WireError(WireError::Bug))
                            })
                            .await?;
                    }
                    Err(code) => {
                        output_producer.send_status(req_id, code, "").await?;
                    }
                }
                self.state = HandlerState::Idle;
            }
            SftpPacket::Init(..)
            | SftpPacket::Version(..)
            | SftpPacket::Status(..)
            | SftpPacket::Handle(..)
            | SftpPacket::Data(..)
            | SftpPacket::Name(..)
            | SftpPacket::Attrs(..) => {
                error!(
                    "Unexpected SftpPacket in ProcessRequest state: {:?}",
                    sftp_packet.sftp_num()
                );
                return Err(SunsetError::BadUsage {}.into());
            }
        }
        Ok(())
    }
    /// - Decodes the buffer_in request
    /// - Process the request delegating
    /// operations to a [`SftpServer`] implementation
    /// - Serializes an answer in `output_producer`
    ///
    /// Returns the amount of data consumed.
    async fn process(
        &mut self,
        buffer_in: &[u8],
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
    ) -> SftpResult<usize> {
        /*
        Possible scenarios:
            - Init: The init handshake has to be performed. Only Init packet is accepted. NAV(Idle)
            - handshake?: The client has received an Init packet and is processing it. NAV( Init, Idle)
            - Idle: Ready to process request. No request pending. In this point. NAV(ProcessRequest, Fragment)
            - Fragment: There is a fragmented request and more data is needed. NAV(ProcessRequest, ProcessLongRequest)
            - ProcessRequest: The client has received a request and is processing it. NAV(Idle)
            - ProcessLongRequest: The client has received a request that cannot fit in the buffer. Special treatment is required. NAV(Idle)
         */
        let mut buf = buffer_in;

        trace!("Received {:} bytes to process", buf.len());

        trace!("Entering loop to process the full received buffer");
        // In ProcessRequest state, we need to handle the request before returning.
        while buf.len() > 0
            || matches!(self.state, HandlerState::ProcessRequest { .. })
        {
            debug!(
                "<=======================[ SFTP Process State: {:?} ]=======================> Buffer remaining: {}",
                self.state,
                buf.len()
            );
            match &self.state {
                HandlerState::ProcessWriteRequest {
                    offset,
                    remaining_data: data_len,
                } => {
                    if let Some(request) = self.request_holder.valid_request() {
                        if let SftpPacket::Write(req_id, write) = request {
                            let used = (*data_len as usize).min(buf.len());
                            let remaining_data = *data_len - used as u32;

                            let data = &buf[..used];
                            buf = &buf[used..];
                            match self
                                .file_server
                                .write(&T::try_from(&write.handle)?, *offset, data)
                                .await
                            {
                                Ok(_) => {
                                    if remaining_data == 0 {
                                        output_producer
                                            .send_status(
                                                req_id,
                                                StatusCode::SSH_FX_OK,
                                                "",
                                            )
                                            .await?;
                                        trace!("Still in buffer: {buf:?}");
                                        self.state = HandlerState::Idle;
                                    } else {
                                        self.state =
                                            HandlerState::ProcessWriteRequest {
                                                offset: *offset + (used as u64),
                                                remaining_data,
                                            };
                                    }
                                }
                                Err(e) => {
                                    error!("SFTP write thrown: {:?}", e);
                                    output_producer
                                        .send_status(
                                            req_id,
                                            StatusCode::SSH_FX_FAILURE,
                                            "error writing",
                                        )
                                        .await?;
                                    self.state = HandlerState::ClearBuffer {
                                        data: remaining_data as usize,
                                    };
                                }
                            };
                        } else {
                            // todo!("Wrong transition? Uncontrolled for now");
                            return Err(SunsetError::bug())?;
                        }
                    } else {
                        // todo!("Wrong transition? Uncontrolled for now");
                        return Err(SunsetError::bug())?;
                    }
                }
                HandlerState::Uninitialized => {
                    debug!("Creating a source: buf_len = {:?}", buf.len());
                    let mut source = SftpSource::new(&buf);

                    match SftpPacket::decode_request(&mut source) {
                        Ok(request) => match request {
                            SftpPacket::Init(InitVersionClient {
                                version: SFTP_VERSION,
                            }) => {
                                debug!(
                                    "Accepted initialization request: {:?}",
                                    request
                                );
                                output_producer
                                    .send_packet(&SftpPacket::Version(
                                        InitVersionLowest { version: SFTP_VERSION },
                                    ))
                                    .await?;
                                buf = &buf[buf.len() - source.remaining()..];
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::Init(init_version_client) => {
                                error!(
                                    "Incompatible SFTP Version: {:?} is not {SFTP_VERSION:?}",
                                    &init_version_client
                                );
                                return Err(SftpError::NotSupported);
                            }
                            _ => {
                                error!(
                                    "Wrong SFTP Packet before Init or incompatible version: {request:?}"
                                );
                                return Err(SftpError::NotInitialized);
                            }
                        },
                        Err(e) => {
                            error!("Malformed SFTP Packet before Init: {e:?}");
                            return Err(SftpError::MalformedPacket);
                        } // Err(e) => {
                          //     error!("Malformed SFTP Packet before Init: {e:?}");
                          //     return Err(SftpError::MalformedPacket);
                          // }
                    }
                }
                HandlerState::Idle => {
                    self.request_holder.reset();
                    debug!("Creating a source: buf_len = {:?}", buf.len());
                    let mut source = SftpSource::new(&buf);
                    trace!("source: {source:?}");

                    match SftpPacket::decode_request(&mut source) {
                        Ok(request) => {
                            debug!("Got a valid request {:?}", request.sftp_num());
                            self.request_holder.try_hold(&source.buffer_used())?;

                            // We got the request. Moving on to process it before deserializing more
                            // data
                            self.state = HandlerState::ProcessRequest {
                                sftp_num: request.sftp_num(),
                            };
                            // TODO Wasteful. Will have to decode the request again. Maybe hold it?
                            buf = &buf[buf.len() - source.remaining()..];
                        }
                        Err(WireError::RanOut) => {
                            debug!("source: {source:?}");
                            let rl = self
                                .request_holder
                                .try_hold(&source.consume_all())?;

                            buf = &buf[buf.len() - source.remaining()..];
                            debug!(
                                "Incomplete packet. request holder initialized with {rl:?} bytes"
                            );
                            self.state = HandlerState::ProcessFragment;
                        }
                        Err(WireError::UnknownPacket { number }) => {
                            error!("Unknown packet: {number}");
                            output_producer
                                .send_status(
                                    ReqId(
                                        source
                                            .peek_packet_req_id()
                                            .unwrap_or(u32::MAX),
                                    ),
                                    StatusCode::SSH_FX_OP_UNSUPPORTED,
                                    "",
                                )
                                .await?;
                            buf = &buf[buf.len() - source.remaining()..];
                            debug!(
                                "Unknown Packet. clearing the buffer in place since it filts"
                            );
                        }
                        Err(WireError::PacketWrong) => {
                            error!("Not a request: ");
                            output_producer
                                .send_status(
                                    ReqId(
                                        source
                                            .peek_packet_req_id()
                                            .unwrap_or(u32::MAX),
                                    ),
                                    StatusCode::SSH_FX_BAD_MESSAGE,
                                    "Not a request",
                                )
                                .await?;
                        }
                        Err(e) => {
                            error!("Unexpected error: Bug!");
                            return Err(SftpError::WireError(e));
                        }
                    };
                }
                HandlerState::ProcessFragment => {
                    match self.request_holder.try_appending_for_valid_request(&buf) {
                        Ok(sftp_num) => {
                            let used = self.request_holder.appended();
                            debug!(
                                "{used:?} bytes added. We got a complete request: {sftp_num:?}:: {:?}",
                                self.request_holder
                            );
                            debug!(
                                "Request: {:?}",
                                self.request_holder.valid_request()
                            );
                            buf = &buf[used..];
                            self.state = HandlerState::ProcessRequest { sftp_num }
                        }
                        Err(RequestHolderError::RanOut) => {
                            let used = self.request_holder.appended();
                            buf = &buf[used..];
                            debug!(
                                "{used:?} bytes added. Will keep adding \
                                until we hold a valid request"
                            );
                        }
                        Err(RequestHolderError::NoRoom) => {
                            error!(
                                "Could not complete the request. holding buffer is full"
                            );
                            return Err(SunsetError::Bug.into());
                        }
                        Err(e) => {
                            error!("{e:?}");
                            return Err(e.into());
                        }
                    }
                }
                HandlerState::ProcessRequest { .. } => {
                    // At this point the assumption is that the request holder will contain
                    // a full valid request (Lets call this an invariant)

                    self.process_validated_request(&output_producer).await?;
                    // Return so that more input can be read if possible.
                    return Ok(buffer_in.len() - buf.len());
                }
                HandlerState::ClearBuffer { data } => {
                    if *data == 0 {
                        self.state = HandlerState::Idle;
                    } else {
                        buf = &buf[(*data).min(buf.len())..]
                    }
                }
            }
            trace!("Process will check buf len {:?}", buf.len());
        }
        debug!("Whole buffer processed. Getting more data");
        debug_assert_eq!(buf.len(), 0);
        Ok(buffer_in.len())
    }
}
