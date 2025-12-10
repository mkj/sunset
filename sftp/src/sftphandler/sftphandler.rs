use crate::error::SftpError;
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    self, InitVersionClient, InitVersionLowest, LStat, ReqId, SFTP_VERSION, SftpNum,
    SftpPacket, Stat, StatusCode,
};
use crate::server::{DirReply, ReadReply};
use crate::sftperror::SftpResult;
use crate::sftphandler::requestholder::{RequestHolder, RequestHolderError};
use crate::sftphandler::sftpoutputchannelhandler::{
    SftpOutputPipe, SftpOutputProducer,
};
use crate::sftpserver::SftpServer;
use crate::sftpsource::SftpSource;

use embassy_futures::select::select;
use sunset::Error as SunsetError;
use sunset::sshwire::{SSHSource, WireError};
use sunset_async::ChanInOut;

use core::u32;
use embedded_io_async::Read;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

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
/// It will delegate request to an [`crate::sftpserver::SftpServer`]
/// implemented by the library
/// user taking into account the local system details.
///
/// The compiler time constant `BUFFER_OUT_SIZE` is used to define the
/// size of the output buffer for the subsystem [`Embassy-sync::pipe`] used
/// to send responses safely across the instantiated structure.
///
pub struct SftpHandler<'a, T, S, const BUFFER_OUT_SIZE: usize>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
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
    S: SftpServer<'a, T>,
{
    /// Creates a new instance of the structure.
    ///
    /// Requires:
    ///
    /// - `file_server` (implementing [`crate::sftpserver::SftpServer`] ): to execute
    /// the request in the local system
    /// - `incomplete_request_buffer`: used to deal with fragmented
    /// packets during [`SftpHandler::process`]
    pub fn new(file_server: &'a mut S, request_buffer: &'a mut [u8]) -> Self {
        SftpHandler {
            file_server,
            // partial_write_request_tracker: None,
            state: HandlerState::default(),
            request_holder: RequestHolder::new(request_buffer),
            _marker: core::marker::PhantomData,
        }
    }

    /// - Decodes the buffer_in request
    /// - Process the request delegating
    /// operations to a [`SftpServer`] implementation
    /// - Serializes an answer in `output_producer`
    ///
    async fn process(
        &mut self,
        buffer_in: &[u8],
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
    ) -> SftpResult<()> {
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

        // We used `run_another_loop` to bypass the buf len check in
        // cases where we need to process data held
        // TODO: Fix this pattern
        let mut skip_checking_buffer = false;
        trace!("Entering loop to process the full received buffer");
        while skip_checking_buffer || buf.len() > 0 {
            debug!(
                "<=======================[ SFTP Process State: {:?} ]=======================> Buffer remaining: {}",
                self.state,
                buf.len()
            );
            skip_checking_buffer = false;
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
                            match self.file_server.write(
                                &T::try_from(&write.handle)?,
                                *offset,
                                data,
                            ) {
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
                            todo!("Wrong transition? Uncontrolled for now");
                        }
                    } else {
                        todo!("Wrong transition? Uncontrolled for now");
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

                            buf = &buf[buf.len() - source.remaining()..];

                            // We got the request. Moving on to process it before deserializing more
                            // data
                            skip_checking_buffer = true;
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
                                            .peak_packet_req_id()
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
                                            .peak_packet_req_id()
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

                    if let Some(request) = self.request_holder.valid_request() {
                        if !request.sftp_num().is_request() {
                            error!(
                                "Unexpected SftpPacket: {:?}",
                                request.sftp_num()
                            );
                            // return Err(SunsetError::BadUsage.build().into())
                            return Err(sunset::error::BadUsage.build().into());
                        }
                        match request {
                            // SftpPacket::Init(init_version_client) => todo!(),
                            // SftpPacket::Version(init_version_lowest) => todo!(),
                            SftpPacket::Read(req_id, ref read) => {
                                debug!("Read request: {:?}", request);

                                let mut reply =
                                    ReadReply::new(req_id, output_producer);
                                if let Err(error) = self
                                    .file_server
                                    .read(
                                        &T::try_from(&read.handle)?,
                                        read.offset,
                                        read.len,
                                        &mut reply,
                                    )
                                    .await
                                {
                                    error!("Error reading data: {:?}", error);
                                    if let SftpError::FileServerError(status) = error
                                    {
                                        output_producer
                                            .send_status(
                                                req_id,
                                                status,
                                                "Could not list attributes",
                                            )
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

                                match reply.read_diff() {
                                    diff if diff > 0 => {
                                        debug!(
                                            "ReadReply not completed after read operation. Still need to send {} bytes",
                                            diff
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                    diff if diff < 0 => {
                                        error!(
                                            "ReadReply has sent more data than announced: {} bytes extra",
                                            -diff
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                    _ => {}
                                }

                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::LStat(req_id, LStat { file_path: path }) => {
                                match self.file_server.stats(false, path.as_str()?) {
                                    Ok(attrs) => {
                                        debug!(
                                            "List stats for {} is {:?}",
                                            path, attrs
                                        );

                                        output_producer
                                            .send_packet(&SftpPacket::Attrs(
                                                req_id, attrs,
                                            ))
                                            .await?;
                                    }
                                    Err(status) => {
                                        error!(
                                            "Error listing stats for {}: {:?}",
                                            path, status
                                        );
                                        output_producer
                                            .send_status(
                                                req_id,
                                                status,
                                                "Could not list attributes",
                                            )
                                            .await?;
                                    }
                                };
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::Stat(req_id, Stat { file_path: path }) => {
                                match self.file_server.stats(true, path.as_str()?) {
                                    Ok(attrs) => {
                                        debug!(
                                            "List stats for {} is {:?}",
                                            path, attrs
                                        );

                                        output_producer
                                            .send_packet(&SftpPacket::Attrs(
                                                req_id, attrs,
                                            ))
                                            .await?;
                                    }
                                    Err(status) => {
                                        error!(
                                            "Error listing stats for {}: {:?}",
                                            path, status
                                        );
                                        output_producer
                                            .send_status(
                                                req_id,
                                                status,
                                                "Could not list attributes",
                                            )
                                            .await?;
                                    }
                                };
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::ReadDir(req_id, read_dir) => {
                                let mut reply =
                                    DirReply::new(req_id, output_producer);
                                if let Err(status) = self
                                    .file_server
                                    .readdir(
                                        &T::try_from(&read_dir.handle)?,
                                        &mut reply,
                                    )
                                    .await
                                {
                                    error!("Open failed: {:?}", status);

                                    output_producer
                                        .send_status(
                                            req_id,
                                            status,
                                            "Error Reading Directory",
                                        )
                                        .await?;
                                };
                                match reply.read_diff() {
                                    diff if diff > 0 => {
                                        debug!(
                                            "DirReply not completed after read operation. Still need to send {} bytes",
                                            diff
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                    diff if diff < 0 => {
                                        error!(
                                            "DirReply has sent more data than announced: {} bytes extra",
                                            -diff
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                    _ => {}
                                }
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::OpenDir(req_id, open_dir) => {
                                match self
                                    .file_server
                                    .opendir(open_dir.dirname.as_str()?)
                                {
                                    Ok(opaque_file_handle) => {
                                        let response = SftpPacket::Handle(
                                            req_id,
                                            proto::Handle {
                                                handle: opaque_file_handle
                                                    .into_file_handle(),
                                            },
                                        );
                                        output_producer
                                            .send_packet(&response)
                                            .await?;
                                    }
                                    Err(status_code) => {
                                        error!("Open failed: {:?}", status_code);
                                        output_producer
                                            .send_status(
                                                req_id,
                                                StatusCode::SSH_FX_FAILURE,
                                                "",
                                            )
                                            .await?;
                                    }
                                };
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::Close(req_id, close) => {
                                match self
                                    .file_server
                                    .close(&T::try_from(&close.handle)?)
                                {
                                    Ok(_) => {
                                        output_producer
                                            .send_status(
                                                req_id,
                                                StatusCode::SSH_FX_OK,
                                                "",
                                            )
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
                                {
                                    Ok(opaque_file_handle) => {
                                        let response = SftpPacket::Handle(
                                            req_id,
                                            proto::Handle {
                                                handle: opaque_file_handle
                                                    .into_file_handle(),
                                            },
                                        );
                                        output_producer
                                            .send_packet(&response)
                                            .await?;
                                    }
                                    Err(status_code) => {
                                        error!("Open failed: {:?}", status_code);
                                        output_producer
                                            .send_status(
                                                req_id,
                                                StatusCode::SSH_FX_FAILURE,
                                                "",
                                            )
                                            .await?;
                                    }
                                };
                                self.state = HandlerState::Idle;
                            }
                            SftpPacket::PathInfo(req_id, path_info) => {
                                match self
                                    .file_server
                                    .realpath(path_info.path.as_str()?)
                                {
                                    Ok(name_entry) => {
                                        let mut dir_reply =
                                            DirReply::new(req_id, output_producer);
                                        let encoded_len =
                                                crate::sftpserver::helpers::get_name_entry_len(&name_entry)?;
                                        debug!(
                                            "PathInfo encoded length: {:?}",
                                            encoded_len
                                        );
                                        trace!(
                                            "PathInfo Response content: {:?}",
                                            encoded_len
                                        );
                                        dir_reply
                                            .send_header(1, encoded_len)
                                            .await?;
                                        dir_reply.send_item(&name_entry).await?;
                                        if dir_reply.read_diff() != 0 {
                                            error!(
                                                "PathInfo reply not completed after sending the only item"
                                            );
                                            return Err(SunsetError::Bug.into());
                                        }
                                    }
                                    Err(code) => {
                                        output_producer
                                            .send_status(req_id, code, "")
                                            .await?;
                                    }
                                }
                                self.state = HandlerState::Idle;
                            }
                            // SftpPacket::Status(req_id, status) => todo!(),
                            // SftpPacket::Handle(req_id, handle) => todo!(),
                            // SftpPacket::Data(req_id, data) => todo!(),
                            // SftpPacket::Name(req_id, name) => todo!(),
                            // SftpPacket::Attrs(req_id, attrs) => todo!(),
                            _ => {

                                // TODO: Use a catch all
                            }
                        }
                    } else {
                        return Err(SunsetError::bug().into());
                    }
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
        Ok(())
    }

    /// Take the [`ChanInOut`] and locks, Processing all the request from stdio until
    /// an EOF is received
    pub async fn process_loop(
        &mut self,
        stdio: ChanInOut<'a>,
        buffer_in: &mut [u8],
    ) -> SftpResult<()> {
        let (mut chan_in, chan_out) = stdio.split();

        let mut sftp_output_pipe = SftpOutputPipe::<BUFFER_OUT_SIZE>::new();

        let (mut output_consumer, output_producer) =
            sftp_output_pipe.split(chan_out)?;

        let output_consumer_loop = output_consumer.receive_task();

        let processing_loop = async {
            loop {
                trace!("SFTP: About to read bytes from SSH Channel");
                let lr: usize = match chan_in.read(buffer_in).await {
                    Ok(lr) => lr,
                    Err(e) => match e {
                        SunsetError::NoRoom { .. } => {
                            error!("SSH channel is full");
                            continue;
                        }
                        _ => return Err(e.into()),
                    },
                };

                debug!("SFTP <---- received: {:?} bytes", lr);
                trace!("SFTP <---- received: {:?}", &buffer_in[0..lr]);
                if lr == 0 {
                    debug!("client disconnected");
                    return Err(SftpError::ClientDisconnected);
                }

                self.process(&buffer_in[0..lr], &output_producer).await?;
            }
            #[allow(unreachable_code)]
            SftpResult::Ok(())
        };
        match select(processing_loop, output_consumer_loop).await {
            embassy_futures::select::Either::First(r) => {
                error!("Processing returned: {:?}", r);
                r
            }
            embassy_futures::select::Either::Second(r) => {
                error!("Output consumer returned: {:?}", r);
                r
            }
        }
    }
}
