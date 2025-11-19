use super::PartialWriteRequestTracker;

use crate::error::SftpError;
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    self, InitVersionLowest, LStat, ReqId, SFTP_VERSION, SftpNum, SftpPacket, Stat,
    StatusCode,
};
use crate::requestholder::{RequestHolder, RequestHolderError};
use crate::server::{DirReply, ReadReply};
use crate::sftperror::SftpResult;
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
enum SftpHandleState {
    /// The handle is not initialized
    #[default]
    Initializing,
    /// The handle is ready to process requests
    Idle,
    // /// The request is fragmented and needs special handling
    // Fragmented(FragmentedRequestState),
    /// A request that is clipped needs to be process. It cannot be decoded
    /// and more bytes are needed
    ProcessingClippedRequest,
    /// A request, with a length over the incoming buffer capacity is being
    /// processed.
    ///
    /// E.g. a write request with size exceeding the
    /// buffer size: Processing this request will require to be split
    /// into multiple write actions
    ProcessingLongRequest,
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
    state: SftpHandleState,

    /// The local SFTP File server implementing the basic SFTP requests
    /// defined by [`crate::sftpserver::SftpServer`]
    file_server: &'a mut S,

    /// Use to process SFTP Write packets that have been received
    /// partially and the remaining is expected in successive buffers  
    partial_write_request_tracker: Option<PartialWriteRequestTracker<T>>,

    /// Used to handle received buffers that do not hold a complete request [`SftpPacket`]
    incomplete_request_holder: RequestHolder<'a>,
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
    pub fn new(
        file_server: &'a mut S,
        incomplete_request_buffer: &'a mut [u8],
    ) -> Self {
        SftpHandler {
            file_server,
            partial_write_request_tracker: None,
            state: SftpHandleState::default(),
            incomplete_request_holder: RequestHolder::new(incomplete_request_buffer),
        }
    }

    /// WIP: A version of process that takes a chan_out to write the data
    ///
    /// Maintaining an internal status:
    ///
    /// - Decodes the buffer_in request
    /// - Process the request delegating
    /// operations to a [`SftpHandler::process`] implementation
    /// - Serializes an answer in buffer_out
    ///
    /// **Returns**: A result containing the number of bytes used in
    /// `buffer_out`
    async fn process(
        &mut self,
        buffer_in: &[u8],
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
    ) -> SftpResult<()> {
        let mut buf = buffer_in;

        trace!("Received {:} bytes to process", buf.len());

        trace!("Entering loop to process the full received buffer");
        while buf.len() > 0 {
            debug!(
                "<=======================[ SFTP Process State: {:?} ]=======================> Buffer remaining: {}",
                self.state,
                buf.len()
            );

            match &self.state {
                SftpHandleState::ProcessingClippedRequest => {
                    if let Err(e) = self
                        .incomplete_request_holder
                        .try_append_for_valid_request(&buf)
                    {
                        match e {
                            RequestHolderError::RanOut => {
                                warn!(
                                    "There was not enough bytes in the buffer_in. \
                                                We will continue adding bytes"
                                );
                                buf = &buf
                                    [self.incomplete_request_holder.appended()..];
                                continue;
                            }
                            RequestHolderError::WireError(WireError::RanOut) => {
                                warn!(
                                    "WIRE ERROR: There was not enough bytes in the buffer_in. \
                                                We will continue adding bytes"
                                );
                                buf = &buf
                                    [self.incomplete_request_holder.appended()..];
                                continue;
                            }
                            RequestHolderError::NoRoom => {
                                warn!(
                                    "The request holder is full but the request in is incomplete. \
                                                We will try to decode it"
                                );
                            }

                            _ => {
                                error!(
                                    "Unhandled error completing incomplete request {:?}",
                                    e,
                                );
                                return Err(SunsetError::Bug.into());
                            }
                        }
                    } else {
                        debug!("Incomplete request holder completed the request!");
                    }

                    let used = self.incomplete_request_holder.appended();
                    buf = &buf[used..];

                    let mut source = SftpSource::new(
                        &self.incomplete_request_holder.try_get_ref()?,
                    );
                    trace!("Internal Source Content: {:?}", source);

                    match SftpPacket::decode_request(&mut source) {
                        Ok(request) => {
                            Self::handle_general_request(
                                &mut self.file_server,
                                output_producer,
                                request,
                            )
                            .await?;
                            self.incomplete_request_holder.reset();
                            self.state = SftpHandleState::Idle;
                        }
                        Err(e) => match e {
                            WireError::UnknownPacket { number } => {
                                warn!(
                                    "Unknown packet: packetId = {:?}. Will flush \
                                    its length and send unsupported back",
                                    number
                                );

                                let req_id = ReqId(source.peak_packet_req_id()?);
                                let len = source.peak_total_packet_len()? as usize;
                                source.consume_first(len)?;
                                output_producer
                                    .send_status(
                                        req_id,
                                        StatusCode::SSH_FX_OP_UNSUPPORTED,
                                        "Error decoding SFTP Packet",
                                    )
                                    .await?;
                            }
                            WireError::RanOut => match Self::handle_ran_out(
                                &mut self.file_server,
                                output_producer,
                                &mut source,
                            )
                            .await
                            {
                                Ok(holder) => {
                                    self.partial_write_request_tracker =
                                        Some(holder);
                                    self.incomplete_request_holder.reset();
                                    self.state =
                                        SftpHandleState::ProcessingLongRequest;
                                }
                                Err(e) => match e {
                                    _ => {
                                        error!(
                                            "handle_ran_out finished with error: {:?}",
                                            e
                                        );
                                        return Err(SunsetError::Bug.into());
                                    }
                                },
                            },
                            WireError::NoRoom => {
                                error!("Not enough space to fit the request")
                            }
                            _ => {
                                error!(
                                    "Unhandled error decoding assembled packet: {:?}",
                                    e
                                );
                                return Err(WireError::PacketWrong.into());
                            }
                        },
                    }
                }
                SftpHandleState::ProcessingLongRequest => {
                    let mut source = SftpSource::new(&buf);
                    trace!("Source content: {:?}", source);

                    let mut write_tracker = if let Some(wt) =
                        self.partial_write_request_tracker.take()
                    {
                        wt
                    } else {
                        error!(
                            "BUG: SftpHandleState::ProcessingLongRequest cannot take the write tracker"
                        );
                        return Err(SunsetError::Bug.into());
                    };

                    let opaque_handle = write_tracker.get_opaque_file_handle();

                    let usable_data = source
                        .remaining()
                        .min(write_tracker.get_remain_data_len() as usize);

                    let data_segment = source.dec_as_binstring(usable_data)?;

                    let data_segment_len = u32::try_from(data_segment.0.len())
                        .map_err(|e| {
                            error!("Error casting data segment len to u32: {e}");
                            SunsetError::Bug
                        })?;
                    let current_write_offset =
                        write_tracker.get_remain_data_offset();
                    write_tracker
                        .update_remaining_after_partial_write(data_segment_len);

                    debug!(
                        "Processing successive chunks of a long write packet. \
                                    Writing : opaque_handle = {:?}, write_offset = {:?}, \
                                    data_segment = {:?}, data remaining = {:?}",
                        opaque_handle,
                        current_write_offset,
                        data_segment,
                        write_tracker.get_remain_data_len()
                    );

                    match self.file_server.write(
                        &opaque_handle,
                        current_write_offset,
                        data_segment.as_ref(),
                    ) {
                        Ok(_) => {
                            if write_tracker.get_remain_data_len() > 0 {
                                self.partial_write_request_tracker =
                                    Some(write_tracker);
                            } else {
                                output_producer
                                    .send_status(
                                        write_tracker.get_req_id(),
                                        StatusCode::SSH_FX_OK,
                                        "",
                                    )
                                    .await?;
                                info!("Finished multi part Write Request");
                                self.state = SftpHandleState::Idle;
                            }
                        }
                        Err(e) => {
                            error!("SFTP write thrown: {:?}", e);
                            output_producer
                                .send_status(
                                    write_tracker.get_req_id(),
                                    StatusCode::SSH_FX_FAILURE,
                                    "error writing",
                                )
                                .await?;
                            self.state = SftpHandleState::Idle;
                        }
                    };
                    buf = &buf[buf.len() - source.remaining()..];
                }
                SftpHandleState::Initializing => {
                    let (source, sftp_packet) = create_sftp_source_and_packet(buf);
                    match sftp_packet {
                        Ok(request) => {
                            match request {
                                SftpPacket::Init(_) => {
                                    let version =
                                        SftpPacket::Version(InitVersionLowest {
                                            version: SFTP_VERSION,
                                        });

                                    output_producer.send_packet(&version).await?;
                                    self.state = SftpHandleState::Idle;
                                }
                                _ => {
                                    error!(
                                        "Request received before init: {:?}",
                                        request
                                    );
                                    return Err(SftpError::NotInitialized);
                                }
                            };
                        }
                        Err(_) => {
                            error!(
                                "Malformed SFTP Packet before Init: {:?}",
                                sftp_packet
                            );
                            return Err(SftpError::MalformedPacket);
                        }
                    }
                    buf = &buf[buf.len() - source.remaining()..];
                }
                SftpHandleState::Idle => {
                    let (mut source, sftp_packet) =
                        create_sftp_source_and_packet(buf);
                    match sftp_packet {
                        Ok(request) => {
                            Self::handle_general_request(
                                &mut self.file_server,
                                output_producer,
                                request,
                            )
                            .await?;
                        }
                        Err(e) => match e {
                            WireError::RanOut => {
                                warn!(
                                    "RanOut for the SFTP Packet in the source buffer: {:?}",
                                    e
                                );

                                match Self::handle_ran_out(
                                    &mut self.file_server,
                                    output_producer,
                                    &mut source,
                                )
                                .await
                                {
                                    Ok(holder) => {
                                        self.partial_write_request_tracker =
                                            Some(holder);
                                        self.state =
                                            SftpHandleState::ProcessingLongRequest;
                                    }
                                    Err(e) => {
                                        error!("Error handle_ran_out");
                                        match e {
                                            SftpError::WireError(
                                                WireError::RanOut,
                                            ) => {
                                                let read = self
                                                    .incomplete_request_holder
                                                    .try_hold(&buf)?;
                                                buf = &buf[read..];

                                                self.state = SftpHandleState::ProcessingClippedRequest;
                                                continue;
                                            }
                                            _ => {
                                                return Err(SunsetError::Bug.into());
                                            }
                                        }
                                    }
                                };
                            }
                            WireError::UnknownPacket { number } => {
                                warn!(
                                    "Unknown packet: packetId = {:?}. Will flush \
                                    its length and send unsupported back",
                                    number
                                );

                                let req_id = ReqId(source.peak_packet_req_id()?);
                                let len = source.peak_total_packet_len()? as usize;
                                source.consume_first(len)?;
                                output_producer
                                    .send_status(
                                        req_id,
                                        StatusCode::SSH_FX_OP_UNSUPPORTED,
                                        "Error decoding SFTP Packet",
                                    )
                                    .await?;
                            }
                            _ => {
                                error!("Error decoding SFTP Packet: {:?}", e);
                                output_producer
                                    .send_status(
                                        ReqId(u32::MAX),
                                        StatusCode::SSH_FX_OP_UNSUPPORTED,
                                        "Error decoding SFTP Packet",
                                    )
                                    .await?;
                            }
                        },
                    };
                    buf = &buf[buf.len() - source.remaining()..];
                    trace!("New buffer len {} bytes ", buf.len())
                }
            }
            trace!("Process checking buf len {:?}", buf.len());
        }
        trace!("Exiting process with Ok(())");
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
                let lr = chan_in.read(buffer_in).await?;

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
                debug!("Processing returned: {:?}", r);
                r
            }
            embassy_futures::select::Either::Second(r) => {
                warn!("Output consumer returned: {:?}", r);
                r
            }
        }
    }

    /// Handles Healthy formed SftpRequest. Will return error if:
    ///
    /// - The request (SftpPacket) is not a request
    ///
    /// - The request is an unknown SftpPacket
    ///
    /// - The request is an initialization packet, and the initialization
    /// has already been performed
    async fn handle_general_request(
        file_server: &mut S,
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
        request: SftpPacket<'_>,
    ) -> Result<(), SftpError>
    where
        T: OpaqueFileHandle,
    {
        debug!("Handling general request: {:?}", request);
        match request {
            SftpPacket::Init(_) => {
                error!("The Init packet is not a request but an initialization");
                return Err(SftpError::AlreadyInitialized);
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let dir_reply = DirReply::new(req_id, output_producer);
                let name_entry = file_server.realpath(path_info.path.as_str()?)?;

                let encoded_len =
                    crate::sftpserver::helpers::get_name_entry_len(&name_entry)?;
                debug!("PathInfo encoded length: {:?}", encoded_len);
                trace!("PathInfo Response content: {:?}", encoded_len);
                dir_reply.send_header(1, encoded_len).await?;
                dir_reply.send_item(&name_entry).await?;
            }
            SftpPacket::Open(req_id, open) => {
                match file_server.open(open.filename.as_str()?, &open.pflags) {
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
            }
            // TODO The visitor behavioral pattern could be use in write to speed-up
            // the writing process
            SftpPacket::Write(req_id, write) => {
                match file_server.write(
                    &T::try_from(&write.handle)?,
                    write.offset,
                    write.data.as_ref(),
                ) {
                    Ok(_) => {
                        output_producer
                            .send_status(req_id, StatusCode::SSH_FX_OK, "")
                            .await?;
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
                    }
                };
            }
            SftpPacket::Close(req_id, close) => {
                match file_server.close(&T::try_from(&close.handle)?) {
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
            }
            SftpPacket::OpenDir(req_id, open_dir) => {
                match file_server.opendir(open_dir.dirname.as_str()?) {
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
            }
            SftpPacket::ReadDir(req_id, read_dir) => {
                if let Err(status) = file_server
                    .readdir(
                        &T::try_from(&read_dir.handle)?,
                        &DirReply::new(req_id, output_producer),
                    )
                    .await
                {
                    error!("Open failed: {:?}", status);

                    output_producer
                        .send_status(req_id, status, "Error Reading Directory")
                        .await?;
                };
            }
            SftpPacket::Read(req_id, read) => {
                if let Err(error) = file_server
                    .read(
                        &T::try_from(&read.handle)?,
                        read.offset,
                        read.len,
                        &ReadReply::new(req_id, output_producer),
                    )
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
                }
            }
            SftpPacket::LStat(req_id, LStat { file_path: path }) => {
                match file_server.stats(false, path.as_str()?) {
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
                }
            }
            SftpPacket::Stat(req_id, Stat { file_path: path }) => {
                match file_server.stats(true, path.as_str()?) {
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
                }
            }
            _ => {
                error!("Unsupported request type: {:?}", request);
                return Err(SftpError::NotSupported);
            }
        }
        Ok(())
    }

    // TODO Handle other long requests
    /// Some long request will not fit in the channel buffers. Such requests
    /// will require to be handled differently. Gathering the data in and
    /// processing it as we receive it in the channel in buffer.
    ///
    /// In the current approach, a tracker is required to store the state of
    /// the processing of such long requests.
    ///
    /// With an implementation that where able to hold the channel_in there might
    /// be no need to keep this tracker.
    ///
    /// **WARNING:** Only `SSH_FXP_WRITE` has been implemented!
    ///
    async fn handle_ran_out(
        file_server: &mut S,
        output_producer: &SftpOutputProducer<'_, BUFFER_OUT_SIZE>,
        source: &mut SftpSource<'_>,
    ) -> SftpResult<PartialWriteRequestTracker<T>> {
        debug!("Handing Ran out");
        let packet_type = source.peak_packet_type()?;
        match packet_type {
            SftpNum::SSH_FXP_WRITE => {
                debug!(
                    "about to decode packet partial write content. Source remaining = {:?}",
                    source.remaining()
                );
                let (
                    obscured_file_handle,
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                ) = source
                    .dec_packet_partial_write_content_and_get_tracker::<T>()?;

                trace!(
                    "obscured_file_handle = {:?}, req_id = {:?}, \
                    offset = {:?}, data_in_buffer = {:?}, \
                    write_tracker = {:?}",
                    obscured_file_handle,
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                );

                match file_server.write(
                    &obscured_file_handle,
                    offset,
                    data_in_buffer.as_ref(),
                ) {
                    Ok(_) => {
                        debug!(
                            "Storing a write tracker for a fragmented write request"
                        );
                        return Ok(write_tracker);
                    }
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        output_producer
                            .send_status(
                                req_id,
                                StatusCode::SSH_FX_FAILURE,
                                "error writing ",
                            )
                            .await?;
                        return Err(SftpError::FileServerError(e));
                    }
                };
            }
            _ => {
                error!(
                    "RanOut of Packet type could not be handled {:?}",
                    packet_type
                );
                return Err(SftpError::NotSupported);
            }
        };
        // Ok(())
    }
}

/// Function to create an SFTP source and decode an SFTP packet from it.
///
/// Defined to avoid code duplication.
fn create_sftp_source_and_packet(
    buf: &[u8],
) -> (SftpSource<'_>, Result<SftpPacket<'_>, WireError>) {
    debug!("Creating a source: buf_len = {:?}", buf.len());
    let mut source = SftpSource::new(&buf);

    let sftp_packet = SftpPacket::decode_request(&mut source);
    (source, sftp_packet)
}
