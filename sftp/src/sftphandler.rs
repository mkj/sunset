use crate::proto::{
    self, InitVersionLowest, ReqId, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION, SftpNum,
    SftpPacket, Status, StatusCode,
};
use crate::requestholder::{RequestHolder, RequestHolderError};
use crate::sftperror::SftpResult;
use crate::sftpserver::SftpServer;
use crate::sftpsink::SftpSink;
use crate::sftpsource::SftpSource;
use crate::{OpaqueFileHandle, SftpError};

use sunset::Error as SunsetError;
use sunset::sshwire::{SSHSource, WireError, WireResult};

use core::{u32, usize};
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
    /// The request is fragmented and needs special handling
    Fragmented(FragmentedRequestState),
}

/// FSM subset to handle fragmented request as part of [`SftpHandleState`]
#[derive(Debug, PartialEq, Eq)]
enum FragmentedRequestState {
    /// A request that is clipped needs to be process. It cannot be decoded
    /// and more bytes are needed
    ProcessingClippedRequest,
    /// A request, with a length over the incoming buffer capacity is being
    /// processed
    ProcessingLongRequest,
}

// TODO: Generalize this to allow other request types
/// Used to keep record of a long SFTP Write request that does not fit in
/// receiving buffer and requires processing in batches
#[derive(Debug)]
pub struct PartialWriteRequestTracker<T: OpaqueFileHandle> {
    req_id: ReqId,
    obscure_file_handle: T,
    remain_data_len: u32,
    remain_data_offset: u64,
}

impl<T: OpaqueFileHandle> PartialWriteRequestTracker<T> {
    /// Creates a new [`PartialWriteRequestTracker`]
    pub fn new(
        req_id: ReqId,
        obscure_file_handle: T,
        remain_data_len: u32,
        remain_data_offset: u64,
    ) -> WireResult<Self> {
        Ok(PartialWriteRequestTracker {
            req_id,
            obscure_file_handle: obscure_file_handle,
            remain_data_len,
            remain_data_offset,
        })
    }
    /// Returns the opaque file handle associated with the request
    /// tracked
    pub fn get_opaque_file_handle(&self) -> T {
        self.obscure_file_handle.clone()
    }
}

/// Process the raw buffers in and out from a subsystem channel decoding
/// request and encoding responses
///
/// It will delegate request to an [`crate::sftpserver::SftpServer`]
/// implemented by the library
/// user taking into account the local system details.
pub struct SftpHandler<'a, T, S>
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

    incomplete_request_holder: RequestHolder<'a>,
}

impl<'a, T, S> SftpHandler<'a, T, S>
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

    /// Maintaining an internal status:
    ///
    /// - Decodes the buffer_in request
    /// - Process the request delegating
    /// operations to a [`SftpHandler::process`] implementation
    /// - Serializes an answer in buffer_out
    ///
    /// **Returns**: A result containing the number of bytes used in
    /// `buffer_out`
    pub async fn process(
        &mut self,
        buffer_in: &[u8],
        // incomplete_request_holder: &mut RequestHolder<'_>,
        buffer_out: &mut [u8],
    ) -> SftpResult<usize> {
        let in_len = buffer_in.len();
        let mut buffer_in_remaining_index = 0;

        let mut used_out_accumulated_index = 0;

        trace!("Received {:} bytes to process", in_len);

        if !matches!(self.state, SftpHandleState::Fragmented(_))
            & in_len.lt(&SFTP_MINIMUM_PACKET_LEN)
        {
            return Err(WireError::PacketWrong.into());
        }

        while buffer_in_remaining_index < in_len {
            let mut sink =
                SftpSink::new(&mut buffer_out[used_out_accumulated_index..]);

            debug!(
                "<=======================[ SFTP Process State: {:?} ]=======================>",
                self.state
            );

            match &self.state {
                SftpHandleState::Fragmented(fragment_case) => {
                    match fragment_case {
                        FragmentedRequestState::ProcessingClippedRequest => {
                            if let Err(e) = self
                                .incomplete_request_holder
                                .try_append_for_valid_request(
                                    // TODO: All your problems are here. Focus
                                    &buffer_in[buffer_in_remaining_index..],
                                )
                            {
                                match e {
                                    RequestHolderError::RanOut => {
                                        warn!(
                                            "There was not enough bytes in the buffer_in. \
                                            We will continue adding bytes"
                                        );
                                        buffer_in_remaining_index += self
                                            .incomplete_request_holder
                                            .appended();
                                        continue;
                                    }
                                    RequestHolderError::WireError(
                                        WireError::RanOut,
                                    ) => {
                                        warn!(
                                            "WIRE ERROR: There was not enough bytes in the buffer_in. \
                                            We will continue adding bytes"
                                        );
                                        buffer_in_remaining_index += self
                                            .incomplete_request_holder
                                            .appended();
                                        continue;
                                    }
                                    RequestHolderError::NoRoom => {
                                        warn!(
                                            "The request holder if full but the request in incomplete"
                                        )
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
                                debug!(
                                    "Incomplete request holder completed the request!"
                                );
                            }

                            let used = self.incomplete_request_holder.appended();
                            buffer_in_remaining_index += used;

                            let mut source = SftpSource::new(
                                &self.incomplete_request_holder.try_get_ref()?,
                            );
                            trace!("Internal Source Content: {:?}", source);

                            match SftpPacket::decode_request(&mut source) {
                                Ok(request) => {
                                    Self::handle_general_request(
                                        &mut self.file_server,
                                        &mut sink,
                                        request,
                                    )?;
                                    self.incomplete_request_holder.reset();
                                    self.state = SftpHandleState::Idle;
                                }
                                Err(e) => match e {
                                    WireError::RanOut => {
                                        match Self::handle_ran_out(
                                            &mut self.file_server,
                                            &mut sink,
                                            &mut source,
                                        ) {
                                            Ok(holder) => {
                                                self.partial_write_request_tracker =
                                                    Some(holder);
                                                self.incomplete_request_holder
                                                    .reset();
                                                self.state = SftpHandleState::Fragmented(FragmentedRequestState::ProcessingLongRequest);
                                            }
                                            Err(e) => match e {
                                                _ => {
                                                    error!(
                                                        "handle_ran_out finished with error: {:?}",
                                                        e
                                                    );
                                                    return Err(
                                                        SunsetError::Bug.into()
                                                    );
                                                }
                                            },
                                        }
                                    }
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
                        FragmentedRequestState::ProcessingLongRequest => {
                            let mut source = SftpSource::new(
                                &buffer_in[buffer_in_remaining_index..],
                            );
                            trace!("Source content: {:?}", source);

                            let mut write_tracker = if let Some(wt) =
                                self.partial_write_request_tracker.take()
                            {
                                wt
                            } else {
                                error!(
                                    "BUG: FragmentedRequestState::ProcessingLongRequest cannot take the write tracker"
                                );
                                return Err(SunsetError::Bug.into());
                            };

                            let opaque_handle =
                                write_tracker.get_opaque_file_handle();

                            let usable_data = source
                                .remaining()
                                .min(write_tracker.remain_data_len as usize); // TODO: Where does in_len comes from?
                            // in_len.min(write_tracker.remain_data_len as usize);

                            let data_segment = // Fails!!
                                            source.dec_as_binstring(usable_data)?;

                            let data_segment_len = u32::try_from(
                                data_segment.0.len(),
                            )
                            .map_err(|e| {
                                error!("Error casting data segment len to u32: {e}");
                                SunsetError::Bug
                            })?;
                            let current_write_offset =
                                write_tracker.remain_data_offset;
                            write_tracker.remain_data_offset +=
                                data_segment_len as u64;
                            write_tracker.remain_data_len -= data_segment_len;

                            debug!(
                                "Processing successive chunks of a long write packet. \
                                Writing : opaque_handle = {:?}, write_offset = {:?}, \
                                data_segment = {:?}, data remaining = {:?}",
                                opaque_handle,
                                current_write_offset,
                                data_segment,
                                write_tracker.remain_data_len
                            );

                            match self.file_server.write(
                                &opaque_handle,
                                current_write_offset,
                                data_segment.as_ref(),
                            ) {
                                Ok(_) => {
                                    if write_tracker.remain_data_len > 0 {
                                        self.partial_write_request_tracker =
                                            Some(write_tracker);
                                    } else {
                                        push_ok(write_tracker.req_id, &mut sink)?;
                                        info!("Finished multi part Write Request");
                                        self.state = SftpHandleState::Idle;
                                    }
                                }
                                Err(e) => {
                                    error!("SFTP write thrown: {:?}", e);
                                    push_general_failure(
                                        write_tracker.req_id,
                                        "error writing",
                                        &mut sink,
                                    )?;
                                    self.state = SftpHandleState::Idle;
                                }
                            };
                            buffer_in_remaining_index = in_len - source.remaining();
                        }
                    }
                }

                _ => {
                    let mut source =
                        SftpSource::new(&buffer_in[buffer_in_remaining_index..]);
                    trace!("Source content: {:?}", source);

                    let sftp_packet = SftpPacket::decode_request(&mut source);

                    match self.state {
                        SftpHandleState::Fragmented(_) => {
                            return Err(
                                SftpError::SunsetError(SunsetError::Bug).into()
                            );
                        }
                        SftpHandleState::Initializing => match sftp_packet {
                            Ok(request) => {
                                match request {
                                    SftpPacket::Init(_) => {
                                        let version =
                                            SftpPacket::Version(InitVersionLowest {
                                                version: SFTP_VERSION,
                                            });

                                        info!("Sending '{:?}'", version);
                                        version.encode_response(&mut sink)?;
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
                        },
                        SftpHandleState::Idle => {
                            match sftp_packet {
                                Ok(request) => {
                                    // self.handle_general_request(&mut sink, request)?
                                    Self::handle_general_request(
                                        &mut self.file_server,
                                        &mut sink,
                                        request,
                                    )?;
                                }
                                Err(e) => match e {
                                    WireError::RanOut => {
                                        warn!(
                                            "RanOut for the SFTP Packet in the source buffer: {:?}",
                                            e
                                        );

                                        match Self::handle_ran_out(
                                            &mut self.file_server,
                                            &mut sink,
                                            &mut source,
                                        ) {
                                            Ok(holder) => {
                                                self.partial_write_request_tracker =
                                                    Some(holder);
                                                self.state =
                                                        SftpHandleState::Fragmented(FragmentedRequestState::ProcessingLongRequest)
                                            }
                                            Err(e) => {
                                                error!("Error handle_ran_out");
                                                match e {
                                                    SftpError::WireError(
                                                        WireError::RanOut,
                                                    ) => {
                                                        let read = self.incomplete_request_holder
                                                            .try_hold(
                                                            &buffer_in
                                                                [buffer_in_remaining_index..],
                                                        )?;
                                                        buffer_in_remaining_index +=
                                                            read;
                                                        self.state = SftpHandleState::Fragmented(FragmentedRequestState::ProcessingClippedRequest);
                                                        continue;
                                                    }
                                                    _ => {
                                                        return Err(
                                                            SunsetError::Bug.into(),
                                                        );
                                                    }
                                                }
                                            }
                                        };
                                    }
                                    WireError::UnknownPacket { number: _ } => {
                                        warn!("Error decoding SFTP Packet:{:?}", e);
                                        push_unsupported(
                                            ReqId(u32::MAX),
                                            &mut sink,
                                        )?;
                                    }
                                    _ => {
                                        error!(
                                            "Error decoding SFTP Packet: {:?}",
                                            e
                                        );
                                        push_unsupported(
                                            ReqId(u32::MAX),
                                            &mut sink,
                                        )?;
                                    }
                                },
                            };
                        }
                    }
                    buffer_in_remaining_index = in_len - source.remaining();
                }
            };
            used_out_accumulated_index += sink.finalize();
        }

        Ok(used_out_accumulated_index)
    }

    fn handle_general_request(
        file_server: &mut S,
        sink: &mut SftpSink<'_>,
        request: SftpPacket<'_>,
    ) -> Result<(), SftpError>
    where
        T: OpaqueFileHandle,
    {
        match request {
            SftpPacket::Init(_) => {
                error!("The Init packet is not a request but an initialization");
                return Err(SftpError::AlreadyInitialized);
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let a_name = file_server.realpath(path_info.path.as_str()?)?;

                let response = SftpPacket::Name(req_id, a_name);

                response.encode_response(sink)?;
            }
            SftpPacket::Open(req_id, open) => {
                match file_server.open(open.filename.as_str()?, &open.attrs) {
                    Ok(opaque_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: opaque_file_handle.into_file_handle(),
                            },
                        );
                        response.encode_response(sink)?;
                        info!("Sending '{:?}'", response);
                    }
                    Err(status_code) => {
                        error!("Open failed: {:?}", status_code);
                        push_general_failure(req_id, "", sink)?;
                    }
                };
            }
            SftpPacket::Write(req_id, write) => {
                match file_server.write(
                    &T::try_from(&write.handle)?,
                    write.offset,
                    write.data.as_ref(),
                ) {
                    Ok(_) => push_ok(req_id, sink)?,
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        push_general_failure(req_id, "error writing", sink)?
                    }
                };
            }
            SftpPacket::Close(req_id, close) => {
                match file_server.close(&T::try_from(&close.handle)?) {
                    Ok(_) => push_ok(req_id, sink)?,
                    Err(e) => {
                        error!("SFTP Close thrown: {:?}", e);
                        push_general_failure(req_id, "", sink)?
                    }
                }
            }
            _ => {
                error!("Unsuported request type");
                push_unsupported(ReqId(0), sink)?;
            }
        }
        Ok(())
    }

    // TODO: Handle more long requests
    /// Handles long request that do not fit in the buffers and stores a tracker
    ///
    /// **WARNING:** Only `SSH_FXP_WRITE` has been implemented!
    ///
    fn handle_ran_out(
        file_server: &mut S,
        sink: &mut SftpSink<'_>,
        source: &mut SftpSource<'_>,
    ) -> SftpResult<PartialWriteRequestTracker<T>> {
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
                        // partial_write_request_tracker = Some(write_tracker); // TODO: This might belong to return value
                    }
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        push_general_failure(req_id, "error writing ", sink)?;
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

#[inline]
fn push_ok(req_id: ReqId, sink: &mut SftpSink<'_>) -> Result<(), WireError> {
    let response = SftpPacket::Status(
        req_id,
        Status {
            code: StatusCode::SSH_FX_OK,
            message: "".into(),
            lang: "en-US".into(),
        },
    );
    trace!("Pushing an OK status message: {:?}", response);
    response.encode_response(sink)?;
    Ok(())
}

#[inline]
fn push_unsupported(
    req_id: ReqId,
    sink: &mut SftpSink<'_>,
) -> Result<(), WireError> {
    let response = SftpPacket::Status(
        req_id,
        Status {
            code: StatusCode::SSH_FX_OP_UNSUPPORTED,
            message: "Not implemented".into(),
            lang: "en-US".into(),
        },
    );
    debug!("Pushing a unsupported status message: {:?}", response);
    response.encode_response(sink)?;
    Ok(())
}

#[inline]
fn push_general_failure(
    req_id: ReqId,
    msg: &'static str,
    sink: &mut SftpSink<'_>,
) -> Result<(), WireError> {
    let response = SftpPacket::Status(
        req_id,
        Status {
            code: StatusCode::SSH_FX_FAILURE,
            message: msg.into(),
            lang: "en-US".into(),
        },
    );
    debug!("Pushing a general failure status message: {:?}", response);
    response.encode_response(sink)?;
    Ok(())
}
