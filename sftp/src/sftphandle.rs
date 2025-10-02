use crate::proto::{
    self, InitVersionLowest, ReqId, SFTP_FIELD_ID_INDEX, SFTP_MINIMUM_PACKET_LEN,
    SFTP_VERSION, SftpNum, SftpPacket, Status, StatusCode,
};
use crate::requestholder::{RequestHolder, RequestHolderError};
use crate::sftperror::SftpResult;
use crate::sftpserver::SftpServer;
use crate::sftpsink::SftpSink;
use crate::sftpsource::SftpSource;
use crate::{OpaqueFileHandle, SftpError};

use sunset::Error as SunsetError;
use sunset::Error;
use sunset::sshwire::{SSHSource, WireError, WireResult};

use core::{u32, usize};
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

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

#[derive(Debug, PartialEq, Eq)]
enum FragmentedRequestState {
    /// A request that is clipped needs to be process. It cannot be decoded and more bytes are needed
    ProcessingClippedRequest,
    /// A request, with a length over the incoming buffer capacity is being processed
    ProcessingLongRequest,
}

/// Used to keep record of a long SFTP Write request that does not fit in receiving buffer and requires processing in batches
#[derive(Debug)]
pub struct PartialWriteRequestTracker<T: OpaqueFileHandle> {
    req_id: ReqId,
    obscure_file_handle: T,
    remain_data_len: u32,
    remain_data_offset: u64,
}

impl<T: OpaqueFileHandle> PartialWriteRequestTracker<T> {
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

    pub fn get_opaque_file_handle(&self) -> T {
        self.obscure_file_handle.clone()
    }
}

/// Process the raw buffers in and out from a subsystem channel decoding request and encoding responses
///
/// It will delegate request to an `SftpServer` implemented by the library user taking into account the local system details.
pub struct SftpHandler<'a, T, S>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
{
    /// Holds the internal state if the SFTP handle
    state: SftpHandleState,

    /// The local SFTP File server implementing the basic SFTP requests defined by `SftpServer`
    file_server: &'a mut S,

    /// Once the client and the server have verified the agreed SFTP version the session is initialized
    initialized: bool,

    /// Use to process SFTP Write packets that have been received partially and the remaining is expected in successive buffers  
    partial_write_request_tracker: Option<PartialWriteRequestTracker<T>>,
}

impl<'a, T, S> SftpHandler<'a, T, S>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
{
    pub fn new(file_server: &'a mut S) -> Self {
        SftpHandler {
            file_server,
            initialized: false,
            partial_write_request_tracker: None,
            state: SftpHandleState::default(),
        }
    }

    /// Decodes the buffer_in request, process the request delegating operations to an Struct implementing SftpServer,
    /// serializes an answer in buffer_out and **returns** the length used in buffer_out
    pub async fn process(
        &mut self,
        buffer_in: &[u8],
        incomplete_request_holder: &mut RequestHolder<'_>,
        buffer_out: &mut [u8],
    ) -> SftpResult<usize> {
        let in_len = buffer_in.len();
        let mut buffer_in_remaining_index = 0;

        let mut used_out_accumulated_index = 0;

        trace!("Received {:} bytes to process", in_len);

        // let mut pending_incomplete_request = incomplete_request_holder.is_busy();
        // let pending_long_request = self.partial_write_request_tracker.is_some();

        if !matches!(self.state, SftpHandleState::Fragmented(_))
            & in_len.lt(&SFTP_MINIMUM_PACKET_LEN)
        {
            return Err(WireError::PacketWrong.into());
        }

        while buffer_in_remaining_index < in_len {
            let mut sink =
                SftpSink::new(&mut buffer_out[used_out_accumulated_index..]);

            debug!("SFTP Process State: {:?}", self.state);

            match &self.state {
                SftpHandleState::Fragmented(fragment_case) => {
                    match fragment_case {
                        FragmentedRequestState::ProcessingClippedRequest => {
                            let append_result = incomplete_request_holder
                                .try_append_for_valid_request(
                                    &buffer_in[buffer_in_remaining_index..],
                                );

                            if let Err(e) = append_result {
                                match e {
                                    RequestHolderError::RanOut => {
                                        warn!(
                                            "There was not enough bytes in the buffer_in. \
                                            We will continue adding bytes"
                                        );
                                        buffer_in_remaining_index +=
                                            incomplete_request_holder.appended();
                                        continue;
                                    }
                                    RequestHolderError::NoRoom => {
                                        warn!(
                                            "There is not enough room in incomplete request holder \
                                            to accommodate this packet buffer."
                                        )
                                    }
                                    RequestHolderError::WireError(
                                        WireError::RanOut,
                                    ) => {
                                        warn!(
                                            "There is not enough room in incomplete request holder \
                                            to accommodate this packet buffer."
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
                                    "Incomplete request holder completes request!"
                                );
                            }
                            let mut source = SftpSource::new(
                                &incomplete_request_holder.try_get_ref()?,
                            );
                            trace!("Internal Source Content: {:?}", source);

                            let sftp_packet =
                                SftpPacket::decode_request(&mut source);

                            match sftp_packet {
                                Ok(request) => {
                                    self.handle_general_request(&mut sink, request)?;
                                }
                                Err(e) => match e {
                                    WireError::NoRoom => {
                                        todo!("The packet do not fit in the buffer")
                                    }
                                    WireError::RanOut => {
                                        todo!("Not enough data to decode the packet")
                                    }
                                    _ => {
                                        error!(
                                            "Unhandled error decoding assembled packet: {:?}",
                                            e
                                        );
                                    }
                                },
                            }

                            let used = incomplete_request_holder.appended();
                            buffer_in_remaining_index += used;

                            incomplete_request_holder.reset();
                            self.state = SftpHandleState::Idle;
                            todo!("FragmentedRequestState::ProcessingClippedRequest")
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
                                return Err(SftpError::SunsetError(
                                    SunsetError::Bug,
                                ));
                            };

                            let opaque_handle =
                                write_tracker.get_opaque_file_handle();

                            let usable_data =
                                in_len.min(write_tracker.remain_data_len as usize);

                            let data_segment = // Fails!!
                                            source.dec_as_binstring(usable_data)?;

                            let data_segment_len =
                                u32::try_from(data_segment.0.len())
                                    .map_err(|e| SunsetError::Bug)?;
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
                                    SftpPacket::Init(init_version_client) => {
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
                                    self.handle_general_request(&mut sink, request)?
                                }
                                Err(e) => match e {
                                    WireError::RanOut => {
                                        warn!(
                                            "RanOut for the SFTP Packet in the source buffer: {:?}",
                                            e
                                        );

                                        match self.process_ran_out(&mut sink, &mut source) {
                                                Ok(_) => {
                                                    self.state =
                                                        SftpHandleState::Fragmented(FragmentedRequestState::ProcessingLongRequest)
                                                }
                                                Err(e) => match e {
                                                    SftpError::WireError(WireError::RanOut) => {
                                                        let read = incomplete_request_holder
                                                            .try_hold(
                                                            &buffer_in
                                                                [buffer_in_remaining_index..],
                                                        )?; // Fails because it does not fit. Also. It is not the beginning of a new packet
                                                        self.state = SftpHandleState::Fragmented(FragmentedRequestState::ProcessingClippedRequest)
                                                    }
                                                    _ => return (Err(SunsetError::Bug.into())),
                                                },
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
        &mut self,
        sink: &mut SftpSink<'_>,
        request: SftpPacket<'_>,
    ) -> Result<(), SftpError>
    where
        T: OpaqueFileHandle,
    {
        Ok(match request {
            SftpPacket::Init(init_version_client) => {
                return Err(SftpError::MalformedPacket);
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let a_name = self.file_server.realpath(path_info.path.as_str()?)?;

                let response = SftpPacket::Name(req_id, a_name);

                response.encode_response(sink)?;
            }
            SftpPacket::Open(req_id, open) => {
                match self.file_server.open(open.filename.as_str()?, &open.attrs) {
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
                match self.file_server.write(
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
                match self.file_server.close(&T::try_from(&close.handle)?) {
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
        })
    }

    fn process_ran_out(
        &mut self,
        sink: &mut SftpSink<'_>,
        source: &mut SftpSource<'_>,
    ) -> Result<(), SftpError> {
        let packet_type = source.peak_packet_type()?;
        match packet_type {
            SftpNum::SSH_FXP_WRITE => {
                debug!("about to decode packet partial write content",);
                let (
                    obscured_file_handle,
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                ) = source.dec_packet_partial_write_content_and_get_tracker()?;

                trace!(
                    "obscured_file_handle = {:?}, req_id = {:?}, \
                    offset = {:?}, data_in_buffer = {:?}, \
                    write_tracker = {:?}",
                    obscured_file_handle, // This file_handle will be the one facilitated by the demosftpserver, this is, an obscured file handle
                    req_id,
                    offset,
                    data_in_buffer,
                    write_tracker,
                );

                match self.file_server.write(
                    &obscured_file_handle,
                    offset,
                    data_in_buffer.as_ref(),
                ) {
                    Ok(_) => {
                        self.partial_write_request_tracker = Some(write_tracker);
                    }
                    Err(e) => {
                        error!("SFTP write thrown: {:?}", e);
                        push_general_failure(req_id, "error writing ", sink)?;
                    }
                };
            }
            _ => {
                error!("Packet type could not be handled {:?}", packet_type);
                push_general_failure(
                    ReqId(u32::MAX),
                    "Unsupported Request: Too long",
                    sink,
                )?;
            }
        };
        Ok(())
    }

}

#[inline]
fn push_ok(req_id: ReqId, sink: &mut SftpSink<'_>) -> Result<(), WireError> {
    let response = SftpPacket::Status(
        req_id,
        Status {
            code: StatusCode::SSH_FX_OK,
            message: "".into(),
            lang: "EN".into(),
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
            lang: "EN".into(),
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
            lang: "EN".into(),
        },
    );
    debug!("Pushing a general failure status message: {:?}", response);
    response.encode_response(sink)?;
    Ok(())
}
