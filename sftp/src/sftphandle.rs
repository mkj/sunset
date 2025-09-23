use crate::OpaqueFileHandle;
use crate::proto::{
    self, InitVersionLowest, ReqId, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION, SftpNum,
    SftpPacket, Status, StatusCode,
};
use crate::sftpserver::SftpServer;
use crate::sftpsink::SftpSink;
use crate::sftpsource::SftpSource;

use sunset::sshwire::{SSHDecode, WireError, WireResult};

use core::u32;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::usize;

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

    pub fn get_file_handle(&self) -> T {
        self.obscure_file_handle.clone()
    }
}

//#[derive(Debug, Clone)]
pub struct SftpHandler<'a, T, S>
where
    T: OpaqueFileHandle,
    S: SftpServer<'a, T>,
{
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
        }
    }

    /// Decodes the buffer_in request, process the request delegating operations to an Struct implementing SftpServer,
    /// serializes an answer in buffer_out and return the length used in buffer_out
    pub async fn process(
        &mut self,
        buffer_in: &[u8],
        buffer_out: &mut [u8],
    ) -> WireResult<usize> {
        let in_len = buffer_in.len();
        debug!("Received {:} bytes to process", in_len);

        if self.partial_write_request_tracker.is_none()
            & in_len.lt(&SFTP_MINIMUM_PACKET_LEN)
        {
            return Err(WireError::PacketWrong);
        }

        let mut source = SftpSource::new(buffer_in);
        trace!("Source content: {:?}", source);

        let mut sink = SftpSink::new(buffer_out);

        if let Some(mut write_tracker) = self.partial_write_request_tracker.take() {
            trace!(
                "Processing successive chunks of a long write packet. Stored data: {:?}",
                write_tracker
            );

            let usable_data = in_len.min(write_tracker.remain_data_len as usize);

            if in_len > write_tracker.remain_data_len as usize {
                // This is because we are receiving one packet and the beginning of the next one
                let sftp_num = source.peak_packet_type_with_offset(
                    write_tracker.remain_data_len as usize,
                )?;
                error!(
                    "There is too much data in the buffer! {:?} > than expected {:?}. There is a trailing packet in buffer: {:?}",
                    in_len, write_tracker.remain_data_len, sftp_num
                );
            };

            let data_segment = source.dec_as_binstring(usable_data)?;

            // TODO: Do proper casting with checks u32::try_from(data_in_buffer.0.len())
            let data_segment_len = data_segment.0.len() as u32;

            let current_write_offset = write_tracker.remain_data_offset;
            write_tracker.remain_data_offset += data_segment_len as u64;
            write_tracker.remain_data_len -= data_segment_len;

            let obscure_file_handle = write_tracker.get_file_handle();
            debug!(
                "Processing successive chunks of a long write packet. Writing : obscure_file_handle = {:?}, write_offset = {:?}, data_segment = {:?}, data remaining = {:?}",
                obscure_file_handle,
                current_write_offset,
                data_segment,
                write_tracker.remain_data_len
            );
            match self.file_server.write(
                &obscure_file_handle,
                current_write_offset,
                data_segment.as_ref(),
            ) {
                Ok(_) => {
                    if write_tracker.remain_data_len > 0 {
                        self.partial_write_request_tracker = Some(write_tracker);
                    } else {
                        push_ok(write_tracker.req_id, &mut sink)?;
                        info!("Finished multi part Write Request");
                        self.partial_write_request_tracker = None; // redundant
                    }
                }
                Err(e) => {
                    self.partial_write_request_tracker = None;
                    error!("SFTP write thrown: {:?}", e);
                    push_general_failure(
                        write_tracker.req_id,
                        "error writing",
                        &mut sink,
                    )?;
                }
            };

            return Ok(sink.finalize());
        }

        let packet_length = u32::dec(&mut source)?;
        trace!("Packet field length content: {}", packet_length);

        match SftpPacket::decode_request(&mut source) {
            Ok(request) => {
                info!("received request: {:?}", request);
                self.process_known_request(&mut sink, request).await?;
            }
            Err(e) => {
                match e {
                    WireError::RanOut => {
                        warn!(
                            "RanOut for the SFTP Packet in the source buffer: {:?}",
                            e
                        );
                        // let packet_total_length = source.peak_packet_len()?;
                        let packet_type = source.peak_packet_type()?;
                        match packet_type {
                            SftpNum::SSH_FXP_WRITE => {
                                let (
                                    file_handle,
                                    req_id,
                                    offset,
                                    data_in_buffer,
                                    write_tracker,
                                ) = source
                                    .get_packet_partial_write_content_and_tracker(
                                    )?;
                                debug!(
                                    "Packet is too long for the source buffer, will write what we have now and continue writing later"
                                );
                                trace!(
                                    "handle = {:?}, req_id = {:?}, offset = {:?}, data_in_buffer = {:?}, write_tracker = {:?}",
                                    file_handle, // This file_handle will be the one facilitated by the demosftpserver, this is, an obscured file handle
                                    req_id,
                                    offset,
                                    data_in_buffer,
                                    write_tracker
                                );

                                match self.file_server.write(
                                    &file_handle,
                                    offset,
                                    data_in_buffer.as_ref(),
                                ) {
                                    Ok(_) => {
                                        self.partial_write_request_tracker =
                                            Some(write_tracker);
                                    }
                                    Err(e) => {
                                        error!("SFTP write thrown: {:?}", e);
                                        push_general_failure(
                                            req_id,
                                            "error writing ",
                                            &mut sink,
                                        )?;
                                    }
                                };
                            }
                            _ => {
                                push_general_failure(
                                    ReqId(u32::MAX),
                                    "Unsupported Request: Too long",
                                    &mut sink,
                                )?;
                            }
                        };
                    }
                    WireError::UnknownPacket { number: _ } => {
                        warn!("Error decoding SFTP Packet:{:?}", e);
                        push_unsupported(ReqId(u32::MAX), &mut sink)?;
                    }
                    _ => {
                        error!("Error decoding SFTP Packet: {:?}", e);
                        push_unsupported(ReqId(u32::MAX), &mut sink)?;
                    }
                }
            }
        };

        Ok(sink.finalize())
    }

    async fn process_known_request(
        &mut self,
        sink: &mut SftpSink<'_>,
        request: SftpPacket<'_>,
    ) -> Result<(), WireError> {
        if !self.initialized && !matches!(request, SftpPacket::Init(_)) {
            push_general_failure(ReqId(u32::MAX), "Not Initialized", sink)?;
            error!("Request sent before init: {:?}", request);
            return Ok(());
        }
        match request {
            SftpPacket::Init(_) => {
                // TODO: Do a real check, provide the lowest version or return an error if the client cannot handle the server SFTP_VERSION
                let version =
                    SftpPacket::Version(InitVersionLowest { version: SFTP_VERSION });

                info!("Sending '{:?}'", version);

                version.encode_response(sink)?;

                self.initialized = true;
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let a_name =
                    self.file_server
                        .realpath(path_info.path.as_str().expect(
                            "Could not deref and the errors are not harmonized",
                        ))
                        .expect("Could not deref and the errors are not harmonized");

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
                        push_general_failure(req_id, "error writing ", sink)?
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
                push_unsupported(ReqId(0), sink)?;
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
    debug!("Pushing an OK status message: {:?}", response);
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
