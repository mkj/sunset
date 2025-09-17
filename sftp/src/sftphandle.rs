use crate::proto::{
    self, InitVersionLowest, ReqId, SFTP_FIELD_ID_INDEX, SFTP_FIELD_LEN_INDEX,
    SFTP_FIELD_LEN_LENGTH, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION,
    SFTP_WRITE_REQID_INDEX, SftpNum, SftpPacket, Status, StatusCode,
};
use crate::sftpserver::SftpServer;
use crate::{FileHandle, ObscuredFileHandle};

use sunset::sshwire::{
    BinString, SSHDecode, SSHSink, SSHSource, WireError, WireResult,
};

use core::u32;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::usize;

/// Used to keep record of a long SFTP Write request that does not fit in receiving buffer and requires processing in batches
#[derive(Debug)]
struct PartialWriteRequestTracker {
    req_id: ReqId,
    obscure_file_handle: ObscuredFileHandle, // TODO: Change the file handle in SftpServer functions signature so it has a sort fixed length handle.
    data_len: u32,
    remain_data_len: u32,
    remain_data_offset: u64,
}

impl PartialWriteRequestTracker {
    pub fn new(
        req_id: ReqId,
        obscure_file_handle: ObscuredFileHandle,
        data_len: u32,
        remain_data_len: u32,
        remain_data_offset: u64,
    ) -> WireResult<Self> {
        let mut ret = PartialWriteRequestTracker {
            req_id,
            obscure_file_handle: obscure_file_handle,
            data_len,
            remain_data_len,
            remain_data_offset,
        };
        Ok(ret)
    }

    pub fn get_file_handle(&self) -> ObscuredFileHandle {
        self.obscure_file_handle.clone()
    }
}

/// SftpSource implements SSHSource and also extra functions to handle some challenges with long SFTP packets in constrained environments
#[derive(Default, Debug)]
pub struct SftpSource<'de> {
    pub buffer: &'de [u8],
    pub index: usize,
}

impl<'de> SSHSource<'de> for SftpSource<'de> {
    // Original take
    fn take(&mut self, len: usize) -> sunset::sshwire::WireResult<&'de [u8]> {
        if len + self.index > self.buffer.len() {
            return Err(WireError::RanOut);
        }
        let original_index = self.index;
        let slice = &self.buffer[self.index..self.index + len];
        self.index += len;
        trace!(
            "slice returned: {:?}. original index {:?}, new index: {:?}",
            slice, original_index, self.index
        );
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.buffer.len() - self.index
    }

    fn ctx(&mut self) -> &mut sunset::packets::ParseContext {
        todo!("Which context for sftp?");
    }
}

impl<'de> SftpSource<'de> {
    pub fn new(buffer: &'de [u8]) -> Self {
        SftpSource { buffer: buffer, index: 0 }
    }

    /// Peaks the buffer for packet type. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case the result will contain garbage
    fn peak_packet_type(&self) -> WireResult<SftpNum> {
        // const SFTP_ID_BUFFER_INDEX: usize = 4; // All SFTP packet have the packet type after a u32 length field
        // const SFTP_MINIMUM_LENGTH: usize = 9; // Corresponds to a minimal SSH_FXP_INIT packet
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            Ok(SftpNum::from(self.buffer[SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Peaks the buffer for packet length. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case the result will contain garbage
    fn peak_packet_len(&self) -> WireResult<u32> {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            let mut raw_bytes = [0u8; 4];
            raw_bytes.copy_from_slice(
                &self.buffer[SFTP_FIELD_LEN_INDEX
                    ..SFTP_FIELD_LEN_INDEX + SFTP_FIELD_LEN_LENGTH],
            );

            Ok(u32::from_be_bytes(raw_bytes))
        }
    }

    /// Assuming that the buffer contains a Write request packet initial bytes, Peaks the buffer for the handle length. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed write packets, in other case the result will contain garbage
    fn get_packet_partial_write_content_and_tracker(
        &mut self,
    ) -> WireResult<(
        ObscuredFileHandle,
        ReqId,
        u64,
        BinString<'de>,
        PartialWriteRequestTracker,
    )> {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            let prev_index = self.index;
            self.index = SFTP_WRITE_REQID_INDEX;
            let req_id = ReqId::dec(self)?;
            let file_handle = FileHandle::dec(self)?;

            let obscured_file_handle =
                ObscuredFileHandle::from_binstring(&file_handle.0)
                    .ok_or(WireError::BadString)?;

            let offset = u64::dec(self)?;
            let data_len = u32::dec(self)?;

            let data_len_in_buffer = self.buffer.len() - self.index;
            let data_in_buffer = BinString(self.take(data_len_in_buffer)?);

            self.index = prev_index;

            let remain_data_len = data_len - data_len_in_buffer as u32;
            let remain_data_offset = offset + data_len_in_buffer as u64;
            trace!(
                "Request ID = {:?}, Handle = {:?}, offset = {:?}, data length in buffer = {:?}, data in current buffer {:?} ",
                req_id, file_handle, offset, data_len_in_buffer, data_in_buffer
            );

            let write_tracker = PartialWriteRequestTracker::new(
                req_id,
                ObscuredFileHandle::from_filehandle(&file_handle)
                    .ok_or(WireError::BadString)?,
                data_len,
                remain_data_len,
                remain_data_offset,
            )?;

            Ok((obscured_file_handle, req_id, offset, data_in_buffer, write_tracker))
        }
    }

    /// Used to decode the whole SSHSource as a single BinString
    ///
    /// It will not use the first four bytes as u32 for length, instead it will use the length of the data received and use it to set the length of the returned BinString.
    fn dec_all_as_binstring(&mut self) -> WireResult<BinString<'_>> {
        Ok(BinString(self.take(self.buffer.len())?))
    }
}

#[derive(Default)]
pub struct SftpSink<'g> {
    pub buffer: &'g mut [u8],
    index: usize,
}

impl<'g> SftpSink<'g> {
    pub fn new(s: &'g mut [u8]) -> Self {
        SftpSink { buffer: s, index: SFTP_FIELD_LEN_LENGTH }
    }

    /// Finalise the buffer by prepending the payload size and returning
    ///
    /// Returns the final index in the buffer as a reference for the space used
    pub fn finalize(&mut self) -> usize {
        if self.index <= SFTP_FIELD_LEN_LENGTH {
            warn!("SftpSink trying to terminate it before pushing data");
            return 0;
        } // size is 0
        let used_size = (self.index - SFTP_FIELD_LEN_LENGTH) as u32;

        used_size
            .to_be_bytes()
            .iter()
            .enumerate()
            .for_each(|(i, v)| self.buffer[i] = *v);

        self.index
    }
}

impl<'g> SSHSink for SftpSink<'g> {
    fn push(&mut self, v: &[u8]) -> sunset::sshwire::WireResult<()> {
        if v.len() + self.index > self.buffer.len() {
            return Err(WireError::NoRoom);
        }
        trace!("Sink index: {:}", self.index);
        v.iter().for_each(|val| {
            self.buffer[self.index] = *val;
            self.index += 1;
        });
        trace!("Sink new index: {:}", self.index);
        Ok(())
    }
}

//#[derive(Debug, Clone)]
pub struct SftpHandler<'a> {
    file_server: &'a mut dyn SftpServer<'a>,
    ///
    buffer_in_len: usize,
    /// Once the client and the server have verified the agreed SFTP version the session is initialized
    initialized: bool,
    // /// Use to process SFTP packets that have been received partially and the remaining is expected in successive buffers
    // long_packet: bool,
    /// Use to process SFTP Write packets that have been received partially and the remaining is expected in successive buffers  
    partial_write_request_tracker: Option<PartialWriteRequestTracker>,
}

impl<'a> SftpHandler<'a> {
    pub fn new(
        file_server: &'a mut impl SftpServer<'a>,
        buffer_len: usize, // max_file_handlers: u32
    ) -> Self {
        if buffer_len < 256 {
            warn!(
                "Buffer length too small, must be at least 256 bytes. You are in uncharted territory"
            )
        }
        SftpHandler {
            file_server,
            buffer_in_len: buffer_len,
            // long_packet: false,
            initialized: false,
            partial_write_request_tracker: None,
        }
    }

    /// Decodes the buffer_in request, process the request delegating operations to an Struct implementing SftpServer,
    /// serialises an answer in buffer_out and return the length usedd in buffer_out
    pub async fn process(
        &mut self,
        buffer_in: &[u8],
        buffer_out: &mut [u8],
    ) -> WireResult<usize> {
        let in_len = buffer_in.len();
        debug!("Received {:} bytes to process", in_len);

        let mut source = SftpSource::new(buffer_in);
        trace!("Source content: {:?}", source);

        let mut sink = SftpSink::new(buffer_out);

        if let Some(mut write_tracker) = self.partial_write_request_tracker.take() {
            trace!(
                "Processing successive chunks of a long write packet . Stored data: {:?}",
                write_tracker
            );
            if in_len > write_tracker.remain_data_len as usize {
                // TODO: Investigate if we are receiving one packet and the beginning of the next one
                error!(
                    "There is too much data in the buffer! {:?} > than max expected {:?}",
                    in_len, write_tracker.remain_data_len
                );
                return Err(WireError::PacketWrong); // TODO: Handle this error instead of failing.
            }

            let current_write_offset = write_tracker.remain_data_offset;
            let data_in_buffer = source.dec_all_as_binstring()?;

            // TODO: Do proper casting with checks u32::try_from(data_in_buffer.0.len())
            let data_in_buffer_len = data_in_buffer.0.len() as u32;

            write_tracker.remain_data_offset += data_in_buffer_len as u64;
            write_tracker.remain_data_len -= data_in_buffer_len;

            let obscure_file_handle = write_tracker.get_file_handle();
            debug!(
                "Processing successive chunks of a long write packet. Writing : obscure_file_handle = {:?}, write_offset = {:?}, data = {:?}, data remaining = {:?}",
                obscure_file_handle,
                current_write_offset,
                data_in_buffer,
                write_tracker.remain_data_len
            );
            match self.file_server.write(
                &obscure_file_handle,
                current_write_offset,
                data_in_buffer.as_ref(),
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

        if self.partial_write_request_tracker.is_none()
            & in_len.lt(&SFTP_MINIMUM_PACKET_LEN)
        {
            return Err(WireError::PacketWrong);
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
                    Ok(obscured_file_handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle {
                                handle: obscured_file_handle.to_filehandle(),
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
                    &ObscuredFileHandle::from_filehandle(&write.handle)
                        .ok_or(WireError::BadString)?,
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
                match self.file_server.close(
                    &ObscuredFileHandle::from_filehandle(&close.handle)
                        .ok_or(WireError::BadString)?,
                ) {
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
