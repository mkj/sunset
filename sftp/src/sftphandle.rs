use crate::proto::{
    self, Handle, InitVersionLowest, ReqId, SFTP_FIELD_ID_INDEX,
    SFTP_FIELD_LEN_INDEX, SFTP_FIELD_LEN_LENGTH, SFTP_MINIMUM_PACKET_LEN,
    SFTP_VERSION, SFTP_WRITE_REQID_INDEX, SftpNum, SftpPacket, Status, StatusCode,
};
use crate::sftpserver::SftpServer;

use sunset::sshwire::{SSHDecode, SSHSink, SSHSource, WireError, WireResult};

use core::u32;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::usize;

/// This implementation is an extension of the SSHSource interface to handle some challenges with SFTP packets
///
#[derive(Default, Debug)]
pub struct SftpSource<'de> {
    pub buffer: &'de [u8],
    pub index: usize,
}

impl<'de> SSHSource<'de> for SftpSource<'de> {
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
        todo!(
            "I don't know what to do with the ctx, since sftp does not have context"
        );
    }
}

impl<'de> SftpSource<'de> {
    pub fn new(buffer: &'de [u8]) -> Self {
        SftpSource { buffer: buffer, index: 0 }
    }

    /// Rewinds the index back to the initial byte
    ///
    /// In case of an error deserializing the SSHSource it allows reprocessing the buffer from start
    pub fn rewind(&mut self) -> () {
        self.index = 0;
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

    /// Assuming that the buffer contains a Write request packet, Peaks the buffer for the handle length. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed write packets, in other case the result will contain garbage
    fn peak_write_handle_offset_n_data_len(
        &mut self,
    ) -> WireResult<(Handle<'_>, ReqId, u64, u32)> {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            let prev_index = self.index;
            self.index = SFTP_WRITE_REQID_INDEX;
            let req_id = ReqId::dec(self)?;
            let handle = Handle::dec(self)?;
            let offset = u64::dec(self)?;
            let data_len = u32::dec(self)?;

            self.index = prev_index;

            debug!(
                "Request ID = {:?}, Handle = {:?}, offset = {:?}, data length = {:?}, ",
                req_id, handle, offset, data_len
            );
            Ok((handle, req_id, offset, data_len))
        }
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
    pub fn finalise(&mut self) -> usize {
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
    buffer_in_len: usize,
    initialized: bool,
    long_packet: bool,
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
            long_packet: false,
            initialized: false,
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
        if !self.long_packet & in_len.lt(&SFTP_MINIMUM_PACKET_LEN) {
            return Err(WireError::PacketWrong);
        }

        let mut source = SftpSource::new(buffer_in);
        trace!("Source content: {:?}", source);

        let packet_length = u32::dec(&mut source)?;
        trace!("Packet field length content: {}", packet_length);

        let mut sink = SftpSink::new(buffer_out);

        match SftpPacket::decode_request(&mut source) {
            Ok(request) => {
                info!("received request: {:?}", request);
                self.process_known_request(&mut sink, request).await?;
            }
            Err(e) => match e {
                WireError::RanOut => {
                    warn!(
                        "RanOut for the SFTP Packet in the source buffer: {:?}",
                        e
                    );
                    source.rewind(); // Not strictly required
                    let packet_total_length = source.peak_packet_len()?;
                    let packet_type = source.peak_packet_type()?;
                    match packet_type {
                        SftpNum::SSH_FXP_WRITE => {
                            self.long_packet = true;
                            let (file_handle, req_id, offset, data_len) =
                                source.peak_write_handle_offset_n_data_len()?;
                            warn!(
                                "We got a long Write packet. Excellent! total len = {:?}, type = {:?}, req_id = {:?}, handle = {:?}, offset = {:?}, data_len = {:?}",
                                packet_total_length,
                                packet_type,
                                req_id,
                                file_handle,
                                offset,
                                data_len
                            );
                        }
                        _ => {
                            error!(
                                "We do not know how to handle this long packet: {:?}",
                                packet_type
                            );
                            todo!(
                                " Push a general failure with the request ID and RanOut comment"
                            );
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
            },
        };

        Ok(sink.finalise())
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
                    Ok(handle) => {
                        let response = SftpPacket::Handle(
                            req_id,
                            proto::Handle { handle: handle.into() },
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
                    &write.handle,
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
                match self.file_server.close(&close.handle) {
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
