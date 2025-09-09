use crate::proto::{
    self, FileHandle, InitVersionLowest, ReqId, SFTP_VERSION, SftpPacket, Status,
    StatusCode,
};
use crate::sftpserver::SftpServer;

use sunset::sshwire::{SSHDecode, SSHSink, SSHSource, WireError, WireResult};

use core::u32;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

#[derive(Default, Debug)]
pub struct SftpSource<'de> {
    pub buffer: &'de [u8],
    pub index: usize,
}

impl<'de> SSHSource<'de> for SftpSource<'de> {
    fn take(&mut self, len: usize) -> sunset::sshwire::WireResult<&'de [u8]> {
        if len + self.index > self.buffer.len() {
            return Err(WireError::NoRoom);
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

// // This implementation is an extension of the SSHSource interface.
// impl<'de> SftpSource<'de> {
//     /// Rewinds the index back to the initial byte
//     ///
//     /// In case of an error deserialising the SSHSource it allows reprocesing the buffer from start
//     pub fn rewind(&mut self) -> () {
//         self.index = 0;
//     }
// }

#[derive(Default)]
pub struct SftpSink<'g> {
    pub buffer: &'g mut [u8],
    index: usize,
}

impl<'g> SftpSink<'g> {
    const LENG_FIELD_LEN: usize = 4; // TODO: Move it to a better location

    pub fn new(s: &'g mut [u8]) -> Self {
        SftpSink { buffer: s, index: Self::LENG_FIELD_LEN }
    }

    /// Finalise the buffer by prepending the payload size and returning
    ///
    /// Returns the final index in the buffer as a reference for the space used
    pub fn finalise(&mut self) -> usize {
        if self.index <= SftpSink::LENG_FIELD_LEN {
            warn!("SftpSink trying to terminate it before pushing data");
            return 0;
        } // size is 0
        let used_size = (self.index - 4) as u32;

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
    initialized: bool,
}

impl<'a> SftpHandler<'a> {
    pub fn new(
        file_server: &'a mut impl SftpServer<'a>,
        // max_file_handlers: u32
    ) -> Self {
        SftpHandler { file_server, initialized: false }
    }

    /// Decodes the buffer_in request, process the request delegating operations to an Struct implementing SftpServer,
    /// serialises an answer in buffer_out and return the length usedd in buffer_out
    pub async fn process(
        &mut self,
        buffer_in: &[u8],
        buffer_out: &mut [u8],
    ) -> WireResult<usize> {
        if buffer_in.len() < 4 {
            return Err(WireError::PacketWrong);
        }

        let mut source = SftpSource { buffer: buffer_in, index: 0 };
        trace!("Source content: {:?}", source);

        let packet_length = u32::dec(&mut source)?;
        trace!("Packet field lenght content: {}", packet_length);

        let mut sink = SftpSink::new(buffer_out);

        match SftpPacket::decode_request(&mut source) {
            Ok(request) => {
                info!("received request: {:?}", request);
                self.process_known_request(&mut sink, request).await?;
            }
            Err(e) => match e {
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
