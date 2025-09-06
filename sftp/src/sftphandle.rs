use crate::proto::{
    InitVersionLowest, ReqId, SFTP_VERSION, SftpPacket, Status, StatusCode,
};
use crate::sftpserver::{ItemHandle, SftpServer};

use sunset::sshwire::{SSHDecode, SSHSink, SSHSource, WireError, WireResult};

use core::marker::PhantomData;
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
        SftpSink { buffer: s, index: 0 }
        // SftpSink { buffer: s, index: SftpSink::LENG_FIELD_LEN }
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
        v.iter().for_each(|val| {
            self.buffer[self.index] = *val;
            self.index += 1;
        });
        {}
        Ok(())
    }
}

#[derive(Debug)]
pub struct SftpHandler<T>
where
    T: SftpServer,
{
    server_type: PhantomData<T>,
    handle_list: Vec<ItemHandle>,
    initialized: bool,
}

impl<T> SftpHandler<T>
where
    T: SftpServer,
{
    pub fn new(buffer_in: &[u8], buffer_out: &mut [u8]) -> Self {
        SftpHandler {
            server_type: PhantomData,
            handle_list: vec![],
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
        if buffer_in.len() < 4 {
            return Err(WireError::PacketWrong);
        }

        let mut source = SftpSource { buffer: buffer_in, index: 0 };
        trace!("Source content: {:?}", source);

        let packet_length = u32::dec(&mut source)?;
        trace!("Packet field lenght content: {}", packet_length);

        let mut sink = SftpSink::new(buffer_out);

        // TODO: Handle gracesfully unknow packets
        let request = match SftpPacket::decode_request(&mut source) {
            Ok(request) => {
                info!("received request: {:?}", request);
                request
            }
            Err(e) => {
                warn!("Could not decode the request: {:?}", e);
                return Err(e);
            }
        };

        if !self.initialized && !matches!(request, SftpPacket::Init(_)) {
            return Err(WireError::SSHProto); // TODO: Start using the SFTP Errors
        }

        match request {
            SftpPacket::Init(_) => {
                // TODO: Do a real check, provide the lowest version or return an error if the client cannot handle the server SFTP_VERSION
                let version =
                    SftpPacket::Version(InitVersionLowest { version: SFTP_VERSION });

                info!("Sending '{:?}'", version);

                version.encode_response(ReqId(0), &mut sink)?;

                self.initialized = true;
            }
            SftpPacket::PathInfo(req_id, path_info) => {
                let a_name =
                    T::realpath(path_info.path.as_str().expect(
                        "Could not deref and the errors are not harmonised",
                    ))
                    .await
                    .expect("Could not deref and the errors are not harmonised");

                let response = SftpPacket::Name(req_id, a_name);

                response.encode_response(req_id, &mut sink)?;
            }
            _ => {
                let response = SftpPacket::Status(
                    ReqId(0),
                    Status {
                        code: StatusCode::SSH_FX_OP_UNSUPPORTED,
                        message: "Not implemented".into(),
                        lang: "EN".into(),
                    },
                );
                response.encode_response(ReqId(0), &mut sink)?;
            }
        };

        Ok(sink.finalise())
    }
}
