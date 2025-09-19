use crate::proto::SFTP_FIELD_LEN_LENGTH;

use sunset::sshwire::{SSHSink, WireError};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

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
