use crate::proto::SFTP_FIELD_LEN_LENGTH;

use sunset::sshwire::{SSHSink, WireError};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// A implementation fo [`SSHSink`] that observes some constraints for
/// SFTP packets
///
/// **Important**: It needs to be [`SftpSink::finalize`] to add the packet
/// len
#[derive(Default)]
pub struct SftpSink<'g> {
    pub buffer: &'g mut [u8],
    index: usize,
}

impl<'g> SftpSink<'g> {
    /// Initializes the Sink, with the particularity that it will leave
    /// [`crate::proto::SFTP_FIELD_LEN_LENGTH`] bytes empty at the
    /// start of the buffer that will contain the total packet length
    /// once the [`SftpSink::finalize`] method is called
    pub fn new(s: &'g mut [u8]) -> Self {
        SftpSink { buffer: s, index: SFTP_FIELD_LEN_LENGTH }
    }

    /// Finalise the buffer by prepending the packet length field,
    /// excluding the field itself.
    ///
    /// **Returns** the final index in the buffer as a reference of the
    /// space used
    pub fn finalize(&mut self) -> usize {
        if self.index <= SFTP_FIELD_LEN_LENGTH {
            warn!("SftpSink trying to terminate it before pushing data");
            return 0;
        } // size is 0
        let used_size = self.payload_len() as u32;

        used_size
            .to_be_bytes()
            .iter()
            .enumerate()
            .for_each(|(i, v)| self.buffer[i] = *v);

        self.index
    }

    /// Auxiliary method to allow seen the len used by the encoded payload
    pub fn payload_len(&self) -> usize {
        self.index - SFTP_FIELD_LEN_LENGTH
    }

    /// Auxiliary method to allow an immutable reference to the encoded payload
    pub fn payload_slice(&self) -> &[u8] {
        &self.buffer[SFTP_FIELD_LEN_LENGTH..self.payload_len()]
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
