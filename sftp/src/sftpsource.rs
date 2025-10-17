use crate::error::{SftpError, SftpResult};
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    ReqId, SFTP_FIELD_ID_INDEX, SFTP_FIELD_LEN_INDEX, SFTP_FIELD_LEN_LENGTH,
    SFTP_MINIMUM_PACKET_LEN, SFTP_WRITE_REQID_INDEX, SftpNum,
};
use crate::protocol::FileHandle;
use crate::sftphandler::PartialWriteRequestTracker;

use sunset::sshwire::{BinString, SSHDecode, SSHSource, WireError, WireResult};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// SftpSource implements [`SSHSource`] and also extra functions to handle
/// some challenges related to long SFTP packets in constrained environments
#[derive(Default, Debug)]
pub struct SftpSource<'de> {
    buffer: &'de [u8],
    index: usize,
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
        todo!("Which context for sftp?");
    }
}

impl<'de> SftpSource<'de> {
    /// Creates a new [`SftpSource`] referencing a buffer
    pub fn new(buffer: &'de [u8]) -> Self {
        debug!("New source with content: : {:?}", buffer);
        SftpSource { buffer: buffer, index: 0 }
    }

    /// Peaks the buffer for packet type [`SftpNum`]. This does not advance
    /// the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a
    /// `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case
    /// the result will contain garbage
    pub(crate) fn peak_packet_type(&self) -> WireResult<SftpNum> {
        if self.buffer.len() < SFTP_FIELD_ID_INDEX + 1 {
            Err(WireError::RanOut)
        } else {
            Ok(SftpNum::from(self.buffer[SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Peaks the buffer for packet length. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)`
    /// would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case the result
    /// will contain garbage
    pub(crate) fn peak_packet_len(&self) -> WireResult<u32> {
        if self.buffer.len() < SFTP_FIELD_LEN_INDEX + SFTP_FIELD_LEN_LENGTH {
            Err(WireError::RanOut)
        } else {
            let bytes: [u8; 4] = self.buffer
                [SFTP_FIELD_LEN_INDEX..SFTP_FIELD_LEN_INDEX + SFTP_FIELD_LEN_LENGTH]
                .try_into()
                .expect("slice length mismatch");

            Ok(u32::from_be_bytes(bytes))
        }
    }

    /// Assuming that the buffer contains a [`proto::Write`] request packet initial
    /// bytes and not its totality, extracts a partial version of the write request
    /// and a Write request tracker to handle and a tracker to continue processing
    /// subsequent portions of the request from a SftpSource
    ///
    /// **Warning**: will only work in well formed write packets, in other case
    /// the result will contain garbage
    pub(crate) fn dec_packet_partial_write_content_and_get_tracker<
        T: OpaqueFileHandle,
    >(
        &mut self,
    ) -> SftpResult<(T, ReqId, u64, BinString<'de>, PartialWriteRequestTracker<T>)>
    {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            return Err(WireError::RanOut.into());
        }

        match self.peak_packet_type()? {
            SftpNum::SSH_FXP_WRITE => {}
            _ => return Err(SftpError::NotSupported),
        };

        self.index = SFTP_WRITE_REQID_INDEX;
        let req_id = ReqId::dec(self)?;
        let file_handle = FileHandle::dec(self)?;

        let offset = u64::dec(self)?;
        let data_len = u32::dec(self)?;

        let data_len_in_buffer = self.buffer.len() - self.index;
        let data_in_buffer = BinString(self.take(data_len_in_buffer)?);

        let remain_data_len = data_len - data_len_in_buffer as u32;
        let remain_data_offset = offset + data_len_in_buffer as u64;
        trace!(
            "Request ID = {:?}, Handle = {:?}, offset = {:?}, data length in buffer = {:?}, data in current buffer {:?} ",
            req_id, file_handle, offset, data_len_in_buffer, data_in_buffer
        );

        let write_tracker = PartialWriteRequestTracker::new(
            req_id,
            OpaqueFileHandle::try_from(&file_handle)?,
            remain_data_len,
            remain_data_offset,
        )?;

        let obscured_file_handle = OpaqueFileHandle::try_from(&file_handle)?;
        Ok((obscured_file_handle, req_id, offset, data_in_buffer, write_tracker))
    }

    /// Used to decode a slice of [`SSHSource`] as a single BinString
    ///
    /// It will not use the first four bytes as u32 for length, instead
    /// it will use the length of the data received and use it to set the
    /// length of the returned BinString.
    pub(crate) fn dec_as_binstring(
        &mut self,
        len: usize,
    ) -> WireResult<BinString<'_>> {
        Ok(BinString(self.take(len)?))
    }
}
