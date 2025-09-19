use crate::proto::{
    ReqId, SFTP_FIELD_ID_INDEX, SFTP_MINIMUM_PACKET_LEN, SFTP_WRITE_REQID_INDEX,
    SftpNum,
};
use crate::sftphandle::PartialWriteRequestTracker;
use crate::{FileHandle, OpaqueFileHandle};

use sunset::sshwire::{BinString, SSHDecode, SSHSource, WireError, WireResult};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

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
    pub(crate) fn peak_packet_type(&self) -> WireResult<SftpNum> {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            Ok(SftpNum::from(self.buffer[SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Peaks the buffer for packet type adding an offset. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: This might only work in special conditions, such as those where the , in other case the result will contain garbage
    pub(crate) fn peak_packet_type_with_offset(
        &self,
        starting_offset: usize,
    ) -> WireResult<SftpNum> {
        // const SFTP_ID_BUFFER_INDEX: usize = 4; // All SFTP packet have the packet type after a u32 length field
        // const SFTP_MINIMUM_LENGTH: usize = 9; // Corresponds to a minimal SSH_FXP_INIT packet
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            Ok(SftpNum::from(self.buffer[starting_offset + SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Assuming that the buffer contains a Write request packet initial bytes, Peaks the buffer for the handle length. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed write packets, in other case the result will contain garbage
    pub(crate) fn get_packet_partial_write_content_and_tracker<
        T: OpaqueFileHandle,
    >(
        &mut self,
    ) -> WireResult<(T, ReqId, u64, BinString<'de>, PartialWriteRequestTracker<T>)>
    {
        if self.buffer.len() < SFTP_MINIMUM_PACKET_LEN {
            Err(WireError::PacketWrong)
        } else {
            let prev_index = self.index;
            self.index = SFTP_WRITE_REQID_INDEX;
            let req_id = ReqId::dec(self)?;
            let file_handle = FileHandle::dec(self)?;

            let obscured_file_handle = OpaqueFileHandle::try_from(&file_handle)?;
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
                OpaqueFileHandle::try_from(&file_handle)?,
                remain_data_len,
                remain_data_offset,
            )?;

            Ok((obscured_file_handle, req_id, offset, data_in_buffer, write_tracker))
        }
    }

    /// Used to decode the whole SSHSource as a single BinString ignoring the len field
    ///
    /// It will not use the first four bytes as u32 for length, instead it will use the length of the data received and use it to set the length of the returned BinString.
    pub(crate) fn dec_all_as_binstring(&mut self) -> WireResult<BinString<'_>> {
        Ok(BinString(self.take(self.buffer.len())?))
    }

    /// Used to decode a slice of SSHSource as a single BinString ignoring the len field
    ///
    /// It will not use the first four bytes as u32 for length, instead it will use the length of the data received and use it to set the length of the returned BinString.
    pub(crate) fn dec_as_binstring(
        &mut self,
        len: usize,
    ) -> WireResult<BinString<'_>> {
        Ok(BinString(self.take(len)?))
    }
}
