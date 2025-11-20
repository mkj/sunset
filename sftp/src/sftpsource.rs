use crate::error::{SftpError, SftpResult};
use crate::handles::OpaqueFileHandle;
use crate::proto::{
    ReqId, SFTP_FIELD_ID_INDEX, SFTP_FIELD_LEN_INDEX, SFTP_FIELD_LEN_LENGTH,
    SFTP_FIELD_REQ_ID_INDEX, SFTP_FIELD_REQ_ID_LEN, SFTP_MINIMUM_PACKET_LEN,
    SFTP_WRITE_REQID_INDEX, SftpNum,
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
    /// the result will contains garbage
    pub(crate) fn peak_packet_type(&self) -> WireResult<SftpNum> {
        if self.buffer.len() <= SFTP_FIELD_ID_INDEX {
            debug!(
                "Peak packet type failed: buffer len <= SFTP_FIELD_ID_INDEX ( {:?} <= {:?})",
                self.buffer.len(),
                SFTP_FIELD_ID_INDEX
            );
            Err(WireError::RanOut)
        } else {
            Ok(SftpNum::from(self.buffer[SFTP_FIELD_ID_INDEX]))
        }
    }

    /// Peaks the buffer for packet length field. This does not advance the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a `dec(s)`
    /// would fail
    ///
    /// Use `peak_total_packet_len` instead if you want to also consider the the
    /// length field
    ///
    /// **Warning**: will only work in well formed packets, in other case the result
    /// will contains garbage
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

    /// Peaks the packet in the source to obtain a total packet length, which
    /// considers the length of the length field itself. For the packet length field
    /// use [`peak_packet_len()`]
    ///
    ///  This does not advance the reading index
    ///
    /// This does not consider the length field itself
    /// Useful to observe the packet fields in special conditions where a `dec(s)`
    /// would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case the result
    /// will contains garbage
    pub(crate) fn peak_total_packet_len(&self) -> WireResult<u32> {
        Ok(self.peak_packet_len()? + SFTP_FIELD_LEN_LENGTH as u32)
    }

    // TODO: Test This for correctness
    /// Compares the total source capacity and the peaked packet length
    /// plus the length field length itself to find out if the packet fit
    /// in the source  
    /// **Warning**: will only work in well formed packets, in other case
    /// the result will contains garbage
    pub fn packet_fits(&self) -> WireResult<bool> {
        Ok(self.buffer.len() >= self.peak_total_packet_len()? as usize)
    }

    /// Assuming that the buffer contains a [`proto::Write`] request packet initial
    /// bytes and not its totality:
    ///
    /// **Returns**:
    ///
    /// - An [`OpaqueFileHandle`] to guide the Write operation,
    /// - Request ID as [`ReqId`],
    /// - Offset as [`u64`]
    /// - Data in the buffer as [`BinString`]
    /// - [`PartialWriteRequestTracker`] to handle subsequent portions of the request
    ///
    /// **Warning**: will only work in well formed write packets, in other case
    /// the result will contains garbage
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

    pub fn peak_packet_req_id(&self) -> WireResult<u32> {
        if self.buffer.len() < SFTP_FIELD_REQ_ID_INDEX + SFTP_FIELD_REQ_ID_LEN {
            Err(WireError::RanOut)
        } else {
            let bytes: [u8; 4] = self.buffer[SFTP_FIELD_REQ_ID_INDEX
                ..SFTP_FIELD_REQ_ID_INDEX + SFTP_FIELD_LEN_LENGTH]
                .try_into()
                .expect("slice length mismatch");

            Ok(u32::from_be_bytes(bytes))
        }
    }

    /// Discards the first elements of the  
    pub fn consume_first(&mut self, len: usize) -> WireResult<()> {
        if len > self.buffer.len() {
            Err(WireError::RanOut)
        } else {
            self.index = len;
            Ok(())
        }
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;

    fn status_buffer() -> [u8; 27] {
        let expected_status_packet_slice: [u8; 27] = [
            0, 0, 0, 23,  //                            Packet len
            101, //                                     Packet type
            0, 0, 0, 16, //                             ReqId
            0, 0, 0, 1, //                              Status code: SSH_FX_EOF
            0, 0, 0, 1,  //                             string message length
            65, //                                      string message content
            0, 0, 0, 5, //                              string lang length
            101, 110, 45, 85, 83, //                    string lang content
        ];
        expected_status_packet_slice
    }

    #[test]
    fn peaking_len() {
        let buffer_status = status_buffer();
        let sink = SftpSource::new(&buffer_status);

        let read_packet_len = sink.peak_packet_len().unwrap();
        let original_packet_len = 23u32;
        assert_eq!(original_packet_len, read_packet_len);
    }
    #[test]
    fn peaking_total_len() {
        let buffer_status = status_buffer();
        let sink = SftpSource::new(&buffer_status);

        let read_total_packet_len = sink.peak_total_packet_len().unwrap();
        let original_total_packet_len = 23u32 + 4u32;
        assert_eq!(original_total_packet_len, read_total_packet_len);
    }

    #[test]
    fn peaking_type() {
        let buffer_status = status_buffer();
        let sink = SftpSource::new(&buffer_status);
        let read_packet_type = sink.peak_packet_type().unwrap();
        let original_packet_type = SftpNum::from(101u8);
        assert_eq!(original_packet_type, read_packet_type);
    }
    #[test]
    fn peaking_req_id() {
        let buffer_status = status_buffer();
        let sink = SftpSource::new(&buffer_status);
        let read_req_id = sink.peak_packet_req_id().unwrap();
        let original_req_id = 16u32;
        assert_eq!(original_req_id, read_req_id);
    }

    #[test]
    fn packet_does_fit() {
        let buffer_status = status_buffer();
        let sink = SftpSource::new(&buffer_status);
        assert_eq!(true, sink.packet_fits().unwrap());
    }

    #[test]
    fn packet_does_not_fit() {
        let buffer_status = status_buffer();
        let no_room_buffer = &buffer_status[..buffer_status.len() - 2];
        let sink = SftpSource::new(no_room_buffer);
        assert_eq!(false, sink.packet_fits().unwrap());
    }
}
