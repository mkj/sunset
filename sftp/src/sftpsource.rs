use crate::proto::{
    SFTP_FIELD_ID_INDEX, SFTP_FIELD_LEN_INDEX, SFTP_FIELD_LEN_LENGTH,
    SFTP_FIELD_REQ_ID_INDEX, SFTP_FIELD_REQ_ID_LEN, SftpNum,
};

use sunset::sshwire::{SSHSource, WireError, WireResult};

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
    pub fn packet_fits(&self) -> bool {
        match self.peak_total_packet_len() {
            Ok(len) => self.buffer.len() >= len as usize,
            Err(_) => false,
        }
    }

    /// Peaks the buffer for packet request id [`u32`]. This does not advance
    /// the reading index
    ///
    /// Useful to observe the packet fields in special conditions where a
    /// `dec(s)` would fail
    ///
    /// **Warning**: will only work in well formed packets, in other case
    /// the result will contains garbage
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

    pub fn buffer_used(&self) -> &[u8] {
        &self.buffer[..self.index]
    }

    /// returns a slice on the held buffer and makes it unavailable for further  
    /// decodes.
    pub fn consume_all(&mut self) -> &[u8] {
        self.index = self.buffer.len();
        self.buffer
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
        let source = SftpSource::new(&buffer_status);

        let read_packet_len = source.peak_packet_len().unwrap();
        let original_packet_len = 23u32;
        assert_eq!(original_packet_len, read_packet_len);
    }
    #[test]
    fn peaking_total_len() {
        let buffer_status = status_buffer();
        let source = SftpSource::new(&buffer_status);

        let read_total_packet_len = source.peak_total_packet_len().unwrap();
        let original_total_packet_len = 23u32 + 4u32;
        assert_eq!(original_total_packet_len, read_total_packet_len);
    }

    #[test]
    fn peaking_type() {
        let buffer_status = status_buffer();
        let source = SftpSource::new(&buffer_status);
        let read_packet_type = source.peak_packet_type().unwrap();
        let original_packet_type = SftpNum::from(101u8);
        assert_eq!(original_packet_type, read_packet_type);
    }
    #[test]
    fn peaking_req_id() {
        let buffer_status = status_buffer();
        let source = SftpSource::new(&buffer_status);
        let read_req_id = source.peak_packet_req_id().unwrap();
        let original_req_id = 16u32;
        assert_eq!(original_req_id, read_req_id);
    }

    #[test]
    fn packet_does_fit() {
        let buffer_status = status_buffer();
        let source = SftpSource::new(&buffer_status);
        assert_eq!(true, source.packet_fits());
    }

    #[test]
    fn packet_does_not_fit() {
        let buffer_status = status_buffer();
        let no_room_buffer = &buffer_status[..buffer_status.len() - 2];
        let source = SftpSource::new(no_room_buffer);
        assert_eq!(false, source.packet_fits());
    }

    #[test]
    fn consume_all_remaining() {
        let inc_array: [u8; 512] = core::array::from_fn(|i| (i % 255) as u8);
        let mut source = SftpSource::new(&inc_array);
        let _consumed = source.consume_all();
        assert_eq!(0usize, source.remaining());
    }

    #[test]
    fn consume_all_consumed() {
        let inc_array: [u8; 512] = core::array::from_fn(|i| (i % 255) as u8);
        let mut source = SftpSource::new(&inc_array);
        let consumed = source.consume_all();
        assert_eq!(inc_array.len(), consumed.len());
    }
}
