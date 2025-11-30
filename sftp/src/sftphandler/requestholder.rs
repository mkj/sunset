use crate::{
    proto::{SftpNum, SftpPacket},
    sftpsource::SftpSource,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use sunset::sshwire::WireError;

#[derive(Debug)]
pub enum RequestHolderError {
    /// The slice to hold is too long
    NoRoom,
    /// The slice holder is keeping a slice already. Consideer cleaning
    Busy,
    /// The slice holder is empty
    Empty,
    /// There is not enough data in the slice we are trying to add. we need more data
    RanOut,
    /// The Packet held is not a request
    NotRequest,
    /// WireError
    WireError(WireError),
}

impl From<WireError> for RequestHolderError {
    fn from(value: WireError) -> Self {
        RequestHolderError::WireError(value)
    }
}

pub(crate) type RequestHolderResult<T> = Result<T, RequestHolderError>;

/// Helper struct to manage short fragmented requests that have been
/// received in consecutive read operations
///
/// For requests exceeding the length of buffers other techniques, such
/// as composing them into multiple request, might help reducing the
/// required buffer sizes. This is recommended for restricted environments.
///
/// The intended use for this RequestHolder is (in order):
/// - `new`: Initialize the struct with a slice that will keep the
/// request in memory
///
/// - `try_hold`: load the data for an incomplete request
///
/// - `try_append_for_valid_request`: append more data from another
/// slice to complete the request
///
/// - `try_get_ref`: returns a reference to the portion of the slice
/// containing a request
///
/// - `reset`: reset counters and flags to allow `try_hold` a new request
///
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RequestHolder<'a> {
    /// The buffer used to contain the data for the request
    buffer: &'a mut [u8],
    /// The index of the last byte in the buffer containing usable data
    buffer_fill_index: usize,
    /// Number of bytes appended in a previous `try_hold` or `try_append_for_valid_request` slice
    appended: usize,
    /// Used to mark when the structure is holding data
    busy: bool,
}

impl<'a> RequestHolder<'a> {
    /// The buffer will be used to hold a full request. Choose a
    /// reasonable size for this buffer.
    pub(crate) fn new(buffer: &'a mut [u8]) -> Self {
        RequestHolder {
            buffer: buffer,
            buffer_fill_index: 0,
            busy: false,
            appended: 0,
        }
    }

    /// Uses the internal buffer to store a copy of the provided slice
    ///
    /// The definition of `try_hold` and `try_append_slice` separately
    /// is deliberated to follow an order in composing the held request
    ///
    /// Increases the `appended()` counter
    ///
    /// returns:
    ///
    /// - Ok(usize): the number of bytes read from the slice
    ///
    /// - `Err(Busy)`: If there has been a call to `try_hold` without a call to `reset`
    pub(crate) fn try_hold(&mut self, slice: &[u8]) -> RequestHolderResult<usize> {
        if self.busy {
            return Err(RequestHolderError::Busy);
        }

        self.busy = true;
        self.try_append_slice(slice)?;
        let read_in = self.appended();
        self.appended = 0;
        Ok(read_in)
    }

    /// Resets the structure allowing it to hold a new request.
    ///
    /// Resets the `appended()` counter.
    ///
    /// Will **clear** the previous data from the buffer.
    pub(crate) fn reset(&mut self) -> () {
        self.busy = false;
        self.buffer_fill_index = 0;
        self.appended = 0;
        self.buffer.fill(0);
    }

    /// Appends a byte at a time to the internal buffer and tries to
    /// decode a request
    ///
    /// Reset and increase the `appended()` counter.
    ///
    /// **Returns**:
    ///
    /// - `Ok(())`: A valid request is held now
    ///
    /// - `Err(NotRequest)`: The decoded packet is not a request
    ///
    /// - `Err(RanOut)`: Not enough bytes in the slice to add a single byte
    ///
    /// - `Err(NoRoom)`: The internal buffer is full
    ///
    /// - `Err(Empty)`: If the structure has not been loaded with `try_hold`
    ///
    pub(crate) fn try_appending_for_valid_request(
        &mut self,
        slice_in: &[u8],
    ) -> RequestHolderResult<SftpNum> {
        debug!(
            "try_appending_for_valid_request: self = {:?}\n\
            Space left = {:?}\n\
            Length of slice to append from = {:?}",
            self,
            self.remaining_len(),
            slice_in.len()
        );

        if !self.busy {
            error!("Request Holder is not busy");
            return Err(RequestHolderError::Empty);
        }

        self.appended = 0; // reset appended bytes counter. Try_append_slice will increase it

        if self.is_full() {
            error!("Request Holder is full");
            return Err(RequestHolderError::NoRoom);
        }

        if let Some(request) = self.valid_request() {
            debug!("The request holder already contained a valid request");
            return Ok(request.sftp_num());
        }

        let mut slice = slice_in;
        loop {
            debug!(
                "try_appending_for_valid_request: Slice length {:?}",
                slice.len()
            );
            if slice.len() > 0 {
                self.try_append_slice(&[slice[0]])?;
                slice = &slice[1..];
                let mut source = SftpSource::new(self.try_get_ref()?);
                if let Ok(pt) = source.peak_packet_type() {
                    if !pt.is_request() {
                        error!("The request candidate is not a request: {pt:?}");
                        return Err(RequestHolderError::NotRequest);
                    }
                } else {
                    continue;
                };
                match SftpPacket::decode_request(&mut source) {
                    Ok(request) => {
                        debug!("Request is {:?}", request);
                        return Ok(request.sftp_num());
                    }
                    Err(WireError::RanOut) => {
                        if slice.len() == 0 {
                            return Err(RequestHolderError::RanOut);
                        }
                    }
                    Err(WireError::NoRoom) => {
                        return Err(RequestHolderError::NoRoom);
                    }
                    Err(WireError::PacketWrong) => {
                        return Err(RequestHolderError::NotRequest);
                    }
                    Err(e) => return Err(RequestHolderError::WireError(e)),
                }
            } else {
                return Err(RequestHolderError::RanOut);
            }
        }
    }

    pub(crate) fn valid_request(&self) -> Option<SftpPacket<'_>> {
        if !self.busy {
            return None;
        }
        let mut source = SftpSource::new(self.try_get_ref().unwrap_or(&[0]));
        match SftpPacket::decode_request(&mut source) {
            Ok(request) => {
                return Some(request);
            }
            Err(..) => return None,
        }
    }

    /// Gets a reference to the slice that it is holding
    pub(crate) fn try_get_ref(&self) -> RequestHolderResult<&[u8]> {
        if self.busy {
            debug!(
                "Returning reference to: {:?}",
                &self.buffer[..self.buffer_fill_index]
            );
            Ok(&self.buffer[..self.buffer_fill_index])
        } else {
            Err(RequestHolderError::Empty)
        }
    }

    pub(crate) fn is_full(&mut self) -> bool {
        self.buffer_fill_index == self.buffer.len()
    }

    #[allow(unused)]
    /// Returns true if it has a slice in its buffer
    pub(crate) fn is_busy(&self) -> bool {
        self.busy
    }

    /// Returns the bytes appened in the last call to
    /// [`RequestHolder::try_append_for_valid_request`] or
    /// [`RequestHolder::try_append_for_valid_header`] or
    /// [`RequestHolder::try_append_slice`] or
    /// [`RequestHolder::try_appending_single_byte`]  
    pub(crate) fn appended(&self) -> usize {
        self.appended
    }

    /// Appends a slice to the internal buffer. Requires the buffer to
    /// be busy by using `try_hold` first
    ///
    /// Increases the `appended` counter but does not reset it
    ///
    /// Returns:
    ///
    /// - `Ok(())`: the slice was appended
    ///
    /// - `Err(Empty)`: If the structure has not been loaded with `try_hold`
    ///
    /// - `Err(NoRoom)`: The internal buffer is full but there is not a full valid request in the buffer
    fn try_append_slice(&mut self, slice: &[u8]) -> RequestHolderResult<()> {
        if slice.len() == 0 {
            warn!("try appending a zero length slice");
            return Ok(());
        }
        if !self.busy {
            return Err(RequestHolderError::Empty);
        }

        let in_len = slice.len();
        if in_len > self.remaining_len() {
            return Err(RequestHolderError::NoRoom);
        }
        debug!("Adding: {:?}", slice);

        self.buffer[self.buffer_fill_index..self.buffer_fill_index + in_len]
            .copy_from_slice(slice);

        self.buffer_fill_index += in_len;
        debug!(
            "RequestHolder: index = {:?}, slice = {:?}",
            self.buffer_fill_index,
            self.try_get_ref()?
        );
        self.appended += in_len;
        Ok(())
    }

    /// Returns the number of bytes unused at the end of the buffer,
    /// this is, the remaining length
    fn remaining_len(&self) -> usize {
        self.buffer.len() - self.buffer_fill_index
    }
}

#[cfg(test)]
mod local_test {
    use super::*;
    // use crate::requestholder::RequestHolder;

    #[cfg(test)]
    extern crate std;
    #[cfg(test)]
    use std::println;

    fn get_buffer_with_valid_request() -> [u8; 85] {
        [
            0, 0, 128, 25, 6, 0, 0, 0, 23, 0, 0, 0, 4, 249, 67, 81, 122, 0, 0, 0, 0,
            0, 9, 128, 0, 0, 0, 128, 0, 116, 101, 115, 116, 105, 110, 103, 47, 111,
            117, 116, 47, 49, 48, 48, 77, 66, 95, 114, 97, 110, 100, 111, 109, 0, 0,
            0, 26, 0, 0, 0, 4, 0, 0, 1, 164, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]
    }
    #[test]
    fn valid_request_uses_filled_data() {
        let mut clean_buffer = [0u8; 256];
        let buff_data = get_buffer_with_valid_request();

        let mut rh = RequestHolder::new(&mut clean_buffer);
        rh.try_hold(&buff_data).unwrap();
        assert!(rh.valid_request().is_some());

        rh.reset();
        assert!(rh.valid_request().is_none());

        rh.try_hold(&buff_data[..5]).unwrap();
        assert!(rh.valid_request().is_none());
    }

    #[test]
    fn try_appending_for_valid_request_uses_filled_data() {
        let mut clean_buffer = [0u8; 256];
        let buff_data = get_buffer_with_valid_request();

        let mut rh = RequestHolder::new(&mut clean_buffer);
        rh.try_hold(&buff_data).unwrap();
        assert!(rh.valid_request().is_some());

        rh.reset();
        assert!(rh.valid_request().is_none());

        rh.try_hold(&buff_data[..5]).unwrap();
        assert!(rh.try_appending_for_valid_request(&buff_data[5..10]).is_err());
    }

    #[test]
    fn try_appending_for_valid_request_works() {
        let mut clean_buffer = [0u8; 256];
        let buff_data = get_buffer_with_valid_request();
        println!("{buff_data:?}");

        let mut rh = RequestHolder::new(&mut clean_buffer);
        rh.try_hold(&buff_data).unwrap();
        assert!(rh.valid_request().is_some());

        rh.reset();
        assert!(rh.valid_request().is_none());

        rh.try_hold(&buff_data[..5]).unwrap();
        println!("before appending{rh:?}");
        let appending = rh.try_appending_for_valid_request(&buff_data[5..]);
        // println!("{appending:?}",);
        println!("after appending {rh:?}");
        assert!(appending.is_ok());
    }
}
