use crate::{proto, sftpsource::SftpSource};

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
    /// WireError
    WireError(WireError),
    Bug,
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
#[derive(Debug)]
pub struct RequestHolder<'a> {
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
    pub fn new(buffer: &'a mut [u8]) -> Self {
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
    pub fn try_hold(&mut self, slice: &[u8]) -> RequestHolderResult<usize> {
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
    /// Will not clear the previous data from the buffer.
    pub fn reset(&mut self) -> () {
        self.busy = false;
        self.buffer_fill_index = 0;
        self.appended = 0;
    }

    /// Using the content of the `RequestHolder` tries to find a valid
    /// SFTP request appending from slice into the internal buffer to
    /// form a valid request.
    ///
    /// Reset and increase the `appended()` counter.
    ///
    /// **Returns**:
    ///
    /// - `Ok(())`: Full valid request
    ///
    /// - `Err(RanOut)`: Not enough bytes in the slice to complete a valid request or fill the buffer
    ///
    /// - `Err(NoRoom)`: The internal buffer is full but there is not a full valid request in the buffer
    ///
    /// - `Err(Empty)`: If the structure has not been loaded with `try_hold`
    ///
    /// - `Err(Bug)`: An unexpected condition arises
    pub fn try_append_for_valid_request(
        &mut self,
        slice: &[u8],
    ) -> RequestHolderResult<()> {
        debug!(
            "try_append_for_valid_request: self = {:?}\n\
            Space left = {:?}\n\
            Length of slice to append from = {:?}",
            self,
            self.remaining_len(),
            slice.len()
        );

        if !self.busy {
            error!("Request Holder is not busy");
            return Err(RequestHolderError::Empty);
        }

        if self.is_full() {
            error!("Request Holder is full");
            return Err(RequestHolderError::NoRoom);
        }

        self.appended = 0; // reset appended bytes counter

        // If we will not be able to read the SFTP packet ID we clearly need more data
        if self.buffer_fill_index + slice.len() < proto::SFTP_FIELD_ID_INDEX {
            self.try_append_slice(&slice)?;
            error!(
                "[Buffer fill index = {:?}] + [slice.len = {:?}] = {:?} < SFTP field id index = {:?}",
                self.buffer_fill_index,
                slice.len(),
                self.buffer_fill_index + slice.len(),
                proto::SFTP_FIELD_ID_INDEX
            );
            return Err(RequestHolderError::RanOut);
        }

        let complete_to_id_index = (proto::SFTP_FIELD_ID_INDEX + 1)
            .checked_sub(self.buffer_fill_index)
            .unwrap_or(0);

        if complete_to_id_index > 0 {
            warn!(
                "The held fragment len = {:?}, is insufficient to peak \
                the length and type. Will append {:?} to reach the \
                id field index: {:?}",
                self.buffer_fill_index,
                complete_to_id_index,
                proto::SFTP_FIELD_ID_INDEX
            );
            if complete_to_id_index > slice.len() {
                self.try_append_slice(&slice)?;
                error!(
                    "The slice to include to the held fragment is too \
                short to complete to id index. More data is required."
                );
                return Err(RequestHolderError::RanOut);
            } else {
                self.try_append_slice(&slice[..complete_to_id_index])?;
            };
        }

        let (packet_len, packet_type) = {
            let temp_source = SftpSource::new(self.try_get_ref()?);
            let packet_len = temp_source.peak_packet_len()? as usize;
            let packet_type = temp_source.peak_packet_type()?;
            (packet_len, packet_type)
        };
        debug!("Request len = {:?}, type = {:?}", packet_len, packet_type);

        let remaining_packet_len =
            packet_len - (self.buffer_fill_index - proto::SFTP_FIELD_LEN_LENGTH);
        // The packet len does not include the packet len field itself (4 bytes)
        // https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-3
        debug!(
            "[Total Packet len = {:?}] = [Packet len copied so far = {:}] \
            - [SFTP Field len length = {:?}] + [Remaining packet len = {:?}]",
            packet_len,
            self.buffer_fill_index,
            proto::SFTP_FIELD_LEN_LENGTH,
            remaining_packet_len,
        );
        assert_eq!(
            packet_len,
            self.buffer_fill_index - proto::SFTP_FIELD_LEN_LENGTH
                + remaining_packet_len
        );
        // TODO: Fix the mess with the logic and the indexes to address the slice. IT IS PANICKING
        if remaining_packet_len <= self.remaining_len() {
            // We have all the remaining packet bytes in the slice and fits in the buffer

            if (slice.len()) < (remaining_packet_len + self.appended()) {
                self.try_append_slice(&slice[self.appended()..])?;
                return Err(RequestHolderError::RanOut);
            } else {
                self.try_append_slice(
                    &slice[self.appended()..remaining_packet_len],
                )?;
                return Ok(());
            }
        } else {
            // the remaining packet bytes are more than we can fit in the buffer
            // But they may not fit in the slice neither

            let start = self.appended();
            let end = self.remaining_len().min(slice.len() - self.appended());

            debug!(
                "Will finally take the range: [{:?}..{:?}] from the slice [0..{:?}]",
                start,
                end,
                slice.len()
            );
            self.try_append_slice(
                &slice[self.appended()
                    ..self.remaining_len().min(slice.len() - self.appended())],
            )?;
            if self.is_full() {
                return Err(RequestHolderError::NoRoom);
            } else {
                return Err(RequestHolderError::RanOut);
            }
        }
    }

    /// Gets a reference to the slice that it is holding
    pub fn try_get_ref(&self) -> RequestHolderResult<&[u8]> {
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

    pub fn is_full(&mut self) -> bool {
        self.buffer_fill_index == self.buffer.len()
    }

    #[allow(unused)]
    /// Returns true if it has a slice in its buffer
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Returns the bytes appened in the last call to `try_append_for_valid_request`
    pub fn appended(&self) -> usize {
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
        // self.buffer.len() - self.buffer_fill_index - 1 // TODO: Off by one?
        self.buffer.len() - self.buffer_fill_index
    }
}
