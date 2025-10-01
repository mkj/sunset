use crate::{proto, sftperror, sftpsource::SftpSource};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use sunset::sshwire::WireError;

#[derive(Debug)]
pub(crate) enum RequestHolderError {
    /// The slice to hold is too long
    NoRoom,
    /// The slice holder is keeping a slice already. Consideer cleaning
    Busy,
    /// The slice holder is empty
    Empty,
    /// The instance has been invalidated
    Invalid,
    /// There is not enough data in the slice we are trying to add. we need more data
    RanOut,
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
/// - **OR** `invalidate`: return the reference to the slice provided in `new`
/// and mark the structure as invalid. At this point it should be disposed
#[derive(Debug)]
pub struct RequestHolder<'a> {
    /// The buffer used to contain the data for the request
    buffer: &'a mut [u8],
    /// The index of the last byte in the buffer containing usable data
    buffer_fill_index: usize,
    /// Number of bytes appended to foundational `try_hold` slice
    appended: usize,
    /// Marks the structure as invalid
    invalid: bool,
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
            invalid: false,
            busy: false,
            appended: 0,
        }
    }

    /// Resets the structure allowing it to hold a new request.
    ///
    /// Will not remove the previous data from the buffer
    pub fn reset(&mut self) -> () {
        self.busy = false;
        self.invalid = false;
        self.buffer_fill_index = 0;
        self.appended = 0;
    }

    /// Invalidates the current instance and returns its original buffer. Does not erase previous data
    pub fn invalidate(&mut self) -> RequestHolderResult<&[u8]> {
        if !self.busy {
            return Err(RequestHolderError::Empty);
        }
        if self.invalid {
            return Err(RequestHolderError::Invalid);
        }

        self.invalid = true;
        // self.buffer_fill_index = 0;
        Ok(&self.buffer)
    }

    /// Uses the internal buffer to store a copy of the provided slice
    ///
    /// The definition of `try_hold` and `try_append_slice` separately
    /// is deliberated to follow an order in composing the held request
    ///
    /// returns the number of bytes read from the slice
    pub fn try_hold(&mut self, slice: &[u8]) -> RequestHolderResult<usize> {
        if self.busy {
            return Err(RequestHolderError::Busy);
        }
        if self.invalid {
            return Err(RequestHolderError::Invalid);
        }

        self.busy = true;
        self.try_append_slice(slice)?;
        let read_in = self.appended();
        self.appended = 0;
        Ok(read_in)
    }

    /// Appends a slice to the internal buffer. Requires the buffer to
    /// be busy by using `try_hold` first
    ///
    /// Increases the `appended` counter
    ///
    /// Returns the number of bytes appended
    fn try_append_slice(&mut self, slice: &[u8]) -> RequestHolderResult<()> {
        if slice.len() == 0 {
            warn!("try appending a zero length slice");
            return Ok(());
        }
        if !self.busy {
            return Err(RequestHolderError::Empty);
        }

        if self.invalid {
            return Err(RequestHolderError::Invalid);
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

    /// Using the content of the `RequestHolder` tries to find a valid
    /// SFTP request appending from slice into the internal buffer to
    /// form a valid request
    ///
    /// Returns the number of bytes appended
    pub fn try_append_for_valid_request(
        &mut self,
        slice: &[u8],
    ) -> RequestHolderResult<()> {
        self.appended = 0; // reset appended bytes counter

        debug!(
            "try_append_for_valid_request: self = {:?}\n\
            Space left = {:?}\n\
            Length of slice to append from = {:?}",
            self,
            self.remaining_len(),
            slice.len()
        );

        if self.invalid {
            return Err(RequestHolderError::Invalid);
        }

        if !self.busy {
            return Err(RequestHolderError::Empty);
        }

        // This makes sure that we do  not try to read more slice than we can
        if self.buffer_fill_index + slice.len() < proto::SFTP_FIELD_ID_INDEX {
            self.try_append_slice(&slice)?;
            return Err(RequestHolderError::RanOut);
        }

        let complete_to_id_index = proto::SFTP_FIELD_ID_INDEX
            .checked_sub(self.buffer_fill_index - 1)
            .unwrap_or(0);

        if complete_to_id_index > 0 {
            warn!(
                "The held fragment len = {:?}, is insufficient to peak\
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

        let packet_len =
            SftpSource::new(self.try_get_ref()?).peak_packet_len()? as usize;

        let packet_type = SftpSource::new(self.try_get_ref()?).peak_packet_type()?;
        debug!("Request len = {:?}, type = {:?}", packet_len, packet_type);

        let remaining_packet_len = packet_len - self.buffer_fill_index; // TODO: Careful, the packet len does not include the packet len field

        if remaining_packet_len <= (self.remaining_len()) {
            if remaining_packet_len > slice.len() {
                self.try_append_slice(&slice[self.appended()..])?;
                error!(
                    "The slice to include to the held fragment does not \
                    contain the whole packet. More data is required."
                );
                return Err(RequestHolderError::RanOut);
            }
            self.try_append_slice(&slice[self.appended()..])?; // The only Ok
        } else {
            warn!(
                "The request does not fit in the buffer: \
                (req len = {:?} > buffer len = {:?} )",
                packet_len,
                self.buffer.len()
            );
            if self.remaining_len() < (slice.len() - self.appended()) {
                self.try_append_slice(
                    &slice[self.appended()..self.remaining_len()],
                )?;
            } else {
                self.try_append_slice(&slice[self.appended()..])?;
            }
            return Err(RequestHolderError::NoRoom);
        }
        Ok(())
    }

    /// Gets a reference to the slice that it is holding
    pub fn try_get_ref(&self) -> RequestHolderResult<&[u8]> {
        if self.invalid {
            return Err(RequestHolderError::Invalid);
        }

        if self.busy {
            Ok(&self.buffer[..self.buffer_fill_index])
        } else {
            Err(RequestHolderError::Empty)
        }
    }

    /// Returns true if it has a slice in its buffer
    pub fn is_busy(&self) -> bool {
        self.busy
    }

    /// Returns the bytes appened in the last call to `try_append_for_valid_request`
    pub fn appended(&self) -> usize {
        self.appended
    }

    /// Returns the number of bytes unused at the end of the buffer,
    /// this is, the remaining length
    fn remaining_len(&self) -> usize {
        self.buffer.len() - self.buffer_fill_index - 1 // Off by one?
    }
}
