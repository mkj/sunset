//! Presents SSH channels as async
use core::future::poll_fn;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embedded_io_async::{ErrorType, Read, Write};

use crate::*;
use sunset::{ChanData, ChanNum, Result};

/// Common implementation
pub(crate) struct ChanIO<'g> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'g dyn async_sunset::ChanCore,
}

impl<'g> ChanIO<'g> {
    /// Create a new Normal ChanIO.
    ///
    /// Only to be called by add_channel(), which has already set
    /// the initial refcount = 1.
    pub(crate) fn new_normal(
        num: ChanNum,
        sunset: &'g dyn async_sunset::ChanCore,
    ) -> Self {
        Self { num, dt: ChanData::Normal, sunset }
    }

    pub(crate) fn clone_stderr(&self) -> Self {
        let mut c = self.clone();
        c.dt = ChanData::Stderr;
        c
    }
}

impl core::fmt::Debug for ChanIO<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanIO")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl ChanIO<'_> {
    pub async fn until_closed(&self) -> Result<()> {
        poll_fn(|cx| self.sunset.poll_until_channel_closed(cx, self.num)).await
    }

    pub async fn term_window_change(
        &self,
        winch: sunset::packets::WinChange,
    ) -> Result<()> {
        poll_fn(|cx| self.sunset.poll_term_window_change(cx, self.num, &winch)).await
    }
}

impl Drop for ChanIO<'_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

// ChanIO implements Clone to share between ChanIn/ChanOut/ChanInOut.
// There's only one waker for each of in/out/ext, so allowing clone
// on the ChanInOut etc isn't desirable - having two instances polling
// the same direction/dt will just result in churn between wakers if they're
// in different tasks.
impl Clone for ChanIO<'_> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self { num: self.num, dt: self.dt, sunset: self.sunset }
    }
}

impl ErrorType for ChanIO<'_> {
    type Error = sunset::Error;
}

impl Read for ChanIO<'_> {
    async fn read(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<usize, sunset::Error> {
        poll_fn(|cx| self.sunset.poll_read_channel(cx, self.num, self.dt, buf))
            .await
            .map_err(Into::into)
    }
}

impl Write for ChanIO<'_> {
    async fn write(
        &mut self,
        buf: &[u8],
    ) -> core::result::Result<usize, sunset::Error> {
        poll_fn(|cx| self.sunset.poll_write_channel(cx, self.num, self.dt, buf))
            .await
            .map_err(Into::into)
    }

    // TODO: not sure how easy end-to-end flush is
    async fn flush(&mut self) -> core::result::Result<(), sunset::Error> {
        // No-op flush: underlying SSH channel does not expose an explicit
        // flush operation via the sunset ChanCore API, so treat flush as
        // immediately successful.
        Ok(())
    }
}

// Public wrappers for In only

/// An input-only SSH channel.
///
/// This is used as stderr for a client.
///
/// <div class="warning">
///
/// This must be read, otherwise the SSH session will block.
///
/// </div>
///
/// `Clone` is implemented for convenience, but only one instance each
/// should be read from.
/// Otherwise ordering will be arbitrary, and if competing readers or writers
/// are in different tasks, there will be churn as they continually wake
/// each other up. Simultaneous single-reader and single-writer is fine.
#[derive(Debug, Clone)]
pub struct ChanIn<'g>(ChanIO<'g>);

impl<'g> ChanIn<'g> {
    pub(crate) fn new(io: ChanIO<'g>) -> Self {
        io.sunset.inc_read_chan(io.num, io.dt);
        Self(io)
    }

    /// Wait until the channel closes.
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }
}

impl Drop for ChanIn<'_> {
    fn drop(&mut self) {
        self.0.sunset.dec_read_chan(self.0.num, self.0.dt)
    }
}

/// An output-only SSH channel.
///
/// This is used as stderr for a server, or can also be obtained using
/// [`ChanInOut::split()`] for cases where a channel's input should
/// be discarded.
///
/// `Clone` is implemented for convenience, but only one instance each
/// should be read from or written to (this applies to `split()` instances too).
/// Otherwise ordering will be arbitrary, and if competing readers or writers
/// are in different tasks, there will be churn as they continually wake
/// each other up. Simultaneous single-reader and single-writer is fine.
#[derive(Debug, Clone)]
pub struct ChanOut<'g>(ChanIO<'g>);

impl<'g> ChanOut<'g> {
    pub(crate) fn new(io: ChanIO<'g>) -> Self {
        Self(io)
    }

    /// Wait until the channel closes.
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }

    /// Send a terminal size change notification
    ///
    /// Only applicable to client shell channels with a PTY
    pub async fn term_window_change(
        &self,
        winch: sunset::packets::WinChange,
    ) -> Result<()> {
        self.0.term_window_change(winch).await
    }
}

/// A bidirectional SSH channel.
///
/// Used as stdin/stdout for a shell/exec/subsystem.
/// Represents other forwarded transports.
///
/// <div class="warning">
///
/// This must be read, otherwise the SSH session will block.
/// If input isn't required, use [`split()`](Self::split) and
/// discard the input half.
///
/// </div>
///
/// `Clone` is implemented for convenience, but only one instance each
/// should be read from or written to (this applies to `split()` instances too).
/// Otherwise ordering will be arbitrary, and if competing readers or writers
/// are in different tasks, there will be churn as they continually wake
/// each other up. Simultaneous single-reader and single-writer is fine.
#[derive(Debug, Clone)]
pub struct ChanInOut<'g>(ChanIO<'g>);

impl<'g> ChanInOut<'g> {
    pub(crate) fn new(io: ChanIO<'g>) -> Self {
        io.sunset.inc_read_chan(io.num, io.dt);
        Self(io)
    }

    /// Convert this into separate input and output.
    ///
    /// Note the warning above against simultaneous use and `Clone`.
    pub fn split(&self) -> (ChanIn<'g>, ChanOut<'g>) {
        (ChanIn::new(self.0.clone()), ChanOut::new(self.0.clone()))
    }

    /// Wait until the channel closes.
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }

    /// Send a terminal size change notification
    ///
    /// Only applicable to client shell channels with a PTY
    pub async fn term_window_change(
        &self,
        winch: sunset::packets::WinChange,
    ) -> Result<()> {
        self.0.term_window_change(winch).await
    }
}

impl Drop for ChanInOut<'_> {
    fn drop(&mut self) {
        self.0.sunset.dec_read_chan(self.0.num, self.0.dt)
    }
}

impl ErrorType for ChanInOut<'_> {
    type Error = sunset::Error;
}

impl ErrorType for ChanIn<'_> {
    type Error = sunset::Error;
}

impl ErrorType for ChanOut<'_> {
    type Error = sunset::Error;
}

impl Read for ChanInOut<'_> {
    async fn read(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanInOut<'_> {
    async fn write(
        &mut self,
        buf: &[u8],
    ) -> core::result::Result<usize, sunset::Error> {
        self.0.write(buf).await
    }

    async fn flush(&mut self) -> core::result::Result<(), sunset::Error> {
        self.0.flush().await
    }
}

impl Read for ChanIn<'_> {
    async fn read(
        &mut self,
        buf: &mut [u8],
    ) -> core::result::Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanOut<'_> {
    async fn write(
        &mut self,
        buf: &[u8],
    ) -> core::result::Result<usize, sunset::Error> {
        self.0.write(buf).await
    }

    async fn flush(&mut self) -> core::result::Result<(), sunset::Error> {
        self.0.flush().await
    }
}
