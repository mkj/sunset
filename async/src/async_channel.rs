//! Presents SSH channels as async
use core::future::poll_fn;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embedded_io_async::{ErrorType, Read, Write};

use crate::*;
use sunset::{ChanData, ChanNum, Result};

/// Common implementation
struct ChanIO<'g> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'g dyn async_sunset::ChanCore,
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
}

impl Drop for ChanIO<'_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

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
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        poll_fn(|cx| self.sunset.poll_read_channel(cx, self.num, self.dt, buf)).await
    }
}

impl Write for ChanIO<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        poll_fn(|cx| self.sunset.poll_write_channel(cx, self.num, self.dt, buf))
            .await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

// Public wrappers for In only

/// A standard bidirectional SSH channel
#[derive(Debug)]
pub struct ChanInOut<'g>(ChanIO<'g>);

// Manual Clone since derive requires template parameters impl Clone.
impl Clone for ChanInOut<'_> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// An input-only SSH channel, such as stderr for a client
#[derive(Debug, Clone)]
pub struct ChanIn<'g>(ChanIO<'g>);

#[derive(Debug, Clone)]
/// An output-only SSH channel, such as stderr for a server
pub struct ChanOut<'g>(ChanIO<'g>);

impl<'g> ChanInOut<'g> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g dyn async_sunset::ChanCore,
    ) -> Self {
        Self(ChanIO { num, dt, sunset })
    }

    /// A future that waits until the channel closes
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
        poll_fn(|cx| self.0.sunset.poll_term_window_change(cx, self.0.num, &winch))
            .await
    }
}

impl<'g> ChanIn<'g> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g dyn async_sunset::ChanCore,
    ) -> Self {
        Self(ChanIO { num, dt, sunset })
    }
}

impl<'g> ChanOut<'g> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g dyn async_sunset::ChanCore,
    ) -> Self {
        Self(ChanIO { num, dt, sunset })
    }

    /// A future that waits until the channel closes
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
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
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanInOut<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}

impl Read for ChanIn<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanOut<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}
