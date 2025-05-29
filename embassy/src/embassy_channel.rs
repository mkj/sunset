//! Presents SSH channels as async
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embedded_io_async::{ErrorType, Read, Write};

use crate::*;
use embassy_sunset::EmbassySunset;
use sunset::{ChanData, ChanNum, Result};

/// Common implementation
struct ChanIO<'g, 'a> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'g EmbassySunset<'a>,
}

impl core::fmt::Debug for ChanIO<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanIO")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl ChanIO<'_, '_> {
    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.num).await
    }
}

impl Drop for ChanIO<'_, '_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

impl Clone for ChanIO<'_, '_> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self { num: self.num, dt: self.dt, sunset: self.sunset }
    }
}

impl ErrorType for ChanIO<'_, '_> {
    type Error = sunset::Error;
}

impl Read for ChanIO<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.num, self.dt, buf).await
    }
}

impl Write for ChanIO<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.num, self.dt, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

// Public wrappers for In only

/// A standard bidirectional SSH channel
#[derive(Debug, Clone)]
pub struct ChanInOut<'g, 'a>(ChanIO<'g, 'a>);

/// An input-only SSH channel, such as stderr for a client
#[derive(Debug, Clone)]
pub struct ChanIn<'g, 'a>(ChanIO<'g, 'a>);

#[derive(Debug, Clone)]
/// An output-only SSH channel, such as stderr for a server
pub struct ChanOut<'g, 'a>(ChanIO<'g, 'a>);

impl<'g, 'a> ChanInOut<'g, 'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g EmbassySunset<'a>,
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
        self.0.sunset.term_window_change(self.0.num, winch).await
    }
}

impl<'g, 'a> ChanIn<'g, 'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g EmbassySunset<'a>,
    ) -> Self {
        Self(ChanIO { num, dt, sunset })
    }
}

impl<'g, 'a> ChanOut<'g, 'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(
        num: ChanNum,
        dt: ChanData,
        sunset: &'g EmbassySunset<'a>,
    ) -> Self {
        Self(ChanIO { num, dt, sunset })
    }

    /// A future that waits until the channel closes
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }
}

impl ErrorType for ChanInOut<'_, '_> {
    type Error = sunset::Error;
}

impl ErrorType for ChanIn<'_, '_> {
    type Error = sunset::Error;
}

impl ErrorType for ChanOut<'_, '_> {
    type Error = sunset::Error;
}

impl Read for ChanInOut<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanInOut<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}

impl Read for ChanIn<'_, '_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl Write for ChanOut<'_, '_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}
