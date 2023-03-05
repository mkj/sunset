//! Presents SSH channels as async
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embedded_io::{asynch, Io};

use crate::*;
use embassy_sunset::EmbassySunset;
use sunset::{Result, ChanData, ChanNum};

/// Common implementation
struct ChanIO<'a> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
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
        self.sunset.until_channel_closed(self.num).await
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
        Self {
            num: self.num,
            dt: self.dt,
            sunset: self.sunset,
        }
    }
}

impl Io for ChanIO<'_> {
    type Error = sunset::Error;
}

impl<'a> asynch::Read for ChanIO<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.num, self.dt, buf).await
    }
}

impl<'a> asynch::Write for ChanIO<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.num, self.dt, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

// Public wrappers for In only

/// An standard bidirectional SSH channel
#[derive(Clone, Debug)]
pub struct ChanInOut<'a>(ChanIO<'a>);

/// An input-only SSH channel, such as stderr for a client
#[derive(Clone, Debug)]
pub struct ChanIn<'a>(ChanIO<'a>);

#[derive(Clone, Debug)]
/// An output-only SSH channel, such as stderr for a server
pub struct ChanOut<'a>(ChanIO<'a>);

impl<'a> ChanInOut<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self(ChanIO {
            num, dt, sunset,
        })
    }

    /// A future that waits until the channel closes
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }

    /// Send a terminal size change notification
    ///
    /// Only applicable to client shell channels with a PTY
    pub async fn term_window_change(&self, winch: sunset::packets::WinChange) -> Result<()> {
        self.0.sunset.term_window_change(self.0.num, winch).await
    }
}

impl<'a> ChanIn<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self(ChanIO {
            num, dt, sunset,
        })
    }
}

impl<'a> ChanOut<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self(ChanIO {
            num, dt, sunset,
        })
    }

    /// A future that waits until the channel closes
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }
}

impl Io for ChanInOut<'_> {
    type Error = sunset::Error;
}

impl Io for ChanIn<'_> {
    type Error = sunset::Error;
}

impl Io for ChanOut<'_> {
    type Error = sunset::Error;
}

impl<'a> asynch::Read for ChanInOut<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl<'a> asynch::Write for ChanInOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}

impl<'a> asynch::Read for ChanIn<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl<'a> asynch::Write for ChanOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}
