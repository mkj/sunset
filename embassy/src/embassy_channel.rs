//! Presents SSH channels as async
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embedded_io::{asynch, Io};

use crate::*;
use embassy_sunset::EmbassySunset;
use sunset::{Result, ChanData, ChanNum, CliBehaviour, ServBehaviour};

/// Common implementation
struct ChanIO<'a, C: CliBehaviour, S: ServBehaviour> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a, C, S>,
}

impl<C: CliBehaviour, S: ServBehaviour> core::fmt::Debug for ChanIO<'_, C, S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanIO")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl<C: CliBehaviour, S: ServBehaviour> ChanIO<'_, C, S> {
    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.num).await
    }
}

impl<C: CliBehaviour, S: ServBehaviour> Drop for ChanIO<'_, C, S> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

impl<C: CliBehaviour, S: ServBehaviour> Clone for ChanIO<'_, C, S> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self {
            num: self.num,
            dt: self.dt,
            sunset: self.sunset,
        }
    }
}

impl<C: CliBehaviour, S: ServBehaviour> Io for ChanIO<'_, C, S> {
    type Error = sunset::Error;
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Read for ChanIO<'a, C, S> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.num, self.dt, buf).await
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Write for ChanIO<'a, C, S> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.num, self.dt, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

// Public wrappers for In only

/// An standard bidirectional SSH channel
#[derive(Debug)]
pub struct ChanInOut<'a, C: CliBehaviour, S: ServBehaviour>(ChanIO<'a, C, S>);

/// An input-only SSH channel, such as stderr for a client
#[derive(Debug)]
pub struct ChanIn<'a, C: CliBehaviour, S: ServBehaviour>(ChanIO<'a, C, S>);

#[derive(Debug)]
/// An output-only SSH channel, such as stderr for a server
pub struct ChanOut<'a, C: CliBehaviour, S: ServBehaviour>(ChanIO<'a, C, S>);

// derive(Clone) adds unwanted `: Clone` bounds on C and S, so we implement manually
// https://github.com/rust-lang/rust/issues/26925
impl<'a, C: CliBehaviour, S: ServBehaviour> Clone for ChanInOut<'a, C, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<'a, C: CliBehaviour, S: ServBehaviour> Clone for ChanIn<'a, C, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<'a, C: CliBehaviour, S: ServBehaviour> Clone for ChanOut<'a, C, S> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> ChanInOut<'a, C, S> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a, C, S>) -> Self {
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

impl<'a, C: CliBehaviour, S: ServBehaviour> ChanIn<'a, C, S> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a, C, S>) -> Self {
        Self(ChanIO {
            num, dt, sunset,
        })
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> ChanOut<'a, C, S> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a, C, S>) -> Self {
        Self(ChanIO {
            num, dt, sunset,
        })
    }

    /// A future that waits until the channel closes
    pub async fn until_closed(&self) -> Result<()> {
        self.0.until_closed().await
    }
}

impl<C: CliBehaviour, S: ServBehaviour> Io for ChanInOut<'_, C, S> {
    type Error = sunset::Error;
}

impl<C: CliBehaviour, S: ServBehaviour> Io for ChanIn<'_, C, S> {
    type Error = sunset::Error;
}

impl<C: CliBehaviour, S: ServBehaviour> Io for ChanOut<'_, C, S> {
    type Error = sunset::Error;
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Read for ChanInOut<'a, C, S> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Write for ChanInOut<'a, C, S> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Read for ChanIn<'a, C, S> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).await
    }
}

impl<'a, C: CliBehaviour, S: ServBehaviour> asynch::Write for ChanOut<'a, C, S> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).await
    }
}
