//! Presents SSH channels as async
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::ops::DerefMut;

use embedded_io::{asynch, Io};

use crate::*;
use embassy_sunset::EmbassySunset;
use sunset::{Result, ChanData, ChanHandle, ChanNum};

pub struct ChanInOut<'a> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

pub struct ChanIn<'a> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

pub struct ChanOut<'a> {
    num: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

impl core::fmt::Debug for ChanInOut<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanInOut")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ChanIn<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanExtIn")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ChanOut<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanOut")
            .field("num", &self.num)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl<'a> ChanInOut<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            num, dt, sunset,
        }
    }

    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.num).await
    }

    pub async fn term_window_change(&self, winch: sunset::packets::WinChange) -> Result<()> {
        self.sunset.term_window_change(self.num, winch).await
    }
}

impl<'a> ChanIn<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            num, dt, sunset,
        }
    }
}

impl<'a> ChanOut<'a> {
    // caller must have already incremented the refcount
    pub(crate) fn new(num: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            num, dt, sunset,
        }
    }

    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.num).await
    }
}

impl Drop for ChanIn<'_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

impl Drop for ChanOut<'_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

impl Drop for ChanInOut<'_> {
    fn drop(&mut self) {
        self.sunset.dec_chan(self.num)
    }
}

impl Clone for ChanIn<'_> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self {
            num: self.num,
            dt: self.dt,
            sunset: self.sunset,
        }
    }
}

impl Clone for ChanOut<'_> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self {
            num: self.num,
            dt: self.dt,
            sunset: self.sunset,
        }
    }
}

impl Clone for ChanInOut<'_> {
    fn clone(&self) -> Self {
        self.sunset.inc_chan(self.num);
        Self {
            num: self.num,
            dt: self.dt,
            sunset: self.sunset,
        }
    }
}

impl Io for ChanInOut<'_> {
    // TODO or something else?
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
        self.sunset.read_channel(self.num, self.dt, buf).await
    }
}

impl<'a> asynch::Write for ChanInOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.num, self.dt, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

impl<'a> asynch::Read for ChanIn<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.num, self.dt, buf).await
    }
}

impl<'a> asynch::Write for ChanOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.num, self.dt, buf).await
    }
}
