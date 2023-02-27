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
use sunset::{Result, ChanData, ChanNum};

#[derive(Clone)]
pub struct ChanInOut<'a> {
    chan: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

#[derive(Clone)]
pub struct ChanIn<'a> {
    chan: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

#[derive(Clone)]
pub struct ChanOut<'a> {
    chan: ChanNum,
    dt: ChanData,
    sunset: &'a EmbassySunset<'a>,
}

impl core::fmt::Debug for ChanInOut<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanInOut")
            .field("chan", &self.chan)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ChanIn<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanExtIn")
            .field("chan", &self.chan)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ChanOut<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChanOut")
            .field("chan", &self.chan)
            .field("dt", &self.dt)
            .finish_non_exhaustive()
    }
}


impl<'a> ChanInOut<'a> {
    pub(crate) fn new(chan: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            chan, dt, sunset,
        }
    }

    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.chan).await
    }

    pub async fn term_window_change(&self, winch: sunset::packets::WinChange) -> Result<()> {
        error!("term_winch {:?}", winch);
        self.sunset.with_runner(|runner| runner.term_window_change(self.chan, winch)).await
    }
}

impl<'a> ChanIn<'a> {
    pub(crate) fn new(chan: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            chan, dt, sunset,
        }
    }
}

impl<'a> ChanOut<'a> {
    pub(crate) fn new(chan: ChanNum, dt: ChanData, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            chan, dt, sunset,
        }
    }

    pub async fn until_closed(&self) -> Result<()> {
        self.sunset.until_channel_closed(self.chan).await
    }
}

impl<'a> Io for ChanInOut<'a> {
    // TODO or something else?
    type Error = sunset::Error;
}

impl<'a> Io for ChanIn<'a> {
    type Error = sunset::Error;
}

impl<'a> Io for ChanOut<'a> {
    type Error = sunset::Error;
}

impl<'a> asynch::Read for ChanInOut<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.chan, self.dt, buf).await
    }
}

impl<'a> asynch::Write for ChanInOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.chan, self.dt, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}

impl<'a> asynch::Read for ChanIn<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel(self.chan, self.dt, buf).await
    }
}

impl<'a> asynch::Write for ChanOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.chan, self.dt, buf).await
    }
}
