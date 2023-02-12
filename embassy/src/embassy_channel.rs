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

pub struct Channel<'a> {
    chan: u32,
    sunset: &'a EmbassySunset<'a>,
}

impl<'a> Channel<'a> {
    /// Should be called by a SSH client when the local terminal changes size
    /// (`SIGWINCH` is received). Only applicable to client session
    /// channels with a pty.
    pub async fn term_window_change(&self) {
        todo!("term_window_change");
        // let wc = match pty::win_size() {
        //     Ok(wc) => wc,
        //     Err(e) => {
        //         warn!("Failed getting window size: {e}");
        //         return;
        //     }
        // };

        // // TODO: also need to wait for spare output buffer
        // self.sunset.inner.lock().await
        // .runner.term_window_change(self.chan, wc);
    }
}

pub struct ChanInOut<'a> {
    chan: u32,
    sunset: &'a EmbassySunset<'a>,

    // rlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
    // wlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

pub struct ChanExtIn<'a> {
    chan: u32,
    ext: u32,
    sunset: &'a EmbassySunset<'a>,

    // rlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

pub struct ChanExtOut<'a> {
    chan: u32,
    ext: u32,
    sunset: &'a EmbassySunset<'a>,

    // wlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

impl<'a> ChanInOut<'a> {
    pub(crate) fn new(chan: u32, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            chan, sunset,
            // rlfut: None, wlfut: None,
        }
    }
}

// impl Clone for ChanInOut<'_> {
//     fn clone(&self) -> Self {
//         Self {
//             chan: self.chan, sunset: self.sunset.private_clone(),
//             // rlfut: None, wlfut: None,
//         }
//     }
// }

impl<'a> ChanExtIn<'a> {
    pub(crate) fn new(chan: u32, ext: u32, sunset: &'a EmbassySunset<'a>) -> Self {
        Self {
            chan, ext, sunset,
            // rlfut: None,
        }
    }
}

impl<'a> Io for ChanInOut<'a> {
    // TODO or something else?
    type Error = sunset::Error;
}

impl<'a> asynch::Read for ChanInOut<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.sunset.read_channel_stdin(self.chan, buf).await
    }
}

impl<'a> asynch::Write for ChanInOut<'a> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.sunset.write_channel(self.chan, None, buf).await
    }

    // TODO: not sure how easy end-to-end flush is
    // async fn flush(&mut self) -> Result<(), Self::Error> {
    // }
}