#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

use core::ops::DerefMut;

use embedded_io::{asynch, Io};

use embassy_sync::{pipe, mutex::Mutex, signal::Signal};
use embassy_sync::pipe::Pipe;
use embassy_futures::select::{select, Either};

use sunset_embassy::{SunsetMutex, SunsetRawMutex};

pub const READ_SIZE: usize = 4000;
pub const WRITE_SIZE: usize = 64;

// TODO: this is fairly ugly, the mutex and counter could perhaps be abstracted

/// Allows a bidirectional pipe to be shared by many endpoints
///
/// One end of the pipe is fixed (attached to eg a physical/virtual
/// uart), used with `.split()`. `TakePipeStorage` is the backing store,
/// the `TakePipe` struct returned by `.pipe()` has the functionality.
///
/// The other end can be used by many clients, one at a time.
/// When a subsequent client takes the pipe (with `.take()`), the existing
/// client loses the pipe and gets EOF.
///
/// It works a bit like `screen -r -d`.
pub(crate) struct TakePipeStorage {
	fanout: Pipe<SunsetRawMutex, READ_SIZE>,
    fanin: Pipe<SunsetRawMutex, WRITE_SIZE>,
    wake: Signal<SunsetRawMutex, ()>,
}

impl TakePipeStorage {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn pipe(&self) -> TakePipe {
        TakePipe {
            shared_read: Mutex::new((0, self.fanout.reader())),
            shared_write: Mutex::new((0, self.fanin.writer())),
            pipe: self,
        }
    }
}

impl Default for TakePipeStorage {
    fn default() -> Self {
        Self {
            fanout: Pipe::new(),
            fanin: Pipe::new(),
            wake: Signal::new(),
        }
    }
}

pub(crate) struct TakePipe<'a> {
    shared_read: Mutex<SunsetRawMutex, (u64, pipe::Reader<'a, SunsetRawMutex, READ_SIZE>)>,
    shared_write: Mutex<SunsetRawMutex, (u64, pipe::Writer<'a, SunsetRawMutex, WRITE_SIZE>)>,
    pipe: &'a TakePipeStorage,
}

impl<'a> TakePipe<'a> {
    pub async fn take(&'a self) -> (TakeRead<'a>, TakeWrite<'a>) {

        self.pipe.wake.signal(());
        let mut lr = self.shared_read.lock().await;
        let (cr, _r) = lr.deref_mut();
        let mut lw = self.shared_write.lock().await;
        let (cw, _w) = lw.deref_mut();
        *cr += 1;
        *cw += 1;
        debug_assert!(*cr == *cw);
        // We could .clear() the pipes, but
        // that wouldn't deal with data that has already progressed
        // further along out the SSH channel etc. So we leave that
        // for high levels to deal with if needed.
        self.pipe.wake.reset();

        let r = TakeRead {
            pipe: self.pipe,
            shared: Some(&self.shared_read),
            counter: *cr,
        };
        let w = TakeWrite {
            pipe: self.pipe,
            shared: Some(&self.shared_write),
            counter: *cw,
        };
        (r, w)
    }

    pub fn is_in_use(&self) -> bool {
        self.shared_read.try_lock().is_err()
    }

    pub fn split(&'a self) -> (TakePipeRead<'a>, TakePipeWrite<'a>) {
        let r = TakePipeRead {
            pipe: self.pipe,
        };
        let w = TakePipeWrite {
            pipe: self.pipe,
        };
        (r, w)
    }
}

pub(crate) struct TakePipeRead<'a> {
    pipe: &'a TakePipeStorage,
}

pub(crate) struct TakePipeWrite<'a> {
    pipe: &'a TakePipeStorage,
}

impl<'a> asynch::Read for TakePipeRead<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        let r = self.pipe.fanin.read(buf).await;
        Ok(r)
    }
}

impl<'a> asynch::Write for TakePipeWrite<'a> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        let r = self.pipe.fanout.write(buf).await;
        Ok(r)
    }
}

impl Io for TakePipeRead<'_> {
    type Error = sunset::Error;
}

impl Io for TakePipeWrite<'_> {
    type Error = sunset::Error;
}

pub(crate) struct TakeRead<'a> {
    pipe: &'a TakePipeStorage,
    shared: Option<&'a SunsetMutex<(u64, pipe::Reader<'a, SunsetRawMutex, READ_SIZE>)>>,
    counter: u64,
}

impl asynch::Read for TakeRead<'_> {

    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        let p = self.shared.ok_or(sunset::Error::ChannelEOF)?;

        let op = async {
            let mut p = p.lock().await;
            let (c, o) = p.deref_mut();
            if *c != self.counter {
                return Err(sunset::Error::ChannelEOF);
            }
            Ok(o.read(buf).await)
        };

        let r = select(
            op,
            self.pipe.wake.wait(),
        );

        match r.await {
            // read completed
            Either::First(l) => l,
            // lost the pipe
            Either::Second(()) => {
                self.shared = None;
                Err(sunset::Error::ChannelEOF)
            }
        }
    }
}

impl Io for TakeRead<'_> {
    type Error = sunset::Error;
}

pub(crate) struct TakeWrite<'a> {
    pipe: &'a TakePipeStorage,
    shared: Option<&'a SunsetMutex<(u64, pipe::Writer<'a, SunsetRawMutex, WRITE_SIZE>)>>,
    counter: u64,
}

impl asynch::Write for TakeWrite<'_> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        let p = self.shared.ok_or(sunset::Error::ChannelEOF)?;

        let op = async {
            let mut p = p.lock().await;
            let (c, o) = p.deref_mut();
            if *c != self.counter {
                return Err(sunset::Error::ChannelEOF);
            }
            Ok(o.write(buf).await)
        };

        let r = select(
            op,
            self.pipe.wake.wait(),
        );

        match r.await {
            // write completed
            Either::First(l) => l,
            // lost the pipe
            Either::Second(_) => {
                self.shared = None;
                Err(sunset::Error::ChannelEOF)
            }
        }
    }
}

impl Io for TakeWrite<'_> {
    type Error = sunset::Error;
}
