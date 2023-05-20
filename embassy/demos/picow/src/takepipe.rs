use embedded_io::{asynch, Io};

use embassy_sync::{pipe, mutex::{MutexGuard, Mutex}, signal::Signal};
use embassy_sync::pipe::Pipe;
use embassy_futures::select::{select, Either};

use sunset_embassy::{SunsetMutex, SunsetRawMutex};

pub const READ_SIZE: usize = 4000;
pub const WRITE_SIZE: usize = 64;

/// Allows a bidirectional pipe to be shared by many endpoints
///
/// One end of the pipe is fixed (attached to eg a physical/virtual
/// uart), used with `.split()`.
///
/// The other end can be used by many clients, one at a time.
/// When a subsequent client takes the pipe (with `.take()`), the existing
/// client loses the pipe and gets EOF.
///
/// It works a bit like `screen -r -d`.
pub(crate) struct TakePipe {
	fanout: Pipe<SunsetRawMutex, READ_SIZE>,
    fanin: Pipe<SunsetRawMutex, WRITE_SIZE>,
    wake: Signal<SunsetRawMutex, ()>,
}

impl TakePipe {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn base(&self) -> TakeBase {
        TakeBase {
            shared_read: Mutex::new(self.fanout.reader()),
            shared_write: Mutex::new(self.fanin.writer()),
            pipe: self,
        }
    }
}

impl Default for TakePipe {
    fn default() -> Self {
        Self {
            fanout: Pipe::new(),
            fanin: Pipe::new(),
            wake: Signal::new(),
        }
    }
}

pub(crate) struct TakeBase<'a> {
    shared_read: Mutex<SunsetRawMutex, pipe::Reader<'a, SunsetRawMutex, READ_SIZE>>,
    shared_write: Mutex<SunsetRawMutex, pipe::Writer<'a, SunsetRawMutex, WRITE_SIZE>>,
    pipe: &'a TakePipe,
}

impl<'a> TakeBase<'a> {
    pub async fn take(&'a self) -> (TakeRead<'a>, TakeWrite<'a>) {
        self.pipe.wake.signal(());
        let r = self.shared_read.lock().await;
        let w = self.shared_write.lock().await;
        // We could .clear() the pipes, but
        // that wouldn't deal with data that has already progressed
        // further along out the SSH channel etc. So we leave that
        // for high levels to deal with if needed.
        self.pipe.wake.reset();

        let r = TakeRead {
            pipe: self.pipe,
            shared: Some(r),
        };
        let w = TakeWrite {
            pipe: self.pipe,
            shared: Some(w),
        };
        (r, w)
    }

    pub fn split(&'a self) -> (TakeBaseRead<'a>, TakeBaseWrite<'a>) {
        let r = TakeBaseRead {
            pipe: self.pipe,
        };
        let w = TakeBaseWrite {
            pipe: self.pipe,
        };
        (r, w)
    }
}

pub(crate) struct TakeBaseRead<'a> {
    pipe: &'a TakePipe,
}

pub(crate) struct TakeBaseWrite<'a> {
    pipe: &'a TakePipe,
}

impl<'a> asynch::Read for TakeBaseRead<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        Ok(self.pipe.fanin.read(buf).await)
    }
}

impl<'a> asynch::Write for TakeBaseWrite<'a> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        Ok(self.pipe.fanout.write(buf).await)
    }
}

impl Io for TakeBaseRead<'_> {
    type Error = sunset::Error;
}

impl Io for TakeBaseWrite<'_> {
    type Error = sunset::Error;
}

pub(crate) struct TakeRead<'a> {
    pipe: &'a TakePipe,
    shared: Option<MutexGuard<'a, SunsetRawMutex, pipe::Reader<'a, SunsetRawMutex, READ_SIZE>>>,
}

impl asynch::Read for TakeRead<'_> {

    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        let p = self.shared.as_ref().ok_or(sunset::Error::ChannelEOF)?;

        let r = select(
            p.read(buf),
            self.pipe.wake.wait(),
        );

        match r.await {
            // read completed
            Either::First(l) => Ok(l),
            // lost the pipe
            Either::Second(l) => {
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
    pipe: &'a TakePipe,
    shared: Option<MutexGuard<'a, SunsetRawMutex, pipe::Writer<'a, SunsetRawMutex, WRITE_SIZE>>>,
}

impl asynch::Write for TakeWrite<'_> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        let p = self.shared.as_ref().ok_or(sunset::Error::ChannelEOF)?;

        let r = select(
            p.write(buf),
            self.pipe.wake.wait(),
        );

        match r.await {
            // write completed
            Either::First(l) => Ok(l),
            // lost the pipe
            Either::Second(l) => {
                self.shared = None;
                Err(sunset::Error::ChannelEOF)
            }
        }
    }
}

impl Io for TakeWrite<'_> {
    type Error = sunset::Error;
}
