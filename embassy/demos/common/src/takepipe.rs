#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::ops::DerefMut;

use embedded_io_async::{ErrorType, Read, Write};

use embassy_futures::select::{select, Either};
use embassy_sync::pipe::Pipe;
use embassy_sync::{mutex::Mutex, pipe, signal::Signal};

use sunset_embassy::{SunsetMutex, SunsetRawMutex};

pub const READ_SIZE: usize = 200;
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
pub struct TakePipeStorage {
    fanout: Pipe<SunsetRawMutex, READ_SIZE>,
    fanin: Pipe<SunsetRawMutex, WRITE_SIZE>,
}

impl TakePipeStorage {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn build(&mut self) -> TakePipe {
        let (fanout_r, fanout_w) = self.fanout.split();
        let (fanin_r, fanin_w) = self.fanin.split();
        TakePipe {
            shared_read: Mutex::new((0, fanout_r)),
            shared_write: Mutex::new((0, fanin_w)),
            reader: fanin_r,
            writer: fanout_w,
            wake: Signal::new(),
        }
    }
}

impl Default for TakePipeStorage {
    fn default() -> Self {
        Self { fanout: Pipe::new(), fanin: Pipe::new() }
    }
}

pub struct TakePipe<'a> {
    // fanout
    shared_read: SunsetMutex<(u64, pipe::Reader<'a, SunsetRawMutex, READ_SIZE>)>,
    writer: pipe::Writer<'a, SunsetRawMutex, READ_SIZE>,
    // fanin
    reader: pipe::Reader<'a, SunsetRawMutex, WRITE_SIZE>,
    shared_write: SunsetMutex<(u64, pipe::Writer<'a, SunsetRawMutex, WRITE_SIZE>)>,
    wake: Signal<SunsetRawMutex, ()>,
}

impl<'a> TakePipe<'a> {
    pub async fn take(&'a self) -> (TakeRead<'a>, TakeWrite<'a>) {
        self.wake.signal(());
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
        self.wake.reset();

        let r = TakeRead { pipe: Some(self), counter: *cr };
        let w = TakeWrite { pipe: Some(self), counter: *cw };
        (r, w)
    }

    pub fn is_in_use(&self) -> bool {
        self.shared_read.try_lock().is_err()
    }

    pub fn split(&'a self) -> (TakePipeRead<'a>, TakePipeWrite<'a>) {
        let r = TakePipeRead { pipe: self };
        let w = TakePipeWrite { pipe: self };
        (r, w)
    }
}

pub struct TakePipeRead<'a> {
    pipe: &'a TakePipe<'a>,
}

pub struct TakePipeWrite<'a> {
    pipe: &'a TakePipe<'a>,
}

impl<'a> Read for TakePipeRead<'a> {
    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        let r = self.pipe.reader.read(buf).await;
        Ok(r)
    }
}

impl<'a> Write for TakePipeWrite<'a> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        let r = self.pipe.writer.write(buf).await;
        Ok(r)
    }
}

impl ErrorType for TakePipeRead<'_> {
    type Error = sunset::Error;
}

impl ErrorType for TakePipeWrite<'_> {
    type Error = sunset::Error;
}

pub struct TakeRead<'a> {
    pipe: Option<&'a TakePipe<'a>>,
    counter: u64,
}

impl Read for TakeRead<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> sunset::Result<usize> {
        let p = self.pipe.ok_or(sunset::Error::ChannelEOF)?;

        let op = async {
            let mut p = p.shared_read.lock().await;
            let (c, o) = p.deref_mut();
            if *c != self.counter {
                return Err(sunset::Error::ChannelEOF);
            }
            // OK unwrap, pipe.read() is infallible
            Ok(o.read(buf).await.unwrap())
        };

        let r = select(op, p.wake.wait());

        match r.await {
            // read completed
            Either::First(l) => l,
            // lost the pipe
            Either::Second(()) => {
                self.pipe = None;
                Err(sunset::Error::ChannelEOF)
            }
        }
    }
}

impl ErrorType for TakeRead<'_> {
    type Error = sunset::Error;
}

pub struct TakeWrite<'a> {
    pipe: Option<&'a TakePipe<'a>>,
    counter: u64,
}

impl Write for TakeWrite<'_> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        let p = self.pipe.ok_or(sunset::Error::ChannelEOF)?;

        let op = async {
            let mut p = p.shared_write.lock().await;
            let (c, o) = p.deref_mut();
            if *c != self.counter {
                return Err(sunset::Error::ChannelEOF);
            }
            // OK unwrap, pipe.write is infallible
            Ok(o.write(buf).await.unwrap())
        };

        let r = select(op, p.wake.wait());

        match r.await {
            // write completed
            Either::First(l) => l,
            // lost the pipe
            Either::Second(_) => {
                self.pipe = None;
                Err(sunset::Error::ChannelEOF)
            }
        }
    }
}

impl ErrorType for TakeWrite<'_> {
    type Error = sunset::Error;
}

#[cfg(test)]
mod tests {
    use crate::takepipe::*;
    use anyhow::Result;
    use embedded_io_async::{Read, Write};

    async fn read_vec(len: usize, r: &mut impl Read) -> Result<Vec<u8>> {
        let mut v = vec![0; len];

        let l = r.read(&mut v).await.map_err(|_| anyhow::anyhow!("read failed"))?;
        v.truncate(l);
        Ok(v)
    }

    #[tokio::test]
    async fn t1() -> Result<()> {
        let mut t = TakePipeStorage::new();
        let t = t.build();

        let (mut r1, mut w1) = t.split();

        let (mut ra, mut wa) = t.take().await;

        w1.write_all(b"bees").await?;

        let v = read_vec(30, &mut ra).await?;
        assert_eq!(v, b"bees");

        w1.write_all(b"bees").await?;

        let (mut rb, mut wb) = t.take().await;

        // original pipe should fail
        read_vec(30, &mut ra).await.unwrap_err();
        wa.write(b"xxx").await.unwrap_err();

        // new pipe gets it
        let v = read_vec(30, &mut rb).await?;
        assert_eq!(v, b"bees");

        // other way
        wb.write(b"skink").await?;
        let v = read_vec(3, &mut r1).await?;
        assert_eq!(v, b"ski");

        // split read
        w1.write_all(b"dragonfly").await?;
        // rb gets the first bit
        let v = read_vec(3, &mut rb).await?;
        assert_eq!(v, b"dra");

        // take another pipe
        let (mut rc, mut _wc) = t.take().await;
        // rb fails
        read_vec(30, &mut rb).await.unwrap_err();

        // rc gets the rest of the write
        let v = read_vec(30, &mut rc).await?;
        assert_eq!(v, b"gonfly");

        Ok(())
    }
}
