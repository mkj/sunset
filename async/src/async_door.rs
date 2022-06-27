#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use futures::lock::{Mutex, OwnedMutexLockFuture, OwnedMutexGuard};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify as TokioNotify;

use std::io::Error as IoError;
use std::io::ErrorKind;
use std::collections::HashMap;

use core::task::Waker;
use core::ops::DerefMut;
use std::sync::Arc;

use door_sshproto as door;
use door::{Behaviour, AsyncCliBehaviour, Runner, Result, Event, ChanEvent};
// use door_sshproto::client::*;

use pretty_hex::PrettyHex;

pub struct Inner<'a> {
    runner: Runner<'a>,
    // TODO: perhaps behaviour can move to runner? unsure of lifetimes.
    behaviour: Behaviour<'a>,

    chan_read_wakers: HashMap<(u32, Option<u32>), Waker>,
    chan_write_wakers: HashMap<(u32, Option<u32>), Waker>,
}

pub struct AsyncDoor<'a> {
    // Not contended much since the Runner is inherently single threaded anyway,
    // using a single buffer for input/output.
    inner: Arc<Mutex<Inner<'a>>>,

    progress_notify: Arc<TokioNotify>,

}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>, behaviour: Behaviour<'a>) -> Self {
        let chan_read_wakers = HashMap::new();
        let chan_write_wakers = HashMap::new();
        let inner = Arc::new(Mutex::new(Inner { runner, behaviour,
            chan_read_wakers, chan_write_wakers }));
        let progress_notify = Arc::new(TokioNotify::new());
        Self { inner, progress_notify }
    }

    fn private_clone(&self) -> Self {
        Self { inner: self.inner.clone(),
            progress_notify: self.progress_notify.clone(),
        }
    }

    pub fn socket(&self) -> AsyncDoorSocket<'a> {
        AsyncDoorSocket::new(self)
    }

    pub async fn progress<F, R>(&mut self, f: F)
        -> Result<Option<R>>
        where F: FnOnce(door::Event) -> Result<Option<R>> {
        trace!("progress");
        let mut wakers = Vec::new();
        let res = {
            let mut inner = self.inner.lock().await;
            let inner = inner.deref_mut();
            let ev = inner.runner.progress(&mut inner.behaviour).await?;
            let r = if let Some(ev) = ev {
                let r = match ev {
                    Event::Channel(ChanEvent::Eof { num }) => {
                        // TODO
                        Ok(None)
                    },
                    _ => f(ev),
                };
                trace!("async prog done payload");
                r
            } else {
                Ok(None)
            };
            inner.runner.done_payload()?;

            if let Some(ce) = inner.runner.ready_channel_input() {
                inner.chan_read_wakers.remove(&ce)
                .map(|w| wakers.push(w));
            }

            // Pending https://github.com/rust-lang/rust/issues/59618
            // HashMap::drain_filter
            // TODO: untested.
            // TODO: fairness? Also it's not clear whether progress notify
            // will always get woken by runner.wake() to update this...
            inner.chan_write_wakers.retain(|(ch, ext), w| {
                match inner.runner.ready_channel_send(*ch) {
                    Some(n) if n > 0 => {
                        wakers.push(w.clone());
                        false
                    }
                    _ => true
                }
            });

            r
        };
        // lock is dropped before waker or notify

        for w in wakers {
            trace!("woken {w:?}");
            w.wake()
        }

        // TODO: currently this is only woken by incoming data, should it
        // also wake internally from runner or conn? It runs once at start
        // to kick off the outgoing handshake at least.
        if let Ok(None) = res {
            trace!("progress wait");
            self.progress_notify.notified().await;
            trace!("progress awaited");
        }
        res
    }

    pub async fn with_runner<F, R>(&mut self, f: F) -> R
        where F: FnOnce(&mut Runner) -> R {
        let mut inner = self.inner.lock().await;
        f(&mut inner.runner)
    }
}

/// Tries to lock Inner for a poll_read()/poll_write().
/// lock_fut from the caller holds the future so that it can
/// be woken later if the lock was contended
fn poll_lock<'a>(inner: Arc<Mutex<Inner<'a>>>, cx: &mut Context<'_>,
    lock_fut: &mut Option<OwnedMutexLockFuture<Inner<'a>>>)
        -> Poll<OwnedMutexGuard<Inner<'a>>> {
    let mut g = inner.lock_owned();
    let p = Pin::new(&mut g).poll(cx);
    *lock_fut = match p {
        Poll::Ready(_) => None,
        Poll::Pending => Some(g),
    };
    p
}

pub struct AsyncDoorSocket<'a> {
    door: AsyncDoor<'a>,

    read_lock_fut: Option<OwnedMutexLockFuture<Inner<'a>>>,
    write_lock_fut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

impl<'a> AsyncDoorSocket<'a> {
    fn new(door: &AsyncDoor<'a>) -> Self {
        AsyncDoorSocket { door: door.private_clone(),
            read_lock_fut: None, write_lock_fut: None }
    }
}

impl<'a> AsyncRead for AsyncDoorSocket<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        trace!("poll_read");

        let mut p = poll_lock(self.door.inner.clone(), cx, &mut self.read_lock_fut);

        let runner = match p {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => {
                trace!("poll_read pending lock");
                return Poll::Pending
            }
        };

        let b = buf.initialize_unfilled();
        let r = runner.output(b).map_err(|e| IoError::new(ErrorKind::Other, e));

        match r {
            Ok(0) => {
                trace!("set output waker");
                runner.set_output_waker(cx.waker().clone());
                Poll::Pending
            }
            Ok(sz) => {
                trace!("{:?}", (&b[..sz]).hex_dump());
                buf.advance(sz);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<'a> AsyncWrite for AsyncDoorSocket<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        trace!("poll_write");

        let mut p = poll_lock(self.door.inner.clone(), cx, &mut self.write_lock_fut);

        let runner = match p {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => {
                trace!("poll_write pending lock");
                return Poll::Pending;
            }
        };

        // TODO: should runner just have poll_write/poll_read?
        // TODO: is ready_input necessary? .input() should return size=0
        // if nothing is consumed. Or .input() could return a Poll<Result<usize>>
        let r = if runner.ready_input() {
            let r = runner
                .input(buf)
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            runner.set_input_waker(cx.waker().clone());
            Poll::Pending
        };

        // drop before waking others
        drop(runner);

        if let Poll::Ready(_) = r {
            // TODO: only notify if packet traffic.payload().is_some() ?
            // Though we also are using progress() for other events.
            self.door.progress_notify.notify_one();
            trace!("notify progress");
        }
        r
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), IoError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), IoError>> {
        // TODO
        error!("connection closed");
        Poll::Ready(Ok(()))
    }
}

pub struct ChanInOut<'a> {
    chan: u32,
    door: AsyncDoor<'a>,

    rlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
    wlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

pub struct ChanExtIn<'a> {
    chan: u32,
    ext: u32,
    door: AsyncDoor<'a>,

    rlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

pub struct ChanExtOut<'a> {
    chan: u32,
    ext: u32,
    door: AsyncDoor<'a>,

    wlfut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

impl<'a> ChanInOut<'a> {
    pub(crate) fn new(chan: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, door: door.private_clone(),
            rlfut: None, wlfut: None,
        }
    }
}

impl Clone for ChanInOut<'_> {
    fn clone(&self) -> Self {
        Self {
            chan: self.chan, door: self.door.private_clone(),
            rlfut: None, wlfut: None,
        }
    }
}

impl<'a> ChanExtIn<'a> {
    pub(crate) fn new(chan: u32, ext: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, ext, door: door.private_clone(),
            rlfut: None,
        }
    }
}

impl<'a> AsyncRead for ChanInOut<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        let this = self.deref_mut();
        chan_poll_read(&mut this.door, this.chan, None, cx, buf, &mut this.rlfut)
    }
}

impl<'a> AsyncRead for ChanExtIn<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        let this = self.deref_mut();
        chan_poll_read(&mut this.door, this.chan, Some(this.ext), cx, buf, &mut this.rlfut)
    }
}

// Common for `ChanInOut` and `ChanExtIn`
fn chan_poll_read<'a>(
    door: &mut AsyncDoor<'a>,
    chan: u32,
    ext: Option<u32>,
    cx: &mut Context,
    buf: &mut ReadBuf,
    lock_fut: &mut Option<OwnedMutexLockFuture<Inner<'a>>>,
) -> Poll<Result<(), IoError>> {
    trace!("chan read");

    let mut p = poll_lock(door.inner.clone(), cx, lock_fut);
    let inner = match p {
        Poll::Ready(ref mut i) => i,
        Poll::Pending => {
            return Poll::Pending
        }
    };

    let runner = &mut inner.runner;

    let b = buf.initialize_unfilled();
    let r = runner.channel_input(chan, ext, b)
        .map_err(|e| IoError::new(std::io::ErrorKind::Other, e));

    match r {
        // poll_read() returns 0 on EOF, if the channel isn't eof yet
        // we want to return pending
        Ok(0) if !runner.channel_eof(chan) => {
            let w = cx.waker().clone();
            inner.chan_read_wakers.insert((chan, ext), w);
            Poll::Pending
        }
        Ok(sz) => {
            buf.advance(sz);
            Poll::Ready(Ok(()))
        }
        Err(e) => Poll::Ready(Err(e)),
    }
}

impl<'a> AsyncWrite for ChanInOut<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        let this = self.deref_mut();
        chan_poll_write(&mut this.door, this.chan, None, cx, buf, &mut this.wlfut)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        // perhaps common between InOut and ExtOut?
        todo!("channel poll_shutdown")
    }
}

fn chan_poll_write<'a>(
    door: &mut AsyncDoor<'a>,
    chan: u32,
    ext: Option<u32>,
    cx: &mut Context<'_>,
    buf: &[u8],
    lock_fut: &mut Option<OwnedMutexLockFuture<Inner<'a>>>,
) -> Poll<Result<usize, IoError>> {
    trace!("chan write");

    let mut p = poll_lock(door.inner.clone(), cx, lock_fut);
    let runner = match p {
        Poll::Ready(ref mut i) => &mut i.runner,
        Poll::Pending => return Poll::Pending,
    };

    match runner.channel_send(chan, ext, buf) {
        Ok(Some(l)) if l == 0 => Poll::Pending,
        Ok(Some(l)) => Poll::Ready(Ok(l)),
        // return 0 for EOF
        Ok(None) => Poll::Ready(Ok(0)),
        Err(e) => Poll::Ready(Err(IoError::new(ErrorKind::Other, e))),
    }
}
