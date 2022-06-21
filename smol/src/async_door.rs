use door::sshnames::SSH_EXTENDED_DATA_STDERR;
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

// TODO
use anyhow::{anyhow, Context as _, Error, Result};

use door::{Behaviour, Runner};
use door_sshproto as door;
use door_sshproto::error::Error as DoorError;
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

    read_lock_fut: Option<OwnedMutexLockFuture<Inner<'a>>>,
    write_lock_fut: Option<OwnedMutexLockFuture<Inner<'a>>>,
}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>, behaviour: Behaviour<'a>) -> Self {
        let chan_read_wakers = HashMap::new();
        let chan_write_wakers = HashMap::new();
        let inner = Arc::new(Mutex::new(Inner { runner, behaviour,
            chan_read_wakers, chan_write_wakers }));
        let progress_notify = Arc::new(TokioNotify::new());
        Self { inner, progress_notify, read_lock_fut: None, write_lock_fut: None }
    }

    pub async fn progress<F, R>(&mut self, f: F)
        -> Result<Option<R>>
        where F: FnOnce(door::Event) -> Result<Option<R>> {
        trace!("progress");
        let mut wakers = Vec::new();
        let res = {
            let mut inner = self.inner.lock().await;
            let inner = inner.deref_mut();
            let ev = inner.runner.progress(&mut inner.behaviour).await.context("progess")?;
            let r = if let Some(ev) = ev {
                let r = f(ev);
                inner.runner.done_payload()?;
                r
            } else {
                Ok(None)
            };

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
                if inner.runner.ready_channel_send(*ch, *ext) {
                    wakers.push(w.clone());
                    false
                } else {
                    true
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

    // TODO: return a Channel object that gives events like WinChange or exit status
    // TODO: move to SimpleClient or something?
    pub async fn open_client_session(&mut self, exec: Option<&str>, pty: bool)
    -> Result<(ChanInOut<'a>, ChanExtIn<'a>)> {
        let chan = self.with_runner(|runner| {
            runner.open_client_session(exec, pty)
        }).await?;

        let cstd = ChanInOut::new(chan, &self);
        let cerr = ChanExtIn::new(chan, SSH_EXTENDED_DATA_STDERR, &self);
        Ok((cstd, cerr))
    }

}

impl Clone for AsyncDoor<'_> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(),
            progress_notify: self.progress_notify.clone(),
            read_lock_fut: None,
            write_lock_fut: None,
        }
    }
}


/// Tries to locks Inner for a poll_read()/poll_write().
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

impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        trace!("poll_read");

        let mut p = poll_lock(self.inner.clone(), cx, &mut self.read_lock_fut);

        let runner = match p {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => {
                trace!("poll_read pending lock");
                return Poll::Pending
            }
        };

        runner.set_output_waker(cx.waker().clone());
        let b = buf.initialize_unfilled();
        let r = runner.output(b).map_err(|e| IoError::new(ErrorKind::Other, e));

        match r {
            // poll_read() returning 0 means EOF, we don't want that
            Ok(0) => {
                trace!("set output waker");
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

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        trace!("poll_write");

        let mut p = poll_lock(self.inner.clone(), cx, &mut self.write_lock_fut);

        let runner = match p {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => {
                trace!("poll_write pending lock");
                return Poll::Pending;
            }
        };

        runner.set_input_waker(cx.waker().clone());
        // TODO: should runner just have poll_write/poll_read?
        // TODO: is ready_input necessary? .input() should return size=0
        // if nothing is consumed. Or .input() could return a Poll<Result<usize>>
        let r = if runner.ready_input() {
            let r = runner
                .input(buf)
                .map_err(|e| IoError::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            Poll::Pending
        };

        // drop before waking others
        drop(runner);

        if let Poll::Ready(_) = r {
            // TODO: only notify if packet traffic.payload().is_some() ?
            // Though we also are using progress() for other events.
            self.progress_notify.notify_one();
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
        todo!("poll_close")
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
    fn new(chan: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, door: door.clone(),
            rlfut: None, wlfut: None,
        }
    }
}

impl Clone for ChanInOut<'_> {
    fn clone(&self) -> Self {
        Self {
            chan: self.chan, door: self.door.clone(),
            rlfut: None, wlfut: None,
        }
    }
}

impl<'a> ChanExtIn<'a> {
    fn new(chan: u32, ext: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, ext, door: door.clone(),
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
        // sz=0 means EOF, we don't want that
        Ok(0) => {
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

    let mut p = poll_lock(door.inner.clone(), cx, lock_fut);
    let runner = match p {
        Poll::Ready(ref mut i) => &mut i.runner,
        Poll::Pending => return Poll::Pending,
    };
    todo!()
}
