use door::sshnames::SSH_EXTENDED_DATA_STDERR;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use pin_utils::pin_mut;

use futures::lock::Mutex;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify as TokioNotify;

use std::io::Error as IoError;
use std::io::ErrorKind;

use core::task::Waker;
use std::sync::Arc;
use futures::task::AtomicWaker;

// TODO
use anyhow::{anyhow, Context as _, Error, Result};
use core::ops::DerefMut;

use door::{Behaviour, Runner};
use door_sshproto as door;
use door_sshproto::error::Error as DoorError;
// use door_sshproto::client::*;
use async_trait::async_trait;

use pretty_hex::PrettyHex;

pub struct Inner<'a> {
    runner: Runner<'a>,
    // TODO: perhaps behaviour can move to runner? unsure of lifetimes.
    behaviour: Behaviour<'a>,
}

pub struct AsyncDoor<'a> {
    // Not contended much since the Runner is inherently single threaded anyway,
    // using a single buffer for input/output.
    inner: Arc<Mutex<Inner<'a>>>,

    progress_notify: Arc<TokioNotify>,
}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>, behaviour: Behaviour<'a>) -> Self {
        let inner = Arc::new(Mutex::new(Inner { runner, behaviour }));
        let progress_notify = Arc::new(TokioNotify::new());
        Self { inner, progress_notify }
    }

    pub fn clone(&'_ self) -> Self {
        Self { inner: self.inner.clone(),
            progress_notify: self.progress_notify.clone() }
    }

    pub async fn progress<F, R>(&mut self, f: F)
        -> Result<Option<R>>
        where F: FnOnce(door::Event) -> Result<Option<R>> {
        {
            let res = {
                let mut inner = self.inner.lock().await;
                let inner = inner.deref_mut();
                let ev = inner.runner.progress(&mut inner.behaviour).await.context("progess")?;
                if let Some(ev) = ev {
                    let r = f(ev);
                    inner.runner.done_payload()?;
                    r
                } else {
                    Ok(None)
                }
            };
            // TODO: currently this is only woken by incoming data, should it
            // also wake internally from runner or conn? It runs once at start
            // to kick off the outgoing handshake at least.
            if let Ok(None) = res {
                self.progress_notify.notified().await;
            }
            res
        }
    }

    pub async fn with_runner<F, R>(&mut self, f: F) -> R
        where F: FnOnce(&mut Runner) -> R {
        let mut inner = self.inner.lock().await;
        f(&mut inner.runner)
    }

    // fn channel_poll_read(
    //     self: Pin<&mut Self>,
    //     cx: &mut Context<'_>,
    //     buf: &mut ReadBuf,

    pub async fn open_client_session(&mut self, exec: Option<&str>, pty: bool)
    -> Result<(ChanInOut<'a>, ChanExtIn<'a>)> {
        let chan = self.with_runner(|runner| {
            runner.open_client_session(exec, pty)
        }).await?;

        let door = self.clone();
        let cstd = ChanInOut { door, chan };
        let door = self.clone();
        let cerr = ChanExtIn { door, chan, ext: SSH_EXTENDED_DATA_STDERR };
        Ok((cstd, cerr))
    }

}

impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        trace!("poll_read");

        // TODO: can this go into a common function returning a Poll<MappedMutexGuard<Runner>>?
        //  Lifetimes seem tricky.
        let g = self.inner.lock();
        pin_mut!(g);
        let mut g = g.poll(cx);
        let runner = match g {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => return Poll::Pending,
        };

        let b = buf.initialize_unfilled();
        let r = runner.output(b).map_err(|e| IoError::new(ErrorKind::Other, e));

        match r {
            // sz=0 means EOF, we don't want that
            Ok(0) => {
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

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        trace!("poll_write");

        let g = self.inner.lock();
        pin_mut!(g);
        let mut g = g.poll(cx);
        let runner = match g {
            Poll::Ready(ref mut i) => &mut i.runner,
            Poll::Pending => return Poll::Pending,
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
}

pub struct ChanExtIn<'a> {
    chan: u32,
    ext: u32,
    door: AsyncDoor<'a>,
}

pub struct ChanExtOut<'a> {
    chan: u32,
    ext: u32,
    door: AsyncDoor<'a>,
}

impl<'a> ChanInOut<'a> {
    fn new(chan: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, door: door.clone(),
        }
    }
}

impl<'a> ChanExtIn<'a> {
    fn new(chan: u32, ext: u32, door: &AsyncDoor<'a>) -> Self {
        Self {
            chan, ext, door: door.clone(),
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
        chan_poll_read(&mut this.door, this.chan, None, cx, buf)
    }
}

impl<'a> AsyncRead for ChanExtIn<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        let this = self.deref_mut();
        chan_poll_read(&mut this.door, this.chan, Some(this.ext), cx, buf)
    }
}

// Common for `ChanInOut` and `ChanExtIn`
fn chan_poll_read(
    door: &mut AsyncDoor,
    chan: u32,
    ext: Option<u32>,
    cx: &mut Context,
    buf: &mut ReadBuf,
) -> Poll<Result<(), IoError>> {

    error!("chan_poll_read {chan} {ext:?}");

    let g = door.inner.lock();
    pin_mut!(g);
    let mut g = g.poll(cx);
    let runner = match g {
        Poll::Ready(ref mut i) => &mut i.runner,
        Poll::Pending => {
            trace!("lock pending");
            return Poll::Pending
        }
    };

    trace!("chan_poll_read locked");

    let b = buf.initialize_unfilled();
    let r = runner.channel_input(chan, ext, b)
        .map_err(|e| IoError::new(std::io::ErrorKind::Other, e));

    match r {
        // sz=0 means EOF, we don't want that
        Ok(0) => {
            runner.set_output_waker(cx.waker().clone());
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
        chan_poll_write(&mut this.door, this.chan, None, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        // perhaps common between InOut and ExtOut?
        todo!("channel poll_shutdown")
    }
}

fn chan_poll_write(
    door: &mut AsyncDoor,
    chan: u32,
    ext: Option<u32>,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<Result<usize, IoError>> {

    let mut g = door.inner.lock();
    pin_mut!(g);
    let runner = match g.poll(cx) {
        Poll::Ready(ref mut i) => &mut i.runner,
        Poll::Pending => return Poll::Pending,
    };
    todo!()
}
