#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use pin_utils::pin_mut;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Notify as TokioNotify;

use std::io::Error as IoError;
use std::io::ErrorKind;

use core::task::Waker;
use std::sync::{Arc, Mutex, MutexGuard};
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

#[derive(Clone)]
pub struct AsyncDoor<'a> {
    inner: Arc<TokioMutex<Inner<'a>>>,

    read_waker: Arc<AtomicWaker>,
    write_waker: Arc<AtomicWaker>,
    progress_notify: Arc<TokioNotify>,
}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>, behaviour: Behaviour<'a>) -> Self {
        let inner = Arc::new(TokioMutex::new(Inner { runner, behaviour }));
        let read_waker = Arc::new(AtomicWaker::new());
        let write_waker = Arc::new(AtomicWaker::new());
        let progress_notify = Arc::new(TokioNotify::new());
        Self { inner, read_waker, write_waker, progress_notify }
    }

    pub async fn progress<F, R>(&mut self, f: F)
        -> Result<Option<R>> where F: FnOnce(door::Event) -> Result<Option<R>> {
        {
            info!("progress top");
            let res = {
                let mut inner = self.inner.lock().await;
                info!("progress locked");
                let inner = inner.deref_mut();
                let ev = inner.runner.progress(&mut inner.behaviour).await.context("progess")?;
                info!("progress ev {ev:?}");
                if let Some(ev) = ev {
                    let r = f(ev);
                    inner.runner.done_payload()?;
                    r
                } else {
                    Ok(None)
                }
            };
            self.read_waker.take().map(|w| w.wake());
            self.write_waker.take().map(|w| w.wake());
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
}

impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        trace!("poll_read");

        // try to lock, or return pending
        self.read_waker.register(cx.waker());
        let mut inner = self.inner.try_lock();
        let runner = if let Ok(ref mut inner) = inner {
            &mut inner.deref_mut().runner
        } else {
            return Poll::Pending
        };

        let b = buf.initialize_unfilled();
        let r = runner.output(b).map_err(|e| IoError::new(ErrorKind::Other, e));

        let r = match r {
            // sz=0 means EOF
            Ok(0) => Poll::Pending,
            Ok(sz) => {
                trace!("{:?}", (&b[..sz]).hex_dump());
                buf.advance(sz);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        };
        drop(inner);
        self.write_waker.take().map(|w| w.wake());
        r
    }
}

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        trace!("poll_write");

        // try to lock, or return pending
        self.write_waker.register(cx.waker());
        let mut inner = self.inner.try_lock();
        let runner = if let Ok(ref mut inner) = inner {
            &mut inner.deref_mut().runner
        } else {
            return Poll::Pending
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
            Poll::Pending
        };
        drop(inner);
        self.progress_notify.notify_one();
        self.read_waker.take().map(|w| w.wake());
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
