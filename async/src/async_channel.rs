#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::ops::DerefMut;

use std::io::Error as IoError;
use std::io::ErrorKind;
use std::collections::HashMap;

use futures::lock::{Mutex, OwnedMutexLockFuture, OwnedMutexGuard};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::*;
use async_door::{Inner, poll_lock};

pub struct Channel<'a> {
    chan: u32,
    door: AsyncDoor<'a>,
}

impl<'a> Channel<'a> {
    /// Should be called by a SSH client when the local terminal changes size
    /// (`SIGWINCH` is received). Only applicable to client session
    /// channels with a pty.
    pub async fn term_window_change(&self) {
        let wc = match pty::win_size() {
            Ok(wc) => wc,
            Err(e) => {
                warn!("Failed getting window size: {e}");
                return;
            }
        };

        // TODO: also need to wait for spare output buffer
        self.door.inner.lock().await
        .runner.term_window_change(self.chan, wc);
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
    let inner = match p {
        Poll::Ready(ref mut i) => i,
        Poll::Pending => return Poll::Pending,
    };
    let runner = &mut inner.runner;

    match runner.channel_send(chan, ext, buf) {
        Ok(Some(l)) if l == 0 => {
            inner.chan_write_wakers.insert((chan, ext), cx.waker().clone());
            Poll::Pending
        }
        Ok(Some(l)) => Poll::Ready(Ok(l)),
        // return 0 for EOF
        Ok(None) => Poll::Ready(Ok(0)),
        Err(e) => Poll::Ready(Err(IoError::new(ErrorKind::Other, e))),
    }
}
