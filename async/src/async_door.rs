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
use door::{Runner, Result, Event, ChanEvent, Behaviour};

use pretty_hex::PrettyHex;

#[derive(Debug)]
pub(crate) struct Inner<'a> {
    pub runner: Runner<'a>,

    pub chan_read_wakers: HashMap<(u32, Option<u32>), Waker>,
    pub chan_write_wakers: HashMap<(u32, Option<u32>), Waker>,
}

pub struct AsyncDoor<'a> {
    pub(crate) inner: Arc<Mutex<Inner<'a>>>,

    progress_notify: Arc<TokioNotify>,
}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>) -> Self {
        let chan_read_wakers = HashMap::new();
        let chan_write_wakers = HashMap::new();
        let inner = Arc::new(Mutex::new(Inner { runner,
            chan_read_wakers, chan_write_wakers }));
        let progress_notify = Arc::new(TokioNotify::new());
        Self { inner, progress_notify }
    }

    pub(crate) fn private_clone(&self) -> Self {
        Self { inner: self.inner.clone(),
            progress_notify: self.progress_notify.clone(),
        }
    }

    pub fn socket(&self) -> AsyncDoorSocket<'a> {
        AsyncDoorSocket::new(self)
    }

    /// The `f` closure should return `Some` if the result should be returned
    /// from `progress()`, or `None` to not do that.
    /// XXX better docs, perhaps it won't take a closure anyway
    pub async fn progress(&mut self,
        b: &mut Behaviour<'_>)
        -> Result<()> {
        trace!("progress");
        let mut wakers = Vec::new();

        // scoped lock
        {
            let mut inner = self.inner.lock().await;
            trace!("locked progress");
            let inner = inner.deref_mut();
            inner.runner.progress(b).await?;

            trace!("pre wakers {:?}", inner.chan_read_wakers);
            if let Some(ce) = inner.runner.ready_channel_input() {
                inner.chan_read_wakers.remove(&ce)
                .map(|w| wakers.push(w));
            }
            trace!("pos wakers {:?}", inner.chan_read_wakers);

            // Pending HashMap::drain_filter
            // https://github.com/rust-lang/rust/issues/59618
            // TODO: untested.
            // TODO: fairness? Also it's not clear whether progress notify
            // will always get woken by runner.wake() to update this...
            inner.chan_write_wakers.retain(|(ch, _ext), w| {
                match inner.runner.ready_channel_send(*ch) {
                    Some(n) if n > 0 => {
                        wakers.push(w.clone());
                        false
                    }
                    _ => true
                }
            });
        }

        for w in wakers {
            trace!("woken {w:?}");
            w.wake()
        }

        // // TODO: currently this is only woken by incoming data, should it
        // // also wake internally from runner or conn? It runs once at start
        // // to kick off the outgoing handshake at least.
        trace!("progress wait");
        self.progress_notify.notified().await;
        trace!("progress awaited");

        Ok(())
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
pub(crate) fn poll_lock<'a>(inner: Arc<Mutex<Inner<'a>>>, cx: &mut Context<'_>,
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
        trace!("poll_write {}", buf.len());

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
            trace!("not ready");
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

