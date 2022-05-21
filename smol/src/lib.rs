#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use core::pin::Pin;
use core::task::{Context,Poll};
use pin_utils::pin_mut;
use core::future::Future;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::io::Error as IoError;
use std::io::ErrorKind;

use std::sync::{Arc,Mutex,MutexGuard};

use parking_lot::lock_api::ArcMutexGuard;
use parking_lot::Mutex as ParkingLotMutex;

// TODO
use anyhow::{Context as _, Result, Error, anyhow};

use door_sshproto as door;
use door_sshproto::error::Error as DoorError;
use door_sshproto::{HookResult,HookError,HookQuery};
use door::{Runner, Behaviour};
// use door_sshproto::client::*;

pub struct DoorSession {

}

impl<'a> door::ClientHooks<'a> for DoorSession {
    fn username(&mut self, p: &mut door::ResponseString) -> HookResult<()> {
        // TODO unwrap
        p.push_str("matt").unwrap();
        Ok(())
    }

    fn valid_hostkey(&mut self, key: &door::PubKey) -> HookResult<bool> {
        trace!("valid_hostkey for {key:?}");
        Ok(true)
    }

    fn auth_password(&mut self, pwbuf: &mut door::ResponseString) -> HookResult<bool> {
        let pw = rpassword::prompt_password("password: ").map_err(|e| {
            warn!("read_password failed {e:}");
            HookError::Fail
        })?;
        if pwbuf.push_str(&pw).is_err() {
            Err(HookError::Fail)
        } else {
            Ok(true)
        }
    }

    fn authenticated(&mut self) -> HookResult<()> {
        info!("Authentication succeeded");
        Ok(())
    }

}

pub struct Inner<'a> {
    runner: Runner<'a>,

}

struct LockFut<'a> {
    locked_inner: Option<ArcMutexGuard<parking_lot::RawMutex, Inner<'a>>>,
}

struct AsyncBehaviour {
    pub async fn username() -> ResponseString {
        let s = ResponseString::new();
        s.push_str("matt");
        s
    }

}

pub struct AsyncDoor<'a> {
    inner: Arc<ParkingLotMutex<Inner<'a>>>,
    out_progress_fut: Option<Pin<Box<dyn Future<Output = Result<(), DoorError>> + Send + 'a>>>,
    behaviour: door::Behaviour,
}

impl Clone for AsyncDoor<'_> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            behaviour: Behaviour::default(),
            out_progress_fut: None,
        }
    }
}

impl<'a> AsyncDoor<'a> {
    pub fn new(runner: Runner<'a>) -> Self {
        let inner = Inner {
            runner,
        };
        Self {
            inner: Arc::new(ParkingLotMutex::new(inner)),
            behaviour: Behaviour::default(),
            out_progress_fut: None,
        }
    }

    pub fn next_request(&'a self) -> MailboxMutexFut<'a> {
        trace!("next_req");
        MailboxMutexFut { mbox: &self.inner }
    }

    pub fn reply_request(&self, reply: HookResult<HookQuery>) -> Result<(), DoorError> {
        debug!("reply {reply:?}");
        let runner = &mut self.lock()?.runner;
        runner.hook_reply().set(reply);
        Ok(())
    }

    fn lock(&self) -> Result<parking_lot::MutexGuard<Inner<'a>>, DoorError> {
        // trace!("lock");
        Ok(self.inner.lock())
        // .map_err(|_| DoorError::bug())
    }
}

pub struct MailboxMutexFut<'a> {
    mbox: &'a ParkingLotMutex<Inner<'a>>,
}

impl<'a> Future for MailboxMutexFut<'a> {
    type Output = HookQuery;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // trace!("mailmutex top");
        let mut m = self.get_mut().mbox.lock();
        let r = m.runner.hook_query().poll_get(cx.waker().clone());
        // trace!("mailmutex done {r:?}");
        // trace!("mailmutex q {:?}", m.hook_query());
        r
    }
}

// struct RequestStream {
// }

// impl Stream for async_dup::Mutex<AsyncDoor<'_>> {
//     type Item = door::HookMailbox;
//     fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {


//     }
// }



impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &mut ReadBuf) -> Poll<Result<(), IoError>>
    {
        trace!("poll_read");

        let r = if let Some(f) = self.out_progress_fut.as_mut() {
            f.as_mut().poll(cx)
        } else {
            let mut inner = ParkingLotMutex::lock_arc(&self.inner);
            // TODO: should this be conditional on the result of the poll?
            inner.runner.set_output_waker(cx.waker().clone());
            // async move block to capture `inner`
            let mut b = Box::pin(async move {
                inner.runner.out_progress().await
            });
            // let mut b = Box::pin(guard_wait(inner));
            let r = b.as_mut().poll(cx);
            if let Poll::Pending = r {
                self.out_progress_fut = Some(b);
            }
            r
            // self.out_progress_fut = Some(
            // self.out_progress_fut.as_mut().as_mut().unwrap()

        };
        if let Poll::Pending = r {
            return Poll::Pending
        }

        let runner = &mut self.inner.lock().runner;

        let b = buf.initialize_unfilled();
        let r = runner.output(b)
        .map_err(|e| IoError::new(ErrorKind::Other, e));

        let r = match r {
            // sz=0 means EOF
            Ok(0) => Poll::Pending,
            Ok(sz) => {
                buf.advance(sz);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        };
        info!("finish poll_read {r:?}");
        r
    }
}

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &[u8]) -> Poll<Result<usize, IoError>>
    {
        // trace!("poll_write");
        let runner = &mut self.lock()
            .map_err(|e| IoError::new(ErrorKind::Other, e))?
            .runner;
        // trace!("poll_write got lock");
        // trace!("write size {}", buf.len());
        runner.set_input_waker(cx.waker().clone());
        // TODO: should runner just have poll_write/poll_read?
        // TODO: is ready_input necessary? .input() should return size=0
        // if nothing is consumed. Or .input() could return a Poll<Result<usize>>
        let r = if runner.ready_input() {
            let r = runner.input(buf)
            .map_err(|e| IoError::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            Poll::Pending
        };
        // trace!("poll_write {r:?}");
        r
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>)
    -> Poll<Result<(), IoError>>
    {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>)
    -> Poll<Result<(), IoError>>
    {
        todo!("poll_close")
    }
}