#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use futures_io::{AsyncRead, AsyncWrite};
use core::pin::Pin;
use core::task::{Context,Poll};

// TODO
use anyhow::{Context as _, Result, Error};

use door_sshproto as door;
use door_sshproto::error::Error as DoorError;
// use door_sshproto::client::*;

pub struct DoorSession {

}

impl<'a> door::ClientHooks<'a> for DoorSession {
    fn username(&self) -> Result<door::ResponseString, DoorError> {
        let mut p = door::ResponseString::new();
        // TODO unwrap
        p.push_str("matt").unwrap();
        Ok(p)
    }

    fn valid_hostkey(&mut self, hostname: &str, key: &door::PubKey<'a>) -> Result<bool, door::Error> {
        return Ok(true)
    }

    fn authenticated(&mut self) {
        info!("Authentication succeeded")
    }

}


pub struct AsyncDoor<'a> {
    pub runner: door_sshproto::Runner<'a>,
}

impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &mut [u8]) -> Poll<Result<usize, futures_io::Error>>
    {
        if self.runner.output_pending() {
            let r = self.runner.output(buf)
            .map_err(|e| futures_io::Error::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            self.runner.set_output_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &[u8]) -> Poll<Result<usize, futures_io::Error>>
    {
        // TODO: should runner just have poll_write/poll_read?
        if self.runner.ready_input() {
            let r = self.runner.input(buf)
            .map_err(|e| futures_io::Error::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            self.runner.set_input_waker(cx.waker().clone());
            Poll::Pending
        }

    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>)
    -> Poll<Result<(), futures_io::Error>>
    {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>)
    -> Poll<Result<(), futures_io::Error>>
    {
        todo!("poll_close")
    }

}
