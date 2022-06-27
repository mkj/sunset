#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use snafu::{prelude::*, Whatever};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::unix::AsyncFd;
use std::os::unix::io::{RawFd, FromRawFd};
use std::io::{Read, Write};

use std::io::Error as IoError;
use std::io::ErrorKind;

use core::pin::Pin;
use core::task::{Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};

use crate::*;
use crate::async_door::*;

use door_sshproto as door;
use door::{Behaviour, AsyncCliBehaviour, Runner, Result};
use door::sshnames::SSH_EXTENDED_DATA_STDERR;
use door::config::*;

pub struct SSHClient<'a> {
    door: AsyncDoor<'a>,
}

impl<'a> SSHClient<'a> {
    pub fn new(buf: &'a mut [u8], behaviour: Box<dyn AsyncCliBehaviour+Send>) -> Result<Self> {
        let runner = Runner::new_client(buf)?;
        let b = Behaviour::new_async_client(behaviour);
        let door = AsyncDoor::new(runner, b);
        Ok(Self {
            door
        })
    }

    pub fn socket(&self) -> AsyncDoorSocket<'a> {
        self.door.socket()
    }

    pub async fn progress<F, R>(&mut self, f: F)
        -> Result<Option<R>>
        where F: FnOnce(door::Event) -> Result<Option<R>> {
        self.door.progress(f).await
    }

    // TODO: return a Channel object that gives events like WinChange or exit status
    // TODO: move to SimpleClient or something?
    pub async fn open_client_session_nopty(&mut self, exec: Option<&str>)
    -> Result<(ChanInOut<'a>, ChanExtIn<'a>)> {
        let chan = self.door.with_runner(|runner| {
            runner.open_client_session(exec, None)
        }).await?;

        let cstd = ChanInOut::new(chan, &self.door);
        let cerr = ChanExtIn::new(chan, SSH_EXTENDED_DATA_STDERR, &self.door);
        Ok((cstd, cerr))
    }

    pub async fn open_client_session_pty(&mut self, exec: Option<&str>)
    -> Result<ChanInOut<'a>> {

        // XXX error handling
        let pty = pty::current_pty().expect("pty fetch");

        let chan = self.door.with_runner(|runner| {
            runner.open_client_session(exec, Some(pty))
        }).await?;

        let cstd = ChanInOut::new(chan, &self.door);
        Ok(cstd)
    }
}
