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
use crate::async_sunset::*;
use crate::async_channel::*;

use sunset::{Behaviour, CliBehaviour, Runner, Result};
use sunset::sshnames::SSH_EXTENDED_DATA_STDERR;
use sunset::config::*;

pub struct SSHClient<'a> {
    sunset: AsyncSunset<'a>,
}

impl<'a> SSHClient<'a> {
    pub fn new(inbuf: &'a mut [u8],
        outbuf: &'a mut [u8]) -> Result<Self> {
        let runner = Runner::new_client(inbuf, outbuf)?;
        let sunset = AsyncSunset::new(runner);
        Ok(Self {
            sunset
        })
    }

    pub fn socket(&self) -> AsyncSunsetSocket<'a> {
        self.sunset.socket()
    }

    /// Takes a closure to run on the "output" of the progress call.
    /// (This output can't be returned directly since it refers
    /// to contents of `Self` and would hit lifetime issues).
    pub async fn progress(&mut self,
        b: &mut (dyn CliBehaviour+Send)) -> Result<()> {

        let mut b = Behaviour::new_client(b);
        self.sunset.progress(&mut b).await
    }

    // TODO: return a Channel object that gives events like WinChange or exit status
    // TODO: move to SimpleClient or something?
    pub async fn open_session_nopty(&mut self, exec: Option<&str>)
    -> Result<(ChanInOut<'a>, ChanExtIn<'a>)> {
        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session(exec, None)
        }).await?;

        let cstd = ChanInOut::new(chan, &self.sunset);
        let cerr = ChanExtIn::new(chan, SSH_EXTENDED_DATA_STDERR, &self.sunset);
        Ok((cstd, cerr))
    }

    pub async fn open_session_pty(&mut self, exec: Option<&str>)
    -> Result<ChanInOut<'a>> {

        // XXX error handling
        let pty = pty::current_pty().expect("pty fetch");

        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session(exec, Some(pty))
        }).await?;

        let cstd = ChanInOut::new(chan, &self.sunset);
        Ok(cstd)
    }
}
