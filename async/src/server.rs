#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use snafu::{prelude::*, Whatever};

use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use std::io::Error as IoError;
use std::io::ErrorKind;

use core::pin::Pin;
use core::task::{Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};

use crate::async_channel::*;
use crate::async_sunset::*;
use crate::*;

use sunset::config::*;
use sunset::sshnames::SSH_EXTENDED_DATA_STDERR;
use sunset::{ServBehaviour, Behaviour, Result, Runner};

pub struct SSHServer<'a> {
    sunset: AsyncSunset<'a>,
}

impl<'a> SSHServer<'a> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        b: &mut (dyn ServBehaviour + Send),
        ) -> Result<Self> {
        let runner = Runner::new_server(inbuf, outbuf, b)?;
        let sunset = AsyncSunset::new(runner);
        Ok(Self { sunset })
    }

    pub fn socket(&self) -> AsyncSunsetSocket<'a> {
        self.sunset.socket()
    }

    pub async fn progress(
        &mut self,
        b: &mut (dyn ServBehaviour + Send),
    ) -> Result<()>
    {
        let mut b = Behaviour::new_server(b);
        self.sunset.progress(&mut b).await
    }

    pub async fn channel(&mut self, ch: u32) -> Result<(ChanInOut<'a>, Option<ChanExtOut<'a>>)> {
        let ty = self.sunset.with_runner(|r| r.channel_type(ch)).await?;
        let inout = ChanInOut::new(ch, &self.sunset);
        // TODO ext
        let ext = None;
        Ok((inout, ext))
    }
}
