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
use crate::async_door::*;
use crate::*;

use door::config::*;
use door::sshnames::SSH_EXTENDED_DATA_STDERR;
use door::{ServBehaviour, Behaviour, Result, Runner};
use door_sshproto as door;

pub struct SSHServer<'a> {
    door: AsyncDoor<'a>,
}

impl<'a> SSHServer<'a> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        b: &mut (dyn ServBehaviour + Send),
        ) -> Result<Self> {
        let runner = Runner::new_server(inbuf, outbuf, b)?;
        let door = AsyncDoor::new(runner);
        Ok(Self { door })
    }

    pub fn socket(&self) -> AsyncDoorSocket<'a> {
        self.door.socket()
    }

    pub async fn progress(
        &mut self,
        b: &mut (dyn ServBehaviour + Send),
    ) -> Result<()>
    {
        let mut b = Behaviour::new_server(b);
        self.door.progress(&mut b).await
    }

    pub async fn channel(&mut self, ch: u32) -> Result<(ChanInOut<'a>, Option<ChanExtOut<'a>>)> {
        let ty = self.door.with_runner(|r| r.channel_type(ch)).await?;
        let inout = ChanInOut::new(ch, &self.door);
        // TODO ext
        let ext = None;
        Ok((inout, ext))
    }
}
