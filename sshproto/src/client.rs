#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;

use crate::{*, packets::ChannelOpen};
use packets::{Packet, PubKey};
use sshnames::*;
use cliauth::CliAuth;
use conn::RespPackets;
use sign::SignKey;
use behaviour::CliBehaviour;
use heapless::String;

pub struct Client {
    pub(crate) auth: CliAuth,
}

impl Client {
    pub fn new() -> Result<Self> {
        Ok(Client {
            auth: CliAuth::new(),
        })
    }

    // pub fn check_hostkey(hostkey: )

    pub(crate) async fn auth_success(&mut self, resp: &mut RespPackets<'_>, b: &mut CliBehaviour<'_>) -> Result<()> {
        resp.push(Packet::ServiceRequest(
            packets::ServiceRequest { name: SSH_SERVICE_CONNECTION } ).into()).trap()?;
        self.auth.success(b).await
    }

    pub(crate) async fn banner(&mut self, banner: &packets::UserauthBanner<'_>, b: &mut CliBehaviour<'_>) {
        b.show_banner(banner.message, banner.lang);
    }
}

pub struct ClientHandle {
    pub(crate) open_session: bool,
    pub(crate) pty: bool,
}

impl ClientHandle {
    pub(crate) fn new() -> Self {
        Self {
            open_session: false,
            pty: false,
        }
    }

    pub fn open_session(&mut self, pty: bool) -> Result<()> {
        if self.open_session {
            return Err(Error::Custom { msg: "Only one session can be opened per callback" })
        }
        self.open_session = true;
        self.pty = pty;
        Ok(())
    }

}
