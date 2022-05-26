#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;

use crate::{*, packets::ChannelOpen};
use packets::{Packet, PubKey, ParseContext};
use sshnames::*;
use cliauth::CliAuth;
use conn::RespPackets;
use sign::SignKey;
use behaviour::CliBehaviour;
use heapless::String;

pub(crate) struct Client {
    pub auth: CliAuth,
}

impl Client {
    pub fn new() -> Self {
        Client {
            auth: CliAuth::new(),
        }
    }

    // pub fn check_hostkey(hostkey: )

    pub(crate) async fn auth_success(&mut self, resp: &mut RespPackets<'_>,
        parse_ctx: &mut ParseContext,
        b: &mut CliBehaviour<'_>) -> Result<()> {

        parse_ctx.cli_auth_type = None;
        resp.push(Packet::ServiceRequest(
            packets::ServiceRequest { name: SSH_SERVICE_CONNECTION } ).into()).trap()?;
        self.auth.success(b).await
    }

    pub(crate) async fn banner(&mut self, banner: &packets::UserauthBanner<'_>, b: &mut CliBehaviour<'_>) {
        b.show_banner(banner.message, banner.lang).await
    }
}
