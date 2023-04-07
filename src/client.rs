#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;

use crate::{packets::ChannelOpen, *};
use behaviour::CliBehaviour;
use cliauth::CliAuth;
use heapless::String;
use packets::{Packet, ParseContext, PubKey};
use sign::SignKey;
use sshnames::*;
use traffic::TrafSend;

pub(crate) struct Client {
    pub auth: CliAuth,
}

impl Client {
    pub fn new() -> Self {
        Client { auth: CliAuth::new() }
    }

    pub(crate) fn auth_success(
        &mut self,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
        b: &mut impl CliBehaviour,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;

        // github.com doesn't like this, openssh doesn't send it
        // s.send(packets::ServiceRequest { name: SSH_SERVICE_CONNECTION })?;

        self.auth.success(b)
    }

    pub(crate) fn banner(
        &mut self,
        banner: &packets::UserauthBanner<'_>,
        b: &mut impl CliBehaviour,
    ) {
        b.show_banner(banner.message, banner.lang)
    }
}
