#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::*;
use cliauth::CliAuth;
use packets::ParseContext;

#[derive(Default, Debug)]
pub struct Client {
    pub(crate) auth: CliAuth,
}

impl Client {
    pub(crate) fn auth_success(
        &mut self,
        parse_ctx: &mut ParseContext,
    ) -> DispatchEvent {
        parse_ctx.cli_auth_type = None;
        self.auth.success()
    }
}
