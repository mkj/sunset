#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};


use crate::*;
use crate::cliauth::CliAuth;

pub(crate) struct Client<'a> {
    pub auth: CliAuth<'a>,
}

impl<'a> Client<'a> {
    pub fn new() -> Self {
        Client {
            auth: CliAuth::new(),
        }
    }

    // pub fn check_hostkey(hostkey: )


    pub fn banner(&mut self, banner: &packets::UserauthBanner) {
        info!("Got banner:\n{}", banner.message);
    }
}
