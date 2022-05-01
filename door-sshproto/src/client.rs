#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};


use crate::*;
use crate::packets::Packet;
use crate::sshnames::*;
use crate::cliauth::CliAuth;
use crate::conn::RespPackets;

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

    pub fn auth_success(&mut self, resp: &mut RespPackets) -> Result<()> {
        resp.push(Packet::ServiceRequest(
            packets::ServiceRequest { name: SSH_SERVICE_CONNECTION } )).trap()?;
        Ok(())
    }


    pub fn banner(&mut self, banner: &packets::UserauthBanner) {
        info!("Got banner:\n{}", banner.message);
    }
}
