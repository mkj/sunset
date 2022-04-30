#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::Vec;

use crate::conn::RespPackets;
use crate::packets::Packet;
use crate::*;
use crate::sshnames::*;
use crate::sign::SignKey;

enum ReqType<'a> {
    None,
    Password,
    PubKey(&'a SignKey),
}

pub(crate) struct CliAuth<'a> {
    username: &'a str,
    started: bool,

    last_req: ReqType<'a>,
}

impl<'a> CliAuth<'a> {
    pub fn new() -> Self {
        CliAuth {
            started: false,
            username: "matt", // TODO. also this username length counts towards packet buffer size limit
            last_req: ReqType::None,
        }
    }

    pub fn start(&mut self, resp: &mut RespPackets<'a>) -> Result<()> {
        if !self.started {
            self.started = true;
            resp.push(Packet::ServiceRequest(
                packets::ServiceRequest { name: SSH_SERVICE_USERAUTH })).trap()?;
            resp.push(Packet::UserauthRequest(
                packets::UserauthRequest {
                    username: self.username,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::None,
                })).trap()?;
            self.last_req = ReqType::None;
        }
        Ok(())
    }

    fn try_password(&self) -> Packet<'a> {
        let mut pw = String::new();

        std::io::stdin().read_line(&mut pw).unwrap_or(0);
        Packet::UserauthRequest(
            packets::UserauthRequest {
                username: self.username,
                service: SSH_SERVICE_CONNECTION,
                method: packets::AuthMethod::Password(packets::MethodPassword
                    { change: false, password: &pw } ) } )
    }

    pub fn failure(&mut self, failure: &packets::UserauthFailure,
        resp: &mut RespPackets<'a>) -> Result<()> {
        // match self.last_req {
        //     ReqType::PubKey(k) => {
        //         // TODO: remove k from the list
        //         Ok(())
        //     }
        //     _ => { Ok(()) }
        // }

        if failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)? {
            resp.push(self.try_password());
        }
        Ok(())
    }

    pub fn success(&mut self, success: &packets::UserauthSuccess) -> Result<()> {
        Ok(())
    }
}
