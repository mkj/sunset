#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::*;
use crate::packets::{ServiceAccept, ServiceRequest};
use crate::servauth::ServAuth;
use crate::sshnames::{SSH_SERVICE_CONNECTION, SSH_SERVICE_USERAUTH};
use traffic::TrafSend;

pub(crate) struct Server {
    pub(crate) auth: ServAuth,
}

impl Server {
    pub fn new(
        ) -> Self {
        Server { auth: ServAuth::new() }
    }

    pub fn service_request(&self, p: &ServiceRequest, s: &mut TrafSend) -> Result<()> {
        let success = match p.name {
            SSH_SERVICE_USERAUTH => true,
            SSH_SERVICE_CONNECTION => self.auth.authed,
            _ => false,
        };
        if success {
            s.send(ServiceAccept { name: p.name })
        } else {
            warn!("Received unexpected service request '{}'", p.name);
            error::SSHProto.fail()
        }
    }
}
