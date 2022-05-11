#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::{String, Vec};
use no_panic::no_panic;

use crate::client::*;
use crate::conn::RespPackets;
use crate::packets::{Packet, Signature};
use crate::sign::SignKey;
use crate::sshnames::*;
use crate::*;

// pub for packets::ParseContext
pub enum Req {
    None,
    Password(ResponseString),
    PubKey(SignKey),
}

pub enum AuthState {
    Unstarted,
    MethodQuery,
    Request { last_req: Req },
    Idle,
}

pub struct CliAuth {
    state: AuthState,

    username: ResponseString,

    // Starts as true, set to false if hook.auth_password() returns None.
    // Not set false if the server rejects auth.
    try_password: bool,

    // Set to false if hook.next_pubkey() returns None.
    try_pubkey: bool,
}

impl CliAuth {
    // TODO: take preferred/ordered authmethods
    pub fn new() -> Self {
        CliAuth {
            state: AuthState::Unstarted,
            username: ResponseString::new(),
            try_password: true,
            try_pubkey: true,
        }
    }

    // May be called multiple times
    pub fn start<'b>(
        &'b mut self, hooks: &mut dyn ClientHooks, resp: &mut RespPackets<'b>,
    ) -> Result<()> {
        if let AuthState::Unstarted = self.state {
            hooks
                .username(&mut self.username)
                .map_err(|_| Error::HookError { msg: "no username provided" })?;

            self.state = AuthState::MethodQuery;
            resp.push(Packet::ServiceRequest(packets::ServiceRequest {
                name: SSH_SERVICE_USERAUTH,
            }))
            .trap()?;
            resp.push(Packet::UserauthRequest(packets::UserauthRequest {
                username: &self.username,
                service: SSH_SERVICE_CONNECTION,
                method: packets::AuthMethod::None,
            }))
            .trap()?;
            trace!("{resp:#?}");
        }
        Ok(())
    }

    fn make_password_req(&mut self, hooks: &mut dyn ClientHooks) -> Result<Option<Req>> {
        let mut pw = ResponseString::new();
        match hooks.auth_password(&mut pw) {
            Err(_) => Err(Error::HookError { msg: "No password returned" }),
            Ok(r) if r => Ok(Some(Req::Password(pw))),
            Ok(_) => Ok(None),
        }
    }

    fn make_pubkey_req(&mut self, hooks: &mut dyn ClientHooks) -> Result<Option<Req>> {
        let pk = hooks.next_authkey().map_err(|_| {
            self.try_pubkey = false;
            Error::HookError { msg: "next_pubkey failed TODO" }
        })?;
        let pk = pk.map(|pk| Req::PubKey(pk));
        if pk.is_none() {
            self.try_pubkey = false;
        }
        Ok(pk)
    }

    // Creates a packet from the current request
    fn req_packet(&self) -> Result<Packet> {
        if let AuthState::Request { last_req: req } = &self.state {
            match req {
                Req::PubKey(key) => {
                    let mut pubmethod = packets::MethodPubKey {
                        sig_algo: "",
                        pubkey: key.pubkey(),
                        sig: None,
                    };
                    // already checked by make_pubkey_req()
                    pubmethod.sig_algo =
                        Signature::sig_algorithm_name_for_pubkey(&pubmethod.pubkey).trap()?;
                    Ok(Packet::UserauthRequest(packets::UserauthRequest {
                        username: &self.username,
                        service: SSH_SERVICE_CONNECTION,
                        method: packets::AuthMethod::PubKey(pubmethod) }))
                }
                Req::Password(pw) => {
                    // let pw = if let AuthState::Request {
                    //     last_req: Req::Password(ref mut pw),
                    // } = self.state
                    // {
                    //     pw
                    // } else {
                    //     return Error::bug_msg("unreachable");
                    // };
                    Ok(Packet::UserauthRequest(packets::UserauthRequest {
                        username: &self.username,
                        service: SSH_SERVICE_CONNECTION,
                        method: packets::AuthMethod::Password(packets::MethodPassword {
                            change: false,
                            password: pw,
                        }),
                    }))
                }
                _ => todo!()
            }
        } else {
            Err(Error::bug())
        }
    }

    // mystery: not quite sure why the 'b lifetime is required
    pub fn failure<'b>(
        &'b mut self, failure: &packets::UserauthFailure,
        hooks: &mut dyn ClientHooks, resp: &mut RespPackets<'b>,
    ) -> Result<()> {
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            while self.try_pubkey {
                let req = self.make_pubkey_req(hooks)?;
                if let Some(req) = req {
                    self.state = AuthState::Request { last_req: req };
                    break;
                }
            }
        }

        if matches!(self.state, AuthState::Idle)
            && self.try_password
            && failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)? {
            let req = self.make_password_req(hooks)?;
            if let Some(req) = req {
                self.state = AuthState::Request { last_req: req };
            }
        }

        if !(self.try_pubkey || self.try_password) {
            return Err(Error::HookError { msg: "No authentication methods left" })
        }

        if let AuthState::Request { last_req: req } = &self.state {
            let p = self.req_packet()?;
            resp.push(p).trap()?;
        }
        Ok(())
    }

    pub fn success(&mut self, hooks: &mut dyn ClientHooks) -> Result<ClientHandle> {
        // TODO: check current state? Probably just informational
        self.state = AuthState::Idle;
        let mut handle = client::ClientHandle::new();
        let _ = hooks.authenticated(&mut handle);
        // TODO errors
        Ok(handle)
    }
}
