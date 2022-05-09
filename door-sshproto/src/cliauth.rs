#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::{String, Vec};
use no_panic::no_panic;

use crate::client::*;
use crate::conn::RespPackets;
use crate::packets::Packet;
use crate::sign::SignKey;
use crate::sshnames::*;
use crate::*;

// pub for packets::ParseContext
pub enum Req<'a> {
    None,
    Password(ResponseString),
    PubKey(&'a SignKey),
}

pub enum AuthState<'a> {
    Unstarted,
    MethodQuery,
    Request { last_req: Req<'a> },
}

pub struct CliAuth<'a> {
    state: AuthState<'a>,

    username: ResponseString,

    // Set once from hooks.auth_keys(), iterates through the key being tried.
    next_pubkey: Option<core::slice::Iter<'a, &'a PubKey<'a>>>,

    // Starts as true, set to false if hook.auth_password() returns `Skip`.
    // Not set false if the server rejects auth.
    try_password: bool,
}

impl<'a> CliAuth<'a> {
    // TODO: take preferred/ordered authmethods
    pub fn new() -> Self {
        CliAuth {
            state: AuthState::Unstarted,
            username: ResponseString::new(),
            next_pubkey: None,
            try_password: true,
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
        }
        Ok(())
    }

    fn send_password(
        &mut self, hooks: &mut dyn ClientHooks,
    ) -> Result<Option<Packet>> {
        let mut pw = ResponseString::new();
        match hooks.auth_password(&mut pw) {
            Err(HookError::Fail) => {
                Err(Error::HookError { msg: "No password returned" })
            }
            Err(HookError::Skip) => Ok(None),
            Ok(()) => {
                self.state = AuthState::Request { last_req: Req::Password(pw) };
                // TODO: zeroize local pw?
                let pw = if let AuthState::Request {
                    last_req: Req::Password(ref mut pw),
                } = self.state
                {
                    pw
                } else {
                    return Error::bug_msg("unreachable");
                };
                Ok(Some(Packet::UserauthRequest(packets::UserauthRequest {
                    username: &self.username,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::Password(packets::MethodPassword {
                        change: false,
                        password: pw,
                    }),
                })))
            }
        }
    }

    // mystery: not quite sure why the 'b lifetime is required
    pub fn failure<'b>(
        &'b mut self, failure: &packets::UserauthFailure,
        hooks: &mut dyn ClientHooks, resp: &mut RespPackets<'b>,
    ) -> Result<()> {
        if self.next_pubkey.is_none() {
            let pubkeys = match hooks.auth_keys() {
                Ok(p) => p,
                Err(HookError::Skip) => &[],
                Err(_) => todo!(),
            };
            // self.next_pubkey = Some(pubkeys.iter());
        }
        // match self.last_req {
        //     Req::PubKey(k) => {
        //         // TODO: remove k from the list
        //         Ok(())
        //     }
        //     _ => { Ok(()) }
        // }

        if failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)? {
            let pw = self.send_password(hooks)?;
            if let Some(pw) = pw {
                resp.push(pw).trap()?;
            } else {
            }
        }
        Ok(())
    }

    pub fn success(&mut self, hooks: &mut dyn ClientHooks) -> Result<()> {
        let r = hooks.authenticated();
        // TODO errors
        Ok(())
    }
}
