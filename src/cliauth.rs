#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use no_panic::no_panic;
use pretty_hex::PrettyHex;


use crate::{packets::UserauthPkOk, *};
use behaviour::CliBehaviour;
use traffic::TrafSend;
use client::*;
use packets::{MessageNumber, AuthMethod, MethodPubKey, ParseContext, UserauthRequest};
use packets::{Packet, Signature, Userauth60};
use sign::{SignKey, OwnedSig};
use sshnames::*;
use sshwire::{BinString, Blob};
use kex::SessId;
use auth::AuthType;

// pub for packets::ParseContext
pub enum Req {
    Password(ResponseString),
    PubKey { key: SignKey },
}

pub(crate) enum AuthState {
    Unstarted,
    MethodQuery,
    Request { last_req: Req, sig: Option<OwnedSig> },
    Idle,
}

impl Req {
    // Creates a packet from the current request
    fn req_packet<'b>(
        &'b self,
        username: &'b str,
        parse_ctx: &mut ParseContext,
    ) -> Result<Packet<'b>> {
        let username = username.into();
        let p = match self {
            Req::PubKey { key, .. } => {
                // already checked by make_pubkey_req()
                parse_ctx.cli_auth_type = Some(AuthType::PubKey);
                packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method: key.pubkey().try_into()?,
                }.into()
            }
            Req::Password(pw) => {
                parse_ctx.cli_auth_type = Some(AuthType::Password);
                packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::Password(packets::MethodPassword {
                        change: false,
                        password: pw.as_str().into(),
                    }),
                }.into()
            }
        };
        Ok(p)
    }
}

pub(crate) struct CliAuth {
    state: AuthState,

    username: ResponseString,

    // Starts as true, set to false if hook.auth_password() returns None.
    // Not set false if the server rejects auth.
    try_password: bool,

    // Set to false if hook.next_authkey() returns None.
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
    pub async fn progress<'b>(
        &'b mut self,
        s: &mut TrafSend<'_, '_>,
        b: &mut dyn CliBehaviour,
    ) -> Result<()> {
        if let AuthState::Unstarted = self.state {
            self.state = AuthState::MethodQuery;
            self.username = b.username()?;

            s.send(packets::ServiceRequest {
                name: SSH_SERVICE_USERAUTH,
            })?;

            s.send(packets::UserauthRequest {
                username: self.username.as_str().into(),
                service: SSH_SERVICE_CONNECTION,
                method: packets::AuthMethod::None,
            })?;
        }
        Ok(())
    }

    async fn make_password_req(
        &mut self,
        b: &mut dyn CliBehaviour,
    ) -> Result<Option<Req>> {
        let mut pw = ResponseString::new();
        match b.auth_password(&mut pw) {
            Err(_) => Err(Error::BehaviourError { msg: "No password returned" }),
            Ok(r) if r => Ok(Some(Req::Password(pw))),
            Ok(_) => Ok(None),
        }
    }

    /// Retrieves the next pubkey to try from Behaviour, and returns the request.
    /// Returns None if none are available. `self.try_pubkey` will be set false
    /// when no more will be available.
    async fn make_pubkey_req(
        &mut self,
        b: &mut dyn CliBehaviour,
    ) -> Option<Req> {
        let k = b.next_authkey().unwrap_or_else(|e| {
            warn!("Error getting pubkey for auth");
            None
        });

        match k {
            Some(key) => {
                if key.is_agent() {
                    warn!("TODO: skipping agent key");
                    None
                } else {
                    Some(Req::PubKey { key })
                }
            }
            None => {
                trace!("stop iterating pubkeys");
                self.try_pubkey = false;
                None
            }
        }
    }

    pub fn auth_sig_msg(
        key: &SignKey,
        sess_id: &SessId,
        p: &Packet,
        b: &mut dyn CliBehaviour,
    ) -> Result<OwnedSig> {
        if let Packet::UserauthRequest(UserauthRequest {
            username,
            service,
            method: AuthMethod::PubKey(MethodPubKey { sig_algo, pubkey, .. }),
        }) = p
        {
            let sig_packet = UserauthRequest {
                username: *username,
                service,
                method: AuthMethod::PubKey(MethodPubKey {
                    sig_algo,
                    pubkey: pubkey.clone(),
                    sig: None,
                }),
            };

            let msg = auth::AuthSigMsg::new(&sig_packet, sess_id);
            let mut ctx = ParseContext::default();
            ctx.method_pubkey_force_sig_bool = true;
            if key.is_agent() {
                Ok(b.agent_sign(key, &msg)?)
            } else {
                key.sign(&&msg, Some(&ctx))
            }
        } else {
            Err(Error::bug())
        }
    }

    pub async fn auth60(
        &mut self,
        auth60: &packets::Userauth60<'_>,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend<'_, '_>,
        b: &mut dyn CliBehaviour,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;

        match auth60 {
            Userauth60::PkOk(pkok) => self.auth_pkok(pkok, sess_id, parse_ctx, s, b),
            Userauth60::PwChangeReq(_req) => todo!("pwchange"),
        }
    }

    fn auth_pkok(
        &mut self,
        pkok: &UserauthPkOk<'_>,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend<'_, '_>,
        b: &mut dyn CliBehaviour,
    ) -> Result<()> {
        // We are only sending keys one at a time so they shouldn't
        // get out of sync. In future we could change it to send
        // multiple requests pipelined, though unsure of server
        // acceptance of that.
        match &mut self.state {
            // Some tricky logistics to create the signature in self.state
            // using a packet borrowed from other parts of self.state
            AuthState::Request { last_req, ref mut sig } => {
                if sig.is_some() {
                    return Err(Error::SSHProtoError);
                }
                if let Req::PubKey { key, .. } = last_req {
                    if key.pubkey() != pkok.key.0 {
                        return Err(Error::SSHProtoError);
                    }
                }

                let mut p = last_req.req_packet(&self.username, parse_ctx)?;
                let last_req = &last_req;
                if let Req::PubKey { key, .. } = last_req {
                    // Create the signature
                    let new_sig = Self::auth_sig_msg(&key, sess_id, &p, b)?;
                    let rsig = sig.insert(new_sig);

                    // Put it in the packet
                    if let Packet::UserauthRequest(UserauthRequest {
                        method:
                            AuthMethod::PubKey(MethodPubKey {
                                sig: ref mut psig, ..
                            }),
                        ..
                    }) = p
                    {
                        let rsig = &*rsig;
                        *psig = Some(Blob(rsig.into()))
                    }
                    s.send(p)?;
                    return Ok(());
                }
            }
            _ => (),
        }
        trace!("Unexpected userauth60");
        Err(Error::SSHProtoError)
    }

    pub async fn failure(
        &mut self,
        failure: &packets::UserauthFailure<'_>,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend<'_, '_>,
        b: &mut dyn CliBehaviour,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            while self.try_pubkey {
                let req = self.make_pubkey_req(b).await;
                if let Some(req) = req {
                    self.state = AuthState::Request { last_req: req, sig: None };
                    break;
                }
            }
        }

        if matches!(self.state, AuthState::Idle)
            && self.try_password
            && failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)?
        {
            let req = self.make_password_req(b).await?;
            if let Some(req) = req {
                self.state = AuthState::Request { last_req: req, sig: None };
            }
        }

        if !(self.try_pubkey || self.try_password) {
            return Err(Error::BehaviourError {
                msg: "No authentication methods left",
            });
        }

        if let AuthState::Request { last_req, .. } = &self.state {
            let p = last_req.req_packet(&self.username, parse_ctx)?;
            s.send(p)?;
        }
        Ok(())
    }

    pub fn success(&mut self, b: &mut dyn CliBehaviour) -> Result<()> {
        // TODO: check current state? Probably just informational
        self.state = AuthState::Idle;
        let _ = b.authenticated();
        // TODO errors
        Ok(())
    }
}
