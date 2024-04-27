use self::{conn::DispatchEvent, event::{CliEvent, CliEventId}};

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use pretty_hex::PrettyHex;


use crate::{packets::UserauthPkOk, *};
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
enum Req {
    // TODO replace Req with something else
    Password(String<30>),
    PubKey { key: SignKey },
}

enum AuthState {
    Unstarted,
    MethodQuery,
    Request { last_req: Req },
    Idle,
}

impl Req {
    // Creates a packet from the current request
    // parse_ctx.cli_auth_type will be updated
    // sig is an optional signature for pubkey auth
    fn req_packet<'b>(
        &'b self,
        username: &'b str,
        parse_ctx: &mut ParseContext,
        sig: Option<&'b OwnedSig>,
    ) -> Result<Packet<'b>> {

        let username = username.into();
        let p = match self {
            Req::PubKey { key, .. } => {
                // already checked by make_pubkey_req()
                parse_ctx.cli_auth_type = Some(AuthType::PubKey);
                let method = AuthMethod::PubKey(MethodPubKey::new(key.pubkey(), sig)?);
                packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method,
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

    username: String<{config::MAX_USERNAME}>,

    /// Starts as true, set to false if hook.auth_password() returns None.
    /// Not set false if the server rejects auth.
    try_password: bool,

    /// Set to false if hook.next_authkey() returns None.
    try_pubkey: bool,

    /// Set once we are OKed from MSG_EXT_INFO
    allow_rsa_sha2: bool,
}

impl CliAuth {
    // TODO: take preferred/ordered authmethods
    pub fn new() -> Self {
        CliAuth {
            state: AuthState::Unstarted,
            username: String::new(),
            try_password: true,
            try_pubkey: true,
            allow_rsa_sha2: false,
        }
    }

    // May be called multiple times
    pub fn progress(&mut self) -> DispatchEvent {
        if let AuthState::Unstarted = self.state {
            self.state = AuthState::MethodQuery;
            DispatchEvent::CliEvent(event::CliEventId::Username)
            // continued in resume_username()
        } else {
            Default::default()
        }
    }

    pub fn resume_username(&mut self, s: &mut TrafSend, username: &str) -> Result<()> {
        // TODO; error handling
        self.username = username.try_into().map_err(|_| Error::msg("Username too long"))?;
        s.send(packets::ServiceRequest {
            name: SSH_SERVICE_USERAUTH,
        })?;

        s.send(packets::UserauthRequest {
            username: self.username.as_str().into(),
            service: SSH_SERVICE_CONNECTION,
            method: packets::AuthMethod::None,
        })?;
        Ok(())

    }

    /// Retrieves the next pubkey to try, and returns the request.
    /// Returns None if none are available. `self.try_pubkey` will be set false
    /// when no more will be available.
    fn make_pubkey_req(
        &mut self,
    ) -> Option<Req> {
        #[allow(clippy::never_loop)]
        loop {
            todo!("event req");
            let k = None;
            // let k = b.next_authkey().unwrap_or_else(|_| {
            //     warn!("Error getting pubkey for auth");
            //     None
            // });

            match k {
                Some(key) => {
                    #[cfg(feature = "rsa")]
                    match key {
                        SignKey::RSA(_) | SignKey::AgentRSA(_) => {
                            if !self.allow_rsa_sha2 {
                                trace!("Skipping rsa key, no ext-info");
                                continue
                            }
                        }
                        _ => (),
                    }

                    break Some(Req::PubKey { key })
                }
                None => {
                    trace!("stop iterating pubkeys");
                    self.try_pubkey = false;
                    break None
                }
            }
        }
    }

    pub fn auth_sig_msg(
        key: &SignKey,
        sess_id: &SessId,
        p: &Packet<'_>,
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
                    force_sig: true,
                }),
            };

            let msg = auth::AuthSigMsg::new(&sig_packet, sess_id);
            key.sign(&&msg)
            // todo event
            // NO ASYNC
            // if key.is_agent() {
            //     Ok(b.agent_sign(key, &msg).await?)
            // } else {
            //     key.sign(&&msg)
            // }
        } else {
            Err(Error::bug())
        }
    }

    pub fn auth60(
        &mut self,
        auth60: &packets::Userauth60,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;

        match auth60 {
            Userauth60::PkOk(pkok) => self.auth_pkok(pkok, sess_id, parse_ctx, s),
            Userauth60::PwChangeReq(_req) => self.change_password(),
        }
    }

    fn auth_pkok(
        &mut self,
        pkok: &UserauthPkOk,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<()> {
        match &mut self.state {
            AuthState::Request { last_req } => {
                if let Req::PubKey { ref key } = last_req {
                    if key.pubkey() != pkok.key.0 {
                        trace!("Received pkok for a different key");
                        return Err(Error::SSHProtoError);
                    }

                    // Sign the packet without the signature
                    let p = last_req.req_packet(&self.username, parse_ctx, None)?;
                    todo!("event sig");
                    // let new_sig = Self::auth_sig_msg(key, sess_id, &p, b)?;
                    // let p = last_req.req_packet(&self.username, parse_ctx, Some(&new_sig))?;

                    // s.send(p)?;
                    return Ok(());
                }
            }
            _ => (),
        }
        trace!("Unexpected userauth60");
        Err(Error::SSHProtoError)
    }

    fn change_password(&self) -> Result<()> {
        // Doesn't seem to be widely implemented, we'll just fail.
        Err(Error::msg("Password has expired"))
    }

    pub fn failure(
        &mut self,
        failure: &packets::UserauthFailure,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        parse_ctx.cli_auth_type = None;
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            while self.try_pubkey {
                // TODO event
                self.try_pubkey = false;
                let req = None; // TODO
                // let req = self.make_pubkey_req(b);
                if let Some(req) = req {
                    self.state = AuthState::Request { last_req: req };
                    break;
                }
            }
        }

        if matches!(self.state, AuthState::Idle)
            && self.try_password
            && failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)?
        {
            return Ok(DispatchEvent::CliEvent(event::CliEventId::Password))
        }

        if let AuthState::Request { last_req, .. } = &self.state {
            let p = last_req.req_packet(&self.username, parse_ctx, None)?;
            s.send(p)?;
        } else {
            todo!("no more auth methods left");
        }
        Ok(DispatchEvent::None)
    }

    pub fn resume_password(&mut self, s: &mut TrafSend, password: &str,
        parse_ctx: &mut ParseContext) -> Result<()> {
        // TODO; error handling
        let req = match password.try_into() {
            Ok(p) => Req::Password(p),
            Err(_) => return error::BadUsage.fail(),
        };
        let p = req.req_packet(&self.username, parse_ctx, None)?;
        s.send(p)?;
        self.state = AuthState::Request { last_req: req };
        Ok(())
    }

    pub fn success(&mut self) -> DispatchEvent {
        // TODO: check current state? Probably just informational
        self.state = AuthState::Idle;
        DispatchEvent::CliEvent(CliEventId::Authenticated)
    }

    pub fn handle_ext_info(&mut self, p: &packets::ExtInfo) {
        if let Some(ref algs) = p.server_sig_algs {
            // we only worry about rsa-sha256, assuming other older key types are fine

            // OK unwrap: is a remote namelist
            self.allow_rsa_sha2 = algs.has_algo(SSH_NAME_RSA_SHA256).unwrap();
            trace!("setting allow_rsa_sha2 = {}", self.allow_rsa_sha2);
        }
    }
}
