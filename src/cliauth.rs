use self::{
    conn::DispatchEvent,
    event::{CliEvent, CliEventId},
};

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use pretty_hex::PrettyHex;

use crate::{packets::UserauthPkOk, *};
use auth::AuthType;
use client::*;
use kex::SessId;
use packets::{
    AuthMethod, MessageNumber, MethodPubKey, ParseContext, UserauthRequest,
};
use packets::{Packet, Signature, Userauth60};
use sign::{OwnedSig, SignKey};
use sshnames::*;
use sshwire::{BinString, Blob};
use traffic::TrafSend;

enum AuthState {
    Unstarted,
    MethodQuery,
    // other request types
    Request,
    RequestKey { key: SignKey },
    Idle,
}

pub(crate) struct CliAuth {
    state: AuthState,

    username: String<{ config::MAX_USERNAME }>,

    /// Starts as true, set to false if hook.auth_password() returns None.
    /// Not set false if the server rejects auth.
    try_password: bool,

    /// Set to false if hook.next_authkey() returns None.
    try_pubkey: bool,

    /// Set once we are OKed from MSG_EXT_INFO
    allow_rsa_sha2: bool,
}

impl CliAuth {
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

    pub fn resume_username(
        &mut self,
        s: &mut TrafSend,
        username: &str,
    ) -> Result<()> {
        // TODO; error handling
        self.username =
            username.try_into().map_err(|_| Error::msg("Username too long"))?;
        s.send(packets::ServiceRequest { name: SSH_SERVICE_USERAUTH })?;

        s.send(packets::UserauthRequest {
            username: self.username.as_str().into(),
            service: SSH_SERVICE_CONNECTION,
            method: packets::AuthMethod::None,
        })?;
        Ok(())
    }

    pub fn auth60(
        &mut self,
        auth60: &packets::Userauth60,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        match auth60 {
            Userauth60::PkOk(pkok) => self.auth_pkok(pkok, sess_id, parse_ctx, s),
            Userauth60::PwChangeReq(_req) => {
                self.change_password()?;
                parse_ctx.cli_auth_type = None;
                Ok(DispatchEvent::None)
            }
        }
    }

    fn auth_sig_msg<'b>(
        &'b self,
        key: &'b SignKey,
        sess_id: &'b SessId,
    ) -> Result<AuthSigMsg<'b>> {
        let p = req_packet_pubkey(&self.username, &key, None, true)?;
        Ok(auth::AuthSigMsg::new(p, sess_id))
    }

    fn auth_pkok(
        &mut self,
        pkok: &UserauthPkOk,
        sess_id: &SessId,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let AuthState::RequestKey { key } = &self.state else {
            trace!("Unexpected userauth60");
            return error::SSHProto.fail();
        };

        if key.pubkey() != pkok.key.0 {
            trace!("Received pkok for a different key");
            return error::SSHProto.fail();
        }

        if key.is_agent() {
            return Ok(DispatchEvent::CliEvent(CliEventId::AgentSign));
        }

        // Sign the packet without the signature
        let msg = self.auth_sig_msg(key, sess_id)?;
        let sig = key.sign(&msg)?;
        let p = req_packet_pubkey(&self.username, &key, Some(&sig), true)?;

        s.send(p)?;
        parse_ctx.cli_auth_type = None;
        Ok(DispatchEvent::None)
    }

    pub fn resume_agentsign(
        &self,
        sig: Option<&OwnedSig>,
        parse_ctx: &mut ParseContext,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let AuthState::RequestKey { key } = &self.state else {
            return Err(Error::bug());
        };

        parse_ctx.cli_auth_type = None;

        let Some(sig) = sig else {
            // Request the next key
            return Ok(DispatchEvent::CliEvent(CliEventId::Pubkey));
        };

        let p = req_packet_pubkey(&self.username, &key, Some(&sig), true)?;
        s.send(p)?;
        Ok(DispatchEvent::None)
    }

    fn change_password(&self) -> Result<()> {
        // Doesn't seem to be widely implemented, we'll just fail.
        Err(Error::msg("Password has expired"))
    }

    /// handles auth failure packet from the server (which also provides
    /// the initial list of auth methods)
    pub fn failure(
        &mut self,
        failure: &packets::UserauthFailure,
        parse_ctx: &mut ParseContext,
    ) -> Result<DispatchEvent> {
        parse_ctx.cli_auth_type = None;
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if self.try_pubkey && failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            return Ok(DispatchEvent::CliEvent(event::CliEventId::Pubkey));
        }

        if matches!(self.state, AuthState::Idle)
            && self.try_password
            && failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)?
        {
            return Ok(DispatchEvent::CliEvent(event::CliEventId::Password));
        }

        error::NoAuthMethods.fail()
    }

    pub fn resume_password(
        &mut self,
        s: &mut TrafSend,
        password: Option<&str>,
        parse_ctx: &mut ParseContext,
    ) -> Result<()> {
        let Some(password) = password else {
            self.try_password = false;
            return error::NoAuthMethods.fail();
        };

        let p = req_packet_password(&self.username, password);
        s.send(p)?;
        parse_ctx.cli_auth_type = Some(AuthType::Password);
        self.state = AuthState::Request;
        Ok(())
    }

    // May return another event to try, such as password auth
    pub fn resume_pubkey(
        &mut self,
        s: &mut TrafSend,
        key: Option<SignKey>,
        parse_ctx: &mut ParseContext,
    ) -> Result<DispatchEvent> {
        let Some(key) = key else {
            self.try_pubkey = false;
            if self.try_password {
                return Ok(DispatchEvent::CliEvent(CliEventId::Password));
            }
            return error::NoAuthMethods.fail();
        };

        #[cfg(feature = "rsa")]
        if (matches!(key, SignKey::RSA(_)) || matches!(key, SignKey::AgentRSA(_)))
            && !self.allow_rsa_sha2
        {
            // RSA keys are only used when the server has confirmed that rsa-sha2
            // signatures are OK by sending ext-info.
            trace!("Skipping rsa key, no ext-info");
            // Ask for another public key
            return Ok(DispatchEvent::CliEvent(CliEventId::Pubkey));
        }

        let p = req_packet_pubkey(&self.username, &key, None, false)?;
        s.send(p)?;
        parse_ctx.cli_auth_type = Some(AuthType::PubKey);
        trace!("authtype {:?}", parse_ctx.cli_auth_type);
        self.state = AuthState::RequestKey { key };
        Ok(DispatchEvent::None)
    }

    pub fn fetch_agentsign_key(&self) -> Result<&SignKey> {
        let AuthState::RequestKey { key } = &self.state else {
            return Err(Error::bug());
        };
        debug_assert!(key.is_agent());
        Ok(key)
    }

    pub fn fetch_agentsign_msg<'b>(
        &'b self,
        sess_id: &'b SessId,
    ) -> Result<AuthSigMsg<'b>> {
        let AuthState::RequestKey { key } = &self.state else {
            return Err(Error::bug());
        };

        // Sign the packet without the signature
        self.auth_sig_msg(key, sess_id)
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

fn req_packet_password<'b>(username: &'b str, password: &'b str) -> Packet<'b> {
    packets::UserauthRequest {
        username: username.into(),
        service: SSH_SERVICE_CONNECTION,
        method: packets::AuthMethod::Password(packets::MethodPassword {
            change: false,
            password: password.into(),
        }),
    }
    .into()
}

fn req_packet_pubkey<'b>(
    username: &'b str,
    key: &'b SignKey,
    sig: Option<&'b OwnedSig>,
    force_sig: bool,
) -> Result<packets::UserauthRequest<'b>> {
    let mut mp = MethodPubKey::new(key.pubkey(), sig)?;
    mp.force_sig = force_sig;
    let method = AuthMethod::PubKey(mp);
    Ok(packets::UserauthRequest {
        username: username.into(),
        service: SSH_SERVICE_CONNECTION,
        method,
    })
}
