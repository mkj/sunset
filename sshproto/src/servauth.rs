#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::Vec;

use crate::sshnames::*;
use crate::*;
use packets::{AuthMethod, Userauth60, UserauthPkOk};
use traffic::TrafSend;

pub(crate) struct ServAuth {
    pub authed: bool,
}

// for auth_inner()
enum AuthResp {
    // success
    Success,
    // failed, send a response
    Failure,
    // failure, a response has already been send
    FailNoReply,
}

impl ServAuth {
    pub fn new(b: &mut dyn ServBehaviour) -> Self {
        Self { authed: false }
    }

    /// Returns `true` if auth succeeds
    pub fn request(
        &self,
        p: packets::UserauthRequest,
        s: &mut TrafSend,
        b: &mut dyn ServBehaviour,
    ) -> Result<bool> {
        let r = self.auth_inner(p, s, b)?;

        match r {
            AuthResp::Success => {
                s.send(packets::UserauthSuccess {})?;
                Ok(true)
            }
            AuthResp::Failure => {
                let mut n: Vec<&str, NUM_AUTHMETHOD> = Vec::new();
                let methods = self.avail_methods(&mut n);
                let methods = (&methods).into();

                s.send(packets::UserauthFailure { methods, partial: false })?;
                Ok(false)
            }
            AuthResp::FailNoReply => Ok(false),
        }
    }

    pub fn auth_inner(
        &self,
        p: packets::UserauthRequest,
        s: &mut TrafSend,
        b: &mut dyn ServBehaviour,
    ) -> Result<AuthResp> {
        // even allows "none" auth
        if b.auth_unchallenged(p.username) {
            return Ok(AuthResp::Success);
        }

        let success = match p.method {
            AuthMethod::Password(m) => b.auth_password(p.username, m.password),
            AuthMethod::PubKey(m) => {
                let allowed_key = b.auth_pubkey(p.username, &m.pubkey.0);
                if allowed_key {
                    if m.sig.is_none() {
                        s.send(Userauth60::PkOk(UserauthPkOk {
                            algo: m.sig_algo,
                            key: m.pubkey,
                        }))?;
                        return Ok(AuthResp::FailNoReply);
                    } else {
                        self.verify_pubkey(&m)
                    }
                } else {
                    false
                }
            }
            AuthMethod::None => {
                // nothing to do
                false
            }
            AuthMethod::Unknown(u) => {
                debug!("Request for unknown auth method {}", u);
                false
            }
        };

        if success {
            Ok(AuthResp::Success)
        } else {
            Ok(AuthResp::Failure)
        }
    }

    /// Returns `true` on successful signature verifcation. `false` on bad signature.
    fn verify_pubkey(&self, m: &packets::MethodPubKey) -> bool {
        let sig = match m.sig.as_ref() {
            Some(s) => &s.0,
            None => return false,
        };

        let sig_type = match sig.sig_type() {
            Ok(t) => t,
            Err(_) => return false,
        };

        false
        // XXX
        // sig_type.verify(&m.pubkey.0, sess_id.as)

        // m.pubkey.
    }

    fn avail_methods<'f>(
        &self,
        buf: &'f mut Vec<&str, NUM_AUTHMETHOD>,
    ) -> namelist::LocalNames<'f> {
        buf.clear();
        // for
        buf.as_slice().into()
    }
}
