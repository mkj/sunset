#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::sshnames::*;
use crate::*;
use packets::{AuthMethod, Userauth60, UserauthPkOk};
use sshwire::{BinString, Blob};
use traffic::TrafSend;
use kex::SessId;

pub(crate) struct ServAuth {
    pub authed: bool,
}

impl ServAuth {
    pub fn new() -> Self {
        Self { authed: false }
    }

    /// Returns `true` if auth succeeds
    pub async fn request(
        &mut self,
        mut p: packets::UserauthRequest<'_>,
        sess_id: &SessId,
        s: &mut TrafSend<'_, '_>,
        b: &mut impl ServBehaviour,
    ) -> Result<bool> {

        enum AuthResp {
            Success,
            Failure,
            // failure, a response has already been send
            FailNoReply,
        }

        // TODO: what to do they've already authed? we have to be careful in case
        // behaviours don't handle it well.

        let username = p.username.clone();

        let inner = async {
            // even allows "none" auth
            if b.auth_unchallenged(p.username).await {
                return Ok(AuthResp::Success) as Result<_>
            }

            let success = match p.method {
                AuthMethod::Password(m) => {
                    if b.have_auth_password(p.username) {
                        b.auth_password(p.username, m.password).await
                    } else {
                        false
                    }
                }
                AuthMethod::PubKey(ref m) => {
                    if b.have_auth_pubkey(p.username) {
                        let allowed_key = b.auth_pubkey(p.username, &m.pubkey.0).await;
                        if allowed_key {
                            if m.sig.is_some() {
                                self.verify_sig(&mut p, sess_id)
                            } else {
                                s.send(Userauth60::PkOk(UserauthPkOk {
                                    algo: m.sig_algo,
                                    key: m.pubkey.clone(),
                                }))?;
                                return Ok(AuthResp::FailNoReply);
                            }
                        } else {
                            false
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
        };

        // failure sends a list of available methods
        match inner.await? {
            AuthResp::Success => {
                self.authed = true;
                s.send(packets::UserauthSuccess {})?;
                Ok(true)
            }
            AuthResp::Failure => {
                let methods = self.avail_methods(username, b);
                let methods = (&methods).into();

                s.send(packets::UserauthFailure { methods, partial: false })?;
                Ok(false)
            }
            AuthResp::FailNoReply => Ok(false),
        }
    }

    /// Must be passed a MethodPubkey packet with a signature part
    fn verify_sig(&self, p: &mut packets::UserauthRequest, sess_id: &SessId) -> bool {
        // Remove the signature from the packet - the signature message includes
        // packet without that signature part.

        let sig = match &mut p.method {
            AuthMethod::PubKey(m) => m.sig.take(),
            _ => {
                debug_assert!(false, "must be passed MethodPubkey");
                return false;
            }
        };

        // clumsy splitting m and p
        let m = match &p.method {
            AuthMethod::PubKey(m) => m,
            _ => return false,
        };

        let sig = match sig.as_ref() {
            Some(s) => &s.0,
            None => {
                debug_assert!(false, "missing signature");
                return false;
            }
        };

        let sig_type = match sig.sig_type() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let msg = auth::AuthSigMsg::new(&p, sess_id);
        match sig_type.verify(&m.pubkey.0, &&msg, sig) {
            Ok(()) => true,
            Err(e) => { trace!("sig failed  {e}"); false},
        }
    }

    fn avail_methods<'f>(
        &self,
        user: TextString,
        b: &mut impl ServBehaviour,
    ) -> namelist::LocalNames {
        let mut l = namelist::LocalNames::new();

        // OK unwrap: buf is large enough
        if b.have_auth_password(user) {
            l.0.push(SSH_AUTHMETHOD_PASSWORD).unwrap()
        }
        if b.have_auth_pubkey(user) {
            l.0.push(SSH_AUTHMETHOD_PUBLICKEY).unwrap()
        }
        l
    }
}
