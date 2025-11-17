#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::sshnames::*;
use crate::*;
use event::{CliEvent, ServEventId};
use kex::SessId;
use packets::{AuthMethod, Packet, Userauth60, UserauthPkOk, UserauthRequest};
use sshwire::{BinString, Blob};
use traffic::TrafSend;

use heapless::{String, Vec};

/// Server authentication context
///
/// `methods_` can be during runtime, though if they
/// are changed after the auth process starts it's unknown
/// if client implementations will handle varying auth methods correctly.
#[derive(Debug)]
pub(crate) struct ServAuth {
    pub authed: bool,

    /// Used so that `AuthFirst` is only presented once to the application.
    tried_first: bool,

    /// Username previously used, as an array of bytes
    pub username: Option<Vec<u8, { config::MAX_USERNAME }>>,

    /// Whether to advertise password authentication and present it to the application
    ///
    /// Enabled by default
    pub method_password: bool,
    /// Whether to advertise pubkey authentication and present it to the application.
    ///
    /// Enabled by default
    pub method_pubkey: bool,
}

impl Default for ServAuth {
    fn default() -> Self {
        Self {
            authed: false,
            tried_first: false,
            username: None,
            method_password: true,
            method_pubkey: true,
        }
    }
}

impl ServAuth {
    /// Configure which authentication methods are allowed
    pub fn set_auth_methods(&mut self, password: bool, pubkey: bool) {
        self.method_password = password;
        self.method_pubkey = pubkey;
    }

    /// Returns an event for the app, or `DispatchEvent::None` if auth failure
    /// has been returned immediately.
    pub fn request(
        &mut self,
        sess_id: &SessId,
        s: &mut TrafSend,
        p: packets::UserauthRequest,
    ) -> Result<DispatchEvent> {
        // TODO: what to do if they've already authed? we have to be careful in case
        // app event handlers don't expect it?

        if let Some(prev) = &self.username {
            // Compare with an existing username
            if prev != p.username.0 {
                warn!("Client tried varying usernames");
                return error::SSHProtoUnsupported.fail();
            }
        } else {
            // Set new username and query app for auth methods
            match Vec::from_slice(p.username.0) {
                Result::Ok(u) => self.username = Some(u),
                Result::Err(_) => {
                    warn!("Client tried too long username");
                    return error::SSHProtoUnsupported.fail();
                }
            }
        }
        debug_assert!(self.username.is_some());

        if self.authed {
            trace!("Success after already authed");
            s.send(packets::UserauthSuccess {})?;
            return Ok(DispatchEvent::None);
        }

        let ev = match p.method {
            AuthMethod::Password(_) if self.method_password => {
                DispatchEvent::ServEvent(ServEventId::PasswordAuth)
            }
            AuthMethod::PubKey(_) if self.method_pubkey => {
                self.request_pubkey(p, sess_id)?
            }
            _ => {
                if !self.tried_first {
                    DispatchEvent::ServEvent(ServEventId::FirstAuth)
                } else {
                    DispatchEvent::None
                }
            }
        };

        // FirstAuth would have been returned by now.
        self.tried_first = true;

        // Auth method isn't supported, send failure straight away.
        // No concerns about timing leaks since it is independent of the username.
        if ev.is_none() {
            self.send_failure(s)?;
        }

        Ok(ev)
    }

    fn send_failure(&self, s: &mut TrafSend) -> Result<()> {
        let methods = self.avail_methods();
        let methods = (&methods).into();
        s.send(packets::UserauthFailure { methods, partial: false })
    }

    fn request_pubkey(
        &mut self,
        mut p: packets::UserauthRequest,
        sess_id: &SessId,
    ) -> Result<DispatchEvent> {
        // Extract the signature separately. The message for the signature
        // includes the auth packet without the signature part.
        let (key, sig) = match &mut p.method {
            AuthMethod::PubKey(m) => {
                let sig = m.sig.take();
                // When we have a signature, we need to set force_sig=true so that the encoded message for verification has the boolean set correctly
                m.force_sig = sig.is_some();
                (&m.pubkey.0, sig)
            }
            _ => return Err(Error::bug()),
        };

        if let PubKey::Unknown(u) = key {
            debug!("Unknown pubkey type {u}");
            return Ok(DispatchEvent::None);
        }

        if let Some(ref sig) = sig {
            // Real signature, validate it.
            if !self.verify_sig(&p, &sig.0, sess_id) {
                // Auth failure. OK to return early here since
                // this doesn't rely on any particular username, no concerns
                // about timing leaks.
                return Ok(DispatchEvent::None);
            }
        }

        // Proceed to query the app whether login is allowed
        let real_sig = sig.is_some();
        Ok(DispatchEvent::ServEvent(ServEventId::PubkeyAuth { real_sig }))
    }

    pub fn resume_request(&mut self, allow: bool, s: &mut TrafSend) -> Result<()> {
        if allow {
            self.authed = true;
            s.send(packets::UserauthSuccess {})
        } else {
            self.send_failure(s)
        }
    }

    pub fn resume_pkok(&self, p: Packet, s: &mut TrafSend) -> Result<()> {
        if let Packet::UserauthRequest(UserauthRequest {
            method: AuthMethod::PubKey(m),
            ..
        }) = p
        {
            s.send(Userauth60::PkOk(UserauthPkOk {
                algo: m.sig_algo,
                key: m.pubkey,
            }))
        } else {
            Err(Error::bug())
        }
    }

    /// Must be passed a MethodPubkey packet with a signature part None
    fn verify_sig(
        &self,
        p: &packets::UserauthRequest,
        sig: &Signature,
        sess_id: &SessId,
    ) -> bool {
        // Remove the signature from the packet - the signature message includes
        // packet without that signature part.

        let sig_type = match sig.sig_type() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let key = match &p.method {
            AuthMethod::PubKey(m) => &m.pubkey.0,
            _ => {
                debug_assert!(false, "Wrong method");
                return false;
            }
        };

        let msg = auth::AuthSigMsg::new(p.clone(), sess_id);
        match sig_type.verify(key, &msg, sig) {
            Ok(()) => true,
            Err(e) => {
                trace!("sig failed  {e}");
                false
            }
        }
    }

    fn avail_methods(&self) -> namelist::LocalNames {
        let mut l = namelist::LocalNames::new();

        // OK unwrap: buf is large enough
        if self.method_password {
            l.0.push(SSH_AUTHMETHOD_PASSWORD).unwrap()
        }
        if self.method_pubkey {
            l.0.push(SSH_AUTHMETHOD_PUBLICKEY).unwrap()
        }
        l
    }
}
