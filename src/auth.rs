#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};

use crate::*;
use behaviour::CliBehaviour;
use client::*;
use packets::ParseContext;
use packets::{Packet, Signature, Userauth60};
use sign::SignKey;
use sshnames::*;
use sshwire::{BinString, SSHEncode, WireResult};
use kex::SessId;

/// The message to be signed in a pubkey authentication message,
/// RFC4252 Section 7. The packet is a UserauthRequest, with None sig.
pub(crate) struct AuthSigMsg<'a> {
    pub sess_id: BinString<'a>,
    pub u: &'a packets::UserauthRequest<'a>,
}

impl SSHEncode for AuthSigMsg<'_> {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: sshwire::SSHSink {
        self.sess_id.enc(s)?;

        let m = packets::MessageNumber::SSH_MSG_USERAUTH_REQUEST as u8;
        m.enc(s)?;

        (*self.u).enc(s)?;
        Ok(())
    }
}

impl<'a> AuthSigMsg<'a> {
    pub fn new(u: &'a packets::UserauthRequest<'a>, sess_id: &'a SessId) -> Self {
        auth::AuthSigMsg {
            sess_id: BinString(sess_id.as_ref()),
            u,
        }
    }
}

#[derive(Clone, Debug)]
pub enum AuthType {
    Password,
    PubKey,
}

