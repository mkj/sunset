#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use serde::Serialize;

use crate::*;
use behaviour::CliBehaviour;
use client::*;
use conn::RespPackets;
use packets::ParseContext;
use packets::{Packet, Signature, Userauth60};
use sign::SignKey;
use sshnames::*;
use wireformat::BinString;
use sshwire_derive::SSHEncode;

/// The message to be signed in a pubkey authentication message,
/// RFC4252 Section 7. The packet is a UserauthRequest, with None sig.
#[derive(Serialize, SSHEncode)]
pub(crate) struct AuthSigMsg<'a> {
    pub sess_id: BinString<'a>,

    // always SSH_MSG_USERAUTH_REQUEST
    pub msg_num: u8,

    //TODO: does encoding the whole Packet enum bloat binary?
    pub u: packets::UserauthRequest<'a>,
}

