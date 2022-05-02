//! SSH protocol packets. A [`Packet`] can be serialized/deserialized to the
//! SSH Binary Packet Protocol using [`serde`] with [`crate::wireformat`].
//!
//! These are mostly container formats though there is some logic to determine
//! which enum variant needs deserializing for certain packet types.
use core::borrow::BorrowMut;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use serde::de;
use serde::de::{DeserializeSeed, Expected, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeTuple, Serializer};
use serde::Deserializer;

use serde::{Deserialize, Serialize};

use crate::namelist::NameList;
use crate::wireformat::{BinString, Blob};
use crate::*;

/// State to be passed to deserialisation.
/// Use this so the parser can select the correct enum variant to deserialize.
#[derive(Default)]
pub struct ParseContext<'a> {
    pub cli_auth_type: Option<cliauth::ReqType<'a>>,
}

impl<'a> ParseContext<'a> {
    pub fn new() -> Self {
        ParseContext { cli_auth_type: None }
    }
}

/// State passed as the Deserializer seed.
pub(crate) struct PacketState<'a> {
    pub ctx: &'a ParseContext<'a>,
    // Private fields that keep state during parsing.
    // TODO Perhaps not actually necessary, could be removed and just pass ParseContext?
    // pub(crate) ty: Cell<Option<MessageNumber>>,
}

// we have repeated `match` statements for the various packet types, use a macro
macro_rules! messagetypes {
    (
        $( ( $message_num:literal, $SpecificPacketVariant:ident, $SpecificPacketType:ty, $SSH_MESSAGE_NAME:ident ), )*
    ) => {


#[derive(Debug)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum MessageNumber {
    // variants are eg
    // SSH_MSG_KEXINIT = 20,
    $(
    $SSH_MESSAGE_NAME = $message_num,
    )*
}

impl TryFrom<u8> for MessageNumber {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            // eg
            // 20 = Ok(MessageNumber::SSH_MSG_KEXINIT)
            $(
            $message_num => Ok(MessageNumber::$SSH_MESSAGE_NAME),
            )*
            _ => {
                Err(Error::UnknownPacket { number: v })
            }
        }
    }
}

/// Some packets require context to parse, so we pass PacketState
pub(crate) struct DeserPacket<'a>(pub(crate) &'a PacketState<'a>);

impl<'de: 'a, 'a> DeserializeSeed<'de> for DeserPacket<'a> {
    type Value = Packet<'de>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis<'b> {
            seed: &'b PacketState<'b>,
        }

        impl<'de: 'b, 'b> Visitor<'de> for Vis<'b> {
            type Value = Packet<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Packet")
            }
            fn visit_seq<V>(self, mut seq: V) -> Result<Packet<'de>, V::Error>
            where
                V: SeqAccess<'de>
            {
                // First byte is always message number
                let msg_num: u8 = seq
                    .next_element()?
                    // .map_err(|_| Error::RanOut)?
                    .ok_or_else(|| de::Error::missing_field("message number"))?;
                let ty = MessageNumber::try_from(msg_num);
                let ty = match ty {
                    Ok(t) => t,
                    Err(_) => {
                        return Err(de::Error::invalid_value(de::Unexpected::Unsigned(msg_num as u64),
                            &self));
                    }
                };

                // Decode based on the message number
                let p = match ty {
                    // eg
                    // MessageNumber::SSH_MSG_KEXINIT => Packet::KexInit(
                    // ...
                    $(
                    MessageNumber::$SSH_MESSAGE_NAME => Packet::$SpecificPacketVariant(
                        seq.next_element()?
                        // .map_err(|_| Error::RanOut)?
                        .ok_or_else(|| de::Error::missing_field("rest of packet"))?
                        // .ok_or_else(|| Error::RanOut)?
                    ),
                    )*
                };

                Ok(p)
            }
        }
        deserializer.deserialize_seq(Vis { seed: self.0 })
    }
}

impl<'a> Serialize for Packet<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;

        let t = self.message_num() as u8;
        seq.serialize_element(&t)?;

        match self {
            // eg
            // Packet::KexInit(p) => {
            // ...
            $(
            Packet::$SpecificPacketVariant(p) => {
                seq.serialize_element(p)?;
            }
            )*
        };

        seq.end()
    }
}

/// Top level SSH packet enum
#[derive(Debug)]
pub enum Packet<'a> {
    // eg KexInit(KexInit<'a>),
    $(
    $SpecificPacketVariant($SpecificPacketType),
    )*
}

impl<'a> Packet<'a> {
    pub fn message_num(&self) -> MessageNumber {
        match self {
            // eg
            // Packet::KexInit() => {
            // ..
            $(
            Packet::$SpecificPacketVariant(_) => {
                MessageNumber::$SSH_MESSAGE_NAME
            }
            )*
        }
    }
}

} } // macro

messagetypes![
(1, Disconnect, Disconnect<'a>, SSH_MSG_DISCONNECT),
(2, Ignore, Ignore, SSH_MSG_IGNORE),
(3, Unimplemented, Unimplemented, SSH_MSG_UNIMPLEMENTED),
(4, Debug, Debug<'a>, SSH_MSG_DEBUG),
(5, ServiceRequest, ServiceRequest<'a>, SSH_MSG_SERVICE_REQUEST),
(6, ServiceAccept, ServiceAccept<'a>, SSH_MSG_SERVICE_ACCEPT),
(20, KexInit, KexInit<'a>, SSH_MSG_KEXINIT),
(21, NewKeys, NewKeys, SSH_MSG_NEWKEYS),
(30, KexDHInit, KexDHInit<'a>, SSH_MSG_KEXDH_INIT),
(31, KexDHReply, KexDHReply<'a>, SSH_MSG_KEXDH_REPLY),
(50, UserauthRequest, UserauthRequest<'a>, SSH_MSG_USERAUTH_REQUEST),
(51, UserauthFailure, UserauthFailure<'a>, SSH_MSG_USERAUTH_FAILURE),
(52, UserauthSuccess, UserauthSuccess, SSH_MSG_USERAUTH_SUCCESS),
(53, UserauthBanner, UserauthBanner<'a>, SSH_MSG_USERAUTH_BANNER),
// either SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
// or SSH_MSG_USERAUTH_PK_OK
(60, Userauth60, Userauth60<'a>, SSH_MSG_USERAUTH_60),
];

// Note:
// Each struct needs one #[borrow] tag before one of the struct fields with a lifetime
// (eg `blob: BinString<'a>`). That avoids the cryptic error in derive:
// error[E0495]: cannot infer an appropriate lifetime for lifetime parameter `'de` due to conflicting requirements

#[derive(Serialize, Deserialize, Debug)]
pub struct KexInit<'a> {
    pub cookie: [u8; 16],
    #[serde(borrow)]
    pub kex: NameList<'a>,
    pub hostkey: NameList<'a>, // is actually a signature type, not a key type
    pub cipher_c2s: NameList<'a>,
    pub cipher_s2c: NameList<'a>,
    pub mac_c2s: NameList<'a>,
    pub mac_s2c: NameList<'a>,
    pub comp_c2s: NameList<'a>,
    pub comp_s2c: NameList<'a>,
    pub lang_c2s: NameList<'a>,
    pub lang_s2c: NameList<'a>,
    pub first_follows: bool,
    pub reserved: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NewKeys {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ignore {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Debug<'a> {
    pub always_display: bool,
    pub message: &'a str,
    pub lang: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Disconnect<'a> {
    pub reason: u32,
    pub desc: &'a str,
    pub lang: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Unimplemented {
    pub seq: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KexDHInit<'a> {
    #[serde(borrow)]
    pub q_c: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KexDHReply<'a> {
    #[serde(borrow)]
    pub k_s: Blob<PubKey<'a>>,
    pub q_s: BinString<'a>,
    pub sig: Blob<Signature<'a>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceRequest<'a> {
    pub name: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ServiceAccept<'a> {
    pub name: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthRequest<'a> {
    pub username: &'a str,
    pub service: &'a str,
    pub method: AuthMethod<'a>,
}

/// The method-specific part of a [`UserauthRequest`].
#[derive(Serialize, Deserialize, Debug)]
pub enum AuthMethod<'a> {
    #[serde(borrow)]
    #[serde(rename = "password")]
    Password(MethodPassword<'a>),
    #[serde(rename = "publickey")]
    Pubkey(MethodPubkey<'a>),
    #[serde(rename = "none")]
    None,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Userauth60<'a> {
    #[serde(borrow)]
    PkOk(UserauthPkOk<'a>),
    PwChangeReq(UserauthPwChangeReq<'a>)
}

impl<'a> Userauth60<'a> {
    /// Special handling in [`wireformat`]
    pub(crate) fn variant(ctx: &ParseContext) -> Result<&'static str> {
        match ctx.cli_auth_type {
            Some(cliauth::ReqType::Password) => Ok("PwChangeReq"),
            Some(cliauth::ReqType::PubKey(..)) => Ok("PkOk"),
            _ => return Err(Error::PacketWrong),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthPkOk<'a> {
    pub algo: &'a str,
    #[serde(borrow)]
    pub key: Blob<PubKey<'a>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthPwChangeReq<'a> {
    pub prompt: &'a str,
    pub lang: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MethodPassword<'a> {
    pub change: bool,
    pub password: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MethodPubkey<'a> {
    pub trial: bool,
    pub algo: &'a str,
    pub pubkey: PubKey<'a>,
    // TODO: need to deserialize sig as an Option
    pub sig: Option<&'a [u8]>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthFailure<'a> {
    #[serde(borrow)]
    pub methods: NameList<'a>,
    pub partial: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthSuccess {}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthBanner<'a> {
    #[serde(borrow)]
    pub message: &'a str,
    pub lang: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PubKey<'a> {
    #[serde(borrow)]
    #[serde(rename = "ssh-ed25519")]
    Ed25519(Ed25519PubKey<'a>),
    #[serde(rename = "ssh-rsa")]
    RSA(RSAPubKey<'a>),
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Ed25519PubKey<'a> {
    #[serde(borrow)]
    pub key: BinString<'a>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RSAPubKey<'a> {
    #[serde(borrow)]
    pub e: BinString<'a>,
    pub n: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Signature<'a> {
    #[serde(borrow)]
    #[serde(rename = "ssh-ed25519")]
    Ed25519(Ed25519Sig<'a>),
    #[serde(rename = "rsa-sha2-256")]
    RSA(RSASig<'a>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ed25519Sig<'a> {
    #[serde(borrow)]
    pub sig: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RSASig<'a> {
    #[serde(borrow)]
    pub sig: BinString<'a>,
}


#[cfg(test)]
mod tests {
    use crate::{packets, wireformat};

    #[test]
    /// check round trip of packet enums is right
    fn packet_type() {
        for i in 0..=255 {
            let ty = packets::MessageNumber::try_from(i);
            if let Ok(ty) = ty {
                assert_eq!(i, ty as u8);
            }
        }
    }
}
