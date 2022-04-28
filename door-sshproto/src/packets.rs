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
use crate::wireformat::BinString;
use crate::*;

macro_rules! messagetypes {
    ( $( ( $message_num:literal, $SpecificPacketVariant:ident, $SpecificPacketType:ty, $SSH_MESSAGE_NAME:ident ), )* ) => {


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

impl<'de: 'a, 'a> Deserialize<'de> for Packet<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PacketVisitor;

        impl<'de> Visitor<'de> for PacketVisitor {
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
        deserializer.deserialize_seq(PacketVisitor { })
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

}
}

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
];

// Note:
// Each struct needs one #[borrow] tag before one of the struct fields with a lifetime
// (eg "blob: BinString<'a>"). That avoids the cryptic error in derive:
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
    pub k_s: BinString<'a>,
    pub q_s: BinString<'a>,
    pub sig: BinString<'a>,
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
    pub method: &'a str,
    // TODO: need to deserialize AuthMethod enum
    pub a: AuthMethod<'a>,
}

/// The method-specific part of a [`UserauthRequest`].
#[derive(Serialize, Deserialize, Debug)]
pub enum AuthMethod<'a> {
    #[serde(borrow)]
    Password(MethodPassword<'a>),
    Pubkey(MethodPubkey<'a>),
    None,
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
    pub pubkey: &'a [u8],
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
pub struct UserauthSuccess {
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserauthBanner<'a> {
    #[serde(borrow)]
    pub message: &'a str,
    pub lang: &'a str,
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
