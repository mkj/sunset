//! SSH protocol packets. A [`Packet`] can be serialized/deserialized to the
//! SSH Binary Packet Protocol using [`serde`] with [`crate::wireformat`].
//!
//! These are mostly container formats though there is some logic to determine
//! which enum variant needs deserializing for certain packet types.
//!
//! Some packet formats are self describing, eg [`UserauthRequest`] has a `method`
//! string that switches between [`MethodPubkey`] and [`MethodPassword`]. Other packets
//! such as [`KexDHReply`] don't have that structure, instead they depend on previous
//! state of the SSH session. That state is passed with [`ParseContext`].
#[allow(unused_imports)]
use {
    crate::error::{Error,TrapBug},
    log::{debug, error, info, log, trace, warn},
};
use core::borrow::BorrowMut;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use serde::de;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeTuple, Serializer};
use serde::Deserializer;

use serde::{Deserialize, Serialize};

use crate::*;
use crate::kex::KexType;
use crate::namelist::NameList;
use crate::wireformat::BinString;


/// State to be passed to deserialisation. Use this so the parser can select the correct
/// enum variant to deserialize.
pub struct ParseContext {
    pub kextype: Option<KexType>,
}

impl ParseContext {
    pub fn new() -> Self {
        ParseContext { kextype: None }
    }
}

/// State passed as the Deserializer seed.
pub(crate) struct PacketState<'a> {
    pub ctx: &'a ParseContext,
    // Private fields that keep state during parsing.
    // TODO Perhaps not actually necessary, could be removed and just pass ParseContext?
    // pub(crate) ty: Cell<Option<MessageNumber>>,
}

#[derive(Debug)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum MessageNumber {
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
}

impl TryFrom<u8> for MessageNumber {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            20 => Ok(MessageNumber::SSH_MSG_KEXINIT),
            30 => Ok(MessageNumber::SSH_MSG_KEXDH_INIT),
            31 => Ok(MessageNumber::SSH_MSG_KEXDH_REPLY),
            50 => Ok(MessageNumber::SSH_MSG_USERAUTH_REQUEST),
            _ => {
                trace!("Unknown packet type {v}");
                Err(Error::UnknownPacket)
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
        struct PacketVisitor<'b> {
            seed: &'b PacketState<'b>,
        }

        impl<'de: 'b, 'b> Visitor<'de> for PacketVisitor<'b> {
            type Value = Packet<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Packet")
            }
            fn visit_seq<V>(self, mut seq: V) -> Result<Packet<'de>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                // First byte is always message number
                let msg_num: u8 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let ty: MessageNumber = msg_num
                    .try_into()
                    .map_err(|_| de::Error::custom("Unknown packet type"))?;

                // Decode based on the message number
                let p = match ty {
                    MessageNumber::SSH_MSG_KEXINIT => Packet::KexInit(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_KEXDH_INIT => Packet::KexDHInit(
                        seq.next_element_seed(DeserKexDHInit(self.seed))?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_KEXDH_REPLY => Packet::KexDHReply(
                        seq.next_element_seed(DeserKexDHReply(self.seed))?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_USERAUTH_REQUEST => todo!("userauth"),
                };

                Ok(p)
            }
        }
        deserializer.deserialize_seq(PacketVisitor { seed: self.0 })
    }
}

impl<'a> Serialize for Packet<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;

        match self {
            Packet::KexInit(p) => {
                let t = MessageNumber::SSH_MSG_KEXINIT as u8;
                seq.serialize_element(&t)?;
                seq.serialize_element(p)?;
            }
            Packet::KexDHInit(p) => {
                let t = MessageNumber::SSH_MSG_KEXDH_INIT as u8;
                seq.serialize_element(&t)?;
                seq.serialize_element(p)?;
            }
            Packet::KexDHReply(p) => {
                let t = MessageNumber::SSH_MSG_KEXDH_REPLY as u8;
                seq.serialize_element(&t)?;
                seq.serialize_element(p)?;
            }
            Packet::UserauthRequest(p) => {
                let t = MessageNumber::SSH_MSG_USERAUTH_REQUEST as u8;
                seq.serialize_element(&t)?;
                seq.serialize_element(p)?;
            }
        };

        seq.end()
    }
}

/// Top level SSH packet enum
#[derive(Debug)]
pub enum Packet<'a> {
    KexInit(KexInit<'a>),
    KexDHInit(KexDHInit<'a>),
    KexDHReply(KexDHReply<'a>),
    UserauthRequest(UserauthRequest<'a>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KexInit<'a> {
    pub cookie: [u8; 16],
    #[serde(borrow)]
    pub kex: NameList<'a>,
    pub hostkey: NameList<'a>,
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

#[derive(Serialize, Debug)]
pub enum KexDHInit<'a> {
    Curve25519Init(Curve25519Init<'a>),
    DiffieHellmanInit(DiffieHellmanInit),
}

/// Deserialize implementation  for KexDHInit
struct DeserKexDHInit<'a>(&'a PacketState<'a>);

impl<'de: 'a, 'a> DeserializeSeed<'de> for DeserKexDHInit<'a> {
    type Value = KexDHInit<'de>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Use the algo variant that was negotiated in KEX
        match self.0.ctx.kextype {
            Some(KexType::Curve25519) => Ok(KexDHInit::Curve25519Init(
                Curve25519Init::deserialize(deserializer)?,
            )),
            // Some(KexType::DiffieHellman) => Ok(KexDHInit::DiffieHellmanInit(
            //     DiffieHellmanInit::deserialize(deserializer)?,
            // )),
            None => Err(de::Error::custom("kextype not set")),
        }
    }
}

#[derive(Serialize, Debug)]
pub enum KexDHReply<'a> {
    Curve25519Reply(Curve25519Reply<'a>),
    DiffieHellmanReply( DiffieHellmanReply<'a>),
}

/// Deserialize implementation for KexDHReply
struct DeserKexDHReply<'a>(&'a PacketState<'a>);

impl<'de: 'a, 'a> DeserializeSeed<'de> for DeserKexDHReply<'a> {
    type Value = KexDHReply<'de>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Use the algo variant that was negotiated in KEX
        match self.0.ctx.kextype {
            Some(KexType::Curve25519) => Ok(KexDHReply::Curve25519Reply(
                Curve25519Reply::deserialize(deserializer)?,
            )),
            // KexType::DiffieHellman => Ok(KexDHReply::DiffieHellmanReply(
            //     DiffieHellmanReply::deserialize(deserializer)?,
            // )),
            None => Err(de::Error::custom("kextype not set")),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Curve25519Init<'a> {
    #[serde(borrow)]
    pub q_c: BinString<'a>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Curve25519Reply<'a> {
    #[serde(borrow)]
    pub k_s: BinString<'a>,
    pub q_s: BinString<'a>,
    pub sig: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DiffieHellmanInit {
    pub e: u32,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct DiffieHellmanReply<'a> {
    #[serde(borrow)]
    pub k_s: BinString<'a>,
    pub f: BinString<'a>, // mpint
    pub sig: BinString<'a>,
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

#[cfg(test)]
mod tests {
    use crate::{packets,wireformat};

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
