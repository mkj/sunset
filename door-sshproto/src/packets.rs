//! SSH protocol packets. A [`Packet`] can be serialized/deserialized to the
//! SSH Binary Packet Protocol using [`serde`] with [`crate::wireformat`].
//!
//! These are mostly container formats though there is some logic to determine
//! which enum variant needs deserializing for certain packet types.
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


#[derive(Debug)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum MessageNumber {
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,
    SSH_MSG_USERAUTH_REQUEST = 50,
}

impl TryFrom<u8> for MessageNumber {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            20 => Ok(MessageNumber::SSH_MSG_KEXINIT),
            21 => Ok(MessageNumber::SSH_MSG_NEWKEYS),
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
                    MessageNumber::SSH_MSG_NEWKEYS => Packet::NewKeys(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_KEXDH_INIT => Packet::KexDHInit(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_KEXDH_REPLY => Packet::KexDHReply(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?,
                    ),
                    MessageNumber::SSH_MSG_USERAUTH_REQUEST => todo!("userauth"),
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

        match self {
            Packet::KexInit(p) => {
                let t = MessageNumber::SSH_MSG_KEXINIT as u8;
                seq.serialize_element(&t)?;
                seq.serialize_element(p)?;
            }
            Packet::NewKeys(p) => {
                let t = MessageNumber::SSH_MSG_NEWKEYS as u8;
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

// Note:
// Each struct needs one #[borrow] tag to avoid the cryptic error in derive:
// error[E0495]: cannot infer an appropriate lifetime for lifetime parameter `'de` due to conflicting requirements

/// Top level SSH packet enum
#[derive(Debug)]
pub enum Packet<'a> {
    KexInit(KexInit<'a>),
    NewKeys(NewKeys),
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

#[derive(Serialize, Deserialize, Debug)]
pub struct NewKeys {
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
