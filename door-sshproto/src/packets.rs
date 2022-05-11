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

use heapless::String;
use serde::de;
use serde::de::{
    DeserializeSeed, Error as DeError, Expected, MapAccess, SeqAccess, Visitor,
};
use serde::ser::{
    Error as SerError, SerializeSeq, SerializeStruct, SerializeTuple, Serializer,
};
use serde::Deserializer;

use serde::{Deserialize, Serialize};

use crate::*;
use crate::{namelist::NameList, sshnames::*};
use crate::wireformat::{BinString, Blob};
use crate::sign::SigType;

// Each struct needs one #[borrow] tag before one of the struct fields with a lifetime
// (eg `blob: BinString<'a>`). That avoids the cryptic error in derive:
// error[E0495]: cannot infer an appropriate lifetime for lifetime parameter `'de` due to conflicting requirements

// Any `enum` needs to have special handling to select a variant when deserializing.
// This is done in conjunction with [`wireformat::deserialize_enum`].

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

/// Named to avoid clashing with [`fmt::Debug`]
#[derive(Serialize, Deserialize, Debug)]
pub struct DebugPacket<'a> {
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
    // #[serde(deserialize_with = "wrap_unknown")]
    pub method: AuthMethod<'a>,
}

/// The method-specific part of a [`UserauthRequest`].
#[derive(Serialize, Deserialize, Debug)]
pub enum AuthMethod<'a> {
    #[serde(borrow)]
    #[serde(rename = "password")]
    Password(MethodPassword<'a>),
    #[serde(rename = "publickey")]
    PubKey(MethodPubKey<'a>),
    #[serde(rename = "none")]
    None,
    #[serde(skip_serializing)]
    Unknown(Unknown<'a>),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Userauth60<'a> {
    #[serde(borrow)]
    PkOk(UserauthPkOk<'a>),
    PwChangeReq(UserauthPwChangeReq<'a>),
}

impl<'a> Userauth60<'a> {
    /// Special handling in [`wireformat`]
    pub(crate) fn variant(ctx: &ParseContext) -> Result<&'static str> {
        match ctx.cli_auth_type {
            Some(cliauth::Req::Password(_)) => Ok("PwChangeReq"),
            Some(cliauth::Req::PubKey(..)) => Ok("PkOk"),
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

#[derive(Serialize, Deserialize)]
pub struct MethodPassword<'a> {
    pub change: bool,
    pub password: &'a str,
}

// Don't print password
impl<'a> fmt::Debug for MethodPassword<'a>{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MethodPassword")
            .field("change", &self.change)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct MethodPubKey<'a> {
    /// A signature algorithm name (not key algorithm name).
    pub sig_algo: &'a str,
    pub pubkey: PubKey<'a>,
    pub sig: Option<Blob<Signature<'a>>>,
}

impl<'a> Serialize for MethodPubKey<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        seq.serialize_element(&self.sig.is_some())?;
        seq.serialize_element(&self.sig_algo)?;
        seq.serialize_element(&self.pubkey)?;
        if let Some(s) = &self.sig {
            seq.serialize_element(&s)?;
        }
        seq.end()
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for MethodPubKey<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;

        impl<'de> Visitor<'de> for Vis {
            type Value = MethodPubKey<'de>;

            fn expecting(
                &self, formatter: &mut core::fmt::Formatter,
            ) -> core::fmt::Result {
                formatter.write_str("MethodPubKey")
            }
            fn visit_seq<V>(self, mut seq: V) -> Result<MethodPubKey<'de>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let actual_sig = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("actual_sig flag"))?;

                let sig_algo = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("sig_algo"))?;

                let pubkey = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("pubkey"))?;

                let sig = if actual_sig {
                    Some(
                        seq.next_element()?
                            .ok_or_else(|| de::Error::missing_field("sig"))?,
                    )
                } else {
                    None
                };

                Ok(MethodPubKey { sig_algo, pubkey, sig })
            }
        }
        deserializer.deserialize_seq(Vis)
    }
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PubKey<'a> {
    #[serde(borrow)]
    #[serde(rename = "ssh-ed25519")]
    Ed25519(Ed25519PubKey<'a>),
    #[serde(rename = "ssh-rsa")]
    RSA(RSAPubKey<'a>),
    #[serde(skip_serializing)]
    Unknown(Unknown<'a>),
}

impl<'a> PubKey<'a> {
    /// The algorithm name presented. May be invalid.
    pub fn algorithm_name(&self) -> &'a str {
        match self {
            PubKey::Ed25519(_) => SSH_NAME_ED25519,
            PubKey::RSA(_) => SSH_NAME_RSA,
            PubKey::Unknown(u) => u.0,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ed25519PubKey<'a> {
    #[serde(borrow)]
    pub key: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    RSA256(RSA256Sig<'a>),
    #[serde(skip_serializing)]
    Unknown(Unknown<'a>),
}

impl<'a> Signature<'a> {
    /// The algorithm name presented. May be invalid.
    pub fn algorithm_name(&self) -> &'a str {
        match self {
            Signature::Ed25519(_) => SSH_NAME_ED25519,
            Signature::RSA256(_) => SSH_NAME_RSA_SHA256,
            Signature::Unknown(u) => u.0,
        }
    }

    /// Returns the signature algorithm name for a public key.
    /// Returns (`Error::UnknownMethod`) if the PubKey is unknown
    /// Currently can return a unique signature name for a public key
    /// since ssh-rsa isn't supported, only rsa-sha2-256 (as an example)
    pub fn sig_algorithm_name_for_pubkey(pubkey: &PubKey) -> Result<&'static str> {
        match pubkey {
            PubKey::Ed25519(_) => Ok(SSH_NAME_ED25519),
            PubKey::RSA(_) => Ok(SSH_NAME_RSA_SHA256),
            PubKey::Unknown(u) => Err(Error::UnknownMethod {kind: "key",
                    name: u.0.into() })
        }
    }

    pub fn sig_type(&self) -> Result<SigType> {
        match self {
            Signature::Ed25519(_) => Ok(SigType::Ed25519),
            Signature::RSA256(_) => Ok(SigType::RSA256),
            Signature::Unknown(u) => {
                Err(Error::UnknownMethod {kind: "signature",
                    name: u.0.into() })
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ed25519Sig<'a> {
    #[serde(borrow)]
    pub sig: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RSA256Sig<'a> {
    #[serde(borrow)]
    pub sig: BinString<'a>,
}

// #[derive(Serialize, Deserialize, Debug)]
// pub struct GlobalRequest<'a> {
//     name: &'a str,
//     want_reply: bool,
//     request: GlobalRequestMethod<'a>,
// }

// enum GlobalRequestMethod<'a> {
//     TcpipForward<'a>,
//     CancelTcpipForward,
// }

#[derive(Debug)]
pub struct ChannelOpen<'a> {
    // channel_type is implicit in the type enum below
    pub number: u32,
    pub initial_window: u32,
    pub max_packet: u32,
    pub ch: ChannelType<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ChannelType<'a> {
    #[serde(borrow)]
    #[serde(rename = "forwarded-tcpip")]
    ForwardedTcpip(ForwardedTcpip<'a>),
    #[serde(rename = "direct-tcpip")]
    DirectTcpip(DirectTcpip<'a>),
    #[serde(rename = "session")]
    Session,
    // #[serde(rename = "x11")]
    // Session(X11<'a>),
    // #[serde(rename = "auth-agent@openssh.com")]
    // Session(Agent<'a>),
    #[serde(skip_serializing)]
    Unknown(Unknown<'a>),
}

impl<'a> Serialize for ChannelOpen<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_struct("ChannelOpen", 5)?;
        let channel_type = match self.ch {
            ChannelType::Session => "session",
            ChannelType::ForwardedTcpip(_) => "forwarded-tcpip",
            ChannelType::DirectTcpip(_) => "direct-tcpip",
            ChannelType::Unknown(_) => return Err(S::Error::custom("unknown")),
        };
        seq.serialize_field("channel_type", channel_type)?;
        seq.serialize_field("number", &self.number)?;
        seq.serialize_field("initial_window", &self.initial_window)?;
        seq.serialize_field("max_packet", &self.initial_window)?;
        seq.serialize_field("ch", &self.ch)?;
        seq.end()
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for ChannelOpen<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;

        impl<'de> Visitor<'de> for Vis {
            type Value = ChannelOpen<'de>;

            fn expecting(
                &self, formatter: &mut core::fmt::Formatter,
            ) -> core::fmt::Result {
                formatter.write_str("ChannelOpen")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ChannelOpen<'de>, V::Error>
            where
                V: MapAccess<'de>,
            {
                // a bit horrible
                let mut _k: &'de str;
                let _channel_type: &'de str;
                let number;
                let initial_window;
                let max_packet;
                let ch;
                (_k, _channel_type) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("channel_type"))?;
                (_k, number) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("number"))?;
                (_k, initial_window) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("initial_window"))?;
                (_k, max_packet) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("max_packet"))?;
                (_k, ch) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("ch"))?;

                Ok(ChannelOpen { number, initial_window, max_packet, ch })
            }
        }
        deserializer.deserialize_struct(
            "ChannelOpen",
            &["channel_type", "number", "initial_window", "max_packet", "ch"],
            Vis,
        )
    }
}

// Placeholder for unknown method names. These are sometimes non-fatal and
// need to be handled by the relevant code, for example newly invented pubkey types
#[derive(Debug,Deserialize,Clone)]
pub struct Unknown<'a>(pub &'a str);


// impl<'a> ChannelType<'a> {
//     /// Special handling in [`wireformat`]
//     pub(crate) fn variant(&self) -> Result<&'static str> {
//     }
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct ForwardedTcpip<'a> {
    address: &'a str,
    port: u32,
    origin: &'a str,
    origin_port: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectTcpip<'a> {
    address: &'a str,
    port: u32,
    origin: &'a str,
    origin_port: u32,
}

/// State to be passed to deserialisation.
/// Use this so the parser can select the correct enum variant to deserialize.
#[derive(Default)]
pub struct ParseContext<'a> {
    pub cli_auth_type: Option<cliauth::Req>,
    lifetime: PhantomData<&'a ()>, // TODO
}

impl<'a> ParseContext<'a> {
    pub fn new() -> Self {
        ParseContext { cli_auth_type: None, lifetime: PhantomData::default() }
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

impl<'de: 'a, 'a> Deserialize<'de> for Packet<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;

        impl<'de> Visitor<'de> for Vis {
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
                        .ok_or_else(|| de::Error::missing_field("rest of packet"))?
                    ),
                    )*
                };

                Ok(p)
            }
        }
        deserializer.deserialize_seq(Vis { })
    }
}

impl<'a> Serialize for Packet<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(2))?;

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
(4, DebugPacket, DebugPacket<'a>, SSH_MSG_DEBUG),
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

// (80            SSH_MSG_GLOBAL_REQUEST),
// (81            SSH_MSG_REQUEST_SUCCESS),
// (82            SSH_MSG_REQUEST_FAILURE),
(90, ChannelOpen, ChannelOpen<'a>, SSH_MSG_CHANNEL_OPEN),
// (91            SSH_MSG_CHANNEL_OPEN_CONFIRMATION),
// (92            SSH_MSG_CHANNEL_OPEN_FAILURE),
// (93            SSH_MSG_CHANNEL_WINDOW_ADJUST),
// (94            SSH_MSG_CHANNEL_DATA),
// (95            SSH_MSG_CHANNEL_EXTENDED_DATA),
// (96            SSH_MSG_CHANNEL_EOF),
// (97            SSH_MSG_CHANNEL_CLOSE),
// (98            SSH_MSG_CHANNEL_REQUEST),
// (99            SSH_MSG_CHANNEL_SUCCESS),
// (100            SSH_MSG_CHANNEL_FAILURE),
];

#[cfg(test)]
mod tests {
    use crate::doorlog::init_test_log;
    use crate::packets::*;
    use crate::sshnames::*;
    use crate::wireformat::tests::{assert_serialize_equal, test_roundtrip};
    use crate::wireformat::{packet_from_bytes, write_ssh};
    use crate::{packets, wireformat};
    use pretty_hex::PrettyHex;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

    fn json_roundtrip(p: &Packet) {
        let t = serde_json::to_string_pretty(p).unwrap();
        trace!("json {t}");
        let p2 = serde_json::from_str(&t).unwrap();

        assert_serialize_equal(p, &p2);
    }

    #[test]
    /// Tests MethodPubKey custom serde
    fn roundtrip_authpubkey() {
        init_test_log();
        // with None sig
        let s = sign::tests::make_ed25519_signkey();
        let p = Packet::UserauthRequest(UserauthRequest {
            username: "matt",
            service: "conn",
            method: AuthMethod::PubKey(MethodPubKey {
                sig_algo: SSH_NAME_ED25519,
                pubkey: s.pubkey(),
                sig: None,
            }),
        });
        test_roundtrip(&p);

        // again with a near-genuine sig
        let sig = Signature::Ed25519(Ed25519Sig {
            sig: BinString("something".as_bytes()),
        });
        let sig = Some(Blob(sig));
        let p = Packet::UserauthRequest(UserauthRequest {
            username: "matt",
            service: "conn",
            method: AuthMethod::PubKey(MethodPubKey {
                sig_algo: SSH_NAME_ED25519,
                pubkey: s.pubkey(),
                sig,
            }),
        });
        test_roundtrip(&p);
    }

    #[test]
    fn roundtrip_channel_open() {
        init_test_log();
        let p = Packet::ChannelOpen(ChannelOpen {
            number: 111,
            initial_window: 50000,
            max_packet: 20000,
            ch: ChannelType::DirectTcpip(DirectTcpip {
                address: "localhost",
                port: 4444,
                origin: "somewhere",
                origin_port: 0,
            }),
        });
        test_roundtrip(&p);
        json_roundtrip(&p);

        let p = Packet::ChannelOpen(ChannelOpen {
            number: 0,
            initial_window: 899,
            max_packet: 14,
            ch: ChannelType::Session,
        });
        test_roundtrip(&p);
        json_roundtrip(&p);
    }

    #[test]
    fn unknown_method() {
        init_test_log();
        let p = Packet::ChannelOpen(ChannelOpen {
            number: 0,
            initial_window: 899,
            max_packet: 14,
            ch: ChannelType::Session,
        });
        let mut buf1 = vec![88; 1000];
        let l = write_ssh(&mut buf1, &p).unwrap();
        buf1.truncate(l);
        // change a byte
        buf1[8] = 'X' as u8;
        trace!("broken: {:?}", buf1.hex_dump());
        let ctx = ParseContext::default();
        let p2 = packet_from_bytes(&buf1, &ctx).unwrap();
        trace!("broken: {p2:#?}");
    }

    #[test]
    #[should_panic]
    fn unknown_method_ser() {
        init_test_log();
        let p = Packet::ChannelOpen(ChannelOpen {
            number: 0,
            initial_window: 200000,
            max_packet: 88200,
            ch: ChannelType::Unknown(Unknown("audio-stream"))
        });
        let mut buf1 = vec![88; 1000];
        write_ssh(&mut buf1, &p).unwrap();
    }

    #[test]
    /// See whether we work with another `Serializer`/`Deserializer`.
    /// Not required, but might make `packets` more reusable without `wireformat`.
    fn json() {
        init_test_log();
        let p = Packet::Userauth60(Userauth60::PwChangeReq(UserauthPwChangeReq {
            prompt: "change the password",
            lang: "",
        }));
        json_roundtrip(&p);

        // Fails, namelist string sections are serialized piecewise, serde
        // doesn't have any API to write strings in parts. It's fine for
        // SSH format since we have no sequence delimiters.

        // let cli_conf = kex::AlgoConfig::new(true);
        // let cli = kex::Kex::new().unwrap();
        // let p = cli.make_kexinit(&cli_conf);
        // json_roundtrip(&p);

        // It seems BinString also has problems, haven't figured where the
        // problem is.
    }
}
