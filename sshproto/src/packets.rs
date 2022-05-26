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

use ring::signature::Signature as RingSig;

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
            Some(cliauth::AuthType::Password) => Ok("PwChangeReq"),
            Some(cliauth::AuthType::PubKey) => Ok("PkOk"),
            _ => {
                trace!("Wrong packet state for userauth60");
                return Err(Error::PacketWrong)
            }
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
    pub pubkey: Blob<PubKey<'a>>,
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ed25519PubKey<'a> {
    #[serde(borrow)]
    pub key: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
    /// Is passed our own [`SignKey`] since a Ring signature doesn't
    /// identify the algorithm.
    pub(crate) fn from_ring(k: &SignKey, r: &'a RingSig) -> Result<Self> {
        match k {
            SignKey::Ed25519(_) => Ok(Signature::Ed25519(Ed25519Sig { sig: BinString(r.as_ref()) })),
        }

    }

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
    pub fn sig_name_for_pubkey(pubkey: &PubKey) -> Result<&'static str> {
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
    pub num: u32,
    pub initial_window: u32,
    pub max_packet: u32,
    pub ch: ChannelOpenType<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ChannelOpenType<'a> {
    #[serde(rename = "session")]
    Session,
    #[serde(rename = "forwarded-tcpip")]
    #[serde(borrow)]
    ForwardedTcpip(ForwardedTcpip<'a>),
    #[serde(rename = "direct-tcpip")]
    DirectTcpip(DirectTcpip<'a>),
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
            ChannelOpenType::Session => "session",
            ChannelOpenType::ForwardedTcpip(_) => "forwarded-tcpip",
            ChannelOpenType::DirectTcpip(_) => "direct-tcpip",
            ChannelOpenType::Unknown(_) => return Err(S::Error::custom("unknown")),
        };
        seq.serialize_field("channel_type", channel_type)?;
        seq.serialize_field("num", &self.num)?;
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
                let num;
                let initial_window;
                let max_packet;
                let ch;
                (_k, _channel_type) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("channel_type"))?;
                (_k, num) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("num"))?;
                (_k, initial_window) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("initial_window"))?;
                (_k, max_packet) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("max_packet"))?;
                (_k, ch) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("ch"))?;

                Ok(ChannelOpen { num, initial_window, max_packet, ch })
            }
        }
        // deserialize as a struct so wireformat can get the channel_type
        // used to decode the ch enum.
        deserializer.deserialize_struct(
            "ChannelOpen",
            &["channel_type", "num", "initial_window", "max_packet", "ch"],
            Vis,
        )
    }
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelOpenConfirmation {
    pub num: u32,
    pub sender_num: u32,
    pub initial_window: u32,
    pub max_packet: u32,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelOpenFailure<'a> {
    pub num: u32,
    pub reason: u32,
    pub desc: &'a str,
    pub lang: &'a str,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelWindowAdjust {
    pub num: u32,
    pub adjust: u32,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelData<'a> {
    pub num: u32,
    #[serde(borrow)]
    pub data: BinString<'a>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelDataExt<'a> {
    pub num: u32,
    pub code: u32,
    #[serde(borrow)]
    pub data: BinString<'a>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelEof {
    pub num: u32,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelClose {
    pub num: u32,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelSuccess {
    pub num: u32,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct ChannelFailure {
    pub num: u32,
}

#[derive(Debug)]
pub struct ChannelRequest<'a> {
    pub num: u32,
    // channel_type is implicit in the type enum below
    pub want_reply: bool,
    pub ch: ChannelReqType<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ChannelReqType<'a> {
    #[serde(rename = "shell")]
    Shell,
    #[serde(rename = "exec")]
    #[serde(borrow)]
    Exec(Exec<'a>),
    #[serde(rename = "pty-req")]
    Pty(Pty<'a>),
    #[serde(rename = "subsystem")]
    Subsystem(Subsystem<'a>),
    #[serde(rename = "window-change")]
    WinChange(WinChange),
    #[serde(rename = "signal")]
    Signal(Signal<'a>),
    #[serde(rename = "exit-status")]
    ExitStatus(ExitStatus),
    #[serde(rename = "exit-signal")]
    ExitSignal(ExitSignal<'a>),
    #[serde(rename = "break")]
    Break(Break),
    // Other requests that aren't implemented at present:
    // auth-agent-req@openssh.com
    // x11-req
    // env
    // xon-xoff
    #[serde(skip_serializing)]
    Unknown(Unknown<'a>),
}

impl<'a> Serialize for ChannelRequest<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_struct("ChannelRequest", 5)?;
        let channel_type = match self.ch {
            ChannelReqType::Shell => "shell",
            ChannelReqType::Exec(_) => "exec",
            ChannelReqType::Pty(_) => "pty-req",
            ChannelReqType::Subsystem(_) => "subsystem",
            ChannelReqType::WinChange(_) => "window-change",
            ChannelReqType::Signal(_) => "signal",
            ChannelReqType::ExitStatus(_) => "exit-status",
            ChannelReqType::ExitSignal(_) => "exit-signal",
            ChannelReqType::Break(_) => "break",
            ChannelReqType::Unknown(_) => return Err(S::Error::custom("unknown")),
        };
        seq.serialize_field("num", &self.num)?;
        seq.serialize_field("channel_type", channel_type)?;
        seq.serialize_field("want_reply", &self.want_reply)?;
        seq.serialize_field("ch", &self.ch)?;
        seq.end()
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for ChannelRequest<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis;

        impl<'de> Visitor<'de> for Vis {
            type Value = ChannelRequest<'de>;

            fn expecting(
                &self, formatter: &mut core::fmt::Formatter,
            ) -> core::fmt::Result {
                formatter.write_str("ChannelRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ChannelRequest<'de>, V::Error>
            where
                V: MapAccess<'de>,
            {
                // a bit horrible
                let mut _k: &'de str;
                let _channel_type: &'de str;
                let num;
                let want_reply;
                let ch;
                (_k, num) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("num"))?;
                (_k, _channel_type) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("channel_type"))?;
                (_k, want_reply) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("want_reply"))?;
                (_k, ch) = map
                    .next_entry()?
                    .ok_or_else(|| de::Error::missing_field("ch"))?;

                Ok(ChannelRequest { num, want_reply, ch })
            }
        }
        // deserialize as a struct so wireformat can get the channel_type
        // used to decode the ch enum.
        deserializer.deserialize_struct(
            "ChannelRequest",
            &["num", "channel_type", "want_reply", "ch"],
            Vis,
        )
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Exec<'a> {
    pub command: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pty<'a> {
    pub term: &'a str,
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
    pub modes: BinString<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Subsystem<'a> {
    pub subsystem: &'a str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WinChange {
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Signal<'a> {
    pub sig: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExitStatus {
    pub status: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExitSignal<'a> {
    pub signal: &'a str,
    pub core: bool,
    pub error: &'a str,
    pub lang: &'a str,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Break {
    pub length: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ForwardedTcpip<'a> {
    pub address: &'a str,
    pub port: u32,
    pub origin: &'a str,
    pub origin_port: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DirectTcpip<'a> {
    pub address: &'a str,
    pub port: u32,
    pub origin: &'a str,
    pub origin_port: u32,
}


// Placeholder for unknown method names. These are sometimes non-fatal and
// need to be handled by the relevant code, for example newly invented pubkey types
// This is deliberately not Serializable, we only receive it.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Unknown<'a>(pub &'a str);

/// State to be passed to deserialisation.
/// Use this so the parser can select the correct enum variant to deserialize.
#[derive(Default, Clone, Debug)]
pub struct ParseContext {
    pub cli_auth_type: Option<cliauth::AuthType>,
}

impl ParseContext {
    pub fn new() -> Self {
        ParseContext { cli_auth_type: None }
    }
}

/// State passed as the Deserializer seed.
pub(crate) struct PacketState {
    pub ctx: ParseContext,
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
// One of
// SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
// SSH_MSG_USERAUTH_PK_OK
// SSH_MSG_USERAUTH_INFO_REQUEST
(60, Userauth60, Userauth60<'a>, SSH_MSG_USERAUTH_60),
// (61, SSH_MSG_USERAUTH_INFO_RESPONSE),

// (80            SSH_MSG_GLOBAL_REQUEST),
// (81            SSH_MSG_REQUEST_SUCCESS),
// (82            SSH_MSG_REQUEST_FAILURE),
(90, ChannelOpen, ChannelOpen<'a>, SSH_MSG_CHANNEL_OPEN),
(91, ChannelOpenConfirmation, ChannelOpenConfirmation, SSH_MSG_CHANNEL_OPEN_CONFIRMATION),
(92, ChannelOpenFailure, ChannelOpenFailure<'a>, SSH_MSG_CHANNEL_OPEN_FAILURE),
(93, ChannelWindowAdjust, ChannelWindowAdjust, SSH_MSG_CHANNEL_WINDOW_ADJUST),
(94, ChannelData, ChannelData<'a>, SSH_MSG_CHANNEL_DATA),
(95, ChannelDataExt, ChannelDataExt<'a>, SSH_MSG_CHANNEL_EXTENDED_DATA),
(96, ChannelEof, ChannelEof, SSH_MSG_CHANNEL_EOF),
(97, ChannelClose, ChannelClose, SSH_MSG_CHANNEL_CLOSE),
(98, ChannelRequest, ChannelRequest<'a>, SSH_MSG_CHANNEL_REQUEST),
(99, ChannelSuccess, ChannelSuccess, SSH_MSG_CHANNEL_SUCCESS),
(100, ChannelFailure, ChannelFailure, SSH_MSG_CHANNEL_FAILURE),
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
                pubkey: Blob(s.pubkey()),
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
                pubkey: Blob(s.pubkey()),
                sig,
            }),
        });
        test_roundtrip(&p);
    }

    #[test]
    fn roundtrip_channel_open() {
        init_test_log();
        let p = Packet::ChannelOpen(ChannelOpen {
            num: 111,
            initial_window: 50000,
            max_packet: 20000,
            ch: ChannelOpenType::DirectTcpip(DirectTcpip {
                address: "localhost",
                port: 4444,
                origin: "somewhere",
                origin_port: 0,
            }),
        });
        test_roundtrip(&p);
        json_roundtrip(&p);

        let p = Packet::ChannelOpen(ChannelOpen {
            num: 0,
            initial_window: 899,
            max_packet: 14,
            ch: ChannelOpenType::Session,
        });
        test_roundtrip(&p);
        json_roundtrip(&p);
    }

    #[test]
    fn unknown_method() {
        init_test_log();
        let p = Packet::ChannelOpen(ChannelOpen {
            num: 0,
            initial_window: 899,
            max_packet: 14,
            ch: ChannelOpenType::Session,
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
            num: 0,
            initial_window: 200000,
            max_packet: 88200,
            ch: ChannelOpenType::Unknown(Unknown("audio-stream"))
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
