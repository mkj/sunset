//! SSH wire format reading/writing.
//! Used in conjunction with [`sshwire_derive`] and the [`packet`](crate::packets) format
//! definitions.

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::str;
use core::convert::AsRef;
use core::fmt::{self,Debug};
use pretty_hex::PrettyHex;
use snafu::{prelude::*, Location};

use ascii::{AsAsciiStr, AsciiChar, AsciiStr};

use crate::*;
use packets::{Packet, ParseContext};

/// A generic destination for serializing, used similarly to `serde::Serializer`
pub trait SSHSink {
    fn push(&mut self, v: &[u8]) -> WireResult<()>;
    fn ctx(&self) -> Option<&ParseContext> {
        None
    }
}

/// A generic source for a packet, used similarly to `serde::Deserializer`
pub trait SSHSource<'de> {
    fn take(&mut self, len: usize) -> WireResult<&'de [u8]>;
    fn pos(&self) -> usize;
    fn ctx(&mut self) -> &mut ParseContext;
}

/// Encodes the type in SSH wire format
pub trait SSHEncode {
    fn enc<S>(&self, s: &mut S) -> WireResult<()> where S: SSHSink;
}

/// For enums with an externally provided name
pub trait SSHEncodeEnum {
    /// Returns the current variant, used for encoding parent structs.
    /// Fails if it is Unknown
    fn variant_name(&self) -> WireResult<&'static str>;
}

/// Decodes `struct` and `enum`s without an externally provided enum name
pub trait SSHDecode<'de>: Sized {
    fn dec<S>(s: &mut S) -> WireResult<Self> where S: SSHSource<'de>;
}

/// Decodes enums with an externally provided name
pub trait SSHDecodeEnum<'de>: Sized {
    /// `var` is the variant name to decode, as raw bytes off the wire.
    fn dec_enum<S>(s: &mut S, var: &'de [u8]) -> WireResult<Self> where S: SSHSource<'de>;
}

/// A subset of [`Error`] for `SSHEncode` and `SSHDecode`.
///
/// Compiled code size is very sensitive to the size of this
/// enum so we avoid unused elements.
#[derive(Debug)]
pub enum WireError {
    NoRoom,

    RanOut,

    BadString,

    BadName,

    UnknownVariant,

    PacketWrong,

    SSHProtoError,

    UnknownPacket { number: u8 },
}

impl From<WireError> for Error {
    fn from(w: WireError) -> Self {
        match w {
            WireError::NoRoom => Error::NoRoom,
            WireError::RanOut => Error::RanOut,
            WireError::BadString => Error::BadString,
            WireError::BadName => Error::BadName,
            WireError::SSHProtoError => Error::SSHProtoError,
            WireError::PacketWrong => Error::PacketWrong,
            WireError::UnknownVariant => Error::bug_err_msg("Can't encode Unknown"),
            WireError::UnknownPacket { number } => Error::UnknownPacket { number },
        }
    }
}

pub type WireResult<T> = core::result::Result<T, WireError>;

///////////////////////////////////////////////

/// Parses a [`Packet`] from a borrowed `&[u8]` byte buffer.
pub fn packet_from_bytes<'a>(b: &'a [u8], ctx: &ParseContext) -> Result<Packet<'a>> {
    let ctx = ParseContext { seen_unknown: false, .. ctx.clone()};
    let mut s = DecodeBytes { input: b, pos: 0, parse_ctx: ctx };
    let p = Packet::dec(&mut s)?;

    if s.pos() != b.len() && !s.ctx().seen_unknown {
        // No length check if the packet had an unknown variant
        // - it skipped parsing the remainder of the packet.
        Err(Error::WrongPacketLength)
    } else {
        Ok(p)
    }
}

pub fn read_ssh<'a, T: SSHDecode<'a>>(b: &'a [u8], ctx: Option<ParseContext>) -> Result<T> {
    let mut s = DecodeBytes { input: b, pos: 0, parse_ctx: ctx.unwrap_or_default() };
    Ok(T::dec(&mut s)?)
}

pub fn write_ssh<T>(target: &mut [u8], value: &T) -> Result<usize>
where
    T: SSHEncode,
{
    let mut s = EncodeBytes { target, pos: 0 };
    value.enc(&mut s)?;
    Ok(s.pos)
}

/// Hashes the SSH wire format representation of `value`, with a `u32` length prefix.
pub fn hash_ser_length<T>(hash_ctx: &mut impl digest::DynDigest,
    value: &T) -> Result<()>
where
    T: SSHEncode,
{
    let len: u32 = length_enc(value)?;
    hash_ctx.update(&len.to_be_bytes());
    hash_ser(hash_ctx, value, None)
}

/// Hashes the SSH wire format representation of `value`
pub fn hash_ser<T>(hash_ctx: &mut impl digest::DynDigest,
    value: &T,
    parse_ctx: Option<&ParseContext>,
    ) -> Result<()>
where
    T: SSHEncode,
{
    let mut s = EncodeHash { hash_ctx, parse_ctx: parse_ctx.cloned() };
    value.enc(&mut s)?;
    Ok(())
}

/// Returns `WireError::NoRoom` if larger than `u32`
fn length_enc<T>(value: &T) -> WireResult<u32>
where
    T: SSHEncode,
{
    let mut s = EncodeLen { pos: 0 };
    value.enc(&mut s)?;
    s.pos.try_into().map_err(|_| WireError::NoRoom)
}

struct EncodeBytes<'a> {
    target: &'a mut [u8],
    pos: usize,
}

impl SSHSink for EncodeBytes<'_> {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        if self.pos + v.len() > self.target.len() {
            return Err(WireError::NoRoom);
        }
        self.target[self.pos..self.pos + v.len()].copy_from_slice(v);
        self.pos += v.len();
        Ok(())
    }
}

struct EncodeLen {
    pos: usize,
}

impl SSHSink for EncodeLen {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        self.pos += v.len();
        Ok(())
    }
}

struct EncodeHash<'a> {
    hash_ctx: &'a mut dyn digest::DynDigest,
    parse_ctx: Option<ParseContext>,
}

impl SSHSink for EncodeHash<'_> {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        self.hash_ctx.update(v);
        Ok(())
    }

    fn ctx(&self) -> Option<&ParseContext> {
        self.parse_ctx.as_ref()
    }
}

struct DecodeBytes<'a> {
    input: &'a [u8],
    pos: usize,
    parse_ctx: ParseContext,
}

impl<'de> SSHSource<'de> for DecodeBytes<'de> {
    fn take(&mut self, len: usize) -> WireResult<&'de [u8]> {
        if len > self.input.len() {
            return Err(WireError::RanOut);
        }
        let t;
        (t, self.input) = self.input.split_at(len);
        self.pos += len;
        Ok(t)
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn ctx(&mut self) -> &mut ParseContext {
        &mut self.parse_ctx
    }
}

// Hashes a slice to be treated as a mpint. Has u32 length prefix
// and an extra 0x00 byte if the MSB is set.
pub fn hash_mpint(hash_ctx: &mut dyn digest::DynDigest, m: &[u8]) {
    let pad = m.len() > 0 && (m[0] & 0x80) != 0;
    let l = m.len() as u32 + pad as u32;
    hash_ctx.update(&l.to_be_bytes());
    if pad {
        hash_ctx.update(&[0x00]);
    }
    hash_ctx.update(m);
}

///////////////////////////////////////////////

/// A SSH style binary string. Serialized as `u32` length followed by the bytes
/// of the slice.
/// Application API
#[derive(Clone,PartialEq)]
pub struct BinString<'a>(pub &'a [u8]);

impl<'a> AsRef<[u8]> for BinString<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> Debug for BinString<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BinString(len={})", self.0.len())
    }
}

impl SSHEncode for BinString<'_> {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: sshwire::SSHSink {
        (self.0.len() as u32).enc(s)?;
        self.0.enc(s)
    }
}

impl<'de> SSHDecode<'de> for BinString<'de> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: sshwire::SSHSource<'de> {
        let len = u32::dec(s)? as usize;
        Ok(BinString(s.take(len)?))
    }

}

/// A text string that may be presented to a user or used
/// for things such as a password, username, exec command, TCP hostname, etc.
///
/// The SSH protocol defines it to be UTF-8, though
/// in some applications it could be treated as ASCII-only.
/// The library treats it as an opaque `&[u8]`, leaving
/// decoding to the [`Behaviour`].
///
/// Note that SSH protocol identifiers in `Packet` etc
/// are `&str` rather than `TextString`, and always defined as ASCII.
/// Application API
#[derive(Clone,PartialEq,Copy)]
pub struct TextString<'a>(pub &'a [u8]);

impl<'a> TextString<'a> {
    /// Returns the UTF-8 decoded string, using [`core::str::from_utf8`]
    /// Don't call this if you are avoiding including UTF-8 routines in
    /// the binary.
    pub fn as_str(&self) -> Result<&'a str> {
        core::str::from_utf8(self.0).map_err(|_| Error::BadString)
    }

    pub fn as_ascii(&self) -> Result<&'a str> {
        self.0.as_ascii_str().map_err(|_| Error::BadString).map(|s| s.as_str())
    }
}

impl<'a> AsRef<[u8]> for TextString<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> From<&'a str> for TextString<'a> {
    fn from(s: &'a str) -> Self {
        TextString(s.as_bytes())
    }
}

impl<'a> Debug for TextString<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.0);
        if let Ok(s) = s {
            write!(f, "TextString(\"{}\")", s.escape_default())
        } else {
            write!(f, "TextString(not utf8!, {:#?})", self.0.hex_dump())
        }
    }
}

impl SSHEncode for TextString<'_> {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: sshwire::SSHSink {
        (self.0.len() as u32).enc(s)?;
        self.0.enc(s)
    }
}

impl<'de> SSHDecode<'de> for TextString<'de> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: sshwire::SSHSource<'de> {
        let len = u32::dec(s)? as usize;
        Ok(TextString(s.take(len)?))
    }
}

/// A wrapper for a `u32` length prefixed data structure `B`, such as a public key blob
pub struct Blob<B>(pub B);

impl<B> AsRef<B> for Blob<B> {
    fn as_ref(&self) -> &B {
        &self.0
    }
}

impl<B: Clone> Clone for Blob<B> {
    fn clone(&self) -> Self {
        Blob(self.0.clone())
    }
}

impl<B: SSHEncode + Debug> Debug for Blob<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(len) = sshwire::length_enc(&self.0) {
            write!(f, "Blob(len={len}, {:?})", self.0)
        } else {
            write!(f, "Blob(len>u32, {:?})", self.0)
        }
    }
}

impl<B: SSHEncode> SSHEncode for Blob<B> {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: sshwire::SSHSink {
        let len: u32 = sshwire::length_enc(&self.0)?;
        len.enc(s)?;
        self.0.enc(s)
    }
}

impl<'de, B: SSHDecode<'de>> SSHDecode<'de> for Blob<B> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: sshwire::SSHSource<'de> {
        let len = u32::dec(s)? as usize;
        let pos1 = s.pos();
        let inner = SSHDecode::dec(s)?;
        let pos2 = s.pos();

        // Sanity check the length matched
        let used_len = pos2 - pos1;
        if used_len == len {
            Ok(Blob(inner))
        } else {
            let extra = len.checked_sub(used_len).ok_or_else(|| {
                trace!("inner consumed past length of SSH Blob. \
                    Expected {} bytes, got {} bytes {}..{}",
                    len, pos2-pos1, pos1, pos2);
                WireError::SSHProtoError
            })?;
            // Skip over unconsumed bytes in the blob.
            // This can occur with Unknown variants
            s.take(extra)?;
            Ok(Blob(inner))
        }
    }
}

///////////////////////////////////////////////

impl SSHEncode for u8 {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        s.push(&[*self])
    }
}

impl SSHEncode for bool {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        (*self as u8).enc(s)
    }
}

impl SSHEncode for u32 {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        s.push(&self.to_be_bytes())
    }
}

// no length prefix
impl SSHEncode for &[u8] {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        // data
        s.push(&self)
    }
}

// no length prefix
impl<const N: usize> SSHEncode for [u8; N] {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        s.push(self)
    }
}

impl SSHEncode for &str {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        let v = self.as_bytes();
        // length prefix
        (v.len() as u32).enc(s)?;
        s.push(v)
    }
}

impl<T: SSHEncode> SSHEncode for Option<T> {
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        if let Some(t) = self.as_ref() {
            t.enc(s)?;
        }
        Ok(())
    }
}

impl SSHEncode for &AsciiStr{
    fn enc<S>(&self, s: &mut S) -> WireResult<()>
    where S: SSHSink {
        let v = self.as_bytes();
        BinString(v).enc(s)
    }
}

impl<'de> SSHDecode<'de> for bool {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        Ok(u8::dec(s)? != 0)
    }
}

// #[inline] seems to decrease code size somehow

impl<'de> SSHDecode<'de> for u8 {
    #[inline]
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        let t = s.take(core::mem::size_of::<u8>())?;
        Ok(u8::from_be_bytes(t.try_into().unwrap()))
    }
}

impl<'de> SSHDecode<'de> for u32 {
    #[inline]
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        let t = s.take(core::mem::size_of::<u32>())?;
        Ok(u32::from_be_bytes(t.try_into().unwrap()))
    }
}

/// Decodes a SSH name string. Must be ASCII
/// without control characters. RFC4251 section 6.
pub fn try_as_ascii<'a>(t: &'a [u8]) -> WireResult<&'a AsciiStr> {
    let n = t.as_ascii_str().map_err(|_| WireError::BadName)?;
    if n.chars().any(|ch| ch.is_ascii_control() || ch == AsciiChar::DEL) {
        return Err(WireError::BadName);
    }
    Ok(n)
}

pub fn try_as_ascii_str<'a>(t: &'a [u8]) -> WireResult<&'a str> {
    try_as_ascii(t).map(AsciiStr::as_str)
}

impl<'de: 'a, 'a> SSHDecode<'de> for &'a str {
    #[inline]
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        let len = u32::dec(s)?;
        let t = s.take(len as usize)?;
        try_as_ascii_str(t)
    }
}

impl<'de: 'a, 'a> SSHDecode<'de> for &'de AsciiStr {
    fn dec<S>(s: &mut S) -> WireResult<&'de AsciiStr>
    where
        S: SSHSource<'de>, {
        let b: BinString = SSHDecode::dec(s)?;
        try_as_ascii(b.0)
    }
}

impl<'de, const N: usize> SSHDecode<'de> for [u8; N] {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        // TODO is there a better way? Or can we return a slice?
        let mut l = [0u8; N];
        l.copy_from_slice(s.take(N)?);
        Ok(l)
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use crate::*;
    use sunsetlog::init_test_log;
    use error::Error;
    use packets::*;
    use sshwire::*;
    use pretty_hex::PrettyHex;

    /// Checks that two items serialize the same
    pub fn assert_serialize_equal<'de, T: SSHEncode>(p1: &T, p2: &T) {
        let mut buf1 = vec![99; 2000];
        let mut buf2 = vec![88; 1000];
        let l1 = write_ssh(&mut buf1, p1).unwrap();
        let l2 = write_ssh(&mut buf2, p2).unwrap();
        buf1.truncate(l1);
        buf2.truncate(l2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    /// check that hash_ser_length() matches hashing a serialized message
    fn test_hash_packet() {
        use sha2::Sha256;
        use digest::Digest;
        let input = "hello";
        let mut buf = vec![99; 20];
        let w1 = write_ssh(&mut buf, &input).unwrap();
        buf.truncate(w1);

        // hash_ser_length
        let mut hash_ctx = Sha256::new();
        hash_ser_length(&mut hash_ctx, &input).unwrap();
        let digest1 = hash_ctx.finalize();

        let mut hash_ctx = Sha256::new();
        hash_ctx.update(&(w1 as u32).to_be_bytes());
        hash_ctx.update(&buf);
        let digest2 = hash_ctx.finalize();

        assert_eq!(digest1, digest2);

        // hash_ser
        let mut hash_ctx = Sha256::new();
        hash_ctx.update(&(w1 as u32).to_be_bytes());
        hash_ser(&mut hash_ctx, &input, None).unwrap();
        let digest3 = hash_ctx.finalize();
        assert_eq!(digest3, digest2);
    }

    pub fn test_roundtrip_context(p: &Packet, ctx: &ParseContext) {
        let mut buf = vec![99; 200];
        let l = write_ssh(&mut buf, p).unwrap();
        buf.truncate(l);
        trace!("wrote packet {:?}", buf.hex_dump());

        let p2 = packet_from_bytes(&buf, &ctx).unwrap();
        trace!("returned packet {:#?}", p2);
        assert_serialize_equal(p, &p2);
    }

    /// With default context
    pub fn test_roundtrip(p: &Packet) {
        test_roundtrip_context(&p, &ParseContext::default());
    }

    /// Tests parsing a packet with a ParseContext.
    #[test]
    fn test_parse_context() {
        init_test_log();
        let mut ctx = ParseContext::new();

        let p = Userauth60::PwChangeReq(UserauthPwChangeReq {
            prompt: "change the password".into(),
            lang: "".into(),
        }).into();
        let mut pw = ResponseString::new();
        pw.push_str("123").unwrap();
        ctx.cli_auth_type = Some(auth::AuthType::Password);
        test_roundtrip_context(&p, &ctx);

        // PkOk is a more interesting case because the PubKey inside it is also
        // an enum but that can identify its own enum variant.
        let p = Userauth60::PkOk(UserauthPkOk {
            algo: "ed25519",
            key: Blob(PubKey::Ed25519(Ed25519PubKey {
                key: BinString(&[0x11, 0x22, 0x33]),
            })),
        }).into();
        let s = SignKey::generate(KeyType::Ed25519).unwrap();
        ctx.cli_auth_type = Some(auth::AuthType::PubKey);
        test_roundtrip_context(&p, &ctx);
    }
}
