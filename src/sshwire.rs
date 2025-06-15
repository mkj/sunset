//! SSH wire format reading/writing.
//!
//! Used in conjunction with [`sunset_sshwire_derive`] and the [`packet`](crate::packets) format
//! definitions.
//!
//! SSH wire format is described in [RFC4251](https://tools.ietf.org/html/rfc4251) SSH Architecture

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::convert::AsRef;
use core::fmt::{self, Debug, Display};
use core::str::FromStr;
use digest::Output;
use pretty_hex::PrettyHex;
use snafu::{prelude::*, Location};

use ascii::{AsAsciiStr, AsciiChar, AsciiStr};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};

use digest::Digest;

use crate::*;
use packets::{Packet, ParseContext};

/// A generic destination for serializing, used similarly to `serde::Serializer`
pub trait SSHSink {
    fn push(&mut self, v: &[u8]) -> WireResult<()>;
}

/// A generic source for a packet, used similarly to `serde::Deserializer`
pub trait SSHSource<'de> {
    fn take(&mut self, len: usize) -> WireResult<&'de [u8]>;
    fn remaining(&self) -> usize;
    fn ctx(&mut self) -> &mut ParseContext;
}

/// Encodes the type in SSH wire format
pub trait SSHEncode {
    /// Encode data
    ///
    /// The state of the `SSHSink` is undefined after an error is returned, data may
    /// have been partially encoded.
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()>;
}

/// For enums with an externally provided name
pub trait SSHEncodeEnum {
    /// Returns the current variant, used for encoding parent structs.
    /// Fails if it is Unknown
    fn variant_name(&self) -> WireResult<&'static str>;
}

/// Decodes `struct` and `enum`s without an externally provided enum name
pub trait SSHDecode<'de>: Sized {
    /// Decode data
    ///
    /// The state of the `SSHSource` is undefined after an error is returned, data may
    /// have been partially consumed.
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>;
}

/// Decodes enums with an externally provided name
pub trait SSHDecodeEnum<'de>: Sized {
    /// `var` is the variant name to decode, as raw bytes off the wire.
    fn dec_enum<S>(s: &mut S, var: &'de [u8]) -> WireResult<Self>
    where
        S: SSHSource<'de>;
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

    SSHProto,

    BadKeyFormat,

    UnknownPacket { number: u8 },
}

impl From<WireError> for Error {
    fn from(w: WireError) -> Self {
        match w {
            WireError::NoRoom => error::NoRoom.build(),
            WireError::RanOut => error::RanOut.build(),
            WireError::BadString => Error::BadString,
            WireError::BadName => Error::BadName,
            WireError::SSHProto => error::SSHProto.build(),
            WireError::PacketWrong => error::PacketWrong.build(),
            WireError::BadKeyFormat => Error::BadKeyFormat,
            WireError::UnknownVariant => Error::bug_err_msg("Can't encode Unknown"),
            WireError::UnknownPacket { number } => Error::UnknownPacket { number },
        }
    }
}

pub type WireResult<T> = core::result::Result<T, WireError>;

///////////////////////////////////////////////

/// Parses a [`Packet`] from a borrowed `&[u8]` byte buffer.
pub fn packet_from_bytes<'a>(b: &'a [u8], ctx: &ParseContext) -> Result<Packet<'a>> {
    let ctx = ParseContext { seen_unknown: false, ..ctx.clone() };
    let mut s = DecodeBytes { input: b, parse_ctx: ctx };
    let p = Packet::dec(&mut s)?;

    if s.input.len() != 0 && !s.ctx().seen_unknown {
        // No length check if the packet had an unknown variant
        // - it skipped parsing the remainder of the packet.
        Err(Error::WrongPacketLength)
    } else {
        Ok(p)
    }
}

pub fn read_ssh<'a, T: SSHDecode<'a>>(
    b: &'a [u8],
    ctx: Option<ParseContext>,
) -> Result<T> {
    let mut s = DecodeBytes { input: b, parse_ctx: ctx.unwrap_or_default() };
    Ok(T::dec(&mut s)?)
}

pub fn write_ssh(target: &mut [u8], value: &dyn SSHEncode) -> Result<usize> {
    let mut s = EncodeBytes { target };
    value.enc(&mut s)?;
    let end_len = s.target.len();
    debug_assert!(target.len() >= end_len);
    Ok(target.len() - end_len)
}

#[cfg(feature = "std")]
pub fn ssh_push_vec(target: &mut Vec<u8>, value: &dyn SSHEncode) -> Result<()> {
    let orig = target.len();
    let l = length_enc(value)? as usize;
    target.resize(orig + l, 0);
    write_ssh(&mut target[orig..], value)?;
    Ok(())
}

/// Hashes the SSH wire format representation of `value`, with a `u32` length prefix.
pub fn hash_ser_length(
    hash_ctx: &mut impl SSHWireDigestUpdate,
    value: &dyn SSHEncode,
) -> Result<()> {
    let len: u32 = length_enc(value)?;
    hash_ctx.digest_update(&len.to_be_bytes());
    hash_ser(hash_ctx, value)
}

/// Hashes the SSH wire format representation of `value`
///
/// Will only fail if `value.enc()` can return an error.
pub fn hash_ser(
    hash_ctx: &mut impl SSHWireDigestUpdate,
    value: &dyn SSHEncode,
) -> Result<()> {
    let mut s = EncodeHash { hash_ctx };
    value.enc(&mut s)?;
    Ok(())
}

/// Returns `WireError::NoRoom` if larger than `u32`
pub fn length_enc(value: &dyn SSHEncode) -> WireResult<u32> {
    let mut s = EncodeLen { pos: 0 };
    value.enc(&mut s)?;
    s.pos.try_into().map_err(|_| WireError::NoRoom)
}

struct EncodeBytes<'a> {
    target: &'a mut [u8],
}

impl<'a> SSHSink for EncodeBytes<'a> {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        if v.len() > self.target.len() {
            return Err(WireError::NoRoom);
        }
        // keep the borrow checker happy
        let tmp = core::mem::replace(&mut self.target, &mut []);
        let t;
        (t, self.target) = tmp.split_at_mut(v.len());
        t.copy_from_slice(v);
        Ok(())
    }
}

struct EncodeLen {
    pos: usize,
}

impl SSHSink for EncodeLen {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        self.pos = self.pos.checked_add(v.len()).ok_or(WireError::NoRoom)?;
        Ok(())
    }
}

struct EncodeHash<'a> {
    hash_ctx: &'a mut dyn SSHWireDigestUpdate,
}

impl SSHSink for EncodeHash<'_> {
    fn push(&mut self, v: &[u8]) -> WireResult<()> {
        self.hash_ctx.digest_update(v);
        Ok(())
    }
}

struct DecodeBytes<'a> {
    input: &'a [u8],
    parse_ctx: ParseContext,
}

impl<'de> SSHSource<'de> for DecodeBytes<'de> {
    fn take(&mut self, len: usize) -> WireResult<&'de [u8]> {
        if len > self.input.len() {
            return Err(WireError::RanOut);
        }
        let t;
        (t, self.input) = self.input.split_at(len);
        Ok(t)
    }

    fn remaining(&self) -> usize {
        self.input.len()
    }

    fn ctx(&mut self) -> &mut ParseContext {
        &mut self.parse_ctx
    }
}

// Hashes a slice to be treated as a mpint. Has u32 length prefix
// and an extra 0x00 byte if the MSB is set.
pub fn hash_mpint(hash_ctx: &mut dyn SSHWireDigestUpdate, m: &[u8]) {
    let pad = !m.is_empty() && (m[0] & 0x80) != 0;
    let l = m.len() as u32 + pad as u32;
    hash_ctx.digest_update(&l.to_be_bytes());
    if pad {
        hash_ctx.digest_update(&[0x00]);
    }
    hash_ctx.digest_update(m);
}

///////////////////////////////////////////////

/// A SSH style binary string. Serialized as `u32` length followed by the bytes
/// of the slice.
/// Application API
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct BinString<'a>(pub &'a [u8]);

impl AsRef<[u8]> for BinString<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl Debug for BinString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BinString(len={})", self.0.len())
    }
}

impl SSHEncode for BinString<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        (self.0.len() as u32).enc(s)?;
        self.0.enc(s)
    }
}

impl<'de> SSHDecode<'de> for BinString<'de> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: sshwire::SSHSource<'de>,
    {
        let len = u32::dec(s)? as usize;
        Ok(BinString(s.take(len)?))
    }
}

impl<const N: usize> SSHEncode for heapless::String<N> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        self.as_str().enc(s)
    }
}

/// A text string that may be presented to a user or used
/// for things such as a password, username, exec command, TCP hostname, etc.
///
/// The SSH protocol defines it to be UTF-8, though
/// in some applications it could be treated as ASCII-only.
/// Sunset treats it as an opaque `&[u8]`, leaving
/// interpretation to the application.
///
/// Note that SSH protocol identifiers in [`Packet`]
/// are `&str` rather than `TextString`, and always defined as ASCII. For
/// example `"publickey"`, `"ssh-ed25519"`.
///
/// Application API
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct TextString<'a>(pub &'a [u8]);

impl<'a> TextString<'a> {
    /// Returns the UTF-8 decoded string, using [`core::str::from_utf8`]
    ///
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

impl Debug for TextString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.0);
        if let Ok(s) = s {
            write!(f, "TextString(\"{}\")", s.escape_default())
        } else {
            write!(f, "TextString(not utf8!, {:#?})", self.0.hex_dump())
        }
    }
}

impl Display for TextString<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = core::str::from_utf8(self.0);
        if let Ok(s) = s {
            write!(f, "\"{}\"", s.escape_default())
        } else {
            write!(f, "{:?}", self)
        }
    }
}

impl SSHEncode for TextString<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        (self.0.len() as u32).enc(s)?;
        self.0.enc(s)
    }
}

impl<'de> SSHDecode<'de> for TextString<'de> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: sshwire::SSHSource<'de>,
    {
        let len = u32::dec(s)? as usize;
        Ok(TextString(s.take(len)?))
    }
}

/// A wrapper for a `u32` length prefixed data structure `B`, such as a public key blob
#[derive(PartialEq, Clone)]
pub struct Blob<B>(pub B);

#[cfg(feature = "arbitrary")]
impl<'arb: 'a, 'a, B: Arbitrary<'arb>> Arbitrary<'arb> for Blob<B> {
    fn arbitrary(u: &mut Unstructured<'arb>) -> arbitrary::Result<Self> {
        Ok(Blob(Arbitrary::arbitrary(u)?))
    }
}

impl<B> AsRef<B> for Blob<B> {
    fn as_ref(&self) -> &B {
        &self.0
    }
}

impl<T: SSHEncode> SSHEncode for &T {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        (*self).enc(s)
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
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let len: u32 = sshwire::length_enc(&self.0)?;
        len.enc(s)?;
        self.0.enc(s)
    }
}

impl<'de, B: SSHDecode<'de>> SSHDecode<'de> for Blob<B> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: sshwire::SSHSource<'de>,
    {
        let len = u32::dec(s)? as usize;
        let rem1 = s.remaining();
        let inner = SSHDecode::dec(s)?;
        let rem2 = s.remaining();

        // Sanity check the length matched
        let used_len = rem1 - rem2;
        if used_len != len {
            if s.ctx().seen_unknown {
                // Skip over unconsumed bytes in the blob.
                // This can occur with Unknown variants
                let extra = len.checked_sub(used_len).ok_or(WireError::SSHProto)?;
                s.take(extra)?;
            } else {
                trace!(
                    "SSH blob length differs. \
                    Expected {} bytes, got {} remaining {}, {}",
                    len,
                    used_len,
                    rem1,
                    rem2
                );
                return Err(WireError::SSHProto);
            }
        }
        Ok(Blob(inner))
    }
}

///////////////////////////////////////////////

impl SSHEncode for u8 {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        s.push(&[*self])
    }
}

impl SSHEncode for bool {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        (*self as u8).enc(s)
    }
}

impl SSHEncode for u32 {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        s.push(&self.to_be_bytes())
    }
}

// no length prefix
impl SSHEncode for &[u8] {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        // data
        s.push(self)
    }
}

// no length prefix
impl<const N: usize> SSHEncode for [u8; N] {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        s.push(self.as_slice())
    }
}

impl SSHEncode for &str {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let v = self.as_bytes();
        // length prefix
        (v.len() as u32).enc(s)?;
        s.push(v)
    }
}

impl<T: SSHEncode> SSHEncode for Option<T> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        if let Some(t) = self.as_ref() {
            t.enc(s)?;
        }
        Ok(())
    }
}

impl SSHEncode for &AsciiStr {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let v = self.as_bytes();
        BinString(v).enc(s)
    }
}

impl<'de> SSHDecode<'de> for bool {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        Ok(u8::dec(s)? != 0)
    }
}

impl<'de> SSHDecode<'de> for u8 {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let t = s.take(core::mem::size_of::<u8>())?;
        Ok(u8::from_be_bytes(t.try_into().unwrap()))
    }
}

impl<'de> SSHDecode<'de> for u32 {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let t = s.take(core::mem::size_of::<u32>())?;
        Ok(u32::from_be_bytes(t.try_into().unwrap()))
    }
}

/// Decodes a SSH name string. Must be ASCII
/// without control characters. RFC4251 section 6.
pub fn try_as_ascii(t: &[u8]) -> WireResult<&AsciiStr> {
    let n = t.as_ascii_str().map_err(|_| WireError::BadName)?;
    if n.chars().any(|ch| ch.is_ascii_control() || ch == AsciiChar::DEL) {
        return Err(WireError::BadName);
    }
    Ok(n)
}

pub fn try_as_ascii_str(t: &[u8]) -> WireResult<&str> {
    try_as_ascii(t).map(AsciiStr::as_str)
}

impl<'de: 'a, 'a> SSHDecode<'de> for &'a str {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let len = u32::dec(s)?;
        let t = s.take(len as usize)?;
        try_as_ascii_str(t)
    }
}

impl<'de: 'a, 'a> SSHDecode<'de> for &'de AsciiStr {
    fn dec<S>(s: &mut S) -> WireResult<&'de AsciiStr>
    where
        S: SSHSource<'de>,
    {
        let b: BinString = SSHDecode::dec(s)?;
        try_as_ascii(b.0)
    }
}

impl<'de, const N: usize> SSHDecode<'de> for &'de [u8; N] {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        // OK unwrap: take() fails if the length is short
        Ok(s.take(N)?.try_into().unwrap())
    }
}

impl<'de, const N: usize> SSHDecode<'de> for [u8; N] {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        // OK unwrap: take() fails if the length is short
        Ok(s.take(N)?.try_into().unwrap())
    }
}

impl<'de, const N: usize> SSHDecode<'de> for heapless::String<N> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        heapless::String::from_str(SSHDecode::dec(s)?).map_err(|_| WireError::NoRoom)
    }
}

/// Like `digest::DynDigest` but simpler.
///
/// Doesn't have any optional methods that depend on `alloc`.
pub trait SSHWireDigestUpdate {
    fn digest_update(&mut self, data: &[u8]);
}

impl SSHWireDigestUpdate for sha2::Sha256 {
    fn digest_update(&mut self, data: &[u8]) {
        self.update(data)
    }
}

impl SSHWireDigestUpdate for sha2::Sha512 {
    fn digest_update(&mut self, data: &[u8]) {
        self.update(data)
    }
}

#[cfg(feature = "rsa")]
fn top_bit_set(b: &[u8]) -> bool {
    b.first().unwrap_or(&0) & 0x80 != 0
}

#[cfg(feature = "rsa")]
impl SSHEncode for rsa::BigUint {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let b = self.to_bytes_be();
        let b = b.as_slice();

        // rfc4251 mpint, need a leading zero byte if top bit is set
        let pad = top_bit_set(b);
        let len = b.len() as u32 + pad as u32;
        len.enc(s)?;

        if pad {
            0u8.enc(s)?;
        }

        b.enc(s)
    }
}

#[cfg(feature = "rsa")]
impl<'de> SSHDecode<'de> for rsa::BigUint {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let b = BinString::dec(s)?;
        if top_bit_set(b.0) {
            trace!("received negative mpint");
            return Err(WireError::BadKeyFormat);
        }
        Ok(rsa::BigUint::from_bytes_be(b.0))
    }
}

// TODO: is there already something like this?
pub enum OwnOrBorrow<'a, T> {
    Own(T),
    Borrow(&'a T),
}

impl<T: SSHEncode> SSHEncode for OwnOrBorrow<'_, T> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        match self {
            Self::Own(t) => t.enc(s),
            Self::Borrow(t) => t.enc(s),
        }
    }
}

impl<'de, T: SSHDecode<'de>> SSHDecode<'de> for OwnOrBorrow<'_, T> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        Ok(Self::Own(T::dec(s)?))
    }
}

impl<'a, T> core::borrow::Borrow<T> for OwnOrBorrow<'a, T> {
    fn borrow(&self) -> &T {
        match self {
            Self::Own(t) => t,
            Self::Borrow(t) => t,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::*;
    use error::Error;
    use packets::*;
    use pretty_hex::PrettyHex;
    use sshwire::*;
    use sunsetlog::init_test_log;

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
        use digest::Digest;
        use sha2::Sha256;
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
        hash_ser(&mut hash_ctx, &input).unwrap();
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
        })
        .into();
        ctx.cli_auth_type = Some(auth::AuthType::Password);
        test_roundtrip_context(&p, &ctx);

        // PkOk is a more interesting case because the PubKey inside it is also
        // an enum but that can identify its own enum variant.
        let p = Userauth60::PkOk(UserauthPkOk {
            algo: "ed25519",
            key: Blob(PubKey::Ed25519(Ed25519PubKey { key: Blob([0x11; 32]) })),
        })
        .into();
        ctx.cli_auth_type = Some(auth::AuthType::PubKey);
        test_roundtrip_context(&p, &ctx);
    }

    // Some other blob decoding tests are in packets module

    #[test]
    fn wrong_blob_size() {
        let p1 = Blob(BinString(b"hello"));

        let mut buf1 = vec![88; 1000];
        let l = write_ssh(&mut buf1, &p1).unwrap();
        // some leeway
        buf1.truncate(l + 5);
        // make the length one extra
        buf1[3] += 1;
        let r: Result<Blob<BinString>, _> = read_ssh(&buf1, None);
        assert!(matches!(r.unwrap_err(), Error::SSHProto { .. }));

        let mut buf1 = vec![88; 1000];
        let l = write_ssh(&mut buf1, &p1).unwrap();
        // some leeway
        buf1.truncate(l + 5);
        // make the length one short
        buf1[3] -= 1;
        let r: Result<Blob<BinString>, _> = read_ssh(&buf1, None);
        assert!(matches!(r.unwrap_err(), Error::SSHProto { .. }));
    }

    #[test]
    fn wrong_packet_size() {
        let p1 = packets::NewKeys {};
        let p1: Packet = p1.into();
        let ctx = ParseContext::new();

        let mut buf1 = vec![88; 1000];
        let l = write_ssh(&mut buf1, &p1).unwrap();

        // too long
        buf1.truncate(l + 1);
        let r = packet_from_bytes(&buf1, &ctx);
        assert!(matches!(r.unwrap_err(), Error::WrongPacketLength));

        // success
        buf1.truncate(l);
        packet_from_bytes(&buf1, &ctx).unwrap();

        // short
        buf1.truncate(l - 1);
        let r = packet_from_bytes(&buf1, &ctx);
        assert!(matches!(r.unwrap_err(), Error::RanOut { .. }));
    }

    #[test]
    fn overflow_encode() {
        let mut buf1 = vec![22; 7];

        assert_eq!(write_ssh(&mut buf1, &"").unwrap(), 4);
        assert_eq!(write_ssh(&mut buf1, &"a").unwrap(), 5);
        assert_eq!(write_ssh(&mut buf1, &"aa").unwrap(), 6);
        assert_eq!(write_ssh(&mut buf1, &"aaa").unwrap(), 7);
        assert!(matches!(
            write_ssh(&mut buf1, &"aaaa").unwrap_err(),
            Error::NoRoom { .. }
        ));
    }
}
