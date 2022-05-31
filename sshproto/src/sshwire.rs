#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::str;

use crate::*;
use packets::{Packet, ParseContext};


pub trait SSHSink {
    fn push(&mut self, v: &[u8]) -> Result<()>;
    fn ctx(&self) -> Option<&ParseContext> {
        None
    }
}

pub trait SSHSource<'de> {
    fn take(&mut self, len: usize) -> Result<&'de [u8]>;
    fn ctx(&self) -> &ParseContext;
}

pub trait SSHEncode {
    fn enc<S>(&self, s: &mut S) -> Result<()> where S: SSHSink;
}

/// For enums with an externally provided name
pub trait SSHEncodeEnum {
    /// Returns the current variant, used for encoding parent structs.
    /// Fails if it is Unknown
    fn variant_name(&self) -> Result<&'static str>;
}

/// Decodes `struct` and `enum`s without an externally provided enum name
pub trait SSHDecode<'de>: Sized {
    fn dec<S>(s: &mut S) -> Result<Self> where S: SSHSource<'de>;
}

/// Decodes enums with an externally provided name
pub trait SSHDecodeEnum<'de>: Sized {
    /// `var` is the variant name to decode
    fn dec_enum<S>(s: &mut S, var: &'de str) -> Result<Self> where S: SSHSource<'de>;
}

///////////////////////////////////////////////

/// Parses a [`Packet`] from a borrowed `&[u8]` byte buffer.
pub fn packet_from_bytes<'a>(b: &'a [u8], ctx: &ParseContext) -> Result<Packet<'a>> {
    let mut s = DecodeBytes { input: b, pos: 0, parse_ctx: ctx.clone() };
    Packet::dec(&mut s).map_err(|e| {
        // TODO better handling of this. Stuff it in PacketState.
        // Also should return which MessageNumber failed in later parsing
        if let Error::InvalidDeserializeU8 { value } = e {
            // This assumes that the only deserialize that can hit
            // invalid_value() is an unknown packet type. Seems safe at present.
            Error::UnknownPacket { number: value }
        } else {
            e
        }
    })
}

pub fn write_ssh<T>(target: &mut [u8], value: &T) -> Result<usize>
where
    T: SSHEncode,
{
    let mut s = EncodeBytes { target, pos: 0 };
    value.enc(&mut s)?;
    Ok(s.pos)
}

pub fn length_enc<T>(value: &T) -> Result<usize>
where
    T: SSHEncode,
{
    let mut s = EncodeLen { pos: 0 };
    value.enc(&mut s)?;
    Ok(s.pos)
}

struct EncodeBytes<'a> {
    target: &'a mut [u8],
    pos: usize,
}

impl SSHSink for EncodeBytes<'_> {
    fn push(&mut self, v: &[u8]) -> Result<()> {
        if self.pos + v.len() > self.target.len() {
            return Err(Error::NoRoom);
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
    fn push(&mut self, v: &[u8]) -> Result<()> {
        self.pos += v.len();
        Ok(())
    }
}

struct EncodeHash<'a> {
    hash_ctx: &'a mut dyn digest::DynDigest,
    parse_ctx: Option<ParseContext>,
}

impl SSHSink for EncodeHash<'_> {
    fn push(&mut self, v: &[u8]) -> Result<()> {
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
    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        if len > self.input.len() {
            return Err(Error::RanOut);
        }
        let t;
        (t, self.input) = self.input.split_at(len);
        self.pos += len;
        Ok(t)
    }

    fn ctx(&self) -> &ParseContext {
        &self.parse_ctx
    }
}

///////////////////////////////////////////////

impl SSHEncode for u8 {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        s.push(&[*self])
    }
}

impl SSHEncode for bool {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        (*self as u8).enc(s)
    }
}

impl SSHEncode for u32 {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        s.push(&self.to_be_bytes())
    }
}

// no length prefix
impl SSHEncode for &[u8] {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        // data
        s.push(&self)
    }
}

// no length prefix
impl<const N: usize> SSHEncode for [u8; N] {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        s.push(self)
    }
}

impl SSHEncode for &str {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        let v = self.as_bytes();
        // length prefix
        (v.len() as u32).enc(s)?;
        s.push(v)
    }
}

impl<T: SSHEncode> SSHEncode for Option<T> {
    fn enc<S>(&self, s: &mut S) -> Result<()>
    where S: SSHSink {
        if let Some(t) = self.as_ref() {
            t.enc(s)?;
        }
        Ok(())
    }
}

impl<'de> SSHDecode<'de> for bool {
    fn dec<S>(s: &mut S) -> Result<Self>
    where S: SSHSource<'de> {
        Ok(u8::dec(s)? != 0)
    }
}

// TODO: inline seemed to help code size in wireformat?
impl<'de> SSHDecode<'de> for u8 {
    #[inline]
    fn dec<S>(s: &mut S) -> Result<Self>
    where S: SSHSource<'de> {
        let t = s.take(core::mem::size_of::<u8>())?;
        Ok(u8::from_be_bytes(t.try_into().unwrap()))
    }
}

impl<'de> SSHDecode<'de> for u32 {
    #[inline]
    fn dec<S>(s: &mut S) -> Result<Self>
    where S: SSHSource<'de> {
        let t = s.take(core::mem::size_of::<u32>())?;
        Ok(u32::from_be_bytes(t.try_into().unwrap()))
    }
}

impl<'de: 'a, 'a> SSHDecode<'de> for &'a str {
    #[inline]
    fn dec<S>(s: &mut S) -> Result<Self>
    where S: SSHSource<'de> {
        let len = u32::dec(s)?;
        let t = s.take(len as usize)?;
        str::from_utf8(t).map_err(|_| Error::BadString)
    }
}

impl<'de, const N: usize> SSHDecode<'de> for [u8; N] {
    fn dec<S>(s: &mut S) -> Result<Self>
    where S: SSHSource<'de> {
        // TODO is there a better way? Or can we return a slice?
        let mut l = [0u8; N];
        l.copy_from_slice(s.take(N)?);
        Ok(l)
    }
}
