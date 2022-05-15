//! SSH protocol serialization.
//! Implements enough of serde to handle the formats defined in [`crate::packets`]

//! See [RFC4251](https://datatracker.ietf.org/doc/html/rfc4251) for encodings,
//! [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253) and others for packet structure
use serde::de::value::{BorrowedStrDeserializer, SeqAccessDeserializer};
use serde::{
    de::{self, value::MapAccessDeserializer, IntoDeserializer, MapAccess},
    de::{DeserializeSeed, EnumAccess, SeqAccess, VariantAccess, Visitor},
    ser,
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

use pretty_hex::PrettyHex;
#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::packets::{Packet, PacketState, ParseContext};
use crate::{packets::UserauthPkOk, *};
use core::cell::Cell;
use core::convert::AsRef;
use core::fmt::{self,Debug};
use core::slice;
use core::marker::PhantomData;

/// Parses a [`Packet`] from a borrowed `&[u8]` byte buffer.
pub fn packet_from_bytes<'a>(
    b: &'a [u8], ctx: &'a ParseContext<'a>,
) -> Result<Packet<'a>> {
    let mut ds = DeSSHBytes::from_bytes(b, ctx);
    Packet::deserialize(&mut ds).map_err(|e| {
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
    // TODO check for trailing bytes, pos != b.len()
}

// Hashes a slice to be treated as a mpint. Has u32 length prefix
// and an extra 0x00 byte if the MSB is set.
pub fn hash_mpint(hash_ctx: &mut ring::digest::Context, m: &[u8]) {
    let pad = m.len() > 0 && (m[0] & 0x80) != 0;
    let l = m.len() as u32 + pad as u32;
    hash_ctx.update(&l.to_be_bytes());
    if pad {
        hash_ctx.update(&[0x00]);
    }
    hash_ctx.update(m);
}

/// Writes a SSH packet to a buffer. Returns the length written.
pub fn write_ssh<T>(target: &mut [u8], value: &T) -> Result<usize>
where
    T: Serialize,
{
    let mut serializer = SeSSHBytes::WriteBytes { target, pos: 0 };
    value.serialize(&mut serializer)?;
    Ok(match serializer {
        SeSSHBytes::WriteBytes { target: _, pos } => pos,
        _ => 0, // TODO is there a better syntax here? we know it's always WriteBytes
    })
}

/// Hashes the contents of a SSH packet, updating the provided context.
/// Adds a `u32` length prefix.
pub fn hash_ser_length<T>(
    hash_ctx: &mut ring::digest::Context, value: &T,
) -> Result<()>
where
    T: Serialize,
{
    // calculate the u32 length prefix
    let len = SeSSHBytes::get_length(value)? as u32;
    hash_ctx.update(&len.to_be_bytes());
    let mut serializer = SeSSHBytes::WriteHash { hash_ctx };
    // the rest of the packet
    value.serialize(&mut serializer)?;
    Ok(())
}

/// Hashes the contents of a `Serialize` item such as a public key.
/// No length prefix is added.
pub fn hash_ser<T>(hash_ctx: &mut ring::digest::Context, value: &T) -> Result<()>
where
    T: Serialize,
{
    let mut serializer = SeSSHBytes::WriteHash { hash_ctx };
    value.serialize(&mut serializer)?;
    Ok(())
}

type Res = Result<()>;

/// A SSH style binary string. Serialized as 32 bit length followed by the bytes
/// of the slice.
#[derive(Deserialize,Clone)]
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

impl<'a> Serialize for BinString<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0)
    }
}

// a wrapper for a u32 prefixed data structure `B`, such as a public key blob
pub struct Blob<B>(pub B);

impl<B> AsRef<B> for Blob<B> {
    fn as_ref(&self) -> &B {
        &self.0
    }
}

impl<B: Serialize + Debug> Debug for Blob<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let len = SeSSHBytes::get_length(&self.0)
            .map_err(|_| ser::Error::custom(Error::bug()))?;
        write!(f, "Blob(len={len}, {:?})", self.0)
    }
}

impl<B: Serialize> Serialize for Blob<B> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        let len = SeSSHBytes::get_length(&self.0)
            .map_err(|_| ser::Error::custom(Error::bug()))? as u32;
        seq.serialize_element(&len)?;
        seq.serialize_element(&self.0)?;
        seq.end()
    }
}

impl<'de, B: Deserialize<'de> + Serialize> Deserialize<'de> for Blob<B> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Vis<'de, B> {
            ph: PhantomData<B>,
            lifetime: PhantomData<&'de ()>,
        }

        impl<'de, B: Deserialize<'de> + Serialize> Visitor<'de> for Vis<'de, B> {
            type Value = Blob<B>;

            fn expecting(
                &self, formatter: &mut core::fmt::Formatter,
            ) -> core::fmt::Result {
                formatter.write_str("length prefixed blob")
            }
            fn visit_seq<V>(self, mut seq: V) -> Result<Blob<B>, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let bloblen: u32 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("length"))?;

                let inner: B = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::missing_field("rest of packet"))?;

                // TODO: is there a better way to find the length consumed?
                // If we could enforce that D is a DeSSHBytes we can look
                // at the length...
                let gotlen = SeSSHBytes::get_length(&inner)
                    .map_err(|_| de::Error::custom(Error::bug()))?;
                if bloblen as usize != gotlen {
                    return Err(de::Error::custom(format_args!(
                        "Expected {} of length {}, got {}",
                        core::any::type_name::<B>(),
                        bloblen,
                        gotlen
                    )));
                }
                Ok(Blob(inner))
            }
        }
        deserializer.deserialize_seq(Vis { ph: PhantomData, lifetime: PhantomData })
    }
}

/// Serializer for the SSH wire protocol. Writes into a borrowed `&mut [u8]` buffer.
/// Optionally compute the hash of the packet or the length required.
enum SeSSHBytes<'a> {
    WriteBytes { target: &'a mut [u8], pos: usize },
    WriteHash { hash_ctx: &'a mut ring::digest::Context },
    Length { pos: usize },
}

impl SeSSHBytes<'_> {
    /// Returns the length required to serialize `value`
    pub fn get_length<S>(value: S) -> Result<usize>
    where
        S: Serialize,
    {
        let mut serializer = SeSSHBytes::Length { pos: 0 };
        value.serialize(&mut serializer)?;
        let len = match serializer {
            SeSSHBytes::Length { pos } => pos,
            _ => 0, // TODO is there a better syntax here? we know it's always WriteBytes
        };
        Ok(len)
    }

    /// Appends serialized data
    fn push(&mut self, v: &[u8]) -> Res {
        match self {
            SeSSHBytes::WriteBytes { target, ref mut pos } => {
                if *pos + v.len() > target.len() {
                    return Err(Error::NoRoom);
                }
                target[*pos..*pos + v.len()].copy_from_slice(v);
                *pos += v.len();
            }
            SeSSHBytes::Length { ref mut pos } => {
                *pos += v.len();
            }
            SeSSHBytes::WriteHash { hash_ctx } => {
                hash_ctx.update(v);
            }
        }
        Ok(())
    }
}

impl Serializer for &mut SeSSHBytes<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    type SerializeSeq = Self;
    type SerializeStruct = Self;
    type SerializeTuple = Self;
    type SerializeStructVariant = ser::Impossible<(), Error>;
    type SerializeTupleStruct = ser::Impossible<(), Error>;
    type SerializeTupleVariant = ser::Impossible<(), Error>;
    type SerializeMap = ser::Impossible<(), Error>;

    fn serialize_bool(self, v: bool) -> Res {
        self.serialize_u8(v as u8)
    }
    fn serialize_u8(self, v: u8) -> Res {
        self.push(&[v])
    }
    fn serialize_u32(self, v: u32) -> Res {
        self.push(&v.to_be_bytes())
    }
    /// Not actually used in any SSH packets, mentioned in the arch doc
    fn serialize_u64(self, v: u64) -> Res {
        self.push(&v.to_be_bytes())
    }
    /// Serialize raw bytes with no prefix
    fn serialize_bytes(self, v: &[u8]) -> Res {
        self.serialize_u32(v.len() as u32)?;
        self.push(v)
        // todo!(
        //     "This is asymmetric with deserialize_bytes, but isn't currently being used."
        // )
    }
    fn serialize_str(self, v: &str) -> Res {
        let b = v.as_bytes();
        self.serialize_u32(b.len() as u32)?;
        self.push(b)
    }

    fn serialize_some<T>(self, v: &T) -> Res
    where
        T: ?Sized + Serialize,
    {
        v.serialize(self)
    }
    // for truncated last option for publickey
    fn serialize_none(self) -> Res {
        Ok(())
    }
    fn serialize_newtype_struct<T>(self, _name: &'static str, v: &T) -> Res
    where
        T: ?Sized + Serialize,
    {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T>(
        self, name: &'static str, _variant_index: u32, variant: &'static str, v: &T,
    ) -> Res
    where
        T: ?Sized + Serialize,
    {
        match name {
            "Userauth60" | "ChannelOpenType" | "ChannelReqType" => {
                // Name is elsewhere, part of the parent struct or
                // from ParseContext
            }
            "PubKey" | "Signature" | "AuthMethod" => {
                // Name is immediately before the enum
                self.serialize_str(variant)?;
            }
            _ => {
                return Error::bug_args(format_args!("Mystery enum {name}"))
            }
        };
        v.serialize(self)
    }

    // for "none" variant
    fn serialize_unit_variant(
        self, name: &'static str, _variant_index: u32, variant: &'static str,
    ) -> Res {
        match name {
            "ChannelType" => Ok(()), // "session" unit variant
            _ => self.serialize_str(variant),
        }
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self> {
        Ok(self)
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self> {
        Ok(self)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self> {
        Ok(self)
    }

    fn collect_str<T: ?Sized>(self, _: &T) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_i8(self, _: i8) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_i16(self, _: i16) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_i32(self, _: i32) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_i64(self, _: i64) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_u16(self, _: u16) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_f32(self, _: f32) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_f64(self, _: f64) -> Res {
        Err(Error::NoSerializer)
    }
    // TODO: perhaps useful?
    fn serialize_char(self, _: char) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_unit(self) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_tuple_struct(
        self, _name: &'static str, _len: usize,
    ) -> Result<Self::SerializeTupleStruct> {
        Err(Error::NoSerializer)
    }
    fn serialize_tuple_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant> {
        Err(Error::NoSerializer)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
        Err(Error::NoSerializer)
    }
    fn serialize_struct_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant> {
        Err(Error::NoSerializer)
    }
}

impl ser::SerializeSeq for &mut SeSSHBytes<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStruct for &mut SeSSHBytes<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(
        &mut self, _key: &'static str, value: &T,
    ) -> Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ser::SerializeTuple for &mut SeSSHBytes<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_element<T: ?Sized>(&mut self, value: &T) -> Result<(), Self::Error>
    where
        T: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Deserializer for the SSH wire protocol, from borrowed `&[u8]`
/// Implements enough of serde to handle the formats defined in [`crate::packets`]
pub(crate) struct DeSSHBytes<'a> {
    input: &'a [u8],
    pos: usize,

    parse_ctx: &'a ParseContext<'a>,

    /// MapAccessDeSSH can capture the string value of a selected field
    /// for use as an enum variant selector
    capture_next_str: bool,
    capture_str: Option<&'a str>,

    /// A variant name to be used for the next enum deserialization
    next_variant: Option<&'a str>,
}

impl<'de> DeSSHBytes<'de> {
    // XXX: rename to new() ?
    pub fn from_bytes(input: &'de [u8], ctx: &'de ParseContext) -> Self {
        DeSSHBytes {
            input,
            pos: 0,
            parse_ctx: ctx,
            capture_next_str: false,
            capture_str: None,
            next_variant: None,
        }
    }

    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        if len > self.input.len() {
            return Err(Error::RanOut);
        }
        let (t, rest) = self.input.split_at(len);
        self.input = rest;
        self.pos += len;
        trace!(target: "serde,hexdump", "take new pos {}, {:?}", self.pos, t.hex_dump());
        Ok(t)
    }

    #[inline]
    fn parse_u8(&mut self) -> Result<u8> {
        let t = self.take(core::mem::size_of::<u8>())?;
        let u = u8::from_be_bytes(t.try_into().unwrap());
        // println!("deser u8 {u}");
        Ok(u)
    }

    #[inline]
    fn parse_u32(&mut self) -> Result<u32> {
        let t = self.take(core::mem::size_of::<u32>())?;
        let u = u32::from_be_bytes(t.try_into().unwrap());
        // println!("deser u32 {u}");
        Ok(u)
    }

    fn parse_u64(&mut self) -> Result<u64> {
        let t = self.take(core::mem::size_of::<u64>())?;
        Ok(u64::from_be_bytes(t.try_into().unwrap()))
    }

    #[inline]
    fn parse_str(&mut self) -> Result<&'de str> {
        let len = self.parse_u32()?;
        let t = self.take(len as usize)?;
        let s = core::str::from_utf8(t).map_err(|_| Error::BadString)?;
        trace!(target: "serde", "parse_str '{s}'");
        Ok(s)
    }
}

impl<'de, 'a> Deserializer<'de> for &'a mut DeSSHBytes<'de> {
    type Error = Error;

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_bool(self.parse_u8()? != 0)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u8(self.parse_u8()?)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u32(self.parse_u32()?)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_u64(self.parse_u64()?)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let s = self.parse_str()?;
        if self.capture_next_str {
            debug_assert!(self.capture_str.is_none());
            self.capture_str = Some(s);
            self.capture_next_str = false
        }
        visitor.visit_borrowed_str(s)
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    /* deserialize_bytes() is like a string but with binary data. it has
    a u32 prefix of the length. Fixed length byte arrays use _tuple() */
    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let len = self.parse_u32()?;
        let t = self.take(len as usize)?;
        visitor.visit_borrowed_bytes(t)
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SeqAccessDeSSH { ds: self, len: Some(len) })
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_seq(SeqAccessDeSSH { ds: self, len: None })
    }

    fn deserialize_struct<V>(
        self, name: &'static str, fields: &'static [&'static str], visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        let variant_field = match name {
            |"ChannelOpen"
            |"ChannelRequest"
            => Some("channel_type"),
            _ => None,
        };

        if variant_field.is_some() {
            // We need a struct deserializer to extract specific fields
            let ma = MapAccessDeSSH::new(self, fields, variant_field);
            let v = visitor.visit_map(ma)?;
            debug_assert!(self.next_variant.is_none());
            Ok(v)
        } else {
            // A simple deserialize_tuple is smaller
            self.deserialize_tuple(fields.len(), visitor)
        }
    }

    fn deserialize_enum<V>(
        self, name: &'static str, variants: &'static [&'static str], visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let variant_name = match name {
            "Userauth60" => packets::Userauth60::variant(self.parse_ctx)?,
            |"ChannelOpenType"
            |"ChannelReqType"
            => self.next_variant.take().trap()?,
            "PubKey" | "Signature" | "AuthMethod" => {
                // The variant is selected by the method name in the packet,
                // using `#[serde(rename)]` in `packets` enum definition.
                self.parse_str()?
            }
            _ => {
                // A mystery enum has been added to packets.rs
                return Error::bug_args(format_args!("Mystery enum {name}"))
            }
        };

        let unknown_variant = !variants.contains(&variant_name) || variant_name == "Unknown";

        let stringenum = SSHStringEnum {
            ds: self, variant_name, unknown_variant };

        visitor.visit_enum(stringenum)
    }

    fn deserialize_newtype_struct<V>(
        self, _name: &'static str, visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_tuple_struct<V>(
        self, _name: &'static str, _len: usize, _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }

    fn deserialize_unit<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }
    // The remainder will fail.
    serde::forward_to_deserialize_any! {
        i8 i16 i32 i64 i128 u16 u128 f32 f64 char string
        byte_buf unit_struct
        map ignored_any
        option
    }
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }
}

struct SeqAccessDeSSH<'a, 'b: 'a> {
    ds: &'a mut DeSSHBytes<'b>,
    len: Option<usize>,
}

impl<'a, 'b: 'a> SeqAccess<'b> for SeqAccessDeSSH<'a, 'b> {
    type Error = Error;
    #[inline]
    fn next_element_seed<V: DeserializeSeed<'b>>(
        &mut self, seed: V,
    ) -> Result<Option<V::Value>> {
        if let Some(ref mut len) = self.len {
            if *len > 0 {
                *len -= 1;
                Ok(Some(DeserializeSeed::deserialize(seed, &mut *self.ds)?))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(DeserializeSeed::deserialize(seed, &mut *self.ds)?))
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.len
    }
}

struct MapAccessDeSSH<'de, 'a> {
    ds: &'a mut DeSSHBytes<'de>,
    fields: &'static [&'static str],
    pos: usize,

    // We want to use a field in a parent struct to choose the
    // variant of a child enum. We record the field here
    // and use it in deserialize_enum().
    // This assumes that no intervening enums are decoded before
    // the desired one.
    // Perhaps in future #[serde(flatten)] etc could be used instead.
    variant_field: Option<&'a str>,
}

impl<'de: 'a, 'a> MapAccessDeSSH<'de, 'a> {
    fn new(
        ds: &'a mut DeSSHBytes<'de>, fields: &'static [&'static str],
        variant_field: Option<&'a str>,
    ) -> Self {
        debug_assert!(ds.next_variant.is_none());
        MapAccessDeSSH { ds, fields, pos: 0, variant_field }
    }
}

impl<'de: 'a, 'a> MapAccess<'de> for MapAccessDeSSH<'de, 'a> {
    type Error = Error;

    // inline reduces code size
    #[inline]
    fn next_key_seed<S: DeserializeSeed<'de>>(
        &mut self, seed: S,
    ) -> Result<Option<S::Value>> {
        if self.pos < self.fields.len() {
            debug_assert!(self.ds.capture_str.is_none());
            debug_assert!(!self.ds.capture_next_str);
            if let Some(cf) = self.variant_field {
                // The subsequent next_value_seed() should
                // capture the string value if this is our
                // capture_field.
                self.ds.capture_next_str = cf == self.fields[self.pos];
            };

            // Return the field name as the key
            let dsfield =
                BorrowedStrDeserializer::<Error>::new(self.fields[self.pos]);
            self.pos += 1;
            Ok(Some(DeserializeSeed::deserialize(seed, dsfield)?))
        } else {
            Ok(None)
        }
    }

    #[inline]
    fn next_value_seed<S: DeserializeSeed<'de>>(
        &mut self, seed: S,
    ) -> Result<S::Value> {
        let v = DeserializeSeed::deserialize(seed, &mut *self.ds)?;

        // Stash any captured value
        let cap = self.ds.capture_str.take();
        debug_assert!(!self.ds.capture_next_str);
        if cap.is_some() {
            debug_assert!(self.ds.next_variant.is_none());
            self.ds.next_variant = cap;
        }
        Ok(v)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.fields.len())
    }
}

struct SSHStringEnum<'a, 'de: 'a> {
    ds: &'a mut DeSSHBytes<'de>,

    /// Set to the variant name to choose from this enum.
    variant_name: &'de str,
    /// Set when the variant_name doesn't match any known.
    /// Rather than failing, a "Unknown" variant is returned.
    /// A Unknown variant is included in all the enum types that
    /// could potentially receive known content.
    unknown_variant: bool,
}

// Figures which SSH string (eg "password") identifies the enum
impl<'de, 'a> EnumAccess<'de> for SSHStringEnum<'a, 'de> {
    type Error = crate::error::Error;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant)>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = if self.unknown_variant {
            "Unknown"
        } else {
            self.variant_name
        };
        // mystery: why doesn't variant.into_deserializer() work?
        let n = BorrowedStrDeserializer::<Error>::new(variant);
        let n = seed.deserialize(n)?;
        Ok((n, self))
    }
}

// Creates a struct out of thin air with the given content
struct SyntheticNewtypeSeqAccess<'de> {
    content: Option<&'de str>
}

impl<'de: 'a, 'a> SeqAccess<'de> for SyntheticNewtypeSeqAccess<'de> {
    type Error = Error;
    fn next_element_seed<V: DeserializeSeed<'de>>(
        &mut self, seed: V,
    ) -> Result<Option<V::Value>> {
        let content = self.content.take();
        let c = content.map(|c| {
            let b = BorrowedStrDeserializer::<Error>::new(c);
            seed.deserialize(b)
        })
        .transpose()?;
        Ok(c)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(1)
    }
}

// Decodes a variant from an enum.
// We only use newtype and unit variants
impl<'de, 'a> VariantAccess<'de> for SSHStringEnum<'a, 'de> {
    type Error = Error;

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        if self.unknown_variant {
            // Put the unknown variant name in an Unknown newtype
            let u = SyntheticNewtypeSeqAccess { content: Some(self.variant_name) };
            let b = SeqAccessDeserializer::new(u);
            seed.deserialize(b).into()
        } else {
            seed.deserialize(self.ds)
        }
    }

    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn tuple_variant<V>(
        self, _len: usize, _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }

    fn struct_variant<V>(
        self, _fields: &'static [&'static str], _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::doorlog::init_test_log;
    use crate::error::Error;
    use crate::packets::*;
    use crate::wireformat::*;
    use crate::*;
    // use pretty_hex::PrettyHex;

    /// Checks that two items serialize the same
    pub fn assert_serialize_equal<'de, T: Serialize>(p1: &T, p2: &T) {
        let mut buf1 = vec![99; 2000];
        let mut buf2 = vec![88; 1000];
        let l1 = write_ssh(&mut buf1, &p1).unwrap();
        let l2 = write_ssh(&mut buf2, &p2).unwrap();
        buf1.truncate(l1);
        buf2.truncate(l2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    /// check that hash_ser_length() matches hashing a serialized message
    fn test_hash_packet() {
        use ring::digest;
        let input = "hello";
        let mut buf = vec![99; 20];
        let w1 = wireformat::write_ssh(&mut buf, &input).unwrap();
        buf.truncate(w1);

        // hash_ser_length
        let mut hash_ctx = digest::Context::new(&digest::SHA256);
        wireformat::hash_ser_length(&mut hash_ctx, &input).unwrap();
        let digest1 = hash_ctx.finish();

        let mut hash_ctx = digest::Context::new(&digest::SHA256);
        hash_ctx.update(&(w1 as u32).to_be_bytes());
        hash_ctx.update(&buf);
        let digest2 = hash_ctx.finish();

        assert_eq!(digest1.as_ref(), digest2.as_ref());

        // hash_ser
        let mut hash_ctx = digest::Context::new(&digest::SHA256);
        hash_ctx.update(&(w1 as u32).to_be_bytes());
        wireformat::hash_ser(&mut hash_ctx, &input).unwrap();
        let digest3 = hash_ctx.finish();
        assert_eq!(digest3.as_ref(), digest2.as_ref());
    }

    pub fn test_roundtrip_context(p: &Packet, ctx: &ParseContext) {
        let mut buf = vec![99; 200];
        let l = write_ssh(&mut buf, &p).unwrap();
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

        let p = Packet::Userauth60(Userauth60::PwChangeReq(UserauthPwChangeReq {
            prompt: "change the password",
            lang: "",
        }));
        let mut pw = client::ResponseString::new();
        pw.push_str("123").unwrap();
        ctx.cli_auth_type = Some(cliauth::Req::Password(pw ));
        test_roundtrip_context(&p, &ctx);

        // PkOk is a more interesting case because the PubKey inside it is also
        // an enum but that can identify its own enum variant.
        let p = Packet::Userauth60(Userauth60::PkOk(UserauthPkOk {
            algo: "ed25519",
            key: Blob(PubKey::Ed25519(Ed25519PubKey {
                key: BinString(&[0x11, 0x22, 0x33]),
            })),
        }));
        let s = sign::tests::make_ed25519_signkey();
        ctx.cli_auth_type = Some(cliauth::Req::PubKey(s));
        test_roundtrip_context(&p, &ctx);
    }
}
