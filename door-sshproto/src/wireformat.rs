//! SSH protocol serialization.
//! Implements enough of serde to handle the formats defined in [`crate::packets`]

//! See [RFC4251](https://datatracker.ietf.org/doc/html/rfc4251) for encodings,
//! [RFC4253](https://datatracker.ietf.org/doc/html/rfc4253) and others for packet structure
use serde::{
    de, ser,
    de::{DeserializeSeed, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::error::{Error,Result};
use crate::packets::Packet;
use core::cell::Cell;
use core::slice;
use core::convert::AsRef;

/// Parses a [`Packet`] from a borrowed `&[u8]` byte buffer.
pub fn packet_from_bytes<'a>(b: &'a [u8]) -> Result<Packet<'a>> {

    let mut ds = DeSSHBytes::from_bytes(b);
    Packet::deserialize(&mut ds)
    .map_err(|e| {
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
pub fn hash_packet<T>(hash_ctx: &mut ring::digest::Context, value: &T) -> Result<()>
where
    T: Serialize,
{
    // calculate the u32 length prefix
    let mut serializer = SeSSHBytes::Length { pos: 0 };
    value.serialize(&mut serializer)?;
    let len = match serializer {
        SeSSHBytes::Length { pos } => pos,
        _ => 0, // TODO is there a better syntax here? we know it's always WriteBytes
    } as u32;
    hash_ctx.update(&len.to_be_bytes());
    let mut serializer = SeSSHBytes::WriteHash { hash_ctx };
    // the rest of the packet
    value.serialize(&mut serializer)?;
    Ok(())
}

type Res = Result<()>;

#[derive(Deserialize)]
/// A SSH style binary string. Serialized as 32 bit length followed by the bytes
/// of the slice.
pub struct BinString<'a>(pub &'a [u8]);

impl<'a> AsRef<[u8]> for BinString<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.0
    }
}

impl<'a> core::fmt::Debug for BinString<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BinString(len={}", self.0.len())
    }
}

impl<'a> Serialize for BinString<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        let l = self.0.len() as u32;
        seq.serialize_element(&l)?;
        seq.serialize_element(self.0)?;
        seq.end()
    }
}


/// Serializer for the SSH wire protocol. Writes into a borrowed `&mut [u8]` buffer.
/// Optionally compute the hash of the packet rather than serializing.
enum SeSSHBytes<'a> {
    WriteBytes { target: &'a mut [u8], pos: usize },
    Length { pos: usize },
    WriteHash { hash_ctx: &'a mut ring::digest::Context },
}

impl SeSSHBytes<'_> {
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
        self.push(v)?;
        todo!(
            "This is asymmetric with deserialize_bytes, but isn't currently being used."
        )
    }
    fn serialize_str(self, v: &str) -> Res {
        let b = v.as_bytes();
        self.serialize_u32(b.len() as u32)?;
        self.push(b)
    }
    fn serialize_none(self) -> Res {
        Ok(())
    }
    fn serialize_some<T>(self, v: &T) -> Res
    where
        T: ?Sized + Serialize,
    {
        v.serialize(self)
    }
    fn serialize_newtype_struct<T>(self, _name: &'static str, v: &T) -> Res
    where
        T: ?Sized + Serialize,
    {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T>(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str,
        v: &T,
    ) -> Res
    where
        T: ?Sized + Serialize,
    {
        v.serialize(self)
    }
    fn serialize_seq(
        self, _len: Option<usize>,
    ) -> Result<Self::SerializeSeq> {
        Ok(self)
    }
    fn serialize_struct(
        self, _name: &'static str, _len: usize,
    ) -> Result<Self::SerializeSeq> {
        Ok(self)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple> {
        Ok(self)
    }

    // Required for no_std
    fn collect_str<T: ?Sized>(self, _: &T) -> Res {
        Err(Error::NoSerializer)
    }

    // Not in the SSH protocol
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
    fn serialize_unit_variant(
        self, _name: &'static str, _variant_index: u32, _variant: &'static str,
    ) -> Res {
        Ok(())
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
    fn serialize_map(
        self, _len: Option<usize>,
    ) -> Result<Self::SerializeMap> {
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
struct DeSSHBytes<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'de> DeSSHBytes<'de> {
    // XXX: rename to new() ?
    pub fn from_bytes(input: &'de [u8]) -> Self {
        DeSSHBytes { input, pos: 0 }
    }
    // #[inline]
    fn take(&mut self, len: usize) -> Result<&'de [u8]> {
        if len > self.input.len() {
            return Err(Error::RanOut);
        }
        let (t, rest) = self.input.split_at(len);
        self.input = rest;
        self.pos += len;
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
        Ok(s)
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
        visitor.visit_borrowed_str(self.parse_str()?)
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
        self, _name: &'static str, fields: &'static [&'static str], visitor: V,
    ) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_enum<V>(
        self, _name: &'static str, _variants: &'static [&'static str], _visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        // visitor.visit_enum(self);
        panic!("enum")
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
        todo!("unit")
    }
    // The remainder will fail.
    serde::forward_to_deserialize_any! {
        i8 i16 i32 i64 i128 u16 u128 f32 f64 char string
        byte_buf unit_struct
        map identifier ignored_any
        option
    }
    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: Visitor<'de>,
    {
        Err(Error::NoSerializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::*;
    // use pretty_hex::PrettyHex;

    #[test]
    /// check that hash_packet() matches hashing a serialized message
    fn test_hash_packet() {
        use ring::digest;
        let input = "hello";
        let mut buf = vec![99; 20];
        let w1 = wireformat::write_ssh(&mut buf, &input).unwrap();
        buf.truncate(w1);

        let mut hash_ctx = digest::Context::new(&digest::SHA256);
        wireformat::hash_packet(&mut hash_ctx, &input).unwrap();
        let digest1 = hash_ctx.finish();

        let mut hash_ctx = digest::Context::new(&digest::SHA256);
        hash_ctx.update(&(w1 as u32).to_be_bytes());
        hash_ctx.update(&buf);
        let digest2 = hash_ctx.finish();

        assert_eq!(digest1.as_ref(), digest2.as_ref());
    }

}
