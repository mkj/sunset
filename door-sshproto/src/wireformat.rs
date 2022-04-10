use serde::{ser, de, Serializer, Serialize, Deserializer, Deserialize};
use crate::error::Error;
use core::result::{Result};
use core::slice;

/// See rfc4251 for encodings

pub struct SeSSH<'a> {
    target: &'a mut[u8],
    pos: usize,
}

type Res = Result<(), Error>;

/// Returns the length written.
// TODO: is there a nicer way? IterMut?
pub fn write_ssh<T>(target: &mut [u8], value: &T) -> Result<usize, Error>
        where T: Serialize {
    let mut serializer = SeSSH {
        target,
        pos: 0,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.pos)
}

impl SeSSH<'_> {

    fn push(&mut self, v: &[u8]) -> Res {
        // TODO: can IterMut be used somehow?
        if self.pos + v.len() > self.target.len() {
            return Err(Error::NoSpace);
        }
        self.target[self.pos..self.pos + v.len()].copy_from_slice(v);
        self.pos += v.len();
        Ok(())
    }
}

impl Serializer for &mut SeSSH<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    type SerializeSeq = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;
    type SerializeTuple = ser::Impossible<(), Error>;
    type SerializeTupleStruct = ser::Impossible<(), Error>;
    type SerializeTupleVariant = ser::Impossible<(), Error>;
    type SerializeMap = ser::Impossible<(), Error>;

    fn serialize_bool(self, v: bool) -> Res {
        self.serialize_u32(v as u32)
    }
    fn serialize_u8(self, v: u8) -> Res {
        self.push(&[v])
    }
    fn serialize_u32(self, v: u32) -> Res {
        self.push(&v.to_be_bytes())
    }
    // Not actually used in any SSH packets, mentioned in the arch doc
    fn serialize_u64(self, v: u64) -> Res {
        self.push(&v.to_be_bytes())
    }
    fn serialize_str(self, v: &str) -> Res {
        self.serialize_u32(v.as_bytes().len() as u32)?;
        self.push(v.as_bytes())
    }
    fn serialize_bytes(self, v: &[u8]) -> Res {
        self.push(v)
    }
    // XXX Unsure if we're using Option
    fn serialize_none(self) -> Res {
        Ok(())
    }
    fn serialize_some<T>(self, v: &T) -> Res
            where T: ?Sized + Serialize {
        v.serialize(self)
    }
    fn serialize_newtype_struct<T>(self, _name: &'static str, v: &T) -> Res
            where T: ?Sized + Serialize {
        v.serialize(self)
    }
    fn serialize_newtype_variant<T>(self,
            _name: &'static str, _variant_index: u32, _variant: &'static str,
            v: &T) -> Res
            where T: ?Sized + Serialize {
        v.serialize(self)
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Ok(self)
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeSeq, Error> {
        Ok(self)
    }
    fn serialize_struct_variant(self,
            _name: &'static str, _variant_index: u32, _variant: &'static str,
            _len: usize) -> Result<Self::SerializeSeq, Error> {
        Ok(self)
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
    fn serialize_unit_variant(self,
            _name: &'static str, _variant_index: u32, _variant: &'static str) -> Res {
        Err(Error::NoSerializer)
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(Error::NoSerializer)
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize)
            -> Result<Self::SerializeTupleStruct, Error> {
        Err(Error::NoSerializer)
    }
    fn serialize_tuple_variant(self,
            _name: &'static str, _variant_index: u32, _variant: &'static str,
            _len: usize) -> Result<Self::SerializeTupleVariant, Error> {
        Err(Error::NoSerializer)
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(Error::NoSerializer)
    }
}

impl ser::SerializeSeq for &mut SeSSH<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
            where T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStruct for &mut SeSSH<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
            where T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl ser::SerializeStructVariant for &mut SeSSH<'_> {
    type Ok = ();
    type Error = crate::error::Error;

    fn serialize_field<T>(&mut self, _key: &'static str, value: &T) -> Result<(), Self::Error>
            where T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct DeSSH {

}
