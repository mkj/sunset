//! SSH comma separated algorithm lists.
#[allow(unused_imports)]
use {
    crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};

use serde::de;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeTuple, Serializer};
use serde::Deserializer;

use serde::{Deserialize, Serialize};


/// A comma separated string, can be deserialized or serialized.
/// Used for remote name lists.
#[derive(Serialize, Deserialize, Debug)]
pub struct StringNames<'a>(pub &'a str);

/// A list of names, can only be serialized. Used for local name lists, comes
/// from local fixed lists
/// Deliberately 'static since it should only come from hardcoded local strings
/// SSH_NAME_* in [`kex`]. We don't validate string contents.
#[derive(Debug)]
pub struct LocalNames<'a>(pub &'a[&'static str]);

/// The general form that can store either representation
#[derive(Serialize, Debug)]
pub enum NameList<'a> {
    String(StringNames<'a>),
    Local(LocalNames<'a>),
}

impl<'de: 'a, 'a> Deserialize<'de> for NameList<'a> {
    fn deserialize<D>(deserializer: D) -> Result<NameList<'a>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = StringNames::deserialize(deserializer)?;
        if s.0.is_ascii() {
            Ok(NameList::String(s))
        } else {
            Err(de::Error::custom("algorithm isn't ascii"))
        }
    }
}

/// Serialize the list of names with comma separators
impl<'a> Serialize for LocalNames<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(None)?;
        let names = &self.0;
        for i in 0..names.len() {
            seq.serialize_element(names[i].as_bytes());
            if i < names.len()-1 {
                seq.serialize_element(&(',' as u8));
            }
        }
        seq.end()
    }
}

impl<'a> From<&'a str> for StringNames<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}
impl<'a> From<&'a [&'static str]> for LocalNames<'a> {
    fn from(s: &'a [&'static str]) -> Self {
        Self(s)
    }
}
impl<'a> From<&'a str> for NameList<'a> {
    fn from(s: &'a str) -> Self {
        NameList::String(s.into())
    }
}
impl<'a> Into<NameList<'a>> for &LocalNames<'a> {
    fn into(self) -> NameList<'a> {
        NameList::Local(LocalNames(self.0))
    }

}

impl<'a> NameList<'a> {
    /// Returns the first name in this namelist that matches, based on SSH priority.
    /// The SSH client's list (which could be either remote or ours) is used
    /// to determine priority.
    /// `self` is a remote list, `our_options` are our own allowed options in preference
    /// order.
    /// Must only be called on [`StringNames`], will fail if called with self as [`LocalNames`].
    pub fn first_protocol_match(
        &self, is_client: bool, our_options: &LocalNames,
    ) -> Result<Option<&str>, Error> {
        match self {
            NameList::String(s) => {
                Ok(if is_client {
                    s.first_match(our_options)
                } else {
                    s.first_options_match(our_options)
                })
            },
            NameList::Local(_) => Err(Error::Bug)
        }
    }
}

impl<'a> StringNames<'a> {
    /// Returns the first name in this namelist that matches one of the provided options
    fn first_match(&self, options: &LocalNames) -> Option<&str> {
        trace!("match {:?} options {:?}", self, options);
        for n in self.0.split(',') {
            for o in options.0.iter() {
                trace!("match {} options {} {}", n, *o, (*n == **o));
                if n == *o {
                    return Some(n);
                }
            }
        }
        trace!("None");
        None
    }

    /// Returns the first of "options" that is in this namelist
    fn first_options_match(&self, options: &LocalNames) -> Option<&str> {
        trace!("firstopmatch {:?} options {:?}", self, options);
        for o in options.0.iter() {
            for n in self.0.split(',') {
                if n == *o {
                    return Some(n);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{wireformat};
    use crate::namelist::*;
    use pretty_hex::PrettyHex;


    #[test]
    fn test_localnames_serialize() {
        let tests: Vec<&[&str]> = vec![
            &["foo", "quux", "boo"],
            &[],
            &["one"],
            &["one", "2"],
            &["", "2"],
            &["3", ""],
            &["", ""],
            &[",", ","], // not really valid
        ];
        for t in tests.iter() {
            let n = NameList::Local(LocalNames(t));
            let mut buf = vec![99; 30];
            let l = wireformat::write_ssh(&mut buf, &n).unwrap();
            buf.truncate(l);
            let out1 = core::str::from_utf8(&buf).unwrap();
            // check that a join with std gives the same result.
            assert_eq!(out1, t.join(","));
        }
    }
}
