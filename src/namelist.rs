//! SSH comma separated algorithm lists.
//!
//! Used when implementing protocol encoding/decoding, not
//! required for general SSH session use.
#[allow(unused_imports)]
use {
    crate::error::{Error, Result},
    log::{debug, error, info, log, trace, warn},
};

use ascii::{AsciiChar::Comma, AsciiStr};

use sunset_sshwire_derive::{SSHDecode, SSHEncode};

use crate::*;
use heapless::{CapacityError, Vec};
use sshwire::{SSHDecode, SSHEncode, SSHSink, SSHSource, WireResult};

// Used for lists of:
// - algorithm names
// - key types
// - signature types
// - auth types

/// Max count of LocalNames entries
///
/// Current max is for kex: (mlkem, curve25519, curve25519@libssh, ext-info, strictkex, kexguess2)
pub const MAX_LOCAL_NAMES: usize = 6;
static EMPTY_LOCALNAMES: LocalNames = LocalNames::new();

/// A comma separated string, can be decoded or encoded.
/// Used for remote name lists.
///
/// Wire format is described in [RFC4251](https://tools.ietf.org/html/rfc4251) SSH Architecture "name-list"
#[derive(SSHEncode, SSHDecode, Debug, Clone)]
pub struct StringNames<'a>(pub &'a AsciiStr);

/// A list of names, can only be encoded. Used for local name lists, comes
/// from local fixed lists
///
/// Deliberately `'static` since it should only come from hardcoded local strings
/// `SSH_NAME_*` in [`crate::sshnames`]. We don't validate string contents.
#[derive(Debug, Default, Clone)]
pub struct LocalNames(pub Vec<&'static str, MAX_LOCAL_NAMES>);

/// The general form that can store either representation
#[derive(SSHEncode, Debug, Clone)]
#[sshwire(no_variant_names)]
pub enum NameList<'a> {
    String(StringNames<'a>),
    Local(&'a LocalNames),
}

impl<'de: 'a, 'a> SSHDecode<'de> for NameList<'a> {
    fn dec<S>(s: &mut S) -> WireResult<NameList<'a>>
    where
        S: SSHSource<'de>,
    {
        Ok(NameList::String(StringNames::dec(s)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'arb: 'a, 'a> arbitrary::Arbitrary<'arb> for NameList<'a> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'arb>) -> arbitrary::Result<Self> {
        Self::single(u.arbitrary()?).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

/// Serialize the list of names with comma separators
impl SSHEncode for &LocalNames {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let names = self.0.as_slice();
        // space for names and commas
        let strlen = names.iter().map(|n| n.len()).sum::<usize>()
            + names.len().saturating_sub(1);
        (strlen as u32).enc(s)?;
        for i in 0..names.len() {
            names[i].as_bytes().enc(s)?;
            if i < names.len() - 1 {
                b','.enc(s)?;
            }
        }
        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for StringNames<'a> {
    type Error = ();
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Ok(Self(AsciiStr::from_ascii(s).map_err(|_| ())?))
    }
}
impl<'a> TryFrom<&'a str> for NameList<'a> {
    type Error = ();
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Ok(NameList::String(s.try_into()?))
    }
}

// for tests
impl TryFrom<&[&'static str]> for LocalNames {
    type Error = sunset::error::Error;
    fn try_from(s: &[&'static str]) -> Result<Self, Error> {
        Ok(Self(Vec::from_slice(s)?))
    }
}

impl From<CapacityError> for Error {
    fn from(_e: CapacityError) -> Error {
        error::NoRoom.build()
    }
}


impl<'a> From<&'a LocalNames> for NameList<'a> {
    fn from(s: &'a LocalNames) -> Self {
        NameList::Local(s)
    }
}

impl<'a> NameList<'a> {
    /// Returns the first name in this namelist that matches, based on SSH priority.
    ///
    /// The SSH client's list (which could be either remote or ours) is used
    /// to determine priority.
    /// `self` is a remote list, `our_options` are our own allowed options in preference
    /// order.
    /// Must only be called on [`StringNames`], will fail if called with self as [`LocalNames`].
    pub fn first_match(
        &self,
        is_client: bool,
        our_options: &LocalNames,
    ) -> Result<Option<&'static str>> {
        match self {
            NameList::String(s) => Ok(if is_client {
                s.first_options_match(our_options)
            } else {
                s.first_string_match(our_options)
            }),
            // we only expect to call first_match() on a packet deserialized
            // as a NameList::String
            NameList::Local(_) => Err(Error::bug()),
        }
    }

    /// Returns whether the `algo` is contained in this list
    ///
    /// Fails iff given a Local variant
    pub fn has_algo(&self, algo: &str) -> Result<bool> {
        match self {
            NameList::String(s) => Ok(s.has_algo(algo)),
            // only expected to be called on remote lists
            NameList::Local(_) => Err(Error::bug()),
        }
    }

    /// Returns the first algorithm in the list, or `""` if the list is empty.
    pub fn first(&self) -> &str {
        match self {
            NameList::String(s) => s.first(),
            NameList::Local(s) => s.first(),
        }
    }

    /// Returns an empty `Local` variant
    pub fn empty() -> Self {
        Self::Local(&EMPTY_LOCALNAMES)
    }

    /// Returns a `String` variant namelist with a single name.
    ///
    /// Useful for testing specific matches.
    pub fn single(name: &'a str) -> Result<Self> {
        AsciiStr::from_ascii(name.as_bytes())
            .map_err(|_| Error::BadString)
            .map(|n| Self::String(StringNames(n)))
    }
}

impl StringNames<'_> {
    /// Returns the first name in this namelist that matches one of the provided options
    fn first_string_match(&self, options: &LocalNames) -> Option<&'static str> {
        for n in self.0.split(Comma) {
            for o in options.0.iter() {
                if n == *o {
                    return Some(*o);
                }
            }
        }
        None
    }

    /// Returns the first of "options" that is in this namelist
    fn first_options_match(&self, options: &LocalNames) -> Option<&'static str> {
        for o in options.0.iter() {
            for n in self.0.split(Comma) {
                if n == *o {
                    return Some(*o);
                }
            }
        }
        None
    }

    fn first(&self) -> &str {
        // unwrap is OK, split() always returns an item
        self.0.split(Comma).next().unwrap().as_str()
    }

    fn has_algo(&self, algo: &str) -> bool {
        self.0.split(Comma).any(|a| a == algo)
    }
}

impl LocalNames {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn first(&self) -> &str {
        if self.0.is_empty() {
            ""
        } else {
            self.0[0]
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::namelist::*;

    use std::vec::Vec;

    #[test]
    fn test_match() {
        let r1 = NameList::String("rho,cog".try_into().unwrap());
        let r2 = NameList::String("woe".try_into().unwrap());
        let l1 = LocalNames::try_from(["rho", "cog"].as_slice()).unwrap();
        let l2 = LocalNames::try_from(["cog", "rho"].as_slice()).unwrap();
        let l3 = LocalNames::try_from(["now", "woe"].as_slice()).unwrap();
        assert_eq!(r1.first_match(true, &l1).unwrap(), Some("rho"));
        assert_eq!(r1.first_match(false, &l1).unwrap(), Some("rho"));
        assert_eq!(r1.first_match(true, &l2).unwrap(), Some("cog"));
        assert_eq!(r1.first_match(false, &l2).unwrap(), Some("rho"));
        assert_eq!(r2.first_match(false, &l1).unwrap(), None);
        assert_eq!(r2.first_match(false, &l2).unwrap(), None);
        assert_eq!(r2.first_match(false, &l3).unwrap(), Some("woe"));
    }

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
            let n = LocalNames::try_from(*t).unwrap();
            let n = NameList::Local(&n);
            let mut buf = vec![99; 30];
            let l = sshwire::write_ssh(&mut buf, &n).unwrap();
            buf.truncate(l);
            let out1 = core::str::from_utf8(&buf).unwrap();
            // check that a join with std gives the same result.
            assert_eq!(buf[..4], ((buf.len() - 4) as u32).to_be_bytes());
            assert_eq!(out1[4..], t.join(","));
        }
    }

    #[test]
    fn test_first() {
        let tests: Vec<&[&str]> = vec![&["foo", "quux", "boo"], &[], &["one"]];

        for t in tests.iter() {
            let l = LocalNames::try_from(*t).unwrap();
            let l = NameList::Local(&l);
            let x = t.join(",");
            let s: NameList = x.as_str().try_into().unwrap();
            assert_eq!(l.first(), s.first());
            if t.len() == 0 {
                assert_eq!(l.first(), "");
            } else {
                assert_eq!(l.first(), t[0]);
            }
        }
    }

    #[test]
    fn test_has_algo() {
        fn n(list: &str, has: &str) -> bool {
            let s: NameList = list.try_into().unwrap();
            s.has_algo(has).unwrap()
        }
        assert_eq!(n("", ""), true);
        assert_eq!(n("", "one"), false);
        assert_eq!(n("zzz", ""), false);
        assert_eq!(n("zzz", "one"), false);
        assert_eq!(n("zzz", "zzz"), true);
        assert_eq!(n("zzz", "zz"), false);
        assert_eq!(n("zz,more", "zzz"), false);
        assert_eq!(n("zzz,boo", "zzz"), true);
        assert_eq!(n("zzz,boo", "boo"), true);
        assert_eq!(n("zzz,boo", "urp"), false);
    }

    #[test]
    fn localnames_max_size() {
        let s = vec!["one"; MAX_LOCAL_NAMES + 1];
        LocalNames::try_from(s.as_slice()).unwrap_err();
        let s = vec!["one"; MAX_LOCAL_NAMES];
        LocalNames::try_from(s.as_slice()).unwrap();
    }
}
