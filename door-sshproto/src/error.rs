use core::str::Utf8Error;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::fmt::Arguments;

use serde::de::{Expected, Unexpected};
use snafu::{prelude::*, Location};

use heapless::String;

// RFC4251 defines a maximum of 64, but 35 is probably enough to identify
// a problem.
#[derive(Debug)]
pub struct UnknownName(pub String<35>);

impl From<&str> for UnknownName {

    /// Indicates truncation
    fn from(from: &str) -> Self {
        let mut s = String::<35>::new();
        let mut len = from.len();
        if len > s.capacity() {
            len = (len-3).min(s.capacity() - 3)
        }
        s.push_str(&from[..len]).unwrap();
        if s.len() != from.len() {
            s.push_str("...").unwrap();
        }
        UnknownName(s)
    }
}



// TODO: can we make Snafu not require Debug?
// TODO: maybe split this into a list of public vs private errors?
#[non_exhaustive]
#[derive(Snafu, Debug)]
pub enum Error {
    /// Output buffer ran out of room
    NoRoom,

    /// Input buffer ran out
    RanOut,

    /// Not implemented (unused in SSH protocol)
    // internal
    NoSerializer,

    /// Not a UTF8 string
    BadString,

    /// Decryption failure or integrity mismatch
    BadDecrypt,

    /// Signature is incorrect
    BadSignature,

    /// Signature doesn't match key type
    SignatureMismatch { key: UnknownName, sig: UnknownName },

    /// Error in received SSH protocol
    SSHProtoError,

    /// Remote peer isn't SSH
    NotSSH,

    /// Unknown packet type
    UnknownPacket { number: u8 },

    /// Received packet at a disallowed time.
    // TODO: this is kind of a subset of SSHProtoError, maybe not needed
    PacketWrong,

    /// No matching algorithm
    AlgoNoMatch { algo: &'static str },

    /// Packet size too large (or bad decrypt)
    BigPacket { size: usize },

    /// Packet had an unknown method
    UnknownMethod,

    /// Serde invalid value
    // internal
    InvalidDeserializeU8 { value: u8 },

    /// Other custom error
    // TODO: these could eventually get categorised
    Custom { msg: &'static str },

    /// Program bug.
    /// This state should not be reached, previous logic should have prevented it.
    /// Don't create `Bug` directly, instead use [`Error::bug()`] or
    /// [`.trap()`](TrapBug::trap) to make finding the source easier.
    Bug { location: snafu::Location },
}

trait SomeError {}

impl SomeError for Error {}

impl Error {
    pub fn msg(m: &'static str) -> Error {
        Error::Custom { msg: m }
    }

    #[track_caller]
    #[cold]
    /// Panics in debug builds, returns [`Error::Bug`] in release.
    // TODO: this should return a Result since it's always used as Err(Error::bug())
    pub fn bug() -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug");
        } else {
            let caller = std::panic::Location::caller();
            Error::Bug {
                location: snafu::Location::new(
                    caller.file(),
                    caller.line(),
                    caller.column(),
                ),
            }
        }
    }

    /// Like [`bug()`] but with a message
    /// The message can be used instead of a comment, is logged at `debug` level.
    #[track_caller]
    #[cold]
    /// TODO: is the generic `T` going to make it bloat?
    pub fn bug_msg<T>(args: Arguments) -> Result<T, Error> {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug: {args}");
        } else {
            debug!("Hit a bug: {args}");
            let caller = std::panic::Location::caller();
            Err(Error::Bug {
                location: snafu::Location::new(
                    caller.file(),
                    caller.line(),
                    caller.column(),
                ),
            })
        }
    }

}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait TrapBug<T> {
    /// `.trap()` should be used like `.unwrap()`, in situations
    /// never expected to fail. Instead it calls [`Error::bug()`].
    /// (or debug builds may panic)
    #[track_caller]
    fn trap(self) -> Result<T, Error>;

    /// Like [`trap()`] but with a message, calls [`Error::bug_msg()`]
    /// The message can be used instead of a comment.
    #[track_caller]
    fn trap_msg(self, args: Arguments) -> Result<T, Error>;
}

impl<T, E> TrapBug<T> for Result<T, E> {
    fn trap(self) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Ok(i) = self {
            Ok(i)
        } else {
            Err(Error::bug())
        }
    }
    fn trap_msg(self, args: Arguments) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Ok(i) = self {
            Ok(i)
        } else {
            Error::bug_msg(args)
        }
    }
}

impl<T> TrapBug<T> for Option<T> {
    fn trap(self) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Some(i) = self {
            Ok(i)
        } else {
            Err(Error::bug())
        }
    }
    fn trap_msg(self, args: Arguments) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Some(i) = self {
            Ok(i)
        } else {
            Error::bug_msg(args)
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(_e: Utf8Error) -> Error {
        Error::BadString
    }
}

// impl serde::de::StdError for Error {}

// TODO: need to figure how to return our own Error variants from serde
// rather than using serde Error::custom().
impl serde::ser::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: core::fmt::Display,
    {
        let _ = msg;
        #[cfg(feature = "std")]
        println!("custom ser error: {}", msg);

        Error::msg("ser error")
    }
}

impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: core::fmt::Display,
    {
        let _ = msg;
        #[cfg(feature = "std")]
        println!("custom de error: {}", msg);
        panic!("{}", msg);

        Error::msg("de error")
    }

    fn invalid_value(unexp: Unexpected<'_>, exp: &dyn Expected) -> Self {
        if let Unexpected::Unsigned(val) = unexp {
            if val <= 255 {
                return Error::InvalidDeserializeU8 { value: val as u8 };
            }
        }
        debug!("Invalid deserialize. Expected {} got {}", exp, unexp);
        Error::bug()
    }

    fn unknown_variant(variant: &str, expected: &'static [&'static str]) -> Self {
        debug!("Unknown variant '{variant}' wasn't caught");
        Error::bug()
    }
}

pub struct ExpectedMessageNumber;

impl Expected for ExpectedMessageNumber {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "a known SSH message number")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::error::*;
    use crate::doorlog::init_test_log;
    use crate::packets::Unknown;

    #[test]
    fn unknown_name_from() {
        init_test_log();
        // test the test
        const LIM: usize = 44;
        let s: UnknownName = "a".into();
        let cap = s.0.capacity();
        assert!(LIM > cap + 6);

        for i in 0..LIM {
            let mut s = "qwertyu".repeat(10);
            s.truncate(i);
            let u: UnknownName = s.as_str().into();
            if i <= cap {
                assert!(&u.0 == s.as_str());
            } else {
                assert!(&u.0[cap-3..] == "...");
            }

        }
    }

}

