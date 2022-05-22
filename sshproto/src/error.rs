use core::str::Utf8Error;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::fmt::Arguments;
use core::fmt;

use serde::de::{Expected, Unexpected};
use snafu::{prelude::*, Location};

use heapless::String;

use crate::behaviour::BhError;

// RFC4251 defines a maximum of 64, but 35 is probably enough to identify
// a problem.
#[derive(Debug)]
pub struct UnknownName(pub String<35>);

    impl fmt::Display for UnknownName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for UnknownName {

    /// Indicates truncation
    fn from(from: &str) -> Self {
        let mut s = String::new();
        // +10 to avoid wasteful iteration on untrusted input
        let need = from.escape_default().take(s.capacity()+10).count();
        let used = if need > s.capacity() {
            s.capacity() - 4
        } else {
            need
        };
        for e in from.escape_default().take(used) {
            s.push(e).unwrap()
        }

        if need > used {
            s.push_str(" ...").unwrap()
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

    #[snafu(display("Signature \"{sig}\" doesn't match key type \"{key}\""))]
    SignatureMismatch { key: UnknownName, sig: UnknownName },

    /// Error in received SSH protocol
    SSHProtoError,

    /// Remote peer isn't SSH
    NotSSH,

    /// Bad key format
    BadKey,

    /// Ran out of channels
    NoChannels,

    /// Bad channel number
    BadChannel,

    // Used for unknown key types etc.
    #[snafu(display("{what} is not available"))]
    NotAvailable { what: &'static str },

    #[snafu(display("Unknown packet type {number}"))]
    UnknownPacket { number: u8 },

    /// Received packet at a disallowed time.
    // TODO: this is kind of a subset of SSHProtoError, maybe not needed
    PacketWrong,

    #[snafu(display("No matching {algo} algorithm"))]
    AlgoNoMatch { algo: &'static str },

    #[snafu(display("Packet size {size} too large (or bad decrypt)"))]
    BigPacket { size: usize },

    /// An unknown SSH name is provided, for a key type, signature type,
    /// channel name etc.
    #[snafu(display("Unknown {kind} method {name}"))]
    UnknownMethod { kind: &'static str, name: UnknownName },

    /// Serde invalid value
    // internal
    InvalidDeserializeU8 { value: u8 },

    /// Implementation behaviour error
    #[snafu(display("Failure from application: {msg}"))]
    BehaviourError { msg: &'static str },

    #[snafu(display("{msg}"))]
    // TODO: these could eventually get categorised
    Custom { msg: &'static str },

    // This state should not be reached, previous logic should have prevented it.
    // Create this using [`Error::bug()`] or [`.trap()`](TrapBug::trap).
    #[snafu(display("Program bug {location}"))]
    Bug { location: snafu::Location },
}

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
            let caller = core::panic::Location::caller();
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
    /// The message can be used instead of a code comment, is logged at `debug` level.
    #[track_caller]
    #[cold]
    /// TODO: is the generic `T` going to make it bloat?
    pub fn bug_args<T>(args: Arguments) -> Result<T, Error> {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug: {args}");
        } else {
            debug!("Hit a bug: {args}");
            let caller = core::panic::Location::caller();
            Err(Error::Bug {
                location: snafu::Location::new(
                    caller.file(),
                    caller.line(),
                    caller.column(),
                ),
            })
        }
    }

    #[track_caller]
    #[cold]
    /// TODO: is the generic `T` going to make it bloat?
    pub fn bug_msg<T>(msg: &str) -> Result<T, Error> {
        Self::bug_args(format_args!("{}", msg))
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
            Error::bug_args(args)
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
            Error::bug_args(args)
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(_e: Utf8Error) -> Error {
        Error::BadString
    }
}

impl From<BhError> for Error {
    fn from(e: BhError) -> Error {
        match e {
            BhError::Fail => Error::BehaviourError { msg: "Unknown" }
        }
    }
}

// needed for docs. TODO cfg for doc?
// #[cfg(feature = "std")]
// impl serde::de::StdError for Error {}

// TODO: need to figure how to return our own Error variants from serde
// rather than using serde Error::custom().
impl serde::ser::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: core::fmt::Display,
    {
        trace!("custom ser error: {}", msg);

        Error::msg("ser error")
    }
}

impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: core::fmt::Display,
    {
        trace!("custom de error: {}", msg);

        Error::msg("de error")
    }

    fn invalid_value(unexp: Unexpected<'_>, exp: &dyn Expected) -> Self {
        if let Unexpected::Unsigned(val) = unexp {
            if val <= 255 {
                return Error::InvalidDeserializeU8 { value: val as u8 };
            }
        }
        info!("Invalid input. Expected {} got {:?}", exp, unexp);
        if let Unexpected::Str(_) = unexp {
            return Error::BadString
        }
        Error::bug()
    }

    fn unknown_variant(variant: &str, _expected: &'static [&'static str]) -> Self {
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
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn unknown_name_from_pt(s: std::string::String) {
            let u: UnknownName = s.as_str().into();
            let cap = u.0.capacity();
            if s.escape_default().count() > cap {
                assert_eq!(&u.0[cap-4..], " ...");
            }
        }

    }

}

