#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use core::str::Utf8Error;

use serde::de::{Expected, Unexpected};
use snafu::{prelude::*,Location};

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
    SignatureMismatch { key: &'static str, sig: &'static str },

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

    /// Serde invalid value
    // internal
    InvalidDeserializeU8 { value: u8 },

    /// Other custom error
    // TODO: these 
    Custom { msg: &'static str },

    /// Program bug.
    /// This state should not be reached, previous logic should have prevented it.
    /// Don't create `Bug` directly, instead use [`Error::bug()`] or
    /// [`.trap()`](TrapBug::trap) to make finding the source easier.
    Bug {
        location: snafu::Location,
    }
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
            Error::Bug { location: snafu::Location::new(caller.file(), caller.line(), caller.column()) }
        }
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait TrapBug<T> {
    /// `.trap()` should be used like `.unwrap()`, in situations
    /// never expected to fail. Instead it returns [`Error::Bug`].
    /// (or debug builds may panic)
    #[track_caller]
    fn trap(self) -> Result<T, Error>;
}

impl<T, E> TrapBug<T> for Result<T, E>
{
    fn trap(self) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Ok(i) = self {
            Ok(i)
        } else {
            Err(Error::bug())
        }
    }
}

impl<T> TrapBug<T> for Option<T>
{
    fn trap(self) -> Result<T, Error> {
        // call directly so that Location::caller() works
        if let Some(i) = self {
            Ok(i)
        } else {
            Err(Error::bug())
        }
    }
}

impl From<Utf8Error> for Error {
    fn from(_e: Utf8Error) -> Error {
        Error::BadString
    }
}

impl serde::de::StdError for Error {}

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

        error!("serde de error: {}", msg);
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
}

pub struct ExpectedMessageNumber;

impl Expected for ExpectedMessageNumber {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "a known SSH message number")
    }
}
