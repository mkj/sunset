use core::str::Utf8Error;

use snafu::prelude::*;

// TODO: can we make Snafu not require Debug?
#[non_exhaustive]
#[derive(Snafu, Debug)]
pub enum Error {
    /// Output buffer ran out of room
    NoRoom,

    /// Input buffer ran out
    RanOut,

    /// Not implemented (unused in SSH protocol)
    NoSerializer,

    /// Not a UTF8 string
    BadString,

    /// Decryption failure or integrity mismatch
    BadDecrypt,

    /// Error in received SSH protocol
    SSHProtoError,

    /// Remote peer isn't SSH
    NotSSH,

    /// Unknown packet type
    UnknownPacket,

    /// Received packet at a disallowed time
    PacketWrong,

    /// No matching algorithm
    AlgoNoMatch { algo: &'static str },

    /// Packet size too large (or bad decrypt)
    BigPacket,

    /// Random number generation failure
    RngError,

    /// Other custom error
    // TODO: these 
    Custom { msg: &'static str },

    /// Program bug.
    /// This state should not be reached, previous logic should have prevented it.
    /// Don't create `Bug` directly, instead use [`Error::bug()`] or
    /// [`.trap()`](TrapBug::trap) to make finding the source easier.
    Bug,
}

impl Error {
    pub fn msg(m: &'static str) -> Error {
        Error::Custom { msg: m }
    }

    #[inline]
    /// Panics in debug builds, returns [`Error::Bug`] in release.
    // TODO: this should return a Result since it's always used as Err(Error::bug())
    pub fn bug() -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug");
        } else {
            Error::Bug
        }
    }
}

pub trait TrapBug<T> {
    /// `.trap()` should be used like `.unwrap()`, in situations
    /// never expected to fail. Instead it returns [`Error::Bug`].
    /// (or debug builds may panic)
    fn trap(self) -> Result<T, Error>;
}

impl<T, E> TrapBug<T> for Result<T, E>
{
    fn trap(self) -> Result<T, Error> {
        self.map_err(|_| Error::bug())
    }
}

impl<T> TrapBug<T> for Option<T>
{
    fn trap(self) -> Result<T, Error> {
        self.ok_or_else(|| Error::bug())
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
        #[cfg(feature = "std")]
        println!("custom de error: {}", msg);

        Error::msg("de error")
    }
}
