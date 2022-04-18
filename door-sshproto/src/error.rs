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
    Custom { msg: &'static str },

    /// Program bug.
    /// This state should not be reached, previous logic should have prevented it.
    Bug,
}

impl Error {
    pub fn msg(m: &'static str) -> Error {
        Error::Custom { msg: m }
    }
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Error {
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
