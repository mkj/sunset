use core::str::Utf8Error;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::fmt::Arguments;
use core::fmt;

use snafu::{prelude::*, Location};

use heapless::String;

use crate::behaviour::BhError;

// TODO: can we make Snafu not require Debug?
// TODO: maybe split this into a list of public vs private errors?

#[non_exhaustive]
#[derive(Snafu, Debug)]
pub enum Error {
    /// Output buffer ran out of room
    NoRoom,

    /// Input buffer ran out
    RanOut,

    /// Not a UTF-8 string
    BadString,

    /// Not a valid SSH ASCII string
    BadName,

    /// Key exchange incorrect
    BadKex,

    /// Decryption failed
    BadDecrypt,

    /// Signature is incorrect
    BadSig,

    /// Integer overflow in packet
    BadNumber,

    /// Error in received SSH protocol. Will disconnect.
    SSHProtoError,

    /// Remote peer isn't SSH
    NotSSH,

    /// Bad key format
    BadKey,

    /// Ran out of channels
    NoChannels,

    /// Bad channel number
    BadChannel,

    /// SSH packet contents doesn't match length
    WrongPacketLength,

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
    #[snafu(display("Unknown {kind} method"))]
    UnknownMethod { kind: &'static str},

    /// Implementation behaviour error
    #[snafu(display("Failure from application: {msg}"))]
    BehaviourError { msg: &'static str },

    #[snafu(display("{msg}"))]
    // TODO: these could eventually get categorised
    Custom { msg: &'static str },

    // This state should not be reached, previous logic should have prevented it.
    // Create this using [`Error::bug()`] or [`.trap()`](TrapBug::trap).
    // Location is currently disabled due to bloat.
    // #[snafu(display("Program bug {location}"))]
    // Bug { location: snafu::Location },
    /// Program bug
    Bug,

    // TODO remove this
    OtherBug { location: snafu::Location },
}

impl Error {
    pub fn msg(m: &'static str) -> Error {
        Error::Custom { msg: m }
    }

    #[cold]
    /// Panics in debug builds, returns [`Error::Bug`] in release.
    // TODO: this should return a Result since it's always used as Err(Error::bug())
    pub fn bug() -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug");
        } else {
            // let caller = core::panic::Location::caller();
            Error::Bug
            // {
            //     location: snafu::Location::new(
            //         caller.file(),
            //         caller.line(),
            //         caller.column(),
            //     ),
            // }
        }
    }

    pub fn otherbug() -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug");
        } else {
            let caller = core::panic::Location::caller();
            Error::OtherBug
            {
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
    #[cold]
    pub fn bug_fmt(args: Arguments) -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug: {args}");
        } else {
            debug!("Hit a bug: {args}");
            // TODO: this bloats binaries with full paths
            // https://github.com/rust-lang/rust/issues/95529 is having function
            // let caller = core::panic::Location::caller();
            Error::Bug
            // {
            //     location: snafu::Location::new(
            //         caller.file(),
            //         caller.line(),
            //         caller.column(),
            //     ),
            // }
        }
    }

    #[cold]
    /// TODO: is the generic `T` going to make it bloat?
    pub fn bug_msg<T>(msg: &str) -> Result<T, Error> {
        Err(Self::bug_fmt(format_args!("{}", msg)))
    }

    #[cold]
    pub fn bug_err_msg(msg: &str) -> Error {
        Self::bug_fmt(format_args!("{}", msg))
    }

}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait TrapBug<T> {
    /// `.trap()` should be used like `.unwrap()`, in situations
    /// never expected to fail. Instead it calls [`Error::bug()`].
    /// (or debug builds may panic)
    fn trap(self) -> Result<T, Error>;

    /// Like [`trap()`] but with a message, calls [`Error::bug_msg()`]
    /// The message can be used instead of a comment.
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
            Err(Error::bug_fmt(args))
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
            Err(Error::bug_fmt(args))
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

#[cfg(test)]
pub(crate) mod tests {
    use crate::error::*;
    use crate::sunsetlog::init_test_log;
    use crate::packets::Unknown;
    use proptest::prelude::*;


}

