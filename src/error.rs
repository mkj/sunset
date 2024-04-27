use core::str::Utf8Error;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::fmt::Arguments;
use core::fmt;

use snafu::{prelude::*, Location};

use heapless::String;

use crate::channel::ChanNum;

// TODO: can we make Snafu not require Debug?

/// The Sunset error type.
#[non_exhaustive]
#[derive(Snafu, Debug)]
#[snafu(context(suffix(false)))]
// TODO: maybe split this into a list of public vs private errors?
#[snafu(visibility(pub))]
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

    /// Packet integrity failed
    BadDecrypt,

    /// Signature is incorrect
    BadSig,

    /// Integer overflow in packet
    BadNumber,

    /// Error in received SSH protocol. Will disconnect.
    SSHProtoError,

    /// Peer sent something we don't handle. Will disconnect.
    ///
    /// This differs to `SSHProtoError`. In this case the peer may be
    /// behaved within the SSH specifications, but Sunset doesn't
    /// support it.
    // TODO: 'static disconnect message to return?
    SSHProtoUnsupported,

    /// Received a key with invalid structure, or too large.
    BadKeyFormat,

    /// Remote peer isn't SSH
    NotSSH,

    /// Bad key format
    BadKey,

    /// Ran out of channels
    NoChannels,

    #[snafu(display("Bad channel number {num}"))]
    BadChannel { num: ChanNum },

    /// Bad channel data type
    ///
    /// Returned from an API call that would imply ChanData::Stderr
    /// being sent to a server. This error will not be returned for
    /// network data in the incorrect direction, instead that data is dropped.
    BadChannelData,

    /// Bad application usage
    ///
    /// Returned from an API call when the API is used incorrectly.
    /// Examples could include:
    /// - A `ChanHandle` is used incorrectly, for example being cloned
    ///   (millions of times) and not released.
    // TODO: /// #[snafu(display("Failure from application: {msg}"))]
    BadUsage {
        #[snafu(implicit)]
        backtrace: snafu::Backtrace,
        // TODO
        // msg: &'static str,
    },

    /// SSH packet contents doesn't match length
    WrongPacketLength,

    /// Channel EOF
    ///
    /// This is an expected error when a SSH channel completes. Can be returned
    /// by channel read/write functions. Any further calls in the same direction
    /// will fail similarly.
    ChannelEOF,

    // Used for unknown key types etc.
    #[snafu(display("{what} is not available"))]
    NotAvailable { what: &'static str },

    #[snafu(display("Unknown packet type {number}"))]
    UnknownPacket { number: u8 },

    /// Received packet at a disallowed time.
    // TODO: this is kind of a subset of SSHProtoError, maybe not needed
    PacketWrong,
    // #[snafu(display("Program bug {location}"))]
    // Bug { location: snafu::Location },

    #[snafu(display("No matching {algo} algorithm"))]
    AlgoNoMatch { algo: &'static str },

    #[snafu(display("Packet size {size} too large (or bad decrypt)"))]
    BigPacket { size: usize },

    /// An unknown SSH name is provided, for a key type, signature type,
    /// channel name etc.
    #[snafu(display("Unknown {kind} method"))]
    UnknownMethod { kind: &'static str},

    #[snafu(display("{msg}"))]
    // TODO: these could eventually get categorised
    Custom { msg: &'static str },

    /// IO Error
    #[cfg(feature = "std")]
    IoError { source: std::io::Error },

    // This state should not be reached, previous logic should have prevented it.
    // Create this using [`Error::bug()`] or [`.trap()`](TrapBug::trap).
    // Location is currently disabled due to bloat.
    // #[snafu(display("Program bug {location}"))]
    // Bug { location: snafu::Location },
    /// Program bug
    Bug,
}

impl Error {
    pub fn msg(m: &'static str) -> Error {
        Error::Custom { msg: m }
    }

    #[cold]
    #[track_caller]
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

    /// Like [`bug()`](Error::bug) but with a message
    ///
    /// The message can be used instead of a code comment, is logged at `debug` level.
    #[cold]
    pub fn bug_fmt(args: Arguments) -> Error {
        // Easier to track the source of errors in development,
        // but release builds shouldn't panic.
        if cfg!(debug_assertions) {
            panic!("Hit a bug: {args}");
        } else {
            trace!("Hit a bug: {args}");
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

#[cfg(feature = "embedded-io")]
impl embedded_io::Error for Error {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

/// A Sunset-specific Result type.
pub type Result<T, E = Error> = core::result::Result<T, E>;

pub trait TrapBug<T> {
    /// `.trap()` should be used like `.unwrap()`, in situations
    /// never expected to fail. Instead it calls [`Error::bug()`].
    /// (or debug builds may panic)
    fn trap(self) -> Result<T, Error>;

    /// Like `trap()` but with a message, calls [`Error::bug_msg()`]
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
    #[track_caller]
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

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IoError { source: value }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::error::*;
    use crate::sunsetlog::init_test_log;
    use crate::packets::Unknown;

}

