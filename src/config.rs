// TODO
pub const DEFAULT_WINDOW: usize = 1000;
pub const DEFAULT_MAX_PACKET: usize = 1000;

// TODO: Perhaps instead of MAX_CHANNELS we could have a type alias
// of either heapless::Vec<> or std::vec::Vec<>
//
// This size is arbitrary and may be increased, though note that some code paths assume
// a linear scan of channels can happen quickly, so may need reworking for performance.
pub const MAX_CHANNELS: usize = 4;

// Enough for longest 23 of "screen.konsole-256color" on my system
// Unsure if this is specified somewhere
pub const MAX_TERM: usize = 32;

pub const DEFAULT_TERM: &str = "xterm";

pub const RSA_DEFAULT_KEYSIZE: usize = 2048;
pub const RSA_MIN_KEYSIZE: usize = 1024;

/// Maximum username for client or server
///
/// 31 is the limit for various Linux APIs like wtmp
/// A larger limit can be set with `larger` crate feature
#[cfg(not(feature = "larger"))]
pub const MAX_USERNAME: usize = 31;

/// Maximum username for client or server
///
/// 31 is the limit for various Linux APIs like wtmp
#[cfg(feature = "larger")]
pub const MAX_USERNAME: usize = 256;

// TODO: server auth timeout/tries
