// TODO
pub const DEFAULT_WINDOW: usize = 1000;
pub const DEFAULT_MAX_PACKET: usize = 1000;

// TODO: perhaps this is a parameter, the Channel Vec storage type itself is a parameter
// and boundless for alloc.

// This can be increased arbitrarily, though note that some code paths assume
// a linear scan of channels can happen quickly, so may need reworking for performance.
pub const MAX_CHANNELS: usize = 4;

// TODO
pub const MAX_EXEC: usize = 200;

// Enough for longest 23 of "screen.konsole-256color" on my system
// Unsure if this is specified somewhere
pub const MAX_TERM: usize = 32;

pub const DEFAULT_TERM: &str = "xterm";

pub const RSA_DEFAULT_KEYSIZE: usize = 2048;
pub const RSA_MIN_KEYSIZE: usize = 1024;
