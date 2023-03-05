#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buf)
    .map_err(|_| {
        Error::msg("RNG failed")
    })
}
