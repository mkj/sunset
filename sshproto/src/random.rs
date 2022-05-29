#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use rand::RngCore;

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // TODO: can this return an error?
    rand::rngs::OsRng.try_fill_bytes(buf)
        .map_err(|e| {
            debug!("RNG failed: {e:?}");
            Error::msg("RNG failed")
        })
}
