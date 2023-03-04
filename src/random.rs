#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use rand::{RngCore, Rng, CryptoRng};
use core::num::Wrapping;

pub type SunsetRng = rand::rngs::OsRng;

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // TODO: can this return an error?
    let mut rng = SunsetRng::default();
    rng.try_fill_bytes(buf)
        .map_err(|e| {
            debug!("RNG failed: {e:?}");
            Error::msg("RNG failed")
        })
}
