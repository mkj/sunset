#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use rand::{RngCore, Rng, CryptoRng};
use core::num::Wrapping;

#[cfg(feature = "getrandom")]
pub type DoorRng = rand::rngs::OsRng;

#[cfg(feature = "fakerandom")]
pub type DoorRng = FakeRng;

#[derive(Clone, Copy, Debug, Default)]
pub struct FakeRng {
    state: Wrapping<u32>,
}

impl CryptoRng for FakeRng {}

impl RngCore for FakeRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill_with(|| {
              self.state = Wrapping(14013u32) * self.state + Wrapping(2531011u32);
              ((self.state>>16).0 & 0xFF) as u8
        });
        dest.fill(8)

    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(dest.fill(8))
        // Ok(dest.fill_with(|| {
        //       self.state = Wrapping(14013u32) * self.state + Wrapping(2531011u32);
        //       ((self.state>>16).0 & 0xFF) as u8
        // }))
    }

}

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // TODO: can this return an error?
    let mut rng = DoorRng::default();
    rng.try_fill_bytes(buf)
        .map_err(|e| {
            debug!("RNG failed: {e:?}");
            Error::msg("RNG failed")
        })
}
