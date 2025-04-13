pub use ed25519_dalek::SigningKey;
use rand_core::CryptoRng;
use rand_core::CryptoRngCore;
use rand_core::RngCore;
use static_cell::StaticCell;
pub use x25519_dalek::EphemeralSecret;
#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

pub trait CryptoRngProvider {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error>;
    fn make_ephemeral_secret(&self) -> Result<x25519_dalek::EphemeralSecret, Error>;
    fn make_signing_key(&self) -> Result<ed25519_dalek::SigningKey, Error>;
}

#[cfg(not(feature = "getrandom"))]
struct NopRngProvider;

#[cfg(not(feature = "getrandom"))]
impl CryptoRngProvider for NopRngProvider {
    fn fill_random(&self, _buf: &mut [u8]) -> Result<(), Error> {
        Err(Error::MissingCryptoProvider)
    }
    fn make_ephemeral_secret(&self) -> Result<x25519_dalek::EphemeralSecret, Error> {
        Err(Error::MissingCryptoProvider)
    }
    fn make_signing_key(&self) -> Result<ed25519_dalek::SigningKey, Error> {
        Err(Error::MissingCryptoProvider)
    }
}

#[cfg(feature = "getrandom")]
struct OsRngProvider;

#[cfg(feature = "getrandom")]
impl CryptoRngProvider for OsRngProvider {
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), Error> {
        return getrandom::getrandom(buf).map_err(|_| Error::msg("RNG failed"));
    }

    fn make_ephemeral_secret(&self) -> Result<x25519_dalek::EphemeralSecret, Error> {
        Ok(x25519_dalek::EphemeralSecret::random_from_rng(&mut rand_core::OsRng))
    }

    fn make_signing_key(&self) -> Result<ed25519_dalek::SigningKey, Error> {
        Ok(ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng))
    }
}

#[cfg(feature = "getrandom")]
static RNG: &(dyn CryptoRngProvider + Sync) = &OsRngProvider;
#[cfg(not(feature = "getrandom"))]
static mut RNG: &(dyn CryptoRngProvider + Sync) = &NopRngProvider;

#[cfg(not(feature = "getrandom"))]
pub unsafe fn assign_rng(rng: &'static (dyn CryptoRngProvider + Sync)) {
    RNG = rng;
}

#[cfg(feature = "getrandom")]
pub fn get_rng() -> &'static dyn CryptoRngProvider {
    RNG
}

#[cfg(not(feature = "getrandom"))]
pub fn get_rng() -> &'static dyn CryptoRngProvider {
    // SAFETY: It's a bit sketchy but only in an embedded
    // situation where assign_rng is possible to call.
    unsafe { RNG }
}

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    get_rng().fill_random(buf)
}
