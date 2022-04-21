use rand::RngCore;
use ring::rand::SecureRandom;
use crate::error::Error;

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // TODO: can this return an error?
    rand::rngs::OsRng.fill_bytes(buf);
    Ok(())
}
