use rand::RngCore;
use crate::error::Error;

pub fn fill_random(buf: &mut [u8]) -> Result<(), Error> {
    // TODO: can this return an error?
    rand::rngs::OsRng.try_fill_bytes(buf);
    Ok(())
}
