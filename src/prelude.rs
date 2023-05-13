#![allow(unused_imports)]

#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

pub use crate::error::{Error, Result, TrapBug};
