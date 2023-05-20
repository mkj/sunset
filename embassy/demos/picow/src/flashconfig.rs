#[allow(unused_imports)]
use {
    sunset::error::{Error, Result, TrapBug},
};

#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

use embassy_rp::flash::{Flash, ERASE_SIZE, FLASH_BASE};
use embassy_rp::peripherals::FLASH;

use sha2::Digest;

use core::borrow::Borrow;

use sunset_sshwire_derive::*;
use sunset::sshwire;
use sunset::sshwire::{BinString, SSHEncode, SSHDecode, WireResult, SSHSource, SSHSink, WireError};
use sunset::sshwire::OwnOrBorrow;

use crate::demo_common::SSHConfig;

// bump this when the format changes
const CURRENT_VERSION: u8 = 1;

// TODO: unify offsets with wifi's romfw feature
const CONFIG_OFFSET: u32 = 0x150000;
const FLASH_SIZE: usize = 2*1024*1024;

#[derive(SSHEncode, SSHDecode)]
struct FlashConfig<'a> {
    version: u8,
    config: OwnOrBorrow<'a, SSHConfig>,
    /// sha256 hash of config
    hash: [u8; 32],
}

fn config_hash(config: &SSHConfig) -> Result<[u8; 32]> {
    let mut h = sha2::Sha256::new();
    sshwire::hash_ser(&mut h, config, None)?;
    Ok(h.finalize().into())
}

/// Loads a SSHConfig at startup. Good for persisting hostkeys.
pub fn load_or_create(flash: &mut Flash<'_, FLASH, FLASH_SIZE>) -> Result<SSHConfig> {
    let c = load(flash);
    match load(flash) {
        Ok(c) => {
            info!("Good existing config");
            return Ok(c)
        }
        Err(c) => info!("Existing config bad, making new"),
    }

    create(flash)
}

pub fn create(flash: &mut Flash<'_, FLASH, FLASH_SIZE>) -> Result<SSHConfig> {
    let c = SSHConfig::new()?;
    if let Err(e) = save(flash, &c) {
        warn!("Error writing config");
    }
    Ok(c)
}

pub fn load(flash: &mut Flash<'_, FLASH, FLASH_SIZE>) -> Result<SSHConfig> {
    let mut buf = [0u8; ERASE_SIZE];
    flash.read(CONFIG_OFFSET, &mut buf).map_err(|_| Error::msg("flash error"))?;
    let s: FlashConfig = sshwire::read_ssh(&buf, None)?;

    if s.version != CURRENT_VERSION {
        return Err(Error::msg("wrong config version"))
    }

    let calc_hash = config_hash(s.config.borrow())?;
    if calc_hash != s.hash {
        return Err(Error::msg("bad config hash"))
    }

    if let OwnOrBorrow::Own(c) = s.config {
        Ok(c)
    } else {
        // OK panic - OwnOrBorrow always decodes to Own variant
        panic!()
    }
}

pub fn save(flash: &mut Flash<'_, FLASH, FLASH_SIZE>, config: &SSHConfig) -> Result<()> {
    let mut buf = [0u8; ERASE_SIZE];
    let sc = FlashConfig {
        version: CURRENT_VERSION,
        config: OwnOrBorrow::Borrow(&config),
        hash: config_hash(&config)?,
    };
    sshwire::write_ssh(&mut buf, &sc)?;
    trace!("flash erase");
    flash.erase(CONFIG_OFFSET, CONFIG_OFFSET + ERASE_SIZE as u32)
    .map_err(|_| Error::msg("flash erase error"))?;

    trace!("flash write");
    flash.write(CONFIG_OFFSET, &buf)
    .map_err(|_| Error::msg("flash write error"))?;

    trace!("save done");
    Ok(())
}

