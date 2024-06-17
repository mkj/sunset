#[allow(unused_imports)]
use {
    sunset::error::{Error, Result, TrapBug},
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embassy_rp::flash::{Flash, Async, ERASE_SIZE};
use embassy_rp::peripherals::FLASH;

use sha2::Digest;

use core::borrow::Borrow;

use sunset_sshwire_derive::*;
use sunset::sshwire;
use sunset::sshwire::OwnOrBorrow;
use embedded_storage_async::nor_flash::NorFlash;

use crate::demo_common;
use demo_common::SSHConfig;

// TODO: unify offsets with wifi's romfw feature
const CONFIG_OFFSET: u32 = 0x150000;
pub const FLASH_SIZE: usize = 2*1024*1024;

pub(crate) struct Fl<'a> {
    flash: Flash<'a, FLASH, Async, FLASH_SIZE>,
    // Only a single task can write to flash at a time,
    // keeping a buffer here saves duplicated buffer space in each task.
    buf: [u8; FlashConfig::BUF_SIZE],
}

impl<'a> Fl<'a> {
    pub fn new(flash: Flash<'a, FLASH, Async, FLASH_SIZE>) -> Self {
        Self {
            flash,
            buf: [0u8; FlashConfig::BUF_SIZE],
        }
    }
}

// SSHConfig::CURRENT_VERSION must be bumped if any of this struct changes
#[derive(SSHEncode, SSHDecode)]
struct FlashConfig<'a> {
    version: u8,
    config: OwnOrBorrow<'a, SSHConfig>,
    /// sha256 hash of config
    hash: [u8; 32],
}

impl FlashConfig<'_> {
    const BUF_SIZE: usize = 4 + SSHConfig::BUF_SIZE + 32;
}
const _: () = assert!(FlashConfig::BUF_SIZE % 4 == 0, "flash reads must be a multiple of 4");

fn config_hash(config: &SSHConfig) -> Result<[u8; 32]> {
    let mut h = sha2::Sha256::new();
    sshwire::hash_ser(&mut h, config)?;
    Ok(h.finalize().into())
}

/// Loads a SSHConfig at startup. Good for persisting hostkeys.
pub async fn load_or_create(flash: &mut Fl<'_>) -> Result<SSHConfig> {
    match load(flash).await {
        Ok(c) => {
            info!("Good existing config");
            return Ok(c)
        }
        // Err(sunset::Error::Custom(msg: msg)) => info!("Existing config bad, making new. {}", msg),
        Err(e) => info!("Existing config bad, making new. {e}"),
    }

    create(flash).await
}

pub async fn create(flash: &mut Fl<'_>) -> Result<SSHConfig> {
    let c = SSHConfig::new()?;
    if let Err(_) = save(flash, &c).await {
        warn!("Error writing config");
    }
    Ok(c)
}

pub async fn load(fl: &mut Fl<'_>) -> Result<SSHConfig> {
    fl.flash.read(CONFIG_OFFSET, &mut fl.buf).await.map_err(|e| {
        debug!("flash read error 0x{CONFIG_OFFSET:x} {e:?}");
        Error::msg("flash error")
    })?;

    // use pretty_hex::PrettyHex;
    // use core::fmt::Write;
    // let mut b = demo_common::BufOutput::default();
    // writeln!(b, "load {:?}", buf.hex_dump());
    // info!("{}", &b.s);

    let s: FlashConfig = sshwire::read_ssh(&fl.buf, None)?;

    if s.version != SSHConfig::CURRENT_VERSION {
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

pub async fn save(fl: &mut Fl<'_>, config: &SSHConfig) -> Result<()> {
    let sc = FlashConfig {
        version: SSHConfig::CURRENT_VERSION,
        config: OwnOrBorrow::Borrow(&config),
        hash: config_hash(&config)?,
    };
    let l = sshwire::write_ssh(&mut fl.buf, &sc)?;
    let buf = &fl.buf[..l];

    // use pretty_hex::PrettyHex;
    // use core::fmt::Write;
    // let mut b = demo_common::BufOutput::default();
    // writeln!(b, "save {:?}", buf.hex_dump());
    // info!("{}", &b.s);

    trace!("flash erase");
    fl.flash.erase(CONFIG_OFFSET, CONFIG_OFFSET + ERASE_SIZE as u32)
    .await
    .map_err(|_| Error::msg("flash erase error"))?;

    trace!("flash write");
    fl.flash.write(CONFIG_OFFSET, &buf).await
    .map_err(|_| Error::msg("flash write error"))?;

    info!("flash save done");
    Ok(())
}

