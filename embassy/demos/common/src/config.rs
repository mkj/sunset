#[allow(unused_imports)]
use {
    sunset::error::{Error, Result, TrapBug},
};

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused)]
#[cfg(feature = "defmt")]
use defmt::{debug, info, warn, panic, error, trace};

use heapless::String;

use sunset_sshwire_derive::*;
use sunset::sshwire;
use sunset::sshwire::{BinString, SSHEncode, SSHDecode, WireResult, SSHSource, SSHSink, WireError};

use sunset::{SignKey, KeyType};

// Be sure to bump picow flash_config::CURRENT_VERSION
// if this struct changes (or encode/decode impls).
#[derive(Debug)]
pub struct SSHConfig {
    pub hostkey: SignKey,
    /// login password
    pub pw_hash: Option<[u8; 32]>,
    /// SSID
    pub wifi_net: String<32>,
    /// WPA2 passphrase. None is Open network.
    pub wifi_pw: Option<String<63>>,
}

impl SSHConfig {
    /// Creates a new config with default parameters.
    ///
    /// Will only fail on RNG failure.
    pub fn new() -> Result<Self> {
        let hostkey = SignKey::generate(KeyType::Ed25519, None)?;

        let wifi_net = option_env!("WIFI_NETWORK").unwrap_or("guest").into();
        let wifi_pw = option_env!("WIFI_PASSWORD").map(|p| p.into());
        Ok(SSHConfig {
            hostkey,
            pw_hash: None,
            wifi_net,
            wifi_pw,
        })
    }
}

// a private encoding specific to demo config, not SSH defined.
fn enc_signkey(k: &SignKey, s: &mut dyn SSHSink) -> WireResult<()> {
    // need to add a variant field if we support more key types.
    match k {
        SignKey::Ed25519(seed) => seed.enc(s),
        _ => Err(WireError::UnknownVariant),
    }
}

fn dec_signkey<'de, S>(s: &mut S) -> WireResult<SignKey> where S: SSHSource<'de> {
    Ok(SignKey::Ed25519(SSHDecode::dec(s)?))
}

impl SSHEncode for SSHConfig {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        enc_signkey(&self.hostkey, s)?;
        self.pw_hash.is_some().enc(s)?;
        self.pw_hash.enc(s)?;

        self.wifi_net.as_str().enc(s)?;

        self.wifi_pw.is_some().enc(s)?;
        if let Some(ref p) = self.wifi_pw {
            p.as_str().enc(s)?;
        }
        Ok(())
    }
}

impl<'de> SSHDecode<'de> for SSHConfig {
    fn dec<S>(s: &mut S) -> WireResult<Self> where S: SSHSource<'de> {
        let hostkey = dec_signkey(s)?;

        let have_pw_hash = bool::dec(s)?;
        let pw_hash = have_pw_hash.then(|| SSHDecode::dec(s)).transpose()?;

        let wifi_net = <&str>::dec(s)?.into();
        let have_wifi_pw = bool::dec(s)?;

        let wifi_pw = have_wifi_pw.then(|| {
            let p: &str = SSHDecode::dec(s)?;
            Ok(p.into())
        })
        .transpose()?;
        Ok(Self {
            hostkey,
            pw_hash,
            wifi_net,
            wifi_pw,
        })
    }
}


