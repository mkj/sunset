#[allow(unused_imports)]
use sunset::error::{Error, Result, TrapBug};

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
use log::{debug, error, info, log, trace, warn};

#[allow(unused)]
#[cfg(feature = "defmt")]
use defmt::{debug, error, info, panic, trace, warn};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use heapless::String;

use sunset_sshwire_derive::*;

use sunset::sshwire::{
    SSHDecode, SSHEncode, SSHSink, SSHSource, WireError, WireResult,
};

use sunset::packets::Ed25519PubKey;
use sunset::{KeyType, SignKey};

pub const KEY_SLOTS: usize = 3;

// Be sure to bump CURRENT_VERSION
// if this struct changes (or encode/decode impls).
// BUF_SIZE will probably also need updating.
#[derive(Debug, Clone, PartialEq)]
pub struct SSHConfig {
    pub hostkey: SignKey,

    /// login password for serial
    pub console_pw: Option<PwHash>,
    pub console_keys: [Option<Ed25519PubKey>; KEY_SLOTS],
    pub console_noauth: bool,

    /// For serial admin interface, or ssh
    ///
    /// If unset then serial logins are allowed without a password.
    /// SSH logins are never allowed without a password. TODO add a flag
    /// to disable all SSH password logins.
    pub admin_pw: Option<PwHash>,
    /// for ssh admin
    pub admin_keys: [Option<Ed25519PubKey>; KEY_SLOTS],

    /// SSID
    pub wifi_net: String<32>,
    /// WPA2 passphrase. None is Open network.
    pub wifi_pw: Option<String<63>>,
}

impl SSHConfig {
    /// Bump this when the format changes
    pub const CURRENT_VERSION: u8 = 4;
    /// A buffer this large will fit any SSHConfig.
    // It can be updated by looking at
    // `cargo test -- roundtrip_config --show-output`
    pub const BUF_SIZE: usize = 443;

    /// Creates a new config with default parameters.
    ///
    /// Will only fail on RNG failure.
    pub fn new() -> Result<Self> {
        let hostkey = SignKey::generate(KeyType::Ed25519, None)?;

        let wifi_net = option_env!("WIFI_NET").unwrap_or("guest").into();
        let wifi_pw = option_env!("WIFI_PW").map(|p| p.into());
        Ok(SSHConfig {
            hostkey,
            console_pw: None,
            console_keys: Default::default(),
            console_noauth: false,
            admin_pw: None,
            admin_keys: Default::default(),
            wifi_net,
            wifi_pw,
        })
    }

    pub fn set_console_pw(&mut self, pw: Option<&str>) -> Result<()> {
        self.console_pw = pw.map(|p| PwHash::new(p)).transpose()?;
        Ok(())
    }

    pub fn check_console_pw(&mut self, pw: &str) -> bool {
        if let Some(ref p) = self.console_pw {
            p.check(pw)
        } else {
            false
        }
    }

    pub fn set_admin_pw(&mut self, pw: Option<&str>) -> Result<()> {
        self.admin_pw = pw.map(|p| PwHash::new(p)).transpose()?;
        Ok(())
    }

    pub fn check_admin_pw(&mut self, pw: &str) -> bool {
        if let Some(ref p) = self.admin_pw {
            p.check(pw)
        } else {
            false
        }
    }
}

// a private encoding specific to demo config, not SSH defined.
fn enc_signkey(k: &SignKey, s: &mut dyn SSHSink) -> WireResult<()> {
    // need to add a variant field if we support more key types.
    match k {
        SignKey::Ed25519(k) => k.to_bytes().enc(s),
        _ => Err(WireError::UnknownVariant),
    }
}

fn dec_signkey<'de, S>(s: &mut S) -> WireResult<SignKey>
where
    S: SSHSource<'de>,
{
    let k: ed25519_dalek::SecretKey = SSHDecode::dec(s)?;
    let k = ed25519_dalek::SigningKey::from_bytes(&k);
    Ok(SignKey::Ed25519(k))
}

// encode Option<T> as a bool then maybe a value
fn enc_option<T: SSHEncode>(v: &Option<T>, s: &mut dyn SSHSink) -> WireResult<()> {
    v.is_some().enc(s)?;
    v.enc(s)
}

fn dec_option<'de, S, T: SSHDecode<'de>>(s: &mut S) -> WireResult<Option<T>>
where
    S: SSHSource<'de>,
{
    bool::dec(s)?.then(|| SSHDecode::dec(s)).transpose()
}

impl SSHEncode for SSHConfig {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        info!("enc si");
        enc_signkey(&self.hostkey, s)?;

        info!("enc pw");
        enc_option(&self.console_pw, s)?;

        for k in self.console_keys.iter() {
            info!("enc k");
            enc_option(k, s)?;
        }

        self.console_noauth.enc(s)?;

        info!("enc ad");
        enc_option(&self.admin_pw, s)?;

        for k in self.admin_keys.iter() {
            info!("enc ke");
            enc_option(k, s)?;
        }

        info!("enc net");
        self.wifi_net.as_str().enc(s)?;
        info!("enc netpw");
        enc_option(&self.wifi_pw, s)?;
        Ok(())
    }
}

impl<'de> SSHDecode<'de> for SSHConfig {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        info!("dec si");
        let hostkey = dec_signkey(s)?;

        info!("dec pw");
        let console_pw = dec_option(s)?;

        let mut console_keys = [None, None, None];
        for k in console_keys.iter_mut() {
            info!("dec k");
            *k = dec_option(s)?;
        }

        let console_noauth = SSHDecode::dec(s)?;

        info!("dec ad");
        let admin_pw = dec_option(s)?;

        let mut admin_keys = [None, None, None];
        for k in admin_keys.iter_mut() {
            info!("dec adk");
            *k = dec_option(s)?;
        }

        info!("dec wn");
        let wifi_net = SSHDecode::dec(s)?;
        info!("dec wp");
        let wifi_pw = dec_option(s)?;

        Ok(Self {
            hostkey,
            console_pw,
            console_keys,
            console_noauth,
            admin_pw,
            admin_keys,
            wifi_net,
            wifi_pw,
        })
    }
}

/// Stores a bcrypt password hash.
///
/// We use bcrypt because it seems the best password hashing option where
/// memory hardness isn't possible (the rp2040 is smaller than CPU or GPU memory).
///
/// The cost is currently set to 6, taking ~500ms on a 125mhz rp2040.
/// Time converges to roughly 8.6ms * 2**cost
///
/// Passwords are pre-hashed to avoid bcrypt's 72 byte limit.
/// rust-bcrypt allows nulls in passwords.
/// We use an hmac rather than plain hash to avoid password shucking
/// (an attacker bcrypts known hashes from some other breach, then
/// brute forces the weaker hash for any that match).
#[derive(Clone, SSHEncode, SSHDecode, PartialEq)]
pub struct PwHash {
    salt: [u8; 16],
    hash: [u8; 24],
    cost: u8,
}

impl PwHash {
    const COST: u8 = 6;
    /// `pw` must not be empty.
    pub fn new(pw: &str) -> Result<Self> {
        if pw.is_empty() {
            return sunset::error::BadUsage.fail();
        }

        let mut salt = [0u8; 16];
        sunset::random::fill_random(&mut salt)?;
        let prehash = Self::prehash(pw, &salt);
        let cost = Self::COST;
        let hash = bcrypt::bcrypt(cost as u32, salt, &prehash);
        Ok(Self { salt, hash, cost })
    }

    pub fn check(&self, pw: &str) -> bool {
        if pw.is_empty() {
            return false;
        }
        let prehash = Self::prehash(pw, &self.salt);
        let check_hash =
            bcrypt::bcrypt(self.cost as u32, self.salt.clone(), &prehash);
        check_hash == self.hash
    }

    fn prehash(pw: &str, salt: &[u8]) -> [u8; 32] {
        // OK unwrap: can't fail, accepts any length
        let mut prehash = Hmac::<Sha256>::new_from_slice(&salt).unwrap();
        prehash.update(pw.as_bytes());
        prehash.finalize().into_bytes().into()
    }
}

impl core::fmt::Debug for PwHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PwHash").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    use config::PwHash;
    use sunset::packets::Ed25519PubKey;
    use sunset::sshwire::{self, Blob};

    #[test]
    fn roundtrip_config() {
        // default config
        let c1 = SSHConfig::new().unwrap();
        let mut buf = [0u8; 1000];
        let l = sshwire::write_ssh(&mut buf, &c1).unwrap();
        let v = &buf[..l];
        let c2: SSHConfig = sshwire::read_ssh(&buf, None).unwrap();
        assert_eq!(c1, c2);

        // All the fruit, to check BUF_SIZE.
        // Variable length fields are all max size.
        let mut c1 = SSHConfig {
            hostkey: c1.hostkey,
            console_pw: Some(PwHash::new("zong").unwrap()),
            console_keys: [
                Some(Ed25519PubKey { key: Blob([14u8; 32]) }),
                Some(Ed25519PubKey { key: Blob([24u8; 32]) }),
                Some(Ed25519PubKey { key: Blob([34u8; 32]) }),
            ],
            console_noauth: true,
            admin_pw: Some(PwHash::new("f").unwrap()),
            admin_keys: [
                Some(Ed25519PubKey { key: Blob([19u8; 32]) }),
                Some(Ed25519PubKey { key: Blob([29u8; 32]) }),
                Some(Ed25519PubKey { key: Blob([39u8; 32]) }),
            ],
            wifi_net: core::str::from_utf8([b'a'; 32].as_slice()).unwrap().into(),
            wifi_pw: Some(
                core::str::from_utf8([b'f'; 63].as_slice()).unwrap().into(),
            ),
        };

        let mut buf = [0u8; SSHConfig::BUF_SIZE];
        let l = sshwire::write_ssh(&mut buf, &c1).unwrap();
        println!("BUF_SIZE must be at least {}", l);
        let v = &buf[..l];
        let c2: SSHConfig = sshwire::read_ssh(&buf, None).unwrap();
        assert_eq!(c1, c2);
    }
}
