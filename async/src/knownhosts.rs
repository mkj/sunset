#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::io::{BufRead, Write, Read};
use std::io;

use crate::*;
use sunset::packets::PubKey;

type OpenSSHKey = ssh_key::PublicKey;

#[derive(Debug)]
pub enum KnownHostsError {
    /// Host Key Mismatch
    Mismatch { path: PathBuf, line: usize, existing: OpenSSHKey },

    /// User didn't accept new key
    NotAccepted,

    /// Failure
    Failure {
        source: Box<dyn std::error::Error>
    },

    Other { msg: String },
}

impl<E> From<E> for KnownHostsError
where
    E: std::error::Error + 'static
{
    fn from(e: E) -> Self {
        KnownHostsError::Failure { source: Box::new(e) }
    }
}

const USER_KNOWN_HOSTS: &str = ".ssh/known_hosts";

fn user_known_hosts() -> Result<PathBuf, KnownHostsError> {
    // home_dir() works fine on linux.
    #[allow(deprecated)]
    let p = std::env::home_dir().ok_or_else(|| KnownHostsError::Other {
        msg: "Failed getting home directory".into(),
    })?;
    Ok(p.join(USER_KNOWN_HOSTS))
}

pub fn check_known_hosts(
    host: &str,
    port: u16,
    key: &PubKey,
) -> Result<(), KnownHostsError> {
    let p = user_known_hosts()?;
    check_known_hosts_file(host, port, key, &p)
}

/// Returns a `(host, key)` entry from a known_hosts line, or `None` if not matching
fn line_entry(line: &str) -> Option<(String, String)> {
    line.split_once(' ').map(|(h, k)| (h.into(), k.into()))
}

/// Returns the host string. Non-22 ports are appended.
fn host_part(host: &str, port: u16) -> String {
    let mut host = host.to_lowercase();
    if port != sunset::sshnames::SSH_PORT {
        host = format!("[{host}]:{port}");
    }
    host
}

pub fn check_known_hosts_file(
    host: &str,
    port: u16,
    key: &PubKey,
    p: &Path,
) -> Result<(), KnownHostsError> {
    let f = File::open(p)?;
    let f = io::BufReader::new(f);

    let match_host = host_part(host, port);

    let pubk: OpenSSHKey = key.try_into()?;

    for (line, (lh, lk)) in f.lines().enumerate()
        .filter_map(|(num, l)| {
            if let Ok(l) = l {
                line_entry(&l).map(|entry| (num, entry))
            } else {
                None
            }
        }) {
        let line = line + 1;

        if lh != match_host {
            continue;
        }

        let known_key = match OpenSSHKey::from_openssh(&lk) {
            Ok(k) => k,
            Err(e) => {
                warn!("Unparsed key for \"{}\" on line {}:{}", host, p.display(), line);
                trace!("{e:?}");
                continue;
            }
        };

        if pubk.algorithm() != known_key.algorithm() {
            debug!("Line {line}, Ignoring other-format existing key {known_key:?}")
        } else {
            if pubk.key_data() == known_key.key_data() {
                debug!("Line {line}, found matching key");
                return Ok(())
            } else {
                let fp = known_key.fingerprint(Default::default());
                println!("\nHost key mismatch for {match_host} in ~/.ssh/known_hosts line {line}\n\
                    Existing key has fingerprint {fp}\n");
                return Err(KnownHostsError::Mismatch { path: p.to_path_buf(), line, existing: known_key });
            }
        }
    }

    // no match, maybe add it
    ask_to_confirm(host, port, key, p)
}

fn read_tty_response() -> Result<String, std::io::Error> {
    let mut s;
    let mut f = File::open("/dev/tty");
    let f: &mut dyn Read = match f.as_mut() {
        Ok(f) => f,
        Err(_) => {
            s = io::stdin();
            &mut s
        },
    };

    let mut f = io::BufReader::new(f);
    let mut resp = String::new();
    f.read_line(&mut resp)?;
    Ok(resp)
}

fn ask_to_confirm(
    host: &str,
    port: u16,
    key: &PubKey,
    p: &Path,
) -> Result<(), KnownHostsError> {

    let k: OpenSSHKey = key.try_into()?;
    let fp = k.fingerprint(Default::default());
    let h = host_part(host, port);
    let _ = writeln!(io::stderr(), "\nHost {h} is not in ~/.ssh/known_hosts\nFingerprint {fp}\nDo you want to continue connecting? (y/n)");

    let mut resp = read_tty_response()?;
    resp.make_ascii_lowercase();
    if resp.starts_with('y') {
        add_key(host, port, key, p)
    } else {
        Err(KnownHostsError::NotAccepted)
    }
}

fn add_key(
    host: &str,
    port: u16,
    key: &PubKey,
    p: &Path,
) -> Result<(), KnownHostsError> {

    let k: OpenSSHKey = key.try_into()?;
    // encode it
    let k = k.to_openssh()?;

    let h = host_part(host, port);

    let entry = format!("{h} {k}\n");

    let mut f = std::fs::OpenOptions::new().append(true).open(p)?;

    f.write_all(entry.as_bytes())?;

    Ok(())
}

