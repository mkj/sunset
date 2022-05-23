use crate::error::{Error,TrapBug};

pub(crate) const OUR_VERSION: &[u8] = "SSH-2.0-door".as_bytes();

const SSH_PREFIX: &[u8] = "SSH-2.0-".as_bytes();

// RFC4253 4.2 says max length 255 incl CR LF.
// TODO find what's in the wild
const MAX_REMOTE_VERSION_LEN: usize = 253;
const MAX_LINES: usize = 50;

pub const CR: u8 = 0x0d;
pub const LF: u8 = 0x0a;

/// Parses and stores the remove SSH version string
pub struct RemoteVersion {
    storage: [u8; MAX_REMOTE_VERSION_LEN],
    /// Parse state
    st: VersPars,
    num_lines: usize,
}

/// Version parsing state.
/// We need to match
/// `SSH-2.0-softwareversion SP comments CR LF`
/// at the start of a line. The server may first send other lines
/// which are discarded.
// TODO: SSH impls advertising SSH1 compatibility will have "SSH-1.99-" instead.
// We may need to handle parsing that as well for compatibility. It's possible
// they aren't common or important these days.

#[derive(Debug)]
pub(crate) enum VersPars {
    /// Reading start of a line, before receiving a full SSH-2.0- prefix
    Start(usize),
    /// Have a line that didn't start with SSH-2.0-, discarding until LF
    Discarding,
    /// Currently reading a SSH-2.0- string, waiting for ending CR
    FillSSH(usize),
    /// Have ending CR after a version, Waiting for ending LF
    HaveCR(usize),
    /// Completed string.
    Done(usize),
}

impl<'a> RemoteVersion {
    pub fn new() -> Self {
        RemoteVersion {
            storage: [0; MAX_REMOTE_VERSION_LEN],
            st: VersPars::Start(0),
            num_lines: 0,
        }
    }

    /// Returns the parsed version if stored.
    pub fn version(&'a self) -> Option<&'a [u8]> {
        match &self.st {
            VersPars::Done(len) => {
                let (s, _) = self.storage.split_at(*len);
                Some(s)
            }
            _ => None,
        }
    }

    /// Reads the initial SSH stream to find the version string and returns
    /// the number of bytes consumed.
    /// Behaviour is undefined if called later after an error.
    pub fn consume(&mut self, buf: &[u8]) -> Result<usize, Error> {
        // consume input byte by byte, feeding through the states
        let mut taken = 0;
        for &b in buf {
            match self.st {
                VersPars::Done(_) => {}
                _ => taken += 1,
            }

            match self.st {
                VersPars::Start(ref mut pos) => {
                    let w = self.storage.get_mut(*pos).ok_or(Error::NoRoom)?;
                    *w = b;
                    *pos += 1;
                    // Check if line so far matches SSH-2.0-
                    let (s, _) = self.storage.split_at(*pos);
                    if s == SSH_PREFIX {
                        self.st = VersPars::FillSSH(*pos)
                    } else if *pos <= SSH_PREFIX.len() {
                        let (ssh, _) = SSH_PREFIX.split_at(*pos);
                        if ssh != s {
                            self.st = VersPars::Discarding
                        }
                    } else {
                        self.st = VersPars::Discarding
                    }
                }

                VersPars::Discarding => {
                    if b == LF {
                        self.st = VersPars::Start(0);
                        self.num_lines += 1;
                        if self.num_lines > MAX_LINES {
                            return Err(Error::NotSSH);
                        }
                    }
                }

                VersPars::FillSSH(ref mut pos) => match b {
                    CR => {
                        let (s, _) = self.storage.split_at(*pos);
                        if !s.is_ascii() {
                            return Err(Error::msg("bad remote version"));
                        }
                        self.st = VersPars::HaveCR(*pos);
                    }
                    LF => {
                        return Err(Error::msg("bad remote version"));
                    }
                    _ => {
                        let w = self.storage.get_mut(*pos).ok_or(Error::NoRoom)?;
                        *w = b;
                        *pos += 1;
                    }
                },
                VersPars::HaveCR(len) => {
                    match b {
                        LF => self.st = VersPars::Done(len),
                        _ => return Err(Error::msg("bad remote version")),
                    };
                }

                VersPars::Done(_) => {
                    break;
                }
            }
        }
        // Ran out of input
        Ok(taken)
    }
}

#[cfg(test)]
#[rustfmt::skip]
mod tests {
    use crate::ident;
    use crate::error::{Error,TrapBug};
    use crate::doorlog::init_test_log;
    use proptest::prelude::*;

    fn test_version(v: &str, split: usize, expect: &str) -> Result<usize, Error> {
        let mut r = ident::RemoteVersion::new();

        let split = split.min(v.len());
        let (a, b) = v.as_bytes().split_at(split);

        let (taken1, done1) = r.consume(a)?;
        let (taken2, done2) = r.consume(b)?;

        if done1 {
            assert!(done2);
            assert!(taken2 == 0);
        }
        if taken2 > 0 {
            assert_eq!(taken1, a.len());
        }

        let v = core::str::from_utf8(r.version().ok_or(Error::NotSSH)?)?;
        assert_eq!(v, expect);
        Ok(taken1 + taken2)
    }

    #[test]
    /// check round trip of packet enums is right
    fn version() -> Result<(), Error> {
        let long = core::str::from_utf8(&[60u8; 300]).unwrap();
        // split input at various positions
        let splits = [
            (0..40).collect(),
            vec![200,252,253,254,255,256],
        ].concat();
        for &i in splits.iter() {
            test_version("SSH-2.0-@\x0d\x0a", i, "SSH-2.0-@").unwrap();
            test_version("SSH-2.0-good something SSH-2.0-trick\x0d\x0azzz", i, "SSH-2.0-good something SSH-2.0-trick").unwrap();
            test_version("SSH-2.0-@\x0a\x0d", i, "").unwrap_err();
            test_version("SSH-2.0-@\x0a\x0d", i, "").unwrap_err();
            test_version("bleh \x0d\x0aSSH-2.0-@\x0d\x0a", i, "SSH-2.0-@").unwrap();
            assert_eq!(test_version("SSH-2.0-@\x0d\x0amore", i, "SSH-2.0-@").unwrap(), 11);
            assert_eq!(test_version("\x0d\x0aSSH-2.0-@\x0d\x0amore", i, "SSH-2.0-@").unwrap(), 13);
            test_version("\x0d\x0aSSH-2.0bleh \x0d\x0aSSH-2.0-@\x0d\x0a", i, "SSH-2.0-@").unwrap();

            test_version(&long, i, "").unwrap_err();
            test_version(&format!("{long}\x0d\x0aSSH-2.0-works\x0d\x0a"), i, "SSH-2.0-works").unwrap();
            test_version(&format!("{long}    \x0aSSH-2.0-works\x0d\x0a"), i, "SSH-2.0-works").unwrap();
            // a CR by itself is insufficient
            test_version(&format!("{long}     \x0dSSH-2.0-works\x0d\x0a"), i, "").unwrap_err();
        }
        Ok(())
    }

    // // TODO: maybe fuzzing would work better.
    // // also hits an ICE, perhaps
    // // https://github.com/rust-lang/rust/pull/94391
    // proptest! {
    //     #[test]
    //     fn version_pt(prepa: bool, prepb: bool,
    //         mut a: [u8; 20],
    //         mut b: &[u8; 20],
    //         ) {
    //         let mut r = ident::RemoteVersion::new();

    //         // if prepa {
    //         //     a = format!("SSH-2.0-{a}");
    //         // }
    //         // if prepb {
    //         //     b = format!("SSH-2.0-{b}");
    //         // }
    //         // println!("a {a:?}");
    //         // println!("b {b:?}");


    //         let (taken1, done1) = r.consume(&a).unwrap();
    //         let (taken2, done2) = r.consume(&b).unwrap();

    //         if done1 {
    //             assert!(done2);
    //             assert!(taken2 == 0);
    //         }
    //         if taken2 > 0 {
    //             assert_eq!(taken1, a.len());
    //         }

    //         // only allow UTF8 version strings
    //         if let Some(v) = r.version() {
    //             let v = core::str::from_utf8(v).unwrap();
    //             println!("v {v}");
    //         }
    //     }
    // }
}
