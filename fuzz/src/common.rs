#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::io::ErrorKind;
use std::panic::RefUnwindSafe;
use std::path::Path;

use sshwire::BinString;
use sunset::*;

use sunset_sshwire_derive::*;

#[derive(SSHEncode)]
pub struct FuzzInput<'p> {
    pub data: BinString<'p>,
    pub control: BinString<'p>,
}

impl<'de, 'p> ::sunset::sshwire::SSHDecode<'de> for FuzzInput<'p>
where
    'de: 'p,
{
    fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
        s: &mut S,
    ) -> ::sunset::sshwire::WireResult<Self> {
        let field_data: BinString = ::sunset::sshwire::SSHDecode::dec(s)?;
        println!("fd {field_data:?}");
        let field_control: BinString = ::sunset::sshwire::SSHDecode::dec(s)?;
        println!("fc {field_control:?}");
        Ok(Self { data: field_data, control: field_control })
    }
}

impl<'p> FuzzInput<'p> {
    const MIN_DATA: usize = 2000;
    const MIN_CONTROL: usize = 2000;

    pub fn new(input: &'p [u8]) -> Result<Self> {
        let input = sshwire::read_ssh::<FuzzInput>(input, None)?;
        if input.data.0.len() < Self::MIN_DATA {
            println!("mindata {}", input.data.0.len());
            return error::RanOut.fail();
        }
        if input.control.0.len() < Self::MIN_CONTROL {
            println!("mincontrol");
            return error::RanOut.fail();
        }
        Ok(input)
    }

    pub fn from_parts(data: &'p [u8], control: &'p [u8]) -> Self {
        Self { data: BinString(data), control: BinString(control) }
    }

    pub fn done_data(&mut self, len: usize) {
        let (_, d) = self.data.0.split_at(len);
        self.data.0 = d;
    }

    pub fn control_u32(&mut self) -> Result<u32> {
        self.control
            .0
            .split_at_checked(core::mem::size_of::<u32>())
            .map(|(v, rest)| {
                let val = u32::from_be_bytes(v.try_into().unwrap());
                self.control.0 = rest;
                val
            })
            .ok_or(error::RanOut.build())
    }

    /// Returns `Err` when input runs out.
    pub fn chance(&mut self, chance: f32) -> Result<bool> {
        self.control_u32().map(|v| (v as f32 / u32::MAX as f32) < chance)
    }
}

fn each_arg<F>(f: F)
where
    F: Fn(&Path, &[u8]),
{
    for arg in std::env::args().skip(1) {
        let mut paths = vec![];
        match std::fs::read_dir(&arg) {
            Ok(dir) => {
                for ent in dir {
                    match &ent {
                        Ok(e) => {
                            paths.push(e.path());
                        }
                        Err(e) => warn!("Problem with {ent:?}: {e:?}"),
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotADirectory => {
                paths.push(arg.into());
            }
            Err(e) => warn!("Bad path {arg:?}: {e:?}"),
        }
        for s in paths {
            let data = match std::fs::read(&s) {
                Ok(data) => data,
                Err(e) if e.kind() == ErrorKind::IsADirectory => continue,
                Err(e) => {
                    warn!("Failed {s:?}: {e:?}");
                    continue;
                }
            };
            f(&s, &data);
        }
    }
}

fn check_error(r: Result<()>) {
    if let Err(e) = r {
        match e {
            // Errors that should not occur.
            // May indicate a bug in this fuzz harness.
            Error::BadChannel { .. }
            | Error::BadChannelData
            | Error::BadUsage { .. }
            | Error::Custom { .. }
            | Error::Bug => panic!("Unexpected error {e:#?}"),
            _ => (),
        }
    }
}

pub fn run_main<F, CTX>(ctx: &CTX, run: F)
where
    // afl uses catch_unwind so needs unwindsafe
    F: Fn(Option<&Path>, &CTX, &[u8]) -> Result<()> + RefUnwindSafe,
    CTX: RefUnwindSafe,
{
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    )
    .init();

    #[cfg(feature = "honggfuzz")]
    {
        loop {
            honggfuzz::fuzz!(|data: &[u8]| {
                let e = run(None, ctx, data);
                check_error(e);
            })
        }
    }

    #[cfg(feature = "afl")]
    {
        afl::fuzz!(|data: &[u8]| {
            let e = run(None, ctx, data);
            check_error(e);
        });
    }

    #[cfg(feature = "nofuzz")]
    {
        each_arg(|filename, data| {
            info!("running {filename:?}");
            match run(Some(filename), ctx, data) {
                Err(Error::AlgoNoMatch { algo }) => {
                    error!("{filename:?} No Algo match {algo:?}")
                }
                Err(e) => {
                    warn!("Exited with error: {e:#?}");
                    check_error(Err(e));
                }
                Ok(_) => panic!("Finished somehow"),
            }
        });
    }
}

mod test {

    #[test]
    fn test_inp() {
        let a = [4u8; 0x800];
        let x = FuzzInput { data: BinString(&a), control: BinString(&a) };
        let mut v = vec![];
        sshwire::ssh_push_vec(&mut v, &x).unwrap();
        println!("v {v:#02x?}");

        let x2 = FuzzInput::new(&v).unwrap();
    }
}
