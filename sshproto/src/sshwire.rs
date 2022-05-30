#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};


pub trait SSHSink {
    fn push(&mut self, v: &[u8]) -> Result<()>;
}

pub trait SSHSource<'de> {
    fn take(&mut self, len: usize) -> Result<&'de [u8]>;
}

pub trait SSHEncode {
    fn enc<S>(&self, e: &mut S) -> Result<()> where S: SSHSink;
}

impl SSHEncode for u8 {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        e.push(&[*self])
    }
}

impl SSHEncode for bool {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        (*self as u8).enc(e)
    }
}

impl SSHEncode for u32 {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        e.push(&self.to_be_bytes())
    }
}

// no length prefix
impl SSHEncode for &[u8] {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        // data
        e.push(&self)
    }
}

// no length prefix
impl<const N: usize> SSHEncode for [u8; N] {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        e.push(self)
    }
}

impl SSHEncode for &str {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        let v = self.as_bytes();
        // length prefix
        (v.len() as u32).enc(e)?;
        e.push(v)
    }
}

impl<T: SSHEncode> SSHEncode for Option<T> {
    fn enc<S>(&self, e: &mut S) -> Result<()>
    where S: SSHSink {
        if let Some(t) = self.as_ref() {
            t.enc(e)?;
        }
        Ok(())
    }
}
