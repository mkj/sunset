// #![no_std]
#![forbid(unsafe_code)]
// XXX unused_imports only during dev churn
#![allow(unused_imports)]

#[cfg(test)]
#[macro_use]
extern crate std;

pub mod packets;
// XXX decide what is public
pub mod conn;
pub mod encrypt;
pub mod error;
pub mod ident;
pub mod kex;
pub mod test;
pub mod traffic;
pub mod wireformat;
pub mod namelist;
pub mod random;
pub mod sshnames;
pub mod sign;

pub mod client;
pub mod cliauth;

pub mod server;
pub mod servauth;

pub mod doorlog;
