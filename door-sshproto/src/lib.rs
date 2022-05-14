#![no_std]
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

mod client;
mod cliauth;

mod server;
mod servauth;

pub mod doorlog;
mod channel;
mod config;
mod runner;
mod hooks;

pub use client::Client;
pub use client::ResponseString;
pub use client::ClientHooks;
pub use hooks::{HookError, HookResult};
pub use runner::Runner;
pub use conn::Conn;
pub use packets::PubKey;
pub use error::Error;
