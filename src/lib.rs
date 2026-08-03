//! Sunset SSH
//!
//! Sunset is a SSH library for embedded and larger systems. The core `sunset` crate
//! is IO-less, suitable for both async and non-async uses.

// Tests use std as it's easier
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
// avoids headscratching
#![deny(unused_must_use)]
// Static allocations hit this inherently.
#![allow(clippy::large_enum_variant)]
// Nested if statements are often more logical,
// or allow for future additions.
#![allow(clippy::collapsible_if)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod config;
pub mod packets;
pub mod sshnames;
pub mod sshwire;
// exported so that some Channel error variants can be created with .fail().
// perhaps the ones of interest should be exported separately.
pub mod error;
pub mod namelist;

pub mod event;

mod conn;
mod encrypt;
mod ident;
mod kex;
mod random;
mod sign;
mod test;

mod cliauth;
mod client;

mod servauth;
mod server;

mod auth;
mod channel;
mod runner;
mod ssh_chapoly;
mod sunsetlog;
mod termmodes;
mod traffic;

use conn::DispatchEvent;

pub use sshwire::TextString;

pub use auth::AuthSigMsg;
pub use channel::{ChanData, ChanNum, CliSessionExit, CliSessionOpener};
pub use channel::{ChanOpened, Pty, SessionCommand};
pub use error::{Error, Result};
pub use packets::{PubKey, Signature};
pub use sign::{KeyType, OwnedSig, SignKey};
pub use sshnames::ChanFail;

pub use event::{CliEvent, Event, ServEvent};
pub use runner::ChanHandle;
pub use runner::Runner;

pub use client::Client;
pub use conn::CliServ;
pub use server::Server;

// So that sshwire-derive can refer to ::sunset::sshwire
extern crate self as sunset;

#[cfg(feature = "embedded-io")]
pub use embedded_io;

// Re-exports.
// Crypto formats so that applications can handle
// private keys themselves.
pub use ed25519_dalek;

#[cfg(feature = "_ecdsa")]
pub use ecdsa;
#[cfg(feature = "ecdsa256")]
pub use p256;

#[cfg(feature = "rsa")]
pub use rsa;
