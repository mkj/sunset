// Tests use std as it's easier
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#![forbid(unsafe_code)]

// avoids headscratching
#![deny(unused_must_use)]

// for the time being silence the lint. need to figure if we actually
// want to work with Send (not needed for embassy)
#![allow(async_fn_in_trait)]

// XXX unused_imports only during dev churn
#![allow(unused_imports)]

pub mod sshwire;
pub mod packets;
pub mod sshnames;
pub mod config;
// exported so that some Channel error variants can be created with .fail().
// perhaps the ones of interest should be expored separately.
pub mod error;
// perhaps don't need this, users could just use getrandom?
pub mod random;

pub mod event;

mod conn;
mod encrypt;
mod ident;
mod kex;
mod test;
mod namelist;
mod sign;

mod client;
mod cliauth;

mod server;
mod servauth;

mod sunsetlog;
mod auth;
mod channel;
mod runner;
mod termmodes;
mod ssh_chapoly;
mod traffic;

use conn::DispatchEvent;
use event::{CliEventId, ServEventId};

// Application API
pub use sshwire::TextString;

pub use sign::{SignKey, KeyType, OwnedSig};
pub use packets::{PubKey, Signature};
pub use error::{Error,Result};
pub use channel::{Pty, ChanOpened, SessionCommand};
pub use sshnames::ChanFail;
pub use channel::{ChanData, ChanNum, CliSessionExit};
pub use auth::AuthSigMsg;

pub use runner::Runner;
pub use runner::ChanHandle;
pub use event::{Event, CliEvent, ServEvent};
