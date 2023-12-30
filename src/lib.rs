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
// exported so that UnusedCli can be used
mod behaviour;
// exported so that some Channel error variants can be created with .fail().
// perhaps the ones of interest should be expored separately.
pub mod error;
// perhaps don't need this, users could just use getrandom?
pub mod random;

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
mod noasync;


// Application API
pub use behaviour::{Behaviour, ServBehaviour, CliBehaviour,
    BhError, BhResult, ResponseString};
pub use sshwire::TextString;

pub use runner::Runner;
pub use sign::{SignKey, KeyType, OwnedSig};
pub use packets::{PubKey, Signature};
pub use error::{Error,Result};
pub use channel::{Pty, ChanOpened, SessionOpener, SessionCommand};
pub use sshnames::ChanFail;
pub use channel::{ChanData, ChanNum};
pub use runner::ChanHandle;
pub use auth::AuthSigMsg;
pub use noasync::non_async;
