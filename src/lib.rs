// Tests use std as it's easier
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#![forbid(unsafe_code)]

// avoids headscratching
#![deny(unused_must_use)]

// XXX unused_imports only during dev churn
#![allow(unused_imports)]

#![feature(async_fn_in_trait)]

// XXX decide what is public
pub mod conn;
pub mod encrypt;
pub mod error;
pub mod ident;
pub mod kex;
pub mod test;
pub mod namelist;
pub mod random;
pub mod sshnames;
pub mod sign;

mod client;
mod cliauth;

mod server;
mod servauth;

// mod bhtokio;
// mod bhnostd;

pub mod sunsetlog;
mod auth;
mod channel;
mod runner;
// TODO only public for UnusedCli etc. 
pub mod behaviour;
mod termmodes;
mod ssh_chapoly;
mod traffic;

pub mod packets;
pub mod sshwire;
pub mod config;

// Application API
pub use behaviour::{Behaviour, ServBehaviour, CliBehaviour,
    BhError, BhResult, ResponseString};
pub use sshwire::TextString;

pub use runner::Runner;
pub use sign::{SignKey, KeyType, OwnedSig};
pub use packets::{PubKey, Signature};
pub use error::{Error,Result};
pub use channel::{ChanMsg, ChanMsgDetails, Pty, ChanOpened};
pub use sshnames::ChanFail;
pub use channel::{ChanData, ChanNum};
pub use runner::ChanHandle;
pub use auth::AuthSigMsg;
