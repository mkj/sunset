// Tests use std as it's easier
// The "std" feature at present uses Box for async fn in traits,
// though that may change later and the 'feature = "std" predicate
// won't be needed.
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#![forbid(unsafe_code)]

// XXX unused_imports only during dev churn
#![allow(unused_imports)]

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
mod mailbox;

// mod bhtokio;
// mod bhnostd;

pub mod doorlog;
mod channel;
mod config;
mod runner;
mod behaviour;
mod async_behaviour;
mod termmodes;

pub use behaviour::{Behaviour, BhError, BhResult, ResponseString};
pub use async_behaviour::{AsyncCliBehaviour,AsyncServBehaviour};

pub use client::Client;
pub use runner::Runner;
pub use conn::Conn;
pub use packets::PubKey;
pub use error::Error;
pub use mailbox::{Mailbox,MailboxFut};
