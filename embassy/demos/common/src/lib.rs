#![cfg_attr(not(any(feature = "std", test)), no_std)]

#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
// #![allow(incomplete_features)]

mod server;

pub mod config;
pub mod menu;
pub mod demo_menu;

pub use server::{Shell, listener};
pub use config::SSHConfig;
pub use demo_menu::BufOutput;

// needed for derive
use sunset::sshwire;
