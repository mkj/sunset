#![no_std]

#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
// #![allow(incomplete_features)]

mod config;
mod server;

pub mod demo_menu;

pub use server::{Shell, listener};
pub use config::SSHConfig;
