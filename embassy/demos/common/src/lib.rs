#![cfg_attr(not(any(feature = "std", test)), no_std)]

// avoid warning about Send for the time being
#[allow(async_fn_in_trait)]
mod server;

pub mod config;
pub mod demo_menu;
pub mod menu;
pub mod takepipe;

pub use config::SSHConfig;
pub use demo_menu::BufOutput;
pub use server::{listener, DemoServer, ServerApp};

// needed for derive
use sunset::sshwire;
