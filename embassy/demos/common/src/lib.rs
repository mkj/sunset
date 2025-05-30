#![cfg_attr(not(test), no_std)]

// avoid warning about Send for the time being
#[allow(async_fn_in_trait)]
mod server;

pub mod config;
pub mod menu;
mod menu_buf;
pub mod takepipe;

pub use config::SSHConfig;
pub use menu_buf::AsyncMenuBuf;
pub use server::{listener, DemoServer, ServerApp};

// needed for derive
use sunset::sshwire;
