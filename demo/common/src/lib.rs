#![cfg_attr(not(test), no_std)]

// avoid warning about Send for the time being
#[allow(async_fn_in_trait)]
mod server;

pub mod config;
mod copyloop;
pub mod menu;
mod menu_buf;
pub mod takepipe;

pub use config::SSHConfig;
pub use menu_buf::AsyncMenuBuf;
pub use server::{DemoCommon, DemoServer, listen};

pub use copyloop::{
    io_buf_copy, io_buf_copy_noreaderror, io_copy, io_copy_nowriteerror,
};
