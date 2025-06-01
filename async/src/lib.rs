//! Async for Sunset SSH
//!
//! This provides async for Sunset SSH.
#![no_std]
#![forbid(unsafe_code)]
// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod async_channel;
mod async_sunset;
mod client;
mod server;

// TODO: if SSHServer and SSHClient don't specialise much then
// they could share a common implementation. Wait and see
pub use client::SSHClient;
pub use server::SSHServer;

pub use async_channel::{ChanIn, ChanInOut, ChanOut};

pub use async_sunset::{
    io_buf_copy, io_copy, ProgressHolder, SunsetMutex, SunsetRawMutex,
};
pub use async_sunset::{io_buf_copy_noreaderror, io_copy_nowriteerror};
