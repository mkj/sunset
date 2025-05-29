#![no_std]
#![cfg_attr(feature = "try-polonius", forbid(unsafe_code))]
// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod client;
mod embassy_channel;
mod embassy_sunset;
mod server;

// TODO: if SSHServer and SSHClient don't specialise much then
// they could share a common implementation. Wait and see
pub use client::SSHClient;
pub use server::SSHServer;

pub use embassy_channel::{ChanIn, ChanInOut, ChanOut};

pub use embassy_sunset::{
    io_buf_copy, io_copy, ProgressHolder, SunsetMutex, SunsetRawMutex,
};
pub use embassy_sunset::{io_buf_copy_noreaderror, io_copy_nowriteerror};
