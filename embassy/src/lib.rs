#![no_std]

#![cfg_attr(feature = "try-polonius", forbid(unsafe_code))]

// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod server;
mod client;
mod embassy_sunset;
mod embassy_channel;

// TODO: if SSHServer and SSHClient don't specialise much then
// they could share a common implementation. Wait and see
pub use server::SSHServer;
pub use client::SSHClient;

pub use embassy_channel::{ChanInOut, ChanIn, ChanOut};

pub use embassy_sunset::{SunsetMutex, SunsetRawMutex, ProgressHolder, io_copy, io_buf_copy};
pub use embassy_sunset::{io_copy_nowriteerror, io_buf_copy_noreaderror};
