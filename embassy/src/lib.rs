#![no_std]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#![forbid(unsafe_code)]

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

pub use embassy_sunset::{SunsetMutex, SunsetRawMutex, io_copy, io_buf_copy};
