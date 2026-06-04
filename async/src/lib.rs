//! Async for [Sunset SSH](sunset)
//!
//! [`SSHClient`] and [`SSHServer`] provide async-executor agnostic SSH
//! implementations. These can be used on full-sized async platforms
//! (Tokio, smol, etc) as well as on `no_std` embedded platforms such as
//! [`embassy-executor`](https://docs.rs/embassy-executor).
//!
//! On std platforms some higher level functionality is in
//! `sunset-stdasync` crate.
//! [`embedded-io-adapters`](https://docs.rs/embedded-io-adapters)
//! can be used for `Read` or `Write` traits with different async runtimes.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod async_channel;
mod async_sunset;
mod client;
mod server;

pub use client::SSHClient;
pub use server::SSHServer;

pub use async_channel::{ChanIn, ChanInOut, ChanOut};

pub use async_sunset::{ProgressHolder, SunsetMutex, SunsetRawMutex};
