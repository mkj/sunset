#![no_std]

mod server;
mod client;
mod embassy_sunset;

// TODO: if SSHServer and SSHClient don't specialise much then
// they could share a common implementation. Wait and see
pub use server::SSHServer;
pub use client::SSHClient;
