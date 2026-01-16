//! Sunset SSH for larger systems
//!
//! `sunset-std` is for Sunset SSH on non-embedded systems,
//! using async executors such as smol or tokio.
//!
//! [`AgentClient`] can communicate with a separate `ssh-agent` for signing.
//!
//! `sunsetc` example is usable as a day-to-day SSH client on Linux.
// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod agent;
mod cmdline_client;
pub mod knownhosts;
mod pty;

#[cfg(unix)]
mod fdio;
#[cfg(unix)]
use fdio::{stderr_out, stdin, stdout};

use pty::{raw_pty, RawPtyGuard};

pub use cmdline_client::CmdlineClient;

pub use agent::AgentClient;

// for sshwire derive
