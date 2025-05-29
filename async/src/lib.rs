#![allow(unused_imports)]
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
use sunset::sshwire;
