#![allow(unused_imports)]

// avoid mysterious missing awaits
#![deny(unused_must_use)]

mod pty;
mod cmdline_client;

#[cfg(unix)]
mod fdio;
#[cfg(unix)]
pub use fdio::{stdin, stdout, stderr_out};

pub use pty::{raw_pty, RawPtyGuard};

pub use cmdline_client::CmdlineClient;
