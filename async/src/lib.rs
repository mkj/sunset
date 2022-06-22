#![forbid(unsafe_code)]
#![allow(unused_imports)]

mod client;
mod async_door;
mod simple_client;

pub use async_door::AsyncDoor;
pub use client::SSHClient;
pub use simple_client::SimpleClient;

#[cfg(unix)]
mod fdio;
#[cfg(unix)]
pub use fdio::{stdin, stdout, stderr};
