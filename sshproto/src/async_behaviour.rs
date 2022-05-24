// std only, see comments in behaviour.rs
#![cfg(feature = "std")]


#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use async_trait::async_trait;
use std::boxed::Box;

use crate::*;
use behaviour::*;

pub(crate) enum AsyncCliServ {
    Client(Box<dyn AsyncCliBehaviour + Send>),
    Server(Box<dyn AsyncServBehaviour + Send>),
}

impl AsyncCliServ {
    pub fn client(&mut self) -> Result<CliBehaviour> {
        let c = match self {
            Self::Client(c) => c,
            _ => Error::bug_msg("Not client")?,
        };
        let c = CliBehaviour {
            inner: c.as_mut(),
            phantom: core::marker::PhantomData::default(),
        };
        Ok(c)
    }

    pub fn server(&mut self) -> Result<ServBehaviour> {
        let c = match self {
            Self::Server(c) => c,
            _ => Error::bug_msg("Not server")?,
        };
        let c = ServBehaviour {
            inner: c.as_mut(),
            phantom: core::marker::PhantomData::default(),
        };
        Ok(c)
    }

    pub(crate) fn progress(&mut self, runner: &mut Runner) -> Result<()> {
        match self {
            Self::Client(i) => i.progress(runner),
            Self::Server(i) => i.progress(runner),
        }
    }
}

#[async_trait(?Send)]
pub trait AsyncCliBehaviour {
    /// Should not block
    fn progress(&mut self, runner: &mut Runner) -> Result<()> { Ok(()) }

    /// Provide the username to use for authentication. Will only be called once
    /// per session.
    /// If the username needs to change a new connection should be made
    /// – servers often have limits on authentication attempts.
    ///
    async fn username(&mut self) -> BhResult<ResponseString>;

    /// Whether to accept a hostkey for the server. The implementation
    /// should compare the key with the key expected for the hostname used.
    async fn valid_hostkey(&mut self, key: &PubKey) -> BhResult<bool>;

    /// Get a password to use for authentication returning `Ok(true)`.
    /// Return `Ok(false)` to skip password authentication
    // TODO: having the hostname and username is useful to build a prompt?
    // or we could provide a full prompt as Args
    #[allow(unused)]
    async fn auth_password(&mut self, pwbuf: &mut ResponseString) -> BhResult<bool> {
        Ok(false)
    }

    /// Get the next private key to authenticate with. Will not be called
    /// again once returning `HookError::Skip`
    /// The default implementation returns `HookError::Skip`
    async fn next_authkey(&mut self) -> BhResult<Option<sign::SignKey>> {
        Ok(None)
    }

    /// Called after authentication has succeeded
    // TODO: perhaps this should be an eventstream not a behaviour?
    async fn authenticated(&mut self);

    /// Show a banner sent from a server. Arguments are provided
    /// by the server so could be hazardous, they should be escaped with
    /// [`banner.escape_default()`](core::str::escape_default) or similar.
    /// Language may be empty, is provided by the server.
    #[allow(unused)]
    async fn show_banner(&self, banner: &str, language: &str) {
        info!("Got banner:\n{}", banner.escape_default());
    }
    // TODO: postauth channel callbacks
}

#[async_trait(?Send)]
pub trait AsyncServBehaviour {
    fn progress(&mut self, runner: &mut Runner) -> Result<()> { Ok(()) }
}
