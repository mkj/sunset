// std only, see comments in behaviour.rs
#![cfg(feature = "std")]


#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use async_trait::async_trait;
use std::boxed::Box;

use crate::{*, conn::RespPackets};
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

    pub(crate) async fn chan_handler(&mut self, resp: &mut RespPackets<'_>, chan_msg: ChanMsg) -> Result<()> {
        match self {
            Self::Client(i) => i.chan_handler(resp, chan_msg).await,
            Self::Server(i) => i.chan_handler(resp, chan_msg),
        }
    }
}

// Send+Sync bound here is required for trait objects since there are
// default implementations of some methods.
// https://docs.rs/async-trait/latest/async_trait/index.html#dyn-traits
// #[async_trait(?Send)]
#[async_trait]
pub trait AsyncCliBehaviour: Sync+Send {
    async fn chan_handler(&mut self, resp: &mut RespPackets, chan_msg: ChanMsg) -> Result<()>;

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

    /// This is a `Behaviour` method rather than an [`Event`] because
    /// it must be displayed prior to other authentication
    /// functions. `Events` may be handled asynchronously so wouldn't
    /// guarantee that.
    #[allow(unused)]
    async fn show_banner(&self, banner: &str, language: &str) {
        info!("Got banner:\n{:?}", banner.escape_default());
    }
    // TODO: postauth channel callbacks
}

// #[async_trait(?Send)]
#[async_trait]
pub trait AsyncServBehaviour: Sync+Send {
    fn progress(&mut self, runner: &mut Runner) -> Result<()> { Ok(()) }

    fn chan_handler(&mut self, resp: &mut RespPackets, chan_msg: ChanMsg) -> Result<()>;
}
