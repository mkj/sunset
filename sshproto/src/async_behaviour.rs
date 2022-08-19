// std only, see comments in behaviour.rs
#![cfg(feature = "std")]


#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use async_trait::async_trait;

use crate::{*, conn::RespPackets};
use packets::{ForwardedTcpip,DirectTcpip};
use channel::ChanOpened;
use sshnames::*;
use behaviour::*;

pub(crate) enum AsyncCliServ<'a> {
    Client(&'a mut (dyn AsyncCliBehaviour + Send)),
    Server(&'a mut (dyn AsyncServBehaviour + Send)),
}

impl<'a> AsyncCliServ<'a> {
    pub fn client(&mut self) -> Result<CliBehaviour> {
        let c = match self {
            Self::Client(c) => c,
            _ => Error::bug_msg("Not client")?,
        };
        let c = CliBehaviour {
            inner: *c,
        };
        Ok(c)
    }

    pub fn server(&mut self) -> Result<ServBehaviour> {
        let c = match self {
            Self::Server(c) => c,
            _ => Error::bug_msg("Not server")?,
        };
        let c = ServBehaviour {
            inner: *c,
        };
        Ok(c)
    }
}

// Send+Sync bound here is required for trait objects since there are
// default implementations of some methods.
// https://docs.rs/async-trait/latest/async_trait/index.html#dyn-traits
// #[async_trait(?Send)]
#[async_trait]
pub trait AsyncCliBehaviour: Sync+Send {
    /// Provide the user to use for authentication. Will only be called once
    /// per session.
    /// If the user needs to change a new connection should be made
    /// – servers often have limits on authentication attempts.
    ///
    async fn username(&mut self) -> BhResult<ResponseString>;

    /// Whether to accept a hostkey for the server. The implementation
    /// should compare the key with the key expected for the hostname used.
    async fn valid_hostkey(&mut self, key: &PubKey) -> BhResult<bool>;

    /// Get a password to use for authentication returning `Ok(true)`.
    /// Return `Ok(false)` to skip password authentication
    // TODO: having the hostname and user is useful to build a prompt?
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

    #[allow(unused)]
    fn open_tcp_forwarded(&self, chan: u32, t: &ForwardedTcpip) -> ChanOpened {
        ChanOpened::Failure(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE)
    }

    #[allow(unused)]
    fn open_tcp_direct(&self, chan: u32, t: &DirectTcpip) -> ChanOpened {
        ChanOpened::Failure(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE)
    }
}

// #[async_trait(?Send)]
#[async_trait]
pub trait AsyncServBehaviour: Sync+Send {
    // TODO: load keys on demand?
    // at present `async` isn't very useful here, since it can't load keys
    // on demand. perhaps it should have a callback to get key types,
    // then later request a single key.
    // Also could make it take a closure to call with the key, lets it just
    // be loaded on the stack rather than kept in memory for the whole lifetime.
    async fn hostkeys(&mut self) -> BhResult<&[sign::SignKey]>;

    // TODO: or return a slice of enums
    fn have_auth_password(&self, user: &str) -> bool;
    fn have_auth_pubkey(&self, user: &str) -> bool;


    #[allow(unused)]
    // TODO: change password
    async fn auth_password(&mut self, user: &str, password: &str) -> bool {
        false
    }

    /// Returns true if the pubkey can be used to log in.
    /// TODO: allow returning pubkey restriction options
    #[allow(unused)]
    async fn auth_pubkey(&mut self, user: &str, pubkey: &sign::SignKey) -> bool {
        false
    }

    /// Returns whether a session can be opened
    fn open_session(&mut self, chan: u32) -> channel::ChanOpened;

    #[allow(unused)]
    fn open_tcp_forwarded(&mut self, chan: u32, t: &ForwardedTcpip) -> ChanOpened {
        ChanOpened::Failure(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE)
    }

    #[allow(unused)]
    fn open_tcp_direct(&mut self, chan: u32, t: &DirectTcpip) -> ChanOpened {
        ChanOpened::Failure(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE)
    }

    #[allow(unused)]
    fn sess_req_shell(&mut self, chan: u32) -> bool {
        false
    }

    #[allow(unused)]
    fn sess_req_exec(&mut self, chan: u32, cmd: &str) -> bool {
        false
    }

    #[allow(unused)]
    fn sess_pty(&mut self, chan: u32, pty: &Pty) -> bool {
        false
    }
}
