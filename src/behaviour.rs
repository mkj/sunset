#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::convert::Infallible;

use snafu::prelude::*;

use crate::*;
use packets::{ForwardedTcpip,DirectTcpip};
use channel::ChanOpened;
use sshnames::*;
use sshwire::TextString;

// TODO: "Bh" is an ugly abbreviation. Naming is hard.
// How about SSHApp instead? CliApp, ServApp?

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub type BhResult<T> = core::result::Result<T, BhError>;

/// At present only a single failure type is implemented
#[derive(Debug,Snafu)]
pub enum BhError {
    Fail,
}

/// A stack-allocated string to store responses for usernames or passwords.
///
/// Presently limited to 100 bytes as an arbitrary fixed size.
// TODO this might get replaced with something better
pub type ResponseString = heapless::String<100>;

// TODO: once async functions in traits work with no_std, some of the trait
// methods could become async. Need to decide whether to be Send or not.
//  Tracking Issue for static async fn in traits
// https://github.com/rust-lang/rust/issues/91611
//  And dyn traits
// https://github.com/rust-lang/rust/issues/107011

// TODO: another interim option would to split the async trait methods
// into a separate trait (which impls the non-async trait)

/// Provides either client or server application behaviour
///
/// The actual behaviour is provided by [`CliBehaviour`] or [`ServBehaviour`].
///
/// Applications using sunset-embassy don't need to use this directly,
/// instead passing a CliBehaviour or ServBehaviour.
pub enum Behaviour<'a, C: CliBehaviour, S: ServBehaviour> {
    Client(&'a mut C),
    Server(&'a mut S),
}

impl<'a, C: CliBehaviour> From<&'a mut C> for Behaviour<'a, C, UnusedServ> {
    fn from(b: &'a mut C) -> Self {
        Self::Client(b)
    }
}

impl<'a, S: ServBehaviour> From<&'a mut S> for Behaviour<'a, UnusedCli, S> {
    fn from(b: &'a mut S) -> Self {
        Self::Server(b)
    }
}

impl<'a, C, S> Behaviour<'a, C, S>
    where C: CliBehaviour, S: ServBehaviour
{
    /// Create a new client `Behaviour` instance
    pub fn new_client(b: &'a mut C) -> Behaviour<C, UnusedServ> {
        Behaviour::<C, UnusedServ>::Client(b)
    }

    /// Create a new server `Behaviour` instance
    pub fn new_server(b: &'a mut S) -> Behaviour<UnusedCli, S> {
        Behaviour::<UnusedCli, S>::Server(b)
    }

    /// Calls either client or server
    pub(crate) fn open_tcp_forwarded(&mut self, chan: ChanHandle,
        t: &ForwardedTcpip) -> channel::ChanOpened {
        match self {
            Self::Client(b) => b.open_tcp_forwarded(chan, t),
            Self::Server(b) => b.open_tcp_forwarded(chan, t),
        }
    }

    /// Calls either client or server
    pub(crate) fn open_tcp_direct(&mut self, chan: ChanHandle,
        t: &DirectTcpip) -> channel::ChanOpened {
        match self {
            Self::Client(b) => b.open_tcp_direct(chan, t),
            Self::Server(b) => b.open_tcp_direct(chan, t),
        }
    }

    /// Calls either client or server
    pub(crate) fn disconnected(&mut self, desc: TextString) {
        match self {
            Self::Client(b) => b.disconnected(desc),
            Self::Server(b) => b.disconnected(desc),
        }
    }

    pub(crate) fn is_client(&self) -> bool {
        matches!(self, Self::Client(_))
    }

    pub(crate) fn client(&mut self) -> Result<&mut C> {
        match self {
            Self::Client(c) => Ok(*c),
            _ => error::PacketWrong.fail()
        }
    }

    pub(crate) fn server(&mut self) -> Result<&mut S> {
        match self {
            Self::Server(c) => Ok(*c),
            _ => error::PacketWrong.fail(),
        }
    }
}

/// Defines application behaviour as a client
///
/// The trait methods are called by the Sunset runner during the connection. Some
/// methods request information, such as [`username()`][Self::username]. Other
/// methods inform of events that have occurred, such as [`session_opened()`][Self::session_opened]
/// or [`disconnected()`][Self::disconnected].
///
/// When running async with `sunset-embassy`, the `CliBehaviour` will be passed inside
/// a `SunsetMutex` to allow external mutability if needed.
pub trait CliBehaviour {
    /// Provide the user to use for authentication. Will only be called once
    /// per session.
    ///
    /// If the user needs to change a new connection should be made
    /// – servers often have limits on authentication attempts.
    ///
    fn username(&mut self) -> BhResult<ResponseString>;

    /// Whether to accept a hostkey for the server. The implementation
    /// should compare the key with the key expected for the hostname used.
    fn valid_hostkey(&mut self, key: &PubKey) -> BhResult<bool>;

    /// Get a password to use for authentication returning `Ok(true)`.
    /// Return `Ok(false)` to skip password authentication
    // TODO: having the hostname and user is useful to build a prompt?
    // or we could provide a full prompt as Args
    #[allow(unused)]
    fn auth_password(&mut self, pwbuf: &mut ResponseString) -> BhResult<bool> {
        Ok(false)
    }

    /// Get the next private key used to attempt authentication.
    ///
    /// Will not be called again once returning `None`.
    /// The default implementation returns `None`.
    fn next_authkey(&mut self) -> BhResult<Option<sign::SignKey>> {
        Ok(None)
    }

    /// Sign an authentication request with a key held externally
    /// (most likely in an SSH agent).
    ///
    /// `key` is a key previously returned from `next_authkey()`,
    /// it will be one of the `Agent...` variants.
    ///
    /// The client can call [`msg.enc()`](crate::sshwire::SSHEncode::enc()) to obtain the
    /// message to use for agent signing.
    #[allow(unused)]
    async fn agent_sign(&mut self, key: &sign::SignKey, msg: &AuthSigMsg<'_>) -> BhResult<sign::OwnedSig> {
        Err(BhError::Fail)
    }

    /// Called after authentication has succeeded
    // TODO: perhaps this should be an eventstream not a behaviour?
    fn authenticated(&mut self);

    /// Provides the disconnect message sent by a server
    ///
    /// Note that this may not be called in cases where the SSH TCP connection
    /// is simply closed.
    #[allow(unused)]
    fn disconnected(&mut self, desc: TextString) {
    }

    /// Show a banner sent from a server. Arguments are provided
    /// by the server so could be hazardous, `banner` should be escaped with
    /// [`str::escape_default()`](str::escape_default) or similar.
    /// Language may be empty, is provided by the server.

    // This is a `Behaviour` method rather than an [`Event`] because
    // it must be displayed prior to other authentication
    // functions. `Events` may be handled asynchronously so wouldn't
    // guarantee that.
    #[allow(unused)]
    fn show_banner(&mut self, banner: TextString, language: TextString) {
    }
    // TODO: postauth channel callbacks

    #[allow(unused)]
    async fn session_opened(&mut self, chan: ChanNum, opener: &mut SessionOpener<'_, '_, '_>) -> BhResult<()> {
        Err(BhError::Fail)
    }

    #[allow(unused)]
    fn open_tcp_forwarded(&mut self, chan: ChanHandle, t: &ForwardedTcpip) -> ChanOpened {
        ChanOpened::Failure((ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE, chan))
    }

    #[allow(unused)]
    fn open_tcp_direct(&mut self, chan: ChanHandle, t: &DirectTcpip) -> ChanOpened {
        ChanOpened::Failure((ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE, chan))
    }
}

/// Defines application behaviour as a server
///
/// The trait methods are called by the Sunset runner during the connection. The response
/// from these methods changes how the connection is handled, for example whether to allow authentication
/// or opening a channel.
///
/// Channel requests also provide a [`ChanHandle`] argument which can be passed to IO methods
/// to read/write data.
///
/// When running async with `sunset-embassy`, the `ServBehaviour` will be passed inside
/// a `SunsetMutex` to allow external mutability if needed.
pub trait ServBehaviour {
    // TODO: load keys on demand?
    // at present `async` isn't very useful here, since it can't load keys
    // on demand. perhaps it should have a callback to get key types,
    // then later request a single key.
    // Also could make it take a closure to call with the key, lets it just
    // be loaded on the stack rather than kept in memory for the whole lifetime.
    // TODO: a slice of references is a bit awkward?

    /// Requests hostkeys for the server
    fn hostkeys(&mut self) -> BhResult<heapless::Vec<&SignKey, 2>>;

    #[allow(unused)]
    // TODO: or return a slice of enums
    /// Queries whether password authentication should be allowed
    ///
    /// Implementations should take care to avoid leaking user existence
    /// based on timing.
    fn have_auth_password(&self, username: TextString) -> bool {
        false
    }

    #[allow(unused)]
    /// Queries whether pubkey authentication should be allowed
    ///
    /// Implementations should take care to avoid leaking user existence
    /// based on timing.
    fn have_auth_pubkey(&self, username: TextString) -> bool {
        false
    }

    #[allow(unused)]
    /// Return true to allow the user to log in with no authentication
    ///
    /// This obviously has security implications.
    ///
    /// Implementations may need to take care to avoid leaking user existence
    /// based on timing.
    async fn auth_unchallenged(&mut self, username: TextString<'_>) -> bool {
        false
    }

    #[allow(unused)]
    // TODO: change password
    /// Test if a password is valid.
    ///
    /// Implementations should store passwords hashed, and perform password hash comparisons
    /// in constant time, using [`subtle::ConstantTimeEq`] or similar.
    ///
    /// Implementations may need to take care to avoid leaking user existence
    /// based on timing.
    async fn auth_password(&mut self, username: TextString<'_>, password: TextString<'_>) -> bool {
        false
    }

    /// Returns true if the pubkey can be used to log in.
    ///
    /// TODO: allow returning pubkey restriction options
    ///
    /// Implementations may need to take care to avoid leaking user existence
    /// based on timing.
    #[allow(unused)]
    async fn auth_pubkey(&mut self, username: TextString<'_>, pubkey: &PubKey<'_>) -> bool {
        false
    }

    /// Returns whether a session (shell or command) can be opened
    fn open_session(&mut self, chan: ChanHandle) -> channel::ChanOpened;

    #[allow(unused)]
    fn open_tcp_forwarded(&mut self, chan: ChanHandle, t: &ForwardedTcpip) -> ChanOpened {
        ChanOpened::Failure((ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE, chan))
    }

    #[allow(unused)]
    fn open_tcp_direct(&mut self, chan: ChanHandle, t: &DirectTcpip) -> ChanOpened {
        ChanOpened::Failure((ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE, chan))
    }

    /// Called when a shell is requested, returns a boolean request success status
    #[allow(unused)]
    fn sess_shell(&mut self, chan: ChanNum) -> bool {
        false
    }

    /// Called when a command execution is requested, returns a boolean request success status
    #[allow(unused)]
    fn sess_exec(&mut self, chan: ChanNum, cmd: TextString) -> bool {
        false
    }

    /// Called when a PTY (interactive terminal) is requested, returns a boolean request success status
    #[allow(unused)]
    fn sess_pty(&mut self, chan: ChanNum, pty: &Pty) -> bool {
        false
    }

    /// Provides the disconnect message sent by a client
    ///
    /// Note that this may not be called in cases where the SSH TCP connection
    /// is simply closed.
    #[allow(unused)]
    fn disconnected(&mut self, desc: TextString) {
    }
}

// Placeholders that will not be instantiated
// For some reason these need to be public because they leak
// from the async call to EmbassySunset::run() ?
#[doc(hidden)]
pub struct UnusedCli(Infallible);
impl CliBehaviour for UnusedCli {
    fn username(&mut self) -> BhResult<ResponseString> {
        unreachable!()
    }
    fn valid_hostkey(&mut self, _key: &PubKey) -> BhResult<bool> {
        unreachable!()
    }
    fn authenticated(&mut self) {
        unreachable!()
    }
}

#[doc(hidden)]
pub struct UnusedServ(Infallible);
impl ServBehaviour for UnusedServ {
    fn hostkeys(&mut self) -> BhResult<heapless::Vec<&SignKey, 2>> {
        unreachable!()
    }
    fn open_session(&mut self, _chan: ChanHandle) -> channel::ChanOpened {
        unreachable!()
    }
}
