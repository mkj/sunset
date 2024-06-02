/// Events used by applications running the SSH connection
///
/// These include hostkeys, authentication, and shell/command sessions

use self::{channel::Channel, packets::{AuthMethod, MethodPubKey, UserauthRequest}};

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::mem::Discriminant;
use core::fmt::Debug;

use crate::*;
use sshwire::TextString;
use packets::Packet;
use channel::{CliSessionOpener, CliSessionExit};

#[derive(Debug)]
pub enum Event<'g, 'a> {
    Cli(CliEvent<'g, 'a>),
    Serv(ServEvent<'g, 'a>),

    /// Connection state has progressed
    ///
    /// Should poll `Runner::progress()` again
    Progressed,

    /// No event
    ///
    /// No progress, may idle waiting for external events.
    None,
}

impl<'g, 'a> Event<'g, 'a> {
    pub(crate) fn from_dispatch(disp: DispatchEvent, runner: &'g mut Runner<'a>) -> Result<Self> {
        match disp {
            DispatchEvent::CliEvent(x) => Ok(Self::Cli(x.event(runner)?)),
            DispatchEvent::ServEvent(x) => Ok(Self::Serv(x.event(runner)?)),
            DispatchEvent::None => Ok(Self::None),
            | DispatchEvent::Progressed  => Ok(Self::Progressed),
            // Events handled internally by Runner::progress()
            | DispatchEvent::Data(_)
            => Err(Error::bug()),
        }
    }
}

pub enum CliEvent<'g, 'a>
{
    Hostkey(CheckHostkey<'g, 'a>),
    Username(RequestUsername<'g, 'a>),
    Password(RequestPassword<'g, 'a>),
    Authenticated,
    SessionOpened(CliSessionOpener<'g, 'a>),
    /// Remote process exited
    SessionExit(CliSessionExit<'g>),

    /// The SSH connection is no longer running
    Defunct,

    // ChanRequest(ChanRequest<'g, 'a>),
    // Banner { banner: TextString<'a>, language: TextString<'a> },
}

impl Debug for CliEvent<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let e = match self {
            Self::Hostkey(_) => "Hostkey",
            Self::Username(_) => "Username",
            Self::Password(_) => "Password",
            Self::Authenticated => "Authenticated",
            Self::SessionOpened(_) => "SessionOpened",
            Self::SessionExit(_) => "SessionExit",
            Self::Defunct => "Defunct",
        };
        write!(f, "CliEvent({e})")
    }
}

pub struct RequestUsername<'g, 'a> {
    runner: &'g mut Runner<'a>,
}

impl RequestUsername<'_, '_> {
    pub fn respond(self, username: impl AsRef<str>) -> Result<()> {
        self.runner.resume_cliusername(username.as_ref())
    }
}

pub struct RequestPassword<'g, 'a> {
    runner: &'g mut Runner<'a>,
}

impl RequestPassword<'_, '_> {
    pub fn password(self, password: impl AsRef<str>) -> Result<()> {
        self.runner.resume_clipassword(password.as_ref())
    }
}

pub struct CheckHostkey<'g, 'a> {
    runner: &'g mut Runner<'a>,
}

impl CheckHostkey<'_, '_> {
    pub fn hostkey(&self) -> Result<PubKey> {
        self.runner.fetch_checkhostkey()
    }

    pub fn accept(self) -> Result<()> {
        self.runner.resume_checkhostkey(true)
    }

    pub fn reject(self) -> Result<()> {
        self.runner.resume_checkhostkey(false)
    }
}

// impl CliExit<''_, '_> {
//     pub fn 

// }

#[derive(Debug, Clone, Copy)]
pub(crate) enum CliEventId {
    Hostkey,
    Username,
    Password,
    Authenticated,
    SessionOpened(ChanNum),
    SessionExit,
    Defunct

    // TODO:
    // Disconnected
    // Banner,
    // AuthPubkey
    // AgentSign
    // OpenTCPForwarded (new session)
    // TCPDirectOpened (response)
}

impl CliEventId {
    pub fn event<'g, 'a>(self, runner: &'g mut Runner<'a>) -> Result<CliEvent<'g, 'a>> {
        let pk = runner.packet()?;

        match self {
            Self::Username => {
                Ok(CliEvent::Username(RequestUsername { runner }))
            }
            Self::Password => {
                Ok(CliEvent::Password(RequestPassword { runner }))
            }
            Self::Hostkey => {
                debug_assert!(matches!(pk, Some(Packet::KexDHReply(_))));
                Ok(CliEvent::Hostkey(CheckHostkey { runner }))
            }
            Self::Authenticated => Ok(CliEvent::Authenticated),
            Self::SessionOpened(h) => {
                Ok(CliEvent::SessionOpened(runner.cli_session_opener(h)?))
            }
            // (Self::Banner, Packet::UserauthBanner(p)) => {
            //     CliEvent::Banner { banner: p.message, language: p.lang }
            // }
            Self::SessionExit => {
                Ok(CliEvent::SessionExit(runner.fetch_cli_session_exit()?))
            }
            Self::Defunct => error::BadUsage.fail()
        }
    }

    // Whether the event must have called an appropriate `resume_` method.
    // Used for internal correctness checks.
    pub(crate) fn needs_resume(&self) -> bool {
        match self {
            | Self::Authenticated
            | Self::SessionOpened(_)
            | Self::SessionExit
            | Self::Defunct
            => false,
            | Self::Hostkey
            | Self::Username
            | Self::Password
            => true,
        }
    }
}

pub enum ServEvent<'g, 'a> {
    Hostkeys(ServHostkeys<'g, 'a>),
    PasswordAuth(ServPasswordAuth<'g, 'a>),
    PubkeyAuth(ServPubkeyAuth<'g, 'a>),
    FirstAuth(ServFirstAuth<'g, 'a>),
    OpenSession(ServOpenSession<'g, 'a>),
    SessionShell(ChanRequest<'g, 'a>),
    SessionExec(ChanRequest<'g, 'a>),
    SessionPty(ChanRequest<'g, 'a>),
    /// The SSH session is no longer running
    Defunct,
}

impl Debug for ServEvent<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let e = match self {
            Self::Hostkeys(_) => "Hostkeys",
            Self::PasswordAuth(_) => "PasswordAuth",
            Self::PubkeyAuth(_) => "PubkeyAuth",
            Self::FirstAuth(_) => "FirstAuth",
            Self::OpenSession(_) => "OpenSession",
            Self::SessionShell(_) => "SessionShell",
            Self::SessionExec(_) => "SessionExec",
            Self::SessionPty(_) => "SessionPty",
            Self::Defunct => "Defunct",
        };
        write!(f, "ServEvent({e})")
    }
}

pub struct ServHostkeys<'g, 'a> {
    runner: &'g mut Runner<'a>,
}

impl<'g, 'a> ServHostkeys<'g, 'a> {
    pub fn hostkeys(self, keys: &[&SignKey]) -> Result<()> {
        self.runner.resume_servhostkeys(keys)
    }
}

pub struct ServPasswordAuth<'g, 'a> {
    runner: &'g mut Runner<'a>,
    done: bool,
}

impl<'g, 'a> ServPasswordAuth<'g, 'a> {
    fn new(runner: &'g mut Runner<'a>) -> Self {
        Self {
            runner,
            done: false,
        }
    }

    pub fn username(&self) -> Result<&str> {
        self.raw_username()?.as_str()
    }

    pub fn password(&self) -> Result<&str> {
        self.raw_password()?.as_str()
    }

    pub fn allow(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_servauth(true)
    }

    /// Does not need to be called explicitly, also occurs on drop without `allow()`
    pub fn deny(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_servauth(false)
    }

    pub fn raw_username(&self) -> Result<TextString> {
        self.runner.fetch_servusername()
    }

    pub fn raw_password(&self) -> Result<TextString> {
        self.runner.fetch_servpassword()
    }
}

// implement Drop to be the same as .deny()
impl Drop for ServPasswordAuth<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.runner.resume_servauth(false) {
                trace!("Error for pw auth: {e}")
            }
        }
    }
}

pub struct ServPubkeyAuth<'g, 'a> {
    runner: &'g mut Runner<'a>,
    done: bool,
    // Indicates whether this was a real auth request (signature already
    // verified) or a query for public key suitability.
    real_sig: bool,
}

impl<'g, 'a> ServPubkeyAuth<'g, 'a> {
    fn new(runner: &'g mut Runner<'a>, real_sig: bool) -> Self {
        Self {
            runner,
            done: false,
            real_sig
        }
    }

    pub fn username(&self) -> Result<&str> {
        self.raw_username()?.as_str()
    }

    pub fn pubkey(&self) -> Result<PubKey> {
        self.runner.fetch_servpubkey()
    }

    pub fn allow(mut self) -> Result<()> {
        self.done = true;
        if self.real_sig {
            self.runner.resume_servauth(true)
        } else {
            self.runner.resume_servauth_pkok()
        }
    }

    /// Does not need to be called explicitly, also occurs on drop without `allow()`
    pub fn deny(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_servauth(false)
    }

    pub fn raw_username(&self) -> Result<TextString> {
        self.runner.fetch_servusername()
    }
}

// implement Drop to be the same as .deny()
impl Drop for ServPubkeyAuth<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.runner.resume_servauth(false) {
                trace!("Error for pw auth: {e}")
            }
        }
    }
}

pub struct ServFirstAuth<'g, 'a> {
    runner: &'g mut Runner<'a>,
    done: bool,
}

impl<'g, 'a> ServFirstAuth<'g, 'a> {
    fn new(runner: &'g mut Runner<'a>) -> Self {
        Self {
            runner,
            done: false,
        }
    }
    pub fn username(&self) -> Result<&str> {
        self.raw_username()?.as_str()
    }

    pub fn allow(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_servauth(true)
    }

    /// Does not need to be called explicitly, also occurs on drop without `allow()`
    pub fn deny(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_servauth(false)
    }

    pub fn raw_username(&self) -> Result<TextString> {
        self.runner.fetch_servusername()
    }
}

// implement Drop to be the same as .deny()
impl Drop for ServFirstAuth<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.runner.resume_servauth(false) {
                trace!("Error for first auth: {e}")
            }
        }
    }
}


pub struct ServOpenSession<'g, 'a> {
    runner: &'g mut Runner<'a>,
    done: bool,
    ch: ChanNum,
}

impl<'g, 'a> ServOpenSession<'g, 'a> {
    fn new(runner: &'g mut Runner<'a>, ch: ChanNum) -> Self {
        Self {
            runner,
            done: false,
            ch,
        }
    }
    pub fn accept(mut self) -> Result<ChanHandle> {
        self.done = true;
        self.runner.resume_chanopen(self.ch, None)?;
        Ok(ChanHandle(self.ch))
    }

    /// Does not need to be called explicitly, also occurs on drop without `accept()`
    pub fn reject(mut self, reason: ChanFail) -> Result<()> {
        self.done = true;
        self.runner.resume_chanopen(self.ch, Some(reason))
    }
}

// implement Drop to be the same as .reject()
impl Drop for ServOpenSession<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.runner.resume_chanopen(self.ch, 
                Some(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)) {
                trace!("Error for chanopen: {e}")
            }
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub(crate) enum ServEventId {
    Hostkeys,
    PasswordAuth,
    PubkeyAuth { real_sig: bool },
    FirstAuth,
    OpenSession { ch: ChanNum },
    SessionShell,
    SessionExec,
    SessionPty,
    Defunct,

    // TODO:
    // Disconnected
    // OpenTCPForwarded (new session)
    // TCPDirectOpened (response)
    // Banner
}

impl ServEventId {
    pub fn event<'g, 'a>(self, runner: &'g mut Runner<'a>) -> Result<ServEvent<'g, 'a>> {
        let p = if cfg!(debug_assertions) { runner.packet()? } else { None };

        match self {
            Self::Hostkeys => {
                debug_assert!(matches!(p, Some(Packet::KexDHInit(_))));
                Ok(ServEvent::Hostkeys(ServHostkeys { runner }))
            }
            Self::PasswordAuth => {
                debug_assert!(matches!(p, Some(Packet::UserauthRequest(_))));
                Ok(ServEvent::PasswordAuth(ServPasswordAuth::new(runner)))
            }
            Self::PubkeyAuth { real_sig } => {
                debug_assert!(matches!(p, Some(Packet::UserauthRequest(_))));
                Ok(ServEvent::PubkeyAuth(ServPubkeyAuth::new(runner, real_sig)))
            }
            Self::FirstAuth => {
                debug_assert!(matches!(p, Some(Packet::UserauthRequest(_))));
                Ok(ServEvent::FirstAuth(ServFirstAuth::new(runner)))
            }
            Self::OpenSession { ch } => {
                debug_assert!(matches!(p, Some(Packet::ChannelOpen(_))));
                Ok(ServEvent::OpenSession(ServOpenSession::new(runner, ch)))
            }
            Self::SessionShell => {
                debug_assert!(matches!(p, Some(Packet::ChannelRequest(_))));
                Ok(ServEvent::SessionShell(ChanRequest::new(runner)))
            }
            Self::SessionExec => {
                debug_assert!(matches!(p, Some(Packet::ChannelRequest(_))));
                Ok(ServEvent::SessionExec(ChanRequest::new(runner)))
            }
            Self::SessionPty => {
                debug_assert!(matches!(p, Some(Packet::ChannelRequest(_))));
                Ok(ServEvent::SessionPty(ChanRequest::new(runner)))
            }
            Self::Defunct => Ok(ServEvent::Defunct),
        }
    }

    // Whether the event must have called an appropriate `resume_` method.
    // Used for internal correctness checks.
    pub(crate) fn needs_resume(&self) -> bool {
        match self {
            | Self::Defunct
            => false,
            | Self::Hostkeys
            | Self::FirstAuth
            | Self::PasswordAuth
            | Self::PubkeyAuth { .. }
            | Self::OpenSession { .. }
            | Self::SessionShell
            | Self::SessionExec
            | Self::SessionPty
            => true,
        }
    }
}

pub struct ChanRequest<'g, 'a> {
    runner: &'g mut Runner<'a>,
    done: bool,
}

impl<'g, 'a> ChanRequest<'g, 'a> {
    fn new(runner: &'g mut Runner<'a>) -> Self {
        Self {
            runner,
            done: false,
        }
    }
    /// Indicate that the request succeeded.
    ///
    /// Note that if the peer didn't request a reply, this call
    /// will not do anything.
    pub fn succeed(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_chanreq(true)
    }

    /// Indicate that the request failed.
    ///
    /// Note that if the peer didn't request a reply, this call
    /// will not do anything.
    /// Does not need to be called explicitly, also occurs on drop without `accept()`
    pub fn fail(mut self) -> Result<()> {
        self.done = true;
        self.runner.resume_chanreq(false)
    }

    pub fn channel(&self) -> Result<ChanNum> {
        self.runner.fetch_reqchannel()
    }

    // TODO: does the app care about wantreply?
}

// implement Drop to be the same as .fail()
impl Drop for ChanRequest<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            if let Err(e) = self.runner.resume_chanreq(false) {
                trace!("Error for chanreq: {e}")
            }
        }
    }
}

