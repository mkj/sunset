//! Represents the state of a SSH connection.

use self::{
    cliauth::CliAuth,
    event::Banner,
    packets::{AuthMethod, UserauthRequest},
};

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug, *},
    log::{debug, error, info, log, trace, warn},
};

use core::char::MAX;
use core::task::{Poll, Waker};

use heapless::Vec;
use pretty_hex::PrettyHex;

use crate::*;
use channel::{Channels, CliSessionExit};
use client::Client;
use config::MAX_CHANNELS;
use event::{CliEvent, ServEvent};
use kex::{AlgoConfig, Kex, SessId};
use packets::{Packet, ParseContext};
use server::Server;
use sshnames::*;
use traffic::TrafSend;

/// The core state of a SSH instance.
pub(crate) struct Conn<CS: CliServ> {
    state: ConnState,

    // State of any current Key Exchange
    kex: Kex<CS>,

    sess_id: Option<SessId>,

    cliserv: CS,

    algo_conf: AlgoConfig,

    parse_ctx: ParseContext,

    /// Remote version string. Kept for later kexinit rekeying
    // TODO: could save space by hashing it into a KexHash and storing that instead.
    // 256 bytes -> 112 bytes
    pub(crate) remote_version: ident::RemoteVersion,

    pub(crate) channels: Channels,
}

#[derive(Debug)]
enum ConnState {
    /// The initial state
    SendIdent,
    /// Prior to SSH binary packet protocol, receiving remote version identification
    ReceiveIdent,
    /// Waiting for first Kex to complete
    FirstKex,
    /// Binary protocol has started, auth hasn't succeeded
    PreAuth,
    /// After auth success
    Authed,
    // Cleanup ??
}

// must_use so return values can't be forgotten in Conn::dispatch_packet
#[must_use]
#[derive(Debug, Clone)]
pub(crate) enum DispatchEvent {
    /// Incoming channel data
    Data(channel::DataIn),
    CliEvent(event::CliEventId),
    ServEvent(event::ServEventId),
    /// NewKeys was received, wake any output channels in case they were waiting.
    KexDone,
    /// Connection state has changed, should poll again
    Progressed,
    /// No event
    None,
}

impl Default for DispatchEvent {
    fn default() -> Self {
        Self::None
    }
}

impl DispatchEvent {
    pub fn take(&mut self) -> Self {
        core::mem::replace(self, DispatchEvent::None)
    }

    pub fn is_some(&self) -> bool {
        !self.is_none()
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Used by Runner to determine whether an event requires a resume call before
    /// continuing. Informational events don't.
    /// Some events don't need calling manually, but their Drop impl will
    /// call the appropriate resume method.
    pub(crate) fn needs_resume(&self) -> bool {
        match self {
            Self::None | Self::Data(_) | Self::KexDone | Self::Progressed => false,
            Self::CliEvent(x) => x.needs_resume(),
            Self::ServEvent(x) => x.needs_resume(),
        }
    }

    pub(crate) fn is_event(&self) -> bool {
        match self {
            Self::CliEvent(_) | Self::ServEvent(_) => true,
            _ => false,
        }
    }
}

#[derive(Default, Debug)]
/// Returned state from `handle_payload()` or `progress()` for `Runner` to use.
pub(crate) struct Dispatched {
    pub event: DispatchEvent,

    /// packet was Disconnect
    // TODO replace with an event
    pub disconnect: bool,
}

pub trait CliServ: Sized + Send + Default {
    fn is_client() -> bool;

    #[inline]
    fn try_server(&self) -> Option<&server::Server> {
        None
    }

    #[inline]
    fn try_mut_server(&mut self) -> Option<&mut server::Server> {
        None
    }

    #[inline]
    fn try_client(&self) -> Option<&client::Client> {
        None
    }

    #[inline]
    fn try_mut_client(&mut self) -> Option<&mut client::Client> {
        None
    }

    #[expect(private_interfaces)]
    fn dispatch_into_event<'a, 'g>(
        runner: &'g mut Runner<'a, Self>,
        disp: DispatchEvent,
    ) -> Result<Event<'g, 'a>>;
}

impl CliServ for client::Client {
    #[inline]
    fn is_client() -> bool {
        true
    }

    #[inline]
    fn try_client(&self) -> Option<&client::Client> {
        Some(self)
    }

    #[inline]
    fn try_mut_client(&mut self) -> Option<&mut client::Client> {
        Some(self)
    }

    #[expect(private_interfaces)]
    fn dispatch_into_event<'a, 'g>(
        runner: &'g mut Runner<'a, Self>,
        disp: DispatchEvent,
    ) -> Result<Event<'g, 'a>> {
        match disp {
            DispatchEvent::CliEvent(x) => Ok(Event::Cli(x.event(runner)?)),
            DispatchEvent::ServEvent(_) => Err(Error::bug()),
            DispatchEvent::None => Ok(Event::None),
            DispatchEvent::Progressed => Ok(Event::Progressed),
            // Events handled internally by Runner::progress()
            DispatchEvent::Data(_) | DispatchEvent::KexDone => Err(Error::bug()),
        }
    }
}

impl CliServ for server::Server {
    #[inline]
    fn is_client() -> bool {
        false
    }

    #[inline]
    fn try_server(&self) -> Option<&server::Server> {
        Some(self)
    }

    #[inline]
    fn try_mut_server(&mut self) -> Option<&mut server::Server> {
        Some(self)
    }

    #[expect(private_interfaces)]
    fn dispatch_into_event<'a, 'g>(
        runner: &'g mut Runner<'a, Self>,
        disp: DispatchEvent,
    ) -> Result<Event<'g, 'a>> {
        match disp {
            DispatchEvent::CliEvent(_) => Err(Error::bug()),
            DispatchEvent::ServEvent(x) => Ok(Event::Serv(x.event(runner)?)),
            DispatchEvent::None => Ok(Event::None),
            DispatchEvent::Progressed => Ok(Event::Progressed),
            // Events handled internally by Runner::progress()
            DispatchEvent::Data(_) | DispatchEvent::KexDone => Err(Error::bug()),
        }
    }
}

impl<CS: CliServ> Conn<CS> {
    pub fn new() -> Self {
        let algo_conf = AlgoConfig::new(CS::is_client());
        let cliserv = CS::default();

        Conn {
            sess_id: None,
            kex: Kex::new(),
            remote_version: ident::RemoteVersion::new(CS::is_client()),
            state: ConnState::SendIdent,
            algo_conf,
            channels: Channels::new(CS::is_client()),
            parse_ctx: ParseContext::new(),
            cliserv,
        }
    }

    #[inline]
    fn is_client(&self) -> bool {
        CS::is_client()
    }

    #[inline]
    fn is_server(&self) -> bool {
        !self.is_client()
    }

    #[inline]
    pub fn server(&self) -> Result<&server::Server> {
        self.cliserv.try_server().ok_or_else(|| Error::bug())
    }

    #[inline]
    fn try_mut_server(&mut self) -> Option<&mut server::Server> {
        self.cliserv.try_mut_server()
    }

    #[inline]
    fn mut_server(&mut self) -> Result<&mut server::Server> {
        self.try_mut_server().ok_or_else(|| Error::bug())
    }

    #[inline]
    fn client(&self) -> Result<&client::Client> {
        self.cliserv.try_client().ok_or_else(|| Error::bug())
    }

    #[inline]
    fn try_mut_client(&mut self) -> Option<&mut client::Client> {
        self.cliserv.try_mut_client()
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    // TODO can this just move to the bottom of handle_payload(), and make module-private?
    pub(crate) fn progress(
        &mut self,
        s: &mut TrafSend,
    ) -> Result<Dispatched, Error> {
        let mut disp = Dispatched::default();
        match self.state {
            ConnState::SendIdent => {
                s.send_version()?;
                // send early to avoid round trip latency
                // TODO: first_follows would have a second packet here
                self.kex.send_kexinit(&self.algo_conf, s)?;
                disp.event = DispatchEvent::Progressed;
                self.state = ConnState::ReceiveIdent
            }
            ConnState::ReceiveIdent => {
                if self.remote_version.version().is_some() {
                    // Ready to start binary packets. We've already send our KexInit with SendIdent.
                    disp.event = DispatchEvent::Progressed;
                    self.state = ConnState::FirstKex
                }
            }
            ConnState::FirstKex => {
                if self.sess_id.is_some() {
                    disp.event = DispatchEvent::Progressed;
                    self.state = ConnState::PreAuth
                }
            }
            ConnState::PreAuth => {
                // TODO. need to figure how we'll do "unbounded" responses
                // and backpressure. can_output() should have a size check?
                if s.can_output() {
                    if let Some(cli) = self.try_mut_client() {
                        disp.event = cli.auth.progress();
                    }
                }
                // send userauth request
            }
            ConnState::Authed => {
                // no events needed
            }
        }
        trace!("-> {:?}, {disp:?}", self.state);

        // TODO: if keys.seq > MAX_REKEY then we must rekey for security.

        Ok(disp)
    }

    pub(crate) fn initial_sent(&self) -> bool {
        !matches!(self.state, ConnState::SendIdent)
    }

    pub(crate) fn packet<'p>(&self, payload: &'p [u8]) -> Result<Packet<'p>> {
        sshwire::packet_from_bytes(payload, &self.parse_ctx)
    }

    /// Consumes an input payload which is a view into [`traffic::Traffic::rxbuf`].
    /// We queue response packets that can be sent (written into the same buffer)
    /// after `handle_payload()` runs.
    pub(crate) fn handle_payload(
        &mut self,
        payload: &[u8],
        seq: u32,
        s: &mut TrafSend,
    ) -> Result<Dispatched, Error> {
        // Parse the packet
        match self.packet(payload) {
            Ok(p) => {
                let num = p.message_num() as u8;
                let a = self.dispatch_packet(p, s);
                match a {
                    Err(Error::SSHProto { .. }) | Err(Error::PacketWrong { .. }) => {
                        debug!("Error handling {num} packet")
                    }
                    _ => (),
                }
                a
            }
            Err(Error::UnknownPacket { number }) => {
                trace!("Unimplemented packet type {number}");
                s.send(packets::Unimplemented { seq })?;
                Ok(Dispatched::default())
            }
            Err(e) => {
                debug!("Error decoding packet: {e}");
                trace!("Input:\n{:#?}", payload.hex_dump());
                Err(e)
            }
        }
    }

    /// Check that a packet is received in the correct state
    fn check_packet(&self, p: &Packet) -> Result<()> {
        let r = if self.is_first_kex() && self.kex.is_strict() {
            // Strict Kex doesn't allow even packets like Ignore or Debug
            match p.category() {
                packets::Category::Kex => Ok(()),
                _ => {
                    debug!("Non-kex packet during strict kex");
                    error::SSHProto.fail()
                }
            }
        } else if !matches!(self.kex, Kex::Idle | Kex::KexInit { .. }) {
            // Normal KEX only allows certain packets
            match p.category() {
                packets::Category::All => Ok(()),
                packets::Category::Kex => Ok(()),
                _ => {
                    debug!("Invalid packet during kex");
                    error::SSHProto.fail()
                }
            }
        } else {
            // No KEX in progress, check for post-auth packets
            match p.category() {
                packets::Category::All => Ok(()),
                packets::Category::Kex => Ok(()),
                packets::Category::Auth => match self.state {
                    ConnState::PreAuth | ConnState::Authed => Ok(()),
                    _ => error::SSHProto.fail(),
                },
                packets::Category::Sess => match self.state {
                    ConnState::Authed => Ok(()),
                    _ => error::SSHProto.fail(),
                },
            }
        };

        if r.is_err() {
            debug!("Received unexpected packet {}", p.message_num() as u8);
            trace!("state is {:?}", self.state);
        }
        r
    }

    fn is_first_kex(&self) -> bool {
        self.sess_id.is_none()
    }

    pub fn kex_is_idle(&self) -> bool {
        matches!(self.kex, Kex::Idle)
    }

    pub fn dispatch_packet(
        &mut self,
        packet: Packet,
        s: &mut TrafSend,
    ) -> Result<Dispatched, Error> {
        // TODO: perhaps could consolidate packet client vs server checks
        trace!("Incoming {packet:#?}");
        let mut disp = Dispatched::default();

        self.check_packet(&packet)?;

        match packet {
            Packet::KexInit(k) => {
                self.kex.handle_kexinit(
                    k,
                    &self.algo_conf,
                    &self.remote_version,
                    self.is_first_kex(),
                    s,
                )?;
            }
            Packet::KexDHInit(_p) => {
                disp.event = self.kex.handle_kexdhinit()?;
            }
            Packet::KexDHReply(_p) => {
                disp.event = self.kex.handle_kexdhreply()?;
            }
            Packet::NewKeys(_) => {
                self.kex.handle_newkeys(&mut self.sess_id, s)?;
                disp.event = DispatchEvent::KexDone;
            }
            Packet::ExtInfo(p) => {
                if let Some(cli) = self.try_mut_client() {
                    cli.auth.handle_ext_info(&p);
                }
                // could potentially pass it to other handlers too
            }
            Packet::ServiceRequest(p) => {
                let Some(serv) = self.try_mut_server() else {
                    debug!("Server sent a service request");
                    return error::SSHProto.fail();
                };
                serv.service_request(&p, s)?;
            }
            Packet::ServiceAccept(p) => {
                // Don't need to do anything, if a request failed the server disconnects
                trace!("Received service accept {}", p.name);
            }
            Packet::Ignore(_) => {
                // nothing to do
            }
            Packet::Unimplemented(_) => {
                warn!("Received SSH unimplemented message");
            }
            Packet::DebugPacket(p) => {
                let level = match p.always_display {
                    true => log::Level::Info,
                    false => log::Level::Debug,
                };
                log!(level, "SSH debug message from remote host: {}", p.message);
            }
            Packet::Disconnect(_p) => {
                // We ignore p.reason.
                // SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                disp.disconnect = true;
            }
            Packet::UserauthRequest(p) => {
                let Some(serv) = self.cliserv.try_mut_server() else {
                    debug!("Server sent an auth request");
                    return error::SSHProto.fail();
                };
                let sess_id = self.sess_id.as_ref().trap()?;
                disp.event = serv.auth.request(sess_id, s, p)?;
            }
            Packet::UserauthFailure(p) => {
                let Some(cli) = self.cliserv.try_mut_client() else {
                    debug!("Received UserauthFailure as a server");
                    return error::SSHProto.fail();
                };
                disp.event = cli.auth.failure(&p, &mut self.parse_ctx)?;
            }
            Packet::UserauthSuccess(_) => {
                let Some(cli) = self.cliserv.try_mut_client() else {
                    debug!("Received UserauthSuccess as a server");
                    return error::SSHProto.fail();
                };
                if matches!(self.state, ConnState::PreAuth) {
                    self.state = ConnState::Authed;
                    disp.event = cli.auth_success(&mut self.parse_ctx);
                } else {
                    debug!("Received UserauthSuccess unrequested")
                }
            }
            Packet::UserauthBanner(_) => {
                if self.is_server() {
                    debug!("Received banner as a server");
                    return error::SSHProto.fail();
                }
                disp.event = DispatchEvent::CliEvent(CliEventId::Banner);
            }
            Packet::Userauth60(p) => {
                let Some(cli) = self.cliserv.try_mut_client() else {
                    debug!("Received userauth60 as a server");
                    return error::SSHProto.fail();
                };
                let sess_id = self.sess_id.as_ref().trap()?;
                disp.event = cli.auth.auth60(&p, sess_id, &mut self.parse_ctx, s)?;
            }
            Packet::ChannelOpen(_)
            | Packet::ChannelOpenConfirmation(_)
            | Packet::ChannelOpenFailure(_)
            | Packet::ChannelWindowAdjust(_)
            | Packet::ChannelData(_)
            | Packet::ChannelDataExt(_)
            | Packet::ChannelEof(_)
            | Packet::ChannelClose(_)
            | Packet::ChannelRequest(_)
            | Packet::ChannelSuccess(_)
            | Packet::ChannelFailure(_) => {
                disp.event = self.channels.dispatch(packet, s)?;
            }
            Packet::GlobalRequest(p) => {
                trace!("Got global request {p:?}");
                if p.want_reply {
                    s.send(packets::RequestFailure {})?;
                }
            }
            Packet::RequestSuccess(_p) => {
                trace!("Got global request success")
            }
            Packet::RequestFailure(_) => {
                trace!("Got global request failure")
            }
        };
        Ok(disp)
    }
}

impl Conn<Client> {
    pub(crate) fn cliauth(&self) -> Result<&CliAuth> {
        let cli = self.client()?;
        Ok(&cli.auth)
    }

    pub(crate) fn mut_cliauth(
        &mut self,
    ) -> Result<(&mut CliAuth, &mut ParseContext)> {
        let cli = self.cliserv.try_mut_client().ok_or_else(|| Error::bug())?;
        Ok((&mut cli.auth, &mut self.parse_ctx))
    }

    pub(crate) fn fetch_agentsign_msg(&self) -> Result<AuthSigMsg<'_>> {
        let cli = self.client()?;
        let sess_id = self.sess_id.as_ref().trap()?;
        cli.auth.fetch_agentsign_msg(sess_id)
    }

    pub(crate) fn resume_checkhostkey(
        &mut self,
        payload: &[u8],
        s: &mut TrafSend,
        accept: bool,
    ) -> Result<()> {
        self.client()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHReply(p) = packet {
            if !accept {
                // TODO set state to closing?
                info!("Host key rejected");
                return error::BadUsage.fail();
            }

            self.kex.resume_kexdhreply(&p, &mut self.sess_id, s)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_checkhostkey<'f>(
        &self,
        payload: &'f [u8],
    ) -> Result<PubKey<'f>> {
        self.client()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHReply(p) = packet {
            Ok(p.k_s.0)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_cli_session_exit<'p>(
        &mut self,
        payload: &'p [u8],
    ) -> Result<CliSessionExit<'p>> {
        self.client()?;
        let packet = self.packet(payload)?;
        CliSessionExit::new(&packet)
    }

    pub(crate) fn fetch_cli_banner<'p>(
        &mut self,
        payload: &'p [u8],
    ) -> Result<Banner<'p>> {
        self.client()?;
        if let Packet::UserauthBanner(b) = self.packet(payload)? {
            Ok(Banner(b))
        } else {
            Err(Error::bug())
        }
    }
}

impl Conn<Server> {
    pub(crate) fn resume_servhostkeys(
        &mut self,
        payload: &[u8],
        s: &mut TrafSend,
        keys: &[&SignKey],
    ) -> Result<()> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHInit(p) = packet {
            self.kex.resume_kexdhinit(
                &p,
                self.is_first_kex(),
                keys,
                &mut self.sess_id,
                s,
            )
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_servpassword<'f>(
        &self,
        payload: &'f [u8],
    ) -> Result<TextString<'f>> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::UserauthRequest(UserauthRequest {
            method: AuthMethod::Password(m),
            ..
        }) = packet
        {
            Ok(m.password)
        } else {
            Err(Error::bug())
        }
    }
    pub(crate) fn fetch_servpubkey<'f>(
        &self,
        payload: &'f [u8],
    ) -> Result<PubKey<'f>> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::UserauthRequest(UserauthRequest {
            method: AuthMethod::PubKey(m),
            ..
        }) = packet
        {
            Ok(m.pubkey.0)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn resume_servauth(
        &mut self,
        allow: bool,
        s: &mut TrafSend,
    ) -> Result<()> {
        let auth = &mut self.mut_server()?.auth;
        auth.resume_request(allow, s)?;
        if auth.authed && matches!(self.state, ConnState::PreAuth) {
            self.state = ConnState::Authed;
        }
        return Ok(());
    }

    pub(crate) fn resume_servauth_pkok(
        &mut self,
        payload: &[u8],
        s: &mut TrafSend,
    ) -> Result<()> {
        let p = self.packet(payload)?;
        self.server()?.auth.resume_pkok(p, s)
    }

    pub(crate) fn set_auth_methods(
        &mut self,
        password: bool,
        pubkey: bool,
    ) -> Result<()> {
        let auth = &mut self.mut_server()?.auth;
        auth.set_auth_methods(password, pubkey);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::conn::*;
    use crate::error::Error;
    use crate::sunsetlog::*;
}
