//! Represents the state of a SSH connection.

use self::{cliauth::CliAuth, packets::{AuthMethod, UserauthRequest}};

#[allow(unused_imports)]
use {
    crate::error::{*, Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::char::MAX;
use core::task::{Waker,Poll};

use pretty_hex::PrettyHex;
use heapless::Vec;

use crate::*;
use sshnames::*;
use client::Client;
use packets::{Packet,ParseContext};
use server::Server;
use traffic::TrafSend;
use channel::{Channels, CliSessionExit};
use config::MAX_CHANNELS;
use kex::{Kex, SessId, AlgoConfig};
use event::{CliEvent, ServEvent};

/// The core state of a SSH instance.
pub(crate) struct Conn {
    state: ConnState,

    // State of any current Key Exchange
    kex: Kex,

    sess_id: Option<SessId>,

    cliserv: ClientServer,

    algo_conf: AlgoConfig,

    parse_ctx: ParseContext,

    /// Remote version string. Kept for later kexinit rekeying
    // TODO: could save space by hashing it into a KexHash and storing that instead.
    // 256 bytes -> 112 bytes
    pub(crate) remote_version: ident::RemoteVersion,

    pub(crate) channels: Channels,
}

// TODO: what tricks can we do to optimise away client or server code if we only
// want one of them?
enum ClientServer {
    Client(client::Client),
    Server(server::Server),
}

impl ClientServer {
    pub fn is_client(&self) -> bool {
        matches!(self, ClientServer::Client(_))
    }
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

#[must_use]
#[derive(Debug, Clone)]
pub(crate) enum DispatchEvent
{
    /// Incoming channel data
    Data(channel::DataIn),
    CliEvent(event::CliEventId),
    ServEvent(event::ServEventId),
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
            | Self::None
            | Self::Data(_)
            | Self::Progressed
            => false,
            Self::CliEvent(x) => x.needs_resume(),
            Self::ServEvent(x) => x.needs_resume(),
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

impl Conn {
    pub fn new(is_client: bool) -> Result<Self> {
        let algo_conf = AlgoConfig::new(is_client);
        let cliserv = if is_client {
            ClientServer::Client(client::Client::new())
        } else {
            ClientServer::Server(server::Server::new())
        };

        Ok(Conn {
            sess_id: None,
            kex: Kex::new(),
            remote_version: ident::RemoteVersion::new(cliserv.is_client()),
            state: ConnState::SendIdent,
            algo_conf,
            channels: Channels::new(cliserv.is_client()),
            parse_ctx: ParseContext::new(),
            cliserv,
        })
    }

    pub fn is_client(&self) -> bool {
        self.cliserv.is_client()
    }

    pub fn server(&self) -> Result<&server::Server> {
        match &self.cliserv {
            ClientServer::Server(s) => Ok(s),
            _ => Err(Error::bug())
        }
    }

    pub fn mut_server(&mut self) -> Result<&mut server::Server> {
        match &mut self.cliserv {
            ClientServer::Server(s) => Ok(s),
            _ => Err(Error::bug())
        }
    }

    pub fn client(&self) -> Result<&client::Client> {
        match &self.cliserv {
            ClientServer::Client(x) => Ok(x),
            _ => Err(Error::bug())
        }
    }

    pub fn mut_client(&mut self) -> Result<&mut client::Client> {
        match &mut self.cliserv {
            ClientServer::Client(x) => Ok(x),
            _ => Err(Error::bug())
        }
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    // TODO can this just move to the bottom of handle_payload(), and make module-private?
    pub(crate) fn progress(&mut self, s: &mut TrafSend) -> Result<Dispatched, Error> {
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
                    if let ClientServer::Client(cli) = &mut self.cliserv {
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

    pub(crate) fn packet<'p>(&self, payload: &'p[u8]) -> Result<Packet<'p>> {
        sshwire::packet_from_bytes(payload, &self.parse_ctx)
    }

    /// Consumes an input payload which is a view into [`traffic::Traffic::rxbuf`].
    /// We queue response packets that can be sent (written into the same buffer)
    /// after `handle_payload()` runs.
    pub(crate) fn handle_payload(&mut self, payload: &[u8], seq: u32, 
        s: &mut TrafSend) -> Result<Dispatched, Error> {
        // Parse the packet
        trace!("Received\n{:#?}", payload.hex_dump());

        match self.packet(payload) {
            Ok(p) => {
                let num = p.message_num() as u8;
                let a = self.dispatch_packet(p, s);
                match a {
                    | Err(Error::SSHProto { .. })
                    | Err(Error::PacketWrong)
                    => debug!("Error handling {num} packet"),
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
                error!("Error decoding packet: {e}");
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
                },
            }
        } else if !matches!(self.kex, Kex::Idle) {
            // Normal KEX only allows certain packets
            match p.category() {
                packets::Category::All => Ok(()),
                packets::Category::Kex => Ok(()),
                _ => {
                    debug!("Invalid packet during kex");
                    error::SSHProto.fail()
                },
            }
        } else {
            // No KEX in progress, check for post-auth packets
            match p.category() {
                packets::Category::All => Ok(()),
                packets::Category::Kex => Ok(()),
                packets::Category::Auth => {
                    match self.state {
                        | ConnState::PreAuth
                        | ConnState::Authed
                        => Ok(()),
                        _ => error::SSHProto.fail(),
                    }
                }
                packets::Category::Sess => {
                    match self.state {
                        ConnState::Authed
                        => Ok(()),
                        _ => error::SSHProto.fail(),
                    }
                }
            }
        };

        if r.is_err() {
            error!("Received unexpected packet {}",
                p.message_num() as u8);
            debug!("state is {:?}", self.state);
        }
        r
    }

    fn is_first_kex(&self) -> bool {
        self.sess_id.is_none()
    }

    pub fn dispatch_packet(&mut self, packet: Packet, s: &mut TrafSend,
    ) -> Result<Dispatched, Error> {
        // TODO: perhaps could consolidate packet client vs server checks
        trace!("Incoming {packet:#?}");
        let mut disp = Dispatched::default();

        self.check_packet(&packet)?;

        match packet {
            Packet::KexInit(k) => {
                self.kex.handle_kexinit(
                    k,
                    self.cliserv.is_client(),
                    &self.algo_conf,
                    &self.remote_version,
                    self.is_first_kex(),
                    s,
                )?;
            }
            Packet::KexDHInit(p) => {
                if self.cliserv.is_client() {
                    // TODO: client/server validity checks should move somewhere more general
                    trace!("kexdhinit not server");
                    return error::SSHProto.fail();
                }

                disp.event = self.kex.handle_kexdhinit()?;
            }
            Packet::KexDHReply(p) => {
                if !self.cliserv.is_client() {
                    // TODO: client/server validity checks should move somewhere more general
                    trace!("kexdhreply not server");
                    return error::SSHProto.fail();
                }

                disp.event = self.kex.handle_kexdhreply();
            }
            Packet::NewKeys(_) => {
                self.kex.handle_newkeys(&mut self.sess_id, s)?;
            }
            Packet::ExtInfo(p) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.handle_ext_info(&p);
                }
                // could potentially pass it to other handlers too
            }
            Packet::ServiceRequest(p) => {
                if let ClientServer::Server(serv) = &mut self.cliserv {
                    serv.service_request(&p, s)?;
                } else {
                    debug!("Server sent a service request");
                    return error::SSHProto.fail()
                }
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
            Packet::Disconnect(p) => {
                // We ignore p.reason.
                // SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                disp.disconnect = true;
            }
            Packet::UserauthRequest(p) => {
                if let ClientServer::Server(serv) = &mut self.cliserv {
                    let sess_id = self.sess_id.as_ref().trap()?;
                    disp.event = serv.auth.request(sess_id, s, p)?;
                } else {
                    debug!("Server sent an auth request");
                    return error::SSHProto.fail()
                }
            }
            Packet::UserauthFailure(p) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    disp.event = cli.auth.failure(&p, &mut self.parse_ctx)?;
                } else {
                    debug!("Received UserauthFailure as a server");
                    return error::SSHProto.fail()
                }
            }
            Packet::UserauthSuccess(_) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    if matches!(self.state, ConnState::PreAuth) {
                        self.state = ConnState::Authed;
                        disp.event = cli.auth_success(&mut self.parse_ctx);
                    } else {
                        debug!("Received UserauthSuccess unrequested")
                    }
                } else {
                    debug!("Received UserauthSuccess as a server");
                    return error::SSHProto.fail()
                }
            }
            Packet::UserauthBanner(p) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.banner(&p);
                } else {
                    debug!("Received banner as a server");
                    return error::SSHProto.fail()
                }
            }
            Packet::Userauth60(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    let sess_id = self.sess_id.as_ref().trap()?;
                    disp.event = cli.auth.auth60(&p, sess_id, &mut self.parse_ctx, s)?;
                } else {
                    debug!("Received userauth60 as a server");
                    return error::SSHProto.fail()
                }
            }
            | Packet::ChannelOpen(_)
            | Packet::ChannelOpenConfirmation(_)
            | Packet::ChannelOpenFailure(_)
            | Packet::ChannelWindowAdjust(_)
            | Packet::ChannelData(_)
            | Packet::ChannelDataExt(_)
            | Packet::ChannelEof(_)
            | Packet::ChannelClose(_)
            | Packet::ChannelRequest(_)
            | Packet::ChannelSuccess(_)
            | Packet::ChannelFailure(_)

            => {
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

    pub(crate) fn cliauth(&self) -> Result<&CliAuth> {
        let ClientServer::Client(cli) = &self.cliserv else {
            return Err(Error::bug())
        };
        Ok(&cli.auth)
    }

    pub(crate) fn mut_cliauth(&mut self) -> Result<(&mut CliAuth, &mut ParseContext)> {
        let ClientServer::Client(cli) = &mut self.cliserv else {
            return Err(Error::bug())
        };
        Ok((&mut cli.auth, &mut self.parse_ctx))
    }


    pub(crate) fn fetch_agentsign_msg(&self) -> Result<AuthSigMsg> {
        let ClientServer::Client(cli) = &self.cliserv else {
            return Err(Error::bug())
        };

        let sess_id = self.sess_id.as_ref().trap()?;
        cli.auth.fetch_agentsign_msg(sess_id)
    }

    pub(crate) fn resume_checkhostkey(&mut self, 
        payload: &[u8],
        s: &mut TrafSend,
        accept: bool) -> Result<()> {
        self.client()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHReply(p) = packet {
            if !accept {
                // TODO set state to closing?
                info!("Host key rejected");
                return error::BadUsage.fail()
            }

            self.kex.resume_kexdhreply(&p, self.is_first_kex(), s)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_checkhostkey<'f>(&self, payload: &'f [u8]) -> Result<PubKey<'f>> {
        self.client()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHReply(p) = packet {
            Ok(p.k_s.0)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_cli_session_exit<'p>(&mut self, payload: &'p [u8]) -> Result<CliSessionExit<'p>> {
        self.client()?;
        let packet = self.packet(payload)?;
        CliSessionExit::new(&packet)
    }

    pub(crate) fn resume_servhostkeys(&mut self,
        payload: &[u8], s: &mut TrafSend, keys: &[&SignKey]) -> Result<()> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::KexDHInit(p) = packet {
            self.kex.resume_kexdhinit(&p, keys, s)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_servpassword<'f>(&self, payload: &'f [u8]) -> Result<TextString<'f>> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::UserauthRequest(UserauthRequest {method: AuthMethod::Password(m), ..}) = packet {
            Ok(m.password)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn fetch_servpubkey<'f>(&self, payload: &'f [u8]) -> Result<PubKey<'f>> {
        self.server()?;

        let packet = self.packet(payload)?;
        if let Packet::UserauthRequest(UserauthRequest {method: AuthMethod::PubKey(m), ..}) = packet {
            Ok(m.pubkey.0)
        } else {
            Err(Error::bug())
        }
    }

    pub(crate) fn resume_servauth(&mut self, allow: bool, s: &mut TrafSend) -> Result<()> {
        let auth = &mut self.mut_server()?.auth;
        auth.resume_request(allow, s)?;
        if auth.authed && matches!(self.state, ConnState::PreAuth) {
            self.state = ConnState::Authed;
        }
        return Ok(())
    }

    pub(crate) fn resume_servauth_pkok(&mut self, payload: &[u8], s: &mut TrafSend) -> Result<()> {
        let p = self.packet(payload)?;
        self.server()?.auth.resume_pkok(p, s)
    }
}

#[cfg(test)]
mod tests {
    use crate::sunsetlog::*;
    use crate::conn::*;
    use crate::error::Error;
}

