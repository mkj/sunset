//! Represents the state of a SSH connection.

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
use encrypt::KeyState;
use packets::{Packet,ParseContext};
use server::Server;
use traffic::TrafSend;
use channel::Channels;
use config::MAX_CHANNELS;
use kex::{Kex, SessId, AlgoConfig};

/// The core state of a SSH instance.
pub(crate) struct Conn<C: CliBehaviour, S: ServBehaviour> {
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

    pub(crate) channels: Channels<C, S>,
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

#[derive(Default)]
/// Returned state from `handle_payload()` for `Runner` to use.
pub(crate) struct Dispatched {
    pub data_in: Option<channel::DataIn>,
    /// set for sensitive payloads such as password auth
    // TODO is this really worthwhile? channel data can be just as sensitive.
    pub zeroize_payload: bool,
    /// packet was Disconnect
    pub disconnect: bool,
}

impl<C: CliBehaviour, S: ServBehaviour> Conn<C, S> {
    pub fn new_client() -> Result<Self> {
        let algo_conf = AlgoConfig::new(true);
        Self::new(ClientServer::Client(client::Client::new()), algo_conf)
    }

    pub fn new_server() -> Result<Self> {
        let algo_conf = AlgoConfig::new(false);
        Self::new(ClientServer::Server(server::Server::new()), algo_conf)
    }

    fn new(cliserv: ClientServer, algo_conf: AlgoConfig) -> Result<Self, Error> {
        Ok(Conn {
            sess_id: None,
            kex: Kex::new(),
            remote_version: ident::RemoteVersion::new(),
            state: ConnState::SendIdent,
            algo_conf,
            cliserv,
            channels: Channels::new(),
            parse_ctx: ParseContext::new(),
        })
    }

    pub fn is_client(&self) -> bool {
        self.cliserv.is_client()
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    // TODO can this just move to the bottom of handle_payload(), and make module-private?
    pub(crate) async fn progress(
        &mut self,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<(), Error> {
        match self.state {
            ConnState::SendIdent => {
                s.send_version()?;
                // send early to avoid round trip latency
                // TODO: first_follows would have a second packet here
                self.kex.send_kexinit(&self.algo_conf, s)?;
                self.state = ConnState::ReceiveIdent
            }
            ConnState::ReceiveIdent => {
                if self.remote_version.version().is_some() {
                    // Ready to start binary packets. We've already send our KexInit with SendIdent.
                    self.state = ConnState::FirstKex
                }
            }
            ConnState::FirstKex => {
                if self.sess_id.is_some() {
                    self.state = ConnState::PreAuth
                }
            }
            ConnState::PreAuth => {
                // TODO. need to figure how we'll do "unbounded" responses
                // and backpressure. can_output() should have a size check?
                if s.can_output() {
                    if let ClientServer::Client(cli) = &mut self.cliserv {
                        cli.auth.progress(s, b.client()?).await?;
                    }
                }
                // send userauth request
            }

            _ => {
                // TODO
            }
        }

        // TODO: if keys.seq > MAX_REKEY then we must rekey for security.

        Ok(())
    }

    pub(crate) fn initial_sent(&self) -> bool {
        match self.state {
            ConnState::SendIdent => false,
            _ => true,
        }
    }

    /// Consumes an input payload which is a view into [`traffic::Traffic::rxbuf`].
    /// We queue response packets that can be sent (written into the same buffer)
    /// after `handle_payload()` runs.
    pub(crate) async fn handle_payload(
        &mut self, payload: &[u8], seq: u32,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<Dispatched, Error> {
        // Parse the packet
        let r = sshwire::packet_from_bytes(payload, &self.parse_ctx);

        match r {
            Ok(p) => self.dispatch_packet(p, s, b).await,
            Err(Error::UnknownPacket { number }) => {
                trace!("Unimplemented packet type {number}");
                s.send(packets::Unimplemented { seq })?;
                Ok(Dispatched::default())
            }
            Err(e) => {
                trace!("Error decoding packet: {e} {:#?}", payload.hex_dump());
                return Err(e)
            }
        }
    }

    /// Check that a packet is received in the correct state
    fn check_packet(&self, p: &Packet) -> Result<()> {
        let r = match p.category() {
            packets::Category::All => Ok(()),
            packets::Category::Kex => Ok(()),
            packets::Category::Auth => {
                match self.state {
                    | ConnState::PreAuth
                    | ConnState::Authed
                    => Ok(()),
                    _ => Err(Error::SSHProtoError),
                }
            }
            packets::Category::Sess => {
                match self.state {
                    ConnState::Authed
                    => Ok(()),
                    _ => Err(Error::SSHProtoError),
                }
            }
        };

        // TODO: reject other packets while kex is in progress?

        if r.is_err() {
            error!("Received unexpected packet {}",
                p.message_num() as u8);
            debug!("state is {:?}", self.state);
        }
        r
    }

    async fn dispatch_packet(
        &mut self, packet: Packet<'_>, s: &mut TrafSend<'_, '_>, b: &mut Behaviour<'_, C, S>,
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
                    s,
                )?;
            }
            Packet::KexDHInit(p) => {
                if self.cliserv.is_client() {
                    // TODO: client/server validity checks should move somewhere more general
                    trace!("kexdhinit not server");
                    return Err(Error::SSHProtoError);
                }

                self.kex.handle_kexdhinit(&p, s, b.server()?)?;
            }
            Packet::KexDHReply(p) => {
                if !self.cliserv.is_client() {
                    // TODO: client/server validity checks should move somewhere more general
                    trace!("kexdhreply not server");
                    return Err(Error::SSHProtoError);
                }

                self.kex.handle_kexdhreply(&p, s, b.client()?).await?;
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
                    return Err(Error::SSHProtoError)
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
                b.disconnected(p.desc);
                disp.disconnect = true;
            }
            Packet::UserauthRequest(p) => {
                if let ClientServer::Server(serv) = &mut self.cliserv {
                    disp.zeroize_payload = true;
                    let sess_id = self.sess_id.as_ref().trap()?;
                    let success = serv.auth.request(p, sess_id, s, b.server()?).await?;
                    if success {
                        self.state = ConnState::Authed;
                    }
                } else {
                    debug!("Server sent an auth request");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthFailure(p) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.failure(&p, &mut self.parse_ctx, s, b.client()?).await?;
                } else {
                    debug!("Received UserauthFailure as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthSuccess(_) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    if matches!(self.state, ConnState::PreAuth) {
                        self.state = ConnState::Authed;
                        cli.auth_success(&mut self.parse_ctx, s, b.client()?)?;
                    } else {
                        debug!("Received UserauthSuccess unrequested")
                    }
                } else {
                    debug!("Received UserauthSuccess as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthBanner(p) => {
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.banner(&p, b.client()?);
                } else {
                    debug!("Received banner as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::Userauth60(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    let sess_id = self.sess_id.as_ref().trap()?;
                    cli.auth.auth60(&p, sess_id, &mut self.parse_ctx, s, b.client()?).await?;
                } else {
                    debug!("Received userauth60 as a server");
                    return Err(Error::SSHProtoError)
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
                disp.data_in = self.channels.dispatch(packet, self.cliserv.is_client(), s, b).await?;
            }
            Packet::GlobalRequest(p) => {
                trace!("Got global request {p:?}");
                if p.want_reply {
                    s.send(packets::RequestFailure {})?;
                }
            }
            Packet::RequestSuccess(p) => {
                trace!("Got global request success")
            }
            Packet::RequestFailure(_) => {
                trace!("Got global request failure")
            }
        };
        Ok(disp)
    }
}

#[cfg(test)]
mod tests {
    use crate::sunsetlog::*;
    use crate::conn::*;
    use crate::error::Error;
}

