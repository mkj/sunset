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
use kex::{SessId, AlgoConfig};

/// The core state of a SSH instance.
pub struct Conn {
    state: ConnState,

    /// Next kex to run
    kex: kex::Kex,

    sess_id: Option<SessId>,

    cliserv: ClientServer,

    algo_conf: AlgoConfig,

    parse_ctx: ParseContext,

    /// Remote version string. Kept for later kexinit rekeying
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

    pub fn is_server(&self) -> bool {
        matches!(self, ClientServer::Server(_))
    }
}

#[derive(Debug)]
enum ConnState {
    SendIdent,
    SendFirstKexInit,
    /// Prior to SSH binary packet protocol, receiving remote version identification
    ReceiveIdent,
    /// Binary packet protocol has started, KexInit not yet received
    PreKex,
    /// At any time between receiving KexInit and NewKeys.
    ///
    /// Can occur multiple times during a session, at later key exchanges.
    /// Non-kex packets are not allowed during that time
    InKex {
        done_auth: bool,
        output: Option<kex::KexOutput>,
    },

    /// After first NewKeys, prior to auth success.
    PreAuth,
    /// After auth success
    Authed,
    // Cleanup ??
}

#[derive(Default)]
pub(crate) struct Dispatched {
    pub data_in: Option<channel::DataIn>,
    /// set for sensitive payloads such as password auth
    pub zeroize_payload: bool,
}

impl Conn {
    pub fn new_client() -> Result<Self> {
        let algo_conf = AlgoConfig::new(true);
        Self::new(ClientServer::Client(client::Client::new()), algo_conf)
    }

    pub fn new_server(
        ) -> Result<Self> {
        // XXX
        let algo_conf = AlgoConfig::new(false);
        Self::new(ClientServer::Server(server::Server::new()), algo_conf)
    }

    fn new(cliserv: ClientServer, algo_conf: AlgoConfig) -> Result<Self, Error> {
        Ok(Conn {
            kex: kex::Kex::new()?,
            sess_id: None,
            remote_version: ident::RemoteVersion::new(),
            state: ConnState::SendIdent,
            algo_conf,
            cliserv,
            channels: Channels::new(),
            parse_ctx: ParseContext::new(),
        })
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    pub(crate) async fn progress(
        &mut self,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_>,
    ) -> Result<(), Error> {
        debug!("progress conn state {:?}", self.state);
        match self.state {
            ConnState::SendIdent => {
                s.send_version()?;
                self.kex.send_kexinit(&self.algo_conf, s)?;
                // TODO: first_follows would have a second packet here
                self.state = ConnState::ReceiveIdent
            }
            ConnState::ReceiveIdent => {
                if self.remote_version.version().is_some() {
                    self.state = ConnState::PreKex;
                }
            }
            ConnState::PreAuth => {
                // TODO. need to figure how we'll do "unbounded" responses
                // and backpressure. can_output() should have a size check?
                if s.can_output() {
                    if let ClientServer::Client(cli) = &mut self.cliserv {
                        cli.auth.start(s, b.client()?).await?;
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
            | ConnState::SendIdent
            | ConnState::SendFirstKexInit
            => false,
            _ => true,
        }
    }

    /// Consumes an input payload which is a view into [`traffic::Traffic::rxbuf`].
    /// We queue response packets that can be sent (written into the same buffer)
    /// after `handle_payload()` runs.
    pub(crate) async fn handle_payload(
        &mut self, payload: &[u8], seq: u32,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_>,
    ) -> Result<Dispatched, Error> {
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
            packets::Category::Kex => {
                match self.state {
                    ConnState::InKex {..} => Ok(()),
                    _ => Err(Error::SSHProtoError),
                }
            }
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

        if r.is_err() {
            error!("Received unexpected packet {}",
                p.message_num() as u8);
            debug!("state is {:?}", self.state);
        }
        r
    }

    async fn dispatch_packet(
        &mut self, packet: Packet<'_>, s: &mut TrafSend<'_, '_>, b: &mut Behaviour<'_>,
    ) -> Result<Dispatched, Error> {
        // TODO: perhaps could consolidate packet client vs server checks
        trace!("Incoming {packet:#?}");
        let mut disp = Dispatched::default();

        self.check_packet(&packet)?;

        match packet {
            Packet::KexInit(_) => {
                if matches!(self.state, ConnState::InKex { .. }) {
                    return Err(Error::PacketWrong);
                }
                self.state = ConnState::InKex {
                    done_auth: matches!(self.state, ConnState::Authed),
                    output: None,
                };
                self.kex.handle_kexinit(
                    &packet,
                    self.cliserv.is_client(),
                    &self.algo_conf,
                    &self.remote_version,
                    s,
                )?;
            }
            Packet::KexDHInit(p) => {
                match self.state {
                    ConnState::InKex { done_auth: _, ref mut output } => {
                        if self.cliserv.is_client() {
                            // TODO: client/server validity checks should move somewhere more general
                            trace!("kexdhinit not server");
                            return Err(Error::SSHProtoError);
                        }
                        if self.kex.maybe_discard_packet() {
                            // ok
                        } else {
                            let kex =
                                core::mem::replace(&mut self.kex, kex::Kex::new()?);
                            *output = Some(kex.handle_kexdhinit(&p, &self.sess_id, s, b.server()?)?);
                        }
                    }
                    _ => return Err(Error::PacketWrong),
                }
            }
            Packet::KexDHReply(p) => {
                match self.state {
                    ConnState::InKex { done_auth: _, ref mut output } => {
                        if let ClientServer::Client(_cli) = &mut self.cliserv {
                            if self.kex.maybe_discard_packet() {
                                // ok
                            } else {
                                let kex =
                                    core::mem::replace(&mut self.kex, kex::Kex::new()?);
                                *output = Some(kex.handle_kexdhreply(&p, &self.sess_id, s, b.client()?).await?);
                            }
                        } else {
                            // TODO: client/server validity checks should move somewhere more general
                            trace!("Not kexdhreply not client");
                            return Err(Error::SSHProtoError);
                        }
                    }
                    _ => return Err(Error::PacketWrong),
                }
            }
            Packet::NewKeys(_) => {
                match self.state {
                    ConnState::InKex { done_auth, ref mut output } => {
                        // NewKeys shouldn't be received before kexdhinit/kexdhreply.

                        // .as_ref() rather than .take(), so we can zeroize later
                        let ko = output.as_ref().ok_or(Error::PacketWrong)?;
                        // keys.take() leaves remnant memory in output, but output will zeroize soon
                        s.rekey(ko.keys.clone());
                        self.sess_id.get_or_insert(ko.h.clone());
                        // zeroize output.keys via ZeroizeOnDrop
                        *output = None;
                        self.state = if done_auth {
                            ConnState::Authed
                        } else {
                            ConnState::PreAuth
                        };
                    }
                    _ => return Err(Error::PacketWrong),
                }
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
                warn!("SSH debug message from remote host: '{:?}'", p.message);
            }
            Packet::Disconnect(p) => {
                // TODO: SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                info!("Received disconnect: {:?}", p.desc);
            }
            Packet::UserauthRequest(p) => {
                if let ClientServer::Server(serv) = &mut self.cliserv {
                    disp.zeroize_payload = true;
                    let sess_id = self.sess_id.as_ref().trap()?;
                    let success = serv.auth.request(p, sess_id, s, b.server()?)?;
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
                // TODO: client only
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
                    cli.auth.auth60(&p, sess_id, &mut self.parse_ctx, s).await?;
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
            // TODO: maybe needs a conn or cliserv argument.
            => {
                disp.data_in = self.channels.dispatch(packet, s, b).await?;
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

