#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
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
use channel::{Channels, ChanEvent, ChanEventMaker};
use config::MAX_CHANNELS;
use kex::SessId;

/// The core state of a SSH instance.
pub struct Conn<'a> {
    state: ConnState,

    /// Next kex to run
    kex: kex::Kex,

    sess_id: Option<SessId>,

    cliserv: ClientServer,

    algo_conf: kex::AlgoConfig<'a>,

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

// Application API
#[derive(Debug)]
pub enum Event<'a> {
    Channel(ChanEvent<'a>),
    CliAuthed,
}

pub(crate) enum EventMaker {
    Channel(ChanEventMaker),
    CliAuthed,
}

impl<'a> Conn<'a> {
    pub fn new_client() -> Result<Self> {
        Self::new(ClientServer::Client(client::Client::new()))
    }

    pub fn new_server() -> Result<Self> {
        Self::new(ClientServer::Server(server::Server::new()))
    }

    fn new(cliserv: ClientServer) -> Result<Self, Error> {
        Ok(Conn {
            kex: kex::Kex::new()?,
            sess_id: None,
            remote_version: ident::RemoteVersion::new(),
            state: ConnState::SendIdent,
            algo_conf: kex::AlgoConfig::new(cliserv.is_client()),
            cliserv,
            channels: Channels::new(),
            parse_ctx: ParseContext::new(),
        })
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    pub(crate) async fn progress<'b>(
        &mut self,
        s: &mut TrafSend<'_>,
        b: &mut Behaviour<'_>,
    ) -> Result<(), Error> {
        debug!("progress conn state {:?}", self.state);
        match self.state {
            ConnState::SendIdent => {
                s.send_version(ident::OUR_VERSION)?;
                let p = self.kex.send_kexinit(&self.algo_conf, s)?;
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
    pub(crate) async fn handle_payload<'p>(
        &mut self, payload: &'p [u8], seq: u32,
        s: &mut TrafSend<'_>,
        b: &mut Behaviour<'_>,
    ) -> Result<Dispatched, Error> {
        let r = sshwire::packet_from_bytes(payload, &self.parse_ctx);
        match r {
            Ok(p) => self.dispatch_packet(p, s, b).await,
            Err(Error::UnknownPacket { number }) => {
                trace!("Unimplemented packet type {number}");
                s.send(packets::Unimplemented { seq })?;
                Ok(Dispatched { event: None })
            }
            Err(e) => return Err(e),
        }
    }

    async fn dispatch_packet<'p>(
        &mut self, packet: Packet<'p>, s: &mut TrafSend<'_>, b: &mut Behaviour<'_>,
    ) -> Result<Dispatched, Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        trace!("Incoming {packet:#?}");
        let mut event = None;
        match packet {
            Packet::KexInit(_) => {
                if matches!(self.state, ConnState::InKex { .. }) {
                    return Err(Error::PacketWrong);
                }
                self.state = ConnState::InKex {
                    done_auth: matches!(self.state, ConnState::Authed),
                    output: None,
                };
                let r = self.kex.handle_kexinit(
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
                        if let ClientServer::Client(cli) = &mut self.cliserv {
                            if self.kex.maybe_discard_packet() {
                                // ok
                            } else {
                                let kex =
                                    core::mem::replace(&mut self.kex, kex::Kex::new()?);
                                *output = Some(kex.handle_kexdhreply(&p, &self.sess_id, s, b.client()?).await?);
                            }
                        } else {
                            // TODO: client/server validity checks should move somewhere more general
                            return Err(Error::SSHProtoError);
                        }
                    }
                    _ => return Err(Error::PacketWrong),
                }
            }
            Packet::NewKeys(_) => {
                match self.state {
                    ConnState::InKex { done_auth, ref mut output } => {
                        // NewKeys shouldn't be received before kexdhinit/kexdhreply
                        let output = output.take().ok_or(Error::PacketWrong)?;
                        s.rekey(output.keys);
                        self.sess_id.get_or_insert(output.h);
                        self.state = if done_auth {
                            ConnState::Authed
                        } else {
                            ConnState::PreAuth
                        };
                    }
                    _ => return Err(Error::PacketWrong),
                }
            }
            Packet::ServiceRequest(_p) => {
                // TODO: this is server only
                todo!("service request");
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
            Packet::UserauthRequest(_p) => {
                // TODO: this is server only
                todo!("userauth request");
            }
            Packet::UserauthFailure(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.failure(&p, &mut self.parse_ctx, s, b.client()?).await?;
                } else {
                    debug!("Received UserauthFailure as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthSuccess(_) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    if matches!(self.state, ConnState::PreAuth) {
                        self.state = ConnState::Authed;
                        cli.auth_success(&mut self.parse_ctx, s, b.client()?)?;
                        event = Some(EventMaker::CliAuthed);
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
                    cli.auth.auth60(&p, self.sess_id.as_ref().trap()?, &mut self.parse_ctx, s).await?;
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
                let chev = self.channels.dispatch(packet, s, b).await?;
                event = chev.map(|c| EventMaker::Channel(c))
           }
        };
        Ok(Dispatched { event })
    }

    /// creates an `Event` that borrows data from the payload. Some `Event` variants don't
    /// require payload data, the payload is not required in that case.
    /// Those variants are allowed to return `resp` packets from `dispatch()`
    pub(crate) fn make_event<'p>(&mut self, payload: Option<&'p [u8]>, ev: EventMaker)
            -> Result<Option<Event<'p>>> {
        let p = payload.map(|pl| sshwire::packet_from_bytes(pl, &self.parse_ctx)).transpose()?;
        let r = match ev {
            EventMaker::Channel(ChanEventMaker::DataIn(_)) => {
                // caller should have handled it instead
                return Err(Error::bug())
            }
            EventMaker::Channel(cev) => {
                let c = cev.make(p.trap()?);
                c.map(|c| Event::Channel(c))
            }
            EventMaker::CliAuthed => Some(Event::CliAuthed),
        };
        Ok(r)
    }

}

// TODO: delete this
pub(crate) struct Dispatched {
    pub event: Option<EventMaker>,
}

#[cfg(test)]
mod tests {
    use crate::doorlog::*;
    use crate::conn::*;
    use crate::error::Error;

    // #[test]
    // fn event_variants() {
    //     // TODO sanity check event variants.
    // }
}

