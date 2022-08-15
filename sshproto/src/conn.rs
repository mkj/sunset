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
use traffic::{Traffic,PacketMaker};
use channel::{Channels, ChanEvent, ChanEventMaker};
use config::MAX_CHANNELS;
use kex::SessId;

// TODO a max value needs to be analysed
pub(crate) const MAX_RESPONSES: usize = 4;

pub type RespPackets<'a> = heapless::Vec<PacketMaker<'a>, MAX_RESPONSES>;

pub(crate) enum Handled<'a> {
    Response(RespPackets<'a>),
}

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
        &mut self, traffic: &mut Traffic<'b>, keys: &mut KeyState,
        b: &mut Behaviour<'_>,
    ) -> Result<(), Error> {
        debug!("progress conn state {:?}", self.state);
        let mut resp = RespPackets::new();
        match self.state {
            ConnState::SendIdent => {
                traffic.send_version(ident::OUR_VERSION)?;
                let p = self.kex.make_kexinit(&self.algo_conf);
                // TODO: first_follows would have a second packet here
                resp.push(p.into()).trap()?;
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
                if traffic.can_output() {
                    if let ClientServer::Client(cli) = &mut self.cliserv {
                        cli.auth.start(&mut resp, b.client()?).await?;
                    }
                }
                // send userauth request
            }

            _ => {
                // TODO
            }
        }
        for r in resp {
            r.send_packet(traffic, keys)?;
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

    /// Consumes an input payload which is a view into [`traffic::Traffic::buf`].
    /// We queue response packets that can be sent (written into the same buffer)
    /// after `handle_payload()` runs.
    pub(crate) async fn handle_payload<'p>(
        &mut self, payload: &'p [u8], seq: u32,
        keys: &mut KeyState, b: &mut Behaviour<'_>,
    ) -> Result<Dispatched<'_>, Error> {
        let r = sshwire::packet_from_bytes(payload, &self.parse_ctx);
        match r {
            Ok(p) => self.dispatch_packet(p, keys, b).await,
            Err(Error::UnknownPacket { number }) => {
                trace!("Unimplemented packet type {number}");
                let p: Packet = packets::Unimplemented { seq }.into();
                let mut resp = RespPackets::new();
                // unwrap is OK, single packet has space
                resp.push(p.into()).unwrap();
                Ok(Dispatched { resp, event: None })
            }
            Err(e) => return Err(e),
        }
    }

    async fn dispatch_packet<'p>(
        &mut self, packet: Packet<'p>, keys: &mut KeyState, b: &mut Behaviour<'_>,
    ) -> Result<Dispatched<'_>, Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        trace!("Incoming {packet:#?}");
        let mut resp = RespPackets::new();
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
                    self.cliserv.is_client(),
                    &self.algo_conf,
                    &self.remote_version,
                    &packet,
                )?;
                if let Some(r) = r {
                    resp.push(r.into()).trap()?;
                }
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
                            *output = Some(kex.handle_kexdhinit(&p, &self.sess_id)?);
                            let reply = output.as_ref().trap()?.make_kexdhreply(&b.server()?)?;
                            resp.push(reply.into()).trap()?;
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
                                *output = Some(kex.handle_kexdhreply(&p, &self.sess_id, &mut b.client()?).await?);
                                resp.push(Packet::NewKeys(packets::NewKeys {}).into()).trap()?;
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
                        keys.rekey(output.keys);
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
                    cli.auth.failure(&p, &mut b.client()?, &mut resp, &mut self.parse_ctx).await?;
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
                        cli.auth_success(&mut resp, &mut self.parse_ctx, &mut b.client()?).await?;
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
                    cli.banner(&p, &mut b.client()?).await;
                } else {
                    debug!("Received banner as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::Userauth60(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.auth60(&p, &mut resp, self.sess_id.as_ref().trap()?, &mut self.parse_ctx).await?;
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
                let chev = self.channels.dispatch(packet, &mut resp, b).await?;
                event = chev.map(|c| EventMaker::Channel(c))
           }
        };
        Ok(Dispatched { resp, event })
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

// pub(crate) struct Dispatched<'r, 'e> {
//     pub resp: RespPackets<'r>,
//     pub event: Option<Event<'e>>,
// }

pub(crate) struct Dispatched<'r> {
    pub resp: RespPackets<'r>,
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

