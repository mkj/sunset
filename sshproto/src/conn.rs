#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::char::MAX;
use core::task::{Waker,Poll};

use ring::digest::Digest;
use pretty_hex::PrettyHex;

use heapless::Vec;

use crate::sshnames::*;
use crate::*;
use client::Client;
use encrypt::KeyState;
use packets::{Packet,ParseContext};
use server::Server;
use traffic::{Traffic,PacketMaker};
use channel::{Channel, Channels};
use config::MAX_CHANNELS;
use mailbox::Mailbox;

// TODO a max value needs to be analysed
pub(crate) const MAX_RESPONSES: usize = 4;

pub(crate) type RespPackets<'a> = heapless::Vec<PacketMaker<'a>, MAX_RESPONSES>;

/// The core state of a SSH instance.
pub struct Conn<'a> {
    state: ConnState,

    /// Next kex to run
    kex: kex::Kex,

    /// TODO: Digest is sized to fit 512 bits, we only need 256 for sha256.
    /// Perhaps we could put it into a [u8: 256] newtype.
    sess_id: Option<Digest>,

    cliserv: ClientServer,

    algo_conf: kex::AlgoConfig<'a>,

    /// Remote version string. Kept for later kexinit rekeying
    pub(crate) remote_version: ident::RemoteVersion,

    channels: Channels,
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
    /// Can occur multiple times during a session, at later key exchanges
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

impl<'a> Conn<'a> {
    pub fn new_client(client: client::Client) -> Result<Self> {
        Self::new(ClientServer::Client(client))
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
        })
    }

    /// Updates `ConnState` and sends any packets required to progress the connection state.
    pub(crate) async fn progress<'b>(
        &mut self, traffic: &mut Traffic<'b>, keys: &mut KeyState,
        b: &mut Behaviour,
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
                // and backpressure.
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
    pub(crate) async fn handle_payload(
        &mut self, payload: &[u8], keys: &mut KeyState, b: &mut Behaviour
    ) -> Result<RespPackets<'_>, Error> {
        trace!("conn state {:?}", self.state);
        let ctx = ParseContext::new();
        let p = wireformat::packet_from_bytes(payload, &ctx)?;
        self.dispatch_packet(&p, keys, b).await
    }

    async fn dispatch_packet(
        &mut self, packet: &Packet<'_>, keys: &mut KeyState, b: &mut Behaviour
    ) -> Result<RespPackets<'_>, Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        trace!("Incoming {packet:#?}");
        let mut resp = RespPackets::new();
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
                    packet,
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
                            *output = Some(kex.handle_kexdhinit(p, &self.sess_id)?);
                            let reply = output.as_ref().trap()?.make_kexdhreply()?;
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
                                *output = Some(kex.handle_kexdhreply(p, &self.sess_id, &mut b.client()?).await?);
                                resp.push(Packet::NewKeys(packets::NewKeys {}).into())
                                    .trap()?;
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
                warn!(
                    "SSH debug message from remote host: '{}'",
                    p.message.escape_default()
                );
            }
            Packet::Disconnect(p) => {
                // TODO: SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                info!("Received disconnect: {}", p.desc.escape_default());
            }
            Packet::UserauthRequest(_p) => {
                // TODO: this is server only
                todo!("userauth request");
            }
            Packet::UserauthFailure(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.failure(p, &mut b.client()?, &mut resp).await?;
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
                        cli.auth_success(&mut resp, &mut b.client()?).await?;
                        // if h.open_session {
                        //     let (chan, p) = self.channels.open(
                        //         packets::ChannelOpenType::Session)?;
                        //     resp.push(p).trap()?;
                        //     if h.pty {
                        //         todo!();
                        //     }
                        // }
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
                    cli.banner(p, &mut b.client()?).await;
                } else {
                    debug!("Received banner as a server");
                    return Err(Error::SSHProtoError)
                }
            }
            Packet::Userauth60(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    todo!();
                } else {
                    debug!("Received banner as a server");
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
            // TODO: probably needs a conn or cliserv argument.
            => self.channels.dispatch(packet)?,
        };
        Ok(resp)
    }
}
