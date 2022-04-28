#[allow(unused_imports)]
use {
    crate::error::{Error,TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use std::char::MAX;

use ring::digest::Digest;
use heapless::Vec;

use crate::*;
use encrypt::KeyState;
use packets::Packet;
use traffic::Traffic;
use client::Client;
use server::Server;
use crate::sshnames::*;

const MAX_RESPONSES: usize = 4;
pub(crate) type RespPackets<'a> = Vec<Packet<'a>, MAX_RESPONSES>;

pub struct Runner<'a> {
    conn: Conn<'a>,

    /// Binary packet handling
    traffic: Traffic<'a>,

    /// Current encryption/integrity keys
    keys: KeyState,
}

impl<'a> Runner<'a> {
    /// [`iobuf`] must be sized to fit the largest SSH packet allowed.
    pub fn new(conn: Conn<'a>, iobuf: &'a mut [u8]) -> Result<Self, Error> {
        let mut runner = Runner { conn,
            traffic: traffic::Traffic::new(iobuf),
            keys: KeyState::new_cleartext(),
             };

        let resp = runner.conn.progress(&mut runner.traffic, &mut runner.keys)?;
        for r in resp {
            runner.traffic.send_packet(&r, &mut runner.keys)?;
        }
        Ok(runner)
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let (size, payload) = self.traffic.input(
            &mut self.keys,
            &mut self.conn.remote_version,
            buf,
        )?;
        if let Some(payload) = payload {
            let resp = self.conn.handle_payload(payload, &mut self.keys)?;
            for r in resp {
                self.traffic.send_packet(&r, &mut self.keys)?;
            }
        }
        let resp = self.conn.progress(&mut self.traffic, &mut self.keys)?;
        for r in resp {
            self.traffic.send_packet(&r, &mut self.keys)?;
        }
        Ok(size)
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let l = self.traffic.output(buf)?;
        let resp = self.conn.progress(&mut self.traffic, &mut self.keys)?;
        for r in resp {
            self.traffic.send_packet(&r, &mut self.keys)?;
        }
        Ok(l)
    }

    pub fn ready_input(&self) -> bool {
        self.traffic.ready_input()
    }

    pub fn output_pending(&self) -> bool {
        self.traffic.output_pending()
    }
}

/// The core state of a SSH instance.
pub struct Conn<'a> {
    state: ConnState,

    /// Next kex to run
    kex: kex::Kex,

    /// TODO: Digest is sized to fit 512 bits, we only need 256 for sha256.
    /// Perhaps we could put it into a [u8: 256] newtype.
    sess_id: Option<Digest>,

    cliserv: ClientServer<'a>,

    algo_conf: kex::AlgoConfig<'a>,

    /// Remote version string. Kept for later kexinit rekeying
    remote_version: ident::RemoteVersion,
}

// TODO: what tricks can we do to optimise away client or server code if we only
// want one of them?
enum ClientServer<'a> {
    Client(client::Client<'a>),
    Server(server::Server),
}

impl<'a> ClientServer<'a> {
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
    InKex { done_auth: bool, output: Option<kex::KexOutput> },

    /// After first NewKeys, prior to auth success. 
    PreAuth,
    /// After auth success
    Authed,
    // Cleanup ??
}

impl<'a> Conn<'a> {
    pub fn new() -> Result<Self, Error> {
        let cliserv = ClientServer::Client(Client::new());
        Ok(Conn {
            kex: kex::Kex::new()?,
            sess_id: None,
            remote_version: ident::RemoteVersion::new(),
            state: ConnState::SendIdent,
            algo_conf: kex::AlgoConfig::new(cliserv.is_client()),
            cliserv,
        })
    }

    fn progress(&mut self, traffic: &mut Traffic, keys: &mut KeyState) -> Result<RespPackets, Error> {
        trace!("conn state {:?}", self.state);
        let mut resp = RespPackets::new();
        match self.state {
            ConnState::SendIdent => {
                traffic.send_version(ident::OUR_VERSION)?;
                let p = self.kex.make_kexinit(&self.algo_conf);
                traffic.send_packet(&p, keys)?;
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
                    if let ClientServer::Client(c) = &mut self.cliserv {
                        c.auth.start(&mut resp)?;
                    }
                }
                // send userauth request
            }

            _ => {
                // TODO
            }
        }

        // TODO: if keys.seq > MAX_REKEY then we must rekey for security.

        Ok(resp)
    }

    /// Consumes an input payload
    pub(crate) fn handle_payload(
        &mut self, payload: &[u8], keys: &mut KeyState,
    ) -> Result<RespPackets, Error> {
        trace!("conn state {:?}", self.state);
        // self.keys.next_seq_decrypt();
        let p = wireformat::packet_from_bytes(payload)?;
        self.dispatch_packet(&p, keys)
    }

    fn dispatch_packet(&mut self, packet: &Packet, keys: &mut KeyState)
            -> Result<RespPackets, Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        let mut resp = Vec::new();
        match packet {
            Packet::KexInit(_) => {
                if matches!(self.state, ConnState::InKex { .. }) {
                    return Err(Error::PacketWrong);
                }
                self.state = ConnState::InKex {
                    done_auth: matches!(self.state, ConnState::Authed),
                    output: None,
                };
                let r = self.kex
                    .handle_kexinit(
                        self.cliserv.is_client(),
                        &self.algo_conf,
                        &self.remote_version,
                        packet,
                    )?;
                if let Some(r) = r {
                    resp.push(r).trap()?;
                }
                Ok(resp)
            }
            Packet::KexDHInit(p) => {
                match self.state {
                    ConnState::InKex { done_auth: _, ref mut output } => {
                        if self.cliserv.is_client() {
                            // TODO: client/server validity checks should move somewhere more general
                            return Err(Error::SSHProtoError);
                        }
                        if self.kex.maybe_discard_packet() {
                            Ok(resp)
                        } else {
                            let kex = core::mem::replace(&mut self.kex, kex::Kex::new()?);
                            *output = Some(kex.handle_kexdhinit(p, &self.sess_id)?);
                            let reply = output.as_ref().trap()?.make_kexdhreply()?;
                            resp.push(reply).trap()?;
                            Ok(resp)
                        }
                    }
                    _ => Err(Error::PacketWrong)
                }
            }
            Packet::KexDHReply(p) => {
                match self.state {
                    ConnState::InKex { done_auth: _, ref mut output } => {
                        if !self.cliserv.is_client() {
                            // TODO: client/server validity checks should move somewhere more general
                            return Err(Error::SSHProtoError);
                        }
                        if self.kex.maybe_discard_packet() {
                            Ok(resp)
                        } else {
                            let kex = core::mem::replace(&mut self.kex, kex::Kex::new()?);
                            *output = Some(kex.handle_kexdhreply(p, &self.sess_id)?);
                            resp.push(Packet::NewKeys(packets::NewKeys{})).trap()?;
                            Ok(resp)
                        }
                    }
                    _ => Err(Error::PacketWrong)
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
                        Ok(resp)
                    },
                    _ => Err(Error::PacketWrong)
                }
            }
            Packet::ServiceAccept(p) => {
                // Don't need to do anything, if a request failed the server disconnects
                trace!("Received service accept {}", p.name);
                Ok(resp)
            }
            Packet::Ignore(_) => {
                Ok(resp)
            }
            Packet::Unimplemented(_) => {
                warn!("Received SSH unimplemented message");
                Ok(resp)
            }
            Packet::Debug(p) => {
                warn!("SSH debug message from remote host: '{}'", p.message.escape_default());
                Ok(resp)
            }
            Packet::Disconnect(p) => {
                // TODO: SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                info!("Received disconnect: {}", p.desc.escape_default());
                Ok(resp)
            }
            Packet::Disconnect(p) => {
                // TODO: SSH2_DISCONNECT_BY_APPLICATION is normal, sent by openssh client.
                info!("Received disconnect: {}", p.desc.escape_default());
                Ok(resp)
            }
            Packet::ServiceRequest(p) => {
                // TODO: this is server only
                todo!("service request");
                Ok(resp)
            }
            Packet::UserauthRequest(p) => {
                // TODO: this is server only
                todo!("userauth request");
                Ok(resp)
            }
            Packet::UserauthFailure(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.failure(p)?;
                    Ok(resp)
                } else {
                    debug!("Received UserauthFailure as a server");
                    Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthSuccess(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.auth.success(p)?;
                    Ok(resp)
                } else {
                    debug!("Received UserauthSuccess as a server");
                    Err(Error::SSHProtoError)
                }
            }
            Packet::UserauthBanner(p) => {
                // TODO: client only
                if let ClientServer::Client(cli) = &mut self.cliserv {
                    cli.banner(p);
                    Ok(resp)
                } else {
                    debug!("Received banner as a server");
                    Err(Error::SSHProtoError)
                }
            }
        }
    }
}
