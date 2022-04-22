#[allow(unused_imports)]
use {
    crate::error::{Error,TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use ring::digest::Digest;

use crate::*;
use encrypt::KeyState;
use packets::Packet;
use traffic::Traffic;

pub struct Runner<'a> {
    conn: Conn<'a>,
    /// Binary packet handling
    traffic: Traffic<'a>,
}

impl<'a> Runner<'a> {
    pub fn new(conn: Conn<'a>, iobuf: &'a mut [u8]) -> Result<Self, Error> {
        let mut r = Runner { conn, traffic: traffic::Traffic::new(iobuf) };

        r.conn.progress(&mut r.traffic);
        Ok(r)
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        trace!("input of {}", buf.len());
        let (size, payload) = self.traffic.input(
            &mut self.conn.keys,
            &mut self.conn.remote_version,
            buf,
        )?;
        trace!("input handled {size} of {}", buf.len());

        if let Some(payload) = payload {
            let resp = self.conn.handle_payload(payload)?;
            if let Some(r) = resp {
                self.traffic.send_packet(&r)?;
            }
        }
        self.conn.progress(&mut self.traffic);
        Ok(size)
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let l = self.traffic.output(&mut self.conn.keys, buf)?;
        self.conn.progress(&mut self.traffic);
        Ok(l)
    }

    pub fn ready_input(&self) -> bool {
        self.traffic.ready_input()
    }

    pub fn ready_output(&self) -> bool {
        self.traffic.ready_output()
    }
}

/// The core state of a SSH instance.
pub struct Conn<'a> {
    state: ConnState,

    /// next kex to run
    kex: kex::Kex,

    /// Current encryption/integrity keys
    keys: KeyState,

    /// TODO: Digest is sized to fit 512 bits, we only need 256 for sha256.
    /// Perhaps we could put it into a [u8: 256] newtype.
    sess_id: Option<Digest>,

    pub(crate) is_client: bool,

    pub(crate) algo_conf: kex::AlgoConfig<'a>,

    /// Remote version string. Kept for later kexinit rekeying
    pub(crate) remote_version: ident::RemoteVersion,
}

#[derive(Debug)]
enum ConnState {
    SendIdent,
    SendKexInit,
    /// Prior to SSH binary packet protocol, receiving remote version identification
    ReceiveIdent,
    /// Binary packet protocol has started, KexInit not yet received
    PreKex,
    /// At any time between receiving KexInit and NewKeys. Can occur multiple times
    /// at later key exchanges
    InKex { output: Option<kex::KexOutput> },

    /// After first NewKeys, prior to auth success
    PreAuth,
    /// After auth success
    Auth,
    // Cleanup ??
}

impl<'a> Conn<'a> {
    /// [`iobuf`] must be sized to fit the largest SSH packet allowed
    pub fn new() -> Result<Self, Error> {
        let is_client = true; // TODO= true;
        Ok(Conn {
            kex: kex::Kex::new()?,
            keys: KeyState::new_cleartext(),
            sess_id: None,
            remote_version: ident::RemoteVersion::new(),
            state: ConnState::SendIdent,
            algo_conf: kex::AlgoConfig::new(is_client),
            is_client,
        })
    }

    fn progress(&mut self, traffic: &mut Traffic) -> Result<(), Error> {
        trace!("conn state {:?}", self.state);
        match self.state {
            ConnState::SendIdent => {
                traffic.send_version(ident::OUR_VERSION)?;
                self.state = ConnState::SendKexInit
            }
            ConnState::SendKexInit => {
                let p = self.kex.make_kexinit(&self.algo_conf);
                traffic.send_packet(&p)?;
                self.state = ConnState::ReceiveIdent;
            }
            ConnState::ReceiveIdent => {
                if self.remote_version.version().is_some() {
                    self.state = ConnState::PreKex;
                }
            }
            _ => {
                // TODO
            }
        }
        Ok(())
    }

    /// Consumes an input payload
    pub(crate) fn handle_payload(
        &mut self, payload: &[u8],
    ) -> Result<Option<Packet>, Error> {
        trace!("conn state {:?}", self.state);
        // self.keys.next_seq_decrypt();
        trace!("bef");
        let p = wireformat::packet_from_bytes(payload)?;
        trace!("handle_payload() got {p:#?}");
        self.dispatch_packet(&p)
    }

    fn dispatch_packet(&mut self, packet: &Packet) -> Result<Option<Packet>, Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        match packet {
            Packet::KexInit(p) => {
                if matches!(self.state, ConnState::InKex { .. }) {
                    return Err(Error::PacketWrong);
                }
                self.state = ConnState::InKex { output: None };
                self.kex
                    .handle_kexinit(
                        self.is_client,
                        &self.algo_conf,
                        &self.remote_version,
                        packet,
                    )
            }
            Packet::KexDHInit(p) => {
                match self.state {
                    ConnState::InKex { ref mut output } => {
                        if self.is_client {
                            // TODO: client/server validity checks should move somewhere more general
                            return Err(Error::SSHProtoError);
                        }
                        let kex = core::mem::replace(&mut self.kex, kex::Kex::new()?);
                        *output = Some(kex.handle_kexdhinit(p, &self.sess_id)?);
                        let reply = output.as_ref().trap()?.make_kexdhreply()?;
                        Ok(Some(reply))
                    }
                    _ => Err(Error::PacketWrong)
                }
            }
            Packet::KexDHReply(p) => {
                match self.state {
                    ConnState::InKex { ref mut output } => {
                        if !self.is_client {
                            // TODO: client/server validity checks should move somewhere more general
                            return Err(Error::SSHProtoError);
                        }
                        let kex = core::mem::replace(&mut self.kex, kex::Kex::new()?);
                        *output = Some(kex.handle_kexdhreply(p, &self.sess_id)?);
                        trace!("after reply");
                        Ok(None)
                    }
                    _ => Err(Error::PacketWrong)
                }
            }
            p => {
                warn!("Unhandled packet {p:?}");
                Err(Error::UnknownPacket)
            }
        }
    }
}
