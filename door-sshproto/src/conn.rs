#[allow(unused_imports)]
use {
    crate::error::Error,
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
    pub fn new(conn: Conn<'a>, iobuf: &'a mut [u8]) -> Self {
        Runner {
            conn,
            traffic: traffic::Traffic::new(iobuf),
        }
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let (size, payload) = self.traffic.input(&mut self.conn.keys, &mut self.conn.remote_version, buf)?;
        if let Some(payload) = payload {
            if matches!(self.conn.state, ConnState::Ident) {
                self.conn.state = ConnState::PreKex;
            }
            self.conn.handle_payload(payload)?
        }
        Ok(size)
    }

}

/// The core state of a SSH instance.
pub struct Conn<'a> {
    state: ConnState,

    /// In-progress kex state
    kex: Option<kex::Kex>,

    /// Current encryption/integrity keys
    keys: KeyState,

    /// TODO: Digest is sized to fit 512 bits, we only need 256 for ours currently?
    sess_id: Option<Digest>,

    pub(crate) is_client: bool,

    pub(crate) algo_conf: kex::AlgoConfig<'a>,

    /// Remote version string. Kept for later kexinit rekeying
    pub(crate) remote_version: ident::RemoteVersion,

    parse_ctx: packets::ParseContext,
}

enum ConnState {
    /// Prior to SSH binary packet protocol, receiving remote version identification
    Ident,
    /// Binary packet protocol has started, KexInit not yet received
    PreKex,
    /// At any time between receiving KexInit and NewKeys. Can occur multiple times
    /// at later key exchanges
    InKex,
    /// After first NewKeys, prior to auth success
    PreAuth,
    /// After auth success
    Auth,
    // Cleanup ??
}

impl<'a> Conn<'a> {
    /// [`iobuf`] must be sized to fit the largest SSH packet allowed
    pub fn new() -> Self {
        let is_client = true; // TODO= true;
        Conn {
            kex: None,
            keys: KeyState::new_cleartext(),
            sess_id: None,
            remote_version: ident::RemoteVersion::new(),
            parse_ctx: packets::ParseContext::new(),
            state: ConnState::Ident,
            algo_conf: kex::AlgoConfig::new(is_client),
            is_client,
        }
    }

    /// Consumes an input payload
    pub(crate) fn handle_payload(&mut self, payload: &[u8]) -> Result<(), Error> {
        if matches!(self.state, ConnState::Ident) {
            return Err(Error::Bug);
        }
        self.keys.next_seq_decrypt();
        trace!("bef");
        let p = wireformat::packet_from_bytes(payload, &self.parse_ctx)?;
        trace!("handle_payload() got {p:#?}");
        self.dispatch_packet(&p)?;
        Ok(())
    }

    fn dispatch_packet(&mut self, packet: &Packet) -> Result<(), Error> {
        // TODO: perhaps could consolidate packet allowed checks into a separate function
        // to run first?
        match packet {
            Packet::KexInit(p) => {
                if matches!(self.state, ConnState::InKex) {
                    return Err(Error::PacketWrong);
                }
                self.kex.get_or_insert_with(kex::Kex::new).handle_kexinit(
                    self.is_client,
                    &self.algo_conf,
                    &self.remote_version,
                    p,
                )
            }
            p => {
                warn!("Unhandled packet {p:?}");
                Err(Error::UnknownPacket)
            }
        }
    }
}
