// TODO: for fixed_ names, remove once they're removed
#![allow(non_upper_case_globals)]
#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::fmt;
use core::marker::PhantomData;

use rand::rngs::OsRng;
use sha2::Sha256;
use digest::Digest;

use crate::*;
use encrypt::{Cipher, Integ, Keys};
use ident::RemoteVersion;
use namelist::LocalNames;
use packets::{Packet, PubKey, Signature};
use sign::SigType;
use sshnames::*;
use wireformat::{hash_mpint, hash_ser, hash_ser_length, BinString, Blob};
use behaviour::{CliBehaviour, Behaviour, ServBehaviour};

// at present we only have curve25519 with sha256
const MAX_SESSID: usize = 32;
pub type SessId = heapless::Vec<u8, MAX_SESSID>;

// #[cfg(test)]
use pretty_hex::PrettyHex;

const EMPTY_LOCALNAMES: LocalNames = LocalNames(&[]);

// TODO this will be configurable.
const fixed_options_kex: LocalNames =
    LocalNames(&[SSH_NAME_CURVE25519, SSH_NAME_CURVE25519_LIBSSH]);
const fixed_options_hostsig: LocalNames = LocalNames(&[
    SSH_NAME_ED25519,
    #[cfg(alloc)]
    SSH_NAME_RSA_SHA256,
]);

const fixed_options_cipher: LocalNames =
    LocalNames(&[SSH_NAME_CHAPOLY, SSH_NAME_AES256_CTR]);
const fixed_options_mac: LocalNames = LocalNames(&[SSH_NAME_HMAC_SHA256]);
const fixed_options_comp: LocalNames = LocalNames(&[SSH_NAME_NONE]);

pub(crate) struct AlgoConfig<'a> {
    kexs: LocalNames<'a>,
    hostsig: LocalNames<'a>,
    ciphers: LocalNames<'a>,
    macs: LocalNames<'a>,
    comps: LocalNames<'a>,
}

impl<'a> AlgoConfig<'a> {
    /// Creates the standard algorithm configuration
    /// TODO: ext-info-s and ext-info-c
    pub fn new(_is_client: bool) -> Self {
        AlgoConfig {
            kexs: fixed_options_kex,
            hostsig: fixed_options_hostsig,
            ciphers: fixed_options_cipher,
            macs: fixed_options_mac,
            comps: fixed_options_comp,
        }
    }
}

pub(crate) struct Kex {
    // TODO: we could enum only keeping currently required fields.
    // To be done once the structure stabilises

    // Cookie sent in our KexInit packet. Kept so that we can reproduce the
    // KexInit packet when calculating the exchange hash.
    our_cookie: [u8; 16],

    // populated once we have sent and received KexInit
    algos: Option<Algos>,

    kex_hash: Option<KexHash>,
}

struct KexHash {
    // Could be made generic if we add other kex methods
    hash_ctx: Sha256,
}

// kexhash state. progessively include version idents, kexinit payloads, hostsig, e/f, secret
impl KexHash {
    fn new(
        kex: &Kex, algos: &Algos, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion, remote_kexinit: &packets::Packet,
    ) -> Result<Self> {
        // RFC4253 section 8:
        // The hash H is computed as the HASH hash of the concatenation of the
        // following:
        //    string    V_C, the client's identification string (CR and LF
        //              excluded)
        //    string    V_S, the server's identification string (CR and LF
        //              excluded)
        //    string    I_C, the payload of the client's SSH_MSG_KEXINIT
        //    string    I_S, the payload of the server's SSH_MSG_KEXINIT
        //    string    K_S, the host key
        //    mpint     e, exchange value sent by the client (aka q_c)
        //    mpint     f, exchange value sent by the server (aka q_s)
        //    mpint     K, the shared secret

        let mut kh = KexHash { hash_ctx: Sha256::new() };
        let remote_version = remote_version.version().trap()?;
        // Recreate our own kexinit packet to hash.
        let own_kexinit = kex.make_kexinit(algo_conf);
        if algos.is_client {
            kh.hash_slice(ident::OUR_VERSION);
            kh.hash_slice(remote_version);
            hash_ser_length(&mut kh.hash_ctx, &own_kexinit)?;
            hash_ser_length(&mut kh.hash_ctx, remote_kexinit)?;
        } else {
            kh.hash_slice(remote_version);
            kh.hash_slice(ident::OUR_VERSION);
            hash_ser_length(&mut kh.hash_ctx, remote_kexinit)?;
            hash_ser_length(&mut kh.hash_ctx, &own_kexinit)?
        }
        // The remainder of hash_ctx is updated after kexdhreply

        Ok(kh)
    }

    /// Fill everything except K.
    /// q_c and q_s need to be padded as mpint (extra 0x00 if high bit set)
    /// for ecdsa and DH modes, but not for curve25519.
    fn prefinish(&mut self, host_key: &PubKey, q_c: &[u8], q_s: &[u8]) -> Result<()> {
        hash_ser_length(&mut self.hash_ctx, host_key)?;
        self.hash_slice(q_c);
        self.hash_slice(q_s);
        Ok(())
    }

    /// Compute the remainder of the hash, consuming KexHash
    /// K should be provided as raw bytes, it will be padded as an mpint
    /// internally.
    fn finish(mut self, k: &[u8]) -> SessId {
        hash_mpint(&mut self.hash_ctx, k);
        // unwrap is OK, hash sized
        SessId::from_slice(&self.hash_ctx.finalize()).unwrap()
    }

    // Hashes a slice, with added u32 length prefix.
    fn hash_slice(&mut self, v: &[u8]) {
        self.hash_ctx.update(&(v.len() as u32).to_be_bytes());
        self.hash_ctx.update(v);
    }
}

/// Records the chosen algorithms while key exchange proceeds
#[derive(Debug)]
pub(crate) struct Algos {
    pub kex: SharedSecret,
    pub hostsig: SigType,
    pub cipher_enc: Cipher,
    pub cipher_dec: Cipher,
    pub integ_enc: Integ,
    pub integ_dec: Integ,

    // If first_kex_packet_follows was set in SSH_MSG_KEXINIT but the
    // guessed algorithms don't match, we discard the next message (RFC4253 Sec 7).
    // This flag is reset to `false` after the packet has been discarded.
    //
    // We allow it for client or server, though it doesn't make much sense
    // for a server to guess a kexdhreply message - the signature will be wrong.
    pub discard_next: bool,

    // avoid having to keep passing it separately, though this
    // is global state.
    pub is_client: bool,
}

impl fmt::Display for Algos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (cc, cs, mc, ms) = if self.is_client {
            (&self.cipher_enc, &self.cipher_dec, &self.integ_enc, &self.integ_dec)
        } else {
            (&self.cipher_dec, &self.cipher_enc, &self.integ_dec, &self.integ_enc)
        };

        write!(f, "Negotiated algorithms\nkex {}\nhostkey {}\ncipher c->s {}\ncipher s->c {}\nmac c->s {}\nmac s->c {}",
            self.kex, self.hostsig.algorithm_name(), cc, cs, mc, ms)
    }
}

impl Kex {
    pub fn new() -> Result<Self> {
        let mut our_cookie = [0u8; 16];
        random::fill_random(our_cookie.as_mut_slice())?;
        Ok(Kex { our_cookie, algos: None, kex_hash: None })
    }

    /// Returns `Option<Packet>` with an optional kexdhinit message to send
    pub fn handle_kexinit(
        &mut self, is_client: bool, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion, p: &packets::Packet,
    ) -> Result<Option<Packet>> {
        let remote_kexinit =
            if let Packet::KexInit(k) = p { k } else { return Err(Error::bug()) };
        let algos = Self::algo_negotiation(is_client, remote_kexinit, algo_conf)?;
        debug!("Negotiated algorithms {algos}");
        self.kex_hash =
            Some(KexHash::new(self, &algos, algo_conf, remote_version, p)?);
        self.algos = Some(algos);

        if is_client {
            Ok(Some(self.algos.as_ref().trap()?.kex.make_kexdhinit()?))
        } else {
            Ok(None)
        }
    }

    pub fn maybe_discard_packet(&mut self) -> bool {
        if let Some(ref mut a) = self.algos {
            core::mem::replace(&mut a.discard_next, false)
        } else {
            false
        }
    }

    pub fn make_kexinit<'a>(&self, conf: &'a AlgoConfig) -> packets::Packet<'a> {
        packets::KexInit {
            cookie: self.our_cookie,
            kex: (&conf.kexs).into(),
            hostkey: (&conf.hostsig).into(),
            cipher_c2s: (&conf.ciphers).into(),
            cipher_s2c: (&conf.ciphers).into(),
            mac_c2s: (&conf.macs).into(),
            mac_s2c: (&conf.macs).into(),
            comp_c2s: (&conf.comps).into(),
            comp_s2c: (&conf.comps).into(),
            lang_c2s: (&EMPTY_LOCALNAMES).into(),
            lang_s2c: (&EMPTY_LOCALNAMES).into(),
            first_follows: false,
            reserved: 0,
        }.into()
    }

    fn make_kexdhinit(&self) -> Result<Packet> {
        let algos = self.algos.as_ref().trap()?;
        if !algos.is_client {
            return Err(Error::bug());
        }
        algos.kex.make_kexdhinit()
    }

    // returns packet to send, and kex output
    // consumes self.
    pub fn handle_kexdhinit<'a>(
        self, p: &packets::KexDHInit, sess_id: &Option<SessId>,
    ) -> Result<KexOutput> {
        if self.algos.as_ref().trap()?.is_client {
            return Err(Error::bug());
        }
        SharedSecret::handle_kexdhinit(self, p, sess_id)
    }

    // returns packet to send, and H exchange hash.
    // consumes self.
    pub async fn handle_kexdhreply<'f>(
        self, p: &packets::KexDHReply<'f>, sess_id: &Option<SessId>,
        b: &mut CliBehaviour<'_>,
    ) -> Result<KexOutput> {
        if !self.algos.as_ref().trap()?.is_client {
            return Err(Error::bug());
        }
        SharedSecret::handle_kexdhreply(self, p, sess_id, b).await
    }

    /// Perform SSH algorithm negotiation
    fn algo_negotiation(
        is_client: bool, p: &packets::KexInit, conf: &AlgoConfig,
    ) -> Result<Algos> {
        let kexguess2 = p.kex.has_algo(SSH_NAME_KEXGUESS2)?;

        // For each algorithm we select the first name in the client's
        // list that is also present in the server's list.
        let kex_method = p
            .kex
            .first_match(is_client, &conf.kexs)?
            .ok_or(Error::AlgoNoMatch { algo: "kex" })?;
        if kex_method == SSH_NAME_KEXGUESS2 {
            trace!("kexguess2 was negotiated, returning AlgoNoMatch");
            return Err(Error::AlgoNoMatch { algo: "kex" });
        }
        let kex = SharedSecret::from_name(kex_method)?;
        let goodguess_kex = if kexguess2 {
            p.kex.first() == kex_method
        } else {
            p.kex.first() == conf.kexs.first()
        };

        let hostsig_method = p
            .hostkey
            .first_match(is_client, &conf.hostsig)?
            .ok_or(Error::AlgoNoMatch { algo: "hostkey" })?;
        let hostsig = SigType::from_name(hostsig_method)?;
        let goodguess_hostkey = if kexguess2 {
            p.hostkey.first() == hostsig_method
        } else {
            p.hostkey.first() == conf.hostsig.first()
        };

        // Switch between client/server tx/rx
        let c2s = (&p.cipher_c2s, &p.mac_c2s, &p.comp_c2s);
        let s2c = (&p.cipher_s2c, &p.mac_s2c, &p.comp_s2c);
        let ((cipher_tx, mac_tx, comp_tx), (cipher_rx, mac_rx, comp_rx)) =
            if is_client { (c2s, s2c) } else { (s2c, c2s) };

        let n = cipher_tx
            .first_match(is_client, &conf.ciphers)?
            .ok_or(Error::AlgoNoMatch { algo: "encryption" })?;
        let cipher_enc = Cipher::from_name(n)?;
        let n = cipher_rx
            .first_match(is_client, &conf.ciphers)?
            .ok_or(Error::AlgoNoMatch { algo: "encryption" })?;
        let cipher_dec = Cipher::from_name(n)?;

        // We ignore mac algorithms for AEAD ciphers
        let integ_enc = if let Some(integ) = cipher_enc.integ() {
            integ
        } else {
            let n = mac_tx
                .first_match(is_client, &conf.macs)?
                .ok_or(Error::AlgoNoMatch { algo: "mac" })?;
            Integ::from_name(n)?
        };
        let integ_dec = if let Some(integ) = cipher_dec.integ() {
            integ
        } else {
            let n = mac_rx
                .first_match(is_client, &conf.macs)?
                .ok_or(Error::AlgoNoMatch { algo: "mac" })?;
            Integ::from_name(n)?
        };

        // Compression only matches "none", we don't need further handling
        // at the moment.
        comp_tx
            .first_match(is_client, &conf.comps)?
            .ok_or(Error::AlgoNoMatch { algo: "compression" })?;
        comp_rx
            .first_match(is_client, &conf.comps)?
            .ok_or(Error::AlgoNoMatch { algo: "compression" })?;

        // Ignore language fields at present. Unsure which implementations
        // use it, possibly SunSSH

        let discard_next = p.first_follows && !(goodguess_kex && goodguess_hostkey);

        Ok(Algos {
            kex,
            hostsig,
            cipher_enc,
            cipher_dec,
            integ_enc,
            integ_dec,
            discard_next,
            is_client,
        })
    }
}

#[derive(Debug)]
pub(crate) enum SharedSecret {
    KexCurve25519(KexCurve25519),
    // ECDH?
}

impl fmt::Display for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::KexCurve25519(_) => SSH_NAME_CURVE25519
        };
        write!(f, "{n}")
    }
}

impl SharedSecret {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            SSH_NAME_CURVE25519 | SSH_NAME_CURVE25519_LIBSSH => {
                Ok(SharedSecret::KexCurve25519(KexCurve25519::new()?))
            }
            _ => Err(Error::bug()),
        }
    }

    pub(crate) fn hash(&self) -> Sha256 {
        match self {
            SharedSecret::KexCurve25519(_) => Sha256::new(),
        }
    }

    fn make_kexdhinit(&self) -> Result<Packet> {
        let q_c = self.pubkey();
        trace!("pubkey ours {:?}", self.pubkey().hex_dump());
        let q_c = BinString(q_c);
        Ok(packets::KexDHInit { q_c }.into())
    }

    // client only
    async fn handle_kexdhreply<'f>(
        mut kex: Kex, p: &packets::KexDHReply<'f>, sess_id: &Option<SessId>,
        b: &mut CliBehaviour<'_>
    ) -> Result<KexOutput> {
        // let mut algos = kex.algos.take().trap()?;
        let mut algos = kex.algos.trap()?;
        let mut kex_hash = kex.kex_hash.take().trap()?;
        kex_hash.prefinish(&p.k_s.0, algos.kex.pubkey(), p.q_s.0)?;
        // consumes the sharedsecret private key in algos
        let kex_out = match algos.kex {
            SharedSecret::KexCurve25519(_) => {
                KexCurve25519::secret(&mut algos, p.q_s.0, kex_hash, sess_id)?
            }
        };

        algos.hostsig.verify(&p.k_s.0, kex_out.h.as_ref(), &p.sig.0)?;
        debug!("Hostkey signature is valid");
        if matches!(b.valid_hostkey(&p.k_s.0).await, Ok(true)) {
            Ok(kex_out)
        } else {
            Err(Error::BehaviourError { msg: "Host key rejected" })
        }
    }

    // server only. consumes kex.
    fn handle_kexdhinit<'a>(
        mut kex: Kex, p: &packets::KexDHInit, sess_id: &Option<SessId>,
    ) -> Result<KexOutput> {
        // let mut algos = kex.algos.take().trap()?;
        let mut algos = kex.algos.trap()?;
        let mut kex_hash = kex.kex_hash.take().trap()?;
        // TODO
        let fake_hostkey = PubKey::Ed25519(packets::Ed25519PubKey{ key: BinString(&[]) });
        kex_hash.prefinish(&fake_hostkey, p.q_c.0, algos.kex.pubkey())?;
        let kex_out = match algos.kex {
            SharedSecret::KexCurve25519(ref k) => {
                let pubkey = (k.ours.as_ref().trap()?).into();
                let mut kex_out = KexCurve25519::secret(&mut algos, p.q_c.0, kex_hash, sess_id)?;
                kex_out.pubkey = Some(pubkey);
                kex_out
            }
        };

        Ok(kex_out)
    }

    fn pubkey<'a>(&'a self) -> &'a [u8] {
        match self {
            SharedSecret::KexCurve25519(k) => k.pubkey(),
        }
    }
}

pub(crate) struct KexOutput {
    pub h: SessId,
    pub keys: Keys,

    // storage for kex packet reply content that outlives Kex
    // TODO: this should become generic
    pubkey: Option<x25519_dalek::PublicKey>,
}

impl fmt::Debug for KexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KexOutput")
            .field("pubkey", &self.pubkey.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> KexOutput {
    fn make(
        k: &[u8], algos: &Algos, kex_hash: KexHash, sess_id: &Option<SessId>,
    ) -> Result<Self> {
        let h = kex_hash.finish(k);

        let sess_id = sess_id.as_ref().unwrap_or(&h);
        let keys = Keys::new_from(k, &h, &sess_id, algos)?;

        Ok(KexOutput { h, keys, pubkey: None })
    }

    // server only
    pub fn make_kexdhreply(&'a self) -> Result<Packet<'a>> {
        let q_s = BinString(self.pubkey.as_ref().trap()?.as_bytes());
        // TODO
        let k_s = Blob(PubKey::Ed25519(packets::Ed25519PubKey{ key: BinString(&[]) }));
        let sig = Blob(Signature::Ed25519(packets::Ed25519Sig{ sig: BinString(&[]) }));
        Ok(packets::KexDHReply { k_s, q_s, sig }.into())
        // then sign it.
    }
}

pub(crate) struct KexCurve25519 {
    ours: Option<x25519_dalek::EphemeralSecret>,
    pubkey: x25519_dalek::PublicKey,
}

impl core::fmt::Debug for KexCurve25519 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("KexCurve25519")
            .field("ours", &if self.ours.is_some() { "Some" } else { "None" })
            .field("pubkey", self.pubkey.as_bytes())
            .finish()
    }
}

impl KexCurve25519 {
    fn new() -> Result<Self> {
        let ours = x25519_dalek::EphemeralSecret::new(OsRng);
        let pubkey = (&ours).into();
        Ok(KexCurve25519 { ours: Some(ours), pubkey })
    }

    fn pubkey<'a>(&'a self) -> &'a [u8] {
        self.pubkey.as_bytes()
    }

    fn secret<'a>(
        algos: &mut Algos, theirs: &[u8], kex_hash: KexHash,
        sess_id: &Option<SessId>,
    ) -> Result<KexOutput> {
        #[warn(irrefutable_let_patterns)] // until we have other algos
        let kex = if let SharedSecret::KexCurve25519(k) = &mut algos.kex {
            k
        } else {
            return Err(Error::bug());
        };
        let ours = kex.ours.take().trap()?;
        let theirs: [u8; 32] = theirs.try_into().map_err(|_| Error::BadKex)?;
        let theirs = theirs.into();
        let shsec = ours.diffie_hellman(&theirs);
        KexOutput::make(shsec.as_bytes(), algos, kex_hash, sess_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt;
    use crate::error::Error;
    use crate::ident::RemoteVersion;
    use crate::kex;
    use crate::packets::{Packet,ParseContext};
    use crate::*;
    use crate::doorlog::init_test_log;
    use pretty_hex::PrettyHex;

    use super::SSH_NAME_CURVE25519;

    #[test]
    fn test_name_match() {
        // check that the from_name() functions are complete
        for k in kex::fixed_options_kex.0.iter() {
            kex::SharedSecret::from_name(k).unwrap();
        }
        for k in kex::fixed_options_hostsig.0.iter() {
            sign::SigType::from_name(k).unwrap();
        }
        for k in kex::fixed_options_cipher.0.iter() {
            encrypt::Cipher::from_name(k).unwrap();
        }
        for k in kex::fixed_options_mac.0.iter() {
            encrypt::Integ::from_name(k).unwrap();
        }
    }

    // Unknown names fail. This is easy to hit if the names of from_name()
    // match statements are mistyped or aren't imported.
    #[test]
    #[should_panic]
    fn test_unknown_kex() {
        kex::SharedSecret::from_name("bad").unwrap();
    }
    #[test]
    #[should_panic]
    fn test_unknown_sig() {
        sign::SigType::from_name("bad").unwrap();
    }
    #[test]
    #[should_panic]
    fn test_unknown_cipher() {
        encrypt::Cipher::from_name("bad").unwrap();
    }
    #[test]
    #[should_panic]
    fn test_unknown_integ() {
        encrypt::Integ::from_name("bad").unwrap();
    }

    /// Round trip a `Packet`
    fn reserialize<'a>(out_buf: &'a mut [u8], p: Packet, ctx: &ParseContext) -> Packet<'a> {
        wireformat::write_ssh(out_buf, &p).unwrap();
        wireformat::packet_from_bytes(out_buf, &ctx).unwrap()
    }

    #[test]
    fn test_agree_kex() {
        init_test_log();
        let mut bufc = [0u8; 1000];
        let mut bufs = [0u8; 1000];
        let cli_conf = kex::AlgoConfig::new(true);
        let serv_conf = kex::AlgoConfig::new(false);
        let mut serv_version = RemoteVersion::new();
        // needs to be hardcoded because that's what we send.
        serv_version.consume("SSH-2.0-door\r\n".as_bytes()).unwrap();
        let mut cli_version = RemoteVersion::new();
        cli_version.consume("SSH-2.0-door\r\n".as_bytes()).unwrap();

        let mut cli = kex::Kex::new().unwrap();
        let mut serv = kex::Kex::new().unwrap();

        // reserialize so we end up with NameList::String not Local
        let ctx = ParseContext::new();
        let si = serv.make_kexinit(&serv_conf);
        let si = reserialize(&mut bufs, si, &ctx);
        let ci = cli.make_kexinit(&cli_conf);
        let ci = reserialize(&mut bufc, ci, &ctx);

        serv.handle_kexinit(false, &serv_conf, &cli_version, &ci).unwrap();
        cli.handle_kexinit(true, &cli_conf, &serv_version, &si).unwrap();

        let ci = cli.make_kexdhinit().unwrap();
        let ci = if let Packet::KexDHInit(k) = ci { k } else { panic!() };
        let sout = serv.handle_kexdhinit(&ci, &None).unwrap();
        let kexreply = sout.make_kexdhreply().unwrap();

        let kexreply =
            if let Packet::KexDHReply(k) = kexreply { k } else { panic!() };
        // TODO need host signatures for it to succeed
        // let cout = cli.handle_kexdhreply(&kexreply, &None).unwrap();

        // assert_eq!(cout.h.as_ref(), sout.h.as_ref());
    }
}
