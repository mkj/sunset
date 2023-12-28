// TODO: for fixed_ names, remove once they're removed
#![allow(non_upper_case_globals)]
#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::fmt;

use sha2::Sha256;
use digest::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, CryptoRng, OsRng};

use crate::*;
use encrypt::{Cipher, Integ, Keys};
use ident::RemoteVersion;
use traffic::TrafSend;
use namelist::{NameList,LocalNames};
use packets::{Packet, PubKey, Signature};
use sign::SigType;
use sshnames::*;
use sshwire::{hash_mpint, BinString, Blob};
use sshwire::{hash_ser, hash_ser_length};
use behaviour::{CliBehaviour, Behaviour, ServBehaviour};

// at present we only have curve25519 with sha256
const MAX_SESSID: usize = 32;
pub type SessId = heapless::Vec<u8, MAX_SESSID>;

use pretty_hex::PrettyHex;

// TODO this will be configurable.
const fixed_options_kex: &[&str] =
    &[SSH_NAME_CURVE25519, SSH_NAME_CURVE25519_LIBSSH];

/// Options that can't be negotiated
const marker_only_kexs: &[&str] =
    &[SSH_NAME_EXT_INFO_C, SSH_NAME_EXT_INFO_S, SSH_NAME_KEXGUESS2,
    SSH_NAME_STRICT_KEX_C, SSH_NAME_STRICT_KEX_S];

const fixed_options_hostsig: &[&str] = &[
    SSH_NAME_ED25519,
    #[cfg(feature = "rsa")]
    SSH_NAME_RSA_SHA256,
];

const fixed_options_cipher: &[&str] =
    &[SSH_NAME_CHAPOLY, SSH_NAME_AES256_CTR];
const fixed_options_mac: &[&str] = &[SSH_NAME_HMAC_SHA256];
const fixed_options_comp: &[&str] = &[SSH_NAME_NONE];

pub(crate) struct AlgoConfig {
    kexs: LocalNames,
    hostsig: LocalNames,
    ciphers: LocalNames,
    macs: LocalNames,
    comps: LocalNames,
}

impl AlgoConfig {
    /// Creates the standard algorithm configuration
    /// TODO: ext-info-s and ext-info-c
    pub fn new(is_client: bool) -> Self {
        // OK unwrap: static arrays are < MAX_LOCAL_NAMES
        let mut kexs: LocalNames = fixed_options_kex.try_into().unwrap();

        // Only clients are interested in ext-info
        // TODO perhaps it could go behind cfg rsa?
        if is_client {
            // OK unwrap: static arrays are <= MAX_LOCAL_NAMES
            kexs.0.push(SSH_NAME_EXT_INFO_C).unwrap();
            kexs.0.push(SSH_NAME_STRICT_KEX_C).unwrap();
        } else {
            kexs.0.push(SSH_NAME_STRICT_KEX_S).unwrap();
        }

        // OK unwrap: static arrays are <= MAX_LOCAL_NAMES
        kexs.0.push(SSH_NAME_KEXGUESS2).unwrap();

        AlgoConfig {
            kexs,
            hostsig: fixed_options_hostsig.try_into().unwrap(),
            ciphers: fixed_options_cipher.try_into().unwrap(),
            macs: fixed_options_mac.try_into().unwrap(),
            comps: fixed_options_comp.try_into().unwrap(),
        }
    }
}


/// The current state of the Kex
#[derive(Debug)]
pub(crate) enum Kex {
    /// No key exchange in progress
    Idle,

    /// Waiting for a KexInit packet, have sent one.
    KexInit {
        // Cookie sent in our KexInit packet. Kept so that we can reproduce the
        // KexInit packet when calculating the exchange hash.
        our_cookie: KexCookie,
    },
    /// Waiting for KexDHInit (server) or KexDHReply (client)
    KexDH {
        algos: Algos,
        kex_hash: KexHash,
    },
    /// Waiting for NewKeys. `output` is new keys to take into use
    NewKeys {
        output: KexOutput,
        algos: Algos,
    },

    /// A transient state use internally to transition between other states.
    ///
    /// Returned from .take()
    /// Should only ever occur while inside a method call, a proper state
    /// will be set before returning. (Could remain set if an error occurs,
    /// but an error returned from Kex is not recoverable anyway).
    Taken,
}

type KexCookie = [u8; 16];

#[derive(Debug)]
pub(crate) struct KexHash {
    // Could be made generic if we add other kex methods
    hash_ctx: Sha256,
}

// kexhash state. progessively include version idents, kexinit payloads, hostsig, e/f, secret
impl KexHash {
    fn new(
        algos: &Algos, algo_conf: &AlgoConfig, our_cookie: &KexCookie,
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
        let own_kexinit = Kex::make_kexinit(our_cookie, algo_conf);
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
    fn prefinish(&mut self, host_key: &PubKey, q_c: &[u8], q_s: &[u8]) -> Result<()> {
        hash_ser_length(&mut self.hash_ctx, host_key)?;

        // TODO: q_c and q_s need to be padded as mpint (extra 0x00 if high bit set)
        // for ecdsa and DH modes, but not for curve25519.

        // A hacky sanity check that this is curve25519
        debug_assert_eq!(q_c.len(), 32);

        self.hash_slice(q_c);
        self.hash_slice(q_s);
        Ok(())
    }

    /// Compute the remainder of the hash, consuming KexHash
    /// K should be provided as raw bytes, it will be padded as an mpint
    /// internally.
    fn finish(mut self, k: &[u8]) -> SessId {
        hash_mpint(&mut self.hash_ctx, k);
        // OK unwrap, hash sized
        SessId::from_slice(&self.hash_ctx.finalize()).unwrap()
    }

    // Hashes a slice, with added u32 length prefix.
    fn hash_slice(&mut self, v: &[u8]) {
        self.hash_ctx.update((v.len() as u32).to_be_bytes());
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

    // whether the remote side supports ext-info
    pub send_ext_info: bool,

    // whether the remote side supports strict kex. will be ignored
    // for non-first KEX
    pub strict_kex: bool,
}

impl fmt::Display for Algos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (cc, cs, mc, ms) = if self.is_client {
            (&self.cipher_enc, &self.cipher_dec, &self.integ_enc, &self.integ_dec)
        } else {
            (&self.cipher_dec, &self.cipher_enc, &self.integ_dec, &self.integ_enc)
        };

        write!(f, "Negotiated algorithms {{\nkex {}\nhostkey {}\ncipher c->s {}\ncipher s->c {}\nmac c->s {}\nmac s->c {}\n}}",
            self.kex, self.hostsig.algorithm_name(), cc, cs, mc, ms)
    }
}

impl Kex {
    pub fn new() -> Self {
        Kex::Idle
    }

    fn take(&mut self) -> Self {
        debug_assert!(!matches!(self, Kex::Taken));
        core::mem::replace(self, Kex::Taken)
    }

    /// Sends a `KexInit` message. Must be called from `Idle` state
    pub fn send_kexinit(&mut self, conf: &AlgoConfig, s: &mut TrafSend) -> Result<()> {
        if !matches!(self, Kex::Idle) {
            return Err(Error::bug());
        }
        let mut our_cookie = [0u8; 16];
        random::fill_random(our_cookie.as_mut_slice())?;
        s.send(Kex::make_kexinit(&our_cookie, conf))?;
        *self = Kex::KexInit { our_cookie };
        Ok(())
    }

    pub fn handle_kexinit(
        &mut self, remote_kexinit: packets::KexInit, is_client: bool, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion,
        first_kex: bool,
        s: &mut TrafSend,
    ) -> Result<()> {
        // Reply if we haven't already received one. This will bump the state to Kex::KexInit
        if let Kex::Idle = self {
            self.send_kexinit(algo_conf, s)?;
        }

        let our_cookie = if let Kex::KexInit { ref our_cookie } = self {
            our_cookie
        } else {
            // already received a KexInit
            return error::PacketWrong.fail();
        };

        let algos = Self::algo_negotiation(is_client, &remote_kexinit, algo_conf)?;
        debug!("{algos}");

        if first_kex && algos.strict_kex {
            if s.recv_seq() != 1 {
                debug!("kexinit has strict kex but wasn't first packet");
                return error::PacketWrong.fail();
            }
        }
        if is_client {
            let p = algos.kex.make_kexdhinit()?;
            s.send(p)?;
        }
        let kex_hash = KexHash::new(&algos, algo_conf, our_cookie, remote_version, &remote_kexinit.into())?;
        *self = Kex::KexDH {
            algos,
            kex_hash
        };
        Ok(())
    }

    fn make_kexinit<'a>(cookie: &'a KexCookie, conf: &'a AlgoConfig) -> Packet<'a> {
        packets::KexInit {
            cookie,
            kex: (&conf.kexs).into(),
            hostsig: (&conf.hostsig).into(),
            cipher_c2s: (&conf.ciphers).into(),
            cipher_s2c: (&conf.ciphers).into(),
            mac_c2s: (&conf.macs).into(),
            mac_s2c: (&conf.macs).into(),
            comp_c2s: (&conf.comps).into(),
            comp_s2c: (&conf.comps).into(),
            lang_c2s: NameList::empty(),
            lang_s2c: NameList::empty(),
            first_follows: false,
            reserved: 0,
        }.into()
    }

    pub fn handle_kexdhinit(
        &mut self, p: &packets::KexDHInit,
        s: &mut TrafSend, b: &mut impl ServBehaviour,
    ) -> Result<()> {
        if let Kex::KexDH { algos, ..} = self {
            if algos.is_client {
                return Err(Error::bug());
            }

            if algos.discard_next {
                algos.discard_next = false;
                // Ignore this packet
                return Ok(())
            }
        }

        if let Kex::KexDH { mut algos, kex_hash } = self.take() {
            let output = SharedSecret::handle_kexdhinit(&mut algos, kex_hash, p, s, b)?;
            *self = Kex::NewKeys { output, algos };
            s.send(packets::NewKeys {})?;
            Ok(())
        } else {
            error::PacketWrong.fail()
        }
    }

    pub async fn handle_kexdhreply<'f>(
        &mut self, p: &packets::KexDHReply<'f>,
        s: &mut TrafSend<'_, '_>,
        b: &mut impl CliBehaviour,
        first_kex: bool,
    ) -> Result<()> {
        if let Kex::KexDH { algos, ..} = self {
            if !algos.is_client {
                return Err(Error::bug());
            }

            if algos.discard_next {
                algos.discard_next = false;
                // Ignore this packet
                return Ok(())
            }
        }

        if let Kex::KexDH { mut algos, kex_hash } = self.take() {
            let output = SharedSecret::handle_kexdhreply(&mut algos, kex_hash, p, b).await?;
            s.send(packets::NewKeys {})?;

            if first_kex && algos.send_ext_info {
                self.send_ext_info(s)?;
            }

            *self = Kex::NewKeys { output, algos };
            Ok(())
        } else {
            error::PacketWrong.fail()
        }
    }

    pub fn send_ext_info(&self, s: &mut TrafSend) -> Result<()> {
        if cfg!(feature = "rsa") {
            // OK unwrap: namelist has capacity
            let algs = ([SSH_NAME_RSA_SHA256, SSH_NAME_ED25519].as_slice()).try_into().unwrap();
            let ext = packets::ExtInfo {
                server_sig_algs: Some(NameList::Local(&algs)),
            };
            s.send(ext)?;
        }
        Ok(())
    }

    pub fn handle_newkeys(&mut self, sess_id: &mut Option<SessId>, s: &mut TrafSend<'_, '_>) -> Result<()> {
        if let Kex::NewKeys { output, algos } = self.take() {
            // We will have already sent our own NewKeys message if we reach thi
            // state.

            // The first KEX's H becomes the persistent sess_id
            let sess_id = sess_id.get_or_insert(output.h.clone());
            let keys = Keys::derive(output, sess_id, &algos)?;
            if algos.strict_kex {
                s.enable_strict_kex()
            }
            s.rekey(keys);
            *self = Kex::Idle;
            Ok(())
        } else {
            error::PacketWrong.fail()
        }
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

        // Certain kex method names aren't actual algorithms, just markers.
        // If they are negotiated it means no valid method matched
        if marker_only_kexs.contains(&kex_method) {
            return Err(Error::AlgoNoMatch { algo: "kex" });
        }

        let kex = SharedSecret::from_name(kex_method)?;
        let goodguess_kex = if kexguess2 {
            p.kex.first() == kex_method
        } else {
            p.kex.first() == conf.kexs.first()
        };

        // we only send MSG_EXT_INFO to a client, don't look
        // for SSH_NAME_EXT_INFO_S
        let send_ext_info = if is_client {
            false
        } else {
            // OK unwrap: p.kex is a remote list
            p.kex.has_algo(SSH_NAME_EXT_INFO_C).unwrap()
        };

        // we always send strict-kex, so just check if the other had it
        let other_strict = if is_client {
            SSH_NAME_STRICT_KEX_S
        } else {
            SSH_NAME_STRICT_KEX_C
        };
        let strict_kex = p.kex.has_algo(other_strict).unwrap();

        debug!("hostsig {:?}    vs   {:?}", p.hostsig, conf.hostsig);
        let hostsig_method = p
            .hostsig
            .first_match(is_client, &conf.hostsig)?
            .ok_or(Error::AlgoNoMatch { algo: "hostkey" })?;
        let hostsig = SigType::from_name(hostsig_method)?;
        let goodguess_hostkey = if kexguess2 {
            p.hostsig.first() == hostsig_method
        } else {
            p.hostsig.first() == conf.hostsig.first()
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
            send_ext_info,
            strict_kex,
        })
    }

    pub fn is_strict(&self) -> bool {
        match self {
            Kex::KexDH { algos: Algos { strict_kex: true, ..}, .. } => true,
            Kex::NewKeys { algos: Algos { strict_kex: true, ..}, .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug, ZeroizeOnDrop)]
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
    pub fn from_name(name: &'static str) -> Result<Self> {
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
        let q_c = BinString(q_c);
        Ok(packets::KexDHInit { q_c }.into())
    }

    // client only
    async fn handle_kexdhreply<'f>(
        algos: &mut Algos, mut kex_hash: KexHash,
        p: &packets::KexDHReply<'f>,
        b: &mut impl CliBehaviour
    ) -> Result<KexOutput> {
        kex_hash.prefinish(&p.k_s.0, algos.kex.pubkey(), p.q_s.0)?;
        // consumes the sharedsecret private key in algos
        let kex_out = match algos.kex {
            SharedSecret::KexCurve25519(_) => {
                KexCurve25519::secret(algos, p.q_s.0, kex_hash)?
            }
        };

        // TODO: error message on signature failure.
        let h: &[u8] = kex_out.h.as_ref();
        trace!("verify  h {}", h.hex_dump());
        algos.hostsig.verify(&p.k_s.0, &h, &p.sig.0)?;
        debug!("Hostkey signature is valid");
        if matches!(b.valid_hostkey(&p.k_s.0), Ok(true)) {
            Ok(kex_out)
        } else {
            Err(Error::BehaviourError { msg: "Host key rejected" })
        }
    }

    // server only. consumes algos and kex_hash
    fn handle_kexdhinit(
        algos: &mut Algos, mut kex_hash: KexHash,
        p: &packets::KexDHInit,
        s: &mut TrafSend, b: &mut impl ServBehaviour,
    ) -> Result<KexOutput> {
        // hostkeys list must contain the signature type
        trace!("hostkeys {:?}", b.hostkeys());
        let hk = b.hostkeys()?;
        let hostkey = hk.as_slice().iter().find(|k| k.can_sign(algos.hostsig)).trap()?;

        kex_hash.prefinish(&hostkey.pubkey(), p.q_c.0, algos.kex.pubkey())?;
        let (kex_out, kex_pub) = match algos.kex {
            SharedSecret::KexCurve25519(_) => {
                let kex_out = KexCurve25519::secret(algos, p.q_c.0, kex_hash)?;
                (kex_out, algos.kex.pubkey())
            }
        };

        Self::send_kexdhreply(&kex_out, kex_pub, hostkey, s)?;
        Ok(kex_out)
    }

    // server only
    pub fn send_kexdhreply(ko: &KexOutput, kex_pub: &[u8], hostkey: &SignKey, s: &mut TrafSend) -> Result<()> {
        let q_s = BinString(kex_pub);

        let k_s = Blob(hostkey.pubkey());
        trace!("sign kexreply h {}", ko.h.as_slice().hex_dump());
        let sig = hostkey.sign(&ko.h.as_slice())?;
        let sig: Signature = (&sig).into();
        let sig = Blob(sig);
        s.send(packets::KexDHReply { k_s, q_s, sig })
    }

    fn pubkey(&self) -> &[u8] {
        match self {
            SharedSecret::KexCurve25519(k) => k.pubkey(),
        }
    }
}

// TODO ZeroizeOnDrop. Sha256 doesn't support it yet.
// https://github.com/RustCrypto/hashes/issues/87
pub(crate) struct KexOutput {
    /// `H` for this exchange, conn takes the first as sess_id
    h: SessId,
    /// An digest instance that has already hashed `HASH(K || H` (see rfc4253).
    /// Always Sha256 for the time being.
    partial_hash: Sha256,
}

impl fmt::Debug for KexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KexOutput")
            .finish_non_exhaustive()
    }
}

impl KexOutput {
    fn new(k: &[u8], algos: &Algos, kex_hash: KexHash) -> Self {
        let h = kex_hash.finish(k);

        let mut partial_hash = algos.kex.hash();
        hash_mpint(&mut partial_hash, k);
        partial_hash.update(&h);

        KexOutput { h, partial_hash }
    }

    /// Constructor from a direct SessId
    #[cfg(test)]
    pub fn new_test(k: &[u8], algos: &Algos, h: &SessId) -> Self {
        let mut partial_hash = algos.kex.hash();
        hash_mpint(&mut partial_hash, k);
        partial_hash.update(h);

        KexOutput { h: h.clone(), partial_hash }
    }

    /// RFC4253 7.2. `K1 = HASH(K || H || "A" || session_id)` etc
    pub fn compute_key<'a>(&self,
        letter: char, len: usize, out: &'a mut [u8],
        sess_id: &SessId,
    ) -> Result<&'a [u8], Error> {
        if len > out.len() {
            return Err(Error::bug());
        }
        // TODO: will Sha256::output_size() become const?
        let hsz = Sha256::output_size();
        let w = &mut [0u8; 32];
        debug_assert!(w.len() >= hsz);
        // two rounds is sufficient with sha256 and current max key
        debug_assert!(2 * hsz >= out.len());

        let l = len.min(hsz);
        let (k1, rest) = out.split_at_mut(l);
        let (k2, _) = rest.split_at_mut(len - l);

        let sess_id: &[u8] = sess_id;

        let mut hash_ctx = self.partial_hash.clone();
        // K || H is already included
        hash_ctx.update([letter as u8]);
        hash_ctx.update(sess_id);
        hash_ctx.finalize_into(w.into());

        // fill first part
        k1.copy_from_slice(&w[..k1.len()]);

        if !k2.is_empty() {
            // generate next block K2 = HASH(K || H || K1)
            let mut hash_ctx = self.partial_hash.clone();
            // K || H is already included
            hash_ctx.update(k1);
            hash_ctx.finalize_into(w.into());
            k2.copy_from_slice(&w[..k2.len()]);
        }
        Ok(&out[..len])
    }


}

#[derive(ZeroizeOnDrop)]
pub(crate) struct KexCurve25519 {
    // Initialised in `new()`, cleared after deriving the secret
    ours: Option<x25519_dalek::EphemeralSecret>,
    // pubkey is relatively expensive to compute from the secret key
    pubkey: [u8; 32],
}

impl core::fmt::Debug for KexCurve25519 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("KexCurve25519")
            .field("ours", &if self.ours.is_some() { "Some" } else { "None" })
            .field("pubkey", &self.pubkey)
            .finish()
    }
}

impl KexCurve25519 {
    fn new() -> Result<Self> {
        let mut s = [0u8; 32];
        random::fill_random(s.as_mut_slice())?;
        // TODO: check that pure random bytes are OK
        let ours = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let pubkey = x25519_dalek::PublicKey::from(&ours);
        let pubkey = pubkey.to_bytes();
        Ok(KexCurve25519 { ours: Some(ours), pubkey })
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn secret(algos: &mut Algos, theirs: &[u8], kex_hash: KexHash) -> Result<KexOutput> {
        #[allow(irrefutable_let_patterns)] // until we have other algos
        let kex = if let SharedSecret::KexCurve25519(k) = &mut algos.kex {
            k
        } else {
            return Err(Error::bug());
        };
        let theirs: [u8; 32] = theirs.try_into().map_err(|_| Error::BadKex)?;
        let theirs = theirs.into();
        let shsec = kex.ours.take().trap()?.diffie_hellman(&theirs);
        Ok(KexOutput::new(shsec.as_bytes(), algos, kex_hash))
    }
}

#[cfg(test)]
mod tests {
    use pretty_hex::PrettyHex;

    use crate::encrypt::{self, SSH_PAYLOAD_START, KeyState};
    use crate::error::Error;
    use crate::ident::RemoteVersion;
    use crate::kex::*;
    use crate::kex;
    use crate::packets::{Packet,ParseContext};
    use crate::*;
    use crate::sunsetlog::init_test_log;
    use std::collections::VecDeque;

    // TODO:
    // - test algo negotiation

    use super::SSH_NAME_CURVE25519;

    #[test]
    fn test_name_match() {
        // check that the from_name() functions are complete
        for k in kex::fixed_options_kex.iter() {
            kex::SharedSecret::from_name(k).unwrap();
        }
        for k in kex::fixed_options_hostsig.iter() {
            sign::SigType::from_name(k).unwrap();
        }
        for k in kex::fixed_options_cipher.iter() {
            encrypt::Cipher::from_name(k).unwrap();
        }
        for k in kex::fixed_options_mac.iter() {
            encrypt::Integ::from_name(k).unwrap();
        }
    }

    // Unknown names fail. This is easy to hit if the names of from_name()
    // match statements are mistyped or aren't imported.
    // These are separate tests because they trigger `Error::bug()` which
    // is an explicit panic in debug builds.
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
    fn _reencode<'a>(out_buf: &'a mut [u8], p: Packet) -> Packet<'a> {
        let ctx = Default::default();
        let l = sshwire::write_ssh(out_buf, &p).unwrap();
        sshwire::packet_from_bytes(&out_buf[..l], &ctx).unwrap()
    }

    struct TestServBehaviour<'a> {
        keys: Vec<&'a SignKey>,
    }

    impl<'a> ServBehaviour for TestServBehaviour<'a> {
        fn hostkeys(&mut self) -> BhResult<heapless::Vec<&SignKey, 2>> {
            Ok(heapless::Vec::from_slice(self.keys.as_slice()).unwrap())
        }

        fn have_auth_pubkey(&self, _username: TextString) -> bool {
            false
        }

        fn have_auth_password(&self, _username: TextString) -> bool {
            false
        }

        fn open_session(&mut self, _chan: ChanHandle) -> ChanOpened {
            ChanOpened::Success
        }
    }

    struct TestCliBehaviour {
        allow_key: bool,
    }

    impl CliBehaviour for TestCliBehaviour {
        fn username(&mut self) -> BhResult<ResponseString> {
            Ok("matt".try_into().unwrap())
        }

        fn valid_hostkey(&mut self, _key: &PubKey) -> BhResult<bool> {
            Ok(self.allow_key)
        }

        fn authenticated(&mut self) {
        }
    }

    /// A debug fixture to capture output then deserialize it.
    /// Leaks lots.
    struct TrafCatcher {
        traf_out: traffic::TrafOut<'static>,
        traf_in: traffic::TrafIn<'static>,
        keys: encrypt::KeyState,
        rv: RemoteVersion,

        buf: VecDeque<u8>,
    }

    // Round trips packets through TrafOut/TrafIn, allowing
    // to capture sent packets.
    // This leaks vectors rather than dealing with borrowed Packets
    impl TrafCatcher {
        fn new() -> Self {
            let traf_in = traffic::TrafIn::new(vec![0u8; 3000].leak());
            let mut rv = RemoteVersion::new();
            rv.consume(b"SSH-2.0-thing\r\n").unwrap();
            rv.version().unwrap();

            Self {
                traf_out: traffic::TrafOut::new(vec![0u8; 3000].leak()),
                traf_in,
                keys: encrypt::KeyState::new_cleartext(),
                rv,
                buf: VecDeque::new(),
            }
        }

        fn sender<'f>(&'f mut self) -> traffic::TrafSend<'f, 'static> {
            self.traf_out.sender(&mut self.keys)
        }

        // Returns Some(packet), or None if empty
        fn next(&mut self) -> Option<Packet<'static>> {
            // get output
            let mut b = vec![0u8; 3000];
            let l = self.traf_out.output(b.as_mut_slice());
            assert!(l < b.len(), "Not enough space");
            let b = &b[..l];

            self.buf.extend(b.iter());
            let b = self.buf.make_contiguous();

            self.traf_in.done_payload(false);
            let l = self.traf_in.input(&mut self.keys, &mut self.rv, b).unwrap();
            self.buf.drain(..l);

            self.traf_in.payload().map(|(payload, _seq)| {
                let payload = Vec::from(payload).leak();
                sshwire::packet_from_bytes(payload, &Default::default()).unwrap()
            })
        }
    }

    #[test]
    fn test_agree_kex_allow_key() {
        test_agree_kex(true)
    }

    #[test]
    #[should_panic(expected = "Host key rejected")]
    fn test_agree_kex_disallow_key() {
        test_agree_kex(false)
    }

    // other things to test:
    // - first_follows, and kexguess2

    fn test_agree_kex(allow_key: bool) {
        #![allow(unused)]
        init_test_log();
        let cli_conf = kex::AlgoConfig::new(true);
        let serv_conf = kex::AlgoConfig::new(false);

        // needs to be hardcoded because that's what we send.
        let mut s = Vec::from(crate::ident::OUR_VERSION);
        s.extend_from_slice(b"\r\n");
        let mut version = RemoteVersion::new();
        version.consume(s.as_slice()).unwrap();

        let mut keys = vec![];
        keys.push(crate::SignKey::generate(crate::KeyType::Ed25519, None).unwrap());
        let keys: Vec<&SignKey> = keys.iter().collect();
        let mut sb = TestServBehaviour {
            keys,
        };
        let mut sb = Behaviour::<behaviour::UnusedCli, _>::new_server(&mut sb);
        let sb = sb.server().unwrap();
        let mut cb = TestCliBehaviour {
            allow_key
        };
        let mut cb = Behaviour::<_, behaviour::UnusedServ>::new_client(&mut cb);
        let cb = cb.client().unwrap();

        let mut ts = TrafCatcher::new();
        let mut tc = TrafCatcher::new();

        let mut cli = kex::Kex::new();
        let mut serv = kex::Kex::new();

        serv.send_kexinit(&serv_conf, &mut ts.sender()).unwrap();
        cli.send_kexinit(&cli_conf, &mut tc.sender()).unwrap();

        let cli_init = tc.next().unwrap();
        let cli_init = if let Packet::KexInit(k) = cli_init { k } else { panic!() };
        assert!(tc.next().is_none());
        let serv_init = ts.next().unwrap();
        let serv_init = if let Packet::KexInit(k) = serv_init { k } else { panic!() };
        assert!(ts.next().is_none());

        serv.handle_kexinit(cli_init, false, &serv_conf, &version, true, &mut ts.sender()).unwrap();
        cli.handle_kexinit(serv_init, true, &cli_conf, &version, true, &mut tc.sender()).unwrap();

        let cli_dhinit = tc.next().unwrap();
        let cli_dhinit = if let Packet::KexDHInit(k) = cli_dhinit { k } else { panic!() };
        assert!(tc.next().is_none());

        assert!(ts.next().is_none());

        serv.handle_kexdhinit(&cli_dhinit, &mut ts.sender(), sb).unwrap();
        let serv_dhrep = ts.next().unwrap();
        let serv_dhrep = if let Packet::KexDHReply(k) = serv_dhrep { k } else { panic!() };
        assert!(matches!(ts.next().unwrap(), Packet::NewKeys(_)));

        let s = &mut tc.sender();
        let f = cli.handle_kexdhreply(&serv_dhrep, s, cb, true);
        let f = crate::non_async(f).unwrap();
        f.unwrap();
        assert!(matches!(tc.next().unwrap(), Packet::NewKeys(_)));
        assert!(matches!(tc.next(), None));

        let (cout, calgos) = if let Kex::NewKeys { output, algos } = cli {
            (output, algos)
        } else {
            panic!();
        };
        let (sout, salgos) = if let Kex::NewKeys { output, algos } = serv {
            (output, algos)
        } else {
            panic!();
        };

        // output hash matches
        assert_eq!(cout.h, sout.h);

        // roundtrip with the derived keys
        let sess_id = SessId::from_slice(&Sha256::digest(b"some sessid")).unwrap();

        let mut skeys = crate::encrypt::KeyState::new_cleartext();
        skeys.rekey(Keys::derive(sout, &sess_id, &salgos).unwrap());
        let mut ckeys = crate::encrypt::KeyState::new_cleartext();
        ckeys.rekey(Keys::derive(cout, &sess_id, &calgos).unwrap());

        roundtrip(b"this", &mut skeys, &mut ckeys);
        roundtrip(&[13u8; 50], &mut ckeys, &mut skeys);

    }

    fn roundtrip(payload: &[u8], enc: &mut KeyState, dec: &mut KeyState) {
        let mut b = vec![];
        b.resize(SSH_PAYLOAD_START, 0);
        b.extend_from_slice(payload);
        b.resize(100, 0);

        let l = enc.encrypt(payload.len(), &mut b).unwrap();
        let l_dec = dec.decrypt_first_block(&mut b).unwrap();
        assert_eq!(l, l_dec);
        b.resize(l_dec, 0u8);
        let l = dec.decrypt(&mut b).unwrap();
        let dec_payload = &b[SSH_PAYLOAD_START..SSH_PAYLOAD_START+l];
        assert_eq!(payload, dec_payload);
    }
}
