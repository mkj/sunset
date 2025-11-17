// TODO: for fixed_ names, remove once they're removed
#![allow(non_upper_case_globals)]
#![cfg_attr(fuzzing, allow(dead_code))]
#![cfg_attr(fuzzing, allow(unreachable_code))]
#![cfg_attr(fuzzing, allow(unused_variables))]

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::{fmt, marker::PhantomData};

use digest::Digest;
#[cfg(feature = "mlkem")]
use ml_kem::{
    kem::{Decapsulate, Encapsulate, EncapsulationKey, Kem},
    Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::*;
use encrypt::{Cipher, Integ, KeysRecv, KeysSend};
use event::{CliEventId, ServEventId};
use ident::RemoteVersion;
use namelist::{LocalNames, NameList};
use packets::{KexCookie, Packet, PubKey, Signature};
use sign::SigType;
use sshnames::*;
use sshwire::{
    hash_mpint, hash_ser, hash_ser_length, BinString, Blob, SSHWireDigestUpdate,
};
use traffic::TrafSend;

// at present we only have curve25519 with sha256
const MAX_SESSID: usize = 32;
pub type SessId = heapless::Vec<u8, MAX_SESSID>;

// TODO this will be configurable.
const fixed_options_kex: &[&str] = &[
    #[cfg(feature = "mlkem")]
    SSH_NAME_MLKEM_X25519,
    SSH_NAME_CURVE25519,
    SSH_NAME_CURVE25519_LIBSSH,
];

/// Options that can't be negotiated
const marker_only_kexs: &[&str] = &[
    SSH_NAME_EXT_INFO_C,
    SSH_NAME_EXT_INFO_S,
    SSH_NAME_KEXGUESS2,
    SSH_NAME_STRICT_KEX_C,
    SSH_NAME_STRICT_KEX_S,
];

const fixed_options_hostsig: &[&str] = &[
    SSH_NAME_ED25519,
    #[cfg(feature = "rsa")]
    SSH_NAME_RSA_SHA256,
];

const fixed_options_cipher: &[&str] = &[SSH_NAME_CHAPOLY, SSH_NAME_AES256_CTR];
const fixed_options_mac: &[&str] = &[SSH_NAME_HMAC_SHA256];
const fixed_options_comp: &[&str] = &[SSH_NAME_NONE];

#[derive(Debug)]
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
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub(crate) enum Kex<CS: CliServ> {
    /// No key exchange in progress
    Idle,

    /// Waiting for a KexInit packet, have sent one.
    KexInit {
        // Cookie sent in our KexInit packet. Kept so that we can reproduce the
        // KexInit packet when calculating the exchange hash.
        our_cookie: KexCookie,
    },
    /// Waiting for KexDHInit (server) or KexDHReply (client)
    KexDH { algos: Algos<CS>, kex_hash: KexHash },
    /// Waiting for NewKeys. `output` is new keys to take into use
    NewKeys { output: KexOutput, algos: Algos<CS> },

    /// A transient state use internally to transition between other states.
    ///
    /// Returned from .take()
    /// Should only ever occur while inside a method call, a proper state
    /// will be set before returning. (Could remain set if an error occurs,
    /// but an error returned from Kex is not recoverable anyway).
    Taken,
}

#[derive(Debug)]
pub(crate) struct KexHash {
    // Could be made generic if we add other kex methods
    hash_ctx: Sha256,
}

// kexhash state. progessively include version idents, kexinit payloads, hostsig, e/f, secret
impl KexHash {
    fn new<CS: CliServ>(
        algo_conf: &AlgoConfig,
        our_cookie: &KexCookie,
        remote_version: &RemoteVersion,
        remote_kexinit: &packets::Packet,
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
        let own_kexinit = Kex::<CS>::make_kexinit(our_cookie, algo_conf);
        if CS::is_client() {
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

    /// Hash the server signing public key
    fn hash_hostkey(&mut self, host_key: &PubKey) -> Result<()> {
        hash_ser_length(&mut self.hash_ctx, host_key)
    }

    /// Hash shared secret derivation q_c/q_s (aka e/f)
    fn hash_pubkeys(&mut self, q_c: &[u8], q_s: &[u8]) -> Result<()> {
        // TODO: q_c and q_s need to be padded as mpint (extra 0x00 if high bit set)
        // for ecdsa and DH modes, but not for curve25519.

        self.hash_slice(q_c);
        self.hash_slice(q_s);
        Ok(())
    }

    /// Compute the remainder of the hash, consuming KexHash
    fn finish(mut self, k: &KexKey) -> SessId {
        k.hash(&mut self.hash_ctx);
        // OK unwrap, hash sized
        SessId::from_slice(&self.hash_ctx.finalize()).unwrap()
    }

    // Hashes a slice, with added u32 length prefix.
    fn hash_slice(&mut self, v: &[u8]) {
        let _ = hash_ser(&mut self.hash_ctx, &BinString(v));
    }
}

/// K shared secret from rfc4253.
#[allow(unused)]
enum KexKey<'a> {
    /// curve25519 and older KEXes encode as a mpint
    Mpint(&'a [u8]),
    /// mlkem and sntrup hybrids encode as a SSH string
    String(&'a [u8]),
}

impl<'a> KexKey<'a> {
    fn hash(&self, hash_ctx: &mut impl SSHWireDigestUpdate) {
        match self {
            Self::Mpint(k) => hash_mpint(hash_ctx, k),
            Self::String(k) => {
                let _ = hash_ser(hash_ctx, &BinString(k));
            }
        }
    }
}

/// Records the chosen algorithms while key exchange proceeds
#[derive(Debug)]
pub(crate) struct Algos<CS: CliServ> {
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

    // whether the remote side supports ext-info
    pub send_ext_info: bool,

    // whether the remote side supports strict kex. will be ignored
    // for non-first KEX
    pub strict_kex: bool,

    pub _cs: PhantomData<CS>,
}

impl<CS: CliServ> fmt::Display for Algos<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (cc, cs, mc, ms) = if CS::is_client() {
            (&self.cipher_enc, &self.cipher_dec, &self.integ_enc, &self.integ_dec)
        } else {
            (&self.cipher_dec, &self.cipher_enc, &self.integ_dec, &self.integ_enc)
        };

        write!(f, "Negotiated algorithms {{\nkex {}\nhostkey {}\ncipher c->s {}\ncipher s->c {}\nmac c->s {}\nmac s->c {}\n}}",
            self.kex, self.hostsig.algorithm_name(), cc, cs, mc, ms)
    }
}

impl Algos<Client> {
    #[cfg(test)]
    pub fn test_swap_to_server(self) -> Algos<Server> {
        Algos {
            kex: self.kex,
            hostsig: self.hostsig,
            // Swap enc and dec
            cipher_enc: self.cipher_dec,
            cipher_dec: self.cipher_enc,
            integ_enc: self.integ_dec,
            integ_dec: self.integ_enc,
            discard_next: self.discard_next,
            send_ext_info: self.send_ext_info,
            strict_kex: self.strict_kex,
            _cs: PhantomData,
        }
    }
}

impl<CS: CliServ> Kex<CS> {
    pub fn new() -> Self {
        Kex::Idle
    }

    fn take(&mut self) -> Self {
        debug_assert!(!matches!(self, Kex::Taken));
        core::mem::replace(self, Kex::Taken)
    }

    /// Sends a `KexInit` message. Must be called from `Idle` state
    pub fn send_kexinit(
        &mut self,
        conf: &AlgoConfig,
        s: &mut TrafSend,
    ) -> Result<()> {
        if !matches!(self, Kex::Idle) {
            return Err(Error::bug());
        }
        let mut our_cookie = KexCookie([0u8; 16]);
        random::fill_random(our_cookie.0.as_mut_slice())?;
        s.send(Self::make_kexinit(&our_cookie, conf))?;
        *self = Kex::KexInit { our_cookie };
        Ok(())
    }

    pub fn handle_kexinit(
        &mut self,
        remote_kexinit: packets::KexInit,
        algo_conf: &AlgoConfig,
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

        let mut algos = Self::algo_negotiation(&remote_kexinit, algo_conf)?;
        debug!("{algos}");

        if first_kex && algos.strict_kex && s.recv_seq() != 1 {
            debug!("kexinit has strict kex but wasn't first packet");
            return error::PacketWrong.fail();
        }
        if CS::is_client() {
            algos.kex.send_kexdhinit(s)?;
        }
        let kex_hash = KexHash::new::<CS>(
            algo_conf,
            our_cookie,
            remote_version,
            &remote_kexinit.into(),
        )?;
        *self = Kex::KexDH { algos, kex_hash };
        Ok(())
    }

    fn make_kexinit<'a>(cookie: &KexCookie, conf: &'a AlgoConfig) -> Packet<'a> {
        packets::KexInit {
            cookie: cookie.clone(),
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
        }
        .into()
    }

    pub fn handle_newkeys(
        &mut self,
        sess_id: &mut Option<SessId>,
        s: &mut TrafSend,
    ) -> Result<()> {
        if let Kex::NewKeys { output, algos } = self.take() {
            // We will have already sent our own NewKeys message if we reach thi
            // state, so can unwrap sess_id.
            let sess_id = sess_id.as_ref().unwrap();
            let dec = KeysRecv::new(&output, sess_id, &algos);
            s.rekey_recv(dec);
            *self = Kex::Idle;
            Ok(())
        } else {
            error::PacketWrong.fail()
        }
    }

    /// Perform SSH algorithm negotiation
    fn algo_negotiation(
        p: &packets::KexInit,
        conf: &AlgoConfig,
    ) -> Result<Algos<CS>> {
        let kexguess2 = p.kex.has_algo(SSH_NAME_KEXGUESS2)?;

        // For each algorithm we select the first name in the client's
        // list that is also present in the server's list.
        let kex_method = p
            .kex
            .first_match(CS::is_client(), &conf.kexs)?
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
        let send_ext_info = if CS::is_client() {
            false
        } else {
            // OK unwrap: p.kex is a remote list
            p.kex.has_algo(SSH_NAME_EXT_INFO_C).unwrap()
        };

        // we always send strict-kex, so just check if the other had it
        let other_strict = if CS::is_client() {
            SSH_NAME_STRICT_KEX_S
        } else {
            SSH_NAME_STRICT_KEX_C
        };
        let strict_kex = p.kex.has_algo(other_strict).unwrap();

        debug!("hostsig {:?}    vs   {:?}", p.hostsig, conf.hostsig);
        let hostsig_method = p
            .hostsig
            .first_match(CS::is_client(), &conf.hostsig)?
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
            if CS::is_client() { (c2s, s2c) } else { (s2c, c2s) };

        let n = cipher_tx
            .first_match(CS::is_client(), &conf.ciphers)?
            .ok_or(Error::AlgoNoMatch { algo: "encryption" })?;
        let cipher_enc = Cipher::from_name(n)?;
        let n = cipher_rx
            .first_match(CS::is_client(), &conf.ciphers)?
            .ok_or(Error::AlgoNoMatch { algo: "encryption" })?;
        let cipher_dec = Cipher::from_name(n)?;

        // We ignore mac algorithms for AEAD ciphers
        let integ_enc = if let Some(integ) = cipher_enc.integ() {
            integ
        } else {
            let n = mac_tx
                .first_match(CS::is_client(), &conf.macs)?
                .ok_or(Error::AlgoNoMatch { algo: "mac" })?;
            Integ::from_name(n)?
        };
        let integ_dec = if let Some(integ) = cipher_dec.integ() {
            integ
        } else {
            let n = mac_rx
                .first_match(CS::is_client(), &conf.macs)?
                .ok_or(Error::AlgoNoMatch { algo: "mac" })?;
            Integ::from_name(n)?
        };

        // Compression only matches "none", we don't need further handling
        // at the moment.
        comp_tx
            .first_match(CS::is_client(), &conf.comps)?
            .ok_or(Error::AlgoNoMatch { algo: "compression" })?;
        comp_rx
            .first_match(CS::is_client(), &conf.comps)?
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
            send_ext_info,
            strict_kex,
            _cs: PhantomData,
        })
    }

    pub fn is_strict(&self) -> bool {
        matches!(
            self,
            Kex::KexDH { algos: Algos { strict_kex: true, .. }, .. }
                | Kex::NewKeys { algos: Algos { strict_kex: true, .. }, .. }
        )
    }

    pub fn handle_kexdhreply(&self) -> Result<DispatchEvent> {
        if !CS::is_client() {
            trace!("kexdhreply not client");
            return error::SSHProto.fail();
        }
        if !matches!(self, Kex::KexDH { .. }) {
            return error::PacketWrong.fail();
        }
        Ok(DispatchEvent::CliEvent(event::CliEventId::Hostkey))
    }

    pub fn handle_kexdhinit(&mut self) -> Result<DispatchEvent> {
        if CS::is_client() {
            trace!("kexdhinit not server");
            return error::SSHProto.fail();
        }

        if let Kex::KexDH { algos, .. } = self {
            if algos.discard_next {
                algos.discard_next = false;
                // Ignore this packet
                return Ok(DispatchEvent::None);
            }
        } else {
            return error::PacketWrong.fail();
        }

        Ok(DispatchEvent::ServEvent(ServEventId::Hostkeys))
    }

    /// Send NewKeys and switch to next encryption key.
    fn send_newkeys(
        &mut self,
        output: KexOutput,
        algos: Algos<CS>,
        sess_id: &mut Option<SessId>,
        s: &mut TrafSend,
    ) -> Result<()> {
        debug_assert!(matches!(self, Self::Taken));

        s.send(packets::NewKeys {})?;
        // Switch to new encryption keys after sending NewKeys

        // The first KEX's H becomes the persistent sess_id
        let sess_id = sess_id.get_or_insert(output.h.clone());
        let enc = KeysSend::new(&output, sess_id, &algos);
        s.rekey_send(enc, algos.strict_kex);
        *self = Kex::NewKeys { output, algos };
        Ok(())
    }
}

impl Kex<Client> {
    pub fn resume_kexdhreply(
        &mut self,
        p: &packets::KexDHReply,
        sess_id: &mut Option<SessId>,
        s: &mut TrafSend,
    ) -> Result<()> {
        trace!("resume");
        if let Kex::KexDH { algos, .. } = self {
            if algos.discard_next {
                algos.discard_next = false;
                // Ignore this packet
                return Ok(());
            }
        }

        if let Kex::KexDH { mut algos, kex_hash } = self.take() {
            let output = SharedSecret::handle_kexdhreply(&mut algos, kex_hash, p)?;
            self.send_newkeys(output, algos, sess_id, s)
            // TODO could send ext_info here on first_kex
        } else {
            // Already checked in handle_kexdhreply
            Err(Error::bug())
        }
    }
}

impl Kex<Server> {
    pub fn resume_kexdhinit(
        &mut self,
        p: &packets::KexDHInit,
        first_kex: bool,
        keys: &[&SignKey],
        sess_id: &mut Option<SessId>,
        s: &mut TrafSend,
    ) -> Result<()> {
        if let Kex::KexDH { mut algos, kex_hash } = self.take() {
            let ext_info = algos.send_ext_info;

            let output =
                SharedSecret::handle_kexdhinit(&mut algos, kex_hash, keys, p, s)?;
            self.send_newkeys(output, algos, sess_id, s)?;

            if first_kex && ext_info {
                self.send_ext_info(s)?;
            }
            Ok(())
        } else {
            // Already checked in handle_kexdhinit
            Err(Error::bug())
        }
    }

    // Not inherently server-only, but no client use yet in sunset.
    pub fn send_ext_info(&self, s: &mut TrafSend) -> Result<()> {
        if cfg!(feature = "rsa") {
            // OK unwrap: namelist has capacity
            let algs = ([SSH_NAME_RSA_SHA256, SSH_NAME_ED25519].as_slice())
                .try_into()
                .unwrap();
            let ext =
                packets::ExtInfo { server_sig_algs: Some(NameList::Local(&algs)) };
            s.send(ext)?;
        }
        Ok(())
    }
}

#[derive(Debug, ZeroizeOnDrop)]
pub(crate) enum SharedSecret {
    KexCurve25519(KexCurve25519),
    #[cfg(feature = "mlkem")]
    KexMlkemX25519(KexMlkemX25519),
}

impl fmt::Display for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::KexCurve25519(_) => SSH_NAME_CURVE25519,
            #[cfg(feature = "mlkem")]
            Self::KexMlkemX25519(_) => SSH_NAME_MLKEM_X25519,
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
            #[cfg(feature = "mlkem")]
            SSH_NAME_MLKEM_X25519 => {
                Ok(SharedSecret::KexMlkemX25519(KexMlkemX25519::new()?))
            }
            _ => Err(Error::bug()),
        }
    }

    fn send_kexdhinit(&mut self, s: &mut TrafSend) -> Result<()> {
        #[cfg(feature = "mlkem")]
        let mlkem_bytes;
        let q_c = match self {
            Self::KexCurve25519(k) => k.pubkey(),
            #[cfg(feature = "mlkem")]
            Self::KexMlkemX25519(k) => {
                mlkem_bytes = k.init_pubkey_arr_client();
                &mlkem_bytes
            }
        };
        let q_c = BinString(q_c);
        let p: Packet = packets::KexDHInit { q_c }.into();
        s.send(p)
    }

    // client only
    fn handle_kexdhreply(
        algos: &mut Algos<Client>,
        mut kex_hash: KexHash,
        p: &packets::KexDHReply,
    ) -> Result<KexOutput> {
        kex_hash.hash_hostkey(&p.k_s.0)?;
        // consumes the sharedsecret private key in algos
        let kex_out = match &mut algos.kex {
            SharedSecret::KexCurve25519(k) => k.secret(p.q_s.0, kex_hash, true),
            #[cfg(feature = "mlkem")]
            SharedSecret::KexMlkemX25519(k) => {
                k.secret_decap_client(p.q_s.0, kex_hash)
            }
        }?;

        // TODO: error message on signature failure.
        let h: &[u8] = kex_out.h.as_ref();
        trace!("verify  h {h:02x?}");
        algos
            .hostsig
            .verify(&p.k_s.0, &h, &p.sig.0)
            .inspect_err(|_| warn!("Bad host signature"))?;
        debug!("Hostkey signature is valid");
        Ok(kex_out)
    }

    // server only. consumes algos and kex_hash
    fn handle_kexdhinit(
        algos: &mut Algos<Server>,
        mut kex_hash: KexHash,
        keys: &[&SignKey],
        p: &packets::KexDHInit,
        s: &mut TrafSend,
    ) -> Result<KexOutput> {
        if keys.is_empty() {
            debug!("Hostkey list is empty");
            return error::BadUsage.fail();
        }

        let hostkey = keys.iter().find(|k| k.can_sign(algos.hostsig));
        let hostkey = hostkey.ok_or_else(|| {
            // TODO: hostkeys should be requested
            // earlier and used for kexinit algorithm negotiation too,
            // so then this shouldn't fail here.
            debug!("No suitable hostkey provided");
            error::BadUsage.build()
        })?;

        kex_hash.hash_hostkey(&hostkey.pubkey())?;

        #[cfg(feature = "mlkem")]
        let mlkem_bytes;
        let (kex_out, pubkey) = match &mut algos.kex {
            SharedSecret::KexCurve25519(k) => {
                (k.secret(p.q_c.0, kex_hash, false)?, k.pubkey())
            }
            #[cfg(feature = "mlkem")]
            SharedSecret::KexMlkemX25519(k) => {
                let ko;
                (ko, mlkem_bytes) = k.secret_encap_server(p.q_c.0, kex_hash)?;
                (ko, mlkem_bytes.as_slice())
            }
        };

        Self::send_kexdhreply(&kex_out, pubkey, hostkey, s)?;
        Ok(kex_out)
    }

    // server only
    pub fn send_kexdhreply(
        ko: &KexOutput,
        kex_pub: &[u8],
        hostkey: &SignKey,
        s: &mut TrafSend,
    ) -> Result<()> {
        let q_s = BinString(kex_pub);

        let k_s = Blob(hostkey.pubkey());
        trace!("sign kexreply h {:02x?}", ko.h.as_slice());
        let sig = hostkey.sign(&ko.h.as_slice())?;
        let sig: Signature = (&sig).into();
        let sig = Blob(sig);
        s.send(packets::KexDHReply { k_s, q_s, sig })
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
        f.debug_struct("KexOutput").finish_non_exhaustive()
    }
}

impl KexOutput {
    /// Older algorithms define K shared secret to be a mpint.
    /// mlkem and sntrup define it as a string.
    fn new(k: KexKey, kex_hash: KexHash) -> Self {
        let h = kex_hash.finish(&k);

        // current kex all use sha256
        let mut partial_hash = Sha256::new();

        k.hash(&mut partial_hash);
        partial_hash.update(&h);

        KexOutput { h, partial_hash }
    }

    /// Constructor from a direct SessId
    #[cfg(test)]
    pub fn new_test(k: &[u8], h: &SessId) -> Self {
        let mut partial_hash = Sha256::new();
        hash_mpint(&mut partial_hash, k);
        partial_hash.update(h);

        KexOutput { h: h.clone(), partial_hash }
    }

    /// RFC4253 7.2. `K1 = HASH(K || H || "A" || session_id)` etc
    pub fn compute_key<'a>(
        &self,
        letter: char,
        len: usize,
        out: &'a mut [u8],
        sess_id: &SessId,
    ) -> &'a [u8] {
        debug_assert!(len <= out.len());
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
        &out[..len]
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
        let ours = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let pubkey = x25519_dalek::PublicKey::from(&ours);
        let pubkey = pubkey.to_bytes();
        Ok(KexCurve25519 { ours: Some(ours), pubkey })
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn raw_secret(&mut self, theirs: &[u8]) -> Result<x25519_dalek::SharedSecret> {
        let theirs: [u8; 32] = theirs.try_into().map_err(|_| Error::BadKex)?;
        let theirs = theirs.into();
        Ok(self.ours.take().trap()?.diffie_hellman(&theirs))
    }

    fn secret(
        &mut self,
        theirs: &[u8],
        mut kex_hash: KexHash,
        is_client: bool,
    ) -> Result<KexOutput> {
        if is_client {
            kex_hash.hash_pubkeys(self.pubkey(), theirs)?;
        } else {
            kex_hash.hash_pubkeys(theirs, self.pubkey())?;
        }
        let shsec = self.raw_secret(theirs)?;
        Ok(KexOutput::new(KexKey::Mpint(shsec.as_bytes()), kex_hash))
    }
}

#[derive(ZeroizeOnDrop)]
#[cfg(feature = "mlkem")]
pub(crate) struct KexMlkemX25519 {
    ecdh: KexCurve25519,
    // Initialised in `new()`, cleared after deriving the secret
    mlkem_ours: Option<<Kem<MlKem768Params> as KemCore>::DecapsulationKey>,
}

#[cfg(feature = "mlkem")]
impl core::fmt::Debug for KexMlkemX25519 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("KexMlkemX25519")
            .field("ours", &if self.mlkem_ours.is_some() { "Some" } else { "None" })
            .field("ecdh", &self.ecdh)
            .finish()
    }
}

#[cfg(feature = "mlkem")]
impl KexMlkemX25519 {
    // Literals for readability, checked below.
    const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
    const MLKEM768_PUBKEY_SIZE: usize = 1184;
    const X25519_PUBKEY_SIZE: usize = 32;
    const PUBLICKEY_SIZE: usize =
        Self::MLKEM768_PUBKEY_SIZE + Self::X25519_PUBKEY_SIZE;
    const CIPHERTEXT_SIZE: usize =
        Self::MLKEM768_CIPHERTEXT_SIZE + Self::X25519_PUBKEY_SIZE;

    const _CHECK0: () = assert!(
        Self::MLKEM768_PUBKEY_SIZE
            == size_of::<ml_kem::Encoded::<EncapsulationKey::<MlKem768Params>>>()
    );
    const _CHECK1: () = assert!(
        Self::MLKEM768_CIPHERTEXT_SIZE == size_of::<ml_kem::Ciphertext<MlKem768>>()
    );

    fn new() -> Result<Self> {
        Ok(Self { ecdh: KexCurve25519::new()?, mlkem_ours: None })
    }

    /// Generates the publickey for a sent kexdhinit
    fn init_pubkey_arr_client(&mut self) -> [u8; Self::PUBLICKEY_SIZE] {
        debug_assert!(self.mlkem_ours.is_none());
        // TODO does this construct in-place?
        let (dk, _ek) = MlKem768::generate(&mut rand_core::OsRng);
        let pubkey = self.pubkey_client(dk.encapsulation_key());
        self.mlkem_ours = Some(dk);
        pubkey
    }

    fn pubkey_client(
        &mut self,
        ek: &EncapsulationKey<MlKem768Params>,
    ) -> [u8; Self::PUBLICKEY_SIZE] {
        let mut out = [0u8; Self::PUBLICKEY_SIZE];
        // Concatenate pq and ecdh.
        // C_INIT = C_PK2 || C_PK1.  C_PK2 pq kem, C_PK1 ecdh
        let (pq, ec) = out.split_at_mut(Self::MLKEM768_PUBKEY_SIZE);
        let pq: &mut [u8; Self::MLKEM768_PUBKEY_SIZE] = pq.try_into().unwrap();
        *pq = ek.as_bytes().into();
        ec.copy_from_slice(self.ecdh.pubkey());
        out
    }

    /// Generates the encapsulated ciphertext for a sent kexdhreply, and
    /// derives the shared secret KexOutput.
    fn secret_encap_server(
        &mut self,
        c_pk: &[u8],
        mut kex_hash: KexHash,
    ) -> Result<(KexOutput, [u8; Self::CIPHERTEXT_SIZE])> {
        let mut ct_out = [0u8; Self::CIPHERTEXT_SIZE];

        // C_INIT = C_PK2 || C_PK1.  C_PK2 pq kem, C_PK1 ecdh
        let (pq_in, ec_in) = c_pk
            .split_at_checked(Self::MLKEM768_PUBKEY_SIZE)
            .ok_or_else(|| error::BadKex.build())?;

        let ek = pq_in.try_into().map_err(|_| error::BadKex.build())?;
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(ek);

        // S_REPLY = S_CT2 || S_PK1.  S_CT2 pq kem, S_PK1 ecdh
        let (pq, ec) = ct_out.split_at_mut(Self::MLKEM768_CIPHERTEXT_SIZE);
        let pq: &mut [u8; Self::MLKEM768_CIPHERTEXT_SIZE] = pq.try_into().unwrap();
        let enc = ek
            .encapsulate(&mut rand_core::OsRng)
            .map_err(|_| error::BadKex.build())?;
        let (ct, pq_secret) = enc.into();
        // TODO: check if this is another stack copy.
        *pq = ct.into();
        ec.copy_from_slice(self.ecdh.pubkey());

        kex_hash.hash_pubkeys(c_pk, &ct_out)?;
        Ok((self.derive_secret(&pq_secret, ec_in, kex_hash)?, ct_out))
    }

    fn secret_decap_client(
        &mut self,
        s_pk: &[u8],
        mut kex_hash: KexHash,
    ) -> Result<KexOutput> {
        // S_REPLY = S_CT2 || S_PK1.  S_CT2 pq kem, S_PK1 ecdh
        let (pq_in, ec_in) = s_pk
            .split_at_checked(Self::MLKEM768_CIPHERTEXT_SIZE)
            .ok_or_else(|| error::BadKex.build())?;

        let ct: &Ciphertext<MlKem768> =
            pq_in.try_into().map_err(|_| error::BadKex.build())?;
        let dk = self.mlkem_ours.take().trap()?;
        let pq_secret = dk.decapsulate(ct).map_err(|_| error::BadKex.build())?;

        let ek = dk.encapsulation_key();
        let c_pk = self.pubkey_client(ek);

        kex_hash.hash_pubkeys(&c_pk, s_pk)?;
        self.derive_secret(&pq_secret, ec_in, kex_hash)
    }

    // common code to derive a hybrid secret. the PQ KEM shared secret is already established,
    // this derives the ecdh shared secret and combines them.
    fn derive_secret(
        &mut self,
        pq_secret: &[u8],
        ecdh_theirs: &[u8],
        kex_hash: KexHash,
    ) -> Result<KexOutput> {
        let ec_secret = self.ecdh.raw_secret(ecdh_theirs)?;
        // K = HASH(K_PQ || K_CL)
        let mut combiner = sha2::Sha256::new();
        combiner.update(pq_secret);
        combiner.update(&ec_secret);
        // TODO zeroize
        let comb_sec = combiner.finalize();
        Ok(KexOutput::new(KexKey::String(&comb_sec), kex_hash))
    }
}

#[cfg(test)]
mod tests {
    use pretty_hex::PrettyHex;

    use crate::encrypt::{self, KeyState, KeysRecv, KeysSend, SSH_PAYLOAD_START};
    use crate::error::Error;
    use crate::ident::RemoteVersion;
    use crate::kex;
    use crate::kex::*;
    use crate::packets::{Packet, ParseContext};
    use crate::sunsetlog::init_test_log;
    use crate::*;
    use std::collections::VecDeque;

    // TODO:
    // - test algo negotiation

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
            let mut rv = RemoteVersion::new(false);
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
            let b = self.traf_out.output_buf();

            self.buf.extend(b.iter());
            let l = b.len();
            self.traf_out.consume_output(l);
            let b = self.buf.make_contiguous();

            self.traf_in.done_payload();
            let l = self.traf_in.input(&mut self.keys, &mut self.rv, b).unwrap();
            self.buf.drain(..l);

            self.traf_in.payload().map(|(payload, _seq)| {
                let payload = Vec::from(payload).leak();
                sshwire::packet_from_bytes(payload, &Default::default()).unwrap()
            })
        }
    }

    // other things to test:
    // - first_follows, and kexguess2
    // - kex rejection. is in conn though.

    #[test]
    fn test_each_kex() {
        for name in fixed_options_kex {
            test_kex_allow(name)
        }
    }

    fn test_kex_allow(chosen_kex: &'static str) {
        // #![allow(unused)]
        init_test_log();
        let mut cli_conf = kex::AlgoConfig::new(true);
        let serv_conf = kex::AlgoConfig::new(false);

        // Use the tested kex algorithm
        cli_conf.kexs = LocalNames::new();
        cli_conf.kexs.0.push(chosen_kex).unwrap();

        // needs to be hardcoded because that's what we send.
        let mut s = Vec::from(crate::ident::OUR_VERSION);
        s.extend_from_slice(b"\r\n");
        let mut version = RemoteVersion::new(true);
        version.consume(s.as_slice()).unwrap();

        let mut keys = vec![];
        keys.push(crate::SignKey::generate(crate::KeyType::Ed25519, None).unwrap());
        let keys: Vec<&SignKey> = keys.iter().collect();

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
        let serv_init =
            if let Packet::KexInit(k) = serv_init { k } else { panic!() };
        assert!(ts.next().is_none());

        serv.handle_kexinit(cli_init, &serv_conf, &version, true, &mut ts.sender())
            .unwrap();
        cli.handle_kexinit(serv_init, &cli_conf, &version, true, &mut tc.sender())
            .unwrap();

        let cli_dhinit = tc.next().unwrap();
        let cli_dhinit =
            if let Packet::KexDHInit(k) = cli_dhinit { k } else { panic!() };
        assert!(tc.next().is_none());

        assert!(ts.next().is_none());

        let sess_id = SessId::from_slice(&Sha256::digest(b"some sessid")).unwrap();
        let mut sess_id = Some(sess_id);

        let ev = serv.handle_kexdhinit().unwrap();
        assert!(matches!(ev, DispatchEvent::ServEvent(ServEventId::Hostkeys)));
        serv.resume_kexdhinit(
            &cli_dhinit,
            true,
            keys.as_slice(),
            &mut sess_id,
            &mut ts.sender(),
        )
        .unwrap();
        let serv_dhrep = ts.next().unwrap();
        let serv_dhrep =
            if let Packet::KexDHReply(k) = serv_dhrep { k } else { panic!() };
        assert!(matches!(ts.next().unwrap(), Packet::NewKeys(_)));

        let s = &mut tc.sender();
        let ev = cli.handle_kexdhreply().unwrap();
        assert!(matches!(ev, DispatchEvent::CliEvent(CliEventId::Hostkey)));
        cli.resume_kexdhreply(&serv_dhrep, &mut sess_id, s).unwrap();
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
        let sess_id = &sess_id.unwrap();

        let mut skeys = crate::encrypt::KeyState::new_cleartext();
        let enc = KeysSend::new(&sout, &sess_id, &salgos);
        let dec = KeysRecv::new(&sout, &sess_id, &salgos);
        skeys.rekey_send(enc, true);
        skeys.rekey_recv(dec);

        let mut ckeys = crate::encrypt::KeyState::new_cleartext();
        let enc = KeysSend::new(&cout, &sess_id, &calgos);
        let dec = KeysRecv::new(&cout, &sess_id, &calgos);
        ckeys.rekey_send(enc, true);
        ckeys.rekey_recv(dec);

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
        let dec_payload = &b[SSH_PAYLOAD_START..SSH_PAYLOAD_START + l];
        assert_eq!(payload, dec_payload);
    }
}
