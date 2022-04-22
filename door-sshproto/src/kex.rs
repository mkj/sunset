// TODO: for fixed_ names, remove once they're removed
#![allow(non_upper_case_globals)]

use core::marker::PhantomData;
use core::fmt;

use crate::encrypt::{Cipher, Integ, Keys};
use crate::ident::RemoteVersion;
use crate::namelist::LocalNames;
use crate::packets::Packet;
use crate::wireformat::BinString;
use crate::*;
use ring::agreement;
use ring::digest::{self, Context as DigestCtx, Digest};
use ring::signature::Signature;
#[allow(unused_imports)]
use {
    crate::error::{Error, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

// #[cfg(test)]
use pretty_hex::PrettyHex;

// RFC8731
pub const SSH_NAME_CURVE25519: &str = "curve25519-sha256";
// An older alias prior to standardisation. Eventually could be removed
pub const SSH_NAME_CURVE25519_LIBSSH: &str = "curve25519-sha256@libssh.org";
// RFC8308 Extension Negotiation
pub const SSH_NAME_EXT_INFO_S: &str = "ext-info-s";
pub const SSH_NAME_EXT_INFO_C: &str = "ext-info-c";

// RFC8709
pub const SSH_NAME_ED25519: &str = "ssh-ed25519";
// RFC8332
pub const SSH_NAME_RSA_SHA256: &str = "rsa-sha2-256";
// RFC4253
pub const SSH_NAME_RSA_SHA1: &str = "ssh-rsa";

// RFC4344
pub const SSH_NAME_AES256_CTR: &str = "aes256-ctr";
// OpenSSH PROTOCOL.chacha20poly1305.txt
pub const SSH_NAME_CHAPOLY: &str = "chacha20-poly1305@openssh.com";
// OpenSSH PROTOCOL.
pub const SSH_NAME_AES256_GCM: &str = "aes256-gcm@openssh.com";
// (No-one uses aes-gcm RFC5647 from the NSA, it fails to define mac negotiation
// sensibly and has horrible naming style)

// RFC6668
pub const SSH_NAME_HMAC_SHA256: &str = "hmac-sha2-256";

// RFC4253
pub const SSH_NAME_NONE: &str = "none";

const EMPTY_LOCALNAMES: LocalNames = LocalNames(&[]);

// TODO this will be configurable.
const fixed_options_kex: LocalNames =
    LocalNames(&[SSH_NAME_CURVE25519, SSH_NAME_CURVE25519_LIBSSH]);
const fixed_options_hostkey: LocalNames =
    LocalNames(&[SSH_NAME_ED25519, SSH_NAME_RSA_SHA256, SSH_NAME_RSA_SHA1]);

const fixed_options_cipher: LocalNames =
    LocalNames(&[SSH_NAME_CHAPOLY, SSH_NAME_AES256_CTR]);
const fixed_options_mac: LocalNames = LocalNames(&[SSH_NAME_HMAC_SHA256]);
const fixed_options_comp: LocalNames = LocalNames(&[SSH_NAME_NONE]);

pub(crate) struct AlgoConfig<'a> {
    kexs: LocalNames<'a>,
    hostkeys: LocalNames<'a>,
    ciphers: LocalNames<'a>,
    macs: LocalNames<'a>,
    comps: LocalNames<'a>,
}

impl<'a> AlgoConfig<'a> {
    /// Creates the standard algorithm configuration
    /// TODO: ext-info-s and ext-info-c
    pub fn new(is_client: bool) -> Self {
        AlgoConfig {
            kexs: fixed_options_kex,
            hostkeys: fixed_options_hostkey,
            ciphers: fixed_options_cipher,
            macs: fixed_options_mac,
            comps: fixed_options_comp,
        }
    }
}

#[allow(non_snake_case)]
pub(crate) struct Kex {
    // TODO: we could be tricky here and have an enum that saves memory
    // by only keeping currently required fields. to be done once the structure
    // stabilises

    // Cookie sent in our KexInit packet. Kept so that we can reproduce the
    // KexInit packet when calculating the exchange hash.
    our_cookie: [u8; 16],

    // populated once we have sent and received KexInit
    algos: Option<Algos>,

    kex_hash: Option<KexHash>,
}

struct KexHash {
    hash_ctx: DigestCtx,
}

// kexhash state. progessively include version idents, kexinit payloads, hostkey, e/f, secret
impl KexHash {
    fn new(
        kex: &Kex, algos: &Algos, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion, remote_kexinit: &packets::Packet,
    ) -> Result<Self, Error> {
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

        let mut hash_ctx = DigestCtx::new(algos.kex.get_hash());
        let remote_version = remote_version.version().trap()?;
        // Recreate our own kexinit packet to hash.
        // The remote packet is missing packet type so we add it.
        let own_kexinit = kex.make_kexinit(algo_conf);
        if algos.is_client {
            hash_ctx.update(ident::OUR_VERSION);
            hash_ctx.update(remote_version);
            wireformat::hash_ssh(&mut hash_ctx, &own_kexinit)?;
            // hash_ctx.update(&[packets::MessageNumber::SSH_MSG_KEXINIT as u8]);
            wireformat::hash_ssh(&mut hash_ctx, remote_kexinit)?;
        } else {
            hash_ctx.update(remote_version);
            hash_ctx.update(ident::OUR_VERSION);
            // hash_ctx.update(&[packets::MessageNumber::SSH_MSG_KEXINIT as u8]);
            wireformat::hash_ssh(&mut hash_ctx, remote_kexinit)?;
            wireformat::hash_ssh(&mut hash_ctx, &own_kexinit)?
        }
        // The remainder of hash_ctx is updated after kexdhreply

        Ok(KexHash { hash_ctx })
    }

    // Fill everything except K
    fn prefinish(&mut self, host_key: &[u8], q_c: &[u8], q_s: &[u8]) {
        self.hash_ctx.update(host_key);
        self.hash_ctx.update(q_c);
        self.hash_ctx.update(q_s);
    }

    // Compute the remainder of the hash, consuming KexHash
    fn finish(mut self, k: &[u8]) -> Digest {
        self.hash_ctx.update(k);
        self.hash_ctx.finish()
    }
}

enum KexState {
    New,
    SentKexInit,
    RecvKexInit,
    //... todo
}

/// Records the chosen algorithms while key exchange proceeds
pub(crate) struct Algos {
    pub kex: SharedSecret,
    // hostkey: HostKey,
    pub cipher_enc: Cipher,
    pub cipher_dec: Cipher,
    pub integ_enc: Integ,
    pub integ_dec: Integ,

    // avoid having to keep passing it separately, though this
    // is global state.
    pub is_client: bool,
}

impl Kex {
    pub fn new() -> Result<Self, Error> {
        let mut our_cookie = [0u8; 16];
        random::fill_random(our_cookie.as_mut_slice())?;
        Ok(Kex { our_cookie, algos: None, kex_hash: None })
    }

    /// Returns `Option<Packet>` with an optional kexdhinit message to send
    pub fn handle_kexinit<'a>(
        &'a mut self, is_client: bool, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion, p: &packets::Packet,
    ) -> Result<Option<Packet<'a>>, Error> {
        let remote_kexinit = if let Packet::KexInit(k) = p {
            k
        } else {
            return Err(Error::bug())
        };
        let algos = Self::algo_negotiation(is_client, remote_kexinit, algo_conf)?;
        self.kex_hash = Some(KexHash::new(
            self,
            &algos,
            algo_conf,
            remote_version,
            p,
        )?);
        self.algos = Some(algos);

        if is_client {
            Ok(Some(self.algos.as_ref().trap()?.kex.make_kexdhinit()?))
        } else {
            Ok(None)
        }
    }

    pub fn make_kexinit<'a>(&self, conf: &'a AlgoConfig) -> packets::Packet<'a> {
        let k = packets::KexInit {
            cookie: self.our_cookie,
            kex: (&conf.kexs).into(),
            hostkey: (&conf.hostkeys).into(),
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
        };
        packets::Packet::KexInit(k)
    }

    fn make_kexdhinit(&self) -> Result<Packet, Error> {
        let algos = self.algos.as_ref().trap()?;
        if !algos.is_client {
            return Err(Error::bug());
        }
        algos.kex.make_kexdhinit()
    }

    // returns packet to send, and kex output
    // consumes self.
    pub fn handle_kexdhinit<'a>(
        self, p: &packets::KexDHInit, sess_id: &Option<Digest>,
    ) -> Result<KexOutput, Error> {
        if self.algos.as_ref().trap()?.is_client {
            return Err(Error::bug());
        }
        SharedSecret::handle_kexdhinit(self, p, sess_id)
    }

    // returns packet to send, and H exchange hash.
    // consumes self.
    pub fn handle_kexdhreply<'a>(
        self, p: &packets::KexDHReply, sess_id: &Option<Digest>,
    ) -> Result<KexOutput, Error> {
        if !self.algos.as_ref().trap()?.is_client {
            return Err(Error::bug());
        }
        SharedSecret::handle_kexdhreply(self, p, sess_id)
    }

    /// Perform SSH algorithm negotiation
    fn algo_negotiation(
        is_client: bool, p: &packets::KexInit, conf: &AlgoConfig,
    ) -> Result<Algos, Error> {
        // For each algorithm we select the first name in the client's
        // list that is also present in the server's list.
        let kex_method = p
            .kex
            .first_match(is_client, &conf.kexs)?
            .ok_or(Error::AlgoNoMatch { algo: "kex" })?;
        let kex = SharedSecret::from_name(kex_method)?;
        let hostkey_method = p
            .hostkey
            .first_match(is_client, &conf.hostkeys)?
            .ok_or(Error::AlgoNoMatch { algo: "hostkey" })?;

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

        // Ignore language fields at present. unsure which implementations
        // use it, possibly SunSSH

        Ok(Algos { kex, cipher_enc, cipher_dec, integ_enc, integ_dec, is_client })
    }
}

/// Negotiated Key Exchange (KEX) type, used to parse kexinit/kexreply packets.
#[derive(Debug)]
pub enum KexType {
    Curve25519,
    // DiffieHellman,
}

#[derive(Debug)]
pub(crate) enum SharedSecret {
    KexCurve25519(KexCurve25519),
    // ECDH?
}

impl SharedSecret {
    fn from_name(name: &str) -> Result<Self, Error> {
        match name {
            SSH_NAME_CURVE25519 | SSH_NAME_CURVE25519_LIBSSH => {
                Ok(SharedSecret::KexCurve25519(KexCurve25519::new()?))
            }
            _ => Err(Error::bug()),
        }
    }

    fn get_type(&self) -> KexType {
        match self {
            SharedSecret::KexCurve25519(_) => KexType::Curve25519,
        }
    }

    pub(crate) fn get_hash(&self) -> &'static digest::Algorithm {
        match self {
            SharedSecret::KexCurve25519(_) => &digest::SHA256,
        }
    }

    fn make_kexdhinit(&self) -> Result<Packet, Error> {
        let q_c = match self {
            SharedSecret::KexCurve25519(k) => k.pubkey(),
        };
        let q_c = BinString(q_c);
        Ok(Packet::KexDHInit(packets::KexDHInit { q_c }))
    }

    // client only
    fn handle_kexdhreply<'a>(
        mut kex: Kex, p: &packets::KexDHReply, sess_id: &Option<Digest>,
    ) -> Result<KexOutput, Error> {
        // let mut algos = kex.algos.take().trap()?;
        let mut algos = kex.algos.trap()?;
        let mut kex_hash = kex.kex_hash.take().trap()?;
        kex_hash.prefinish(p.k_s.0, algos.kex.pubkey(), p.q_s.0);
        let kex_out = match algos.kex {
            SharedSecret::KexCurve25519(_) => {
                KexCurve25519::secret(&mut algos, p.q_s.0, kex_hash, sess_id)?
            }
        };
        warn!("Need to validate signature");
        Ok(kex_out)
    }

    // server only. consumes kex.
    fn handle_kexdhinit<'a>(
        mut kex: Kex, p: &packets::KexDHInit, sess_id: &Option<Digest>,
    ) -> Result<KexOutput, Error> {
        // let mut algos = kex.algos.take().trap()?;
        let mut algos = kex.algos.trap()?;
        let mut kex_hash = kex.kex_hash.take().trap()?;
        kex_hash.prefinish(&[], p.q_c.0, algos.kex.pubkey());
        let mut kex_out = match algos.kex {
            SharedSecret::KexCurve25519(_) => {
                KexCurve25519::secret(&mut algos, p.q_c.0, kex_hash, sess_id)?
            }
        };

        kex_out.shsec = Some(algos.kex);
        Ok(kex_out)
    }

    fn pubkey<'a>(&'a self) -> &'a [u8] {
        match self {
            SharedSecret::KexCurve25519(k) => k.pubkey(),
        }
    }
}

pub(crate) struct KexOutput {
    h: Digest,
    keys: Keys,

    // storage for kex packet reply contents that outlives Kex
    shsec: Option<SharedSecret>,
    sig: Option<Signature>,
}

impl fmt::Debug for KexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KexOutput, shsec {} sig {}",
            self.shsec.is_some(), self.sig.is_some())
    }
}

impl<'a> KexOutput {
    fn make(
        k: &[u8], algos: &Algos, kex_hash: KexHash, sess_id: &Option<Digest>,
    ) -> Result<Self, Error> {
        let h = kex_hash.finish(k);

        let sess_id = sess_id.as_ref().unwrap_or(&h);
        let keys = Keys::new_from(k, &h, &sess_id, algos)?;

        Ok(KexOutput { h, keys, shsec: None, sig: None })
    }

    // server only
    pub fn make_kexdhreply(&'a self) -> Result<Packet<'a>, Error> {
        let q_s = self.shsec.as_ref().trap()?.pubkey();
        let q_s = BinString(q_s);
        let k_s = BinString(&[]); // TODO
        let sig = BinString(&[]);
        Ok(Packet::KexDHReply(packets::KexDHReply { k_s, q_s, sig }))
        // then sign it.
    }

}

#[derive(Debug)]
pub(crate) struct KexCurve25519 {
    ours: Option<agreement::EphemeralPrivateKey>,
    pubkey: agreement::PublicKey,
}

impl KexCurve25519 {
    fn new() -> Result<Self, Error> {
        let ours = agreement::EphemeralPrivateKey::generate(
            &agreement::X25519,
            &ring::rand::SystemRandom::new(),
        )
        .trap()?;
        let pubkey = ours.compute_public_key().trap()?;
        Ok(KexCurve25519 { ours: Some(ours), pubkey })
    }

    fn pubkey<'a>(&'a self) -> &'a [u8] {
        self.pubkey.as_ref()
    }

    fn secret<'a>(
        algos: &mut Algos, theirs: &[u8], kex_hash: KexHash,
        sess_id: &Option<Digest>,
    ) -> Result<KexOutput, Error> {
        let kex = if let SharedSecret::KexCurve25519(k) = &mut algos.kex {
            k
        } else {
            return Err(Error::bug());
        };
        let ours = kex.ours.take().trap()?;
        let theirs = agreement::UnparsedPublicKey::new(&agreement::X25519, &theirs);
        let o = agreement::agree_ephemeral(
            ours,
            &theirs,
            Error::Custom { msg: "x25519 agree failed" },
            |k| {
                let o = KexOutput::make(k, algos, kex_hash, sess_id);
                trace!("kexout , is_err {}", o.is_err());
                o
            },
        );
        trace!("agree");
        o
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt;
    use crate::error::Error;
    use crate::ident::RemoteVersion;
    use crate::kex;
    use crate::packets::Packet;
    use crate::*;
    use pretty_hex::PrettyHex;

    use super::SSH_NAME_CURVE25519;

    #[test]
    fn test_name_match() {
        // check that the from_name() functions are complete
        for k in kex::fixed_options_kex.0.iter() {
            let n = kex::SharedSecret::from_name(k).unwrap();
        }
        for k in kex::fixed_options_cipher.0.iter() {
            let n = encrypt::Cipher::from_name(k).unwrap();
        }
        for k in kex::fixed_options_mac.0.iter() {
            let n = encrypt::Integ::from_name(k).unwrap();
        }
    }

    // unknown names fail.
    #[test]
    #[should_panic]
    fn test_unknown_kex() {
        kex::SharedSecret::from_name("bad").unwrap();
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
    fn reserialize<'a>(out_buf: &'a mut [u8], p: Packet) -> Packet<'a> {
        wireformat::write_ssh(out_buf, &p).unwrap();
        wireformat::packet_from_bytes(out_buf).unwrap()
    }

    #[test]
    fn test_agree_kex() {
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
        let si = serv.make_kexinit(&serv_conf);
        let si = reserialize(&mut bufs, si);
        let ci = cli.make_kexinit(&cli_conf);
        let ci = reserialize(&mut bufc, ci);

        serv.handle_kexinit(false, &serv_conf, &cli_version, &ci).unwrap();
        cli.handle_kexinit(true, &cli_conf, &serv_version, &si).unwrap();

        let ci = cli.make_kexdhinit().unwrap();
        let ci = if let Packet::KexDHInit(k) = ci { k } else { panic!() };
        let sout = serv.handle_kexdhinit(&ci, &None).unwrap();
        let kexreply = sout.make_kexdhreply().unwrap();

        let kexreply = if let Packet::KexDHReply(k) = kexreply { k } else { panic!() };
        let cout = cli.handle_kexdhreply(&kexreply, &None).unwrap();

        assert_eq!(cout.h.as_ref(), sout.h.as_ref());
    }
}
