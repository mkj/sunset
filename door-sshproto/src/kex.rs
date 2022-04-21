use crate::encrypt::{Cipher, Integ};
use crate::ident::RemoteVersion;
use crate::namelist::LocalNames;
use crate::wireformat::BinString;
use crate::packets::Packet;
use crate::*;
use ring::digest::{self, Context as DigestCtx, Digest};
use ring::agreement;
#[allow(unused_imports)]
use {
    crate::error::{Error,TrapBug},
    log::{debug, error, info, log, trace, warn},
};

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

const empty_localnames: LocalNames = LocalNames(&[]);

// TODO this will be configurable.
const fixed_options_kex: LocalNames =
    LocalNames(&[SSH_NAME_CURVE25519, SSH_NAME_CURVE25519_LIBSSH]);
const fixed_options_hostkey: LocalNames =
    LocalNames(&[SSH_NAME_ED25519, SSH_NAME_RSA_SHA256, SSH_NAME_RSA_SHA1]);

const fixed_options_cipher: LocalNames = LocalNames(&[SSH_NAME_CHAPOLY, SSH_NAME_AES256_CTR]);
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
        kex: &Kex, algos: &Algos, algo_conf: &AlgoConfig, remote_version: &RemoteVersion,
        remote_kexinit: &packets::KexInit,
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
        //    mpint     e, exchange value sent by the client
        //    mpint     f, exchange value sent by the server
        //    mpint     K, the shared secret

        let mut hash_ctx = DigestCtx::new(algos.kex.get_hash());
        let remote_version = remote_version.version().ok_or(Error::Bug)?;
        // Recreate our own kexinit packet to hash
        let own_kexinit = kex.make_kexinit(algo_conf);
        if algos.is_client {
            hash_ctx.update(ident::OUR_VERSION);
            hash_ctx.update(remote_version);
            wireformat::hash_ssh(&mut hash_ctx, &own_kexinit)?;
            wireformat::hash_ssh(&mut hash_ctx, remote_kexinit)?;
        } else {
            hash_ctx.update(remote_version);
            hash_ctx.update(ident::OUR_VERSION);
            wireformat::hash_ssh(&mut hash_ctx, remote_kexinit)?;
            wireformat::hash_ssh(&mut hash_ctx, &own_kexinit)?
        }
        // The remainder of hash_ctx is updated after kexdhreply

        Ok(KexHash {
            hash_ctx,
        })
    }

    // Compute the remainder of the hash
    fn finish(mut self, host_key: &[u8], e: &[u8], f: &[u8], k: &[u8]) -> Digest {
        self.hash_ctx.update(host_key);
        self.hash_ctx.update(e);
        self.hash_ctx.update(f);
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
    pub fn new() -> Self {
        let mut our_cookie = [0u8; 16];
        random::fill_random(our_cookie.as_mut_slice());
        Kex { our_cookie, algos: None, kex_hash: None }
    }
    /// Returns `Option<Packet>` with an optional kexdhinit message to send
    pub fn handle_kexinit<'a>(
        &'a mut self, is_client: bool, algo_conf: &AlgoConfig,
        remote_version: &RemoteVersion, remote_kexinit: &packets::KexInit,
    ) -> Result<Option<Packet<'a>>, Error> {
        let algos = Self::algo_negotiation(is_client, remote_kexinit, algo_conf)?;
        self.kex_hash = Some(KexHash::new(self,
            &algos,
            algo_conf,
            remote_version,
            remote_kexinit,
        )?);
        self.algos = Some(algos);


        if is_client {
            if let Some(algos) = &mut self.algos {
                return Ok(Some(algos.kex.make_kexdhinit()?))
            }
        }
        Ok(None)
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
            lang_c2s: (&empty_localnames).into(),
            lang_s2c: (&empty_localnames).into(),
            first_follows: false,
            reserved: 0,
        };
        packets::Packet::KexInit(k)
    }


    // returns packet to send, and H exchange hash
    pub fn handle_kexdhreply<'a>(&'a mut self, p: &packets::KexDHReply)
        -> Result<(Packet, Digest), Error> {
        let algos = self.algos.take().ok_or_else(|| Error::bug())?;
        // let H = self.finish_kexhash(p.k_s, )
        // self.algos.kex.
        todo!()
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
            _ => Err(Error::Bug),
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
        match self {
            SharedSecret::KexCurve25519(k) => k.make_kexdhinit()

        }
    }

    // server only
    fn make_kexdhreply(&self) -> Result<Packet, Error> {
        match self {
            SharedSecret::KexCurve25519(k) => k.make_kexdhreply()

        }
        // then sign it.
    }

    // client only
    fn handle_kexdhreply<'a>(self, kh: &mut KexHash, p: &Packet) -> Result<Packet<'a>, Error> {
        // let K = match self {
        //     SharedSecret::KexCurve25519(k) => k.handle_kexdhreply(p)
        // }
        todo!()
    }
}

#[derive(Debug)]
pub(crate) struct KexCurve25519 {
    ours: agreement::EphemeralPrivateKey,
    pubkey: agreement::PublicKey,
}

impl KexCurve25519 {
    fn new() -> Result<Self, Error> {
        let ours = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &ring::rand::SystemRandom::new()).trap()?;
        let pubkey = ours.compute_public_key().trap()?;
        Ok(KexCurve25519 {
            // TODO random source. also failure modes are unclear
            ours: ours,
            pubkey: pubkey,
        })
    }
    // TODO: can we remove all the lifetimes?
    fn make_kexdhinit<'a>(&'a self) -> Result<Packet<'a>, Error> {
        Ok(Packet::KexDHInit(
            packets::KexDHInit { q_c: BinString(self.pubkey.as_ref()) } ))
    }

    fn make_kexdhreply<'a>(&'a self) -> Result<Packet<'a>, Error> {
        todo!();
        // Ok(Packet::KexDHInit(KexDHInit::Curve25519Init(
    }

    fn handle_kexdhreply<'a>(self, kh: &mut KexHash, sessid: &Option<Digest>,
            theirs: &[u8]) -> Result<Packet<'a>, Error> {
        let theirs = agreement::UnparsedPublicKey::new(&agreement::X25519, &theirs);
        let k = agreement::agree_ephemeral(self.ours, &theirs, Error::Bug,
            |k| {
                todo!();
                Ok(())
            });

        // Ok(Packet::KexDHInit(KexDHInit::Curve25519Init(
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt;
    use crate::error::Error;
    use crate::kex;

    #[test]
    fn test_name_match() {
        // check that the from_name() functions are complete
        for k in kex::fixed_options_kex.0.iter() {
            let n = kex::SharedSecret::from_name(k).unwrap();
            println!("{k} {n:?}");
        }
        for k in kex::fixed_options_cipher.0.iter() {
            let n = encrypt::Cipher::from_name(k).unwrap();
            println!("{k} {n:?}");
        }
        for k in kex::fixed_options_mac.0.iter() {
            let n = encrypt::Integ::from_name(k).unwrap();
            println!("{k} {n:?}");
        }
        // unknown names fail
        kex::SharedSecret::from_name("bad").unwrap_err();
        encrypt::Cipher::from_name("bad").unwrap_err();
        encrypt::Integ::from_name("bad").unwrap_err();
    }
}
