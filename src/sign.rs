
#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use core::ops::Deref;

use signature::Verifier;
use zeroize::ZeroizeOnDrop;

use crate::*;
use packets::ParseContext;
use sshnames::*;
use packets::{PubKey, Signature, Ed25519PubKey};
use sshwire::{BinString, SSHEncode, Blob};

use pretty_hex::PrettyHex;

use core::mem::discriminant;

use digest::Digest;

#[cfg(feature = "rsa")]
use rsa::signature::{DigestVerifier, DigestSigner};
#[cfg(feature = "rsa")]
use packets::RSAPubKey;

// #[cfg(feature = "rsa")]
// use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};

// RSA requires alloc.

#[derive(Debug, Clone, Copy)]
pub enum SigType {
    Ed25519,
    #[cfg(feature = "rsa")]
    RSA,
    // Ecdsa
}

impl SigType {
    /// Must be a valid name
    pub fn from_name(name: &'static str) -> Result<Self> {
        match name {
            SSH_NAME_ED25519 => Ok(SigType::Ed25519),
            #[cfg(feature = "rsa")]
            SSH_NAME_RSA_SHA256 => Ok(SigType::RSA),
            _ => Err(Error::bug()),
        }
    }

    /// Returns a valid name
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            SigType::Ed25519 => SSH_NAME_ED25519,
            #[cfg(feature = "rsa")]
            SigType::RSA => SSH_NAME_RSA_SHA256,
        }
    }

    /// Returns `Ok(())` on success
    pub fn verify(
        &self, pubkey: &PubKey, msg: &dyn SSHEncode, sig: &Signature, parse_ctx: Option<&ParseContext>) -> Result<()> {

        // Check that the signature type is known
        let sig_type = sig.sig_type().map_err(|_| Error::BadSig)?;

        // `self` is the expected signature type from kex/auth packet
        // This would also get caught by SignatureMismatch below
        // but that error message is intended for mismatch key vs sig.
        if discriminant(&sig_type) != discriminant(self) {
            warn!("Received {:?} signature, expecting {}",
                sig.algorithm_name(), self.algorithm_name());
            return Err(Error::BadSig)
        }

        match (self, pubkey, sig) {

            (SigType::Ed25519, PubKey::Ed25519(k), Signature::Ed25519(s)) => {
                let k: &[u8; 32] = &k.key.0;
                let k: salty::PublicKey = k.try_into().map_err(|_| Error::BadKey)?;
                let s: &[u8; 64] = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
                let s: salty::Signature = s.into();
                k.verify_parts(&s, |h| {
                    sshwire::hash_ser(h, msg, parse_ctx).map_err(|_| salty::Error::ContextTooLong)
                })
                .map_err(|_| Error::BadSig)
            }

            #[cfg(feature = "rsa")]
            (SigType::RSA, PubKey::RSA(k), Signature::RSA(s)) => {
                let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new_with_prefix(k.key.clone());
                let s: Box<[u8]> = s.sig.0.into();
                let signature = s.into();

                let mut h = sha2::Sha256::new();
                sshwire::hash_ser(&mut h, msg, parse_ctx)?;
                verifying_key.verify_digest(h, &signature)
                .map_err(|e| {
                    trace!("RSA signature failed: {e}");
                    Error::BadSig
                })
            }

            _ => {
                warn!("Signature \"{:?}\" doesn't match key type \"{:?}\"",
                    sig.algorithm_name(),
                    pubkey.algorithm_name(),
                    );
                Err(Error::BadSig)
            }
        }
    }
}

pub enum OwnedSig {
    // salty::Signature doesn't let us borrow the inner bytes,
    // so we just store raw bytes here.
    Ed25519([u8; 64]),
    #[cfg(feature = "rsa")]
    RSA(rsa::pkcs1v15::Signature),
}

impl From<salty::Signature> for OwnedSig {
    fn from(s: salty::Signature) -> Self {
        OwnedSig::Ed25519(s.to_bytes())
    }
}

#[cfg(feature = "rsa")]
impl From<rsa::pkcs1v15::Signature> for OwnedSig {
    fn from(s: rsa::pkcs1v15::Signature) -> Self {
        OwnedSig::RSA(s)
    }
}

impl TryFrom<Signature<'_>> for OwnedSig {
    type Error = Error;
    fn try_from(s: Signature) -> Result<Self> {
        match s {
            Signature::Ed25519(s) => {
                let s: [u8; 64] = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
                Ok(OwnedSig::Ed25519(s))
            }
            #[cfg(feature = "rsa")]
            Signature::RSA(s) => {
                let s: Box<[u8]> = s.sig.0.into();
                Ok(OwnedSig::RSA(s.into()))
            }
            Signature::Unknown(u) => {
                debug!("Unknown {u} signature");
                Err(Error::UnknownMethod {kind: "signature" })
            }
        }
    }
}
/// Signing key types.
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519,
    #[cfg(feature = "rsa")]
    RSA,
}

/// A SSH signing key.
///
/// This may hold the private key part locally
/// or potentially send the signing requests to an SSH agent or other entity.
#[derive(ZeroizeOnDrop, Clone)]
pub enum SignKey {
    // 32 byte seed value is the private key
    Ed25519([u8; 32]),

    #[zeroize(skip)]
    AgentEd25519(salty::PublicKey),

    #[cfg(feature = "rsa")]
    // TODO zeroize doesn't seem supported? though BigUint has Zeroize
    #[zeroize(skip)]
    RSA(rsa::RsaPrivateKey),

    #[cfg(feature = "rsa")]
    #[zeroize(skip)]
    AgentRSA(rsa::RsaPublicKey),
}

impl SignKey {
    pub fn generate(ty: KeyType, bits: Option<usize>) -> Result<Self> {
        match ty {
            KeyType::Ed25519 => {
                if bits.unwrap_or(256) != 256 {
                    return Err(Error::msg("Bad key size"));
                }
                let mut seed = [0u8; 32];
                random::fill_random(&mut seed)?;
                Ok(Self::Ed25519(seed))
            },

            #[cfg(feature = "rsa")]
            KeyType::RSA => {
                let bits = bits.unwrap_or(config::RSA_DEFAULT_KEYSIZE);
                if bits < config::RSA_MIN_KEYSIZE
                    || bits > rsa::RsaPublicKey::MAX_SIZE
                    || (bits % 8 != 0) {
                    return Err(Error::msg("Bad key size"));
                }

                let k = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, bits)
                .map_err(|e| {
                    debug!("RSA key generation error {e}");
                    // RNG shouldn't fail, keysize has been checked
                    Error::bug()
                })?;
                Ok(Self::RSA(k))
            },
        }
    }

    pub fn pubkey(&self) -> PubKey {
        match self {
            SignKey::Ed25519(seed) => {
                let k = salty::Keypair::from(seed);
                PubKey::Ed25519(Ed25519PubKey
                { key: Blob(k.public.as_bytes().clone()) } )
            },

            SignKey::AgentEd25519(pk) => PubKey::Ed25519(Ed25519PubKey
                { key: Blob(pk.as_bytes().clone()) } ),


            #[cfg(feature = "rsa")]
            SignKey::RSA(k) => PubKey::RSA(RSAPubKey { key: k.deref().clone() }),

            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(pk) => PubKey::RSA(RSAPubKey { key: pk.clone() }),
        }
    }

    #[cfg(feature = "openssh-key")]
    pub fn from_openssh(k: impl AsRef<[u8]>) -> Result<Self> {
        let k = ssh_key::PrivateKey::from_openssh(k)
            .map_err(|_| {
                Error::msg("Unsupported OpenSSH key")
            })?;

        k.try_into()
    }

    pub fn from_agent_pubkey(pk: &PubKey) -> Result<Self> {
        match pk {
            PubKey::Ed25519(k) => {
                let k: salty::PublicKey = k.try_into().map_err(|_| Error::BadKey)?;
                Ok(Self::AgentEd25519(k))
            },

            #[cfg (feature = "rsa")]
            PubKey::RSA(k) => Ok(Self::AgentRSA(k.key.clone())),

            PubKey::Unknown(_) => {
                Err(Error::msg("Unsupported agent key"))
            }
        }
    }

    /// Returns whether this `SignKey` can create a given signature type
    pub(crate) fn can_sign(&self, sig_type: SigType) -> bool {
        match self {
            | SignKey::Ed25519(_)
            | SignKey::AgentEd25519(_)
            => matches!(sig_type, SigType::Ed25519),

            #[cfg(feature = "rsa")]
            | SignKey::RSA(_)
            | SignKey::AgentRSA(_)
            => matches!(sig_type, SigType::RSA),
        }
    }

    pub(crate) fn sign(&self, msg: &impl SSHEncode, parse_ctx: Option<&ParseContext>) -> Result<OwnedSig> {
        let sig: OwnedSig = match self {
            SignKey::Ed25519(seed) => {
                let k = salty::Keypair::from(seed);
                let sig = k.sign_parts(|h| {
                    sshwire::hash_ser(h, msg, parse_ctx).map_err(|_| salty::Error::ContextTooLong)
                })
                .trap()?;
                sig.into()
            }

            #[cfg(feature = "rsa")]
            SignKey::RSA(k) => {
                let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new_with_prefix(k.clone());
                let mut h = sha2::Sha256::new();
                sshwire::hash_ser(&mut h, msg, parse_ctx)?;
                let sig = signing_key.try_sign_digest(h).map_err(|e| {
                    trace!("RSA signing failed: {e:?}");
                    Error::bug()
                })?;
                sig.into()
            }

            // callers should check for agent keys first
            | SignKey::AgentEd25519(_) => return Error::bug_msg("agent sign"),
            #[cfg(feature = "rsa")]
            | SignKey::AgentRSA(_) => return Error::bug_msg("agent sign"),

        };

        // {
        //     // Faults in signing can expose the private key. We verify the signature
        //     // just created to avoid this problem.
        //     // TODO: Maybe this needs to be configurable for slow platforms?
        //     let vsig: Signature = (&sig).into();
        //     let sig_type = vsig.sig_type().unwrap();
        //     sig_type.verify(&self.pubkey(), msg, &vsig, parse_ctx)?;
        // }

        Ok(sig)
    }

    pub(crate) fn is_agent(&self) -> bool {
        match self {
            SignKey::Ed25519(_) => false,
            #[cfg(feature = "rsa")]
            SignKey::RSA(_) => false,

            SignKey::AgentEd25519(_) => true,
            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(_) => true,
        }
    }
}

impl core::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::Ed25519(_) => "Ed25519",
            Self::AgentEd25519(_) => "AgentEd25519",
            #[cfg(feature = "rsa")]
            Self::RSA(_) => "RSA",
            #[cfg(feature = "rsa")]
            Self::AgentRSA(_) => "AgentRSA",
        };
        write!(f, "SignKey::{s}")
    }
}

#[cfg(feature = "openssh-key")]
impl TryFrom<ssh_key::PrivateKey> for SignKey {
    type Error = Error;
    fn try_from(k: ssh_key::PrivateKey) -> Result<Self> {
        match k.key_data() {
            ssh_key::private::KeypairData::Ed25519(k) => {
                Ok(SignKey::Ed25519(k.private.to_bytes()))
            }

            #[cfg(feature = "rsa")]
            ssh_key::private::KeypairData::Rsa(k) => {
                let primes = vec![
                    (&k.private.p).try_into().map_err(|_| Error::BadKey)?,
                    (&k.private.q).try_into().map_err(|_| Error::BadKey)?,
                ];
                let key = rsa::RsaPrivateKey::from_components(
                    (&k.public.n).try_into().map_err(|_| Error::BadKey)?,
                    (&k.public.e).try_into().map_err(|_| Error::BadKey)?,
                    (&k.private.d).try_into().map_err(|_| Error::BadKey)?,
                    primes,
                ).map_err(|_| Error::BadKey)?;
                Ok(SignKey::RSA(key))
            }
            _ => Err(Error::NotAvailable { what: k.algorithm().as_str() })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use crate::*;
    use sshnames::SSH_NAME_ED25519;
    use packets;
    use sign::*;
    use sunsetlog::init_test_log;

    // TODO: tests for sign()/verify() and invalid signatures
}
