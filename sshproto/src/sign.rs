use crate::{sshnames::SSH_NAME_RSA_SHA256, packets::Ed25519PubKey};

#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use rand::rngs::OsRng;
use ed25519_dalek as dalek;
use ed25519_dalek::{Verifier, Signer};

use crate::*;
use crate::sshnames::*;
use crate::packets::{PubKey,Signature};
use crate::wireformat::{BinString};
use pretty_hex::PrettyHex;

use core::mem::discriminant;

// RSA requires alloc.

#[derive(Debug)]
pub enum SigType {
    Ed25519,
    RSA256,
    // Ecdsa
}

impl SigType {
    /// Must be a valid name
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            SSH_NAME_ED25519 => Ok(SigType::Ed25519),
            SSH_NAME_RSA_SHA256 => Ok(SigType::RSA256),
            _ => Err(Error::bug()),
        }
    }

    /// Returns a valid name
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            SigType::Ed25519 => SSH_NAME_ED25519,
            SigType::RSA256 => SSH_NAME_RSA_SHA256,
        }
    }

    pub fn verify(
        &self, pubkey: &PubKey, message: &[u8], sig: &Signature) -> Result<()> {

        // Check that the signature type is known
        let sig_type = sig.sig_type()?;

        // `self` is the expected signature type from kex/auth packet
        // This would also get caught by SignatureMismatch below
        // but that error message is intended for mismatch key vs sig.
        if discriminant(&sig_type) != discriminant(self) {
            warn!("Received {} signature, expecting {}",
                sig.algorithm_name(), self.algorithm_name());
            return Err(Error::BadSignature)
        }

        match (self, pubkey, sig) {

            (SigType::Ed25519, PubKey::Ed25519(k), Signature::Ed25519(s)) => {
                let k = dalek::PublicKey::from_bytes(k.key.0).map_err(|_| Error::BadKey)?;
                let s = dalek::Signature::from_bytes(s.sig.0).map_err(|_| Error::BadSignature)?;
                k.verify(message, &s).map_err(|_| Error::BadSignature)
            }

            (SigType::RSA256, ..) => {
                // TODO
                warn!("RSA256 is not implemented for no_std");
                Err(Error::BadSignature)
            }

            _ => {
                Err(Error::SignatureMismatch {
                    key: pubkey.algorithm_name().into(),
                    sig: sig.algorithm_name().into(),
                })
            }
        }
    }
}

pub(crate) enum OwnedSig {
    // dalek::Signature doesn't let us borrow the inner bytes,
    // so we just store raw bytes here.
    Ed25519([u8; 64]),
    RSA256, // TODO
}

impl From<dalek::Signature> for OwnedSig {
    fn from(s: dalek::Signature) -> Self {
        OwnedSig::Ed25519(s.to_bytes())
    }

}

/// A SSH signing key. This may hold the private part locally
/// or could potentially send the signing requests to a SSH agent
/// or other entitiy.
pub enum SignKey {
    Ed25519(dalek::Keypair),
}

impl SignKey {
    pub fn pubkey(&self) -> PubKey {
        match self {
            SignKey::Ed25519(k) => {PubKey::Ed25519(Ed25519PubKey
                { key: BinString(k.public.as_bytes()) } )
            }
        }
    }

    pub fn from_openssh(k: impl AsRef<[u8]>) -> Result<Self> {
        let k = ssh_key::PrivateKey::from_openssh(k)
            .map_err(|_| {
                Error::msg("Unsupported OpenSSH key")
            })?;

        k.try_into()
    }

    pub(crate) fn sign_serialize<'s>(&self, msg: &'s impl serde::Serialize) -> Result<OwnedSig> {
        match self {
            SignKey::Ed25519(k) => {
                let exk: dalek::ExpandedSecretKey = (&k.secret).into();
                exk.sign_parts(|h| {
                    wireformat::hash_ser(h, msg).map_err(|_| dalek::SignatureError::new())
                }, &k.public)
                .trap()
                .map(|s| s.into())
            }
        }
    }
}

// TODO: this might go behind a feature?
impl TryFrom<ssh_key::PrivateKey> for SignKey {
    type Error = Error;
    fn try_from(k: ssh_key::PrivateKey) -> Result<Self> {
        match k.key_data() {
            ssh_key::private::KeypairData::Ed25519(k) => {
                let edk = dalek::Keypair {
                    secret: dalek::SecretKey::from_bytes(&k.private.to_bytes())
                        .map_err(|_| Error::BadKey)?,
                    public: dalek::PublicKey::from_bytes(&k.public.0)
                        .map_err(|_| Error::BadKey)?,
                };
                Ok(SignKey::Ed25519(edk))
            }
            _ => Err(Error::NotAvailable { what: k.algorithm().as_str() })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use rand::rngs::OsRng;
    use ed25519_dalek::Signer;

    use crate::sshnames::SSH_NAME_ED25519;
    use crate::{packets, wireformat};
    use crate::sign::*;
    use crate::wireformat::tests::assert_serialize_equal;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use crate::doorlog::init_test_log;

    pub(crate) fn make_ed25519_signkey() -> SignKey {
        let mut rng = OsRng{};
        let ed = dalek::Keypair::generate(&mut rng);
        sign::SignKey::Ed25519(ed)
    }

}
