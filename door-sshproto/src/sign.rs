use crate::{sshnames::SSH_NAME_RSA_SHA256, packets::Ed25519PubKey};

#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use crate::*;
use crate::sshnames::*;
use ring::signature::{KeyPair, Ed25519KeyPair, UnparsedPublicKey, ED25519};
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
            Ed25519 => SSH_NAME_ED25519,
            RSA256 => SSH_NAME_RSA_SHA256,
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
                let k = UnparsedPublicKey::new(&ED25519, &k.key);
                let s = s.sig.0;
                trace!(target: "hexdump", "sig {:?}", s.hex_dump());
                k.verify(message, s).map_err(|_| Error::BadSignature)
            }

            (SigType::RSA256, ..) => {
                // TODO
                warn!("RSA256 is not implemented for no_std");
                Err(Error::BadSignature)
            }

            _ => {
                Err(Error::SignatureMismatch {
                    key: pubkey.algorithm_name().into(),
                    sig: "ed25519todo".into()
                })
            }
        }
    }
}

pub enum SignKey {
    Ed25519(Ed25519KeyPair),
}

impl SignKey {
    pub fn pubkey(&self) -> PubKey {
        match self {
            SignKey::Ed25519(k) => {PubKey::Ed25519(Ed25519PubKey
                { key: BinString(k.public_key().as_ref()) } )
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::sshnames::SSH_NAME_ED25519;
    use crate::{packets, wireformat};
    use crate::sign::*;
    use crate::wireformat::tests::assert_serialize_equal;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use crate::doorlog::init_test_log;

    pub(crate) fn make_ed25519_signkey() -> SignKey {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes =
            ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let ed = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .unwrap();
        sign::SignKey::Ed25519(ed)
    }

}
