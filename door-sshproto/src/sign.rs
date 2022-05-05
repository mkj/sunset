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

// RSA requires alloc.

#[derive(Debug)]
pub(crate) enum SigType {
    Ed25519,
    #[cfg(alloc)]
    RSA256,
    // Ecdsa
}

impl SigType {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            SSH_NAME_ED25519 => Ok(SigType::Ed25519),
            #[cfg(alloc)]
            SSH_NAME_RSA_SHA256 => Ok(SigType::RSA256),
            _ => Err(Error::bug()),
        }
    }

    pub fn verify(
        &self, pubkey: &PubKey, message: &[u8], sig: &Signature) -> Result<()> {

        match self {
            SigType::Ed25519 => {
                let pubkey = if let PubKey::Ed25519(k) = pubkey {
                    UnparsedPublicKey::new(&ED25519, &k.key)
                } else {
                    return Err(Error::SignatureMismatch {
                        // TODO
                        key: "todo".into(), sig: "ed25519todo".into() })
                };
                let sig = if let Signature::Ed25519(sig) = sig {
                    sig.sig.0
                } else {
                    return Err(Error::SignatureMismatch { key: "todo".into(), sig: "ed25519todo".into() })
                };
                trace!(target: "hexdump", "verify message {:?}", message.hex_dump());
                trace!(target: "hexdump", "sig {:?}", sig.hex_dump());
                pubkey.verify(message, sig).map_err(|_| Error::BadSignature)
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
