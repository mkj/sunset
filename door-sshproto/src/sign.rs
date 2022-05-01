use crate::sshnames::SSH_NAME_RSA_SHA256;

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::*;
use crate::sshnames::*;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use crate::packets::{PubKey,Signature};
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
                    trace!(target: "hexdump", "pubkey {:?}", k.key.hex_dump());
                    UnparsedPublicKey::new(&ED25519, &k.key)
                } else {
                    return Err(Error::SignatureMismatch { key: "todo", sig: "ed25519todo" })
                };
                let sig = if let Signature::Ed25519(sig) = sig {
                    sig.sig.0
                } else {
                    return Err(Error::SignatureMismatch { key: "todo", sig: "ed25519todo" })
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

