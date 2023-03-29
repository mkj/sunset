
#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use salty::{SecretKey, PublicKey};
use signature::Verifier;
use zeroize::ZeroizeOnDrop;

use crate::*;
use packets::ParseContext;
use sshnames::*;
use packets::{PubKey, Signature, Ed25519PubKey};
use sshwire::{BinString, SSHEncode};

use pretty_hex::PrettyHex;

use core::mem::discriminant;

// RSA requires alloc.

#[derive(Debug, Clone, Copy)]
pub enum SigType {
    Ed25519,
    RSA256,
    // Ecdsa
}

impl SigType {
    /// Must be a valid name
    pub fn from_name(name: &'static str) -> Result<Self> {
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

    /// Returns `Ok(())` on success
    pub fn verify(
        &self, pubkey: &PubKey, msg: &impl SSHEncode, sig: &Signature, parse_ctx: Option<&ParseContext>) -> Result<()> {

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
                let k: &[u8; 32] = k.key.0.try_into().map_err(|_| Error::BadKey)?;
                let k: salty::PublicKey = k.try_into().map_err(|_| Error::BadKey)?;
                let s: &[u8; 64] = s.sig.0.try_into().map_err(|_| Error::BadSig)?;
                let s: salty::Signature = s.into();
                k.verify_parts(&s, |h| {
                    sshwire::hash_ser(h, msg, parse_ctx).map_err(|_| salty::Error::ContextTooLong)
                })
                .map_err(|_| Error::BadSig)
            }

            (SigType::RSA256, PubKey::RSA(_k), Signature::RSA256(_s)) => {
                // TODO
                warn!("RSA256 is not implemented for no_std");
                Err(Error::BadSig)
                // // untested
                // use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme};
                // let k: RsaPublicKey = k.try_into()?;
                // let h = sha2::Sha256::digest(message);
                // k.verify(rsa::padding::PaddingScheme::PKCS1v15Sign{ hash: rsa::hash::Hash::SHA2_256},
                //     &h,
                //     s.sig.0)
                // .map_err(|e| {
                //     trace!("RSA signature failed: {e}");
                //     Error::BadSig
                // })
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

pub(crate) enum OwnedSig {
    // salty::Signature doesn't let us borrow the inner bytes,
    // so we just store raw bytes here.
    Ed25519([u8; 64]),
    _RSA256, // TODO
}

impl From<salty::Signature> for OwnedSig {
    fn from(s: salty::Signature) -> Self {
        OwnedSig::Ed25519(s.to_bytes())
    }

}

/// Signing key types.
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519,
}

/// A SSH signing key. This may hold the private part locally
/// or could potentially send the signing requests to a SSH agent
/// or other entitiy.
#[derive(ZeroizeOnDrop)]
pub enum SignKey {
    // TODO bloat: this is an expanded keypair, we should store the raw bytes
    Ed25519(salty::Keypair),
}

impl SignKey {
    pub fn generate(ty: KeyType) -> Result<Self> {
        match ty {
            KeyType::Ed25519 => {
                let mut seed = [0u8; 32];
                random::fill_random(seed.as_mut_slice())?;
                Ok(Self::Ed25519((&seed).into()))
            },
        }
    }

    pub fn pubkey(&self) -> PubKey {
        match self {
            SignKey::Ed25519(k) => {PubKey::Ed25519(Ed25519PubKey
                { key: BinString(k.public.as_bytes()) } )
            }
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

    /// Returns whether this `SignKey` can create a given signature type
    pub(crate) fn can_sign(&self, sig_type: SigType) -> bool {
        match self {
            SignKey::Ed25519(_) => matches!(sig_type, SigType::Ed25519),
        }
    }

    pub(crate) fn sign(&self, msg: &impl SSHEncode, parse_ctx: Option<&ParseContext>) -> Result<OwnedSig> {
        let sig: OwnedSig = match self {
            SignKey::Ed25519(k) => {
                k.sign_parts(|h| {
                    sshwire::hash_ser(h, msg, parse_ctx).map_err(|_| salty::Error::ContextTooLong)
                })
                .trap()
                .map(|s| s.into())
            }
        }?;

        {
            // Faults in signing can expose the private key. We verify the signature
            // just created to avoid this problem.
            // TODO: Maybe this needs to be configurable for slow platforms?
            let vsig: Signature = (&sig).into();
            let sig_type = vsig.sig_type().unwrap();
            sig_type.verify(&self.pubkey(), msg, &vsig, parse_ctx)?;
        }

        Ok(sig)
    }
}

impl core::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignKey")
        .field("Ed25519", &"...")
        .finish()
    }
}

#[cfg(feature = "openssh-key")]
impl TryFrom<ssh_key::PrivateKey> for SignKey {
    type Error = Error;
    fn try_from(k: ssh_key::PrivateKey) -> Result<Self> {
        match k.key_data() {
            ssh_key::private::KeypairData::Ed25519(k) => {
                let key = salty::Keypair {
                    secret: (&k.private.to_bytes()).into(),
                    public: (&k.public.0).try_into().map_err(|_| Error::BadKey)?,
                };
                Ok(SignKey::Ed25519(key))
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
