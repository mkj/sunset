#![cfg_attr(fuzzing, allow(dead_code))]

#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use chacha20::cipher::{
    KeyIvInit, StreamCipher, StreamCipherSeek, StreamCipherSeekCore,
};
use chacha20::ChaCha20;
use digest::KeyInit;
use poly1305::universal_hash::generic_array::GenericArray;
use poly1305::universal_hash::UniversalHash;
use poly1305::Poly1305;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use pretty_hex::PrettyHex;

use crate::*;
use encrypt::SSH_LENGTH_SIZE;

#[derive(Clone, ZeroizeOnDrop)]
/// `chacha20-poly1305@openssh.com` authenticated cipher
pub struct SSHChaPoly {
    /// Length key
    k1: [u8; 32],
    /// Packet key
    k2: [u8; 32],
}

impl SSHChaPoly {
    pub const TAG_LEN: usize = 16;
    pub const KEY_LEN: usize = 64;

    /// `key` must be 64 bytes
    pub fn new_from_slice(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_LEN {
            return Err(Error::BadKey);
        }
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&key[32..64]);
        k2.copy_from_slice(&key[..32]);
        Ok(Self { k1, k2 })
    }

    fn cha20(key: &[u8; 32], seq: u32) -> ChaCha20 {
        let mut nonce = [0u8; 12];
        nonce[8..].copy_from_slice(&seq.to_be_bytes());
        ChaCha20::new(key.into(), (&nonce).into())
    }

    /// Decrypts the packet length.
    ///
    /// `buf` must be at least 4 bytes, extra data is ignored.
    pub fn packet_length(&self, seq: u32, buf: &[u8]) -> Result<u32> {
        if buf.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        let mut b: [u8; SSH_LENGTH_SIZE] =
            buf[..SSH_LENGTH_SIZE].try_into().unwrap();
        let mut c = Self::cha20(&self.k1, seq);
        c.apply_keystream(&mut b);
        trace!("packet_length {:?}", b.hex_dump());
        Ok(u32::from_be_bytes(b))
    }

    /// Decrypts in-place and validates the MAC.
    ///
    /// Length has already been decrypted by `packet_length()`.
    pub fn decrypt(&self, seq: u32, msg: &mut [u8], mac: &[u8]) -> Result<()> {
        if msg.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        if mac.len() != Self::TAG_LEN {
            return Err(Error::BadDecrypt);
        }

        let mut c = Self::cha20(&self.k2, seq);
        let mut poly_key = [0u8; 32];
        c.apply_keystream(&mut poly_key);

        // check tag
        let msg_tag = poly1305::Tag::from_slice(mac);
        let poly = Poly1305::new((&poly_key).into());
        // compute_unpadded() adds the necessary trailing 1 byte when padding output
        let tag = poly.compute_unpadded(msg);
        let good: bool = tag.ct_eq(msg_tag).into();
        if !good {
            return Err(Error::BadDecrypt);
        }

        // decrypt payload
        let (_, payload) = msg.split_at_mut(SSH_LENGTH_SIZE);
        // set block counter to 1
        c.seek(64u32);
        c.apply_keystream(payload);
        Ok(())
    }

    /// Encrypt in-place, including length, payload, MAC.
    pub fn encrypt(&self, seq: u32, msg: &mut [u8], mac: &mut [u8]) -> Result<()> {
        if msg.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        if mac.len() != Self::TAG_LEN {
            return Err(Error::BadDecrypt);
        }

        // encrypt length
        let l = (msg.len() - SSH_LENGTH_SIZE) as u32;
        let msg_len = &mut msg[..SSH_LENGTH_SIZE];
        msg_len.copy_from_slice(&(l.to_be_bytes()));
        let mut c = Self::cha20(&self.k1, seq);
        c.apply_keystream(msg_len);

        let mut c = Self::cha20(&self.k2, seq);

        // encrypt payload
        let (_, payload) = msg.split_at_mut(SSH_LENGTH_SIZE);
        // set block counter to 1
        c.seek(64u32);
        c.apply_keystream(payload);

        // compute tag
        let mut poly_key = [0u8; 32];
        // set block counter to 0
        c.seek(0u32);
        c.apply_keystream(&mut poly_key);
        let poly = Poly1305::new((&poly_key).into());
        let tag = poly.compute_unpadded(msg);
        mac.copy_from_slice(tag.as_slice());

        Ok(())
    }
}
