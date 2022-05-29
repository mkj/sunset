#[allow(unused_imports)]
use {
    crate::error::*,
    log::{debug, error, info, log, trace, warn},
};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek, StreamCipherSeekCore};
use poly1305::Poly1305;
use poly1305::universal_hash::{NewUniversalHash, UniversalHash};
use poly1305::universal_hash::generic_array::GenericArray;


use crate::*;
use encrypt::SSH_LENGTH_SIZE;

pub struct SSHChaPoly {
    k1: [u8; 32],
    k2: [u8; 32],
}

const TAG_LEN: usize = 16;
const KEY_LEN: usize = 64;

impl SSHChaPoly {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_LEN {
            return Err(Error::BadKey)
        }
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&key[32..64]);
        k2.copy_from_slice(&key[..32]);
        Ok(Self {
            k1,
            k2,
        })
    }

    pub const fn tag_len() -> usize {
        TAG_LEN
    }

    pub const fn key_len() -> usize {
        KEY_LEN
    }

    fn cha20(key: &[u8; 32], seq: u32) -> ChaCha20 {
        let mut nonce = [0u8; 12];
        nonce[8..].copy_from_slice(&seq.to_be_bytes());
        ChaCha20::new(key.into(), (&nonce).into())
    }

    pub fn packet_length(&self, seq: u32, buf: &[u8]) -> Result<u32> {
        if buf.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        let mut b: [u8; SSH_LENGTH_SIZE] = buf[..SSH_LENGTH_SIZE].try_into().unwrap();
        let mut c = Self::cha20(&self.k1, seq);
        c.apply_keystream(&mut b);
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }

    pub fn decrypt(&self, seq: u32, msg: &mut [u8], mac: &[u8]) -> Result<()> {
        if msg.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        if mac.len() != TAG_LEN {
            return Err(Error::BadDecrypt);
        }
        let msg_tag = poly1305::Tag::new(*GenericArray::from_slice(mac));

        let mut c = Self::cha20(&self.k2, seq);
        let mut poly_key = [0u8; 32];
        c.apply_keystream(&mut poly_key);

        // check tag
        let poly = Poly1305::new((&poly_key).into());
        let tag = poly.compute_unpadded(msg);
        if tag != msg_tag {
            return Err(Error::BadDecrypt);
        }

        // encrypt payload
        let (_, payload) = msg.split_at_mut(SSH_LENGTH_SIZE);
        // set block counter to 1
        c.seek(64u32);
        c.apply_keystream(payload);
        Ok(())
    }

    pub fn encrypt(&self, seq: u32, msg: &mut [u8], mac: &mut [u8]) -> Result<()> {
        if msg.len() < SSH_LENGTH_SIZE {
            return Err(Error::BadDecrypt);
        }
        if mac.len() != TAG_LEN {
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
        // set block counter to 1
        c.seek(0u32);
        c.apply_keystream(&mut poly_key);
        let poly = Poly1305::new((&poly_key).into());
        let tag = poly.compute_unpadded(msg);
        mac.copy_from_slice(&tag.into_bytes());

        Ok(())
    }
}
