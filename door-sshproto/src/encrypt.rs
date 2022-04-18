#[allow(unused_imports)]
use {
    crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};

use core::num::Wrapping;
use ring::aead::chacha20_poly1305_openssh as chapoly;
use aes::cipher::{KeyIvInit, KeySizeUser, BlockSizeUser, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::Digest;

use crate::kex;
use crate::*;

// TODO: check that Ctr32 is sufficient. Should be OK with SSH rekeying.
type Aes256Ctr32BE = ctr::Ctr32BE<aes::Aes256>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;


// RFC4253 Section 6. Including length u32 length field, excluding MAC
const SSH_MIN_PACKET_SIZE: usize = 16;
const SSH_MIN_PADLEN: usize = 4;
const SSH_MIN_BLOCK: usize = 8;
pub const SSH_LENGTH_SIZE: usize = 4;

/// Stateful [`Keys`], stores a sequence number as well
pub(crate) struct KeyState {
    keys: Keys,
    // Packet sequence numbers. These must be transferred to subsequent KeyState
    // since they don't reset with rekeying.
    seq_encrypt: Wrapping<u32>,
    seq_decrypt: Wrapping<u32>,
}

impl KeyState {
    /// A brand new `KeyState` with no encryption, zero sequence numbers
    pub fn new_cleartext() -> Self {
        KeyState {
            keys: Keys::new_cleartext(),
            seq_encrypt: Wrapping(0),
            seq_decrypt: Wrapping(0),
        }
    }

    pub fn next_seq_decrypt(&mut self) {
        self.seq_decrypt += 1;
    }

    /// Decrypts the first block in the buffer, returning the length.
    pub fn decrypt_first_block(&mut self, buf: &mut [u8]) -> Result<u32, Error> {
        self.keys.decrypt_first_block(buf, self.seq_decrypt.0)
    }

    /// Decrypt bytes 4 onwards of the buffer and validate AEAD Tag or MAC.
    /// Ensures that the packet meets minimum length.
    pub fn decrypt<'b>(&mut self, buf: &'b mut [u8]) -> Result<(), Error> {
        self.keys.decrypt(buf, self.seq_decrypt.0)
    }

    /// [`buf`] is the entire output buffer to encrypt in place.
    /// payload_len is the length of the payload portion
    /// This is stateful, updating the sequence number.
    pub fn encrypt<'b>(
        &mut self, payload_len: usize, buf: &'b mut [u8],
    ) -> Result<usize, Error> {
        let e = self.keys.encrypt(payload_len, buf, self.seq_encrypt.0);
        self.seq_encrypt += 1;
        e
    }
    pub fn size_integ_enc(&self) -> usize {
        self.keys.integ_enc.size_out()
    }
    pub fn size_integ_dec(&self) -> usize {
        self.keys.integ_dec.size_out()
    }
    pub fn size_block_enc(&self) -> usize {
        self.keys.enc.size_block()
    }
    pub fn size_block_dec(&self) -> usize {
        self.keys.dec.size_block()
    }
}

pub(crate) struct Keys {
    pub(crate) enc: EncKey,
    pub(crate) dec: DecKey,

    pub(crate) integ_enc: IntegKey,
    pub(crate) integ_dec: IntegKey,
}

impl Keys {
    // pub(crate) fn new(
    //     enc: EncKey, dec: DecKey, integ_enc: IntegKey, integ_dec: IntegKey,
    // ) -> Self {
    //     Keys { enc, dec, integ_enc, integ_dec }
    // }

    pub fn new_cleartext() -> Self {
        Keys {
            enc: EncKey::NoCipher,
            dec: DecKey::NoCipher,
            integ_enc: IntegKey::NoInteg,
            integ_dec: IntegKey::NoInteg,
        }
    }

    /// Decrypts the first block in the buffer, returning the length.
    /// Whether bytes `buf[4..block_size]` are decrypted depends on the cipher, they may be
    /// handled later by [`decrypt`]. Bytes `buf[0..4]` may not be modified.
    pub fn decrypt_first_block(
        &mut self, buf: &mut [u8], seq: u32,
    ) -> Result<u32, Error> {
        if buf.len() < self.dec.size_block() {
            return Err(Error::Bug);
        }
        let buf4: [u8; 4] = buf[0..4].try_into().unwrap();

        let d4 = match &mut self.dec {
            DecKey::ChaPoly(openkey) => {
                openkey.decrypt_packet_length(seq, buf4);
                &buf4
            }
            DecKey::Aes256Ctr(a) => {
                a.apply_keystream(&mut buf[..16]);
                buf[..4].try_into().unwrap()
            }
            DecKey::NoCipher => &buf4,
        };
        Ok(u32::from_be_bytes(*d4))
    }

    /// Decrypt bytes 4 onwards of the buffer and validate AEAD Tag or MAC.
    /// Ensures that the packet meets minimum length.
    /// The first block_size bytes may have been already decrypted by
    /// [`decrypt_first_block`]
    /// depending on the cipher.
    pub fn decrypt(&mut self, buf: &mut [u8], seq: u32) -> Result<(), Error> {
        let size_block = self.dec.size_block();
        let size_integ = self.integ_dec.size_out();
        if buf.len() < size_block {
            return Err(Error::BadDecrypt);
        }
        if 4 + buf.len() - size_integ < SSH_MIN_PACKET_SIZE {
            return Err(Error::SSHProtoError);
        }
        // "MUST be a multiple of the cipher block size".
        // encrypted length for aead ciphers doesn't include the length prefix.
        let len = if self.dec.is_aead() { 0 } else { SSH_LENGTH_SIZE } + buf.len()
            - size_integ;

        if len % size_block != 0 {
            return Err(Error::SSHProtoError);
        }

        let (data, mac) = buf.split_at_mut(buf.len() - size_integ);

        // TODO: ETM modes would check integrity here.

        match &mut self.dec {
            DecKey::ChaPoly(openkey) => {
                let mac: &mut [u8; chapoly::TAG_LEN] =
                    mac.try_into().map_err(|_| Error::Bug)?;

                openkey
                    .open_in_place(seq, data, mac)
                    .map_err(|_| Error::BadDecrypt)?;
            }
            DecKey::Aes256Ctr(a) => {
                a.apply_keystream(data);
            }
            DecKey::NoCipher => {}
        }

        match self.integ_dec {
            IntegKey::ChaPoly => {}
            IntegKey::NoInteg => {}
            IntegKey::HmacSha256(k) => {
                // new_from_slice can't fail.
                let mut h = HmacSha256::new_from_slice(&k).unwrap();
                h.update(data);
                h.verify_slice(mac)
                .map_err(|_| Error::BadDecrypt)?;
            }
        }
        Ok(())
    }

    /// Padding is required to meet
    /// - minimum packet length
    /// - minimum padding size,
    /// - encrypted length being a multiple of block length
    fn get_encrypt_pad(&self, payload_len: usize) -> usize {
        let size_block = self.enc.size_block();
        let size_integ = self.integ_enc.size_out();
        // aead ciphers don't include the initial length field in encrypted blocks
        let len =
            1 + payload_len + if self.enc.is_aead() { 0 } else { SSH_LENGTH_SIZE };

        // round padding length upwards so that len is a multiple of block size
        let mut padlen = self.enc.size_block() - len % self.enc.size_block();

        // need at least 4 bytes padding
        if padlen < SSH_MIN_PADLEN {
            padlen += self.enc.size_block()
        }

        // The minimum size of a packet is 16 (plus mac)
        // We know we already have at least 8 bytes because of blocksize rounding.
        if SSH_LENGTH_SIZE + 1 + payload_len + padlen < SSH_MIN_PACKET_SIZE {
            padlen += self.enc.size_block()
        }
        padlen
    }

    /// Encrypt a buffer in-place, adding packet size, padding, MAC etc.
    /// Returns the total length.
    /// Ensures that the packet meets minimum and other length requirements.
    pub fn encrypt(
        &mut self, payload_len: usize, buf: &mut [u8], seq: u32,
    ) -> Result<usize, Error> {
        let size_block = self.enc.size_block();
        let size_integ = self.integ_enc.size_out();
        let padlen = self.get_encrypt_pad(payload_len);
        // len is everything except the MAC
        let len = SSH_LENGTH_SIZE + 1 + payload_len + padlen;

        if self.enc.is_aead() {
            debug_assert_eq!((len - SSH_LENGTH_SIZE) % size_block, 0);
        } else {
            debug_assert_eq!(len % size_block, 0);
        };

        if len + size_integ > buf.len() {
            error!("Output buffer {} is too small for packet", buf.len());
            return Err(Error::Bug);
        }

        // write the length
        buf[0..SSH_LENGTH_SIZE]
            .copy_from_slice(&((len - SSH_LENGTH_SIZE) as u32).to_be_bytes());
        // write random padding
        let pad_start = SSH_LENGTH_SIZE+1+payload_len;
        debug_assert_eq!(pad_start+padlen, len);
        random::fill_random(&mut buf[pad_start..pad_start+padlen]);

        let (enc, rest) = buf.split_at_mut(len);
        let (mac, _) = rest.split_at_mut(size_integ);

        match self.integ_enc {
            IntegKey::ChaPoly => {}
            IntegKey::NoInteg => {}
            IntegKey::HmacSha256(k) => {
                // new_from_slice can't fail.
                let mut h = HmacSha256::new_from_slice(&k).unwrap();
                h.update(enc);
                let result = h.finalize();
                mac.copy_from_slice(&result.into_bytes());
            }
        }

        match &mut self.enc {
            EncKey::ChaPoly(sealkey) => {
                let mac: &mut [u8; chapoly::TAG_LEN] =
                    mac.try_into().map_err(|_| Error::Bug)?;

                sealkey.seal_in_place(seq, enc, mac);
            }
            EncKey::Aes256Ctr(a) => {
                a.apply_keystream(enc);
            }
            EncKey::NoCipher => {}
        }

        // ETM modes would go here.

        Ok(len + size_integ)
    }
}

/// Placeholder for a cipher type prior to creating a a [`EncKey`] or [`DecKey`],
/// for use during key setup in [`kex`]
pub(crate) enum Cipher {
    ChaPoly,
    Aes256Ctr,
    // TODO Aes gcm etc
}

impl Cipher {
    /// Creates a cipher key by algorithm name. Must be passed a known name.
    pub fn from_name(name: &str) -> Result<Self, Error> {
        use crate::kex::*;
        match name {
            SSH_NAME_CHAPOLY => Ok(Cipher::ChaPoly),
            SSH_NAME_SSH_NAME_AES256_CTR => Ok(Cipher::Aes256Ctr),
            _ => Err(Error::Bug),
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::ChaPoly => chapoly::KEY_LEN,
            Cipher::Aes256Ctr => aes::Aes256::key_size(),
        }
    }
    pub fn iv_len(&self) -> usize {
        match self {
            Cipher::ChaPoly => 0,
            Cipher::Aes256Ctr => aes::Aes256::block_size(),
        }
    }
    /// Returns the [`Integ`] for this cipher, or None if not aead
    pub fn integ(&self) -> Option<Integ> {
        match self {
            Cipher::ChaPoly => Some(Integ::ChaPoly),
            Cipher::Aes256Ctr => None,
        }
    }
}

pub(crate) enum EncKey {
    ChaPoly(chapoly::SealingKey),
    Aes256Ctr(Aes256Ctr32BE),
    // AesGcm(Todo?)
    // AesCtr(Todo?)
    NoCipher,
}

impl EncKey {
    /// Construct a key
    pub fn from_cipher(cipher: &Cipher, key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        match cipher {
            Cipher::ChaPoly => {
                let key: &[u8; 64] = key.try_into().map_err(|_| Error::Bug)?;
                Ok(EncKey::ChaPoly(chapoly::SealingKey::new(key)))
            }
            Cipher::Aes256Ctr => {
                let key: &[u8; 32] = key.try_into().map_err(|_| Error::Bug)?;
                let iv: &[u8; 16] = iv.try_into().map_err(|_| Error::Bug)?;
                Ok(EncKey::Aes256Ctr(Aes256Ctr32BE::new(key.into(), iv.into())))
            }
        }
    }
    pub fn is_aead(&self) -> bool {
        match self {
            EncKey::ChaPoly(_) => true,
            EncKey::Aes256Ctr(_a) => false,
            EncKey::NoCipher => false,
        }
    }
    pub fn size_block(&self) -> usize {
        match self {
            EncKey::ChaPoly(_) => SSH_MIN_BLOCK,
            EncKey::Aes256Ctr(_) => aes::Aes256::block_size(),
            EncKey::NoCipher => SSH_MIN_BLOCK,
        }
    }
}

pub(crate) enum DecKey {
    ChaPoly(chapoly::OpeningKey),
    Aes256Ctr(Aes256Ctr32BE),
    // AesGcm256
    // AesCtr256
    NoCipher,
}

impl DecKey {
    /// Construct a key
    pub fn from_cipher(cipher: &Cipher, key: &[u8], iv: &[u8]) -> Result<Self, Error> {
        match cipher {
            Cipher::ChaPoly => {
                let key: &[u8; 64] = key.try_into().map_err(|_| Error::Bug)?;
                Ok(DecKey::ChaPoly(chapoly::OpeningKey::new(key)))
            }
            Cipher::Aes256Ctr => {
                let key: &[u8; 32] = key.try_into().map_err(|_| Error::Bug)?;
                let iv: &[u8; 16] = iv.try_into().map_err(|_| Error::Bug)?;
                Ok(DecKey::Aes256Ctr(Aes256Ctr32BE::new(key.into(), iv.into())))
            }
        }
    }
    pub fn is_aead(&self) -> bool {
        match self {
            DecKey::ChaPoly(_) => true,
            DecKey::Aes256Ctr(_a) => false,
            DecKey::NoCipher => false,
        }
    }
    pub fn size_block(&self) -> usize {
        match self {
            DecKey::ChaPoly(_) => SSH_MIN_BLOCK,
            DecKey::Aes256Ctr(_) => aes::Aes256::block_size(),
            DecKey::NoCipher => SSH_MIN_BLOCK,
        }
    }
}

pub(crate) enum Integ {
    ChaPoly,
    HmacSha256,
    // aesgcm?
}

/// Placeholder for a [`IntegKey`] type prior to keying. For use during key setup in [`kex`]
impl Integ {
    /// Matches a MAC name. Should not be called for AEAD ciphers, instead use [`EncKey::integ`] etc
    pub fn from_name(name: &str) -> Result<Self, Error> {
        // TODO: match standalone HMAC names here.
        match name {
            SSH_NAME_HMAC_SHA256 => Ok(Integ::HmacSha256),
            _ => Err(Error::Bug),
        }
    }
}

pub(crate) enum IntegKey {
    ChaPoly,
    HmacSha256([u8; 32]),
    // aesgcm?
    // Sha2Hmac ?
    NoInteg,
}

impl IntegKey {
    pub fn from_integ(integ: Integ, key: &[u8]) -> Self {
        match integ {
            Integ::ChaPoly => IntegKey::ChaPoly,
            Integ::HmacSha256 => {
                // hmac new_from_slice() can't fail.
                let h = HmacSha256::new_from_slice(key).unwrap();
                IntegKey::HmacSha256(key.try_into().unwrap())
            }
        }
    }
    pub fn size_out(&self) -> usize {
        match self {
            IntegKey::ChaPoly => chapoly::TAG_LEN,
            IntegKey::HmacSha256(_) => sha2::Sha256::output_size(),
            IntegKey::NoInteg => 0,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::encrypt::{Keys, SSH_LENGTH_SIZE};
    use crate::error::Error;
    #[allow(unused_imports)]
    use log::{debug, error, info, log, trace, warn};

    #[test]
    fn roundtrip_nocipher() {
        // check padding works
        let keys = Keys::new_cleartext();
        for i in 0usize..40 {
            let mut v: std::vec::Vec<u8> = (0u8..i as u8 + 30).collect();
            let orig_payload = v[SSH_LENGTH_SIZE..SSH_LENGTH_SIZE + i].to_vec();
            let seq = 123u32.rotate_left(i as u32); // something arbitrary

            let written = keys.encrypt(i, v.as_mut_slice(), seq).unwrap();

            v.truncate(written);
            let l =
                keys.decrypt_first_block(v.as_mut_slice(), seq).unwrap() as usize;
            keys.decrypt(v.as_mut_slice(), seq).unwrap();
            let dec_payload = v[SSH_LENGTH_SIZE..SSH_LENGTH_SIZE + i].to_vec();
            assert_eq!(written, l + SSH_LENGTH_SIZE + keys.integ_enc.size_out());
            assert_eq!(orig_payload, dec_payload);
        }
    }
}
