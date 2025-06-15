//! Handles encryption/decryption and framing a payload in a SSH packet.

#![cfg_attr(fuzzing, allow(dead_code))]
#![cfg_attr(fuzzing, allow(unused_variables))]

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::fmt;
use core::fmt::Debug;
use core::num::Wrapping;

use aes::{
    cipher::{BlockSizeUser, KeyIvInit, KeySizeUser, StreamCipher},
    Aes256,
};
use hmac::{Hmac, Mac};
use pretty_hex::PrettyHex;
use sha2::Digest as Sha2DigestForTrait;
use zeroize::ZeroizeOnDrop;

use crate::*;
use kex::{self, SessId};
use ssh_chapoly::SSHChaPoly;
use sshnames::*;
use sshwire::hash_mpint;

// TODO: check that Ctr32 is sufficient. Should be OK with SSH rekeying.
type Aes256Ctr32BE = ctr::Ctr32BE<aes::Aes256>;
type HmacSha256 = hmac::Hmac<sha2::Sha256>;

const SSH_MIN_PADLEN: usize = 4;
const SSH_MIN_BLOCK: usize = 8;
pub const SSH_LENGTH_SIZE: usize = 4;
pub const SSH_PAYLOAD_START: usize = SSH_LENGTH_SIZE + 1;

// TODO: should calculate/check these somehow
/// Largest is aes256ctr
const MAX_IV_LEN: usize = 32;
/// Largest is chacha. Also applies to MAC keys
const MAX_KEY_LEN: usize = 64;

/// Stateful [`Keys`], stores a sequence number as well, a single instance
/// is kept for the entire session.
#[derive(Debug)]
pub(crate) struct KeyState {
    keys: Keys,
    // Packet sequence numbers.
    // These reset on newkeys when strict kex is in effect.
    pub seq_encrypt: Wrapping<u32>,
    pub seq_decrypt: Wrapping<u32>,
    strict_kex: bool,
    done_first_kex: bool,
}

impl KeyState {
    /// A brand new `KeyState` with no encryption, zero sequence numbers
    pub fn new_cleartext() -> Self {
        KeyState {
            keys: Keys::new_cleartext(),
            seq_encrypt: Wrapping(0),
            seq_decrypt: Wrapping(0),
            strict_kex: false,
            done_first_kex: false,
        }
    }

    pub fn is_cleartext(&self) -> bool {
        matches!(self.keys.enc, EncKey::NoCipher)
            || matches!(self.keys.dec, DecKey::NoCipher)
    }

    /// Updates with new keys
    pub fn rekey(&mut self, keys: Keys) {
        trace!("rekey");
        self.keys = keys;
        self.done_first_kex = true;
        if self.strict_kex {
            self.seq_decrypt = Wrapping(0);
            self.seq_encrypt = Wrapping(0);
        }
    }

    pub fn enable_strict_kex(&mut self) {
        if !self.done_first_kex {
            self.strict_kex = true
        }
    }

    pub fn recv_seq(&self) -> u32 {
        self.seq_decrypt.0
    }

    /// Decrypts the first block in the buffer
    ///
    /// Returning the length.
    pub fn decrypt_first_block(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.keys.decrypt_first_block(buf, self.seq_decrypt.0)
    }

    /// Decrypt and validate the remainder of the buffer.
    ///
    /// Decrypt bytes 4 onwards of the buffer and validate AEAD Tag or MAC.
    /// Ensures that the packet meets minimum length.
    pub fn decrypt(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let e = self.keys.decrypt(buf, self.seq_decrypt.0);
        self.seq_decrypt += 1;
        e
    }

    /// Encrypt the output buffer
    ///
    /// [`buf`] is the entire output buffer to encrypt in place.
    /// payload_len is the length of the payload portion
    /// This is stateful, updating the sequence number.
    pub fn encrypt(
        &mut self,
        payload_len: usize,
        buf: &mut [u8],
    ) -> Result<usize, Error> {
        let e = self.keys.encrypt(payload_len, buf, self.seq_encrypt.0);
        self.seq_encrypt += 1;
        e
    }

    pub fn size_block_dec(&self) -> usize {
        self.keys.dec.size_block()
    }

    /// Returns the maximum payload that can fit in an available buffer
    /// after header, encryption, padding, mac
    pub fn max_enc_payload(&self, total_avail: usize) -> usize {
        // mac is independent of the rest
        let total_avail = total_avail.saturating_sub(self.keys.integ_enc.size_out());

        let overhead = SSH_LENGTH_SIZE + 1 + SSH_MIN_PADLEN;
        let mut space = total_avail;

        // multiple of block length
        let enc_len = if self.keys.enc.is_aead() {
            total_avail.saturating_sub(SSH_LENGTH_SIZE)
        } else {
            total_avail
        };

        // round down to block size
        let extra_block = enc_len % self.keys.enc.size_block();
        if extra_block != 0 {
            space = space.saturating_sub(extra_block);
        }

        space.saturating_sub(overhead)
    }
}

// Clone is required so we can clone() then drop the original in place,
// avoiding issues with Option::take(). This could be revisited.
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub(crate) struct Keys {
    pub(crate) enc: EncKey,
    pub(crate) dec: DecKey,

    #[zeroize(skip)]
    pub(crate) integ_enc: IntegKey,
    #[zeroize(skip)]
    pub(crate) integ_dec: IntegKey,
}

impl Keys {
    fn new_cleartext() -> Self {
        Keys {
            enc: EncKey::NoCipher,
            dec: DecKey::NoCipher,
            integ_enc: IntegKey::NoInteg,
            integ_dec: IntegKey::NoInteg,
        }
    }

    pub fn derive(
        kex_out: kex::KexOutput,
        sess_id: &SessId,
        algos: &kex::Algos,
    ) -> Result<Self, Error> {
        let mut key = [0u8; MAX_KEY_LEN];
        let mut iv = [0u8; MAX_IV_LEN];

        let [iv_e, iv_d, k_e, k_d, i_e, i_d] = if algos.is_client {
            ['A', 'B', 'C', 'D', 'E', 'F']
        } else {
            ['B', 'A', 'D', 'C', 'F', 'E']
        };

        let enc = {
            let ci = kex_out.compute_key(
                iv_e,
                algos.cipher_enc.iv_len(),
                &mut iv,
                sess_id,
            )?;
            let ck = kex_out.compute_key(
                k_e,
                algos.cipher_enc.key_len(),
                &mut key,
                sess_id,
            )?;
            EncKey::from_cipher(&algos.cipher_enc, ck, ci)?
        };

        let dec = {
            let ci = kex_out.compute_key(
                iv_d,
                algos.cipher_dec.iv_len(),
                &mut iv,
                sess_id,
            )?;
            let ck = kex_out.compute_key(
                k_d,
                algos.cipher_dec.key_len(),
                &mut key,
                sess_id,
            )?;
            DecKey::from_cipher(&algos.cipher_dec, ck, ci)?
        };

        let integ_enc = {
            let ck = kex_out.compute_key(
                i_e,
                algos.integ_enc.key_len(),
                &mut key,
                sess_id,
            )?;
            IntegKey::from_integ(&algos.integ_enc, ck)?
        };

        let integ_dec = {
            let ck = kex_out.compute_key(
                i_d,
                algos.integ_dec.key_len(),
                &mut key,
                sess_id,
            )?;
            IntegKey::from_integ(&algos.integ_dec, ck)?
        };

        Ok(Keys { enc, dec, integ_enc, integ_dec })
    }

    /// Decrypts the first block in the buffer
    ///
    /// Returns the length of the
    /// total SSH packet (including length+mac) which is calculated
    /// from the decrypted first 4 bytes.
    /// Whether bytes `buf[4..block_size]` are decrypted depends on the cipher, they may be
    /// handled later by [`decrypt`]. Bytes `buf[0..4]` may be left unmodified.
    fn decrypt_first_block(
        &mut self,
        buf: &mut [u8],
        seq: u32,
    ) -> Result<usize, Error> {
        if buf.len() < self.dec.size_block() {
            return Err(Error::bug());
        }

        #[cfg(fuzzing)]
        let len = u32::from_be_bytes(buf[..SSH_LENGTH_SIZE].try_into().unwrap());

        #[cfg(not(fuzzing))]
        let len = match &mut self.dec {
            DecKey::ChaPoly(k) => k.packet_length(seq, buf).trap()?,
            DecKey::Aes256Ctr(a) => {
                a.apply_keystream(&mut buf[..16]);
                u32::from_be_bytes(buf[..SSH_LENGTH_SIZE].try_into().unwrap())
            }
            DecKey::NoCipher => {
                u32::from_be_bytes(buf[..SSH_LENGTH_SIZE].try_into().unwrap())
            }
        };

        let total_len = len
            .checked_add((SSH_LENGTH_SIZE + self.integ_dec.size_out()) as u32)
            .ok_or(Error::BadDecrypt)?;

        Ok(total_len as usize)
    }

    /// Decrypt the whole packet buffer and validate AEAD Tag or MAC.
    ///
    /// Returns the payload length.
    /// Ensures that the packet meets minimum length.
    /// The first block_size bytes may have been already decrypted by
    /// [`decrypt_first_block`] depending on the cipher.
    fn decrypt(&mut self, buf: &mut [u8], seq: u32) -> Result<usize, Error> {
        let size_block = self.dec.size_block();
        let size_integ = self.integ_dec.size_out();

        if buf.len() < size_block + size_integ {
            debug!("Bad packet, {} smaller than block size", buf.len());
            return error::SSHProto.fail();
        }
        // "MUST be a multiple of the cipher block size".
        // encrypted length for aead ciphers doesn't include the length prefix.
        let sublength = if self.dec.is_aead() { SSH_LENGTH_SIZE } else { 0 };
        let len = buf.len() - size_integ - sublength;

        if len % size_block != 0 {
            debug!("Bad packet, not multiple of block size");
            return error::SSHProto.fail();
        }

        let (data, mac) = buf.split_at_mut(buf.len() - size_integ);

        // roundtrip tests are exhaustive over short packet lengths
        debug_assert!(data.len() >= size_block);

        // ETM modes would check integrity here.

        #[cfg(not(fuzzing))]
        match &mut self.dec {
            DecKey::ChaPoly(k) => {
                k.decrypt(seq, data, mac).map_err(|_| Error::BadDecrypt)?;
            }
            DecKey::Aes256Ctr(a) => {
                // safe index, checked data.len()
                a.apply_keystream(&mut data[16..]);
            }
            DecKey::NoCipher => {}
        }

        #[cfg(not(fuzzing))]
        match self.integ_dec {
            IntegKey::ChaPoly => {}
            IntegKey::NoInteg => {}
            IntegKey::HmacSha256(k) => {
                let mut h = HmacSha256::new_from_slice(&k).trap()?;
                h.update(&seq.to_be_bytes());
                h.update(data);
                h.verify_slice(mac).map_err(|_| Error::BadDecrypt)?;
            }
        }

        let padlen = data[SSH_LENGTH_SIZE] as usize;
        if padlen < SSH_MIN_PADLEN {
            debug!("Packet padding too short");
            return error::SSHProto.fail();
        }

        let payload_len = buf
            .len()
            .checked_sub(SSH_LENGTH_SIZE + 1 + size_integ + padlen)
            .ok_or_else(|| {
                debug!("Bad padding length");
                error::SSHProto.build()
            })?;

        Ok(payload_len)
    }

    /// Padding is required to meet
    /// - minimum packet length
    /// - minimum padding size,
    /// - encrypted length being a multiple of block length
    fn calc_encrypt_pad(&self, payload_len: usize) -> usize {
        let size_block = self.enc.size_block();
        // aead ciphers don't include the initial length field in encrypted blocks
        let len =
            1 + payload_len + if self.enc.is_aead() { 0 } else { SSH_LENGTH_SIZE };

        // round padding length upwards so that len is a multiple of block size
        let mut padlen = size_block - len % size_block;

        // need at least 4 bytes padding
        if padlen < SSH_MIN_PADLEN {
            padlen += size_block
        }

        padlen
    }

    /// Encrypt a buffer in-place, adding packet size, padding, MAC etc.
    /// Returns the total length.
    /// Ensures that the packet meets minimum and other length requirements.
    fn encrypt(
        &mut self,
        payload_len: usize,
        buf: &mut [u8],
        seq: u32,
    ) -> Result<usize, Error> {
        let size_block = self.enc.size_block();
        let size_integ = self.integ_enc.size_out();
        let padlen = self.calc_encrypt_pad(payload_len);
        // len is everything except the MAC
        let len = SSH_LENGTH_SIZE + 1 + payload_len + padlen;

        if self.enc.is_aead() {
            debug_assert_eq!((len - SSH_LENGTH_SIZE) % size_block, 0);
        } else {
            debug_assert_eq!(len % size_block, 0);
        };

        if len + size_integ > buf.len() {
            error!("Output buffer {} is too small for packet", buf.len());
            return error::NoRoom.fail();
        }

        // write the length
        let blen = ((len - SSH_LENGTH_SIZE) as u32).to_be_bytes();
        buf[..SSH_LENGTH_SIZE].copy_from_slice(&blen);
        // write random padding
        buf[SSH_LENGTH_SIZE] = padlen as u8;
        let pad_start = SSH_LENGTH_SIZE + 1 + payload_len;
        debug_assert_eq!(pad_start + padlen, len);
        random::fill_random(&mut buf[pad_start..pad_start + padlen])?;

        let (enc, rest) = buf.split_at_mut(len);
        let (mac, _) = rest.split_at_mut(size_integ);

        match self.integ_enc {
            IntegKey::ChaPoly => {}
            IntegKey::NoInteg => {}
            IntegKey::HmacSha256(k) => {
                let mut h = HmacSha256::new_from_slice(&k).trap()?;
                h.update(&seq.to_be_bytes());
                h.update(enc);
                let result = h.finalize();
                mac.copy_from_slice(&result.into_bytes());
            }
        }

        match &mut self.enc {
            EncKey::ChaPoly(k) => k.encrypt(seq, enc, mac).trap()?,
            EncKey::Aes256Ctr(a) => {
                a.apply_keystream(enc);
            }
            EncKey::NoCipher => {}
        }

        // ETM integ modes would go here.

        Ok(len + size_integ)
    }
}

/// Placeholder for a cipher type prior to creating an [`EncKey`] or [`DecKey`],
/// for use during key setup in [`kex`]
#[derive(Debug, Clone)]
pub(crate) enum Cipher {
    ChaPoly,
    Aes256Ctr,
    // TODO AesGcm etc
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::ChaPoly => SSH_NAME_CHAPOLY,
            Self::Aes256Ctr => SSH_NAME_AES256_CTR,
        };
        write!(f, "{n}")
    }
}

impl Cipher {
    /// Creates a cipher key by algorithm name. Must be passed a known name.
    pub fn from_name(name: &'static str) -> Result<Self, Error> {
        match name {
            SSH_NAME_CHAPOLY => Ok(Cipher::ChaPoly),
            SSH_NAME_AES256_CTR => Ok(Cipher::Aes256Ctr),
            _ => Err(Error::bug()),
        }
    }

    /// Length in bytes
    pub fn key_len(&self) -> usize {
        match self {
            Cipher::ChaPoly => SSHChaPoly::KEY_LEN,
            Cipher::Aes256Ctr => aes::Aes256::key_size(),
        }
    }

    /// Length in bytes
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

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) enum EncKey {
    ChaPoly(SSHChaPoly),
    Aes256Ctr(Aes256Ctr32BE),
    // AesGcm(Todo?)
    NoCipher,
}

impl Debug for EncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::ChaPoly(_) => "ChaPoly",
            Self::Aes256Ctr(_) => "Aes256Ctr",
            Self::NoCipher => "NoCipher",
        };
        f.write_fmt(format_args!("EncKey::{n}"))
    }
}

// TODO: could probably unify EncKey and DecKey as "CipherKey".
// Ring had sealing/opening keys which are separate, but RustCrypto
// uses the same structs in both directions.

impl EncKey {
    /// Construct a key
    pub fn from_cipher<'a>(
        cipher: &Cipher,
        key: &'a [u8],
        iv: &'a [u8],
    ) -> Result<Self, Error> {
        match cipher {
            Cipher::ChaPoly => {
                Ok(EncKey::ChaPoly(SSHChaPoly::new_from_slice(key).trap()?))
            }
            Cipher::Aes256Ctr => Ok(EncKey::Aes256Ctr(
                Aes256Ctr32BE::new_from_slices(key, iv).trap()?,
            )),
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

#[derive(Clone, ZeroizeOnDrop)]
pub(crate) enum DecKey {
    ChaPoly(SSHChaPoly),
    Aes256Ctr(Aes256Ctr32BE),
    // AesGcm256
    // AesCtr256
    NoCipher,
}

impl Debug for DecKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::ChaPoly(_) => "ChaPoly",
            Self::Aes256Ctr(_) => "Aes256Ctr",
            Self::NoCipher => "NoCipher",
        };
        f.write_fmt(format_args!("DecKey::{n}"))
    }
}

impl DecKey {
    /// Construct a key
    pub fn from_cipher<'a>(
        cipher: &Cipher,
        key: &'a [u8],
        iv: &'a [u8],
    ) -> Result<Self, Error> {
        match cipher {
            Cipher::ChaPoly => {
                Ok(DecKey::ChaPoly(SSHChaPoly::new_from_slice(key).trap()?))
            }
            Cipher::Aes256Ctr => Ok(DecKey::Aes256Ctr(
                Aes256Ctr32BE::new_from_slices(key, iv).trap()?,
            )),
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

/// Placeholder for a [`IntegKey`] type prior to keying. For use during key setup in [`kex`]
#[derive(Debug, Clone)]
pub(crate) enum Integ {
    ChaPoly,
    HmacSha256,
    // aesgcm?
}

impl Integ {
    /// Matches a MAC name. Should not be called for AEAD ciphers, instead use [`EncKey::integ`] etc
    pub fn from_name(name: &'static str) -> Result<Self, Error> {
        match name {
            SSH_NAME_HMAC_SHA256 => Ok(Integ::HmacSha256),
            _ => Err(Error::bug()),
        }
    }
    /// length in bytes
    fn key_len(&self) -> usize {
        match self {
            Integ::ChaPoly => 0,
            Integ::HmacSha256 => 32,
        }
    }
}

impl fmt::Display for Integ {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::ChaPoly => SSH_NAME_CHAPOLY,
            Self::HmacSha256 => SSH_NAME_HMAC_SHA256,
        };
        write!(f, "{n}")
    }
}

#[derive(Clone)]
pub(crate) enum IntegKey {
    ChaPoly,
    HmacSha256([u8; 32]),
    // aesgcm?
    NoInteg,
}

impl Debug for IntegKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = match self {
            Self::ChaPoly => "ChaPoly",
            Self::HmacSha256(_) => "HmacSha256",
            Self::NoInteg => "NoInteg",
        };
        f.write_fmt(format_args!("IntegKey::{n}"))
    }
}

impl IntegKey {
    pub fn from_integ(integ: &Integ, key: &[u8]) -> Result<Self, Error> {
        match integ {
            Integ::ChaPoly => Ok(IntegKey::ChaPoly),
            Integ::HmacSha256 => Ok(IntegKey::HmacSha256(key.try_into().trap()?)),
        }
    }
    pub fn size_out(&self) -> usize {
        match self {
            IntegKey::ChaPoly => SSHChaPoly::TAG_LEN,
            IntegKey::HmacSha256(_) => sha2::Sha256::output_size(),
            IntegKey::NoInteg => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt::*;
    use crate::error::Error;
    use crate::kex::KexOutput;
    use crate::sshnames::SSH_NAME_CURVE25519;
    use crate::sunsetlog::*;
    #[allow(unused_imports)]
    use pretty_hex::PrettyHex;
    use sha2::Sha256;

    // setting `corrupt` tests that incorrect mac is detected
    fn do_roundtrips(
        keys_enc: &mut KeyState,
        keys_dec: &mut KeyState,
        corrupt: bool,
    ) {
        for i in 0usize..80 {
            let mut v: std::vec::Vec<u8> = (0u8..i as u8 + 60).collect();
            let orig_payload = v[SSH_PAYLOAD_START..SSH_PAYLOAD_START + i].to_vec();

            let written = keys_enc.encrypt(i, v.as_mut_slice()).unwrap();

            v.truncate(written);

            if corrupt {
                // flip a bit of the payload
                v[SSH_PAYLOAD_START] ^= 4;
            }

            let l = keys_dec.decrypt_first_block(v.as_mut_slice()).unwrap();
            assert_eq!(l, v.len());

            let dec = keys_dec.decrypt(v.as_mut_slice());

            if corrupt {
                assert!(matches!(dec, Err(Error::BadDecrypt)));
                return;
            }
            let payload_len = dec.unwrap();
            assert_eq!(payload_len, i);
            let dec_payload = v[SSH_PAYLOAD_START..SSH_PAYLOAD_START + i].to_vec();
            assert_eq!(orig_payload, dec_payload);
        }
    }

    #[test]
    fn roundtrip_nocipher() {
        // check padding works
        let mut ke = KeyState::new_cleartext();
        let mut kd = KeyState::new_cleartext();
        do_roundtrips(&mut ke, &mut kd, false);
    }

    #[test]
    #[should_panic]
    fn roundtrip_nocipher_corrupt() {
        // test the test, cleartext has no mac
        let mut ke = KeyState::new_cleartext();
        let mut kd = KeyState::new_cleartext();
        do_roundtrips(&mut ke, &mut kd, true);
    }

    // returns combinations of ciphers as Some(), as well as a single
    // None for no-cipher
    fn algo_combos() -> impl Iterator<Item = Option<kex::Algos>> {
        // TODO make this combinatorial
        // order is enc, dec
        const COMBOS: [(Cipher, Integ, Cipher, Integ); 4] = [
            (
                Cipher::Aes256Ctr,
                Integ::HmacSha256,
                Cipher::Aes256Ctr,
                Integ::HmacSha256,
            ),
            (Cipher::ChaPoly, Integ::ChaPoly, Cipher::ChaPoly, Integ::ChaPoly),
            (Cipher::Aes256Ctr, Integ::HmacSha256, Cipher::ChaPoly, Integ::ChaPoly),
            (Cipher::ChaPoly, Integ::ChaPoly, Cipher::Aes256Ctr, Integ::HmacSha256),
        ];
        COMBOS
            .iter()
            .map(|(ce, ie, cd, id)| {
                Some(kex::Algos {
                    kex: kex::SharedSecret::from_name(SSH_NAME_CURVE25519).unwrap(),
                    hostsig: sign::SigType::Ed25519,
                    cipher_enc: ce.clone(),
                    cipher_dec: cd.clone(),
                    integ_enc: ie.clone(),
                    integ_dec: id.clone(),
                    discard_next: false,
                    is_client: false,
                    send_ext_info: true,
                    strict_kex: false,
                })
            })
            // and plaintext
            .chain(core::iter::once(None))
    }

    #[test]
    fn algo_roundtrips() {
        init_test_log();

        for mut algos in algo_combos() {
            let mut keys_enc = KeyState::new_cleartext();
            let mut keys_dec = KeyState::new_cleartext();
            if let Some(ref mut algos) = algos {
                // arbitrary keys
                let h = SessId::from_slice(&Sha256::digest(
                    "some exchange hash".as_bytes(),
                ))
                .unwrap();
                let sess_id =
                    SessId::from_slice(&Sha256::digest("some sessid".as_bytes()))
                        .unwrap();
                let sharedkey = b"hello";
                let ko = KexOutput::new_test(sharedkey, &algos, &h);
                let ko_b = KexOutput::new_test(sharedkey, &algos, &h);

                trace!("algos enc {algos:?}");
                let newkeys = Keys::derive(ko, &sess_id, &algos).unwrap();
                keys_enc.rekey(newkeys);

                // client and server enc/dec keys are derived differently, we need them
                // to match for this test
                algos.is_client = !algos.is_client;
                core::mem::swap(&mut algos.cipher_enc, &mut algos.cipher_dec);
                core::mem::swap(&mut algos.integ_enc, &mut algos.integ_dec);
                trace!("algos dec {algos:?}");
                let newkeys_b = Keys::derive(ko_b, &sess_id, &algos).unwrap();
                keys_dec.rekey(newkeys_b);
            } else {
                trace!("Trying cleartext");
            }

            do_roundtrips(&mut keys_enc, &mut keys_dec, false);
            // corrupt test only for non-plaintext
            if algos.is_some() {
                do_roundtrips(&mut keys_enc, &mut keys_dec, true);
            }
        }
    }

    #[test]
    fn max_enc_payload() {
        init_test_log();
        for algos in algo_combos() {
            let mut keys = KeyState::new_cleartext();
            if let Some(algos) = algos {
                // arbitrary keys
                let h = SessId::from_slice(&Sha256::digest(b"some exchange hash"))
                    .unwrap();
                let sess_id =
                    SessId::from_slice(&Sha256::digest(b"some sessid")).unwrap();
                let sharedkey = b"hello";
                let ko = KexOutput::new_test(sharedkey, &algos, &h);
                let newkeys = Keys::derive(ko, &sess_id, &algos).unwrap();

                keys.rekey(newkeys);
                trace!("algos {algos:?}");
                trace!("integ {}", keys.keys.integ_enc.size_out());
            } else {
                trace!("cleartext");
            }

            let mut buf = [0u8; 100];

            for i in 1..80 {
                let p = keys.max_enc_payload(i);
                trace!("i {i} p {p}");
                if p > 0 {
                    let l = keys.encrypt(p, &mut buf).unwrap();
                    trace!("i {i} p {p} l {l}");
                    assert!(l <= i);
                    assert!(l >= i.saturating_sub(keys.keys.enc.size_block()));

                    // check a larger payload would bump the packet size
                    let l = keys.encrypt(p + 1, &mut buf).unwrap();
                    assert!(l > i);
                }
            }
        }
    }
}
