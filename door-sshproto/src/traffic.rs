#[allow(unused_imports)]
use {
    crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};

use crate::encrypt::SSH_LENGTH_SIZE;
use crate::encrypt::KeyState;
use crate::ident::{RemoteVersion};
use crate::*;

pub(crate) struct Traffic<'a> {
    // TODO: if smoltcp exposed both ends of a CircularBuffer to recv()
    // we could perhaps just work directly in smoltcp's provided buffer?
    // Would need changes to ring chapoly_openssh and block ciphers.

    // TODO: decompression will need another buffer

    /// Accumulated input or output buffer.
    /// Should be sized to fit the largest packet allowed.
    /// Contains ciphertext or cleartext, encrypted/decrypted in-place.
    buf: &'a mut [u8],
    state: TrafState,
}

/// State machine for reads/writes sharing [`Traffic::buf`]
#[derive(Debug)]
enum TrafState {
    /// buf is unused
    Idle,

    /// Reading remote version, not SSH packet format
    Version,
    /// Reading initial block for packet length. idx > 0.
    ReadInitial {
        idx: usize,
    },
    /// Reading remainder of encrypted packet
    Read {
        idx: usize,
        expect: usize,
    },
    /// Whole encryped packet has been read
    ReadComplete {
        len: usize,
    },
    /// Decrypted complete input payload
    InPayload {
        len: usize,
    },

    OutPayload {
        len: usize,
    },
    /// Encrypted, writing to the socket
    Write {
        idx: usize,
        len: usize,
    },
}

impl<'a> Traffic<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Traffic {
            buf,
            state: TrafState::Version,
        }
    }

    /// Returns the number of bytes consumed, and optionally
    /// a complete packet payload.
    pub fn input(&mut self, keys: &mut KeyState, remote_version: &mut RemoteVersion,
        buf: &[u8]) -> Result<(usize, Option<&[u8]>), Error> {
        let mut inlen = 0;
        trace!("input() state: {:?}", self.state);
        if let TrafState::Version = self.state {
            // handle initial version string
            let (l, done) = remote_version.consume(buf)?;
            trace!("input() l: {l} {done}");
            if done {
                self.state = TrafState::Idle
            }
            inlen += l;
        }
        let buf = &buf[inlen..];

        inlen += self.fill_input(keys, buf)?;

        trace!("input() state2: {:?}", self.state);
        let payload = if let TrafState::InPayload { len } = self.state {
        use pretty_hex::PrettyHex;
            let payload = &self.buf[SSH_LENGTH_SIZE + 1..SSH_LENGTH_SIZE + 1 + len];
            self.state = TrafState::Idle;
        trace!("pyload {:?}", &payload.hex_dump());
            Some(payload)
        } else {
            None
        };


        trace!("input() state2: {:?}", self.state);

        Ok((inlen, payload))
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, keys: &mut KeyState, buf: &mut [u8]) -> Result<usize, Error> {
        if let TrafState::OutPayload { len } = self.state {
            // Payload ready, encrypt it
            let len = keys.encrypt(len, self.buf)?;
            self.state = TrafState::Write { idx: 0, len };
        }

        match self.state {
            TrafState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(buf.len());
                buf.copy_from_slice(&self.buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done, read the next packet
                    self.state = TrafState::Idle
                }
                Ok(wlen)
            }
            _ => Ok(0),
        }
    }

    fn fill_input(&mut self, keys: &mut KeyState, buf: &[u8]) -> Result<usize, Error> {
        let size_block = keys.size_block_dec();
        let size_integ = keys.size_integ_dec();
        // 'r' is the remaining input, a slice that moves along.
        // Used to calculate the size to return
        let mut r = buf;

        // Either Idle with input, or filling the initial block
        if let Some(idx) = match self.state {
            TrafState::Idle if r.len() > 0 => Some(0),
            TrafState::ReadInitial { idx } => Some(idx),
            _ => None,
        } {
            let need = (size_block - idx).clamp(0, r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.buf[idx..idx + need];
            w.copy_from_slice(x);
            self.state = TrafState::ReadInitial { idx: idx + need }
        }

        // Have enough input now to decrypt the packet length
        if let TrafState::ReadInitial { idx } = self.state {
            if idx >= size_block {
                let w = &mut self.buf[..size_block];
                let total_len =
                    keys
                        .decrypt_first_block(w)?
                        .checked_add((SSH_LENGTH_SIZE + size_integ) as u32)
                        .ok_or(Error::BadDecrypt)? as usize;

                if total_len > self.buf.len() {
                    // TODO: Or just BadDecrypt could make more sense if
                    // it were packet corruption/decryption failure
                    warn!("total_len {total_len:08x}");
                    return Err(Error::BigPacket);
                }
                self.state = TrafState::Read { idx, expect: total_len }
            }
        }

        // Know expected length, read until the end of the packet.
        // We have already validated that expect_len <= buf_size
        if let TrafState::Read { ref mut idx, expect } = self.state {
            let need = (expect - *idx).min(r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.buf[*idx..*idx + need];
            w.copy_from_slice(x);
            *idx += need;
            if *idx == expect {
                self.state = TrafState::ReadComplete { len: expect }
            }
        }

        if let TrafState::ReadComplete { len } = self.state {
            let w = &mut self.buf[SSH_LENGTH_SIZE..len];
            keys.decrypt(w)?;
            let padlen = w[0] as usize;
            trace!("len {len} sub {} padlen {padlen}",
                SSH_LENGTH_SIZE + 1 + size_integ + padlen);
            let payload_len = len
                .checked_sub(SSH_LENGTH_SIZE + 1 + size_integ + padlen)
                .ok_or(Error::SSHProtoError)?;

            self.state = TrafState::InPayload { len: payload_len }
        }

        Ok(buf.len() - r.len())
    }
}
