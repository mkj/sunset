#[allow(unused_imports)]
use {
    crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};

use crate::encrypt::KeyState;
use crate::encrypt::SSH_LENGTH_SIZE;
use crate::ident::RemoteVersion;
use crate::*;

const SSH_PAYLOAD_START: usize = SSH_LENGTH_SIZE+1;

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
    // set to true once we have read a version
    done_version: bool,
}

/// State machine for reads/writes sharing [`Traffic::buf`]
#[derive(Debug)]
enum TrafState {

    /// Reading input, buffer is unused
    Idle,
    /// Reading initial block for packet length. idx > 0.
    ReadInitial { idx: usize },
    /// Reading remainder of encrypted packet
    Read { idx: usize, expect: usize },
    /// Whole encryped packet has been read
    ReadComplete { len: usize },
    /// Decrypted complete input payload
    InPayload { len: usize },

    /// Packet awaiting output
    OutPayload { len: usize },
    /// Encrypted, writing to the socket
    Write {
        idx: usize,
        len: usize,
    },
}

impl<'a> Traffic<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Traffic { buf, state: TrafState::Idle, done_version: false }
    }

    pub fn ready_input(&self) -> bool {
        match self.state {
            TrafState::Idle
            | TrafState::ReadInitial { .. }
            | TrafState::Read { .. } => true,
            TrafState::ReadComplete { .. }
            | TrafState::InPayload { .. }
            | TrafState::OutPayload { .. }
            | TrafState::Write { .. } => false,
        }
    }

    pub fn ready_output(&self) -> bool {
        match self.state {
            TrafState::Write { .. }
            | TrafState::OutPayload { .. } => true,
            _ => false
        }
    }

    /// Returns the number of bytes consumed, and optionally
    /// a complete packet payload.
    pub fn input(
        &mut self, keys: &mut KeyState, remote_version: &mut RemoteVersion,
        buf: &[u8],
    ) -> Result<(usize, Option<&[u8]>), Error> {
        let mut inlen = 0;
        trace!("state {:?} input {}", self.state, buf.len());
        if !self.done_version && matches!(self.state, TrafState::Idle) {
            // handle initial version string
            let l;
            (l, self.done_version) = remote_version.consume(buf)?;
            inlen += l;
        }
        let buf = &buf[inlen..];

        inlen += self.fill_input(keys, buf)?;

        let payload = if let TrafState::InPayload { len } = self.state {
            let payload = &self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
            self.state = TrafState::Idle;
            Some(payload)
        } else {
            None
        };

        Ok((inlen, payload))
    }

    pub fn send_version(&mut self, buf: &[u8]) -> Result<(), Error> {
        self.send(buf)?;
        match self.state {
            TrafState::Write { idx: _, ref mut len } => {
                // add the newline
                if *len > self.buf.len() + 2 {
                    return Err(Error::Bug);
                }
                self.buf[*len] = ident::CR;
                self.buf[*len + 1] = ident::LF;
                *len += 2;
            }
            _ => {}
        }
        Ok(())
    }

    fn send(&mut self, buf: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, TrafState::Idle) {
            return Err(Error::Bug);
        }

        if buf.len() > self.buf.len() {
            return Err(Error::NoRoom);
        }

        self.buf[..buf.len()].copy_from_slice(buf);
        self.state =
            TrafState::Write { idx: 0, len: buf.len() };
        trace!("state {:?}", self.state);

        Ok(())
    }


    pub fn send_packet(&mut self, p: &packets::Packet) -> Result<(), Error> {
        // TODO: we could probably move the encryption from output() here.
        let len = wireformat::write_ssh(&mut self.buf[SSH_PAYLOAD_START..], p)?;
        self.state = TrafState::OutPayload { len };
        Ok(())

    }

    /// Write any pending output, returning the size written
    pub fn output(
        &mut self, keys: &mut KeyState, buf: &mut [u8],
    ) -> Result<usize, Error> {
        trace!("output state {:?}", self.state);
        if let TrafState::OutPayload { len } = self.state {
            // Payload ready, encrypt it
            let len = keys.encrypt(len, self.buf)?;
            self.state = TrafState::Write { idx: 0, len };
        }

        match self.state {
            TrafState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
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

    fn fill_input(
        &mut self, keys: &mut KeyState, buf: &[u8],
    ) -> Result<usize, Error> {
        let size_block = keys.size_block_dec();
        let size_integ = keys.size_integ_dec();
        // 'r' is the remaining input, a slice that moves along.
        // Used to calculate the size to return
        let mut r = buf;

        // Fill the initial block from either Idle with input,
        // partial initial block
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
                    keys.decrypt_first_block(w)?
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
            let payload_len = len
                .checked_sub(SSH_LENGTH_SIZE + 1 + size_integ + padlen)
                .ok_or(Error::SSHProtoError)?;

            self.state = TrafState::InPayload { len: payload_len }
        }

        Ok(buf.len() - r.len())
    }
}
