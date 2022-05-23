#[allow(unused_imports)]
use {
    crate::error::{Error,Result},
    log::{debug, error, info, log, trace, warn},
};

use crate::encrypt::KeyState;
use crate::encrypt::{SSH_LENGTH_SIZE, SSH_PAYLOAD_START};
use crate::ident::RemoteVersion;
use crate::*;
use crate::packets::Packet;
use pretty_hex::PrettyHex;

pub(crate) struct Traffic<'a> {
    // TODO: if smoltcp exposed both ends of a CircularBuffer to recv()
    // we could perhaps just work directly in smoltcp's provided buffer?
    // Would need changes to ring chapoly_openssh and block ciphers.

    // TODO: decompression will need another buffer
    /// Accumulated input or output buffer.
    /// Should be sized to fit the largest packet allowed for input, or
    /// sequence of packets to be sent at once (see [`conn::MAX_RESPONSES`]).
    /// Contains ciphertext or cleartext, encrypted/decrypted in-place.
    /// When reading only contains a single SSH packet at a time.
    /// Writing may contain multiple SSH packets to write out, encrypted
    /// in-place as they are written to `buf`.
    buf: &'a mut [u8],
    state: TrafState,
}

/// State machine for reads/writes sharing [`Traffic::buf`]
#[derive(Debug)]
enum TrafState {

    /// Awaiting read or write, buffer is unused
    Idle,
    /// Reading initial encrypted block for packet length. idx > 0.
    ReadInitial { idx: usize },
    /// Reading remainder of encrypted packet
    Read { idx: usize, expect: usize },
    /// Whole encrypted packet has been read
    ReadComplete { len: usize },
    /// Decrypted complete input payload
    InPayload { len: usize },

    /// Writing to the socket. Buffer is encrypted in-place.
    /// Should never be left in idx==len state,
    /// instead should transition to Idle
    Write {
        /// Cursor position in the buffer
        idx: usize,
        /// Buffer available to write
        len: usize,
    },
}

#[derive(Debug)]
pub(crate) enum PacketMaker<'a> {
    Packet(Packet<'a>),
    ChanReq(channel::Req),
}

impl<'a> From<Packet<'a>> for PacketMaker<'a> {
    fn from(p: Packet<'a>) -> Self {
        PacketMaker::Packet(p)
    }
}

impl<'a> PacketMaker<'a> {
    pub fn send_packet(self, traffic: &mut Traffic, keys: &mut KeyState) -> Result<()> {
        match self {
            Self::Packet(p) => traffic.send_packet(p, keys),
            Self::ChanReq(r) => traffic.send_packet(r.packet()?, keys),
        }
    }
}

impl<'a> Traffic<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Traffic { buf, state: TrafState::Idle }
    }

    pub fn ready_input(&self) -> bool {
        match self.state {
            TrafState::Idle
            | TrafState::ReadInitial { .. }
            | TrafState::Read { .. } => true,
            TrafState::ReadComplete { .. }
            | TrafState::InPayload { .. }
            | TrafState::Write { .. } => false,
        }
    }

    pub fn output_pending(&self) -> bool {
        match self.state {
            TrafState::Write { .. } => true,
            _ => false
        }
    }

    pub fn can_output(&self) -> bool {
        match self.state {
            TrafState::Write { .. }
            | TrafState::Idle => true,
            _ => false
        }
    }

    /// Returns the number of bytes consumed.
    pub fn input(
        &mut self, keys: &mut KeyState, remote_version: &mut RemoteVersion,
        buf: &[u8],
    ) -> Result<usize, Error> {
        let mut inlen = 0;
        trace!("state {:?} input {}", self.state, buf.len());
        if remote_version.version().is_none() && matches!(self.state, TrafState::Idle) {
            // Handle initial version string
            let l;
            l = remote_version.consume(buf)?;
            inlen += l;
        }
        let buf = &buf[inlen..];

        inlen += self.fill_input(keys, buf)?;
        trace!("after inlen {inlen} state {:?}", self.state);
        Ok(inlen)
    }

    /// Returns a reference to the decrypted payload buffer if ready
    pub(crate) fn payload(&mut self) -> Option<&[u8]> {
        trace!("traf payload {:?}", self.state);
        if let TrafState::InPayload { len } = self.state {
            let payload = &self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
            Some(payload)
        } else {
            None
        }
    }

    pub(crate) fn done_payload(&mut self) -> Result<(), Error> {
        match self.state {
            TrafState::InPayload { .. } => {
                self.state = TrafState::Idle;
                Ok(())
            }
            _ => Err(Error::bug())
        }
    }

    pub fn send_version(&mut self, buf: &[u8]) -> Result<(), Error> {
        if !matches!(self.state, TrafState::Idle) {
            return Err(Error::bug());
        }

        if buf.len() + 2 > self.buf.len() {
            return Err(Error::NoRoom);
        }

        self.buf[..buf.len()].copy_from_slice(buf);
        self.buf[buf.len()] = ident::CR;
        self.buf[buf.len()+1] = ident::LF;
        self.state = TrafState::Write { idx: 0, len: buf.len() + 2 };
        Ok(())
    }

    /// Serializes and and encrypts a packet to send
    pub fn send_packet(&mut self, p: packets::Packet, keys: &mut KeyState) -> Result<()> {
        trace!("send_packet {:?}", p.message_num());

        // Either a fresh buffer or appending to write
        let (idx, len) = match self.state {
            TrafState::Idle => (0, 0),
            TrafState::Write { idx, len } => (idx, len),
            _ => Err(Error::bug())?,
        };

        // Use the remainder of our buffer to write the packet. Payload starts
        // after the length and padding bytes which get filled by encrypt()
        let wbuf = &mut self.buf[len..];
        if wbuf.len() < SSH_PAYLOAD_START {
            return Err(Error::NoRoom)
        }
        let plen = wireformat::write_ssh(&mut wbuf[SSH_PAYLOAD_START..], &p)?;
        trace!("Sending {p:?}");
        // trace!("{:?}", (&wbuf[SSH_PAYLOAD_START..SSH_PAYLOAD_START+plen]).hex_dump());

        // Encrypt in place
        let elen = keys.encrypt(plen, wbuf)?;
        self.state = TrafState::Write { idx, len: len+elen };
        Ok(())

    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> usize {
        trace!("output state {:?}", self.state);

        match self.state {
            TrafState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done, read the next packet
                    self.state = TrafState::Idle
                }
                wlen
            }
            _ => 0,
        }
    }

    fn fill_input(
        &mut self, keys: &mut KeyState, buf: &[u8],
    ) -> Result<usize, Error> {
        let size_block = keys.size_block_dec();
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
                let total_len = keys.decrypt_first_block(w)? as usize;
                if total_len > self.buf.len() {
                    // TODO: Or just BadDecrypt could make more sense if
                    // it were packet corruption/decryption failure
                    panic!("xxx");
                    return Err(Error::BigPacket { size: total_len });
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
            let w = &mut self.buf[0..len];
            let payload_len = keys.decrypt(w)?;
            self.state = TrafState::InPayload { len: payload_len }
        }

        Ok(buf.len() - r.len())
    }
}
