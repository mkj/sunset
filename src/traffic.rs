#[allow(unused_imports)]
use {
    crate::error::{Error,Result},
    log::{debug, error, info, log, trace, warn},
};

use zeroize::Zeroize;

use crate::encrypt::KeyState;
use crate::encrypt::{SSH_LENGTH_SIZE, SSH_PAYLOAD_START};
use crate::ident::RemoteVersion;
use crate::channel::{ChanNum, ChanData};
use crate::*;
use crate::packets::Packet;
use pretty_hex::PrettyHex;

pub(crate) struct TrafOut<'a> {
    // TODO: if smoltcp exposed both ends of a CircularBuffer to recv()
    // we could perhaps just work directly in smoltcp's provided buffer?
    // Would need changes to ciphers with block boundaries

    // TODO: decompression will need another buffer
    /// Accumulated input or output buffer.
    /// Should be sized to fit the largest packet allowed for input, or
    /// sequence of packets to be sent at once (see [`conn::MAX_RESPONSES`]).
    /// Contains ciphertext or cleartext, encrypted/decrypted in-place.
    /// Writing may contain multiple SSH packets to write out, encrypted
    /// in-place as they are written to `buf`.
    buf: &'a mut [u8],
    state: TxState,
}

pub(crate) struct TrafIn<'a> {
    // TODO: if smoltcp exposed both ends of a CircularBuffer to recv()
    // we could perhaps just work directly in smoltcp's provided buffer?
    // Would need changes to ciphers with block boundaries

    // TODO: decompression will need another buffer
    /// Accumulated input or output buffer.
    /// Should be sized to fit the largest packet allowed for input, or
    /// sequence of packets to be sent at once (see [`conn::MAX_RESPONSES`]).
    /// Contains ciphertext or cleartext, encrypted/decrypted in-place.
    /// Writing may contain multiple SSH packets to write out, encrypted
    /// in-place as they are written to `buf`.
    /// Only contains a single SSH packet at a time.
    buf: &'a mut [u8],
    state: RxState,
}

/// State machine for writes
#[derive(Debug)]
enum TxState {

    /// Awaiting write, buffer is unused
    Idle,

    /// Writing to the socket. Buffer is encrypted in-place.
    /// Should never be left in `idx==len` state,
    /// instead should transition to Idle
    Write {
        /// Cursor position in the buffer
        idx: usize,
        /// Buffer available to write
        len: usize,
    },
}

#[derive(Debug)]
enum RxState {

    /// Awaiting read, buffer is unused
    Idle,
    /// Reading initial encrypted block for packet length. idx > 0.
    ReadInitial { idx: usize },
    /// Reading remainder of encrypted packet
    Read { idx: usize, expect: usize },
    /// Whole encrypted packet has been read
    ReadComplete { len: usize },
    /// Decrypted complete input payload
    InPayload { len: usize, seq: u32 },
    /// Decrypted incoming channel data
    InChannelData {
        /// channel number
        chan: u32,
        /// extended flag. usually None, or `Some(1)` for `SSH_EXTENDED_DATA_STDERR`
        dt: ChanData,
        /// read index of channel data. should transition to Idle once `idx==len`
        idx: usize,
        /// length of channel data
        len: usize,
    },
}

impl<'a> TrafIn<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, state: RxState::Idle }
    }

    pub fn ready_input(&self) -> bool {
        match self.state {
            | RxState::Idle
            | RxState::ReadInitial { .. }
            | RxState::Read { .. }
            => true,
            | RxState::ReadComplete { .. }
            | RxState::InPayload { .. }
            | RxState::InChannelData { .. }
            => false,
        }
    }

    /// Returns the number of bytes consumed.
    pub fn input(
        &mut self, keys: &mut KeyState, remote_version: &mut RemoteVersion,
        buf: &[u8],
    ) -> Result<usize, Error> {
        let mut inlen = 0;
        debug_assert!(self.ready_input());
        if remote_version.version().is_none() && matches!(self.state, RxState::Idle) {
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

    /// Called when `payload()` and `payload_reborrow()` are complete.
    pub(crate) fn done_payload(&mut self, zeroize: bool) -> Result<(), Error> {
        match self.state {
            RxState::InPayload { len, .. } => {
                if zeroize {
                    self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len].zeroize();
                }
                trace!("channel_input idle was {:?} done_payload", self.state);
                self.state = RxState::Idle;
                Ok(())
            }
            _ => {
                // Just ignore it
                // warn!("done_payload called without payload, st {:?}", self.state);
                Ok(())
            }
        }
    }

    /// Returns a reference to the decrypted payload buffer if ready,
    /// and the `seq` of that packet.
    pub(crate) fn payload(&mut self) -> Option<(&[u8], u32)> {
        match self.state {
            | RxState::InPayload { len, seq }
            => {
                let payload = &self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
                Some((payload, seq))
            }
            _ => None,
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
            RxState::Idle if r.len() > 0 => Some(0),
            RxState::ReadInitial { idx } => Some(idx),
            _ => None,
        } {
            let need = (size_block - idx).clamp(0, r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.buf[idx..idx + need];
            w.copy_from_slice(x);
            self.state = RxState::ReadInitial { idx: idx + need }
        }

        // Have enough input now to decrypt the packet length
        if let RxState::ReadInitial { idx } = self.state {
            if idx >= size_block {
                let w = &mut self.buf[..size_block];
                let total_len = keys.decrypt_first_block(w)? as usize;
                if total_len > self.buf.len() {
                    // TODO: Or just BadDecrypt could make more sense if
                    // it were packet corruption/decryption failure
                    return Err(Error::BigPacket { size: total_len });
                }
                self.state = RxState::Read { idx, expect: total_len }
            }
        }

        // Know expected length, read until the end of the packet.
        // We have already validated that expect_len <= buf_size
        if let RxState::Read { ref mut idx, expect } = self.state {
            let need = (expect - *idx).min(r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.buf[*idx..*idx + need];
            w.copy_from_slice(x);
            *idx += need;
            if *idx == expect {
                self.state = RxState::ReadComplete { len: expect }
            }
        }

        if let RxState::ReadComplete { len } = self.state {
            let w = &mut self.buf[..len];
            let seq = keys.recv_seq();
            let payload_len = keys.decrypt(w)?;
            self.state = RxState::InPayload { len: payload_len, seq }
        }

        Ok(buf.len() - r.len())
    }

    /// Returns `(channel, dt, length)`
    pub fn ready_channel_input(&self) -> Option<(u32, ChanData, usize)> {
        trace!("ready_channel_input state {:?}", self.state);
        match self.state {
            RxState::InChannelData { chan, dt, idx, len } => {
                let rem = len - idx;
                debug_assert!(rem > 0);
                Some((chan, dt, rem))
            },
            _ => None,
        }
    }

    pub fn set_channel_input(&mut self, di: channel::DataIn) -> Result<()> {
        trace!("traf chan input state {:?}", self.state);
        match self.state {
            RxState::InPayload { .. } => {
                let idx = SSH_PAYLOAD_START + di.offset;
                self.state = RxState::InChannelData { chan: di.num, dt: di.dt, idx, len: idx + di.len };
                Ok(())
            }
            _ => Err(Error::bug()),
        }
    }

    // Returns the length consumed, and an Option<len> indicating whether the whole
    // data packet has been completed, or None if some is still pending.
    pub fn channel_input(
        &mut self,
        chan: u32,
        dt: ChanData,
        buf: &mut [u8],
    ) -> (usize, Option<usize>) {
        trace!("channel input {chan} dt arg {dt:?} state {:?}", self.state);

        match self.state {
            RxState::InChannelData { chan: c, dt: e, ref mut idx, len }
            if (c, e) == (chan, dt) => {
                debug_assert!(len >= *idx);
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done.
                    trace!("channel_input idle was {:?} all done", self.state);
                    self.state = RxState::Idle;
                    (wlen, Some(len))
                } else {
                    (wlen, None)
                }
            }
            _ => (0, None)
        }
    }

    // Returns (length, complete: Option<len: usize>>, Option(dt))
    pub fn channel_input_either(
        &mut self,
        chan: u32,
        buf: &mut [u8],
    ) -> (usize, Option<usize>, ChanData) {
        trace!("channel input {chan} state {:?}", self.state);

        match self.state {
            RxState::InChannelData { chan: c, dt, ref mut idx, len }
            if c == chan => {
                debug_assert!(len >= *idx);
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                // info!("idx {} += wlen {} = {}", *idx, wlen, *idx+wlen);
                *idx += wlen;

                if *idx == len {
                    // all done.
                    trace!("channel_input idle was {:?} all done", self.state);
                    self.state = RxState::Idle;
                    (wlen, Some(len), dt)
                } else {
                    (wlen, None, dt)
                }
            }
            _ => (0, None, ChanData::Normal)
        }
    }

    /// Returns the length of data discarded
    pub fn discard_channel_input(&mut self, chan: u32) -> usize {
        match self.state {
            RxState::InChannelData { chan: c, len, .. }
            if c == chan => {
                trace!("channel_input idle was {:?} discard", self.state);
                self.state = RxState::Idle;
                len
            }
            _ => 0
        }
    }
}

impl<'a> TrafOut<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, state: TxState::Idle }
    }

    /// Serializes and and encrypts a packet to send
    pub(crate) fn send_packet(&mut self, p: packets::Packet, keys: &mut KeyState) -> Result<()> {
        trace!("send_packet {:?}", p.message_num());

        // Either a fresh buffer or appending to write
        let (idx, len) = match self.state {
            TxState::Idle => (0, 0),
            TxState::Write { idx, len } => (idx, len),
        };

        // Sanity check
        match p.category() {
            packets::Category::All | packets::Category::Kex => (), // OK cleartext
            _ => {
                if keys.is_cleartext() {
                    return Error::bug_msg("send cleartext")
                }
            }
        }

        // Use the remainder of our buffer to write the packet. Payload starts
        // after the length and padding bytes which get filled by encrypt()
        let wbuf = &mut self.buf[len..];
        if wbuf.len() < SSH_PAYLOAD_START {
            return Err(Error::NoRoom)
        }
        let plen = sshwire::write_ssh(&mut wbuf[SSH_PAYLOAD_START..], &p)?;
        trace!("Sending {p:?}");
        trace!("new {plen} {:?}", (&wbuf[SSH_PAYLOAD_START..SSH_PAYLOAD_START+plen]).hex_dump());

        // Encrypt in place
        let elen = keys.encrypt(plen, wbuf)?;
        self.state = TxState::Write { idx, len: len+elen };
        Ok(())

    }

    pub fn output_pending(&self) -> bool {
        match self.state {
            TxState::Write { .. } => true,
            _ => false
        }
    }

    /// A simple test if a packet can be sent. `send_allowed` should be used
    /// for more general situations
    pub fn can_output(&self) -> bool {
        // TODO don't use this
        true
    }

    /// Returns payload space available to send a packet. Returns 0 if not ready or full
    pub fn send_allowed(&self, keys: &KeyState) -> usize {
        // TODO: test for full output buffer
        match self.state {
            TxState::Write { len, .. } => {
                keys.max_enc_payload(self.buf.len() - len)
            }
            TxState::Idle => {
                keys.max_enc_payload(self.buf.len())
            }
        }
    }

    pub fn send_version(&mut self) -> Result<(), Error> {
        if !matches!(self.state, TxState::Idle) {
            return Err(Error::bug());
        }

        let len = ident::write_version(&mut self.buf)?;
        self.state = TxState::Write { idx: 0, len };
        Ok(())
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> usize {
        let r = match self.state {
            TxState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done, read the next packet
                    self.state = TxState::Idle
                }
                wlen
            }
            _ => 0,
        };
        trace!("output state now {:?}", self.state);
        r
    }


    pub fn sender<'s>(&'s mut self, keys: &'s mut KeyState) -> TrafSend<'s, 'a> {
        TrafSend::new(self, keys)
    }

}

/// Convenience to pass TrafOut with keys
pub(crate) struct TrafSend<'s, 'a> {
    out: &'s mut TrafOut<'a>,
    keys: &'s mut KeyState,
}

impl<'s, 'a> TrafSend<'s, 'a> {
    fn new<'f>(out: &'s mut TrafOut<'a>, keys: &'s mut KeyState) -> Self {
        Self {
            out,
            keys,
        }
    }

    pub fn send<'p, P: Into<packets::Packet<'p>>>(&mut self, p: P) -> Result<()> {
        self.out.send_packet(p.into(), self.keys)
    }


    pub fn rekey(&mut self, keys: encrypt::Keys) {
        self.keys.rekey(keys)
    }

    pub fn send_version(&mut self) -> Result<(), Error> {
        self.out.send_version()
    }

    pub fn can_output(&self) -> bool {
        self.out.can_output()
    }
}

