use core::fmt;

#[allow(unused_imports)]
use {
    crate::error::{Error, Result},
    log::{debug, error, info, log, trace, warn},
};

use zeroize::Zeroize;

use crate::channel::{ChanData, ChanNum};
use crate::encrypt::KeyState;
use crate::encrypt::{SSH_LENGTH_SIZE, SSH_PAYLOAD_START};
use crate::ident::RemoteVersion;
use crate::packets::Packet;
use crate::*;
use pretty_hex::PrettyHex;

// TODO: if smoltcp exposed both ends of a CircularBuffer to recv()
// we could perhaps just work directly in smoltcp's provided buffer?
// Would need changes to ciphers with block boundaries

pub(crate) struct TrafOut<'a> {
    // TODO: decompression will need another buffer
    /// Accumulated output buffer.
    ///
    /// Should be sized to fit the largest
    /// sequence of packets to be sent at once.
    /// Contains ciphertext or cleartext, encrypted in-place.
    /// Writing may contain multiple SSH packets to write out, encrypted
    /// in-place as they are written to `buf`.
    buf: &'a mut [u8],
    state: TxState,
}

// TODO only pub for testing
// pub(crate) struct TrafIn<'a> {
pub struct TrafIn<'a> {
    // TODO: decompression will need another buffer
    /// Accumulated input buffer.
    ///
    /// Should be sized to fit the largest packet allowed for input.
    /// Contains ciphertext or cleartext, decrypted in-place.
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

    /// No more output will be produced
    Closed,
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
        chan: ChanNum,
        /// Normal or Stderr
        dt: ChanData,
        /// read index of channel data. should transition to Idle once `idx==len`
        idx: usize,
        /// length of channel data
        len: usize,
    },
}

impl core::fmt::Debug for TrafIn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafIn").field("state", &self.state).finish_non_exhaustive()
    }
}

impl core::fmt::Debug for TrafOut<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrafOut").field("state", &self.state).finish_non_exhaustive()
    }
}

impl<'a> TrafIn<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, state: RxState::Idle }
    }

    pub fn is_input_ready(&self) -> bool {
        match self.state {
            RxState::Idle | RxState::ReadInitial { .. } | RxState::Read { .. } => {
                true
            }
            RxState::ReadComplete { .. }
            | RxState::InPayload { .. }
            | RxState::InChannelData { .. } => false,
        }
    }

    /// Returns the number of bytes consumed.
    pub fn input(
        &mut self,
        keys: &mut KeyState,
        remote_version: &mut RemoteVersion,
        buf: &[u8],
    ) -> Result<usize, Error> {
        let mut inlen = 0;
        debug_assert!(self.is_input_ready());
        if remote_version.version().is_none() && matches!(self.state, RxState::Idle)
        {
            // Handle initial version string
            inlen += remote_version.consume(buf)?;
        }
        let buf = &buf[inlen..];

        inlen += self.fill_input(keys, buf)?;
        Ok(inlen)
    }

    /// Called when `payload()` is complete.
    pub(crate) fn done_payload(&mut self) {
        if let RxState::InPayload { .. } = self.state {
            self.state = RxState::Idle
        }
    }

    /// Called when `payload()` is complete, zeroizes the payload
    /// Also calls `done_payload()`.
    pub(crate) fn zeroize_payload(&mut self) {
        if let RxState::InPayload { len, .. } = self.state {
            self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len].zeroize();
            self.done_payload()
        }
    }

    /// Returns a reference to the decrypted payload buffer if ready,
    /// and the `seq` of that packet.
    // TODO: only pub for testing
    // pub(crate) fn payload(&mut self) -> Option<(&[u8], u32)> {
    pub fn payload(&self) -> Option<(&[u8], u32)> {
        match self.state {
            RxState::InPayload { len, seq } => {
                let payload = &self.buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
                Some((payload, seq))
            }
            _ => None,
        }
    }

    fn fill_input(
        &mut self,
        keys: &mut KeyState,
        buf: &[u8],
    ) -> Result<usize, Error> {
        let size_block = keys.size_block_dec();
        // 'r' is the remaining input, a slice that moves along.
        // Used to calculate the size to return
        let mut r = buf;

        trace!("fill_input {:?}", self.state);

        // Fill the initial block from either Idle with input,
        // partial initial block
        if let Some(idx) = match self.state {
            RxState::Idle if !r.is_empty() => Some(0),
            RxState::ReadInitial { idx } => Some(idx),
            _ => None,
        } {
            trace!("fill_input idle idx {idx}");
            let need = (size_block - idx).clamp(0, r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.buf[idx..idx + need];
            w.copy_from_slice(x);
            self.state = RxState::ReadInitial { idx: idx + need }
        }

        // Have enough input now to decrypt the packet length
        if let RxState::ReadInitial { idx } = self.state {
            trace!("fill_input readinit {idx}");
            if idx >= size_block {
                let w = &mut self.buf[..size_block];
                let total_len = keys.decrypt_first_block(w)?;
                if total_len > self.buf.len() {
                    // TODO: Or just BadDecrypt could make more sense if
                    // it were packet corruption/decryption failure
                    return Err(Error::BigPacket { size: total_len });
                }
                if total_len < size_block {
                    return Err(Error::BadDecrypt);
                }
                trace!("fill_input set read  {idx} ex {total_len}");
                self.state = RxState::Read { idx, expect: total_len }
            }
        }

        // Know expected length, read until the end of the packet.
        // We have already validated that expect_len <= buf_size
        if let RxState::Read { ref mut idx, expect } = self.state {
            trace!("expect {expect} idx {idx}");
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
        trace!("out");

        Ok(buf.len() - r.len())
    }

    /// Returns `(channel, dt, length)`
    pub fn read_channel_ready(&self) -> Option<(ChanNum, ChanData, usize)> {
        match self.state {
            RxState::InChannelData { chan, dt, idx, len } => {
                debug_assert!(len > idx);
                let rem = len - idx;
                Some((chan, dt, rem))
            }
            _ => None,
        }
    }

    /// Set channel data ready to be read.
    pub fn set_read_channel_data(&mut self, di: channel::DataIn) -> Result<()> {
        match self.state {
            RxState::InPayload { .. } => {
                let idx = SSH_PAYLOAD_START + di.dt.packet_offset();
                self.state = RxState::InChannelData {
                    chan: di.num,
                    dt: di.dt,
                    idx,
                    len: idx + di.len.get(),
                };
                Ok(())
            }
            _ => Err(Error::bug()),
        }
    }

    // Returns the length returned, and an Option<len> indicating whether the whole
    // data packet has been completed, or None if some is still pending.
    pub fn read_channel(
        &mut self,
        chan: ChanNum,
        dt: ChanData,
        buf: &mut [u8],
    ) -> (usize, Option<usize>) {
        match self.state {
            RxState::InChannelData { chan: c, dt: e, ref mut idx, len }
                if (c, e) == (chan, dt) =>
            {
                debug_assert!(len > *idx);
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done.
                    self.state = RxState::Idle;
                    (wlen, Some(len))
                } else {
                    (wlen, None)
                }
            }
            _ => (0, None),
        }
    }

    // Returns (length, complete: Option<len: usize>>, Option(dt))
    pub fn read_channel_either(
        &mut self,
        chan: ChanNum,
        buf: &mut [u8],
    ) -> (usize, Option<usize>, ChanData) {
        match self.state {
            RxState::InChannelData { chan: c, dt, ref mut idx, len }
                if c == chan =>
            {
                debug_assert!(len > *idx);
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.buf[*idx..*idx + wlen]);
                // info!("idx {} += wlen {} = {}", *idx, wlen, *idx+wlen);
                *idx += wlen;

                if *idx == len {
                    // all done.
                    self.state = RxState::Idle;
                    (wlen, Some(len), dt)
                } else {
                    (wlen, None, dt)
                }
            }
            _ => (0, None, ChanData::Normal),
        }
    }

    /// Returns the length of data discarded
    pub fn discard_read_channel(&mut self, chan: ChanNum) -> usize {
        match self.state {
            RxState::InChannelData { chan: c, len, .. } if c == chan => {
                self.state = RxState::Idle;
                len
            }
            _ => 0,
        }
    }
}

impl<'a> TrafOut<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, state: TxState::Idle }
    }

    /// Serializes and and encrypts a packet to send
    pub(crate) fn send_packet(
        &mut self,
        p: packets::Packet,
        keys: &mut KeyState,
    ) -> Result<()> {
        // Sanity check
        match p.category() {
            packets::Category::All | packets::Category::Kex => (), // OK cleartext
            _ => {
                if keys.is_cleartext() {
                    return Error::bug_msg("send cleartext");
                }
            }
        }

        // Either a fresh buffer or appending to write
        let (idx, len) = match self.state {
            TxState::Idle => (0, 0),
            TxState::Write { idx, len } => (idx, len),
            TxState::Closed => {
                trace!("Dropped output after close {p:?}");
                return Ok(());
            }
        };

        // Use the remainder of our buffer to write the packet. Payload starts
        // after the length and padding bytes which get filled by encrypt()
        let wbuf = &mut self.buf[len..];
        if wbuf.len() < SSH_PAYLOAD_START {
            return error::NoRoom.fail();
        }
        let plen = sshwire::write_ssh(&mut wbuf[SSH_PAYLOAD_START..], &p)?;
        trace!("Sending {p:?}");

        // Encrypt in place
        let elen = keys.encrypt(plen, wbuf)?;
        self.state = TxState::Write { idx, len: len + elen };
        Ok(())
    }

    pub fn is_output_pending(&self) -> bool {
        matches!(self.state, TxState::Write { .. })
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
            TxState::Write { len, .. } => keys.max_enc_payload(self.buf.len() - len),
            TxState::Idle => keys.max_enc_payload(self.buf.len()),
            // output will just be dropped in closed state.
            TxState::Closed => self.buf.len(),
        }
    }

    /// Move to Closed state. Current output is lost, future output
    /// is discarded. This is called when the output tcp pipe
    /// has closed so there's nowhere to send output anyway.
    pub fn close(&mut self) {
        self.state = TxState::Closed
    }

    pub fn closed(&self) -> bool {
        matches!(self.state, TxState::Closed)
    }

    pub fn send_version(&mut self) -> Result<(), Error> {
        if !matches!(self.state, TxState::Idle) {
            return Err(Error::bug());
        }

        let len = ident::write_version(self.buf)?;
        self.state = TxState::Write { idx: 0, len };
        Ok(())
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> usize {
        let b = self.output_buf();
        let wlen = buf.len().min(b.len());
        buf[..wlen].copy_from_slice(&b[..wlen]);
        self.consume_output(wlen);
        wlen
    }

    pub fn output_buf(&mut self) -> &[u8] {
        match self.state {
            TxState::Write { ref mut idx, len } => {
                let wlen = len - *idx;
                &self.buf[*idx..*idx + wlen]
            }
            _ => &[],
        }
    }

    pub fn consume_output(&mut self, l: usize) {
        match self.state {
            TxState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(l);
                *idx += wlen;

                if *idx == len {
                    // all done, read the next packet
                    self.state = TxState::Idle
                }
            }
            _ => (),
        }
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
    fn new(out: &'s mut TrafOut<'a>, keys: &'s mut KeyState) -> Self {
        Self { out, keys }
    }

    pub fn send<'p, P: Into<packets::Packet<'p>>>(&mut self, p: P) -> Result<()> {
        self.out.send_packet(p.into(), self.keys)
    }

    pub fn rekey(&mut self, keys: encrypt::Keys) {
        self.keys.rekey(keys)
    }

    pub fn enable_strict_kex(&mut self) {
        self.keys.enable_strict_kex()
    }

    pub fn send_version(&mut self) -> Result<(), Error> {
        self.out.send_version()
    }

    pub fn can_output(&self) -> bool {
        self.out.can_output()
    }

    /// Returns the current receive sequence number
    pub fn recv_seq(&self) -> u32 {
        self.keys.seq_decrypt.0
    }
}
