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
    // Would need changes to ciphers with block boundaries

    // TODO: decompression will need another buffer
    /// Accumulated input or output buffer.
    /// Should be sized to fit the largest packet allowed for input, or
    /// sequence of packets to be sent at once (see [`conn::MAX_RESPONSES`]).
    /// Contains ciphertext or cleartext, encrypted/decrypted in-place.
    /// Writing may contain multiple SSH packets to write out, encrypted
    /// in-place as they are written to `buf`.
    tx_buf: &'a mut [u8],
    /// Only contains a single SSH packet at a time.
    rx_buf: &'a mut [u8],

    tx_state: TxState,
    rx_state: RxState,
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
    /// Decrypted complete input payload. It has been dispatched by handle_payload(),
    /// remains "borrowed" for use by a progress() Event.
    BorrowPayload { len: usize },
    /// Decrypted incoming channel data
    InChannelData {
        /// channel number
        chan: u32,
        /// extended flag. usually None, or `Some(1)` for `SSH_EXTENDED_DATA_STDERR`
        ext: Option<u32>,
        /// read index of channel data. should transition to Idle once `idx==len`
        idx: usize,
        /// length of buffer, end of channel data
        len: usize,
    },
}

impl<'a> Traffic<'a> {
    pub fn new(rx_buf: &'a mut [u8], tx_buf: &'a mut [u8]) -> Self {
        Traffic { tx_buf, rx_buf,
            tx_state: TxState::Idle,
            rx_state: RxState::Idle,
        }
    }

    pub fn ready_input(&self) -> bool {
        match self.rx_state {
            RxState::Idle
            | RxState::ReadInitial { .. }
            | RxState::Read { .. } => true,
            RxState::ReadComplete { .. }
            | RxState::InPayload { .. }
            | RxState::BorrowPayload { .. }
            | RxState::InChannelData { .. }
            => false,
        }
    }

    pub fn output_pending(&self) -> bool {
        match self.tx_state {
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
        match self.tx_state {
            TxState::Write { len, .. } => {
                keys.max_enc_payload(self.tx_buf.len() - len)
            }
            TxState::Idle => {
                keys.max_enc_payload(self.tx_buf.len())
            }
        }
    }

    /// Returns the number of bytes consumed.
    pub fn input(
        &mut self, keys: &mut KeyState, remote_version: &mut RemoteVersion,
        buf: &[u8],
    ) -> Result<usize, Error> {
        let mut inlen = 0;
        trace!("state {:?} input {}", self.rx_state, buf.len());
        if remote_version.version().is_none() && matches!(self.rx_state, RxState::Idle) {
            // Handle initial version string
            let l;
            l = remote_version.consume(buf)?;
            inlen += l;
        }
        let buf = &buf[inlen..];

        inlen += self.fill_input(keys, buf)?;
        trace!("after inlen {inlen} state {:?}", self.rx_state);
        Ok(inlen)
    }

    /// Returns a reference to the decrypted payload buffer if ready,
    /// and the `seq` of that packet.
    pub(crate) fn payload(&mut self) -> Option<(&[u8], u32)> {
        match self.rx_state {
            | RxState::InPayload { len, seq }
            => {
                let payload = &self.rx_buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
                Some((payload, seq))
            }
            _ => None,
        }
    }

    pub(crate) fn payload_reborrow(&mut self) -> Option<&[u8]> {
        match self.rx_state {
            | RxState::InPayload { len, .. }
            | RxState::BorrowPayload { len, .. }
            => {
                let payload = &self.rx_buf[SSH_PAYLOAD_START..SSH_PAYLOAD_START + len];
                Some(payload)
            }
            _ => None,
        }
    }

    /// Called when `payload()` has been handled once, can still be
    /// `payload_reborrow()`ed later.
    pub(crate) fn handled_payload(&mut self) -> Result<(), Error> {
        match self.rx_state {
            | RxState::InPayload { len, .. }
            | RxState::BorrowPayload { len }
            => {
                self.rx_state = RxState::BorrowPayload { len };
                Ok(())
            }
            _ => Err(Error::bug())
        }
    }

    /// Called when `payload()` and `payload_reborrow()` are complete.
    pub(crate) fn done_payload(&mut self) -> Result<(), Error> {
        match self.rx_state {
            | RxState::InPayload { .. }
            | RxState::BorrowPayload { .. }
            => {
                self.rx_state = RxState::Idle;
                Ok(())
            }
            _ => {
                // Just ignore it
                // warn!("done_payload called without payload, st {:?}", self.state);
                Ok(())
            }
        }
    }

    pub fn send_version(&mut self, buf: &[u8]) -> Result<(), Error> {
        if !matches!(self.tx_state, TxState::Idle) {
            return Err(Error::bug());
        }

        if buf.len() + 2 > self.tx_buf.len() {
            return Err(Error::NoRoom);
        }

        self.tx_buf[..buf.len()].copy_from_slice(buf);
        self.tx_buf[buf.len()] = ident::CR;
        self.tx_buf[buf.len()+1] = ident::LF;
        self.tx_state = TxState::Write { idx: 0, len: buf.len() + 2 };
        Ok(())
    }

    /// Serializes and and encrypts a packet to send
    pub fn send_packet(&mut self, p: packets::Packet, keys: &mut KeyState) -> Result<()> {
        trace!("send_packet {:?}", p.message_num());

        // Either a fresh buffer or appending to write
        let (idx, len) = match self.tx_state {
            TxState::Idle => (0, 0),
            TxState::Write { idx, len } => (idx, len),
            _ => {
                trace!("bad state {:?}", self.tx_state);
                Err(Error::bug())?
            }
        };

        // Use the remainder of our buffer to write the packet. Payload starts
        // after the length and padding bytes which get filled by encrypt()
        let wbuf = &mut self.tx_buf[len..];
        if wbuf.len() < SSH_PAYLOAD_START {
            return Err(Error::NoRoom)
        }
        let plen = sshwire::write_ssh(&mut wbuf[SSH_PAYLOAD_START..], &p)?;
        trace!("Sending {p:?}");
        trace!("new {plen} {:?}", (&wbuf[SSH_PAYLOAD_START..SSH_PAYLOAD_START+plen]).hex_dump());

        // Encrypt in place
        let elen = keys.encrypt(plen, wbuf)?;
        self.tx_state = TxState::Write { idx, len: len+elen };
        Ok(())

    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> usize {
        let r = match self.tx_state {
            TxState::Write { ref mut idx, len } => {
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.tx_buf[*idx..*idx + wlen]);
                *idx += wlen;

                if *idx == len {
                    // all done, read the next packet
                    self.tx_state = TxState::Idle
                }
                wlen
            }
            _ => 0,
        };
        trace!("output state now {:?}", self.tx_state);
        r
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
        if let Some(idx) = match self.rx_state {
            RxState::Idle if r.len() > 0 => Some(0),
            RxState::ReadInitial { idx } => Some(idx),
            _ => None,
        } {
            let need = (size_block - idx).clamp(0, r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.rx_buf[idx..idx + need];
            w.copy_from_slice(x);
            self.rx_state = RxState::ReadInitial { idx: idx + need }
        }

        // Have enough input now to decrypt the packet length
        if let RxState::ReadInitial { idx } = self.rx_state {
            if idx >= size_block {
                let w = &mut self.rx_buf[..size_block];
                let total_len = keys.decrypt_first_block(w)? as usize;
                if total_len > self.rx_buf.len() {
                    // TODO: Or just BadDecrypt could make more sense if
                    // it were packet corruption/decryption failure
                    return Err(Error::BigPacket { size: total_len });
                }
                self.rx_state = RxState::Read { idx, expect: total_len }
            }
        }

        // Know expected length, read until the end of the packet.
        // We have already validated that expect_len <= buf_size
        if let RxState::Read { ref mut idx, expect } = self.rx_state {
            let need = (expect - *idx).min(r.len());
            let x;
            (x, r) = r.split_at(need);
            let w = &mut self.rx_buf[*idx..*idx + need];
            w.copy_from_slice(x);
            *idx += need;
            if *idx == expect {
                self.rx_state = RxState::ReadComplete { len: expect }
            }
        }

        if let RxState::ReadComplete { len } = self.rx_state {
            let w = &mut self.rx_buf[0..len];
            let seq = keys.recv_seq();
            let payload_len = keys.decrypt(w)?;
            self.rx_state = RxState::InPayload { len: payload_len, seq }
        }

        Ok(buf.len() - r.len())
    }

    pub fn ready_channel_input(&self) -> Option<(u32, Option<u32>)> {
        match self.rx_state {
            RxState::InChannelData { chan, ext, .. } => Some((chan, ext)),
            _ => None,
        }
    }

    pub fn set_channel_input(&mut self, di: channel::DataIn) -> Result<()> {
        trace!("traf chan input state {:?}", self.rx_state);
        match self.rx_state {
            RxState::Idle => {
                let idx = SSH_PAYLOAD_START + di.offset;
                self.rx_state = RxState::InChannelData { chan: di.num, ext: di.ext, idx, len: idx + di.len };
                // error!("set input {:?}", self.state);
                trace!("all buf {:?}", self.rx_buf[..32].hex_dump());
                trace!("set chan input offset {} idx {} {:?}",
                    di.offset, idx,
                    self.rx_buf[idx..idx + di.len].hex_dump());
                Ok(())
            }
            _ => Err(Error::bug()),
        }
    }

    // Returns the length consumed, and a bool indicating whether the whole
    // data packet has been completed.
    pub fn channel_input(
        &mut self,
        chan: u32,
        ext: Option<u32>,
        buf: &mut [u8],
    ) -> (usize, bool) {
        trace!("channel input {chan} {ext:?} st {:?}", self.rx_state);

        match self.rx_state {
            RxState::InChannelData { chan: c, ext: e, ref mut idx, len }
            if (c, e) == (chan, ext) => {
                if *idx > len {
                    error!("bad idx {} len {} e {:?} c {}", *idx, len, e, c);
                }
                let wlen = (len - *idx).min(buf.len());
                buf[..wlen].copy_from_slice(&self.rx_buf[*idx..*idx + wlen]);
                // info!("idx {} += wlen {} = {}", *idx, wlen, *idx+wlen);
                *idx += wlen;

                if *idx == len {
                    // all done.
                    self.rx_state = RxState::Idle;
                    (wlen, true)
                } else {
                    (wlen, false)
                }
            }
            _ => (0, false)
        }
    }

}

pub(crate) struct TrafSend<'a> {
    traffic: &'a mut Traffic<'a>,
    keys: &'a mut KeyState,
}

impl<'a> TrafSend<'a> {
    pub fn new(traffic: &mut Traffic, keys: &mut KeyState) -> Self {
        Self {
            traffic,
            keys,
        }
    }

    pub fn send<'p, P: Into<packets::Packet<'p>>>(&self, p: P) -> Result<()> {
        self.traffic.send_packet(p.into(), self.keys)
    }

    pub fn rekey(&self, keys: encrypt::Keys) {
        self.keys.rekey(keys)
    }
}
