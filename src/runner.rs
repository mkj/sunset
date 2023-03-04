#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};

use pretty_hex::PrettyHex;

use crate::*;
use packets::{ChannelDataExt, ChannelData};
use crate::channel::{ChanNum, ChanData};
use encrypt::KeyState;
use traffic::{TrafIn, TrafOut, TrafSend};

use conn::{Conn, Dispatched};

// Runner public methods take a `ChanHandle` which cannot be cloned. This prevents
// confusion if an application were to continue using a channel after the channel
// was completed. The `ChanHandle` is consumed by `Runner::channel_done()`.
// Internally sunset uses `ChanNum`, which is just a newtype around u32.

pub struct Runner<'a> {
    conn: Conn,

    /// Binary packet handling from the network buffer
    traf_in: TrafIn<'a>,
    /// Binary packet handling to the network buffer
    traf_out: TrafOut<'a>,

    /// Current encryption/integrity keys
    keys: KeyState,

    /// Waker when output is ready
    output_waker: Option<Waker>,
    /// Waker when ready to consume input.
    input_waker: Option<Waker>,

    closed: bool,
}

impl core::fmt::Debug for Runner<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Runner")
        .field("keys", &self.keys)
        .field("output_waker", &self.output_waker)
        .field("input_waker", &self.input_waker)
        .finish_non_exhaustive()
    }
}

impl<'a> Runner<'a> {
    /// `inbuf` must be sized to fit the largest SSH packet allowed.
    pub fn new_client(
        inbuf: &'a mut [u8],
        outbuf: &'a mut [u8],
    ) -> Result<Runner<'a>, Error> {
        let conn = Conn::new_client()?;
        let runner = Runner {
            conn,
            traf_in: TrafIn::new(inbuf),
            traf_out: TrafOut::new(outbuf),
            keys: KeyState::new_cleartext(),
            output_waker: None,
            input_waker: None,
            closed: false,
        };

        Ok(runner)
    }

    pub fn new_server(
        inbuf: &'a mut [u8],
        outbuf: &'a mut [u8],
    ) -> Result<Runner<'a>, Error> {
        let conn = Conn::new_server()?;
        let runner = Runner {
            conn,
            traf_in: TrafIn::new(inbuf),
            traf_out: TrafOut::new(outbuf),
            keys: KeyState::new_cleartext(),
            output_waker: None,
            input_waker: None,
            closed: false,
        };

        Ok(runner)
    }

    pub fn is_client(&self) -> bool {
        self.conn.is_client()
    }

    /// Drives connection progress, handling received payload and queueing
    /// other packets to send as required.
    ///
    /// This must be polled/awaited regularly, passing in `behaviour`.
    ///
    /// This method is async but will not await unless the `Behaviour` implementation
    /// does so. Note that some computationally intensive operations may be performed
    /// during key exchange.
    ///
    /// Returns Ok(true) if an input packet was handled, Ok(false) if no packet was ready
    /// (Can also return various errors)
    pub async fn progress(&mut self, behaviour: &mut Behaviour<'_>) -> Result<bool> {
        let mut progressed = false;
        let mut s = self.traf_out.sender(&mut self.keys);
        // Handle incoming packets
        if let Some((payload, seq)) = self.traf_in.payload() {
            progressed = true;
            let d = self.conn.handle_payload(payload, seq, &mut s, behaviour).await?;

            if let Some(data_in) = d.data_in {
                // incoming channel data, we haven't finished with payload
                trace!("handle_payload chan input {data_in:?}");
                self.traf_in.set_channel_input(data_in)?;
            } else {
                // other packets have been completed
                trace!("handle_payload done");
                self.traf_in.done_payload(d.zeroize_payload)?;
            }
        }

        self.conn.progress(&mut s, behaviour).await?;
        self.wake();

        Ok(progressed)
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.traf_in.input(
            &mut self.keys,
            &mut self.conn.remote_version,
            buf,
        )
    }

    /// Write any pending output to the wire, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.closed {
            return error::ChannelEOF.fail()
        }
        let r = self.traf_out.output(buf);
        if r > 0 {
            trace!("output() wake");
            self.wake();
        }
        Ok(r)
    }

    pub fn is_input_ready(&self) -> bool {
        (self.conn.initial_sent() && self.traf_in.is_input_ready()) || self.closed
    }

    pub fn is_output_pending(&self) -> bool {
        self.traf_out.is_output_pending() || self.closed
    }

    /// Set a waker to be notified when the `Runner` is ready
    /// to accept input from the main SSH socket.
    pub fn set_input_waker(&mut self, waker: &Waker) {
        if let Some(ref w) = self.input_waker {
            if w.will_wake(waker) {
                return
            }
        }
        self.input_waker.replace(waker.clone())
        .map(|w| w.wake());
    }

    /// Set a waker to be notified when SSH socket output is ready
    pub fn set_output_waker(&mut self, waker: &Waker) {
        if let Some(ref w) = self.output_waker {
            if w.will_wake(waker) {
                return
            }
        }
        self.output_waker.replace(waker.clone())
        .map(|w| w.wake());
    }

    pub fn close(&mut self) {
        trace!("runner close");
        self.closed = true;
        if let Some(w) = self.output_waker.take() {
            w.wake()
        }
    }

    // TODO: move somewhere client specific?
    pub fn open_client_session(&mut self, exec: Option<&str>, pty: Option<channel::Pty>) -> Result<ChanHandle> {
        trace!("open_client_session");
        let mut init_req = channel::InitReqs::new();
        if let Some(pty) = pty {
            init_req.push(channel::ReqDetails::Pty(pty)).trap()?;
        }
        if let Some(cmd) = exec {
            let mut s = channel::ExecString::new();
            s.push_str(cmd).trap()?;
            init_req.push(channel::ReqDetails::Exec(s)).trap()?;
        } else {
            init_req.push(channel::ReqDetails::Shell).trap()?;
        }
        let (chan, p) = self.conn.channels.open(packets::ChannelOpenType::Session, init_req)?;
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(ChanHandle(chan))
    }

    /// Send data from this application out the wire.
    /// Returns `Ok(len)` consumed, `Err(Error::ChannelEof)` on EOF,
    /// or other errors.
    pub fn channel_send(
        &mut self,
        chan: &ChanHandle,
        dt: ChanData,
        buf: &[u8],
    ) -> Result<usize> {
        if self.closed {
            return error::ChannelEOF.fail()
        }

        if buf.len() == 0 {
            return Ok(0)
        }

        let len = self.ready_channel_send(chan, dt)?;
        let len = match len {
            Some(l) if l == 0 => return Ok(0),
            Some(l) => l,
            None => return Err(Error::ChannelEOF),
        };

        let len = len.min(buf.len());

        let p = self.conn.channels.send_data(chan.0, dt, &buf[..len])?;
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(len)
    }

    /// Receive data coming from the wire into this application.
    /// Returns `Ok(len)` received, `Err(Error::ChannelEof)` on EOF,
    /// or other errors. Ok(0) indicates no data available, ie pending.
    /// TODO: EOF is unimplemented
    pub fn channel_input(
        &mut self,
        chan: &ChanHandle,
        dt: ChanData,
        buf: &mut [u8],
    ) -> Result<usize> {
        if self.closed {
            return error::ChannelEOF.fail()
        }

        dt.validate_receive(self.conn.is_client())?;

        if self.is_channel_eof(chan) {
            return error::ChannelEOF.fail()
        }

        trace!("runner chan in");
        let (len, complete) = self.traf_in.channel_input(chan.0, dt, buf);
        trace!("runner chan in, len {len} complete {complete:?} dt {dt:?}");
        if let Some(len) = complete {
            let wind_adjust = self.conn.channels.finished_input(chan.0, len)?;
            if let Some(wind_adjust) = wind_adjust {
                self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
            }
            self.wake();
        }
        Ok(len)
    }

    /// Receives input data, either dt or normal.
    pub fn channel_input_either(
        &mut self,
        chan: &ChanHandle,
        buf: &mut [u8],
    ) -> Result<(usize, ChanData)> {
        trace!("runner chan in");
        let (len, complete, dt) = self.traf_in.channel_input_either(chan.0, buf);
        trace!("runner chan in, len {len} complete {complete:?} dt {dt:?}");
        if let Some(len) = complete {
            let wind_adjust = self.conn.channels.finished_input(chan.0, len)?;
            if let Some(wind_adjust) = wind_adjust {
                self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
            }
            self.wake();
        }
        Ok((len, dt))
    }


    /// Discards any channel input data pending for `chan`, regardless of whether
    /// normal or `dt`.
    pub fn discard_channel_input(&mut self, chan: &ChanHandle) -> Result<()> {
        let len = self.traf_in.discard_channel_input(chan.0);
        let wind_adjust = self.conn.channels.finished_input(chan.0, len)?;
        if let Some(wind_adjust) = wind_adjust {
            self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
        }
        self.wake();
        Ok(())
    }

    /// Indicates when channel data is ready.
    ///
    /// When channel data is ready, returns a tuple
    /// `Some((channel, dt, len))`
    /// `len` is the amount of data ready remaining to read, will always be non-zero.
    /// Note that this returns a `ChanNum` index rather than a `ChanHandle` (which would
    /// be owned by the caller already.
    ///
    /// Returns `None` if no data ready.
    pub fn ready_channel_input(&self) -> Option<(ChanNum, ChanData, usize)> {
        self.traf_in.ready_channel_input()
    }

    pub fn is_channel_eof(&self, chan: &ChanHandle) -> bool {
        self.conn.channels.have_recv_eof(chan.0) || self.closed
    }

    pub fn is_channel_closed(&self, chan: &ChanHandle) -> bool {
        self.conn.channels.is_closed(chan.0) || self.closed
    }

    /// Returns the maximum data that may be sent to a channel
    ///
    /// Returns `Ok(None)` on channel closed.
    ///
    /// May fail with `BadChannelData` if dt is invalid for this session.
    pub fn ready_channel_send(&self, chan: &ChanHandle, dt: ChanData) -> Result<Option<usize>> {
        if self.closed {
            return Ok(None)
        }
        // TODO: return 0 if InKex means we can't transmit packets.

        // Avoid apps polling forever on a packet type that won't come
        dt.validate_send(self.conn.is_client())?;

        // minimum of buffer space and channel window available
        let payload_space = self.traf_out.send_allowed(&self.keys);
        // subtract space for packet headers prior to data
        let payload_space = payload_space.saturating_sub(dt.packet_offset());
        Ok(self.conn.channels.send_allowed(chan.0).map(|s| s.min(payload_space)))
    }

    /// Returns `true` if the channel and `dt` are currently valid for writing.
    /// Note that they may not be ready to send output.
    pub fn valid_channel_send(&self, chan: &ChanHandle, dt: ChanData) -> bool {
        self.conn.channels.valid_send(chan.0, dt)
    }

    /// Must be called when an application has finished with a channel.
    ///
    /// Channel numbers will not be re-used without calling this, so
    /// failing to call this may result in running out of channels.
    pub fn channel_done(&mut self, chan: ChanHandle) -> Result<()> {
        self.conn.channels.done(chan.0)
    }

    /// Send a terminal window size change report.
    ///
    /// Only call on a client session with a pty
    pub fn term_window_change(&mut self, chan: &ChanHandle, winch: packets::WinChange) -> Result<()> {
        if self.is_client() {
            let mut s = self.traf_out.sender(&mut self.keys);
            self.conn.channels.term_window_change(chan.0, winch, &mut s)
        } else {
            error::BadChannelData.fail()
        }
    }

    fn wake(&mut self) {
        if self.is_input_ready() {
            trace!("wake ready_input, waker {:?}", self.input_waker);
            if let Some(w) = self.input_waker.take() {
                trace!("wake input waker");
                w.wake()
            }
        }

        if self.is_output_pending() {
            if let Some(w) = self.output_waker.take() {
                trace!("wake output waker");
                w.wake()
            } else {
                trace!("no waker");
            }
        }
    }
}

/// Represents an open channel, owned by the application.
///
/// Must be released by calling [`Runner::channel_done()`]
pub struct ChanHandle(pub(crate) ChanNum);

impl ChanHandle {
    /// Returns the channel number
    ///
    /// This can be used by applications as an index.
    /// Channel numbers satisfy
    /// `0 <= num < sunset::config::MAX_CHANNELS`.
    /// An index may be reused after a call to [`Runner::channel_done()`],
    /// applications must take care not to keep using this `num()` index after
    /// that.
    pub fn num(&self) -> ChanNum {
        self.0
    }
}

impl core::fmt::Debug for ChanHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChanHandle({})", self.num())
    }
}

#[cfg(test)]
mod tests {
    // TODO: test send_allowed() limits
}
