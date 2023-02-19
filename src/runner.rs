#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};

use pretty_hex::PrettyHex;

use crate::*;
use packets::{ChannelDataExt, ChannelData};
use encrypt::KeyState;
use traffic::{TrafIn, TrafOut, TrafSend};

use conn::{Conn, Dispatched};

pub struct Runner<'a> {
    conn: Conn,

    /// Binary packet handling from the network buffer
    traf_in: TrafIn<'a>,
    /// Binary packet handling to the network buffer
    traf_out: TrafOut<'a>,

    /// Current encryption/integrity keys
    keys: KeyState,

    /// Waker when output is ready
    pub output_waker: Option<Waker>,
    /// Waker when ready to consume input.
    pub input_waker: Option<Waker>,
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
    pub async fn progress(&mut self, behaviour: &mut Behaviour<'_>) -> Result<()> {
        let mut s = self.traf_out.sender(&mut self.keys);
        // Handle incoming packets
        if let Some((payload, seq)) = self.traf_in.payload() {
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

        Ok(())
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
        let r = self.traf_out.output(buf);
        if r > 0 {
            trace!("output() wake");
            self.wake();
        }
        Ok(r)
    }

    pub fn ready_input(&self) -> bool {
        self.conn.initial_sent() && self.traf_in.ready_input()
    }

    pub fn output_pending(&self) -> bool {
        self.traf_out.output_pending()
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

    // TODO: move somewhere client specific?
    pub fn open_client_session(&mut self, exec: Option<&str>, pty: Option<channel::Pty>) -> Result<u32> {
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
        let (ch, p) = self.conn.channels.open(packets::ChannelOpenType::Session, init_req)?;
        let chan = ch.num();
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(chan)
    }

    // pub fn channel_type(&self, chan: u32) -> Result<channel::ChanType> {
    //     self.conn.channels.get(chan).map(|c| c.ty)
    // }

    /// Send data from this application out the wire.
    /// Returns `Ok(len)` consumed, `Err(Error::ChannelEof)` on EOF,
    /// or other errors.
    pub fn channel_send(
        &mut self,
        chan: u32,
        ext: Option<u32>,
        buf: &[u8],
    ) -> Result<usize> {
        if buf.len() == 0 {
            return Ok(0)
        }

        if let Some(e) = ext {
            if self.conn.is_client() || e != sshnames::SSH_EXTENDED_DATA_STDERR {
                // not currently supported
                return error::BadChannelExt.fail()
            }
        }

        let len = self.ready_channel_send(chan, ext.is_some());
        let len = match len {
            Some(l) if l == 0 => return Ok(0),
            Some(l) => l,
            None => return Err(Error::ChannelEOF),
        };

        let len = len.min(buf.len());

        let p = self.conn.channels.send_data(chan, ext, &buf[..len])?;
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
        chan: u32,
        ext: Option<u32>,
        buf: &mut [u8],
    ) -> Result<usize> {

        if let Some(e) = ext {
            if !self.conn.is_client() || e != sshnames::SSH_EXTENDED_DATA_STDERR {
                // not currently supported
                return error::BadChannelExt.fail()
            }
        }

        trace!("runner chan in");
        let (len, complete) = self.traf_in.channel_input(chan, ext, buf);
        trace!("runner chan in, len {len} complete {complete}");
        if complete {
            let wind_adjust = self.conn.channels.finished_input(chan)?;
            if let Some(wind_adjust) = wind_adjust {
                self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
            }
            self.wake();
        }
        Ok(len)
    }

    /// Receives input data, either ext or normal.
    pub fn channel_input_either(
        &mut self,
        chan: u32,
        buf: &mut [u8],
    ) -> Result<(usize, Option<u32>)> {
        trace!("runner chan in");
        let (len, complete, ext) = self.traf_in.channel_input_either(chan, buf);
        trace!("runner chan in, len {len} complete {complete} ext {ext:?}");
        if complete {
            let wind_adjust = self.conn.channels.finished_input(chan)?;
            if let Some(wind_adjust) = wind_adjust {
                self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
            }
            self.wake();
        }
        Ok((len, ext))
    }


    /// Discards any channel input data pending for `chan`, regardless of whether
    /// normal or `ext`.
    pub fn discard_channel_input(&mut self, chan: u32) -> Result<()> {
        self.traf_in.discard_channel_input(chan);
        let wind_adjust = self.conn.channels.finished_input(chan)?;
        if let Some(wind_adjust) = wind_adjust {
            self.traf_out.send_packet(wind_adjust, &mut self.keys)?;
        }
        self.wake();
        Ok(())
    }

    /// When channel data is ready, returns a tuple
    /// `Some((channel, ext, len))` where `ext` is `None` for stdout
    /// or `Some(sshnames::SSH_EXTENDED_DATA_STDERR)` for stderr.
    /// `len` is the amount of data ready remaining to read, will always be non-zero.
    /// Returns `None` if no data ready.
    pub fn ready_channel_input(&self) -> Option<(u32, Option<u32>, usize)> {
        self.traf_in.ready_channel_input()
    }

    pub fn channel_eof(&self, chan: u32) -> bool {
        self.conn.channels.have_recv_eof(chan)
    }

    // Returns the maximum data that may be sent to a channel, or
    // `None` on channel closed
    pub fn ready_channel_send(&self, chan: u32, is_ext: bool) -> Option<usize> {
        // TODO: return 0 if InKex means we can't transmit packets.

        // minimum of buffer space and channel window available
        let payload_space = self.traf_out.send_allowed(&self.keys);
        let offset = if is_ext {
            ChannelDataExt::DATA_OFFSET
        } else {
            ChannelData::DATA_OFFSET
        };
        let payload_space = payload_space.saturating_sub(offset);
        self.conn.channels.send_allowed(chan).map(|s| s.min(payload_space))
    }

    /// Returns `true` if the channel and `ext` are currently valid for writing.
    /// Note that they may not be ready to send output.
    pub fn valid_channel_send(&self, chan: u32, ext: Option<u32>) -> bool {
        self.conn.channels.valid_send(chan, ext)
    }

    /// Must be called when an application has finished with a channel.
    ///
    /// Channel numbers will not be re-used without calling this, so
    /// failing to call this can result in running out of channels.
    ///
    /// Any further calls using the same channel number may result
    /// in data from a different channel re-using the same number.
    pub fn channel_done(&mut self, chan: u32) -> Result<()> {
        self.conn.channels.done(chan)
    }

    pub fn term_window_change(&self, _chan: u32, _wc: packets::WinChange) -> Result<()> {
        todo!("term_window_change()");
        // Needs to check that it is a channel with pty.
        // self.conn.channels.term_window_change(chan, wc)
    }

    // pub fn chan_pending(&self) -> bool {
    //     self.conn.chan_pending()
    // }

    // pub fn set_chan_waker(&mut self, waker: Waker) {
    //     self.chan_waker = Some(waker);
    // }

    fn wake(&mut self) {
        if self.ready_input() {
            trace!("wake ready_input, waker {:?}", self.input_waker);
            if let Some(w) = self.input_waker.take() {
                trace!("wake input waker");
                w.wake()
            }
        }

        if self.output_pending() {
            if let Some(w) = self.output_waker.take() {
                trace!("wake output waker");
                w.wake()
            } else {
                trace!("no waker");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // TODO: test send_allowed() limits
}
