#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};

use pretty_hex::PrettyHex;

use crate::{*, channel::ChanEvent};
use encrypt::KeyState;
use traffic::{TrafIn, TrafOut, TrafSend};

use conn::{Conn, Dispatched, EventMaker, Event};
use channel::ChanEventMaker;

pub struct Runner<'a> {
    conn: Conn<'a>,

    /// Binary packet handling from the network buffer
    traf_in: TrafIn<'a>,
    /// Binary packet handling to the network buffer
    traf_out: TrafOut<'a>,

    /// Current encryption/integrity keys
    keys: KeyState,

    output_waker: Option<Waker>,
    input_waker: Option<Waker>,
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


    /// Drives connection progress, handling received payload and sending
    /// other packets as required. This must be polled/awaited regularly.
    /// Optionally returns `Event` which provides channel or session
    /// event to the application.
    /// [`done_payload()`] must be called after any `Ok` result.
    pub async fn progress<'f>(&'f mut self, behaviour: &mut Behaviour<'_>) -> Result<Option<Event<'f>>, Error> {
        let mut s = self.traf_out.sender(&mut self.keys);
        let em = if let Some((payload, seq)) = self.traf_in.payload() {
            // Lifetimes here are a bit subtle.
            // `payload` has self.traffic lifetime, used until `handle_payload`
            // completes.
            // The `resp` from handle_payload() references self.conn, consumed
            // by the send_packet().
            // After that progress() can perform more send_packet() itself.

            let d = self.conn.handle_payload(payload, seq, &mut s, behaviour).await?;
            self.traf_in.handled_payload()?;

            if d.event.is_none() {
                // switch to using the buffer for output.
                self.traf_in.done_payload()?;
            }

            d.event
        } else {
            None
        };

        // We split return values into Event/EventMaker to work around
        // the payload borrow range extending too long.
        // Polonius would solve this. We can't use polonius-the-crab
        // because we're calling async functions.
        // "Borrow checker extends borrow range in code with early return"
        // https://github.com/rust-lang/rust/issues/54663
        let ev = if let Some(em) = em {
            trace!("em");
            match em {
                EventMaker::Channel(ChanEventMaker::DataIn(di)) => {
                    trace!("chanmaaker {di:?}");
                    self.traf_in.done_payload()?;
                    self.traf_in.set_channel_input(di)?;
                    // TODO: channel wakers
                    None
                }
                _ => {
                    // Some(payload) is only required for some variants in make_event()
                    panic!("delete this codepath")
                }
            }
        } else {
            trace!("no em, conn progress");
            self.conn.progress(&mut s, behaviour).await?;
            self.wake();
            None
        };
        trace!("prog event {ev:?}");

        Ok(ev)
    }

    pub fn done_payload(&mut self) -> Result<()> {
        self.traf_in.done_payload()?;
        self.wake();
        Ok(())
    }

    pub fn wake(&mut self) {
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
        let chan = ch.number();
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(chan)
    }

    /// Send data from this application out the wire.
    /// Returns `Some` the length of `buf` consumed, or `None` on EOF
    pub fn channel_send(
        &mut self,
        chan: u32,
        ext: Option<u32>,
        buf: &[u8],
    ) -> Result<Option<usize>> {
        let len = self.ready_channel_send(chan);
        let len = match len {
            Some(l) if l == 0 => return Ok(Some(0)),
            Some(l) => l,
            None => return Ok(None),
        };

        let len = len.min(buf.len());

        let p = self.conn.channels.send_data(chan, ext, &buf[..len])?;
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(Some(len))
    }

    /// Receive data coming from the wire into this application
    pub fn channel_input(
        &mut self,
        chan: u32,
        ext: Option<u32>,
        buf: &mut [u8],
    ) -> Result<usize> {
        trace!("runner chan in");
        let (len, complete) = self.traf_in.channel_input(chan, ext, buf);
        if complete {
            let p = self.conn.channels.finished_input(chan)?;
            if let Some(p) = p {
                self.traf_out.send_packet(p, &mut self.keys)?;
            }
            self.wake();
        }
        Ok(len)
    }

    pub fn ready_input(&self) -> bool {
        self.conn.initial_sent() && self.traf_in.ready_input()
    }

    pub fn output_pending(&self) -> bool {
        self.traf_out.output_pending()
    }

    pub fn set_input_waker(&mut self, waker: Waker) {
        self.input_waker = Some(waker);
    }

    pub fn set_output_waker(&mut self, waker: Waker) {
        self.output_waker = Some(waker);
    }

    pub fn ready_channel_input(&self) -> Option<(u32, Option<u32>)> {
        self.traf_in.ready_channel_input()
    }

    pub fn channel_eof(&self, chan: u32) -> bool {
        self.conn.channels.have_recv_eof(chan)
    }

    // Returns None on channel closed
    pub fn ready_channel_send(&self, chan: u32) -> Option<usize> {
        // minimum of buffer space and channel window available
        let buf_space = self.traf_out.send_allowed(&self.keys);
        self.conn.channels.send_allowed(chan).map(|s| s.min(buf_space))
    }

    pub fn term_window_change(&self, chan: u32, wc: packets::WinChange) -> Result<()> {
        todo!();
        // self.conn.channels.term_window_change(chan, wc)
    }

    // pub fn chan_pending(&self) -> bool {
    //     self.conn.chan_pending()
    // }

    // pub fn set_chan_waker(&mut self, waker: Waker) {
    //     self.chan_waker = Some(waker);
    // }
}
