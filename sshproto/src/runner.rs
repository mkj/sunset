#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};

use pretty_hex::PrettyHex;

use crate::*;
use encrypt::KeyState;
use traffic::Traffic;

pub struct Runner<'a> {
    conn: Conn<'a>,

    /// Binary packet handling to and from the network buffer
    traffic: Traffic<'a>,

    /// Current encryption/integrity keys
    keys: KeyState,

    output_waker: Option<Waker>,
    input_waker: Option<Waker>,
}

impl<'a> Runner<'a> {
    /// `iobuf` must be sized to fit the largest SSH packet allowed.
    pub async fn new(
        conn: Conn<'a>,
        iobuf: &'a mut [u8],
    ) -> Result<Runner<'a>, Error> {
        let runner = Runner {
            conn,
            traffic: traffic::Traffic::new(iobuf),
            keys: KeyState::new_cleartext(),
            output_waker: None,
            input_waker: None,
        };

        Ok(runner)
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        trace!("in size {} {:?}", buf.len(), buf.hex_dump());
        let size = self.traffic.input(
            &mut self.keys,
            &mut self.conn.remote_version,
            buf,
        )?;
        // payload is dispatched by out_progress() on the output side
        if self.traffic.payload().is_some() {
            trace!("payload some, waker {:?}", self.output_waker);
            if let Some(w) = self.output_waker.take() {
                trace!("woke");
                w.wake()
            }
        }
        Ok(size)
    }

    // Drives connection progress, handling received payload and sending
    // other packets as required
    pub async fn out_progress(&mut self, b: &mut Behaviour<'_>) -> Result<(), Error> {
        trace!("out_progress top");
        if let Some(payload) = self.traffic.payload() {
            trace!("out_progress payload");
            // Lifetimes here are a bit subtle.
            // `payload` has self.traffic lifetime, used until `handle_payload`
            // completes.
            // The `resp` from handle_payload() references self.conn, consumed
            // by the send_packet().
            // After that progress() can perform more send_packet() itself.

            let resp = self.conn.handle_payload(payload, &mut self.keys, b).await?;
            debug!("done_payload");
            self.traffic.done_payload()?;
            for r in resp {
                r.send_packet(&mut self.traffic, &mut self.keys)?;
            }
        }
        self.conn.progress(&mut self.traffic, &mut self.keys, b).await?;

        b.progress(self)?;

        trace!("out_progress done");
        Ok(())
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let r = self.traffic.output(buf);
        if self.ready_input() {
            if let Some(w) = self.input_waker.take() {
                w.wake()
            }
        }
        Ok(r)
        // TODO: need some kind of progress() here which
        // will return errors
    }

    pub fn open_client_session(&mut self, exec: Option<&str>, pty: bool) -> Result<u32> {
        trace!("open_client_session");
        let mut init_req = channel::InitReqs::new();
        if pty {
            todo!("pty needs modes and that");
        }
        if let Some(cmd) = exec {
            let mut s = channel::ExecString::new();
            s.push_str(cmd).trap()?;
            init_req.push(channel::ReqDetails::Exec(s)).trap()?;
        } else {
            init_req.push(channel::ReqDetails::Shell).trap()?;
        }
        let (ch, p) = self.conn.channels.open(packets::ChannelOpenType::Session, init_req)?;
        self.traffic.send_packet(p, &mut self.keys)?;
        Ok(ch.number())
    }

    pub fn channel_input(
        &mut self,
        chan: u32,
        msg: channel::ChanMsg,
    ) -> Result<usize> {
        todo!()
    }

    pub fn channel_output(
        &mut self,
        chan: u32,
        buf: &mut [u8],
    ) -> Result<Poll<channel::ChanOut>> {
        todo!()
    }

    pub fn ready_input(&self) -> bool {
        self.conn.initial_sent() && self.traffic.ready_input()
    }

    pub fn set_input_waker(&mut self, waker: Waker) {
        self.input_waker = Some(waker);
    }

    pub fn output_pending(&self) -> bool {
        !self.conn.initial_sent() || self.traffic.output_pending()
    }

    pub fn set_output_waker(&mut self, waker: Waker) {
        self.output_waker = Some(waker);
    }

    // pub fn chan_pending(&self) -> bool {
    //     self.conn.chan_pending()
    // }

    // pub fn set_chan_waker(&mut self, waker: Waker) {
    //     self.chan_waker = Some(waker);
    // }
}
