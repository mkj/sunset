#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::Waker;

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
    pub fn new(conn: Conn<'a>, iobuf: &'a mut [u8]) -> Result<Self, Error> {
        let mut runner = Runner {
            conn,
            traffic: traffic::Traffic::new(iobuf),
            keys: KeyState::new_cleartext(),
            output_waker: None,
            input_waker: None,
        };

        runner.conn.progress(&mut runner.traffic, &mut runner.keys)?;
        let runner = runner;
        Ok(runner)
    }

    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        let (size, payload) = self.traffic.input(
            &mut self.keys,
            &mut self.conn.remote_version,
            buf,
        )?;
        if let Some(payload) = payload {
            // Lifetimes here are a bit subtle.
            // `payload` has self.traffic lifetime, used until `handle_payload` completes.
            // The `resp` from handle_payload() references self.conn, consumed
            // by the send_packet().
            // After that progress() can perform more send_packet() itself.

            let resp = self.conn.handle_payload(payload, &mut self.keys)?;
            for r in resp {
                self.traffic.send_packet(r, &mut self.keys)?;
            }
            self.conn.progress(&mut self.traffic, &mut self.keys)?;
        }
        // TODO: do we only need to wake once?
        if let Some(w) = self.output_waker.take() {
            if self.output_pending() {
                w.wake()
            }
        }
        Ok(size)
    }

    /// Write any pending output, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let r = self.traffic.output(buf);
        if let Some(w) = self.input_waker.take() {
            if self.ready_input() {
                w.wake()
            }
        }
        Ok(r)
        // TODO: need some kind of progress() here which
        // will return errors
    }

    pub fn ready_input(&self) -> bool {
        self.traffic.ready_input()
    }

    pub fn set_input_waker(&mut self, waker: Waker) {
        self.input_waker = Some(waker);
    }

    pub fn output_pending(&self) -> bool {
        self.traffic.output_pending()
    }

    pub fn set_output_waker(&mut self, waker: Waker) {
        self.output_waker = Some(waker);
    }
}

