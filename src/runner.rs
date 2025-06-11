#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::{
    hash::Hash,
    mem::discriminant,
    task::{Poll, Waker},
};

use pretty_hex::PrettyHex;

use crate::packets::{Packet, Subsystem};
use crate::*;
use channel::{ChanData, ChanNum};
use channel::{CliSessionExit, CliSessionOpener};
use encrypt::KeyState;
use event::{CliEvent, CliEventId, Event, ServEvent, ServEventId};
use packets::{ChannelData, ChannelDataExt};
use traffic::{TrafIn, TrafOut};

use conn::{CliServ, Conn, DispatchEvent, Dispatched};

pub(crate) type ServRunner<'a> = Runner<'a, server::Server>;
pub(crate) type CliRunner<'a> = Runner<'a, client::Client>;

// Runner public methods take a `ChanHandle` which cannot be cloned. This prevents
// confusion if an application were to continue using a channel after the channel
// was completed. The `ChanHandle` is consumed by `Runner::channel_done()`.
// Internally sunset uses `ChanNum`, which is just a newtype around u32.

/// A SSH session instance
///
/// An application provides network or channel data to `Runner` method calls,
/// and provides customisation callbacks via `CliBehaviour` or `ServBehaviour`.
pub struct Runner<'a, CS: conn::CliServ> {
    conn: Conn<CS>,

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

    closed_input: bool,

    resume_event: DispatchEvent,
    // Some incoming packets will produce multiple Events from a single packet.
    // (such as Userauth, where we query application for a pubkey or password).
    // The Event handler can set extra_resume_event which will cause that
    // event to be emitted on the next .progress() call.
    extra_resume_event: DispatchEvent,
}

impl<CS: CliServ> core::fmt::Debug for Runner<'_, CS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Runner")
            .field("keys", &self.keys)
            .field("output_waker", &self.output_waker)
            .field("input_waker", &self.input_waker)
            .finish_non_exhaustive()
    }
}

// #[derive(Default, Debug, Clone)]
// pub struct Progress<'g, 'a> {
//     pub event: Event<'g, 'a>,
// }

impl<'a> Runner<'a, client::Client> {
    /// `inbuf` and `outbuf` must be sized to fit the largest SSH packet allowed.
    pub fn new_client(
        inbuf: &'a mut [u8],
        outbuf: &'a mut [u8],
    ) -> Runner<'a, client::Client> {
        Self::new(inbuf, outbuf)
    }
}

impl<'a> Runner<'a, server::Server> {
    /// `inbuf` and `outbuf` must be sized to fit the largest SSH packet allowed.
    pub fn new_server(
        inbuf: &'a mut [u8],
        outbuf: &'a mut [u8],
    ) -> Runner<'a, server::Server> {
        Self::new(inbuf, outbuf)
    }
}

impl<'a, CS: CliServ> Runner<'a, CS> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8]) -> Runner<'a, CS> {
        Runner {
            conn: Conn::new(),
            traf_in: TrafIn::new(inbuf),
            traf_out: TrafOut::new(outbuf),
            keys: KeyState::new_cleartext(),
            output_waker: None,
            input_waker: None,
            closed_input: false,
            resume_event: DispatchEvent::None,
            extra_resume_event: DispatchEvent::None,
        }
    }

    /// Drives connection progress, handling received payload and queueing
    /// packets to send as required.
    pub fn progress(&mut self) -> Result<Event<'_, 'a>> {
        // Any previous Event must have been dropped to be able to call progress()
        // again, since it borrows from Runner. We can check if it was dropped
        // without a required response, or complete the payload handling otherwise.
        let prev = self.resume_event.take();
        if prev.needs_resume() {
            // Events that need a response would have cleared runner.resume_event in their
            // resume handler.
            debug!("No response provided to {:?} event", prev);
            return error::BadUsage.fail();
        }

        // Another event may be pending from the same payload, emit it.
        let ex = self.extra_resume_event.take();
        if ex.is_some() {
            self.resume_event = ex.clone();
            return CS::dispatch_into_event(self, ex);
        }

        // Previous event payload is complete
        if prev.is_event() {
            self.traf_in.done_payload();
        }

        let mut disp = Dispatched::default();
        let mut s = self.traf_out.sender(&mut self.keys);

        // Handle incoming packets
        if let Some((payload, seq)) = self.traf_in.payload() {
            disp = self.conn.handle_payload(payload, seq, &mut s)?;

            match disp.event {
                DispatchEvent::Data(data_in) => {
                    // incoming channel data, we haven't finished with payload
                    self.traf_in.set_read_channel_data(data_in)?;
                    disp.event = DispatchEvent::None
                }
                DispatchEvent::CliEvent(_) | DispatchEvent::ServEvent(_) => {
                    // will return as an event
                }
                DispatchEvent::None => {
                    // packets have been completed
                    self.traf_in.done_payload()
                }
                // TODO, may get used later?
                DispatchEvent::Progressed => return Err(Error::bug()),
            }
        } else if self.closed_input {
            // all incoming packets have been consumed, and we're closed for input,
            if CS::is_client() {
                return Ok(Event::Cli(CliEvent::Defunct));
            } else {
                return Ok(Event::Serv(ServEvent::Defunct));
            }
        }

        // If there isn't any pending event for the application, run conn.progress()
        // (which may return other events).
        if disp.event.is_none() {
            disp = self.conn.progress(&mut s)?;
            trace!("prog disp {disp:?}");
            match disp.event {
                DispatchEvent::CliEvent(_)
                | DispatchEvent::ServEvent(_)
                | DispatchEvent::None
                | DispatchEvent::Progressed => (),
                // Don't expect data from conn.progress()
                DispatchEvent::Data(_) => return Err(Error::bug()),
            }
        }

        self.wake();

        // Record the event for later checks
        self.resume_event = disp.event.clone();

        // Create an Event that borrows from Runner
        CS::dispatch_into_event(self, disp.event)
    }

    pub(crate) fn packet(&self) -> Result<Option<packets::Packet>> {
        if let Some((payload, _seq)) = self.traf_in.payload() {
            self.conn.packet(payload).map(|p| Some(p))
        } else {
            Ok(None)
        }
    }

    // Accept bytes from the wire, returning the size consumed
    pub fn input(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if self.closed_input {
            return error::SessionEOF.fail();
        }
        if !self.is_input_ready() {
            return Ok(0);
        }
        self.traf_in.input(&mut self.keys, &mut self.conn.remote_version, buf)
    }

    // Whether [`input()`](input) is ready
    pub fn is_input_ready(&self) -> bool {
        (self.conn.initial_sent() && self.traf_in.is_input_ready())
            || self.closed_input
    }

    /// Set a waker to be notified when [`input()`](Self::input) is ready to be called.
    pub fn set_input_waker(&mut self, waker: &Waker) {
        if let Some(ref w) = self.input_waker {
            if w.will_wake(waker) {
                return;
            }
        }
        if let Some(w) = self.input_waker.replace(waker.clone()) {
            w.wake()
        }
    }

    /// Indicate that the input SSH tcp socket has closed
    pub fn close_input(&mut self) {
        trace!("close_input");
        self.closed_input = true;
    }

    /// Write any pending output to the wire, returning the size written
    pub fn output(&mut self, buf: &mut [u8]) -> usize {
        let r = self.traf_out.output(buf);
        if !self.traf_out.is_output_pending() {
            // State has changed
            self.wake();
        }
        r
    }

    /// Returns a buffer of output to send over the wire.
    ///
    /// Call [`consume_output()`](Self::consume_output) to indicate how many bytes were used.
    ///
    /// This is similar to `std::io::BufRead::fill_buf(), but an empty
    /// slice returned does not indicate EOF.
    pub fn output_buf(&mut self) -> &[u8] {
        self.traf_out.output_buf()
    }

    /// Indicate how many bytes were taken from `output_buf()`
    pub fn consume_output(&mut self, l: usize) {
        self.traf_out.consume_output(l);
        if !self.traf_out.is_output_pending() {
            // State has changed
            self.wake();
        }
    }

    // Whether [`output()`](output) is ready
    pub fn is_output_pending(&self) -> bool {
        self.traf_out.is_output_pending()
    }

    /// Set a waker to be notified when [`output()`](Self::output) will have pending data
    pub fn set_output_waker(&mut self, waker: &Waker) {
        if let Some(ref w) = self.output_waker {
            if w.will_wake(waker) {
                return;
            }
        }
        if let Some(w) = self.output_waker.replace(waker.clone()) {
            w.wake()
        }
    }

    /// Indicate that the output SSH tcp socket has closed
    pub fn close_output(&mut self) {
        trace!("close_input");
        self.traf_out.close();
        self.wake();
    }

    // TODO: move somewhere client specific?
    pub fn open_client_session(&mut self) -> Result<ChanHandle> {
        trace!("open_client_session");

        let (chan, p) =
            self.conn.channels.open(packets::ChannelOpenType::Session)?;
        self.traf_out.send_packet(p, &mut self.keys)?;
        self.wake();
        Ok(ChanHandle(chan))
    }

    /// Send data from this application out the wire.
    ///
    /// Returns `Ok(len)` consumed, `Err(Error::ChannelEof)` on EOF,
    /// or other errors.
    pub fn write_channel(
        &mut self,
        chan: &ChanHandle,
        dt: ChanData,
        buf: &[u8],
    ) -> Result<usize> {
        if self.traf_out.closed() {
            // TODO: unsure if we need this
            return error::ChannelEOF.fail();
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let len = self.write_channel_ready(chan, dt)?;
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
    ///
    /// Returns `Ok(len)` received, `Err(Error::ChannelEof)` on EOF,
    /// or other errors. Ok(0) indicates no data available, ie pending.
    /// TODO: EOF is unimplemented
    pub fn read_channel(
        &mut self,
        chan: &ChanHandle,
        dt: ChanData,
        buf: &mut [u8],
    ) -> Result<usize> {
        if self.closed_input {
            return error::ChannelEOF.fail();
        }

        dt.validate_receive(CS::is_client())?;

        if self.is_channel_eof(chan) {
            return error::ChannelEOF.fail();
        }

        let (len, complete) = self.traf_in.read_channel(chan.0, dt, buf);
        if let Some(x) = complete {
            self.finished_read_channel(chan, x)?;
        }
        Ok(len)
    }

    /// Receives input data, either normal or extended.
    pub fn read_channel_either(
        &mut self,
        chan: &ChanHandle,
        buf: &mut [u8],
    ) -> Result<(usize, ChanData)> {
        let (len, complete, dt) = self.traf_in.read_channel_either(chan.0, buf);
        if let Some(x) = complete {
            self.finished_read_channel(chan, x)?;
        }
        Ok((len, dt))
    }

    /// Discards any channel input data pending for `chan`, regardless of whether
    /// normal or extended.
    pub fn discard_read_channel(&mut self, chan: &ChanHandle) -> Result<()> {
        let x = self.traf_in.discard_read_channel(chan.0);
        self.finished_read_channel(chan, x)?;
        Ok(())
    }

    fn finished_read_channel(
        &mut self,
        chan: &ChanHandle,
        len: usize,
    ) -> Result<()> {
        let mut s = self.traf_out.sender(&mut self.keys);
        self.conn.channels.finished_read(chan.0, len, &mut s)?;
        self.wake();
        Ok(())
    }

    /// Indicates when channel data is ready.
    ///
    /// When channel data is ready, returns a tuple
    /// `Some((channel, data, len))`
    /// `len` is the amount of data ready remaining to read, will always be non-zero.
    /// Note that this returns a `ChanNum` index rather than a `ChanHandle` (which would
    /// be owned by the caller already.
    ///
    /// Returns `None` if no data ready.
    pub fn read_channel_ready(&self) -> Option<(ChanNum, ChanData, usize)> {
        self.traf_in.read_channel_ready()
    }

    pub fn is_channel_eof(&self, chan: &ChanHandle) -> bool {
        self.conn.channels.have_recv_eof(chan.0) || self.closed_input
    }

    pub fn is_channel_closed(&self, chan: &ChanHandle) -> bool {
        self.conn.channels.is_closed(chan.0) || self.closed_input
    }

    /// Returns the maximum data that may be sent to a channel
    ///
    /// Returns `Ok(None)` on channel closed.
    ///
    /// May fail with `BadChannelData` if dt is invalid for this session.
    pub fn write_channel_ready(
        &self,
        chan: &ChanHandle,
        dt: ChanData,
    ) -> Result<Option<usize>> {
        if self.traf_out.closed() {
            return Ok(None);
        }
        // TODO: return 0 if InKex means we can't transmit packets.

        // Avoid apps polling forever on a packet type that won't come
        dt.validate_send(CS::is_client())?;

        // minimum of buffer space and channel window available
        let payload_space = self.traf_out.send_allowed(&self.keys);
        // subtract space for packet headers prior to data
        let payload_space = payload_space.saturating_sub(dt.packet_offset());
        let r = Ok(self
            .conn
            .channels
            .send_allowed(chan.0)
            .map(|s| s.min(payload_space)));
        trace!("ready_channel_send {chan:?} -> {r:?}");
        r
    }

    /// Returns `true` if the channel and `dt` are currently valid for writing.
    ///
    /// Note that they may not be ready to send output.
    pub fn is_write_channel_valid(&self, chan: &ChanHandle, dt: ChanData) -> bool {
        // TODO is this needed? currently unused
        self.conn.channels.valid_send(chan.0, dt)
    }

    /// Must be called when an application has finished with a channel.
    ///
    /// Channel numbers will not be re-used without calling this, so
    /// failing to call this may result in running out of channels.
    pub fn channel_done(&mut self, chan: ChanHandle) -> Result<()> {
        self.conn.channels.done(chan.0)?;
        self.wake();
        Ok(())
    }

    /// Send a terminal window size change report.
    ///
    /// Only call on a client session with a pty
    pub fn term_window_change(
        &mut self,
        chan: &ChanHandle,
        winch: &packets::WinChange,
    ) -> Result<()> {
        if CS::is_client() {
            let mut s = self.traf_out.sender(&mut self.keys);
            self.conn.channels.term_window_change(chan.0, winch, &mut s)
        } else {
            error::BadChannelData.fail()
        }
    }

    /// Send a break to a session channel
    ///
    /// `length` is in milliseconds, or
    /// pass 0 as a default (to be interpreted by the remote implementation).
    /// Otherwise length will be clamped to the range [500, 3000] ms.
    /// Only call on a client session.
    pub fn term_break(&mut self, chan: &ChanHandle, length: u32) -> Result<()> {
        if CS::is_client() {
            let mut s = self.traf_out.sender(&mut self.keys);
            self.conn.channels.term_break(chan.0, length, &mut s)
        } else {
            error::BadChannelData.fail()
        }
    }

    pub(crate) fn cli_session_opener(
        &mut self,
        ch: ChanNum,
    ) -> Result<CliSessionOpener<'_, 'a>> {
        let ch = self.conn.channels.get(ch)?;
        let s = self.traf_out.sender(&mut self.keys);

        Ok(CliSessionOpener { ch, s })
    }

    pub(crate) fn fetch_cli_session_exit(&mut self) -> Result<CliSessionExit> {
        let (payload, _seq) = self.traf_in.payload().trap()?;
        self.conn.fetch_cli_session_exit(payload)
    }

    pub(crate) fn fetch_cli_banner(&mut self) -> Result<event::Banner> {
        let (payload, _seq) = self.traf_in.payload().trap()?;
        self.conn.fetch_cli_banner(payload)
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

    fn check_resume_inner(&self, expect: &DispatchEvent, compare: &DispatchEvent) {
        match (expect, compare) {
            (DispatchEvent::CliEvent(e), DispatchEvent::CliEvent(c)) => {
                debug_assert_eq!(
                    discriminant(c),
                    discriminant(e),
                    "Expected response to pending {expect:?} event"
                )
            }
            (DispatchEvent::ServEvent(e), DispatchEvent::ServEvent(c)) => {
                debug_assert_eq!(
                    discriminant(c),
                    discriminant(e),
                    "Expected response to pending {expect:?} event"
                )
            }
            _ => debug_assert!(false),
        }
    }

    fn resume(&mut self, expect: &DispatchEvent) {
        let prev_event = self.resume_event.take();
        self.check_resume_inner(expect, &prev_event)
    }

    fn check_resume(&self, expect: &DispatchEvent) {
        self.check_resume_inner(expect, &self.resume_event)
    }

    pub(crate) fn resume_cliusername(&mut self, username: &str) -> Result<()> {
        self.resume(&DispatchEvent::CliEvent(CliEventId::Username));
        let mut s = self.traf_out.sender(&mut self.keys);
        let (cliauth, _) = self.conn.mut_cliauth()?;
        cliauth.resume_username(&mut s, username)?;
        self.traf_in.done_payload();
        Ok(())
    }

    pub(crate) fn resume_clipassword(
        &mut self,
        password: Option<&str>,
    ) -> Result<()> {
        self.resume(&DispatchEvent::CliEvent(CliEventId::Password));
        self.traf_in.done_payload();
        let mut s = self.traf_out.sender(&mut self.keys);
        let (cliauth, ctx) = self.conn.mut_cliauth()?;
        cliauth.resume_password(&mut s, password, ctx)?;
        // assert that resume_password() returns error with none password.
        // otherwise we might need to handle other events like with clipubkey
        debug_assert!(password.is_some(), "no password");
        Ok(())
    }

    pub(crate) fn resume_clipubkey(&mut self, key: Option<SignKey>) -> Result<()> {
        self.resume(&DispatchEvent::CliEvent(CliEventId::Pubkey));
        let mut s = self.traf_out.sender(&mut self.keys);
        let (cliauth, ctx) = self.conn.mut_cliauth()?;
        self.extra_resume_event = cliauth.resume_pubkey(&mut s, key, ctx)?;
        if self.extra_resume_event.is_none() {
            self.traf_in.done_payload();
        }
        Ok(())
    }

    pub(crate) fn fetch_agentsign_key(&self) -> Result<&SignKey> {
        self.check_resume(&DispatchEvent::CliEvent(CliEventId::AgentSign));
        let cliauth = self.conn.cliauth()?;
        cliauth.fetch_agentsign_key()
    }

    pub(crate) fn fetch_agentsign_msg(&self) -> Result<AuthSigMsg> {
        self.check_resume(&DispatchEvent::CliEvent(CliEventId::AgentSign));
        self.conn.fetch_agentsign_msg()
    }

    pub(crate) fn resume_agentsign(&mut self, sig: Option<&OwnedSig>) -> Result<()> {
        self.resume(&DispatchEvent::CliEvent(CliEventId::AgentSign));
        let (cliauth, ctx) = self.conn.mut_cliauth()?;
        let mut s = self.traf_out.sender(&mut self.keys);
        self.extra_resume_event = cliauth.resume_agentsign(sig, ctx, &mut s)?;
        if self.extra_resume_event.is_none() {
            self.traf_in.done_payload();
        }
        Ok(())
    }

    pub(crate) fn resume_checkhostkey(&mut self, accept: bool) -> Result<()> {
        self.resume(&DispatchEvent::CliEvent(CliEventId::Hostkey));

        let (payload, _seq) = self.traf_in.payload().trap()?;
        let mut s = self.traf_out.sender(&mut self.keys);

        self.conn.resume_checkhostkey(payload, &mut s, accept)?;
        self.traf_in.done_payload();
        Ok(())
    }

    pub(crate) fn fetch_checkhostkey(&self) -> Result<PubKey<'_>> {
        self.check_resume(&DispatchEvent::CliEvent(CliEventId::Hostkey));

        let (payload, _seq) = self.traf_in.payload().trap()?;

        self.conn.fetch_checkhostkey(payload)
    }

    pub(crate) fn resume_servhostkeys(&mut self, keys: &[&SignKey]) -> Result<()> {
        self.resume(&DispatchEvent::ServEvent(ServEventId::Hostkeys));
        let (payload, _seq) = self.traf_in.payload().trap()?;
        let mut s = self.traf_out.sender(&mut self.keys);
        self.conn.resume_servhostkeys(payload, &mut s, keys)?;
        self.traf_in.done_payload();
        Ok(())
    }

    pub(crate) fn fetch_servusername(&self) -> Result<TextString> {
        let u = self.conn.server()?.auth.username.as_ref().trap()?;
        Ok(TextString(u.as_slice()))
    }

    pub(crate) fn fetch_servpassword(&self) -> Result<TextString> {
        self.check_resume(&DispatchEvent::ServEvent(ServEventId::PasswordAuth));
        let (payload, _seq) = self.traf_in.payload().trap()?;
        self.conn.fetch_servpassword(payload)
    }

    pub(crate) fn fetch_servpubkey(&self) -> Result<PubKey> {
        self.check_resume(&DispatchEvent::ServEvent(ServEventId::PubkeyAuth {
            real_sig: false,
        }));
        let (payload, _seq) = self.traf_in.payload().trap()?;
        self.conn.fetch_servpubkey(payload)
    }

    pub(crate) fn resume_servauth(&mut self, allow: bool) -> Result<()> {
        let prev_event = self.resume_event.take();
        // auth packets have passwords
        self.traf_in.zeroize_payload();
        debug_assert!(
            matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::PasswordAuth)
            ) || matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::PubkeyAuth { .. })
            ) || matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::FirstAuth)
            )
        );

        let mut s = self.traf_out.sender(&mut self.keys);
        self.conn.resume_servauth(allow, &mut s)
    }

    pub(crate) fn resume_servauth_pkok(&mut self) -> Result<()> {
        self.resume(&DispatchEvent::ServEvent(ServEventId::PubkeyAuth {
            real_sig: false,
        }));

        let (payload, _seq) = self.traf_in.payload().trap()?;
        let mut s = self.traf_out.sender(&mut self.keys);
        let r = self.conn.resume_servauth_pkok(payload, &mut s);
        self.traf_in.done_payload();
        r
    }

    pub(crate) fn resume_chanopen(
        &mut self,
        num: ChanNum,
        failure: Option<ChanFail>,
    ) -> Result<()> {
        self.resume(&DispatchEvent::ServEvent(ServEventId::OpenSession { num }));
        self.traf_in.done_payload();
        let mut s = self.traf_out.sender(&mut self.keys);
        self.conn.channels.resume_open(num, failure, &mut s)
    }

    fn check_chanreq(prev_event: &DispatchEvent) {
        debug_assert!(
            matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::SessionShell { .. })
            ) || matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::SessionExec { .. })
            ) || matches!(
                prev_event,
                DispatchEvent::ServEvent(ServEventId::SessionPty { .. })
            )
        );
    }

    pub(crate) fn resume_chanreq(&mut self, success: bool) -> Result<()> {
        let prev_event = self.resume_event.take();
        trace!("resume chanreq {prev_event:?} {success}");
        Self::check_chanreq(&prev_event);

        let mut s = self.traf_out.sender(&mut self.keys);
        let (payload, _seq) = self.traf_in.payload().trap()?;
        let p = self.conn.packet(payload)?;
        let r = self.conn.channels.resume_chanreq(&p, success, &mut s);
        self.traf_in.done_payload();
        r
    }

    pub(crate) fn fetch_servcommand(&self) -> Result<TextString> {
        Self::check_chanreq(&self.resume_event);
        let (payload, _seq) = self.traf_in.payload().trap()?;
        let p = self.conn.packet(payload)?;
        self.conn.channels.fetch_servcommand(&p)
    }
}

/// Represents an open channel, owned by the application.
///
/// Must be released by calling [`Runner::channel_done()`]

// Inner contents are crate-private to ensure that arbitrary
// channel numbers cannot be used after closing/reuse.
//
// This must not be `Clone`
#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ChanHandle(pub(crate) ChanNum);

impl ChanHandle {
    /// Returns the channel number
    ///
    /// This can be used by applications as an index.
    /// Channel numbers satisfy
    /// `0 <= num < sunset::config::MAX_CHANNELS`.
    ///
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
