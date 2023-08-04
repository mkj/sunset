#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::{mem, marker::PhantomData};

use heapless::{Deque, String, Vec};

use crate::*;
use config::*;
use conn::Dispatched;
use packets::{
    ChannelData, ChannelDataExt, ChannelOpen, ChannelOpenFailure, ChannelOpenType,
    ChannelReqType, ChannelRequest, Packet,
};
use sshnames::*;
use sshwire::{BinString, TextString, SSHEncodeEnum};
use traffic::TrafSend;
use runner::ChanHandle;

use snafu::ErrorCompat;

pub(crate) struct Channels<C: CliBehaviour, S: ServBehaviour> {
    ch: [Option<Channel>; config::MAX_CHANNELS],
    _ph: (PhantomData<C>, PhantomData<S>),
}

impl<C: CliBehaviour, S: ServBehaviour> Channels<C, S> {
    pub fn new() -> Self {
        Channels {
            ch: Default::default(),
            _ph: Default::default()
        }
    }

    pub fn open<'b>(
        &mut self,
        ty: packets::ChannelOpenType<'b>,
    ) -> Result<(ChanNum, Packet<'b>)> {
        let num = self.unused_chan()?;

        let chan = Channel::new(num, (&ty).into());
        let p = packets::ChannelOpen {
            num: num.0,
            initial_window: chan.recv.window as u32,
            max_packet: chan.recv.max_packet as u32,
            ty,
        }
        .into();
        let ch = &mut self.ch[num.0 as usize];
        let ch = ch.insert(chan);
        Ok((ch.num(), p))
    }

    /// Returns a `Channel` for a local number, any state including `InOpen`.
    fn get_any(&self, num: ChanNum) -> Result<&Channel> {
        self.ch
            .get(num.0 as usize)
            // out of range
            .ok_or(error::BadChannel { num }.build())?
            .as_ref()
            // unused channel
            .ok_or(error::BadChannel { num }.build())
    }

    /// Returns a `Channel` for a local number. Excludes `InOpen` or `Opening` state.
    fn get(&self, num: ChanNum) -> Result<&Channel> {
        let ch = self.get_any(num)?;

        match ch.state {
            | ChanState::InOpen
            | ChanState::Opening { .. }
            => error::BadChannel { num }.fail(),
            _ => Ok(ch)
        }
    }

    fn get_any_mut(&mut self, num: ChanNum) -> Result<&mut Channel> {
        self.ch
            .get_mut(num.0 as usize)
            // out of range
            .ok_or(error::BadChannel { num }.build())?
            .as_mut()
            // unused channel
            .ok_or(error::BadChannel { num }.build())
    }

    fn get_mut(&mut self, num: ChanNum) -> Result<&mut Channel> {
        let ch = self.get_any_mut(num)?;

        match ch.state {
            | ChanState::InOpen
            | ChanState::Opening { .. }
            => error::BadChannel { num }.fail(),
            _ => Ok(ch)
        }
    }

    /// Must be called when an application has finished with a channel.
    pub fn done(&mut self, num: ChanNum) -> Result<()> {
        let ch = self.get_mut(num)?;
        debug_assert!(!ch.app_done);
        ch.app_done = true;
        Ok(())
    }

    fn remove_any(&mut self, num: ChanNum) -> Result<()> {
        trace!("remove_any channel {}", num);
        self.ch[num.0 as usize] = None;
        Ok(())
    }

    fn remove(&mut self, num: ChanNum) -> Result<()> {
        // TODO any checks?
        let ch = self.get_any_mut(num)?;
        if ch.app_done {
            trace!("removing channel {}", num);
            self.ch[num.0 as usize] = None;
        } else {
            ch.state = ChanState::PendingDone;
            trace!("not removing channel {}, not finished", num);
        }
        Ok(())
    }

    /// Returns the first available channel
    fn unused_chan(&self) -> Result<ChanNum> {
        self.ch
            .iter()
            .enumerate()
            .find_map(
                |(i, ch)| if ch.as_ref().is_none() { Some(ChanNum(i as u32)) } else { None },
            )
            .ok_or(Error::NoChannels)
    }

    /// Creates a new channel in InOpen state.
    fn reserve_chan(&mut self, co: &ChannelOpen<'_>) -> Result<&mut Channel> {
        let num = self.unused_chan()?;
        let mut chan = Channel::new(num, (&co.ty).into());
        chan.send = Some(ChanDir {
            num: co.num,
            max_packet: co.max_packet as usize,
            window: co.initial_window as usize,
        });
        chan.state = ChanState::InOpen;

        let ch = &mut self.ch[num.0 as usize];
        *ch = Some(chan);
        Ok(ch.as_mut().unwrap())
    }

    /// Returns the channel data packet to send.
    ///
    /// Caller has already checked valid length with send_allowed(), and
    /// validated `dt`.
    /// Don't call with zero length data.
    pub(crate) fn send_data<'b>(
        &mut self,
        num: ChanNum,
        dt: ChanData,
        data: &'b [u8],
    ) -> Result<Packet<'b>> {
        debug_assert!(!data.is_empty());

        let ch = self.get_mut(num)?;
        let send = ch.send.as_mut().trap()?;
        if data.len() > send.max_packet || data.len() > send.window {
            trace!("data len {}, max {}, window {}",
                data.len(), send.max_packet, send.window);
            return Err(Error::bug());
        }
        send.window -= data.len();
        trace!("send_data: new window {}", send.window);

        let data = BinString(data);
        let p = match dt {
            ChanData::Normal => packets::ChannelData { num: send.num, data }.into(),
            ChanData::Stderr => packets::ChannelDataExt {
                num: send.num, code: sshnames::SSH_EXTENDED_DATA_STDERR, data }.into(),
        };

        Ok(p)
    }

    /// Informs the channel layer that an incoming packet has been read out,
    /// so a window adjustment can be queued.
    pub(crate) fn finished_input(&mut self, num: ChanNum, len: usize) -> Result<Option<Packet>> {
        let ch = self.get_mut(num)?;
        ch.finished_input(len);
        ch.check_window_adjust()
    }

    pub(crate) fn have_recv_eof(&self, num: ChanNum) -> bool {
        self.get(num).map_or(false, |c| c.have_recv_eof())
    }

    pub(crate) fn is_closed(&self, num: ChanNum) -> bool {
        self.get(num).map_or(false, |c| c.is_closed())
    }


    pub(crate) fn send_allowed(&self, num: ChanNum) -> Option<usize> {
        self.get(num).map_or(Some(0), |c| c.send_allowed())
    }

    pub(crate) fn valid_send(&self, num: ChanNum, dt: ChanData) -> bool {
        self.get(num).map_or(false, |c| c.valid_send(dt))
    }

    pub(crate) fn term_window_change(&self, num: ChanNum, winch: packets::WinChange,
        s: &mut TrafSend) -> Result<()> {
        let ch = self.get(num)?;
        match ch.ty {
            ChanType::Session => Req::WinChange(winch).send(ch, s),
            _ => error::BadChannelData.fail(),
        }
    }

    fn dispatch_open(
        &mut self,
        p: &ChannelOpen<'_>,
        s: &mut TrafSend,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<()> {
        match self.dispatch_open_inner(p, s, b) {
            Err(DispatchOpenError::Failure(f)) => {
                s.send(packets::ChannelOpenFailure {
                    num: p.num, // ChannelOpen.num is the sender's number
                    reason: f as u32,
                    desc: "".into(),
                    lang: "",
                })?;
                Ok(())
            }
            Err(DispatchOpenError::Error(e)) => Err(e),
            Ok(()) => Ok(()),
        }
    }

    // the caller will send failure messages if required
    fn dispatch_open_inner(
        &mut self,
        p: &ChannelOpen<'_>,
        s: &mut TrafSend,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<(), DispatchOpenError> {
        if b.is_client() && matches!(p.ty, ChannelOpenType::Session) {
            // only server should receive session opens
            trace!("dispatch not server");
            return Err(Error::SSHProtoError.into());
        }

        // get a channel
        let ch = match &p.ty {
            ChannelOpenType::Unknown(u) => {
                debug!("Rejecting unknown channel type '{u}'");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            _ => self.reserve_chan(p)?,
        };

        let handle = ChanHandle(ch.num());

        // beware that a reserved channel must be cleaned up on failure

        // run the Behaviour function
        let r = match &p.ty {
            ChannelOpenType::Session => {
                // OK unwrap: earlier test ensures b.server() succeeds
                let bserv = b.server().unwrap();
                bserv.open_session(handle)
            }
            ChannelOpenType::ForwardedTcpip(t) => b.open_tcp_forwarded(handle, t),
            ChannelOpenType::DirectTcpip(t) => b.open_tcp_direct(handle, t),
            ChannelOpenType::Unknown(_) => {
                unreachable!()
            }
        };

        match r {
            ChanOpened::Success => {
                trace!("chanop success");
                s.send(ch.open_done()?)?;
            }
            ChanOpened::Failure((failure, rhandle)) => {
                trace!("chanop fail {:?} rh {:?}", failure, rhandle);
                let n = ch.num();
                if n != rhandle.num() {
                    trace!("application returned a different ChanHandle!");
                    return Err(error::BadUsage.build().into())
                }
                self.remove_any(n)?;
                return Err(failure.into());
            }
            ChanOpened::Defer => {
                // application will reply later
            }
        }

        Ok(())
    }

    // Some returned errors will be caught by caller and returned as SSH messages
    async fn dispatch_inner(
        &mut self,
        packet: Packet<'_>,
        is_client: bool,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<Option<DataIn>> {
        let mut data_in = None;
        match packet {
            Packet::ChannelOpen(p) => {
                self.dispatch_open(&p, s, b)?;
            }

            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_any_mut(ChanNum(p.num))?;
                match ch.state {
                    ChanState::Opening => {
                        debug_assert!(ch.send.is_none());
                        ch.send = Some(ChanDir {
                            num: p.sender_num,
                            max_packet: p.max_packet as usize,
                            window: p.initial_window as usize,
                        });

                        if matches!(ch.ty, ChanType::Session) {
                            // let the CliBehaviour open a shell etc
                            let mut opener = SessionOpener::new(ch, s);
                            let r = b.client()?.session_opened(ch.num(), &mut opener).await;
                            if r.is_err() {
                                trace!("Error from session_opened");
                            }
                        }

                        ch.state = ChanState::Normal;
                    }
                    _ => {
                        trace!("Bad channel state");
                        return Err(Error::SSHProtoError)
                    }
                }
            }

            Packet::ChannelOpenFailure(p) => {
                let ch = self.get_any(ChanNum(p.num))?;
                if ch.send.is_some() {
                    // TODO: or just warn?
                    trace!("open failure late?");
                    return Err(Error::SSHProtoError);
                } else {
                    self.remove(ChanNum(p.num))?;
                    // TODO event
                }
            }
            Packet::ChannelWindowAdjust(p) => {
                let send = self.get_mut(ChanNum(p.num))?.send.as_mut().trap()?;
                send.window = send.window.saturating_add(p.adjust as usize);
                trace!("new window {}", send.window);
            }
            Packet::ChannelData(p) => {
                self.get(ChanNum(p.num))?;
                // TODO check we are expecting input
                let di = DataIn {
                    num: ChanNum(p.num),
                    dt: ChanData::Normal,
                    len: p.data.0.len(),
                };
                data_in = Some(di);
            }
            Packet::ChannelDataExt(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                if !is_client || p.code != sshnames::SSH_EXTENDED_DATA_STDERR {
                    // Discard the data, sunset can't handle this
                    debug!("Ignoring unexpected dt data, code {}", p.code);
                    ch.finished_input(p.data.0.len());
                } else {
                    // TODO check we are expecting input and dt is valid.
                    let di = DataIn {
                        num: ChanNum(p.num),
                        dt: ChanData::Stderr,
                        len: p.data.0.len(),
                    };
                    data_in = Some(di);
                }
            }
            Packet::ChannelEof(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                ch.handle_eof(s, b)?;
            }
            Packet::ChannelClose(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                ch.handle_close(s)?;
            }
            Packet::ChannelRequest(p) => {
                match self.get_mut(ChanNum(p.num)) {
                    Ok(ch) => ch.dispatch_request(&p, s, b)?,
                    Err(_) => debug!("Ignoring request to unknown channel: {p:#?}"),
                }
            }
            Packet::ChannelSuccess(_p) => {
                trace!("channel success, TODO");
            }
            Packet::ChannelFailure(_p) => {
                trace!("channel failure, TODO");
            }
            _ => Error::bug_msg("unreachable")?,
        };

        Ok(data_in)
    }

    /// Incoming packet handling
    // TODO: protocol errors etc should perhaps be less fatal,
    // ssh implementations are usually imperfect.
    pub async fn dispatch(
        &mut self,
        packet: Packet<'_>,
        is_client: bool,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<Option<DataIn>> {
        let r = self.dispatch_inner(packet, is_client, s, b).await;

        match r {
            Err(Error::BadChannel { num, .. }) => {
                warn!("Ignoring bad channel number {:?}", num);
                // warn!("Ignoring bad channel number {:?}", r.unwrap_err().backtrace());
                Ok(None)
            }
            // TODO: close channel on error? or on SSHProtoError?
            Err(any) => Err(any),
            Ok(data_in) => Ok(data_in),
        }
    }
}

#[derive(Clone, Copy)]
pub enum ChanType {
    Session,
    Tcp,
}

impl From<&ChannelOpenType<'_>> for ChanType {
    fn from(c: &ChannelOpenType<'_>) -> Self {
        match c {
            ChannelOpenType::Session => ChanType::Session,
            ChannelOpenType::DirectTcpip(_) => ChanType::Tcp,
            ChannelOpenType::ForwardedTcpip(_) => ChanType::Tcp,
            ChannelOpenType::Unknown(_) => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct ModePair {
    pub opcode: u8,
    pub arg: u32,
}

#[derive(Debug)]
pub struct Pty {
    pub term: String<MAX_TERM>,
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
    pub modes: Vec<ModePair, { termmodes::NUM_MODES }>,
}

impl TryFrom<&packets::PtyReq<'_>> for Pty {
    type Error = Error;
    fn try_from(p: &packets::PtyReq) -> Result<Self, Self::Error> {
        debug!("TODO implement pty modes");
        let term = p.term.as_ascii()?.try_into().map_err(|_| Error::BadString)?;
        Ok(Pty {
            term,
            cols: p.cols,
            rows: p.rows,
            width: p.width,
            height: p.height,
            modes: Vec::new(),
        })
    }
}
/// Like a `packets::ChannelReqType` but with storage.
/// Lifetime-free variants have the packet part directly.
#[derive(Debug)]
pub enum Req<'a> {
    // TODO let hook impls provide a string type?
    Shell,
    Exec(&'a str),
    Subsystem(&'a str),
    Pty(Pty),
    WinChange(packets::WinChange),
    Break(packets::Break),
    // Signal,
    // ExitStatus,
    // ExitSignal,
}

impl Req<'_> {
    pub(crate) fn send(self, ch: &Channel, s: &mut TrafSend) -> Result<()> {
        let t;
        let req = match self {
            Req::Shell => ChannelReqType::Shell,
            Req::Pty(pty) => {
                debug!("TODO implement pty modes");
                t = pty.term;
                ChannelReqType::Pty(packets::PtyReq {
                    term: TextString(t.as_bytes()),
                    cols: pty.cols,
                    rows: pty.rows,
                    width: pty.width,
                    height: pty.height,
                    modes: BinString(&[]),
                })
            }
            Req::Exec(cmd) => {
                ChannelReqType::Exec(packets::Exec { command: cmd.into() })
            }
            Req::Subsystem(cmd) => {
                ChannelReqType::Subsystem(packets::Subsystem { subsystem: cmd.into() })
            }
            Req::WinChange(rt) => ChannelReqType::WinChange(rt),
            Req::Break(rt) => ChannelReqType::Break(rt),
        };

        let p = ChannelRequest {
            num: ch.send_num()?,
            // we aren't handling responses for anything
            want_reply: false,
            req,
        };
        let p: Packet = p.into();
        s.send(p)
    }
}

/// Convenience for the types of session channels that can be opened
pub enum SessionCommand<S: AsRef<str>> {
    Shell,
    Exec(S),
    Subsystem(S),
}

impl<'a, S: AsRef<str> + 'a> Into<Req<'a>> for &'a SessionCommand<S> {
    fn into(self) -> Req<'a> {
        match self  {
            SessionCommand::Shell => Req::Shell,
            SessionCommand::Exec(s) => Req::Exec(s.as_ref()),
            SessionCommand::Subsystem(s) => Req::Subsystem(s.as_ref()),
        }
    }
}

/// Per-direction channel variables
#[derive(Debug)]
struct ChanDir {
    /// `u32` rather than `ChanNum` because it can also be used
    /// for the sender-side number
    num: u32,
    max_packet: usize,
    window: usize,
}

#[derive(Debug)]
enum ChanState {
    /// An incoming channel open request that has not yet been responded to.
    ///
    /// Not to be used for normal channel messages
    InOpen,

    // TODO: perhaps .get() and .get_mut() should ignore Opening state channels?

    Opening,
    Normal,
    RecvEof,
    // TODO: recvclose state probably shouldn't be possible, we remove it straight away?
    RecvClose,
    /// The channel is unused and ready to close after a call to `done()`
    PendingDone,
}

pub(crate) struct Channel {
    ty: ChanType,
    state: ChanState,
    sent_eof: bool,
    sent_close: bool,
    // // queue of requests sent with want_reply
    // last_req: heapless::Deque<ReqKind, MAX_OUTSTANDING_REQS>,

    recv: ChanDir,
    /// populated in all states except `Opening`
    send: Option<ChanDir>,

    /// Accumulated bytes for the next window adjustment (inbound data direction)
    pending_adjust: usize,

    full_window: usize,

    /// Set once application has called `done()`. The channel
    /// will only be removed from the list
    /// (allowing channel number re-use) if `app_done` is set
    app_done: bool,
}

impl Channel {
    fn new(num: ChanNum, ty: ChanType) -> Self {
        Channel {
            ty,
            state: ChanState::Opening,
            sent_close: false,
            sent_eof: false,
            // last_req: Deque::new(),
            recv: ChanDir {
                num: num.0,
                // TODO these should depend on SSH rx buffer size minus overhead
                max_packet: config::DEFAULT_MAX_PACKET,
                window: config::DEFAULT_WINDOW,
            },
            send: None,
            pending_adjust: 0,
            full_window: config::DEFAULT_WINDOW,
            app_done: false,
        }
    }

    /// Local channel number
    pub(crate) fn num(&self) -> ChanNum {
        ChanNum(self.recv.num)
    }

    /// Remote channel number, fails if channel is in progress opening
    ///
    /// Returned as a plain `u32` since it is a different namespace than `ChanNum`.
    /// This is the channel number included in most sent packets.
    pub(crate) fn send_num(&self) -> Result<u32> {
        Ok(self.send.as_ref().trap()?.num)
    }

    /// Returns an open confirmation reply packet to send.
    /// Must be called with state of `InOpen`.
    fn open_done<'p>(&mut self) -> Result<Packet<'p>> {
        debug_assert!(matches!(self.state, ChanState::InOpen));

        self.state = ChanState::Normal;
        let p = packets::ChannelOpenConfirmation {
            num: self.send_num()?,
            sender_num: self.recv.num,
            initial_window: self.recv.window as u32,
            max_packet: self.recv.max_packet as u32,
        }
        .into();
        Ok(p)
    }

    fn dispatch_request<C: CliBehaviour, S: ServBehaviour>(
        &mut self,
        p: &packets::ChannelRequest,
        s: &mut TrafSend,
        b: &mut Behaviour<'_, C, S>,
    ) -> Result<()> {
        // only servers accept requests
        let r = match b {
            Behaviour::Server(ref mut b) => {
                // OK unwrap: is server
                // let b = b.as_server().unwrap();
                self.dispatch_server_request(p, s, *b)
            }
            Behaviour::Client(ref mut b) => {
                // OK unwrap: is client
                // let b = b.as_client().unwrap();
                self.dispatch_client_request(p, s, *b)
            }
        };

        let success = r.unwrap_or_else(|e| {
            debug!("Error in channel req handling for {p:?}, {e:?}");
            false
        });

        if p.want_reply {
            let num = self.send_num()?;
            if success {
                s.send(packets::ChannelSuccess { num })?;
            } else {
                s.send(packets::ChannelFailure { num })?;
            }
        }
        Ok(())
    }


    /// Returns Ok(want_reply: bool) on success
    fn dispatch_server_request(
        &self,
        p: &packets::ChannelRequest,
        _s: &mut TrafSend,
        b: &mut impl ServBehaviour,
    ) -> Result<bool> {
        if !matches!(self.ty, ChanType::Session) {
            return Ok(false);
        }

        match &p.req {
            ChannelReqType::Shell => Ok(b.sess_shell(self.num())),
            ChannelReqType::Exec(ex) => Ok(b.sess_exec(self.num(), ex.command)),
            ChannelReqType::Pty(pty) => {
                let cpty = pty.try_into()?;
                Ok(b.sess_pty(self.num(), &cpty))
            }
            _ => {
                if let ChannelReqType::Unknown(u) = &p.req {
                    warn!("Unknown channel req type \"{}\"", u)
                } else {
                    // OK unwrap: tested for Unknown
                    warn!(
                        "Unhandled channel req \"{}\"",
                        p.req.variant_name().unwrap()
                    )
                };
                Ok(false)
            }
        }
    }

    /// Returns Ok(want_reply: bool) on success
    fn dispatch_client_request(
        &mut self,
        p: &packets::ChannelRequest,
        s: &mut TrafSend,
        _b: &mut impl CliBehaviour,
    ) -> Result<bool> {
        if !matches!(self.ty, ChanType::Session) {
            return Ok(false);
        }

        match &p.req {
            ChannelReqType::ExitStatus(_st) => {
                // TODO
                self.handle_close(s)?;
                Ok(true)
            }
            ChannelReqType::ExitSignal(_sig) => {
                // TODO
                self.handle_close(s)?;
                Ok(true)
            }
            _ => {
                if let ChannelReqType::Unknown(u) = &p.req {
                    warn!("Unknown channel req type \"{}\"", u)
                } else {
                    // OK unwrap: tested for Unknown
                    warn!(
                        "Unhandled channel req \"{}\"",
                        p.req.variant_name().unwrap()
                    )
                };
                Ok(false)
            }
        }
    }

    fn handle_eof<C: CliBehaviour, S: ServBehaviour>(&mut self, s: &mut TrafSend, _b: &mut Behaviour<'_, C, S>) -> Result<()> {
        //TODO: check existing state?
        if !self.sent_eof {
            s.send(packets::ChannelEof { num: self.send_num()? })?;
            self.sent_eof = true;
        }

        self.state = ChanState::RecvEof;
        // todo!();
        Ok(())
    }

    fn handle_close(&mut self, s: &mut TrafSend) -> Result<()> {
        //TODO: check existing state?
        if !self.sent_close {
            s.send(packets::ChannelClose { num: self.send_num()? })?;
            self.sent_close = true;
        }
        self.state = ChanState::RecvClose;
        Ok(())
    }

    fn finished_input(&mut self, len: usize) {
        self.pending_adjust = self.pending_adjust.saturating_add(len)
    }

    fn have_recv_eof(&self) -> bool {
        matches!(self.state, ChanState::RecvEof | ChanState::RecvClose)
    }

    fn is_closed(&self) -> bool {
        matches!(self.state, ChanState::RecvClose)
    }

    // None on close
    fn send_allowed(&self) -> Option<usize> {
        let r = self.send.as_ref().map(|s| usize::min(s.window, s.max_packet));
        trace!("send_allowed {r:?}");
        r
    }

    pub(crate) fn valid_send(&self, _dt: ChanData) -> bool {
        // TODO: later we should only allow non-pty "session" channels
        // to have dt, for stderr only.
        true
    }

    /// Returns a window adjustment packet if required
    fn check_window_adjust(&mut self) -> Result<Option<Packet>> {
        let num = self.send.as_mut().trap()?.num;
        if self.pending_adjust > self.full_window / 2 {
            let adjust = self.pending_adjust as u32;
            self.pending_adjust = 0;
            let p = packets::ChannelWindowAdjust { num, adjust }.into();
            Ok(Some(p))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub(crate) struct DataIn {
    pub num: ChanNum,
    pub dt: ChanData,
    pub len: usize,
}

/// The result of a channel open request.
pub enum ChanOpened {
    Success,
    /// A channel open response will be sent later (for eg TCP open)
    Defer,
    /// A SSH failure code, as well as returning the passed channel handle
    Failure((ChanFail, ChanHandle))
}

/// A SSH protocol local channel number
///
/// The number will always be in the range `0 <= num < MAX_CHANNELS`
/// and can be used as an index by applications.
/// Most external application API methods take a `ChanHandle` instead.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ChanNum(pub u32);

impl core::fmt::Display for ChanNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Channel data packet type.
///
/// The SSH specification allows other `u32` types, though Sunset doesn't
/// currently implement it, they are not widely used.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ChanData {
    /// `SSH_MSG_CHANNEL_DATA`
    Normal,
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA`
    Stderr,
    // Future API:
    // Other(u32),
}

impl ChanData {
    pub(crate) fn validate_send(&self, is_client: bool) -> Result<()> {
        if matches!(self, ChanData::Stderr) && is_client {
            error::BadChannelData.fail()
        } else {
            Ok(())
        }
    }

    pub(crate) fn validate_receive(&self, is_client: bool) -> Result<()> {
        if matches!(self, ChanData::Stderr) && !is_client {
            error::BadChannelData.fail()
        } else {
            Ok(())
        }
    }

    pub(crate) fn packet_offset(&self) -> usize {
        match self {
            ChanData::Normal => ChannelData::DATA_OFFSET,
            ChanData::Stderr => ChannelDataExt::DATA_OFFSET,
        }
    }
}

// for dispatch_open_inner()
enum DispatchOpenError {
    /// A program error
    Error(Error),
    /// A SSH failure response
    Failure(ChanFail),
}

impl From<Error> for DispatchOpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::NoChannels => Self::Failure(ChanFail::SSH_OPEN_RESOURCE_SHORTAGE),
            e => Self::Error(e),
        }
    }
}

impl From<ChanFail> for DispatchOpenError {
    fn from(f: ChanFail) -> Self {
        Self::Failure(f)
    }
}

pub struct SessionOpener<'a, 's, 't> {
    ch: &'a Channel,
    s: &'a mut TrafSend<'s, 't>,
}

impl<'a, 's, 't> SessionOpener<'a, 's, 't> {
    fn new(ch: &'a Channel, s: &'a mut TrafSend<'s, 't>) -> Self {
        Self {
            ch,
            s,
        }
    }

    pub fn cmd<S: AsRef<str>>(&mut self, cmd: &SessionCommand<S>) {
        self.send(cmd.into())
    }

    pub fn shell(&mut self) {
        self.send(Req::Shell)
    }

    pub fn exec(&mut self, cmd: &str) {
        self.send(Req::Exec(cmd))
    }

    pub fn subsystem(&mut self, cmd: &str) {
        self.send(Req::Subsystem(cmd))
    }

    pub fn pty(&mut self, pty: channel::Pty) {
        self.send(Req::Pty(pty))
    }

    fn send(&mut self, req: Req) {
        let r = req.send(self.ch, self.s);
        if let Err(e) = r {
            warn!("Error sending request: {e:?}")
        }
    }
}

