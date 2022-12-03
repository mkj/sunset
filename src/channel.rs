#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::mem;

use heapless::{Deque, String, Vec};

use crate::{sshwire::SSHEncodeEnum, *};
use config::*;
use conn::Dispatched;
use packets::{
    ChannelData, ChannelDataExt, ChannelOpen, ChannelOpenFailure, ChannelOpenType,
    ChannelReqType, ChannelRequest, Packet,
};
use sshnames::*;
use sshwire::{BinString, TextString};
use traffic::TrafSend;

/// The result of a channel open request.
pub enum ChanOpened {
    Success,
    /// A channel open response will be sent later (for eg TCP open)
    Defer,
    Failure(ChanFail),
}

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],

    /// The size of channel data last set with `DataIn`.
    pending_input: Option<PendInput>,
}

pub(crate) type InitReqs = Vec<ReqDetails, MAX_INIT_REQS>;

// for dispatch_open_inner()
enum DispatchOpenError {
    Error(Error),
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

impl Channels {
    pub fn new() -> Self {
        Channels { ch: Default::default(), pending_input: None }
    }

    pub fn open<'b>(
        &mut self,
        ty: packets::ChannelOpenType<'b>,
        init_req: InitReqs,
    ) -> Result<(&Channel, Packet<'b>)> {
        let (num, ch) = self.unused_chan()?;

        let chan = Channel::new(num, (&ty).into(), init_req);
        let p = packets::ChannelOpen {
            num,
            initial_window: chan.recv.window as u32,
            max_packet: chan.recv.max_packet as u32,
            ty,
        }
        .into();
        *ch = Some(chan);
        Ok((ch.as_ref().unwrap(), p))
    }

    /// Returns a `Channel` for a local number, any state including `InOpen`.
    fn get_any(&self, num: u32) -> Result<&Channel> {
        self.ch
            .get(num as usize)
            // out of range
            .ok_or(Error::BadChannel)?
            .as_ref()
            // unused channel
            .ok_or(Error::BadChannel)
    }

    /// Returns a `Channel` for a local number. Excludes `InOpen` state.
    fn get(&self, num: u32) -> Result<&Channel> {
        let ch = self.get_any(num)?;

        if matches!(ch.state, ChanState::InOpen) {
            Err(Error::BadChannel)
        } else {
            Ok(ch)
        }
    }

    fn get_mut(&mut self, num: u32) -> Result<&mut Channel> {
        let ch = self
            .ch
            .get_mut(num as usize)
            // out of range
            .ok_or(Error::BadChannel)?
            .as_mut()
            // unused channel
            .ok_or(Error::BadChannel)?;

        if matches!(ch.state, ChanState::InOpen) {
            Err(Error::BadChannel)
        } else {
            Ok(ch)
        }
    }

    /// Must be called when an application has finished with a channel.
    pub fn done(&mut self, num: u32) -> Result<()> {
        self.get_mut(num)?.app_done = true;
        Ok(())
    }

    fn remove(&mut self, num: u32) -> Result<()> {
        // TODO any checks?
        let ch = self.ch.get_mut(num as usize).ok_or(Error::BadChannel)?;
        if let Some(c) = ch {
            if c.app_done {
                trace!("removing channel {}", num);
                *ch = None;
            } else {
                c.state = ChanState::PendingDone;
                trace!("not removing channel {}, not finished", num);
            }
            Ok(())
        } else{
            Err(Error::BadChannel)
        }
    }

    /// Returns the first available channel
    fn unused_chan(&mut self) -> Result<(u32, &mut Option<Channel>)> {
        self.ch
            .iter_mut()
            .enumerate()
            .find_map(
                |(i, ch)| if ch.as_mut().is_none() { Some((i as u32, ch)) } else { None },
            )
            .ok_or(Error::NoChannels)
    }

    /// Creates a new channel in InOpen state.
    fn reserve_chan(&mut self, co: &ChannelOpen<'_>) -> Result<&mut Channel> {
        let (num, ch) = self.unused_chan()?;
        let mut chan = Channel::new(num, (&co.ty).into(), Vec::new());
        chan.send = Some(ChanDir {
            num: co.num,
            max_packet: co.max_packet as usize,
            window: co.initial_window as usize,
        });
        chan.state = ChanState::InOpen;

        *ch = Some(chan);
        Ok(ch.as_mut().unwrap())
    }

    /// Returns the channel data packet to send.
    /// Caller has already checked valid length with send_allowed().
    /// Don't call with zero length data.
    pub(crate) fn send_data<'b>(
        &mut self,
        num: u32,
        ext: Option<u32>,
        data: &'b [u8],
    ) -> Result<Packet<'b>> {
        debug_assert!(data.len() > 0);

        let send = self.get_mut(num)?.send.as_mut().trap()?;
        if data.len() > send.max_packet || data.len() > send.window {
            return Err(Error::bug());
        }
        send.window -= data.len();

        let data = BinString(data);
        let p = if let Some(code) = ext {
            // TODO: check code is valid for this channel
            packets::ChannelDataExt { num: send.num, code, data }.into()
        } else {
            packets::ChannelData { num: send.num, data }.into()
        };

        Ok(p)
    }

    /// Informs the channel layer that an incoming packet has been read out,
    /// so a window adjustment can be queued.
    pub(crate) fn finished_input(&mut self, num: u32) -> Result<Option<Packet>> {
        match self.pending_input {
            Some(ref p) if p.chan == num => {
                let len = p.len;
                self.get_mut(num)?.finished_input(len);
                self.pending_input = None;

                self.get_mut(num)?.check_window_adjust()
            }
            _ => Err(Error::bug()),
        }
    }

    pub(crate) fn have_recv_eof(&self, num: u32) -> bool {
        self.get(num).map_or(false, |c| c.have_recv_eof())
    }

    pub(crate) fn send_allowed(&self, num: u32) -> Option<usize> {
        self.get(num).map_or(Some(0), |c| c.send_allowed())
    }

    pub(crate) fn valid_send(&self, num: u32, ext: Option<u32>) -> bool {
        self.get(num).map_or(false, |c| c.valid_send(ext))
    }

    fn dispatch_open(
        &mut self,
        p: &ChannelOpen<'_>,
        s: &mut TrafSend,
        b: &mut Behaviour<'_>,
    ) -> Result<()> {
        match self.dispatch_open_inner(p, s, b) {
            Err(DispatchOpenError::Failure(f)) => {
                s.send(packets::ChannelOpenFailure {
                    num: p.num,
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
        b: &mut Behaviour<'_>,
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

        // beware that a reserved channel must be cleaned up on failure

        // run the Behaviour function
        let r = match &p.ty {
            ChannelOpenType::Session => {
                // unwrap: earlier test ensures b.server() succeeds
                let bserv = b.server().unwrap();
                bserv.open_session(ch.num())
            }
            ChannelOpenType::ForwardedTcpip(t) => b.open_tcp_forwarded(ch.num(), t),
            ChannelOpenType::DirectTcpip(t) => b.open_tcp_direct(ch.num(), t),
            ChannelOpenType::Unknown(_) => {
                unreachable!()
            }
        };

        match r {
            ChanOpened::Success => {
                s.send(ch.open_done()?)?;
            }
            ChanOpened::Failure(f) => {
                let n = ch.num();
                self.remove(n)?;
                return Err(f.into());
            }
            ChanOpened::Defer => {
                // application will reply later
            }
        }

        Ok(())
    }

    pub fn dispatch_request(
        &mut self,
        p: &packets::ChannelRequest,
        s: &mut TrafSend,
        b: &mut Behaviour<'_>,
    ) -> Result<()> {
        if let Ok(ch) = self.get(p.num) {
            // only servers accept requests
            let success = if let Ok(b) = b.server() {
                ch.dispatch_server_request(p, s, b).unwrap_or_else(|e| {
                    debug!("Error in channel req handling for {p:?}, {e:?}");
                    false
                })
            } else {
                false
            };

            if p.want_reply {
                let num = ch.send_num()?;
                if success {
                    s.send(packets::ChannelSuccess { num })?;
                } else {
                    s.send(packets::ChannelFailure { num })?;
                }
            }
        } else {
            debug!("Ignoring request to unknown channel: {p:#?}");
        }
        Ok(())
    }

    // Some returned errors will be caught by caller and returned as SSH messages
    async fn dispatch_inner(
        &mut self,
        packet: Packet<'_>,
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_>,
    ) -> Result<Option<DataIn>> {
        trace!("chan dispatch");
        let mut data_in = None;
        match packet {
            Packet::ChannelOpen(p) => {
                self.dispatch_open(&p, s, b)?;
            }

            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_mut(p.num)?;
                match ch.state {
                    ChanState::Opening { .. } => {
                        let init_state =
                            mem::replace(&mut ch.state, ChanState::Normal);
                        if let ChanState::Opening { init_req } = init_state {
                            debug_assert!(ch.send.is_none());
                            ch.send = Some(ChanDir {
                                num: p.sender_num,
                                max_packet: p.max_packet as usize,
                                window: p.initial_window as usize,
                            });
                            for r in init_req {
                                ch.request(r, s)?
                            }
                            ch.state = ChanState::Normal;
                        }
                    }
                    _ => {
                        trace!("Bad channel state");
                        return Err(Error::SSHProtoError)
                    }
                }
            }

            Packet::ChannelOpenFailure(p) => {
                let ch = self.get(p.num)?;
                if ch.send.is_some() {
                    // TODO: or just warn?
                    trace!("open failure late?");
                    return Err(Error::SSHProtoError);
                } else {
                    self.remove(p.num)?;
                    // TODO event
                }
            }
            Packet::ChannelWindowAdjust(p) => {
                let send = self.get_mut(p.num)?.send.as_mut().trap()?;
                send.window = send.window.saturating_add(p.adjust as usize);
            }
            Packet::ChannelData(p) => {
                self.get(p.num)?;
                // TODO check we are expecting input
                if self.pending_input.is_some() {
                    return Err(Error::bug());
                }
                self.pending_input =
                    Some(PendInput { chan: p.num, len: p.data.0.len() });
                let di = DataIn {
                    num: p.num,
                    ext: None,
                    offset: ChannelData::DATA_OFFSET,
                    len: p.data.0.len(),
                };
                data_in = Some(di);
            }
            Packet::ChannelDataExt(p) => {
                self.get(p.num)?;
                // TODO check we are expecting input and ext is valid.
                if self.pending_input.is_some() {
                    return Err(Error::bug());
                }
                self.pending_input =
                    Some(PendInput { chan: p.num, len: p.data.0.len() });
                let di = DataIn {
                    num: p.num,
                    ext: Some(p.code),
                    offset: ChannelDataExt::DATA_OFFSET,
                    len: p.data.0.len(),
                };
                trace!("{di:?}");
            }
            Packet::ChannelEof(p) => {
                self.get(p.num)?;
            }
            Packet::ChannelClose(_p) => {
                // todo!();
                error!("ignoring channel close");
            }
            Packet::ChannelRequest(p) => {
                self.dispatch_request(&p, s, b)?;
            }
            Packet::ChannelSuccess(_p) => {
                trace!("channel success, TODO");
            }
            Packet::ChannelFailure(_p) => {
                todo!("ChannelFailure");
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
        s: &mut TrafSend<'_, '_>,
        b: &mut Behaviour<'_>,
    ) -> Result<Option<DataIn>> {
        let r = self.dispatch_inner(packet, s, b).await;

        match r {
            Err(Error::BadChannel) => {
                warn!("Ignoring bad channel number");
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

// TODO: name confused with packets::Pty
#[derive(Debug)]
pub struct Pty {
    // or could we put String into packets::Pty and serialize modes there...
    pub term: String<MAX_TERM>,
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
    // TODO: perhaps we need something serializable here
    pub modes: Vec<ModePair, { termmodes::NUM_MODES }>,
}

impl TryFrom<&packets::Pty<'_>> for Pty {
    type Error = Error;
    fn try_from(p: &packets::Pty) -> Result<Self, Self::Error> {
        warn!("TODO implement pty modes");
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
pub(crate) type ExecString = heapless::String<MAX_EXEC>;

/// Like a `packets::ChannelReqType` but with storage.
/// Lifetime-free variants have the packet part directly.
#[derive(Debug)]
pub enum ReqDetails {
    // TODO let hook impls provide a string type?
    Shell,
    Exec(ExecString),
    Pty(Pty),
    // Subsytem { subsystem: heapless::String<MAX_EXEC> },
    WinChange(packets::WinChange),
    Break(packets::Break),
}

#[derive(Debug)]
pub struct Req {
    num: u32,
    details: ReqDetails,
}

impl ReqDetails {
    fn want_reply(&self) -> bool {
        match self {
            Self::WinChange(_) => false,
            _ => true,
        }
    }
}

impl Req {
    pub(crate) fn packet<'a>(&'a self) -> Result<Packet<'a>> {
        let num = self.num;
        let want_reply = self.details.want_reply();
        let ty = match &self.details {
            ReqDetails::Shell => ChannelReqType::Shell,
            ReqDetails::Pty(pty) => {
                warn!("TODO implement pty modes");
                ChannelReqType::Pty(packets::Pty {
                    term: TextString(pty.term.as_bytes()),
                    cols: pty.cols,
                    rows: pty.rows,
                    width: pty.width,
                    height: pty.height,
                    modes: BinString(&[]),
                })
            }
            ReqDetails::Exec(cmd) => {
                ChannelReqType::Exec(packets::Exec { command: cmd.as_str().into() })
            }
            ReqDetails::WinChange(rt) => ChannelReqType::WinChange(rt.clone()),
            ReqDetails::Break(rt) => ChannelReqType::Break(rt.clone()),
        };
        let p = ChannelRequest { num, want_reply, req: ty }.into();
        Ok(p)
    }
}

// Variants match packets::ChannelReqType, without data
enum ReqKind {
    Shell,
    Exec,
    Pty,
    Subsystem,
    WinChange,
    Signal,
    ExitStatus,
    ExitSignal,
    Break,
}

// shell+pty. or perhaps this should match the hook queue size and then
// we can stop servicing the hook queue if this limit is reached.
const MAX_OUTSTANDING_REQS: usize = 2;
const MAX_INIT_REQS: usize = 2;

/// Per-direction channel variables
pub struct ChanDir {
    num: u32,
    max_packet: usize,
    window: usize,
}

enum ChanState {
    /// An incoming channel open request that has not yet been responded to.
    ///
    /// Not to be used for normal channel messages
    InOpen,
    /// `init_req` are the request messages to be sent once the ChannelOpenConfirmation
    /// is received
    // TODO: this is wasting half a kB. where else could we store it? could
    // the Behaviour own it? Or we don't store them here, just callback to the Behaviour.
    Opening {
        init_req: InitReqs,
    },
    Normal,
    RecvEof,
    // TODO: recvclose state probably shouldn't be possible, we remove it straight away?
    RecvClose,
    /// The channel is unused and ready to close after a call to `done()`
    PendingDone,
}

pub(crate) struct Channel {
    pub ty: ChanType,
    state: ChanState,
    sent_eof: bool,
    sent_close: bool,
    // queue of requests sent with want_reply
    last_req: heapless::Deque<ReqKind, MAX_OUTSTANDING_REQS>,

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
    fn new(num: u32, ty: ChanType, init_req: InitReqs) -> Self {
        Channel {
            ty,
            state: ChanState::Opening { init_req },
            sent_close: false,
            sent_eof: false,
            last_req: Deque::new(),
            recv: ChanDir {
                num,
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
    pub(crate) fn num(&self) -> u32 {
        self.recv.num
    }

    /// Remote channel number, fails if channel is in progress opening
    pub(crate) fn send_num(&self) -> Result<u32> {
        Ok(self.send.as_ref().trap()?.num)
    }

    fn request(&mut self, req: ReqDetails, s: &mut TrafSend) -> Result<()> {
        let num = self.send.as_ref().trap()?.num;
        let r = Req { num, details: req };
        s.send(r.packet()?)
    }

    /// Returns an open confirmation reply packet to send.
    /// Must be called with state of `InOpen`.
    fn open_done<'p>(&mut self) -> Result<Packet<'p>> {
        debug_assert!(matches!(self.state, ChanState::InOpen));

        self.state = ChanState::Normal;
        let p = packets::ChannelOpenConfirmation {
            num: self.send_num()?,
            // unwrap: state is InOpen
            sender_num: self.send.as_ref().unwrap().num,
            initial_window: self.recv.window as u32,
            max_packet: self.recv.max_packet as u32,
        }
        .into();
        Ok(p)
    }

    fn dispatch_server_request(
        &self,
        p: &packets::ChannelRequest,
        _s: &mut TrafSend,
        b: &mut dyn ServBehaviour,
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

    fn finished_input(&mut self, len: usize) {
        self.pending_adjust = self.pending_adjust.saturating_add(len)
    }

    fn have_recv_eof(&self) -> bool {
        match self.state {
            ChanState::RecvEof | ChanState::RecvClose => true,
            _ => false,
        }
    }

    // None on close
    fn send_allowed(&self) -> Option<usize> {
        self.send.as_ref().map(|s| usize::max(s.window, s.max_packet))
    }

    pub(crate) fn valid_send(&self, ext: Option<u32>) -> bool {
        // TODO: later we should only allow non-pty "session" channels
        // to have ext, for stderr only.
        true
    }

    /// Returns a window adjustment packet if required
    fn check_window_adjust(&mut self) -> Result<Option<Packet>> {
        let send = self.send.as_mut().trap()?;
        if self.pending_adjust > self.full_window / 2 {
            let adjust = self.pending_adjust as u32;
            self.pending_adjust = 0;
            let p = packets::ChannelWindowAdjust { num: send.num, adjust }.into();
            Ok(Some(p))
        } else {
            Ok(None)
        }
    }
}

pub struct ChanMsg {
    pub num: u32,
    pub msg: ChanMsgDetails,
}

pub enum ChanMsgDetails {
    Data,
    ExtData { ext: u32 },
    // TODO: perhaps we don't need the storaged ReqDetails, just have the reqtype packet?
    Req(ReqDetails),
    // TODO closein/closeout/eof, etc. Should also return the exit status etc
    Close,
}

#[derive(Debug)]
pub(crate) struct DataIn {
    pub num: u32,
    pub ext: Option<u32>,
    pub offset: usize,
    pub len: usize,
}

struct PendInput {
    chan: u32,
    len: usize,
}
