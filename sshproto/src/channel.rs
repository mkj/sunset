    #[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::mem;

use heapless::{Deque, String, Vec};

use crate::{conn::RespPackets, *};
use config::*;
use packets::{ChannelReqType, ChannelRequest, Packet, ChannelOpen, ChannelOpenType, ChannelData, ChannelDataExt};
use sshwire::{BinString, TextString};
use sshnames::*;

pub enum ChanOpened {
    Success,

    /// A channel open response will be sent later
    Defer,

    Failure(ChanFail),
}

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],

    /// The size of data last set with `ChanEvent::DataIn`.
    pending_input: Option<PendInput>,
}

pub(crate) type InitReqs = Vec<ReqDetails, MAX_INIT_REQS>;

impl Channels {
    pub fn new() -> Self {
        Channels {
            ch: Default::default(),
            pending_input: None,
        }
    }

    pub fn open<'b>(
        &mut self,
        ty: packets::ChannelOpenType<'b>,
        init_req: InitReqs,
    ) -> Result<(&Channel, Packet<'b>)> {
        let num = self.unused_chan()?;

        let chan = Channel::new(num, (&ty).into(), init_req);
        let p = packets::ChannelOpen {
            num,
            initial_window: chan.recv.window as u32,
            max_packet: chan.recv.max_packet as u32,
            ty,
        }
        .into();
        let ch = &mut self.ch[num as usize];
        *ch = Some(chan);
        Ok((ch.as_ref().unwrap(), p))
    }

    /// Returns a `Channel` for a local number, any state.
    pub fn get_any(&self, num: u32) -> Result<&Channel> {
        self.ch
            .get(num as usize)
            // out of range
            .ok_or(Error::BadChannel)?
            .as_ref()
            // unused channel
            .ok_or(Error::BadChannel)
    }

    /// Returns a `Channel` for a local number. Excludes `InOpen` state.
    pub fn get(&self, num: u32) -> Result<&Channel> {
        let ch = self.get_any(num)?;

        if matches!(ch.state, ChanState::InOpen) {
            Err(Error::BadChannel)
        } else {
            Ok(ch)
        }
    }

    pub fn get_mut(&mut self, num: u32) -> Result<&mut Channel> {
        let ch = self.ch
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

    fn remove(&mut self, num: u32) -> Result<()> {
        // TODO any checks?
        *self.ch.get_mut(num as usize).ok_or(Error::BadChannel)? = None;
        Err(Error::otherbug())
        // Ok(())
    }

    /// Returns the first available channel
    fn unused_chan(&self) -> Result<u32> {
        self.ch.iter().enumerate()
            .find_map(
                |(i, ch)| if ch.as_ref().is_none() { Some(i as u32) } else { None },
            )
            .ok_or(Error::NoChannels)
    }

    /// Creates a new channel in InOpen state.
    fn reserve_chan(&mut self, co: &ChannelOpen<'_>) -> Result<&mut Channel> {
        let num = self.unused_chan()?;
        let mut chan = Channel::new(num, (&co.ty).into(), Vec::new());
        chan.send = Some(ChanDir {
            num: co.num,
            max_packet: co.max_packet as usize,
            window: co.initial_window as usize,
            });
        chan.state = ChanState::InOpen;

        let ch = &mut self.ch[num as usize];
        *ch = Some(chan);
        Ok(ch.as_mut().unwrap())
    }

    /// Returns the channel data packet to send, and the length of data consumed.
    /// Caller has already checked valid length with send_allowed()
    pub(crate) fn send_data<'b>(&mut self, num: u32, ext: Option<u32>, data: &'b [u8])
            -> Result<Packet<'b>> {
        let send = self.get_mut(num)?.send.as_mut().trap()?;
        if data.len() > send.max_packet || data.len() > send.window {
            return Err(Error::bug())
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

    pub fn channel_open(&mut self, p: &ChannelOpen<'_>,
        resp: &mut RespPackets<'_>,
        b: &mut Behaviour<'_>,
        ) -> Result<Option<ChanEventMaker>> {
        let mut failure = None;
        let open_res = match &p.ty {
            ChannelOpenType::Session => {
                // only server should receive session opens
                let bserv = b.server().map_err(|_| Error::SSHProtoError)?;

                match self.reserve_chan(p) {
                    Ok(ch) => {
                        let r = bserv.open_session(ch.recv.num);
                        Some((ch, r))
                    }
                    Err(_) => {
                        failure = Some(ChanFail::SSH_OPEN_RESOURCE_SHORTAGE);
                        None
                    },
                }
            }
            ChannelOpenType::ForwardedTcpip(t) => {
                match self.reserve_chan(p) {
                    Ok(ch) => {
                        let r = b.open_tcp_forwarded(ch.recv.num);
                        Some((ch, r))
                    }
                    Err(_) => {
                        failure = Some(ChanFail::SSH_OPEN_RESOURCE_SHORTAGE);
                        None
                    },
                }

            }
            ChannelOpenType::DirectTcpip(t) => {
                match self.reserve_chan(p) {
                    Ok(ch) => {
                        let r = b.open_tcp_direct(ch.recv.num);
                        Some((ch, r))
                    }
                    Err(_) => {
                        failure = Some(ChanFail::SSH_OPEN_RESOURCE_SHORTAGE);
                        None
                    },
                }
            }
            ChannelOpenType::Unknown(u) => {
                debug!("Rejecting unknown channel type '{u}'");
                failure = Some(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
                None
            }
        };

        match open_res {
            Some((ch, r)) => {
                match r {
                    ChanOpened::Success => {
                        ch.open_done();
                    },
                    ChanOpened::Failure(f) => {
                        failure = Some(f);
                    }
                    ChanOpened::Defer => {
                        // application will reply later
                    }
                }
            }
            _ => ()
        }

        if let Some(reason) = failure {
            let r = packets::ChannelOpenFailure {
                num: p.num,
                reason: reason as u32,
                desc: "".into(),
                lang: "",
            };
            let r: Packet = r.into();
            resp.push(r.into()).trap()?;
        }

        Ok(None)
    }

    /// Incoming packet handling
    // TODO: protocol errors etc should perhaps be less fatal,
    // ssh implementations are usually imperfect.
    pub async fn dispatch(
        &mut self,
        packet: Packet<'_>,
        resp: &mut RespPackets<'_>,
        b: &mut Behaviour<'_>,
    ) -> Result<Option<ChanEventMaker>> {
        trace!("chan dispatch");
        let r = match packet {
            Packet::ChannelOpen(p) => {
                self.channel_open(&p, resp, b)
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
                                ch.request(r, resp)?
                            }
                            ch.state = ChanState::Normal;
                        }
                        Ok(None)
                    }
                    _ => Err(Error::SSHProtoError),
                }
            }
            Packet::ChannelOpenFailure(p) => {
                let ch = self.get(p.num)?;
                if ch.send.is_some() {
                    // TODO: or just warn?
                    Err(Error::SSHProtoError)
                } else {
                    self.remove(p.num);
                    // TODO event
                    Ok(None)
                }
            }
            Packet::ChannelWindowAdjust(p) => {
                let send = self.get_mut(p.num)?.send.as_mut().trap()?;
                send.window = send.window.saturating_add(p.adjust as usize);
                Ok(None)
            }
            Packet::ChannelData(p) => {
                let ch = self.get(p.num)?;
                // TODO check we are expecting input
                if self.pending_input.is_some() {
                    return Err(Error::bug())
                }
                self.pending_input = Some(PendInput { chan: p.num, len: p.data.0.len() });
                let di = DataIn { num: p.num, ext: None, offset: p.data_offset(), len: p.data.0.len() };
                Ok(Some(ChanEventMaker::DataIn(di)))
            }
            Packet::ChannelDataExt(p) => {
                let ch = self.get(p.num)?;
                // TODO check we are expecting input and ext is valid.
                if self.pending_input.is_some() {
                    return Err(Error::bug())
                }
                self.pending_input = Some(PendInput { chan: p.num, len: p.data.0.len() });
                let di = DataIn { num: p.num, ext: Some(p.code), offset: p.data_offset(), len: p.data.0.len() };
                trace!("{di:?}");
                Ok(Some(ChanEventMaker::DataIn(di)))
            }
            Packet::ChannelEof(p) => {
                let _ch = self.get(p.num)?;
                Ok(Some(ChanEventMaker::Eof { num: p.num }))
            }
            Packet::ChannelClose(_p) => {
                // todo!();
                error!("ignoring channel close");
                Ok(None)
            }
            Packet::ChannelRequest(p) => {
                match self.get(p.num) {
                    Ok(ch) => Ok(Some(ChanEventMaker::Req)),
                    Err(ch) => {
                        if p.want_reply {
                            // TODO respond with an error
                        }
                        Ok(None)
                    }
                }
            }
            Packet::ChannelSuccess(_p) => {
                trace!("channel success, TODO");
                Ok(None)
            }
            Packet::ChannelFailure(_p) => {
                todo!();
            }
            _ => Error::bug_msg("unreachable")
        };
        match r {
            Err(Error::BadChannel) => {
                warn!("Ignoring bad channel number");
                Ok(None)
            }
            Ok(ev) => Ok(ev),
            // TODO: close channel on error? or on SSHProtoError?
            Err(any) => Err(any),
        }
    }
}

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
    // or could we put String into packets::Pty and serialize modes there...
    pub term: String<MAX_TERM>,
    pub cols: u32,
    pub rows: u32,
    pub width: u32,
    pub height: u32,
    // TODO: perhaps we need something serializable here
    pub modes: Vec<ModePair, { termmodes::NUM_MODES }>,
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
    /// An incoming channel open request that has not yet been responded to,
    /// should not be used
    InOpen,
    /// `init_req` are the request messages to be sent once the ChannelOpenConfirmation
    /// is received
    // TODO: this is wasting half a kB. where else could we store it? could
    // the Behaviour own it? Or we don't store them here, just callback to the Behaviour.
    Opening { init_req: InitReqs },
    Normal,

    RecvEof,

    // TODO: recvclose state probably shouldn't be possible, we remove it straight away?
    RecvClose,
}

pub(crate) struct Channel {
    ty: ChanType,
    state: ChanState,
    sent_eof: bool,
    sent_close: bool,
    // queue of requests sent with want_reply
    last_req: heapless::Deque<ReqKind, MAX_OUTSTANDING_REQS>,

    recv: ChanDir,
    // filled after confirmation when we initiate the channel
    send: Option<ChanDir>,

    /// Accumulated bytes for the next window adjustment (inbound data direction)
    pending_adjust: usize,

    full_window: usize,
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
        }
    }

    fn request(&mut self, req: ReqDetails, resp: &mut RespPackets) -> Result<()> {
        let num = self.send.as_ref().trap()?.num;
        let r = Req { num, details: req };
        resp.push(r.into()).trap()?;
        Ok(())
    }

    pub(crate) fn number(&self) -> u32 {
        self.recv.num
    }

    fn open_done(&mut self) {
        debug_assert!(matches!(self.state, ChanState::InOpen));
        self.state = ChanState::Normal
    }

    fn finished_input(&mut self, len: usize ) {
        self.pending_adjust = self.pending_adjust.saturating_add(len)
    }

    fn have_recv_eof(&self) -> bool {
        match self.state {
            |ChanState::RecvEof
            |ChanState::RecvClose
            => true,
            _ => false,
        }

    }

    // None on close
    fn send_allowed(&self) -> Option<usize> {
        self.send.as_ref().map(|s| usize::max(s.window, s.max_packet))
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

/// Application API
#[derive(Debug)]
pub enum ChanEvent<'a> {
    // TODO: perhaps this one should go a level above since it isn't for existing channels?
    OpenSuccess { num: u32 },

    // TODO details
    // OpenRequest { },

    ReqPty { num: u32, want_reply: bool, pty: packets::Pty<'a> },

    Req { num: u32, req: ChannelReqType<'a> },
    // TODO closein/closeout/eof, etc. Should also return the exit status etc

    Eof { num: u32 },

    Close { num: u32 },
    // TODO: responses to a previous ChanMsg?
}

/// An event returned from `Channel::dispatch()`.
/// Most are propagated to the application, `DataIn is caught by `runner`
#[derive(Debug)]
pub(crate) enum ChanEventMaker {
    /// Channel data is ready with `channel_input()`. This breaks the `Packet` abstraction
    /// by returning the offset into the payload buffer, used by `traffic`.
    DataIn(DataIn),

    OpenSuccess { num: u32 },

    // A ChannelRequest. Will be split into separate ChanEvent variants
    // for each type.
    Req,
    // TODO closein/closeout/eof, etc. Should also return the exit status etc

    Eof { num: u32 },

    Close { num: u32 },
    // TODO: responses to a previous ChanMsg?
}

impl ChanEventMaker {
    // To be called on the same packet that created the ChanEventMaker.
    pub fn make<'p>(&self, packet: Packet<'p>) -> Option<ChanEvent<'p>> {
        match self {
            // Datain is handled at the traffic level, not propagated as an Event
            Self::DataIn(_) => {
                debug!("DataIn should not be reached");
                None
            }
            Self::OpenSuccess { num } => Some(ChanEvent::OpenSuccess { num: *num }),
            Self::Req => {
                if let Packet::ChannelRequest(ChannelRequest { num, want_reply, req }) = packet {
                    match req {
                        ChannelReqType::Pty(pty) => Some(ChanEvent::ReqPty { num, want_reply, pty }),
                        _ => {
                            warn!("Unhandled {:?}", self);
                            None
                        }
                    }
                } else {
                    // TODO: return a bug result?
                    warn!("Req event maker but not request packet");
                    None
                }
            }
            Self::Eof { num } => Some(ChanEvent::Eof { num: *num }),
            Self::Close { num } => Some(ChanEvent::Close { num: *num }),
        }

    }
}

struct PendInput {
    chan: u32,
    len: usize,
}
