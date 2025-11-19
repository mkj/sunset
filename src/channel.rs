use self::packets::ExitSignal;

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::num::NonZeroUsize;
use core::task::Waker;
use core::{marker::PhantomData, mem};

use heapless::{Deque, String, Vec};

use crate::{runner::set_waker, *};
use config::*;
use conn::DispatchEvent;
use conn::Dispatched;
use event::{CliEventId, ServEventId};
use packets::{
    ChannelData, ChannelDataExt, ChannelOpen, ChannelOpenFailure, ChannelOpenType,
    ChannelReqType, ChannelRequest, Packet,
};
use runner::ChanHandle;
use sshnames::*;
use sshwire::{BinString, SSHEncodeEnum, TextString};
use traffic::TrafSend;

use snafu::ErrorCompat;

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],
    is_client: bool,
}

impl Channels {
    pub fn new(is_client: bool) -> Self {
        Channels { ch: Default::default(), is_client }
    }

    pub fn open<'b>(
        &mut self,
        ty: packets::ChannelOpenType<'b>,
    ) -> Result<(ChanNum, Packet<'b>)> {
        let num = self.unused_chan()?;

        let chan = Channel::new(num, (&ty).into());
        let p = packets::ChannelOpen {
            sender_num: num.0,
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
    pub(crate) fn get(&self, num: ChanNum) -> Result<&Channel> {
        let ch = self.get_any(num)?;

        match ch.state {
            ChanState::InOpen | ChanState::Opening { .. } => {
                error::BadChannel { num }.fail()
            }
            _ => Ok(ch),
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
            ChanState::InOpen | ChanState::Opening { .. } => {
                error::BadChannel { num }.fail()
            }
            _ => Ok(ch),
        }
    }

    pub fn _from_handle(&self, handle: &ChanHandle) -> &Channel {
        self.get(handle.0).unwrap()
    }

    pub fn from_handle_mut(&mut self, handle: &ChanHandle) -> &mut Channel {
        self.get_mut(handle.0).unwrap()
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
            .find_map(|(i, ch)| {
                if ch.as_ref().is_none() {
                    Some(ChanNum(i as u32))
                } else {
                    None
                }
            })
            .ok_or(Error::NoChannels)
    }

    /// Creates a new channel in InOpen state.
    fn reserve_chan(&mut self, co: &ChannelOpen) -> Result<&mut Channel> {
        let num = self.unused_chan()?;
        let mut chan = Channel::new(num, (&co.ty).into());
        chan.send = Some(ChanDir {
            num: co.sender_num,
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
            trace!(
                "data len {}, max {}, window {}",
                data.len(),
                send.max_packet,
                send.window
            );
            return Err(Error::bug());
        }
        send.window -= data.len();
        trace!("send_data: new window {}", send.window);

        let data = BinString(data);
        let p = match dt {
            ChanData::Normal => packets::ChannelData { num: send.num, data }.into(),
            ChanData::Stderr => packets::ChannelDataExt {
                num: send.num,
                code: sshnames::SSH_EXTENDED_DATA_STDERR,
                data,
            }
            .into(),
        };

        Ok(p)
    }

    /// Informs the channel layer that an incoming packet has been read out,
    /// so a window adjustment can be sent.
    pub(crate) fn finished_read(
        &mut self,
        num: ChanNum,
        len: usize,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get_mut(num)?;
        ch.finished_input(len);
        if let Some(w) = ch.check_window_adjust()? {
            // The send buffer may be full. Ignore the failure and hope another adjustment is
            // sent later. TODO improve this.
            match s.send(w) {
                Ok(_) => ch.pending_adjust = 0,
                Err(Error::NoRoom { .. }) => {
                    // TODO better retry rather than hoping a retry occurs
                    debug!("noroom for adjustment")
                }
                error => return error,
            }
        }
        Ok(())
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

    /// Wake the channel with a ready input data packet.
    pub fn wake_read(&mut self, num: ChanNum, dt: ChanData, is_client: bool) {
        if let Ok(ch) = self.get_mut(num) {
            ch.wake_read(dt, is_client);
        } else {
            debug_assert!(false, "wake_read bad channel");
        }
    }

    /// Wake all ready output channels
    pub fn wake_write(&mut self, is_client: bool) {
        for ch in self.ch.iter_mut().filter_map(|c| c.as_mut()) {
            ch.wake_write(None, is_client)
        }
    }

    pub(crate) fn term_window_change(
        &self,
        num: ChanNum,
        winch: &packets::WinChange,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get(num)?;
        match ch.ty {
            ChanType::Session => Req::WinChange(winch.clone()).send(ch, s),
            _ => error::BadChannelData.fail(),
        }
    }

    pub(crate) fn term_break(
        &self,
        num: ChanNum,
        length: u32,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get(num)?;
        let br = packets::Break {
            length: if length == 0 { 0 } else { length.clamp(500, 3000) },
        };
        match ch.ty {
            ChanType::Session => Req::Break(br).send(ch, s),
            _ => error::BadChannelData.fail(),
        }
    }

    fn dispatch_open(
        &mut self,
        p: &ChannelOpen<'_>,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        match self.dispatch_open_inner(p) {
            Err(DispatchOpenError::Failure(f)) => {
                s.send(packets::ChannelOpenFailure {
                    num: p.sender_num,
                    reason: f as u32,
                    desc: "".into(),
                    lang: "",
                })?;
                Ok(DispatchEvent::None)
            }
            Err(DispatchOpenError::Error(e)) => Err(e),
            Ok(ev) => Ok(ev),
        }
    }

    // the caller will send failure messages if required
    fn dispatch_open_inner(
        &mut self,
        p: &ChannelOpen,
    ) -> Result<DispatchEvent, DispatchOpenError> {
        // Check validity before reserving a channel
        match &p.ty {
            ChannelOpenType::Unknown(u) => {
                error!("Rejecting unknown channel type '{u}'");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            ChannelOpenType::Session if self.is_client => {
                trace!("dispatch not server");
                return Err(error::SSHProto.build().into());
            }
            ChannelOpenType::ForwardedTcpip(_) => {
                // TODO implement it
                debug!("Rejecting forwarded tcp");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            ChannelOpenType::DirectTcpip(_) => {
                // TODO implement it
                debug!("Rejecting direct tcp");
                return Err(ChanFail::SSH_OPEN_UNKNOWN_CHANNEL_TYPE.into());
            }
            _ => (),
        }

        // Reserve a channel
        let ch = self.reserve_chan(p)?;

        // Beware that a reserved channel must be cleaned up on failure

        match &p.ty {
            ChannelOpenType::Session => {
                Ok(DispatchEvent::ServEvent(ServEventId::OpenSession {
                    num: ch.num(),
                }))
            }
            // ChannelOpenType::ForwardedTcpip(t) => b.open_tcp_forwarded(handle, t),
            // ChannelOpenType::DirectTcpip(t) => b.open_tcp_direct(handle, t),
            _ => {
                // Checked above
                unreachable!()
            }
        }
    }

    pub fn resume_open(
        &mut self,
        c: ChanNum,
        failure: Option<ChanFail>,
        s: &mut TrafSend,
    ) -> Result<()> {
        let ch = self.get_any_mut(c)?;
        if let Some(failure) = failure {
            let sender_num = ch.send_num()?;
            self.remove_any(c)?;
            s.send(packets::ChannelOpenFailure {
                num: sender_num,
                reason: failure as u32,
                desc: "".into(),
                lang: "",
            })?;
            Ok(())
        } else {
            // Success
            s.send(ch.open_done()?)
        }
    }

    // Some returned errors will be caught by caller and returned as SSH messages
    fn dispatch_inner(
        &mut self,
        packet: Packet,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let mut ev = DispatchEvent::default();
        let is_client = self.is_client;

        match packet {
            Packet::ChannelOpen(p) => {
                ev = self.dispatch_open(&p, s)?;
            }

            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_any_mut(ChanNum(p.num))?;
                match ch.state {
                    ChanState::Opening => {
                        debug_assert!(ch.send.is_none());

                        if ch.app_done {
                            return Ok(DispatchEvent::None);
                        }

                        ch.send = Some(ChanDir {
                            num: p.sender_num,
                            max_packet: p.max_packet as usize,
                            window: p.initial_window as usize,
                        });

                        match ch.ty {
                            ChanType::Session => {
                                ev = DispatchEvent::CliEvent(
                                    CliEventId::SessionOpened(ch.num()),
                                );
                            }
                            ChanType::Tcp => {
                                trace!("TODO tcp channel")
                            }
                        }

                        ch.state = ChanState::Normal;
                    }
                    _ => {
                        trace!("Bad channel state {:?}", ch.state);
                        return error::SSHProto.fail();
                    }
                }
            }

            Packet::ChannelOpenFailure(p) => {
                let ch = self.get_any(ChanNum(p.num))?;
                if ch.send.is_some() {
                    // TODO: or just warn?
                    trace!("open failure late?");
                    return error::SSHProto.fail();
                } else {
                    self.remove(ChanNum(p.num))?;
                    // TODO event
                }
            }
            Packet::ChannelWindowAdjust(p) => {
                let chan = self.get_mut(ChanNum(p.num))?;
                let send = chan.send.as_mut().trap()?;
                send.window = send.window.saturating_add(p.adjust as usize);
                trace!("new window {}", send.window);
                // Wake any writers that might have been blocked.
                chan.wake_write(None, is_client);
            }
            Packet::ChannelData(p) => {
                let ch = self.get(ChanNum(p.num))?;
                if ch.app_done {
                    trace!("Ignoring data for done channel");
                } else if let Some(len) = NonZeroUsize::new(p.data.0.len()) {
                    // TODO check we are expecting input
                    let di =
                        DataIn { num: ChanNum(p.num), dt: ChanData::Normal, len };
                    ev = DispatchEvent::Data(di);
                } else {
                    trace!("Zero length channeldata");
                }
            }
            Packet::ChannelDataExt(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                if ch.app_done {
                    trace!("Ignoring data for done channel");
                } else if !is_client || p.code != sshnames::SSH_EXTENDED_DATA_STDERR
                {
                    // Discard the data, sunset can't handle this
                    debug!("Ignoring unexpected dt data, code {}", p.code);
                    ch.finished_input(p.data.0.len());
                } else {
                    if let Some(len) = NonZeroUsize::new(p.data.0.len()) {
                        // TODO check we are expecting input and dt is valid.
                        let di = DataIn {
                            num: ChanNum(p.num),
                            dt: ChanData::Stderr,
                            len,
                        };
                        ev = DispatchEvent::Data(di);
                    } else {
                        trace!("Zero length channeldataext");
                    }
                }
            }
            Packet::ChannelEof(p) => {
                let ch = self.get_mut(ChanNum(p.num))?;
                ch.handle_eof(s, is_client)?;
            }
            Packet::ChannelClose(p) => {
                let is_client = self.is_client;
                let ch = self.get_mut(ChanNum(p.num))?;
                ch.handle_close(s, is_client)?;
            }
            Packet::ChannelRequest(p) => {
                let is_client = self.is_client;
                match self.get_mut(ChanNum(p.num)) {
                    Ok(ch) => {
                        ev = ch.dispatch_request(&p, s, is_client);
                    }
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

        Ok(ev)
    }

    /// Incoming packet handling
    // TODO: protocol errors etc should perhaps be less fatal,
    // ssh implementations are usually imperfect.
    pub fn dispatch(
        &mut self,
        packet: Packet,
        s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        let r = self.dispatch_inner(packet, s);

        match r {
            Err(Error::BadChannel { num, .. }) => {
                warn!("Ignoring bad channel number {:?}", num);
                // warn!("Ignoring bad channel number {:?}", r.unwrap_err().backtrace());
                Ok(DispatchEvent::default())
            }
            // TODO: close channel on error? or on SSHProtoError?
            r => r,
        }
    }

    pub fn resume_chanreq(
        &self,
        p: &Packet,
        success: bool,
        s: &mut TrafSend,
    ) -> Result<()> {
        if let Packet::ChannelRequest(r) = p {
            let ch = self.get(ChanNum(r.num))?;
            if r.want_reply {
                let num = ch.send_num()?;
                if success {
                    s.send(packets::ChannelSuccess { num })
                } else {
                    s.send(packets::ChannelFailure { num })
                }
            } else {
                Ok(())
            }
        } else {
            Err(Error::bug())
        }
    }

    pub fn fetch_servcommand<'p>(&self, p: &Packet<'p>) -> Result<TextString<'p>> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::Exec(packets::Exec { command }),
                ..
            })
            | Packet::ChannelRequest(ChannelRequest {
                req:
                    ChannelReqType::Subsystem(packets::Subsystem { subsystem: command }),
                ..
            }) => Ok(command.clone()),
            _ => Err(Error::bug()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ChanType {
    Session,
    Tcp,
}

impl From<&ChannelOpenType<'_>> for ChanType {
    fn from(c: &ChannelOpenType) -> Self {
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
            Req::Subsystem(cmd) => ChannelReqType::Subsystem(packets::Subsystem {
                subsystem: cmd.into(),
            }),
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

impl<'a, S: AsRef<str> + 'a> From<&'a SessionCommand<S>> for Req<'a> {
    fn from(val: &'a SessionCommand<S>) -> Self {
        match val {
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

#[derive(Debug)]
pub(crate) struct Channel {
    ty: ChanType,
    state: ChanState,
    sent_eof: bool,
    sent_close: bool,

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

    // Wakers for notifying readyness. Usually used for async.
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    /// Will be a stderr read waker for a client, or stderr write waker for
    /// a server.
    ext_waker: Option<Waker>,
}

impl Channel {
    fn new(num: ChanNum, ty: ChanType) -> Self {
        Channel {
            ty,
            state: ChanState::Opening,
            sent_close: false,
            sent_eof: false,
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
            read_waker: None,
            write_waker: None,
            ext_waker: None,
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

    pub fn set_read_waker(&mut self, dt: ChanData, is_client: bool, waker: &Waker) {
        match dt {
            ChanData::Normal => {
                set_waker(&mut self.read_waker, waker);
            }
            ChanData::Stderr => {
                if is_client {
                    set_waker(&mut self.ext_waker, waker);
                } else {
                    debug_assert!(false, "server ext read waker");
                }
            }
        }
    }

    pub fn set_write_waker(&mut self, dt: ChanData, is_client: bool, waker: &Waker) {
        match dt {
            ChanData::Normal => {
                set_waker(&mut self.write_waker, waker);
            }
            ChanData::Stderr => {
                if !is_client {
                    set_waker(&mut self.ext_waker, waker);
                } else {
                    debug_assert!(false, "client ext write waker");
                }
            }
        }
    }

    pub fn wake_read(&mut self, dt: ChanData, is_client: bool) {
        match dt {
            ChanData::Normal => {
                self.read_waker.take().map(|w| w.wake());
            }
            ChanData::Stderr => {
                if is_client {
                    self.ext_waker.take().map(|w| w.wake());
                }
            }
        }
    }

    pub fn wake_write(&mut self, dt: Option<ChanData>, is_client: bool) {
        if dt == Some(ChanData::Normal) || dt == None {
            self.read_waker.take().map(|w| w.wake());
        }
        if !is_client && (dt == Some(ChanData::Normal) || dt == None) {
            self.ext_waker.take().map(|w| w.wake());
        }
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

    fn dispatch_request(
        &mut self,
        p: &packets::ChannelRequest,
        s: &mut TrafSend,
        is_client: bool,
    ) -> DispatchEvent {
        let r = match (is_client, self.app_done) {
            // Reject requests if the application has closed
            // the channel. ChannelEOF is arbitrary.
            (_, true) => Err(Error::ChannelEOF),
            (true, _) => self.dispatch_client_request(p, s),
            (false, _) => self.dispatch_server_request(p, s),
        };

        r.unwrap_or_else(|_| {
            // All errors just send an error response, no failure.
            if p.want_reply {
                let num = self.send_num();
                debug_assert!(num.is_ok());
                if let Ok(num) = num {
                    let _ = s.send(packets::ChannelFailure { num });
                }
            }
            DispatchEvent::None
        })
    }

    fn dispatch_server_request(
        &self,
        p: &packets::ChannelRequest,
        _s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        if !matches!(self.ty, ChanType::Session) {
            return Err(Error::SSHProtoUnsupported);
        }

        let num = self.num();
        match &p.req {
            ChannelReqType::Shell => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionShell { num }))
            }
            ChannelReqType::Exec(_) => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionExec { num }))
            }
            ChannelReqType::Subsystem(_) => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionSubsystem { num }))
            }
            ChannelReqType::Pty(_) => {
                Ok(DispatchEvent::ServEvent(ServEventId::SessionPty { num }))
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
                Err(Error::SSHProtoUnsupported)
            }
        }
    }

    /// Returns Ok(want_reply: bool) on success
    fn dispatch_client_request(
        &mut self,
        p: &packets::ChannelRequest,
        _s: &mut TrafSend,
    ) -> Result<DispatchEvent> {
        if !matches!(self.ty, ChanType::Session) {
            return Err(Error::SSHProtoUnsupported);
        }

        match &p.req {
            ChannelReqType::ExitStatus(_) => {
                Ok(DispatchEvent::CliEvent(CliEventId::SessionExit))
            }
            ChannelReqType::ExitSignal(_sig) => {
                Ok(DispatchEvent::CliEvent(CliEventId::SessionExit))
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
                Err(Error::SSHProtoUnsupported)
            }
        }
    }

    fn handle_eof(&mut self, s: &mut TrafSend, is_client: bool) -> Result<()> {
        //TODO: check existing state?
        if !self.sent_eof {
            s.send(packets::ChannelEof { num: self.send_num()? })?;
            self.sent_eof = true;
        }

        // Wake readers on EOF
        self.wake_read(ChanData::Normal, is_client);
        if is_client {
            self.wake_read(ChanData::Stderr, is_client);
        }

        self.state = ChanState::RecvEof;
        // todo!();
        Ok(())
    }

    fn handle_close(&mut self, s: &mut TrafSend, is_client: bool) -> Result<()> {
        //TODO: check existing state?
        if !self.sent_close {
            s.send(packets::ChannelClose { num: self.send_num()? })?;
            self.sent_close = true;
        }

        // Wake readers and writers on EOF
        self.wake_read(ChanData::Normal, is_client);
        if is_client {
            self.wake_read(ChanData::Stderr, is_client);
        }
        self.wake_write(None, is_client);

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
    ///
    /// Does not reset the adjustment to 0, should be done by caller on successful send.
    fn check_window_adjust(&self) -> Result<Option<Packet<'_>>> {
        let num = self.send.as_ref().trap()?.num;
        if self.pending_adjust > self.full_window / 2 {
            let adjust = self.pending_adjust as u32;
            let p = packets::ChannelWindowAdjust { num, adjust }.into();
            Ok(Some(p))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DataIn {
    pub num: ChanNum,
    pub dt: ChanData,
    // Zero length data does nothing.
    pub len: NonZeroUsize,
}

/// The result of a channel open request.
pub enum ChanOpened {
    Success,
    /// A channel open response will be sent later (for eg TCP open)
    Defer,
    /// A SSH failure code, as well as returning the passed channel handle
    Failure((ChanFail, ChanHandle)),
}

/// A SSH protocol local channel number
///
/// The number will always be in the range `0 <= num < MAX_CHANNELS`
/// and can be used as an index by applications.
/// Most external application API methods take a `ChanHandle` instead.
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Ord, PartialOrd)]
pub struct ChanNum(pub u32);

impl core::fmt::Display for ChanNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Channel data type, normal or stderr
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ChanData {
    /// `SSH_MSG_CHANNEL_DATA`
    Normal,
    /// `SSH_MSG_CHANNEL_EXTENDED_DATA`. Only `Stderr` is implemented by Sunset,
    /// other types are not widely used.
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

// constructed from runner::cli_session_opener()
/// Sends shell, command, or other requests to a newly opened session channel
pub struct CliSessionOpener<'g, 'a> {
    pub(crate) ch: &'g Channel,
    pub(crate) s: TrafSend<'g, 'a>,
}

impl<'g, 'a> CliSessionOpener<'g, 'a> {
    /// Returns the channel associated with this session.
    ///
    /// This will match that previously returned from [`Runner::cli_session_opener`]
    /// or `SSHClient::open_session_pty()` (or `_nopty()`)
    pub fn channel(&self) -> ChanNum {
        self.ch.num()
    }

    /// Requests a Pseudo-TTY for the channel.
    ///
    /// This must be sent prior to requesting a shell or command.
    /// Shells using a PTY will only receive data on the stdin FD, not stderr.

    // TODO: set a flag in the channel so that it drops data on stderr, to
    // avoid waiting forever for a consumer?
    pub fn pty(&mut self, pty: channel::Pty) -> Result<()> {
        self.send(Req::Pty(pty))
    }

    /// Requests a particular command or shell for a channel
    pub fn cmd<S: AsRef<str>>(&mut self, cmd: &SessionCommand<S>) -> Result<()> {
        self.send(cmd.into())
    }

    pub fn shell(&mut self) -> Result<()> {
        self.send(Req::Shell)
    }

    pub fn exec(&mut self, cmd: impl AsRef<str>) -> Result<()> {
        self.send(Req::Exec(cmd.as_ref()))
    }

    pub fn subsystem(&mut self, cmd: impl AsRef<str>) -> Result<()> {
        self.send(Req::Subsystem(cmd.as_ref()))
    }

    fn send(&mut self, req: Req) -> Result<()> {
        req.send(self.ch, &mut self.s)
    }
}

impl core::fmt::Debug for CliSessionOpener<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CliSessionOpener").finish()
    }
}

#[derive(Debug)]
pub enum CliSessionExit<'g> {
    /// Remote process exited with an exit status code
    Status(u32),
    /// Remote process exited by signal
    Signal(ExitSignal<'g>),
}

impl<'g> CliSessionExit<'g> {
    pub fn new(p: &Packet<'g>) -> Result<Self> {
        match p {
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::ExitStatus(e),
                ..
            }) => Ok(Self::Status(e.status)),
            Packet::ChannelRequest(ChannelRequest {
                req: ChannelReqType::ExitSignal(e),
                ..
            }) => Ok(Self::Signal(e.clone())),
            _ => Err(Error::bug()),
        }
    }
}
