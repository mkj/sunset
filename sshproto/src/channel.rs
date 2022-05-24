#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::mem;

use heapless::{String,Deque,Vec};

use crate::{*, conn::RespPackets};
use packets::{Packet,ChannelRequest,ChannelReqType};
use config::*;

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],
}

pub(crate) type InitReqs = Vec<ReqDetails, MAX_INIT_REQS>;

impl Channels {
    pub fn new() -> Self {
        Channels { ch: Default::default() }
    }

    pub fn open<'b>(
        &mut self, ty: packets::ChannelOpenType<'b>,
        init_req: InitReqs) -> Result<(&Channel, Packet<'b>)> {
        // first available channel
        let num = self
            .ch
            .iter()
            .enumerate()
            .find_map(
                |(i, ch)| if ch.as_ref().is_none() { Some(i as u32) } else { None },
            )
            .ok_or(Error::NoChannels)?;

        let chan = Channel {
            state: ChanState::Opening { init_req },
            ty: (&ty).into(),
            last_req: Deque::new(),
            recv: ChanDir {
                num,
                max_packet: config::DEFAULT_MAX_PACKET,
                window: config::DEFAULT_WINDOW,
            },
            send: None,
        };
        let p = packets::Packet::ChannelOpen(packets::ChannelOpen {
            num,
            initial_window: chan.recv.window as u32,
            max_packet: chan.recv.max_packet as u32,
            ch: ty,
        });
        let ch = &mut self.ch[num as usize];
        *ch = Some(chan);
        Ok((ch.as_ref().unwrap(), p))
    }

    fn get_chan(&mut self, num: u32) -> Result<&mut Channel> {
        self.ch
            .get_mut(num as usize)
            // out of range
            .ok_or(Error::BadChannel)?
            .as_mut()
            // unused channel
            .ok_or(Error::BadChannel)
    }

    fn remove(&mut self, num: u32) -> Result<()> {
        // TODO any checks?
        *self.ch .get_mut(num as usize).ok_or(Error::BadChannel)? = None;
        Ok(())
    }

    // incoming packet handling
    pub fn dispatch(&mut self, packet: &Packet, resp: &mut RespPackets) -> Result<()> {
        let r = match packet {
            Packet::ChannelOpen(_p) => {
                todo!();
            }
            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_chan(p.num)?;
                match ch.state {
                    ChanState::Opening {..} => {
                        let init_state = mem::replace(&mut ch.state, ChanState::Normal);
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
                        Ok(())

                    }
                    _ => Err(Error::SSHProtoError),
                }
            }
            Packet::ChannelOpenFailure(p) => {
                let ch = self.get_chan(p.num)?;
                if ch.send.is_some() {
                    Err(Error::SSHProtoError)
                } else {
                    self.remove(p.num)
                }
            }
            Packet::ChannelWindowAdjust(_p) => {
                todo!();
            }
            Packet::ChannelData(_p) => {
                todo!();
            }
            Packet::ChannelDataExt(_p) => {
                todo!();
            }
            Packet::ChannelEof(_p) => {
                todo!();
            }
            Packet::ChannelClose(_p) => {
                todo!();
            }
            Packet::ChannelRequest(_p) => {
                todo!();
            }
            Packet::ChannelSuccess(_p) => {
                trace!("channel success, TODO");
                Ok(())
            }
            Packet::ChannelFailure(_p) => {
                todo!();
            }
            _ => unreachable!(),
        };
        match r {
            Err(Error::BadChannel) => {
                warn!("Ignoring bad channel number");
                Ok(())
            }
            // TODO: close channel on error? or on SSHProtoError?
            any => any,
        }
    }
}

pub enum ChanType {
    Session,
}

impl From<&packets::ChannelOpenType<'_>> for ChanType {
    fn from(c: &packets::ChannelOpenType<'_>) -> Self {
        match c {
            packets::ChannelOpenType::Session => ChanType::Session,
            packets::ChannelOpenType::DirectTcpip(_) => todo!(),
            packets::ChannelOpenType::ForwardedTcpip(_) => todo!(),
            packets::ChannelOpenType::Unknown(_) => unreachable!(),
        }
    }
}

#[derive(Debug)]
struct ModePair {
    opcode: u8,
    arg: u32,
}

#[derive(Debug)]
pub struct Pty {
    // or could we put String into packets::Pty and serialize modes there...
    term: String<MAX_TERM>,
    cols: u32,
    rows: u32,
    width: u32,
    height: u32,
    // TODO: perhaps we need something serializable here
    modes: Vec<ModePair, {termmodes::NUM_MODES}>,
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
pub(crate) struct Req {
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
            ReqDetails::Shell => {
                ChannelReqType::Shell
            }
            ReqDetails::Pty(_pty) => {
                todo!("serialize modes")
            }
            ReqDetails::Exec(cmd) => {
                ChannelReqType::Exec(packets::Exec {command: &cmd})
            }
            ReqDetails::WinChange(rt) => {
                ChannelReqType::WinChange(rt.clone())
            }
            ReqDetails::Break(rt) => {
                ChannelReqType::Break(rt.clone())
            }
        };
        let p = Packet::ChannelRequest(ChannelRequest {
            num,
            want_reply,
            ch: ty,
        });
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

pub struct ChanDir {
    num: u32,
    max_packet: usize,
    window: usize,
}

pub enum ChanState {
    // TODO: this is wasting half a kB. where else could we store it?
    Opening { init_req: InitReqs },
    Normal,
    DrainRead,
    DrainWrite,
}

pub struct Channel {
    ty: ChanType,
    state: ChanState,
    // queue of requests sent with want_reply
    last_req: heapless::Deque<ReqKind, MAX_OUTSTANDING_REQS>,

    recv: ChanDir,
    // filled after confirmation
    send: Option<ChanDir>,
}

impl Channel {
    fn request(&mut self, req: ReqDetails, resp: &mut RespPackets) -> Result<()> {
        let num = self.send.as_ref().trap()?.num;
        let r = Req {num, details: req };
        resp.push(r.into()).trap()?;
        Ok(())
    }

    pub(crate) fn number(&self) -> u32 {
        self.recv.num
    }
}

pub enum ChanMsg<'a> {
    Data(&'a [u8]),
    ExtData { ext: u32, data: &'a [u8] },
    // TODO: perhaps we don't need the storaged ReqDetails, just have the reqtype packet?
    Req(ReqDetails),
    // TODO closein/closeout/eof, etc. Should also return the exit status etc
    Close,
}

pub enum ChanOut {
    // Size written into [`channel_output()`](runner::Runner::channel_output)
    // `buf` argument.
    Data(usize),
    // Size written into [`channel_output()`](runner::Runner::channel_output)
    // `buf` argument.
    ExtData { ext: u32, size: usize },
    // TODO: perhaps we don't need the storaged ReqDetails, just have the reqtype packet?
    Req(ReqDetails),
    // TODO closein/closeout/eof, etc. Should also return the exit status etc

    // TODO: responses to a previous ChanMsg

    Close,
}
