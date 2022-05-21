#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::{String,Deque,Vec};

use crate::{*, conn::RespPackets};
use packets::{Packet,ChannelRequest,ChannelReqType};
use config::*;

pub(crate) struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],
}

impl Channels {
    pub fn new() -> Self {
        Channels { ch: Default::default() }
    }

    pub fn open<'b>(
        &mut self, ty: packets::ChannelOpenType<'b>,
        then: ReqDetails) -> Result<(&Channel, Packet<'b>)> {
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
            state: ChanState::Normal,
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
    pub fn dispatch(&mut self, packet: &Packet) -> Result<()> {
        let r = match packet {
            Packet::ChannelOpen(_p) => {
                todo!();
            }
            Packet::ChannelOpenConfirmation(p) => {
                let ch = self.get_chan(p.num)?;
                if ch.send.is_none() {
                    ch.send = Some(ChanDir {
                        num: p.sender_num,
                        max_packet: p.max_packet as usize,
                        window: p.initial_window as usize,
                    });
                    Ok(())
                } else {
                    debug!("Duplicate open confirmation");
                    Err(Error::SSHProtoError)
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
                todo!();
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

/// Like a `packets::ChannelReqType` but with storage.
/// Lifetime-free variants have the packet part directly.
#[derive(Debug)]
pub enum ReqDetails {
    // TODO let hook impls provide a string type?
    Shell,
    Exec(heapless::String<MAX_EXEC>),
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

impl Req {
    pub(crate) fn packet<'a>(&'a self) -> Result<Packet<'a>> {
        let p = match &self.details {
            ReqDetails::Shell => {
                // let np = if pty.is_some() { 2 } else { 1 };
                // if self.last_req
                // TODO put it in last_req, validating space free
                Packet::ChannelRequest(ChannelRequest {
                    num: self.num,
                    want_reply: true,
                    ch: ChannelReqType::Shell,
                })
            }
            ReqDetails::Pty(_pty) => {
                todo!("serialize modes")
            }
            ReqDetails::Exec(cmd) => {
                Packet::ChannelRequest(ChannelRequest {
                    num: self.num,
                    want_reply: true,
                    ch: ChannelReqType::Exec(packets::Exec {command: &cmd}),
                })
            }
            ReqDetails::WinChange(rt) => {
                Packet::ChannelRequest(ChannelRequest {
                    num: self.num,
                    want_reply: false,
                    ch: ChannelReqType::WinChange(rt.clone()),
                })
            }
            ReqDetails::Break(rt) => {
                Packet::ChannelRequest(ChannelRequest {
                    num: self.num,
                    want_reply: true,
                    ch: ChannelReqType::Break(rt.clone()),
                })
            }
        };
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

pub struct ChanDir {
    num: u32,
    max_packet: usize,
    window: usize,
}

pub enum ChanState {
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
        // if self.last_req.is_some() {
        //     return Err(Error::bug());
        // }
        // let p = match req {
        //     Pty => {
        //         todo!()
        //         // packets::Packet(packets::Chan
        //     }
        // };
        // Ok(p)
        todo!()
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
    Close,
}
