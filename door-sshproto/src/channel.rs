#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use heapless::{String,Deque};

use crate::*;
use packets::Packet;
use config::*;

pub struct Channels {
    ch: [Option<Channel>; config::MAX_CHANNELS],
}

impl Channels {
    pub fn new() -> Self {
        Channels { ch: Default::default() }
    }

    pub fn open<'b>(
        &mut self, ty: packets::ChannelOpenType<'b>,
        then: packets::ChannelRequest) -> Result<(&Channel, Packet<'b>)> {
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
            last_req: None,
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
            Packet::ChannelOpen(p) => {
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
            Packet::ChannelWindowAdjust(p) => {
                todo!();
            }
            Packet::ChannelData(p) => {
                todo!();
            }
            Packet::ChannelDataExt(p) => {
                todo!();
            }
            Packet::ChannelEof(p) => {
                todo!();
            }
            Packet::ChannelClose(p) => {
                todo!();
            }
            Packet::ChannelRequest(p) => {
                todo!();
            }
            Packet::ChannelSuccess(p) => {
                todo!();
            }
            Packet::ChannelFailure(p) => {
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

pub enum Req {
    Pty,
}

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
    last_req: Option<Req>,

    recv: ChanDir,
    // filled after confirmation
    send: Option<ChanDir>,
}

impl Channel {
    fn request(&mut self, req: Req) -> Result<Packet> {
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

    pub(crate) fn request_pty(&mut self) -> Result<Packet> {
        if let ChanType::Session = self.ty {
            self.request(Req::Pty)
        } else {
            Err(Error::bug())
        }
    }
}
