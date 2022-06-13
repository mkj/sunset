#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;
use core::task::{Waker,Poll};
use core::future::Future;
use core::mem;
use core::fmt;
use core::marker::PhantomData;

use heapless::spsc::{Queue,Producer,Consumer};

use crate::*;
use packets::{self,Packet};
use runner::{self,Runner};
use channel::ChanMsg;
use conn::RespPackets;
use sshwire::TextString;

// TODO: "Bh" is an ugly abbreviation. Naming is hard.

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub type BhResult<T> = core::result::Result<T, BhError>;

#[derive(Debug,Snafu)]
pub enum BhError {
    Fail,
}

#[cfg(feature = "tokio-queue")]
pub type ReplyChannel = bhtokio::ReplyChannel;

// TODO: once async functions in traits work with no_std, this can all be reworked
// to probably have Behaviour as a trait not a struct.
//  Tracking Issue for static async fn in traits
// https://github.com/rust-lang/rust/issues/91611

// Even without no_std async functions in traits we could probably make Behaviour
// a type alias to 'impl AsyncBehaviour" on std, and a wrapper struct on no_std.
// That will require
// Permit impl Trait in type aliases
// https://github.com/rust-lang/rust/issues/63063

pub struct Behaviour<'a> {
    #[cfg(feature = "std")]
    inner: crate::async_behaviour::AsyncCliServ,
    #[cfg(not(feature = "std"))]
    inner: crate::block_behaviour::BlockCliServ<'a>,

    pub phantom: PhantomData<&'a ()>,
}

#[cfg(feature = "std")]
impl Behaviour<'_> {
    pub fn new_async_client(b: std::boxed::Box<dyn async_behaviour::AsyncCliBehaviour + Send>) -> Self {
        Self {
            inner: async_behaviour::AsyncCliServ::Client(b),
            phantom: PhantomData::default(),
        }
    }

    pub fn new_async_server(b: std::boxed::Box<dyn async_behaviour::AsyncServBehaviour + Send>) -> Self {
        Self {
            inner: async_behaviour::AsyncCliServ::Server(b),
            phantom: PhantomData::default(),
        }
    }

    pub(crate) fn progress(&mut self, runner: &mut Runner) -> Result<()> {
        self.inner.progress(runner)
    }

    pub(crate) async fn chan_handler(&mut self, resp: &mut RespPackets<'_>, chan_msg: ChanMsg) -> Result<()> {
        self.inner.chan_handler(resp, chan_msg).await
    }

    // TODO: or should we just pass CliBehaviour and ServBehaviour through runner,
    // don't switch here at all
    pub(crate) fn client(&mut self) -> Result<CliBehaviour> {
        self.inner.client()
    }
    pub(crate) fn server(&mut self) -> Result<ServBehaviour> {
        self.inner.server()
    }
}

#[cfg(not(feature = "std"))]
impl<'a> Behaviour<'a>
{
    pub fn new_blocking_client(b: &'a mut dyn BlockCliBehaviour) -> Self {
        Self {
            inner: block_behaviour::BlockCliServ::Client(b),
            phantom: PhantomData::default(),
        }
    }

    pub fn new_blocking_server(b: &'a mut dyn BlockServBehaviour) -> Self {
        Self {
            inner: block_behaviour::BlockCliServ::Server(b),
            phantom: PhantomData::default(),
        }
    }
    pub(crate) fn progress(&mut self, runner: &mut Runner) -> Result<()> {
        self.inner.progress(runner)
    }

    pub(crate) async fn chan_handler(&mut self, resp: &mut RespPackets<'_>, chan_msg: ChanMsg) -> Result<()> {
        self.inner.chan_handler(resp, chan_msg)
    }

    // TODO: or should we just pass CliBehaviour and ServBehaviour through runner,
    // don't switch here at all
    pub(crate) fn client(&mut self) -> Result<CliBehaviour> {
        self.inner.client()
    }
    pub(crate) fn server(&mut self) -> Result<ServBehaviour> {
        self.inner.server()
    }
}

pub struct CliBehaviour<'a> {
    #[cfg(feature = "std")]
    pub inner: &'a mut dyn async_behaviour::AsyncCliBehaviour,
    #[cfg(not(feature = "std"))]
    pub inner: &'a mut dyn block_behaviour::BlockCliBehaviour,
    // pub phantom: core::marker::PhantomData<&'a ()>,
}

// wraps everything in AsyncCliBehaviour
#[cfg(feature = "std")]
impl<'a> CliBehaviour<'a> {
    pub(crate) async fn username(&mut self) -> BhResult<ResponseString>{
        self.inner.username().await
    }

    pub(crate) async fn valid_hostkey<'f>(&mut self, key: &PubKey<'f>) -> BhResult<bool> {
        self.inner.valid_hostkey(key).await
    }

    #[allow(unused)]
    pub(crate) async fn auth_password(&mut self, pwbuf: &mut ResponseString) -> BhResult<bool> {
        self.inner.auth_password(pwbuf).await
    }

    pub(crate) async fn next_authkey(&mut self) -> BhResult<Option<sign::SignKey>> {
        self.inner.next_authkey().await
    }

    pub(crate) async fn authenticated(&mut self) {
        self.inner.authenticated().await
    }

    pub(crate) async fn show_banner(&self, banner: TextString<'_>, language: TextString<'_>) -> Result<()> {
        let banner = banner.as_str().map_err(|e| { warn!("Bad banner {:?}", banner); e})?;
        let language = language.as_str()?;
        self.inner.show_banner(banner, language).await;
        Ok(())
    }
}

// no-std blocking variant
#[cfg(not(feature = "std"))]
impl<'a> CliBehaviour<'a> {
    pub(crate) async fn username(&mut self) -> BhResult<ResponseString>{
        self.inner.username()
    }

    pub(crate) async fn valid_hostkey<'f>(&mut self, key: &PubKey<'f>) -> BhResult<bool> {
        self.inner.valid_hostkey(key)
    }

    #[allow(unused)]
    pub(crate) async fn auth_password(&mut self, pwbuf: &mut ResponseString) -> BhResult<bool> {
        self.inner.auth_password(pwbuf)
    }

    pub(crate) async fn next_authkey(&mut self) -> BhResult<Option<sign::SignKey>> {
        self.inner.next_authkey()
    }

    pub(crate) async fn authenticated(&mut self) {
        self.inner.authenticated()
    }

    // TODO: make ascii/utf8 a feature
    pub(crate) async fn show_banner(&self, banner: TextString<'_>, language: TextString<'_>) -> Result<()> {
        let banner = banner.as_ascii().map_err(|e| { warn!("Bad banner {:?}", banner); e})?;
        let language = language.as_ascii()?;
        self.inner.show_banner(banner, language);
        Ok(())
    }
}

pub struct ServBehaviour<'a> {
    #[cfg(feature = "std")]
    pub inner: &'a mut dyn async_behaviour::AsyncServBehaviour,
    #[cfg(not(feature = "std"))]
    pub inner: &'a mut dyn block_behaviour::BlockServBehaviour,
    pub phantom: core::marker::PhantomData<&'a ()>,
}

#[cfg(feature = "std")]
impl<'a> ServBehaviour<'a> {

}
/// A stack-allocated string to store responses for usernames or passwords.
// 100 bytes is an arbitrary size.
pub type ResponseString = heapless::String<100>;

// // TODO sketchy api
// pub enum BhQuery<'a> {
//     Username(ResponseString),
//     ValidHostkey(PubKey<'a>),
//     Password(PubKey<'a>),
// }

// pub enum BhCommand {
//     Session(),
// }

// // not derived since it can hold passwords etc
// impl fmt::Debug for BhQuery<'_> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "Query ...todo...")
//     }
// }

// pub struct HookAskFut<'a> {
//     mbox: &'a mut HookMailbox,
// }

// impl<'a> core::future::Future for HookAskFut<'a> {
//     type Output = HookQuery;
//     fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
//         let m = &mut self.get_mut().mbox;
//         if let Some(reply) = m.reply.take() {
//             Poll::Ready(reply)
//         } else {
//             m.reply_waker.take().map(|w| {
//                 // this shouldn't happen?
//                 warn!("existing waker");
//                 w.wake()
//             });
//             m.reply_waker = Some(cx.waker().clone());
//             Poll::Pending
//         }
//     }
// }

// impl core::future::Future for HookMailbox {
//     type Output = HookQuery;
//     fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
//         let m = self.get_mut();
//         if let Some(reply) = m.reply.take() {
//             Poll::Ready(reply)
//         } else {
//             m.reply_waker.take().map(|w| {
//                 // this shouldn't happen?
//                 warn!("existing waker");
//                 w.wake()
//             });
//             m.reply_waker = Some(cx.waker().clone());
//             Poll::Pending
//         }
//     }
// }


// struct HookCon<'a> {
//     c: Consumer<'a, Query, 2>,
// }

// impl<'a> Future for HookCon<'a> {
//     type Output = Query;
//     fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> Poll<Self::Output> {
//         if let Some(r) = self.c.dequeue() {
//             Poll::Ready(r)
//         } else {
//             // TODO
//             // assert!(self.waker.is_none());
//             // self.waker = Some(cx.waker().clone());
//             Poll::Pending
//         }
//     }
// }

