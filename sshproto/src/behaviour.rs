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

use heapless::spsc::{Queue,Producer,Consumer};

use crate::*;
use crate::packets::{self,Packet};
use crate::runner::{self,Runner};


use mailbox::Mailbox;

// TODO: "Bh" is an ugly abbreviation. Naming is hard.

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub type BhResult<T> = core::result::Result<T, BhError>;

#[derive(Debug,Snafu)]
pub enum BhError {
    Fail,
    #[doc(hidden)]
    Unimplemented,
}

#[cfg(feature = "tokio-queue")]
pub type ReplyChannel = bhtokio::ReplyChannel;

// TODO: once async functions in traits work with no_std, this can all be reworked
// to have Queryer and Responder traits. For now we use #[cfg] for dispatch.

// TODO: should have client or server specific BhQuerys
pub struct Requests {
    #[cfg(feature = "tokio-queue")]
    req: crate::bhtokio::Responder,
}

impl Requests {
    pub async fn next_query(&self) -> BhResult<ReplyChannel> {
        self.req.next_query().await
    }
}

pub(crate) struct Behaviour {
    #[cfg(feature = "tokio-queue")]
    req: crate::bhtokio::Queryer,
    is_client: bool,
}

impl Behaviour {
    async fn query(&self, q: BhQuery) -> BhResult<BhQuery> {
        self.req.query(q).await
    }

    fn client(&self) -> Result<ClientBehaviour> {
        if self.is_client {
            Ok(ClientBehaviour { b: self })
        } else {
            Err(Error::bug())
        }
    }
}

pub(crate) struct ClientBehaviour<'a> {
    pub b: &'a Behaviour,
}

impl ClientBehaviour {
    // TODO async?
    fn show_banner(&

}

/// A stack-allocated string to store responses for usernames or passwords.
// 100 bytes is an arbitrary size.
pub type ResponseString = heapless::String<100>;

// pub struct HookQuery {
//     pub query: Query,
//     responded: bool,

//     resp_q: Queue<Query, 2>,

//     // waker for the library. The app gets awoken from runner.
//     waker: Option<Waker>,
// }

// pub struct HookMailbox {
//     pub query: Option<HookQuery>,
//     pub(crate) query_waker: Option<Waker>,
//     pub(crate) reply: Option<HookQuery>,
//     pub(crate) reply_waker: Option<Waker>,
// }

// TODO sketchy api. maybe the var shouldn't be pub.
pub enum BhQuery {
    Username(ResponseString),
}

pub enum BhCommand {
    Session(),
}

// not derived since it can hold passwords etc
impl fmt::Debug for BhQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Username(u) => {
                f.debug_struct("HookQuery::Username")
                .field("username", u)
                .finish()
            }
        }
    }
}

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

