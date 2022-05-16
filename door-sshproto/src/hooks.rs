#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;
use core::task::{Waker,Poll};
use core::future::Future;
use core::mem;

use heapless::spsc::{Queue,Producer,Consumer};

use crate::packets::{self,Packet};
use crate::runner::{self,Runner};

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub type HookResult<T> = core::result::Result<T, HookError>;

#[derive(Debug,Snafu)]
pub enum HookError {
    Fail,
    #[doc(hidden)]
    Unimplemented,
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

pub(crate) struct HookMailbox {
    pub query: Query,
    pub(crate) reply: Option<Query>,
    pub(crate) waker: Option<Waker>,
}

impl core::future::Future for HookMailbox {
    type Output = Query;
    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        let m = self.get_mut();
        if let Some(reply) = m.reply.take() {
            Poll::Ready(reply)
        } else {
            m.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

// TODO sketchy api. maybe the var shouldn't be pub.
pub enum Query {
    Username(ResponseString),
    Unset,
}

// perhaps should be called mailbox
impl<'a> HookMailbox {
    pub(crate) fn new() -> Self {
        Self {
            query: Query::Unset,
            reply: None,
            waker: None
        }
    }

    pub(crate) fn set(&mut self, query: Query) -> Result<()> {
        if self.waker.is_some() {
            Error::bug_msg("Waker should not be set")?
        }
        if !matches!(self.query, Query::Unset) {
            Error::bug_msg("last query wasn't consumed")?;
        }
        self.query = query;
        self.reply = None;

        Ok(())
    }

    pub fn reply(&mut self, reply: Query) -> Result<()> {
        // TODO: check discriminants match for query/reply
        self.reply = Some(reply);
        self.waker.take().map(|w| w.wake());
        Ok(())
    }

}

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

