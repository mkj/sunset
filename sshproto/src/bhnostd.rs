#![cfg(not(feature = "tokio-queue"))]

#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::*;
use crate::behaviour::*;

// TODO
const CAPACITY: usize = 1;

pub(crate) fn pair() -> (Queryer, Responder) {
    let (s, r) = mpsc::channel(CAPACITY);
    (Queryer { pipe: s }, Responder { pipe: r } )
}

pub(crate) struct Queryer {
    pipe: Sender,
}

impl Queryer {
    pub async fn query(&self, q: BhQuery) -> BhResult<BhQuery> {
        let (tx, rx) = oneshot::channel();
        self.pipe.send((q, tx)).await.trap()?;
        rx.await.trap()?
    }
}


pub(crate) struct Responder {
    pipe: Receiver,
}

impl Responder {
    pub async fn next_query(&self) -> BhResult<ReplyChannel> {
        let (query, tx) = self.pipe.recv().await;
        Ok(ReplyChannel::new(query, tx))
    }
}

pub struct ReplyChannel {
    query: BhQuery,
    query_disc: core::mem::Discriminant<BhQuery>,
    tx: ReplyTx,
}

impl ReplyChannel {
    fn new(query: BhQuery, tx: ReplyTx) -> Self {
        let query_disc = core::mem::discriminant(&query);
        Self {
            query,
            query_disc,
            tx,
        }
    }
    pub fn query(&self) -> &BhQuery {
        &self.query
    }

    pub fn reply(self, r: BhResult<BhQuery>) -> BhResult<()> {
        if let Ok(r) = r {
            let reply_disc = core::mem::discriminant(&r);
            if reply_disc != self.query_disc {
                warn!("Mismatch reply");
                let _ = self.tx.send(Err(BhError::Fail));
                return Err(BhError::Fail);
            }
        }
        self.tx.send(r).map_err(|_| BhError::Fail)
    }
}
