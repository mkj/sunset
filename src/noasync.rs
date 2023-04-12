#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use crate::*;

use core::task::{Context, Poll};
use core::future::Future;

pub struct PendingAwait;

/// Runs an async function that is not expected to `.await`.
///
/// Returns `Err(PendingAwait)` if the Future attempts to perform an asynchronous operation.
/// This is intended to be used by non-async applications to wrap a call to [`Runner::progress()`],
/// where all [`CliBehaviour`] or [`ServBehaviour`] callback implementations are known to be non-awaiting.
pub fn non_async<F>(f: F) -> Result<F::Output, PendingAwait> where F: Future {
    futures::pin_mut!(f);

    let w = futures::task::noop_waker();

    match f.poll(&mut Context::from_waker(&w)) {
        Poll::Ready(r) => Ok(r),
        Poll::Pending => Err(PendingAwait),
    }
}
