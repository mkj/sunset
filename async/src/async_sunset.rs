#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use core::future::{poll_fn, Future};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::task::{Context, Poll, Poll::Pending, Poll::Ready};

use embassy_futures::join;
use embassy_futures::select::select;
#[allow(unused_imports)]
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, NoopRawMutex};
use embassy_sync::mutex::{Mutex, MutexGuard};
use embassy_sync::signal::Signal;
use embassy_sync::waitqueue::WakerRegistration;
use embedded_io_async::{BufRead, Read, Write};

use pin_utils::pin_mut;

use sunset::config::MAX_CHANNELS;
use sunset::event::Event;
use sunset::{error, ChanData, ChanHandle, ChanNum, CliServ, Error, Result, Runner};

#[cfg(feature = "multi-thread")]
pub type SunsetRawMutex = CriticalSectionRawMutex;
#[cfg(not(feature = "multi-thread"))]
pub type SunsetRawMutex = NoopRawMutex;

pub type SunsetMutex<T> = Mutex<SunsetRawMutex, T>;

#[derive(Debug)]
struct Wakers {
    chan_read: [WakerRegistration; MAX_CHANNELS],

    chan_write: [WakerRegistration; MAX_CHANNELS],

    /// Will be a stderr read waker for a client, or stderr write waker for
    /// a server.
    chan_ext: [WakerRegistration; MAX_CHANNELS],

    // TODO: do we need a separate waker for this?
    chan_close: [WakerRegistration; MAX_CHANNELS],
}

struct Inner<'a, CS: CliServ> {
    runner: Runner<'a, CS>,

    wakers: Wakers,

    // May only be safely modified when the corresponding
    // `chan_refcounts` is zero.
    chan_handles: [Option<ChanHandle>; MAX_CHANNELS],
}

impl<'a, CS: CliServ> Inner<'a, CS> {
    /// Helper to lookup the corresponding ChanHandle
    ///
    /// Returns split references that will be required by many callers
    fn fetch(
        &mut self,
        num: ChanNum,
    ) -> Result<(&mut Runner<'a, CS>, &ChanHandle, &mut Wakers)> {
        let h = self
            .chan_handles
            .get(num.0 as usize)
            .ok_or(Error::BadChannel { num })?;
        h.as_ref()
            .map(|ch| (&mut self.runner, ch, &mut self.wakers))
            .ok_or_else(Error::bug)
    }
}

/// A handle used for storage from a [`SSHClient::progress()`](crate::SSHClient::progress)
/// or [`SSHServer::progress()`](crate::SSHServer::progress) call.
pub struct ProgressHolder<'g, 'a, CS: CliServ> {
    guard: Option<MutexGuard<'g, SunsetRawMutex, Inner<'a, CS>>>,
}

impl<'g, 'a, CS: CliServ> ProgressHolder<'g, 'a, CS> {
    pub fn new() -> Self {
        Self { guard: None }
    }
}

impl<CS: CliServ> Default for ProgressHolder<'_, '_, CS> {
    fn default() -> Self {
        Self::new()
    }
}

/// Provides an async wrapper for Sunset core
///
/// A [`ChanHandle`] provided by sunset core must be added with [`add_channel()`] before
/// a method can be called with the equivalent ChanNum.
///
/// Applications use `async_sunset::{Client,Server}`.
pub(crate) struct AsyncSunset<'a, CS: CliServ> {
    inner: SunsetMutex<Inner<'a, CS>>,

    progress_notify: Signal<SunsetRawMutex, ()>,
    last_progress_idled: AtomicBool,

    // wake_progress() should be called after modifying these atomics, to
    // trigger the progress loop to handle state changes

    // When draining the last events
    moribund: AtomicBool,

    // Refcount for `Inner::chan_handles`. Must be non-async so it can be
    // decremented on `ChanIn::drop()` etc.
    // The pending chan_refcount=0 handling occurs in the `progress()` loop.
    //
    // thumbv6m has no atomic usize add/sub.
    chan_refcounts: [portable_atomic::AtomicUsize; MAX_CHANNELS],
}

impl<CS: CliServ> core::fmt::Debug for AsyncSunset<'_, CS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut d = f.debug_struct("AsyncSunset");
        if let Ok(i) = self.inner.try_lock() {
            d.field("runner", &i.runner);
        } else {
            d.field("inner", &"(locked)");
        }
        d.finish_non_exhaustive()
    }
}

impl<'a, CS: CliServ> AsyncSunset<'a, CS> {
    pub fn new(runner: Runner<'a, CS>) -> Self {
        let wakers = Wakers {
            chan_read: Default::default(),
            chan_write: Default::default(),
            chan_ext: Default::default(),
            chan_close: Default::default(),
        };
        let inner = Inner { runner, wakers, chan_handles: Default::default() };
        let inner = Mutex::new(inner);

        let progress_notify = Signal::new();

        Self {
            inner,
            moribund: AtomicBool::new(false),
            progress_notify,
            chan_refcounts: Default::default(),
            last_progress_idled: AtomicBool::new(false),
        }
    }

    /// Runs the session to completion
    pub async fn run(
        &self,
        rsock: &mut impl Read,
        wsock: &mut impl Write,
    ) -> Result<()> {
        // Some loops need to terminate other loops on completion.
        // prog finish -> stop rx
        // rx finish -> stop tx
        let tx_stop = Signal::<SunsetRawMutex, ()>::new();
        let rx_stop = Signal::<SunsetRawMutex, ()>::new();

        let tx = async {
            let r = self
                .output_loop(wsock)
                .await
                .inspect(|r| warn!("tx complete {r:?}"));
            r
        };
        let tx = select(tx, tx_stop.wait());

        // rxbuf outside the async block avoids an extraneous copy somehow
        let mut rxbuf = [0; 1024];
        let rx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let l = match rsock.read(&mut rxbuf).await {
                    Ok(0) => {
                        debug!("net EOF");
                        self.with_runner(|r| r.close_input()).await;
                        self.moribund.store(true, Relaxed);
                        self.wake_progress();
                        break Ok(());
                    }
                    Ok(l) => l,
                    Err(_) => {
                        info!("socket read error");
                        self.with_runner(|r| r.close_input()).await;
                        break Err(Error::ChannelEOF);
                    }
                };
                let mut rxbuf = &rxbuf[..l];
                while !rxbuf.is_empty() {
                    let n = self.input(rxbuf).await?;
                    self.wake_progress();
                    rxbuf = &rxbuf[n..];
                }
            }
            .inspect(|r| warn!("rx complete {r:?}"))
        };

        // TODO: if RX fails (bad decrypt etc) it doesn't cancel prog, so gets stuck
        let rx = async {
            let r = select(rx, rx_stop.wait()).await;
            tx_stop.signal(());
            r
        };

        // TODO: we might want to let `prog` run until buffers are drained
        // in case a disconnect message was received.
        // TODO Is there a nice way than this?
        let f = join::join(rx, tx).await;
        let (_frx, _ftx) = f;

        // debug!("frx {_frx:?}");
        // debug!("ftx {_ftx:?}");

        // TODO: is this a good way to do cancellation...?
        // self.with_runner(|runner| runner.close()).await;
        // // Wake any channels that were awoken after the runner closed
        // let mut inner = self.inner.lock().await;
        // self.wake_channels(&mut inner)?;
        Ok(())
    }

    fn wake_progress(&self) {
        self.progress_notify.signal(())
    }

    fn wake_channels(&self, inner: &mut Inner<CS>) -> Result<()> {
        // Read wakers
        let w = &mut inner.wakers;
        if let Some((num, dt, _len)) = inner.runner.read_channel_ready() {
            let waker = match dt {
                ChanData::Normal => &mut w.chan_read[num.0 as usize],
                ChanData::Stderr => &mut w.chan_ext[num.0 as usize],
            };
            if waker.occupied() {
                waker.wake();
            } else {
                // No waker waiting for this packet, so drop it.
                // This avoids the case where for example a client application
                // is only reading from a Stdin ChanIn, but some data arrives
                // over the write fore Stderr. Something needs to mark it done,
                // since the session can't proceed until it's consumed.
                if let Some(h) = &inner.chan_handles[num.0 as usize] {
                    inner.runner.discard_read_channel(h)?
                }
            }
        }

        for (idx, c) in inner.chan_handles.iter().enumerate() {
            let ch = if let Some(ch) = c.as_ref() { ch } else { continue };

            // Write wakers

            // TODO: if this is slow we could be smarter about aggregating dt vs standard,
            // or handling the case of full out payload buffers.
            if inner.runner.write_channel_ready(ch, ChanData::Normal)?.unwrap_or(0)
                > 0
            {
                w.chan_write[idx].wake()
            }

            if !CS::is_client()
                && inner
                    .runner
                    .write_channel_ready(ch, ChanData::Stderr)?
                    .unwrap_or(0)
                    > 0
            {
                w.chan_ext[idx].wake()
            }

            // TODO: do we want to keep waking it?
            if inner.runner.is_channel_eof(ch) {
                w.chan_read[idx].wake();
                if CS::is_client() {
                    w.chan_ext[idx].wake();
                }
            }

            if inner.runner.is_channel_closed(ch) {
                w.chan_close[idx].wake();
            }
        }
        Ok(())
    }

    /// Check for channels that have reached zero refcount
    ///
    /// When a ChanIO is dropped the refcount may reach 0, but
    /// without "async Drop" it isn't possible to take the `inner` lock during
    /// `drop()`.
    /// Instead this runs periodically from an async context to release channels.
    fn clear_refcounts(&self, inner: &mut Inner<CS>) -> Result<()> {
        for (ch, count) in
            inner.chan_handles.iter_mut().zip(self.chan_refcounts.iter())
        {
            let count = count.load(Relaxed);
            if count > 0 {
                debug_assert!(ch.is_some());
                continue;
            }
            if let Some(ch) = ch.take() {
                // done with the channel
                inner.runner.channel_done(ch)?;
            }
        }
        Ok(())
    }

    /// Returns an `Event`.
    ///
    /// The returned `Event` borrows from the mutex locked in `ph`.
    pub(crate) async fn progress<'g, 'f>(
        &'g self,
        ph: &'f mut ProgressHolder<'g, 'a, CS>,
    ) -> Result<Event<'f, 'a>> {
        // In case a ProgressHolder was reused, release any guard.
        *ph = ProgressHolder::default();

        // Ideally we would .wait() after calling .progress() below when
        // Event::None is returned, but the borrow checker won't allow that.
        // Instead we wait at the start of the next progress() call,
        // but will return immediately if something external
        // has woken the progress_notify in the interim.
        //
        // TODO: rework once rustc's polonius is stable.
        // https://github.com/rust-lang/rust/issues/54663
        //
        // This is a non-atomic swap since thumbv6m won't support it.
        // Only one task should be calling progress(), so that's OK.
        let need_wait = self.last_progress_idled.load(Relaxed);
        if need_wait {
            self.last_progress_idled.store(false, Relaxed);
            self.progress_notify.wait().await;
        }

        // The returned event borrows from a guard inside ProgressHolder
        let inner = ph.guard.insert(self.inner.lock().await);

        // Drop deferred finished channels
        self.clear_refcounts(inner)?;
        // Wake channels
        self.wake_channels(inner)?;

        if self.moribund.load(Relaxed) {
            // if we're flushing, we exit once there is no progress
            debug!("All data flushed")
            // TODO make this do something!
        }

        let ev = inner.runner.progress();
        if matches!(ev, Ok(Event::None)) {
            // nothing happened, will progress_notify.wait() next progress() call, see above.
            self.last_progress_idled.store(true, Relaxed);
        }
        ev
    }

    pub(crate) async fn with_runner<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Runner<CS>) -> R,
    {
        let mut inner = self.inner.lock().await;
        f(&mut inner.runner)
    }

    /// helper to perform a function on the `inner`, returning a `Poll` value
    async fn poll_inner<F, T>(&self, mut f: F) -> T
    where
        F: FnMut(&mut Inner<CS>, &mut Context) -> Poll<T>,
    {
        poll_fn(|cx| {
            // Attempt to lock .inner
            let i = self.inner.lock();
            pin_mut!(i);
            match i.poll(cx) {
                Poll::Ready(mut inner) => f(&mut inner, cx),
                Poll::Pending => {
                    // .inner lock is busy
                    Poll::Pending
                }
            }
        })
        .await
    }

    pub async fn output_loop(&self, wsock: &mut impl Write) -> Result<()> {
        poll_fn(|cx| {
            // Attempt to lock .inner
            let i = self.inner.lock();
            pin_mut!(i);
            let Ready(mut inner) = i.poll(cx) else {
                return Pending;
            };

            loop {
                let buf = inner.runner.output_buf();
                if buf.is_empty() {
                    // no output ready
                    inner.runner.set_output_waker(cx.waker());
                    return Pending;
                }

                let res = {
                    let w = wsock.write(buf);
                    pin_mut!(w);
                    w.poll(cx)
                };

                return match res {
                    Pending => Pending,
                    Ready(Ok(0)) => {
                        info!("socket EOF");
                        inner.runner.close_output();
                        Ready(error::ChannelEOF.fail())
                    }
                    Ready(Ok(write_len)) => {
                        let buf_len = buf.len();
                        inner.runner.consume_output(write_len);
                        if write_len < buf_len {
                            // Must keep going until either wsock
                            // or output_buf returns Pending and
                            // registers a waker.
                            continue;
                        }
                        Pending
                    }
                    Ready(Err(_e)) => {
                        info!("socket write error");
                        inner.runner.close_output();
                        Ready(error::ChannelEOF.fail())
                    }
                };
            }
        })
        .await
    }

    pub async fn input(&self, buf: &[u8]) -> Result<usize> {
        let res = self
            .poll_inner(|inner, cx| {
                if inner.runner.is_input_ready() {
                    match inner.runner.input(buf) {
                        Ok(0) => {
                            inner.runner.set_input_waker(cx.waker());
                            Poll::Pending
                        }
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) => Poll::Ready(Err(e)),
                    }
                } else {
                    inner.runner.set_input_waker(cx.waker());
                    Poll::Pending
                }
            })
            .await;
        self.wake_progress();
        res
    }

    /// Adds a new channel handle provided by sunset core.
    ///
    /// AsyncSunset will take ownership of the handle. An initial refcount
    /// must be provided, this will match the number of ChanIO that
    /// will be created. (A zero initial refcount would be prone to immediate
    /// garbage collection).
    /// ChanIO will take care of `inc_chan()` on clone, `dec_chan()` on drop.
    pub(crate) async fn add_channel(
        &self,
        handle: ChanHandle,
        init_refcount: usize,
    ) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let idx = handle.num().0 as usize;
        if inner.chan_handles[idx].is_some() {
            return error::Bug.fail();
        }

        debug_assert_eq!(self.chan_refcounts[idx].load(Relaxed), 0);

        inner.chan_handles[idx] = Some(handle);
        self.chan_refcounts[idx].store(init_refcount, Relaxed);
        Ok(())
    }
}

// necessary for the &dyn ChanCore
#[cfg(feature = "multi-thread")]
pub(crate) trait MaybeSend: Sync {}
#[cfg(not(feature = "multi-thread"))]
pub(crate) trait MaybeSend {}

impl<'a, CS: CliServ> MaybeSend for AsyncSunset<'a, CS> {}

// Ideally the poll_...() methods would be async, but that isn't
// dyn compatible at present. Instead run poll_fn in the ChanIO caller.
pub(crate) trait ChanCore: MaybeSend {
    fn inc_chan(&self, num: ChanNum);
    fn dec_chan(&self, num: ChanNum);

    fn poll_until_channel_closed(
        &self,
        cx: &mut Context,
        num: ChanNum,
    ) -> Poll<Result<()>>;

    fn poll_read_channel(
        &self,
        cx: &mut Context,
        num: ChanNum,
        dt: ChanData,
        buf: &mut [u8],
    ) -> Poll<Result<usize>>;

    fn poll_write_channel(
        &self,
        cx: &mut Context,
        num: ChanNum,
        dt: ChanData,
        buf: &[u8],
    ) -> Poll<Result<usize>>;

    fn poll_term_window_change(
        &self,
        cx: &mut Context,
        num: ChanNum,
        winch: &sunset::packets::WinChange,
    ) -> Poll<Result<()>>;
}

impl<'a, CS: CliServ> ChanCore for AsyncSunset<'a, CS> {
    fn inc_chan(&self, num: ChanNum) {
        let c = self.chan_refcounts[num.0 as usize].fetch_add(1, SeqCst);
        debug_assert_ne!(c, 0);
        // overflow shouldn't be possible unless ChanIn etc is leaking
        debug_assert_ne!(c, usize::MAX);
    }

    fn dec_chan(&self, num: ChanNum) {
        // refcounts that hit zero will be cleaned up later in clear_refcounts()
        let c = self.chan_refcounts[num.0 as usize].fetch_sub(1, SeqCst);
        debug_assert_ne!(c, 0);
        if c == 1 {
            // refcount hit zero, progress() will clean it up
            // in an async context
            self.wake_progress();
        }
    }

    fn poll_until_channel_closed(
        &self,
        cx: &mut Context,
        num: ChanNum,
    ) -> Poll<Result<()>> {
        // Attempt to lock .inner
        let i = self.inner.lock();
        pin_mut!(i);
        let Ready(mut inner) = i.poll(cx) else {
            return Pending;
        };

        let (runner, h, wakers) = inner.fetch(num)?;
        if runner.is_channel_closed(h) {
            Poll::Ready(Ok(()))
        } else {
            wakers.chan_close[num.0 as usize].register(cx.waker());
            Poll::Pending
        }
    }

    /// Reads channel data.
    fn poll_read_channel(
        &self,
        cx: &mut Context,
        num: ChanNum,
        dt: ChanData,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        // Attempt to lock .inner
        let i = self.inner.lock();
        pin_mut!(i);
        let Ready(mut inner) = i.poll(cx) else {
            return Pending;
        };

        let (runner, h, wakers) = inner.fetch(num)?;
        let i = match runner.read_channel(h, dt, buf) {
            Ok(0) => {
                // 0 bytes read, pending
                match dt {
                    ChanData::Normal => {
                        wakers.chan_read[num.0 as usize].register(cx.waker());
                    }
                    ChanData::Stderr => {
                        wakers.chan_ext[num.0 as usize].register(cx.waker());
                    }
                }
                Poll::Pending
            }
            Err(Error::ChannelEOF) => Poll::Ready(Ok(0)),
            r => Poll::Ready(r),
        };
        if matches!(i, Poll::Ready(_)) {
            self.wake_progress()
        }
        i
    }

    fn poll_write_channel(
        &self,
        cx: &mut Context,
        num: ChanNum,
        dt: ChanData,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        // Attempt to lock .inner
        let i = self.inner.lock();
        pin_mut!(i);
        let Ready(mut inner) = i.poll(cx) else {
            return Pending;
        };

        let (runner, h, wakers) = inner.fetch(num)?;
        let l = runner.write_channel(h, dt, buf);
        if let Ok(0) = l {
            // 0 bytes written, pending
            match dt {
                ChanData::Normal => {
                    wakers.chan_write[num.0 as usize].register(cx.waker());
                }
                ChanData::Stderr => {
                    wakers.chan_ext[num.0 as usize].register(cx.waker());
                }
            }
            Poll::Pending
        } else {
            self.wake_progress();
            Poll::Ready(l)
        }
    }

    fn poll_term_window_change(
        &self,
        cx: &mut Context,
        num: ChanNum,
        winch: &sunset::packets::WinChange,
    ) -> Poll<Result<()>> {
        // Attempt to lock .inner
        let i = self.inner.lock();
        pin_mut!(i);
        let Ready(mut inner) = i.poll(cx) else {
            return Pending;
        };
        let (runner, h, _) = inner.fetch(num)?;
        Poll::Ready(runner.term_window_change(h, winch))
    }
}

pub async fn io_copy<const B: usize, R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
{
    let mut b = [0u8; B];
    loop {
        let n = r.read(&mut b).await?;
        if n == 0 {
            return sunset::error::ChannelEOF.fail();
        }
        let b = &b[..n];
        w.write_all(b).await?
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_copy_nowriteerror<const B: usize, R, W>(
    r: &mut R,
    w: &mut W,
) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write,
{
    let mut b = [0u8; B];
    loop {
        let n = r.read(&mut b).await?;
        if n == 0 {
            return sunset::error::ChannelEOF.fail();
        }
        let b = &b[..n];
        if let Err(_) = w.write_all(b).await {
            info!("write error");
        }
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_buf_copy<R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: BufRead<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
{
    loop {
        let b = r.fill_buf().await?;
        if b.is_empty() {
            return sunset::error::ChannelEOF.fail();
        }
        let n = b.len();
        w.write_all(b).await?;
        r.consume(n)
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_buf_copy_noreaderror<R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: BufRead,
    W: Write<Error = sunset::Error>,
{
    loop {
        let b = match r.fill_buf().await {
            Ok(b) => b,
            Err(_) => {
                info!("read error");
                embassy_futures::yield_now().await;
                continue;
            }
        };
        if b.is_empty() {
            return sunset::error::ChannelEOF.fail();
        }
        let n = b.len();
        w.write_all(b).await?;
        r.consume(n)
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}
