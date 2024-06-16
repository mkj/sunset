#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use core::future::{poll_fn, Future};
use core::task::{Poll, Context};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};

use embassy_sync::waitqueue::WakerRegistration;
#[allow(unused_imports)]
use embassy_sync::blocking_mutex::raw::{NoopRawMutex,CriticalSectionRawMutex};
use embassy_sync::mutex::{Mutex, MutexGuard};
use embassy_sync::signal::Signal;
use embassy_futures::select::select;
use embassy_futures::join;
use embedded_io_async::{Read, Write, BufRead};

// thumbv6m has no atomic usize add/sub
use atomic_polyfill::AtomicUsize;

use pin_utils::pin_mut;

use sunset::{error, ChanData, ChanHandle, ChanNum, Error, Result, Runner};
use sunset::config::MAX_CHANNELS;
use sunset::event::Event;

#[cfg(feature = "multi-thread")]
pub type SunsetRawMutex = CriticalSectionRawMutex;
#[cfg(not(feature = "multi-thread"))]
pub type SunsetRawMutex = NoopRawMutex;

pub type SunsetMutex<T> = Mutex<SunsetRawMutex, T>;

struct Wakers {
    chan_read: [WakerRegistration; MAX_CHANNELS],

    chan_write: [WakerRegistration; MAX_CHANNELS],

    /// Will be a stderr read waker for a client, or stderr write waker for
    /// a server.
    chan_ext: [WakerRegistration; MAX_CHANNELS],

    // TODO: do we need a separate waker for this?
    chan_close: [WakerRegistration; MAX_CHANNELS],
}

struct Inner<'a> {
    runner: Runner<'a>,

    wakers: Wakers,

    // May only be safely modified when the corresponding
    // `chan_refcounts` is zero.
    chan_handles: [Option<ChanHandle>; MAX_CHANNELS],
}

impl<'a> Inner<'a> {
    /// Helper to lookup the corresponding ChanHandle
    ///
    /// Returns split references that will be required by many callers
    fn fetch(&mut self, num: ChanNum) -> Result<(&mut Runner<'a>, &ChanHandle, &mut Wakers)> {
        let h = self.chan_handles.get(num.0 as usize).ok_or(Error::BadChannel { num })?;
        h.as_ref().map(|ch| {
            (&mut self.runner, ch, &mut self.wakers)
        })
        .ok_or_else(Error::bug)
    }
}

/// A handle used for storage from a [`SSHClient::progress()`](crate::SSHClient::progress)
/// or [`SSHServer::progress()`](crate::SSHServer::progress) call.
#[derive(Default)]
pub struct ProgressHolder<'g, 'a> {
    g: Option<MutexGuard<'g, SunsetRawMutex, Inner<'a>>>,
}

impl<'g, 'a> ProgressHolder<'g, 'a> {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Provides an async wrapper for Sunset core
///
/// A [`ChanHandle`] provided by sunset core must be added with [`add_channel()`] before
/// a method can be called with the equivalent ChanNum.
///
/// Applications use `embassy_sunset::{Client,Server}`.
pub(crate) struct EmbassySunset<'a> {
    inner: SunsetMutex<Inner<'a>>,

    progress_notify: Signal<SunsetRawMutex, ()>,

    // wake_progress() should be called after modifying these atomics, to
    // trigger the progress loop to handle state changes

    // When draining the last events
    moribund: AtomicBool,

    // Refcount for `Inner::chan_handles`. Must be non-async so it can be
    // decremented on `ChanIn::drop()` etc.
    // The pending chan_refcount=0 handling occurs in the `progress()` loop.
    chan_refcounts: [AtomicUsize; MAX_CHANNELS],
}

impl<'a> EmbassySunset<'a> {
    pub fn new(runner: Runner<'a>) -> Self {
        let wakers = Wakers {
            chan_read: Default::default(),
            chan_write: Default::default(),
            chan_ext: Default::default(),
            chan_close: Default::default(),
        };
        let inner = Inner {
            runner,
            wakers,
            chan_handles: Default::default(),
        };
        let inner = Mutex::new(inner);

        let progress_notify = Signal::new();

        Self {
            inner,
            moribund: AtomicBool::new(false),
            progress_notify,
            chan_refcounts: Default::default(),
         }
    }

    /// Runs the session to completion
    pub async fn run(&'a self, rsock: &mut impl Read, wsock: &mut impl Write) -> Result<()>
    {
        // Some loops need to terminate other loops on completion.
        // prog finish -> stop rx
        // rx finish -> stop tx
        let tx_stop = Signal::<SunsetRawMutex, ()>::new();
        let rx_stop = Signal::<SunsetRawMutex, ()>::new();

        let tx = async {
            let mut buf = [0; 1024];
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer?
                // Perhaps not possible async, might deadlock.
                let l = self.output(&mut buf).await?;
                if wsock.write_all(&buf[..l]).await.is_err() {
                    info!("socket write error");
                    self.with_runner(|r| r.close_output()).await;
                    break Err::<(), sunset::Error>(Error::ChannelEOF)
                }
            }
            .inspect(|r| warn!("tx complete {r:?}"))
        };
        let tx = select(tx, tx_stop.wait());

        let rx = async {
            let mut buf = [0; 1024];
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let l = match rsock.read(&mut buf).await {
                    Ok(0) => {
                        debug!("net EOF");
                        self.with_runner(|r| r.close_input()).await;
                        self.moribund.store(true, Relaxed);
                        self.wake_progress();
                        break Ok(())
                    }
                    Ok(l) => l,
                    Err(_) => {
                        info!("socket read error");
                        self.with_runner(|r| r.close_input()).await;
                        break Err(Error::ChannelEOF)
                    }
                };
                let mut buf = &buf[..l];
                while !buf.is_empty() {
                    let n = self.input(buf).await?;
                    self.wake_progress();
                    buf = &buf[n..];
                }
            }
            .inspect(|r| warn!("rx complete {r:?}"))
        };

        // TODO: if RX fails (bad decrypt etc) it doesn't cancel prog, so gets stuck
        let rx = select(rx, rx_stop.wait());
        let rx = async {
            let r = rx.await;
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

    fn wake_channels(&self, inner: &mut Inner) -> Result<()> {
        // Read wakers
        let w = &mut inner.wakers;
        if let Some((num, dt, _len)) = inner.runner.ready_channel_input() {
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
                    inner.runner.discard_channel_input(h)?
                }
            }
        }

        for (idx, c) in inner.chan_handles.iter().enumerate() {
            let ch = if let Some(ch) = c.as_ref() {
                ch
            } else {
                continue
            };

            // Write wakers


            // TODO: if this is slow we could be smarter about aggregating dt vs standard,
            // or handling the case of full out payload buffers.
            if inner.runner.ready_channel_send(ch, ChanData::Normal)?.unwrap_or(0) > 0 {
                w.chan_write[idx].wake()
            }

            if !inner.runner.is_client() && inner.runner.ready_channel_send(ch, ChanData::Stderr)?.unwrap_or(0) > 0 {
                w.chan_ext[idx].wake()
            }

            // TODO: do we want to keep waking it?
            if inner.runner.is_channel_eof(ch) {
                w.chan_read[idx].wake();
                if inner.runner.is_client() {
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
    fn clear_refcounts(&self, inner: &mut Inner) -> Result<()> {
        for (ch, count) in inner.chan_handles.iter_mut().zip(self.chan_refcounts.iter()) {
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

    /// Returns an `Event` once one is ready.
    ///
    /// The returned `Event` borrows from the mutex locked in `ph`.
    pub(crate) async fn progress<'g, 'f>(&'g self, ph: &'f mut ProgressHolder<'g, 'a>) 
        -> Result<Event<'f, 'a>>
    {
        ph.g = None;
        #[cfg(feature = "try-polonius")]
        let guard = &mut ph.g;

        // poll progress until we get an actual event to return
        loop {

            // Safety: At the start of the loop iteration nothing is borrowing from
            // guard, it is set to None. We dereference through a pointer to lose the 'f
            // bound which applies to the Event::Cli/Event::Serv returned variants,
            // but not other match arms.
            //
            // Once polonius is implemented this is unnecessary. polonius-the-crab
            // can't be used since it would require an async closure.
            #[cfg(not(feature = "try-polonius"))]
            let guard = unsafe { &mut *(&mut ph.g as *mut Option<_>) };
            debug_assert!(guard.is_none());

            let idle = {
                let inner = guard.insert(self.inner.lock().await);

                // Drop any finished channels now we have the lock
                self.clear_refcounts(inner)?;

                self.wake_channels(inner)?;
                let ev = inner.runner.progress()?;

                match ev {
                    // Return borrowed Cli/Serv directly, with a Event<'f, 'a> bound.
                    Event::Cli(_) => return Ok(ev),
                    Event::Serv(_) => return Ok(ev),
                    Event::Progressed => false,
                    Event::None => true,
                }
            };

            // Safety: No borrows of guard remain, can lose the inferred 'f lifetime.
            // Not required after polonius.
            #[cfg(not(feature = "try-polonius"))]
            let guard = unsafe { &mut *(&mut ph.g as *mut Option<_>) };

            // Drop the Mutex
            *guard = None;

            if self.moribund.load(Relaxed) {
                // if we're flushing, we exit once there is no progress
                debug!("All data flushed")
            }

            if !idle {
                // Run runner.progress() again if we made forward progress.
                continue;
            }

            // Idle until input is received
            // TODO do we also want to wake in other situations?
            self.progress_notify.wait().await;
        }
    }

    pub(crate) async fn with_runner<F, R>(&self, f: F) -> R
        where F: FnOnce(&mut Runner) -> R {
        let mut inner = self.inner.lock().await;
        f(&mut inner.runner)
    }

    /// helper to perform a function on the `inner`, returning a `Poll` value
    async fn poll_inner<F, T>(&self, mut f: F) -> T
        where F: FnMut(&mut Inner, &mut Context) -> Poll<T> {
        poll_fn(|cx| {
            // Attempt to lock .inner
            let i = self.inner.lock();
            pin_mut!(i);
            match i.poll(cx) {
                Poll::Ready(mut inner) => {
                    f(&mut inner, cx)
                }
                Poll::Pending => {
                    // .inner lock is busy
                    Poll::Pending
                }
            }
        })
        .await
    }

    pub async fn output(&self, buf: &mut [u8]) -> Result<usize> {
        self.poll_inner(|inner, cx| {
            let r = match inner.runner.output(buf) {
                // no output ready
                Ok(0) => {
                    inner.runner.set_output_waker(cx.waker());
                    Poll::Pending
                }
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) => Poll::Ready(Err(e)),
            };
            if r.is_ready() {
                self.wake_progress()
            }
            r
        }).await
    }

    pub async fn input(&self, buf: &[u8]) -> Result<usize> {
        self.poll_inner(|inner, cx| {
            if inner.runner.is_input_ready() {
                let r = match inner.runner.input(buf) {
                    Ok(0) => {
                        inner.runner.set_input_waker(cx.waker());
                        Poll::Pending
                    },
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(e)),
                };
                if r.is_ready() {
                    self.wake_progress()
                }
                r
            } else {
                inner.runner.set_input_waker(cx.waker());
                Poll::Pending
            }
        }).await
    }

    /// Reads channel data.
    pub(crate) async fn read_channel(&self, num: ChanNum, dt: ChanData, buf: &mut [u8]) -> Result<usize> {
        trace!("readch {dt:?}");
        self.poll_inner(|inner, cx| {
            let (runner, h, wakers) = inner.fetch(num)?;
            let i = match runner.channel_input(h, dt, buf) {
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
                Err(Error::ChannelEOF) => {
                    Poll::Ready(Ok(0))
                }
                r => Poll::Ready(r),
            };
            if matches!(i, Poll::Ready(_)) {
                self.wake_progress()
            }
            i
        }).await
    }

    pub(crate) async fn write_channel(&self, num: ChanNum, dt: ChanData, buf: &[u8]) -> Result<usize> {
        self.poll_inner(|inner, cx| {
            let (runner, h, wakers) = inner.fetch(num)?;
            let l = runner.channel_send(h, dt, buf);
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
        }).await
    }

    pub(crate) async fn until_channel_closed(&self, num: ChanNum) -> Result<()> {
        self.poll_inner(|inner, cx| {
            let (runner, h, wakers) = inner.fetch(num)?;
            if runner.is_channel_closed(h) {
                Poll::Ready(Ok(()))
            } else {
                wakers.chan_close[num.0 as usize].register(cx.waker());
                Poll::Pending
            }
        }).await
    }

    pub async fn term_window_change(&self, num: ChanNum, winch: sunset::packets::WinChange) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let (runner, h, _) = inner.fetch(num)?;
        runner.term_window_change(h, winch)
    }

    /// Adds a new channel handle provided by sunset core.
    ///
    /// EmbassySunset will take ownership of the handle. An initial refcount
    /// must be provided, this will match the number of ChanIO that
    /// will be created. (A zero initial refcount would be prone to immediate
    /// garbage collection).
    /// ChanIO will take care of `inc_chan()` on clone, `dec_chan()` on drop.
    pub(crate) async fn add_channel(&self, handle: ChanHandle, init_refcount: usize) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let idx = handle.num().0 as usize;
        if inner.chan_handles[idx].is_some() {
            return error::Bug.fail()
        }

        debug_assert_eq!(self.chan_refcounts[idx].load(Relaxed), 0);

        inner.chan_handles[idx] = Some(handle);
        self.chan_refcounts[idx].store(init_refcount, Relaxed);
        Ok(())
    }

    pub(crate) fn inc_chan(&self, num: ChanNum) {
        let c = self.chan_refcounts[num.0 as usize].fetch_add(1, SeqCst);
        debug_assert_ne!(c, 0);
        // overflow shouldn't be possible unless ChanIn etc is leaking
        debug_assert_ne!(c, usize::MAX);
        // perhaps not necessary? is cheap?
        self.wake_progress();
    }

    pub(crate) fn dec_chan(&self, num: ChanNum) {
        // refcounts that hit zero will be cleaned up later in clear_refcounts()
        let c = self.chan_refcounts[num.0 as usize].fetch_sub(1, SeqCst);
        debug_assert_ne!(c, 0);
        // perhaps not necessary? is cheap?
        self.wake_progress();
    }
}


pub async fn io_copy<const B: usize, R, W>(r: &mut R, w: &mut W) -> Result<()>
    where R: Read<Error=sunset::Error>,
        W: Write<Error=sunset::Error>
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

pub async fn io_copy_nowriteerror<const B: usize, R, W>(r: &mut R, w: &mut W) -> Result<()>
    where R: Read<Error=sunset::Error>,
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
    where R: BufRead<Error=sunset::Error>,
        W: Write<Error=sunset::Error>
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
    where R: BufRead,
        W: Write<Error=sunset::Error>
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
