#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use core::future::{poll_fn, Future};
use core::task::{Poll, Context};
use core::ops::{ControlFlow, DerefMut};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::{Relaxed, SeqCst};

use embassy_sync::waitqueue::WakerRegistration;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_futures::select::select;
use embassy_futures::join;
use embedded_io_async::{Read, Write, BufRead};

// thumbv6m has no atomic usize add/sub
use atomic_polyfill::AtomicUsize;

use pin_utils::pin_mut;

use sunset::{Runner, Result, Error, error, Behaviour, ChanData, ChanHandle, ChanNum, CliBehaviour, ServBehaviour};
use sunset::config::MAX_CHANNELS;

// For now we only support single-threaded executors.
// In future this could be behind a cfg to allow different
// RawMutex for std executors or other situations.
// Also requires making CliBehaviour : Send, etc.
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
        self.chan_handles[num.0 as usize].as_ref().map(|ch| {
            (&mut self.runner, ch, &mut self.wakers)
        })
        .ok_or_else(Error::bug)
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

    exit: AtomicBool,
    flushing: AtomicBool,

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
            exit: AtomicBool::new(false),
            flushing: AtomicBool::new(false),
            progress_notify,
            chan_refcounts: Default::default(),
         }
    }

    /// Runs the session to completion
    ///
    /// `b` is a bit tricky, it allows passing either a Mutex<CliBehaviour> or
    /// Mutex<ServBehaviour> (to be converted into a Behaviour in progress() after 
    /// the mutex is locked).
    pub async fn run<B: ?Sized, M: RawMutex, C: CliBehaviour, S: ServBehaviour>(&self,
        rsock: &mut impl Read,
        wsock: &mut impl Write,
        b: &Mutex<M, B>) -> Result<()>
        where
            for<'f> Behaviour<'f, C, S>: From<&'f mut B>
    {
        // Some loops need to terminate other loops on completion.
        // prog finish -> stop rx
        // rx finish -> stop tx
        let tx_stop = Signal::<SunsetRawMutex, ()>::new();
        let rx_stop = Signal::<SunsetRawMutex, ()>::new();

        let tx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer?
                // Perhaps not possible async, might deadlock.
                let mut buf = [0; 1024];
                let l = self.output(&mut buf).await?;
                wsock.write_all(&buf[..l]).await
                .map_err(|_| {
                    info!("socket write error");
                    Error::ChannelEOF
                })?;
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };
        let tx = select(tx, tx_stop.wait());

        let rx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let mut buf = [0; 1024];
                let l = rsock.read(&mut buf).await
                .map_err(|_| {
                    info!("socket read error");
                    Error::ChannelEOF
                })?;
                if l == 0 {
                    debug!("net EOF");
                    self.flushing.store(true, Relaxed);
                    self.wake_progress();
                    break
                }
                let mut buf = &buf[..l];
                while !buf.is_empty() {
                    let n = self.input(buf).await?;
                    buf = &buf[n..];
                }
            }
            Ok::<_, sunset::Error>(())
        };

        // TODO: if RX fails (bad decrypt etc) it doesn't cancel prog, so gets stuck
        let rx = select(rx, rx_stop.wait());
        let rx = async {
            let r = rx.await;
            tx_stop.signal(());
            r
        };

        let prog = async {
            loop {
                if self.progress(b).await?.is_break() {
                    break Ok(())
                }
            }
        };

        let prog = async {
            let r = prog.await;
            self.with_runner(|runner| runner.close()).await;
            rx_stop.signal(());
            r
        };

        // TODO: we might want to let `prog` run until buffers are drained
        // in case a disconnect message was received.
        // TODO Is there a nice way than this?
        let f = join::join3(prog, rx, tx).await;
        let (fp, _frx, _ftx) = f;

        // debug!("fp {fp:?}");
        // debug!("frx {_frx:?}");
        // debug!("ftx {_ftx:?}");

        // TODO: is this a good way to do cancellation...?
        // self.with_runner(|runner| runner.close()).await;
        // // Wake any channels that were awoken after the runner closed
        // let mut inner = self.inner.lock().await;
        // self.wake_channels(&mut inner)?;
        fp
    }

    fn wake_progress(&self) {
        self.progress_notify.signal(())
    }

    pub async fn exit(&self) {
        self.exit.store(true, Relaxed);
        self.wake_progress()
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
                    inner.runner.discard_channel_input(&h)?
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

            if !inner.runner.is_client() {
                if inner.runner.ready_channel_send(ch, ChanData::Stderr)?.unwrap_or(0) > 0 {
                    w.chan_ext[idx].wake()
                }
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

    /// Returns ControlFlow::Break on session exit.
    ///
    /// B will be either a CliBehaviour or ServBehaviour
    async fn progress<B: ?Sized, M: RawMutex, C: CliBehaviour, S: ServBehaviour>(&self,
        b: &Mutex<M, B>)
        -> Result<ControlFlow<()>>
        where
            for<'f> Behaviour<'f, C, S>: From<&'f mut B>
        {
            let ret;

        {
            if self.exit.load(Relaxed) {
                return Ok(ControlFlow::Break(()))
            }

            let mut inner = self.inner.lock().await;
            {
                {
                    // lock the Mutex around the CliBehaviour or ServBehaviour
                    let mut b = b.lock().await;
                    // dereference the MutexGuard
                    let b = b.deref_mut();
                    // create either Behaviour<C, UnusedServ> or Behaviour<UnusedCli, S>
                    // to pass to the runner.
                    let mut b: Behaviour<C, S> = b.into();
                    ret = inner.runner.progress(&mut b).await?;
                    // b is dropped, allowing other users
                }

                self.wake_channels(&mut inner)?;

                self.clear_refcounts(&mut inner)?;
            }
            // inner dropped
        }

        if ret.disconnected {
            return Ok(ControlFlow::Break(()))
        }

        if !ret.progressed {
            if self.flushing.load(Relaxed) {
                // if we're flushing, we exit once there is no progress
                return Ok(ControlFlow::Break(()))
            }
            // Idle until input is received
            // TODO do we also want to wake in other situations?
            self.progress_notify.wait().await;
        }

        Ok(ControlFlow::Continue(()))
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
            match inner.runner.output(buf) {
                // no output ready
                Ok(0) => {
                    inner.runner.set_output_waker(cx.waker());
                    Poll::Pending
                }
                Ok(n) => Poll::Ready(Ok(n)),
                Err(e) => Poll::Ready(Err(e)),
            }
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
        if num.0 as usize > MAX_CHANNELS {
            return sunset::error::BadChannel { num }.fail()
        }
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
        if num.0 as usize > MAX_CHANNELS {
            return sunset::error::BadChannel { num }.fail()
        }
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
