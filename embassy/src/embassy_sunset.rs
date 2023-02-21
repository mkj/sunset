#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use core::future::{poll_fn, Future};
use core::task::{Poll, Context};

use embassy_sync::waitqueue::WakerRegistration;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_futures::select::{select3, Either3};
use embedded_io::asynch;

use pin_utils::pin_mut;

use sunset::{Runner, Result, Error, Behaviour, sshnames, ChanData, ChanNum};
use sunset::config::MAX_CHANNELS;

// For now we only support single-threaded executors.
// In future this could be behind a cfg to allow different
// RawMutex for std executors or other situations.
pub type SunsetRawMutex = NoopRawMutex;

pub type SunsetMutex<T> = Mutex<SunsetRawMutex, T>;

pub(crate) struct Inner<'a> {
    runner: Runner<'a>,

    chan_read_wakers: [WakerRegistration; MAX_CHANNELS],

    chan_write_wakers: [WakerRegistration; MAX_CHANNELS],

    /// Will be a stderr read waker for a client, or stderr write waker for
    /// a server.
    chan_ext_wakers: [WakerRegistration; MAX_CHANNELS],
}

pub struct EmbassySunset<'a> {
    pub(crate) inner: Mutex<SunsetRawMutex, Inner<'a>>,

    progress_notify: Signal<SunsetRawMutex, ()>,
}

impl<'a> EmbassySunset<'a> {
    pub fn new(runner: Runner<'a>) -> Self {
        let inner = Inner {
            runner,
            chan_read_wakers: Default::default(),
            chan_write_wakers: Default::default(),
            chan_ext_wakers: Default::default(),
        };
        let inner = Mutex::new(inner);

        let progress_notify = Signal::new();

        Self {
            inner,
            progress_notify,
         }
    }

    pub async fn run<B: ?Sized, M: RawMutex>(&self,
        rsock: &mut impl asynch::Read,
        wsock: &mut impl asynch::Write,
        b: &Mutex<M, B>) -> Result<()>
        where
            for<'f> Behaviour<'f>: From<&'f mut B>
    {
        let tx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let mut buf = [0; 1024];
                let l = self.read(&mut buf).await?;
                let mut buf = &buf[..l];
                while buf.len() > 0 {
                    let n = wsock.write(buf).await.expect("TODO handle write error");
                    buf = &buf[n..];
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        let rx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let mut buf = [0; 1024];
                let l = rsock.read(&mut buf).await.expect("TODO handle read error");
                if l == 0 {
                    trace!("net EOF");
                    break
                }
                let mut buf = &buf[..l];
                while buf.len() > 0 {
                    let n = self.write(&buf).await?;
                    buf = &buf[n..];
                }
            }
            Ok::<_, sunset::Error>(())
        };

        let prog = async {
            loop {
                self.progress(b).await?
            }
        };

        // TODO: we might want to let `prog` run until buffers are drained
        // in case a disconnect message was received.
        // TODO Is there a nice way than this?
        match select3(rx, tx, prog).await {
            Either3::First(v) => v,
            Either3::Second(v) => v,
            Either3::Third(v) => v,
        }
    }


    fn wake_channels(&self, inner: &mut Inner) -> Result<()> {
        // Read wakers
        if let Some((chan, dt, _len)) = inner.runner.ready_channel_input() {
            // TODO: if there isn't any waker waiting, could we just drop the packet?
            match dt {
                ChanData::Normal => {
                    trace!("wake ch read dt {:?}", inner.chan_read_wakers[chan as usize]);
                    inner.chan_read_wakers[chan as usize].wake()
                }
                ChanData::Stderr => {
                    trace!("wake ch ext dt {:?}", inner.chan_ext_wakers[chan as usize]);
                    inner.chan_ext_wakers[chan as usize].wake()
                }
            }
        }

        // Write wakers
        for chan in 0..MAX_CHANNELS {
            // TODO: if this is slow we could be smarter about aggregating dt vs standard,
            // or handling the case of full out payload buffers.
            if inner.runner.ready_channel_send(chan as u32, ChanData::Normal)?.unwrap_or(0) > 0 {
                inner.chan_write_wakers[chan].wake()
            }

            if !inner.runner.is_client() {
                if inner.runner.ready_channel_send(chan as u32, ChanData::Stderr)?.unwrap_or(0) > 0 {
                    inner.chan_ext_wakers[chan].wake()
                }
            }
        }
        Ok(())
    }

    pub async fn progress<B: ?Sized, M: RawMutex>(&self,
        b: &Mutex<M, B>)
        -> Result<()>
        where
            for<'f> Behaviour<'f>: From<&'f mut B>
        {

            trace!("embassy progress");
        {
            let mut inner = self.inner.lock().await;
            {
                {
                    trace!("embassy progress inner");
                    let mut b = b.lock().await;
                    trace!("embassy progress behaviour lock");
                    let b: &mut B = &mut b;
                    let mut b: Behaviour = b.into();
                    inner.runner.progress(&mut b).await?;
                    trace!("embassy progress runner done");
                    // b is dropped, allowing other users
                }

                trace!("embassy progress wake chans");
                self.wake_channels(&mut inner)?
            }
            // inner dropped
        }

        // idle until input is received
        // TODO do we also want to wake in other situations?
        self.progress_notify.wait().await;

        Ok(())
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
            let r = match i.poll(cx) {
                Poll::Ready(mut inner) => {
                    f(&mut inner, cx)
                }
                Poll::Pending => {
                    // .inner lock is busy
                    Poll::Pending
                }
            };
            r
        })
        .await
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
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

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.poll_inner(|inner, cx| {
            if inner.runner.ready_input() {
                let r = match inner.runner.input(buf) {
                    Ok(0) => {
                        inner.runner.set_input_waker(cx.waker());
                        Poll::Pending
                    },
                    Ok(n) => Poll::Ready(Ok(n)),
                    Err(e) => Poll::Ready(Err(e)),
                };
                if r.is_ready() {
                    self.progress_notify.signal(())
                }
                r
            } else {
                Poll::Pending
            }
        }).await
    }

    /// Reads channel data.
    pub(crate) async fn read_channel(&self, ch: u32, dt: ChanData, buf: &mut [u8]) -> Result<usize> {
        if ch as usize > MAX_CHANNELS {
            return sunset::error::BadChannel { num: ch }.fail()
        }
        self.poll_inner(|inner, cx| {
            let l = inner.runner.channel_input(ch, dt, buf);
            if let Ok(0) = l {
                // 0 bytes read, pending
                match dt {
                    ChanData::Normal => {
                        trace!("register channel read {ch} waker {:?}", cx.waker());
                        inner.chan_read_wakers[ch as usize].register(cx.waker());
                    }
                    ChanData::Stderr => {
                        trace!("register channel dt {ch} waker {:?}", cx.waker());
                        inner.chan_ext_wakers[ch as usize].register(cx.waker());
                    }
                }
                Poll::Pending
            } else {
                Poll::Ready(l)
            }
        }).await
    }

    /// Reads normal channel data. If extended data is pending it will be discarded.
    // TODO delete this
    pub(crate) async fn read_channel_stdin(&self, ch: u32, buf: &mut [u8]) -> Result<usize> {
        if ch as usize > MAX_CHANNELS {
            return sunset::error::BadChannel { num: ch }.fail()
        }
        self.poll_inner(|inner, cx| {
            let l = inner.runner.channel_input(ch, ChanData::Normal, buf);
            if let Ok(0) = l {
                // 0 bytes read, pending
                trace!("register channel {ch} waker {:?}", cx.waker());
                inner.chan_read_wakers[ch as usize].register(cx.waker());
                // discard any `dt` input for this channel
                match inner.runner.discard_channel_input(ch) {
                    // bad channel is OK, perhaps the channel isn't running yet
                    Err(Error::BadChannel { .. }) => Ok(()),
                    r => r,
                }?;
                Poll::Pending
            } else {
                Poll::Ready(l)
            }
        }).await
    }

    // /// Reads channel data, returning the length read and optionally
    // /// whether it was dt data. Should only be called from
    // /// a single waker for both stdin and stderr, otherwise
    // /// will keep alternating wakers.
    // pub async fn read_channel_either(&self, ch: u32, buf: &mut [u8]) -> Result<(usize, Option<u32>)> {
    //     if ch as usize > MAX_CHANNELS {
    //         return sunset::error::BadChannel { num: ch }.fail()
    //     }
    //     self.poll_inner(|inner, cx| {
    //         let (l, dt) = inner.runner.channel_input_either(ch, buf);
    //         if let Ok(0) = l {
    //             // 0 bytes read, pending
    //             trace!("register channel {ch} waker {:?}", cx.waker());
    //             inner.chan_read_wakers[ch as usize].register(cx.waker());
    //             Poll::Pending
    //         } else {
    //             Poll::Ready((l, dt))
    //         }
    //     }).await
    // }

    pub(crate) async fn write_channel(&self, ch: u32, dt: ChanData, buf: &[u8]) -> Result<usize> {
        if ch as usize > MAX_CHANNELS {
            return sunset::error::BadChannel { num: ch }.fail()
        }
        self.poll_inner(|inner, cx| {
            let l = inner.runner.channel_send(ch, dt, buf);
            if let Ok(0) = l {
                // 0 bytes written, pending
                match dt {
                    ChanData::Normal => {
                        trace!("register channel write {ch} waker {:?}", cx.waker());
                        inner.chan_write_wakers[ch as usize].register(cx.waker());
                    }
                    ChanData::Stderr => {
                        trace!("register channel dt {ch} waker {:?}", cx.waker());
                        inner.chan_ext_wakers[ch as usize].register(cx.waker());
                    }
                }
                Poll::Pending
            } else {
                Poll::Ready(l)
            }
        }).await
    }
}

