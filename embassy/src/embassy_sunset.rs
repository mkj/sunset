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
use embassy_futures::select::select_slice;
use embedded_io::asynch;

use pin_utils::pin_mut;

use sunset::{Runner, Result, Error, Behaviour};
use sunset::config::MAX_CHANNELS;

// For now we only support single-threaded executors.
// In future this could be behind a cfg to allow different
// RawMutex for std executors or other situations.
type SunsetRawMutex = NoopRawMutex;

pub(crate) struct Inner<'a> {
    runner: Runner<'a>,

    // TODO: we might need separate normal/ext read and write
    // WakerRegistrations. otherwise they'll keep waking each other?

    chan_read_wakers: [WakerRegistration; MAX_CHANNELS],

    chan_write_wakers: [WakerRegistration; MAX_CHANNELS],
    /// this is set `true` when the associated `chan_write_wakers` entry
    /// was set for an ext write. This is needed because ext writes
    /// require more buffer, so have different wake conditions.
    ext_write_waker: [bool; MAX_CHANNELS],
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
            ext_write_waker: Default::default(),
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


    fn wake_channels(&self, inner: &mut Inner) {
        if let Some((chan, _ext, _len)) = inner.runner.ready_channel_input() {
            // TODO: if there isn't any waker waiting, should we just drop the packet?
            inner.chan_read_wakers[chan as usize].wake()
        }

        for chan in 0..MAX_CHANNELS {
            let ext = inner.ext_write_waker[chan];
            if inner.runner.ready_channel_send(chan as u32, ext).unwrap_or(0) > 0 {
                inner.chan_write_wakers[chan].wake()
            }
        }
    }

    pub async fn progress<B: ?Sized, M: RawMutex>(&self,
        b: &Mutex<M, B>)
        -> Result<()>
        where
            for<'f> Behaviour<'f>: From<&'f mut B>
        {

        {
            let mut inner = self.inner.lock().await;
            {
                {
                    let mut b = b.lock().await;
                    let b: &mut B = &mut b;
                    let mut b: Behaviour = b.into();
                    inner.runner.progress(&mut b).await?;
                    // b is dropped, allowing other users
                }

                self.wake_channels(&mut inner)
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

    /// Reads normal channel data. If extended data is pending it will be discarded.
    pub async fn read_channel_stdin(&self, ch: u32, buf: &mut [u8]) -> Result<usize> {
        if ch as usize > MAX_CHANNELS {
            return Err(Error::BadChannel)
        }
        self.poll_inner(|inner, cx| {
            let l = inner.runner.channel_input(ch, None, buf);
            if let Ok(0) = l {
                // 0 bytes read, pending
                inner.chan_read_wakers[ch as usize].register(cx.waker());
                // discard any `ext` input for this channel
                inner.runner.discard_channel_input(ch);
                Poll::Pending
            } else {
                Poll::Ready(l)
            }
        }).await
    }

    pub async fn write_channel(&self, ch: u32, ext: Option<u32>, buf: &[u8]) -> Result<usize> {
        if ch as usize > MAX_CHANNELS {
            return Err(Error::BadChannel)
        }
        self.poll_inner(|inner, cx| {
            let l = inner.runner.channel_send(ch, ext, buf);
            if let Ok(0) = l {
                // 0 bytes written, pending
                inner.chan_write_wakers[ch as usize].register(cx.waker());
                inner.ext_write_waker[ch as usize] = ext.is_some();
                Poll::Pending
            } else {
                Poll::Ready(l)
            }
        }).await
    }
}

