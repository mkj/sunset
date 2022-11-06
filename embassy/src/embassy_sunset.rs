#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use core::future::{poll_fn, Future};
use core::task::Poll;

use embassy_sync::waitqueue::WakerRegistration;
use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::signal::Signal;

use pin_utils::pin_mut;

use sunset::{Runner, Result, Behaviour, ServBehaviour, CliBehaviour};
use sunset::config::MAX_CHANNELS;

pub(crate) struct Inner<'a> {
    pub runner: Runner<'a>,

    pub chan_read_wakers: [WakerRegistration; MAX_CHANNELS],
    pub chan_write_wakers: [WakerRegistration; MAX_CHANNELS],
}

pub struct EmbassySunset<'a> {
    pub(crate) inner: Mutex<NoopRawMutex, Inner<'a>>,

    progress_notify: Signal<NoopRawMutex, ()>,
}

impl<'a> EmbassySunset<'a> {
    pub fn new(runner: Runner<'a>) -> Self {
        let inner = Inner {
            runner,
            chan_read_wakers: Default::default(),
            chan_write_wakers: Default::default(),
        };
        let inner = Mutex::new(inner);

        let progress_notify = Signal::new();

        Self {
            inner,
            progress_notify,
         }
    }

    fn wake_channels(&self, inner: &mut Inner) {

            if let Some((chan, _ext)) = inner.runner.ready_channel_input() {
                inner.chan_read_wakers[chan as usize].wake()
            }

            for chan in 0..MAX_CHANNELS {
                if inner.runner.ready_channel_send(chan as u32).unwrap_or(0) > 0 {
                    inner.chan_write_wakers[chan].wake()
                }
            }
    }

    // XXX could we have a concrete NoopRawMutex instead of M?
    pub async fn progress_server<M, B>(&self,
        b: &Mutex<M, B>)
        -> Result<()>
        where M: RawMutex, B: ServBehaviour
        {

        {
            let mut inner = self.inner.lock().await;
            {
                {
                    let mut b = b.lock().await;
                    warn!("progress locked");
                    // XXX: unsure why we need this explicit type
                    let b: &mut B = &mut b;
                    let mut b = Behaviour::new_server(b);
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

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        poll_fn(|cx| {
            // Attempt to lock .inner
            let i = self.inner.lock();
            pin_mut!(i);
            let r = match i.poll(cx) {
                Poll::Ready(mut inner) => {
                    match inner.runner.output(buf) {
                        // no output ready
                        Ok(0) => {
                            inner.runner.set_output_waker(cx.waker());
                            Poll::Pending
                        }
                        Ok(n) => Poll::Ready(Ok(n)),
                        Err(e) => Poll::Ready(Err(e)),
                    }
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

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        poll_fn(|cx| {
            let i = self.inner.lock();
            pin_mut!(i);
            let r = match i.poll(cx) {
                Poll::Ready(mut inner) => {
                    if inner.runner.ready_input() {
                        match inner.runner.input(buf) {
                            Ok(0) => {
                                inner.runner.set_input_waker(cx.waker());
                                Poll::Pending
                            },
                            Ok(n) => Poll::Ready(Ok(n)),
                            Err(e) => Poll::Ready(Err(e)),
                        }
                    } else {
                        Poll::Pending
                    }
                }
                Poll::Pending => {
                    // .inner lock is busy
                    Poll::Pending
                }
            };
            if r.is_ready() {
                // wake up .progress() to handle the input
                self.progress_notify.signal(())
            }
            r
        })
        .await
    }

    // pub async fn read_channel(&self, buf: &mut [u8]) -> Result<usize> {
}
