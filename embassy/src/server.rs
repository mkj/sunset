use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embedded_io_async::{Read, Write};

use sunset::*;
use sunset::behaviour::UnusedCli;

use crate::*;
use embassy_sunset::EmbassySunset;

/// An async SSH server instance 
///
/// The [`run()`][Self::run] method runs the session to completion, with application behaviour
/// defined by the [`ServBehaviour`] instance.
///
/// Once the client has opened sessions, those can be retrieved with [`stdio()`][Self::stdio]
/// and [`stdio_stderr()`][Self::stdio_stderr] methods.
///
/// This is async executor agnostic, though requires the `ServBehaviour` instance
/// to be wrapped in an Embassy [`Mutex`].
pub struct SSHServer<'a> {
    sunset: EmbassySunset<'a>,
}

impl<'a> SSHServer<'a> {
    // May return an error if RNG fails
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        ) -> Result<Self> {
        let runner = Runner::new_server(inbuf, outbuf)?;
        let sunset = EmbassySunset::new(runner);
        Ok(Self { sunset })
    }

    pub async fn run<B: ?Sized, M: RawMutex, S: ServBehaviour>(&self,
        rsock: &mut impl Read,
        wsock: &mut impl Write,
        b: &Mutex<M, B>) -> Result<()>
        where
            for<'f> Behaviour<'f, UnusedCli, S>: From<&'f mut B>
    {
        self.sunset.run(rsock, wsock, b).await
    }

    /// Returns a [`ChanInOut`] representing a channel.
    ///
    /// For a shell this is stdin/stdout, for other channel types it is the only
    /// data type.
    /// `ch` is the [`ChanHandle`] passed to the application's `Behaviour`
    /// methods.
    pub async fn stdio(&'a self, ch: ChanHandle) -> Result<ChanInOut<'a>> {
        let num = ch.num();
        self.sunset.add_channel(ch, 1).await?;
        Ok(ChanInOut::new(num, ChanData::Normal, &self.sunset))
    }

    /// Retrieve the stdin/stdout/stderr streams.
    ///
    /// If stderr is not required, use [`stdio()`][Self::stdio] instead to avoid needing to poll
    /// the returned stderr.
    /// The session will block until the streams are drained (they use the session buffer),
    /// so they must be drained if used.
    pub async fn stdio_stderr(&'a self, ch: ChanHandle)
        -> Result<(ChanInOut<'a>, ChanOut<'a>)> {
        let num = ch.num();
        self.sunset.add_channel(ch, 2).await?;
        let i = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        let e = ChanOut::new(num, ChanData::Stderr, &self.sunset);
        Ok((i, e))
    }

    // TODO: add stdio_stderr()
}
