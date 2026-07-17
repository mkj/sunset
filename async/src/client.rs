use embedded_io_async::{Read, Write};

use sunset::*;

use crate::*;
use async_channel::{ChanIn, ChanInOut};
use async_sunset::{AsyncSunset, ProgressHolder};

/// An async SSH client instance
///
/// The [`run()`][Self::run] method runs the session to completion. [`progress()`][Self::progress]
/// must be polled, and responses given to the events provided.
///
/// Once authentication has completed (`progress()` returns [`CliEvent::Authenticated`]), the application
/// may open remote channels with [`open_session_pty()`][Self::open_session_pty] etc.
///
/// This is async executor agnostic.
pub struct SSHClient<'a> {
    sunset: AsyncSunset<'a, sunset::Client>,
}

impl<'a> SSHClient<'a> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8]) -> Self {
        let runner = Runner::new_client(inbuf, outbuf);
        let sunset = AsyncSunset::new(runner);
        Self { sunset }
    }

    /// Runs the session to completion.
    ///
    /// `rsock` and `wsock` are the SSH network channel (TCP port 22 or equivalent).
    pub async fn run(
        &self,
        rsock: &mut impl Read,
        wsock: &mut impl Write,
    ) -> Result<()> {
        self.sunset.run(rsock, wsock).await
    }

    /// Returns an event from the SSH session.
    ///
    /// Note that on return `ProgressHolder` holds a mutex over the session,
    /// so other calls to `SSHClient` may block until the `ProgressHolder`
    /// is dropped.
    pub async fn progress<'g, 'f>(
        &'g self,
        ph: &'f mut ProgressHolder<'g, 'a, sunset::Client>,
    ) -> Result<CliEvent<'f, 'a>> {
        match self.sunset.progress(ph).await? {
            Event::Cli(x) => Ok(x),
            Event::None => Ok(CliEvent::PollAgain),
            Event::Progressed => Ok(CliEvent::PollAgain),
            _ => Error::bug(),
        }
    }

    pub async fn open_session_nopty(&self) -> Result<(ChanInOut<'_>, ChanIn<'_>)> {
        let ch =
            self.sunset.with_runner(|runner| runner.open_client_session()).await?;

        let io_normal = self.sunset.add_channel(ch).await?;
        let e = ChanIn::new(io_normal.clone_stderr());
        let i = ChanInOut::new(io_normal);
        Ok((i, e))
    }

    pub async fn open_session_pty(&self) -> Result<ChanInOut<'_>> {
        let ch =
            self.sunset.with_runner(|runner| runner.open_client_session()).await?;

        Ok(ChanInOut::new(self.sunset.add_channel(ch).await?))
    }
}

#[cfg(feature = "alloc")]
impl SSHClient<'static> {
    pub fn new_owned() -> Self {
        let runner = Runner::<'static, _>::new_client_owned();
        let sunset = AsyncSunset::new(runner);
        Self { sunset }
    }
}

#[cfg(feature = "futures-io")]
impl SSHClient<'_> {
    pub async fn run_futures_io(
        &self,
        rsock: &mut (impl futures_io::AsyncRead + Unpin),
        wsock: &mut (impl futures_io::AsyncWrite + Unpin),
    ) -> Result<()> {
        let mut rsock = embedded_io_adapters::futures_03::FromFutures::new(rsock);
        let mut wsock = embedded_io_adapters::futures_03::FromFutures::new(wsock);
        self.sunset.run(&mut rsock, &mut wsock).await
    }
}

#[cfg(feature = "tokio")]
impl SSHClient<'_> {
    pub async fn run_tokio(
        &self,
        rsock: &mut (impl tokio::io::AsyncRead + Unpin),
        wsock: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<()> {
        let mut rsock = embedded_io_adapters::tokio_1::FromTokio::new(rsock);
        let mut wsock = embedded_io_adapters::tokio_1::FromTokio::new(wsock);
        self.sunset.run(&mut rsock, &mut wsock).await
    }
}
