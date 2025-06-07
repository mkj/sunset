use embedded_io_async::{Read, Write};

use sunset::*;

use crate::*;
use async_channel::{ChanIn, ChanInOut};
use async_sunset::{AsyncSunset, ProgressHolder};
use sunset::ChanData;

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
            Event::None => return Ok(CliEvent::PollAgain),
            Event::Progressed => Ok(CliEvent::PollAgain),
            _ => Err(Error::bug()),
        }
    }

    pub async fn open_session_nopty(&self) -> Result<(ChanInOut<'_>, ChanIn<'_>)> {
        let chan =
            self.sunset.with_runner(|runner| runner.open_client_session()).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 2).await?;

        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        let cerr = ChanIn::new(num, ChanData::Stderr, &self.sunset);
        Ok((cstd, cerr))
    }

    pub async fn open_session_pty(&self) -> Result<ChanInOut<'_>> {
        let chan =
            self.sunset.with_runner(|runner| runner.open_client_session()).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 1).await?;
        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        Ok(cstd)
    }
}
