use embedded_io_async::{Read, Write};

use sunset::*;

use crate::*;
use async_sunset::{AsyncSunset, ProgressHolder};

/// An async SSH server instance
///
/// The [`run()`][Self::run] method runs the session to completion. [`progress()`][Self::progress]
/// must be polled, and responses given to the events provided.
///
/// Once the client has opened sessions, those can be retrieved with [`stdio()`][Self::stdio]
/// and [`stdio_stderr()`][Self::stdio_stderr] methods.
///
/// This is async executor agnostic.
#[derive(Debug)]
pub struct SSHServer<'a> {
    sunset: AsyncSunset<'a, sunset::Server>,
}

impl<'a> SSHServer<'a> {
    // May return an error if RNG fails
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8]) -> Self {
        let runner = Runner::new_server(inbuf, outbuf);
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
    /// so most other calls to `SSHServer` will block until the `ProgressHolder`
    /// is dropped.
    pub async fn progress<'g, 'f>(
        &'g self,
        ph: &'f mut ProgressHolder<'g, 'a, sunset::Server>,
    ) -> Result<ServEvent<'f, 'a>> {
        // poll until we get an actual event to return
        match self.sunset.progress(ph).await? {
            Event::Serv(x) => Ok(x),
            Event::None => Ok(ServEvent::PollAgain),
            Event::Progressed => Ok(ServEvent::PollAgain),
            Event::Cli(_) => Err(Error::bug()),
        }
    }

    /// Returns a [`ChanInOut`] representing a channel.
    ///
    /// `ch` is the [`ChanHandle`] returned after accepting a [`ServEvent::OpenSession`] event.
    /// If `stderr` is also needed, use [`stdio_stderr()`](Self::stdio_stderr) instead.
    pub async fn stdio(&self, ch: ChanHandle) -> Result<ChanInOut<'_>> {
        Ok(ChanInOut::new(self.sunset.add_channel(ch).await?))
    }

    /// Retrieve the stdin/stdout/stderr streams.
    ///
    /// See [`stdio()`](Self::stdio).
    pub async fn stdio_stderr(
        &self,
        ch: ChanHandle,
    ) -> Result<(ChanInOut<'_>, ChanOut<'_>)> {
        let io_normal = self.sunset.add_channel(ch).await?;
        let e = ChanOut::new(io_normal.clone_stderr());
        let i = ChanInOut::new(io_normal);
        Ok((i, e))
    }
}
