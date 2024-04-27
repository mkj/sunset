use embedded_io_async::{Read, Write};

use sunset::*;

use crate::*;
use embassy_sunset::{EmbassySunset, ProgressHolder};

/// An async SSH server instance 
///
/// The [`run()`][Self::run] method runs the session to completion. [`progress()`][Self::progress]
/// must be polled, and responses given to the events provided.
///
/// Once the client has opened sessions, those can be retrieved with [`stdio()`][Self::stdio]
/// and [`stdio_stderr()`][Self::stdio_stderr] methods.
///
/// This is async executor agnostic.
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

    /// Runs the session to completion.
    ///
    /// `rsock` and `wsock` are the SSH network channel (TCP port 22 or equivalent).
    pub async fn run(&'a self, rsock: &mut impl Read, wsock: &mut impl Write) -> Result<()> {
        self.sunset.run(rsock, wsock).await
    }

    /// Returns an event from the SSH Session
    ///
    /// Note that the returned `ProgressHolder` holds a mutex over the session,
    /// so other calls to `SSHServer` may block until it is dropped.
    pub async fn progress<'g, 'f>(&'g self, ph: &'f mut ProgressHolder<'g, 'a>)
        -> Result<ServEvent<'f, 'a>> {

        // poll until we get an actual event to return
        match self.sunset.progress(ph).await? {
            Event::Serv(x) => return Ok(x),
            _ => return Err(Error::bug()),
        }
    }

    /// Returns a [`ChanInOut`] representing a channel.
    ///
    /// For a shell this is stdin/stdout, for other channel types it is the only
    /// data type.
    /// `ch` is the [`ChanHandle`] provided from accepting a channel open [`ServEvent`].
    /// methods.
    pub async fn stdio(&self, ch: ChanHandle) -> Result<ChanInOut<'_, 'a>> {
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
    pub async fn stdio_stderr(&self, ch: ChanHandle)
        -> Result<(ChanInOut<'_, 'a>, ChanOut<'_, 'a>)> {
        let num = ch.num();
        self.sunset.add_channel(ch, 2).await?;
        let i = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        let e = ChanOut::new(num, ChanData::Stderr, &self.sunset);
        Ok((i, e))
    }

    // TODO: add stdio_stderr()
}
