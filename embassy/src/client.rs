use embedded_io_async::{Read, Write};

use sunset::*;

use crate::*;
use sunset::ChanData;
use embassy_sunset::EmbassySunset;
use embassy_channel::{ChanInOut, ChanIn};

/// An async SSH client instance 
///
/// The [`run()`][Self::run] method runs the session to completion, with application behaviour
/// defined by the [`CliBehaviour`] instance.
///
/// Once authentication has completed ([`authenticated()`][CliBehaviour] is called), the application
/// may open remote channels with [`open_session_pty()`][Self::open_session_pty] etc.
///
/// This is async executor agnostic, though requires the `CliBehaviour` instance
/// to be wrapped in a [`SunsetMutex`].
pub struct SSHClient<'a> {
    sunset: EmbassySunset<'a>,
}

impl<'a> SSHClient<'a> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        ) -> Result<Self> {
        let runner = Runner::new_client(inbuf, outbuf)?;
        let sunset = EmbassySunset::new(runner);
        Ok(Self { sunset })
    }

    /// Runs the session to completion.
    ///
    /// `rsock` and `wsock` are the SSH network channel (TCP port 22 or equivalent).
    /// `b` is an instance of [`CliBehaviour`] which defines application behaviour.
    pub async fn run<C: CliBehaviour>(&self,
        rsock: &mut impl Read,
        wsock: &mut impl Write,
        b: &SunsetMutex<C>) -> Result<()>
    {
        self.sunset.run(rsock, wsock, b).await
    }

    pub async fn exit(&self) {
        self.sunset.exit().await
    }

    pub async fn open_session_nopty(&'a self)
    -> Result<(ChanInOut<'a>, ChanIn<'a>)> {
        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session()
        }).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 2).await?;

        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        let cerr = ChanIn::new(num, ChanData::Stderr, &self.sunset);
        Ok((cstd, cerr))
    }

    pub async fn open_session_pty(&'a self) -> Result<ChanInOut<'a>> {
        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session()
        }).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 1).await?;
        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        Ok(cstd)
    }
}
