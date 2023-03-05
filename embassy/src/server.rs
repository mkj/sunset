use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embedded_io::asynch;

use sunset::*;

use crate::*;
use embassy_sunset::EmbassySunset;

pub struct SSHServer<'a> {
    sunset: EmbassySunset<'a>,
}

impl<'a> SSHServer<'a> {
    /* May return an error if RNG fails */
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        ) -> Result<Self> {
        let runner = Runner::new_server(inbuf, outbuf)?;
        let sunset = EmbassySunset::new(runner);
        Ok(Self { sunset })
    }

    pub async fn run<B: ?Sized, M: RawMutex>(&self,
        rsock: &mut impl asynch::Read,
        wsock: &mut impl asynch::Write,
        b: &Mutex<M, B>) -> Result<()>
        where
            for<'f> Behaviour<'f>: From<&'f mut B>
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
