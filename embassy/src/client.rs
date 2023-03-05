use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embedded_io::asynch;

use sunset::*;

use crate::*;
use sunset::ChanData;
use embassy_sunset::EmbassySunset;
use embassy_channel::{ChanInOut, ChanIn};

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

    pub async fn run<B: ?Sized, M: RawMutex>(&self,
        rsock: &mut impl asynch::Read,
        wsock: &mut impl asynch::Write,
        b: &Mutex<M, B>) -> Result<()>
        where
            for<'f> Behaviour<'f>: From<&'f mut B>
    {
        self.sunset.run(rsock, wsock, b).await
    }

    pub async fn exit(&self) {
        self.sunset.exit().await
    }

    pub async fn open_session_nopty(&'a self, exec: Option<&str>)
    -> Result<(ChanInOut<'a>, ChanIn<'a>)> {
        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session(exec, None)
        }).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 2).await?;

        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        let cerr = ChanIn::new(num, ChanData::Stderr, &self.sunset);
        Ok((cstd, cerr))
    }

    pub async fn open_session_pty(&'a self, exec: Option<&str>, pty: Pty)
    -> Result<ChanInOut<'a>> {

        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session(exec, Some(pty))
        }).await?;

        let num = chan.num();
        self.sunset.add_channel(chan, 1).await?;
        let cstd = ChanInOut::new(num, ChanData::Normal, &self.sunset);
        Ok(cstd)
    }
}
