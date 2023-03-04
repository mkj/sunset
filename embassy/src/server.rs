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

    pub fn stdio(&'a self, ch: ChanNum) -> ChanInOut<'a> {
        ChanInOut::new(ch, ChanData::Normal, &self.sunset)
    }

    pub fn stderr(&'a self, ch: ChanNum) -> ChanOut<'a> {
        ChanOut::new(ch, ChanData::Stderr, &self.sunset)
    }
}
