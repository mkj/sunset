use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};

use sunset::*;

use crate::*;
use embassy_sunset::EmbassySunset;

pub struct SSHServer<'a> {
    sunset: EmbassySunset<'a>,
}

impl<'a> SSHServer<'a> {
    pub fn new(inbuf: &'a mut [u8], outbuf: &'a mut [u8],
        b: &mut (dyn ServBehaviour + Send),
        ) -> Result<Self> {
        let runner = Runner::new_server(inbuf, outbuf, b)?;
        let sunset = EmbassySunset::new(runner);
        Ok(Self { sunset })
    }

    pub async fn progress<M>(&self,
        b: &Mutex<M, impl ServBehaviour>)
        -> Result<()>
        where M: RawMutex
    {
        // let mut b = Behaviour::new_server(b);
        self.sunset.progress_server(b).await
    }

    // pub async fn channel(&mut self, ch: u32) -> Result<(ChanInOut<'a>, Option<ChanExtOut<'a>>)> {
    //     let ty = self.sunset.with_runner(|r| r.channel_type(ch)).await?;
    //     let inout = ChanInOut::new(ch, &self.sunset);
    //     // TODO ext
    //     let ext = None;
    //     Ok((inout, ext))
    // }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.sunset.read(buf).await
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        self.sunset.write(buf).await
    }
}
