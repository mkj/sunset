use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::RawMutex;
use embedded_io::asynch;

use sunset::*;

use crate::*;
use embassy_sunset::EmbassySunset;
use embassy_channel::{ChanInOut, ChanExtIn};

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

    // pub async fn read_channel_stdin(&self, ch: u32, buf: &mut [u8]) -> Result<usize> {
    //     self.sunset.read_channel_stdin(ch, buf).await
    // }

    // pub async fn write_channel(&self, ch: u32, ext: Option<u32>, buf: &[u8]) -> Result<usize> {
    //     self.sunset.write_channel(ch, ext, buf).await
    // }

    pub async fn open_session_nopty(&'a self, exec: Option<&str>)
    -> Result<(ChanInOut<'a>, ChanExtIn<'a>)> {
        let chan = self.sunset.with_runner(|runner| {
            runner.open_client_session(exec, None)
        }).await?;

        let cstd = ChanInOut::new(chan, &self.sunset);
        let cerr = ChanExtIn::new(chan, sshnames::SSH_EXTENDED_DATA_STDERR, &self.sunset);
        Ok((cstd, cerr))
    }

    pub async fn open_session_pty(&self, exec: Option<&str>)
    -> Result<ChanInOut<'a>> {

        // XXX error handling
        todo!("open_session_pty");
        // let pty = pty::current_pty().expect("pty fetch");

        // let chan = self.sunset.with_runner(|runner| {
        //     runner.open_client_session(exec, Some(pty))
        // }).await?;

        // let cstd = ChanInOut::new(chan, &self.sunset);
        // Ok(cstd)
    }
}
