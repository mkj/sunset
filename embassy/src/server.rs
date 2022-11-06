use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_futures::join::join3;
use embassy_net::tcp::TcpSocket;

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

    pub async fn run<M>(&self, socket: &mut TcpSocket<'_>, b: &Mutex<M, impl ServBehaviour>) -> Result<()>
        where M: RawMutex
    {
        let (mut rsock, mut wsock) = socket.split();

        let tx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let mut buf = [0; 1024];
                let l = self.read(&mut buf).await?;
                let mut buf = &buf[..l];
                while buf.len() > 0 {
                    let n = wsock.write(buf).await.expect("TODO handle write error");
                    buf = &buf[n..];
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        let rx = async {
            loop {
                // TODO: make sunset read directly from socket, no intermediate buffer.
                let mut buf = [0; 1024];
                let l = rsock.read(&mut buf).await.expect("TODO handle read error");
                let mut buf = &buf[..l];
                while buf.len() > 0 {
                    let n = self.write(&buf).await?;
                    buf = &buf[n..];
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        let prog = async {
            loop {
                self.progress(b).await?;
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };


        // TODO: handle results
        join3(rx, tx, prog).await;

        Ok(())
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
