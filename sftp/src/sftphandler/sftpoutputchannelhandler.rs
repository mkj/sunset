use crate::error::{SftpError, SftpResult};
use crate::proto::{ReqId, SftpPacket, Status, StatusCode};
use crate::server::SftpSink;

use embassy_sync::mutex::Mutex;
use sunset_async::ChanOut;

use embassy_sync::pipe::{Pipe, Reader as PipeReader, Writer as PipeWriter};
use embedded_io_async::Write;
use sunset_async::SunsetRawMutex;

use log::{debug, error, trace};

type CounterMutex = Mutex<SunsetRawMutex, usize>;

pub struct SftpOutputPipe<const N: usize> {
    pipe: Pipe<SunsetRawMutex, N>,
    counter_send: CounterMutex,
    counter_recv: CounterMutex,
    splitted: bool,
}

/// M: SunsetSunsetRawMutex
impl<const N: usize> SftpOutputPipe<N> {
    /// Creates an empty SftpOutputPipe.
    /// The output channel will be consumed during the split call
    ///
    ///  Usage:
    ///
    /// let output_pipe = SftpOutputPipe::<NoopSunsetRawMutex, 1024>::new();
    ///
    pub fn new() -> Self {
        SftpOutputPipe {
            pipe: Pipe::new(),
            counter_send: Mutex::<SunsetRawMutex, usize>::new(0),
            counter_recv: Mutex::<SunsetRawMutex, usize>::new(0),
            splitted: false,
        }
    }

    // TODO: Check if it panics when called twice
    /// Get a Consumer and Producer pair so the producer can send data to the
    /// output channel without mutable borrows.
    ///
    /// The [`SftpOutputConsumer`] needs to be running to write data to the
    /// [`ChanOut`]
    ///
    /// ## Lifetimes
    /// The lifetime indicates that the lifetime of self, ChanOut and the
    /// consumer and producer are the same. I chose this because if the ChanOut
    /// is closed, there is no point on having a pipe outliving it.
    pub fn split<'a>(
        &'a mut self,
        ssh_chan_out: ChanOut<'a>,
    ) -> SftpResult<(SftpOutputConsumer<'a, N>, SftpOutputProducer<'a, N>)> {
        if self.splitted {
            return Err(SftpError::AlreadyInitialized);
        }
        self.splitted = true;
        let (reader, writer) = self.pipe.split();
        Ok((
            SftpOutputConsumer { reader, ssh_chan_out, counter: &self.counter_recv },
            SftpOutputProducer { writer, counter: &self.counter_send },
        ))
    }
}

/// Consumer that takes ownership of [`ChanOut`]. It pipes the data received
/// from a [`PipeReader`] into the channel
pub(crate) struct SftpOutputConsumer<'a, const N: usize> {
    reader: PipeReader<'a, SunsetRawMutex, N>,
    ssh_chan_out: ChanOut<'a>,
    counter: &'a CounterMutex,
}

impl<'a, const N: usize> SftpOutputConsumer<'a, N> {
    /// Run it to start the piping
    pub async fn receive_task(&mut self) -> SftpResult<()> {
        // TODO: Revert to the simpler version once the root cause of the stall is found
        // debug!("Running SftpOutout Consumer Reader task");
        // let mut buf = [0u8; N];
        // loop {
        //     let rl = self.reader.read(&mut buf).await;
        //     let mut _total = 0;
        //     {
        //         let mut lock = self.counter.lock().await;
        //         *lock += rl;
        //         _total = *lock;
        //     }

        //     debug!("Output Consumer: ---> Reads {rl} bytes. Total {_total}");
        //     if rl > 0 {
        //         self.ssh_chan_out.write_all(&buf[..rl]).await?;
        //         debug!("Output Consumer: Written {:?} bytes ", &buf[..rl].len());
        //         trace!("Output Consumer: Bytes written {:?}", &buf[..rl]);
        //     } else {
        //         error!("Output Consumer: Empty array received");
        //     }
        // }
        debug!("Running SftpOutout Consumer Reader task");
        let mut buf = [0u8; N];
        loop {
            let rl = self.reader.read(&mut buf).await;
            let mut _total = 0;
            {
                let mut lock = self.counter.lock().await;
                *lock += rl;
                _total = *lock;
            }

            trace!("Output Consumer: ---> Reads {rl} bytes. Total {_total}");
            let mut scanning_buffer = &buf[..rl];
            if rl > 0 {
                // Replaced write_all with loop to handle partial writes to discard issues in write_all
                while scanning_buffer.len() > 0 {
                    trace!(
                        "Output Consumer: Tries to write {:?} bytes to ChanOut",
                        scanning_buffer.len()
                    );
                    let wl = self.ssh_chan_out.write(scanning_buffer).await?;
                    debug!("Output Consumer: Written {:?} bytes ", wl);
                    if wl< scanning_buffer.len() {
                        debug!("Output Consumer: ChanOut accepted only part of the buffer");
                    }
                    trace!(
                        "Output Consumer: Bytes written {:?}",
                        &scanning_buffer[..wl]
                    );
                    scanning_buffer = &scanning_buffer[wl..];
                }
                debug!("Output Consumer: Finished writing all bytes in read buffer");
            } else {
                error!("Output Consumer: Empty array received");
            }
        }
    }
}

/// Producer used to send data to a [`ChanOut`] without the restrictions
/// of mutable borrows
#[derive(Clone)]
pub struct SftpOutputProducer<'a, const N: usize> {
    writer: PipeWriter<'a, SunsetRawMutex, N>,
    counter: &'a CounterMutex,
}
impl<'a, const N: usize> SftpOutputProducer<'a, N> {
    /// Sends the data encoded in the provided [`SftpSink`] without including
    /// the size.
    ///
    /// Use this when you are sending chunks of data after a valid header
    pub async fn send_data(&self, buf: &[u8]) -> SftpResult<()> {
        Self::send_buffer(&self.writer, &buf, &self.counter).await;
        Ok(())
    }

    /// Simplifies the task of sending a status response to the client.
    pub async fn send_status(
        &self,
        req_id: ReqId,
        status: StatusCode,
        msg: &'static str,
    ) -> SftpResult<()> {
        let response = SftpPacket::Status(
            req_id,
            Status { code: status, message: msg.into(), lang: "en-US".into() },
        );
        trace!("Output Producer: Pushing a status message: {:?}", response);
        self.send_packet(&response).await?;
        Ok(())
    }

    /// Sends a SFTP Packet into the channel out, including the length field
    pub async fn send_packet(&self, packet: &SftpPacket<'_>) -> SftpResult<()> {
        let mut buf = [0u8; N];
        let mut sink = SftpSink::new(&mut buf);
        packet.encode_response(&mut sink)?;
        debug!("Output Producer: Sending packet {:?}", packet);
        Self::send_buffer(&self.writer, &sink.used_slice(), &self.counter).await;
        Ok(())
    }

    /// Internal associated method to log the writes to the pipe
    async fn send_buffer(
        writer: &PipeWriter<'a, SunsetRawMutex, N>,
        buf: &[u8],
        counter: &CounterMutex,
    ) {
        let mut _total = 0;
        {
            let mut lock = counter.lock().await;
            *lock += buf.len();
            _total = *lock;
        }

        trace!("Output Producer: <--- Sends {:?} bytes. Total {_total}", buf.len());
        trace!("Output Producer: Sending buffer {:?}", buf);

        // writer.write_all(buf); // ??? error[E0596]: cannot borrow `*writer` as mutable, as it is behind a `&` reference

        let mut buf = buf;
        loop {
            if buf.len() == 0 {
                break;
            }

            trace!("Output Producer: Tries to send {:?} bytes", buf.len());
            let bytes_sent = writer.write(&buf).await;
            buf = &buf[bytes_sent..];
            trace!(
                "Output Producer: sent {bytes_sent:?}. {:?} bytes remain ",
                buf.len()
            );
        }
    }
}
