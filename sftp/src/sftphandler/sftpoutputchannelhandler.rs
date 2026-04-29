use crate::error::{SftpError, SftpResult};
use crate::proto::{ReqId, SftpPacket, Status, StatusCode};
use crate::server::SftpSink;

use embassy_sync::pipe::{Pipe, Reader as PipeReader, Writer as PipeWriter};
use embedded_io_async::{ErrorType, Write};
use sunset::Error as SunsetError;
use sunset_async::SunsetRawMutex;

#[cfg(debug_assertions)]
use core::sync::atomic::AtomicUsize;
#[cfg(debug_assertions)]
use core::sync::atomic::Ordering;

use log::{debug, trace};

#[cfg(debug_assertions)]
type Counter = AtomicUsize;

pub struct SftpOutputPipe<const N: usize> {
    pipe: Pipe<SunsetRawMutex, N>,
    split: bool,
    #[cfg(debug_assertions)]
    counter_send: Counter,
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
            #[cfg(debug_assertions)]
            counter_send: Counter::new(0),
            split: false,
        }
    }

    /// Get a Consumer and Producer pair so the producer can send data to the
    /// output channel without mutable borrows.
    ///
    /// The [`SftpOutputConsumer`] needs to be running to write data to the
    /// provided writer.
    ///
    /// ## Lifetimes
    /// The lifetime `'a` ties the pipe reader (from `self`) to the consumer.
    /// The writer `W` carries its own lifetime if needed (e.g. `ChanOut<'a>`).
    pub fn split<'a, W>(&'a mut self, ssh_chan_out: W) -> SftpResult<(SftpOutputConsumer<'a, W, N>, SftpOutputProducer<'a, N>)>
    where
        W: Write + ErrorType<Error = SunsetError>,
    {
        if self.split {
            return Err(SftpError::AlreadyInitialized);
        }
        self.split = true;
        let (reader, writer) = self.pipe.split();
        Ok((
            SftpOutputConsumer {
                pipe_reader: reader,
                ssh_chan_out,
                #[cfg(debug_assertions)]
                counter: 0,
            },
            SftpOutputProducer {
                writer,
                #[cfg(debug_assertions)]
                counter: &self.counter_send,
            },
        ))
    }
}

/// Consumer that pipes data received from a [`PipeReader`] into a writer
/// implementing [`Write`].
///
/// N is the length of the
/// [PipeReader](https://docs.embassy.dev/embassy-sync/git/default/pipe/struct.Reader.html)
/// buffer used to receive the data.
pub(crate) struct SftpOutputConsumer<'a, W, const N: usize> {
    pipe_reader: PipeReader<'a, SunsetRawMutex, N>,
    /// The writer where the channel data is written to
    ssh_chan_out: W,
    /// Only used for debug purposes
    #[cfg(debug_assertions)]
    counter: usize,
}

impl<'a, W, const N: usize> SftpOutputConsumer<'a, W, N>
where
    W: Write + ErrorType<Error = SunsetError>,
{
    /// Run it to start the piping
    pub async fn receive_task(&mut self) -> SftpResult<()> {
        debug!("Running SftpOutout Consumer Reader task");
        let mut buf = [0u8; N];
        loop {
            let rl = self.pipe_reader.read(&mut buf).await;
            if rl == 0 {
                debug!("Output Consumer: Pipe closed, stopping receiving task");
                return Ok(());
            }
            #[cfg(debug_assertions)]
            {
                self.counter = self.counter.wrapping_add(buf.len());

                debug!(
                    "Output Consumer: ---> Reads {rl} bytes. Total {}",
                    self.counter
                );
            }
            let mut scanning_buffer = &buf[..rl];

            // Replaced write_all with loop to handle partial writes to discard issues in write_all
            while scanning_buffer.len() > 0 {
                trace!(
                    "Output Consumer: Tries to write {:?} bytes to ChanOut",
                    scanning_buffer.len()
                );
                let wl = self.ssh_chan_out.write(scanning_buffer).await?;
                debug!("Output Consumer: Written {:?} bytes ", wl);
                if wl < scanning_buffer.len() {
                    debug!(
                        "Output Consumer: ChanOut accepted only part of the buffer"
                    );
                }
                trace!(
                    "Output Consumer: Bytes written {:?}",
                    &scanning_buffer[..wl]
                );
                scanning_buffer = &scanning_buffer[wl..];
            }
            debug!("Output Consumer: Finished writing all bytes in read buffer");
        }
    }
}

/// Producer used to send data to a [`ChanOut`] without the restrictions
/// of mutable borrows
///
/// Under the hood it uses an
/// [embassy_sync Pipe](https://docs.embassy.dev/embassy-sync/git/default/pipe/struct.Pipe.html)
/// where N is the pipe buffer length in bytes
#[derive(Clone)]
pub struct SftpOutputProducer<'a, const N: usize> {
    writer: PipeWriter<'a, SunsetRawMutex, N>,
    #[cfg(debug_assertions)]
    counter: &'a Counter,
}
impl<'a, const N: usize> SftpOutputProducer<'a, N> {
    /// Sends the data encoded in the provided [`SftpSink`] without including
    /// the size.
    ///
    /// Use this when you are sending chunks of data after a valid header
    pub async fn send_data(&self, buf: &[u8]) -> SftpResult<()> {
        Self::send_buffer(
            &self.writer,
            &buf,
            #[cfg(debug_assertions)]
            &self.counter,
        )
        .await;
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
        Self::send_buffer(
            &self.writer,
            &sink.used_slice(),
            #[cfg(debug_assertions)]
            &self.counter,
        )
        .await;
        Ok(())
    }

    /// Internal associated method to log the writes to the pipe
    async fn send_buffer(
        writer: &PipeWriter<'a, SunsetRawMutex, N>,
        buf: &[u8],
        #[cfg(debug_assertions)] counter: &Counter,
    ) {
        #[cfg(debug_assertions)]
        {
            let total = counter.load(Ordering::Relaxed).wrapping_add(buf.len());
            counter.store(total, Ordering::Relaxed);

            debug!(
                "Output Producer: <--- Sends {:?} bytes. Total {total}",
                buf.len()
            );
            trace!("Output Producer: Sending buffer {:?}", buf);
        }

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

#[cfg(test)]
pub mod mock {
    extern crate std;
    use std::vec::Vec;

    use embedded_io_async::{ErrorType, Write};
    use sunset::Error as SunsetError;

    /// A mock writer that buffers all written bytes.
    ///
    /// Optionally injects a one-shot error on the next `write` call,
    /// after which writes succeed again.
    pub struct MockWriter {
        pub buffer: Vec<u8>,
        error: Option<SunsetError>,
    }

    impl MockWriter {
        pub fn new() -> Self {
            Self { buffer: Vec::new(), error: None }
        }

        /// Pre-load an error that will be returned on the next `write` call.
        pub fn inject_error(&mut self, e: SunsetError) {
            self.error = Some(e);
        }
    }

    impl ErrorType for MockWriter {
        type Error = SunsetError;
    }

    impl Write for MockWriter {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, SunsetError> {
            if let Some(e) = self.error.take() {
                return Err(e);
            }
            self.buffer.extend_from_slice(buf);
            Ok(buf.len())
        }
    }
}
