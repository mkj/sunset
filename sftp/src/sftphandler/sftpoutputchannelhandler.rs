#![no_std]
use crate::error::SftpResult;
use crate::proto::{ReqId, SftpPacket, Status, StatusCode};
use crate::server::SftpSink;

use sunset_async::ChanOut;

use embassy_sync::blocking_mutex::raw::RawMutex;
use embassy_sync::pipe::{Pipe, Reader as PipeReader, Writer as PipeWriter};
use embedded_io_async::Write;

use log::{debug, trace};

//// This is the beginning of a new idea:
/// I want to pass ref of an item where different methods in the sftphandler can
/// send data down the ChanOut. That would mutate the ChanOut (since it mutates on write)
/// and would violate the basic rule of only one mut borrow.
///
/// To overcome this hurdle, I can use a two part solution related with a channel or a pipe.
///
///
/// Some notes:
///
/// # sftpoutputchannelwrapper
/// Currently is a mutable entity. That causes issues since it needs to be mutated during loops.
/// ## first usage:
/// push SFTPEncode n times (composition)
// send_payload()
/// ## Second usage:
/// send_packet(SftpPacket)
/// ## last usage:
/// send_status('static str for messages) -> calls send_packet
/// # Alternative to avoid mutation: a channel or pipe
/// What would we put in the pipe?
/// ## 1st. composition:
/// We would create an SftpSink, add the SFTPEncode items and send it as a buffer. Maybe Len field eq to 0?
/// Maybe receive an SftpSink?
/// ## 2nd. SftpPacket
/// SftpSink, encode a packet, terminate it and send the SftpSink. len != 0
/// ## 3rd. SftpPacket::Status
/// Compose the Status SftpPacket, Encode it in SftpSink, finalise it, send the buffer
//

// enum AgentMsg { message to be sent}

// static' RAW_PIPE = Pipe::<NoopRawMutex, 512>::new();

pub struct SftpOutputPipe<M: RawMutex, const N: usize> {
    pipe: Pipe<M, N>,
    capacity: usize,
}

/// M: SunsetRawMutex
impl<M: RawMutex, const N: usize> SftpOutputPipe<M, N> {
    /// Creates an empty SftpOutputPipe.
    /// The output channel will be consumed during the split call
    ///
    ///  Usage:
    ///
    /// let output_pipe = SftpOutputPipe::<NoopRawMutex, 1024>::new();
    ///
    fn new() -> Self {
        SftpOutputPipe { pipe: Pipe::new(), capacity: N }
    }

    /// Returns the inner pipe capacity. This method can be called after
    /// split.
    fn get_capacity(&self) -> usize {
        self.capacity
    }

    // TODO: Check if it panics when called twice
    // TODO: Fix Doc links
    /// Get a Consumer and Producer pair so the producer can send data to the
    /// output channel without mutable borrows.
    ///
    /// The ['SftpOutputConsumer'] needs to be running to write data to the
    /// ['ChanOut']
    ///
    /// ## Lifetimes
    /// The lifetime indicates that the lifetime of self, ChanOut and the
    /// consumer and producer are the same. I chose this because if the ChanOut
    /// is closed, there is no point on having a pipe outliving it.
    fn split<'a>(
        &'a mut self,
        ssh_chan_out: ChanOut<'a>,
    ) -> (SftpOutputConsumer<'a, M, N>, SftpOutputProducer<'a, M, N>) {
        let (reader, writer) = self.pipe.split();
        (SftpOutputConsumer { reader, ssh_chan_out }, SftpOutputProducer { writer })
    }
}
pub struct SftpOutputConsumer<'a, M, const N: usize>
where
    M: RawMutex,
{
    reader: PipeReader<'a, M, N>,
    ssh_chan_out: ChanOut<'a>,
}
impl<'a, M, const N: usize> SftpOutputConsumer<'a, M, N>
where
    M: RawMutex,
{
    /// Run it to start the piping
    pub async fn receive_task(&mut self) -> SftpResult<()> {
        let mut buf = [0u8; N];
        loop {
            let rl = self.reader.read(&mut buf).await;
            debug!("Read {} bytes", rl);
            if rl > 0 {
                self.ssh_chan_out.write_all(&buf[..rl]).await?;
            }
        }
    }
}

#[derive(Clone)]
pub struct SftpOutputProducer<'a, M, const N: usize>
where
    M: RawMutex,
{
    writer: PipeWriter<'a, M, N>,
}
impl<'a, M, const N: usize> SftpOutputProducer<'a, M, N>
where
    M: RawMutex,
{
    pub async fn send_payload(&self, sftp_sink: &SftpSink<'_>) -> SftpResult<()> {
        let buf = sftp_sink.payload_slice();
        Self::send_buffer(&self.writer, &buf).await;
        Ok(())
    }

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
        debug!("Pushing a status message: {:?}", response);
        self.send_packet(&response).await?;
        Ok(())
    }

    /// Push an SFTP Packet into the channel out
    pub async fn send_packet(&self, packet: &SftpPacket<'_>) -> SftpResult<()> {
        let mut buf = [0u8; N];
        let mut sink = SftpSink::new(&mut buf);
        packet.encode_response(&mut sink);
        debug!("Sending packet {:?}", packet);
        Self::send_buffer(&self.writer, &buf).await;
        Ok(())
    }

    async fn send_buffer(writer: &PipeWriter<'a, M, N>, buf: &[u8]) {
        trace!("Sending buffer {:?}", buf);
        writer.write(buf).await;
    }
}
