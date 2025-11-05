use crate::error::SftpResult;
use crate::proto::{ReqId, SftpPacket, Status, StatusCode};
use crate::server::SftpSink;

use sunset_async::ChanOut;

use embassy_sync::pipe::{Pipe, Reader as PipeReader, Writer as PipeWriter};
use embedded_io_async::Write;
use sunset_async::SunsetRawMutex;

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

// static' RAW_PIPE = Pipe::<SunsetRawMutex, 512>::new();

pub struct SftpOutputPipe<const N: usize> {
    pipe: Pipe<SunsetRawMutex, N>,
    capacity: usize,
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
        SftpOutputPipe { pipe: Pipe::new(), capacity: N }
    }

    /// Returns the inner pipe capacity. This method can be called after
    /// split.
    pub fn get_capacity(&self) -> usize {
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
    pub fn split<'a>(
        &'a mut self,
        ssh_chan_out: ChanOut<'a>,
    ) -> (SftpOutputConsumer<'a, N>, SftpOutputProducer<'a, N>) {
        let (reader, writer) = self.pipe.split();
        (SftpOutputConsumer { reader, ssh_chan_out }, SftpOutputProducer { writer })
    }
}
pub struct SftpOutputConsumer<'a, const N: usize> {
    reader: PipeReader<'a, SunsetRawMutex, N>,
    ssh_chan_out: ChanOut<'a>,
}
impl<'a, const N: usize> SftpOutputConsumer<'a, N> {
    /// Run it to start the piping
    pub async fn receive_task(&mut self) -> SftpResult<()> {
        debug!("Running SftpOutout Consumer Reader task");
        let mut buf = [0u8; N];
        loop {
            let rl = self.reader.read(&mut buf).await;
            debug!("Output Consumer Reader task: Reads {} bytes", rl);
            debug!("Output Consumer Reader task: Bytes {:?}", &buf[..rl]);
            if rl > 0 {
                self.ssh_chan_out.write_all(&buf[..rl]).await?;
            }
        }
    }
}

#[derive(Clone)]
pub struct SftpOutputProducer<'a, const N: usize> {
    writer: PipeWriter<'a, SunsetRawMutex, N>,
}
impl<'a, const N: usize> SftpOutputProducer<'a, N> {
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
        debug!("Output Producer: Pushing a status message: {:?}", response);
        self.send_packet(&response).await?;
        Ok(())
    }

    /// Push an SFTP Packet into the channel out
    pub async fn send_packet(&self, packet: &SftpPacket<'_>) -> SftpResult<()> {
        let mut buf = [0u8; N];
        let mut sink = SftpSink::new(&mut buf);
        packet.encode_response(&mut sink)?;
        debug!("Output Producer: Sending packet {:?}", packet);
        sink.finalize();
        Self::send_buffer(&self.writer, &sink.used_slice()).await;
        Ok(())
    }

    async fn send_buffer(writer: &PipeWriter<'a, SunsetRawMutex, N>, buf: &[u8]) {
        debug!("Output Producer: Sends {:?} bytes", buf.len());
        trace!("Output Producer: Sending buffer {:?}", buf);
        writer.write(buf).await;
    }
}
