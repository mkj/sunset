use crate::error::{SftpError, SftpResult};
use crate::proto::{ReqId, SftpPacket, Status, StatusCode};
use crate::sftpsink::SftpSink;

use embedded_io_async::Write;

use log::{debug, trace};

/// Handle to send data to an output channel.
pub struct SftpOutputProducer<'a, W: Write> {
    writer: &'a mut W,
    buf: &'a mut [u8],
}

impl<'a, W: Write> SftpOutputProducer<'a, W> {
    pub fn new(writer: &'a mut W, buf: &'a mut [u8]) -> Self {
        Self { writer, buf }
    }

    // TODO: if/when rust async drop is implemented, flush there.
    /// Flush output
    pub async fn flush(&mut self) -> SftpResult<()> {
        self.writer.flush().await.map_err(|e| SftpError::from_embedded_io(e))
    }

    /// Sends the data encoded in the provided [`SftpSink`] without including
    /// the size.
    ///
    /// Use this when you are sending chunks of data after a valid header
    pub async fn send_data(&mut self, buf: &[u8]) -> SftpResult<()> {
        self.writer.write_all(buf).await.map_err(|e| SftpError::from_embedded_io(e))
    }

    /// Simplifies the task of sending a status response to the client.
    pub async fn send_status(
        &mut self,
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
    pub async fn send_packet(&mut self, packet: &SftpPacket<'_>) -> SftpResult<()> {
        let mut sink = SftpSink::new(self.buf);
        packet.encode_response(&mut sink)?;
        debug!("Output Producer: Sending packet {:?}", packet);

        self.writer
            .write_all(&sink.used_slice())
            .await
            .map_err(|e| SftpError::from_embedded_io(e))
    }

    pub fn sink(&mut self) -> (SftpSink<'_>, &mut W) {
        (SftpSink::new(self.buf), self.writer)
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

        async fn flush(&mut self) -> Result<(), SunsetError> {
            Ok(())
        }
    }
}
