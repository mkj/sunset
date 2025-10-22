use crate::error::SftpResult;
use crate::proto::ReqId;
use crate::proto::SftpPacket;
use crate::proto::Status;
use crate::protocol::StatusCode;
use crate::server::SftpSink;

use sunset::sshwire::WireError;
use sunset_async::ChanOut;

use embedded_io_async::Write;
#[allow(unused_imports)]
use log::{debug, info, trace, warn};

/// Wrapper structure to handle SFTP output operations
///
/// It wraps an SftpSink and a ChanOut to facilitate sending SFTP packets
/// even when they require multiple iterations
pub struct SftpOutputChannelWrapper<'a, 'g> {
    sink: SftpSink<'a>,
    channel_out: ChanOut<'g>,
}

impl<'a, 'g> SftpOutputChannelWrapper<'a, 'g> {
    /// Creates a new OutputWrapper
    ///
    /// This structure wraps an SftpSink and a ChanOut to facilitate
    /// sending SFTP packets even when they require multiple steps
    pub fn new(buffer: &'a mut [u8], channel_out: ChanOut<'g>) -> Self {
        let sink = SftpSink::new(buffer);
        SftpOutputChannelWrapper { channel_out, sink }
    }

    /// Finalizes (Prepends the packet length) and send the data in the
    /// buffer by the subsystem channel out
    pub async fn send_buffer(&mut self) -> SftpResult<usize> {
        if self.sink.payload_len() == 0 {
            debug!("No data to send in the SFTP sink");
            return Ok(0);
        }
        self.sink.finalize();
        let buffer = self.sink.used_slice();
        info!("Sending buffer: '{:?}'", buffer);
        let written = self.channel_out.write(buffer).await?;
        self.sink.reset();
        Ok(written)
    }

    /// Send the data in the buffer by the subsystem channel out without
    ///  prepending the packet length to it.
    ///     
    /// This is useful when an SFTP packet header has already being sent
    /// or when the data requires an special treatment
    pub async fn send_payload(&mut self) -> SftpResult<usize> {
        let payload = self.sink.payload_slice();
        info!("Sending payload: '{:?}'", payload);
        let written = self.channel_out.write(payload).await?;
        self.sink.reset();
        Ok(written)
    }

    /// Push a status message into the channel out
    pub async fn send_status(
        &mut self,
        req_id: ReqId,
        status: StatusCode,
        msg: &'static str,
    ) -> Result<(), WireError> {
        let response = SftpPacket::Status(
            req_id,
            Status { code: status, message: msg.into(), lang: "en-US".into() },
        );
        trace!("Pushing a status message: {:?}", response);
        self.send_packet(response);

        Ok(())
    }

    /// Push an SFTP Packet into the channel out
    pub async fn send_packet(
        &mut self,
        packet: SftpPacket<'_>,
    ) -> Result<(), WireError> {
        packet.encode_response(&mut self.sink)?;
        self.send_buffer().await?;
        Ok(())
    }

    pub async fn push(&mut self, item: &impl SSHEncode) -> Result<(), WireError> {
        item.enc(&mut self.sink)?;
        self.send_buffer().await?;
        Ok(())
    }
}
