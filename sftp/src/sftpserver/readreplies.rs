use crate::{
    error::{SftpError, SftpResult},
    proto::{ENCODED_SSH_FXP_DATA_HEADER, ReqId, SftpNum},
    protocol::StatusCode,
    sftphandler::SftpOutputProducer,
    sftpsink::SftpSink,
};

use embedded_io_async::Write;
use sunset::sshwire::SSHEncode;

use log::debug;

/// Used to provide the header of a read reply, including
/// only the fundamental information such as being an EOF reply or a data reply
///
/// On the corresponding method call will return either a [`crate::sftpserver::ReadDataReply`] or a [`crate::sftpserver::ReadReplyFinished`]
/// which makes easy to implement correct behavior.
pub struct ReadHeaderReply<'a, 'p, W: Write> {
    /// The request Id that will be used in the response
    req_id: ReqId,
    chan_out: &'a mut SftpOutputProducer<'p, W>,
}

impl<'a, 'p, W: Write> ReadHeaderReply<'a, 'p, W> {
    /// Creates a new ReadHeaderReply with the given request ID and output channel.
    ///
    /// It is meant to be called in [`crate::SftpHandler`] and used to call a method of the [`crate::sftpserver::SftpServer`] that requires a read reply header, such as [`crate::sftpserver::SftpServer::read`]
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'a mut SftpOutputProducer<'p, W>,
    ) -> Self {
        Self { req_id, chan_out }
    }

    /// Sends the header for a read reply with the given data length.
    ///
    /// Once used, the only way to obtain a [`ReadReplyFinished`] is by using its returned value.
    pub async fn send_header(
        self,
        data_len: u32,
    ) -> SftpResult<ReadDataReply<'a, 'p, W>> {
        debug!(
            "ReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );

        let (mut sink, w) = self.chan_out.sink();
        Self::encode_data_header(&mut sink, self.req_id, data_len)?;

        // debug!(
        //     "Sending header:  len = {:?}, content = {:?}",
        //     payload.len(),
        //     payload
        // );
        // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
        sink.send(w).await?;

        Ok(ReadDataReply::new(self.req_id, data_len, self.chan_out))
    }

    /// Sends an EOF status response for the read request.
    ///
    /// It will return a [`ReadReplyFinished`] that can be used to represent the state of the successful read reply.
    pub async fn send_eof(&mut self) -> SftpResult<ReadReplyFinished> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await?;
        Ok(ReadReplyFinished::new(self.req_id))
    }

    fn encode_data_header(
        sink: &mut SftpSink,
        req_id: ReqId,
        data_len: u32,
    ) -> Result<(), SftpError> {
        // length field
        (data_len + ENCODED_SSH_FXP_DATA_HEADER).enc(sink)?;
        // packet type (1)
        u8::from(SftpNum::SSH_FXP_DATA).enc(sink)?;
        // request id (4)
        req_id.enc(sink)?;
        // data length (4)
        data_len.enc(sink)?;
        Ok(())
    }
}

/// Helper struct to manage the sending of data in a read reply, ensuring that
/// no more than the announced data length is sent.
///
/// It is used as an argument in the closure passed to [`ReadDataReply::send_data`]
/// and it is meant to be used by the user to send the data of a read reply in chunks,
/// without having to worry about sending more data than the announced length.
pub struct LimitedSender<'a, 'g, W: Write> {
    chan_out: &'a mut SftpOutputProducer<'g, W>,
    remaining: core::cell::Cell<u32>,
}

impl<'a, 'g, W: Write> LimitedSender<'a, 'g, W> {
    fn new(chan_out: &'a mut SftpOutputProducer<'g, W>, limit: u32) -> Self {
        Self { chan_out, remaining: core::cell::Cell::new(limit) }
    }
    /// Sends a chunk of data, ensuring that no more than the announced data length is sent.
    ///
    /// It returns the remaining data length that can be sent after this call.
    pub async fn send_data(&mut self, buff: &[u8]) -> SftpResult<u32> {
        let mut remaining = self.remaining.get();

        let length_to_send = remaining.min(buff.len() as u32);
        self.chan_out.send_data(&buff[..length_to_send as usize]).await?;
        remaining -= length_to_send;
        self.remaining.set(remaining);
        Ok(remaining)
    }

    /// Obtains a [`CompletedDataSent`] if the announced data length has been completely sent, otherwise returns None.
    pub fn completed(&self) -> Option<CompletedDataSent> {
        if self.is_complete() { Some(CompletedDataSent) } else { None }
    }

    fn is_complete(&self) -> bool {
        self.remaining.get() == 0
    }
}

/// A marker struct to represent the completion of the data sending in a read reply
pub struct CompletedDataSent;

/// This struct is used to represent the state of a read reply after the header has been sent
/// but before the data has been completely sent or an EOF has been sent
pub struct ReadDataReply<'a, 'g, W: Write> {
    /// The request Id that will be used in the response
    req_id: ReqId,
    chan_out: &'a mut SftpOutputProducer<'g, W>,
    /// Length of data to be sent as announced in [`ReadHeaderReply::send_header`]
    data_len: u32,
}

impl<'a, 'g, W: Write> ReadDataReply<'a, 'g, W> {
    pub(crate) fn new(
        req_id: ReqId,
        data_len: u32,
        chan_out: &'a mut SftpOutputProducer<'g, W>,
    ) -> Self {
        Self { req_id, chan_out, data_len }
    }

    /// Sends a chunk of data, ensuring that no more than the announced data length is sent.
    /// It provides a closure-based API where the user can send multiple chunks of data until the announced data length is reached.
    ///
    /// It can only be called once, since it consumes self, and it returns a [`ReadReplyFinished`]
    /// that can be used to represent the state of the successful read reply.
    pub async fn send_data<F, Fut>(self, f: F) -> SftpResult<ReadReplyFinished>
    where
        F: FnOnce(LimitedSender<'a, 'g, W>) -> Fut,
        Fut: core::future::Future<Output = SftpResult<CompletedDataSent>>,
    {
        let sender = LimitedSender::new(self.chan_out, self.data_len);
        f(sender).await?;

        Ok(ReadReplyFinished::new(self.req_id))
    }
}

/// This struct is used to represent the state of a read reply after
/// the header and the data have been sent
///
/// It is used as a mandatory return value for a successful [`crate::sftpserver::SftpServer::read`]
/// operation
pub struct ReadReplyFinished {
    _req_id: ReqId,
}

impl ReadReplyFinished {
    pub(crate) fn new(_req_id: ReqId) -> Self {
        Self { _req_id }
    }
}

#[cfg(test)]
mod enforcing_process_tests {
    use crate::sftphandler::MockWriter;

    use super::*;

    extern crate std;

    #[test]
    fn compose_header() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let data_len = 128;
        let mut buffer = [0u8; N];
        let mut sink = SftpSink::new(&mut buffer);

        ReadHeaderReply::<MockWriter>::encode_data_header(
            &mut sink, req_id, data_len,
        )
        .unwrap();

        let payload = sink.payload_slice();
        assert_eq!(
            data_len + ENCODED_SSH_FXP_DATA_HEADER,
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        );
    }

    #[test]
    fn handling_process_eof() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let mut buf = [0u8; N];
        let mut mock = MockWriter::new();
        let mut producer = SftpOutputProducer::new(&mut mock, &mut buf);

        embassy_futures::block_on(async {
            {
                let mut header_reply = ReadHeaderReply::new(req_id, &mut producer);
                let _finished = header_reply
                    .send_eof()
                    .await
                    .expect("send_eof should succeed returning ReadReplyFinished");
            }
        });

        // SSH_FXP_STATUS (101) packet for SSH_FX_EOF (1) with req_id 42:
        // [len:4][type:1=101][req_id:4][code:4][msg_len:4][msg][lang_len:4][lang]
        let buf = &mock.buffer;
        // packet type byte should be 101 (SSH_FXP_STATUS)
        assert_eq!(buf[4], 101, "expected SSH_FXP_STATUS packet type");
        // status code should be 1 (SSH_FX_EOF)
        let code = u32::from_be_bytes(buf[9..13].try_into().unwrap());
        assert_eq!(code, 1, "expected SSH_FX_EOF status code");
    }
    #[test]
    fn handling_process_data() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let mut buf = [0u8; N];
        let mut mock = MockWriter::new();
        let mut producer = SftpOutputProducer::new(&mut mock, &mut buf);

        embassy_futures::block_on(async {
            {
                let header_reply = ReadHeaderReply::new(req_id, &mut producer);

                let data_reply = header_reply
                    .send_header(10)
                    .await
                    .expect("send_eof should succeed returning ReadReplyData");

                let _read_reply_finished = data_reply
                    .send_data(|mut limited_sender| async move {
                        loop {
                            match limited_sender.completed() {
                                Some(token) => return Ok(token),
                                None => limited_sender.send_data(&[0u8; 3]).await?,
                            };
                        }
                    })
                    .await
                    .expect("send_data should succeed returning ReadReplyFinished");
            }
        });

        let buf = &mock.buffer;
        // packet type byte should be 103 (SSH_FXP_DATA)
        assert_eq!(buf[4], 103, "expected SSH_FXP_DATA packet type");

        // data length should be 10
        let data_len = u32::from_be_bytes(
            buf[9..13]
                .try_into()
                .expect("data length should be present in the packet"),
        );
        assert_eq!(data_len, 10, "expected data length of 10 bytes");
        assert_eq!(
            buf.len(),
            13 + 10,
            "expected packet length to be header (13 bytes) + data (10 bytes)"
        );
    }
}
