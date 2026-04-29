use crate::{
    error::{SftpError, SftpResult},
    proto::{ENCODED_SSH_FXP_DATA_MIN_LENGTH, ReqId, SftpNum},
    protocol::StatusCode,
    server::{ReadReply, SftpSink},
    sftphandler::SftpOutputProducer,
};

use sunset::sshwire::SSHEncode;

use log::{debug, error};

pub struct ReadReplyHeader<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// Length of data to be sent as announced in [`ReadReply::send_header`]
    data_len: u32,
    /// Length of data sent so far using [`ReadReply::send_data`]
    data_sent_len: u32,
}

impl<'g, const N: usize> ReadReplyHeader<'g, N> {
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        Self { req_id, chan_out, data_len: 0, data_sent_len: 0 }
    }

    pub async fn send_header(
        &mut self,
        data_len: u32,
    ) -> SftpResult<ReadReplyData<'g, N>> {
        debug!(
            "ReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        let payload = ReadReplyHeader::<N>::encode_data_header(
            &mut sink,
            self.req_id,
            data_len,
        )?;

        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
        self.chan_out.send_data(payload).await?;
        self.data_len = data_len;
        Ok(ReadReplyData::new(self.req_id, self.chan_out))
    }

    pub async fn send_eof(&self) -> SftpResult<ReadReplyFinished<'g, N>> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await?;
        Ok(ReadReplyFinished::new(self.req_id, self.chan_out))
    }

    fn encode_data_header(
        sink: &'g mut SftpSink<'g>,
        req_id: ReqId,
        data_len: u32,
    ) -> Result<&'g [u8], SftpError> {
        // length field
        (data_len + ENCODED_SSH_FXP_DATA_MIN_LENGTH).enc(sink)?;
        // packet type (1)
        u8::from(SftpNum::SSH_FXP_DATA).enc(sink)?;
        // request id (4)
        req_id.enc(sink)?;
        // data length (4)
        data_len.enc(sink)?;
        Ok(sink.payload_slice())
    }
}

pub struct ReadReplyData<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// Length of data to be sent as announced in [`ReadReply::send_header`]
    data_len: u32,
    /// Length of data sent so far using [`ReadReply::send_data`]
    data_sent_len: u32,
}

impl<'g, const N: usize> ReadReplyData<'g, N> {
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        Self { req_id, chan_out, data_len: 0, data_sent_len: 0 }
    }

    pub async fn send_data(
        &mut self,
        buff: &[u8],
    ) -> SftpResult<ReadReplyDataResult<'g, N>> {
        if buff.len() as u32 > (self.data_len - self.data_sent_len) {
            error!(
                "Trying to send more data than announced in the header: \
                data_len = {:?}, data_sent_len = {:?}, buff_len = {:?}",
                self.data_len,
                self.data_sent_len,
                buff.len()
            );
            return Err(SftpError::FileServerError(StatusCode::SSH_FX_FAILURE));
        }

        self.chan_out.send_data(buff).await?;
        self.data_sent_len += buff.len() as u32;

        if self.data_len == self.data_sent_len {
            Ok(ReadReplyDataResult::Finished(ReadReplyFinished::new(
                self.req_id,
                self.chan_out,
            )))
        } else {
            Ok(ReadReplyDataResult::MoreData)
        }
    }
}

pub enum ReadReplyDataResult<'g, const N: usize> {
    MoreData,
    Finished(ReadReplyFinished<'g, N>),
}
pub struct ReadReplyFinished<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
}

impl<'g, const N: usize> ReadReplyFinished<'g, N> {
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        Self { req_id, chan_out: chan_out }
    }
}

#[cfg(test)]
mod enforcing_process_tests {
    use crate::sftphandler::{MockWriter, SftpOutputPipe};

    use super::*;

    #[cfg(test)]
    extern crate std;

    #[test]
    fn compose_header() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let data_len = 128;
        let mut buffer = [0u8; N];
        let mut sink = SftpSink::new(&mut buffer);

        let payload =
            ReadReplyHeader::<N>::encode_data_header(&mut sink, req_id, data_len)
                .unwrap();

        assert_eq!(
            data_len + ENCODED_SSH_FXP_DATA_MIN_LENGTH,
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        );
    }

    #[test]
    fn handling_process_eof() {
        const N: usize = 512;
        let mock_writer = MockWriter::new();
        let req_id = ReqId(42);
        let mut buffer = [0u8; N];
        let mut output_pipe = SftpOutputPipe::<N>::new();

        let (consumer, producer) =
            output_pipe.split(mock_writer).expect("Error splitting output_pipe");
        let mut header = ReadReplyHeader::new(req_id, &producer);

        // Run the consumer in the background to consume the data sent by the header and avoid deadlocks
        let consumer_task = async {
            consumer.receive_task().await.expect("Error running consumer task");
        };
        let producer_task = async {
            header.send_eof().await.expect("Error sending EOF");
        };
        embassy_futures::block_on(async {
            embassy_futures::select!(
                _ = consumer_task => {},
                _ = producer_task => {},
            );
        });
    }
}
