use crate::{
    error::{SftpError, SftpResult},
    proto::{
        ENCODED_SSH_FXP_NAME_HEADER, MAX_NAME_ENTRY_SIZE, NameEntry, ReqId, SftpNum,
    },
    protocol::StatusCode,
    server::SftpSink,
    sftphandler::SftpOutputProducer,
};

use sunset::sshwire::SSHEncode;

use log::{debug, error};

/// Structures and helpers to handle the process of sending read replies for readdir operations in a structured way.
///
/// Enforces the correct sequence of sending a DirRead reply,
/// which consists of first sending a header with the announced data length using [`DirReadHeaderReply::send_header`] and then sending the data itself using [`DirReadDataReply::send_data`].
pub struct DirReadHeaderReply<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
}

impl<'g, const N: usize> DirReadHeaderReply<'g, N> {
    /// Creates a new DirReadHeaderReply with the given request ID and output channel.
    ///
    /// It is meant to be called in [`SftpHandler`] and used to call a method of the [`SftpServer`] that requires a read reply header, such as [`SftpServer::readdir`]
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        Self { req_id, chan_out }
    }

    // /// Sends the header for a read reply with the given data length.
    // ///
    // /// Once used, the only way to obtain a [`DirReadReplyFinished`] is by using its returned value.
    // pub async fn send_header(
    //     self,
    //     data_len: u32,
    // ) -> SftpResult<DirReadDataReply<'g, N>> {
    //     debug!(
    //         "DirReadReply: Sending header for request id {:?}: data length = {:?}",
    //         self.req_id, data_len
    //     );
    //     let mut s = [0u8; N];
    //     let mut sink = SftpSink::new(&mut s);

    //     let payload = DirReadHeaderReply::<N>::encode_data_header(
    //         &mut sink,
    //         self.req_id,
    //         data_len,
    //     )
    //     .map_err(|err| {
    //         error!("WireError: {:?}", err);
    //         StatusCode::SSH_FX_FAILURE
    //     })?;

    //     debug!(
    //         "Sending header:  len = {:?}, content = {:?}",
    //         payload.len(),
    //         payload
    //     );
    //     // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
    //     self.chan_out.send_data(payload).await?;

    //     Ok(DirReadDataReply::new(self.req_id, data_len, self.chan_out))
    // }
    /// Sends the header for a read reply with the given data length.
    ///
    /// Once used, the only way to obtain a [`DirReadReplyFinished`] is by using its returned value.
    pub async fn send_header(
        self,
        data_len: u32,
        count: u32,
    ) -> SftpResult<DirReadDataReply<'g, N>> {
        debug!(
            "DirReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        let payload = DirReadHeaderReply::<N>::encode_header(
            &mut sink,
            self.req_id,
            data_len,
            count,
        )
        .map_err(|err| {
            error!("WireError: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })?;

        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
        self.chan_out.send_data(payload).await?;

        Ok(DirReadDataReply::new(self.req_id, data_len, self.chan_out))
    }

    /// Sends an EOF status response for the read request.
    ///
    /// It will return a [`DirReadReplyFinished`] that can be used to represent the state of the successful read reply.
    pub async fn send_eof(&self) -> SftpResult<DirReadReplyFinished> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await?;
        Ok(DirReadReplyFinished::new(self.req_id))
    }

    fn encode_header(
        sink: &'g mut SftpSink<'g>,
        req_id: ReqId,
        data_len: u32,
        count: u32,
    ) -> Result<&'g [u8], SftpError> {
        // length field
        (data_len + ENCODED_SSH_FXP_NAME_HEADER).enc(sink)?;
        // packet type (1)
        u8::from(SftpNum::SSH_FXP_NAME).enc(sink)?;
        // request id (4)
        req_id.enc(sink)?;
        count.enc(sink)?;
        Ok(sink.payload_slice())
    }
}

/// Represents the state of a successful read reply for a readdir operation after the
/// header has been sent and the data has been completely sent or an EOF status has been sent.
pub struct DirReadReplyFinished {
    /// The request Id that will be use`d in the response
    _req_id: ReqId,
}

impl DirReadReplyFinished {
    pub(crate) fn new(req_id: ReqId) -> Self {
        Self { _req_id: req_id }
    }
}

/// Helper struct to enforce the correct sequence of sending directory items in a readdir
///  reply, which consists of sending items until the announced data length is reached.
pub struct LimitedDirSender<'g, const N: usize> {
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// remaining data length to be sent as announced in [`DirReadDataReply::send_data`]
    ///  when calling the closure with this LimitedDirSender as an argument.
    remaining: core::cell::Cell<u32>,
}

impl<'g, const N: usize> LimitedDirSender<'g, N> {
    fn new(chan_out: &'g SftpOutputProducer<'g, N>, limit: u32) -> Self {
        Self { chan_out, remaining: core::cell::Cell::new(limit) }
    }

    /// Sends a directory item to the client as a [`NameEntry`]
    ///
    /// Call this
    pub async fn send_item(
        &mut self,
        name_entry: &NameEntry<'_>,
    ) -> SftpResult<u32> {
        let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut sftp_sink = SftpSink::new(&mut buffer);
        name_entry.enc(&mut sftp_sink)?;

        self.send_data(sftp_sink.payload_slice()).await
    }
    /// Obtains a [`CompleteDirDataSent`] if the announced data length has been completely sent, otherwise returns None.
    pub fn completed(&self) -> Option<CompleteDirDataSent> {
        if self.is_complete() { Some(CompleteDirDataSent) } else { None }
    }

    async fn send_data(&self, buff: &[u8]) -> SftpResult<u32> {
        let mut remaining = self.remaining.get();

        let length_to_send = remaining.min(buff.len() as u32);
        self.chan_out.send_data(&buff[..length_to_send as usize]).await?;
        remaining -= length_to_send;
        self.remaining.set(remaining);
        Ok(remaining)
    }

    fn is_complete(&self) -> bool {
        self.remaining.get() == 0
    }
}

/// Token struct to represent the state of having sent all the announced data for a readdir reply.
///
/// It can only be obtained by calling [`LimitedDirSender::completed`] after having
/// sent items with [`LimitedDirSender::send_item`] until the announced data length is reached.
///
/// It is used to guarantee that all the announced data has been sent in the closure
/// provided to [`DirReadDataReply::send_data`] before being able to return a [`DirReadReplyFinished`]
/// and thus completing the readdir reply process.
pub struct CompleteDirDataSent;

/// Helper struct to enforce the correct sequence of sending a readdir reply,
///  which consists of first sending a header with the announced data length
/// using [`DirReadHeaderReply::send_header`] and then sending the data
///  itself using [`DirReadDataReply::send_data`].
pub struct DirReadDataReply<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Length of data to be sent as announced in [`DirReadHeaderReply::send_header`]
    data_len: u32,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
}

impl<'g, const N: usize> DirReadDataReply<'g, N> {
    pub(crate) fn new(
        req_id: ReqId,
        data_len: u32,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        Self { req_id, chan_out, data_len }
    }

    /// It provides a closure-based API where the user can send multiple [`NameEntry`]s of data until the announced data length is reached.
    ///
    /// It can only be called once, since it consumes self, and it returns a [`DirReadReplyFinished`]
    /// that can be used to represent the state of the successful read reply.
    pub async fn send_data<F, Fut>(self, f: F) -> SftpResult<DirReadReplyFinished>
    where
        F: FnOnce(LimitedDirSender<'g, N>) -> Fut,
        Fut: core::future::Future<Output = SftpResult<CompleteDirDataSent>>,
    {
        let dir_sender = LimitedDirSender::new(self.chan_out, self.data_len);
        f(dir_sender).await?;

        Ok(DirReadReplyFinished::new(self.req_id))
    }
}

#[cfg(test)]
mod enforcing_process_tests {

    use super::*;

    use crate::{
        proto::{Attrs, Filename, NameEntry},
        server::helpers,
        sftphandler::{MockWriter, SftpOutputPipe},
    };

    extern crate alloc;
    extern crate std;
    use alloc::vec;
    use std::vec::Vec;

    #[test]
    fn handling_process_eof() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let mut output_pipe = SftpOutputPipe::<N>::new();
        let mock = MockWriter::new();
        let (mut consumer, producer) =
            output_pipe.split(mock).expect("split should succeed");

        embassy_futures::block_on(async {
            {
                let dir_header_reply =
                    DirReadHeaderReply::<N>::new(req_id, &producer);
                let _finished = dir_header_reply
                    .send_eof()
                    .await
                    .expect("send_eof should succeed returning ReadReplyFinished");
            }
            drop(producer);
            // Read exactly the one packet written by send_eof; does not loop.
            consumer.receive_once().await.unwrap();
        });

        // SSH_FXP_STATUS (101) packet for SSH_FX_EOF (1) with req_id 42:
        // [len:4][type:1=101][req_id:4][code:4][msg_len:4][msg][lang_len:4][lang]
        let mock = consumer.into_inner();
        let buf = &mock.buffer;
        // packet type byte should be 101 (SSH_FXP_STATUS)
        assert_eq!(buf[4], 101, "expected SSH_FXP_STATUS packet type");
        // status code should be 1 (SSH_FX_EOF)
        let code = u32::from_be_bytes(buf[9..13].try_into().unwrap());
        assert_eq!(code, 1, "expected SSH_FX_EOF status code");
    }

    #[test]
    fn handling_process_data() {
        const N: usize = 2048;

        let req_id = ReqId(42);
        let mut output_pipe = SftpOutputPipe::<N>::new();
        let mock = MockWriter::new();
        let (mut consumer, producer) =
            output_pipe.split(mock).expect("split should succeed");

        // 1. Put together a collection of synthetic directory entries
        let filenames = vec!["file1", "file2", "file3"];
        let name_entries: Vec<NameEntry<'_>> = filenames
            .iter()
            .map(|name| NameEntry {
                filename: Filename::from(*name),
                _longname: Filename::from(""),
                attrs: Attrs::default(),
            })
            .collect();

        // 2. Obtain the length of the data to be sent by encoding these synthetic directory entries and summing their lengths
        let items_encoded_len = name_entries.iter().fold(0u32, |acc: u32, entry| {
            let len = helpers::get_name_entry_len(entry)
                .expect("Decoding should not fail");
            acc.checked_add(len)
                .expect("Length overflow when calculating total encoded length")
        });

        let items_count =
            u32::try_from(name_entries.len()).expect("Count should fit in u32");

        embassy_futures::block_on(async {
            {
                let dir_header_reply =
                    DirReadHeaderReply::<N>::new(req_id, &producer);

                // 3. Call send_header with the length of the data to be sent
                let dir_read_data_reply = dir_header_reply
                    .send_header(items_encoded_len, items_count)
                    .await
                    .expect("send_eof should succeed returning ReadReplyData");

                let _dir_read_reply_finished = dir_read_data_reply
                    .send_data(|mut limited_sender| async move {
                        for entry in name_entries.iter() {
                            limited_sender.send_item(entry).await?;
                        }
                        match limited_sender.completed() {
                            Some(completed_token) => Ok(completed_token),
                            None => Err(SftpError::FileServerError(
                                StatusCode::SSH_FX_FAILURE,
                            )),
                        }
                    })
                    .await
                    .expect("send_data should succeed returning ReadReplyFinished");
            }
            drop(producer);
            // Read exactly the one packet written by send_eof; does not loop.
            consumer.receive_once().await.expect("receive_once should succeed");
        });

        let mock = consumer.into_inner();
        let buf = &mock.buffer;
        // packet type byte should be 104 (SSH_FXP_NAME)
        assert_eq!(buf[4], 104, "expected SSH_FXP_NAME packet type");

        // data length should be
        let items = u32::from_be_bytes(
            buf[9..13]
                .try_into()
                .expect("data length should be present in the packet"),
        );
        assert_eq!(
            items, items_count,
            "expected data length to match encoded length"
        );
        assert_eq!(
            buf.len(),
            13 + items_encoded_len as usize,
            "expected packet length to be header (13 bytes) + data (items_encoded_len bytes)"
        );
    }
}

/// no_std compatible helpers to perform common tasks using solely sunset and sunset-sftp resources
pub mod helpers {
    use crate::{
        error::SftpResult,
        proto::{MAX_NAME_ENTRY_SIZE, NameEntry},
        server::SftpSink,
    };

    use sunset::sshwire::SSHEncode;

    /// Helper function to get the length of a given [`NameEntry`]
    /// as it would be serialized to the wire.
    ///
    /// Use this function to calculate the total length of a collection
    /// of `NameEntry`s in order to send a correct response Name header
    pub fn get_name_entry_len(name_entry: &NameEntry<'_>) -> SftpResult<u32> {
        let mut buf = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut temp_sink = SftpSink::new(&mut buf);
        name_entry.enc(&mut temp_sink)?;
        Ok(temp_sink.payload_len() as u32)
    }
}
