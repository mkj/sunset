use crate::{
    error::{SftpError, SftpResult},
    proto::{
        ENCODED_SSH_FXP_DATA_MIN_LENGTH, MAX_NAME_ENTRY_SIZE, NameEntry, ReqId,
        SftpNum,
    },
    protocol::StatusCode,
    server::SftpSink,
    sftphandler::SftpOutputProducer,
};

use sunset::sshwire::SSHEncode;

use log::{debug, error};

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

    /// Sends the header for a read reply with the given data length.
    ///
    /// Once used, the only way to obtain a [`DirReadReplyFinished`] is by using its returned value.
    pub async fn send_header(
        self,
        data_len: u32,
    ) -> SftpResult<DirReadDataReply<'g, N>> {
        debug!(
            "DirReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        let payload = DirReadHeaderReply::<N>::encode_data_header(
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

        Ok(DirReadDataReply::new(self.req_id, data_len, self.chan_out))
    }

    /// Sends an EOF status response for the read request.
    ///
    /// It will return a [`DirReadReplyFinished`] that can be used to represent the state of the successful read reply.
    pub async fn send_eof(&self) -> SftpResult<DirReadReplyFinished> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await?;
        Ok(DirReadReplyFinished::new(self.req_id))
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

pub struct DirReadReplyFinished {
    /// The request Id that will be use`d in the response
    _req_id: ReqId,
}

impl DirReadReplyFinished {
    pub(crate) fn new(req_id: ReqId) -> Self {
        Self { _req_id: req_id }
    }
}

pub struct LimitedDirSender<'g, const N: usize> {
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// remaining data length to be sent as announced in [`DirReply::send_header`]
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
        name_entry.enc(&mut sftp_sink).map_err(|err| {
            error!("WireError: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })?;

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

pub struct CompleteDirDataSent;

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
    fn compose_header() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let data_len = 128;
        let mut buffer = [0u8; N];
        let mut sink = SftpSink::new(&mut buffer);

        let payload =
            DirReadHeaderReply::<N>::encode_data_header(&mut sink, req_id, data_len)
                .unwrap();

        assert_eq!(
            data_len + ENCODED_SSH_FXP_DATA_MIN_LENGTH,
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        );
    }

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

        embassy_futures::block_on(async {
            {
                let dir_header_reply =
                    DirReadHeaderReply::<N>::new(req_id, &producer);

                // 3. Call send_header with the length of the data to be sent
                let dir_read_data_reply = dir_header_reply
                    .send_header(items_encoded_len)
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
        // packet type byte should be 103 (SSH_FXP_DATA)
        assert_eq!(buf[4], 103, "expected SSH_FXP_DATA packet type");

        // data length should be 10
        let data_len = u32::from_be_bytes(
            buf[9..13]
                .try_into()
                .expect("data length should be present in the packet"),
        );
        assert_eq!(
            data_len, items_encoded_len,
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
pub mod no_std_helpers {
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

/// Helpers structures intended to for environment with `std` available, specially linux.
///
/// The collection helps with directory and directory items enumeration, description
/// and organizing. Providing means to translate them into [`sunset-sftp`] structures
///
#[cfg(feature = "std")]
pub mod std_helpers {
    use crate::{
        proto::{Attrs, Filename},
        protocol::{NameEntry, StatusCode, constants::MAX_NAME_ENTRY_SIZE},
        server::{ReadStatus, SftpOpResult, SftpSink},
    };

    use sunset::sshwire::SSHEncode;

    use log::{debug, error, info};
    use std::{
        fs::{DirEntry, Metadata, ReadDir},
        os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
        time::SystemTime,
    };

    /// This is a helper structure to make ReadDir into something manageable for
    /// [`DirReply`]
    #[derive(Debug)]
    pub struct DirEntriesCollection {
        /// Number of elements
        count: u32,
        /// Computed length of all the encoded elements
        encoded_length: u32,
        /// The actual entries. As you can see these are DirEntry. This is a std choice
        entries: Vec<DirEntry>,
    }

    #[cfg(feature = "std")]
    impl DirEntriesCollection {
        /// Creates this DirEntriesCollection so linux std users do not need to
        /// translate `std` directory elements into Sftp structures before sending a response
        /// back to the client
        pub fn new(dir_iterator: ReadDir) -> SftpOpResult<Self> {
            let mut encoded_length = 0;

            let entries: Vec<DirEntry> = dir_iterator
                .filter_map(|entry_result| {
                    let entry = entry_result.ok()?;
                    let filename = entry.file_name().to_string_lossy().into_owned();
                    let name_entry = NameEntry {
                        filename: Filename::from(filename.as_str()),
                        _longname: Filename::from(""),
                        attrs: Self::get_attrs_or_empty(entry.metadata()),
                    };

                    let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
                    let mut sftp_sink = SftpSink::new(&mut buffer);
                    name_entry.enc(&mut sftp_sink).ok()?;
                    encoded_length += u32::try_from(sftp_sink.payload_len())
                        .map_err(|_| StatusCode::SSH_FX_FAILURE)
                        .ok()?;
                    Some(entry)
                })
                .collect();

            let count = u32::try_from(entries.len())
                .map_err(|_| StatusCode::SSH_FX_FAILURE)?;

            info!(
                "Processed {} entries, estimated serialized length: {}",
                count, encoded_length
            );

            Ok(Self { count, encoded_length, entries })
        }

        /// Using the provided [`DirReply`] sends a response taking care of
        /// composing a SFTP Entry header and sending everything in the right order
        ///
        /// Returns a [`ReadStatus`]
        pub async fn send_response<const N: usize>(
            &self,
            reply: &mut DirReply<'_, N>,
        ) -> SftpOpResult<ReadStatus> {
            self.send_entries_header(reply).await?;
            self.send_entries(reply).await?;
            Ok(ReadStatus::EndOfFile)
        }
        /// Sends a header for all the elements in the ReadDir iterator
        ///
        /// It will take care of counting them and finding the serialized length of each
        /// element
        async fn send_entries_header<const N: usize>(
            &self,
            reply: &mut DirReply<'_, N>,
        ) -> SftpOpResult<()> {
            reply.send_header(self.count, self.encoded_length).await.map_err(|e| {
                debug!("Could not send header {e:?}");
                StatusCode::SSH_FX_FAILURE
            })
        }

        /// Sends the entries in the ReadDir iterator back to the client
        async fn send_entries<const N: usize>(
            &self,
            reply: &mut DirReply<'_, N>,
        ) -> SftpOpResult<()> {
            for entry in &self.entries {
                let filename = entry.file_name().to_string_lossy().into_owned();
                let attrs = Self::get_attrs_or_empty(entry.metadata());
                let name_entry = NameEntry {
                    filename: Filename::from(filename.as_str()),
                    _longname: Filename::from(""),
                    attrs,
                };
                debug!("Sending new item: {:?}", name_entry);
                reply.send_item(&name_entry).await.map_err(|err| {
                    error!("SftpError: {:?}", err);
                    StatusCode::SSH_FX_FAILURE
                })?;
            }
            Ok(())
        }

        fn get_attrs_or_empty(
            maybe_metadata: Result<Metadata, std::io::Error>,
        ) -> Attrs {
            maybe_metadata.map(get_file_attrs).unwrap_or_default()
        }
    }

    #[cfg(feature = "std")]
    /// [`std`] helper function to get [`Attrs`] from a [`Metadata`].
    pub fn get_file_attrs(metadata: Metadata) -> Attrs {
        let time_to_u32 = |time_result: std::io::Result<SystemTime>| {
            time_result
                .ok()?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()?
                .as_secs()
                .try_into()
                .ok()
        };

        Attrs {
            size: Some(metadata.len()),
            uid: Some(metadata.st_uid()),
            gid: Some(metadata.st_gid()),
            permissions: Some(metadata.permissions().mode()),
            atime: time_to_u32(metadata.accessed()),
            mtime: time_to_u32(metadata.modified()),
            ext_count: None,
        }
    }
}
