use crate::error::{SftpError, SftpResult};
use crate::proto::{
    ENCODED_SSH_FXP_DATA_MIN_LENGTH, ENCODED_BASE_NAME_SFTP_PACKET_LENGTH,
    MAX_NAME_ENTRY_SIZE, NameEntry, PFlags, SftpNum,
};
use crate::server::SftpSink;
use crate::sftphandler::SftpOutputProducer;
use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, ReqId, StatusCode},
};

use sunset::sshwire::SSHEncode;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// Result used to store the result of an Sftp Operation
pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// To finish read requests the server needs to answer to
/// **subsequent READ requests** after all the data has been sent already
/// with a [`SftpPacket`] including a status code [`StatusCode::SSH_FX_EOF`].
///
/// [`ReadStatus`] enum has been implemented to keep record of these exhausted
/// read operations.
///
/// See:
///
/// - [Reading and Writing](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
/// - [Scanning Directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7)
#[derive(PartialEq, Debug, Default)]
pub enum ReadStatus {
    // TODO Ideally this will contain an OwnedFileHandle
    /// There is more data to be read therefore the [`SftpServer`] will
    /// send more data in the next read request.
    #[default]
    PendingData,
    /// The server has provided all the data requested therefore the [`SftpServer`]
    /// will send a [`SftpPacket`] including a status code [`StatusCode::SSH_FX_EOF`]
    /// in the next read request.
    EndOfFile,
}

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait SftpServer<'a, T>
where
    T: OpaqueFileHandle,
{
    /// Opens a file for reading/writing
    fn open(&'_ mut self, path: &str, mode: &PFlags) -> SftpOpResult<T> {
        log::error!(
            "SftpServer Open operation not defined: path = {:?}, attrs = {:?}",
            path,
            mode
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Close either a file or directory handle
    fn close(&mut self, handle: &T) -> SftpOpResult<()> {
        log::error!("SftpServer Close operation not defined: handle = {:?}", handle);

        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
    /// Reads from a file that has previously being opened for reading
    /// 
    /// ## Notes to the implementer:
    ///
    /// The implementer is expected to use the parameter `reply` [`DirReply`] to:
    ///
    /// - In case of no more data is to be sent, call `reply.send_eof()`
    /// - There is more data to be sent from an open file:
    ///     1. Call `reply.send_header()` with the length of data to be sent
    ///     2. Call `reply.send_data()` once or multiple times to send all the data announced
    ///     3. Do not call `reply.send_eof()` during this [`readdir`] method call
    /// 

    /// If the length communicated in the header does not match the total length of the data 
    /// sent using `reply.send_data()`, the SFTP session will be broken.
    /// 
    #[allow(unused)]
    async fn read<const N: usize>(
        &mut self,
        opaque_file_handle: &T,
        offset: u64,
        len: u32,
        reply: &mut ReadReply<'_, N>,
    ) -> SftpResult<()> {
        log::error!(
            "SftpServer Read operation not defined: handle = {:?}, offset = {:?}, len = {:?}",
            opaque_file_handle,
            offset,
            len
        );
        Err(SftpError::FileServerError(StatusCode::SSH_FX_OP_UNSUPPORTED))
    }
    /// Writes to a file that has previously being opened for writing
    fn write(
        &mut self,
        opaque_file_handle: &T,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Write operation not defined: handle = {:?}, offset = {:?}, buf = {:?}",
            opaque_file_handle,
            offset,
            buf
        );
        Ok(())
    }

    /// Opens a directory and returns a handle
    fn opendir(&mut self, dir: &str) -> SftpOpResult<T> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Reads the list of items in a directory and returns them using the [`DirReply`]
    /// parameter.
    ///
    /// ## Notes to the implementer:
    ///
    /// The implementer is expected to use the parameter `reply` [`DirReply`] to:
    ///
    /// - In case of no more items in the directory to send, call `reply.send_eof()`
    /// - There are more items in the directory:
    ///     1. Call `reply.send_header()` with the number of items and the [`SSHEncode`]
    /// length of all the items to be sent
    ///     2. Call `reply.send_item()` for each of the items announced to be sent
    ///     3. Do not call `reply.send_eof()` during this [`readdir`] method call
    ///
    /// If the length communicated in the header does not match the total length of all
    /// the items sent using `reply.send_item()`, the SFTP session will be
    /// broken.
    /// 
    /// The server is expected to keep track of the number of items that remain to be sent
    /// to the client since the client will only stop asking for more elements in the
    /// directory when a read dir request is answer with an reply.send_eof()
    ///
    #[allow(unused_variables)]
    async fn readdir<const N: usize>(
        &mut self,
        opaque_dir_handle: &T,
        reply: &mut DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            opaque_dir_handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Provides the real path of the directory specified
    fn realpath(&mut self, dir: &str) -> SftpOpResult<NameEntry<'_>> {
        log::error!("SftpServer RealPath operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Provides the stats of the given file path
    fn stats(&mut self, follow_links: bool, file_path: &str) -> SftpOpResult<Attrs> {
        log::error!(
            "SftpServer Stats operation not defined: follow_link = {:?}, \
            file_path = {:?}",
            follow_links,
            file_path
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}

// TODO Define this
/// A reference structure passed to the [`SftpServer::read()`] method to
/// allow replying with the read data.
/// Uses for [`ReadReply`] to:
///
/// - In case of no more data avaliable to be sent, call `reply.send_eof()`
/// - There is data to be sent from an open file:
///     1. Call `reply.send_header()` with the length of data to be sent
///     2. Call `reply.send_data()` as many times as needed to complete a
/// sent of data of the announced length
///     3. Do not call `reply.send_eof()` during this [`read`] method call
///
/// It handles immutable sending data via the underlying sftp-channel
/// [`sunset_async::async_channel::ChanOut`] used in the context of an
/// SFTP Session.
///
pub struct ReadReply<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,

    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// Length of data to be sent as announced in [`ReadReply::send_header`]
    data_len: u32,
    /// Length of data sent so far using [`ReadReply::send_data`]
    data_sent_len: u32,
}

impl<'g, const N: usize> ReadReply<'g, N> {
    /// New instances can only be created within the crate. Users can only
    /// use other public methods to use it.
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        ReadReply { req_id, chan_out, data_len:0, data_sent_len:0 }
    }

    // TODO Make this enforceable
    // TODO Automate encoding the SftpPacket
    /// Sends a header for `SSH_FXP_DATA` response. This includes the total
    /// response length, the packet type, request id and data length
    ///
    /// The packet data content, excluding the length must be sent using
    /// [`ReadReply::send_data`]
    pub async fn send_header(&mut self, data_len: u32) -> SftpResult<()> {
        debug!(
            "ReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        let payload =
            ReadReply::<N>::encode_data_header(&mut sink, self.req_id, data_len)?;

        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
        self.chan_out.send_data(payload).await?;
        self.data_len = data_len;
        Ok(())
    }

    /// Sends a buffer with data. Call it as many times as needed to send
    /// the announced data length
    ///
    /// **Important**: Call this after you have called `send_header`
    pub async fn send_data(&mut self, buff: &[u8]) -> SftpResult<()> {
        self.chan_out.send_data(buff).await?;
        self.data_sent_len += buff.len() as u32;
        Ok(())
    }

    /// Sends EOF meaning that there is no more data to be sent
    ///
    pub async fn send_eof(&self) -> SftpResult<()> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await
    }

    /// Indicates whether all the data announced in the header has been sent
    /// 
    /// returns 0 when all data has been sent
    /// returns >0 when there is still data to be sent
    /// returns <0 when too much data has been sent
    pub fn read_diff(&self) -> i32 {
        (self.data_len as i32) - (self.data_sent_len as i32)
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

#[cfg(test)]
mod read_reply_tests {
    use super::*;

    #[cfg(test)]
    extern crate std;
    // #[cfg(test)]
    // use std::println;

    #[test]
    fn compose_header() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let data_len = 128;
        let mut buffer = [0u8; N];
        let mut sink = SftpSink::new(&mut buffer);

        let payload =
            ReadReply::<N>::encode_data_header(&mut sink, req_id, data_len).unwrap();

        assert_eq!(
            data_len + ENCODED_SSH_FXP_DATA_MIN_LENGTH,
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        );
    }

}

/// Uses for [`DirReply`] to:
///
/// - In case of no more items in the directory to be sent, call `reply.send_eof()`
/// - There are more items in the directory to be sent:
///     1. Call `reply.send_header()` with the number of items and the [`SSHEncode`]
/// length of all the items to be sent
///     2. Call `reply.send_item()` for each of the items announced to be sent
///     3. Do not call `reply.send_eof()` during this [`readdir`] method call
///
/// It handles immutable sending data via the underlying sftp-channel
/// [`sunset_async::async_channel::ChanOut`] used in the context of an
/// SFTP Session.
///
pub struct DirReply<'g, const N: usize> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
    /// Length of data to be sent as announced in [`ReadReply::send_header`]
    data_len: u32,
    /// Length of data sent so far using [`ReadReply::send_data`]
    data_sent_len: u32,
}

impl<'g, const N: usize> DirReply<'g, N> {
    // const ENCODED_NAME_SFTP_PACKET_LENGTH: u32 = 9;

    /// New instances can only be created within the crate. Users can only
    /// use other public methods to use it.
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'g SftpOutputProducer<'g, N>,
    ) -> Self {
        // DirReply { chan_out: chan_out_wrapper, req_id }
        DirReply { req_id, chan_out, data_len:0, data_sent_len:0 }
    }

    // TODO Make this enforceable
    // TODO Automate encoding the SftpPacket
    /// Sends the header to the client with the number of files as [`NameEntry`] and the [`SSHEncode`]
    /// length of all these [`NameEntry`] items
    pub async fn send_header(
        &mut self,
        count: u32,
        items_encoded_len: u32,
    ) -> SftpResult<()> {
        debug!(
            "I will send the header here for request id {:?}: count = {:?}, length = {:?}",
            self.req_id, count, items_encoded_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        let payload = DirReply::<N>::encode_data_header(
            &mut sink,
            self.req_id,
            items_encoded_len,
            count,
        )?;

        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        self.chan_out.send_data(payload).await?;
        self.data_len = items_encoded_len;
        Ok(())
    }

    /// Sends a directory item to the client as a [`NameEntry`]
    ///
    /// Call this
    pub async fn send_item(&mut self, name_entry: &NameEntry<'_>) -> SftpResult<()> {
        let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut sftp_sink = SftpSink::new(&mut buffer);
        name_entry.enc(&mut sftp_sink).map_err(|err| {
            error!("WireError: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })?;

        self.chan_out.send_data(sftp_sink.payload_slice()).await?;
        self.data_sent_len += sftp_sink.payload_len() as u32;
        Ok(())
    }

    /// Sends EOF meaning that there is no more files in the directory
    pub async fn send_eof(&self) -> SftpResult<()> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await
    }

    /// Indicates whether all the data announced in the header has been sent
    /// 
    /// returns 0 when all data has been sent
    /// returns >0 when there is still data to be sent
    /// returns <0 when too much data has been sent
    pub fn read_diff(&self) -> i32 {
        (self.data_len as i32) - (self.data_sent_len as i32)
    }

    fn encode_data_header(
        sink: &'g mut SftpSink<'g>,
        req_id: ReqId,
        items_encoded_len: u32,
        count: u32,
    ) -> Result<&'g [u8], SftpError> {
        // We need to consider the packet type, Id and count fields
        // This way I collect data required for the header and collect
        // valid entries into a vector (only std)
        (items_encoded_len + ENCODED_BASE_NAME_SFTP_PACKET_LENGTH).enc(sink)?;
        u8::from(SftpNum::SSH_FXP_NAME).enc(sink)?;
        req_id.enc(sink)?;
        count.enc(sink)?;

        Ok(sink.payload_slice())
    }

}

#[cfg(test)]
mod dir_reply_tests {
    use super::*;

    #[cfg(test)]
    extern crate std;
    // #[cfg(test)]
    // use std::println;

    #[test]
    fn compose_header() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let data_len = 128;
        let count = 128;
        let mut buffer = [0u8; N];
        let mut sink = SftpSink::new(&mut buffer);

        let payload =
            DirReply::<N>::encode_data_header(&mut sink, req_id, data_len, count)
                .unwrap();

        // println!("{payload:?}");

        // println!("{:?}", &u32::from_be_bytes(payload[..4].try_into().unwrap()));
        assert_eq!(
            data_len + ENCODED_BASE_NAME_SFTP_PACKET_LENGTH,
            u32::from_be_bytes(payload[..4].try_into().unwrap())
        );
    }
}

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

#[cfg(feature = "std")]
use crate::proto::Filename;
#[cfg(feature = "std")]
use std::{
    fs::{DirEntry, Metadata, ReadDir},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    time::SystemTime,
};

#[cfg(feature = "std")]
/// This is a helper structure to make ReadDir into something manageable for
/// [`DirReply`]
///
/// WIP: Not stable. It has know issues and most likely it's methods will change
///
/// TODO: It does not include longname and that may be an issue
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
    pub fn new(dir_iterator: ReadDir) -> Self {
        use log::info;

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
                //TODO remove this unchecked casting
                encoded_length += sftp_sink.payload_len() as u32;
                Some(entry)
            })
            .collect();

        //TODO remove this unchecked casting
        let count = entries.len() as u32;

        info!(
            "Processed {} entries, estimated serialized length: {}",
            count, encoded_length
        );

        Self { count, encoded_length, entries }
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
