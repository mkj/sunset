use crate::error::SftpResult;
use crate::proto::{
    ENCODED_BASE_NAME_SFTP_PACKET_LENGTH, MAX_NAME_ENTRY_SIZE, NameEntry, PFlags,
};
use crate::server::SftpSink;
use crate::sftphandler::SftpOutputProducer;
use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, ReqId, StatusCode},
};

use sunset::sshwire::SSHEncode;

use core::marker::PhantomData;
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
    fn read(
        &mut self,
        opaque_file_handle: &T,
        offset: u64,
        _reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Read operation not defined: handle = {:?}, offset = {:?}",
            opaque_file_handle,
            offset
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
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
    /// The server is expected to keep track of the number of items that remain to be sent
    /// to the client since the client will only stop asking for more elements in the
    /// directory when a read dir request is answer with an reply.send_eof()
    ///
    #[allow(unused_variables)]
    async fn readdir<const N: usize>(
        &mut self,
        opaque_dir_handle: &T,
        reply: &DirReply<'_, N>,
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
/// **This is a work in progress**
/// A reference structure passed to the [`SftpServer::read()`] method to
/// allow replying with the read data.

pub struct ReadReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> ReadReply<'g, 'a> {
    /// **This is a work in progress**
    ///
    /// Reply with a slice containing the read data
    /// It can be called several times to send multiple data chunks
    ///
    /// **Important**: The first reply should contain the header
    #[allow(unused_variables)]
    pub fn reply(self, data: &[u8]) {}
}

// TODO Implement correct Channel Out
pub struct ChanOut<'g, 'a> {
    _phantom_g: PhantomData<&'g ()>, // 'g look what these might be ChanIO lifetime
    _phantom_a: PhantomData<&'a ()>, // a' Why the second lifetime if ChanIO only needs one
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
        DirReply { req_id, chan_out }
    }

    // TODO Make this enforceable
    /// Sends the header to the client with the number of files as [`NameEntry`] and the [`SSHEncode`]
    /// length of all these [`NameEntry`] items
    pub async fn send_header(
        &self,
        count: u32,
        items_encoded_len: u32,
    ) -> SftpResult<()> {
        debug!(
            "I will send the header here for request id {:?}: count = {:?}, length = {:?}",
            self.req_id, count, items_encoded_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        // We need to consider the packet type, Id and count fields
        // This way I collect data required for the header and collect
        // valid entries into a vector (only std)
        (items_encoded_len + ENCODED_BASE_NAME_SFTP_PACKET_LENGTH).enc(&mut sink)?;
        104u8.enc(&mut sink)?; // TODO Replace hack with 
        self.req_id.enc(&mut sink)?;
        count.enc(&mut sink)?;
        let payload = sink.payload_slice();
        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        self.chan_out.send_data(sink.payload_slice()).await?;
        Ok(())
    }

    /// Sends a directory item to the client as a [`NameEntry`]
    ///
    /// Call this
    pub async fn send_item(&self, name_entry: &NameEntry<'_>) -> SftpResult<()> {
        let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut sftp_sink = SftpSink::new(&mut buffer);
        name_entry.enc(&mut sftp_sink).map_err(|err| {
            error!("WireError: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })?;

        self.chan_out.send_data(sftp_sink.payload_slice()).await
    }

    /// Sends EOF meaning that there is no more files in the directory
    pub async fn send_eof(&self) -> SftpResult<()> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await
    }
}

pub mod helpers {
    use crate::{
        error::SftpResult,
        proto::{MAX_NAME_ENTRY_SIZE, NameEntry},
        server::SftpSink,
    };

    use sunset::sshwire::SSHEncode;

    /// Helper function to get the length of a [`NameEntry`]
    pub fn get_name_entry_len(name_entry: &NameEntry<'_>) -> SftpResult<u32> {
        let mut buf = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut temp_sink = SftpSink::new(&mut buf);
        name_entry.enc(&mut temp_sink)?;
        Ok(temp_sink.payload_len() as u32)
    }
}

// TODO Add this to SFTP library only available with std as a global helper
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
/// BUG: It does not include longname and that may be an issue
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
        reply: &DirReply<'_, N>,
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
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        reply.send_header(self.count, self.encoded_length).await.map_err(|e| {
            debug!("Could not send header {e:?}");
            StatusCode::SSH_FX_FAILURE
        })
    }

    /// Sends the entries in the ReadDir iterator back to the client
    async fn send_entries<const N: usize>(
        &self,
        reply: &DirReply<'_, N>,
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
