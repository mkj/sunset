use crate::error::SftpResult;
use crate::server::SftpSink;
use crate::sftphandler::SftpOutputProducer;
use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, Name, ReqId, StatusCode},
};

use core::marker::PhantomData;
use log::{debug, trace};
use sunset::sshwire::SSHEncode;

// use futures::executor::block_on; TODO Deal with the async nature of [`ChanOut`]

/// Result used to store the result of an Sftp Operation
pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// Since the server needs to answer with an STATUS EOF to finish read requests,
/// Helps handling the completion for reading data.
/// See:
///
/// - [Reading and Writing](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
/// - [Scanning Directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7)
#[derive(PartialEq, Debug, Default)]
pub enum ReadStatus {
    // TODO Ideally this will contain an OwnedFileHandle
    /// There is more data to read
    #[default]
    PendingData,
    /// The server has provided all the data requested
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
    fn open(&'_ mut self, path: &str, attrs: &Attrs) -> SftpOpResult<T> {
        log::error!(
            "SftpServer Open operation not defined: path = {:?}, attrs = {:?}",
            path,
            attrs
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

    /// Reads the list of items in a directory
    #[allow(unused_variables)]
    async fn readdir<const N: usize>(
        &mut self,
        opaque_dir_handle: &T,
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<ReadStatus> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            opaque_dir_handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Provides the real path of the directory specified
    fn realpath(&mut self, dir: &str) -> SftpOpResult<Name<'_>> {
        log::error!("SftpServer RealPath operation not defined: dir = {:?}", dir);
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

// TODO Define this
/// Dir Reply is the structure that will be "visiting" the [`SftpServer`]
///  trait
/// implementation via [`SftpServer::readdir()`] in order to send the
/// directory content list.
///
/// It handles immutable sending data via the underlying sftp-channel
/// [`sunset_async::async_channel::ChanOut`] used in the context of an
/// SFTP Session.
///
// TODO: complete this once the flow is fully developed
/// The usage is simple:
///
/// 1. SftpHandler will: Initialize the structure
/// 2. The `SftpServer` trait implementation for `readdir()` will:
///
///     - Receive the DirReply ref `reply`
///     
///     a. If there are items to send:
///
///         - Instantiate a [`DirEntriesCollection`] with the items in the requested folder
///         - call the `DirEntriesCollection.SendHeader(reply)`
///         - call the `DirEntriesCollection.send_entries(reply)`
///
///     b. If there are no items to send:
///
///         - Call the `reply.send_eof()`
pub struct DirReply<'g, const N: usize> {
    /// The request Id that will be used in the response
    req_id: ReqId,

    /// Immutable writer
    chan_out: &'g SftpOutputProducer<'g, N>,
}

impl<'g, const N: usize> DirReply<'g, N> {
    /// New instance
    pub fn new(req_id: ReqId, chan_out: &'g SftpOutputProducer<'g, N>) -> Self {
        // DirReply { chan_out: chan_out_wrapper, req_id }
        DirReply { req_id, chan_out }
    }

    /// Sends the header to the client. TODO Make this enforceable
    pub async fn send_header(
        &self,
        get_count: u32,
        get_encoded_len: u32,
    ) -> SftpResult<()> {
        debug!(
            "I will send the header here for request id {:?}: count = {:?}, length = {:?}",
            self.req_id, get_count, get_encoded_len
        );
        let mut s = [0u8; N];
        let mut sink = SftpSink::new(&mut s);

        get_encoded_len.enc(&mut sink)?;
        104u8.enc(&mut sink)?; // TODO Remove hack
        self.req_id.enc(&mut sink)?;
        get_count.enc(&mut sink)?;
        let payload = sink.payload_slice();
        debug!(
            "Sending header:  len = {:?}, content = {:?}",
            payload.len(),
            payload
        );
        self.chan_out.send_data(sink.payload_slice()).await?;
        Ok(())
    }

    /// Sends an item to the client
    pub async fn send_item(&self, data: &[u8]) -> SftpResult<()> {
        debug!("Sending item: {:?} bytes", data.len());
        trace!("Sending item: content = {:?}", data);
        self.chan_out.send_data(data).await
    }

    /// Sends EOF meaning that there is no more files in the directory
    pub async fn send_eof(&self) -> SftpResult<()> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await
    }
}
