use crate::error::SftpResult;
use crate::sftphandler::SftpOutputChannelWrapper;
use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, Name, ReqId, StatusCode},
};

use core::marker::PhantomData;
use log::debug;

// use futures::executor::block_on; TODO Deal with the async nature of [`ChanOut`]

/// Result used to store the result of an Sftp Operation
pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

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
    fn readdir(
        &mut self,
        opaque_dir_handle: &T,
        reply: &mut DirReply<'_>,
    ) -> SftpOpResult<()> {
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

/// This trait is an standardized way to interact with an iterator or collection of Directory entries
/// that need to be sent via an SSH_FXP_READDIR SFTP response to a client.
///
/// It uses is expected when implementing an [`SftpServer`] TODO Future trait WIP
pub trait DirEntriesResponseHelpers {
    /// returns the number of directory entries.
    /// Used for the `SSH_FXP_READDIR` response field `count`
    /// as specified in [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
    fn get_count(&self) -> SftpOpResult<u32> {
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Returns the total encoded length in bytes for all directory entries.
    /// Used for the `SSH_FXP_READDIR` general response field `length`
    /// as part of the [General Packet Format](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-3)
    ///
    /// This represents the sum of all [`NameEntry`] structures when encoded
    /// into [`SftpSink`] format. The length is to be pre-computed by
    /// encoding each entry and summing the [`SftpSink::payload_len()`] values.
    fn get_encoded_len(&self) -> SftpOpResult<u32> {
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Must call the callback passing an [`SftpSink::payload_slice()`] as a parameter
    /// were a [`NameEntry`] has been encoded.
    ///
    ///
    #[allow(unused_variables)]
    fn for_each_encoded<F>(&self, writer: F) -> SftpOpResult<()>
    where
        F: FnMut(&[u8]) -> (),
    {
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
/// It contains references to a slice buffer and a output channel
/// [`sunset_async::async_channel::ChanOut`] used in the context of an
/// SFTP Session.
///
/// The usage is simple:
///
/// 1. SftpHandler will: Initialize the structure with the buffer and the ChanOut
/// 2. The `SftpServer` trait implementation for `readdir()` will:
///     a. Receive the DirReply
///     b. Obtain the number of items and the **total** encoded length of
/// the [`NameEntry`] items in the directory and send them calling `send_header`
///     c. Send each serialized `NameEntry`, excluding their length using
/// the `send_item` method
///     
pub struct DirReply<'g> {
    /// Used during the
    req_id: ReqId,
    /// To test muting operations
    chan_out: &'g mut SftpOutputChannelWrapper<'g>,
}

impl<'g> DirReply<'g> {
    /// I am faking a DirReply to prototype it
    // pub fn mock(req_id: ReqId, muting: &'a mut u32) -> Self {
    //     DirReply {
    //         chan_out: ChanOut { _phantom_g: PhantomData, _phantom_a: PhantomData },
    //         // muting,
    //         req_id,
    //     }
    // }
    pub fn new(
        req_id: ReqId,
        chan_out_wrapper: &'g mut SftpOutputChannelWrapper<'g>,
    ) -> Self {
        DirReply { chan_out: chan_out_wrapper, req_id }
    }

    // TODO this will need to do async execution
    /// mocks sending  an item via a stdio
    pub fn send_item(&mut self, data: &[u8]) {
        // *self.muting += 1;
        debug!("Send item: data = {:?}", data);
    }

    // TODO this will need to do async execution
    /// Must be call it first. Make this enforceable
    pub async fn send_header(
        &mut self,
        get_count: u32,
        get_encoded_len: u32,
    ) -> SftpResult<()> {
        debug!(
            "I will send the header here for request id {:?}: count = {:?}, length = {:?}",
            self.req_id, get_count, get_encoded_len
        );
        self.chan_out.push(&get_encoded_len).await?;
        self.chan_out.push(&(104 as u8)).await?;
        self.chan_out.push(&get_count).await?;
        self.chan_out.send_payload().await?;
        Ok(())
    }
}
