use crate::error::{SftpError, SftpResult};
use crate::proto::{Attrs, OpaqueHandle, StatusCode};
use crate::proto::{NameEntry, PFlags};
use crate::server::{DirReadHeaderReply, DirReadReplyFinished};
use crate::sftpserver::{ReadHeaderReply, ReadReplyFinished};

use embedded_io_async::Write;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use sunset::sshwire::{self, BinString};
use sunset_sshwire_derive::{SSHDecode, SSHEncode};

/// Result used to store the result of an Sftp Operation
pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// To finish read requests the server needs to answer to
/// **subsequent READ requests** after all the data has been sent already
/// with a [`crate::proto::SftpPacket`] including a status code [`StatusCode::SSH_FX_EOF`].
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
    /// There is more data to be read therefore the [`SftpServer`] will
    /// send more data in the next read request.
    #[default]
    PendingData,
    /// The server has provided all the data requested therefore the [`SftpServer`]
    /// will send a [`crate::proto::SftpPacket`] including a status code [`crate::proto::StatusCode::SSH_FX_EOF`]
    /// in the next read request.
    EndOfFile,
}

/// A file handle
///
/// Values are defined by a SftpServer implementation
/// which can use a limited range if desired.
/// `FileHandle` and `DirHandle` are allowed to both use the
/// same `u32` values.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct FileHandle(pub u32);

/// A directory handle
///
/// Values are defined by a SftpServer implementation
/// which can use a limited range if desired.
/// `FileHandle` and `DirHandle` are allowed to both use the
/// same `u32` values.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct DirHandle(pub u32);

/// Wire representation of handles. This is an implementation
/// detail hidden from SftpServer implementations.
#[derive(SSHDecode, SSHEncode, Debug)]
struct OpaqueHandleFormat {
    // 0 for file, 1 for dir, others invalid
    is_dir: u8,
    // Allow for 32 bit range, but SftpServer implementations
    // may use a small subset. If a 64 bit value was useful
    // for servers that could be used too.
    handle: u32,
}

impl FileHandle {
    /// `buf` should be from `FileHandle::buffer()`
    pub(crate) fn encode<'a>(&self, buf: &'a mut [u8]) -> OpaqueHandle<'a> {
        let l = sshwire::write_ssh(
            buf,
            &OpaqueHandleFormat { is_dir: 0, handle: self.0 },
        )
        .unwrap();
        OpaqueHandle(BinString(&buf[..l]))
    }

    pub(crate) fn buffer() -> [u8; 5] {
        [0; _]
    }
}

impl DirHandle {
    /// `buf` should be from `DirHandle::buffer()`
    pub(crate) fn encode<'a>(&self, buf: &'a mut [u8]) -> OpaqueHandle<'a> {
        let l = sshwire::write_ssh(
            buf,
            &OpaqueHandleFormat { is_dir: 1, handle: self.0 },
        )
        .unwrap();
        OpaqueHandle(BinString(&buf[..l]))
    }

    pub(crate) fn buffer() -> [u8; 5] {
        [0; _]
    }
}

pub(crate) enum FileOrDirHandle {
    File(FileHandle),
    Dir(DirHandle),
}

/// Decode a wire format file handle into a `FileHandle` or `DirHandle`
///
/// `SSH_FX_BAD_MESSAGE` is returned for handles that
/// don't match the format being used.
pub(crate) fn decode_opaque_handle(
    h: OpaqueHandle,
) -> Result<FileOrDirHandle, StatusCode> {
    let h = sshwire::read_ssh::<OpaqueHandleFormat>(h.0.0, None).map_err(|_| {
        debug!("Bad opaque handle {:02x?}", h.0.0);
        StatusCode::SSH_FX_BAD_MESSAGE
    })?;

    match h.is_dir {
        0 => Ok(FileOrDirHandle::File(FileHandle(h.handle))),
        1 => Ok(FileOrDirHandle::Dir(DirHandle(h.handle))),
        _ => Err(StatusCode::SSH_FX_BAD_MESSAGE),
    }
}

impl TryFrom<OpaqueHandle<'_>> for FileHandle {
    type Error = StatusCode;
    fn try_from(h: OpaqueHandle) -> Result<Self, Self::Error> {
        match decode_opaque_handle(h)? {
            FileOrDirHandle::File(f) => Ok(f),
            _ => Err(StatusCode::SSH_FX_BAD_MESSAGE),
        }
    }
}

impl TryFrom<OpaqueHandle<'_>> for DirHandle {
    type Error = StatusCode;
    fn try_from(h: OpaqueHandle) -> Result<Self, Self::Error> {
        match decode_opaque_handle(h)? {
            FileOrDirHandle::Dir(f) => Ok(f),
            _ => Err(StatusCode::SSH_FX_BAD_MESSAGE),
        }
    }
}

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(crate::proto::StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait SftpServer {
    /// Opens a file for reading/writing
    fn open(
        &mut self,
        path: &str,
        mode: &PFlags,
    ) -> impl core::future::Future<Output = SftpOpResult<FileHandle>>;

    /// Close a file handle
    fn close(
        &mut self,
        handle: FileHandle,
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer Close operation not defined: handle = {:?}",
                handle
            );

            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Reads from a file that has previously being opened for reading
    ///
    /// The opaque_file_handle is a handle that the server can use to identify the file being read. It must have been set in [`crate::sftpserver::SftpServer::open`] function.
    /// The offset is the position in the file from which to start reading.
    /// The len is the number of bytes to read.
    /// The reply is a structure that facilitates the task of sending the response back correctly. See [`ReadHeaderReply`] for more details.
    #[allow(unused)]
    fn read<'g, 'p, W>(
        &mut self,
        handle: FileHandle,
        offset: u64,
        len: u32,
        reply: ReadHeaderReply<'g, 'p, W>,
    ) -> impl core::future::Future<Output = SftpResult<ReadReplyFinished>>
    where
        W: Write,
    {
        async move {
            log::error!(
                "SftpServer Read operation not defined: handle = {:?}, offset = {:?}, len = {:?}",
                handle,
                offset,
                len
            );
            Err(SftpError::FileServerError(StatusCode::SSH_FX_OP_UNSUPPORTED))
        }
    }

    /// Writes to a file that has previously being opened for writing
    ///
    /// The handle is used to identify the file being written.
    /// It must have been set in [`crate::sftpserver::SftpServer::open`] function.
    /// The offset is the position in the file from which to start writing.
    /// The buf is the data to be written.
    fn write(
        &mut self,
        handle: FileHandle,
        offset: u64,
        buf: &[u8],
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer Write operation not defined: handle = {:?}, offset = {:?}, buf = {:?}",
                handle,
                offset,
                buf
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Opens a directory and returns a handle
    ///
    /// The dir is the path of the directory to open. The returned handle can be used in subsequent calls to [`crate::sftpserver::SftpServer::readdir`] to read the contents of the directory.
    fn opendir(
        &mut self,
        dir: &str,
    ) -> impl core::future::Future<Output = SftpOpResult<DirHandle>> {
        async move {
            log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Close a directory handle
    fn closedir(
        &mut self,
        handle: DirHandle,
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer Close operation not defined: handle = {:?}",
                handle
            );

            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Reads the contents of a directory that has previously being opened with [`crate::sftpserver::SftpServer::opendir`]
    ///
    /// Parameters:
    /// - The opaque_dir_handle is a handle that the server can use to identify the directory being read. It must have been set in [`crate::sftpserver::SftpServer::opendir`] function.
    /// - The reply is a structure that facilitates the task of sending the response back correctly. See [`DirReadHeaderReply`] for more details.
    /// - N is the allocated size for the buffer that will be used to send the response back.
    ///
    ///
    #[allow(unused_variables)]
    fn readdir<W: Write>(
        &mut self,
        handle: DirHandle,
        reply: DirReadHeaderReply<'_, '_, W>,
    ) -> impl core::future::Future<Output = SftpOpResult<DirReadReplyFinished>> {
        async move {
            log::error!(
                "SftpServer ReadDir operation not defined: handle = {:?}",
                handle
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Provides the real path of the directory specified
    fn realpath(
        &mut self,
        dir: &str,
    ) -> impl core::future::Future<Output = SftpOpResult<NameEntry<'_>>> {
        async move {
            log::error!(
                "SftpServer RealPath operation not defined: dir = {:?}",
                dir
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Provides the attributes of the given file path
    fn attrs(
        &mut self,
        follow_links: bool,
        file_path: &str,
    ) -> impl core::future::Future<Output = SftpOpResult<Attrs>> {
        async move {
            log::error!(
                "SftpServer Stats operation not defined: follow_link = {:?}, \
                file_path = {:?}",
                follow_links,
                file_path
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }
}
