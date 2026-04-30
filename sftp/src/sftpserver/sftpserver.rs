use crate::error::{SftpError, SftpResult};
use crate::proto::{NameEntry, PFlags};
use crate::server::DirReadHeaderReply;
use crate::sftpserver::{ReadHeaderReply, ReadReplyFinished};
use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, StatusCode},
};

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
pub trait SftpServer<T>
where
    T: OpaqueFileHandle,
{
    /// Opens a file for reading/writing
    fn open(
        &mut self,
        path: &str,
        mode: &PFlags,
    ) -> impl core::future::Future<Output = SftpOpResult<T>> {
        async move {
            log::error!(
                "SftpServer Open operation not defined: path = {:?}, attrs = {:?}",
                path,
                mode
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Close either a file or directory handle
    fn close(
        &mut self,
        handle: &T,
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer Close operation not defined: handle = {:?}",
                handle
            );

            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    #[allow(unused)]
    fn read<const N: usize>(
        &mut self,
        opaque_file_handle: &T,
        offset: u64,
        len: u32,
        reply: ReadHeaderReply<'_, N>,
    ) -> impl core::future::Future<Output = SftpResult<ReadReplyFinished>> {
        async move {
            log::error!(
                "SftpServer Read operation not defined: handle = {:?}, offset = {:?}, len = {:?}",
                opaque_file_handle,
                offset,
                len
            );
            Err(SftpError::FileServerError(StatusCode::SSH_FX_OP_UNSUPPORTED))
        }
    }

    /// Writes to a file that has previously being opened for writing
    fn write(
        &mut self,
        opaque_file_handle: &T,
        offset: u64,
        buf: &[u8],
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer Write operation not defined: handle = {:?}, offset = {:?}, buf = {:?}",
                opaque_file_handle,
                offset,
                buf
            );
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    /// Opens a directory and returns a handle
    fn opendir(
        &mut self,
        dir: &str,
    ) -> impl core::future::Future<Output = SftpOpResult<T>> {
        async move {
            log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
            Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
        }
    }

    #[allow(unused_variables)]
    fn readdir<const N: usize>(
        &mut self,
        opaque_dir_handle: &T,
        reply: DirReadHeaderReply<'_, N>,
    ) -> impl core::future::Future<Output = SftpOpResult<()>> {
        async move {
            log::error!(
                "SftpServer ReadDir operation not defined: handle = {:?}",
                opaque_dir_handle
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
