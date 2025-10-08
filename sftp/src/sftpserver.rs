use crate::{
    handles::OpaqueFileHandle,
    proto::{Attrs, Name, StatusCode},
};

use core::marker::PhantomData;

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
    /// Opens a file or directory for reading/writing
    fn open(&'_ mut self, filename: &str, attrs: &Attrs) -> SftpOpResult<T> {
        log::error!(
            "SftpServer Open operation not defined: filename = {:?}, attrs = {:?}",
            filename,
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

    /// Opens a directory
    fn opendir(&mut self, dir: &str) -> SftpOpResult<T> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Reads the list of items in a directory
    fn readdir(
        &mut self,
        opaque_file_handle: &T,
        _reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            opaque_file_handle
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
pub struct ReadReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> ReadReply<'g, 'a> {
    pub fn reply(self, _data: &[u8]) {}
}

// TODO Define this
pub struct DirReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> DirReply<'g, 'a> {
    pub fn reply(self, _data: &[u8]) {}
}

// TODO Implement correct Channel Out
pub struct ChanOut<'g, 'a> {
    _phantom_g: PhantomData<&'g ()>,
    _phantom_a: PhantomData<&'a ()>,
}
