use crate::proto::{Attrs, FileHandle, Name, StatusCode};

use core::marker::PhantomData;

// TODO: enforce it and do checks for the FileHandle so it properly obscure the file path and user.
//       Hint: In stateful server this can be done with a hash function and a dictionary
/// Used during storage of file handle data for long SFTP Write requests
/// Must be observed by SftpServer handle implementations
pub const FILE_HANDLE_MAX_LEN: usize = 256;

pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait SftpServer<'a> {
    // type Handle<'a>: Into<FileHandle<'a>> + TryFrom<FileHandle<'a>> + Debug + Copy;

    /// Opens a file or directory for reading/writing
    fn open(
        &mut self,
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<FileHandle<'_>> {
        log::error!(
            "SftpServer Open operation not defined: filename = {:?}, attrs = {:?}",
            filename,
            attrs
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Close either a file or directory handle
    fn close(&mut self, handle: &FileHandle) -> SftpOpResult<()> {
        log::error!("SftpServer Close operation not defined: handle = {:?}", handle);

        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn read(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Read operation not defined: handle = {:?}, offset = {:?}",
            handle,
            offset
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn write(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Write operation: handle = {:?}, offset = {:?}, buf = {:?}",
            handle,
            offset,
            String::from_utf8(buf.to_vec())
        );
        Ok(())
    }

    fn opendir(&mut self, dir: &str) -> SftpOpResult<FileHandle<'_>> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn readdir(
        &mut self,
        handle: &FileHandle,
        reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Provides the real path of the directory specified
    fn realpath(&mut self, dir: &str) -> SftpOpResult<Name<'_>> {
        log::error!("SftpServer RealPath operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}

pub struct ReadReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> ReadReply<'g, 'a> {
    pub fn reply(self, data: &[u8]) {}
}

pub struct DirReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> DirReply<'g, 'a> {
    pub fn reply(self, data: &[u8]) {}
}

// TODO: Implement correct Channel Out
pub struct ChanOut<'g, 'a> {
    _phantom_g: PhantomData<&'g ()>,
    _phantom_a: PhantomData<&'a ()>,
}
