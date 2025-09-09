use crate::proto::{Attrs, FileHandle, Name, StatusCode};

use core::marker::PhantomData;

pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait AsyncSftpServer {
    type Handle<'a>: Into<FileHandle<'a>> + TryFrom<FileHandle<'a>> + Debug + Copy;

    /// Opens a file or directory for reading/writing
    async fn open<'a>(
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<FileHandle<'a>> {
        log::error!("SftpServer Open operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Close either a file or directory handle
    async fn close<'a>(&mut self, handle: &FileHandle<'a>) -> SftpOpResult<()> {
        log::error!("SftpServer Close operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    async fn read<'a>(
        handle: &FileHandle<'a>,
        offset: u64,
        reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!("SftpServer Read operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    async fn write<'a>(
        handle: &FileHandle<'a>,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        log::error!("SftpServer Write operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    async fn opendir<'a>(&mut self, dir: &str) -> SftpOpResult<FileHandle<'a>> {
        log::error!("SftpServer OpenDir operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    async fn readdir<'a>(
        handle: &FileHandle<'a>,
        reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!("SftpServer ReadDir operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    /// Provides the real path of the directory specified
    async fn realpath(&mut self, dir: &str) -> SftpOpResult<Name<'_>> {
        log::error!("SftpServer RealPath operation not defined");
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}

pub struct ReadReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> ReadReply<'g, 'a> {
    pub async fn reply(self, data: &[u8]) {}
}

pub struct DirReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> DirReply<'g, 'a> {
    pub async fn reply(self, data: &[u8]) {}
}

// TODO: Implement correct Channel Out
pub struct ChanOut<'g, 'a> {
    _phantom_g: PhantomData<&'g ()>,
    _phantom_a: PhantomData<&'a ()>,
}
