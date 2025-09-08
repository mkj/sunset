use crate::proto::{Attrs, FileHandle, Name, StatusCode};

use core::fmt::Debug;
use core::marker::PhantomData;

pub type SftpOpResult<T> = core::result::Result<T, StatusCode>;

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait SftpServer {
    // type Handle: Into<FileHandle> + TryFrom<FileHandle> + Debug;
    type Handle<'a>: Into<FileHandle<'a>> + TryFrom<FileHandle<'a>> + Debug + Copy;

    // TODO flags struct
    async fn open<'a>(
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<Self::Handle<'a>>;

    /// Close either a file or directory handle
    async fn close<'a>(handle: &Self::Handle<'a>) -> SftpOpResult<()>;

    async fn read<'a>(
        handle: &Self::Handle<'a>,
        offset: u64,
        reply: &mut ReadReply,
    ) -> SftpOpResult<()>;

    async fn write<'a>(
        handle: &Self::Handle<'a>,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()>;

    async fn opendir<'a>(dir: &str) -> SftpOpResult<Self::Handle<'a>>;

    async fn readdir<'a>(
        handle: &Self::Handle<'a>,
        reply: &mut DirReply,
    ) -> SftpOpResult<()>;

    /// Provides the real path of the directory specified
    async fn realpath(dir: &str) -> SftpOpResult<Name<'_>>;
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
