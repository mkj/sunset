use crate::proto::{Attrs, Name, StatusCode};

use core::marker::PhantomData;

pub type SftpResult<T> = core::result::Result<T, StatusCode>;

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
pub trait SftpServer {
    type Handle;

    // TODO flags struct
    async fn open(
        filename: &str,
        flags: u32,
        attrs: &Attrs,
    ) -> SftpResult<Self::Handle>;

    /// Close either a file or directory handle
    async fn close(handle: &Self::Handle) -> SftpResult<()>;

    async fn read(
        handle: &Self::Handle,
        offset: u64,
        reply: &mut ReadReply,
    ) -> SftpResult<()>;

    async fn write(handle: &Self::Handle, offset: u64, buf: &[u8])
    -> SftpResult<()>;

    async fn opendir(dir: &str) -> SftpResult<Self::Handle>;

    async fn readdir(handle: &Self::Handle, reply: &mut DirReply) -> SftpResult<()>;

    /// Provides the real path of the directory specified
    async fn realpath(dir: &str) -> SftpResult<Name<'_>>;
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

#[derive(Debug)]
pub struct ItemHandle {
    client_opaque_handle: String,
}
