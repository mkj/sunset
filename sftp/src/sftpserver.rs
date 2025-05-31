use proto::{StatusCode, Attrs};

pub type Result<T> = core::result::Result<T, StatusCode>;

/// All trait functions are optional in the SFTP protocol.
/// Some less core operations have a Provided implementation returning
/// returns `SSH_FX_OP_UNSUPPORTED`. Common operations must be implemented,
/// but may return `Err(StatusCode::SSH_FX_OP_UNSUPPORTED)`.
trait SftpServer {
    type Handle;

    // TODO flags struct
    async fn open(filename: &str, flags: u32, attrs: &Attrs) -> Result<Self::Handle>;

    /// Close either a file or directory handle
    async fn close(handle: &Self::Handle) -> Result<()>;

    async fn read(handle: &Self::Handle, offset: u64, reply: &mut ReadReply) -> Result<()>;

    async fn write(handle: &Self::Handle, offset: u64, buf: &[u8]) -> Result<()>;

    async fn opendir(dir: &str) -> Result<Self::Handle>;

    async fn readdir(handle: &Self::Handle, reply: &mut DirReply) -> Result<()>;
}

pub struct ReadReply<'g, 'a> {
    chan: ChanOut<'g, 'a>,
}

impl<'g, 'a> ReadReply<'g, 'a> {
    pub async fn reply(self, data: &[u8]) {
        
    }
}
