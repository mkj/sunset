use sunset_sftp::{
    Attrs, DirReply, FileHandle, Filename, Name, NameEntry, ReadReply, SftpOpResult,
    SftpServer, StatusCode,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

pub struct DemoSftpServer {}

impl SftpServer for DemoSftpServer {
    type Handle<'a> = FileHandle<'a>;

    async fn open<'a>(
        filename: &str,
        // flags: u32,
        attrs: &Attrs,
    ) -> SftpOpResult<Self::Handle<'a>> {
        warn!("Wont allow open!");
        Err(StatusCode::SSH_FX_PERMISSION_DENIED)
    }

    async fn close<'a>(handle: &Self::Handle<'a>) -> SftpOpResult<()> {
        todo!()
    }

    async fn read<'a>(
        handle: &Self::Handle<'a>,
        offset: u64,
        reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        todo!()
    }

    async fn write<'a>(
        handle: &Self::Handle<'a>,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        todo!()
    }

    async fn opendir<'a>(dir: &str) -> SftpOpResult<Self::Handle<'a>> {
        todo!()
    }

    async fn readdir<'a>(
        handle: &Self::Handle<'a>,
        reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        todo!()
    }

    async fn realpath(dir: &str) -> SftpOpResult<Name<'_>> {
        debug!("finding path for: {:?}", dir);
        Ok(Name(vec![NameEntry {
            filename: Filename::from("/root/just/kidding"),
            _longname: Filename::from(""),
            attrs: Attrs {
                size: None,
                uid: None,
                gid: None,
                permissions: None,
                atime: None,
                mtime: None,
                ext_count: None,
            },
        }]))
    }
}
