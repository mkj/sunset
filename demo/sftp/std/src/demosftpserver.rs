use std::str::FromStr;

use sunset::TextString;
use sunset_sftp::{
    Attrs, DirReply, Filename, ItemHandle, Name, NameEntry, ReadReply, SftpResult,
    SftpServer,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

pub struct DemoSftpServer {}

impl SftpServer for DemoSftpServer {
    type Handle = ItemHandle;

    async fn open(
        filename: &str,
        flags: u32,
        attrs: &Attrs,
    ) -> SftpResult<Self::Handle> {
        todo!()
    }

    async fn close(handle: &Self::Handle) -> SftpResult<()> {
        todo!()
    }

    async fn read(
        handle: &Self::Handle,
        offset: u64,
        reply: &mut ReadReply<'_, '_>,
    ) -> SftpResult<()> {
        todo!()
    }

    async fn write(
        handle: &Self::Handle,
        offset: u64,
        buf: &[u8],
    ) -> SftpResult<()> {
        todo!()
    }

    async fn opendir(dir: &str) -> SftpResult<Self::Handle> {
        todo!()
    }

    async fn readdir(
        handle: &Self::Handle,
        reply: &mut DirReply<'_, '_>,
    ) -> SftpResult<()> {
        todo!()
    }

    async fn realpath(dir: &str) -> SftpResult<Name<'_>> {
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
