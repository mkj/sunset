use crate::{
    demofilehandlemanager::DemoFileHandleManager,
    demoopaquefilehandle::DemoOpaqueFileHandle,
};

use sunset_sftp::handles::{OpaqueFileHandleManager, PathFinder};
use sunset_sftp::protocol::{Attrs, Filename, Name, NameEntry, StatusCode};
use sunset_sftp::server::{DirReply, ReadReply, SftpOpResult, SftpServer};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::{fs::File, os::unix::fs::FileExt};

pub(crate) struct PrivateFileHandler {
    file_path: String,
    permissions: Option<u32>,
    file: File,
}

static OPAQUE_SALT: &'static str = "12d%32";

impl PathFinder for PrivateFileHandler {
    fn matches(&self, path: &PrivateFileHandler) -> bool {
        self.file_path.as_str().eq_ignore_ascii_case(path.get_path_ref())
    }

    fn get_path_ref(&self) -> &str {
        self.file_path.as_str()
    }
}

/// A basic demo server. Used as a demo and to test SFTP functionality
pub struct DemoSftpServer {
    base_path: String,
    handlers_manager:
        DemoFileHandleManager<DemoOpaqueFileHandle, PrivateFileHandler>,
}

impl DemoSftpServer {
    pub fn new(base_path: String) -> Self {
        DemoSftpServer { base_path, handlers_manager: DemoFileHandleManager::new() }
    }
}

impl SftpServer<'_, DemoOpaqueFileHandle> for DemoSftpServer {
    fn open(
        &mut self,
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<DemoOpaqueFileHandle> {
        debug!("Open file: filename = {:?}, attributes = {:?}", filename, attrs);

        let poxit_attr = attrs
            .permissions
            .as_ref()
            .ok_or(StatusCode::SSH_FX_PERMISSION_DENIED)?;
        let can_write = poxit_attr & 0o222 > 0;
        let can_read = poxit_attr & 0o444 > 0;
        debug!(
            "File open for read/write access: can_read={:?}, can_write={:?}",
            can_read, can_write
        );

        let file = File::options()
            .read(can_read)
            .write(can_write)
            .create(true)
            .open(filename)
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?;

        let fh = self.handlers_manager.insert(
            PrivateFileHandler {
                file_path: filename.into(),
                permissions: attrs.permissions,
                file,
            },
            OPAQUE_SALT,
        );

        debug!(
            "Filename \"{:?}\" will have the obscured file handle: {:?}",
            filename, fh
        );

        fh
    }

    fn realpath(&mut self, dir: &str) -> SftpOpResult<Name<'_>> {
        debug!("finding path for: {:?}", dir);
        Ok(Name(vec![NameEntry {
            filename: Filename::from(self.base_path.as_str()),
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

    fn close(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
    ) -> SftpOpResult<()> {
        if let Some(handle) = self.handlers_manager.remove(opaque_file_handle) {
            debug!(
                "SftpServer Close operation on {:?} was successful",
                handle.file_path
            );
            drop(handle.file); // Not really required but illustrative
            Ok(())
        } else {
            error!(
                "SftpServer Close operation on handle {:?} failed",
                opaque_file_handle
            );
            Err(StatusCode::SSH_FX_FAILURE)
        }
    }

    fn write(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        let private_file_handle = self
            .handlers_manager
            .get_private_as_ref(opaque_file_handle)
            .ok_or(StatusCode::SSH_FX_FAILURE)?;

        let permissions_poxit = (private_file_handle
            .permissions
            .ok_or(StatusCode::SSH_FX_PERMISSION_DENIED))?;

        if (permissions_poxit & 0o222) == 0 {
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        };

        log::trace!(
            "SftpServer Write operation: handle = {:?}, filepath = {:?}, offset = {:?}, buf = {:?}",
            opaque_file_handle,
            private_file_handle.file_path,
            offset,
            String::from_utf8(buf.to_vec())
        );
        let bytes_written = private_file_handle
            .file
            .write_at(buf, offset)
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?;

        log::debug!(
            "SftpServer Write operation: handle = {:?}, filepath = {:?}, offset = {:?}, buffer length = {:?}, bytes written = {:?}",
            opaque_file_handle,
            private_file_handle.file_path,
            offset,
            buf.len(),
            bytes_written
        );

        Ok(())
    }

    fn read(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
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

    fn opendir(&mut self, dir: &str) -> SftpOpResult<DemoOpaqueFileHandle> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn readdir(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
        _reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            opaque_file_handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}
