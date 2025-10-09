use crate::{
    demofilehandlemanager::DemoFileHandleManager,
    demoopaquefilehandle::DemoOpaqueFileHandle,
};

use sunset_sftp::handles::{OpaqueFileHandleManager, PathFinder};
use sunset_sftp::protocol::{Attrs, Filename, Name, NameEntry, StatusCode};
use sunset_sftp::server::{DirReply, ReadReply, SftpOpResult, SftpServer};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::fs;
use std::{fs::File, os::unix::fs::FileExt, path::Path};

pub(crate) enum PrivatePathHandle {
    File(PrivateFileHandle),
    Directory(PrivateDirHandle),
}

pub(crate) struct PrivateFileHandle {
    path: String,
    permissions: Option<u32>,
    file: File,
}

pub(crate) struct PrivateDirHandle {
    path: String,
}

static OPAQUE_SALT: &'static str = "12d%32";

impl PathFinder for PrivatePathHandle {
    fn matches(&self, path: &Self) -> bool {
        match self {
            PrivatePathHandle::File(self_private_path_handler) => {
                if let PrivatePathHandle::File(private_file_handle) = path {
                    return self_private_path_handler.matches(private_file_handle);
                } else {
                    false
                }
            }
            PrivatePathHandle::Directory(self_private_dir_handle) => {
                if let PrivatePathHandle::Directory(private_dir_handle) = path {
                    self_private_dir_handle.matches(private_dir_handle)
                } else {
                    false
                }
            }
        }
    }

    fn get_path_ref(&self) -> &str {
        match self {
            PrivatePathHandle::File(private_file_handler) => {
                private_file_handler.get_path_ref()
            }
            PrivatePathHandle::Directory(private_dir_handle) => {
                private_dir_handle.get_path_ref()
            }
        }
    }
}

impl PathFinder for PrivateFileHandle {
    fn matches(&self, path: &PrivateFileHandle) -> bool {
        self.path.as_str().eq_ignore_ascii_case(path.get_path_ref())
    }

    fn get_path_ref(&self) -> &str {
        self.path.as_str()
    }
}

impl PathFinder for PrivateDirHandle {
    fn matches(&self, path: &PrivateDirHandle) -> bool {
        self.path.as_str().eq_ignore_ascii_case(path.get_path_ref())
    }

    fn get_path_ref(&self) -> &str {
        self.path.as_str()
    }
}

/// A basic demo server. Used as a demo and to test SFTP functionality
pub struct DemoSftpServer {
    base_path: String,
    handlers_manager: DemoFileHandleManager<DemoOpaqueFileHandle, PrivatePathHandle>,
}

impl DemoSftpServer {
    pub fn new(base_path: String) -> Self {
        // TODO What if the base_path does not exist? Create it or Return error?
        DemoSftpServer { base_path, handlers_manager: DemoFileHandleManager::new() }
    }
}

impl SftpServer<'_, DemoOpaqueFileHandle> for DemoSftpServer {
    fn open(
        &mut self,
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<DemoOpaqueFileHandle> {
        let path = Path::new(filename);

        let metadata = fs::symlink_metadata(path).map_err(|e| {
            warn!("Could not open {:?}: {:?}", filename, e);
            StatusCode::SSH_FX_NO_SUCH_FILE
        })?;

        if metadata.is_symlink() {
            return Err(StatusCode::SSH_FX_OP_UNSUPPORTED);
        }

        if metadata.is_dir() {
            debug!("Open Directory = {:?}", filename);

            let fh = self.handlers_manager.insert(
                PrivatePathHandle::Directory(PrivateDirHandle {
                    path: filename.into(),
                }),
                OPAQUE_SALT,
            );

            debug!(
                "Directory \"{:?}\" will have the obscured file handle: {:?}",
                filename, fh
            );

            // Err(StatusCode::SSH_FX_BAD_MESSAGE)
            fh
        } else {
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
                PrivatePathHandle::File(PrivateFileHandle {
                    path: filename.into(),
                    permissions: attrs.permissions,
                    file,
                }),
                OPAQUE_SALT,
            );

            debug!(
                "Filename \"{:?}\" will have the obscured file handle: {:?}",
                filename, fh
            );

            fh
        }
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
            match handle {
                PrivatePathHandle::File(private_file_handle) => {
                    debug!(
                        "SftpServer Close operation on file {:?} was successful",
                        private_file_handle.path
                    );
                    drop(private_file_handle.file); // Not really required but illustrative
                    Ok(())
                }
                PrivatePathHandle::Directory(private_dir_handle) => {
                    debug!(
                        "SftpServer Close operation on dir {:?} was successful",
                        private_dir_handle.path
                    );

                    Ok(())
                }
            }
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
        if let PrivatePathHandle::File(private_file_handle) = self
            .handlers_manager
            .get_private_as_ref(opaque_file_handle)
            .ok_or(StatusCode::SSH_FX_FAILURE)?
        {
            let permissions_poxit = (private_file_handle
                .permissions
                .ok_or(StatusCode::SSH_FX_PERMISSION_DENIED))?;

            if (permissions_poxit & 0o222) == 0 {
                return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
            };

            log::trace!(
            "SftpServer Write operation: handle = {:?}, filepath = {:?}, offset = {:?}, buf = {:?}",
            opaque_file_handle,
            private_file_handle.path,
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
            private_file_handle.path,
            offset,
            buf.len(),
            bytes_written
        );

            Ok(())
        } else {
            Err(StatusCode::SSH_FX_PERMISSION_DENIED)
        }
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
