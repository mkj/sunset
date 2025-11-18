use crate::{
    demofilehandlemanager::DemoFileHandleManager,
    demoopaquefilehandle::DemoOpaqueFileHandle,
};

use sunset_sftp::error::SftpResult;
use sunset_sftp::handles::{OpaqueFileHandleManager, PathFinder};
use sunset_sftp::protocol::{Attrs, Filename, NameEntry, PFlags, StatusCode};
use sunset_sftp::server::helpers::DirEntriesCollection;
use sunset_sftp::server::{
    DirReply, ReadReply, ReadStatus, SftpOpResult, SftpServer,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::{fs::File, os::unix::fs::FileExt, path::Path};

#[derive(Debug)]
pub(crate) enum PrivatePathHandle {
    File(PrivateFileHandle),
    Directory(PrivateDirHandle),
}

#[derive(Debug)]
pub(crate) struct PrivateFileHandle {
    path: String,
    permissions: Option<u32>,
    file: File,
}

#[derive(Debug)]
pub(crate) struct PrivateDirHandle {
    path: String,
    read_status: ReadStatus,
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
    handles_manager: DemoFileHandleManager<DemoOpaqueFileHandle, PrivatePathHandle>,
}

impl DemoSftpServer {
    pub fn new(base_path: String) -> Self {
        // TODO What if the base_path does not exist? Create it or Return error?
        DemoSftpServer { base_path, handles_manager: DemoFileHandleManager::new() }
    }
}

impl SftpServer<'_, DemoOpaqueFileHandle> for DemoSftpServer {
    fn open(
        &mut self,
        filename: &str,
        mode: &PFlags,
    ) -> SftpOpResult<DemoOpaqueFileHandle> {
        debug!("Open file: filename = {:?}, mode = {:?}", filename, mode);

        let can_write = u32::from(mode) & u32::from(&PFlags::SSH_FXF_WRITE) > 0;
        let can_read = u32::from(mode) & u32::from(&PFlags::SSH_FXF_READ) > 0;

        debug!(
            "File open for read/write access: can_read={:?}, can_write={:?}",
            can_read, can_write
        );

        let file = File::options()
            .read(can_read)
            .write(can_write)
            .create(can_write)
            .open(filename)
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?;

        let permissions = file
            .metadata()
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?
            .permissions()
            .mode()
            & 0o777;

        let fh = self.handles_manager.insert(
            PrivatePathHandle::File(PrivateFileHandle {
                path: filename.into(),
                permissions: Some(permissions),
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

    fn opendir(&mut self, dir: &str) -> SftpOpResult<DemoOpaqueFileHandle> {
        debug!("Open Directory = {:?}", dir);

        let dir_handle = self.handles_manager.insert(
            PrivatePathHandle::Directory(PrivateDirHandle {
                path: dir.into(),
                read_status: ReadStatus::default(),
            }),
            OPAQUE_SALT,
        );

        debug!(
            "Directory \"{:?}\" will have the obscured file handle: {:?}",
            dir, dir_handle
        );

        dir_handle
    }

    fn realpath(&mut self, dir: &str) -> SftpOpResult<NameEntry<'_>> {
        info!("finding path for: {:?}", dir);
        let name_entry = NameEntry {
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
        };
        debug!("Will return: {:?}", name_entry);
        Ok(name_entry)
    }

    fn close(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
    ) -> SftpOpResult<()> {
        if let Some(handle) = self.handles_manager.remove(opaque_file_handle) {
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

    async fn read<const N: usize>(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
        offset: u64,
        len: u32,
        reply: &ReadReply<'_, N>,
    ) -> SftpResult<()> {
        if let PrivatePathHandle::File(private_file_handle) = self
            .handles_manager
            .get_private_as_mut_ref(opaque_file_handle)
            .ok_or(StatusCode::SSH_FX_FAILURE)?
        {
            log::debug!(
                "SftpServer Read operation: handle = {:?}, filepath = {:?}, offset = {:?}, len = {:?}",
                opaque_file_handle,
                private_file_handle.path,
                offset,
                len
            );
            let permissions_poxit = private_file_handle.permissions.unwrap_or(0o000);
            if (permissions_poxit & 0o444) == 0 {
                error!(
                    "No read permissions for file {:?}",
                    private_file_handle.path
                );
                return Err(StatusCode::SSH_FX_PERMISSION_DENIED.into());
            };

            let file_len = private_file_handle
                .file
                .metadata()
                .map_err(|err| {
                    error!("Could not read the file length: {:?}", err);
                    StatusCode::SSH_FX_FAILURE
                })?
                .len();

            if offset >= file_len {
                info!("offset is larger than file length, sending EOF");
                reply.send_eof().await.map_err(|err| {
                    error!("Could not sent EOF: {:?}", err);
                    StatusCode::SSH_FX_FAILURE
                })?;
                return Ok(());
            }

            let read_len = if file_len >= len as u64 + offset {
                len
            } else {
                warn!("Read operation: length + offset > file length. Clipping ( {:?} + {:?} > {:?})",
                len, offset, file_len);
                (file_len - offset).try_into().unwrap_or(u32::MAX)
            };

            reply.send_header(offset, read_len).await?;

            const ARBITRARY_BUFFER_LENGTH: usize = 1024;

            let mut read_buff = [0u8; ARBITRARY_BUFFER_LENGTH];

            let mut running_offset = offset;
            let mut remaining = read_len as usize;

            debug!("Starting reading loop: remaining = {}", remaining);
            while remaining > 0 {
                let next_read_len: usize = remaining.min(read_buff.len());
                debug!("next_read_len = {}", next_read_len);
                let br = private_file_handle
                    .file
                    .read_at(&mut read_buff[..next_read_len], running_offset)
                    .map_err(|err| {
                        error!("read error: {:?}", err);
                        StatusCode::SSH_FX_FAILURE
                    })?;
                debug!("{} bytes readed", br);
                reply.send_data(&read_buff[..br.min(remaining)]).await?;
                debug!("Read sent {} bytes", br.min(remaining));
                debug!("remaining {} bytes. {} byte read", remaining, br);

                remaining =
                    remaining.checked_sub(br).ok_or(StatusCode::SSH_FX_FAILURE)?;
                debug!(
                    "after substracting {} bytes, there are {} bytes remaining",
                    br, remaining
                );
                running_offset = running_offset
                    .checked_add(br as u64)
                    .ok_or(StatusCode::SSH_FX_FAILURE)?;
            }
            debug!("Finished sending data");
            return Ok(());
        }
        Err(StatusCode::SSH_FX_PERMISSION_DENIED.into())
    }

    fn write(
        &mut self,
        opaque_file_handle: &DemoOpaqueFileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        if let PrivatePathHandle::File(private_file_handle) = self
            .handles_manager
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

    async fn readdir<const N: usize>(
        &mut self,
        opaque_dir_handle: &DemoOpaqueFileHandle,
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        debug!("read dir for  {:?}", opaque_dir_handle);

        if let PrivatePathHandle::Directory(dir) = self
            .handles_manager
            .get_private_as_mut_ref(opaque_dir_handle)
            .ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?
        {
            if dir.read_status == ReadStatus::EndOfFile {
                reply.send_eof().await.map_err(|error| {
                    error!("{:?}", error);
                    StatusCode::SSH_FX_FAILURE
                })?;
                return Ok(());
            }

            let path_str = dir.path.clone();
            debug!("opaque handle found in handles manager: {:?}", path_str);
            let dir_path = Path::new(&path_str);
            debug!("path: {:?}", dir_path);

            if dir_path.is_dir() {
                debug!("SftpServer ReadDir operation path = {:?}", dir_path);

                let dir_iterator = fs::read_dir(dir_path).map_err(|err| {
                    error!("could not get the directory {:?}: {:?}", path_str, err);
                    StatusCode::SSH_FX_PERMISSION_DENIED
                })?;

                let name_entry_collection = DirEntriesCollection::new(dir_iterator);

                let response_read_status =
                    name_entry_collection.send_response(reply).await?;

                dir.read_status = response_read_status;
                return Ok(());
            } else {
                error!("the path is not a directory = {:?}", dir_path);
                return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
            }
        } else {
            error!("Could not find the directory for {:?}", opaque_dir_handle);
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
    }

    fn stats(&mut self, follow_links: bool, file_path: &str) -> SftpOpResult<Attrs> {
        log::debug!("SftpServer ListStats: file_path = {:?}", file_path);
        let file_path = Path::new(file_path);

        let metadata = if follow_links {
            file_path.metadata() // follows symlinks
        } else {
            file_path.symlink_metadata() // doesn't follow symlinks
        }
        .map_err(|err| {
            error!("Problem listing stats: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })?;

        if file_path.is_file() {
            return Ok(sunset_sftp::server::helpers::get_file_attrs(metadata));
        } else if file_path.is_symlink() {
            return Ok(sunset_sftp::server::helpers::get_file_attrs(metadata));
        } else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
    }
}
