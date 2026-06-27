use crate::stdhelpers::{DirEntriesCollection, get_file_attrs};

use embedded_io_async::Write;
use sunset_sftp::embedded_io_async;
use sunset_sftp::server::DirReadReplyFinished;
use sunset_sftp::{
    error::SftpResult,
    protocol::{Attrs, Filename, NameEntry, PFlags, StatusCode},
    server::{
        DirHandle, DirReadHeaderReply, FileHandle, ReadHeaderReply,
        ReadReplyFinished, ReadStatus, SftpOpResult, SftpServer,
    },
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use strict_path::StrictPath;
/// This is a marker for the SftpDir transactions.
/// See [the mix up problem](https://dk26.github.io/strict-path-rs/tutorial/chapter2_mixup_problem.html)
/// and [markers to the rescue](https://dk26.github.io/strict-path-rs/tutorial/chapter3_markers.html)
/// if you are not familiar with marker types
struct SftpDir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::{fs::File, os::unix::fs::FileExt, path::Path};

/// Used during read operations
const ARBITRARY_READ_BUFFER_LENGTH: usize = 1024;

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

// The ArrayMap in this demo is suitable for a no_alloc embedded platform.
// Another option would be heapless::FnvIndexMap.
//
// Normal std implementations could use a simpler
// HashMap<sftpserver::FileHandle, PrivateFileHandle> instead,
// with arbitrary unique `u32`s for FileHandle.
struct ArrayMap<V, const N: usize> {
    items: [Option<V>; N],
}

impl<V, const N: usize> ArrayMap<V, N> {
    fn new() -> Self {
        Self { items: [const { None }; _] }
    }
    fn insert(&mut self, v: V) -> Result<usize, V> {
        for (i, e) in self.items.iter_mut().enumerate() {
            if e.is_none() {
                *e = Some(v);
                return Ok(i);
            }
        }
        return Err(v);
    }

    fn get(&mut self, index: usize) -> Option<&mut V> {
        self.items.get_mut(index).and_then(|v| v.as_mut())
    }

    fn remove(&mut self, index: usize) -> Option<V> {
        self.items.get_mut(index).and_then(|f| f.take())
    }
}

/// Limit of open file handles
const FILE_HANDLES: usize = 10;
/// Limit of dir file handles
const DIR_HANDLES: usize = 10;

/// A basic demo server. Used as a demo and to test SFTP functionality
pub struct DemoSftpServer {
    base_path: StrictPath<SftpDir>,
    last_real_path: String,

    // File handle map
    files: ArrayMap<PrivateFileHandle, FILE_HANDLES>,
    // Directory handle map
    dirs: ArrayMap<PrivateDirHandle, DIR_HANDLES>,
}

impl DemoSftpServer {
    pub fn new(base_path: String) -> Self {
        if !Path::new(&base_path).exists() {
            debug!("Base path {:?} does not exist. Creating it", base_path);
            fs::create_dir_all(&base_path).unwrap_or_else(|e| {
                panic!("Could not create the base path {:?}: {:?}", base_path, e);
            });
        } else {
            debug!("Base path {:?} already exists", base_path);
        }

        let base_path = StrictPath::<SftpDir>::with_boundary(base_path)
            .unwrap_or_else(|e| {
                panic!("Could not create the base path {:?}", e);
            });

        let real_path = base_path.strictpath_display().to_string();

        DemoSftpServer {
            base_path,
            last_real_path: real_path,
            files: ArrayMap::new(),
            dirs: ArrayMap::new(),
        }
    }
}

impl SftpServer for DemoSftpServer {
    async fn open(
        &mut self,
        filename: &str,
        mode: &PFlags,
    ) -> SftpOpResult<FileHandle> {
        // Untrusted input: user upload, API param, config value, AI agent output, archive entry...
        let Ok(validated_filename_path) = self.base_path.strict_join(filename)
        else {
            error!(
                "Could not validate the filename {:?} with the protected path boundary {:?}",
                filename, self.base_path
            );
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        };

        debug!(
            "Open file: filename = {:?}, mode = {:?}",
            validated_filename_path, mode
        );

        let can_write = u32::from(mode) & u32::from(&PFlags::SSH_FXF_WRITE) > 0;
        let can_read = u32::from(mode) & u32::from(&PFlags::SSH_FXF_READ) > 0;

        info!(
            "File open for read/write access: can_read={:?}, can_write={:?}",
            can_read, can_write
        );

        let file = validated_filename_path
            .open_with()
            .read(can_read)
            .write(can_write)
            .create(can_write)
            .open()
            .map_err(|e| {
                error!(
                    "Could not open the file {:?} with the mode {:?}: {:?}",
                    validated_filename_path, mode, e
                );
                StatusCode::SSH_FX_FAILURE
            })?;

        let permissions = file
            .metadata()
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?
            .permissions()
            .mode()
            & 0o777;

        let fh = self
            .files
            .insert(PrivateFileHandle {
                path: validated_filename_path.strictpath_display().to_string(),
                permissions: Some(permissions),
                file,
            })
            .map(|v| FileHandle(v as u32))
            .map_err(|_| StatusCode::SSH_FX_FAILURE);

        trace!("Filename \"{:?}\" will have file handle: {:?}", filename, fh);

        fh
    }

    async fn opendir(&mut self, dir: &str) -> SftpOpResult<DirHandle> {
        info!("Open Directory = {:?}", dir);
        // Untrusted input: user upload, API param, config value, AI agent output, archive entry...
        let Ok(validated_dir_path) = self.base_path.strict_join(dir) else {
            error!(
                "Could not validate the directory {:?} with the protected path boundary {:?}",
                dir, self.base_path
            );
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        };

        let dir_handle = self
            .dirs
            .insert(PrivateDirHandle {
                path: validated_dir_path.strictpath_display().to_string(),
                read_status: ReadStatus::default(),
            })
            .map(|v| DirHandle(v as u32))
            .map_err(|_| StatusCode::SSH_FX_FAILURE);

        debug!(
            "Directory \"{:?}\" will have the obscured file handle: {:?}",
            dir, dir_handle
        );

        dir_handle
    }

    async fn realpath(&mut self, dir: &str) -> SftpOpResult<NameEntry<'_>> {
        info!("finding path for: {:?}", dir);
        self.last_real_path = self.base_path.strict_join(dir)
            .map_err(|err| {
                error!("Could not validate the directory {:?} with the protected path boundary {:?}: {:?}", dir, self.base_path, err);
                StatusCode::SSH_FX_PERMISSION_DENIED
            })?
            .strictpath_display()
            .to_string();

        let name_entry = NameEntry {
            filename: Filename::from(self.last_real_path.as_str()),
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

    async fn close(&mut self, fh: FileHandle) -> SftpOpResult<()> {
        trace!("close {fh:?}");
        self.files.remove(fh.0 as usize).ok_or(StatusCode::SSH_FX_FAILURE)?;
        Ok(())
    }

    async fn closedir(&mut self, fh: DirHandle) -> SftpOpResult<()> {
        trace!("close {fh:?}");
        self.dirs.remove(fh.0 as usize).ok_or(StatusCode::SSH_FX_FAILURE)?;
        Ok(())
    }

    async fn read<W: Write>(
        &mut self,
        fh: FileHandle,
        offset: u64,
        len: u32,
        mut reply: ReadHeaderReply<'_, '_, W>,
    ) -> SftpResult<ReadReplyFinished> {
        let Some(private_file_handle) = self.files.get(fh.0 as usize) else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE.into());
        };

        log::debug!(
            "SftpServer Read operation: handle = {:?}, filepath = {:?}, offset = {:?}, len = {:?}",
            fh,
            private_file_handle.path,
            offset,
            len
        );

        let permissions_poxit = private_file_handle.permissions.unwrap_or(0o000);
        if (permissions_poxit & 0o444) == 0 {
            error!("No read permissions for file {:?}", private_file_handle.path);
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
            info!(
                "offset is larger than file length, sending EOF for {:?}",
                private_file_handle.path
            );
            let finished = reply.send_eof().await.map_err(|err| {
                error!("Could not sent EOF: {:?}", err);
                StatusCode::SSH_FX_FAILURE
            })?;
            return Ok(finished);
        }

        let read_len = match file_len {
            // Greater or equal than len + offset
            file_len if file_len >= len as u64 + offset => {
                debug!(
                    "File length ({:?}) is greater than offset + len ({:?} + {:?}). Will read the announced length",
                    file_len, offset, len
                );
                len
            }
            _ => {
                debug!(
                    "File length ({:?}) is smaller than offset + len ({:?} + {:?}). Will read until the end of the file",
                    file_len, offset, len
                );
                (file_len - offset).try_into().unwrap_or(u32::MAX)
            }
        };

        let data_reply = reply.send_header(read_len).await?;

        let mut read_buff = [0u8; ARBITRARY_READ_BUFFER_LENGTH];

        let mut accumulated_offset = offset;

        let finished = data_reply
            .send_data(|mut limited_sender| async move {
                loop {
                    match limited_sender.completed() {
                        Some(completed_token) => return Ok(completed_token),
                        None => {
                            let br = private_file_handle
                                .file
                                .read_at(&mut read_buff, accumulated_offset)
                                .map_err(|err| {
                                    error!("read error: {:?}", err);
                                    StatusCode::SSH_FX_FAILURE
                                })?;
                            if br == 0 {
                                error!(
                                    "Unexpected EOF while reading the file {:?}",
                                    private_file_handle.path
                                );
                                return Err(StatusCode::SSH_FX_FAILURE)?;
                            }
                            let _sw =
                                limited_sender.send_data(&read_buff[..br]).await?;
                            accumulated_offset = accumulated_offset
                                .checked_add(br as u64)
                                .ok_or(StatusCode::SSH_FX_FAILURE)?;
                        }
                    }
                }
            })
            .await?;
        return Ok(finished);
    }

    async fn write(
        &mut self,
        fh: FileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        let Some(private_file_handle) = self.files.get(fh.0 as usize) else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE.into());
        };

        let permissions_poxit = (private_file_handle
            .permissions
            .ok_or(StatusCode::SSH_FX_PERMISSION_DENIED))?;

        if (permissions_poxit & 0o222) == 0 {
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        };

        log::trace!(
            "SftpServer Write operation: handle = {:?}, filepath = {:?}, offset = {:?}, buf = {:?}",
            fh,
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
            fh,
            private_file_handle.path,
            offset,
            buf.len(),
            bytes_written
        );

        Ok(())
    }

    async fn readdir<W: Write>(
        &mut self,
        dh: DirHandle,
        mut reply: DirReadHeaderReply<'_, '_, W>,
    ) -> SftpOpResult<DirReadReplyFinished> {
        trace!("read dir for {:?}", dh);

        let Some(dir) = self.dirs.get(dh.0 as usize) else {
            debug!("Could not find the directory for {:?}", dh);
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE.into());
        };

        if dir.read_status == ReadStatus::EndOfFile {
            let finish_token = reply.send_eof().await.map_err(|error| {
                error!("{:?}", error);
                StatusCode::SSH_FX_FAILURE
            })?;
            return Ok(finish_token);
        }

        let path_str = dir.path.clone();
        debug!("opaque handle found in handles manager: {:?}", path_str);
        let dir_path = Path::new(&path_str);
        debug!("path: {:?}", dir_path);

        if dir_path.is_dir() {
            trace!("SftpServer ReadDir operation path = {:?}", dir_path);

            let dir_iterator = fs::read_dir(dir_path).map_err(|err| {
                error!("could not get the directory {:?}: {:?}", path_str, err);
                StatusCode::SSH_FX_PERMISSION_DENIED
            })?;

            let name_entry_collection = DirEntriesCollection::new(dir_iterator)?;

            let encoded_length = name_entry_collection.encoded_length();
            let items_count = name_entry_collection.count();

            let data_reply = reply
                .send_header(encoded_length, items_count)
                .await
                .map_err(|_| StatusCode::SSH_FX_OP_UNSUPPORTED)?;

            let finish_token =
                name_entry_collection.send_entries(data_reply).await?;

            dir.read_status = ReadStatus::EndOfFile;

            return Ok(finish_token);
        } else {
            error!("the path is not a directory = {:?}", dir_path);
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
    }

    async fn attrs(
        &mut self,
        follow_links: bool,
        file_path: &str,
    ) -> SftpOpResult<Attrs> {
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
            return Ok(get_file_attrs(metadata));
        } else if file_path.is_symlink() {
            return Ok(get_file_attrs(metadata));
        } else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
    }
}
