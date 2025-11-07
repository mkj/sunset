use crate::{
    demofilehandlemanager::DemoFileHandleManager,
    demoopaquefilehandle::DemoOpaqueFileHandle,
};

use sunset::sshwire::SSHEncode;
use sunset_sftp::handles::{OpaqueFileHandleManager, PathFinder};
use sunset_sftp::protocol::constants::MAX_NAME_ENTRY_SIZE;
use sunset_sftp::protocol::{Attrs, Filename, Name, NameEntry, StatusCode};
use sunset_sftp::server::{DirReply, ReadReply, SftpOpResult, SftpServer, SftpSink};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::fs::DirEntry;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;
use std::{fs, io};
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

        let fh = self.handles_manager.insert(
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

    fn opendir(&mut self, dir: &str) -> SftpOpResult<DemoOpaqueFileHandle> {
        debug!("Open Directory = {:?}", dir);

        let dir_handle = self.handles_manager.insert(
            PrivatePathHandle::Directory(PrivateDirHandle { path: dir.into() }),
            OPAQUE_SALT,
        );

        debug!(
            "Directory \"{:?}\" will have the obscured file handle: {:?}",
            dir, dir_handle
        );

        dir_handle
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
            .get_private_as_ref(opaque_dir_handle)
            .ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?
        {
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

                name_entry_collection.send_entries_header(reply).await?;

                name_entry_collection.send_entries(reply).await?;

                // name_entry_collection.send_eof(reply).await?;
            } else {
                error!("the path is not a directory = {:?}", dir_path);
                return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
            }
        } else {
            error!("Could not find the directory for {:?}", opaque_dir_handle);
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
        Ok(())
    }
}

// TODO Add this to SFTP library only available with std as a global helper
/// This is a helper structure to make ReadDir into something somehow
/// digestible by [`DirReply`]
///
/// WIP: Not stable. It has know issues and most likely it's methods will change
///
/// BUG: It does not count properly the number of bytes
///
/// BUG: It does not include longname and that may be an issue
#[derive(Debug)]
pub struct DirEntriesCollection {
    /// Number of elements
    count: u32,
    /// Computed length of all the encoded elements
    encoded_length: u32,
    /// The actual entries. As you can see these are DirEntry. This is a std choice
    entries: Vec<DirEntry>,
}

impl DirEntriesCollection {
    pub fn new(dir_iterator: fs::ReadDir) -> Self {
        let mut encoded_length = 9; // TODO We need to consider the packet type, Id and count fields
                                    // This way I collect data required for the header and collect
                                    // valid entries into a vector (only std)
        let entries: Vec<DirEntry> = dir_iterator
            .filter_map(|entry_result| {
                let entry = entry_result.ok()?;
                let filename = entry.file_name().to_string_lossy().into_owned();
                let name_entry = NameEntry {
                    filename: Filename::from(filename.as_str()),
                    _longname: Filename::from(""),
                    attrs: Self::get_attrs_or_empty(entry.metadata()),
                };

                let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
                let mut sftp_sink = SftpSink::new(&mut buffer);
                name_entry.enc(&mut sftp_sink).ok()?;
                //TODO remove this unchecked casting
                encoded_length += sftp_sink.payload_len() as u32;
                Some(entry)
            })
            .collect();

        //TODO remove this unchecked casting
        let count = entries.len() as u32;

        info!(
            "Processed {} entries, estimated serialized length: {}",
            count, encoded_length
        );

        Self { count, encoded_length, entries }
    }

    fn get_attrs_or_empty(
        maybe_metadata: Result<fs::Metadata, std::io::Error>,
    ) -> Attrs {
        maybe_metadata.map(Self::get_attrs).unwrap_or_default()
    }

    fn get_attrs(metadata: fs::Metadata) -> Attrs {
        let time_to_u32 = |time_result: io::Result<SystemTime>| {
            time_result
                .ok()?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()?
                .as_secs()
                .try_into()
                .ok()
        };

        Attrs {
            size: Some(metadata.len()),
            uid: Some(metadata.st_uid()),
            gid: Some(metadata.st_gid()),
            permissions: Some(metadata.permissions().mode()),
            atime: time_to_u32(metadata.accessed()),
            mtime: time_to_u32(metadata.modified()),
            ext_count: None,
        }
    }

    pub async fn send_entries_header<const N: usize>(
        &self,
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        reply.send_header(self.count, self.encoded_length).await.map_err(|e| {
            debug!("Could not send header {e:?}");
            StatusCode::SSH_FX_FAILURE
        })
    }

    pub async fn send_entries<const N: usize>(
        &self,
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        for entry in &self.entries {
            let filename = entry.file_name().to_string_lossy().into_owned();
            let attrs = Self::get_attrs_or_empty(entry.metadata());
            let name_entry = NameEntry {
                filename: Filename::from(filename.as_str()),
                _longname: Filename::from(""),
                attrs,
            };
            debug!("Sending new item: {:?}", name_entry);
            let mut buffer = [0u8; MAX_NAME_ENTRY_SIZE];
            let mut sftp_sink = SftpSink::new(&mut buffer);
            name_entry.enc(&mut sftp_sink).map_err(|err| {
                error!("WireError: {:?}", err);
                StatusCode::SSH_FX_FAILURE
            })?;
            reply.send_item(sftp_sink.payload_slice()).await.map_err(|err| {
                error!("SftpError: {:?}", err);
                StatusCode::SSH_FX_FAILURE
            })?;
        }
        Ok(())
    }

    pub async fn no_files<const N: usize>(
        &self,
        reply: &DirReply<'_, N>,
    ) -> SftpOpResult<()> {
        reply.send_eof().await.map_err(|err| {
            error!("SftpError: {:?}", err);
            StatusCode::SSH_FX_FAILURE
        })
    }
}
