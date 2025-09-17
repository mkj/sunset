use sunset_sftp::{
    Attrs, DirReply, Filename, HandleManager, Name, NameEntry, ObscuredFileHandle,
    PathFinder, ReadReply, SftpOpResult, SftpServer, StatusCode,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use std::{fs::File, os::unix::fs::FileExt};

struct PrivateFileHandler {
    file_path: String,
    permissions: Option<u32>,
    file: File,
}

impl PathFinder for PrivateFileHandler {
    fn matches_path(&self, path: &str) -> bool {
        self.file_path.as_str().eq_ignore_ascii_case(path)
    }
}

pub struct DemoSftpServer {
    base_path: String,
    handlers_manager: HandleManager<PrivateFileHandler>,
}

impl DemoSftpServer {
    pub fn new(base_path: String) -> Self {
        DemoSftpServer { base_path, handlers_manager: HandleManager::new() }
    }
}

impl SftpServer<'_> for DemoSftpServer {
    // Mocking an Open operation. Will not check for permissions
    fn open(
        &mut self,
        filename: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<ObscuredFileHandle> {
        debug!("Open file: filename = {:?}, attributes = {:?}", filename, attrs);

        if self.handlers_manager.is_open(filename) {
            warn!("File {:?} already open, won't allow it", filename);
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        }

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

        let fh = self.handlers_manager.create_handle(PrivateFileHandler {
            file_path: filename.into(),
            permissions: attrs.permissions,
            file,
        });

        debug!(
            "Filename \"{:?}\" will have the obscured file handle: {:?}",
            filename, fh
        );

        Ok(fh)
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
        obscure_file_handle: &ObscuredFileHandle,
    ) -> SftpOpResult<()> {
        if let Some(handle) =
            self.handlers_manager.remove_handle(obscure_file_handle)
        {
            debug!(
                "SftpServer Close operation on {:?} was successful",
                handle.file_path
            );
            drop(handle.file); // Not really required but illustrative
            Ok(())
        } else {
            error!(
                "SftpServer Close operation on handle {:?} failed",
                obscure_file_handle
            );
            Err(StatusCode::SSH_FX_FAILURE)
        }
    }

    fn write(
        &mut self,
        obscured_file_handle: &ObscuredFileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        let private_file_handle = self
            .handlers_manager
            .get_handle_value_as_ref(obscured_file_handle)
            .ok_or(StatusCode::SSH_FX_FAILURE)?;

        let permissions_poxit = (private_file_handle
            .permissions
            .ok_or(StatusCode::SSH_FX_PERMISSION_DENIED))?;

        if (permissions_poxit & 0o222) == 0 {
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        };

        log::trace!(
            "SftpServer Write operation: handle = {:?}, filepath = {:?}, offset = {:?}, buf = {:?}",
            obscured_file_handle,
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
            obscured_file_handle,
            private_file_handle.file_path,
            offset,
            buf.len(),
            bytes_written
        );

        Ok(())
    }

    fn read(
        &mut self,
        obscured_file_handle: &ObscuredFileHandle,
        offset: u64,
        _reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Read operation not defined: handle = {:?}, offset = {:?}",
            obscured_file_handle,
            offset
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn opendir(&mut self, dir: &str) -> SftpOpResult<ObscuredFileHandle> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn readdir(
        &mut self,
        obscured_file_handle: &ObscuredFileHandle,
        _reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            obscured_file_handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}
