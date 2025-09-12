use sunset::sshwire::BinString;
use sunset_sftp::{
    Attrs, DirReply, FileHandle, Filename, Name, NameEntry, ReadReply, SftpOpResult,
    SftpServer, StatusCode,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

pub struct DemoSftpServer {
    valid_handlers: Vec<String>, // TODO: Obscure the handlers
    user_path: String,
}

impl DemoSftpServer {
    pub fn new(user: String) -> Self {
        DemoSftpServer {
            valid_handlers: vec![],
            user_path: format!("/{}/", user.clone()),
        }
    }
}
impl SftpServer<'_> for DemoSftpServer {
    // Mocking an Open operation. Will not check for permissions
    fn open(
        &mut self,
        filename: &str,
        _attrs: &Attrs,
    ) -> SftpOpResult<FileHandle<'_>> {
        if self.valid_handlers.contains(&filename.to_string()) {
            warn!("File {:?} already open, won't allow it", filename);
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        }

        self.valid_handlers.push(filename.to_string());

        let fh = FileHandle(BinString(
            self.valid_handlers.last().expect("just pushed an element").as_bytes(),
        ));
        Ok(fh)
    }

    fn realpath(&mut self, dir: &str) -> SftpOpResult<Name<'_>> {
        debug!("finding path for: {:?}", dir);
        Ok(Name(vec![NameEntry {
            filename: Filename::from(self.user_path.as_str()),
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

    fn close(&mut self, handle: &FileHandle) -> SftpOpResult<()> {
        let initial_count = self.valid_handlers.len();
        if initial_count == 0 {
            log::error!(
                "SftpServer Close operation with no handles stored: handle = {:?}",
                handle
            );
            return Err(StatusCode::SSH_FX_FAILURE);
        }

        let filename =
            String::from_utf8(handle.0.as_ref().to_vec()).unwrap_or("".into());

        if !self.valid_handlers.contains(&filename) {
            log::error!(
                "SftpServer Close operation could not match an stored handler: handle = {:?}",
                handle
            );
            return Err(StatusCode::SSH_FX_FAILURE);
        }
        self.valid_handlers.retain(|handler| handler.ne(&filename));
        log::debug!("SftpServer Close operation on {:?} was successful", filename);
        Ok(())
    }

    fn read(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        reply: &mut ReadReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer Read operation not defined: handle = {:?}, offset = {:?}",
            handle,
            offset
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn write(
        &mut self,
        handle: &FileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        log::debug!(
            "SftpServer Write operation: handle = {:?}, offset = {:?}, buf = {:?}",
            handle,
            offset,
            String::from_utf8(buf.to_vec())
        );
        Ok(())
    }

    fn opendir(&mut self, dir: &str) -> SftpOpResult<FileHandle<'_>> {
        log::error!("SftpServer OpenDir operation not defined: dir = {:?}", dir);
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }

    fn readdir(
        &mut self,
        handle: &FileHandle,
        reply: &mut DirReply<'_, '_>,
    ) -> SftpOpResult<()> {
        log::error!(
            "SftpServer ReadDir operation not defined: handle = {:?}",
            handle
        );
        Err(StatusCode::SSH_FX_OP_UNSUPPORTED)
    }
}
