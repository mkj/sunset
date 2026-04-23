use sunset_sftp::handles::{InitFileHandler, OpaqueFileHandle};
use sunset_sftp::protocol::FileHandle;

use sunset::sshwire::{BinString, WireError};

use rand::prelude::*;

const ID_LEN: usize = 32;
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub(crate) struct DemoOpaqueFileHandle {
    handle_id: [u8; ID_LEN],
}

impl OpaqueFileHandle for DemoOpaqueFileHandle {
    fn try_from(file_handle: &FileHandle<'_>) -> sunset::sshwire::WireResult<Self> {
        if !file_handle.0 .0.len().eq(&core::mem::size_of::<DemoOpaqueFileHandle>())
        {
            return Err(WireError::BadString);
        }

        let mut handle_id = [0u8; ID_LEN];
        handle_id.copy_from_slice(file_handle.0 .0);
        Ok(DemoOpaqueFileHandle { handle_id })
    }

    fn into_file_handle(&self) -> FileHandle<'_> {
        FileHandle(BinString(&self.handle_id))
    }
}

/// Implemented to allow the use of `DemoOpaqueFileHandle` as a key in the `OpaqueHandleManager`
impl InitFileHandler for DemoOpaqueFileHandle {
    fn init() -> Self {
        let handle_id: [u8; ID_LEN] = rand::thread_rng().gen();
        DemoOpaqueFileHandle { handle_id }
    }
}
