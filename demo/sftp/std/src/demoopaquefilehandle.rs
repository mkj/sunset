use sunset_sftp::handles::OpaqueFileHandle;
use sunset_sftp::protocol::FileHandle;

use sunset::sshwire::{BinString, WireError};

use core::hash::Hasher;

use fnv::FnvHasher;

const HASH_LEN: usize = 4;
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub(crate) struct DemoOpaqueFileHandle {
    tiny_hash: [u8; HASH_LEN],
}

impl OpaqueFileHandle for DemoOpaqueFileHandle {
    fn new(seed: &str) -> Self {
        let mut hasher = FnvHasher::default();
        hasher.write(seed.as_bytes());
        DemoOpaqueFileHandle { tiny_hash: (hasher.finish() as u32).to_be_bytes() }
    }

    fn try_from(file_handle: &FileHandle<'_>) -> sunset::sshwire::WireResult<Self> {
        if !file_handle.0 .0.len().eq(&core::mem::size_of::<DemoOpaqueFileHandle>())
        {
            return Err(WireError::BadString);
        }

        let mut tiny_hash = [0u8; HASH_LEN];
        tiny_hash.copy_from_slice(file_handle.0 .0);
        Ok(DemoOpaqueFileHandle { tiny_hash })
    }

    fn into_file_handle(&self) -> FileHandle<'_> {
        FileHandle(BinString(&self.tiny_hash))
    }
}
