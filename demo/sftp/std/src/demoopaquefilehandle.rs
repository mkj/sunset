use sunset_sftp::{FileHandle, OpaqueFileHandle};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct DemoOpaqueFileHandle {}

impl OpaqueFileHandle for DemoOpaqueFileHandle {
    fn new(seed: &str) -> Self {
        todo!("Add some logic to create a hash form the &str from {:}", seed)
    }

    fn try_from(file_handle: &FileHandle<'_>) -> sunset::sshwire::WireResult<Self> {
        todo!(
            "Add some logic to handle the the conversion try_from {:?}",
            file_handle
        )
    }

    fn into_file_handle(&self) -> FileHandle<'_> {
        todo!("Add some logic to handle the the conversion into_file_handle")
    }
}
