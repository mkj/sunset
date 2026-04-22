use sunset_sftp::handles::{
    InitFileHandler, OpaqueFileHandle, OpaqueFileHandleManager, PathFinder,
};
use sunset_sftp::protocol::StatusCode;

use std::collections::HashMap; // Not enforced. Only for std. For no_std environments other solutions can be used to store Key, Value

pub struct DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle + InitFileHandler,
    V: PathFinder,
{
    handle_map: HashMap<K, V>,
}

impl<K, V> DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle + InitFileHandler,
    V: PathFinder,
{
    pub fn new() -> Self {
        Self { handle_map: HashMap::new() }
    }
}

impl<K, V> OpaqueFileHandleManager<K, V> for DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle + InitFileHandler,
    V: PathFinder,
{
    type Err = StatusCode;

    fn insert(&mut self, private_handle: V) -> Result<K, Self::Err> {
        if self
            .handle_map
            .iter()
            .any(|(_, private_handle)| private_handle.matches(&private_handle))
        {
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        }

        let handle = K::init();

        self.handle_map.insert(handle.clone(), private_handle);
        Ok(handle)
    }

    fn remove(&mut self, opaque_handle: &K) -> Option<V> {
        self.handle_map.remove(opaque_handle)
    }

    fn opaque_handle_exist(&self, opaque_handle: &K) -> bool {
        self.handle_map.contains_key(opaque_handle)
    }

    fn get_private_as_ref(&self, opaque_handle: &K) -> Option<&V> {
        self.handle_map.get(opaque_handle)
    }

    fn get_private_as_mut_ref(&mut self, opaque_handle: &K) -> Option<&mut V> {
        self.handle_map.get_mut(opaque_handle)
    }
}
