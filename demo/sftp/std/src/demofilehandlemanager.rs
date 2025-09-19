use sunset_sftp::{
    OpaqueFileHandle, OpaqueFileHandleManager, PathFinder, StatusCode,
};

use std::collections::HashMap; // Not enforced. Only for std. For no_std environments other solutions can be used to store Key, Value

pub struct DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle,
    V: PathFinder,
{
    handle_map: HashMap<K, V>,
}

impl<K, V> DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle,
    V: PathFinder,
{
    pub fn new() -> Self {
        Self { handle_map: HashMap::new() }
    }
}

impl<K, V> OpaqueFileHandleManager<K, V> for DemoFileHandleManager<K, V>
where
    K: OpaqueFileHandle,
    V: PathFinder,
{
    type Error = StatusCode;

    fn insert(&mut self, private_handle: V, salt: &str) -> Result<K, Self::Error> {
        if self
            .handle_map
            .iter()
            .any(|(_, private_handle)| private_handle.matches(&private_handle))
        {
            return Err(StatusCode::SSH_FX_PERMISSION_DENIED);
        }

        let handle = K::new(
            format!("{:}-{:}", &private_handle.get_path_ref(), salt).as_str(),
        );

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
}
