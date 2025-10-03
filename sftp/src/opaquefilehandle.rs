use crate::protocol::FileHandle;

use sunset::sshwire::WireResult;

/// This is the trait with the required methods for interoperability between different opaque file handles
/// used in SFTP transactions
pub trait OpaqueFileHandle:
    Sized + Clone + core::hash::Hash + PartialEq + Eq + core::fmt::Debug
{
    /// Creates a new instance using a given string slice as `seed` which
    /// content should not clearly related to the seed
    fn new(seed: &str) -> Self;

    /// Creates a new `OpaqueFileHandleTrait` copying the content of the `FileHandle`
    fn try_from(file_handle: &FileHandle<'_>) -> WireResult<Self>;

    /// Returns a FileHandle pointing to the data in the `OpaqueFileHandleTrait` Implementation
    fn into_file_handle(&self) -> FileHandle<'_>;
}

/// Used to standardize finding a path within the HandleManager
///
/// Must be implemented by the private handle structure to allow the `OpaqueHandleManager` to look for the path of the file itself
pub trait PathFinder {
    /// Helper function to find elements stored in the HandleManager that matches the give path
    fn matches(&self, path: &Self) -> bool;

    /// gets the path as a reference
    fn get_path_ref(&self) -> &str;
}

/// This trait is used to manage the OpaqueFile
///
/// The SFTP module user is not required to use it but instead is a suggestion for an exchangeable
/// trait that facilitates structuring the store and retrieve of 'OpaqueFileHandleTrait' (K),
/// together with a private handle type or structure (V) that will contains all the details internally stored for the given file.
///
/// The only requisite for v is that implements PathFinder, which in fact is another suggested helper to allow the `OpaqueHandleManager`
/// to look for the file path.
pub trait OpaqueFileHandleManager<K, V>
where
    K: OpaqueFileHandle,
    V: PathFinder,
{
    /// The error used for all the trait members returning an error
    type Error;

    // Excluded since it is too restrictive
    // /// Performs any HandleManager Initialization
    // fn new() -> Self;

    /// Given the private_handle, stores it and return an opaque file handle
    ///
    /// Returns an error if the private_handle has a matching path as obtained from `PathFinder`
    ///
    /// Salt has been added to allow the user to add a factor that will mask how the opaque handle is generated
    fn insert(&mut self, private_handle: V, salt: &str) -> Result<K, Self::Error>;

    ///
    fn remove(&mut self, opaque_handle: &K) -> Option<V>;

    /// Returns true if the opaque handle exist
    fn opaque_handle_exist(&self, opaque_handle: &K) -> bool;

    /// given the opaque_handle returns a reference to the associated private handle
    fn get_private_as_ref(&self, opaque_handle: &K) -> Option<&V>;
}
