use crate::FileHandle;

use sunset::sshwire::{BinString, WireError};

use std::collections::HashMap;

pub const FILE_HANDLE_MAX_LEN: usize = 8;

/// Obscured file handle using Linear Congruential Generator (LCG) for pseudo-random generation.
///
/// This struct provides a fixed-length handle that appears random but is deterministic
/// based on the input seed. Uses LCG with constants from Numerical Recipes.
///
/// # Limitations
///
/// - **Not cryptographically secure**: Predictable if the algorithm and seed are known
/// - **Limited entropy**: u8 seed provides only 256 different possible handles
/// - **Linear correlations**: Sequential seeds produce statistically correlated outputs
/// - **Reversible**: Given the handle, the original seed can potentially be recovered
/// - **Not suitable for security**: Should only be used for obscuration, not protection
///
/// # Security Note
///
/// This is intended for basic handle obscuration in SFTP to prevent casual observation
/// of handle-to-file mappings. It is NOT suitable for cryptographic purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObscuredFileHandle {
    data: [u8; FILE_HANDLE_MAX_LEN],
}

impl ObscuredFileHandle {
    /// Generate a pseudo-random handle from a u8 seed using Linear Congruential Generator.
    ///
    /// Same seed will always produce the same handle. Only 256 different handles
    /// are possible due to u8 seed limitation. This is deliberate to imply its limitations
    ///
    /// TODO: If this library is to be hardened this is a point to address  
    pub fn new(seed: u8) -> Self {
        let mut data = [0u8; FILE_HANDLE_MAX_LEN];

        // Simple Linear Congruential Generator (LCG)
        // Using constants from Numerical Recipes
        let mut state = seed as u64;

        for chunk in data.chunks_mut(8) {
            // LCG: next = (a * current + c) mod 2^64
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);

            let bytes = state.to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }

        Self { data }
    }

    /// Get the handle as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the handle as a Vec<u8> for wire protocol
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Create from existing bytes (for parsing from wire)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FILE_HANDLE_MAX_LEN {
            return None;
        }

        let mut data = [0u8; FILE_HANDLE_MAX_LEN];
        data.copy_from_slice(bytes);
        Some(Self { data })
    }

    /// Create from BinString (for parsing from SFTP wire protocol)
    pub fn from_binstring(binstring: &BinString<'_>) -> Option<Self> {
        Self::from_bytes(binstring.0)
    }

    /// Create from FileHandle (for parsing from SFTP wire protocol)
    pub fn from_filehandle(file_handle: &FileHandle<'_>) -> Option<Self> {
        Self::from_bytes(file_handle.0.0)
    }

    /// Convert to BinString for SFTP wire protocol
    pub fn to_binstring(&self) -> BinString<'_> {
        BinString(&self.data)
    }

    /// Convert to FileHandle for SFTP wire protocol
    pub fn to_filehandle(&self) -> FileHandle<'_> {
        FileHandle(self.to_binstring())
    }
}

// Display trait for debugging/logging
impl core::fmt::Display for ObscuredFileHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.data {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// Standard trait implementations for BinString conversion
impl<'a> From<&'a ObscuredFileHandle> for BinString<'a> {
    fn from(handle: &'a ObscuredFileHandle) -> Self {
        handle.to_binstring()
    }
}

impl<'a> TryFrom<&BinString<'a>> for ObscuredFileHandle {
    type Error = WireError;

    fn try_from(binstring: &BinString<'a>) -> Result<Self, Self::Error> {
        Self::from_binstring(binstring).ok_or(WireError::BadString)
    }
}

impl<'a> TryFrom<BinString<'a>> for ObscuredFileHandle {
    type Error = WireError;

    fn try_from(binstring: BinString<'a>) -> Result<Self, Self::Error> {
        Self::try_from(&binstring)
    }
}

// Conversions with proto::FileHandle
impl<'a> From<&'a ObscuredFileHandle> for crate::proto::FileHandle<'a> {
    fn from(handle: &'a ObscuredFileHandle) -> Self {
        crate::proto::FileHandle(handle.into())
    }
}

impl<'a> TryFrom<&crate::proto::FileHandle<'a>> for ObscuredFileHandle {
    type Error = WireError;

    fn try_from(
        file_handle: &crate::proto::FileHandle<'a>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&file_handle.0)
    }
}

impl<'a> TryFrom<crate::proto::FileHandle<'a>> for ObscuredFileHandle {
    type Error = WireError;

    fn try_from(
        file_handle: crate::proto::FileHandle<'a>,
    ) -> Result<Self, Self::Error> {
        Self::try_from(&file_handle)
    }
}

/// Used to standarise finding a path within the HandleManager
pub trait PathFinder {
    /// Helper function to find elements stored in the HandleManager that matches the give path
    fn matches_path(&self, path: &str) -> bool;
}

// Example usage structure for managing handles
pub struct HandleManager<T>
where
    T: PathFinder,
{
    next_handle_id: u8,
    handle_map: HashMap<ObscuredFileHandle, T>,
}

impl<T: PathFinder> HandleManager<T> {
    pub fn new() -> Self {
        Self { next_handle_id: 1, handle_map: HashMap::new() }
    }

    pub fn create_handle(&mut self, value: T) -> ObscuredFileHandle {
        let handle = ObscuredFileHandle::new(self.next_handle_id);
        self.next_handle_id += 1;

        self.handle_map.insert(handle, value);
        handle
    }

    pub fn get_handle_value_as_ref(
        &self,
        handle: &ObscuredFileHandle,
    ) -> Option<&T> {
        self.handle_map.get(handle)
    }

    pub fn remove_handle(&mut self, handle: &ObscuredFileHandle) -> Option<T> {
        self.handle_map.remove(handle)
    }

    pub fn handle_exists(&self, handle: &ObscuredFileHandle) -> bool {
        self.handle_map.contains_key(handle)
    }

    pub fn is_open(&self, filename: &str) -> bool {
        if self.handle_map.is_empty() {
            return false;
        }
        self.handle_map.iter().any(|(_, element)| element.matches_path(filename))
        // TODO: Fix this. We need to be able to find out if the filename has been open. That cannot be done with a general T. Is will need to implement a trait to check that
        // true
    }
}

impl<T> Default for HandleManager<T>
where
    T: PathFinder,
{
    fn default() -> Self {
        Self::new()
    }
}
