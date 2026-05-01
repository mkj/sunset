/// Helpers structures intended to for environment with `std` available, specially linux.
///
/// The collection helps with directory and directory items enumeration, description
/// and organizing. Providing means to translate them into [`sunset-sftp`] structures
///
use sunset_sftp::{
    error::SftpError,
    protocol::{
        constants::MAX_NAME_ENTRY_SIZE, Attrs, Filename, NameEntry, StatusCode,
    },
    server::{DirReadDataReply, DirReadReplyFinished, SftpOpResult, SftpSink},
};

use sunset::sshwire::SSHEncode;

use log::{debug, error, info};
use std::{
    fs::{DirEntry, Metadata, ReadDir},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    time::SystemTime,
};

/// This is a helper structure to make ReadDir into something manageable for
/// [`DirReply`]
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
    /// Creates this DirEntriesCollection so linux std users do not need to
    /// translate `std` directory elements into Sftp structures before sending a response
    /// back to the client
    pub fn new(dir_iterator: ReadDir) -> SftpOpResult<Self> {
        let mut encoded_length = 0;

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
                encoded_length += u32::try_from(sftp_sink.payload_len())
                    .map_err(|_| StatusCode::SSH_FX_FAILURE)
                    .ok()?;
                Some(entry)
            })
            .collect();

        let count =
            u32::try_from(entries.len()).map_err(|_| StatusCode::SSH_FX_FAILURE)?;

        info!(
            "Processed {} entries, estimated serialized length: {}",
            count, encoded_length
        );

        Ok(Self { count, encoded_length, entries })
    }

    pub(crate) fn encoded_length(&self) -> u32 {
        self.encoded_length
    }
    pub(crate) fn count(&self) -> u32 {
        self.count
    }

    pub(crate) async fn send_entries<const N: usize>(
        &self,
        data_reply: DirReadDataReply<'_, N>,
    ) -> SftpOpResult<DirReadReplyFinished> {
        if self.entries.is_empty() {
            return Err(StatusCode::SSH_FX_EOF);
        }

        let Ok(token) = data_reply
            .send_data(|mut limited_dir_sender| async move {
                for entry in &self.entries {
                    let filename = entry.file_name().to_string_lossy().into_owned();
                    let attrs = Self::get_attrs_or_empty(entry.metadata());
                    let name_entry = NameEntry {
                        filename: Filename::from(filename.as_str()),
                        _longname: Filename::from(""),
                        attrs,
                    };
                    debug!("Sending new item: {:?}", name_entry);

                    limited_dir_sender.send_item(&name_entry).await?;
                }
                match limited_dir_sender.completed() {
                    Some(completed_token) => Ok(completed_token),
                    None => {
                        Err(SftpError::FileServerError(StatusCode::SSH_FX_FAILURE))
                    }
                }
            })
            .await
        else {
            error!("Failed to send directory entries");
            return Err(StatusCode::SSH_FX_FAILURE);
        };
        Ok(token)
    }

    fn get_attrs_or_empty(
        maybe_metadata: Result<Metadata, std::io::Error>,
    ) -> Attrs {
        maybe_metadata.map(get_file_attrs).unwrap_or_default()
    }
}

/// [`std`] helper function to get [`Attrs`] from a [`Metadata`].
pub fn get_file_attrs(metadata: Metadata) -> Attrs {
    let time_to_u32 = |time_result: std::io::Result<SystemTime>| {
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
