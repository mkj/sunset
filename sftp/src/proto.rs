use crate::sftpsource::SftpSource;

use sunset::sshwire::{
    BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
    WireResult,
};
use sunset_sshwire_derive::{SSHDecode, SSHEncode};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use num_enum::FromPrimitive;
use paste::paste;

/// SFTP Minimum packet length is 9 bytes corresponding with `SSH_FXP_INIT`
#[allow(unused)]
pub const SFTP_MINIMUM_PACKET_LEN: usize = 9;

#[allow(unused)]
pub const SFTP_FIELD_LEN_INDEX: usize = 0;
/// SFTP packets length field us u32
#[allow(unused)]
pub const SFTP_FIELD_LEN_LENGTH: usize = 4;
/// SFTP packets have the packet type after a u32 length field
#[allow(unused)]
pub const SFTP_FIELD_ID_INDEX: usize = 4;
/// SFTP packets ID length is 1 byte
#[allow(unused)]
pub const SFTP_FIELD_ID_LEN: usize = 1;
/// SFTP packets start with the length field

/// SFTP packets have the packet request id after field id
#[allow(unused)]
pub const SFTP_FIELD_REQ_ID_INDEX: usize = 5;
/// SFTP packets ID length is 1 byte
#[allow(unused)]
pub const SFTP_FIELD_REQ_ID_LEN: usize = 4;
/// SFTP packets start with the length field

// SSH_FXP_WRITE SFTP Packet definition used to decode long packets that do not fit in one buffer

/// SFTP SSH_FXP_WRITE Packet cannot be shorter than this (len:4+pnum:1+rid:4+hand:4+0+data:4+0 bytes = 17 bytes) [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
// pub const SFTP_MINIMUM_WRITE_PACKET_LEN: usize = 17;

#[allow(unused)]
/// SFTP SSH_FXP_WRITE Packet request id field index  [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
pub const SFTP_WRITE_REQID_INDEX: usize = 5;

/// SFTP SSH_FXP_WRITE Packet handle field index  [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
// pub const SFTP_WRITE_HANDLE_INDEX: usize = 9;

/// Considering the definition in [Section 7](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
/// for `SSH_FXP_READDIR`
///
/// (4 + 256) bytes for path, (4 + 0) bytes for empty long path and 72 bytes for the attributes ( 32/4*7 + 64/4 * 1 = 72)
pub const MAX_NAME_ENTRY_SIZE: usize = 4 + 256 + 4 + 72;

// TODO is utf8 enough, or does this need to be an opaque binstring?
/// See [SSH_FXP_NAME in Responses from the Server to the Client](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Filename<'a>(TextString<'a>);

impl<'a> From<&'a str> for Filename<'a> {
    fn from(s: &'a str) -> Self {
        Filename(TextString(s.as_bytes()))
    }
}

// TODO standardize the encoding of filenames as str
impl<'a> Filename<'a> {
    ///
    pub fn as_str(&self) -> Result<&'a str, WireError> {
        core::str::from_utf8(self.0.0).map_err(|_| WireError::BadString)
    }
}

/// An opaque handle that is used by the server to identify an open
/// file or folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, SSHEncode, SSHDecode)]
pub struct FileHandle<'a>(pub BinString<'a>);

// ========================== Initialization ===========================

/// The reference implementation we are working on is 3, this is, https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
pub const SFTP_VERSION: u32 = 3;

/// The SFTP version of the client
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct InitVersionClient {
    // No ReqId for SSH_FXP_INIT
    pub version: u32,
    // TODO variable number of ExtPair
}

/// The lowers SFTP version from the client and the server
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct InitVersionLowest {
    // No ReqId for SSH_FXP_VERSION
    pub version: u32,
    // TODO variable number of ExtPair
}

// ============================= Requests ==============================

/// Used for `ssh_fxp_open` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Open<'a> {
    /// The relative or absolute path of the file to be open
    pub filename: Filename<'a>,
    /// File [permissions flags](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
    pub pflags: PFlags,
    /// Initial attributes for the file
    pub attrs: Attrs,
}

/// Flags for Open RequestFor more information see [Opening, creating and closing files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
/// TODO: Reference! This is packed as u32 since that is the field data type in specs
#[derive(Debug, FromPrimitive, PartialEq)]
#[repr(u32)]
#[allow(non_camel_case_types, missing_docs)]
pub enum PFlags {
    //#[sshwire(variant = "ssh_fx_read")]
    SSH_FXF_READ = 0x00000001,
    //#[sshwire(variant = "ssh_fx_write")]
    SSH_FXF_WRITE = 0x00000002,
    //#[sshwire(variant = "ssh_fx_append")]
    SSH_FXF_APPEND = 0x00000004,
    //#[sshwire(variant = "ssh_fx_creat")]
    SSH_FXF_CREAT = 0x00000008,
    //#[sshwire(variant = "ssh_fx_trunk")]
    SSH_FXF_TRUNC = 0x00000010,
    //#[sshwire(variant = "ssh_fx_excl")]
    SSH_FXF_EXCL = 0x00000020,
    //#[sshwire(unknown)]
    #[num_enum(catch_all)]
    Multiple(u32),
}

impl<'de> SSHDecode<'de> for PFlags {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        Ok(PFlags::from(u32::dec(s)?))
    }
}

// TODO: Implement an automatic from implementation for u32 to Status code
// This is prone to errors if we update PFlags enum
impl From<&PFlags> for u32 {
    fn from(value: &PFlags) -> Self {
        match value {
            PFlags::SSH_FXF_READ => 0x00000001,
            PFlags::SSH_FXF_WRITE => 0x00000002,
            PFlags::SSH_FXF_APPEND => 0x00000004,
            PFlags::SSH_FXF_CREAT => 0x00000008,
            PFlags::SSH_FXF_TRUNC => 0x00000010,
            PFlags::SSH_FXF_EXCL => 0x00000020,
            PFlags::Multiple(value) => *value,
        }
    }
}
// TODO: Implement an SSHEncode attribute for enums to encode them in a given numeric format
impl SSHEncode for PFlags {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let numeric_value: u32 = self.into();
        numeric_value.enc(s)
    }
}

/// Used for `ssh_fxp_open` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct OpenDir<'a> {
    /// The relative or absolute path of the directory to be open
    pub dirname: Filename<'a>,
}

/// Used for `ssh_fxp_close` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Close<'a> {
    /// An opaque handle that is used by the server to identify an open
    /// file or folder to be closed.
    pub handle: FileHandle<'a>,
}

/// Used for `ssh_fxp_read` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Read<'a> {
    /// An opaque handle that is used by the server to identify an open
    /// file or folder.
    pub handle: FileHandle<'a>,
    /// The offset for the read operation
    pub offset: u64,
    /// The number of bytes to be retrieved
    pub len: u32,
}

/// Used for `ssh_fxp_readdir` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ReadDir<'a> {
    /// An opaque handle that is used by the server to identify an open
    /// file or folder.
    pub handle: FileHandle<'a>,
}

/// Used for `ssh_fxp_write` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Write<'a> {
    /// An opaque handle that is used by the server to identify an open
    /// file or folder.
    pub handle: FileHandle<'a>,
    /// The offset for the read operation
    pub offset: u64,

    pub data_len: u32,
    // pub data: BinString<'a>, // TODO: Find an elegant way to process the write process
}

// TODO: This cannot work because we would need a length field
// #[derive(Debug, SSHEncode, SSHDecode)]
// pub struct WriteData<'a> {
//     pub data_slice: &'a [u8],
// }

/// Used for `ssh_fxp_lstat` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8).
/// LSTAT does not follow symbolic links
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct LStat<'a> {
    /// The path of the element which stats are to be retrieved
    pub file_path: TextString<'a>,
}

/// Used for `ssh_fxp_lstat` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8).
/// STAT does follow symbolic links
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Stat<'a> {
    /// The path of the element which stats are to be retrieved
    pub file_path: TextString<'a>,
}

// ============================= Responses =============================

/// Used for `ssh_fxp_realpath` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.11).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct PathInfo<'a> {
    /// The path
    pub path: TextString<'a>,
}

/// Used for `ssh_fxp_status` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Status<'a> {
    /// See [`StatusCode`] for possible codes
    pub code: StatusCode,
    /// An extra message
    pub message: TextString<'a>,
    /// A language tag as defined by [Tags for the Identification of Languages](https://datatracker.ietf.org/doc/html/rfc1766)
    pub lang: TextString<'a>,
}

/// Used for `ssh_fxp_handle` [response](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, SSHEncode, SSHDecode)]
pub struct Handle<'a> {
    /// An opaque handle that is used by the server to identify an open
    /// file or folder.
    pub handle: FileHandle<'a>,
}

/// Used for `ssh_fxp_data` [responses](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7).
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Data<'a> {
    /// Handle for the file referred
    pub handle: FileHandle<'a>,
    /// Offset in the data read
    pub offset: u64,
    /// raw data
    pub data: BinString<'a>,
}

/// This is the encoded length for the [`Data`] Sftp Response.
///
/// This considers the Packet type (1), the request ID (4),  and the data string
/// length (4)
///
/// - It excludes explicitly length field for the SftpPacket
/// - It excludes explicitly length of the data string content
///
/// It is defined a single source of truth for what is the length for the
/// encoded [`SftpPacket::Data`] variant
///
/// See [Responses from the Server to the Client](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
pub(crate) const ENCODED_BASE_DATA_SFTP_PACKET_LENGTH: u32 = 1 + 4 + 4;

/// Struct to hold `SSH_FXP_NAME` response.
/// See [SSH_FXP_NAME in Responses from the Server to the Client](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct NameEntry<'a> {
    /// Is a file name being returned
    pub filename: Filename<'a>,
    /// longname is an undefined text line like "ls -l",
    /// SHOULD NOT be used.
    pub _longname: Filename<'a>,
    /// Attributes for the file entry
    ///
    /// See [File Attributes](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#autoid-5)
    /// for more information.
    pub attrs: Attrs,
}

/// This is the encoded length for the Name Sftp Response.
///
/// This considers the Packet type (1), the Request Id (4) and
/// count of [`NameEntry`] that will follow
///
/// It excludes the length of [`NameEntry`] explicitly
///
/// It is defined a single source of truth for what is the length for the
/// encoded [`SftpPacket::Name`] variant
///
/// See [Responses from the Server to the Client](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
pub(crate) const ENCODED_BASE_NAME_SFTP_PACKET_LENGTH: u32 = 9;

// TODO Will a Vector be an issue for no_std?
// Maybe we should migrate this to heapless::Vec and let the user decide
// the number of elements via features flags?
/// This is the first part of the `SSH_FXP_NAME` response. It includes
/// only the count of [`NameEntry`] items that follow this Name
///
/// After encoding or decoding [`Name`], [`NameEntry`] must be encoded or
/// decoded `count` times
/// A collection of [`NameEntry`] used for [ssh_fxp_name responses](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7).
#[derive(Debug)]
// pub struct Name<'a>(pub Vec<NameEntry<'a>>);
pub struct Name {
    /// Number of [`NameEntry`] items that follow this Name
    pub count: u32,
}

impl<'de> SSHDecode<'de> for Name {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let count = u32::dec(s)? as u32;

        // let mut names = Vec::with_capacity(count);

        // for _ in 0..count {
        //     names.push(NameEntry::dec(s)?);
        // }

        Ok(Name { count })
    }
}

impl SSHEncode for Name {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        self.count.enc(s)
        // (self.0.len() as u32).enc(s)?;

        // for element in self.0.iter() {
        //     element.enc(s)?;
        // }
        // Ok(())
    }
}

// TODO: Is this really necessary?
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ResponseAttributes {
    pub attrs: Attrs,
}

// Requests/Responses data types

#[derive(Debug, SSHEncode, SSHDecode, Clone, Copy, PartialEq, Eq)]
pub struct ReqId(pub u32);

/// For more information see [Responses from the Server to the Client](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-7)
/// TODO: Reference! This is packed as u32 since that is the field data type in specs
#[derive(Debug, FromPrimitive)]
#[repr(u32)]
#[allow(non_camel_case_types, missing_docs)]
pub enum StatusCode {
    // #[sshwire(variant = "ssh_fx_ok")]
    SSH_FX_OK = 0,
    // #[sshwire(variant = "ssh_fx_eof")]
    SSH_FX_EOF = 1,
    // #[sshwire(variant = "ssh_fx_no_such_file")]
    SSH_FX_NO_SUCH_FILE = 2,
    // #[sshwire(variant = "ssh_fx_permission_denied")]
    SSH_FX_PERMISSION_DENIED = 3,
    // #[sshwire(variant = "ssh_fx_failure")]
    SSH_FX_FAILURE = 4,
    // #[sshwire(variant = "ssh_fx_bad_message")]
    SSH_FX_BAD_MESSAGE = 5,
    // #[sshwire(variant = "ssh_fx_no_connection")]
    SSH_FX_NO_CONNECTION = 6,
    // #[sshwire(variant = "ssh_fx_connection_lost")]
    SSH_FX_CONNECTION_LOST = 7,
    // #[sshwire(variant = "ssh_fx_unsupported")]
    SSH_FX_OP_UNSUPPORTED = 8,
    // #[sshwire(unknown)]
    #[num_enum(catch_all)]
    Other(u32),
}

impl<'de> SSHDecode<'de> for StatusCode {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        Ok(StatusCode::from(u32::dec(s)?))
    }
}

// TODO: Implement an automatic from implementation for u32 to Status code
// This is prone to errors if we update StatusCode enum
impl From<&StatusCode> for u32 {
    fn from(value: &StatusCode) -> Self {
        match value {
            StatusCode::SSH_FX_OK => 0,
            StatusCode::SSH_FX_EOF => 1,
            StatusCode::SSH_FX_NO_SUCH_FILE => 2,
            StatusCode::SSH_FX_PERMISSION_DENIED => 3,
            StatusCode::SSH_FX_FAILURE => 4,
            StatusCode::SSH_FX_BAD_MESSAGE => 5,
            StatusCode::SSH_FX_NO_CONNECTION => 6,
            StatusCode::SSH_FX_CONNECTION_LOST => 7,
            StatusCode::SSH_FX_OP_UNSUPPORTED => 8,
            StatusCode::Other(value) => *value,
        }
    }
}
// TODO: Implement an SSHEncode attribute for enums to encode them in a given numeric format
impl SSHEncode for StatusCode {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let numeric_value: u32 = self.into();
        numeric_value.enc(s)
    }
}

// TODO: Implement extensions. Low in priority
/// Provided to provide a mechanism to implement extensions
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ExtPair<'a> {
    pub name: &'a str,
    pub data: BinString<'a>,
}

/// Files attributes to describe Files as SFTP v3 specification
///
/// See [File Attributes](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#autoid-5)
/// for more information.
#[allow(missing_docs)]
#[derive(Debug, Default, PartialEq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub ext_count: Option<u32>,
    // TODO extensions
}

/// For more information see [File Attributes](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#autoid-5)
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum AttrsFlags {
    SSH_FILEXFER_ATTR_SIZE = 0x01,
    SSH_FILEXFER_ATTR_UIDGID = 0x02,
    SSH_FILEXFER_ATTR_PERMISSIONS = 0x04,
    SSH_FILEXFER_ATTR_ACMODTIME = 0x08,
    SSH_FILEXFER_ATTR_EXTENDED = 0x80000000,
}
impl core::ops::AddAssign<AttrsFlags> for u32 {
    fn add_assign(&mut self, other: AttrsFlags) {
        *self |= other as u32;
    }
}

impl core::ops::BitAnd<AttrsFlags> for u32 {
    type Output = u32;

    fn bitand(self, rhs: AttrsFlags) -> Self::Output {
        self & rhs as u32
    }
}

impl Attrs {
    /// Obtains the flags for the values stored in the [`Attrs`] struct.
    ///
    /// See [File Attributes](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#autoid-5)
    /// for more information.
    pub fn flags(&self) -> u32 {
        let mut flags: u32 = 0;
        if self.size.is_some() {
            flags += AttrsFlags::SSH_FILEXFER_ATTR_SIZE
        }
        if self.uid.is_some() || self.gid.is_some() {
            flags += AttrsFlags::SSH_FILEXFER_ATTR_UIDGID
        }
        if self.permissions.is_some() {
            flags += AttrsFlags::SSH_FILEXFER_ATTR_PERMISSIONS
        }
        if self.atime.is_some() || self.mtime.is_some() {
            flags += AttrsFlags::SSH_FILEXFER_ATTR_ACMODTIME
        }
        // TODO Implement extensions
        // if self.ext_count.is_some() {
        //     flags += AttrsFlags::SSH_FILEXFER_ATTR_EXTENDED
        // }

        flags
    }
}

impl SSHEncode for Attrs {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        self.flags().enc(s)?;

        // IMPORTANT: Order matters in the encoding/decoding since it will be interpreted together with the flags
        if let Some(value) = self.size.as_ref() {
            value.enc(s)?
        }
        if let Some(value) = self.uid.as_ref() {
            value.enc(s)?
        }
        if let Some(value) = self.gid.as_ref() {
            value.enc(s)?
        }
        if let Some(value) = self.permissions.as_ref() {
            value.enc(s)?
        }
        if let Some(value) = self.atime.as_ref() {
            value.enc(s)?
        }
        if let Some(value) = self.mtime.as_ref() {
            value.enc(s)?
        }
        // TODO Implement extensions
        // if let Some(value) = self.ext_count.as_ref() { value.enc(s)? }

        Ok(())
    }
}

impl<'de> SSHDecode<'de> for Attrs {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let mut attrs = Attrs::default();
        let flags = u32::dec(s)? as u32;
        if flags & AttrsFlags::SSH_FILEXFER_ATTR_SIZE != 0 {
            attrs.size = Some(u64::dec(s)?);
        }
        if flags & AttrsFlags::SSH_FILEXFER_ATTR_UIDGID != 0 {
            attrs.uid = Some(u32::dec(s)?);
            attrs.gid = Some(u32::dec(s)?);
        }
        if flags & AttrsFlags::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(u32::dec(s)?);
        }
        if flags & AttrsFlags::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            attrs.atime = Some(u32::dec(s)?);
            attrs.mtime = Some(u32::dec(s)?);
        }
        // TODO Implement extensions
        // if flags & AttrsFlags::SSH_FILEXFER_ATTR_EXTENDED != 0{

        Ok(attrs)
    }
}

macro_rules! sftpmessages {
    (
        init: {
            $( ( $init_message_num:tt,
                $init_packet_variant:ident,
                $init_packet_type:ty,
                $init_ssh_fxp_name:literal
                ),
                 )*
        },
        request: {
            $( ( $request_message_num:tt,
                $request_packet_variant:ident,
                $request_packet_type:ty,
                $request_ssh_fxp_name:literal
                ),
                 )*
        },
        response: {
            $( ( $response_message_num:tt,
                $response_packet_variant:ident,
                $response_packet_type:ty,
                $response_ssh_fxp_name:literal
                ),
                 )*
                },
    ) => {
        paste! {
            /// Represent a subset of the SFTP packet types defined by draft-ietf-secsh-filexfer-02
            #[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive, SSHEncode)]
            #[repr(u8)]
            #[allow(non_camel_case_types)]
            pub enum SftpNum {
                $(
                    #[sshwire(variant = $init_ssh_fxp_name)]
                    [<$init_ssh_fxp_name:upper>] = $init_message_num,
                )*

                $(
                    #[sshwire(variant = $request_ssh_fxp_name)]
                    [<$request_ssh_fxp_name:upper>] = $request_message_num,
                )*

                $(
                    #[sshwire(variant = $response_ssh_fxp_name)]
                    [<$response_ssh_fxp_name:upper>] = $response_message_num,
                )*

                #[sshwire(unknown)]
                #[num_enum(catch_all)]
                Other(u8),
            }
        } // paste

        impl<'de> SSHDecode<'de> for SftpNum {
            fn dec<S>(s: &mut S) -> WireResult<Self>
            where
                S: SSHSource<'de>,
            {
                Ok(SftpNum::from(u8::dec(s)?))
            }
        }
        paste!{
        impl From<SftpNum> for u8{
            fn from(sftp_num: SftpNum) -> u8 {
                match sftp_num {
                    $(
                        SftpNum::[<$init_ssh_fxp_name:upper>] => $init_message_num,
                    )*
                    $(
                        SftpNum::[<$request_ssh_fxp_name:upper>] => $request_message_num,
                    )*
                    $(
                        SftpNum::[<$response_ssh_fxp_name:upper>] => $response_message_num,
                    )*

                    SftpNum::Other(number) => number // Other, not in the enum definition

                }
            }

        }

        } //paste

        impl SftpNum {
            fn is_init(&self) -> bool {
                (1..=1).contains(&(u8::from(self.clone())))
            }

            pub(crate) fn is_request(&self) -> bool {
                // TODO SSH_FXP_EXTENDED
                (3..=20).contains(&(u8::from(self.clone())))
            }

            fn is_response(&self) -> bool {
                // TODO SSH_FXP_EXTENDED_REPLY
                (100..=105).contains(&(u8::from(self.clone())))
                ||(2..=2).contains(&(u8::from(self.clone())))
            }
        }


        /// Top level SSH packet enum
        ///
        /// It helps identifying the SFTP Packet type and handling it accordingly
        /// This is done using the SFTP field type
        #[derive(Debug)]
        pub enum SftpPacket<'a> {
                $(
                    $init_packet_variant($init_packet_type),
                )*
                $(
                    $request_packet_variant(ReqId, $request_packet_type),
                )*
                $(
                    $response_packet_variant(ReqId, $response_packet_type),
                )*

        }


        impl SSHEncode for SftpPacket<'_> {
            fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
                let t = u8::from(self.sftp_num());
                t.enc(s)?;
                match self {
                    // eg
                    // SftpPacket::KexInit(p) => {
                    // ...
                    $(
                    SftpPacket::$init_packet_variant(p) => {
                        p.enc(s)?
                    }
                    )*
                    $(
                    SftpPacket::$request_packet_variant(id, p) => {
                        id.enc(s)?;
                        p.enc(s)?
                    }
                    )*
                    $(
                    SftpPacket::$response_packet_variant(id, p) => {
                        id.enc(s)?;
                        p.enc(s)?
                    }
                    )*
                };
                Ok(())
            }
        }

        paste!{


        impl<'a: 'de, 'de> SSHDecode<'de> for SftpPacket<'a>
        where 'de: 'a // This implies that both lifetimes are equal
        {
            fn dec<S>(s: &mut S) -> WireResult<Self>
            where S: SSHSource<'de> {
                let packet_type_number = u8::dec(s)?;

                let packet_type = SftpNum::from(packet_type_number);

                let decoded_packet = match packet_type {
                    $(
                        SftpNum::[<$init_ssh_fxp_name:upper>] => {

                            let inner_type = <$init_packet_type>::dec(s)?;
                            SftpPacket::$init_packet_variant(inner_type)

                        },
                    )*
                    $(
                        SftpNum::[<$request_ssh_fxp_name:upper>] => {
                            let req_id = <ReqId>::dec(s)?;
                            let inner_type = <$request_packet_type>::dec(s)?;
                            SftpPacket::$request_packet_variant(req_id,inner_type)

                        },
                    )*
                    $(
                        SftpNum::[<$response_ssh_fxp_name:upper>] => {
                            let req_id = <ReqId>::dec(s)?;
                            let inner_type = <$response_packet_type>::dec(s)?;
                            SftpPacket::$response_packet_variant(req_id,inner_type)

                        },
                    )*
                    _ => return Err(WireError::UnknownPacket { number: packet_type_number })
                };
                Ok(decoded_packet)
            }
        }
        } // paste

        impl<'a> SftpPacket<'a> {
            /// Maps `SpecificPacketVariant` to `message_num`
            pub fn sftp_num(&self) -> SftpNum {
                match self {
                    // eg
                    // SftpPacket::Open(_) => {
                    // ..
                    $(
                    SftpPacket::$init_packet_variant(_) => {

                        SftpNum::from($init_message_num as u8)
                    }
                    )*
                    $(
                    SftpPacket::$request_packet_variant(_,_) => {

                        SftpNum::from($request_message_num as u8)
                    }
                    )*
                    $(
                    SftpPacket::$response_packet_variant(_,_) => {

                        SftpNum::from($response_message_num as u8)
                    }
                    )*
                }
            }

            // TODO Maybe change WireResult -> SftpResult and SSHSink to SftpSink?
            // This way I have more internal details and can return a Error::bug() if required
            /// Encode a request.
            ///
            /// Used by a SFTP client. Does not include the length field.
            pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {
                if !self.sftp_num().is_request() {
                    return Err(WireError::PacketWrong)
                    // return Err(Error::bug())
                    // I understand that it would be a bad call of encode_response and
                    // therefore a bug, bug Error::bug() is not compatible with WireResult
                }

                // packet type
                self.sftp_num().enc(s)?;
                // request ID
                id.0.enc(s)?;
                // contents
                self.enc(s)
            }

            // TODO Maybe change WireResult -> SftpResult and SSHSource to SftpSource?
            // This way I have more internal details and can return a more appropriate error if required
            /// Decode a response.
            ///
            /// Used by a SFTP client. Does not include the length field.
            pub fn decode_response<'de>(s: &mut SftpSource<'de>) -> WireResult<(ReqId, Self)>
                where
                // S: SftpSource<'de>,
                'a: 'de, // 'a must outlive 'de and 'de must outlive 'a so they have matching lifetimes
                'de: 'a
            {
                let num = SftpNum::from(u8::dec(s)?);

                if !num.is_response() {
                    return Err(WireError::PacketWrong)
                    // return error::SSHProto.fail();
                    // Not an error in the SSHProtocol rather the SFTP Protocol.
                }

                let id = ReqId(u32::dec(s)?);
                Ok((id, Self::dec(s)?))
            }


            /// Decode a request or initialization packets
            ///
            /// Used by a SFTP server. Does not include the length field.
            ///
            /// It will fail if the received packet is a response, no valid or incomplete packet
            pub fn decode_request<'de>(s: &mut SftpSource<'de>) -> WireResult<Self>
                where
                // S: SftpSource<'de>,
                'a: 'de, // 'a must outlive 'de and 'de must outlive 'a so they have matching lifetimes
                'de: 'a
            {
                let packet_length = u32::dec(s)?;
                trace!("Packet field len = {:?}, buffer len = {:?}", packet_length, s.remaining());

                match Self::dec(s) {
                    Ok(sftp_packet)=> {
                        if (!sftp_packet.sftp_num().is_request()
                            && !sftp_packet.sftp_num().is_init())
                        {
                            Err(WireError::PacketWrong)
                        }else{
                            Ok(sftp_packet)

                        }
                    },
                    Err(e) => {
                        match e {
                            WireError::UnknownPacket{..} if !s.packet_fits() => Err(WireError::RanOut),
                            _ => Err(e)
                        }

                    }
                }
            }

            // TODO Maybe change WireResult -> SftpResult and SSHSink to SftpSink?
            // This way I have more internal details and can return a Error::bug() if required
            /// Encode a response.
            ///
            /// Used by a SFTP server. Does not include the length field.
            ///
            /// Fails if the encoded SFTP Packet is not a response
            pub fn encode_response(&self, s: &mut dyn SSHSink) -> WireResult<()> {

                if !self.sftp_num().is_response() {
                    return Err(WireError::PacketWrong)
                    // return Err(Error::bug())
                    // I understand that it would be a bad call of encode_response and
                    // therefore a bug, bug Error::bug() is not compatible with WireResult
                }

                self.enc(s)
            }

        }

        $(
        impl<'a> From<$init_packet_type> for SftpPacket<'a> {
            fn from(s: $init_packet_type) -> SftpPacket<'a> {
                SftpPacket::$init_packet_variant(s) //find me
            }
        }
        )*
        $(
        /// **Warning**: No Sequence Id can be infered from a Packet Type
        impl<'a> From<$request_packet_type> for SftpPacket<'a> {
            fn from(s: $request_packet_type) -> SftpPacket<'a> {
                warn!("Casting from {:?} to SftpPacket cannot set Request Id",$request_ssh_fxp_name);
                SftpPacket::$request_packet_variant(ReqId(0), s)
            }
        }
        )*
        $(
        /// **Warning**: No Sequence Id can be infered from a Packet Type
        impl<'a> From<$response_packet_type> for SftpPacket<'a> {
            fn from(s: $response_packet_type) -> SftpPacket<'a> {
                warn!("Casting from {:?} to SftpPacket cannot set Request Id",$response_ssh_fxp_name);
                SftpPacket::$response_packet_variant(ReqId(0), s)
            }
        }
        )*

    }; // main macro

} // sftpmessages macro

sftpmessages! [

        init:{
            (1, Init, InitVersionClient, "ssh_fxp_init"),
            (2, Version, InitVersionLowest, "ssh_fxp_version"),
        },

        request: {
            (3, Open, Open<'a>, "ssh_fxp_open"),
            (4, Close, Close<'a>, "ssh_fxp_close"),
            (5, Read, Read<'a>, "ssh_fxp_read"),
            (6, Write, Write<'a>, "ssh_fxp_write"),
            (7, LStat, LStat<'a>, "ssh_fxp_lstat"),
            (11, OpenDir, OpenDir<'a>, "ssh_fxp_opendir"),
            (12, ReadDir, ReadDir<'a>, "ssh_fxp_readdir"),
            (16, PathInfo, PathInfo<'a>, "ssh_fxp_realpath"),
            (17, Stat, Stat<'a>, "ssh_fxp_stat"),
        },

        response: {
            (101, Status, Status<'a>, "ssh_fxp_status"),
            (102, Handle, Handle<'a>, "ssh_fxp_handle"),
            (103, Data, Data<'a>, "ssh_fxp_data"),
            (104, Name, Name, "ssh_fxp_name"),
            (105, Attrs, Attrs, "ssh_fxp_attrs"),
        },
];

#[cfg(test)]
mod proto_tests {
    use super::*;
    use crate::server::SftpSink;

    // TODO: Create tests for every SftpPacket. A good starting point is a
    // roadtrip test

    #[cfg(test)]
    extern crate std;
    #[cfg(test)]
    use std::println;

    #[test]
    fn test_status_encoding() {
        let mut buf = [0u8; 256];
        let mut sink = SftpSink::new(&mut buf);
        let status_packet = SftpPacket::Status(
            ReqId(16),
            Status {
                code: StatusCode::SSH_FX_EOF,
                message: "A".into(),
                lang: "en-US".into(),
            },
        );

        let expected_status_packet_slice: [u8; 27] = [
            0, 0, 0, 23,  //                            Packet len
            101, //                                     Packet type
            0, 0, 0, 16, //                             ReqId
            0, 0, 0, 1, //                              Status code: SSH_FX_EOF
            0, 0, 0, 1,  //                             string message length
            65, //                                      string message content
            0, 0, 0, 5, //                              string lang length
            101, 110, 45, 85, 83, //                    string lang content
        ];

        let _ = status_packet.encode_response(&mut sink);
        sink.finalize();

        assert_eq!(&expected_status_packet_slice, sink.used_slice());
    }

    #[test]
    fn test_attributes_roundtrip() {
        let mut buff = [0u8; MAX_NAME_ENTRY_SIZE];
        let attr_read_only = Attrs {
            size: Some(1),
            uid: Some(2),
            gid: Some(3),
            permissions: Some(222),
            atime: Some(4),
            mtime: Some(5),
            ext_count: None,
            // ext_count: Some(10), // TODO: This does not get deserialized
        };

        let mut sink = SftpSink::new(&mut buff);
        attr_read_only.enc(&mut sink).unwrap();
        println!(
            "attr_read_only encoded_len = {:?}, encoded = {:?}",
            sink.payload_len(),
            sink.payload_slice()
        );
        let mut source = SftpSource::new(sink.payload_slice());
        println!("source = {:?}", source);

        let a_r = Attrs::dec(&mut source);
        match a_r {
            Ok(attrs) => {
                println!("source = {:?}", attrs);
                assert_eq!(attr_read_only, attrs);
            }
            Err(e) => panic!("The attributes could not be decoded: {:?}", e),
        }
    }

    #[test]
    fn test_packet_open_reading() {
        let buff_open_read = [
            0u8, 0, 0,
            58, //                                                      Len
            3,  //                                                       SftpPacket
            0, 0, 0,
            4, //                                                      ReqId
            0, 0, 0,
            41, //                                                     Text String len
            46, 47, 100, 101, 109, 111, 47, 115, 102,
            116, //                   file Path
            112, 47, 115, 116, 100, 47, 116, 101, 115, 116, 105, 110, 103, 47, 111,
            117, 116, 47, 46, 47, 53, 49, 50, 66, 95, 114, 97, 110, 100, 111,
            109, //                                          and 41
            0, 0, 0,
            1, //                                                      PFlags: 1u32 == SSSH_FXF_READ
            0, 0, 0,
            0, //                                                      Attrib flags == 0 No flags, no attributes
        ];

        let mut source = SftpSource::new(&buff_open_read);
        println!("source = {:?}", source);

        match SftpPacket::decode_request(&mut source) {
            Ok(SftpPacket::Open(req_id, open)) => {
                assert_eq!(PFlags::SSH_FXF_READ, open.pflags);
            }
            Ok(other) => panic!("Expected Open packet, got: {:?}", other),
            Err(e) => panic!("Failed to decode packet: {:?}", e),
        }
    }
}
