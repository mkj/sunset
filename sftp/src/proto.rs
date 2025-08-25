use num_enum::{FromPrimitive, TryFromPrimitive};
use sunset::error;
use sunset::error::Error as SunsetError;
use sunset::packets::{MessageNumber, Packet, Unknown};
use sunset::sshwire::{
    BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
    WireResult,
};

use sunset_sshwire_derive::{SSHDecode, SSHEncode};

// TODO is utf8 enough, or does this need to be an opaque binstring?
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Filename<'a>(TextString<'a>);

#[derive(Debug, SSHEncode, SSHDecode)]
struct FileHandle<'a>(pub BinString<'a>);

/// The reference implementation we are working on is 3, this is, https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
const SFTP_VERSION: u32 = 3;
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct InitVersion {
    // No ReqId for SSH_FXP_INIT
    pub version: u32,
    // TODO variable number of ExtPair
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Open<'a> {
    pub filename: Filename<'a>,
    pub pflags: u32,
    pub attrs: Attrs,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Close<'a> {
    pub handle: FileHandle<'a>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Read<'a> {
    pub handle: FileHandle<'a>,
    pub offset: u64,
    pub len: u32,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Write<'a> {
    pub handle: FileHandle<'a>,
    pub offset: u64,
    pub data: BinString<'a>,
}

// Responses

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Status<'a> {
    pub code: StatusCode,
    pub message: TextString<'a>,
    pub lang: TextString<'a>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Handle<'a> {
    pub handle: FileHandle<'a>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Data<'a> {
    pub handle: FileHandle<'a>,
    pub offset: u64,
    pub data: BinString<'a>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct NameEntry<'a> {
    pub filename: Filename<'a>,
    /// longname is an undefined text line like "ls -l",
    /// SHOULD NOT be used.
    pub _longname: Filename<'a>,
    pub attrs: Attrs,
}

#[derive(Debug)]
pub struct Name<'de>(pub Vec<NameEntry<'de>>);

impl<'de> SSHDecode<'de> for Name<'de> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where
        S: SSHSource<'de>,
    {
        let count = u32::dec(s)? as usize;

        let mut names = Vec::with_capacity(count);

        for _ in 0..count {
            names.push(NameEntry::dec(s)?);
        }

        Ok(Name(names))
    }
}

impl SSHEncode for Name<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        (self.0.len() as u32).enc(s)?;

        for element in self.0.iter() {
            element.enc(s)?;
        }
        Ok(())
    }
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ResponseAttributes {
    pub attrs: Attrs,
}

// Requests/Responses data types

#[derive(Debug, SSHEncode, SSHDecode, Clone, Copy)]
pub struct ReqId(pub u32);

#[derive(Debug, FromPrimitive, SSHEncode)]
#[repr(u32)]
#[allow(non_camel_case_types)]
pub enum StatusCode {
    #[sshwire(variant = "ssh_fx_ok")]
    SSH_FX_OK = 0,
    #[sshwire(variant = "ssh_fx_eof")]
    SSH_FX_EOF = 1,
    #[sshwire(variant = "ssh_fx_no_such_file")]
    SSH_FX_NO_SUCH_FILE = 2,
    #[sshwire(variant = "ssh_fx_permission_denied")]
    SSH_FX_PERMISSION_DENIED = 3,
    #[sshwire(variant = "ssh_fx_failure")]
    SSH_FX_FAILURE = 4,
    #[sshwire(variant = "ssh_fx_bad_message")]
    SSH_FX_BAD_MESSAGE = 5,
    #[sshwire(variant = "ssh_fx_no_connection")]
    SSH_FX_NO_CONNECTION = 6,
    #[sshwire(variant = "ssh_fx_connection_lost")]
    SSH_FX_CONNECTION_LOST = 7,
    #[sshwire(variant = "ssh_fx_unsupported")]
    SSH_FX_OP_UNSUPPORTED = 8,
    #[sshwire(unknown)]
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

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ExtPair<'a> {
    pub name: &'a str,
    pub data: BinString<'a>,
}

#[derive(Debug, Default)]
pub struct Attrs {
    // flags: u32, defines used attributes
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
    pub ext_count: Option<u32>,
    // TODO extensions
}

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
        // TODO: Implement extensions
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
        // TODO: Implement extensions
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
        // TODO: Implement extensions
        // if flags & AttrsFlags::SSH_FILEXFER_ATTR_EXTENDED != 0{

        //     todo!("Not implemented");
        // }

        Ok(attrs)
    }
}

#[derive(Debug)]
pub enum Error {
    UnknownPacket { number: u8 },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

// impl From<Error> for SunsetError {
//     fn from(error: Error) -> SunsetError {
//         SunsetError::Custom {
//             msg: match error {
//                 Error::UnknownPacket { number } => {
//                     format_args!("Unknown SFTP packet: {}", number)
//                 }
//             },
//         }
//     }
// }

macro_rules! sftpmessages {
    (
        $( ( $message_num:literal,
            $SpecificPacketVariant:ident,
            $SpecificPacketType:ty,
            $SSH_FXP_NAME:ident
            ),
             )*
    ) => {
        #[derive(Debug, Clone)]
        #[repr(u8)]
        #[allow(non_camel_case_types)]
        pub enum SftpNum {
            // variants are eg
            // SSH_FXP_OPEN = 3,
            $(
            $SSH_FXP_NAME = $message_num,
            )*
        }

        impl SftpNum {
            fn is_request(&self) -> bool {
                // TODO SSH_FXP_EXTENDED
                (2..=99).contains(&(self.clone() as u8))
            }

            fn is_response(&self) -> bool {
                // TODO SSH_FXP_EXTENDED_REPLY
                (100..=199).contains(&(self.clone() as u8))
            }
        }

        impl TryFrom<u8> for SftpNum {
            type Error = Error;
            fn try_from(v: u8) -> Result<Self> {
                match v {
                    // eg
                    // 3 => Ok(SftpNum::SSH_FXP_OPEN)
                    $(
                    $message_num => Ok(SftpNum::$SSH_FXP_NAME),
                    )*
                    _ => {
                        Err(Error::UnknownPacket { number: v })
                    }
                }
            }
        }

        // /// Top level SSH packet enum
        // #[derive(Debug)]
        // pub enum SftpPacket<'a> {
        //     // eg Open(Open<'a>),
        //     $(
        //     $SpecificPacketVariant($SpecificPacketType),
        //     )*
        // }

// impl SSHEncode for SftpPacket<'_> {
//     fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
//         let t = self.message_num() as u8;
//         t.enc(s)?;
//         match self {
//             // eg
//             // Packet::KexInit(p) => {
//             // ...
//             $(
//             Packet::$SpecificPacketVariant(p) => {
//                 p.enc(s)?
//             }
//             )*
//         };
//         Ok(())
//     }
// }

// impl<'de: 'a, 'a> SSHDecode<'de> for SftpPacket<'a> {
//     fn dec<S>(s: &mut S) -> WireResult<Self>
//     where S: SSHSource<'de> {
//         let msg_num = u8::dec(s)?;
//         let ty = MessageNumber::try_from(msg_num);
//         let ty = match ty {
//             Ok(t) => t,
//             Err(_) => return Err(WireError::UnknownPacket { number: msg_num })
//         };

//         // Decode based on the message number
//         let p = match ty {
//             // eg
//             // MessageNumber::SSH_MSG_KEXINIT => Packet::KexInit(
//             // ...
//             $(
//             MessageNumber::$SSH_FXP_NAME => Packet::$SpecificPacketVariant(SSHDecode::dec(s)?),
//             )*
//         };
//         Ok(p)
//     }
// }



// impl<'a> SftpPacket<'a> {
//     pub fn sftp_num(&self) -> SftpNum {
//         match self {
//             // eg
//             // SftpPacket::Open(_) => {
//             // ..
//             $(
//             SftpPacket::$SpecificPacketVariant(_) => {
//                 MessageNumber::$SSH_FXP_NAME
//             }
//             )*
//         }
//     }

//     /// Encode a request.
//     ///
//     /// Used by a SFTP client. Does not include the length field.
//     pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> Result<()> {
//         if !self.sftp_num().is_request() {
//             return Err(Error::bug())
//         }

//         // packet type
//         self.sftp_num().enc(s)?;
//         // request ID
//         id.0.enc(s)?;
//         // contents
//         self.enc(s)
//     }

//     /// Decode a response.
//     ///
//     /// Used by a SFTP client. Does not include the length field.
//     pub fn decode_response(s: &mut dyn SSHSource) -> WireResult<(ReqId, Self)> {
//         let num = SftpNum::try_from(u8::dec(s)?)?;

//         if !num.is_response() {
//             return error::SSHProto.fail();
//         }

//         let id = ReqId(u32::dec(s)?);
//         Ok((id, Self::dec(s)))
//     }

//     /// Decode a request.
//     ///
//     /// Used by a SFTP server. Does not include the length field.
//     pub fn decode_request(s: &mut dyn SSHSource) -> WireResult<(ReqId, Self)> {
//         let num = SftpNum::try_from(u8::dec(s)?)?;

//         if !num.is_request() {
//             return error::SSHProto.fail();
//         }

//         let id = ReqId(u32::dec(s)?);
//         Ok((id, Self::dec(s)))
//     }

//     /// Encode a response.
//     ///
//     /// Used by a SFTP server. Does not include the length field.
//     pub fn encode_response(&self, id: ReqId, s: &mut dyn SSHSink) -> Result<()> {
//         if !self.sftp_num().is_response() {
//             return Err(Error::bug())
//         }

//         // packet type
//         self.sftp_num().enc(s)?;
//         // request ID
//         id.0.enc(s)?;
//         // contents
//         self.enc(s)
//     }
// }

// $(
// impl<'a> From<$SpecificPacketType> for SftpPacket<'a> {
//     fn from(s: $SpecificPacketType) -> SftpPacket<'a> {
//         SftpPacket::$SpecificPacketVariant(s)
//     }
// }
// )*

} } // macro

sftpmessages![

// Message number ranges are also used by Sftpnum::is_request and is_response.

(1, Init, InitVersion, SSH_FXP_INIT),
(2, Version, InitVersion, SSH_FXP_VERSION),

// Requests
(3, Open, Open<'a>, SSH_FXP_OPEN),
(4, Close, Close<'a>, SSH_FXP_CLOSE),
(5, Read, Read<'a>, SSH_FXP_READ),

// Responses
(101, Status, Status<'a>, SSH_FXP_STATUS),
(102, Handle, Handle<'a>, SSH_FXP_HANDLE),
(103, Data, Data<'a>, SSH_FXP_DATA),
(104, Name, Name<'a>, SSH_FXP_NAME),

];
