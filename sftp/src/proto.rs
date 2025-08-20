use core::marker::PhantomData;

use sunset::packets::{MessageNumber, Packet};
use sunset::sshwire::{
    BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
    WireResult,
};
use sunset::{Result, error};

use sunset_sshwire_derive::{SSHDecode, SSHEncode};

// TODO is utf8 enough, or does this need to be an opaque binstring?
#[derive(Debug)]
pub struct Filename<'a>(TextString<'a>);

#[derive(Debug, SSHEncode, SSHDecode)]
struct FileHandle<'a>(pub BinString<'a>);

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
pub struct Name<'a> {
    pub count: u32,
    // TODO repeat NameEntry
    _pd: &'a PhantomData<()>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct NameEntry<'a> {
    pub filename: Filename<'a>,
    /// longname is an undefined text line like "ls -l",
    /// SHOULD NOT be used.
    pub _longname: Filename<'a>,
    pub attrs: Attrs,
}

#[derive(Debug, SSHEncode, SSHDecode, Clone, Copy)]
pub struct ReqId(pub u32);

#[derive(Debug, SSHEncode, SSHDecode)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum StatusCode {
    #[sshwire(variant = "ssh_fx_ok")]
    SSH_FX_OK = 0,
    #[sshwire(variant = "ssh_fx_eof")]
    SSH_FX_EOF = 1,
    #[sshwire(variant = "ssh_fx_no_such_file")]
    SSH_FX_NO_SUCH_FILE = 2,
    #[sshwire(variant = "ssh_fx_premission_denied")]
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
    #[sshwire(variant = "ssh_fx_unsupported")]
    Other(u8),
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct ExtPair<'a> {
    pub name: &'a str,
    pub data: BinString<'a>,
}

#[derive(Debug)]
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

enum Error {
    UnknownPacket { number: u8 },
}

macro_rules! sftpmessages {
    (
        $( ( $message_num:literal,
            $SpecificPacketVariant:ident,
            $SpecificPacketType:ty,
            $SSH_FXP_NAME:ident
            ),
             )*
    ) => {


#[derive(Debug)]
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
        (2..=99).contains(&(*self as u8))
    }

    fn is_response(&self) -> bool {
        // TODO SSH_FXP_EXTENDED_REPLY
        (100..=199).contains(&(*self as u8))
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

impl SSHEncode for SftpPacket<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        let t = self.message_num() as u8;
        t.enc(s)?;
        match self {
            // eg
            // Packet::KexInit(p) => {
            // ...
            $(
            Packet::$SpecificPacketVariant(p) => {
                p.enc(s)?
            }
            )*
        };
        Ok(())
    }
}

impl<'de: 'a, 'a> SSHDecode<'de> for SftpPacket<'a> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        let msg_num = u8::dec(s)?;
        let ty = MessageNumber::try_from(msg_num);
        let ty = match ty {
            Ok(t) => t,
            Err(_) => return Err(WireError::UnknownPacket { number: msg_num })
        };

        // Decode based on the message number
        let p = match ty {
            // eg
            // MessageNumber::SSH_MSG_KEXINIT => Packet::KexInit(
            // ...
            $(
            MessageNumber::$SSH_FXP_NAME => Packet::$SpecificPacketVariant(SSHDecode::dec(s)?),
            )*
        };
        Ok(p)
    }
}

/// Top level SSH packet enum
#[derive(Debug)]
pub enum SftpPacket<'a> {
    // eg Open(Open<'a>),
    $(
    $SpecificPacketVariant($SpecificPacketType),
    )*
}

impl<'a> SftpPacket<'a> {
    pub fn sftp_num(&self) -> SftpNum {
        match self {
            // eg
            // SftpPacket::Open(_) => {
            // ..
            $(
            SftpPacket::$SpecificPacketVariant(_) => {
                MessageNumber::$SSH_FXP_NAME
            }
            )*
        }
    }

    /// Encode a request.
    ///
    /// Used by a SFTP client. Does not include the length field.
    pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> Result<()> {
        if !self.sftp_num().is_request() {
            return Err(Error::bug())
        }

        // packet type
        self.sftp_num().enc(s)?;
        // request ID
        id.0.enc(s)?;
        // contents
        self.enc(s)
    }

    /// Decode a response.
    ///
    /// Used by a SFTP client. Does not include the length field.
    pub fn decode_response(s: &mut dyn SSHSource) -> WireResult<(ReqId, Self)> {
        let num = SftpNum::try_from(u8::dec(s)?)?;

        if !num.is_response() {
            return error::SSHProto.fail();
        }

        let id = ReqId(u32::dec(s)?);
        Ok((id, Self::dec(s)))
    }

    /// Decode a request.
    ///
    /// Used by a SFTP server. Does not include the length field.
    pub fn decode_request(s: &mut dyn SSHSource) -> WireResult<(ReqId, Self)> {
        let num = SftpNum::try_from(u8::dec(s)?)?;

        if !num.is_request() {
            return error::SSHProto.fail();
        }

        let id = ReqId(u32::dec(s)?);
        Ok((id, Self::dec(s)))
    }

    /// Encode a response.
    ///
    /// Used by a SFTP server. Does not include the length field.
    pub fn encode_response(&self, id: ReqId, s: &mut dyn SSHSink) -> Result<()> {
        if !self.sftp_num().is_response() {
            return Err(Error::bug())
        }

        // packet type
        self.sftp_num().enc(s)?;
        // request ID
        id.0.enc(s)?;
        // contents
        self.enc(s)
    }
}

$(
impl<'a> From<$SpecificPacketType> for SftpPacket<'a> {
    fn from(s: $SpecificPacketType) -> SftpPacket<'a> {
        SftpPacket::$SpecificPacketVariant(s)
    }
}
)*

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
