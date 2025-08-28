use num_enum::FromPrimitive;
use paste::paste;
use sunset::sshwire::{
    BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
    WireResult,
};

use sunset_sshwire_derive::{SSHDecode, SSHEncode};

// TODO is utf8 enough, or does this need to be an opaque binstring?
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Filename<'a>(TextString<'a>);

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct FileHandle<'a>(pub BinString<'a>);

/// The reference implementation we are working on is 3, this is, https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
const SFTP_VERSION: u32 = 3;

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

macro_rules! sftpmessages {
    (
        $( ( $message_num:tt,
            $SpecificPacketVariant:ident,
            $SpecificPacketType:ty,
            $SSH_FXP_NAME:ident
            ),
             )*
    ) => {
        paste! {
            #[derive(Debug, Clone, FromPrimitive, SSHEncode)]
            #[repr(u8)]
            #[allow(non_camel_case_types)]
            pub enum SftpNum {
                    // SSH_FXP_OPEN = 3,
                    $(
                    #[sshwire(variant = $SSH_FXP_NAME:lower)]
                    $SSH_FXP_NAME = $message_num,
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

        impl From<SftpNum> for u8{
            fn from(sftp_num: SftpNum) -> u8 {
                match sftp_num {
                                $(
                     SftpNum::$SSH_FXP_NAME => $message_num, // TODO: Fix this
                    )*
                    _ => 0 // Other, not in the enum definition

                }
            }

        }

        impl SftpNum {
            fn is_request(&self) -> bool {
                // TODO SSH_FXP_EXTENDED
                (2..=99).contains(&(u8::from(self.clone())))
            }

            fn is_response(&self) -> bool {
                // TODO SSH_FXP_EXTENDED_REPLY
                (100..=199).contains(&(u8::from(self.clone())))
            }
        }

        /// Top level SSH packet enum
        ///
        /// It helps identifying the SFTP Packet type and handling it accordingly
        /// This is done using the SFTP field type
        #[derive(Debug)]
        pub enum SftpPacket<'a> {
            // eg Open(Open<'a>),
            $(
            $SpecificPacketVariant($SpecificPacketType),
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
                    SftpPacket::$SpecificPacketVariant(p) => {
                        p.enc(s)?
                    }
                    )*
                };
                Ok(())
            }
        }


        impl<'a: 'de, 'de> SSHDecode<'de> for SftpPacket<'a>
        where 'de: 'a // This implies that both lifetimes are equal
        {
            fn dec<S>(s: &mut S) -> WireResult<Self>
            where S: SSHSource<'de> {
                let packet_type_number = u8::dec(s)?;

                let packet_type = SftpNum::from(packet_type_number);

                let decoded_packet = match packet_type {
                    $(
                        SftpNum::$SSH_FXP_NAME => {
                            let inner_type = <$SpecificPacketType>::dec(s)?;
                            SftpPacket::$SpecificPacketVariant(inner_type)
                        },
                    )*
                    _ => return Err(WireError::UnknownPacket { number: packet_type_number })
                };
                Ok(decoded_packet)
            }
        }

        impl<'a> SftpPacket<'a> {
            /// Maps `SpecificPacketVariant` to `message_num`
            pub fn sftp_num(&self) -> SftpNum {
                match self {
                    // eg
                    // SftpPacket::Open(_) => {
                    // ..
                    $(
                    SftpPacket::$SpecificPacketVariant(_) => {

                        SftpNum::from($message_num as u8)
                    }
                    )*
                }
            }

            /// Encode a request.
            ///
            /// Used by a SFTP client. Does not include the length field.
            pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {
                // TODO: handle the Error conversion
                if !self.sftp_num().is_request() {
                    return Err(WireError::PacketWrong)
                    // return Err(Error::bug())
                    // TODO: I understand that it would be a bad call of encode_response and
                    // therefore a bug, bug Error::bug() is not compatible with WireResult
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
            pub fn decode_response<'de, S>(s: &mut S) -> WireResult<(ReqId, Self)>
                where
                S: SSHSource<'de>,
                'a: 'de, // 'a must outlive 'de and 'de must outlive 'a so they have matching lifetimes
                'de: 'a
            {
                let num = SftpNum::from(u8::dec(s)?);

                if !num.is_response() {
                    return Err(WireError::PacketWrong)
                    // return error::SSHProto.fail();
                    // TODO: Not an error in the SSHProtocol rather the SFTP.
                    // Maybe is time to define an SftpError
                }

                let id = ReqId(u32::dec(s)?);
                Ok((id, Self::dec(s)?))
            }

            /// Decode a request.
            ///
            /// Used by a SFTP server. Does not include the length field.
            pub fn decode_request<'de, S>(s: &mut S) -> WireResult<(ReqId, Self)>
                where
                S: SSHSource<'de>,
                'a: 'de, // 'a must outlive 'de and 'de must outlive 'a so they have matching lifetimes
                'de: 'a
            {
                let num = SftpNum::from(u8::dec(s)?);

                if !num.is_request() {
                    return Err(WireError::PacketWrong)
                    // return error::SSHProto.fail();
                    // TODO: Not an error in the SSHProtocol rather the SFTP.
                    // Maybe is time to define an SftpError
                }

                let id = ReqId(u32::dec(s)?);
                Ok((id, Self::dec(s)?))
            }

            /// Encode a response.
            ///
            /// Used by a SFTP server. Does not include the length field.
            pub fn encode_response(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {

                if !self.sftp_num().is_response() {
                    return Err(WireError::PacketWrong)
                    // return Err(Error::bug())
                    // TODO: I understand that it would be a bad call of encode_response and
                    // therefore a bug, bug Error::bug() is not compatible with WireResult
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
        SftpPacket::$SpecificPacketVariant(s) //find me
    }
}
)*

} } // macro

sftpmessages![

// Message number ranges are also used by Sftpnum::is_request and is_response.

(1, Init, InitVersionClient, SSH_FXP_INIT),
    (2, Version, InitVersionLowest, SSH_FXP_VERSION),
    // Requests
    (3, Open, Open<'a>, SSH_FXP_OPEN),
    (4, Close, Close<'a>, SSH_FXP_CLOSE),
    (5, Read, Read<'a>, SSH_FXP_READ),
    (6, Write, Write<'a>, SSH_FXP_WRITE),

    // Responses
    (101, Status, Status<'a>, SSH_FXP_STATUS),
    (102, Handle, Handle<'a>, SSH_FXP_HANDLE),
    (103, Data, Data<'a>, SSH_FXP_DATA),
    (104, Name, Name<'a>, SSH_FXP_NAME),
];
