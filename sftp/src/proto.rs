use sunset::sshwire::{
    BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
    WireResult,
};
use sunset_sshwire_derive::{SSHDecode, SSHEncode};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use num_enum::FromPrimitive;
use paste::paste;
// TODO is utf8 enough, or does this need to be an opaque binstring?
#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Filename<'a>(TextString<'a>);

impl<'a> From<&'a str> for Filename<'a> {
    fn from(s: &'a str) -> Self {
        Filename(TextString(s.as_bytes()))
    }
}

impl<'a> Filename<'a> {
    pub fn as_str(&self) -> Result<&'a str, WireError> {
        core::str::from_utf8(self.0.0).map_err(|_| WireError::BadString)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SSHEncode, SSHDecode)]
pub struct FileHandle<'a>(pub BinString<'a>);

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
pub struct PathInfo<'a> {
    pub path: TextString<'a>,
}

#[derive(Debug, SSHEncode, SSHDecode)]
pub struct Status<'a> {
    pub code: StatusCode,
    pub message: TextString<'a>,
    pub lang: TextString<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, SSHEncode, SSHDecode)]
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
pub struct Name<'a>(pub Vec<NameEntry<'a>>);

impl<'a: 'de, 'de> SSHDecode<'de> for Name<'a>
where
    'de: 'a,
{
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

impl<'a> SSHEncode for Name<'a> {
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

/// Files attributes to describe Files as SFTP v3 specification
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
            #[derive(Debug, Clone, FromPrimitive, SSHEncode)]
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

            fn is_request(&self) -> bool {
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

            /// Encode a request.
            ///
            /// Used by a SFTP client. Does not include the length field.
            pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {
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


            /// Decode a request. Includes Initialization packets
            ///
            /// Used by a SFTP server. Does not include the length field.
            ///
            /// It will fail if the received packet is a response
            pub fn decode_request<'de, S>(s: &mut S) -> WireResult<(Self)>
                where
                S: SSHSource<'de>,
                'a: 'de, // 'a must outlive 'de and 'de must outlive 'a so they have matching lifetimes
                'de: 'a
            {

                let sftp_packet = Self::dec(s)? ;

                if (!sftp_packet.sftp_num().is_request()
                    && !sftp_packet.sftp_num().is_init())
                {
                    return Err(WireError::PacketWrong)
                }

                Ok(sftp_packet)
            }

            /// Encode a response.
            ///
            /// Used by a SFTP server. Does not include the length field.
            ///
            /// Fails if the encoded SFTP Packet is not a response
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
            (16, PathInfo, PathInfo<'a>, "ssh_fxp_realpath"),
        },

        response: {
            (101, Status, Status<'a>, "ssh_fxp_status"),
            (102, Handle, Handle<'a>, "ssh_fxp_handle"),
            (103, Data, Data<'a>, "ssh_fxp_data"),
            (104, Name, Name<'a>, "ssh_fxp_name"),

        },
];
