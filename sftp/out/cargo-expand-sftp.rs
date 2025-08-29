#![feature(prelude_import)]
#[prelude_import]
use std::prelude::rust_2024::*;
#[macro_use]
extern crate std;
mod proto {
    use num_enum::FromPrimitive;
    use paste::paste;
    use sunset::sshwire::{
        BinString, SSHDecode, SSHEncode, SSHSink, SSHSource, TextString, WireError,
        WireResult,
    };
    use sunset_sshwire_derive::{SSHDecode, SSHEncode};
    pub struct Filename<'a>(TextString<'a>);
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Filename<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(f, "Filename", &&self.0)
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Filename<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.0, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Filename<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            Ok(Self(::sunset::sshwire::SSHDecode::dec(s)?))
        }
    }
    pub struct FileHandle<'a>(pub BinString<'a>);
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for FileHandle<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(f, "FileHandle", &&self.0)
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for FileHandle<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.0, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for FileHandle<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            Ok(Self(::sunset::sshwire::SSHDecode::dec(s)?))
        }
    }
    /// The reference implementation we are working on is 3, this is, https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
    const SFTP_VERSION: u32 = 3;
    /// The SFTP version of the client
    pub struct InitVersionClient {
        pub version: u32,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for InitVersionClient {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "InitVersionClient",
                "version",
                &&self.version,
            )
        }
    }
    impl ::sunset::sshwire::SSHEncode for InitVersionClient {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.version, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for InitVersionClient {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_version = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { version: field_version })
        }
    }
    /// The lowers SFTP version from the client and the server
    pub struct InitVersionLowest {
        pub version: u32,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for InitVersionLowest {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "InitVersionLowest",
                "version",
                &&self.version,
            )
        }
    }
    impl ::sunset::sshwire::SSHEncode for InitVersionLowest {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.version, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for InitVersionLowest {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_version = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { version: field_version })
        }
    }
    pub struct Open<'a> {
        pub filename: Filename<'a>,
        pub pflags: u32,
        pub attrs: Attrs,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Open<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "Open",
                "filename",
                &self.filename,
                "pflags",
                &self.pflags,
                "attrs",
                &&self.attrs,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Open<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.filename, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.pflags, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.attrs, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Open<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_filename = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_pflags = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_attrs = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                filename: field_filename,
                pflags: field_pflags,
                attrs: field_attrs,
            })
        }
    }
    pub struct Close<'a> {
        pub handle: FileHandle<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Close<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "Close",
                "handle",
                &&self.handle,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Close<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.handle, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Close<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_handle = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { handle: field_handle })
        }
    }
    pub struct Read<'a> {
        pub handle: FileHandle<'a>,
        pub offset: u64,
        pub len: u32,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Read<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "Read",
                "handle",
                &self.handle,
                "offset",
                &self.offset,
                "len",
                &&self.len,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Read<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.handle, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.offset, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.len, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Read<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_handle = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_offset = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_len = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                handle: field_handle,
                offset: field_offset,
                len: field_len,
            })
        }
    }
    pub struct Write<'a> {
        pub handle: FileHandle<'a>,
        pub offset: u64,
        pub data: BinString<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Write<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "Write",
                "handle",
                &self.handle,
                "offset",
                &self.offset,
                "data",
                &&self.data,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Write<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.handle, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.offset, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.data, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Write<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_handle = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_offset = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_data = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                handle: field_handle,
                offset: field_offset,
                data: field_data,
            })
        }
    }
    pub struct Status<'a> {
        pub code: StatusCode,
        pub message: TextString<'a>,
        pub lang: TextString<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Status<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "Status",
                "code",
                &self.code,
                "message",
                &self.message,
                "lang",
                &&self.lang,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Status<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.code, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.message, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.lang, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Status<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_code = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_message = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_lang = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                code: field_code,
                message: field_message,
                lang: field_lang,
            })
        }
    }
    pub struct Handle<'a> {
        pub handle: FileHandle<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Handle<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "Handle",
                "handle",
                &&self.handle,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Handle<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.handle, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Handle<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_handle = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { handle: field_handle })
        }
    }
    pub struct Data<'a> {
        pub handle: FileHandle<'a>,
        pub offset: u64,
        pub data: BinString<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Data<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "Data",
                "handle",
                &self.handle,
                "offset",
                &self.offset,
                "data",
                &&self.data,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for Data<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.handle, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.offset, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.data, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for Data<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_handle = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_offset = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_data = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                handle: field_handle,
                offset: field_offset,
                data: field_data,
            })
        }
    }
    pub struct NameEntry<'a> {
        pub filename: Filename<'a>,
        /// longname is an undefined text line like "ls -l",
        /// SHOULD NOT be used.
        pub _longname: Filename<'a>,
        pub attrs: Attrs,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for NameEntry<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field3_finish(
                f,
                "NameEntry",
                "filename",
                &self.filename,
                "_longname",
                &self._longname,
                "attrs",
                &&self.attrs,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for NameEntry<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.filename, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self._longname, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.attrs, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for NameEntry<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_filename = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field__longname = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_attrs = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                filename: field_filename,
                _longname: field__longname,
                attrs: field_attrs,
            })
        }
    }
    pub struct Name<'a>(pub Vec<NameEntry<'a>>);
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for Name<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(f, "Name", &&self.0)
        }
    }
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
    pub struct ResponseAttributes {
        pub attrs: Attrs,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ResponseAttributes {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "ResponseAttributes",
                "attrs",
                &&self.attrs,
            )
        }
    }
    impl ::sunset::sshwire::SSHEncode for ResponseAttributes {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.attrs, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for ResponseAttributes {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_attrs = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { attrs: field_attrs })
        }
    }
    pub struct ReqId(pub u32);
    #[automatically_derived]
    impl ::core::fmt::Debug for ReqId {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(f, "ReqId", &&self.0)
        }
    }
    impl ::sunset::sshwire::SSHEncode for ReqId {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.0, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for ReqId {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            Ok(Self(::sunset::sshwire::SSHDecode::dec(s)?))
        }
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ReqId {
        #[inline]
        fn clone(&self) -> ReqId {
            let _: ::core::clone::AssertParamIsClone<u32>;
            *self
        }
    }
    #[automatically_derived]
    impl ::core::marker::Copy for ReqId {}
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
    #[automatically_derived]
    #[allow(non_camel_case_types)]
    impl ::core::fmt::Debug for StatusCode {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                StatusCode::SSH_FX_OK => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_OK")
                }
                StatusCode::SSH_FX_EOF => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_EOF")
                }
                StatusCode::SSH_FX_NO_SUCH_FILE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_NO_SUCH_FILE")
                }
                StatusCode::SSH_FX_PERMISSION_DENIED => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_PERMISSION_DENIED")
                }
                StatusCode::SSH_FX_FAILURE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_FAILURE")
                }
                StatusCode::SSH_FX_BAD_MESSAGE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_BAD_MESSAGE")
                }
                StatusCode::SSH_FX_NO_CONNECTION => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_NO_CONNECTION")
                }
                StatusCode::SSH_FX_CONNECTION_LOST => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_CONNECTION_LOST")
                }
                StatusCode::SSH_FX_OP_UNSUPPORTED => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FX_OP_UNSUPPORTED")
                }
                StatusCode::Other(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Other",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl ::num_enum::FromPrimitive for StatusCode {
        type Primitive = u32;
        fn from_primitive(number: Self::Primitive) -> Self {
            #![allow(non_upper_case_globals)]
            const SSH_FX_OK__num_enum_0__: u32 = 0;
            const SSH_FX_EOF__num_enum_0__: u32 = 1;
            const SSH_FX_NO_SUCH_FILE__num_enum_0__: u32 = 2;
            const SSH_FX_PERMISSION_DENIED__num_enum_0__: u32 = 3;
            const SSH_FX_FAILURE__num_enum_0__: u32 = 4;
            const SSH_FX_BAD_MESSAGE__num_enum_0__: u32 = 5;
            const SSH_FX_NO_CONNECTION__num_enum_0__: u32 = 6;
            const SSH_FX_CONNECTION_LOST__num_enum_0__: u32 = 7;
            const SSH_FX_OP_UNSUPPORTED__num_enum_0__: u32 = 8;
            #[deny(unreachable_patterns)]
            match number {
                SSH_FX_OK__num_enum_0__ => Self::SSH_FX_OK,
                SSH_FX_EOF__num_enum_0__ => Self::SSH_FX_EOF,
                SSH_FX_NO_SUCH_FILE__num_enum_0__ => Self::SSH_FX_NO_SUCH_FILE,
                SSH_FX_PERMISSION_DENIED__num_enum_0__ => Self::SSH_FX_PERMISSION_DENIED,
                SSH_FX_FAILURE__num_enum_0__ => Self::SSH_FX_FAILURE,
                SSH_FX_BAD_MESSAGE__num_enum_0__ => Self::SSH_FX_BAD_MESSAGE,
                SSH_FX_NO_CONNECTION__num_enum_0__ => Self::SSH_FX_NO_CONNECTION,
                SSH_FX_CONNECTION_LOST__num_enum_0__ => Self::SSH_FX_CONNECTION_LOST,
                SSH_FX_OP_UNSUPPORTED__num_enum_0__ => Self::SSH_FX_OP_UNSUPPORTED,
                #[allow(unreachable_patterns)]
                _ => Self::Other(number),
            }
        }
    }
    impl ::core::convert::From<u32> for StatusCode {
        #[inline]
        fn from(number: u32) -> Self {
            ::num_enum::FromPrimitive::from_primitive(number)
        }
    }
    #[doc(hidden)]
    impl ::num_enum::CannotDeriveBothFromPrimitiveAndTryFromPrimitive for StatusCode {}
    impl ::sunset::sshwire::SSHEncode for StatusCode {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            match *self {
                Self::SSH_FX_OK => {}
                Self::SSH_FX_EOF => {}
                Self::SSH_FX_NO_SUCH_FILE => {}
                Self::SSH_FX_PERMISSION_DENIED => {}
                Self::SSH_FX_FAILURE => {}
                Self::SSH_FX_BAD_MESSAGE => {}
                Self::SSH_FX_NO_CONNECTION => {}
                Self::SSH_FX_CONNECTION_LOST => {}
                Self::SSH_FX_OP_UNSUPPORTED => {}
                Self::Other(ref i) => {
                    return Err(::sunset::sshwire::WireError::UnknownVariant);
                }
            }
            #[allow(unreachable_code)] Ok(())
        }
    }
    impl ::sunset::sshwire::SSHEncodeEnum for StatusCode {
        fn variant_name(&self) -> ::sunset::sshwire::WireResult<&'static str> {
            let r = match self {
                Self::SSH_FX_OK => "ssh_fx_ok",
                Self::SSH_FX_EOF => "ssh_fx_eof",
                Self::SSH_FX_NO_SUCH_FILE => "ssh_fx_no_such_file",
                Self::SSH_FX_PERMISSION_DENIED => "ssh_fx_permission_denied",
                Self::SSH_FX_FAILURE => "ssh_fx_failure",
                Self::SSH_FX_BAD_MESSAGE => "ssh_fx_bad_message",
                Self::SSH_FX_NO_CONNECTION => "ssh_fx_no_connection",
                Self::SSH_FX_CONNECTION_LOST => "ssh_fx_connection_lost",
                Self::SSH_FX_OP_UNSUPPORTED => "ssh_fx_unsupported",
                Self::Other(_) => {
                    return Err(::sunset::sshwire::WireError::UnknownVariant);
                }
            };
            #[allow(unreachable_code)] Ok(r)
        }
    }
    impl<'de> SSHDecode<'de> for StatusCode {
        fn dec<S>(s: &mut S) -> WireResult<Self>
        where
            S: SSHSource<'de>,
        {
            Ok(StatusCode::from(u32::dec(s)?))
        }
    }
    pub struct ExtPair<'a> {
        pub name: &'a str,
        pub data: BinString<'a>,
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for ExtPair<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field2_finish(
                f,
                "ExtPair",
                "name",
                &self.name,
                "data",
                &&self.data,
            )
        }
    }
    impl<'a> ::sunset::sshwire::SSHEncode for ExtPair<'a> {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.name, s)?;
            ::sunset::sshwire::SSHEncode::enc(&self.data, s)?;
            Ok(())
        }
    }
    impl<'de, 'a> ::sunset::sshwire::SSHDecode<'de> for ExtPair<'a>
    where
        'de: 'a,
    {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_name = ::sunset::sshwire::SSHDecode::dec(s)?;
            let field_data = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self {
                name: field_name,
                data: field_data,
            })
        }
    }
    pub struct Attrs {
        pub size: Option<u64>,
        pub uid: Option<u32>,
        pub gid: Option<u32>,
        pub permissions: Option<u32>,
        pub atime: Option<u32>,
        pub mtime: Option<u32>,
        pub ext_count: Option<u32>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for Attrs {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            let names: &'static _ = &[
                "size",
                "uid",
                "gid",
                "permissions",
                "atime",
                "mtime",
                "ext_count",
            ];
            let values: &[&dyn ::core::fmt::Debug] = &[
                &self.size,
                &self.uid,
                &self.gid,
                &self.permissions,
                &self.atime,
                &self.mtime,
                &&self.ext_count,
            ];
            ::core::fmt::Formatter::debug_struct_fields_finish(f, "Attrs", names, values)
        }
    }
    #[automatically_derived]
    impl ::core::default::Default for Attrs {
        #[inline]
        fn default() -> Attrs {
            Attrs {
                size: ::core::default::Default::default(),
                uid: ::core::default::Default::default(),
                gid: ::core::default::Default::default(),
                permissions: ::core::default::Default::default(),
                atime: ::core::default::Default::default(),
                mtime: ::core::default::Default::default(),
                ext_count: ::core::default::Default::default(),
            }
        }
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
                flags += AttrsFlags::SSH_FILEXFER_ATTR_SIZE;
            }
            if self.uid.is_some() || self.gid.is_some() {
                flags += AttrsFlags::SSH_FILEXFER_ATTR_UIDGID;
            }
            if self.permissions.is_some() {
                flags += AttrsFlags::SSH_FILEXFER_ATTR_PERMISSIONS;
            }
            if self.atime.is_some() || self.mtime.is_some() {
                flags += AttrsFlags::SSH_FILEXFER_ATTR_ACMODTIME;
            }
            flags
        }
    }
    impl SSHEncode for Attrs {
        fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
            self.flags().enc(s)?;
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
            Ok(attrs)
        }
    }
    #[repr(u8)]
    #[allow(non_camel_case_types)]
    pub enum SftpNum {
        #[sshwire(variant = "ssh_fxp_init")]
        SSH_FXP_INIT = 1,
        #[sshwire(variant = "ssh_fxp_version")]
        SSH_FXP_VERSION = 2,
        #[sshwire(variant = "ssh_fxp_open")]
        SSH_FXP_OPEN = 3,
        #[sshwire(variant = "ssh_fxp_close")]
        SSH_FXP_CLOSE = 4,
        #[sshwire(variant = "ssh_fxp_read")]
        SSH_FXP_READ = 5,
        #[sshwire(variant = "ssh_fxp_write")]
        SSH_FXP_WRITE = 6,
        #[sshwire(variant = "ssh_fxp_status")]
        SSH_FXP_STATUS = 101,
        #[sshwire(variant = "ssh_fxp_handle")]
        SSH_FXP_HANDLE = 102,
        #[sshwire(variant = "ssh_fxp_data")]
        SSH_FXP_DATA = 103,
        #[sshwire(variant = "ssh_fxp_name")]
        SSH_FXP_NAME = 104,
        #[sshwire(unknown)]
        #[num_enum(catch_all)]
        Other(u8),
    }
    #[automatically_derived]
    #[allow(non_camel_case_types)]
    impl ::core::fmt::Debug for SftpNum {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                SftpNum::SSH_FXP_INIT => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_INIT")
                }
                SftpNum::SSH_FXP_VERSION => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_VERSION")
                }
                SftpNum::SSH_FXP_OPEN => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_OPEN")
                }
                SftpNum::SSH_FXP_CLOSE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_CLOSE")
                }
                SftpNum::SSH_FXP_READ => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_READ")
                }
                SftpNum::SSH_FXP_WRITE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_WRITE")
                }
                SftpNum::SSH_FXP_STATUS => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_STATUS")
                }
                SftpNum::SSH_FXP_HANDLE => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_HANDLE")
                }
                SftpNum::SSH_FXP_DATA => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_DATA")
                }
                SftpNum::SSH_FXP_NAME => {
                    ::core::fmt::Formatter::write_str(f, "SSH_FXP_NAME")
                }
                SftpNum::Other(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Other",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    #[allow(non_camel_case_types)]
    impl ::core::clone::Clone for SftpNum {
        #[inline]
        fn clone(&self) -> SftpNum {
            match self {
                SftpNum::SSH_FXP_INIT => SftpNum::SSH_FXP_INIT,
                SftpNum::SSH_FXP_VERSION => SftpNum::SSH_FXP_VERSION,
                SftpNum::SSH_FXP_OPEN => SftpNum::SSH_FXP_OPEN,
                SftpNum::SSH_FXP_CLOSE => SftpNum::SSH_FXP_CLOSE,
                SftpNum::SSH_FXP_READ => SftpNum::SSH_FXP_READ,
                SftpNum::SSH_FXP_WRITE => SftpNum::SSH_FXP_WRITE,
                SftpNum::SSH_FXP_STATUS => SftpNum::SSH_FXP_STATUS,
                SftpNum::SSH_FXP_HANDLE => SftpNum::SSH_FXP_HANDLE,
                SftpNum::SSH_FXP_DATA => SftpNum::SSH_FXP_DATA,
                SftpNum::SSH_FXP_NAME => SftpNum::SSH_FXP_NAME,
                SftpNum::Other(__self_0) => {
                    SftpNum::Other(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    impl ::num_enum::FromPrimitive for SftpNum {
        type Primitive = u8;
        fn from_primitive(number: Self::Primitive) -> Self {
            #![allow(non_upper_case_globals)]
            const SSH_FXP_INIT__num_enum_0__: u8 = 1;
            const SSH_FXP_VERSION__num_enum_0__: u8 = 2;
            const SSH_FXP_OPEN__num_enum_0__: u8 = 3;
            const SSH_FXP_CLOSE__num_enum_0__: u8 = 4;
            const SSH_FXP_READ__num_enum_0__: u8 = 5;
            const SSH_FXP_WRITE__num_enum_0__: u8 = 6;
            const SSH_FXP_STATUS__num_enum_0__: u8 = 101;
            const SSH_FXP_HANDLE__num_enum_0__: u8 = 102;
            const SSH_FXP_DATA__num_enum_0__: u8 = 103;
            const SSH_FXP_NAME__num_enum_0__: u8 = 104;
            #[deny(unreachable_patterns)]
            match number {
                SSH_FXP_INIT__num_enum_0__ => Self::SSH_FXP_INIT,
                SSH_FXP_VERSION__num_enum_0__ => Self::SSH_FXP_VERSION,
                SSH_FXP_OPEN__num_enum_0__ => Self::SSH_FXP_OPEN,
                SSH_FXP_CLOSE__num_enum_0__ => Self::SSH_FXP_CLOSE,
                SSH_FXP_READ__num_enum_0__ => Self::SSH_FXP_READ,
                SSH_FXP_WRITE__num_enum_0__ => Self::SSH_FXP_WRITE,
                SSH_FXP_STATUS__num_enum_0__ => Self::SSH_FXP_STATUS,
                SSH_FXP_HANDLE__num_enum_0__ => Self::SSH_FXP_HANDLE,
                SSH_FXP_DATA__num_enum_0__ => Self::SSH_FXP_DATA,
                SSH_FXP_NAME__num_enum_0__ => Self::SSH_FXP_NAME,
                #[allow(unreachable_patterns)]
                _ => Self::Other(number),
            }
        }
    }
    impl ::core::convert::From<u8> for SftpNum {
        #[inline]
        fn from(number: u8) -> Self {
            ::num_enum::FromPrimitive::from_primitive(number)
        }
    }
    #[doc(hidden)]
    impl ::num_enum::CannotDeriveBothFromPrimitiveAndTryFromPrimitive for SftpNum {}
    impl ::sunset::sshwire::SSHEncode for SftpNum {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            match *self {
                Self::SSH_FXP_INIT => {}
                Self::SSH_FXP_VERSION => {}
                Self::SSH_FXP_OPEN => {}
                Self::SSH_FXP_CLOSE => {}
                Self::SSH_FXP_READ => {}
                Self::SSH_FXP_WRITE => {}
                Self::SSH_FXP_STATUS => {}
                Self::SSH_FXP_HANDLE => {}
                Self::SSH_FXP_DATA => {}
                Self::SSH_FXP_NAME => {}
                Self::Other(ref i) => {
                    return Err(::sunset::sshwire::WireError::UnknownVariant);
                }
            }
            #[allow(unreachable_code)] Ok(())
        }
    }
    impl ::sunset::sshwire::SSHEncodeEnum for SftpNum {
        fn variant_name(&self) -> ::sunset::sshwire::WireResult<&'static str> {
            let r = match self {
                Self::SSH_FXP_INIT => "ssh_fxp_init",
                Self::SSH_FXP_VERSION => "ssh_fxp_version",
                Self::SSH_FXP_OPEN => "ssh_fxp_open",
                Self::SSH_FXP_CLOSE => "ssh_fxp_close",
                Self::SSH_FXP_READ => "ssh_fxp_read",
                Self::SSH_FXP_WRITE => "ssh_fxp_write",
                Self::SSH_FXP_STATUS => "ssh_fxp_status",
                Self::SSH_FXP_HANDLE => "ssh_fxp_handle",
                Self::SSH_FXP_DATA => "ssh_fxp_data",
                Self::SSH_FXP_NAME => "ssh_fxp_name",
                Self::Other(_) => {
                    return Err(::sunset::sshwire::WireError::UnknownVariant);
                }
            };
            #[allow(unreachable_code)] Ok(r)
        }
    }
    impl<'de> SSHDecode<'de> for SftpNum {
        fn dec<S>(s: &mut S) -> WireResult<Self>
        where
            S: SSHSource<'de>,
        {
            Ok(SftpNum::from(u8::dec(s)?))
        }
    }
    impl From<SftpNum> for u8 {
        fn from(sftp_num: SftpNum) -> u8 {
            match sftp_num {
                SftpNum::SSH_FXP_INIT => 1,
                SftpNum::SSH_FXP_VERSION => 2,
                SftpNum::SSH_FXP_OPEN => 3,
                SftpNum::SSH_FXP_CLOSE => 4,
                SftpNum::SSH_FXP_READ => 5,
                SftpNum::SSH_FXP_WRITE => 6,
                SftpNum::SSH_FXP_STATUS => 101,
                SftpNum::SSH_FXP_HANDLE => 102,
                SftpNum::SSH_FXP_DATA => 103,
                SftpNum::SSH_FXP_NAME => 104,
                _ => 0,
            }
        }
    }
    impl SftpNum {
        fn is_request(&self) -> bool {
            (2..=99).contains(&(u8::from(self.clone())))
        }
        fn is_response(&self) -> bool {
            (100..=199).contains(&(u8::from(self.clone())))
        }
    }
    /// Top level SSH packet enum
    ///
    /// It helps identifying the SFTP Packet type and handling it accordingly
    /// This is done using the SFTP field type
    pub enum SftpPacket<'a> {
        Init(InitVersionClient),
        Version(InitVersionLowest),
        Open(Open<'a>),
        Close(Close<'a>),
        Read(Read<'a>),
        Write(Write<'a>),
        Status(Status<'a>),
        Handle(Handle<'a>),
        Data(Data<'a>),
        Name(Name<'a>),
    }
    #[automatically_derived]
    impl<'a> ::core::fmt::Debug for SftpPacket<'a> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                SftpPacket::Init(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Init",
                        &__self_0,
                    )
                }
                SftpPacket::Version(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Version",
                        &__self_0,
                    )
                }
                SftpPacket::Open(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Open",
                        &__self_0,
                    )
                }
                SftpPacket::Close(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Close",
                        &__self_0,
                    )
                }
                SftpPacket::Read(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Read",
                        &__self_0,
                    )
                }
                SftpPacket::Write(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Write",
                        &__self_0,
                    )
                }
                SftpPacket::Status(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Status",
                        &__self_0,
                    )
                }
                SftpPacket::Handle(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Handle",
                        &__self_0,
                    )
                }
                SftpPacket::Data(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Data",
                        &__self_0,
                    )
                }
                SftpPacket::Name(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Name",
                        &__self_0,
                    )
                }
            }
        }
    }
    impl SSHEncode for SftpPacket<'_> {
        fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
            let t = u8::from(self.sftp_num());
            t.enc(s)?;
            match self {
                SftpPacket::Init(p) => p.enc(s)?,
                SftpPacket::Version(p) => p.enc(s)?,
                SftpPacket::Open(p) => p.enc(s)?,
                SftpPacket::Close(p) => p.enc(s)?,
                SftpPacket::Read(p) => p.enc(s)?,
                SftpPacket::Write(p) => p.enc(s)?,
                SftpPacket::Status(p) => p.enc(s)?,
                SftpPacket::Handle(p) => p.enc(s)?,
                SftpPacket::Data(p) => p.enc(s)?,
                SftpPacket::Name(p) => p.enc(s)?,
            };
            Ok(())
        }
    }
    impl<'a: 'de, 'de> SSHDecode<'de> for SftpPacket<'a>
    where
        'de: 'a,
    {
        fn dec<S>(s: &mut S) -> WireResult<Self>
        where
            S: SSHSource<'de>,
        {
            let packet_type_number = u8::dec(s)?;
            let packet_type = SftpNum::from(packet_type_number);
            let decoded_packet = match packet_type {
                SftpNum::SSH_FXP_INIT => {
                    let inner_type = <InitVersionClient>::dec(s)?;
                    SftpPacket::Init(inner_type)
                }
                SftpNum::SSH_FXP_VERSION => {
                    let inner_type = <InitVersionLowest>::dec(s)?;
                    SftpPacket::Version(inner_type)
                }
                SftpNum::SSH_FXP_OPEN => {
                    let inner_type = <Open<'a>>::dec(s)?;
                    SftpPacket::Open(inner_type)
                }
                SftpNum::SSH_FXP_CLOSE => {
                    let inner_type = <Close<'a>>::dec(s)?;
                    SftpPacket::Close(inner_type)
                }
                SftpNum::SSH_FXP_READ => {
                    let inner_type = <Read<'a>>::dec(s)?;
                    SftpPacket::Read(inner_type)
                }
                SftpNum::SSH_FXP_WRITE => {
                    let inner_type = <Write<'a>>::dec(s)?;
                    SftpPacket::Write(inner_type)
                }
                SftpNum::SSH_FXP_STATUS => {
                    let inner_type = <Status<'a>>::dec(s)?;
                    SftpPacket::Status(inner_type)
                }
                SftpNum::SSH_FXP_HANDLE => {
                    let inner_type = <Handle<'a>>::dec(s)?;
                    SftpPacket::Handle(inner_type)
                }
                SftpNum::SSH_FXP_DATA => {
                    let inner_type = <Data<'a>>::dec(s)?;
                    SftpPacket::Data(inner_type)
                }
                SftpNum::SSH_FXP_NAME => {
                    let inner_type = <Name<'a>>::dec(s)?;
                    SftpPacket::Name(inner_type)
                }
                _ => {
                    return Err(WireError::UnknownPacket {
                        number: packet_type_number,
                    });
                }
            };
            Ok(decoded_packet)
        }
    }
    impl<'a> SftpPacket<'a> {
        /// Maps `SpecificPacketVariant` to `message_num`
        pub fn sftp_num(&self) -> SftpNum {
            match self {
                SftpPacket::Init(_) => SftpNum::from(1 as u8),
                SftpPacket::Version(_) => SftpNum::from(2 as u8),
                SftpPacket::Open(_) => SftpNum::from(3 as u8),
                SftpPacket::Close(_) => SftpNum::from(4 as u8),
                SftpPacket::Read(_) => SftpNum::from(5 as u8),
                SftpPacket::Write(_) => SftpNum::from(6 as u8),
                SftpPacket::Status(_) => SftpNum::from(101 as u8),
                SftpPacket::Handle(_) => SftpNum::from(102 as u8),
                SftpPacket::Data(_) => SftpNum::from(103 as u8),
                SftpPacket::Name(_) => SftpNum::from(104 as u8),
            }
        }
        /// Encode a request.
        ///
        /// Used by a SFTP client. Does not include the length field.
        pub fn encode_request(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {
            if !self.sftp_num().is_request() {
                return Err(WireError::PacketWrong);
            }
            self.sftp_num().enc(s)?;
            id.0.enc(s)?;
            self.enc(s)
        }
        /// Decode a response.
        ///
        /// Used by a SFTP client. Does not include the length field.
        pub fn decode_response<'de, S>(s: &mut S) -> WireResult<(ReqId, Self)>
        where
            S: SSHSource<'de>,
            'a: 'de,
            'de: 'a,
        {
            let num = SftpNum::from(u8::dec(s)?);
            if !num.is_response() {
                return Err(WireError::PacketWrong);
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
            'a: 'de,
            'de: 'a,
        {
            let num = SftpNum::from(u8::dec(s)?);
            if !num.is_request() {
                return Err(WireError::PacketWrong);
            }
            let id = ReqId(u32::dec(s)?);
            Ok((id, Self::dec(s)?))
        }
        /// Encode a response.
        ///
        /// Used by a SFTP server. Does not include the length field.
        pub fn encode_response(&self, id: ReqId, s: &mut dyn SSHSink) -> WireResult<()> {
            if !self.sftp_num().is_response() {
                return Err(WireError::PacketWrong);
            }
            self.sftp_num().enc(s)?;
            id.0.enc(s)?;
            self.enc(s)
        }
    }
    impl<'a> From<InitVersionClient> for SftpPacket<'a> {
        fn from(s: InitVersionClient) -> SftpPacket<'a> {
            SftpPacket::Init(s)
        }
    }
    impl<'a> From<InitVersionLowest> for SftpPacket<'a> {
        fn from(s: InitVersionLowest) -> SftpPacket<'a> {
            SftpPacket::Version(s)
        }
    }
    impl<'a> From<Open<'a>> for SftpPacket<'a> {
        fn from(s: Open<'a>) -> SftpPacket<'a> {
            SftpPacket::Open(s)
        }
    }
    impl<'a> From<Close<'a>> for SftpPacket<'a> {
        fn from(s: Close<'a>) -> SftpPacket<'a> {
            SftpPacket::Close(s)
        }
    }
    impl<'a> From<Read<'a>> for SftpPacket<'a> {
        fn from(s: Read<'a>) -> SftpPacket<'a> {
            SftpPacket::Read(s)
        }
    }
    impl<'a> From<Write<'a>> for SftpPacket<'a> {
        fn from(s: Write<'a>) -> SftpPacket<'a> {
            SftpPacket::Write(s)
        }
    }
    impl<'a> From<Status<'a>> for SftpPacket<'a> {
        fn from(s: Status<'a>) -> SftpPacket<'a> {
            SftpPacket::Status(s)
        }
    }
    impl<'a> From<Handle<'a>> for SftpPacket<'a> {
        fn from(s: Handle<'a>) -> SftpPacket<'a> {
            SftpPacket::Handle(s)
        }
    }
    impl<'a> From<Data<'a>> for SftpPacket<'a> {
        fn from(s: Data<'a>) -> SftpPacket<'a> {
            SftpPacket::Data(s)
        }
    }
    impl<'a> From<Name<'a>> for SftpPacket<'a> {
        fn from(s: Name<'a>) -> SftpPacket<'a> {
            SftpPacket::Name(s)
        }
    }
}
