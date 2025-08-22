#![feature(prelude_import)]
#[macro_use]
extern crate std;
#[prelude_import]
use std::prelude::rust_2024::*;
mod proto {
    use sunset::error;
    use sunset::error::Error as SunsetError;
    use sunset::packets::{MessageNumber, Packet, Unknown};
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
    struct FileHandle<'a>(pub BinString<'a>);
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
    pub struct InitVersion {
        pub version: u32,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for InitVersion {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "InitVersion",
                "version",
                &&self.version,
            )
        }
    }
    impl ::sunset::sshwire::SSHEncode for InitVersion {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.version, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for InitVersion {
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
    pub struct Name {
        pub count: u32,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for Name {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "Name",
                "count",
                &&self.count,
            )
        }
    }
    impl ::sunset::sshwire::SSHEncode for Name {
        fn enc(
            &self,
            s: &mut dyn ::sunset::sshwire::SSHSink,
        ) -> ::sunset::sshwire::WireResult<()> {
            ::sunset::sshwire::SSHEncode::enc(&self.count, s)?;
            Ok(())
        }
    }
    impl<'de> ::sunset::sshwire::SSHDecode<'de> for Name {
        fn dec<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
        ) -> ::sunset::sshwire::WireResult<Self> {
            let field_count = ::sunset::sshwire::SSHDecode::dec(s)?;
            Ok(Self { count: field_count })
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
    #[repr(u8)]
    #[allow(non_camel_case_types)]
    pub enum StatusCode<'a> {
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
        Other(Unknown<'a>),
    }
    #[automatically_derived]
    #[allow(non_camel_case_types)]
    impl<'a> ::core::fmt::Debug for StatusCode<'a> {
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
    impl<'a> ::sunset::sshwire::SSHEncode for StatusCode<'a> {
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
    impl<'a> ::sunset::sshwire::SSHEncodeEnum for StatusCode<'a> {
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
    impl<'de, 'a> ::sunset::sshwire::SSHDecodeEnum<'de> for StatusCode<'a>
    where
        'de: 'a,
    {
        fn dec_enum<S: ::sunset::sshwire::SSHSource<'de>>(
            s: &mut S,
            variant: &'de [u8],
        ) -> ::sunset::sshwire::WireResult<Self> {
            let var_str = ::sunset::sshwire::try_as_ascii_str(variant).ok();
            let r = match var_str {
                Some("ssh_fx_ok") => Self::SSH_FX_OK,
                Some("ssh_fx_eof") => Self::SSH_FX_EOF,
                Some("ssh_fx_no_such_file") => Self::SSH_FX_NO_SUCH_FILE,
                Some("ssh_fx_permission_denied") => Self::SSH_FX_PERMISSION_DENIED,
                Some("ssh_fx_failure") => Self::SSH_FX_FAILURE,
                Some("ssh_fx_bad_message") => Self::SSH_FX_BAD_MESSAGE,
                Some("ssh_fx_no_connection") => Self::SSH_FX_NO_CONNECTION,
                Some("ssh_fx_connection_lost") => Self::SSH_FX_CONNECTION_LOST,
                Some("ssh_fx_unsupported") => Self::SSH_FX_OP_UNSUPPORTED,
                _ => {
                    s.ctx().seen_unknown = true;
                    Self::Other(Unknown::new(variant))
                }
            };
            Ok(r)
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
}
