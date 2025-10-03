//! SFTP (SSH File Transfer Protocol) implementation extending [`sunset`].
//!
//! Partially Implements SFTP v3 as defined in [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02).
//!
//! **Work in Progress**: Currently focuses on file upload operations.
//! Long packets for other request types and additional SFTP operations are not yet implemented.
//! `no_std` compatibility is intended but not yet complete.
//!
//! See example usage in the `demo/sftd/std` directory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod opaquefilehandle;
mod proto;
mod requestholder;
mod sftperror;
mod sftphandler;
mod sftpserver;
mod sftpsink;
mod sftpsource;

pub use sftphandler::SftpHandler;

pub mod server {

    pub use crate::sftpserver::DirReply;
    pub use crate::sftpserver::ReadReply;
    pub use crate::sftpserver::SftpOpResult;
    pub use crate::sftpserver::SftpServer;
}

pub mod handles {
    pub use crate::opaquefilehandle::OpaqueFileHandle;
    pub use crate::opaquefilehandle::OpaqueFileHandleManager;
    pub use crate::opaquefilehandle::PathFinder;
}

pub mod protocol {
    pub use crate::proto::Attrs;
    pub use crate::proto::FileHandle;
    pub use crate::proto::Filename;
    pub use crate::proto::Name;
    pub use crate::proto::NameEntry;
    pub use crate::proto::PathInfo;
    pub use crate::proto::StatusCode;
}

pub mod error {
    pub use crate::sftperror::SftpError;
    pub use crate::sftperror::SftpResult;
}
