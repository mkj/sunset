//! SFTP (SSH File Transfer Protocol) implementation for [`sunset`].
//!
//! (Partially) Implements SFTP v3 as defined in [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02).
//!
//! **Work in Progress**: Currently focuses on file upload operations.
//! Long packets for requests other than writing and additional SFTP operations
//! are not yet implemented. `no_std` compatibility is intended but not
//! yet complete. Please see the roadmap and use this crate carefully.
//!
//! This crate implements a handler that, given a [`sunset::ChanHandle`]
//! a `sunset_async::SSHServer` and some auxiliary buffers,
//! can dispatch SFTP packets to a struct implementing [`crate::sftpserver::SftpServer`] trait.
//!
//! See example usage in the `../demo/sftd/std` directory for the intended usage
//! of this library.
//!
//! # Roadmap
//!
//! The following list is an opinionated collection of the points that should be
//! completed to provide growing functionality.
//!
//! ## Basic features
//!
//!  - [x] [SFTP Protocol Initialization](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-4) (Only SFTP V3 supported)
//! - [x] [Canonicalizing the Server-Side Path Name](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.11) support
//! - [x] [Open, close](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
//! and [write](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
//! - [ ] File [read](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4),
//! - [ ] File [stats](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8)
//! - [ ] Directory [Browsing](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7)
//!
//! ## Minimal features for convenient usability
//!
//! - [ ] [Removing files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.5)
//! - [ ] [Renaming files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.5)
//! - [ ] [Creating directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.6)
//! - [ ] [Removing directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.6)
//!
//! ## Extended features
//!
//! - [ ] [Append, create and truncate files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
//! files
//! - [ ] [Reading](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8)
//! files attributes
//! - [ ] [Setting](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.9) files attributes
//! - [ ] [Dealing with Symbolic links](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.10)
//! - [ ] [Vendor Specific](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-8)
//!  request and responses

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

/// Main calling point for the library provided that the user implements
/// a [`crate::sftpserver::SftpServer`].
///
/// Please see basic usage at `../demo/sftd/std`
pub use sftphandler::SftpHandler;

/// Structures and types used to add the details for the target system
pub mod server {

    pub use crate::sftpserver::DirReply;
    pub use crate::sftpserver::ReadReply;
    pub use crate::sftpserver::SftpOpResult;
    pub use crate::sftpserver::SftpServer;
}

/// Handles and helpers used by the [`sftpserver::SftpServer`] trait implementer
pub mod handles {
    pub use crate::opaquefilehandle::OpaqueFileHandle;
    pub use crate::opaquefilehandle::OpaqueFileHandleManager;
    pub use crate::opaquefilehandle::PathFinder;
}

/// SFTP Protocol types and structures
pub mod protocol {
    pub use crate::proto::Attrs;
    pub use crate::proto::FileHandle;
    pub use crate::proto::Filename;
    pub use crate::proto::Name;
    pub use crate::proto::NameEntry;
    pub use crate::proto::PathInfo;
    pub use crate::proto::StatusCode;
}

/// Errors and results used in this crate
pub mod error {
    pub use crate::sftperror::SftpError;
    pub use crate::sftperror::SftpResult;
}
