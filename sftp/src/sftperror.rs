use crate::protocol::StatusCode;

use crate::sftphandler::requestholder::RequestHolderError;
use sunset::Error as SunsetError;
use sunset::sshwire::WireError;

use core::convert::From;
use log::warn;

// TODO Use it more broadly where reasonable
/// Errors that are specific to this SFTP lib
#[derive(Debug)]
pub enum SftpError {
    /// The SFTP server has not been initialised. No SFTP version has been
    /// establish
    NotInitialized,
    /// An `SSH_FXP_INIT` packet was received after the server was already
    /// initialized
    AlreadyInitialized,
    /// A packet could not be decoded as it was malformed
    MalformedPacket,
    /// The server does not have an implementation for the current request.
    /// Some possible causes are:
    ///
    /// - The request has not been handled by an [`crate::sftpserver::SftpServer`]
    /// - Long request which its handling was not implemented
    NotSupported,
    /// The connection has been closed by the client
    ClientDisconnected,
    /// The [`crate::sftpserver::SftpServer`] failed doing an IO operation
    FileServerError(StatusCode),
    // A RequestHolder instance throw an error. See [`crate::requestholder::RequestHolderError`]
    /// A RequestHolder instance threw an error. See `RequestHolderError`
    RequestHolderError(RequestHolderError),
    /// A variant containing a [`WireError`]
    WireError(WireError),
    /// A variant containing a [`SunsetError`]
    SunsetError(SunsetError),
}

impl From<WireError> for SftpError {
    fn from(value: WireError) -> Self {
        SftpError::WireError(value)
    }
}

impl From<SunsetError> for SftpError {
    fn from(value: SunsetError) -> Self {
        SftpError::SunsetError(value)
    }
}

impl From<StatusCode> for SftpError {
    fn from(value: StatusCode) -> Self {
        SftpError::FileServerError(value)
    }
}

impl From<RequestHolderError> for SftpError {
    fn from(value: RequestHolderError) -> Self {
        SftpError::RequestHolderError(value)
    }
}
// impl From<FileServerError> for SftpError {
//     fn from(value: FileServerError) -> Self {
//         SftpError::FileServerError(value)
//     }
// }

impl From<SftpError> for WireError {
    fn from(value: SftpError) -> Self {
        match value {
            SftpError::WireError(wire_error) => wire_error,
            _ => WireError::PacketWrong,
        }
    }
}

impl From<SftpError> for SunsetError {
    fn from(value: SftpError) -> Self {
        match value {
            SftpError::SunsetError(error) => error,
            SftpError::WireError(wire_error) => wire_error.into(),
            SftpError::NotInitialized => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::PacketWrong {}
            }
            SftpError::NotSupported => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::PacketWrong {}
            }
            SftpError::AlreadyInitialized => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::PacketWrong {}
            }
            SftpError::MalformedPacket => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::PacketWrong {}
            }
            SftpError::RequestHolderError(_) => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::Bug
            }
            SftpError::FileServerError(_) => {
                warn!("Casting error loosing information: {:?}", value);
                SunsetError::Bug
            }
            SftpError::ClientDisconnected => SunsetError::ChannelEOF,
        }
    }
}

/// result specific to this SFTP lib
pub type SftpResult<T> = Result<T, SftpError>;
