use core::convert::From;

use sunset::Error as SunsetError;
use sunset::sshwire::WireError;

use crate::{SftpOpResult, StatusCode, requestholder::RequestHolderError};

#[derive(Debug)]
pub enum SftpError {
    NotInitialized,
    AlreadyInitialized,
    MalformedPacket,
    WireError(WireError),
    OperationError(StatusCode),
    SunsetError(SunsetError),
    RequestHolderError(RequestHolderError),
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
        SftpError::OperationError(value)
    }
}

impl From<RequestHolderError> for SftpError {
    fn from(value: RequestHolderError) -> Self {
        SftpError::RequestHolderError(value)
    }
}

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
            SftpError::NotInitialized => SunsetError::PacketWrong {},
            SftpError::AlreadyInitialized => SunsetError::PacketWrong {},
            SftpError::MalformedPacket => SunsetError::PacketWrong {},
            SftpError::OperationError(_) => SunsetError::PacketWrong {},
            SftpError::RequestHolderError(request_holder_error) => SunsetError::Bug,
        }
    }
}

pub type SftpResult<T> = Result<T, SftpError>;
