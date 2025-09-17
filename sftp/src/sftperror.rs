use core::convert::From;

use sunset::sshwire::WireError;

#[derive(Debug)]
pub enum SftpError {
    WireError(WireError),
    // SshError(SshError),
}

impl From<WireError> for SftpError {
    fn from(value: WireError) -> Self {
        SftpError::WireError(value)
    }
}

pub type SftpResult<T> = Result<T, SftpError>;
