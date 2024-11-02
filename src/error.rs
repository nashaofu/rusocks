use crate::address::Address;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    #[error("Unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),

    #[error("Authentication failed")]
    AuthenticationFailed,

    #[error("Invalid command {0}")]
    InvalidCommand(u8),
    #[error("Unsupported command {:?}", self)]
    UnsupportedCommand(u8),

    #[error("Invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("Unsupported address {:?}", self)]
    UnsupportedAddress(Address),

    #[error("Converting a UTF-8 bytes to string error. {0}")]
    Utf8BytesToStringError(#[from] std::string::FromUtf8Error),

    #[error("Internal error")]
    InternalError,
}
