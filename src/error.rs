use crate::socks5::{addr_type::Socks5AddrType, method::Socks5Method};

#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    #[error("Unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),

    #[error("Unsupported methods {:?}", self)]
    UnsupportedMethods(Vec<Socks5Method>),

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Invalid command {0}")]
    InvalidCommand(u8),
    #[error("Unsupported command {:?}", self)]
    UnsupportedCommand(u8),

    #[error("Invalid address type {0}")]
    InvalidAddressType(u8),
    #[error("Unsupported address {:?}", self)]
    UnsupportedAddressType(Socks5AddrType),

    #[error("Converting a UTF-8 bytes to string error. {0}")]
    Utf8BytesToStringError(#[from] std::string::FromUtf8Error),

    #[error("Internal error")]
    InternalError,
}
