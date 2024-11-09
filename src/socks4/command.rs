use crate::error::SocksError;

/// CONNECT X'01'
/// BIND X'02'
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Socks4Command {
    Connect = 0x01,
    Bind = 0x02,
}

impl TryFrom<u8> for Socks4Command {
    type Error = SocksError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            val => Err(SocksError::InvalidCommand(val)),
        }
    }
}

impl Into<u8> for Socks4Command {
    fn into(self) -> u8 {
        match self {
            Self::Connect => 0x01,
            Self::Bind => 0x02,
        }
    }
}
