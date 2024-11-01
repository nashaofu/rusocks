use crate::error::Error;

/// CONNECT X'01'
/// BIND X'02'
/// UDP ASSOCIATE X'03'
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Command {
    Connect = 0x01,
    Bind = 0x02,
    Associate = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Connect),
            0x02 => Ok(Self::Bind),
            0x03 => Ok(Self::Associate),
            val => Err(Error::InvalidCommand(val)),
        }
    }
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Self::Connect => 0x01,
            Self::Bind => 0x02,
            Self::Associate => 0x03,
        }
    }
}
