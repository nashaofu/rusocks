/// X'00' succeeded
/// X'01' general SOCKS server failure
/// X'02' connection not allowed by ruleset
/// X'03' Network unreachable
/// X'04' Host unreachable
/// X'05' Connection refused
/// X'06' TTL expired
/// X'07' Command not supported
/// X'08' Address type not supported
/// X'09' to X'FF' unassigned
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    Failure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    UnsupportedCommand = 0x07,
    UnsupportedAddress = 0x08,
    Unassigned(u8),
}

impl From<u8> for Reply {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::Succeeded,
            0x01 => Self::Failure,
            0x02 => Self::NotAllowed,
            0x03 => Self::NetworkUnreachable,
            0x04 => Self::HostUnreachable,
            0x05 => Self::ConnectionRefused,
            0x06 => Self::TTLExpired,
            0x07 => Self::UnsupportedCommand,
            0x08 => Self::UnsupportedAddress,
            val => Self::Unassigned(val),
        }
    }
}

impl Into<u8> for Reply {
    fn into(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::Failure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TTLExpired => 0x06,
            Self::UnsupportedCommand => 0x07,
            Self::UnsupportedAddress => 0x08,
            Self::Unassigned(val) => val,
        }
    }
}
