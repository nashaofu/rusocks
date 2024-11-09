/// 90: request granted
/// 91: request rejected or failed
/// 92: request rejected becasue SOCKS server cannot connect to identd on the client
/// 93: request rejected because the client program and identd report different user-ids
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Socks4Reply {
    Granted = 0x5a,
    Rejected = 0x5b,
    RejectedByCannotConnectIdentd = 0x5c,
    RejectedByIdentdReportDifferentUserIds = 0x5f,
}

impl From<u8> for Socks4Reply {
    fn from(value: u8) -> Self {
        match value {
            0x5a => Self::Granted,
            0x5b => Self::Rejected,
            0x5c => Self::RejectedByCannotConnectIdentd,
            0x5f => Self::RejectedByIdentdReportDifferentUserIds,
            _ => Self::Rejected,
        }
    }
}

impl Into<u8> for Socks4Reply {
    fn into(self) -> u8 {
        match self {
            Self::Granted => 0x5a,
            Self::Rejected => 0x5b,
            Self::RejectedByCannotConnectIdentd => 0x5c,
            Self::RejectedByIdentdReportDifferentUserIds => 0x5f,
        }
    }
}
