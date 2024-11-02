/// 0x00 NO AUTHENTICATION REQUIRED
/// 0x01 GSSAPI
/// 0x02 USERNAME/PASSWORD
/// 0x03 to X'7F' IANA ASSIGNED
/// 0x80 to X'FE' RESERVED FOR PRIVATE METHODS
/// 0xFF NO ACCEPTABLE METHODS
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Method {
    None = 0x00,
    GssApi = 0x01,
    UserPass = 0x02,
    IanaAssigned(u8),
    Private(u8),
    Unacceptable = 0xff,
}

impl From<u8> for Method {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Self::None,
            0x01 => Self::GssApi,
            0x02 => Self::UserPass,
            0x03..=0x7f => Self::IanaAssigned(value),
            0x80..=0xfe => Self::Private(value),
            0xff => Self::Unacceptable,
        }
    }
}

impl Into<u8> for Method {
    fn into(self) -> u8 {
        match self {
            Self::None => 0x00,
            Self::GssApi => 0x01,
            Self::UserPass => 0x02,
            Self::IanaAssigned(value) => value,
            Self::Private(value) => value,
            Self::Unacceptable => 0xff,
        }
    }
}
