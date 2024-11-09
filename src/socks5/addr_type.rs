use crate::error::SocksError;

/// ATYP   address type of following address
/// IP V4 address: X'01'
/// DOMAINNAME: X'03'
/// IP V6 address: X'04'
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Socks5AddrType {
    IPV4 = 0x01,
    Domain = 0x03,
    IPV6 = 0x04,
}

impl TryFrom<u8> for Socks5AddrType {
    type Error = SocksError;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(Socks5AddrType::IPV4),
            0x03 => Ok(Socks5AddrType::Domain),
            0x04 => Ok(Socks5AddrType::IPV6),
            val => Err(SocksError::InvalidAddressType(val)),
        }
    }
}

impl From<Socks5AddrType> for u8 {
    fn from(addr_type: Socks5AddrType) -> Self {
        match addr_type {
            Socks5AddrType::IPV4 => 0x01,
            Socks5AddrType::Domain => 0x03,
            Socks5AddrType::IPV6 => 0x04,
        }
    }
}
