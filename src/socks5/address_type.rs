use crate::error::Error;

/// ATYP   address type of following address
/// IP V4 address: X'01'
/// DOMAINNAME: X'03'
/// IP V6 address: X'04'
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Socks5AddressType {
    IPV4 = 0x01,
    Domain = 0x03,
    IPV6 = 0x04,
}

impl TryFrom<u8> for Socks5AddressType {
    type Error = Error;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(Socks5AddressType::IPV4),
            0x03 => Ok(Socks5AddressType::Domain),
            0x04 => Ok(Socks5AddressType::IPV6),
            val => Err(Error::InvalidAddressType(val)),
        }
    }
}

impl From<Socks5AddressType> for u8 {
    fn from(addr_type: Socks5AddressType) -> Self {
        match addr_type {
            Socks5AddressType::IPV4 => 0x01,
            Socks5AddressType::Domain => 0x03,
            Socks5AddressType::IPV6 => 0x04,
        }
    }
}
