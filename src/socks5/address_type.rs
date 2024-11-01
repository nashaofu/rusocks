use crate::error::Error;

/// ATYP   address type of following address
/// IP V4 address: X'01'
/// DOMAINNAME: X'03'
/// IP V6 address: X'04'
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressType {
    IPV4 = 0x01,
    Domain = 0x03,
    IPV6 = 0x04,
}

impl TryFrom<u8> for AddressType {
    type Error = Error;
    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            0x01 => Ok(AddressType::IPV4),
            0x03 => Ok(AddressType::Domain),
            0x04 => Ok(AddressType::IPV6),
            val => Err(Error::InvalidAddressType(val)),
        }
    }
}

impl From<AddressType> for u8 {
    fn from(addr_type: AddressType) -> Self {
        match addr_type {
            AddressType::IPV4 => 0x01,
            AddressType::Domain => 0x03,
            AddressType::IPV6 => 0x04,
        }
    }
}
