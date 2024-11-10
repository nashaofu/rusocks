use std::net::{SocketAddrV4, SocketAddrV6};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SocksAddr {
    IPV4(SocketAddrV4),
    Domain(String, u16),
    IPV6(SocketAddrV6),
}

impl SocksAddr {
    pub fn domain(&self) -> String {
        match self {
            Self::IPV4(addr) => addr.ip().to_string(),
            Self::Domain(addr, _) => addr.clone(),
            Self::IPV6(addr) => addr.ip().to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::IPV4(addr) => addr.port(),
            Self::Domain(_, port) => *port,
            Self::IPV6(addr) => addr.port(),
        }
    }
}
