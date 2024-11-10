use std::net::SocketAddr;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use super::addr_type::Socks5AddrType;

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
pub enum Socks5Reply {
    Succeeded = 0x00,
    Failure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    UnsupportedCommand = 0x07,
    UnsupportedAddressType = 0x08,
    Unassigned(u8),
}

impl From<u8> for Socks5Reply {
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
            0x08 => Self::UnsupportedAddressType,
            val => Self::Unassigned(val),
        }
    }
}

impl Into<u8> for Socks5Reply {
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
            Self::UnsupportedAddressType => 0x08,
            Self::Unassigned(val) => val,
        }
    }
}

impl Socks5Reply {
    pub(super) const VERSION: u8 = 0x05;

    /// The SOCKS request information is sent by the client as soon as it has
    /// established a connection to the SOCKS server, and completed the
    /// authentication negotiations.  The server evaluates the request, and
    /// returns a reply formed as follows:
    ///
    ///      +----+-----+-------+------+----------+----------+
    ///      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    ///      +----+-----+-------+------+----------+----------+
    ///      | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///      +----+-----+-------+------+----------+----------+
    ///
    ///   Where:
    ///
    ///        o  VER    protocol version: X'05'
    ///        o  REP    Reply field:
    ///        o  RSV    RESERVED
    ///        o  ATYP   address type of following address
    ///           o  IP V4 address: X'01'
    ///           o  DOMAINNAME: X'03'
    ///           o  IP V6 address: X'04'
    ///        o  BND.ADDR       server bound address
    ///        o  BND.PORT       server bound port in network octet order
    /// Fields marked RESERVED (RSV) must be set to X'00'.
    pub async fn reply<S>(
        &self,
        stream: &mut S,
        bind_addr: SocketAddr,
    ) -> Result<(), io::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (address_type, ip, port) = match bind_addr {
            SocketAddr::V4(addr) => (
                Socks5AddrType::IPV4,
                addr.ip().octets().to_vec(),
                addr.port(),
            ),
            SocketAddr::V6(addr) => (
                Socks5AddrType::IPV6,
                addr.ip().octets().to_vec(),
                addr.port(),
            ),
        };

        let mut buf = vec![Self::VERSION, (*self).into(), 0x00, address_type.into()];
        buf.extend(ip);
        buf.extend(port.to_be_bytes());

        stream.write_all(&buf).await?;

        Ok(())
    }
}
