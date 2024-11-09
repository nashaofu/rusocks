use std::net::SocketAddr;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

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

impl Socks4Reply {
    /// +----+----+----+----+----+----+----+----+
    /// | VN | CD | DSTPORT |      DSTIP        |
    /// +----+----+----+----+----+----+----+----+
    ///   1    1      2              4
    ///
    /// VN is the version of the reply code and should be 0. CD is the result
    /// code with one of the following values:
    ///
    /// 90: request granted
    /// 91: request rejected or failed
    /// 92: request rejected becasue SOCKS server cannot connect to identd on the client
    /// 93: request rejected because the client program and identd report different user-ids
    pub async fn reply<S>(&mut self, stream: &mut S, bind_addr: SocketAddr) -> Result<(), io::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (ip, port) = match bind_addr {
            SocketAddr::V4(addr) => (addr.ip().octets().to_vec(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().octets().to_vec(), addr.port()),
        };

        let mut buf = vec![0x00, (*self).into()];
        buf.extend(port.to_be_bytes());
        buf.extend(ip);

        stream.write_all(&buf).await?;

        Ok(())
    }
}
