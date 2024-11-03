use std::net::SocketAddr;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use super::{address_type::AddressType, reply::Reply};

pub struct Request<S> {
    pub stream: S,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin + Send> Request<S> {
    pub const VERSION: u8 = 0x05;
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn reply(&mut self, reply: Reply, bind_addr: SocketAddr) -> Result<(), io::Error> {
        let (address_type, ip, port) = match bind_addr {
            SocketAddr::V4(addr) => (AddressType::IPV4, addr.ip().octets().to_vec(), addr.port()),
            SocketAddr::V6(addr) => (AddressType::IPV6, addr.ip().octets().to_vec(), addr.port()),
        };

        let mut buf = vec![Self::VERSION, reply.into(), 0x00, address_type.into()];
        buf.extend(ip);
        buf.extend(port.to_be_bytes());

        self.stream.write_all(&buf).await?;

        Ok(())
    }
}
