use std::net::SocketAddr;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use super::reply::Socks4Reply;

pub struct Socks4Request<S> {
    pub stream: S,
}

impl<S: AsyncReadExt + AsyncWriteExt + Unpin + Send> Socks4Request<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    pub async fn reply(
        &mut self,
        reply: Socks4Reply,
        bind_addr: SocketAddr,
    ) -> Result<(), io::Error> {
        let (ip, port) = match bind_addr {
            SocketAddr::V4(addr) => (addr.ip().octets().to_vec(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().octets().to_vec(), addr.port()),
        };

        let mut buf = vec![0x00, reply.into()];
        buf.extend(port.to_be_bytes());
        buf.extend(ip);

        self.stream.write_all(&buf).await?;

        Ok(())
    }
}
