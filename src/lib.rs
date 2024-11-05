pub mod address;
pub mod error;
pub mod socks4;
pub mod socks5;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use error::Error;
use socks4::{Socks4, Socks4Handler};
use socks5::{Socks5, Socks5Handler};

pub enum Socks<H: Socks4Handler + Socks5Handler + Send + Sync> {
    V4(Socks4<H>),
    V5(Socks5<H>),
}

impl<H: Socks4Handler + Socks5Handler + Send + Sync> Socks<H> {
    pub async fn from_stream<S>(
        stream: &mut S,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        handler: H,
    ) -> Result<Self, Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let version = stream.read_u8().await?;

        match version {
            0x04 => Ok(Socks::V4(Socks4::new(peer_addr, local_addr, handler))),
            0x05 => Ok(Socks::V5(Socks5::new(peer_addr, local_addr, handler))),
            v => {
                stream.shutdown().await?;
                Err(Error::UnsupportedVersion(v))
            }
        }
    }

    pub async fn accept<S>(&mut self, stream: &mut S) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        match self {
            Socks::V4(socks4) => socks4.accept(stream).await,
            Socks::V5(socks5) => socks5.accept(stream).await,
        }
    }
}
