pub mod addr;
pub mod error;
pub mod socks4;
pub mod socks5;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use error::SocksError;
use socks4::{Socks4, Socks4Handler};
use socks5::{Socks5, Socks5Handler};

pub enum Socks<H: Socks4Handler + Socks5Handler + Send + Sync> {
    V4(Socks4<H>),
    V5(Socks5<H>),
}

impl<H: Socks4Handler + Socks5Handler + Send + Sync> Socks<H> {
    pub async fn from_stream(stream: &mut TcpStream, handler: H) -> Result<Self, SocksError> {
        let version = stream.read_u8().await?;
        let peer_addr = stream.peer_addr()?;
        let local_addr = stream.local_addr()?;

        match version {
            0x04 => Ok(Socks::V4(Socks4::new(peer_addr, local_addr, handler))),
            0x05 => Ok(Socks::V5(Socks5::new(peer_addr, local_addr, handler))),
            v => {
                stream.shutdown().await?;
                Err(SocksError::UnsupportedVersion(v))
            }
        }
    }

    pub async fn execute(&mut self, stream: &mut TcpStream) -> Result<(), SocksError> {
        match self {
            Socks::V4(socks4) => socks4.execute(stream).await,
            Socks::V5(socks5) => socks5.execute(stream).await,
        }
    }
}
