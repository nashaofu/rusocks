pub mod address;
pub mod error;
pub mod socks4;
pub mod socks5;

use core::fmt;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use address::Address;
use error::Error;
use socks4::Socks4;
use socks5::{method::Method, Socks5};

#[async_trait]
pub trait SocksHandler: Sized + Send {
    type Error: From<Error> + From<io::Error> + Send + fmt::Debug;
    type Stream: AsyncReadExt + AsyncWriteExt + Unpin;

    #[allow(unused_variables)]
    async fn socks4_handshake_command(
        &self,
        command: &socks4::command::Command,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn socks4_auth(
        &self,
        user_id: &String,
        peer_addr: &SocketAddr,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn socks5_handshake_method(&self, methods: &Vec<Method>) -> Result<Method, Self::Error> {
        Ok(Method::None)
    }

    #[allow(unused_variables)]
    async fn socks5_auth_username_password(
        &self,
        username: String,
        password: String,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn socks5_auth_gssapi(
        &self,
        username: String,
        password: String,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    #[allow(unused_variables)]
    async fn socks5_handshake_command(
        &self,
        command: &socks5::command::Command,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn socks5_handshake_address(&self, address: &Address) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn socks4_command_connect(&self, address: &Address) -> Result<Self::Stream, Self::Error>;
    async fn socks4_command_bind(&self, address: &Address) -> Result<(), Self::Error>;
    async fn socks5_command_connect(&self, address: &Address) -> Result<Self::Stream, Self::Error>;
    async fn socks5_command_bind(&self, address: &Address) -> Result<(), Self::Error>;
}

pub enum Socks<H: SocksHandler + Send + Sync> {
    V4(Socks4<H>),
    V5(Socks5<H>),
}

impl<H: SocksHandler + Send + Sync> Socks<H> {
    pub async fn from_stream<S>(
        stream: &mut S,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        handler: H,
    ) -> Result<Self, H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let version = stream.read_u8().await?;

        match version {
            0x04 => Ok(Socks::V4(Socks4::new(peer_addr, local_addr, handler))),
            0x05 => Ok(Socks::V5(Socks5::new(peer_addr, local_addr, handler))),
            v => Err(Error::UnsupportedVersion(v).into()),
        }
    }

    pub async fn accept<S>(&mut self, stream: &mut S) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        match self {
            Socks::V5(socks5) => socks5.accept(stream).await,
            Socks::V4(socks4) => socks4.accept(stream).await,
        }
    }
}
