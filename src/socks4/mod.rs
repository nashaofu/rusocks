pub mod command;
pub mod reply;

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use async_trait::async_trait;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{addr::SocksAddr, error::SocksError};

use command::Socks4Command;
use reply::Socks4Reply;

#[async_trait]
pub trait Socks4Handler {
    type Error: From<SocksError> + From<io::Error> + Error;

    #[allow(unused_variables)]
    async fn allow_command(&self, command: &Socks4Command) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn identd(&self, user_id: &str, peer_addr: &SocketAddr) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn connect(
        &self,
        stream: &mut TcpStream,
        dest_addr: &SocksAddr,
    ) -> Result<(), Self::Error> {
        let mut connect_stream = TcpStream::connect((dest_addr.domain(), dest_addr.port())).await?;
        let bind_addr = connect_stream.local_addr()?;
        Socks4Reply::Granted.reply(stream, bind_addr).await?;

        io::copy_bidirectional(stream, &mut connect_stream).await?;

        Ok(())
    }

    async fn bind(&self, stream: &mut TcpStream, dest_addr: &SocksAddr) -> Result<(), Self::Error> {
        let listener = TcpListener::bind((dest_addr.domain(), dest_addr.port())).await?;
        let bind_addr = listener.local_addr()?.clone();
        Socks4Reply::Granted.reply(stream, bind_addr).await?;

        let (mut bind_stream, _) = listener.accept().await?;

        io::copy_bidirectional(stream, &mut bind_stream).await?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Socks4<H: Socks4Handler + Send + Sync> {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    handler: H,
}

impl<H: Socks4Handler + Send + Sync> Socks4<H> {
    pub const VERSION: u8 = 0x04;

    pub fn new(peer_addr: SocketAddr, local_addr: SocketAddr, handler: H) -> Self {
        Self {
            peer_addr,
            local_addr,
            handler,
        }
    }
    pub async fn execute(&mut self, stream: &mut TcpStream) -> Result<(), SocksError> {
        match self.negotiate(stream).await {
            Ok(_) => Ok(()),
            Err(err) => {
                stream.shutdown().await?;
                Err(SocksError::ExecuteError(err.to_string()))
            }
        }
    }
    pub async fn negotiate(&mut self, stream: &mut TcpStream) -> Result<(), H::Error> {
        let (command, dest_addr, user_id) = match self.negotiate_request(stream).await {
            Ok(val) => val,
            Err(err) => {
                Socks4Reply::Rejected.reply(stream, self.local_addr).await?;

                return Err(err);
            }
        };

        let is_success = match self.handler.identd(&user_id, &self.peer_addr).await {
            Ok(val) => val,
            Err(err) => {
                Socks4Reply::Rejected.reply(stream, self.local_addr).await?;

                return Err(err);
            }
        };

        if !is_success {
            Socks4Reply::Rejected.reply(stream, self.local_addr).await?;

            return Err(SocksError::AuthFailed.into());
        }

        match command {
            Socks4Command::Connect => self.connect(stream, dest_addr).await,
            Socks4Command::Bind => self.bind(stream, dest_addr).await,
        }
    }

    /// +----+----+----+----+----+----+----+----+----+----+....+----+
    /// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
    /// +----+----+----+----+----+----+----+----+----+----+....+----+
    ///    1    1      2              4           variable       1
    ///
    /// VN is the SOCKS protocol version number and should be 4. CD is the
    /// SOCKS command code and should be 1 for CONNECT request. NULL is a byte
    /// of all zero bits.
    async fn negotiate_request(
        &self,
        stream: &mut TcpStream,
    ) -> Result<(Socks4Command, SocksAddr, String), H::Error> {
        let command: Socks4Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self.handler.allow_command(&command).await?;

        if !is_support_command {
            return Err(SocksError::UnsupportedCommand(command.into()).into());
        }

        let port = stream.read_u16().await?;

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await?;

        let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);

        let ipv4_addr = SocksAddr::IPV4(SocketAddrV4::new(ip, port));

        let mut buf = Vec::new();
        loop {
            let val = stream.read_u8().await?;
            if val == 0x00 {
                break;
            } else {
                buf.push(val);
            }
        }

        let user_id = String::from_utf8(buf).map_err(SocksError::Utf8BytesToStringError)?;

        // socks4a 协议，如果ip地址是0.0.0.x的形式，则需要读取域名信息。注意x必须非0
        // https://www.openssh.com/txt/socks4a.protocol
        let ip_bytes = ip.octets();
        let dist_addr =
            if ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0 {
                let mut buf = Vec::new();
                loop {
                    let val = stream.read_u8().await?;
                    if val == 0x00 {
                        break;
                    } else {
                        buf.push(val);
                    }
                }

                let domain = String::from_utf8(buf).map_err(SocksError::Utf8BytesToStringError)?;
                SocksAddr::Domain(domain, port)
            } else {
                ipv4_addr
            };

        Ok((command, dist_addr, user_id))
    }

    async fn connect(&self, stream: &mut TcpStream, dist_addr: SocksAddr) -> Result<(), H::Error> {
        match self.handler.connect(stream, &dist_addr).await {
            Ok(_) => Ok(()),
            Err(err) => {
                Socks4Reply::Rejected.reply(stream, self.local_addr).await?;

                Err(err)
            }
        }
    }

    async fn bind(&self, stream: &mut TcpStream, dist_addr: SocksAddr) -> Result<(), H::Error> {
        match self.handler.bind(stream, &dist_addr).await {
            Ok(_) => Ok(()),
            Err(err) => {
                Socks4Reply::Rejected.reply(stream, self.local_addr).await?;

                Err(err)
            }
        }
    }
}
