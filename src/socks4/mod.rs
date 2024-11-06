pub mod command;
pub mod reply;
pub mod request;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use async_trait::async_trait;
use request::Socks4Request;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::{address::Address, error::Error};

use command::Socks4Command;
use reply::Socks4Reply;

#[async_trait]
pub trait Socks4Handler {
    type ConnectStream: AsyncReadExt + AsyncWriteExt + Unpin;

    #[allow(unused_variables)]
    async fn allow_command(&self, command: &Socks4Command) -> Result<bool, Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn identd(&self, user_id: &str, peer_addr: &SocketAddr) -> Result<bool, Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn connect(&self, address: &Address) -> Result<(Self::ConnectStream, SocketAddr), Error> {
        Err(Error::NotImplemented)
    }

    #[allow(unused_variables)]
    async fn bind<S>(
        &self,
        request: &mut Socks4Request<S>,
        bind_addr: &Address,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        Err(Error::NotImplemented)
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
    pub async fn accept<S>(&mut self, stream: &mut S) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        match self.handshake(stream).await {
            Ok(_) => Ok(()),
            Err(err) => {
                stream.shutdown().await?;
                Err(err)
            }
        }
    }
    pub async fn handshake<S>(&mut self, stream: &mut S) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (command, address, user_id) = match self.handshake_request(stream).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Socks4Reply::Rejected, self.local_addr)
                    .await?;

                return Err(err);
            }
        };

        let is_success = match self.handler.identd(&user_id, &self.peer_addr).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Socks4Reply::Rejected, self.local_addr)
                    .await?;

                return Err(err);
            }
        };

        if !is_success {
            self.handshake_request_reply(stream, Socks4Reply::Rejected, self.local_addr)
                .await?;

            return Err(Error::AuthFailed);
        }

        match command {
            Socks4Command::Connect => self.connect(stream, address).await,
            Socks4Command::Bind => self.bind(stream, address).await,
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
    async fn handshake_request<S>(
        &self,
        stream: &mut S,
    ) -> Result<(Socks4Command, Address, String), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let command: Socks4Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self.handler.allow_command(&command).await?;

        if !is_support_command {
            return Err(Error::UnsupportedCommand(command.into()));
        }

        let port = stream.read_u16().await?;

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await?;

        let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);

        let ipv4_address = Address::IPV4(SocketAddrV4::new(ip, port));

        let mut buf = Vec::new();
        loop {
            let val = stream.read_u8().await?;
            if val == 0x00 {
                break;
            } else {
                buf.push(val);
            }
        }

        let user_id = String::from_utf8(buf).map_err(Error::Utf8BytesToStringError)?;

        // socks4a 协议，如果ip地址是0.0.0.x的形式，则需要读取域名信息。注意x必须非0
        // https://www.openssh.com/txt/socks4a.protocol
        let ip_bytes = ip.octets();
        let address =
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

                let domain = String::from_utf8(buf).map_err(Error::Utf8BytesToStringError)?;
                Address::Domain(domain, port)
            } else {
                ipv4_address
            };

        Ok((command, address, user_id))
    }

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
    async fn handshake_request_reply<S>(
        &self,
        stream: &mut S,
        reply: Socks4Reply,
        bind_addr: SocketAddr,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let mut request = Socks4Request::new(stream);
        request.reply(reply, bind_addr).await?;

        Ok(())
    }

    async fn connect<S>(&self, stream: &mut S, address: Address) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (mut socks_stream, bind_addr) = match self.handler.connect(&address).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Socks4Reply::Rejected, self.local_addr)
                    .await?;

                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Socks4Reply::Granted, bind_addr)
            .await?;
        io::copy_bidirectional(stream, &mut socks_stream).await?;

        Ok(())
    }

    async fn bind<S>(&self, stream: &mut S, bind_addr: Address) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let mut request = Socks4Request::new(stream);

        match self.handler.bind(&mut request, &bind_addr).await {
            Ok(val) => val,
            Err(err) => {
                request
                    .reply(Socks4Reply::Rejected, self.local_addr)
                    .await?;

                return Err(err);
            }
        };

        Ok(())
    }
}
