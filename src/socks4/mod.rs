pub mod command;
pub mod reply;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::{address::Address, error::Error, SocksHandler};

use command::Command;
use reply::Reply;

#[derive(Clone, Debug)]
pub struct Socks4<H: SocksHandler + Send + Sync> {
    peer_addr: SocketAddr,
    #[allow(dead_code)]
    local_addr: SocketAddr,
    handler: H,
}

impl<H: SocksHandler + Send + Sync> Socks4<H> {
    pub const VERSION: u8 = 0x04;

    pub fn new(peer_addr: SocketAddr, local_addr: SocketAddr, handler: H) -> Self {
        Self {
            peer_addr,
            local_addr,
            handler,
        }
    }
    pub async fn accept<S>(&mut self, stream: &mut S) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        match self.handshake(stream).await {
            Ok(_) => Ok(()),
            Err(err) => {
                stream.shutdown().await?;
                Err(err)
            }
        }
    }
    pub async fn handshake<S>(&mut self, stream: &mut S) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (command, address, user_id) = match self.handshake_request(stream).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::Rejected)
                    .await?;

                return Err(err);
            }
        };

        let is_success = match self.handler.socks4_auth(&user_id, &self.peer_addr).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::Rejected)
                    .await?;

                return Err(err);
            }
        };

        if !is_success {
            self.handshake_request_reply(stream, Reply::Rejected)
                .await?;

            return Err(Error::AuthenticationFailed.into());
        }

        match command {
            Command::Connect => self.connect(stream, address).await,
            Command::Bind => self.bind(stream, address).await,
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
    ) -> Result<(Command, Address, String), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let command: Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self.handler.socks4_handshake_command(&command).await?;

        if !is_support_command {
            return Err(Error::UnsupportedCommand(command.into()).into());
        }

        let port = stream.read_u16().await?;

        let mut buf = [0; 4];
        stream.read_exact(&mut buf).await?;

        let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);

        let address = Address::IPV4(SocketAddrV4::new(ip, port));

        let mut buf = Vec::new();
        loop {
            let val = stream.read_u8().await?;
            if val == 0x00 {
                break;
            } else {
                buf.push(val);
            }
        }

        let user_id = String::from_utf8(buf).map_err(|err| Error::Utf8BytesToStringError(err))?;

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
    async fn handshake_request_reply<S>(&self, stream: &mut S, reply: Reply) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (ip, port) = match self.peer_addr {
            SocketAddr::V4(addr) => (addr.ip().octets().to_vec(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().octets().to_vec(), addr.port()),
        };

        let mut buf = vec![0x00, reply.into()];
        buf.extend(ip);
        buf.extend(port.to_le_bytes());

        stream.write_all(&buf).await?;

        if reply != Reply::Granted {
            stream.shutdown().await?;
        }

        Ok(())
    }

    async fn connect<S>(&self, stream: &mut S, address: Address) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut socks_stream = match self.handler.socks4_command_connect(&address).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::Rejected)
                    .await?;

                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Reply::Granted).await?;
        io::copy_bidirectional(stream, &mut socks_stream).await?;

        Ok(())
    }

    async fn bind<S>(&self, stream: &mut S, address: Address) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        match self.handler.socks4_command_bind(&address).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::Rejected)
                    .await?;

                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Reply::Granted).await?;

        Ok(())
    }
}
