pub mod address_type;
pub mod command;
pub mod method;
pub mod reply;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use reply::Reply;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::{address::Address, error::Error, SocksHandler};

use address_type::AddressType;
use command::Command;
use method::Method;

struct HandshakeError {
    err: Error,
    reply: Reply,
}

impl HandshakeError {
    pub fn new(err: Error, reply: Reply) -> Self {
        Self { err, reply }
    }
}

impl From<Error> for HandshakeError {
    fn from(err: Error) -> Self {
        Self {
            err,
            reply: Reply::Failure,
        }
    }
}
impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> Self {
        Self {
            err: err.into(),
            reply: Reply::Failure,
        }
    }
}

/// https://datatracker.ietf.org/doc/html/rfc1928
#[derive(Clone, Debug)]
pub struct Socks5<H: SocksHandler + Send + Sync> {
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    handler: H,
}

impl<H: SocksHandler + Send + Sync> Socks5<H> {
    pub const VERSION: u8 = 0x05;
    pub const SUB_NEGOTIATION: u8 = 0x01;

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
        let method = match self.handshake_method(stream).await {
            Ok(val) => {
                self.handshake_method_reply(stream, val).await?;
                val
            }
            Err(err) => {
                self.handshake_method_reply(stream, Method::Unacceptable)
                    .await?;
                return Err(err);
            }
        };

        match self.handshake_auth(stream, &method).await {
            Ok(is_success) => {
                self.handshake_auth_reply(stream, &method, is_success)
                    .await?;
            }
            Err(err) => {
                self.handshake_auth_reply(stream, &method, false).await?;
                return Err(err);
            }
        };

        let (command, address) = match self.handshake_request(stream).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, err.reply).await?;
                return Err(err.err.into());
            }
        };

        match command {
            Command::Connect => self.connect(stream, &address).await?,
            Command::Bind => self.bind(stream, &address).await?,
            _ => todo!(),
        };

        Ok(())
    }

    /// The client connects to the server, and sends a version
    /// identifier/method selection message:
    ///  
    ///                     +----+----------+----------+
    ///                     |VER | NMETHODS | METHODS  |
    ///                     +----+----------+----------+
    ///                     | 1  |    1     | 1 to 255 |
    ///                     +----+----------+----------+
    ///  
    /// The VER field is set to X'05' for this version of the protocol.  The
    /// NMETHODS field contains the number of method identifier octets that
    /// appear in the METHODS field.
    async fn handshake_method<S: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<Method, H::Error> {
        let method_length = stream.read_u8().await?;
        let mut methods = vec![0; method_length as usize];
        stream.read_exact(&mut methods).await?;

        let methods: Vec<Method> = methods.iter().map(|&v| v.into()).collect();

        let method = self.handler.socks5_handshake_method(&methods).await?;

        if methods.contains(&method) {
            Ok(method)
        } else {
            Ok(Method::Unacceptable)
        }
    }

    /// The server selects from one of the methods given in METHODS, and
    /// sends a METHOD selection message:
    ///  
    ///                           +----+--------+
    ///                           |VER | METHOD |
    ///                           +----+--------+
    ///                           | 1  |   1    |
    ///                           +----+--------+
    ///  
    /// If the selected METHOD is X'FF', none of the methods listed by the
    /// client are acceptable, and the client MUST close the connection.
    ///  
    /// The values currently defined for METHOD are:
    ///  
    ///            o  X'00' NO AUTHENTICATION REQUIRED
    ///            o  X'01' GSSAPI
    ///            o  X'02' USERNAME/PASSWORD
    ///            o  X'03' to X'7F' IANA ASSIGNED
    ///            o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    ///            o  X'FF' NO ACCEPTABLE METHODS
    ///  
    /// The client and server then enter a method-specific sub-negotiation.
    async fn handshake_method_reply<S>(
        &self,
        stream: &mut S,
        method: Method,
    ) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        stream.write_all(&[Self::VERSION, method.into()]).await?;

        Ok(())
    }

    /// GSS-API method
    /// +------+------+------+.......................+
    /// + ver  | mtyp | len  |       token           |
    /// +------+------+------+.......................+
    /// + 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
    /// +------+------+------+.......................+
    async fn handshake_auth<S>(&self, stream: &mut S, method: &Method) -> Result<bool, H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if method.eq(&Method::None) {
            return Ok(true);
        }

        let version = stream.read_u8().await?;

        if version != Self::SUB_NEGOTIATION {
            return Err(crate::error::Error::UnsupportedVersion(version).into());
        }

        match method {
            Method::UserPass => self.handshake_auth_username_password(stream).await,
            _ => todo!(),
        }
    }

    /// username/password method
    /// +----+------+----------+------+----------+
    /// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    /// +----+------+----------+------+----------+
    /// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    /// +----+------+----------+------+----------+
    ///
    async fn handshake_auth_username_password<S>(&self, stream: &mut S) -> Result<bool, H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let username_length = stream.read_u8().await?;
        let mut username = vec![0; username_length as usize];
        stream.read_exact(&mut username).await?;

        let username =
            String::from_utf8(username).map_err(|err| Error::Utf8BytesToStringError(err))?;

        let password_length = stream.read_u8().await?;
        let mut password = vec![0; password_length as usize];
        stream.read_exact(&mut password).await?;

        let password =
            String::from_utf8(password).map_err(|err| Error::Utf8BytesToStringError(err))?;

        let is_success = self
            .handler
            .socks5_auth_username_password(username, password)
            .await?;

        Ok(is_success)
    }

    async fn handshake_auth_reply<S>(
        &self,
        stream: &mut S,
        method: &Method,
        is_success: bool,
    ) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if method.eq(&Method::None) {
            return Ok(());
        }

        match method {
            Method::UserPass => {
                stream
                    .write_all(&[Self::SUB_NEGOTIATION, is_success.into()])
                    .await?;
                Ok(())
            }
            _ => todo!(),
        }
    }

    /// The SOCKS request is formed as follows:
    ///     +----+-----+-------+------+----------+----------+
    ///    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///    +----+-----+-------+------+----------+----------+
    ///    | 1  |  1  | X'00' |  1   | Variable |    2     |
    ///    +----+-----+-------+------+----------+----------+
    ///
    /// Where:
    ///
    ///      o  VER    protocol version: X'05'
    ///      o  CMD
    ///         o  CONNECT X'01'
    ///         o  BIND X'02'
    ///         o  UDP ASSOCIATE X'03'
    ///      o  RSV    RESERVED
    ///      o  ATYP   address type of following address
    ///         o  IP V4 address: X'01'
    ///         o  DOMAINNAME: X'03'
    ///         o  IP V6 address: X'04'
    ///      o  DST.ADDR       desired destination address
    ///      o  DST.PORT desired destination port in network octet
    ///         order
    async fn handshake_request<S>(
        &self,
        stream: &mut S,
    ) -> Result<(Command, Address), HandshakeError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let version = stream.read_u8().await?;
        if version != Self::VERSION {
            return Err(Error::UnsupportedVersion(version).into());
        }

        let command: Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self
            .handler
            .socks5_handshake_command(&command)
            .await
            .map_err(|_| HandshakeError::new(Error::InternalError, Reply::Failure))?;

        if !is_support_command {
            return Err(HandshakeError::new(
                Error::UnsupportedCommand(command.into()),
                Reply::UnsupportedCommand,
            ));
        }

        stream.read_u8().await?;
        let address_type: AddressType = stream.read_u8().await?.try_into()?;

        let address = match address_type {
            AddressType::IPV4 => {
                let mut buf = [0; 4];
                stream.read_exact(&mut buf).await?;

                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = stream.read_u16().await?;

                Address::IPV4(SocketAddrV4::new(ip, port))
            }
            AddressType::Domain => {
                let length = stream.read_u8().await?;
                let mut buf = vec![0; length as usize];
                stream.read_exact(&mut buf).await?;

                let domain =
                    String::from_utf8(buf).map_err(|err| Error::Utf8BytesToStringError(err))?;
                let port = stream.read_u16().await?;

                Address::Domain(domain, port)
            }
            AddressType::IPV6 => {
                let mut buf = [0; 16];
                stream.read_exact(&mut buf).await?;

                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([buf[0], buf[1]]),
                    u16::from_be_bytes([buf[2], buf[3]]),
                    u16::from_be_bytes([buf[4], buf[5]]),
                    u16::from_be_bytes([buf[6], buf[7]]),
                    u16::from_be_bytes([buf[8], buf[9]]),
                    u16::from_be_bytes([buf[10], buf[11]]),
                    u16::from_be_bytes([buf[12], buf[13]]),
                    u16::from_be_bytes([buf[14], buf[15]]),
                );
                let port = stream.read_u16().await?;

                Address::IPV6(SocketAddrV6::new(ip, port, 0, 0))
            }
        };

        let is_support_address = self
            .handler
            .socks5_handshake_address(&address)
            .await
            .map_err(|_| HandshakeError::new(Error::InternalError, Reply::Failure))?;

        if !is_support_address {
            return Err(HandshakeError::new(
                Error::UnsupportedAddress(address),
                Reply::UnsupportedAddress,
            ));
        }

        Ok((command, address))
    }

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
    async fn handshake_request_reply<S>(&self, stream: &mut S, reply: Reply) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let (address_type, ip, port) = match self.local_addr {
            SocketAddr::V4(addr) => (AddressType::IPV4, addr.ip().octets().to_vec(), addr.port()),
            SocketAddr::V6(addr) => (AddressType::IPV6, addr.ip().octets().to_vec(), addr.port()),
        };

        let mut buf = vec![Self::VERSION, reply.into(), 0x00, address_type.into()];
        buf.extend(ip);
        buf.extend(port.to_le_bytes());

        stream.write_all(&buf).await?;

        Ok(())
    }

    pub async fn connect<S>(&self, stream: &mut S, address: &Address) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let mut socks_stream = match self.handler.socks5_command_connect(&address).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::NetworkUnreachable)
                    .await?;
                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Reply::Succeeded)
            .await?;

        io::copy_bidirectional(stream, &mut socks_stream).await?;

        Ok(())
    }

    async fn bind<S>(&self, stream: &mut S, address: &Address) -> Result<(), H::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        match self.handler.socks5_command_bind(&address).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(stream, Reply::HostUnreachable)
                    .await?;

                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Reply::Succeeded)
            .await?;

        Ok(())
    }
}
