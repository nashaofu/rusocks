pub mod address_type;
pub mod command;
pub mod method;
pub mod reply;
pub mod request;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use async_trait::async_trait;
use reply::Socks5Reply;
use request::Socks5Request;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::{address::Address, error::Error};

use address_type::Socks5AddressType;
use command::Socks5Command;
use method::Socks5Method;

#[async_trait]
pub trait Socks5Handler {
    type ConnectStream: AsyncReadExt + AsyncWriteExt + Unpin;

    #[allow(unused_variables)]
    async fn negotiate_method(&self, methods: &[Socks5Method]) -> Result<Socks5Method, Error> {
        if methods.contains(&Socks5Method::None) {
            Ok(Socks5Method::None)
        } else {
            Err(Error::UnsupportedMethods(methods.to_vec()))
        }
    }

    #[allow(unused_variables)]
    async fn auth_by_user_pass(&self, username: &str, password: &str) -> Result<bool, Error> {
        Ok(false)
    }

    #[allow(unused_variables)]
    async fn allow_command(&self, command: &Socks5Command) -> Result<bool, Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn allow_address_type(&self, address: &Socks5AddressType) -> Result<bool, Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn connect(&self, address: &Address) -> Result<(Self::ConnectStream, SocketAddr), Error> {
        Err(Error::InternalError)
    }

    #[allow(unused_variables)]
    async fn bind<S>(
        &self,
        request: &mut Socks5Request<S>,
        bind_addr: &Address,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        Err(Error::InternalError)
    }
}

struct HandshakeError {
    err: Error,
    reply: Socks5Reply,
}

impl HandshakeError {
    pub fn new(err: Error, reply: Socks5Reply) -> Self {
        Self { err, reply }
    }
}

impl From<Error> for HandshakeError {
    fn from(err: Error) -> Self {
        Self {
            err,
            reply: Socks5Reply::Failure,
        }
    }
}
impl From<io::Error> for HandshakeError {
    fn from(err: io::Error) -> Self {
        Self {
            err: err.into(),
            reply: Socks5Reply::Failure,
        }
    }
}

/// https://datatracker.ietf.org/doc/html/rfc1928
#[derive(Clone, Debug)]
pub struct Socks5<H: Socks5Handler + Send + Sync> {
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    handler: H,
}

impl<H: Socks5Handler + Send + Sync> Socks5<H> {
    pub const VERSION: u8 = 0x05;
    pub const SUB_NEGOTIATION: u8 = 0x01;

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
        let method = match self.handshake_method(stream).await {
            Ok(val) => {
                self.handshake_method_reply(stream, val).await?;
                val
            }
            Err(err) => {
                self.handshake_method_reply(stream, Socks5Method::Unacceptable)
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
                self.handshake_request_reply(stream, err.reply, self.local_addr)
                    .await?;
                return Err(err.err);
            }
        };

        match command {
            Socks5Command::Connect => self.connect(stream, &address).await?,
            Socks5Command::Bind => self.bind(stream, &address).await?,
            Socks5Command::Associate => unimplemented!(),
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
    ) -> Result<Socks5Method, Error> {
        let method_length = stream.read_u8().await?;
        let mut methods = vec![0; method_length as usize];
        stream.read_exact(&mut methods).await?;

        let methods: Vec<Socks5Method> = methods.iter().map(|&v| v.into()).collect();

        let method = self.handler.negotiate_method(&methods).await?;

        if methods.contains(&method) {
            Ok(method)
        } else {
            Ok(Socks5Method::Unacceptable)
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
        method: Socks5Method,
    ) -> Result<(), Error>
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
    async fn handshake_auth<S>(&self, stream: &mut S, method: &Socks5Method) -> Result<bool, Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if method.eq(&Socks5Method::None) {
            return Ok(true);
        }

        let version = stream.read_u8().await?;

        if version != Self::SUB_NEGOTIATION {
            return Err(crate::error::Error::UnsupportedVersion(version));
        }

        match method {
            Socks5Method::UserPass => self.handshake_auth_user_pass(stream).await,
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
    async fn handshake_auth_user_pass<S>(&self, stream: &mut S) -> Result<bool, Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let username_length = stream.read_u8().await?;
        let mut username = vec![0; username_length as usize];
        stream.read_exact(&mut username).await?;

        let username = String::from_utf8(username).map_err(Error::Utf8BytesToStringError)?;

        let password_length = stream.read_u8().await?;
        let mut password = vec![0; password_length as usize];
        stream.read_exact(&mut password).await?;

        let password = String::from_utf8(password).map_err(Error::Utf8BytesToStringError)?;

        let is_success = self.handler.auth_by_user_pass(&username, &password).await?;

        Ok(is_success)
    }

    async fn handshake_auth_reply<S>(
        &self,
        stream: &mut S,
        method: &Socks5Method,
        is_success: bool,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        if method.eq(&Socks5Method::None) {
            return Ok(());
        }

        match method {
            Socks5Method::UserPass => {
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
    ) -> Result<(Socks5Command, Address), HandshakeError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let version = stream.read_u8().await?;
        if version != Self::VERSION {
            return Err(Error::UnsupportedVersion(version).into());
        }

        let command: Socks5Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self
            .handler
            .allow_command(&command)
            .await
            .map_err(|_| HandshakeError::new(Error::InternalError, Socks5Reply::Failure))?;

        if !is_support_command {
            return Err(HandshakeError::new(
                Error::UnsupportedCommand(command.into()),
                Socks5Reply::UnsupportedCommand,
            ));
        }

        stream.read_u8().await?;
        let address_type: Socks5AddressType = stream.read_u8().await?.try_into()?;

        let is_support_address_type = self
            .handler
            .allow_address_type(&address_type)
            .await
            .map_err(|_| HandshakeError::new(Error::InternalError, Socks5Reply::Failure))?;

        if !is_support_address_type {
            return Err(HandshakeError::new(
                Error::UnsupportedAddressType(address_type),
                Socks5Reply::UnsupportedAddressType,
            ));
        }

        let address = match address_type {
            Socks5AddressType::IPV4 => {
                let mut buf = [0; 4];
                stream.read_exact(&mut buf).await?;

                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = stream.read_u16().await?;

                Address::IPV4(SocketAddrV4::new(ip, port))
            }
            Socks5AddressType::Domain => {
                let length = stream.read_u8().await?;
                let mut buf = vec![0; length as usize];
                stream.read_exact(&mut buf).await?;

                let domain = String::from_utf8(buf).map_err(Error::Utf8BytesToStringError)?;
                let port = stream.read_u16().await?;

                Address::Domain(domain, port)
            }
            Socks5AddressType::IPV6 => {
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
    async fn handshake_request_reply<S>(
        &self,
        stream: &mut S,
        reply: Socks5Reply,
        bind_addr: SocketAddr,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let mut request = Socks5Request::new(stream);
        request.reply(reply, bind_addr).await?;

        Ok(())
    }

    pub async fn connect<S>(&self, stream: &mut S, target_addr: &Address) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let (mut socks_stream, bind_addr) = match self.handler.connect(target_addr).await {
            Ok(val) => val,
            Err(err) => {
                self.handshake_request_reply(
                    stream,
                    Socks5Reply::NetworkUnreachable,
                    self.local_addr,
                )
                .await?;
                return Err(err);
            }
        };

        self.handshake_request_reply(stream, Socks5Reply::Succeeded, bind_addr)
            .await?;

        io::copy_bidirectional(stream, &mut socks_stream).await?;

        Ok(())
    }

    async fn bind<S>(&self, stream: &mut S, bind_addr: &Address) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let mut request = Socks5Request::new(stream);

        match self.handler.bind(&mut request, bind_addr).await {
            Ok(val) => val,
            Err(err) => {
                request
                    .reply(Socks5Reply::HostUnreachable, self.local_addr)
                    .await?;

                return Err(err);
            }
        };

        Ok(())
    }
}
