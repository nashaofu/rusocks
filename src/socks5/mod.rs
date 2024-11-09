pub mod addr_type;
pub mod command;
pub mod method;
pub mod reply;

use std::{
    error::Error,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use async_trait::async_trait;
use reply::Socks5Reply;
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{addr::SocksAddr, error::SocksError};

use addr_type::Socks5AddrType;
use command::Socks5Command;
use method::Socks5Method;

#[async_trait]
pub trait Socks5Handler {
    type Error: From<SocksError> + From<io::Error> + Error;

    async fn negotiate_method(
        &self,
        methods: &[Socks5Method],
    ) -> Result<Socks5Method, Self::Error> {
        if methods.contains(&Socks5Method::None) {
            Ok(Socks5Method::None)
        } else {
            Err(SocksError::UnsupportedMethods(methods.to_vec()).into())
        }
    }

    #[allow(unused_variables)]
    async fn auth_by_user_pass(&self, username: &str, password: &str) -> Result<bool, Self::Error> {
        Ok(false)
    }

    #[allow(unused_variables)]
    async fn allow_command(&self, command: &Socks5Command) -> Result<bool, Self::Error> {
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn allow_addr_type(&self, address: &Socks5AddrType) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn connect(
        &self,
        stream: &mut TcpStream,
        dest_addr: &SocksAddr,
    ) -> Result<(), Self::Error> {
        let mut connect_stream = TcpStream::connect((dest_addr.domain(), dest_addr.port())).await?;
        let bind_addr = connect_stream.local_addr()?;
        Socks5Reply::Succeeded.reply(stream, bind_addr).await?;

        io::copy_bidirectional(stream, &mut connect_stream).await?;

        Ok(())
    }

    async fn bind(&self, stream: &mut TcpStream, dest_addr: &SocksAddr) -> Result<(), Self::Error> {
        let listener = TcpListener::bind((dest_addr.domain(), dest_addr.port())).await?;
        let bind_addr = listener.local_addr()?.clone();
        Socks5Reply::Succeeded.reply(stream, bind_addr).await?;

        let (mut bind_stream, peer_addr) = listener.accept().await?;

        Socks5Reply::Succeeded.reply(stream, peer_addr).await?;
        io::copy_bidirectional(stream, &mut bind_stream).await?;

        Ok(())
    }

    #[allow(unused_variables)]
    async fn associate(
        &self,
        stream: &mut TcpStream,
        dest_addr: &SocksAddr,
    ) -> Result<(), Self::Error> {
        // let udp_socket = UdpSocket::bind((dest_addr.domain(), dest_addr.port())).await?;
        // let bind_addr = udp_socket.local_addr()?.clone();
        // Socks5Reply::Succeeded.reply(stream, bind_addr).await?;

        // loop {
        //     // +----+------+------+----------+----------+----------+
        //     // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        //     // +----+------+------+----------+----------+----------+
        //     // | 2  |  1   |  1   | Variable |    2     | Variable |
        //     // +----+------+------+----------+----------+----------+
        //     //     The fields in the UDP request header are:

        //     //   o  RSV  Reserved X'0000'
        //     //   o  FRAG    Current fragment number
        //     //   o  ATYP    address type of following addresses:
        //     //      o  IP V4 address: X'01'
        //     //      o  DOMAINNAME: X'03'
        //     //      o  IP V6 address: X'04'
        //     //   o  DST.ADDR       desired destination address
        //     //   o  DST.PORT       desired destination port
        //     //   o  DATA     user data

        //     let mut buf = vec![0u8; 65535];
        //     if let Ok((size, peer_addr)) = udp_socket.recv_from(&mut buf).await {
        //         if buf[0] != 0 || buf[1] != 0 {
        //             continue;
        //         }

        //         let addr_type: Socks5AddrType = buf[3].try_into()?;

        //         let (dist_addr, offset) = match addr_type {
        //             Socks5AddrType::IPV4 => {
        //                 let mut buf = [0; 4];
        //                 stream.read_exact(&mut buf).await?;

        //                 let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
        //                 let port = stream.read_u16().await?;

        //                 (SocksAddr::IPV4(SocketAddrV4::new(ip, port)), 3 + 4)
        //             }
        //             Socks5AddrType::Domain => {
        //                 let length = stream.read_u8().await?;
        //                 let mut buf = vec![0; length as usize];
        //                 stream.read_exact(&mut buf).await?;

        //                 let domain =
        //                     String::from_utf8(buf).map_err(SocksError::Utf8BytesToStringError)?;
        //                 let port = stream.read_u16().await?;

        //                 (SocksAddr::Domain(domain, port), 3 + length)
        //             }
        //             Socks5AddrType::IPV6 => {
        //                 let mut buf = [0; 16];
        //                 stream.read_exact(&mut buf).await?;

        //                 let ip = Ipv6Addr::new(
        //                     u16::from_be_bytes([buf[0], buf[1]]),
        //                     u16::from_be_bytes([buf[2], buf[3]]),
        //                     u16::from_be_bytes([buf[4], buf[5]]),
        //                     u16::from_be_bytes([buf[6], buf[7]]),
        //                     u16::from_be_bytes([buf[8], buf[9]]),
        //                     u16::from_be_bytes([buf[10], buf[11]]),
        //                     u16::from_be_bytes([buf[12], buf[13]]),
        //                     u16::from_be_bytes([buf[14], buf[15]]),
        //                 );
        //                 let port = stream.read_u16().await?;

        //                 (SocksAddr::IPV6(SocketAddrV6::new(ip, port, 0, 0)), 3 + 16)
        //             }
        //         };
        //         let data = &buf[offset as usize..size];
        //         udp_socket.send_to(buf, dist_addr).await.unwrap();
        //     }
        // }

        // Ok(())
        unimplemented!()
    }
}

struct HandshakeError {
    err: SocksError,
    reply: Socks5Reply,
}

impl HandshakeError {
    pub fn new(err: SocksError, reply: Socks5Reply) -> Self {
        Self { err, reply }
    }
}

impl From<SocksError> for HandshakeError {
    fn from(err: SocksError) -> Self {
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
        let method = match self.negotiate_method(stream).await {
            Ok(val) => {
                self.negotiate_method_reply(stream, val).await?;
                val
            }
            Err(err) => {
                self.negotiate_method_reply(stream, Socks5Method::Unacceptable)
                    .await?;
                return Err(err);
            }
        };

        match self.auth(stream, &method).await {
            Ok(is_success) => {
                self.auth_reply(stream, &method, is_success).await?;
            }
            Err(err) => {
                self.auth_reply(stream, &method, false).await?;
                return Err(err);
            }
        };

        let (command, address) = match self.negotiate_request(stream).await {
            Ok(val) => val,
            Err(err) => {
                err.reply.reply(stream, self.local_addr).await?;
                return Err(err.err.into());
            }
        };

        match command {
            Socks5Command::Connect => self.connect(stream, &address).await?,
            Socks5Command::Bind => self.bind(stream, &address).await?,
            Socks5Command::Associate => self.associate(stream, &address).await?,
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
    async fn negotiate_method(&self, stream: &mut TcpStream) -> Result<Socks5Method, H::Error> {
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
    async fn negotiate_method_reply(
        &self,
        stream: &mut TcpStream,
        method: Socks5Method,
    ) -> Result<(), H::Error> {
        stream.write_all(&[Self::VERSION, method.into()]).await?;

        Ok(())
    }

    /// GSS-API method
    /// +------+------+------+.......................+
    /// + ver  | mtyp | len  |       token           |
    /// +------+------+------+.......................+
    /// + 0x01 | 0x01 | 0x02 | up to 2^16 - 1 octets |
    /// +------+------+------+.......................+
    async fn auth(&self, stream: &mut TcpStream, method: &Socks5Method) -> Result<bool, H::Error> {
        if method.eq(&Socks5Method::None) {
            return Ok(true);
        }

        let version = stream.read_u8().await?;

        if version != Self::SUB_NEGOTIATION {
            return Err(crate::error::SocksError::UnsupportedVersion(version).into());
        }

        match method {
            Socks5Method::UserPass => self.auth_by_user_pass(stream).await,
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
    async fn auth_by_user_pass(&self, stream: &mut TcpStream) -> Result<bool, H::Error> {
        let username_length = stream.read_u8().await?;
        let mut username = vec![0; username_length as usize];
        stream.read_exact(&mut username).await?;

        let username = String::from_utf8(username).map_err(SocksError::Utf8BytesToStringError)?;

        let password_length = stream.read_u8().await?;
        let mut password = vec![0; password_length as usize];
        stream.read_exact(&mut password).await?;

        let password = String::from_utf8(password).map_err(SocksError::Utf8BytesToStringError)?;

        let is_success = self.handler.auth_by_user_pass(&username, &password).await?;

        Ok(is_success)
    }

    async fn auth_reply(
        &self,
        stream: &mut TcpStream,
        method: &Socks5Method,
        is_success: bool,
    ) -> Result<(), H::Error> {
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
    async fn negotiate_request(
        &self,
        stream: &mut TcpStream,
    ) -> Result<(Socks5Command, SocksAddr), HandshakeError> {
        let version = stream.read_u8().await?;
        if version != Self::VERSION {
            return Err(SocksError::UnsupportedVersion(version).into());
        }

        let command: Socks5Command = stream.read_u8().await?.try_into()?;

        let is_support_command = self.handler.allow_command(&command).await.map_err(|err| {
            HandshakeError::new(
                SocksError::ExecuteError(err.to_string()),
                Socks5Reply::Failure,
            )
        })?;

        if !is_support_command {
            return Err(HandshakeError::new(
                SocksError::UnsupportedCommand(command.into()),
                Socks5Reply::UnsupportedCommand,
            ));
        }

        stream.read_u8().await?;
        let addr_type: Socks5AddrType = stream.read_u8().await?.try_into()?;

        let is_support_addr_type =
            self.handler
                .allow_addr_type(&addr_type)
                .await
                .map_err(|err| {
                    HandshakeError::new(
                        SocksError::ExecuteError(err.to_string()),
                        Socks5Reply::Failure,
                    )
                })?;

        if !is_support_addr_type {
            return Err(HandshakeError::new(
                SocksError::UnsupportedAddressType(addr_type),
                Socks5Reply::UnsupportedAddressType,
            ));
        }

        let dist_addr = match addr_type {
            Socks5AddrType::IPV4 => {
                let mut buf = [0; 4];
                stream.read_exact(&mut buf).await?;

                let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = stream.read_u16().await?;

                SocksAddr::IPV4(SocketAddrV4::new(ip, port))
            }
            Socks5AddrType::Domain => {
                let length = stream.read_u8().await?;
                let mut buf = vec![0; length as usize];
                stream.read_exact(&mut buf).await?;

                let domain = String::from_utf8(buf).map_err(SocksError::Utf8BytesToStringError)?;
                let port = stream.read_u16().await?;

                SocksAddr::Domain(domain, port)
            }
            Socks5AddrType::IPV6 => {
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

                SocksAddr::IPV6(SocketAddrV6::new(ip, port, 0, 0))
            }
        };

        Ok((command, dist_addr))
    }

    async fn connect(&self, stream: &mut TcpStream, dist_addr: &SocksAddr) -> Result<(), H::Error> {
        match self.handler.connect(stream, &dist_addr).await {
            Ok(_) => Ok(()),
            Err(err) => {
                Socks5Reply::Failure.reply(stream, self.local_addr).await?;

                Err(err)
            }
        }
    }

    async fn bind(&self, stream: &mut TcpStream, dist_addr: &SocksAddr) -> Result<(), H::Error> {
        match self.handler.bind(stream, &dist_addr).await {
            Ok(_) => Ok(()),
            Err(err) => {
                Socks5Reply::Failure.reply(stream, self.local_addr).await?;

                Err(err)
            }
        }
    }

    async fn associate(
        &self,
        stream: &mut TcpStream,
        dist_addr: &SocksAddr,
    ) -> Result<(), H::Error> {
        match self.handler.associate(stream, &dist_addr).await {
            Ok(_) => Ok(()),
            Err(err) => {
                Socks5Reply::Failure.reply(stream, self.local_addr).await?;

                Err(err)
            }
        }
    }
}
