use std::net::SocketAddr;

use async_trait::async_trait;
use rusocks::{
    address::Address,
    error::Error,
    socks4,
    socks5::{self, method::Method},
    Socks, SocksHandler,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select, time,
};

#[tokio::main]
async fn main() {
    // curl -x socks5://127.0.0.1:1080 http://127.0.0.1:8080
    let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let peer_addr = stream.peer_addr().unwrap();
            let local_addr = stream.local_addr().unwrap();

            let handler = Handler {};
            let mut socks = Socks::from_stream(&mut stream, peer_addr, local_addr, handler)
                .await
                .unwrap();

            match socks.accept(&mut stream).await {
                Ok(_) => {
                    println!("success");
                }
                Err(e) => {
                    println!("error: {}", e);
                }
            }
        });
    }
}

struct Handler {}

#[async_trait]
impl SocksHandler for Handler {
    type Error = Error;
    type Stream = TcpStream;
    async fn socks5_handshake_method(&self, _methods: &Vec<Method>) -> Result<Method, Self::Error> {
        Ok(Method::None)
    }

    async fn socks5_auth_username_password(
        &self,
        username: String,
        password: String,
    ) -> Result<bool, Self::Error> {
        println!("username: {}, password: {}", username, password);
        Ok(false)
    }
    async fn socks4_command_connect(
        &self,
        address: &Address,
    ) -> Result<(Self::Stream, SocketAddr), Self::Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        let bind_addr = stream.local_addr()?;

        Ok((stream, bind_addr))
    }

    async fn socks4_command_bind<S>(
        &self,
        request: &mut socks4::request::Request<S>,
        address: &Address,
    ) -> Result<(), Self::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let listener = TcpListener::bind((address.domain(), address.port())).await?;
        let bind_addr = listener.local_addr()?.clone();
        request
            .reply(socks4::reply::Reply::Granted, bind_addr)
            .await?;

        let (mut connect, peer_addr) = listener.accept().await?;
        // 异步处理连接
        println!("Accepted connection from {:?}", peer_addr);
        io::copy_bidirectional(&mut request.stream, &mut connect)
            .await
            .unwrap();
    }
    async fn socks5_command_connect(
        &self,
        address: &Address,
    ) -> Result<(Self::Stream, SocketAddr), Self::Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        let bind_addr = stream.local_addr()?;

        Ok((stream, bind_addr))
    }

    async fn socks5_command_bind<S>(
        &self,
        request: &mut socks5::request::Request<S>,
        bind_addr: &Address,
    ) -> Result<(), Self::Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let listener = TcpListener::bind((bind_addr.domain(), bind_addr.port())).await?;
        let bind_addr = listener.local_addr()?.clone();

        request
            .reply(socks5::reply::Reply::Succeeded, bind_addr)
            .await?;

        select! {
            // 超时关闭
            _ = time::sleep(time::Duration::from_secs(20)) => {
                println!("Shutdown signal received. Stopping the listener...");
                return Ok(());
            }
            Ok((mut connect, peer_addr)) = listener.accept() => {
                println!("Accepted connection from {:?}", peer_addr);
                request.reply(socks5::reply::Reply::Succeeded, peer_addr).await?;
                io::copy_bidirectional(&mut request.stream, &mut connect).await?;
            }
        }

        Ok(())
    }
}
