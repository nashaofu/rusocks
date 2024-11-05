use std::net::SocketAddr;

use async_trait::async_trait;
use rusocks::{
    address::Address,
    error::Error,
    socks4::{reply::Socks4Reply, request::Socks4Request, Socks4Handler},
    socks5::{method::Socks5Method, reply::Socks5Reply, request::Socks5Request, Socks5Handler},
    Socks,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select, time,
};

#[tokio::main]
async fn main() {
    // curl -x socks4://127.0.0.1:1080 http://127.0.0.1:8080
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
impl Socks4Handler for Handler {
    type ConnectStream = TcpStream;

    async fn connect(&self, address: &Address) -> Result<(Self::ConnectStream, SocketAddr), Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        let bind_addr = stream.local_addr()?;

        Ok((stream, bind_addr))
    }

    async fn bind<S>(
        &self,
        request: &mut Socks4Request<S>,
        bind_addr: &Address,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let listener = TcpListener::bind((bind_addr.domain(), bind_addr.port())).await?;
        let bind_addr = listener.local_addr()?.clone();
        request.reply(Socks4Reply::Granted, bind_addr).await?;

        let (mut connect, peer_addr) = listener.accept().await?;
        // 异步处理连接
        println!("Accepted connection from {:?}", peer_addr);
        io::copy_bidirectional(&mut request.stream, &mut connect)
            .await
            .unwrap();

        Ok(())
    }
}

#[async_trait]
impl Socks5Handler for Handler {
    type ConnectStream = TcpStream;

    async fn negotiate_method(&self, _methods: &[Socks5Method]) -> Result<Socks5Method, Error> {
        Ok(Socks5Method::None)
    }

    async fn auth_by_user_pass(&self, username: &str, password: &str) -> Result<bool, Error> {
        println!("username: {}, password: {}", username, password);
        Ok(false)
    }

    async fn connect(&self, address: &Address) -> Result<(Self::ConnectStream, SocketAddr), Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        let bind_addr = stream.local_addr()?;

        Ok((stream, bind_addr))
    }

    async fn bind<S>(
        &self,
        request: &mut Socks5Request<S>,
        bind_addr: &Address,
    ) -> Result<(), Error>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    {
        let listener = TcpListener::bind((bind_addr.domain(), bind_addr.port())).await?;
        let bind_addr = listener.local_addr()?.clone();

        request.reply(Socks5Reply::Succeeded, bind_addr).await?;

        select! {
            // 超时关闭
            _ = time::sleep(time::Duration::from_secs(20)) => {
                println!("Shutdown signal received. Stopping the listener...");
                return Ok(());
            }
            Ok((mut connect, peer_addr)) = listener.accept() => {
                println!("Accepted connection from {:?}", peer_addr);
                request.reply(Socks5Reply::Succeeded, peer_addr).await?;
                io::copy_bidirectional(&mut request.stream, &mut connect).await?;
            }
        }

        Ok(())
    }
}
