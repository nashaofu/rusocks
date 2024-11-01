use async_trait::async_trait;
use rusocks::{address::Address, error::Error, socks5::method::Method, Socks, SocksHandler};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let peer_addr = stream.peer_addr().unwrap();
            let local_addr = stream.local_addr().unwrap();
            println!("new connection from {} to {}", peer_addr, local_addr);

            let handler = Handler {};
            let mut socks = Socks::from_stream(&mut stream, peer_addr, local_addr, handler)
                .await
                .unwrap();

            match socks.accept(&mut stream).await {
                Ok(_) => {
                    println!("handshake success");
                }
                Err(e) => {
                    stream.shutdown().await.unwrap();
                    println!("handshake error: {}", e);
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
    async fn socks4_command_connect(&self, address: &Address) -> Result<Self::Stream, Self::Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        Ok(stream)
    }

    async fn socks4_command_bind(&self, _address: &Address) -> Result<(), Self::Error> {
        // let listener = TcpListener::bind("0.0.0.0:0").await?;

        // tokio::spawn(async move {
        //     while let Ok((mut stream, _)) = listener.accept().await {
        //         tokio::spawn(async move {
        //             let peer_addr = stream.peer_addr().unwrap();
        //             let local_addr = stream.local_addr().unwrap();
        //             println!("new connection from {} to {}", peer_addr, local_addr);
        //         });
        //     }
        // });

        Ok(())
    }
    async fn socks5_command_connect(&self, address: &Address) -> Result<Self::Stream, Self::Error> {
        let stream = TcpStream::connect((address.domain(), address.port())).await?;
        Ok(stream)
    }

    async fn socks5_command_bind(&self, _address: &Address) -> Result<(), Self::Error> {
        Ok(())
    }
}
