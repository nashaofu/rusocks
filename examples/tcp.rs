use async_trait::async_trait;
use rusocks::{
    error::SocksError,
    socks4::Socks4Handler,
    socks5::{method::Socks5Method, Socks5Handler},
    Socks,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    // curl -x socks4://127.0.0.1:1080 http://127.0.0.1:8080
    // curl -x socks5://127.0.0.1:1080 http://127.0.0.1:8080
    let listener = TcpListener::bind("127.0.0.1:1080").await.unwrap();

    while let Ok((mut stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let handler = Handler {};
            let mut socks = Socks::from_stream(&mut stream, handler).await.unwrap();

            match socks.execute(&mut stream).await {
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
    type Error = SocksError;
}

#[async_trait]
impl Socks5Handler for Handler {
    type Error = SocksError;

    async fn negotiate_method(
        &self,
        _methods: &[Socks5Method],
    ) -> Result<Socks5Method, Self::Error> {
        Ok(Socks5Method::None)
    }

    async fn auth_by_user_pass(&self, username: &str, password: &str) -> Result<bool, Self::Error> {
        println!("username: {}, password: {}", username, password);
        Ok(false)
    }
}
