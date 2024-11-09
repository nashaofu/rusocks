use futures::future::join_all;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time;

const SOCKS_VERSION: u8 = 4;
const BIND_COMMAND: u8 = 2;
const SUCCESS_REPLY: u8 = 90;
const FAILURE_REPLY: u8 = 91;

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:1080").await?;
    println!("SOCKS4 Proxy Server started on port 1080");

    loop {
        let (mut client_socket, client_addr) = listener.accept().await?;
        println!("Connection received from {}", client_addr);

        tokio::spawn(async move {
            if let Err(e) = handle_socks4_bind(client_socket).await {
                eprintln!("Error handling connection from {}: {}", client_addr, e);
            }
        });
    }
}

async fn handle_socks4_bind(mut client_socket: TcpStream) -> io::Result<()> {
    // 读取 SOCKS4 请求
    let mut buffer = [0u8; 8];
    client_socket.read_exact(&mut buffer).await?;

    let version = buffer[0];
    let command = buffer[1];
    let port = u16::from_be_bytes([buffer[2], buffer[3]]);
    let ip_addr = IpAddr::V4(Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7]));

    if version != SOCKS_VERSION || command != BIND_COMMAND {
        client_socket
            .write_all(&[0, FAILURE_REPLY, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid SOCKS4 request",
        ));
    }

    // 绑定到一个随机端口并监听
    let bind_listener = TcpListener::bind((ip_addr, port)).await?;
    let bind_addr = bind_listener.local_addr()?;
    println!(
        "Listening for incoming connections on port {}",
        bind_addr.port()
    );

    // 发送回复给客户端，表示准备就绪
    let mut response = vec![0, SUCCESS_REPLY];
    response.extend_from_slice(&bind_addr.port().to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]); // 返回 0.0.0.0 表示任意 IP
    client_socket.write_all(&response).await?;

    run(client_socket, bind_listener).await?;

    Ok(())
}

async fn run<S>(mut client_socket: S, bind_listener: TcpListener) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let client_socket = Arc::new(Mutex::new(client_socket));

    // 并发处理多个远程连接
    loop {
        let (remote_socket, remote_addr) = match bind_listener.accept().await {
            Ok((socket, addr)) => (socket, addr),
            Err(e) => {
                eprintln!("Failed to accept remote connection: {}", e);
                continue;
            }
        };

        println!("Connection established from {}", remote_addr);

        // 向客户端发送连接已建立的响应
        let client_socket_clone = client_socket.clone();
        tokio::spawn(async move {
            // let client_socket_clone = client_socket_clone.lock().unwrap();
            if let Err(e) = forward_traffic(client_socket_clone, remote_socket).await {
                eprintln!("Error during traffic forwarding: {}", e);
            }
        });
    }
}

async fn forward_traffic<S>(
    client_socket: Arc<Mutex<S>>,
    mut remote_socket: TcpStream,
) -> io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
{
    let mut s = client_socket.lock().await;
    let s = s.deref_mut();
    let (mut client_reader, mut client_writer) = s.split();
    let (mut remote_reader, mut remote_writer) = remote_socket.split();

    let client_to_remote = tokio::io::copy(&mut client_reader, &mut remote_writer);
    let remote_to_client = tokio::io::copy(&mut remote_reader, &mut client_writer);

    tokio::select! {
        result = client_to_remote => {
                println!("Error forwarding data from client to remote:");
        }
        result = remote_to_client => {
                println!("Error forwarding data from remote to client:");
        }
    }

    // let t1 = tokio::spawn(async move {
    //     transfer_data("write", client_reader, remote_writer)
    //         .await
    //         .unwrap();
    // });
    // let t2 = tokio::spawn(async move {
    //     transfer_data("read", remote_reader, client_writer)
    //         .await
    //         .unwrap();
    // });

    // join_all([t1, t2]).await;

    Ok(())
}

async fn transfer_data<R, W>(r: &str, mut reader: R, mut writer: W) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await?;
        println!("{} {:?}", r, n);
        if n == 0 {
            time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}
