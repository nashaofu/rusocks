use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn socks5_bind_client(
    socks5_addr: &str,
    bind_addr: SocketAddrV4,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 连接到 SOCKS5 服务器
    let mut stream = TcpStream::connect(socks5_addr).await?;
    println!("Connected to SOCKS5 server");

    // 2. 发送握手请求 (无认证)
    stream.write_all(&[0x05, 0x01, 0x00]).await?; // SOCKS5, 1 method, No Auth (0x00)

    // 3. 接收握手响应
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 0x05 || buf[1] != 0x00 {
        return Err("Unsupported SOCKS5 method".into());
    }
    println!("Handshake completed");

    // 4. 发送 BIND 请求
    let mut request = vec![0x05, 0x02, 0x00, 0x01]; // SOCKS5, BIND command, reserved, address type (domain)
    // request.push(4); // 地址长度
    request.extend_from_slice(&bind_addr.ip().octets()); // 地址本身
    let s = &bind_addr.port().to_be_bytes();
    request.extend(&s.to_vec()); // 端口


    println!("bind addr {}", bind_addr);

    stream.write_all(&request).await?;
    println!("BIND request sent");

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    // 5. 接收第一次响应
    let mut response = [0u8; 10]; // 假设 IPv4 地址和端口长度固定
    stream.read_exact(&mut response).await?;
    if response[1] != 0x00 {
        return Err("BIND request failed".into());
    }

    println!("response {:?}", response);

    let bnd_port = ((response[8] as u16) << 8) | response[9] as u16;
    println!("Server is listening on port: {}", bnd_port);

    // 6. 等待第二次响应以确认连接
    let mut second_response = [0u8; 10];
    stream.read_exact(&mut second_response).await?;
    if second_response[1] != 0x00 {
        return Err("BIND connection failed".into());
    }
    println!("second_response {:?}", second_response);

    println!("BIND connection established");

    let mut s = TcpStream::connect("127.0.0.1:8080").await?;

    io::copy_bidirectional(&mut s, &mut stream).await?;


    Ok(())
}

// 在 async main 或 tokio runtime 中调用
#[tokio::main]
async fn main() {
    if let Err(e) = socks5_bind_client(
        "127.0.0.1:1080",
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8081),
    )
    .await
    {
        eprintln!("Error: {}", e);
    }
}
