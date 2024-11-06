use std::time::Duration;

use futures::future::join_all;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

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

#[tokio::main]
async fn main() -> io::Result<()> {
    let server_addr = "127.0.0.1:1080";
    let target_ip = [127, 0, 0, 1];
    let target_port = 0;

    // send_socks4_bind_request(server_addr, target_port, target_ip).await?;

    let mut stream = TcpStream::connect(server_addr).await?;

    // 构造 SOCKS4 BIND 请求
    let mut request = vec![
        0x04,
        0x02, // SOCKS4, BIND command
        (target_port >> 8) as u8,
        (target_port & 0xFF) as u8, // 端口
        target_ip[0],
        target_ip[1],
        target_ip[2],
        target_ip[3], // IP 地址
    ];
    request.push(0x00); // 用户 ID 结束符

    // 发送请求
    stream.write_all(&request).await?;

    // 读取响应
    let mut response = [0u8; 8];
    stream.read_exact(&mut response).await?;
    if response[1] != 0x5A {
        eprintln!("BIND request failed");
        return Ok(());
    }

    println!("response {:?}", response);

    println!(
        "BIND successful, listening on {}:{}",
        response[4],
        u16::from_be_bytes([response[2], response[3]])
    );

    let external_stream = TcpStream::connect("127.0.0.1:8080").await?;

    // 分离读写部分以并行转发数据
    let (client_reader, client_writer) = io::split(stream);
    let (external_reader, external_writer) = io::split(external_stream);

    let t1 = tokio::spawn(async move {
        transfer_data("write", external_reader, client_writer)
            .await
            .unwrap();
    });
    let t2 = tokio::spawn(async move {
        transfer_data("read", client_reader, external_writer)
            .await
            .unwrap();
    });

    join_all([t1, t2]).await;

    Ok(())
}
