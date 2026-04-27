use std::net::SocketAddr;

use anyhow::Result;
use tokio::net::UdpSocket;
use tracing::info;

pub async fn discover_public_addr() -> Result<SocketAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;

    let mut request = vec![0u8; 20];
    request[0] = 0x00;
    request[1] = 0x01;
    request[2] = 0x00;
    request[3] = 0x00;

    request[4] = 0x21;
    request[5] = 0x12;
    request[6] = 0xA4;
    request[7] = 0x42;

    for byte in request[8..20].iter_mut() {
        *byte = rand::random();
    }

    let stun_server = "stun.l.google.com:19302";
    socket.send_to(&request, stun_server).await?;

    let mut buf = [0u8; 256];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await??;

    parse_stun_response(&buf[..len])
}

fn parse_stun_response(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 20 {
        anyhow::bail!("STUN response too short");
    }

    if data[0] != 0x01 || data[1] != 0x01 {
        anyhow::bail!("Not a STUN Binding Response");
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut offset = 20;

    while offset + 4 <= 20 + msg_len && offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        if attr_type == 0x0020 && attr_len >= 8 {

            let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) ^ 0x2112;
            let ip = std::net::Ipv4Addr::new(
                data[offset + 4] ^ 0x21,
                data[offset + 5] ^ 0x12,
                data[offset + 6] ^ 0xA4,
                data[offset + 7] ^ 0x42,
            );
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            info!("Discovered public address: {}", addr);
            return Ok(addr);
        } else if attr_type == 0x0001 && attr_len >= 8 {

            let port = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ip = std::net::Ipv4Addr::new(
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            );
            let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
            info!("Discovered public address: {}", addr);
            return Ok(addr);
        }

        offset += (attr_len + 3) & !3;
    }

    anyhow::bail!("No mapped address found in STUN response")
}
