use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use quinn::{Endpoint, RecvStream, SendStream, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

use crate::handshake;
use crate::protocol::TransferMessage;

const CHUNK_SIZE: usize = 64 * 1024;
const ENCRYPTED_CHUNK_OVERHEAD: usize = 16;

fn generate_self_signed_cert() -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["beam".into()])?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
    let key_der = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );
    Ok((cert_der, key_der))
}

fn make_server_config() -> Result<ServerConfig> {
    let (cert, key) = generate_self_signed_cert()?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    server_crypto.alpn_protocols = vec![b"beam/2".to_vec()];
    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    )))
}

fn make_client_config() -> Result<quinn::ClientConfig> {
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"beam/2".to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    )))
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub async fn send_file(file_path: &Path, listen_addr: SocketAddr, code: String) -> Result<SocketAddr> {
    let server_config = make_server_config()?;
    let endpoint = Endpoint::server(server_config, listen_addr)?;
    let local_addr = endpoint.local_addr()?;
    info!("QUIC sender listening on {}", local_addr);

    let file_path = file_path.to_path_buf();
    tokio::spawn(async move {
        if let Err(e) = send_file_inner(&endpoint, &file_path, &code).await {
            eprintln!("Transfer error: {}", e);
        }
        endpoint.close(0u32.into(), b"done");
    });

    Ok(local_addr)
}

async fn send_file_inner(endpoint: &Endpoint, file_path: &Path, code: &str) -> Result<()> {
    let conn = endpoint.accept().await
        .context("No incoming connection")?
        .await?;
    info!("Receiver connected");

    let (mut send, mut recv) = conn.open_bi().await?;

    let session_key = handshake::perform_sender_handshake(code, &mut send, &mut recv).await?;
    println!("  E2E handshake complete: SPAKE2 + ML-KEM-768 + ChaCha20-Poly1305");
    let cipher = handshake::make_aead(&session_key)?;

    let metadata = tokio::fs::metadata(file_path).await?;
    let file_size = metadata.len();
    let filename = file_path
        .file_name()
        .context("Invalid filename")?
        .to_string_lossy()
        .to_string();

    let checksum = compute_file_checksum(file_path).await?;

    let header = TransferMessage::FileHeader {
        filename: filename.clone(),
        size: file_size,
        checksum: checksum.clone(),
    };
    let header_bytes = header.to_bytes()?;
    let header_ct = handshake::seal(&cipher, 0, &header_bytes)?;
    write_frame(&mut send, &header_ct).await?;

    let ready_ct = read_frame(&mut recv).await?;
    let _ready = handshake::open(&cipher, 1, &ready_ct)?;

    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("=>-"),
    );

    let mut file = File::open(file_path).await?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut counter: u64 = 2;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let ct = handshake::seal(&cipher, counter, &buf[..n])?;
        write_frame(&mut send, &ct).await?;
        counter += 1;
        pb.inc(n as u64);
    }
    let final_ct = handshake::seal(&cipher, counter, b"END")?;
    write_frame(&mut send, &final_ct).await?;
    send.finish()?;

    pb.finish_with_message("Transfer complete!");
    println!("\n  Sent: {} ({})", filename, format_size(file_size));
    println!("  SHA-256: {}", &checksum[..16]);

    Ok(())
}

pub async fn receive_file(
    sender_addr: SocketAddr,
    output_dir: &Path,
    code: &str,
) -> Result<()> {
    let client_config = make_client_config()?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    info!("Connecting to sender at {}", sender_addr);
    let conn = endpoint.connect(sender_addr, "beam")?.await?;

    let (mut send, mut recv) = conn.accept_bi().await?;

    let session_key = handshake::perform_receiver_handshake(code, &mut send, &mut recv).await?;
    println!("  E2E handshake complete: SPAKE2 + ML-KEM-768 + ChaCha20-Poly1305");
    let cipher = handshake::make_aead(&session_key)?;

    let header_ct = read_frame(&mut recv).await?;
    let header_bytes = handshake::open(&cipher, 0, &header_ct)?;

    let header = TransferMessage::from_bytes(&header_bytes)?;
    let (filename, file_size, expected_checksum) = match header {
        TransferMessage::FileHeader {
            filename,
            size,
            checksum,
        } => (filename, size, checksum),
        _ => anyhow::bail!("Expected FileHeader"),
    };

    println!("  Receiving: {} ({})", filename, format_size(file_size));

    let ready = TransferMessage::Ready.to_bytes()?;
    let ready_ct = handshake::seal(&cipher, 1, &ready)?;
    write_frame(&mut send, &ready_ct).await?;

    let pb = ProgressBar::new(file_size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("=>-"),
    );

    let output_path = output_dir.join(&filename);
    let mut file = File::create(&output_path).await?;
    let mut hasher = Sha256::new();
    let mut counter: u64 = 2;

    loop {
        let frame = match read_frame(&mut recv).await {
            Ok(f) => f,
            Err(e) => {
                let s = e.to_string();
                if s.contains("closed") || s.contains("reset") || s.contains("eof") {
                    break;
                }
                return Err(e);
            }
        };
        let plain = handshake::open(&cipher, counter, &frame)?;
        counter += 1;
        if plain == b"END" {
            break;
        }
        file.write_all(&plain).await?;
        hasher.update(&plain);
        pb.inc(plain.len() as u64);
    }

    pb.finish_with_message("Transfer complete!");

    let actual_checksum = hex::encode(hasher.finalize());
    if actual_checksum != expected_checksum {
        anyhow::bail!(
            "Checksum mismatch!\n  Expected: {}\n  Got:      {}",
            expected_checksum,
            actual_checksum
        );
    }

    println!("\n  Saved: {}", output_path.display());
    println!("  SHA-256: {} (verified)", &actual_checksum[..16]);

    endpoint.close(0u32.into(), b"done");
    Ok(())
}

async fn write_frame(send: &mut SendStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(data).await?;
    Ok(())
}

async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > CHUNK_SIZE + ENCRYPTED_CHUNK_OVERHEAD + 4096 {
        anyhow::bail!("oversized frame: {}", len);
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn compute_file_checksum(path: &Path) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
