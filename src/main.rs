mod code;
mod crypto;
mod nat;
mod protocol;
mod relay;
mod transfer;
mod web;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use tracing::info;

use crate::protocol::SignalMessage;

#[derive(Parser)]
#[command(
    name = "beam",
    about = "Peer-to-peer file transfer. No servers, no sign-ups, just beam it.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file
    Send {
        /// Path to the file to send
        file: PathBuf,

        /// Relay server address
        #[arg(long, default_value = "127.0.0.1:7700")]
        relay: String,
    },

    /// Receive a file
    Receive {
        /// Transfer code (e.g. 7-amber-wolf)
        code: String,

        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Relay server address
        #[arg(long, default_value = "127.0.0.1:7700")]
        relay: String,
    },

    /// Run the signaling relay server
    Relay {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:7700")]
        bind: SocketAddr,
    },

    /// Run the web UI
    Web {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:3000")]
        bind: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("beam=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Send { file, relay } => cmd_send(file, relay).await?,
        Commands::Receive {
            code,
            output,
            relay,
        } => cmd_receive(code, output, relay).await?,
        Commands::Relay { bind } => relay::run_relay(bind).await?,
        Commands::Web { bind } => web::run_web(bind).await?,
    }

    Ok(())
}

async fn cmd_send(file: PathBuf, relay_addr: String) -> Result<()> {
    // Validate file exists
    if !file.exists() {
        anyhow::bail!("File not found: {}", file.display());
    }

    let file = file.canonicalize()?;
    let filename = file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let metadata = tokio::fs::metadata(&file).await?;

    println!("\n  beam send");
    println!("  ────────────────────────────");
    println!("  File: {}", filename);
    println!("  Size: {}", format_size(metadata.len()));

    // Generate transfer code
    let transfer_code = code::generate_code();

    // Start QUIC server for direct transfer
    let quic_addr: SocketAddr = "0.0.0.0:0".parse()?;
    let local_addr = transfer::send_file(&file, quic_addr).await?;
    // Replace 0.0.0.0 with 127.0.0.1 for local connections
    let advertise_addr = if local_addr.ip().is_unspecified() {
        SocketAddr::new("127.0.0.1".parse()?, local_addr.port())
    } else {
        local_addr
    };

    // Connect to relay and register
    let relay_url = format!("ws://{}", relay_addr);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&relay_url)
        .await
        .map_err(|e| anyhow::anyhow!(
            "Could not connect to relay at {}. Is it running? (beam relay)\nError: {}",
            relay_addr, e
        ))?;

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Register with relay
    let register = serde_json::to_string(&SignalMessage::Register {
        code: transfer_code.clone(),
    })?;
    ws_sink.send(Message::Text(register.into())).await?;

    println!("\n  Code: {}", transfer_code);
    println!("\n  On the other device, run:");
    println!("  beam receive {}", transfer_code);
    println!("\n  Waiting for receiver...");

    // Wait for peer to join
    while let Some(Ok(msg)) = ws_stream_rx.next().await {
        if let Message::Text(text) = msg {
            match serde_json::from_str::<SignalMessage>(&text) {
                Ok(SignalMessage::PeerJoined) => {
                    println!("  Receiver connected!");

                    // Send our QUIC address to receiver via relay
                    let peer_info = serde_json::to_string(&SignalMessage::PeerInfo {
                        addr: advertise_addr.to_string(),
                    })?;
                    ws_sink.send(Message::Text(peer_info.into())).await?;
                }
                Ok(SignalMessage::Error { message }) => {
                    anyhow::bail!("Relay error: {}", message);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

async fn cmd_receive(transfer_code: String, output: PathBuf, relay_addr: String) -> Result<()> {
    println!("\n  beam receive");
    println!("  ────────────────────────────");
    println!("  Code: {}", transfer_code);

    // Ensure output directory exists
    tokio::fs::create_dir_all(&output).await?;

    // Connect to relay
    let relay_url = format!("ws://{}", relay_addr);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&relay_url)
        .await
        .map_err(|e| anyhow::anyhow!(
            "Could not connect to relay at {}. Is it running? (beam relay)\nError: {}",
            relay_addr, e
        ))?;

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Join with code
    let join = serde_json::to_string(&SignalMessage::Join {
        code: transfer_code.clone(),
    })?;
    ws_sink.send(Message::Text(join.into())).await?;

    println!("  Connecting to sender...");

    // Wait for sender's address
    while let Some(Ok(msg)) = ws_stream_rx.next().await {
        if let Message::Text(text) = msg {
            match serde_json::from_str::<SignalMessage>(&text) {
                Ok(SignalMessage::PeerInfo { addr }) => {
                    info!("Sender address: {}", addr);
                    let sender_addr: SocketAddr = addr.parse()?;

                    // Connect directly via QUIC
                    println!("  Connected!\n");
                    transfer::receive_file(sender_addr, &output).await?;
                    println!("\n  Done!\n");
                    return Ok(());
                }
                Ok(SignalMessage::Error { message }) => {
                    anyhow::bail!("Error: {}", message);
                }
                _ => {}
            }
        }
    }

    anyhow::bail!("Connection lost to relay");
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
