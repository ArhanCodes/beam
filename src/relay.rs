use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::protocol::SignalMessage;

type Tx = mpsc::UnboundedSender<Message>;

struct Session {
    sender_tx: Tx,
    receiver_tx: Option<Tx>,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// Run the signaling relay server
pub async fn run_relay(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Relay server listening on {}", addr);

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    while let Ok((stream, peer_addr)) = listener.accept().await {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, sessions).await {
                error!("Connection error from {}: {}", peer_addr, e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    sessions: Sessions,
) -> Result<()> {
    let ws_stream = tokio_tungstenite::accept_async(stream).await?;
    info!("New WebSocket connection from {}", peer_addr);

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to forward messages from channel to WebSocket
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut my_code: Option<String> = None;
    let mut is_sender = false;

    while let Some(Ok(msg)) = ws_stream_rx.next().await {
        if let Message::Text(text) = msg {
            match serde_json::from_str::<SignalMessage>(&text) {
                Ok(SignalMessage::Register { code }) => {
                    info!("Sender registered with code: {}", code);
                    my_code = Some(code.clone());
                    is_sender = true;

                    let mut sessions = sessions.lock().await;
                    sessions.insert(
                        code,
                        Session {
                            sender_tx: tx.clone(),
                            receiver_tx: None,
                        },
                    );
                }
                Ok(SignalMessage::Join { code }) => {
                    info!("Receiver joining with code: {}", code);
                    my_code = Some(code.clone());

                    let mut sessions = sessions.lock().await;
                    if let Some(session) = sessions.get_mut(&code) {
                        session.receiver_tx = Some(tx.clone());

                        // Notify sender that receiver joined
                        let notify = serde_json::to_string(&SignalMessage::PeerJoined)?;
                        let _ = session.sender_tx.send(Message::Text(notify.into()));

                        // Tell both peers to use relay mode for simplicity
                        // (direct connection via NAT hole-punching is attempted separately)
                        let peer_addr_msg = serde_json::to_string(&SignalMessage::PeerInfo {
                            addr: peer_addr.to_string(),
                        })?;
                        let _ = session.sender_tx.send(Message::Text(peer_addr_msg.into()));
                    } else {
                        let err = serde_json::to_string(&SignalMessage::Error {
                            message: format!("No sender found for code: {}", code),
                        })?;
                        let _ = tx.send(Message::Text(err.into()));
                    }
                }
                Ok(SignalMessage::PeerInfo { addr }) => {
                    // Forward peer info to the other side
                    let sessions = sessions.lock().await;
                    if let Some(code) = &my_code {
                        if let Some(session) = sessions.get(code) {
                            let msg = serde_json::to_string(&SignalMessage::PeerInfo {
                                addr,
                            })?;
                            if is_sender {
                                if let Some(rx_tx) = &session.receiver_tx {
                                    let _ = rx_tx.send(Message::Text(msg.into()));
                                }
                            } else {
                                let _ = session.sender_tx.send(Message::Text(msg.into()));
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Invalid message from {}: {}", peer_addr, e);
                }
            }
        }
    }

    // Cleanup on disconnect
    if let Some(code) = my_code {
        let mut sessions = sessions.lock().await;
        if is_sender {
            sessions.remove(&code);
            info!("Sender disconnected, removed session: {}", code);
        }
    }

    Ok(())
}
