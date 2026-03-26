use serde::{Deserialize, Serialize};

/// Messages sent over the signaling WebSocket
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalMessage {
    /// Sender registers with the relay, advertising a transfer code
    #[serde(rename = "register")]
    Register { code: String },

    /// Receiver requests to connect to a sender by code
    #[serde(rename = "join")]
    Join { code: String },

    /// Relay tells sender that a receiver has joined
    #[serde(rename = "peer_joined")]
    PeerJoined,

    /// Exchange connection info (IP, port) for direct connection
    #[serde(rename = "peer_info")]
    PeerInfo { addr: String },

    /// Relay tells both peers to fall back to relay mode
    #[serde(rename = "relay_mode")]
    RelayMode,

    /// Error from the relay
    #[serde(rename = "error")]
    Error { message: String },
}

/// Messages sent over the QUIC transfer connection
#[derive(Debug, Serialize, Deserialize)]
pub enum TransferMessage {
    /// File metadata sent before transfer begins
    FileHeader {
        filename: String,
        size: u64,
        checksum: String,
    },
    /// Acknowledgement that receiver is ready
    Ready,
    /// Transfer complete
    Done { checksum: String },
}

impl TransferMessage {
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}
