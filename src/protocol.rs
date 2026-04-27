use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalMessage {

    #[serde(rename = "register")]
    Register { code: String },

    #[serde(rename = "join")]
    Join { code: String },

    #[serde(rename = "peer_joined")]
    PeerJoined,

    #[serde(rename = "peer_info")]
    PeerInfo { addr: String },

    #[serde(rename = "relay_mode")]
    RelayMode,

    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransferMessage {

    FileHeader {
        filename: String,
        size: u64,
        checksum: String,
    },

    Ready,

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
