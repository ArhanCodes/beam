use anyhow::{Context, Result};
use spake2::{Ed25519Group, Identity, Password, Spake2};

pub fn start_sender(code: &str) -> Result<(Spake2<Ed25519Group>, Vec<u8>)> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_a(
        &Password::new(code.as_bytes()),
        &Identity::new(b"beam-sender"),
        &Identity::new(b"beam-receiver"),
    );
    Ok((state, outbound.to_vec()))
}

pub fn start_receiver(code: &str) -> Result<(Spake2<Ed25519Group>, Vec<u8>)> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.as_bytes()),
        &Identity::new(b"beam-sender"),
        &Identity::new(b"beam-receiver"),
    );
    Ok((state, outbound.to_vec()))
}

pub fn finish(state: Spake2<Ed25519Group>, inbound: &[u8]) -> Result<Vec<u8>> {
    state
        .finish(inbound)
        .map_err(|e| anyhow::anyhow!("SPAKE2 key exchange failed: {:?}", e))
        .context("Failed to derive shared secret")
}
