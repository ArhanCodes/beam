use anyhow::{anyhow, Result};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext as PqCiphertext, EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

const PQ_EK_LEN: usize = 1184;
const PQ_CT_LEN: usize = 1088;
const SPAKE2_MSG_LEN: usize = 33;

pub struct SessionKey(pub [u8; 32]);

impl Drop for SessionKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

pub async fn perform_sender_handshake<S, R>(
    code: &str,
    mut send: S,
    mut recv: R,
) -> Result<SessionKey>
where
    S: AsyncWriteUnpin,
    R: AsyncReadUnpin,
{
    let (state, outbound) = Spake2::<Ed25519Group>::start_a(
        &Password::new(code.as_bytes()),
        &Identity::new(b"beam-sender"),
        &Identity::new(b"beam-receiver"),
    );

    let mut rng = OsRng;
    let (pq_dk, pq_ek) = MlKem768::generate(&mut rng);
    let pq_ek_bytes = pq_ek.as_bytes().to_vec();

    let mut a_payload = Vec::with_capacity(SPAKE2_MSG_LEN + PQ_EK_LEN);
    a_payload.extend_from_slice(&outbound);
    a_payload.extend_from_slice(&pq_ek_bytes);

    write_frame(&mut send, &a_payload).await?;

    let b_payload = read_frame(&mut recv).await?;
    if b_payload.len() != SPAKE2_MSG_LEN + PQ_CT_LEN {
        return Err(anyhow!("malformed handshake frame from receiver"));
    }
    let pake_inbound = &b_payload[..SPAKE2_MSG_LEN];
    let pq_ct_bytes = &b_payload[SPAKE2_MSG_LEN..];

    let pake_secret = state
        .finish(pake_inbound)
        .map_err(|e| anyhow!("SPAKE2 handshake failed: {:?}", e))?;

    let pq_ct = PqCiphertext::<MlKem768>::try_from(pq_ct_bytes)
        .map_err(|_| anyhow!("invalid PQ ciphertext length"))?;
    let pq_secret = pq_dk
        .decapsulate(&pq_ct)
        .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;

    let session = derive_session_key(&pake_secret, pq_secret.as_slice());

    let confirm_a = compute_confirm(&session.0, b"beam-confirm-a");
    write_frame(&mut send, &confirm_a).await?;
    let confirm_b = read_frame(&mut recv).await?;
    let expected_b = compute_confirm(&session.0, b"beam-confirm-b");
    if !ct_eq(&confirm_b, &expected_b) {
        return Err(anyhow!(
            "channel confirmation failed; possible MITM or wrong code"
        ));
    }

    Ok(session)
}

pub async fn perform_receiver_handshake<S, R>(
    code: &str,
    mut send: S,
    mut recv: R,
) -> Result<SessionKey>
where
    S: AsyncWriteUnpin,
    R: AsyncReadUnpin,
{
    let (state, outbound) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.as_bytes()),
        &Identity::new(b"beam-sender"),
        &Identity::new(b"beam-receiver"),
    );

    let a_payload = read_frame(&mut recv).await?;
    if a_payload.len() != SPAKE2_MSG_LEN + PQ_EK_LEN {
        return Err(anyhow!("malformed handshake frame from sender"));
    }
    let pake_inbound = &a_payload[..SPAKE2_MSG_LEN];
    let pq_ek_bytes = &a_payload[SPAKE2_MSG_LEN..];

    let pq_ek_encoded = ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(
        pq_ek_bytes,
    )
    .map_err(|_| anyhow!("invalid PQ encapsulation key length"))?;
    let pq_ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&pq_ek_encoded);

    let mut rng = OsRng;
    let (pq_ct, pq_secret) = pq_ek
        .encapsulate(&mut rng)
        .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;

    let pake_secret = state
        .finish(pake_inbound)
        .map_err(|e| anyhow!("SPAKE2 handshake failed: {:?}", e))?;

    let mut b_payload = Vec::with_capacity(SPAKE2_MSG_LEN + PQ_CT_LEN);
    b_payload.extend_from_slice(&outbound);
    b_payload.extend_from_slice(&pq_ct);
    write_frame(&mut send, &b_payload).await?;

    let session = derive_session_key(&pake_secret, pq_secret.as_slice());

    let confirm_a = read_frame(&mut recv).await?;
    let expected_a = compute_confirm(&session.0, b"beam-confirm-a");
    if !ct_eq(&confirm_a, &expected_a) {
        return Err(anyhow!(
            "channel confirmation failed; possible MITM or wrong code"
        ));
    }
    let confirm_b = compute_confirm(&session.0, b"beam-confirm-b");
    write_frame(&mut send, &confirm_b).await?;

    Ok(session)
}

fn derive_session_key(pake: &[u8], pq: &[u8]) -> SessionKey {
    let mut ikm = Zeroizing::new(Vec::with_capacity(pake.len() + pq.len()));
    ikm.extend_from_slice(pake);
    ikm.extend_from_slice(pq);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"beam/2 hybrid session key", &mut out).unwrap();
    SessionKey(out)
}

fn compute_confirm(session_key: &[u8; 32], label: &[u8]) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut out = vec![0u8; 32];
    hk.expand(label, &mut out).unwrap();
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn make_aead(key: &SessionKey) -> Result<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| anyhow!("invalid session key length"))
}

pub fn nonce_for_chunk(counter: u64, direction: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    nonce
}

pub fn seal(cipher: &ChaCha20Poly1305, counter: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    let n = nonce_for_chunk(counter, 0x53);
    cipher
        .encrypt(Nonce::from_slice(&n), plaintext)
        .map_err(|_| anyhow!("AEAD encrypt failed"))
}

pub fn open(cipher: &ChaCha20Poly1305, counter: u64, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let n = nonce_for_chunk(counter, 0x53);
    cipher
        .decrypt(Nonce::from_slice(&n), ciphertext)
        .map_err(|_| anyhow!("AEAD decrypt failed; tampered or wrong key"))
}

pub trait AsyncWriteUnpin: tokio::io::AsyncWrite + Unpin {}
impl<T: tokio::io::AsyncWrite + Unpin> AsyncWriteUnpin for T {}
pub trait AsyncReadUnpin: tokio::io::AsyncRead + Unpin {}
impl<T: tokio::io::AsyncRead + Unpin> AsyncReadUnpin for T {}

async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let len = data.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 8192 {
        return Err(anyhow!("handshake frame too large: {}", len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn handshake_roundtrip_derives_matching_key() {
        let (a, b) = duplex(8192);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let code = "7-amber-wolf";
        let sender = tokio::spawn(perform_sender_handshake(code, a_w, a_r));
        let receiver = tokio::spawn(perform_receiver_handshake(code, b_w, b_r));
        let s_key = sender.await.unwrap().unwrap();
        let r_key = receiver.await.unwrap().unwrap();
        assert_eq!(s_key.0, r_key.0);
    }

    #[tokio::test]
    async fn handshake_with_wrong_code_fails() {
        let (a, b) = duplex(8192);
        let (a_r, a_w) = tokio::io::split(a);
        let (b_r, b_w) = tokio::io::split(b);
        let sender = tokio::spawn(perform_sender_handshake("right-code", a_w, a_r));
        let receiver = tokio::spawn(perform_receiver_handshake("wrong-code", b_w, b_r));
        let s = sender.await.unwrap();
        let r = receiver.await.unwrap();
        assert!(s.is_err() || r.is_err());
    }

    #[tokio::test]
    async fn aead_roundtrip() {
        let k = SessionKey([0x42; 32]);
        let c = make_aead(&k).unwrap();
        let ct = seal(&c, 0, b"hello").unwrap();
        let pt = open(&c, 0, &ct).unwrap();
        assert_eq!(&pt, b"hello");
        let bad = open(&c, 1, &ct);
        assert!(bad.is_err());
    }
}
