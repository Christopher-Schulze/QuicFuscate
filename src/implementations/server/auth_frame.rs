//! QKey-based mutual authentication frame.
//!
//! An `AuthFrame` binds a client identity (`client_id`, the 12-char QKey id) to a
//! point-in-time proof of possession of the QKey token. The proof is an HMAC-SHA-256
//! computed over `client_id || timestamp || nonce` using the 32-byte QKey token as
//! the HMAC key. The server verifies the HMAC and then runs the frame through a
//! `super::replay_window::ReplayWindow` so that a captured frame cannot be reused.
//!
//! Wire format (all integers big-endian):
//! ```text
//!   u8  version            // 0x01
//!   u16 client_id_len
//!   [u8; client_id_len] client_id
//!   u64 timestamp
//!   [u8; 16] nonce
//!   [u8; 32] hmac
//! ```

use crate::crypto::hkdf::hmac_sha256;

/// Wire-format version byte.
const AUTH_FRAME_VERSION: u8 = 0x01;

/// Maximum `client_id` length we accept on deserialization (the QKey id is 12 hex
/// chars; we leave headroom for future identifier schemes without unbounded reads).
const MAX_CLIENT_ID_LEN: usize = 256;

/// QKey-based mutual authentication frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthFrame {
    /// Client identifier (the 12-char QKey id).
    pub client_id: String,
    /// Unix-epoch timestamp (seconds) at frame construction time.
    pub timestamp: u64,
    /// Random 16-byte nonce, unique per frame.
    pub nonce: [u8; 16],
    /// HMAC-SHA-256 over `client_id || timestamp || nonce` keyed by the QKey token.
    pub hmac: [u8; 32],
}

impl AuthFrame {
    /// Build a new auth frame, computing the HMAC over the canonical message
    /// `client_id || timestamp || nonce` using `qkey_token` as the HMAC key.
    pub fn build(client_id: &str, qkey_token: &[u8], timestamp: u64, nonce: &[u8; 16]) -> Self {
        let hmac = compute_hmac(client_id, qkey_token, timestamp, nonce);
        Self { client_id: client_id.to_string(), timestamp, nonce: *nonce, hmac }
    }

    /// Verify this frame's HMAC against the provided client id and QKey token.
    ///
    /// Returns `true` only if the recomputed HMAC matches the stored one in
    /// constant time. The `client_id` argument is taken separately so a server
    /// can confirm the frame is bound to the identity it claims (e.g. the QKey
    /// id from the Initial packet token) rather than trusting the embedded field.
    pub fn verify(&self, client_id: &str, qkey_token: &[u8]) -> bool {
        let expected = compute_hmac(client_id, qkey_token, self.timestamp, &self.nonce);
        constant_time_eq(&self.hmac, &expected)
    }

    /// Serialize the frame for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let client_id_bytes = self.client_id.as_bytes();
        let len = 1 + 2 + client_id_bytes.len() + 8 + 16 + 32;
        let mut out = Vec::with_capacity(len);
        out.push(AUTH_FRAME_VERSION);
        out.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(client_id_bytes);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.hmac);
        out
    }

    /// Deserialize a frame from its wire format. Returns `None` on any
    /// truncation, unsupported version, or implausibly large client id.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 2 + 8 + 16 + 32 {
            return None;
        }
        let mut pos = 0;
        let version = data[pos];
        pos += 1;
        if version != AUTH_FRAME_VERSION {
            return None;
        }
        let id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if id_len > MAX_CLIENT_ID_LEN {
            return None;
        }
        if data.len() < pos + id_len + 8 + 16 + 32 {
            return None;
        }
        let client_id = std::str::from_utf8(&data[pos..pos + id_len]).ok()?.to_string();
        pos += id_len;
        let timestamp = u64::from_be_bytes(data[pos..pos + 8].try_into().ok()?);
        pos += 8;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&data[pos..pos + 32]);
        Some(Self { client_id, timestamp, nonce, hmac })
    }
}

/// Compute the canonical HMAC-SHA-256 over `client_id || timestamp || nonce`.
fn compute_hmac(client_id: &str, qkey_token: &[u8], timestamp: u64, nonce: &[u8; 16]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(client_id.len() + 8 + 16);
    msg.extend_from_slice(client_id.as_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.extend_from_slice(nonce);
    hmac_sha256(qkey_token, &msg)
}

/// Constant-time comparison of two 32-byte digests.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token() -> Vec<u8> {
        let mut tok = [0u8; 32];
        for (i, b) in tok.iter_mut().enumerate() {
            *b = i as u8;
        }
        tok.to_vec()
    }

    fn sample_nonce(seed: u8) -> [u8; 16] {
        let mut n = [0u8; 16];
        for (i, b) in n.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        n
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let token = sample_token();
        let nonce = sample_nonce(1);
        let frame = AuthFrame::build("a1b2c3d4e5f6", &token, 1_700_000_000, &nonce);
        assert!(frame.verify("a1b2c3d4e5f6", &token));
    }

    #[test]
    fn verify_rejects_wrong_token() {
        let token = sample_token();
        let wrong = {
            let mut t = [0u8; 32];
            for (i, b) in t.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(1);
            }
            t.to_vec()
        };
        let nonce = sample_nonce(2);
        let frame = AuthFrame::build("client-1", &token, 123, &nonce);
        assert!(!frame.verify("client-1", &wrong));
    }

    #[test]
    fn verify_rejects_wrong_client_id() {
        let token = sample_token();
        let nonce = sample_nonce(3);
        let frame = AuthFrame::build("client-1", &token, 123, &nonce);
        assert!(!frame.verify("client-2", &token));
    }

    #[test]
    fn verify_rejects_tampered_timestamp() {
        let token = sample_token();
        let nonce = sample_nonce(4);
        let mut frame = AuthFrame::build("client-1", &token, 100, &nonce);
        frame.timestamp = 101;
        assert!(!frame.verify("client-1", &token));
    }

    #[test]
    fn verify_rejects_tampered_nonce() {
        let token = sample_token();
        let mut nonce = sample_nonce(5);
        let frame = AuthFrame::build("client-1", &token, 100, &nonce);
        nonce[0] ^= 0xff;
        let tampered = AuthFrame {
            client_id: frame.client_id.clone(),
            timestamp: frame.timestamp,
            nonce,
            hmac: frame.hmac,
        };
        assert!(!tampered.verify("client-1", &token));
    }

    #[test]
    fn verify_rejects_tampered_hmac() {
        let token = sample_token();
        let nonce = sample_nonce(6);
        let mut frame = AuthFrame::build("client-1", &token, 100, &nonce);
        frame.hmac[0] ^= 0x01;
        assert!(!frame.verify("client-1", &token));
    }

    #[test]
    fn serialization_roundtrip() {
        let token = sample_token();
        let nonce = sample_nonce(7);
        let frame = AuthFrame::build("a1b2c3d4e5f6", &token, 1_700_000_042, &nonce);
        let bytes = frame.to_bytes();
        let decoded = AuthFrame::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn from_bytes_rejects_truncated() {
        let nonce = sample_nonce(8);
        let frame = AuthFrame::build("x", &sample_token(), 1, &nonce);
        let bytes = frame.to_bytes();
        assert!(AuthFrame::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(AuthFrame::from_bytes(&[]).is_none());
    }

    #[test]
    fn from_bytes_rejects_unknown_version() {
        let nonce = sample_nonce(9);
        let frame = AuthFrame::build("x", &sample_token(), 1, &nonce);
        let mut bytes = frame.to_bytes();
        bytes[0] = 0x02;
        assert!(AuthFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_rejects_oversized_client_id() {
        let nonce = sample_nonce(10);
        // Forge a frame with a client_id length just over the cap.
        let mut bytes = vec![AUTH_FRAME_VERSION];
        let big = vec![b'a'; MAX_CLIENT_ID_LEN + 1];
        bytes.extend_from_slice(&((big.len()) as u16).to_be_bytes());
        bytes.extend_from_slice(&big);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(AuthFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn from_bytes_rejects_invalid_utf8_client_id() {
        let nonce = sample_nonce(11);
        let mut bytes = vec![AUTH_FRAME_VERSION];
        let bad = [0xffu8, 0xfe, 0xfd];
        bytes.extend_from_slice(&(bad.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&bad);
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&[0u8; 32]);
        assert!(AuthFrame::from_bytes(&bytes).is_none());
    }

    #[test]
    fn different_nonces_produce_different_hmacs() {
        let token = sample_token();
        let f1 = AuthFrame::build("c", &token, 1, &sample_nonce(20));
        let f2 = AuthFrame::build("c", &token, 1, &sample_nonce(21));
        assert_ne!(f1.hmac, f2.hmac);
    }

    #[test]
    fn different_timestamps_produce_different_hmacs() {
        let token = sample_token();
        let nonce = sample_nonce(22);
        let f1 = AuthFrame::build("c", &token, 1, &nonce);
        let f2 = AuthFrame::build("c", &token, 2, &nonce);
        assert_ne!(f1.hmac, f2.hmac);
    }
}
