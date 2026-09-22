//! Opaque TLS Cover records.
//!
//! `plan_tls_cover_record` builds a TLS record header and random plaintext.
//! That plaintext is not a ClientHello. rustls owns the real handshake.

use zeroize::Zeroize;

const TLS_COVER_HKDF_SALT: &[u8] = b"quicfuscate:tls-cover:salt:v2";
const TLS_COVER_KEY_LEN: usize = 32;
const TLS_COVER_IV_LEN: usize = 12;
const TLS_COVER_MATERIAL_LEN: usize = TLS_COVER_KEY_LEN + TLS_COVER_IV_LEN;

/// Derive fresh connection-local TLS Cover key and IV material from OS entropy.
#[doc(hidden)]
pub fn derive_tls_cover_material(
    profile: &str,
    is_server: bool,
) -> std::io::Result<([u8; TLS_COVER_KEY_LEN], [u8; TLS_COVER_IV_LEN])> {
    let mut entropy = [0u8; TLS_COVER_KEY_LEN];
    qf_common::rng::fill_secure(&mut entropy)?;
    let material = derive_tls_cover_material_from_entropy(profile, is_server, &entropy);
    entropy.zeroize();
    material
}

/// Deterministically derive TLS Cover material from explicit entropy.
#[doc(hidden)]
pub fn derive_tls_cover_material_from_entropy(
    profile: &str,
    is_server: bool,
    entropy: &[u8; TLS_COVER_KEY_LEN],
) -> std::io::Result<([u8; TLS_COVER_KEY_LEN], [u8; TLS_COVER_IV_LEN])> {
    let mut prk = qf_crypto::hkdf::hkdf_extract(TLS_COVER_HKDF_SALT, entropy);
    let info = format!(
        "quicfuscate:tls-cover:{}:{}",
        profile,
        if is_server { "server" } else { "client" }
    );
    let expanded = qf_crypto::hkdf::hkdf_expand(&prk, info.as_bytes(), TLS_COVER_MATERIAL_LEN);
    prk.zeroize();
    let mut output = expanded.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TLS Cover HKDF-Expand rejected a legal length",
        )
    })?;
    let mut key = [0u8; TLS_COVER_KEY_LEN];
    let mut iv = [0u8; TLS_COVER_IV_LEN];
    key.copy_from_slice(&output[..TLS_COVER_KEY_LEN]);
    iv.copy_from_slice(&output[TLS_COVER_KEY_LEN..]);
    prk.zeroize();
    output.zeroize();
    Ok((key, iv))
}

/// Plaintext and timing plan for one synthetic encrypted TLS Cover record.
#[doc(hidden)]
pub struct TlsCoverRecordPlan {
    /// TLS record header authenticated by the root encryption context.
    pub header: [u8; 5],
    /// Synthetic handshake plaintext encrypted by the root context.
    pub payload: Vec<u8>,
    /// Optional synchronous delay applied after encryption on the dedicated cover path.
    pub jitter: Option<std::time::Duration>,
}

/// Bounded planning failure before any encryption or sequence mutation occurs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsCoverRecordPlanError {
    /// A checked record-length calculation exceeded the platform integer range.
    LengthOverflow,
}

/// Plan one synthetic TLS Cover record without accessing root crypto state.
#[doc(hidden)]
pub fn plan_tls_cover_record(
    max_len: usize,
    performance_mode: bool,
    is_server: bool,
    fingerprint_profile: &str,
    environment: &qf_common::env_utils::EnvSnapshot,
) -> Result<Option<TlsCoverRecordPlan>, TlsCoverRecordPlanError> {
    use rand::Rng;

    const TLS_RECORD_HEADER_LEN: usize = 5;
    const AEAD_TAG_LEN: usize = 16;
    let record_overhead = TLS_RECORD_HEADER_LEN + AEAD_TAG_LEN;
    if max_len < record_overhead {
        return Ok(None);
    }

    let payload_capacity = max_len - record_overhead;
    let max_payload = payload_capacity.min(u16::MAX as usize - AEAD_TAG_LEN);
    let mut rng = rand::rng();
    let mut payload_size = if performance_mode {
        max_payload.min(if is_server { 800 } else { 1200 })
    } else {
        let upper = max_payload.min(if is_server { 700 } else { 800 });
        let lower = max_payload.min(if is_server { 150 } else { 200 });
        let base_size = if max_payload > 1000 {
            rng.random_range(lower..=upper)
        } else if lower == upper {
            lower
        } else {
            rng.random_range(lower..=upper)
        };
        base_size
            .checked_add(rng.random_range(0..50))
            .ok_or(TlsCoverRecordPlanError::LengthOverflow)?
            .min(max_payload)
    };

    if !performance_mode {
        let padding_cap = environment
            .parse_first(["QUICFUSCATE_STEALTH_PADDING_MAX", "QUICFUSCATE_STEALTH_MAX_PADDING"])
            .unwrap_or(0usize);
        let headroom = max_payload.saturating_sub(payload_size);
        if padding_cap > 0 && headroom > 0 {
            payload_size = payload_size
                .checked_add(rng.random_range(0..=padding_cap.min(headroom)))
                .ok_or(TlsCoverRecordPlanError::LengthOverflow)?;
        }
    }

    let cipher_len =
        payload_size.checked_add(AEAD_TAG_LEN).ok_or(TlsCoverRecordPlanError::LengthOverflow)?;
    let cipher_len =
        u16::try_from(cipher_len).map_err(|_| TlsCoverRecordPlanError::LengthOverflow)?;
    let cipher_len_bytes = cipher_len.to_be_bytes();
    let header = [0x16, 0x03, 0x03, cipher_len_bytes[0], cipher_len_bytes[1]];

    if fingerprint_profile.len() > 64 {
        return Err(TlsCoverRecordPlanError::LengthOverflow);
    }
    let mut payload = vec![0u8; payload_size];
    rng.fill(&mut payload[..]);

    let jitter = if performance_mode {
        None
    } else {
        environment
            .parse_first::<u64, 1>(["QUICFUSCATE_STEALTH_JITTER_US"])
            .filter(|maximum| *maximum > 0)
            .map(|maximum| std::time::Duration::from_micros(rng.random_range(1..=maximum)))
    };

    Ok(Some(TlsCoverRecordPlan { header, payload, jitter }))
}

/// Cipher suite used by the TLS Cover provider for encrypting synthetic records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsCoverCipherSuite {
    /// ChaCha20-Poly1305 (preferred on platforms without hardware AES).
    ChaCha20Poly1305,
    /// AES-128-GCM (preferred when hardware AES acceleration is available).
    Aes128Gcm,
}

impl TlsCoverCipherSuite {
    /// Returns the stable operator-facing name used by TLS Cover diagnostics.
    #[doc(hidden)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes128Gcm => "aes-128-gcm",
        }
    }

    /// Returns the TLS wire-format cipher suite ID (for ServerHello).
    #[doc(hidden)]
    pub fn tls_id(self) -> u16 {
        match self {
            Self::ChaCha20Poly1305 => 0x1303,
            Self::Aes128Gcm => 0x1301,
        }
    }
}

/// Owned synthetic ServerHello parameters for storing in fingerprint profiles.
#[derive(Debug, Clone)]
pub struct ServerHelloParamsOwned {
    /// TLS protocol version (e.g. `0x0303` for TLS 1.2 compat).
    pub tls_version: u16,
    /// Negotiated cipher suite IANA identifier.
    pub cipher_suite: u16,
    /// Raw extension bytes for the ServerHello record.
    pub extensions: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_cover_cipher_suite_wire_contract_is_stable() {
        assert_eq!(TlsCoverCipherSuite::Aes128Gcm.as_str(), "aes-128-gcm");
        assert_eq!(TlsCoverCipherSuite::Aes128Gcm.tls_id(), 0x1301);
        assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.as_str(), "chacha20-poly1305");
        assert_eq!(TlsCoverCipherSuite::ChaCha20Poly1305.tls_id(), 0x1303);
    }

    #[test]
    fn tls_cover_material_derivation_is_deterministic_and_domain_separated() {
        let entropy = [0x5a; TLS_COVER_KEY_LEN];
        let client = derive_tls_cover_material_from_entropy("chrome", false, &entropy)
            .expect("legal TLS Cover length");
        assert_eq!(
            client,
            derive_tls_cover_material_from_entropy("chrome", false, &entropy)
                .expect("legal TLS Cover length")
        );
        assert_ne!(
            client,
            derive_tls_cover_material_from_entropy("chrome", true, &entropy)
                .expect("legal TLS Cover length")
        );
        assert_ne!(
            client,
            derive_tls_cover_material_from_entropy("firefox", false, &entropy)
                .expect("legal TLS Cover length")
        );
    }

    #[test]
    fn fresh_tls_cover_material_is_not_reused_between_connections() {
        let first = derive_tls_cover_material("chrome", false).expect("first material");
        let second = derive_tls_cover_material("chrome", false).expect("second material");
        assert_ne!(first, second);
    }

    #[test]
    fn performance_record_plan_is_role_bounded_and_has_no_jitter() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([]);
        let client = plan_tls_cover_record(4096, true, false, "chrome", &environment)
            .expect("plan")
            .expect("record");
        let server = plan_tls_cover_record(4096, true, true, "firefox", &environment)
            .expect("plan")
            .expect("record");
        assert_eq!(client.payload.len(), 1200);
        assert_eq!(server.payload.len(), 800);
        assert!(client.jitter.is_none());
        assert!(server.jitter.is_none());
    }

    #[test]
    fn record_plan_respects_tls_u16_length_under_large_padding_cap() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_STEALTH_PADDING_MAX", "100000"),
            ("QUICFUSCATE_STEALTH_JITTER_US", "25"),
        ]);
        let plan = plan_tls_cover_record(100_000, false, false, "edge", &environment)
            .expect("plan")
            .expect("record");
        let encoded_len = u16::from_be_bytes([plan.header[3], plan.header[4]]) as usize;
        assert_eq!(encoded_len, plan.payload.len() + 16);
        assert!(plan.payload.len() <= u16::MAX as usize - 16);
        assert!(plan.jitter.is_some_and(|jitter| jitter.as_micros() <= 25));
    }

    #[test]
    fn record_plan_rejects_capacity_smaller_than_header_and_tag() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([]);
        assert!(plan_tls_cover_record(20, false, false, "chrome", &environment)
            .expect("plan")
            .is_none());
    }

    #[test]
    fn record_plan_plaintext_is_not_a_stamped_client_hello() {
        let environment = qf_common::env_utils::EnvSnapshot::from_pairs([]);
        let mut stamped = 0u32;
        for _ in 0..16 {
            let plan = plan_tls_cover_record(4096, true, false, "chrome", &environment)
                .expect("plan")
                .expect("record");
            let looks_like_hello = plan.payload.first() == Some(&0x01)
                && plan.payload.get(4..6) == Some(&[0x03, 0x03]);
            if looks_like_hello {
                stamped += 1;
            }
        }
        assert_eq!(stamped, 0);
        assert!(plan_tls_cover_record(4096, true, false, &"x".repeat(65), &environment).is_err());
    }

}
