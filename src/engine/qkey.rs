//! QKey - Compact Connection Key Format
//!
//! A single string that contains all connection parameters.
//! Format: `QKey-<base64url_encoded_config>`
//!
//! The config includes an embedded checksum for accidental tamper detection.
//! Note: The checksum is not a cryptographic signature. Treat the QKey token as the capability.
//!
//! # Example
//! ```text
//! QKey-eyJyZW1vdGUiOiIxOTIuMTY4LjEuMTo0NDMzIiwic25pIjoiZXhhbXBsZS5jb20iLCJtZDUiOiJhM2YyYjhjOSJ9
//! ```

use crate::secret::{SecretBytes, SecretString};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URLSAFE, Engine as _};

/// QKey prefix
pub const QKEY_PREFIX: &str = "QKey-";

pub use qf_engine_types::{QKeyConfig, QKeyToken};

// Hard limits to keep parsing safe for untrusted input (copy/paste, clipboard).
const MAX_QKEY_CHARS: usize = 16 * 1024;
const MAX_DECODED_JSON_BYTES: usize = 16 * 1024;

/// Stable QKey id for server-side registries.
///
/// This is *not* a secret. It is used as a compact identifier and should not be relied on for
/// authentication. Authentication must use a separate secret (for example a token verified
/// post-handshake).
pub fn id(qkey: &str) -> String {
    let trimmed = qkey.trim();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    if trimmed
        .get(..QKEY_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(QKEY_PREFIX))
    {
        hasher.update(QKEY_PREFIX.as_bytes());
        hasher.update(&trimmed.as_bytes()[QKEY_PREFIX.len()..]);
    } else {
        hasher.update(trimmed.as_bytes());
    }
    let hex = format!("{:x}", hasher.finalize());
    hex.chars().take(12).collect()
}

/// Generate a QKey string from config.
pub fn generate(config: &QKeyConfig) -> String {
    let json =
        SecretString::new(serde_json::to_string(config).unwrap_or_default(), "qkey_json_encode");
    // Prefer URL-safe base64 without padding for copy/paste stability.
    let encoded = SecretString::new(BASE64_URLSAFE.encode(json.as_bytes()), "qkey_base64_payload");
    let mut qkey = String::with_capacity(QKEY_PREFIX.len() + encoded.len());
    qkey.push_str(QKEY_PREFIX);
    qkey.push_str(&encoded);
    qkey
}

/// Parse a QKey string back to config.
pub fn parse(qkey: &str) -> Result<QKeyConfig, QKeyError> {
    let qkey = qkey.trim();
    if qkey.is_empty() {
        return Err(QKeyError::InvalidPrefix);
    }
    if qkey.len() > MAX_QKEY_CHARS {
        return Err(QKeyError::TooLarge);
    }
    // Check prefix
    if qkey.len() < QKEY_PREFIX.len() {
        return Err(QKeyError::InvalidPrefix);
    }
    let (prefix, rest) = qkey.split_at(QKEY_PREFIX.len());
    if !prefix.eq_ignore_ascii_case(QKEY_PREFIX) {
        return Err(QKeyError::InvalidPrefix);
    }

    // Extract base64 part
    let encoded = rest;

    let decoded = SecretBytes::new(
        BASE64_URLSAFE.decode(encoded).map_err(|_| QKeyError::InvalidBase64)?,
        "qkey_decoded_json",
    );

    if decoded.len() > MAX_DECODED_JSON_BYTES {
        return Err(QKeyError::TooLarge);
    }

    // Parse JSON only after the bounded decoded bytes pass the UTF-8 secret boundary.
    let decoded = SecretString::try_from_bytes(decoded).map_err(|_| QKeyError::InvalidJson)?;
    let config: QKeyConfig =
        serde_json::from_str(decoded.as_str()).map_err(|_| QKeyError::InvalidJson)?;

    // Validate checksum
    if !config.validate() {
        return Err(QKeyError::InvalidChecksum);
    }

    Ok(config)
}

/// QKey error types.
#[derive(Debug, Clone, PartialEq)]
pub enum QKeyError {
    InvalidPrefix,
    InvalidBase64,
    InvalidJson,
    InvalidChecksum,
    TooLarge,
}

impl std::fmt::Display for QKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "QKey must start with '{}'", QKEY_PREFIX),
            Self::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            Self::InvalidJson => write!(f, "Invalid JSON format"),
            Self::InvalidChecksum => write!(f, "Checksum validation failed"),
            Self::TooLarge => write!(f, "QKey payload is too large"),
        }
    }
}

impl std::error::Error for QKeyError {}

/// Convert from EngineConfig to QKeyConfig.
impl From<&crate::engine::EngineConfig> for QKeyConfig {
    fn from(cfg: &crate::engine::EngineConfig) -> Self {
        let stealth = match cfg.stealth.mode {
            crate::engine::StealthMode::Off => None,
            crate::engine::StealthMode::Performance => Some("performance".to_string()),
            crate::engine::StealthMode::Stealth => Some("stealth".to_string()),
            crate::engine::StealthMode::AntiDpi => Some("anti-dpi".to_string()),
            crate::engine::StealthMode::Manual => Some("manual".to_string()),
            crate::engine::StealthMode::Auto => Some("auto".to_string()),
        };

        let fec = match cfg.fec.mode {
            crate::engine::FecMode::Off => None,
            crate::engine::FecMode::Auto => Some("auto".to_string()),
        };

        let mut qkey = QKeyConfig::new(&cfg.connection.remote, &cfg.connection.sni);
        if let Some(s) = stealth {
            qkey = qkey.with_stealth(&s);
        }
        if let Some(f) = fec {
            qkey = qkey.with_fec(&f);
        }
        qkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkey_generate_parse() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com");

        let qkey = generate(&config);
        assert!(qkey.starts_with(QKEY_PREFIX));

        let parsed = parse(&qkey).unwrap();
        assert_eq!(parsed.remote, "192.168.1.1:4433");
        assert_eq!(parsed.sni, "example.com");
        assert!(parsed.validate());
    }

    #[test]
    fn test_qkey_with_options() {
        let config = QKeyConfig::new("vpn.example.com:443", "cdn.example.com")
            .with_stealth("full")
            .with_fec("auto");

        let qkey = generate(&config);
        let parsed = parse(&qkey).unwrap();

        assert_eq!(parsed.stealth, Some("full".to_string()));
        assert_eq!(parsed.fec, Some("auto".to_string()));
    }

    #[test]
    fn test_qkey_invalid_prefix() {
        let result = parse("Invalid-xyz123");
        assert_eq!(result.unwrap_err(), QKeyError::InvalidPrefix);
    }

    #[test]
    fn test_qkey_invalid_checksum() {
        // Create a valid key
        let config = QKeyConfig::new("test:4433", "test.com");
        // Tamper with it. Base64 encoding prevents simple string replacement, so create a bad checksum instead.

        // Create with wrong checksum manually
        let mut bad_config = config.clone();
        // Use a wrong checksum format to ensure validate() fails.
        bad_config.md5 = "s256:00000000".to_string();
        let json = serde_json::to_string(&bad_config).unwrap();
        let encoded = BASE64_URLSAFE.encode(json.as_bytes());
        let bad_qkey = format!("{}{}", QKEY_PREFIX, encoded);

        let result = parse(&bad_qkey);
        assert_eq!(result.unwrap_err(), QKeyError::InvalidChecksum);
    }

    #[test]
    fn test_qkey_prefix_is_case_insensitive_and_trimmed() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com");
        let qkey = generate(&config);
        // Only change the prefix case. Lowercasing the full string would corrupt the base64 payload.
        let rest = &qkey[QKEY_PREFIX.len()..];
        let lower = format!("  {}{}  ", QKEY_PREFIX.to_lowercase(), rest);
        let parsed = parse(&lower).unwrap();
        assert_eq!(parsed.remote, "192.168.1.1:4433");
        assert_eq!(parsed.sni, "example.com");
    }

    #[test]
    fn test_qkey_id_is_stable_across_prefix_case_and_whitespace() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com").with_token(&"a".repeat(64));
        let qkey = generate(&config);
        let rest = &qkey[QKEY_PREFIX.len()..];

        let canonical = format!("{}{}", QKEY_PREFIX, rest);
        let lower = format!("  {}{}  ", QKEY_PREFIX.to_lowercase(), rest);

        assert_eq!(id(&canonical), id(&lower));
    }

    #[test]
    fn test_qkey_compactness() {
        let config =
            QKeyConfig::new("vpn.example.com:4433", "cdn.example.com").with_stealth("full");

        let qkey = generate(&config);

        // Should be reasonably compact
        assert!(qkey.len() < 200);
        println!("QKey length: {} chars", qkey.len());
        println!("QKey: {}", qkey);
    }

    #[test]
    fn test_qkey_invalid_base64() {
        let bad = format!("{}{}", QKEY_PREFIX, "$$$not-base64$$$");
        let err = parse(&bad).unwrap_err();
        assert_eq!(err, QKeyError::InvalidBase64);
    }

    #[test]
    fn test_qkey_invalid_json() {
        // Valid base64, invalid JSON.
        let encoded = BASE64_URLSAFE.encode(b"not-json");
        let bad = format!("{}{}", QKEY_PREFIX, encoded);
        let err = parse(&bad).unwrap_err();
        assert_eq!(err, QKeyError::InvalidJson);
    }

    #[test]
    fn test_qkey_invalid_utf8_payload_is_rejected_as_invalid_json() {
        let encoded = BASE64_URLSAFE.encode(vec![0xff_u8, 0xfe]);
        let bad = format!("{}{}", QKEY_PREFIX, encoded);
        let err = parse(&bad).unwrap_err();
        assert_eq!(err, QKeyError::InvalidJson);
    }

    #[test]
    fn test_qkey_too_large_is_rejected() {
        // Exceed MAX_QKEY_CHARS to guarantee fast rejection before decoding.
        let oversized = format!("{}{}", QKEY_PREFIX, "A".repeat(MAX_QKEY_CHARS));
        assert_eq!(parse(&oversized).unwrap_err(), QKeyError::TooLarge);
    }

    #[test]
    fn qkey_token_normal_replacement_and_parse_error_paths_erase_owned_bytes() {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let mut token = Some(QKeyToken::new("a".repeat(64)));
        drop(token.replace(QKeyToken::new("b".repeat(64))));
        drop(token);

        let invalid_checksum_qkey = {
            let mut config =
                QKeyConfig::new("127.0.0.1:4433", "example.com").with_token(&"c".repeat(64));
            config.md5 = "s256:00000000".to_string();
            generate(&config)
        };
        events.lock().expect("clear setup events").clear();
        assert_eq!(
            parse(&invalid_checksum_qkey).expect_err("invalid checksum must fail"),
            QKeyError::InvalidChecksum
        );

        let events = events.lock().expect("erasure events");
        let token_events: Vec<_> =
            events.iter().filter(|(label, _)| *label == "qkey_token").collect();
        assert!(
            !token_events.is_empty(),
            "normal, replacement, and error owners must emit token erasure evidence"
        );
        for (_, bytes) in token_events {
            assert_eq!(bytes.len(), 64);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
        let decoded = events
            .iter()
            .find_map(|(label, bytes)| (*label == "qkey_decoded_json").then_some(bytes))
            .expect("decoded JSON erasure event");
        assert!(!decoded.is_empty());
        assert!(decoded.iter().all(|byte| *byte == 0));
    }
}
