//! Root-independent QKey codec and validation contracts.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URLSAFE, Engine as _};

/// Prefix identifying a compact QuicFuscate connection key.
pub const QKEY_PREFIX: &str = "QKey-";

const MAX_QKEY_CHARS: usize = 16 * 1024;
const MAX_DECODED_JSON_BYTES: usize = 16 * 1024;

/// Stable QKey id for server-side registries.
///
/// This is not a secret and must not be used as an authentication primitive.
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

/// Generate a compact QKey string from an already validated configuration value.
pub fn generate(config: &super::QKeyConfig) -> String {
    let json = qf_common::secret::SecretString::new(
        serde_json::to_string(config).unwrap_or_default(),
        "qkey_json_encode",
    );
    let encoded = qf_common::secret::SecretString::new(
        BASE64_URLSAFE.encode(json.as_bytes()),
        "qkey_base64_payload",
    );
    let mut qkey = String::with_capacity(QKEY_PREFIX.len() + encoded.len());
    qkey.push_str(QKEY_PREFIX);
    qkey.push_str(&encoded);
    qkey
}

/// Parse and validate a QKey string.
pub fn parse(qkey: &str) -> Result<super::QKeyConfig, QKeyError> {
    let qkey = qkey.trim();
    if qkey.is_empty() {
        return Err(QKeyError::InvalidPrefix);
    }
    if qkey.len() > MAX_QKEY_CHARS {
        return Err(QKeyError::TooLarge);
    }
    if qkey.len() < QKEY_PREFIX.len() {
        return Err(QKeyError::InvalidPrefix);
    }
    let (prefix, encoded) = qkey.split_at(QKEY_PREFIX.len());
    if !prefix.eq_ignore_ascii_case(QKEY_PREFIX) {
        return Err(QKeyError::InvalidPrefix);
    }

    let decoded = qf_common::secret::SecretBytes::new(
        BASE64_URLSAFE.decode(encoded).map_err(|_| QKeyError::InvalidBase64)?,
        "qkey_decoded_json",
    );
    if decoded.len() > MAX_DECODED_JSON_BYTES {
        return Err(QKeyError::TooLarge);
    }

    let decoded = qf_common::secret::SecretString::try_from_bytes(decoded)
        .map_err(|_| QKeyError::InvalidJson)?;
    let config: super::QKeyConfig =
        serde_json::from_str(decoded.as_str()).map_err(|_| QKeyError::InvalidJson)?;
    if !config.validate() {
        return Err(QKeyError::InvalidChecksum);
    }
    Ok(config)
}

/// Failure classes returned by the bounded QKey parser.
#[derive(Debug, Clone, PartialEq)]
pub enum QKeyError {
    /// The value does not start with the QKey prefix.
    InvalidPrefix,
    /// The payload is not valid URL-safe base64 without padding.
    InvalidBase64,
    /// The decoded payload is not valid UTF-8 JSON for QKeyConfig.
    InvalidJson,
    /// The embedded checksum does not match the serialized fields.
    InvalidChecksum,
    /// The encoded or decoded payload exceeds the parser's hard bound.
    TooLarge,
}

impl std::fmt::Display for QKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix => write!(formatter, "QKey must start with '{QKEY_PREFIX}'"),
            Self::InvalidBase64 => formatter.write_str("Invalid base64 encoding"),
            Self::InvalidJson => formatter.write_str("Invalid JSON format"),
            Self::InvalidChecksum => formatter.write_str("Checksum validation failed"),
            Self::TooLarge => formatter.write_str("QKey payload is too large"),
        }
    }
}

impl std::error::Error for QKeyError {}

#[cfg(test)]
mod tests {
    use super::{generate, id, parse, QKeyError, QKEY_PREFIX};
    use crate::QKeyConfig;

    #[test]
    fn qkey_codec_roundtrips_and_normalizes_ids() {
        let config = QKeyConfig::new("192.0.2.1:4433", "example.com").with_fec("auto");
        let qkey = generate(&config);
        let lower_prefix =
            format!("  {}{}  ", QKEY_PREFIX.to_lowercase(), &qkey[QKEY_PREFIX.len()..]);

        assert_eq!(parse(&qkey).expect("generated QKey parses").remote, config.remote);
        assert_eq!(id(&qkey), id(&lower_prefix));
    }

    #[test]
    fn qkey_parser_rejects_invalid_prefix() {
        assert_eq!(
            parse("invalid").expect_err("invalid prefix must fail"),
            QKeyError::InvalidPrefix
        );
    }
}
