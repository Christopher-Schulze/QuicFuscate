//! Root-independent QKey codec and validation contracts.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URLSAFE, Engine as _};

/// Zeroizing owner for an engine configuration QKey bearer token.
#[derive(Clone)]
pub struct QKeyToken(qf_common::secret::SecretString);

const AUTHENTICATED_TRANSCRIPT_DOMAIN: &[u8] = b"quicfuscate-qkey-auth-transcript-v1";

impl QKeyToken {
    /// Create a token owner from its raw string value.
    pub fn new(value: String) -> Self {
        Self(qf_common::secret::SecretString::new(value, "qkey_token"))
    }

    /// Derive the bounded, secret-free transcript hash used by authenticated private control.
    ///
    /// The token is decoded only inside this function and is never returned or logged. The
    /// resulting digest is stable across the client token owner and the server-side verifier
    /// record, so both endpoints can bind the same authenticated control context.
    pub fn authenticated_transcript_hash(&self) -> Option<[u8; 32]> {
        authenticated_transcript_hash_from_token_hex(self)
    }
}

impl std::fmt::Debug for QKeyToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QKeyToken([REDACTED])")
    }
}

impl std::ops::Deref for QKeyToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl AsRef<str> for QKeyToken {
    fn as_ref(&self) -> &str {
        self
    }
}

/// Derive the authenticated transcript hash from a 64-character hexadecimal token.
pub fn authenticated_transcript_hash_from_token_hex(token_hex: &str) -> Option<[u8; 32]> {
    let token_digest = decode_hex_digest(token_hex)?;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(token_digest);
    let verifier_digest = hasher.finalize();
    let mut verifier_digest_array = [0u8; 32];
    verifier_digest_array.copy_from_slice(&verifier_digest);
    Some(hash_authenticated_verifier_digest(&verifier_digest_array))
}

/// Derive the same authenticated transcript hash from the stored SHA-256 verifier digest.
pub fn authenticated_transcript_hash_from_verifier_hash_hex(
    verifier_hash_hex: &str,
) -> Option<[u8; 32]> {
    let verifier_digest = decode_hex_digest(verifier_hash_hex)?;
    Some(hash_authenticated_verifier_digest(&verifier_digest))
}

fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    for (index, pair) in pairs.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        digest[index] = (high << 4) | low;
    }
    Some(digest)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hash_authenticated_verifier_digest(verifier_digest: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(AUTHENTICATED_TRANSCRIPT_DOMAIN);
    hasher.update(verifier_digest);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

impl From<String> for QKeyToken {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for QKeyToken {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

impl serde::Serialize for QKeyToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for QKeyToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

/// Compact connection parameters embedded in a QKey string.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QKeyConfig {
    /// Remote server address (host:port).
    pub remote: String,
    /// SNI hostname for TLS.
    pub sni: String,
    /// Stealth mode (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    /// FEC mode (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
    /// Custom parameters (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
    /// QKey authentication token (hex, optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<QKeyToken>,
    /// Checksum string (`s256:<8-hex>` for newly generated keys).
    #[serde(rename = "m")]
    pub md5: String,
}

impl QKeyConfig {
    /// Create a new QKey configuration.
    pub fn new(remote: &str, sni: &str) -> Self {
        let mut config = Self {
            remote: remote.to_string(),
            sni: sni.to_string(),
            stealth: None,
            fec: None,
            extra: None,
            token: None,
            md5: String::new(),
        };
        config.update_checksum();
        config
    }

    /// Set stealth mode and refresh the checksum.
    pub fn with_stealth(mut self, mode: &str) -> Self {
        self.stealth = Some(mode.to_string());
        self.update_checksum();
        self
    }

    /// Set FEC mode and refresh the checksum.
    pub fn with_fec(mut self, mode: &str) -> Self {
        self.fec = Some(mode.to_string());
        self.update_checksum();
        self
    }

    /// Set custom parameters and refresh the checksum.
    pub fn with_extra(mut self, extra: &str) -> Self {
        self.extra = Some(extra.to_string());
        self.update_checksum();
        self
    }

    /// Set a token from its raw string value and refresh the checksum.
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(QKeyToken::from(token));
        self.update_checksum();
        self
    }

    /// Set an already-owned token without creating another raw-secret owner.
    pub fn with_owned_token(mut self, token: QKeyToken) -> Self {
        self.token = Some(token);
        self.update_checksum();
        self
    }

    fn checksum_prefix8_hex(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for (index, field) in [
            self.remote.as_str(),
            self.sni.as_str(),
            self.stealth.as_deref().unwrap_or(""),
            self.fec.as_deref().unwrap_or(""),
            self.extra.as_deref().unwrap_or(""),
            self.token.as_deref().unwrap_or(""),
        ]
        .into_iter()
        .enumerate()
        {
            if index > 0 {
                hasher.update(b"|");
            }
            hasher.update(field.as_bytes());
        }
        let hex = format!("{:x}", hasher.finalize());
        hex.chars().take(8).collect()
    }

    fn is_hex8(value: &str) -> bool {
        value.len() == 8 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
    }

    fn update_checksum(&mut self) {
        self.md5 = format!("s256:{}", self.checksum_prefix8_hex());
    }

    /// Validate the embedded checksum.
    pub fn validate(&self) -> bool {
        let checksum = self.md5.trim();
        let Some(rest) = checksum.strip_prefix("s256:") else {
            return false;
        };
        Self::is_hex8(rest) && rest.eq_ignore_ascii_case(&self.checksum_prefix8_hex())
    }
}

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
pub fn generate(config: &QKeyConfig) -> String {
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
pub fn parse(qkey: &str) -> Result<QKeyConfig, QKeyError> {
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
    let config: QKeyConfig =
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
    use super::QKeyConfig;
    use super::{generate, id, parse, QKeyError, QKEY_PREFIX};

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
