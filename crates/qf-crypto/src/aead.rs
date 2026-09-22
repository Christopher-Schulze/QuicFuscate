/// Invalid key, IV, nonce, or header-protection secret length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMaterialError {
    /// The material has an invalid exact or minimum length.
    Length {
        algorithm: &'static str,
        material: &'static str,
        expected: usize,
        actual: usize,
        minimum: bool,
    },
    /// HKDF-Expand rejected the requested output length.
    Expand { out_len: usize },
}

impl std::fmt::Display for KeyMaterialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length { algorithm, material, expected, actual, minimum } if *minimum => write!(
                formatter,
                "{algorithm} {material} must be at least {expected} bytes, got {actual}"
            ),
            Self::Length { algorithm, material, expected, actual, .. } => write!(
                formatter,
                "{algorithm} {material} must be exactly {expected} bytes, got {actual}"
            ),
            Self::Expand { out_len } => {
                write!(formatter, "HKDF-Expand rejected an output length of {out_len} bytes")
            }
        }
    }
}

impl std::error::Error for KeyMaterialError {}

impl From<KeyMaterialError> for qf_error::ConnectionError {
    fn from(error: KeyMaterialError) -> Self {
        Self::CryptoError(error.to_string())
    }
}

pub(crate) fn require_exact_length(
    algorithm: &'static str,
    material: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), KeyMaterialError> {
    if actual == expected {
        Ok(())
    } else {
        Err(KeyMaterialError::Length { algorithm, material, expected, actual, minimum: false })
    }
}

pub(crate) fn require_minimum_length(
    algorithm: &'static str,
    material: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), KeyMaterialError> {
    if actual >= expected {
        Ok(())
    } else {
        Err(KeyMaterialError::Length { algorithm, material, expected, actual, minimum: true })
    }
}

pub(crate) fn require_exact_key_iv(
    algorithm: &'static str,
    key: &[u8],
    key_len: usize,
    iv: &[u8],
    iv_len: usize,
) -> Result<(), KeyMaterialError> {
    require_exact_length(algorithm, "key", key_len, key.len())?;
    require_exact_length(algorithm, "IV", iv_len, iv.len())
}

/// QUIC packet protection algorithm identifier.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    /// AES-128-GCM as specified in RFC 9001.
    AES128_GCM,
}
/// QUIC encryption level.
#[derive(Clone, Copy, Debug)]
pub enum Level {
    /// Initial encryption level.
    Initial,
    /// 0-RTT encryption level.
    ZeroRTT,
    /// Handshake encryption level.
    Handshake,
    /// 1-RTT (application data) encryption level.
    OneRTT,
}
/// One in-place AEAD seal operation participating in a batch.
pub struct AeadSealItem<'a> {
    /// QUIC packet number used for nonce derivation.
    pub counter: u64,
    /// Associated data (typically the protected header prefix).
    pub ad: &'a [u8],
    /// Payload buffer: first `plaintext_len` bytes are plaintext; 16-byte tag is written after.
    pub buf: &'a mut [u8],
    /// Plaintext length before the AEAD tag.
    pub plaintext_len: usize,
}

/// One in-place AEAD open operation participating in a batch.
pub struct AeadOpenItem<'a> {
    /// QUIC packet number used for nonce derivation.
    pub counter: u64,
    /// Associated data (typically the protected header prefix).
    pub ad: &'a [u8],
    /// Ciphertext + tag buffer; decrypted plaintext is written in place.
    pub buf: &'a mut [u8],
}

/// Trait for AEAD decryption (open) operations.
pub trait AeadOpen {
    fn open_with_u64_counter(
        &self,
        _counter: u64,
        _ad: &[u8],
        _buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        Err(crate::error::ConnectionError::CryptoError("crypto failure".into()))
    }

    /// Returns true when this implementation has a specialized batch open path.
    fn supports_batch_open(&self) -> bool {
        false
    }

    /// Open multiple packets. Default falls back to single-packet open.
    fn open_batch(
        &self,
        items: &mut [AeadOpenItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        for item in items {
            self.open_with_u64_counter(item.counter, item.ad, item.buf)?;
        }
        Ok(())
    }
}

/// Trait for AEAD encryption (seal) operations.
pub trait AeadSeal {
    fn seal_with_u64_counter(
        &self,
        _counter: u64,
        _ad: &[u8],
        _buf: &mut [u8],
        _len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        Err(crate::error::ConnectionError::CryptoError("crypto failure".into()))
    }

    /// Returns true when this implementation has a specialized batch seal path.
    fn supports_batch_seal(&self) -> bool {
        false
    }

    /// Seal multiple packets. Default falls back to single-packet seal.
    fn seal_batch(
        &self,
        items: &mut [AeadSealItem<'_>],
    ) -> Result<(), crate::error::ConnectionError> {
        for item in items {
            self.seal_with_u64_counter(item.counter, item.ad, item.buf, item.plaintext_len, None)?;
        }
        Ok(())
    }
}

/// Trait for QUIC header protection mask application/removal.
pub trait HeaderProtector {
    fn apply(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError>;
    fn remove(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError>;
}

/// Transport-facing header-protection contract.
///
/// The transport consumes only a five-byte mask and must not depend on the crypto implementation
/// details. Keeping this contract here lets the crypto crate own its implementation while TLS
/// cover providers and transport remain downstream adapters.
pub trait PacketHeaderProtector: Send + Sync {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], crate::error::ConnectionError>;
}

/// Callbacks for TLS key schedule events (secret installation).
pub trait KeyScheduleHooks {
    fn set_read_secret(
        &mut self,
        level: Level,
        alg: Algorithm,
        secret: &[u8],
    ) -> Result<(), crate::error::ConnectionError>;
    fn set_write_secret(
        &mut self,
        level: Level,
        alg: Algorithm,
        secret: &[u8],
    ) -> Result<(), crate::error::ConnectionError>;
}
