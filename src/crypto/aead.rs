use zeroize::Zeroize;

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
        }
    }
}

impl std::error::Error for KeyMaterialError {}

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

/// AES-based QUIC header protection using single-block AES encryption.
pub struct AesHp {
    key: [u8; 16],
}

impl AesHp {
    /// Create a new header protector from the first 16 bytes of `secret`.
    pub fn new(secret: &[u8]) -> Result<Self, KeyMaterialError> {
        require_minimum_length("AES-128-HP", "secret", 16, secret.len())?;
        let mut key = [0u8; 16];
        key.copy_from_slice(&secret[..16]);
        Ok(Self { key })
    }

    pub(crate) fn from_key(key: &[u8; 16]) -> Self {
        Self { key: *key }
    }
}

impl Drop for AesHp {
    fn drop(&mut self) {
        self.key.zeroize();
        crate::secret::observe_erasure("aes_hp_key", &self.key);
    }
}

impl AesHp {
    fn sample_block(&self, sample: &[u8]) -> Result<[u8; 16], KeyMaterialError> {
        require_exact_length("AES-128-HP", "sample", 16, sample.len())?;
        let mut sample_block = [0u8; 16];
        sample_block.copy_from_slice(sample);
        Ok(sample_block)
    }

    fn mask_from_sample(&self, sample: &[u8]) -> Result<[u8; 5], KeyMaterialError> {
        let sample_block = self.sample_block(sample)?;
        let block = crate::crypto::aes128_encrypt_block_fast(&self.key, &sample_block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        Ok(mask)
    }
}

impl HeaderProtector for AesHp {
    fn apply(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError> {
        require_exact_length("AES-128-HP", "mask", 5, mask.len())?;
        let sample_block = self.sample_block(sample)?;
        let block = crate::crypto::aes128_encrypt_block_fast(&self.key, &sample_block);
        for (i, m) in mask.iter_mut().enumerate() {
            *m ^= block[i];
        }
        Ok(())
    }

    fn remove(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError> {
        self.apply(sample, mask) // XOR is self-inverse
    }
}

impl crate::transport::packet::HeaderProtector for AesHp {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], crate::error::ConnectionError> {
        self.mask_from_sample(sample)
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))
    }
}
