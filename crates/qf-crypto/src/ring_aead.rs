//! Audited ring AEAD and QUIC header-protection owners.
//!
//! Live Initial AES-128-GCM, AES header protection, Retry integrity tags,
//! TLS-Cover records, and QKey-registry at-rest envelopes use these types.

use crate::aead::{
    require_exact_key_iv, require_exact_length, require_minimum_length, AeadOpen, AeadSeal,
    HeaderProtector, KeyMaterialError, PacketHeaderProtector,
};
use crate::error::ConnectionError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, CHACHA20_POLY1305, NONCE_LEN};
use zeroize::Zeroize;

const TAG_LEN: usize = 16;

fn crypto_failure() -> ConnectionError {
    ConnectionError::CryptoError("crypto failure".into())
}

fn quic_nonce12(iv: &[u8; 12], counter: u64) -> Result<[u8; NONCE_LEN], ConnectionError> {
    let nonce16 = crate::make_nonce16(iv, counter)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&nonce16[..NONCE_LEN]);
    Ok(nonce)
}

fn bind_key(
    algorithm: &'static ring::aead::Algorithm,
    key: &[u8],
) -> Result<LessSafeKey, ConnectionError> {
    let unbound = UnboundKey::new(algorithm, key).map_err(|_| crypto_failure())?;
    Ok(LessSafeKey::new(unbound))
}

/// RFC 9001 §17.2.5 Retry integrity tag: AES-128-GCM over `aad` with an empty
/// plaintext and the fixed per-version Retry key/nonce pair.
pub fn aes128_gcm_tag_aad_only(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8]) -> [u8; 16] {
    let key = bind_key(&AES_128_GCM, key).expect("fixed-size AES-128-GCM key is valid");
    let tag = key
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), &mut [])
        .expect("sealing an empty payload cannot fail");
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.as_ref());
    out
}

/// RFC 9001 AES-128-GCM owner backed by ring.
pub struct RingAesGcm128 {
    key: LessSafeKey,
    iv: [u8; 12],
}

impl RingAesGcm128 {
    /// Create AES-128-GCM from a 16-byte key and 12-byte IV.
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("AES-128-GCM", aead_key, 16, iv, 12)?;
        let mut key = [0u8; 16];
        key.copy_from_slice(aead_key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        let cipher = Self::from_arrays(&key, &iv_array).map_err(|_| KeyMaterialError::Length {
            algorithm: "AES-128-GCM",
            material: "key",
            expected: 16,
            actual: aead_key.len(),
            minimum: false,
        })?;
        key.zeroize();
        iv_array.zeroize();
        Ok(cipher)
    }

    /// Create AES-128-GCM from typed key and IV arrays.
    pub fn from_arrays(aead_key: &[u8; 16], iv: &[u8; 12]) -> Result<Self, ConnectionError> {
        Ok(Self { key: bind_key(&AES_128_GCM, aead_key)?, iv: *iv })
    }
}

impl Drop for RingAesGcm128 {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl AeadSeal for RingAesGcm128 {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let sealed = crate::checked_seal_capacity(buf.len(), len)?;
        let nonce = Nonce::assume_unique_for_key(quic_nonce12(&self.iv, counter)?);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(ad), &mut buf[..len])
            .map_err(|_| crypto_failure())?;
        buf[len..sealed].copy_from_slice(tag.as_ref());
        Ok(sealed)
    }
}

impl AeadOpen for RingAesGcm128 {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if buf.len() < TAG_LEN {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce = Nonce::assume_unique_for_key(quic_nonce12(&self.iv, counter)?);
        let plaintext =
            self.key.open_in_place(nonce, Aad::from(ad), buf).map_err(|_| crypto_failure())?;
        Ok(plaintext.len())
    }
}

/// RFC 8439 ChaCha20-Poly1305 owner backed by ring.
pub struct RingChaCha20Poly1305 {
    key: LessSafeKey,
    iv: [u8; 12],
}

impl RingChaCha20Poly1305 {
    /// Create ChaCha20-Poly1305 from a 32-byte key and 12-byte IV.
    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_key_iv("ChaCha20-Poly1305", key, 32, iv, 12)?;
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(key);
        let mut iv_array = [0u8; 12];
        iv_array.copy_from_slice(iv);
        let cipher =
            Self::from_arrays(&key_array, &iv_array).map_err(|_| KeyMaterialError::Length {
                algorithm: "ChaCha20-Poly1305",
                material: "key",
                expected: 32,
                actual: key.len(),
                minimum: false,
            })?;
        key_array.zeroize();
        iv_array.zeroize();
        Ok(cipher)
    }

    /// Create ChaCha20-Poly1305 from typed key and IV arrays.
    pub fn from_arrays(key: &[u8; 32], iv: &[u8; 12]) -> Result<Self, ConnectionError> {
        Ok(Self { key: bind_key(&CHACHA20_POLY1305, key)?, iv: *iv })
    }
}

impl Drop for RingChaCha20Poly1305 {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

impl AeadSeal for RingChaCha20Poly1305 {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, ConnectionError> {
        let sealed = crate::checked_seal_capacity(buf.len(), len)?;
        let nonce = Nonce::assume_unique_for_key(quic_nonce12(&self.iv, counter)?);
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(ad), &mut buf[..len])
            .map_err(|_| crypto_failure())?;
        buf[len..sealed].copy_from_slice(tag.as_ref());
        Ok(sealed)
    }
}

impl AeadOpen for RingChaCha20Poly1305 {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        if buf.len() < TAG_LEN {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce = Nonce::assume_unique_for_key(quic_nonce12(&self.iv, counter)?);
        let plaintext =
            self.key.open_in_place(nonce, Aad::from(ad), buf).map_err(|_| crypto_failure())?;
        Ok(plaintext.len())
    }
}

/// RFC 9001 AES-ECB header protection owner backed by ring.
pub struct RingAesHp {
    key: ring::aead::quic::HeaderProtectionKey,
}

impl RingAesHp {
    /// Create a header protector from the first 16 bytes of `secret`.
    pub fn new(secret: &[u8]) -> Result<Self, KeyMaterialError> {
        require_minimum_length("AES-128-HP", "secret", 16, secret.len())?;
        Self::from_key_bytes(&secret[..16])
    }

    /// Create a header protector from a 16-byte AES key.
    pub fn from_key(key: &[u8; 16]) -> Result<Self, ConnectionError> {
        Self::from_key_bytes(key).map_err(|error| ConnectionError::CryptoError(error.to_string()))
    }

    fn from_key_bytes(key: &[u8]) -> Result<Self, KeyMaterialError> {
        require_exact_length("AES-128-HP", "key", 16, key.len())?;
        let key = ring::aead::quic::HeaderProtectionKey::new(&ring::aead::quic::AES_128, key)
            .map_err(|_| KeyMaterialError::Length {
                algorithm: "AES-128-HP",
                material: "key",
                expected: 16,
                actual: key.len(),
                minimum: false,
            })?;
        Ok(Self { key })
    }

    fn mask_from_sample(&self, sample: &[u8]) -> Result<[u8; 5], KeyMaterialError> {
        require_exact_length("AES-128-HP", "sample", 16, sample.len())?;
        self.key.new_mask(sample).map_err(|_| KeyMaterialError::Length {
            algorithm: "AES-128-HP",
            material: "sample",
            expected: 16,
            actual: sample.len(),
            minimum: false,
        })
    }
}

impl HeaderProtector for RingAesHp {
    fn apply(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError> {
        require_exact_length("AES-128-HP", "mask", 5, mask.len())?;
        let block = self.mask_from_sample(sample)?;
        for (dst, src) in mask.iter_mut().zip(block.iter()) {
            *dst ^= *src;
        }
        Ok(())
    }

    fn remove(&self, sample: &[u8], mask: &mut [u8]) -> Result<(), KeyMaterialError> {
        self.apply(sample, mask)
    }
}

impl PacketHeaderProtector for RingAesHp {
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], ConnectionError> {
        self.mask_from_sample(sample)
            .map_err(|error| ConnectionError::CryptoError(error.to_string()))
    }
}
