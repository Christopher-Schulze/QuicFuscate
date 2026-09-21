use crate::error::ConnectionError;
use ring::hkdf::{KeyType, Prk, HKDF_SHA256};

/// RFC 5869 limit for HKDF-SHA256: 255 * HashLen.
const HKDF_SHA256_MAX: usize = 255 * 32;

struct ExpandLen(usize);

impl KeyType for ExpandLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// One-shot SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// HMAC-SHA-256 keyed hash.
///
/// Ring accepts every key length, including an empty key, per RFC 2104.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    let tag = ring::hmac::sign(&key, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// HKDF-Extract: derive a pseudorandom key from salt and input keying material.
///
/// `ring::hkdf::Salt::extract` is this HMAC and then keeps the PRK inside `Prk`.
/// Callers of this function, including RFC 9001 initial-secret tests, need the
/// raw 32 bytes, so the HMAC is invoked directly.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand: expand a pseudorandom key with context info to `out_len` bytes.
///
/// Returns an error when `out_len` exceeds the RFC 5869 limit of 255 * HashLen
/// (8160 bytes for SHA-256). The expand loop is ring's.
pub fn hkdf_expand(
    prk: &[u8; 32],
    info: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, ConnectionError> {
    if out_len > HKDF_SHA256_MAX {
        return Err(ConnectionError::CryptoError(
            "HKDF-Expand output exceeds the RFC 5869 limit".into(),
        ));
    }
    let prk = Prk::new_less_safe(HKDF_SHA256, prk);
    let info_parts = [info];
    let okm = prk.expand(&info_parts, ExpandLen(out_len)).map_err(|_| {
        ConnectionError::CryptoError("HKDF-Expand rejected the output length".into())
    })?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).map_err(|_| {
        ConnectionError::CryptoError("HKDF-Expand rejected the output buffer".into())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_vector() {
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ]
        );
    }

    #[test]
    fn hkdf_expand_accepts_fixed_prk_at_rfc_limit() {
        let output = hkdf_expand(&[0x42; 32], b"strict-contract", 255 * 32)
            .expect("RFC 5869 maximum length is accepted");
        assert_eq!(output.len(), 255 * 32);
        assert!(hkdf_expand(&[0x42; 32], b"strict-contract", 255 * 32 + 1).is_err());
    }
}
