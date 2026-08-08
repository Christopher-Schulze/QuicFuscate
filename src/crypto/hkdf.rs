use sha2::Digest;

/// One-shot SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA-256 keyed hash.
///
/// `Hmac<Sha256>::new_from_slice` is infallible for this digest implementation:
/// the key is normalized to the fixed SHA-256 block size before construction.
/// The dependency still exposes a fallible trait API, so the narrow lint
/// disposition below keeps that proven invariant visible at the call site.
#[allow(clippy::expect_used)]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    // HMAC accepts any key length, including an empty key, per RFC 2104.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// HKDF-Extract: derive a pseudorandom key from salt and input keying material.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand: expand a pseudorandom key with context info to `out_len` bytes.
///
/// # Panics
/// Panics if `out_len` exceeds the RFC 5869 limit of 255 * HashLen = 8160 bytes for SHA-256.
#[allow(clippy::expect_used)]
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    // RFC 5869 §2.3: L must be <= 255*HashLen. For SHA-256 that is 255*32 = 8160 bytes.
    assert!(
        out_len <= 255 * 32,
        "HKDF-Expand: out_len {} exceeds RFC 5869 limit of 8160 bytes",
        out_len
    );
    // from_prk() only fails when prk is shorter than HashLen; our fixed [u8; 32] always satisfies this.
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("PRK length is valid for SHA-256");
    let mut out = vec![0u8; out_len];
    // expand() only fails when out_len exceeds the RFC limit, which we already assert above.
    hk.expand(info, &mut out).expect("output length within HKDF limits");
    out
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
        let output = hkdf_expand(&[0x42; 32], b"strict-contract", 255 * 32);
        assert_eq!(output.len(), 255 * 32);
    }
}
