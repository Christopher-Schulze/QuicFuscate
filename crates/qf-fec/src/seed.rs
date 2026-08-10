//! Connection-local deterministic seed and decode prefetch contracts.

const FOUNTAIN_SEED_LABEL: &[u8] = b"quicfuscate fec fountain v1";

/// Derive the connection-local fountain seed from the matching QUIC 1-RTT secret.
///
/// The sender's write secret is the receiver's read secret, so both endpoints regenerate
/// identical symbol sets without putting the seed on the wire.
#[doc(hidden)]
pub fn derive_fountain_seed(secret: &[u8]) -> u64 {
    let digest = qf_crypto::hkdf::hmac_sha256(secret, FOUNTAIN_SEED_LABEL);
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed_bytes)
}

/// Prefetch the decode-window hot path when the selected CPU backend supports it.
#[inline(always)]
#[doc(hidden)]
pub fn prefetch_decode_window(ptr: *const u8) {
    super::gf_tables::prefetch_fec_slice(ptr);
}
