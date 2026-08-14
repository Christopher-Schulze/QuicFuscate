use super::*;

/// HKDF-based key/iv derivation for AEAD from TLS secrets (RFC 9001 compliant)
pub fn derive_key_iv(secret: &[u8]) -> Result<([u8; 32], [u8; 12]), ConnectionError> {
    derive_key_iv_for_version(secret, crate::transport::PROTOCOL_VERSION)
}

/// Derives version-specific packet key and IV material.
pub fn derive_key_iv_for_version(
    secret: &[u8],
    version: u32,
) -> Result<([u8; 32], [u8; 12]), ConnectionError> {
    let key_vec = crate::crypto::kdf::derive_pkt_key_for_version(secret, 32, version)?;
    let iv_vec = crate::crypto::kdf::derive_pkt_iv_for_version(secret, 12, version)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    Ok((key, iv))
}

/// Derive Initial secrets from destination connection ID (RFC 9001 compliant)
pub fn derive_initial_secrets(
    dcid: &[u8],
    version: u32,
) -> Result<(Vec<u8>, Vec<u8>), ConnectionError> {
    let initial_secret = crate::crypto::kdf::derive_initial_secret(dcid, version);
    let client_secret = crate::crypto::kdf::derive_client_initial_secret(&initial_secret)?;
    let server_secret = crate::crypto::kdf::derive_server_initial_secret(&initial_secret)?;
    Ok((client_secret, server_secret))
}
