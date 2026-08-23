//! Drives the public AEAD seal/open path and the retained data-AEAD selector with arbitrary
//! bytes, including every accepted `force_aead` spelling.
//!
//! A panic, an aborted seal/open, or a fail-open selection on a malformed planner-owned width
//! name is a finding. No key material or handshake state crosses this boundary. The public list
//! covers every accepted `crypto.force_aead` spelling. The internal entries intentionally
//! exercise the runtime's fail-closed fallback for planner-owned width names; they are not valid
//! product configuration values.

use quicfuscate::crypto::aead::{AeadOpen, AeadSeal};
use quicfuscate::crypto::{install_data_aead_config, select_data_aead, ChaCha20Poly1305};
use quicfuscate::engine::{AeadPreference, CryptoConfig};

pub const PUBLIC_FORCE_AEAD_VALUES: [&str; 7] = [
    "auto",
    "aegis-128l",
    "aegis128l",
    "aegis",
    "morus",
    "morus-1280-128",
    "morus1280-128",
];

pub const INTERNAL_AEGIS_BACKEND_VALUES: [&str; 2] = ["aegis-128x4", "aegis-128x8"];

pub fn exercise(data: &[u8]) {
    if data.len() < 44 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[32..44]);
    let payload_len = (data.len() - 44).min(256);
    let mut buf = vec![0u8; payload_len + 16];
    buf[..payload_len].copy_from_slice(&data[44..44 + payload_len]);

    let Ok(seal) = ChaCha20Poly1305::new(&key, &nonce) else {
        return;
    };
    let sealed = seal.seal_with_u64_counter(1, b"ad", &mut buf, payload_len, None);
    if sealed.is_err() {
        return;
    }
    let Ok(open) = ChaCha20Poly1305::new(&key, &nonce) else {
        return;
    };
    if open.open_with_u64_counter(1, b"ad", &mut buf).is_err() {
        return;
    }

    let selector = usize::from(data[0])
        % (PUBLIC_FORCE_AEAD_VALUES.len() + INTERNAL_AEGIS_BACKEND_VALUES.len());
    let force = if selector < PUBLIC_FORCE_AEAD_VALUES.len() {
        PUBLIC_FORCE_AEAD_VALUES[selector]
    } else {
        INTERNAL_AEGIS_BACKEND_VALUES[selector - PUBLIC_FORCE_AEAD_VALUES.len()]
    };
    let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
    cfg.force_aead = force.to_string();
    install_data_aead_config(&cfg);

    let mut key16 = [0u8; 16];
    key16.copy_from_slice(&data[..16]);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&data[32..44]);
    let Ok((seal, open)) = select_data_aead(&key16, &iv) else {
        return;
    };
    let mut data_aead_buf = vec![0u8; payload_len + 16];
    data_aead_buf[..payload_len].copy_from_slice(&data[44..44 + payload_len]);
    if seal.seal_with_u64_counter(7, b"fuzz-ad", &mut data_aead_buf, payload_len, None).is_err() {
        return;
    }
    let _ = open.open_with_u64_counter(7, b"fuzz-ad", &mut data_aead_buf);
}
