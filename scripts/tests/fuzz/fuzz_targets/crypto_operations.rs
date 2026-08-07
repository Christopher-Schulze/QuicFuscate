#![no_main]

use libfuzzer_sys::fuzz_target;

use quicfuscate::crypto::aead::{AeadOpen, AeadSeal};
use quicfuscate::crypto::{install_data_aead_config, select_data_aead, ChaCha20Poly1305};
use quicfuscate::engine::{AeadPreference, CryptoConfig};
use quicfuscate::error::ConnectionError;

fuzz_target!(|data: &[u8]| {
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

    let seal =
        ChaCha20Poly1305::new(&key, &nonce).expect("fuzz fixture uses exact key and IV lengths");
    let sealed = seal.seal_with_u64_counter(1, b"ad", &mut buf, payload_len, None);
    if sealed.is_err() {
        return;
    }
    if let Ok(opened) = ChaCha20Poly1305::new(&key, &nonce)
        .expect("fuzz fixture uses exact key and IV lengths")
        .open_with_u64_counter(1, b"ad", &mut buf)
    {
        let _ = opened;
    } else {
        let _ = ConnectionError::CryptoError("crypto failure".into());
    }

    let force = match data[0] % 5 {
        0 => "aegis-128l",
        1 => "aegis",
        2 => "aegis-128x4",
        3 => "aegis-128x8",
        _ => "morus",
    };
    let mut cfg = CryptoConfig { aead_preference: AeadPreference::Auto, ..Default::default() };
    cfg.force_aead = force.to_string();
    install_data_aead_config(&cfg);

    let key16: [u8; 16] = data[..16].try_into().expect("key16");
    let iv: [u8; 12] = data[32..44].try_into().expect("iv");
    let (seal, open) = select_data_aead(&key16, &iv)
        .expect("fuzz fixture uses exact data-plane key and IV lengths");
    let mut data_aead_buf = vec![0u8; payload_len + 16];
    data_aead_buf[..payload_len].copy_from_slice(&data[44..44 + payload_len]);
    if seal.seal_with_u64_counter(7, b"fuzz-ad", &mut data_aead_buf, payload_len, None).is_err() {
        return;
    }
    let _ = open.open_with_u64_counter(7, b"fuzz-ad", &mut data_aead_buf);
});
