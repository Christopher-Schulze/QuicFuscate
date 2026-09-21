#![cfg(feature = "rust-tests")]
use quicfuscate::optimize::telemetry;
use quicfuscate::transport::packet::{CryptoContext, TlsCoverKeyMaterial};

fn sample_aad() -> Vec<u8> {
    vec![0x16, 0x03, 0x03, 0x00, 0x00]
}

fn sample_plaintext() -> Vec<u8> {
    b"TLS Cover sample payload".to_vec()
}

#[test]
fn tls_cover_chacha_roundtrip() {
    let mut ctx = CryptoContext::default();
    let key = [0x42u8; 32];
    let iv = [0x24u8; 12];
    ctx.install_tls_cover_cipher(TlsCoverKeyMaterial::ChaCha20Poly1305 { key: &key, iv: &iv })
        .expect("install ChaCha20-Poly1305 TLS cover cipher");

    let aad = sample_aad();
    let plaintext = sample_plaintext();
    let before = telemetry::FAKETLS_CHACHA_OPS.get();

    let mut ciphertext = ctx.encrypt_tls_cover_record(&aad, &plaintext).expect("seal");
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let len = ctx.decrypt_tls_cover_record(&aad, ciphertext.as_mut_slice()).expect("open");
    assert_eq!(len, plaintext.len());
    assert_eq!(&ciphertext[..len], plaintext.as_slice());

    let after = telemetry::FAKETLS_CHACHA_OPS.get();
    assert!(after > before, "telemetry counter should increase");
}

#[test]
fn tls_cover_aes_gcm_roundtrip() {
    let mut ctx = CryptoContext::default();
    let mut aes_key = [0u8; 16];
    for (idx, byte) in aes_key.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    let iv = [0x11u8; 12];
    ctx.install_tls_cover_cipher(TlsCoverKeyMaterial::Aes128Gcm { key: &aes_key, iv: &iv })
        .expect("install AES-128-GCM TLS cover cipher");

    let aad = sample_aad();
    let plaintext = sample_plaintext();
    let before = telemetry::FAKETLS_AES_GCM_OPS.get();

    let mut ciphertext = ctx.encrypt_tls_cover_record(&aad, &plaintext).expect("seal");
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let len = ctx.decrypt_tls_cover_record(&aad, ciphertext.as_mut_slice()).expect("open");
    assert_eq!(len, plaintext.len());
    assert_eq!(&ciphertext[..len], plaintext.as_slice());

    let after = telemetry::FAKETLS_AES_GCM_OPS.get();
    assert!(after > before, "telemetry counter should increase");
}

