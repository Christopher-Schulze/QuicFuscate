#![cfg(feature = "rust-tests")]
use quicfuscate::crypto::aes::Aes128Ctx;
use quicfuscate::optimize::telemetry;
use quicfuscate::transport::packet::{CryptoContext, TlsCoverKeyMaterial};

fn poly1305_total_ops() -> u64 {
    telemetry::POLY1305_AVX512_OPS.get()
        + telemetry::POLY1305_AVX2_OPS.get()
        + telemetry::POLY1305_SSE2_OPS.get()
        + telemetry::POLY1305_SVE_OPS.get()
        + telemetry::POLY1305_NEON_OPS.get()
        + telemetry::POLY1305_SCALAR_OPS.get()
}

fn aes_ctr_total_ops() -> u64 {
    telemetry::AES_CTR_AESNI_OPS.get()
        + telemetry::AES_CTR_AESE_OPS.get()
        + telemetry::AES_CTR_SVE_OPS.get()
        + telemetry::AES_CTR_SCALAR_OPS.get()
}

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
    let poly_before = poly1305_total_ops();

    let mut ciphertext = ctx.encrypt_tls_cover_record(&aad, &plaintext).expect("seal");
    assert_eq!(ciphertext.len(), plaintext.len() + 16);

    let len = ctx.decrypt_tls_cover_record(&aad, ciphertext.as_mut_slice()).expect("open");
    assert_eq!(len, plaintext.len());
    assert_eq!(&ciphertext[..len], plaintext.as_slice());

    let after = telemetry::FAKETLS_CHACHA_OPS.get();
    let poly_after = poly1305_total_ops();
    assert!(after > before, "telemetry counter should increase");
    assert!(poly_after > poly_before, "poly1305 backend counters should increase");
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

#[test]
fn aes_ctr_telemetry_increments() {
    let key = [0xA5u8; 16];
    let ctx = Aes128Ctx::new(&key);
    let mut counter = [0u8; 16];
    let input = vec![0x3Cu8; 80];
    let mut output = vec![0u8; input.len()];

    let before = aes_ctr_total_ops();
    ctx.ctr_xor(&mut counter, &input, &mut output);
    let after = aes_ctr_total_ops();
    assert!(
        after > before,
        "AES-CTR counters did not increase (before={}, after={})",
        before,
        after
    );
}
