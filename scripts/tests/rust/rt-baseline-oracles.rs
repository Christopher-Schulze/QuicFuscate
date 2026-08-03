#![cfg(feature = "rust-tests")]
use quicfuscate::crypto::aead::{AeadOpen, AeadSeal};
use quicfuscate::crypto::{Aegis128LAead, AesGcm128, MorusAead};
use quicfuscate::fec::matrix_multiply_scalar;

fn make_vec(data: &[&[u8]]) -> Vec<Vec<u8>> {
    data.iter().map(|row| row.to_vec()).collect()
}

#[test]
fn aegis128l_roundtrip() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 12];
    let mut buf = b"example payload for aegis".to_vec();
    let ad = b"associated-data";

    buf.resize(buf.len() + 16, 0);

    let seal = Aegis128LAead::new(&key, &iv).expect("exact AEGIS fixture lengths");
    let open = Aegis128LAead::new(&key, &iv).expect("exact AEGIS fixture lengths");

    let pt_len = buf.len() - 16;
    let ct_len = seal.seal_with_u64_counter(7, ad, &mut buf, pt_len, None).expect("seal");
    assert_eq!(ct_len, buf.len());

    let mut decrypt_buf = buf.clone();
    let pt_len = open.open_with_u64_counter(7, ad, &mut decrypt_buf).expect("open");
    decrypt_buf.truncate(pt_len);
    assert_eq!(decrypt_buf, b"example payload for aegis");
}

#[test]
fn aes_gcm_roundtrip() {
    let key = [0x33u8; 16];
    let iv = [0x44u8; 12];
    let mut buf = b"aes gcm payload".to_vec();
    buf.resize(buf.len() + 16, 0);

    let seal = AesGcm128::new(&key, &iv).expect("exact AES-GCM fixture lengths");
    let open = AesGcm128::new(&key, &iv).expect("exact AES-GCM fixture lengths");

    let ad = b"aad";
    let pt_len = buf.len() - 16;
    let ct_len = seal.seal_with_u64_counter(123, ad, &mut buf, pt_len, None).expect("seal");
    assert_eq!(ct_len, buf.len());

    let mut decrypt_buf = buf.clone();
    let pt_len = open.open_with_u64_counter(123, ad, &mut decrypt_buf).expect("open");
    decrypt_buf.truncate(pt_len);
    assert_eq!(decrypt_buf, b"aes gcm payload");
}

#[test]
fn morus_roundtrip() {
    let key = [0x55u8; 16];
    let iv = [0x66u8; 12];
    let mut buf = b"morus stream data".to_vec();
    buf.resize(buf.len() + 16, 0);

    let seal = MorusAead::new(&key, &iv).expect("exact MORUS fixture lengths");
    let open = MorusAead::new(&key, &iv).expect("exact MORUS fixture lengths");

    let ad = b"morus aad";
    let pt_len = buf.len() - 16;
    let ct_len = seal.seal_with_u64_counter(0, ad, &mut buf, pt_len, None).expect("seal");
    assert_eq!(ct_len, buf.len());

    let mut decrypt_buf = buf.clone();
    let pt_len = open.open_with_u64_counter(0, ad, &mut decrypt_buf).expect("open");
    decrypt_buf.truncate(pt_len);
    assert_eq!(decrypt_buf, b"morus stream data");
}

#[test]
fn aegis128l_rejects_tampered_tag() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 12];
    let mut buf = b"tamper aegis".to_vec();
    buf.resize(buf.len() + 16, 0);

    let seal = Aegis128LAead::new(&key, &iv).expect("exact AEGIS fixture lengths");
    let open = Aegis128LAead::new(&key, &iv).expect("exact AEGIS fixture lengths");
    let ad = b"aad";
    let pt_len = buf.len() - 16;
    let ct_len = seal.seal_with_u64_counter(9, ad, &mut buf, pt_len, None).expect("seal");
    assert_eq!(ct_len, buf.len());

    let idx = buf.len() - 1;
    buf[idx] ^= 0xFF; // corrupt tag
    let res = open.open_with_u64_counter(9, ad, &mut buf);
    assert!(res.is_err(), "tampered tag must fail");
}

#[test]
fn aes_gcm_rejects_tampered_tag() {
    let key = [0x33u8; 16];
    let iv = [0x44u8; 12];
    let mut buf = b"tamper gcm".to_vec();
    buf.resize(buf.len() + 16, 0);

    let seal = AesGcm128::new(&key, &iv).expect("exact AES-GCM fixture lengths");
    let open = AesGcm128::new(&key, &iv).expect("exact AES-GCM fixture lengths");
    let ad = b"aad";
    let pt_len = buf.len() - 16;
    let ct_len = seal.seal_with_u64_counter(42, ad, &mut buf, pt_len, None).expect("seal");
    assert_eq!(ct_len, buf.len());

    let idx = buf.len() - 2;
    buf[idx] ^= 0xAA; // corrupt tag
    let res = open.open_with_u64_counter(42, ad, &mut buf);
    assert!(res.is_err(), "tampered tag must fail");
}

#[test]
fn matrix_identity_roundtrip() {
    let a = make_vec(&[&[0x12, 0x34, 0x56], &[0xaa, 0xbb, 0xcc], &[0x01, 0x02, 0x03]]);

    let identity = make_vec(&[&[0x01, 0x00, 0x00], &[0x00, 0x01, 0x00], &[0x00, 0x00, 0x01]]);

    let mut result = vec![vec![0u8; 3]; 3];
    matrix_multiply_scalar(&a, &identity, &mut result);
    assert_eq!(result, a);

    let mut zero = vec![vec![0u8; 3]; 3];
    matrix_multiply_scalar(&a, &vec![vec![0u8; 3]; 3], &mut zero);
    assert!(zero.iter().all(|row| row.iter().all(|&v| v == 0)));
}
