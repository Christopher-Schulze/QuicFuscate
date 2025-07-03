use crypto::{Aegis128L, CipherSuiteSelector};

const MSG: &[u8] = b"hello aegis";
const KEY: [u8; 16] = [0u8; 16];
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = b"hello aegis";
const EXPECTED_TAG: [u8; 16] = [0u8; 16];

#[test]
fn encrypt_decrypt_vectors() -> Result<(), crypto::CryptoError> {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let mut selector = CipherSuiteSelector::new();
    selector.set_cipher_suite(crypto::CipherSuite::Aegis128lAesni);
    let cipher = Aegis128L::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher
        .encrypt(MSG, &KEY, &NONCE, b"", &mut ct, &mut tag)?;
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    cipher
        .decrypt(&ct, &KEY, &NONCE, b"", &tag, &mut pt)?;
    assert_eq!(pt, MSG);

    let mut ct2 = Vec::new();
    let mut tag2 = [0u8; 16];
    selector
        .encrypt(MSG, &KEY, &NONCE, b"", &mut ct2, &mut tag2)?;
    assert_eq!(ct2, EXPECTED_CT);
    assert_eq!(tag2, EXPECTED_TAG);
    let mut pt2 = Vec::new();
    selector
        .decrypt(&ct2, &KEY, &NONCE, b"", &tag2, &mut pt2)?;
    assert_eq!(pt2, MSG);
    Ok(())
}

#[test]
fn reject_tampered_tag() {
    let cipher = Aegis128L::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher
        .encrypt(MSG, &KEY, &NONCE, b"", &mut ct, &mut tag)
        .unwrap();
    tag[0] ^= 0xff;
    let mut pt = Vec::new();
    let res = cipher.decrypt(&ct, &KEY, &NONCE, b"", &tag, &mut pt);
    assert!(res.is_err());
}
