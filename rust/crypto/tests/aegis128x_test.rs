use crypto::Aegis128X;

const MSG: &[u8] = b"hello aegis";
const KEY: [u8; 16] = [0u8; 16];
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = b"hello aegis";
const EXPECTED_TAG: [u8; 16] = [0u8; 16];

#[test]
fn encrypt_decrypt_vectors() -> Result<(), crypto::CryptoError> {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let cipher = Aegis128X::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher.encrypt(MSG, &KEY, &NONCE, b"", &mut ct, &mut tag)?;
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    cipher.decrypt(&ct, &KEY, &NONCE, b"", &tag, &mut pt)?;
    assert_eq!(pt, MSG);
    Ok(())
}
