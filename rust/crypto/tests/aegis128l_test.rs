use crypto::{Aegis128L, CipherSuiteSelector};

const MSG: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const AD: &[u8] = b"Comment numero un";
const KEY: &[u8; 16] = b"YELLOW SUBMARINE";
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = &[
    137, 147, 98, 134, 30, 108, 100, 90, 185, 139, 110, 255, 169, 201, 98, 232, 138, 159, 166, 71,
    169, 80, 96, 205, 2, 109, 22, 101, 71, 138, 231, 79, 130, 148, 159, 175, 131, 148, 166, 200,
    180, 159, 139, 138, 80, 104, 188, 50, 89, 53, 204, 111, 12, 212, 196, 143, 98, 25, 129, 118,
    132, 115, 95, 13, 232, 167, 13, 59, 19, 143, 58, 59, 42, 206, 238, 139, 2, 251, 194, 222, 185,
    59, 143, 116, 231, 175, 233, 67, 229, 11, 219, 127, 160, 215, 89, 217, 109, 89, 76, 225, 102,
    118, 69, 94, 252, 2, 69, 205, 251, 65, 159, 177, 3, 101,
];
const EXPECTED_TAG: [u8; 16] = [
    16, 244, 133, 167, 76, 40, 56, 136, 6, 235, 61, 139, 252, 7, 57, 150,
];

#[test]
fn encrypt_decrypt_vectors() -> Result<(), crypto::CryptoError> {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let mut selector = CipherSuiteSelector::new();
    selector.set_cipher_suite(crypto::CipherSuite::Aegis128lAesni);
    let cipher = Aegis128L::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher.encrypt(MSG, KEY, &NONCE, AD, &mut ct, &mut tag)?;
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    cipher.decrypt(&ct, KEY, &NONCE, AD, &tag, &mut pt)?;
    assert_eq!(pt, MSG);

    let mut ct2 = Vec::new();
    let mut tag2 = [0u8; 16];
    selector.encrypt(MSG, KEY, &NONCE, AD, &mut ct2, &mut tag2)?;
    assert_eq!(ct2, EXPECTED_CT);
    assert_eq!(tag2, EXPECTED_TAG);
    let mut pt2 = Vec::new();
    selector.decrypt(&ct2, KEY, &NONCE, AD, &tag2, &mut pt2)?;
    assert_eq!(pt2, MSG);
    Ok(())
}

#[test]
fn reject_tampered_tag() {
    let cipher = Aegis128L::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher
        .encrypt(MSG, KEY, &NONCE, AD, &mut ct, &mut tag)
        .unwrap();
    tag[0] ^= 0xff;
    let mut pt = Vec::new();
    let res = cipher.decrypt(&ct, KEY, &NONCE, AD, &tag, &mut pt);
    assert!(res.is_err());
}
