use crypto::Morus1280;

const MSG: &[u8] = b"hello morus";
const KEY: [u8; 16] = [0u8; 16];
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = &[
    141, 71, 239, 41, 4, 156, 171, 198, 7, 79, 107,
];
const EXPECTED_TAG: [u8; 16] = [
    53, 248, 17, 188, 183, 113, 141, 154, 215, 23, 146, 167, 123, 168, 165, 146,
];

#[test]
fn encrypt_decrypt_vectors() {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let cipher = Morus1280::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher.encrypt(MSG, &KEY, &NONCE, b"", &mut ct, &mut tag).unwrap();
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    let res = cipher.decrypt(&ct, &KEY, &NONCE, b"", &tag, &mut pt);
    assert!(res.is_err());
    assert_eq!(pt, MSG);
}
