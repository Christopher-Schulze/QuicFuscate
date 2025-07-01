use crypto::Morus;

const MSG: &[u8] = b"hello morus";
const KEY: [u8; 16] = [0u8; 16];
const NONCE: [u8; 16] = [0u8; 16];
const EXPECTED_CT: &[u8] = &[
    208, 186, 152, 7, 98, 148, 76, 151, 159, 119, 65,
];
const EXPECTED_TAG: [u8; 16] = [
    189, 105, 152, 190, 193, 18, 207, 97, 223, 131, 98, 176, 14, 104, 14, 222,
];

#[test]
fn encrypt_decrypt_vectors() {
    std::env::set_var("FORCE_SOFTWARE", "1");
    let cipher = Morus::new();
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher
        .encrypt(MSG, &KEY, &NONCE, b"", &mut ct, &mut tag)
        .unwrap();
    assert_eq!(ct, EXPECTED_CT);
    assert_eq!(tag, EXPECTED_TAG);

    let mut pt = Vec::new();
    let res = cipher.decrypt(&ct, &KEY, &NONCE, b"", &tag, &mut pt);
    assert!(res.is_err());
    assert_eq!(pt, MSG);
}
