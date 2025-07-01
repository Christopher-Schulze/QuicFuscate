use crypto::Morus;

#[test]
fn encrypt_decrypt_roundtrip() {
    let cipher = Morus::new();
    let msg = b"hello morus";
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let mut ct = Vec::new();
    let mut tag = [0u8; 16];
    cipher
        .encrypt(msg, &key, &nonce, b"", &mut ct, &mut tag)
        .unwrap();

    let mut pt = Vec::new();
    cipher
        .decrypt(&ct, &key, &nonce, b"", &tag, &mut pt)
        .unwrap();

    assert_eq!(pt, msg);
}
