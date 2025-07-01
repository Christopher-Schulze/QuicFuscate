use crypto::Morus1280;

#[test]
fn encrypt_decrypt_roundtrip() {
    let cipher = Morus1280::new();
    let msg = b"hello morus";
    let key = [0u8; Morus1280::KEY_SIZE];
    let nonce = [0u8; Morus1280::NONCE_SIZE];
    let mut ciphertext = Vec::new();
    let mut tag = [0u8; Morus1280::TAG_SIZE];

    cipher.encrypt(msg, &key, &nonce, &[], &mut ciphertext, &mut tag);

    let mut decrypted = Vec::new();
    assert!(cipher.decrypt(&ciphertext, &key, &nonce, &[], &tag, &mut decrypted));
    assert_eq!(decrypted, msg);
}
