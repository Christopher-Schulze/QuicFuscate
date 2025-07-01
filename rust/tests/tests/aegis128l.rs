use crypto::Aegis128L;

#[test]
fn encrypt_decrypt_roundtrip() {
    let cipher = Aegis128L::new();
    let msg = b"hello aegis";
    let key = [0u8; Aegis128L::KEY_SIZE];
    let nonce = [0u8; Aegis128L::NONCE_SIZE];
    let mut ciphertext = Vec::new();
    let mut tag = [0u8; Aegis128L::TAG_SIZE];

    cipher.encrypt(msg, &key, &nonce, &[], &mut ciphertext, &mut tag);

    let mut decrypted = Vec::new();
    assert!(cipher.decrypt(&ciphertext, &key, &nonce, &[], &tag, &mut decrypted));
    assert_eq!(decrypted, msg);
}
