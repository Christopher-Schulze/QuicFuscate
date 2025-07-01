use crypto::Morus1280;

#[test]
fn encrypt_decrypt_roundtrip() {
    let cipher = Morus1280::new();
    let msg = b"hello morus";
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let mut ciphertext = Vec::new();
    let mut tag = [0u8; 16];

    let _ = cipher.encrypt(msg, &key, &nonce, &[], &mut ciphertext, &mut tag);

    let mut decrypted = Vec::new();
    assert!(
        cipher
            .decrypt(&ciphertext, &key, &nonce, &[], &tag, &mut decrypted)
            .is_ok()
    );
    assert_eq!(decrypted, msg);
}
