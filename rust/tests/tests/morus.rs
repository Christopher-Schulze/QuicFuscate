use crypto::Morus1280;

const KEY_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;

#[test]
fn encrypt_decrypt_roundtrip() {
    let cipher = Morus1280::new();
    let msg = b"hello morus";
    let key = [0u8; KEY_SIZE];
    let nonce = [0u8; NONCE_SIZE];
    let mut ciphertext = Vec::new();
    let mut tag = [0u8; TAG_SIZE];

    let _ = cipher.encrypt(msg, &key, &nonce, &[], &mut ciphertext, &mut tag);

    let mut decrypted = Vec::new();
    assert!(cipher
        .decrypt(&ciphertext, &key, &nonce, &[], &tag, &mut decrypted)
        .is_ok());
    assert_eq!(decrypted, msg);
}
