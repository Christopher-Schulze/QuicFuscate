use crypto::{Aegis128L, CipherSuiteSelector};

#[test]
fn encrypt_decrypt_roundtrip() {
    let selector = CipherSuiteSelector::new();
    let cipher = Aegis128L::new();
    let msg = b"hello aegis";
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
    // ensure selector API also works
    let mut ct2 = Vec::new();
    let mut tag2 = [0u8; 16];
    selector
        .encrypt(msg, &key, &nonce, b"", &mut ct2, &mut tag2)
        .unwrap();
    let mut pt2 = Vec::new();
    selector
        .decrypt(&ct2, &key, &nonce, b"", &tag2, &mut pt2)
        .unwrap();
    assert_eq!(pt2, msg);
}
