use hex;
use quicfuscate::crypto::{CipherSuite, CipherSuiteSelector};

fn run_test(suite: CipherSuite) {
    let selector = CipherSuiteSelector::with_suite(suite);
    let (key_len, nonce_len) = match suite {
        // Both AEGIS variants operate on 128-bit keys and nonces.
        CipherSuite::Aegis128X => (16, 16),
        CipherSuite::Aegis128L => (16, 16),
        CipherSuite::Morus1280_128 => (16, 16),
    };
    let key = vec![0u8; key_len];
    let nonce = vec![0u8; nonce_len];
    let ad = b"ad";
    let plaintext = b"hello world";
    let ct = selector
        .encrypt(&key, &nonce, ad, plaintext)
        .expect("encrypt");
    let pt = selector.decrypt(&key, &nonce, ad, &ct).expect("decrypt");
    assert_eq!(plaintext.to_vec(), pt);
}

#[test]
fn test_aegis128x() {
    run_test(CipherSuite::Aegis128X);
}

#[test]
fn test_aegis128l() {
    run_test(CipherSuite::Aegis128L);
}

#[test]
fn test_morus() {
    run_test(CipherSuite::Morus1280_128);
}

#[test]
fn test_vectors() {
    let selector = CipherSuiteSelector::with_suite(CipherSuite::Aegis128L);
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let ct = selector
        .encrypt(&key, &nonce, b"ad", b"test")
        .expect("encrypt");
    assert_eq!(hex::encode(ct), "5dc5bd6b4aca031f3870dd6ad7068531a3e9866a");

    let selector = CipherSuiteSelector::with_suite(CipherSuite::Morus1280_128);
    let ct = selector
        .encrypt(&key, &nonce, b"ad", b"test")
        .expect("encrypt");
    assert_eq!(hex::encode(ct), "1d36c344344630f7179573e22a6f9ddaa8600269");
}
