use quicfuscate::crypto::{CipherSuite, CipherSuiteSelector};

fn run_test(suite: CipherSuite) {
    let selector = CipherSuiteSelector::with_suite(suite);
    let (key_len, nonce_len) = match suite {
        CipherSuite::Aegis128X => (32, 32),
        CipherSuite::Aegis128L => (16, 16),
        CipherSuite::Morus1280_128 => (16, 16),
    };
    let key = vec![0u8; key_len];
    let nonce = vec![0u8; nonce_len];
    let ad = b"ad";
    let plaintext = b"hello world";
    let ct = selector.encrypt(&key, &nonce, ad, plaintext).expect("encrypt");
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
