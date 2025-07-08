use hex;
use quicfuscate::crypto::{CipherSuite, CipherSuiteSelector};

fn run_test(suite: CipherSuite) {
    let selector = CipherSuiteSelector::with_suite(suite);
    let (key_len, nonce_len) = match suite {
        CipherSuite::Aegis128X => (16, 16),
        CipherSuite::Aegis128L => (16, 16),
        CipherSuite::Aegis256 => (32, 32),
        CipherSuite::Morus1280_128 => (16, 16),
        CipherSuite::Morus1280_256 => (32, 16),
        CipherSuite::SoftwareFallback => (16, 16),
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
fn test_aegis256() {
    run_test(CipherSuite::Aegis256);
}

#[test]
fn test_morus() {
    run_test(CipherSuite::Morus1280_128);
}

#[test]
fn test_morus256() {
    run_test(CipherSuite::Morus1280_256);
}

#[test]
fn test_fallback() {
    run_test(CipherSuite::SoftwareFallback);
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

    let selector = CipherSuiteSelector::with_suite(CipherSuite::Aegis256);
    let key = b"YELLOW SUBMARINEyellow submarine";
    let nonce = [0u8; 32];
    let msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ad = b"Comment numero un";
    let ct = selector.encrypt(key, &nonce, ad, msg).expect("encrypt");
    let (c, tag) = ct.split_at(ct.len() - 16);
    let expected_c = [
        62u8, 90, 21, 90, 245, 182, 17, 214, 55, 102, 124, 12, 140, 5, 78, 233, 79, 134, 10, 29,
        103, 105, 233, 197, 238, 49, 221, 109, 44, 245, 42, 101, 43, 204, 250, 251, 9, 111, 4, 6,
        190, 106, 238, 190, 80, 100, 12, 203, 168, 27, 250, 240, 222, 50, 155, 250, 247, 76, 26,
        233, 228, 18, 17, 187, 52, 229, 159, 66, 12, 62, 120, 255, 42, 90, 14, 50, 243, 148, 197,
        107, 194, 159, 186, 95, 69, 120, 85, 99, 212, 193, 142, 67, 74, 194, 34, 196, 9, 135, 148,
        118, 215, 39, 44, 71, 146, 241, 247, 72, 50, 60, 16, 52, 156, 226,
    ];
    let expected_tag = [
        89u8, 198, 229, 213, 31, 223, 43, 199, 193, 71, 4, 63, 201, 114, 129, 176,
    ];
    assert_eq!(c, expected_c);
    assert_eq!(tag, expected_tag);
    let pt = selector.decrypt(key, &nonce, ad, &ct).expect("decrypt");
    assert_eq!(pt, msg);
}
