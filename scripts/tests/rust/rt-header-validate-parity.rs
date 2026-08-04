#![cfg(feature = "rust-tests")]

#[test]
#[cfg(target_arch = "x86_64")]
fn header_validate_avx512_matches_scalar() {
    if !std::is_x86_feature_detected!("avx512f") {
        return;
    }

    // Valid long header (fixed bit set)
    let mut long_ok = [0u8; 64];
    long_ok[0] = 0xC0; // fixed bit set
    assert!(quicfuscate::simd::validate_header_avx512_for_rust_tests(&long_ok));

    // Invalid: fixed bit cleared
    let mut no_fixed = [0u8; 64];
    no_fixed[0] = 0x00;
    assert!(!quicfuscate::simd::validate_header_avx512_for_rust_tests(&no_fixed));

    // Random cases
    let mut buf = [0u8; 64];
    for i in 0..64 {
        buf.fill(0);
        buf[0] = (i as u8) << 2;
        let scalar = quicfuscate::simd::scalar::validate_header(&buf);
        let simd = quicfuscate::simd::validate_header_avx512_for_rust_tests(&buf);
        assert_eq!(scalar, simd);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn header_validate_sse2_matches_scalar() {
    if !std::is_x86_feature_detected!("sse2") {
        return;
    }

    let mut long_ok = [0u8; 64];
    long_ok[0] = 0xC0; // fixed bit set
    assert!(quicfuscate::simd::validate_header_sse2_for_rust_tests(&long_ok));

    let mut no_fixed = [0u8; 64];
    no_fixed[0] = 0x00;
    assert!(!quicfuscate::simd::validate_header_sse2_for_rust_tests(&no_fixed));

    // Reserved bits cleared for short header
    let mut short_ok = [0u8; 8];
    short_ok[0] = 0x40; // fixed=1, short=1, reserved=0
    assert!(quicfuscate::simd::validate_header_sse2_for_rust_tests(&short_ok));

    // Reserved bits set -> invalid
    let mut short_bad = [0u8; 8];
    short_bad[0] = 0x58; // 0b0101_1000: fixed=1, reserved!=0
    assert!(!quicfuscate::simd::validate_header_sse2_for_rust_tests(&short_bad));
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_header_validate_parity_on_non_x86_64() {}
