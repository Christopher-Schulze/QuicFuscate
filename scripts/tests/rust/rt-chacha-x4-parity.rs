#![cfg(feature = "rust-tests")]
#[cfg(target_arch = "x86_64")]
fn run_chacha20_x4_backend(backend: &str, counter: &quicfuscate::optimize::telemetry::Counter) {
    use quicfuscate::crypto::chacha::chacha20_block;

    let key = [0xABu8; 32];
    let nonce = [0xCDu8; 12];
    let ctr = 0xDEADBEEFu32;
    let before = counter.get();

    struct OverrideGuard;
    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            quicfuscate::optimize::crypto::__test_set_chacha20_x4_override(None);
        }
    }

    let _guard = OverrideGuard;
    quicfuscate::optimize::crypto::__test_set_chacha20_x4_override(Some(backend));
    let blocks = quicfuscate::optimize::crypto::chacha20_blocks_x4(&key, &nonce, ctr);

    for (idx, block) in blocks.iter().enumerate() {
        let expected = chacha20_block(&key, ctr.wrapping_add(idx as u32), &nonce);
        assert_eq!(expected, *block, "backend {} diverged at lane {}", backend, idx);
    }

    assert_eq!(before + 1, counter.get());
}

#[cfg(target_arch = "x86_64")]
#[test]
fn chacha20_x4_matches_scalar_avx2_override() {
    if !std::arch::is_x86_feature_detected!("avx2") {
        eprintln!("SIMD_SKIP test=chacha20_x4_matches_scalar_avx2_override required=avx2");
        return;
    }
    run_chacha20_x4_backend("avx2", &quicfuscate::optimize::telemetry::CHACHA20_X4_AVX2_OPS);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn chacha20_x4_matches_scalar_avx_override() {
    if !std::arch::is_x86_feature_detected!("avx") {
        eprintln!("SIMD_SKIP test=chacha20_x4_matches_scalar_avx_override required=avx");
        return;
    }
    run_chacha20_x4_backend("avx", &quicfuscate::optimize::telemetry::CHACHA20_X4_AVX_OPS);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn chacha20_x4_matches_scalar_sse41_override() {
    if !std::arch::is_x86_feature_detected!("sse4.1")
        || !std::arch::is_x86_feature_detected!("ssse3")
    {
        eprintln!("SIMD_SKIP test=chacha20_x4_matches_scalar_sse41_override required=sse4.1+ssse3");
        return;
    }
    run_chacha20_x4_backend("sse41", &quicfuscate::optimize::telemetry::CHACHA20_X4_SSE41_OPS);
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_chacha20_x4_parity_on_non_x86_64() {}
