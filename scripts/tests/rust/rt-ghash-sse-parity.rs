#![cfg(feature = "rust-tests")]

#[cfg(target_arch = "x86_64")]
fn run_ghash_with_override(mode: &str, aad: &[u8], ct: &[u8]) -> [u8; 16] {
    quicfuscate::crypto::gcm::__test_set_ghash_override(Some(mode));
    let result = quicfuscate::crypto::gcm::ghash([0x11; 16], aad, ct);
    quicfuscate::crypto::gcm::__test_set_ghash_override(None);
    result
}

#[test]
#[cfg(target_arch = "x86_64")]
fn ghash_sse_matches_scalar_when_available() {
    if !std::arch::is_x86_feature_detected!("ssse3")
        || !std::arch::is_x86_feature_detected!("sse4.1")
    {
        eprintln!("SIMD_SKIP test=ghash_sse_matches_scalar_when_available required=ssse3+sse4.1");
        return;
    }

    let aad = b"associated-data";
    let ct = b"ciphertext-payload";

    let before = quicfuscate::optimize::telemetry::GHASH_SSE_OPS.get();
    let hw = run_ghash_with_override("sse", aad, ct);
    let after = quicfuscate::optimize::telemetry::GHASH_SSE_OPS.get();
    assert_eq!(before + 1, after);

    let reference_before = quicfuscate::optimize::telemetry::GHASH_SCALAR_OPS.get();
    let sw = run_ghash_with_override("scalar", aad, ct);
    let reference_after = quicfuscate::optimize::telemetry::GHASH_SCALAR_OPS.get();
    assert_eq!(reference_before + 1, reference_after);

    assert_eq!(hw, sw, "SSE GHASH diverged from scalar reference");
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_ghash_sse_parity_on_non_x86_64() {}
