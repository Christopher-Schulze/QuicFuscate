#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::stealth;
use quicfuscate::optimize::telemetry::{
    HMAC_SHA256_AVX2_OPS, HMAC_SHA256_NEON_OPS, HMAC_SHA256_SCALAR_OPS, HMAC_SHA256_SVE2_OPS,
    HMAC_SHA256_VNNI_OPS,
};
use quicfuscate::optimize::{CpuFeature, FeatureDetector};

#[test]
fn fake_hmac_tracks_backend_and_output() {
    let detector = FeatureDetector::instance();

    let key = [0x42u8; 32];
    let data: Vec<u8> = (0..128).map(|i| (i as u8).wrapping_mul(13)).collect();

    let before = (
        HMAC_SHA256_AVX2_OPS.get(),
        HMAC_SHA256_VNNI_OPS.get(),
        HMAC_SHA256_NEON_OPS.get(),
        HMAC_SHA256_SVE2_OPS.get(),
        HMAC_SHA256_SCALAR_OPS.get(),
    );

    let fake = stealth::generate_fake_hmac(&data, &key);

    let after = (
        HMAC_SHA256_AVX2_OPS.get(),
        HMAC_SHA256_VNNI_OPS.get(),
        HMAC_SHA256_NEON_OPS.get(),
        HMAC_SHA256_SVE2_OPS.get(),
        HMAC_SHA256_SCALAR_OPS.get(),
    );

    let mut hardware_delta = false;

    if cfg!(target_arch = "x86_64") {
        let matrix = detector.features_full().simd_dispatch_matrix();
        if matrix.sha256_vnni {
            hardware_delta |= after.1 > before.1;
        } else if matrix.avx2 {
            hardware_delta |= after.0 > before.0;
        }
    } else if cfg!(target_arch = "aarch64") {
        if detector.has_feature(CpuFeature::SVE2) && detector.has_feature(CpuFeature::SHA256) {
            hardware_delta |= after.3 > before.3;
        } else if detector.has_feature(CpuFeature::SHA256) || detector.has_feature(CpuFeature::SHA2)
        {
            hardware_delta |= after.2 > before.2;
        }
    }

    if hardware_delta {
        let reference = quicfuscate::simd::crypto::hmac_sha256(&key, &data);
        assert_eq!(fake.as_slice(), reference.as_slice(), "hardware path mismatch");
    } else {
        assert!(after.4 > before.4, "expected scalar counter to increase");
        let mut expected = [0u8; 32];
        for (idx, byte) in data.iter().enumerate() {
            expected[idx % 32] ^= byte ^ key[idx % 32];
        }
        assert_eq!(fake, expected, "scalar XOR fallback changed unexpectedly");
    }
}
