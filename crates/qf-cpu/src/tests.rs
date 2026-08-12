use super::CpuFeature;
use super::{
    bitslice_policy_tag, dispatch_bitslice, with_override, AmxCapability, AmxSignals, CpuFeatures,
    CpuProfile, FeatureDetector, PROFILE_OVERRIDE, TEST_FEC_KERNEL_OVERRIDE,
};
use std::sync::{Arc, Barrier};

#[test]
fn test_dispatch_overrides_are_thread_local() {
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first = std::thread::spawn(move || {
        with_override(Some("ref"), || {
            first_barrier.wait();
            TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone())
        })
    });
    let second_barrier = Arc::clone(&barrier);
    let second = std::thread::spawn(move || {
        with_override(Some("avx2"), || {
            second_barrier.wait();
            TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone())
        })
    });

    barrier.wait();
    assert_eq!(first.join().expect("first override thread"), Some("ref".to_string()));
    assert_eq!(second.join().expect("second override thread"), Some("avx2".to_string()));
    assert_eq!(TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone()), None);
}

#[test]
fn test_profile_override_is_thread_local() {
    let barrier = Arc::new(Barrier::new(2));
    let child_barrier = Arc::clone(&barrier);
    let child = std::thread::spawn(move || {
        assert!(super::set_profile_override_for_tests(CpuProfile::Scalar));
        child_barrier.wait();
        FeatureDetector::instance().profile()
    });

    barrier.wait();
    assert_eq!(PROFILE_OVERRIDE.with(std::cell::Cell::get), 0);
    assert_eq!(child.join().expect("profile override thread"), CpuProfile::Scalar);
}

#[test]
fn amx_detection_is_process_free_and_product_fail_closed() {
    let detector = FeatureDetector::instance();
    let capability = detector.amx_capability();

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    if capability.cpu_tile && capability.cpu_int8 {
        assert!(capability.os_tile_state_permitted.is_some());
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
    assert_eq!(capability.os_tile_state_permitted, None);
    assert!(!capability.verified_backend);
    assert!(!capability.product_dispatch_eligible);
    assert_eq!(detector.features_full().amx_tile, capability.cpu_tile);
    assert_eq!(detector.features_full().amx_int8, capability.cpu_int8);
    assert_eq!(detector.features_full().amx_bf16, capability.cpu_bf16);
}

#[test]
fn amx_cpuid_leaf7_decodes_each_feature_bit_independently() {
    assert_eq!(super::decode_amx_cpuid_leaf7(0), (false, false, false));
    assert_eq!(super::decode_amx_cpuid_leaf7(1 << 24), (true, false, false));
    assert_eq!(super::decode_amx_cpuid_leaf7(1 << 25), (false, true, false));
    assert_eq!(super::decode_amx_cpuid_leaf7(1 << 22), (false, false, true));
    assert_eq!(
        super::decode_amx_cpuid_leaf7((1 << 22) | (1 << 24) | (1 << 25)),
        (true, true, true)
    );
}

#[test]
fn avx10_1_cpuid_requires_feature_version_subleaf_and_complete_xcr0_state() {
    const REQUIRED_XCR0_STATE: u64 = 0xe6;

    assert!(super::decode_avx10_1_support(true, 1, 1, REQUIRED_XCR0_STATE));
    assert!(super::decode_avx10_1_support(true, 4, 2, u64::MAX));
    assert!(!super::decode_avx10_1_support(false, 1, 1, REQUIRED_XCR0_STATE));
    assert!(!super::decode_avx10_1_support(true, 0, 1, REQUIRED_XCR0_STATE));
    assert!(!super::decode_avx10_1_support(true, 1, 0, REQUIRED_XCR0_STATE));

    for state_bit in [1, 2, 5, 6, 7] {
        assert!(!super::decode_avx10_1_support(
            true,
            1,
            1,
            REQUIRED_XCR0_STATE & !(1 << state_bit)
        ));
    }
}

#[test]
fn amx_product_eligibility_requires_cpu_os_compiler_and_backend_proof() {
    let all_proven = AmxCapability::from_signals(AmxSignals {
        cpu_tile: true,
        cpu_int8: true,
        cpu_bf16: true,
        os_tile_state_permitted: Some(true),
        compiler_target_tile: true,
        compiler_target_int8: true,
        compiler_target_bf16: true,
        verified_backend: true,
    });
    assert!(all_proven.product_dispatch_eligible);

    let without_bf16 = AmxCapability::from_signals(AmxSignals {
        cpu_bf16: false,
        compiler_target_bf16: false,
        ..AmxSignals {
            cpu_tile: true,
            cpu_int8: true,
            cpu_bf16: true,
            os_tile_state_permitted: Some(true),
            compiler_target_tile: true,
            compiler_target_int8: true,
            compiler_target_bf16: true,
            verified_backend: true,
        }
    });
    assert!(without_bf16.product_dispatch_eligible);

    let missing_os = AmxCapability::from_signals(AmxSignals {
        os_tile_state_permitted: None,
        ..AmxSignals {
            cpu_tile: true,
            cpu_int8: true,
            cpu_bf16: true,
            os_tile_state_permitted: Some(true),
            compiler_target_tile: true,
            compiler_target_int8: true,
            compiler_target_bf16: true,
            verified_backend: true,
        }
    });
    assert!(!missing_os.product_dispatch_eligible);

    let missing_compiler = AmxCapability::from_signals(AmxSignals {
        compiler_target_tile: false,
        ..AmxSignals {
            cpu_tile: true,
            cpu_int8: true,
            cpu_bf16: true,
            os_tile_state_permitted: Some(true),
            compiler_target_tile: true,
            compiler_target_int8: true,
            compiler_target_bf16: true,
            verified_backend: true,
        }
    });
    assert!(!missing_compiler.product_dispatch_eligible);

    let missing_backend = AmxCapability::from_signals(AmxSignals {
        verified_backend: false,
        ..AmxSignals {
            cpu_tile: true,
            cpu_int8: true,
            cpu_bf16: true,
            os_tile_state_permitted: Some(true),
            compiler_target_tile: true,
            compiler_target_int8: true,
            compiler_target_bf16: true,
            verified_backend: true,
        }
    });
    assert!(!missing_backend.product_dispatch_eligible);
}

#[test]
fn simd_dispatch_matrix_requires_every_target_feature() {
    let mut features = CpuFeatures { avx512f: true, ..CpuFeatures::default() };

    assert!(!features.simd_dispatch_matrix().avx512_ack);
    features.avx512vl = true;
    assert!(features.simd_dispatch_matrix().avx512_ack);

    features.avx512bw = true;
    features.avx512vbmi2 = true;
    assert!(features.simd_dispatch_matrix().avx512_vbmi2);
    features.avx512f = false;
    assert!(!features.simd_dispatch_matrix().avx512_vbmi2);
    features.avx512f = true;

    features.avx512cd = true;
    assert!(!features.simd_dispatch_matrix().avx512_vpopcnt);
    features.avx512vpopcntdq = true;
    assert!(features.simd_dispatch_matrix().avx512_vpopcnt);

    features.avx512vnni = true;
    assert!(features.simd_dispatch_matrix().sha256_vnni);
    features.avx512vl = false;
    assert!(!features.simd_dispatch_matrix().sha256_vnni);
    features.avx512vl = true;

    features.vaes = true;
    features.aesni = true;
    assert!(!features.simd_dispatch_matrix().vaes_aes);
    features.sse2 = true;
    assert!(features.simd_dispatch_matrix().vaes_aes);

    features.vpclmulqdq = true;
    features.sse41 = true;
    assert!(features.simd_dispatch_matrix().gf16_vpclmul);
    features.pclmulqdq = true;
    assert!(features.simd_dispatch_matrix().gf16_pclmul);

    features.fma3 = true;
    assert!(features.simd_dispatch_matrix().neural_avx512);
    features.avx2 = true;
    assert!(features.simd_dispatch_matrix().neural_avx2);

    features.avx = true;
    features.ssse3 = true;
    assert!(features.simd_dispatch_matrix().chacha_avx);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn x86_profile_selection_keeps_bmi2_explicit() {
    let cases = [
        ("p0a", CpuFeatures { sse2: true, ..CpuFeatures::default() }, CpuProfile::X86_P0a),
        ("p0b", CpuFeatures { ssse3: true, ..CpuFeatures::default() }, CpuProfile::X86_P0b),
        ("p1a", CpuFeatures { sse42: true, ..CpuFeatures::default() }, CpuProfile::X86_P1a),
        (
            "p1b",
            CpuFeatures { aesni: true, pclmulqdq: true, ..CpuFeatures::default() },
            CpuProfile::X86_P1b,
        ),
        ("p1f", CpuFeatures { avx: true, ..CpuFeatures::default() }, CpuProfile::X86_P1f),
        ("p3a", CpuFeatures { avx512f: true, ..CpuFeatures::default() }, CpuProfile::X86_P3a),
        (
            "p3b",
            CpuFeatures { avx512f: true, vaes: true, vpclmulqdq: true, ..CpuFeatures::default() },
            CpuProfile::X86_P3b,
        ),
        (
            "p3c",
            CpuFeatures {
                avx512f: true,
                avx512bw: true,
                avx512vbmi2: true,
                ..CpuFeatures::default()
            },
            CpuProfile::X86_P3c,
        ),
        (
            "p3d",
            CpuFeatures {
                avx512f: true,
                avx512cd: true,
                avx512vpopcntdq: true,
                ..CpuFeatures::default()
            },
            CpuProfile::X86_P3d,
        ),
        (
            "p3e",
            CpuFeatures { avx512f: true, gfni: true, ..CpuFeatures::default() },
            CpuProfile::X86_P3e,
        ),
        ("p4a", CpuFeatures { avx10_1_256: true, ..CpuFeatures::default() }, CpuProfile::X86_P4a),
        ("p4b", CpuFeatures { avx10_1_512: true, ..CpuFeatures::default() }, CpuProfile::X86_P4b),
    ];

    for (name, features, expected) in cases {
        let without_bmi2 = CpuFeatures { bmi2: false, ..features };
        assert_eq!(
            FeatureDetector::profile_from_features(without_bmi2),
            expected,
            "automatic profile {name} must be selected without BMI2"
        );

        let with_bmi2 = CpuFeatures { bmi2: true, ..features };
        assert_eq!(
            FeatureDetector::profile_from_features(with_bmi2),
            expected,
            "automatic profile {name} must not gain a BMI2-dependent meaning"
        );
    }

    let p2a = CpuFeatures { avx2: true, ..CpuFeatures::default() };
    assert_eq!(FeatureDetector::profile_from_features(p2a), CpuProfile::X86_P2a);

    let p2b = CpuFeatures { avx2: true, bmi2: true, ..CpuFeatures::default() };
    assert_eq!(FeatureDetector::profile_from_features(p2b), CpuProfile::X86_P2b);
}

#[test]
fn override_ref_selects_scalar() {
    let tag =
        with_override(Some("ref"), || dispatch_bitslice(|p| bitslice_policy_tag(p).to_string()));
    assert_eq!(tag, "scalar");
}

#[test]
fn override_invalid_value_graceful_fallback() {
    let tag = with_override(Some("definitely-not-a-kernel"), || {
        dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
    });
    let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
    assert!(allowed.contains(&tag.as_str()), "unexpected policy tag: {}", tag);
}

#[test]
fn override_avx2_best_effort() {
    let det = FeatureDetector::instance();
    let tag =
        with_override(Some("avx2"), || dispatch_bitslice(|p| bitslice_policy_tag(p).to_string()));
    if det.features_full().simd_dispatch_matrix().avx2 {
        assert_eq!(tag, "avx2");
    } else {
        let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()));
    }
}

#[test]
fn override_avx512_best_effort() {
    let det = FeatureDetector::instance();
    let tag =
        with_override(Some("avx512"), || dispatch_bitslice(|p| bitslice_policy_tag(p).to_string()));
    if det.features_full().simd_dispatch_matrix().avx512_vbmi {
        assert_eq!(tag, "avx512");
    } else {
        let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()));
    }
}

#[test]
fn override_neon_best_effort() {
    let det = FeatureDetector::instance();
    let tag =
        with_override(Some("neon"), || dispatch_bitslice(|p| bitslice_policy_tag(p).to_string()));
    if det.features_full().neon && det.features_full().aes && det.features_full().pmull {
        assert_eq!(tag, "neon");
    } else {
        let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()));
    }
}

#[test]
fn override_sve2_best_effort() {
    let det = FeatureDetector::instance();
    let tag =
        with_override(Some("sve2"), || dispatch_bitslice(|p| bitslice_policy_tag(p).to_string()));
    if det.has_feature(CpuFeature::SVE2) {
        assert_eq!(tag, "sve2");
    } else {
        let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()));
    }
}

#[test]
fn ascii_printable_count_matches_scalar_reference() {
    let data: Vec<u8> = (0..=u8::MAX).collect();
    let expected = data.iter().filter(|byte| matches!(byte, 0x20..=0x7E)).count();
    assert_eq!(super::count_ascii_printable(&data), expected);
}

#[test]
fn ascii_printable_count_handles_empty_input() {
    assert_eq!(super::count_ascii_printable(&[]), 0);
}
