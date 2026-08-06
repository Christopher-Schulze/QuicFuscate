#![cfg(feature = "simd-selfcheck")]
#![cfg(feature = "rust-tests")]

use hex::encode;
use quicfuscate::accelerate::string::{base64_decode, base64_encode};
use quicfuscate::simd::galois;
use quicfuscate::{accelerate, simd};

fn scalar_encode_varint(mut val: u64, buf: &mut [u8]) -> usize {
    let (len, prefix): (usize, u8) = if val < (1u64 << 6) {
        (1, 0b00)
    } else if val < (1u64 << 14) {
        (2, 0b01)
    } else if val < (1u64 << 30) {
        (4, 0b10)
    } else if val < (1u64 << 62) {
        (8, 0b11)
    } else {
        return 0;
    };
    if buf.len() < len {
        return 0;
    }
    match len {
        1 => {
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        2 => {
            buf[1] = (val & 0xFF) as u8;
            val >>= 8;
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        4 => {
            for i in (1..4).rev() {
                buf[i] = (val & 0xFF) as u8;
                val >>= 8;
            }
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        8 => {
            for i in (1..8).rev() {
                buf[i] = (val & 0xFF) as u8;
                val >>= 8;
            }
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        _ => unreachable!(),
    }
    len
}

fn reference_inject_pattern(mut data: Vec<u8>, pattern: &[u8], positions: &[usize]) -> Vec<u8> {
    for &pos in positions {
        if pos + pattern.len() <= data.len() {
            data[pos..pos + pattern.len()].copy_from_slice(pattern);
        }
    }
    data
}

fn make_data(len: usize, seed: u32) -> Vec<u8> {
    (0..len).map(|i| (((i as u32).wrapping_mul(31) ^ (seed + 17)) & 0xFF) as u8).collect()
}

#[test]
fn varint_roundtrip_and_consistency() {
    let mut buf_simd = [0u8; 8];
    let mut buf_scalar = [0u8; 8];

    let mut values =
        vec![0, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, (1u64 << 62) - 1];
    for i in 0..10_000u64 {
        let mix = i.wrapping_mul(0x9E37_79B1_85EB_CA87);
        values.push(mix & 0x3FFF_FFFF_FFFF_FFFF);
    }

    for val in values {
        buf_simd.fill(0);
        buf_scalar.fill(0);
        let written_simd = simd::transport::encode_varint(val, &mut buf_simd);
        let written_scalar = scalar_encode_varint(val, &mut buf_scalar);
        assert_eq!(written_simd, written_scalar, "encode len mismatch for {val}");
        assert_eq!(
            &buf_simd[..written_simd],
            &buf_scalar[..written_scalar],
            "encode bytes mismatch for {val}"
        );

        let decoded = simd::transport::decode_varint(&buf_simd[..written_simd]);
        assert_eq!(decoded, Some((val, written_simd)), "decode mismatch for {val}");
    }
}

#[test]
fn simd_sha256_matches_reference_vector() {
    let digest = simd::crypto::sha256(b"abc");
    assert_eq!(encode(digest), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn simd_hmac_sha256_matches_reference_vector() {
    let digest = simd::crypto::hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog");
    assert_eq!(encode(digest), "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

#[test]
fn gf_mul_matches_scalar() {
    let mut dst_simd = vec![0u8; 256];
    let mut dst_scalar = vec![0u8; 256];
    let input = make_data(256, 0x1234);

    for b in 0u8..=u8::MAX {
        dst_simd.fill(0);
        dst_scalar.fill(0);
        galois::gf_mul(&input, b, &mut dst_simd);
        simd::scalar::gf_mul(&input, b, &mut dst_scalar);
        assert_eq!(dst_simd, dst_scalar, "GF mul mismatch for multiplier {b}");
    }
}

#[test]
fn gf_mul_slice_telemetry_tracks_backend() {
    #[cfg(target_arch = "aarch64")]
    {
        use quicfuscate::optimize::telemetry;

        let before = telemetry::FEC_NEON_OPS.get();
        let mut dst = vec![0u8; 128];
        let src = make_data(128, 0xA5A5);
        galois::gf_mul(&src, 0x5b, &mut dst);
        let after = telemetry::FEC_NEON_OPS.get();
        assert!(
            after > before,
            "expected FEC_NEON_OPS to increase (before={before}, after={after})"
        );
    }

    #[cfg(target_arch = "x86_64")]
    {
        use quicfuscate::optimize::telemetry;
        if !std::is_x86_feature_detected!("ssse3") {
            eprintln!("SIMD_SKIP test=gf_mul_slice_telemetry_tracks_backend required=ssse3");
            return;
        }

        // Ensure SSSE3 counter ticks when fallback SIMD path executes.
        let before = telemetry::FEC_SSSE3_OPS.get();
        let mut dst = vec![0u8; 64];
        let src = make_data(64, 0x4242);
        galois::gf_mul(&src, 0xD3, &mut dst);
        let after = telemetry::FEC_SSSE3_OPS.get();
        assert!(
            after > before,
            "expected FEC_SSSE3_OPS to increase (before={before}, after={after})"
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn gf16_vbmi2_matches_scalar() {
    if !std::is_x86_feature_detected!("avx512f")
        || !std::is_x86_feature_detected!("avx512bw")
        || !std::is_x86_feature_detected!("avx512vbmi2")
    {
        eprintln!("SIMD_SKIP test=gf16_vbmi2_matches_scalar required=avx512f+avx512bw+avx512vbmi2");
        return;
    }

    struct OverrideGuard;
    impl OverrideGuard {
        fn set(mode: Option<&str>) -> Self {
            quicfuscate::optimize::__test_set_fec_kernel_override(mode);
            OverrideGuard
        }
    }
    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            quicfuscate::optimize::__test_set_fec_kernel_override(None);
        }
    }

    let coeff = 0xD37B;
    let src: Vec<u16> = (0..96).map(|i| ((i as u16).wrapping_mul(0x9E37) << 1) ^ 0xBEEF).collect();
    let mut vbmi2_dst = vec![0u16; src.len()];
    let mut scalar_dst = vec![0u16; src.len()];

    {
        let _guard = OverrideGuard::set(Some("avx512vbmi2"));
        vbmi2_dst.fill(0);
        quicfuscate::fec::gf16_mul_slice_selfcheck(coeff, &src, &mut vbmi2_dst);
    }

    {
        let _guard = OverrideGuard::set(Some("ref"));
        scalar_dst.fill(0);
        quicfuscate::fec::gf16_mul_slice_selfcheck(coeff, &src, &mut scalar_dst);
    }

    assert_eq!(vbmi2_dst, scalar_dst, "VBMI2 GF16 multiply must match scalar path");
}

#[test]
fn base64_agrees_with_reference() {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    for len in [0usize, 1, 2, 3, 7, 12, 16, 24, 31, 48, 96] {
        let data = make_data(len, 0xDEADBEEF);
        let ours = base64_encode(&data);
        let reference = STANDARD.encode(&data);
        assert_eq!(ours, reference, "base64 mismatch at len {len}");

        let decoded = base64_decode(&ours).expect("decode failed");
        assert_eq!(decoded, data, "decode mismatch at len {len}");
    }
}

#[test]
fn base64_decode_rejects_invalid() {
    assert!(base64_decode("!!!!").is_none(), "invalid symbols should fail");
    assert!(base64_decode("abc").is_none(), "non-multiple-of-4 length should fail");
    assert!(base64_decode("AAAA====").is_none(), "excess padding should fail");
}

#[test]
fn berlekamp_massey_matches_scalar() {
    let syndrome = make_data(48, 0x51F0);
    let scalar_poly = quicfuscate::simd::scalar::berlekamp_massey(&syndrome, syndrome.len());
    let simd_poly = quicfuscate::simd::fec::berlekamp_massey_gf256(&syndrome, syndrome.len());
    assert_eq!(simd_poly, scalar_poly, "Berlekamp-Massey polynomial mismatch");

    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sve2") {
            use quicfuscate::optimize::telemetry;

            let before = telemetry::FEC_BERLEKAMP_SVE2_OPS.get();
            let _ = quicfuscate::simd::fec::berlekamp_massey_gf256(&syndrome, syndrome.len());
            let after = telemetry::FEC_BERLEKAMP_SVE2_OPS.get();
            assert!(
                after > before,
                "expected FEC_BERLEKAMP_SVE2_OPS to increase (before={before}, after={after})"
            );
        }
    }
}

#[test]
fn string_contains_neon_matches_reference() {
    let hay = "The quick brown fox jumps over the lazy dog";
    let needles =
        ["The", "quick", "brown", "lazy", "dog", "jumps over", "ox jumps", "notfound", ""];
    for needle in needles {
        let accel = accelerate::string::string_contains(hay, needle);
        let reference = hay.contains(needle);
        assert_eq!(accel, reference, "contains mismatch for '{needle}'");
    }

    let long_hay = "A".repeat(128) + "needle" + &"B".repeat(64);
    assert!(accelerate::string::string_contains(&long_hay, "needle"));
    assert!(!accelerate::string::string_contains(&long_hay, "needleC"));
}

#[test]
fn random_array_u32_has_entropy() {
    let mut data = vec![0u32; 16];
    accelerate::random::random_array_u32(&mut data);
    let first = data[0];
    let unique = data.iter().filter(|&&v| v != first).count();
    assert!(unique > 0, "random array produced uniform values");
}

#[test]
fn pattern_injection_matches_scalar() {
    let data = make_data(96, 0xC0FFEE);
    let pattern = make_data(24, 0xB16B00);
    let positions = [0usize, 5, 16, 47, 72];

    let mut accelerated = data.clone();
    accelerate::stealth::inject_pattern(&mut accelerated, &pattern, &positions);
    let expected = reference_inject_pattern(data, &pattern, &positions);
    assert_eq!(accelerated, expected);
}

fn reference_add_tls_padding(mut record: Vec<u8>, target_size: usize, padding_byte: u8) -> Vec<u8> {
    if record.len() >= target_size {
        return record;
    }
    let padding_needed = target_size - record.len();
    record.reserve(padding_needed);

    #[cfg(target_arch = "x86_64")]
    {
        let features = quicfuscate::optimize::FeatureDetector::instance().features_full();
        if features.gfni {
            let seed_lo = (record.len() as u64).wrapping_mul(0x9E37_79B1_85EB_CA87)
                ^ (padding_byte as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let seed_hi = (target_size as u64).wrapping_mul(0x94D0_49BB_1331_11EB)
                ^ (padding_needed as u64).rotate_left(29);
            let pad = quicfuscate::accelerate::stealth::gfni_padding_bytes(
                padding_needed,
                padding_byte,
                seed_lo,
                seed_hi,
            );
            record.extend_from_slice(&pad);
            return record;
        }
    }

    while record.len() < target_size {
        record.push(padding_byte);
    }
    record
}

fn reference_congestion_summary(
    samples: &[quicfuscate::accelerate::transport::CongestionSample],
) -> (u64, u64, u64, u64, u64) {
    let mut total_cwnd = 0u64;
    let mut total_inflight = 0u64;
    let mut total_delivery = 0u64;
    let mut total_lost = 0u64;

    for sample in samples {
        total_cwnd += sample.cwnd as u64;
        total_inflight += sample.bytes_in_flight as u64;
        total_delivery += sample.delivery_rate as u64;
        total_lost += sample.lost_packets as u64;
    }

    let score = total_inflight / 1024 + total_lost * 4096 + total_cwnd * 64 + total_delivery / 8192;
    (total_cwnd, total_inflight, total_delivery, total_lost, score)
}

#[test]
fn tls_padding_matches_scalar() {
    let base = make_data(48, 0xDEADBEEF);
    let cases =
        [(48usize, 0u8), (64usize, 0x00), (96usize, 0xFF), (128usize, 0x1A), (49usize, 0x7E)];

    for (target, pad_byte) in cases {
        let mut accelerated = base.clone();
        accelerate::stealth::add_tls_padding(&mut accelerated, target, pad_byte);
        let expected = reference_add_tls_padding(base.clone(), target, pad_byte);
        assert_eq!(
            accelerated, expected,
            "TLS padding mismatch (target={target}, byte={pad_byte:#04x})"
        );
    }
}

#[test]
fn congestion_aggregation_matches_scalar() {
    use quicfuscate::accelerate::transport::{aggregate_congestion, CongestionSample};

    let samples = vec![
        CongestionSample {
            cwnd: 1_024,
            bytes_in_flight: 65_536,
            delivery_rate: 4_194_304,
            lost_packets: 12,
        },
        CongestionSample {
            cwnd: 2_560,
            bytes_in_flight: 131_072,
            delivery_rate: 8_388_608,
            lost_packets: 4,
        },
        CongestionSample {
            cwnd: 512,
            bytes_in_flight: 17_408,
            delivery_rate: 1_048_576,
            lost_packets: 1,
        },
    ];

    let summary = aggregate_congestion(&samples);
    let expected = reference_congestion_summary(&samples);

    assert_eq!(summary.total_cwnd, expected.0, "cwnd sum mismatch");
    assert_eq!(summary.total_bytes_in_flight, expected.1, "bytes_in_flight sum mismatch");
    assert_eq!(summary.total_delivery_rate, expected.2, "delivery rate sum mismatch");
    assert_eq!(summary.total_lost_packets, expected.3, "lost packets sum mismatch");
    assert_eq!(summary.congestion_score, expected.4, "congestion score mismatch");
}

#[test]
fn sort_consistency() {
    for len in 0..=8 {
        let data_u32 = make_data(len, 0xABCDEF).into_iter().map(|b| b as u32).collect::<Vec<_>>();
        let mut accel_u32 = data_u32.clone();
        let mut ref_u32 = data_u32.clone();
        accelerate::sort::sort_u32(&mut accel_u32);
        ref_u32.sort_unstable();
        assert_eq!(accel_u32, ref_u32, "u32 sort mismatch at len {len}");

        let data_f32 = make_data(len, 0xFACECAFE)
            .into_iter()
            .map(|b| (b as f32) / std::f32::consts::PI)
            .collect::<Vec<_>>();
        let mut accel_f32 = data_f32.clone();
        let mut ref_f32 = data_f32.clone();
        accelerate::sort::sort_f32(&mut accel_f32);
        ref_f32.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(accel_f32, ref_f32, "f32 sort mismatch at len {len}");
    }
}
