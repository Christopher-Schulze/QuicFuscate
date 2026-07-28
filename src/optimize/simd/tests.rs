//! optimize::simd::tests (TODO-563).

use super::*;

// ---- core::xor_blocks ----

#[test]
fn test_xor_blocks_basic() {
    let src = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let mut dst = [0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00];
    let expected: Vec<u8> = dst.iter().zip(src.iter()).map(|(a, b)| a ^ b).collect();
    core::xor_blocks(&mut dst, &src);
    assert_eq!(&dst[..], &expected[..]);
}

#[test]
fn test_xor_blocks_empty() {
    let src: [u8; 0] = [];
    let mut dst: [u8; 0] = [];
    core::xor_blocks(&mut dst, &src);
    // Should not panic on empty input
}

#[test]
fn test_xor_blocks_large_simd_aligned() {
    // 256 bytes forces multi-pass through SIMD paths (NEON=16, AVX2=32, AVX512=64)
    let src: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();
    let mut dst: Vec<u8> = vec![0xFF; 256];
    let expected: Vec<u8> = dst.iter().zip(src.iter()).map(|(a, b)| a ^ b).collect();
    core::xor_blocks(&mut dst, &src);
    assert_eq!(dst, expected);
}

#[test]
fn test_xor_blocks_self_inverse() {
    let key = [0x42; 64];
    let original = [0xDE; 64];
    let mut data = original;
    core::xor_blocks(&mut data, &key);
    assert_ne!(data, original);
    core::xor_blocks(&mut data, &key);
    assert_eq!(data, original);
}

// ---- core::popcnt ----

#[test]
fn test_popcnt_empty() {
    assert_eq!(core::popcnt(&[]), 0);
}

#[test]
fn test_popcnt_known_values() {
    assert_eq!(core::popcnt(&[0xFF]), 8);
    assert_eq!(core::popcnt(&[0x00]), 0);
    assert_eq!(core::popcnt(&[0xAA]), 4); // 10101010
    assert_eq!(core::popcnt(&[0x55]), 4); // 01010101
    assert_eq!(core::popcnt(&[0x01]), 1);
}

#[test]
fn test_popcnt_multi_byte() {
    // 16 bytes of 0xFF = 128 bits set
    let data = [0xFF; 16];
    assert_eq!(core::popcnt(&data), 128);
    // Non-aligned size (9 bytes) to test remainder handling
    let data2 = [0xFF; 9];
    assert_eq!(core::popcnt(&data2), 72);
}

// ---- core::crc32 ----

#[test]
fn test_crc32_empty() {
    let crc = core::crc32(&[], 0);
    // CRC32 of empty data with initial 0 = 0 (identity)
    assert_eq!(crc, 0);
}

#[test]
fn test_crc32_deterministic() {
    let data = b"Hello, World!";
    let crc1 = core::crc32(data, 0);
    let crc2 = core::crc32(data, 0);
    assert_eq!(crc1, crc2);
}

#[test]
fn test_crc32_ieee_known_vector() {
    assert_eq!(core::crc32(b"123456789", 0), 0xCBF4_3926);
}

#[test]
fn test_crc32_different_data_different_hash() {
    let crc_a = core::crc32(b"AAAA", 0);
    let crc_b = core::crc32(b"BBBB", 0);
    assert_ne!(crc_a, crc_b);
}

#[test]
fn test_crc32_initial_value_affects_result() {
    let data = b"test";
    let crc_zero = core::crc32(data, 0);
    let crc_nonzero = core::crc32(data, 0xDEADBEEF);
    assert_ne!(crc_zero, crc_nonzero);
}

// ---- core::xor_repeating_key_32 ----

#[test]
fn test_xor_repeating_key32_roundtrip() {
    let key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
        0x1D, 0x1E, 0x1F, 0x20,
    ];
    let original: Vec<u8> = (0..100).collect();
    let mut data = original.clone();
    core::xor_repeating_key_32(&mut data, &key);
    assert_ne!(data, original);
    core::xor_repeating_key_32(&mut data, &key);
    assert_eq!(data, original);
}

#[test]
fn test_xor_repeating_key32_empty() {
    let key = [0xAB; 32];
    let mut data: Vec<u8> = vec![];
    core::xor_repeating_key_32(&mut data, &key);
    assert!(data.is_empty());
}

#[test]
fn test_xor_repeating_key32_single_byte() {
    let key: [u8; 32] = {
        let mut k = [0u8; 32];
        k[0] = 0xFF;
        k
    };
    let mut data = [0x42u8];
    core::xor_repeating_key_32(&mut data, &key);
    assert_eq!(data[0], 0x42 ^ 0xFF);
}

// ---- core::xor_repeating_key (arbitrary) ----

#[test]
fn test_xor_repeating_key_arbitrary_roundtrip() {
    let key = b"secret";
    let original = b"Hello, World! This is a test message.".to_vec();
    let mut data = original.clone();
    core::xor_repeating_key(&mut data, key, 0);
    assert_ne!(data, original);
    core::xor_repeating_key(&mut data, key, 0);
    assert_eq!(data, original);
}

#[test]
fn test_xor_repeating_key_empty_key_noop() {
    let mut data = vec![0x42; 10];
    let original = data.clone();
    core::xor_repeating_key(&mut data, &[], 0);
    assert_eq!(data, original);
}

#[test]
fn test_xor_repeating_key_empty_data_noop() {
    let key = b"key";
    let mut data: Vec<u8> = vec![];
    core::xor_repeating_key(&mut data, key, 0);
    assert!(data.is_empty());
}

#[test]
fn test_xor_repeating_key_offset_correctness() {
    // XOR with offset=3 should start from key[3 % key.len()]
    let key = [0x10, 0x20, 0x30, 0x40, 0x50];
    let mut data = [0x00; 5];
    core::xor_repeating_key(&mut data, &key, 3);
    // offset=3 -> key indices: 3,4,0,1,2
    assert_eq!(data, [0x40, 0x50, 0x10, 0x20, 0x30]);
}

#[test]
fn test_xor_repeating_key_32byte_fast_path() {
    // When key.len()==32 and start%32==0, should use the fast xor_repeating_key_32 path
    // Verify result matches manual computation
    let key: Vec<u8> = (1..=32).collect();
    let key32: [u8; 32] = key.clone().try_into().unwrap();
    let original: Vec<u8> = (0..96).collect();

    let mut via_generic = original.clone();
    core::xor_repeating_key(&mut via_generic, &key, 0);

    let mut via_direct = original.clone();
    core::xor_repeating_key_32(&mut via_direct, &key32);

    assert_eq!(via_generic, via_direct);
}

// ---- galois::gf_mul ----

#[test]
fn test_gf_mul_identity() {
    // GF multiply by 1 is identity
    let input: Vec<u8> = (0..64).collect();
    let mut output = vec![0u8; 64];
    galois::gf_mul(&input, 1, &mut output);
    assert_eq!(output, input);
}

#[test]
fn test_gf_mul_zero() {
    // GF multiply by 0 is zero
    let input: Vec<u8> = (1..65).collect();
    let mut output = vec![0xFFu8; 64];
    galois::gf_mul(&input, 0, &mut output);
    assert!(output.iter().all(|&b| b == 0));
}

#[test]
fn test_gf_mul_empty() {
    let mut output = vec![0u8; 0];
    galois::gf_mul(&[], 0x42, &mut output);
    // Should not panic
}

#[test]
fn test_gf_mul_single_byte() {
    // GF(2^8) multiply 0x53 * 0xCA = known value
    // Verify via the scalar path identity: gf_mul(a,b) == gf_mul(b,a) conceptually
    let mut out_a = [0u8; 1];
    let mut out_b = [0u8; 1];
    galois::gf_mul(&[0x53], 0xCA, &mut out_a);
    galois::gf_mul(&[0xCA], 0x53, &mut out_b);
    // GF multiplication is commutative
    assert_eq!(out_a[0], out_b[0]);
}

#[test]
fn test_gf_mul_deterministic() {
    let input: Vec<u8> = (0..128).collect();
    let mut out1 = vec![0u8; 128];
    let mut out2 = vec![0u8; 128];
    galois::gf_mul(&input, 0x42, &mut out1);
    galois::gf_mul(&input, 0x42, &mut out2);
    assert_eq!(out1, out2);
}

// ---- pattern::find_pattern ----

#[test]
fn test_pattern_find_basic() {
    let haystack = b"Hello, World!";
    assert_eq!(pattern::find_pattern(haystack, b"World"), Some(7));
}

#[test]
fn test_pattern_find_not_found() {
    let haystack = b"Hello, World!";
    assert_eq!(pattern::find_pattern(haystack, b"xyz"), None);
}

#[test]
fn test_pattern_find_at_start() {
    let haystack = b"Hello, World!";
    assert_eq!(pattern::find_pattern(haystack, b"Hello"), Some(0));
}

#[test]
fn test_pattern_find_single_byte_needle() {
    let haystack = b"abcdef";
    assert_eq!(pattern::find_pattern(haystack, b"d"), Some(3));
    assert_eq!(pattern::find_pattern(haystack, b"a"), Some(0));
    assert_eq!(pattern::find_pattern(haystack, b"f"), Some(5));
    assert_eq!(pattern::find_pattern(haystack, b"z"), None);
}

// ---- neural::dot_product ----

#[test]
fn test_dot_product_basic() {
    let a = [1.0f32, 2.0, 3.0, 4.0];
    let b = [5.0f32, 6.0, 7.0, 8.0];
    let result = neural::dot_product(&a, &b);
    // 1*5 + 2*6 + 3*7 + 4*8 = 5+12+21+32 = 70
    assert!((result - 70.0).abs() < 1e-5);
}

#[test]
fn test_dot_product_empty() {
    let result = neural::dot_product(&[], &[]);
    assert!((result - 0.0).abs() < 1e-10);
}

#[test]
fn test_dot_product_single() {
    let result = neural::dot_product(&[3.0], &[7.0]);
    assert!((result - 21.0).abs() < 1e-5);
}

#[test]
fn test_dot_product_orthogonal() {
    // Orthogonal vectors have dot product = 0
    let a = [1.0f32, 0.0, 0.0];
    let b = [0.0f32, 1.0, 0.0];
    let result = neural::dot_product(&a, &b);
    assert!((result - 0.0).abs() < 1e-10);
}

#[test]
fn test_dot_product_mismatched_lengths() {
    // Should use min(a.len(), b.len()) elements
    let a = [1.0f32, 2.0, 3.0, 99.0];
    let b = [4.0f32, 5.0, 6.0];
    let result = neural::dot_product(&a, &b);
    // 1*4 + 2*5 + 3*6 = 4+10+18 = 32
    assert!((result - 32.0).abs() < 1e-5);
}

// ---- compress::histogram ----

#[test]
fn test_histogram_empty() {
    let hist = compress::histogram(&[]);
    assert!(hist.iter().all(|&c| c == 0));
}

#[test]
fn test_histogram_single_byte() {
    let hist = compress::histogram(&[42]);
    assert_eq!(hist[42], 1);
    let total: u32 = hist.iter().sum();
    assert_eq!(total, 1);
}

#[test]
fn test_histogram_uniform() {
    // Each byte value appears exactly once
    let data: Vec<u8> = (0..=255).map(|i| i as u8).collect();
    let hist = compress::histogram(&data);
    for count in &hist {
        assert_eq!(*count, 1);
    }
}

#[test]
fn test_histogram_repeated() {
    let data = vec![0xAA; 100];
    let hist = compress::histogram(&data);
    assert_eq!(hist[0xAA], 100);
    let total: u32 = hist.iter().sum();
    assert_eq!(total, 100);
}

#[test]
fn test_histogram_total_equals_length() {
    let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    let hist = compress::histogram(&data);
    let total: u32 = hist.iter().sum();
    assert_eq!(total, 1024);
}

// ---- compress::find_pattern ----

#[test]
fn test_compress_find_pattern_basic() {
    let haystack = b"ABCDEFGHIJKLMNOP";
    assert_eq!(compress::find_pattern(haystack, b"GHIJ"), Some(6));
}

#[test]
fn test_compress_find_pattern_not_found() {
    let haystack = b"ABCDEFGHIJKLMNOP";
    assert_eq!(compress::find_pattern(haystack, b"XYZ"), None);
}

#[test]
fn test_compress_find_pattern_empty_needle() {
    let haystack = b"ABCDEF";
    assert_eq!(compress::find_pattern(haystack, b""), None);
}

#[test]
fn test_compress_find_pattern_needle_longer_than_haystack() {
    let haystack = b"AB";
    assert_eq!(compress::find_pattern(haystack, b"ABCDEF"), None);
}

#[test]
fn test_compress_find_pattern_full_match() {
    let haystack = b"exact";
    assert_eq!(compress::find_pattern(haystack, b"exact"), Some(0));
}

// ---- crypto::aes_round ----

#[test]
fn test_aes_round_deterministic() {
    let mut state1 = [
        0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
        0x07, 0x34,
    ];
    let mut state2 = state1;
    let round_key = [
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
        0x4F, 0x3C,
    ];
    crypto::aes_round(&mut state1, &round_key);
    crypto::aes_round(&mut state2, &round_key);
    assert_eq!(state1, state2);
}

#[test]
fn test_aes_round_modifies_state() {
    let original = [0x00u8; 16];
    let mut state = original;
    let round_key = [0xFF; 16];
    crypto::aes_round(&mut state, &round_key);
    // AES round should produce different output (at minimum XOR with key)
    assert_ne!(state, original);
}

// ---- crypto::chacha20 ----

#[test]
fn test_chacha20_xor_roundtrip() {
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let original: Vec<u8> = (0..200).collect();
    let mut data = original.clone();
    crypto::chacha20_xor_in_place(&mut data, &key, &nonce, 0);
    assert_ne!(data, original);
    crypto::chacha20_xor_in_place(&mut data, &key, &nonce, 0);
    assert_eq!(data, original);
}

#[test]
fn test_chacha20_blocks_x4_produces_four_distinct_blocks() {
    let key = [0xAA; 32];
    let nonce = [0xBB; 12];
    let blocks = crypto::chacha20_blocks_x4(&key, &nonce, 0);
    // Each block should be distinct (different counter values)
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(blocks[i], blocks[j], "blocks[{}] == blocks[{}]", i, j);
        }
    }
}

#[test]
fn test_chacha20_blocks_x4_matches_scalar() {
    use crate::crypto::chacha::chacha20_block;
    let key = [0x55; 32];
    let nonce = [0x77; 12];
    let counter = 42u32;
    let blocks = crypto::chacha20_blocks_x4(&key, &nonce, counter);
    for i in 0..4u32 {
        let scalar = chacha20_block(&key, counter.wrapping_add(i), &nonce);
        assert_eq!(blocks[i as usize], scalar, "block {} mismatch between x4 and scalar", i);
    }
}

#[test]
fn test_chacha20_blocks_x16_matches_scalar() {
    use crate::crypto::chacha::chacha20_block;
    let key = [0x33; 32];
    let nonce = [0x99; 12];
    let counter = 100u32;
    let blocks = crypto::chacha20_blocks_x16(&key, &nonce, counter);
    for i in 0..16u32 {
        let scalar = chacha20_block(&key, counter.wrapping_add(i), &nonce);
        assert_eq!(blocks[i as usize], scalar, "block {} mismatch between x16 and scalar", i);
    }
}

// ---- FeatureDetector consistency ----

#[test]
fn test_feature_detector_consistent() {
    let features_a = FeatureDetector::instance().features_full();
    let features_b = FeatureDetector::instance().features_full();
    // Same singleton, same pointer
    assert!(std::ptr::eq(features_a, features_b));
}

#[test]
fn test_feature_detector_baseline() {
    let features = FeatureDetector::instance().features_full();
    // On any platform, at least one field should be queryable without panic
    // On aarch64 macOS, NEON is always available
    #[cfg(target_arch = "aarch64")]
    assert!(features.neon, "NEON should always be available on aarch64");
    // On x86_64, SSE2 is baseline
    #[cfg(target_arch = "x86_64")]
    assert!(features.sse2, "SSE2 should always be available on x86_64");
    let _ = features; // suppress unused on other archs
}
