#![cfg(feature = "rust-tests")]

#[cfg(target_arch = "x86_64")]
use rand::{rngs::StdRng, Rng, SeedableRng};

#[cfg(target_arch = "x86_64")]
fn scalar_merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_by_key(|r| r.0);
    let mut out = Vec::with_capacity(ranges.len());
    for (s, e) in ranges.into_iter() {
        if let Some(last) = out.last_mut() {
            if s <= last.1 {
                last.1 = last.1.max(e);
                continue;
            }
        }
        out.push((s, e));
    }
    out
}

#[test]
#[cfg(target_arch = "x86_64")]
fn avx2_matches_scalar_random() {
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    let mut rng = StdRng::seed_from_u64(0xA5A5_5A5A);
    for n in [0usize, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 64, 127, 128].iter().copied() {
        for _ in 0..64 {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let a = rng.random_range(0u64..10_000);
                let b = rng.random_range(a..a + 64);
                v.push((a, b));
            }
            let scalar = scalar_merge(v.clone());
            let avx = quicfuscate::simd::canonical_ack_blocks_avx2_for_rust_tests(&v);
            assert_eq!(scalar, avx);
        }
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn avx512_matches_scalar_random() {
    if !(std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vl")) {
        return;
    }
    let mut rng = SeedableRng::seed_from_u64(0x1234_5678_9ABC_DEF0);
    for n in [8usize, 16, 24, 32, 64, 96, 128].iter().copied() {
        for _ in 0..64 {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let a = rng.random_range(0u64..50_000);
                let b = rng.random_range(a..a + 128);
                v.push((a, b));
            }
            let scalar = scalar_merge(v.clone());
            let wide = quicfuscate::simd::canonical_ack_blocks_avx512_for_rust_tests(&v);
            assert_eq!(scalar, wide);
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_ack_merge_parity_on_non_x86_64() {}
