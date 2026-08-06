#![cfg(feature = "rust-tests")]

#[cfg(target_arch = "x86_64")]
use quicfuscate::optimize::x86_sse2::{xor_repeating_key32_sse2, xor_repeating_sse2};

#[cfg(target_arch = "x86_64")]
fn xor_scalar(dst: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for i in 0..dst.len() {
        dst[i] ^= key[i % key.len()];
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn sse2_xor_repeating_key32_matches_scalar() {
    if !std::is_x86_feature_detected!("sse2") {
        eprintln!("SIMD_SKIP test=sse2_xor_repeating_key32_matches_scalar required=sse2");
        return;
    }
    let key: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let lengths = [0usize, 1, 15, 16, 31, 32, 33, 64, 127, 128, 513];

    for &n in &lengths {
        let mut a: Vec<u8> = (0..n as u32).map(|x| (x as u8).wrapping_mul(29)).collect();
        let mut b = a.clone();

        unsafe { xor_repeating_key32_sse2(&mut a, &key) };
        xor_scalar(&mut b, &key);

        assert_eq!(a, b, "sse2 xor32 parity mismatch at length {}", n);
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn sse2_xor_repeating_matches_scalar_varied_keys() {
    if !std::is_x86_feature_detected!("sse2") {
        eprintln!("SIMD_SKIP test=sse2_xor_repeating_matches_scalar_varied_keys required=sse2");
        return;
    }
    let keys: Vec<Vec<u8>> = vec![
        vec![0x01],
        vec![0xAA, 0xBB, 0xCC],
        vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70],
        (0u8..=15).collect(),
        (0u8..=31).collect(),
    ];
    let lengths = [0usize, 3, 8, 15, 16, 17, 64, 129];

    for key in keys {
        for &n in &lengths {
            let mut a: Vec<u8> = (0..n as u32).map(|x| (x as u8).wrapping_mul(13)).collect();
            let mut b = a.clone();

            unsafe { xor_repeating_sse2(&mut a, &key) };
            xor_scalar(&mut b, &key);

            assert_eq!(a, b, "sse2 xor parity mismatch (len={}, key_len={})", n, key.len());
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[test]
#[ignore = "SKIP: target requires x86_64"]
fn skip_xor_sse2_parity_on_non_x86_64() {}
