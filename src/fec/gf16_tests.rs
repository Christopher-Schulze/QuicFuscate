use rand::Rng;

fn gf16_mul_ref(a: u16, b: u16) -> u16 {
    let mut aa = a;
    let mut bb = b;
    let mut res: u16 = 0;
    while bb != 0 {
        if (bb & 1) != 0 {
            res ^= aa;
        }
        bb >>= 1;
        let carry = (aa & 0x8000) != 0;
        aa <<= 1;
        if carry {
            aa ^= 0x100B;
        }
    }
    res
}

#[test]
fn gf16_mul_consistency_random() {
    use crate::fec::gf_tables::gf16_mul as gf16_mul_impl;
    let mut rng = rand::rng();
    let iters = std::env::var("QUICFUSCATE_GF16_TEST_ITERS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(500);
    for _ in 0..iters {
        let a: u16 = rng.random();
        let b: u16 = rng.random();
        let r1 = gf16_mul_impl(a, b);
        let r2 = gf16_mul_ref(a, b);
        assert_eq!(r1, r2, "gf16 mul mismatch for a={:#06x}, b={:#06x}", a, b);
    }
}

#[cfg(target_arch = "x86_64")]
fn gf16_source_words(count: usize) -> Vec<u16> {
    (0..count).map(|index| (index as u16).wrapping_mul(0x219d) ^ 0xa55a).collect()
}

#[cfg(target_arch = "x86_64")]
fn gf16_initial_words(count: usize) -> Vec<u16> {
    (0..count).map(|index| (index as u16).wrapping_mul(0x1041) ^ 0x5aa5).collect()
}

/// Scalar reference for the fused multiply-XOR the vector kernels implement, bounded exactly the
/// way `bounded_u16_len` bounds the kernels.
#[cfg(target_arch = "x86_64")]
fn gf16_mul_slice_ref(coefficient: u16, source: &[u16], destination: &mut [u16], len: usize) {
    let len = len.min(source.len()).min(destination.len());
    for index in 0..len {
        destination[index] ^= gf16_mul_ref(coefficient, source[index]);
    }
}

#[test]
fn bounded_u16_len_clamps_to_the_shorter_of_request_source_and_destination() {
    let source = vec![0u16; 40];
    let destination = vec![0u16; 24];

    assert_eq!(super::bounded_u16_len(&source, &destination, 16), 16, "request is the minimum");
    assert_eq!(super::bounded_u16_len(&source, &destination, 32), 24, "destination is the minimum");
    assert_eq!(
        super::bounded_u16_len(&destination, &source, 32),
        24,
        "source is the minimum in the mirrored case"
    );
    assert_eq!(super::bounded_u16_len(&source, &destination, usize::MAX), 24, "no overflow");
    assert_eq!(super::bounded_u16_len(&source, &destination, 0), 0, "zero request stays zero");
    assert_eq!(super::bounded_u16_len(&[], &destination, 8), 0, "empty source yields zero");
    assert_eq!(super::bounded_u16_len(&source, &[], 8), 0, "empty destination yields zero");
}

/// Lengths chosen around the 32-word AVX-512 lane so that empty, sub-lane, exact-lane, and
/// masked-tail paths are each covered rather than a single aligned length.
#[cfg(target_arch = "x86_64")]
const GF16_SLICE_LENGTHS: [usize; 9] = [0, 1, 31, 32, 33, 63, 64, 65, 96];

#[cfg(target_arch = "x86_64")]
#[test]
fn gf16_vbmi2_slice_matches_scalar_reference() {
    if !(std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
        && std::arch::is_x86_feature_detected!("avx512vbmi2"))
    {
        eprintln!(
            "SIMD_SKIP test=gf16_vbmi2_slice_matches_scalar_reference required=avx512f+avx512bw+avx512vbmi2"
        );
        return;
    }

    let coefficient = 0x7a31;
    for length in GF16_SLICE_LENGTHS {
        let source = gf16_source_words(length);
        let initial = gf16_initial_words(length);

        let mut expected = initial.clone();
        gf16_mul_slice_ref(coefficient, &source, &mut expected, length);

        let mut actual = initial;
        unsafe {
            super::gf16_mul_slice_vbmi2(coefficient, &source, &mut actual, length);
        }
        assert_eq!(actual, expected, "vbmi2 kernel mismatch at length {length}");
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn gf16_vbmi2_slice_clamps_overlong_requests_and_leaves_the_tail_untouched() {
    if !(std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
        && std::arch::is_x86_feature_detected!("avx512vbmi2"))
    {
        eprintln!(
            "SIMD_SKIP test=gf16_vbmi2_slice_clamps_overlong_requests_and_leaves_the_tail_untouched required=avx512f+avx512bw+avx512vbmi2"
        );
        return;
    }

    let coefficient = 0x2f19;
    // Destination outlives the source, and the request exceeds both. Only the overlapping prefix
    // may change; a kernel that trusted `len` would corrupt the tail or read out of bounds.
    let source = gf16_source_words(20);
    let initial = gf16_initial_words(48);

    let mut expected = initial.clone();
    gf16_mul_slice_ref(coefficient, &source, &mut expected, usize::MAX);

    let mut actual = initial.clone();
    unsafe {
        super::gf16_mul_slice_vbmi2(coefficient, &source, &mut actual, usize::MAX);
    }

    assert_eq!(actual, expected, "overlong request must clamp to the shorter slice");
    assert_eq!(&actual[20..], &initial[20..], "tail beyond the source must stay untouched");
}
