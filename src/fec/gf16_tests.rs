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
#[test]
fn gf16_vbmi2_slice_matches_scalar_reference() {
    if !(std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
        && std::arch::is_x86_feature_detected!("avx512vbmi2"))
    {
        return;
    }

    let coefficient = 0x7a31;
    let source: Vec<u16> =
        (0..64).map(|index| (index as u16).wrapping_mul(0x219d) ^ 0xa55a).collect();
    let initial: Vec<u16> =
        (0..64).map(|index| (index as u16).wrapping_mul(0x1041) ^ 0x5aa5).collect();
    let mut expected = initial.clone();
    for (destination, value) in expected.iter_mut().zip(&source) {
        *destination ^= gf16_mul_ref(coefficient, *value);
    }

    let mut actual = initial;
    unsafe {
        super::gf16_mul_slice_vbmi2(coefficient, &source, &mut actual, source.len());
    }
    assert_eq!(actual, expected);
}
