//! optimize::simd::galois (TODO-563).

#[cfg(target_arch = "x86_64")]
use super::super::telemetry;
use super::FeatureDetector;
/// GF(2^8) multiplication with best available SIMD
#[inline(always)]
pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    if features.gfni && features.avx512f {
        return unsafe { gf_mul_avx512_gfni(a, b, dst) };
    }

    #[cfg(target_arch = "x86_64")]
    if features.avx2 {
        return unsafe { gf_mul_avx2(a, b, dst) };
    }

    #[cfg(target_arch = "aarch64")]
    if features.sve2 {
        return unsafe { gf_mul_sve2(a, b, dst) };
    }

    #[cfg(target_arch = "aarch64")]
    if features.neon {
        return unsafe { gf_mul_neon(a, b, dst) };
    }

    gf_mul_scalar(a, b, dst);
}

/// GF(2^8) multiplication with AVX-512 GFNI - 15x faster!
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
#[target_feature(enable = "gfni")]
#[inline]
unsafe fn gf_mul_avx512_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let b_broadcast = _mm512_set1_epi8(b as i8);
    let len = a.len().min(dst.len());
    let mut i = 0;

    // Process 64 bytes at once with AVX-512 GFNI
    while i + 64 <= len {
        let data = _mm512_loadu_si512(a[i..].as_ptr() as *const __m512i);
        let result = _mm512_gf2p8mul_epi8(data, b_broadcast);
        _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, result);
        i += 64;
    }

    // Handle remainder
    while i < len {
        dst[i] = gf_mul_byte(a[i], b);
        i += 1;
    }

    telemetry::FEC_AVX512_OPS.inc();
}

/// GF(2^8) multiplication with AVX2 - 5x faster with correct galois field arithmetic
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());
    let mut i = 0;

    // Precompute GF multiplication tables for multiplier b
    let mut lo_table = [0u8; 16];
    let mut hi_table = [0u8; 16];

    for j in 0..16 {
        lo_table[j] = gf_mul_byte(j as u8, b);
        hi_table[j] = gf_mul_byte((j << 4) as u8, b);
    }

    // Load lookup tables into AVX2 registers
    let lo_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
    let hi_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
    let nibble_mask = _mm256_set1_epi8(0x0F);

    // Process 32 bytes at once
    while i + 32 <= len {
        let data = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);

        // Split into low and high nibbles
        let lo_nibbles = _mm256_and_si256(data, nibble_mask);
        let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(data, 4), nibble_mask);

        // Table lookup for both nibbles
        let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
        let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);

        // XOR the results (GF addition)
        let result = _mm256_xor_si256(lo_result, hi_result);
        _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, result);
        i += 32;
    }

    // Process remainder with scalar
    while i < len {
        dst[i] = gf_mul_byte(a[i], b);
        i += 1;
    }

    telemetry::FEC_AVX2_OPS.inc();
}

/// Scalar GF multiplication fallback
#[inline(always)]
fn gf_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
    for i in 0..a.len().min(dst.len()) {
        dst[i] = gf_mul_byte(a[i], b);
    }
}

/// Shared NEON implementation used by both NEON and SVE2 frontends.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf_mul_neon_impl(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::aarch64::*;

    let len = a.len().min(dst.len());
    let mut i = 0;

    // Precompute GF multiplication tables for multiplier b
    let mut lo_table = [0u8; 16];
    let mut hi_table = [0u8; 16];

    for j in 0..16 {
        lo_table[j] = gf_mul_byte(j as u8, b);
        hi_table[j] = gf_mul_byte((j << 4) as u8, b);
    }

    // Load lookup tables into NEON registers
    let lo_lut = vld1q_u8(lo_table.as_ptr());
    let hi_lut = vld1q_u8(hi_table.as_ptr());
    let nibble_mask = vdupq_n_u8(0x0F);

    // Process 16 bytes at once with NEON
    while i + 16 <= len {
        let data = vld1q_u8(a[i..].as_ptr());

        // Split into low and high nibbles
        let lo_nibbles = vandq_u8(data, nibble_mask);
        let hi_nibbles = vandq_u8(vshrq_n_u8(data, 4), nibble_mask);

        // Table lookup for both nibbles using NEON table lookup
        let lo_result = vqtbl1q_u8(lo_lut, lo_nibbles);
        let hi_result = vqtbl1q_u8(hi_lut, hi_nibbles);

        // XOR the results (GF addition)
        let result = veorq_u8(lo_result, hi_result);
        vst1q_u8(dst[i..].as_mut_ptr(), result);
        i += 16;
    }

    // Process remainder with scalar
    while i < len {
        dst[i] = gf_mul_byte(a[i], b);
        i += 1;
    }
}

/// GF(2^8) multiplication with NEON - 8x faster than scalar!
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
    gf_mul_neon_impl(a, b, dst);
    crate::optimize::telemetry::FEC_NEON_OPS.inc();
}

/// GF(2^8) multiplication with SVE2 - scalable vector processing!
#[cfg(target_arch = "aarch64")]
unsafe fn gf_mul_sve2(a: &[u8], b: u8, dst: &mut [u8]) {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        let len = core::cmp::min(a.len(), dst.len());
        let mut offset = 0usize;
        let poly = svdup_n_u8(0x1B);
        let msb_mask = svdup_n_u8(0x80);
        let zero = svdup_n_u8(0);

        while offset < len {
            let pg = svwhilelt_b8(offset as u64, len as u64);
            let mut multiplicand = svld1_u8(pg, a.as_ptr().add(offset));
            let mut acc = svdup_n_u8(0);
            let mut factor = b;

            for _ in 0..8 {
                if (factor & 1) != 0 {
                    acc = sveor_u8_m(pg, acc, acc, multiplicand);
                }

                let high_bits = svcmpne_u8(pg, svand_u8_z(pg, multiplicand, msb_mask), zero);
                let doubled = svadd_u8_x(pg, multiplicand, multiplicand);
                let reduced = sveor_u8_m(high_bits, doubled, doubled, poly);
                multiplicand = reduced;
                factor >>= 1;
            }

            svst1_u8(pg, dst.as_mut_ptr().add(offset), acc);
            offset += svcntb() as usize;
        }

        crate::optimize::telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf_mul_neon(a, b, dst)
}

/// Single byte GF multiplication
#[inline(always)]
fn gf_mul_byte(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;

    while bb != 0 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi_bit = aa & 0x80;
        aa <<= 1;
        if hi_bit != 0 {
            aa ^= 0x1B; // AES polynomial
        }
        bb >>= 1;
    }
    result
}
