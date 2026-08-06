//! Extracted SIMD `galois` submodule (TODO-563).

use super::*;

/// GF(2^8) multiplication
#[inline(always)]
pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by a runtime feature check matching the
    // callee's `#[target_feature]`. All callees read from `a`, write to `dst`,
    // and handle length clamping internally (`a.len().min(dst.len())`).
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        // GFNI usage requires AVX-512F+GFNI on x86_64 in this codebase
        if full.gfni && full.avx512f {
            return unsafe { super::x86::gf_mul_avx512_gfni(a, b, dst) };
        }
        if full.simd_dispatch_matrix().avx2 {
            return unsafe { super::x86::gf_mul_avx2(a, b, dst) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            unsafe { arm::gf_mul_sve2(a, b, dst) };
            crate::optimize::telemetry::FEC_SVE2_OPS.inc();
            return;
        }
        if full.neon && full.pmull {
            unsafe { arm::gf_mul_neon_pmull(a, b, dst) };
            crate::optimize::telemetry::FEC_NEON_OPS.inc();
            return;
        }
        if full.neon {
            unsafe { arm::gf_mul_neon(a, b, dst) };
            crate::optimize::telemetry::FEC_NEON_OPS.inc();
            return;
        }
    }

    scalar::gf_mul(a, b, dst)
}

// =========================================================================
// GF(2^4) - 4x less computation for low-loss scenarios (<5%)
// =========================================================================

/// GF(2^4) multiplication - 4x faster than GF(2^8) for low loss
/// Uses polynomial x^4 + x + 1 (0x13 reduction)
#[inline(always)]
pub fn gf4_mul(a: &[u8], b: u8, dst: &mut [u8]) {
    let features = FeatureDetector::instance();
    let b_lo = b & 0x0F;

    // SAFETY: Each branch is guarded by a runtime feature check matching
    // the callee's `#[target_feature]`. Callees clamp to `a.len().min(dst.len())`
    // internally and only read/write within those bounds.
    #[cfg(target_arch = "x86_64")]
    {
        if features.features_full().simd_dispatch_matrix().avx2 {
            unsafe { gf4_mul_avx2(a, b_lo, dst) };
            crate::optimize::telemetry::FEC_AVX2_OPS.inc();
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.features_full().neon {
            unsafe { gf4_mul_neon(a, b_lo, dst) };
            crate::optimize::telemetry::FEC_NEON_OPS.inc();
            return;
        }
    }

    gf4_mul_scalar(a, b_lo, dst)
}

/// Multiply packed GF(2^4) nibbles and XOR the result into `dst`.
#[inline(always)]
pub fn gf4_mul_xor(a: &[u8], b: u8, dst: &mut [u8]) {
    let features = FeatureDetector::instance();
    let b_lo = b & 0x0F;

    #[cfg(target_arch = "x86_64")]
    {
        if features.features_full().simd_dispatch_matrix().avx2 {
            unsafe { gf4_mul_xor_avx2(a, b_lo, dst) };
            crate::optimize::telemetry::FEC_AVX2_OPS.inc();
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.features_full().neon {
            unsafe { gf4_mul_xor_neon(a, b_lo, dst) };
            crate::optimize::telemetry::FEC_NEON_OPS.inc();
            return;
        }
    }

    gf4_mul_xor_scalar(a, b_lo, dst)
}

/// Scalar GF(2^4) multiplication
#[inline]
fn gf4_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
    let len = a.len().min(dst.len());
    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    for i in 0..len {
        let a_lo = a[i] & 0x0F;
        let a_hi = (a[i] >> 4) & 0x0F;
        let r_lo = table[a_lo as usize];
        let r_hi = table[a_hi as usize];
        dst[i] = r_lo | (r_hi << 4);
    }
}

#[inline]
fn gf4_mul_xor_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
    let len = a.len().min(dst.len());
    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    for i in 0..len {
        let byte = a[i];
        dst[i] ^= table[(byte & 0x0F) as usize] | (table[(byte >> 4) as usize] << 4);
    }
}

const fn build_gf4_table() -> [[u8; 16]; 16] {
    let mut table = [[0u8; 16]; 16];
    let mut b = 0;
    while b < 16 {
        let mut a = 0;
        while a < 16 {
            table[b][a] = gf4_mul_byte_const(a as u8, b as u8);
            a += 1;
        }
        b += 1;
    }
    table
}

const GF4_MUL_TABLE: [[u8; 16]; 16] = build_gf4_table();

/// Single GF(2^4) byte multiply with reduction x^4+x+1
#[inline(always)]
const fn gf4_mul_byte_const(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a & 0x0F;
    let mut bb = b & 0x0F;

    let mut bit = 0;
    while bit < 4 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi_bit = aa & 0x08;
        aa <<= 1;
        if hi_bit != 0 {
            aa ^= 0x03; // Reduce by x^4+x+1 (low 4 bits)
        }
        aa &= 0x0F;
        bb >>= 1;
        bit += 1;
    }
    result & 0x0F
}

/// AVX2 GF(2^4) multiplication using table lookup
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf4_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());

    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    let lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(table.as_ptr() as *const _));
    let mask_lo = _mm256_set1_epi8(0x0F);

    let mut i = 0;
    while i + 32 <= len {
        let v = _mm256_loadu_si256(a.as_ptr().add(i) as *const _);

        // Extract low and high nibbles
        let lo = _mm256_and_si256(v, mask_lo);
        let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask_lo);

        // Table lookup for both nibbles
        let r_lo = _mm256_shuffle_epi8(lut, lo);
        let r_hi = _mm256_shuffle_epi8(lut, hi);

        // Combine: r_lo | (r_hi << 4)
        let result = _mm256_or_si256(r_lo, _mm256_slli_epi16(r_hi, 4));

        // Mask to keep only valid nibbles
        let masked = _mm256_and_si256(result, _mm256_set1_epi8(0xFF_u8 as i8));
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut _, masked);
        i += 32;
    }

    // Tail
    if i < len {
        gf4_mul_scalar(&a[i..], b, &mut dst[i..]);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf4_mul_xor_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());
    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    let lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(table.as_ptr() as *const _));
    let mask_lo = _mm256_set1_epi8(0x0F);
    let mut i = 0;
    while i + 32 <= len {
        let source = _mm256_loadu_si256(a.as_ptr().add(i) as *const _);
        let current = _mm256_loadu_si256(dst.as_ptr().add(i) as *const _);
        let lo = _mm256_and_si256(source, mask_lo);
        let hi = _mm256_and_si256(_mm256_srli_epi16(source, 4), mask_lo);
        let product = _mm256_or_si256(
            _mm256_shuffle_epi8(lut, lo),
            _mm256_slli_epi16(_mm256_shuffle_epi8(lut, hi), 4),
        );
        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut _, _mm256_xor_si256(current, product));
        i += 32;
    }
    if i < len {
        gf4_mul_xor_scalar(&a[i..], b, &mut dst[i..]);
    }
}

/// NEON GF(2^4) multiplication
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf4_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
    use ::core::arch::aarch64::*;

    let len = a.len().min(dst.len());

    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    let lut = vld1q_u8(table.as_ptr());
    let mask_lo = vdupq_n_u8(0x0F);

    let mut i = 0;
    while i + 16 <= len {
        let v = vld1q_u8(a.as_ptr().add(i));

        // Extract nibbles
        let lo = vandq_u8(v, mask_lo);
        let hi = vandq_u8(vshrq_n_u8(v, 4), mask_lo);

        // Table lookup
        let r_lo = vqtbl1q_u8(lut, lo);
        let r_hi = vqtbl1q_u8(lut, hi);

        // Combine
        let result = vorrq_u8(r_lo, vshlq_n_u8(r_hi, 4));
        vst1q_u8(dst.as_mut_ptr().add(i), result);
        i += 16;
    }

    // Tail
    if i < len {
        gf4_mul_scalar(&a[i..], b, &mut dst[i..]);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf4_mul_xor_neon(a: &[u8], b: u8, dst: &mut [u8]) {
    use ::core::arch::aarch64::*;

    let len = a.len().min(dst.len());
    let table = &GF4_MUL_TABLE[(b & 0x0F) as usize];
    let lut = vld1q_u8(table.as_ptr());
    let mask_lo = vdupq_n_u8(0x0F);
    let mut i = 0;
    while i + 16 <= len {
        let source = vld1q_u8(a.as_ptr().add(i));
        let current = vld1q_u8(dst.as_ptr().add(i));
        let lo = vandq_u8(source, mask_lo);
        let hi = vandq_u8(vshrq_n_u8(source, 4), mask_lo);
        let product = vorrq_u8(vqtbl1q_u8(lut, lo), vshlq_n_u8(vqtbl1q_u8(lut, hi), 4));
        vst1q_u8(dst.as_mut_ptr().add(i), veorq_u8(current, product));
        i += 16;
    }
    if i < len {
        gf4_mul_xor_scalar(&a[i..], b, &mut dst[i..]);
    }
}

// =========================================================================
// GF(2^16) with VPCLMULQDQ - 5-8x faster for Extreme/Ultra modes
// =========================================================================

/// GF(2^16) multiplication - for Extreme/Ultra FEC modes
/// Uses polynomial x^16 + x^12 + x^3 + x + 1 (0x1100B)
#[inline(always)]
pub fn gf16_mul(a: &[u16], b: u16, dst: &mut [u16]) {
    // SAFETY: Each branch is guarded by a runtime feature check matching
    // the callee's `#[target_feature]`. Callees clamp to
    // `a.len().min(dst.len())` and stay within bounds.
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance();
        let matrix = features.features_full().simd_dispatch_matrix();
        // VPCLMULQDQ is the ultimate for GF(2^16)
        if matrix.gf16_vpclmul {
            unsafe { gf16_mul_vpclmulqdq(a, b, dst) };
            crate::optimize::telemetry::GF16_VPCLMUL_OPS.inc();
            return;
        }
        if matrix.gf16_pclmul {
            unsafe { gf16_mul_pclmulqdq(a, b, dst) };
            crate::optimize::telemetry::GF16_PCLMUL_OPS.inc();
            return;
        }
    }

    gf16_mul_scalar(a, b, dst)
}

/// Scalar GF(2^16) multiplication
fn gf16_mul_scalar(a: &[u16], b: u16, dst: &mut [u16]) {
    let len = a.len().min(dst.len());
    for i in 0..len {
        dst[i] = gf16_mul_single(a[i], b);
    }
}

/// Single GF(2^16) multiply with reduction
#[inline(always)]
fn gf16_mul_single(a: u16, b: u16) -> u16 {
    // Russian peasant multiplication in GF(2^16)
    // Polynomial: x^16 + x^12 + x^3 + x + 1 = 0x1100B
    let mut result = 0u32;
    let mut aa = a as u32;
    let mut bb = b as u32;

    for _ in 0..16 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let hi_bit = aa & 0x8000;
        aa <<= 1;
        if hi_bit != 0 {
            aa ^= 0x100B; // Reduce by polynomial (x^16 term implicit)
        }
        bb >>= 1;
    }
    result as u16
}

/// AVX-512 VPCLMULQDQ for GF(2^16) - 8 u16s at once = 5-8x faster!
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "vpclmulqdq", enable = "sse4.1")]
unsafe fn gf16_mul_vpclmulqdq(a: &[u16], b: u16, dst: &mut [u16]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());
    let b_64 = b as u64;
    let b_vec = _mm512_set1_epi64(b_64 as i64);

    // Reduction polynomial for GF(2^16): x^16 + x^12 + x^3 + x + 1
    const POLY: u64 = 0x100B;
    let poly_vec = _mm512_set1_epi64(POLY as i64);

    let mut i = 0;
    while i + 8 <= len {
        // Load 8 u16 values, expand to 8 u64 for carryless multiply
        let a_lo = _mm_loadu_si128(a.as_ptr().add(i) as *const _);
        let a_32 = _mm256_cvtepu16_epi32(a_lo);
        let a_64 = _mm512_cvtepu32_epi64(a_32);

        // Carryless multiply: a[i] * b (produces 32-bit result in low 64 bits)
        let prod = _mm512_clmulepi64_epi128(a_64, b_vec, 0x00);

        // Reduce: extract bits 16-31 and XOR with polynomial
        let hi16 = _mm512_srli_epi64(prod, 16);
        let reduce = _mm512_clmulepi64_epi128(hi16, poly_vec, 0x00);
        let result_64 = _mm512_xor_si512(prod, reduce);

        // Mask to 16 bits and pack back to u16
        let mask16 = _mm512_set1_epi64(0xFFFF);
        let masked = _mm512_and_si512(result_64, mask16);

        // Pack 64-bit to 32-bit to 16-bit
        let result_32 = _mm512_cvtepi64_epi32(masked);
        let lo = _mm256_castsi256_si128(result_32);
        let hi = _mm256_extracti128_si256(result_32, 1);
        let packed = _mm_packus_epi32(lo, hi);
        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, packed);
        i += 8;
    }

    // Tail
    while i < len {
        dst[i] = gf16_mul_single(a[i], b);
        i += 1;
    }
}

/// PCLMULQDQ version for SSE4.2 systems
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq", enable = "sse4.1")]
unsafe fn gf16_mul_pclmulqdq(a: &[u16], b: u16, dst: &mut [u16]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());
    let b_64 = b as u64;
    let b_vec = _mm_set1_epi64x(b_64 as i64);
    const POLY: u64 = 0x100B;
    let poly_vec = _mm_set1_epi64x(POLY as i64);

    let mut i = 0;
    while i + 2 <= len {
        // Load 2 u16, expand to 2 u64
        let a0 = a[i] as u64;
        let a1 = a[i + 1] as u64;
        let a_vec = _mm_set_epi64x(a1 as i64, a0 as i64);

        // Carryless multiply
        let prod0 = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
        let prod1 = _mm_clmulepi64_si128(a_vec, b_vec, 0x11);

        // Reduce
        let hi0 = _mm_srli_epi64(prod0, 16);
        let hi1 = _mm_srli_epi64(prod1, 16);
        let red0 = _mm_clmulepi64_si128(hi0, poly_vec, 0x00);
        let red1 = _mm_clmulepi64_si128(hi1, poly_vec, 0x00);
        let r0 = _mm_xor_si128(prod0, red0);
        let r1 = _mm_xor_si128(prod1, red1);

        // Extract and store
        dst[i] = _mm_extract_epi16(r0, 0) as u16;
        dst[i + 1] = _mm_extract_epi16(r1, 0) as u16;
        i += 2;
    }

    // Tail
    while i < len {
        dst[i] = gf16_mul_single(a[i], b);
        i += 1;
    }
}
