//! Architecture-dispatched GF(2^16) slice operations for the FEC backend.

use qf_cpu::{CpuFeatures, FeatureDetector};

#[doc(hidden)]
pub const GF16_VBMI2_MIN_WORDS: usize = 32;
#[doc(hidden)]
pub const GF16_AVX512_MIN_WORDS: usize = 64;
#[doc(hidden)]
pub const GF16_AVX2_MIN_WORDS: usize = 32;
#[doc(hidden)]
pub const GF16_SSE2_MIN_WORDS: usize = 16;
#[doc(hidden)]
pub const GF16_SVE2_MIN_WORDS: usize = 24;
#[doc(hidden)]
pub const GF16_NEON_MIN_WORDS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum SimdLevel {
    None,
    Sse2,
    Avx2,
    Avx512Vbmi2,
    Avx512Vbmi,
    Sve2,
    Neon,
}

#[inline(always)]
#[doc(hidden)]
pub fn fec_simd_level_for_features(features: &CpuFeatures) -> SimdLevel {
    let matrix = features.simd_dispatch_matrix();

    if matrix.avx512_vbmi2 {
        SimdLevel::Avx512Vbmi2
    } else if matrix.avx512_vbmi {
        SimdLevel::Avx512Vbmi
    } else if matrix.avx2 {
        SimdLevel::Avx2
    } else if features.sse2 {
        SimdLevel::Sse2
    } else if matrix.sve2 {
        SimdLevel::Sve2
    } else if matrix.neon {
        SimdLevel::Neon
    } else {
        SimdLevel::None
    }
}

#[inline(always)]
#[doc(hidden)]
pub fn gf16_vector_threshold_words_for_features(features: &CpuFeatures) -> usize {
    match fec_simd_level_for_features(features) {
        SimdLevel::Avx512Vbmi2 => GF16_VBMI2_MIN_WORDS,
        SimdLevel::Avx512Vbmi => GF16_AVX512_MIN_WORDS,
        SimdLevel::Avx2 => GF16_AVX2_MIN_WORDS,
        SimdLevel::Sse2 => GF16_SSE2_MIN_WORDS,
        SimdLevel::Sve2 => GF16_SVE2_MIN_WORDS,
        SimdLevel::Neon => GF16_NEON_MIN_WORDS,
        SimdLevel::None => usize::MAX,
    }
}

#[inline(always)]
fn gf16_vector_threshold_words() -> usize {
    gf16_vector_threshold_words_for_features(FeatureDetector::instance().features_full())
}

/// Vectorized GF(2^16) scalar multiply-and-xor over big-endian byte slices.
/// out_xor[j..j+2] ^= gf16_mul(coeff, src[j..j+2]) for all j in steps of 2.
#[inline]
#[doc(hidden)]
pub fn gf16_mul_scalar_slice_u16(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let len = src.len().min(out_xor.len());
    let packet_u16_len = len / 2;
    if coeff == 0 || packet_u16_len == 0 {
        return;
    }

    if coeff == 1 {
        for (source, target) in src[..len].iter().zip(out_xor[..len].iter_mut()) {
            *target ^= *source;
        }
        return;
    }

    let vector_threshold = gf16_vector_threshold_words();
    const CHUNK_SIZE: usize = 64;

    if vector_threshold != usize::MAX && packet_u16_len >= vector_threshold {
        let mut offset = 0;
        while offset < packet_u16_len {
            let chunk_len = (packet_u16_len - offset).min(CHUNK_SIZE);
            let mut source_words = [0u16; CHUNK_SIZE];
            let mut target_words = [0u16; CHUNK_SIZE];

            for (index, (source_word, target_word)) in
                source_words.iter_mut().zip(target_words.iter_mut()).take(chunk_len).enumerate()
            {
                let byte_offset = (offset + index) * 2;
                *source_word = u16::from_be_bytes([src[byte_offset], src[byte_offset + 1]]);
                *target_word = u16::from_be_bytes([out_xor[byte_offset], out_xor[byte_offset + 1]]);
            }

            gf16_mul_slice(coeff, &source_words[..chunk_len], &mut target_words[..chunk_len]);

            for (index, value) in target_words[..chunk_len].iter().enumerate() {
                let byte_offset = (offset + index) * 2;
                let bytes = value.to_be_bytes();
                out_xor[byte_offset] = bytes[0];
                out_xor[byte_offset + 1] = bytes[1];
            }

            offset += chunk_len;
        }
    } else {
        let mut offset = 0;
        while offset + 1 < len {
            let source = u16::from_be_bytes([src[offset], src[offset + 1]]);
            let target = u16::from_be_bytes([out_xor[offset], out_xor[offset + 1]]);
            let value = crate::gf_tables::gf16_mul_add(coeff, source, target);
            let bytes = value.to_be_bytes();
            out_xor[offset] = bytes[0];
            out_xor[offset + 1] = bytes[1];
            offset += 2;
        }
    }
}

#[inline]
#[doc(hidden)]
pub fn gf16_mul_scalar_slice_padded(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let source_len = src.len().min(out_xor.len());
    let even_len = source_len & !1;
    if even_len > 0 {
        gf16_mul_scalar_slice_u16(coeff, &src[..even_len], &mut out_xor[..even_len]);
    }
    if source_len != even_len && even_len + 1 < out_xor.len() {
        let product = crate::gf_tables::gf16_mul(coeff, u16::from_be_bytes([src[even_len], 0]));
        let bytes = product.to_be_bytes();
        out_xor[even_len] ^= bytes[0];
        out_xor[even_len + 1] ^= bytes[1];
    }
}

#[inline(always)]
#[doc(hidden)]
pub fn bounded_u16_len(src: &[u16], dst: &[u16], requested: usize) -> usize {
    requested.min(src.len()).min(dst.len())
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
/// # Safety
///
/// The caller must prove AVX512F, AVX512BW, and AVX512VBMI2 support. `src` and
/// `dst` must remain valid for the duration of the call; `len` is bounded to
/// both slice lengths before any vector access.
pub unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;
    let len = bounded_u16_len(src, dst, len);

    if len == 0 {
        return;
    }

    #[repr(align(64))]
    struct Table([u16; 32]);

    let mut table0_a = Table([0u16; 32]);
    let mut table0_b = Table([0u16; 32]);
    let mut table1_b = Table([0u16; 32]);
    let mut table2_b = Table([0u16; 32]);
    let mut table3_b = Table([0u16; 32]);

    for nibble in 0..16u16 {
        let base = nibble as usize;
        let contribution0 = crate::gf_tables::gf16_mul(coeff, nibble);
        table0_a.0[base] = contribution0;
        table0_a.0[base + 16] = contribution0;
        table0_b.0[base] = contribution0;
        table0_b.0[base + 16] = contribution0;

        let contribution1 = crate::gf_tables::gf16_mul(coeff, nibble << 4);
        table1_b.0[base] = contribution1;
        table1_b.0[base + 16] = contribution1;

        let contribution2 = crate::gf_tables::gf16_mul(coeff, nibble << 8);
        table2_b.0[base] = contribution2;
        table2_b.0[base + 16] = contribution2;

        let contribution3 = crate::gf_tables::gf16_mul(coeff, nibble << 12);
        table3_b.0[base] = contribution3;
        table3_b.0[base + 16] = contribution3;
    }

    let table0_a_vec = _mm512_loadu_si512(table0_a.0.as_ptr() as *const __m512i);
    let table0_b_vec = _mm512_loadu_si512(table0_b.0.as_ptr() as *const __m512i);
    let table1_a_vec = _mm512_setzero_si512();
    let table1_b_vec = _mm512_loadu_si512(table1_b.0.as_ptr() as *const __m512i);
    let table2_a_vec = _mm512_setzero_si512();
    let table2_b_vec = _mm512_loadu_si512(table2_b.0.as_ptr() as *const __m512i);
    let table3_a_vec = _mm512_setzero_si512();
    let table3_b_vec = _mm512_loadu_si512(table3_b.0.as_ptr() as *const __m512i);

    let nibble_mask = _mm512_set1_epi16(0x000F);
    let table_offset = _mm512_set1_epi16(32);

    let mut offset = 0usize;
    while offset + 32 <= len {
        let source = _mm512_loadu_si512(src.as_ptr().add(offset) as *const __m512i);
        let target = _mm512_loadu_si512(dst.as_ptr().add(offset) as *const __m512i);

        let nibble0 = _mm512_and_si512(source, nibble_mask);
        let nibble1 = _mm512_and_si512(_mm512_srli_epi16(source, 4), nibble_mask);
        let nibble2 = _mm512_and_si512(_mm512_srli_epi16(source, 8), nibble_mask);
        let nibble3 = _mm512_srli_epi16(source, 12);

        let index1 = _mm512_add_epi16(nibble1, table_offset);
        let index2 = _mm512_add_epi16(nibble2, table_offset);
        let index3 = _mm512_add_epi16(nibble3, table_offset);

        let contribution0 = _mm512_permutex2var_epi16(table0_a_vec, nibble0, table0_b_vec);
        let contribution1 = _mm512_permutex2var_epi16(table1_a_vec, index1, table1_b_vec);
        let contribution2 = _mm512_permutex2var_epi16(table2_a_vec, index2, table2_b_vec);
        let contribution3 = _mm512_permutex2var_epi16(table3_a_vec, index3, table3_b_vec);

        let partial =
            _mm512_xor_si512(_mm512_xor_si512(contribution0, contribution1), contribution2);
        let result = _mm512_xor_si512(target, _mm512_xor_si512(partial, contribution3));

        _mm512_storeu_si512(dst.as_mut_ptr().add(offset) as *mut __m512i, result);
        offset += 32;
    }

    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }

    qf_telemetry::FEC_GF16_VBMI2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vbmi")]
/// # Safety
///
/// The caller must prove AVX512F and AVX512VBMI support. `src` and `dst` must
/// remain valid for the duration of the call; `len` is bounded to both slice
/// lengths before the loop accesses either slice.
unsafe fn gf16_mul_slice_avx512(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    for index in 0..len {
        dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
    }
    qf_telemetry::FEC_AVX512_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_avx2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    for index in 0..len {
        dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
    }
    qf_telemetry::FEC_AVX2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support. `src` and `dst` must remain valid for
/// the duration of the call; `len` is bounded to both slice lengths before
/// the loop accesses either slice.
unsafe fn gf16_mul_slice_sse2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    for index in 0..len {
        dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove AArch64 NEON support. `src` and `dst` must remain
/// valid for the duration of the call; `len` is bounded to both slice lengths
/// before vector loads, stores, or scalar tail accesses.
unsafe fn gf16_mul_slice_neon(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::aarch64::*;
    let len = bounded_u16_len(src, dst, len);
    let one = vdupq_n_u16(1);
    let polynomial = vdupq_n_u16(0x100b);
    let mut offset = 0;

    while offset + 8 <= len {
        let mut multiplicand = vld1q_u16(src.as_ptr().add(offset));
        let mut factor = vdupq_n_u16(coeff);
        let mut product = vdupq_n_u16(0);
        let target = vld1q_u16(dst.as_ptr().add(offset));

        for _ in 0..16 {
            let factor_mask = vceqq_u16(vandq_u16(factor, one), one);
            product = veorq_u16(product, vandq_u16(multiplicand, factor_mask));
            let carry_mask = vceqq_u16(vshrq_n_u16(multiplicand, 15), one);
            multiplicand =
                veorq_u16(vshlq_n_u16(multiplicand, 1), vandq_u16(polynomial, carry_mask));
            factor = vshrq_n_u16(factor, 1);
        }

        vst1q_u16(dst.as_mut_ptr().add(offset), veorq_u16(target, product));
        offset += 8;
    }

    while offset < len {
        dst[offset] ^= crate::gf_tables::gf16_mul(coeff, src[offset]);
        offset += 1;
    }
    qf_telemetry::FEC_NEON_OPS.inc();
}

#[cfg(target_arch = "aarch64")]
/// # Safety
///
/// On builds that include the SVE2 block, the caller must prove AArch64 SVE2
/// support. `src` and `dst` must remain valid for the duration of the call;
/// `len` is bounded to both slice lengths before predicated accesses. Builds
/// without SVE2 compile to the NEON fallback, which has its own contract.
unsafe fn gf16_mul_slice_sve2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let len = bounded_u16_len(src, dst, len);
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if len == 0 {
            return;
        }

        let coefficient = svdup_n_u16(coeff);
        let polynomial = svdup_n_u16(0x100B);
        let one = svdup_n_u16(1);
        let mut offset = 0usize;
        let vector_len = svcnth() as usize;

        while offset < len {
            let predicate = svwhilelt_b16(offset as u64, len as u64);
            if !svptest_any(svptrue_b16(), predicate) {
                break;
            }

            // Russian-peasant carryless multiply, matching the NEON kernel and
            // the scalar field (0x1100B with the x^16 term implicit). The old
            // svmul/svmulh integer-product form is not a carryless multiply and
            // used the wrong constant 0x000B, so any SVE2 result diverged from
            // the field.
            let mut multiplicand = svld1_u16(predicate, src.as_ptr().add(offset));
            let mut factor = coefficient;
            let mut product = svdup_n_u16(0);
            let target = svld1_u16(predicate, dst.as_ptr().add(offset));

            let mut round = 0;
            while round < 16 {
                let factor_mask = svcmpeq_u16(predicate, svand_u16_x(svptrue_b16(), factor, one), one);
                product = sveor_u16_m(predicate, product, product, svand_u16_m(predicate, factor_mask, multiplicand, svdup_n_u16(0xFFFF)));
                let carry_mask = svcmpeq_u16(predicate, svand_u16_x(svptrue_b16(), svshr_n_u16(multiplicand, 15), one), one);
                multiplicand = sveor_u16_m(
                    predicate,
                    svlsh1_n_u16_m(predicate, svdup_n_u16(0), multiplicand, 1),
                    svlsh1_n_u16_m(predicate, svdup_n_u16(0), multiplicand, 1),
                    svand_u16_m(predicate, carry_mask, polynomial, svdup_n_u16(0xFFFF)),
                );
                factor = svshr_n_u16_x(svptrue_b16(), factor, 1);
                round += 1;
            }

            let result = sveor_u16_m(predicate, target, target, product);

            svst1_u16(predicate, dst.as_mut_ptr().add(offset), result);
            offset += vector_len;
        }

        qf_telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf16_mul_slice_neon(coeff, src, dst, len);
}

/// GF(2^16) multiply-accumulate over u16 slices: `dst[i] ^= coeff * src[i]`.
#[inline(always)]
#[doc(hidden)]
pub fn gf16_mul_slice(coeff: u16, src: &[u16], dst: &mut [u16]) {
    let len = src.len().min(dst.len());
    let src = &src[..len];
    let dst = &mut dst[..len];
    qf_cpu::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<qf_cpu::Avx512Vbmi2>() && len >= GF16_VBMI2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_vbmi2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Avx512>() && len >= GF16_AVX512_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx512(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Avx2>() && len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Sse2>() && len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sse2(coeff, src, dst, len);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<qf_cpu::Sve2>() && len >= GF16_SVE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sve2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<qf_cpu::Neon>() && len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_neon(coeff, src, dst, len);
                }
            }
        }

        let mut index = 0;
        while index + 8 <= len {
            dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
            dst[index + 1] ^= crate::gf_tables::gf16_mul(coeff, src[index + 1]);
            dst[index + 2] ^= crate::gf_tables::gf16_mul(coeff, src[index + 2]);
            dst[index + 3] ^= crate::gf_tables::gf16_mul(coeff, src[index + 3]);
            dst[index + 4] ^= crate::gf_tables::gf16_mul(coeff, src[index + 4]);
            dst[index + 5] ^= crate::gf_tables::gf16_mul(coeff, src[index + 5]);
            dst[index + 6] ^= crate::gf_tables::gf16_mul(coeff, src[index + 6]);
            dst[index + 7] ^= crate::gf_tables::gf16_mul(coeff, src[index + 7]);
            index += 8;
        }
        while index < len {
            dst[index] ^= crate::gf_tables::gf16_mul(coeff, src[index]);
            index += 1;
        }
    });
}
