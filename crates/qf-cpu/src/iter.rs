#[cfg(target_arch = "riscv64")]
use super::CpuProfile;
use super::FeatureDetector;
use qf_telemetry as telemetry;

#[inline(always)]
pub fn sum_f32(data: &[f32]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();
    #[cfg(target_arch = "riscv64")]
    let profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f {
            telemetry::ITER_SUM_F32_AVX512_OPS.inc();
            // SAFETY: the exact AVX-512 Foundation runtime feature is proven above.
            return unsafe { sum_f32_avx512(data) };
        }
        if matrix.avx2 {
            telemetry::ITER_SUM_F32_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { sum_f32_avx2(data) };
        }
        if features.sse2 {
            telemetry::ITER_SUM_F32_SSE_OPS.inc();
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            return unsafe { sum_f32_sse(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            telemetry::ITER_SUM_F32_SVE_OPS.inc();
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { sum_f32_sve2(data) };
        }
        if features.neon {
            telemetry::ITER_SUM_F32_NEON_OPS.inc();
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { sum_f32_neon(data) };
        }
    }

    #[cfg(target_arch = "riscv64")]
    {
        match profile {
            CpuProfile::RVV => {
                telemetry::SIMD_USAGE_RVV.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                telemetry::ITER_SUM_F32_RVV_OPS.inc();
                return sum_f32_rvv(data);
            }
            _ => {}
        }
    }

    telemetry::ITER_SUM_F32_SCALAR_OPS.inc();
    scalar_sum_f32(data)
}

#[inline(always)]
pub fn sum_u32(data: &[u32]) -> u64 {
    if data.is_empty() {
        return 0;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();
    #[cfg(target_arch = "riscv64")]
    let profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f {
            telemetry::ITER_SUM_U32_AVX512_OPS.inc();
            // SAFETY: the exact AVX-512 Foundation runtime feature is proven above.
            return unsafe { sum_u32_avx512(data) };
        }
        if matrix.avx2 {
            telemetry::ITER_SUM_U32_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { sum_u32_avx2(data) };
        }
        if features.sse2 {
            telemetry::ITER_SUM_U32_SSE_OPS.inc();
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            return unsafe { sum_u32_sse(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            telemetry::ITER_SUM_U32_SVE_OPS.inc();
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { sum_u32_sve2(data) };
        }
        if features.neon {
            telemetry::ITER_SUM_U32_NEON_OPS.inc();
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { sum_u32_neon(data) };
        }
    }

    #[cfg(target_arch = "riscv64")]
    {
        match profile {
            CpuProfile::RVV => {
                telemetry::SIMD_USAGE_RVV.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                telemetry::ITER_SUM_U32_RVV_OPS.inc();
                return sum_u32_rvv(data);
            }
            _ => {}
        }
    }

    telemetry::ITER_SUM_U32_SCALAR_OPS.inc();
    scalar_sum_u32(data)
}

#[inline(always)]
pub fn sum_u64(data: &[u64]) -> u128 {
    if data.is_empty() {
        return 0;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();
    #[cfg(target_arch = "riscv64")]
    let profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f {
            telemetry::ITER_SUM_U64_AVX512_OPS.inc();
            // SAFETY: the exact AVX-512 Foundation runtime feature is proven above.
            return unsafe { sum_u64_avx512(data) };
        }
        if matrix.avx2 {
            telemetry::ITER_SUM_U64_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { sum_u64_avx2(data) };
        }
        if features.sse2 {
            telemetry::ITER_SUM_U64_SSE_OPS.inc();
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            return unsafe { sum_u64_sse(data) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            telemetry::ITER_SUM_U64_SVE_OPS.inc();
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { sum_u64_sve2(data) };
        }
        if features.neon {
            telemetry::ITER_SUM_U64_NEON_OPS.inc();
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { sum_u64_neon(data) };
        }
    }

    #[cfg(target_arch = "riscv64")]
    {
        match profile {
            CpuProfile::RVV => {
                telemetry::SIMD_USAGE_RVV.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                telemetry::ITER_SUM_U64_RVV_OPS.inc();
                return sum_u64_rvv(data);
            }
            _ => {}
        }
    }

    telemetry::ITER_SUM_U64_SCALAR_OPS.inc();
    scalar_sum_u64(data)
}

#[inline(always)]
fn scalar_sum_f32(data: &[f32]) -> f32 {
    data.iter().copied().sum()
}

#[inline(always)]
fn scalar_sum_u32(data: &[u32]) -> u64 {
    data.iter().fold(0u64, |acc, &v| acc + v as u64)
}

#[inline(always)]
fn scalar_sum_u64(data: &[u64]) -> u128 {
    data.iter().fold(0u128, |acc, &v| acc + v as u128)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn sum_f32_avx512(data: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let mut acc = _mm512_setzero_ps();
    let mut i = 0usize;
    while i + 16 <= data.len() {
        let v = _mm512_loadu_ps(data.as_ptr().add(i));
        acc = _mm512_add_ps(acc, v);
        i += 16;
    }
    let mut sum = _mm512_reduce_add_ps(acc);
    while i < data.len() {
        sum += *data.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_f32_avx2(data: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let mut acc = _mm256_setzero_ps();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let v = _mm256_loadu_ps(data.as_ptr().add(i));
        acc = _mm256_add_ps(acc, v);
        i += 8;
    }
    let mut tmp = [0f32; 8];
    _mm256_storeu_ps(tmp.as_mut_ptr(), acc);
    let mut sum = tmp.iter().copied().sum::<f32>();
    while i < data.len() {
        sum += *data.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn sum_f32_neon(data: &[f32]) -> f32 {
    use std::arch::aarch64::*;

    let mut acc = vdupq_n_f32(0.0);
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let v = vld1q_f32(data.as_ptr().add(i));
        acc = vaddq_f32(acc, v);
        i += 4;
    }
    let pair = vpadd_f32(vget_low_f32(acc), vget_high_f32(acc));
    let pair = vpadd_f32(pair, pair);
    let mut sum = vget_lane_f32::<0>(pair);
    while i < data.len() {
        sum += *data.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sum_f32_sse(data: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let mut acc = _mm_setzero_ps();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let v = _mm_loadu_ps(data.as_ptr().add(i));
        acc = _mm_add_ps(acc, v);
        i += 4;
    }
    let mut tmp = [0f32; 4];
    _mm_storeu_ps(tmp.as_mut_ptr(), acc);
    let mut sum = tmp.iter().copied().sum::<f32>();
    while i < data.len() {
        sum += *data.get_unchecked(i);
        i += 1;
    }
    sum
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn sum_f32_sve2_impl(data: &[f32]) -> f32 {
    use std::arch::aarch64::*;

    let lanes = svcntw() as usize;
    let mut acc = svdup_f32(0.0);
    let mut offset = 0usize;
    while offset < data.len() {
        let pg = svwhilelt_b32(offset as u64, data.len() as u64);
        let chunk = svld1_f32(pg, data.as_ptr().add(offset));
        acc = svadd_f32_m(pg, acc, acc, chunk);
        offset += lanes;
    }
    svaddv_f32(svptrue_b32(), acc)
}

#[cfg(target_arch = "aarch64")]
unsafe fn sum_f32_sve2(data: &[f32]) -> f32 {
    #[cfg(target_feature = "sve2")]
    {
        sum_f32_sve2_impl(data)
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        sum_f32_neon(data)
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn sum_f32_rvv(data: &[f32]) -> f32 {
    scalar_sum_f32(data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn sum_u32_avx512(data: &[u32]) -> u64 {
    use std::arch::x86_64::*;

    let mut acc = _mm512_setzero_si512();
    let mut i = 0usize;
    while i + 16 <= data.len() {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
        let lo = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(chunk));
        let hi256 = _mm512_extracti32x8_epi32(chunk, 1);
        let hi = _mm512_cvtepu32_epi64(hi256);
        acc = _mm512_add_epi64(acc, lo);
        acc = _mm512_add_epi64(acc, hi);
        i += 16;
    }
    let mut tmp = [0u64; 8];
    _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, acc);
    let mut sum = tmp.iter().copied().sum::<u64>();
    while i < data.len() {
        sum += *data.get_unchecked(i) as u64;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_u32_avx2(data: &[u32]) -> u64 {
    use std::arch::x86_64::*;

    let mut acc = _mm256_setzero_si256();
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let lo128 = _mm256_castsi256_si128(chunk);
        let hi128 = _mm256_extracti128_si256::<1>(chunk);
        let lo64 = _mm256_cvtepu32_epi64(lo128);
        let hi64 = _mm256_cvtepu32_epi64(hi128);
        acc = _mm256_add_epi64(acc, lo64);
        acc = _mm256_add_epi64(acc, hi64);
        i += 8;
    }
    let mut tmp = [0u64; 4];
    _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, acc);
    let mut sum = tmp.iter().copied().sum::<u64>();
    while i < data.len() {
        sum += *data.get_unchecked(i) as u64;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn sum_u32_neon(data: &[u32]) -> u64 {
    use std::arch::aarch64::*;

    let mut acc = vdupq_n_u64(0);
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let chunk = vld1q_u32(data.as_ptr().add(i));
        let widened = vpaddlq_u32(chunk);
        acc = vaddq_u64(acc, widened);
        i += 4;
    }
    let mut tmp = [0u64; 2];
    vst1q_u64(tmp.as_mut_ptr(), acc);
    let mut sum = tmp[0] + tmp[1];
    while i < data.len() {
        sum += *data.get_unchecked(i) as u64;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sum_u32_sse(data: &[u32]) -> u64 {
    use std::arch::x86_64::*;

    let zeros = _mm_setzero_si128();
    let mut acc_lo = _mm_setzero_si128();
    let mut acc_hi = _mm_setzero_si128();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(i) as *const __m128i);
        let lo = _mm_unpacklo_epi32(chunk, zeros);
        let hi = _mm_unpackhi_epi32(chunk, zeros);
        acc_lo = _mm_add_epi64(acc_lo, lo);
        acc_hi = _mm_add_epi64(acc_hi, hi);
        i += 4;
    }
    let acc = _mm_add_epi64(acc_lo, acc_hi);
    let mut tmp = [0u64; 2];
    _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, acc);
    let mut sum = tmp[0] + tmp[1];
    while i < data.len() {
        sum += *data.get_unchecked(i) as u64;
        i += 1;
    }
    sum
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn sum_u32_sve2_impl(data: &[u32]) -> u64 {
    use std::arch::aarch64::*;

    let mut sum: u64 = 0;
    let lanes = svcntw() as usize;
    let mut offset = 0usize;
    while offset < data.len() {
        let pg = svwhilelt_b32(offset as u64, data.len() as u64);
        let chunk = svld1_u32(pg, data.as_ptr().add(offset));
        sum += svaddv_u32(pg, chunk) as u64;
        offset += lanes;
    }
    sum
}

#[cfg(target_arch = "aarch64")]
unsafe fn sum_u32_sve2(data: &[u32]) -> u64 {
    #[cfg(target_feature = "sve2")]
    {
        sum_u32_sve2_impl(data)
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        sum_u32_neon(data)
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn sum_u32_rvv(data: &[u32]) -> u64 {
    scalar_sum_u32(data)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn sum_u64_avx512(data: &[u64]) -> u128 {
    use std::arch::x86_64::*;

    let mut sum = 0u128;
    let mut i = 0usize;
    while i + 8 <= data.len() {
        let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
        let mut tmp = [0u64; 8];
        _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
        sum += tmp[0] as u128
            + tmp[1] as u128
            + tmp[2] as u128
            + tmp[3] as u128
            + tmp[4] as u128
            + tmp[5] as u128
            + tmp[6] as u128
            + tmp[7] as u128;
        i += 8;
    }
    while i < data.len() {
        sum += *data.get_unchecked(i) as u128;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn sum_u64_avx2(data: &[u64]) -> u128 {
    use std::arch::x86_64::*;

    let mut sum = 0u128;
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        let mut tmp = [0u64; 4];
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, chunk);
        sum += tmp[0] as u128 + tmp[1] as u128 + tmp[2] as u128 + tmp[3] as u128;
        i += 4;
    }
    while i < data.len() {
        sum += *data.get_unchecked(i) as u128;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn sum_u64_neon(data: &[u64]) -> u128 {
    use std::arch::aarch64::*;

    let mut sum = 0u128;
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let chunk = vld1q_u64(data.as_ptr().add(i));
        let mut tmp = [0u64; 2];
        vst1q_u64(tmp.as_mut_ptr(), chunk);
        sum += (tmp[0] as u128) + (tmp[1] as u128);
        i += 2;
    }
    while i < data.len() {
        sum += *data.get_unchecked(i) as u128;
        i += 1;
    }
    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn sum_u64_sse(data: &[u64]) -> u128 {
    use std::arch::x86_64::*;

    let mut sum = 0u128;
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let chunk = _mm_loadu_si128(data.as_ptr().add(i) as *const __m128i);
        let mut tmp = [0u64; 2];
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, chunk);
        sum += (tmp[0] as u128) + (tmp[1] as u128);
        i += 2;
    }
    while i < data.len() {
        sum += *data.get_unchecked(i) as u128;
        i += 1;
    }
    sum
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn sum_u64_sve2_impl(data: &[u64]) -> u128 {
    use std::arch::aarch64::*;

    let lanes = svcntd() as usize;
    let mut buf = vec![0u64; lanes];
    let mut sum: u128 = 0;
    let mut offset = 0usize;
    while offset < data.len() {
        let pg = svwhilelt_b64(offset as u64, data.len() as u64);
        let chunk = svld1_u64(pg, data.as_ptr().add(offset));
        svst1_u64(pg, buf.as_mut_ptr(), chunk);
        let active = svcntp_b64(pg, pg) as usize;
        for idx in 0..active {
            sum += buf[idx] as u128;
        }
        offset += lanes;
    }
    sum
}

#[cfg(target_arch = "aarch64")]
unsafe fn sum_u64_sve2(data: &[u64]) -> u128 {
    #[cfg(target_feature = "sve2")]
    {
        sum_u64_sve2_impl(data)
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        sum_u64_neon(data)
    }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn sum_u64_rvv(data: &[u64]) -> u128 {
    scalar_sum_u64(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- sum_f32 ----

    #[test]
    fn test_sum_f32_empty() {
        assert_eq!(sum_f32(&[]), 0.0);
    }

    #[test]
    fn test_sum_f32_single() {
        assert!((sum_f32(&[42.5]) - 42.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_sum_f32_power_of_two_length() {
        // 16 elements - aligns with AVX512/NEON chunk boundaries
        let data: Vec<f32> = (1..=16).map(|i| i as f32).collect();
        let result = sum_f32(&data);
        let expected: f32 = (1..=16).map(|i| i as f32).sum();
        assert!((result - expected).abs() < 0.01, "got {result}, expected {expected}");
    }

    #[test]
    fn test_sum_f32_non_aligned_length() {
        // 19 elements - not a multiple of any SIMD lane width
        let data: Vec<f32> = (1..=19).map(|i| i as f32).collect();
        let result = sum_f32(&data);
        let expected: f32 = (1..=19).map(|i| i as f32).sum();
        assert!((result - expected).abs() < 0.01, "got {result}, expected {expected}");
    }

    #[test]
    fn test_sum_f32_negative_values() {
        let data = [-1.0f32, -2.0, -3.0, 4.0, 5.0];
        let result = sum_f32(&data);
        assert!((result - 3.0).abs() < f32::EPSILON);
    }

    // ---- sum_u32 ----

    #[test]
    fn test_sum_u32_empty() {
        assert_eq!(sum_u32(&[]), 0);
    }

    #[test]
    fn test_sum_u32_single() {
        assert_eq!(sum_u32(&[999]), 999);
    }

    #[test]
    fn test_sum_u32_large_values_no_overflow() {
        // u32::MAX * 4 would overflow u32 but fits in u64
        let data = [u32::MAX; 4];
        let result = sum_u32(&data);
        assert_eq!(result, u32::MAX as u64 * 4);
    }

    #[test]
    fn test_sum_u32_power_of_two_length() {
        let data: Vec<u32> = (1..=16).collect();
        assert_eq!(sum_u32(&data), (1u64 + 16) * 16 / 2);
    }

    #[test]
    fn test_sum_u32_non_aligned_length() {
        let data: Vec<u32> = (1..=17).collect();
        assert_eq!(sum_u32(&data), (1u64 + 17) * 17 / 2);
    }

    // ---- sum_u64 ----

    #[test]
    fn test_sum_u64_empty() {
        assert_eq!(sum_u64(&[]), 0);
    }

    #[test]
    fn test_sum_u64_single() {
        assert_eq!(sum_u64(&[u64::MAX]), u64::MAX as u128);
    }

    #[test]
    fn test_sum_u64_large_values_no_overflow() {
        // u64::MAX * 3 overflows u64 but fits in u128
        let data = [u64::MAX; 3];
        let result = sum_u64(&data);
        assert_eq!(result, u64::MAX as u128 * 3);
    }

    #[test]
    fn test_sum_u64_non_aligned_length() {
        let data: Vec<u64> = (1..=7).collect();
        let result = sum_u64(&data);
        assert_eq!(result, (1u128 + 7) * 7 / 2);
    }

    // ---- scalar fallbacks ----

    #[test]
    fn test_scalar_sum_f32_matches_iter() {
        let data: Vec<f32> = (0..100).map(|i| i as f32 * 0.1).collect();
        let result = scalar_sum_f32(&data);
        let expected: f32 = data.iter().copied().sum();
        assert!((result - expected).abs() < f32::EPSILON);
    }

    #[test]
    fn test_scalar_sum_u32_matches_fold() {
        let data: Vec<u32> = (0..100).collect();
        let result = scalar_sum_u32(&data);
        let expected = data.iter().fold(0u64, |acc, &v| acc + v as u64);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_scalar_sum_u64_matches_fold() {
        let data: Vec<u64> = (0..50).map(|i| i * 1_000_000).collect();
        let result = scalar_sum_u64(&data);
        let expected = data.iter().fold(0u128, |acc, &v| acc + v as u128);
        assert_eq!(result, expected);
    }
}
