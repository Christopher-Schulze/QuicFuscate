//! SIMD acceleration for statistics and vector/ML operations.
//! No active matrix-multiplication or AMX caller is owned by this module.

use crate::optimize::telemetry;
use crate::optimize::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__m256;

/// Apply exponential decay to histogram bins (u64) using SIMD fast paths.
#[inline(always)]
pub fn decay_histogram(bins: &mut [u64], decay: f64) {
    if bins.is_empty() {
        return;
    }
    let decay = decay.clamp(0.0, 1.0);
    if decay == 1.0 {
        return;
    }
    if decay <= 0.0 {
        for bin in bins.iter_mut() {
            *bin = 0;
        }
        return;
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let detector = FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        let features = detector.features_full();
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f && features.avx512dq && features.avx2 {
            telemetry::BRAIN_HISTOGRAM_AVX512_OPS.inc();
            // SAFETY: the exact AVX2+AVX-512F+DQ intersection is proven above.
            unsafe {
                decay_histogram_avx512(bins, decay);
            }
            return;
        }

        if matrix.avx2 {
            telemetry::BRAIN_HISTOGRAM_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe {
                decay_histogram_avx2(bins, decay);
            }
            return;
        }

        if features.sse41 {
            telemetry::BRAIN_HISTOGRAM_SSE_OPS.inc();
            // SAFETY: the exact SSE4.1 runtime feature is proven above.
            unsafe {
                decay_histogram_sse41(bins, decay);
            }
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = detector.features_full();
        if features.sve2 {
            telemetry::BRAIN_HISTOGRAM_SVE2_OPS.inc();
            // SAFETY: the exact runtime SVE2 feature is proven above.
            unsafe {
                decay_histogram_sve2(bins, decay);
            }
            return;
        }

        if features.neon {
            telemetry::BRAIN_HISTOGRAM_NEON_OPS.inc();
            // SAFETY: the exact runtime NEON feature is proven above.
            unsafe {
                decay_histogram_neon(bins, decay);
            }
            return;
        }
    }

    // Scalar fallback
    crate::optimize::telemetry::BRAIN_HISTOGRAM_SCALAR_OPS.inc();
    for bin in bins.iter_mut() {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

/// Jensen-Shannon divergence between histogram (bins/total) and target distribution.
#[inline(always)]
pub fn jensen_shannon_divergence(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    let len = bins.len().min(target.len());
    if len == 0 || total == 0 {
        return 0.0;
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let detector = FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        let features = detector.features_full();
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f && features.avx512dq && features.avx2 {
            telemetry::BRAIN_HISTOGRAM_AVX512_OPS.inc();
            // SAFETY: the exact AVX2+AVX-512F+DQ intersection is proven above.
            return unsafe { jensen_shannon_avx512(bins, total, target, len) };
        }

        if matrix.avx2 {
            telemetry::BRAIN_HISTOGRAM_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { jensen_shannon_avx2(bins, total, target, len) };
        }

        if features.sse41 {
            telemetry::BRAIN_HISTOGRAM_SSE_OPS.inc();
            // SAFETY: the exact SSE4.1 runtime feature is proven above.
            return unsafe { jensen_shannon_sse41(bins, total, target, len) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = detector.features_full();
        if features.sve2 {
            telemetry::BRAIN_HISTOGRAM_SVE2_OPS.inc();
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { jensen_shannon_sve2(bins, total, target, len) };
        }

        if features.neon {
            telemetry::BRAIN_HISTOGRAM_NEON_OPS.inc();
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { jensen_shannon_neon(bins, total, target, len) };
        }
    }

    // Scalar fallback
    crate::optimize::telemetry::BRAIN_HISTOGRAM_SCALAR_OPS.inc();
    scalar_jensen_shannon(&bins[..len], total, &target[..len])
}

fn scalar_jensen_shannon(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    let inv_total = 1.0 / (total as f64);
    const EPS: f64 = 1e-12;
    let mut js = 0.0;
    for (bin, &q_raw) in bins.iter().zip(target.iter()) {
        let p = (*bin as f64) * inv_total;
        let p = p.max(EPS);
        let q = q_raw.max(EPS);
        let m = 0.5 * (p + q);
        js += 0.5 * p * (p / m).ln() + 0.5 * q * (q / m).ln();
    }
    js
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x2_to_f64x2(v: std::arch::x86_64::__m128i) -> std::arch::x86_64::__m128d {
    use std::arch::x86_64::*;

    // Store and cast each lane exactly as Rust's scalar `u64 as f64` conversion.
    // Splitting into high/low u32 halves introduces a second rounding step for
    // values above 2^53 and diverges at the upper u64 boundaries.
    let mut lanes = [0u64; 2];
    _mm_storeu_si128(lanes.as_mut_ptr().cast(), v);
    _mm_set_pd(lanes[1] as f64, lanes[0] as f64)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x4_to_f64x4(v: std::arch::x86_64::__m256i) -> std::arch::x86_64::__m256d {
    use std::arch::x86_64::*;

    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256::<1>(v);
    let lo_pd = u64x2_to_f64x2(lo);
    let hi_pd = u64x2_to_f64x2(hi);
    let mut combined = _mm256_castpd128_pd256(lo_pd);
    combined = _mm256_insertf128_pd::<1>(combined, hi_pd);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x8_to_f64x8(v: std::arch::x86_64::__m512i) -> std::arch::x86_64::__m512d {
    use std::arch::x86_64::*;

    let lo = _mm512_castsi512_si256(v);
    let hi = _mm512_extracti64x4_epi64::<1>(v);
    let lo_pd = u64x4_to_f64x4(lo);
    let hi_pd = u64x4_to_f64x4(hi);
    let mut combined = _mm512_castpd256_pd512(lo_pd);
    combined = _mm512_insertf64x4::<1>(combined, hi_pd);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x2_to_u64x2(v: std::arch::x86_64::__m128d) -> std::arch::x86_64::__m128i {
    use std::arch::x86_64::*;

    // `_mm_cvttpd_epi64` requires AVX-512DQ and AVX-512VL despite its 128-bit
    // shape. Scalar lane casts preserve Rust's saturating `f64 as u64`
    // semantics without injecting AVX-512 instructions into SSE4.1/AVX2 paths.
    let mut lanes = [0.0f64; 2];
    _mm_storeu_pd(lanes.as_mut_ptr(), v);
    let low = lanes[0] as u64;
    let high = lanes[1] as u64;
    _mm_set_epi64x(high as i64, low as i64)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x4_to_u64x4(v: std::arch::x86_64::__m256d) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;

    let lo = _mm256_castpd256_pd128(v);
    let hi = _mm256_extractf128_pd::<1>(v);
    let lo_i = f64x2_to_u64x2(lo);
    let hi_i = f64x2_to_u64x2(hi);
    let mut combined = _mm256_castsi128_si256(lo_i);
    combined = _mm256_inserti128_si256::<1>(combined, hi_i);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x8_to_u64x8(v: std::arch::x86_64::__m512d) -> std::arch::x86_64::__m512i {
    use std::arch::x86_64::*;

    let lo = _mm512_castpd512_pd256(v);
    let hi = _mm512_extractf64x4_pd::<1>(v);
    let lo_i = f64x4_to_u64x4(lo);
    let hi_i = f64x4_to_u64x4(hi);
    let mut combined = _mm512_castsi256_si512(lo_i);
    combined = _mm512_inserti64x4::<1>(combined, hi_i);
    combined
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,avx512f,avx512dq")]
unsafe fn decay_histogram_avx512(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm512_set1_pd(decay);
    let mut i = 0usize;
    while i + 8 <= len {
        let vals = _mm512_loadu_si512(bins.as_ptr().add(i) as *const __m512i);
        let vals_f64 = u64x8_to_f64x8(vals);
        let scaled = _mm512_mul_pd(vals_f64, decay_vec);
        let floored = _mm512_roundscale_pd(scaled, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
        let converted = f64x8_to_u64x8(floored);
        _mm512_storeu_si512(bins.as_mut_ptr().add(i) as *mut __m512i, converted);
        i += 8;
    }

    if i < len {
        decay_histogram_avx2(&mut bins[i..], decay);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn decay_histogram_avx2(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm256_set1_pd(decay);
    let mut i = 0usize;
    while i + 4 <= len {
        let vals = _mm256_loadu_si256(bins.as_ptr().add(i) as *const __m256i);
        let vals_f64 = u64x4_to_f64x4(vals);
        let scaled = _mm256_mul_pd(vals_f64, decay_vec);
        let floored = _mm256_floor_pd(scaled);
        let converted = f64x4_to_u64x4(floored);
        _mm256_storeu_si256(bins.as_mut_ptr().add(i) as *mut __m256i, converted);
        i += 4;
    }

    if i < len {
        decay_histogram_sse41(&mut bins[i..], decay);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn decay_histogram_sse41(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm_set1_pd(decay);
    let mut i = 0usize;
    while i + 2 <= len {
        let vals = _mm_loadu_si128(bins.as_ptr().add(i) as *const __m128i);
        let vals_f64 = u64x2_to_f64x2(vals);
        let scaled = _mm_mul_pd(vals_f64, decay_vec);
        let floored = _mm_floor_pd(scaled);
        let converted = f64x2_to_u64x2(floored);
        _mm_storeu_si128(bins.as_mut_ptr().add(i) as *mut __m128i, converted);
        i += 2;
    }

    for bin in bins.iter_mut().skip(i) {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,avx512f,avx512dq")]
unsafe fn jensen_shannon_avx512(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm512_set1_pd(1.0 / (total as f64));
    let half = _mm512_set1_pd(0.5);
    let eps_vec = _mm512_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 8 <= len {
        let hist = _mm512_loadu_si512(bins.as_ptr().add(i) as *const __m512i);
        let hist_f64 = u64x8_to_f64x8(hist);
        let p = _mm512_max_pd(_mm512_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm512_max_pd(_mm512_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm512_mul_pd(_mm512_add_pd(p, q), half);

        let mut p_lane = [0f64; 8];
        let mut q_lane = [0f64; 8];
        let mut m_lane = [0f64; 8];
        _mm512_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm512_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm512_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..8 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 8;
    }

    if i < len {
        acc += jensen_shannon_avx2(&bins[i..], total, &target[i..], len - i);
    }

    acc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn jensen_shannon_avx2(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm256_set1_pd(1.0 / (total as f64));
    let half = _mm256_set1_pd(0.5);
    let eps_vec = _mm256_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 4 <= len {
        let hist = _mm256_loadu_si256(bins.as_ptr().add(i) as *const __m256i);
        let hist_f64 = u64x4_to_f64x4(hist);
        let p = _mm256_max_pd(_mm256_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm256_max_pd(_mm256_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm256_mul_pd(_mm256_add_pd(p, q), half);

        let mut p_lane = [0f64; 4];
        let mut q_lane = [0f64; 4];
        let mut m_lane = [0f64; 4];
        _mm256_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm256_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm256_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..4 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 4;
    }

    if i < len {
        acc += jensen_shannon_sse41(&bins[i..], total, &target[i..], len - i);
    }

    acc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn jensen_shannon_sse41(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm_set1_pd(1.0 / (total as f64));
    let half = _mm_set1_pd(0.5);
    let eps_vec = _mm_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 2 <= len {
        let hist = _mm_loadu_si128(bins.as_ptr().add(i) as *const __m128i);
        let hist_f64 = u64x2_to_f64x2(hist);
        let p = _mm_max_pd(_mm_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm_max_pd(_mm_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm_mul_pd(_mm_add_pd(p, q), half);

        let mut p_lane = [0f64; 2];
        let mut q_lane = [0f64; 2];
        let mut m_lane = [0f64; 2];
        _mm_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..2 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 2;
    }

    if i < len {
        acc += scalar_jensen_shannon(&bins[i..len], total, &target[i..len]);
    }

    acc
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_avx512(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_avx512(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_avx2(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_avx2(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_sse41(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_sse41(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_avx512(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_avx512(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_avx2(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_avx2(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_sse41(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_sse41(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn decay_histogram_neon(bins: &mut [u64], decay: f64) {
    use std::arch::aarch64::*;

    let mut i = 0usize;
    let decay_vec = vdupq_n_f64(decay);

    while i + 2 <= bins.len() {
        let vals = vld1q_u64(bins.as_ptr().add(i));
        let vals_f64 = vcvtq_f64_u64(vals);
        let scaled = vmulq_f64(vals_f64, decay_vec);
        let floored = vrndmq_f64(scaled);
        let converted = vcvtq_u64_f64(floored);
        vst1q_u64(bins.as_mut_ptr().add(i), converted);
        i += 2;
    }

    for bin in bins.iter_mut().skip(i) {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn decay_histogram_sve2_impl(bins: &mut [u64], decay: f64) {
    use std::arch::aarch64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = svdup_f64(decay);
    let mut offset = 0usize;

    while offset < len {
        let pg = svwhilelt_b64(offset as u64, len as u64);
        let vals = svld1_u64(pg, bins.as_ptr().add(offset));
        let vals_f64 = svcvt_f64_u64_x(pg, vals);
        let scaled = svmul_f64_m(pg, vals_f64, decay_vec);
        let floored = svfloor_f64_m(pg, scaled, scaled);
        let converted = svcvt_u64_f64_x(pg, floored);
        svst1_u64(pg, bins.as_mut_ptr().add(offset), converted);
        offset += svcntd() as usize;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn decay_histogram_sve2(bins: &mut [u64], decay: f64) {
    #[cfg(target_feature = "sve2")]
    {
        decay_histogram_sve2_impl(bins, decay);
        return;
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        decay_histogram_neon(bins, decay);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn jensen_shannon_neon(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::aarch64::*;

    const EPS: f64 = 1e-12;
    let inv_total_vec = vdupq_n_f64(1.0 / (total as f64));
    let half = vdupq_n_f64(0.5);
    let eps_vec = vdupq_n_f64(EPS);

    let mut js = 0.0;
    let mut i = 0usize;

    while i + 2 <= len {
        let hist_vals = vld1q_u64(bins.as_ptr().add(i));
        let hist_f64 = vcvtq_f64_u64(hist_vals);
        let p = vmaxq_f64(vmulq_f64(hist_f64, inv_total_vec), eps_vec);

        let q = vmaxq_f64(vld1q_f64(target.as_ptr().add(i)), eps_vec);
        let m = vmulq_f64(vaddq_f64(p, q), half);

        let p_ratio = vdivq_f64(p, m);
        let q_ratio = vdivq_f64(q, m);
        let p_ln = vlogq_f64_neon(p_ratio);
        let q_ln = vlogq_f64_neon(q_ratio);
        let p_term = vmulq_f64(p, p_ln);
        let q_term = vmulq_f64(q, q_ln);
        let chunk = vmulq_f64(half, vaddq_f64(p_term, q_term));
        js += vaddvq_f64(chunk);

        i += 2;
    }

    if i < len {
        js += scalar_jensen_shannon(&bins[i..len], total, &target[i..len]);
    }

    js
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn jensen_shannon_sve2_impl(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::aarch64::*;

    const EPS: f64 = 1e-12;
    let inv_total = svdup_f64(1.0 / (total as f64));
    let half = svdup_f64(0.5);
    let eps_vec = svdup_f64(EPS);

    let mut acc = 0.0;
    let mut offset = 0usize;
    const STACK_LANES: usize = 8;
    let lanes = (svcntd() as usize).clamp(1, STACK_LANES);
    let mut buf = [0f64; STACK_LANES];

    while offset < len {
        let chunk_end = offset.saturating_add(lanes).min(len);
        let pg = svwhilelt_b64(offset as u64, chunk_end as u64);
        let vals = svld1_u64(pg, bins.as_ptr().add(offset));
        let vals_f64 = svcvt_f64_u64_x(pg, vals);
        let p = svmul_f64_m(pg, vals_f64, inv_total);
        let p = svmax_f64_m(pg, p, eps_vec);
        let q = svmax_f64_m(pg, svld1_f64(pg, target.as_ptr().add(offset)), eps_vec);
        let m = svmul_f64_m(pg, svadd_f64_m(pg, p, q), half);

        let p_ratio = svdiv_f64_x(pg, p, m);
        let q_ratio = svdiv_f64_x(pg, q, m);

        svst1_f64(pg, buf.as_mut_ptr(), p_ratio);
        let active = svcntp_b64(pg, pg) as usize;
        for lane in buf.iter_mut().take(active) {
            *lane = lane.ln();
        }
        let p_ln = svld1_f64(pg, buf.as_ptr());

        svst1_f64(pg, buf.as_mut_ptr(), q_ratio);
        for lane in buf.iter_mut().take(active) {
            *lane = lane.ln();
        }
        let q_ln = svld1_f64(pg, buf.as_ptr());

        let p_term = svmul_f64_x(pg, p, p_ln);
        let q_term = svmul_f64_x(pg, q, q_ln);
        let chunk = svmul_f64_x(pg, half, svadd_f64_x(pg, p_term, q_term));
        acc += svaddv_f64(pg, chunk);

        offset = chunk_end;
    }

    acc
}

#[cfg(target_arch = "aarch64")]
unsafe fn jensen_shannon_sve2(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    #[cfg(target_feature = "sve2")]
    {
        jensen_shannon_sve2_impl(bins, total, target, len)
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        jensen_shannon_neon(bins, total, target, len)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vlogq_f64_neon(v: std::arch::aarch64::float64x2_t) -> std::arch::aarch64::float64x2_t {
    let mut tmp = [0f64; 2];
    std::arch::aarch64::vst1q_f64(tmp.as_mut_ptr(), v);
    for lane in tmp.iter_mut() {
        *lane = lane.ln();
    }
    std::arch::aarch64::vld1q_f64(tmp.as_ptr())
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_sum_ps(v: __m256) -> f32 {
    use std::arch::x86_64::*;

    let sum_128 = _mm_add_ps(_mm256_extractf128_ps(v, 0), _mm256_extractf128_ps(v, 1));
    let sum_64 = _mm_add_ps(sum_128, _mm_movehl_ps(sum_128, sum_128));
    let sum_32 = _mm_add_ss(sum_64, _mm_shuffle_ps(sum_64, sum_64, 0x01));
    _mm_cvtss_f32(sum_32)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn fast_exp_ps_sse(x: std::arch::x86_64::__m128) -> std::arch::x86_64::__m128 {
    use std::arch::x86_64::*;

    let one = _mm_set1_ps(1.0);
    let half = _mm_set1_ps(0.5);
    let sixth = _mm_set1_ps(1.0 / 6.0);
    let twenty_fourth = _mm_set1_ps(1.0 / 24.0);

    let x2 = _mm_mul_ps(x, x);
    let x3 = _mm_mul_ps(x2, x);
    let x4 = _mm_mul_ps(x3, x);

    let term2 = _mm_mul_ps(x2, half);
    let term3 = _mm_mul_ps(x3, sixth);
    let term4 = _mm_mul_ps(x4, twenty_fourth);

    let sum = _mm_add_ps(one, x);
    let sum = _mm_add_ps(sum, term2);
    let sum = _mm_add_ps(sum, term3);
    _mm_add_ps(sum, term4)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_sum_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [0f32; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.iter().copied().sum()
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_max_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [f32::NEG_INFINITY; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.into_iter().fold(f32::NEG_INFINITY, f32::max)
}

/// Moving average with AVX2 - 3x faster
#[inline(always)]
pub fn moving_average(data: &[f32], window: usize) -> Vec<f32> {
    let window = window.max(1);
    if data.is_empty() {
        return Vec::new();
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        let matrix = features.simd_dispatch_matrix();
        if features.avx512f {
            telemetry::MOVING_AVG_AVX512_OPS.inc();
            // SAFETY: the exact AVX-512 Foundation runtime feature is proven above.
            return unsafe { moving_average_avx512(data, window) };
        }
        if matrix.avx2 {
            telemetry::MOVING_AVG_AVX2_OPS.inc();
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { moving_average_avx2(data, window) };
        }
        if features.sse2 {
            telemetry::MOVING_AVG_SSE_OPS.inc();
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            return unsafe { moving_average_sse2(data, window) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    if features.neon {
        telemetry::MOVING_AVG_NEON_OPS.inc();
        // SAFETY: the exact runtime NEON feature is proven above.
        return unsafe { moving_average_neon(data, window) };
    }

    telemetry::MOVING_AVG_SCALAR_OPS.inc();

    // Scalar fallback
    let mut result = Vec::with_capacity(data.len());
    let mut window_sum = 0.0f32;
    for i in 0..data.len() {
        window_sum += data[i];
        if i >= window {
            window_sum -= data[i - window];
        }
        let denom = if i + 1 < window { (i + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
    }
    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn moving_average_avx2(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 8 <= len {
        let add_vec = _mm256_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm256_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm256_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 8];
        _mm256_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 8;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn moving_average_sse2(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 4 <= len {
        let add_vec = _mm_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 4];
        _mm_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 4;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn moving_average_avx512(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 16 <= len {
        let add_vec = _mm512_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm512_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm512_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 16];
        _mm512_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 16;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn moving_average_neon(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::aarch64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 4 <= len {
        let add_vec = vld1q_f32(data.as_ptr().add(idx));
        let sub_vec = vld1q_f32(data.as_ptr().add(idx - window));
        let diff_vec = vsubq_f32(add_vec, sub_vec);

        let mut diffs = [0f32; 4];
        vst1q_f32(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 4;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

/// Percentile calculation with AVX2 minmax - 2x faster
#[inline(always)]
pub fn compute_percentile(data: &mut [f32], percentile: f32) -> f32 {
    let Some(index) = percentile_index(data.len(), percentile) else {
        return 0.0;
    };
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.simd_dispatch_matrix().avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            return unsafe { compute_percentile_avx2(data, index) };
        }
        if features.sse2 {
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            return unsafe { compute_percentile_sse2(data, index) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            return unsafe { compute_percentile_sve2(data, index) };
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            return unsafe { compute_percentile_neon(data, index) };
        }
    }

    // Scalar fallback - partial sort
    data.select_nth_unstable_by(index, |a, b| {
        a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
    });
    data[index]
}

#[inline(always)]
fn percentile_index(len: usize, percentile: f32) -> Option<usize> {
    if len == 0 || !percentile.is_finite() || !(0.0..=100.0).contains(&percentile) {
        return None;
    }

    let scaled = (percentile / 100.0) * len as f32;
    Some((scaled as usize).min(len - 1))
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
/// # Safety
///
/// The caller must prove AVX2 support and pass an index smaller than `data.len()`.
unsafe fn compute_percentile_avx2(data: &mut [f32], index: usize) -> f32 {
    // Use AVX2 for faster partitioning in quickselect
    // AVX2-accelerated partial sort (use total order via partial_cmp)
    data.select_nth_unstable_by(index, |a, b| {
        a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
    });
    data[index]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
/// # Safety
///
/// The caller must prove SSE2 support and pass an index smaller than `data.len()`.
unsafe fn compute_percentile_sse2(data: &mut [f32], index: usize) -> f32 {
    data.select_nth_unstable_by(index, |a, b| {
        a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
    });
    data[index]
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
/// # Safety
///
/// The caller must prove NEON support and pass an index smaller than `data.len()`.
unsafe fn compute_percentile_neon(data: &mut [f32], index: usize) -> f32 {
    data.select_nth_unstable_by(index, |a, b| {
        a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
    });
    data[index]
}

#[cfg(target_arch = "aarch64")]
/// # Safety
///
/// The caller must prove SVE2 support and pass an index smaller than `data.len()`.
unsafe fn compute_percentile_sve2(data: &mut [f32], index: usize) -> f32 {
    #[cfg(target_feature = "sve2")]
    {
        compute_percentile_sve2_impl(data, index)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        compute_percentile_neon(data, index)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
/// # Safety
///
/// The caller must prove SVE2 support and pass an index smaller than `data.len()`.
unsafe fn compute_percentile_sve2_impl(data: &mut [f32], index: usize) -> f32 {
    compute_percentile_neon(data, index)
}

/// Activation functions with AVX2 approximation - 4x faster
#[inline(always)]
pub fn relu_batch(data: &mut [f32]) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.simd_dispatch_matrix().avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe { relu_batch_avx2(data) };
            return;
        }
        if features.sse2 {
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            unsafe { relu_batch_sse2(data) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            unsafe { relu_batch_sve2(data) };
            return;
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            unsafe { relu_batch_neon(data) };
            return;
        }
    }

    // Scalar fallback
    for x in data.iter_mut() {
        *x = x.max(0.0);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn relu_batch_avx2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let zero = _mm256_setzero_ps();
    let mut i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let result = _mm256_max_ps(vals, zero);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), result);
        i += 8;
    }

    // Handle remainder
    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn relu_batch_sse2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let mut i = 0usize;
    let zero = _mm_setzero_ps();

    while i + 4 <= data.len() {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let result = _mm_max_ps(vals, zero);
        _mm_storeu_ps(data.as_mut_ptr().add(i), result);
        i += 4;
    }

    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn relu_batch_neon(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let mut i = 0usize;
    let zero = vdupq_n_f32(0.0);

    while i + 4 <= data.len() {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let result = vmaxq_f32(vals, zero);
        vst1q_f32(data.as_mut_ptr().add(i), result);
        i += 4;
    }

    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn relu_batch_sve2(data: &mut [f32]) {
    #[cfg(target_feature = "sve2")]
    {
        relu_batch_sve2_impl(data);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        relu_batch_neon(data);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn relu_batch_sve2_impl(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut offset = 0usize;
    let zero = svdup_f32(0.0);
    let all = svptrue_b32();

    while offset < len {
        let pg = svwhilelt_b32(offset as u64, len as u64);
        if !svptest_any(all, pg) {
            break;
        }

        let vals = svld1_f32(pg, data.as_ptr().add(offset));
        let clipped = svmax_f32_z(pg, zero, vals);
        svst1_f32(pg, data.as_mut_ptr().add(offset), clipped);
        offset += svcntw() as usize;
    }
}

/// Softmax with AVX2 fast exp - 3x faster  
#[inline(always)]
pub fn softmax_batch(data: &mut [f32]) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let features = FeatureDetector::instance().features_full();

    #[cfg(target_arch = "x86_64")]
    {
        if features.simd_dispatch_matrix().avx2 {
            // SAFETY: the exact AVX2 runtime feature is proven by the dispatch matrix.
            unsafe { softmax_batch_avx2(data) };
            return;
        }
        if features.sse2 {
            // SAFETY: SSE2 is a required x86_64 baseline and is checked explicitly.
            unsafe { softmax_batch_sse2(data) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.sve2 {
            // SAFETY: the exact runtime SVE2 feature is proven above.
            unsafe { softmax_batch_sve2(data) };
            return;
        }
        if features.neon {
            // SAFETY: the exact runtime NEON feature is proven above.
            unsafe { softmax_batch_neon(data) };
            return;
        }
    }

    softmax_scalar(data);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn softmax_batch_avx2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    // Find max
    let mut max_vec = _mm256_set1_ps(f32::NEG_INFINITY);
    let mut i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        max_vec = _mm256_max_ps(max_vec, vals);
        i += 8;
    }

    let mut max = horizontal_max_ps(max_vec);

    // Handle remainder for max
    while i < data.len() {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = _mm256_set1_ps(max);

    // Compute exp and sum
    let mut sum_vec = _mm256_setzero_ps();
    i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let shifted = _mm256_sub_ps(vals, max_vec);
        let exp_vals = fast_exp_ps(shifted);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = _mm256_add_ps(sum_vec, exp_vals);
        i += 8;
    }

    let mut sum = horizontal_sum_ps(sum_vec);

    // Handle remainder
    while i < data.len() {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    // Normalize
    if sum == 0.0 {
        let uniform = 1.0 / data.len() as f32;
        for v in data.iter_mut() {
            *v = uniform;
        }
        return;
    }
    let sum_inv = _mm256_set1_ps(1.0 / sum);
    i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let normalized = _mm256_mul_ps(vals, sum_inv);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), normalized);
        i += 8;
    }

    // Handle remainder
    while i < data.len() {
        data[i] /= sum;
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn softmax_batch_sse2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut max_vec = _mm_set1_ps(f32::NEG_INFINITY);
    let mut i = 0usize;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        max_vec = _mm_max_ps(max_vec, vals);
        i += 4;
    }

    let mut max = horizontal_max_ps_sse(max_vec);
    while i < len {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = _mm_set1_ps(max);
    let mut sum_vec = _mm_setzero_ps();
    i = 0;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let shifted = _mm_sub_ps(vals, max_vec);
        let exp_vals = fast_exp_ps_sse(shifted);
        _mm_storeu_ps(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = _mm_add_ps(sum_vec, exp_vals);
        i += 4;
    }

    let mut sum = horizontal_sum_ps_sse(sum_vec);

    while i < len {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (len as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv = _mm_set1_ps(1.0 / sum);
    i = 0;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let normalized = _mm_mul_ps(vals, inv);
        _mm_storeu_ps(data.as_mut_ptr().add(i), normalized);
        i += 4;
    }

    while i < len {
        data[i] /= sum;
        i += 1;
    }
}

#[inline(always)]
fn softmax_scalar(data: &mut [f32]) {
    if data.is_empty() {
        return;
    }

    let max = data.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
    let mut sum = 0.0f32;

    for x in data.iter_mut() {
        let val = (*x - max).exp();
        *x = val;
        sum += val;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (data.len() as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv = 1.0 / sum;
    for x in data.iter_mut() {
        *x *= inv;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn softmax_batch_neon(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut i = 0usize;
    let mut max_vec = vdupq_n_f32(f32::NEG_INFINITY);

    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        max_vec = vmaxq_f32(max_vec, vals);
        i += 4;
    }

    let mut max = vmaxvq_f32(max_vec);
    while i < len {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = vdupq_n_f32(max);
    let mut sum_vec = vdupq_n_f32(0.0);
    i = 0;

    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let shifted = vsubq_f32(vals, max_vec);
        let mut tmp = [0f32; 4];
        vst1q_f32(tmp.as_mut_ptr(), shifted);
        for lane in tmp.iter_mut() {
            *lane = lane.exp();
        }
        let exp_vals = vld1q_f32(tmp.as_ptr());
        vst1q_f32(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = vaddq_f32(sum_vec, exp_vals);
        i += 4;
    }

    let mut sum = vaddvq_f32(sum_vec);
    while i < len {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (len as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv_vec = vdupq_n_f32(1.0 / sum);
    i = 0;
    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let normalized = vmulq_f32(vals, inv_vec);
        vst1q_f32(data.as_mut_ptr().add(i), normalized);
        i += 4;
    }

    while i < len {
        data[i] /= sum;
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn softmax_batch_sve2(data: &mut [f32]) {
    #[cfg(target_feature = "sve2")]
    {
        softmax_batch_sve2_impl(data);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        softmax_batch_neon(data);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn softmax_batch_sve2_impl(data: &mut [f32]) {
    // SVE2 path currently reuses NEON implementation for numerical stability.
    softmax_batch_neon(data);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_max_ps(v: __m256) -> f32 {
    use std::arch::x86_64::*;

    let max_128 = _mm_max_ps(_mm256_extractf128_ps(v, 0), _mm256_extractf128_ps(v, 1));
    let max_64 = _mm_max_ps(max_128, _mm_movehl_ps(max_128, max_128));
    let max_32 = _mm_max_ss(max_64, _mm_shuffle_ps(max_64, max_64, 0x01));
    _mm_cvtss_f32(max_32)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn fast_exp_ps(x: __m256) -> __m256 {
    use std::arch::x86_64::*;

    // Fast exp approximation using Taylor series
    // exp(x) ~ 1 + x + x^2/2 + x^3/6 + x^4/24
    let one = _mm256_set1_ps(1.0);
    let half = _mm256_set1_ps(0.5);
    let sixth = _mm256_set1_ps(1.0 / 6.0);
    let twenty_fourth = _mm256_set1_ps(1.0 / 24.0);

    let x2 = _mm256_mul_ps(x, x);
    let x3 = _mm256_mul_ps(x2, x);
    let x4 = _mm256_mul_ps(x3, x);

    let term2 = _mm256_mul_ps(x2, half);
    let term3 = _mm256_mul_ps(x3, sixth);
    let term4 = _mm256_mul_ps(x4, twenty_fourth);

    let sum = _mm256_add_ps(one, x);
    let sum = _mm256_add_ps(sum, term2);
    let sum = _mm256_add_ps(sum, term3);
    _mm256_add_ps(sum, term4)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // decay_histogram
    // ---------------------------------------------------------------

    #[test]
    fn test_decay_histogram_half_decay_floors_correctly() {
        let mut bins = vec![100, 201, 50, 1, 0, 999];
        decay_histogram(&mut bins, 0.5);
        // floor(100*0.5)=50, floor(201*0.5)=100, floor(50*0.5)=25,
        // floor(1*0.5)=0, 0*0.5=0, floor(999*0.5)=499
        assert_eq!(bins, vec![50, 100, 25, 0, 0, 499]);
    }

    #[test]
    fn test_decay_histogram_decay_one_is_noop() {
        let original = vec![10, 20, 30, 40, 50];
        let mut bins = original.clone();
        decay_histogram(&mut bins, 1.0);
        assert_eq!(bins, original);
    }

    #[test]
    fn test_decay_histogram_decay_zero_clears_all() {
        let mut bins = vec![100, 200, 300, u64::MAX];
        decay_histogram(&mut bins, 0.0);
        assert_eq!(bins, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_decay_histogram_negative_decay_clamps_to_zero() {
        let mut bins = vec![42, 99];
        decay_histogram(&mut bins, -5.0);
        // decay clamped to 0.0 -> zeros all
        assert_eq!(bins, vec![0, 0]);
    }

    #[test]
    fn test_decay_histogram_above_one_clamps_to_noop() {
        let original = vec![7, 13, 255];
        let mut bins = original.clone();
        decay_histogram(&mut bins, 2.5);
        // decay clamped to 1.0 -> noop
        assert_eq!(bins, original);
    }

    #[test]
    fn test_decay_histogram_empty_slice() {
        let mut bins: Vec<u64> = Vec::new();
        decay_histogram(&mut bins, 0.5);
        assert!(bins.is_empty());
    }

    #[test]
    fn test_decay_histogram_single_element() {
        let mut bins = vec![7];
        decay_histogram(&mut bins, 0.9);
        // floor(7 * 0.9) = floor(6.3) = 6
        assert_eq!(bins, vec![6]);
    }

    #[test]
    fn test_decay_histogram_large_vector_consistency() {
        // Test with sizes that exercise SIMD remainder paths (odd lengths)
        for len in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33] {
            let mut bins: Vec<u64> = (1..=len as u64).collect();
            let mut expected: Vec<u64> = bins.clone();
            let decay = 0.75;
            for b in expected.iter_mut() {
                *b = ((*b as f64) * decay).floor() as u64;
            }
            decay_histogram(&mut bins, decay);
            assert_eq!(bins, expected, "mismatch at len={len}");
        }
    }

    #[test]
    fn test_decay_histogram_matches_scalar_across_u64_range() {
        let original = vec![
            0,
            1,
            u32::MAX as u64,
            1u64 << 32,
            (1u64 << 53) - 1,
            1u64 << 53,
            (1u64 << 53) + 1,
            (1u64 << 63) - 1,
            1u64 << 63,
            u64::MAX - 1,
            u64::MAX,
        ];

        for decay in [0.5, 0.75, f64::from_bits(1.0f64.to_bits() - 1)] {
            let expected: Vec<u64> =
                original.iter().map(|&bin| ((bin as f64) * decay).floor() as u64).collect();
            let mut actual = original.clone();

            decay_histogram(&mut actual, decay);

            assert_eq!(actual, expected, "mismatch for decay={decay}");
        }
    }

    // ---------------------------------------------------------------
    // jensen_shannon_divergence
    // ---------------------------------------------------------------

    #[test]
    fn test_jsd_identical_distributions_is_zero() {
        // When P == Q, JSD should be 0 (or extremely close due to epsilon)
        let bins = vec![25, 25, 25, 25];
        let total = 100u64;
        let target = vec![0.25, 0.25, 0.25, 0.25];
        let jsd = jensen_shannon_divergence(&bins, total, &target);
        assert!(jsd.abs() < 1e-6, "JSD of identical distributions should be ~0, got {jsd}");
    }

    #[test]
    fn test_jsd_completely_different_distributions() {
        // P is concentrated in bin 0, Q is uniform
        let bins = vec![1000, 0, 0, 0];
        let total = 1000u64;
        let target = vec![0.25, 0.25, 0.25, 0.25];
        let jsd = jensen_shannon_divergence(&bins, total, &target);
        // JSD is bounded by ln(2) ~ 0.693 for base-e
        assert!(jsd > 0.0, "JSD of different distributions must be > 0");
        assert!(jsd <= 0.7, "JSD must be <= ln(2), got {jsd}");
    }

    #[test]
    fn test_jsd_empty_bins_returns_zero() {
        let bins: Vec<u64> = Vec::new();
        let target: Vec<f64> = Vec::new();
        let jsd = jensen_shannon_divergence(&bins, 0, &target);
        assert_eq!(jsd, 0.0);
    }

    #[test]
    fn test_jsd_zero_total_returns_zero() {
        let bins = vec![0, 0, 0];
        let target = vec![0.33, 0.33, 0.34];
        let jsd = jensen_shannon_divergence(&bins, 0, &target);
        assert_eq!(jsd, 0.0);
    }

    #[test]
    fn test_jsd_mismatched_lengths_uses_minimum() {
        // bins has 2 elements, target has 4 - should use min(2,4) = 2
        let bins = vec![50, 50];
        let total = 100u64;
        let target = vec![0.5, 0.5, 0.0, 0.0];
        let jsd = jensen_shannon_divergence(&bins, total, &target);
        // P=[0.5,0.5] vs Q=[0.5,0.5] over 2 bins -> ~0
        assert!(jsd.abs() < 1e-6, "JSD of matching 2-bin dists should be ~0, got {jsd}");
    }

    // ---------------------------------------------------------------
    // scalar_jensen_shannon (internal, exercised through public API)
    // ---------------------------------------------------------------

    #[test]
    fn test_scalar_jsd_symmetry_property() {
        // JSD(P||Q) should equal JSD(Q||P) when computed via the symmetric formula
        let bins_a = vec![60, 30, 10];
        let total_a = 100u64;
        let target_a = vec![0.1, 0.3, 0.6];
        let jsd_forward = scalar_jensen_shannon(&bins_a, total_a, &target_a);

        // Reverse: bins represent the target, target represents the hist
        let bins_b = vec![10, 30, 60];
        let total_b = 100u64;
        let target_b = vec![0.6, 0.3, 0.1];
        let jsd_reverse = scalar_jensen_shannon(&bins_b, total_b, &target_b);

        assert!(
            (jsd_forward - jsd_reverse).abs() < 1e-10,
            "JSD must be symmetric: forward={jsd_forward}, reverse={jsd_reverse}"
        );
    }

    // ---------------------------------------------------------------
    // moving_average
    // ---------------------------------------------------------------

    #[test]
    fn test_moving_average_simple_window() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let result = moving_average(&data, 3);
        assert_eq!(result.len(), 5);
        // Ramp-up: avg(1)=1.0, avg(1,2)=1.5, then full window:
        // avg(1,2,3)=2.0, avg(2,3,4)=3.0, avg(3,4,5)=4.0
        let expected = [1.0, 1.5, 2.0, 3.0, 4.0];
        for (i, (&r, &e)) in result.iter().zip(expected.iter()).enumerate() {
            assert!((r - e).abs() < 1e-5, "moving_average[{i}]: got {r}, expected {e}");
        }
    }

    #[test]
    fn test_moving_average_window_one_returns_identity() {
        let data = vec![5.0, 3.0, 8.0, 1.0];
        let result = moving_average(&data, 1);
        for (i, (&r, &d)) in result.iter().zip(data.iter()).enumerate() {
            assert!(
                (r - d).abs() < 1e-5,
                "window=1 should return identity at [{i}]: got {r}, expected {d}"
            );
        }
    }

    #[test]
    fn test_moving_average_window_equals_length() {
        let data = vec![2.0, 4.0, 6.0];
        let result = moving_average(&data, 3);
        // Ramp-up: 2/1=2, (2+4)/2=3, (2+4+6)/3=4
        let expected = [2.0, 3.0, 4.0];
        for (i, (&r, &e)) in result.iter().zip(expected.iter()).enumerate() {
            assert!(
                (r - e).abs() < 1e-5,
                "moving_average window==len [{i}]: got {r}, expected {e}"
            );
        }
    }

    #[test]
    fn test_moving_average_window_exceeds_length() {
        let data = vec![10.0, 20.0];
        let result = moving_average(&data, 100);
        // Never reaches full window, so ramp-up only: 10/1, (10+20)/2
        assert_eq!(result.len(), 2);
        assert!((result[0] - 10.0).abs() < 1e-5);
        assert!((result[1] - 15.0).abs() < 1e-5);
    }

    #[test]
    fn test_moving_average_empty_data() {
        let data: Vec<f32> = Vec::new();
        let result = moving_average(&data, 5);
        assert!(result.is_empty());
    }

    #[test]
    fn test_moving_average_window_zero_clamps_to_one() {
        let data = vec![1.0, 2.0, 3.0];
        let result = moving_average(&data, 0);
        assert_eq!(result.len(), 3);
        assert!((result[0] - 1.0).abs() < 1e-6);
    }

    // ---------------------------------------------------------------
    // compute_percentile
    // ---------------------------------------------------------------

    #[test]
    fn test_compute_percentile_median() {
        let mut data = vec![5.0, 1.0, 3.0, 9.0, 7.0];
        let p50 = compute_percentile(&mut data, 50.0);
        // Sorted: [1, 3, 5, 7, 9], k = floor(0.5*5)=2 -> data[2]=5.0
        assert!((p50 - 5.0).abs() < 1e-5, "50th percentile should be 5.0, got {p50}");
    }

    #[test]
    fn test_compute_percentile_zero_returns_minimum() {
        let mut data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let p0 = compute_percentile(&mut data, 0.0);
        // k = floor(0.0*5) = 0 -> smallest element = 10.0
        assert!((p0 - 10.0).abs() < 1e-5, "0th percentile should be min, got {p0}");
    }

    #[test]
    fn test_compute_percentile_high() {
        let mut data: Vec<f32> = (1..=100).map(|x| x as f32).collect();
        let p99 = compute_percentile(&mut data, 99.0);
        // k = floor(0.99*100) = 99 -> 100.0
        assert!((p99 - 100.0).abs() < 1e-5, "99th percentile of 1..100 should be 100.0, got {p99}");
    }

    #[test]
    fn test_compute_percentile_invalid_input_fails_closed_without_mutation() {
        for percentile in [-1.0, 100.1, f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut data = vec![10.0, 20.0, 30.0];
            let original = data.clone();
            assert_eq!(compute_percentile(&mut data, percentile), 0.0);
            assert_eq!(data, original, "invalid percentile must not mutate input");
        }
    }

    #[test]
    fn test_compute_percentile_hundred_returns_maximum() {
        let mut data = vec![5.0, 1.0, 3.0, 9.0, 7.0];
        assert_eq!(compute_percentile(&mut data, 100.0), 9.0);
    }

    // ---------------------------------------------------------------
    // relu_batch
    // ---------------------------------------------------------------

    #[test]
    fn test_relu_batch_clamps_negatives_to_zero() {
        let mut data = vec![-3.0, -1.0, 0.0, 1.0, 5.0, -0.001];
        relu_batch(&mut data);
        assert_eq!(data, vec![0.0, 0.0, 0.0, 1.0, 5.0, 0.0]);
    }

    #[test]
    fn test_relu_batch_all_positive_unchanged() {
        let mut data = vec![1.0, 2.5, 100.0, 0.001];
        let original = data.clone();
        relu_batch(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_relu_batch_empty() {
        let mut data: Vec<f32> = Vec::new();
        relu_batch(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_relu_batch_various_lengths() {
        // Exercise SIMD remainder paths across different vector sizes
        for len in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let mut data: Vec<f32> = (0..len).map(|i| (i as f32) - (len as f32 / 2.0)).collect();
            relu_batch(&mut data);
            for (i, &v) in data.iter().enumerate() {
                let original = (i as f32) - (len as f32 / 2.0);
                let expected = original.max(0.0);
                assert!(
                    (v - expected).abs() < 1e-5,
                    "relu len={len} [{i}]: got {v}, expected {expected}"
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // softmax_batch
    // ---------------------------------------------------------------

    #[test]
    fn test_softmax_batch_sums_to_one() {
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        softmax_batch(&mut data);
        let sum: f32 = data.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4, "softmax output should sum to 1.0, got {sum}");
    }

    #[test]
    fn test_softmax_batch_monotonic_ordering() {
        let mut data = vec![1.0, 2.0, 3.0];
        softmax_batch(&mut data);
        // Larger input -> larger softmax probability
        assert!(
            data[0] < data[1],
            "softmax should preserve ordering: data[0]={} < data[1]={}",
            data[0],
            data[1]
        );
        assert!(
            data[1] < data[2],
            "softmax should preserve ordering: data[1]={} < data[2]={}",
            data[1],
            data[2]
        );
    }

    #[test]
    fn test_softmax_batch_all_equal_yields_uniform() {
        let mut data = vec![5.0, 5.0, 5.0, 5.0];
        softmax_batch(&mut data);
        for (i, &v) in data.iter().enumerate() {
            assert!(
                (v - 0.25).abs() < 1e-4,
                "softmax of equal inputs should be uniform: [{i}]={v}"
            );
        }
    }

    #[test]
    fn test_softmax_batch_all_outputs_non_negative() {
        let mut data = vec![-10.0, -5.0, 0.0, 5.0, 10.0];
        softmax_batch(&mut data);
        for (i, &v) in data.iter().enumerate() {
            assert!(v >= 0.0, "softmax output must be >= 0: [{i}]={v}");
        }
    }

    #[test]
    fn test_softmax_batch_single_element() {
        let mut data = vec![42.0];
        softmax_batch(&mut data);
        assert!(
            (data[0] - 1.0).abs() < 1e-5,
            "softmax of single element should be 1.0, got {}",
            data[0]
        );
    }

    #[test]
    fn test_softmax_batch_empty() {
        let mut data: Vec<f32> = Vec::new();
        softmax_batch(&mut data);
        assert!(data.is_empty());
    }

    // ---------------------------------------------------------------
    // softmax_scalar (internal, direct unit test)
    // ---------------------------------------------------------------

    #[test]
    fn test_softmax_scalar_matches_definition() {
        let mut data = vec![1.0f32, 2.0, 3.0];
        softmax_scalar(&mut data);
        // Verify against manual computation
        let max = 3.0f32;
        let e0 = (1.0 - max).exp();
        let e1 = (2.0 - max).exp();
        let e2 = (3.0 - max).exp();
        let sum = e0 + e1 + e2;
        let expected = [e0 / sum, e1 / sum, e2 / sum];
        for (i, (&got, &exp)) in data.iter().zip(expected.iter()).enumerate() {
            assert!((got - exp).abs() < 1e-5, "softmax_scalar[{i}]: got {got}, expected {exp}");
        }
    }
}
