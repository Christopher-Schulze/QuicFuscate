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

pub(super) fn scalar_jensen_shannon(bins: &[u64], total: u64, target: &[f64]) -> f64 {
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
pub(super) unsafe fn horizontal_sum_ps(v: __m256) -> f32 {
    use std::arch::x86_64::*;

    let sum_128 = _mm_add_ps(_mm256_extractf128_ps(v, 0), _mm256_extractf128_ps(v, 1));
    let sum_64 = _mm_add_ps(sum_128, _mm_movehl_ps(sum_128, sum_128));
    let sum_32 = _mm_add_ss(sum_64, _mm_shuffle_ps(sum_64, sum_64, 0x01));
    _mm_cvtss_f32(sum_32)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(super) unsafe fn fast_exp_ps_sse(x: std::arch::x86_64::__m128) -> std::arch::x86_64::__m128 {
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
pub(super) unsafe fn horizontal_sum_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [0f32; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.iter().copied().sum()
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(super) unsafe fn horizontal_max_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [f32::NEG_INFINITY; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.into_iter().fold(f32::NEG_INFINITY, f32::max)
}
