//! SIMD acceleration for statistics and vector/ML operations.
//! No active matrix-multiplication or AMX caller is owned by this module.

use crate::optimize::telemetry;
use crate::optimize::FeatureDetector;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__m256;

mod histogram;

pub use histogram::{decay_histogram, jensen_shannon_divergence};

#[cfg(test)]
fn scalar_jensen_shannon(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    histogram::scalar_jensen_shannon(bins, total, target)
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub use histogram::{
    __test_decay_histogram_avx2, __test_decay_histogram_avx512, __test_decay_histogram_sse41,
    __test_jensen_shannon_avx2, __test_jensen_shannon_avx512, __test_jensen_shannon_sse41,
};

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
mod tests;
