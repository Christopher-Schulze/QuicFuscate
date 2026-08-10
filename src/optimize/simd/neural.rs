//! optimize::simd::neural (TODO-563).

#[cfg(target_arch = "x86_64")]
use super::FeatureDetector;

/// Dot product with best available SIMD
#[inline(always)]
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(target_arch = "x86_64")]
    {
        let matrix = FeatureDetector::instance().features_full().simd_dispatch_matrix();
        if matrix.neural_avx512 {
            return unsafe { dot_product_avx512(a, b) };
        }
        if matrix.neural_avx2 {
            return unsafe { dot_product_avx2(a, b) };
        }
    }

    dot_product_scalar(a, b)
}

/// Dot product with AVX-512
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,fma")]
/// # Safety
///
/// The caller must provide AVX-512F and FMA support. `a` and `b` must remain
/// valid immutable slices for the duration of the call; the implementation
/// reads only complete 16-element chunks and a scalar tail.
unsafe fn dot_product_avx512(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let len = a.len().min(b.len());
    let mut sum = _mm512_setzero_ps();
    let chunks = len / 16;

    for i in 0..chunks {
        let va = _mm512_loadu_ps(a[i * 16..].as_ptr());
        let vb = _mm512_loadu_ps(b[i * 16..].as_ptr());
        sum = _mm512_fmadd_ps(va, vb, sum);
    }

    let mut total = _mm512_reduce_add_ps(sum);
    for i in (chunks * 16)..len {
        total += a[i] * b[i];
    }
    total
}

/// Dot product with AVX2 + FMA
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,fma")]
/// # Safety
///
/// The caller must provide AVX2 and FMA support. `a` and `b` must remain valid
/// immutable slices for the duration of the call; the implementation reads
/// only complete 8-element chunks and a scalar tail.
unsafe fn dot_product_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let len = a.len().min(b.len());
    let mut sum = _mm256_setzero_ps();
    let chunks = len / 8;

    for i in 0..chunks {
        let va = _mm256_loadu_ps(a[i * 8..].as_ptr());
        let vb = _mm256_loadu_ps(b[i * 8..].as_ptr());
        sum = _mm256_fmadd_ps(va, vb, sum);
    }

    // Horizontal sum
    let mut sum_array = [0.0f32; 8];
    _mm256_storeu_ps(sum_array.as_mut_ptr(), sum);
    let mut total: f32 = sum_array.iter().sum();
    for i in (chunks * 8)..len {
        total += a[i] * b[i];
    }
    total
}

/// Scalar dot product fallback
fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}
