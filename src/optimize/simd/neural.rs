//! optimize::simd::neural (TODO-563).

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx512f"),
    all(target_arch = "x86_64", target_feature = "fma")
))]
use super::FeatureDetector;

/// Dot product with best available SIMD
#[inline(always)]
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    {
        let features = FeatureDetector::instance().features_full();
        if features.avx512f {
            return unsafe { dot_product_avx512(a, b) };
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
    {
        let features = FeatureDetector::instance().features_full();
        if features.fma {
            return unsafe { dot_product_avx2(a, b) };
        }
    }

    dot_product_scalar(a, b)
}

/// Dot product with AVX-512
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[inline(always)]
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

    // Horizontal sum
    _mm512_reduce_add_ps(sum)
}

/// Dot product with AVX2 + FMA
#[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
#[inline(always)]
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
    sum_array.iter().sum()
}

/// Scalar dot product fallback
fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}
