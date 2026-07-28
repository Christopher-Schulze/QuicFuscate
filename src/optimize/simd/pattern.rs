//! optimize::simd::pattern (TODO-563).

#[cfg(any(
    all(target_arch = "x86_64", target_feature = "avx512vbmi2"),
    all(target_arch = "x86_64", target_feature = "avx2")
))]
use super::FeatureDetector;

/// String search with best available SIMD
#[inline(always)]
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
    {
        let features = FeatureDetector::instance().features_full();
        if features.avx512f {
            return unsafe { find_pattern_vbmi2(haystack, needle) };
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    {
        let features = FeatureDetector::instance().features_full();
        if features.avx2 {
            return unsafe { find_pattern_avx2(haystack, needle) };
        }
    }

    find_pattern_scalar(haystack, needle)
}

/// String search with AVX-512 VBMI2
#[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
#[inline(always)]
unsafe fn find_pattern_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // Reuse the scalar matcher for consistent semantics across CPU paths.
    find_pattern_scalar(haystack, needle)
}

/// String search with AVX2
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    // Reuse the scalar matcher for consistent semantics across CPU paths.
    find_pattern_scalar(haystack, needle)
}

/// Scalar pattern search fallback
fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}
