//! Extracted SIMD `string` submodule (TODO-563).

#[cfg(target_arch = "x86_64")]
use crate::optimize::{CpuFeature, FeatureDetector};

/// String comparison with SIMD acceleration when available.
#[inline(always)]
pub fn compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
    // Both `a` and `b` are borrowed slices of equal length (checked above).
    // Callees process in SIMD-width chunks with scalar tail handling.
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance();
        if features.has_feature(CpuFeature::AVX2) {
            return unsafe { super::x86::string_compare_avx2(a, b) };
        }
        if features.has_feature(CpuFeature::SSE42) {
            return unsafe { super::x86::string_compare_sse42(a, b) };
        }
    }

    a == b
}
