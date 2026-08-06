//! Extracted SIMD `qpack` submodule (TODO-563).

use super::*;

/// Encode bytes using QPACK Huffman coding into `output`.
/// Returns number of bytes written. Runtime-dispatch to NEON on aarch64.
#[inline(always)]
pub fn encode_huff_into(input: &[u8], output: &mut [u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let full = FeatureDetector::instance().features_full();
        if full.simd_dispatch_matrix().avx2 {
            // SAFETY: AVX2 feature verified by runtime detection. Callee reads
            // `input` and writes up to `output.len()` bytes with bounds checks.
            return unsafe { super::x86::qpack_encode_avx2(input, output) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let full = FeatureDetector::instance().features_full();
        if full.neon {
            return crate::simd::arm::qpack_encode_neon(input, output);
        }
    }
    crate::transport::h3::qpack::huff_encode_into(input, output)
}
