//! Extracted SIMD `h3` submodule (TODO-563).

use super::*;

/// QPACK Huffman encoding with SIMD acceleration when available.
#[inline(always)]
pub fn qpack_encode(input: &[u8], output: &mut [u8]) -> usize {
    let features = FeatureDetector::instance();

    // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
    // Callees read from `input`, write to `output` with bounds checks,
    // and return the number of bytes written.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        if full.simd_dispatch_matrix().avx2 {
            return unsafe { super::x86::qpack_encode_avx2(input, output) };
        }
        if full.ssse3 && full.sse41 {
            return unsafe { super::x86::qpack_encode_ssse3(input, output) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            return super::arm::qpack_encode_sve2(input, output);
        }
        if full.neon {
            return super::arm::qpack_encode_neon(input, output);
        }
    }

    scalar::qpack_encode(input, output)
}

/// QPACK Huffman decoding with SIMD acceleration when available.
#[inline(always)]
pub fn qpack_decode(input: &[u8], output: &mut [u8]) -> usize {
    let features = FeatureDetector::instance();

    // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
    // Callees read from `input` and write to `output` with bounds checks.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        if full.simd_dispatch_matrix().avx2 {
            return unsafe { super::x86::qpack_decode_avx2(input, output) };
        }
        if full.ssse3 {
            return unsafe { super::x86::qpack_decode_ssse3(input, output) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            return super::arm::qpack_decode_sve2(input, output);
        }
        if full.neon {
            return super::arm::qpack_decode_neon(input, output);
        }
    }

    scalar::qpack_decode(input, output)
}
