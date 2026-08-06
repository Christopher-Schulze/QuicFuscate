//! Extracted SIMD `fec` submodule (TODO-563).

use super::*;

/// Router: Berlekamp-Massey over GF(256) with best available backend
#[inline(always)]
pub fn berlekamp_massey_gf256(syndrome: &[u8], len: usize) -> Vec<u8> {
    let features = FeatureDetector::instance();
    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. Callees only read `syndrome[..len]` and
    // return an owned Vec - no aliasing or pointer lifetime concerns.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        if full.gfni && full.avx512f {
            return unsafe { super::x86_extended::berlekamp_massey_gfni(syndrome, len) };
        }
        if full.simd_dispatch_matrix().avx2 {
            return unsafe { super::x86_extended::berlekamp_massey_avx2(syndrome, len) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 && std::arch::is_aarch64_feature_detected!("sve2") {
            return unsafe { berlekamp_massey_sve2_dispatch(syndrome, len) };
        }
    }
    // Scalar fallback
    super::scalar::berlekamp_massey(syndrome, len)
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
unsafe fn berlekamp_massey_sve2_dispatch(syndrome: &[u8], len: usize) -> Vec<u8> {
    super::arm::berlekamp_massey_sve2(syndrome, len)
}

#[cfg(any(not(target_arch = "aarch64"), not(target_feature = "sve2")))]
#[inline(always)]
unsafe fn berlekamp_massey_sve2_dispatch(syndrome: &[u8], len: usize) -> Vec<u8> {
    super::scalar::berlekamp_massey(syndrome, len)
}

/// FEC header parsing helper.
///
/// Returns `(kind, u32_field, u64_field)` parsed from the first 13 bytes.
#[inline(always)]
pub fn parse_header_bmi2(header: &[u8]) -> Option<(u8, u32, u64)> {
    if header.len() < 13 {
        return None;
    }

    let kind = header[0];
    let u32_field = u32::from_le_bytes(header[1..5].try_into().ok()?);
    let u64_field = u64::from_le_bytes(header[5..13].try_into().ok()?);

    Some((kind, u32_field, u64_field))
}

/// Varint decoding with BMI2 acceleration when available.
#[inline(always)]
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    #[cfg(target_arch = "x86_64")]
    {
        let features = FeatureDetector::instance();
        let full = features.features_full();
        // SAFETY: Runtime feature detection matches the callee's `#[target_feature]`.
        // Both callees validate `buf.len()` internally before raw pointer reads.
        if full.bmi2 {
            return unsafe { super::x86::varint_decode_bmi2(buf) };
        }
        if full.sse2 {
            if let Some(res) = unsafe { super::x86::varint_decode_sse2_prefast(buf) } {
                return Some(res);
            }
        }
    }

    scalar::decode_varint(buf)
}

/// QUIC packet header validation with SIMD acceleration when available.
#[inline(always)]
pub fn validate_header(header: &[u8]) -> bool {
    if header.len() < 5 {
        return false;
    }

    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. The `header.len() >= 5` guard above ensures
    // the header is non-empty. All callees only read from `header` and return bool.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        if full.avx512f {
            return unsafe { crate::simd::x86_header::validate_header_avx512(header) };
        }
        if full.simd_dispatch_matrix().avx2 {
            return unsafe { super::x86::validate_header_avx2(header) };
        }
        if full.sse2 {
            return unsafe { super::x86::validate_header_sse2(header) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            return unsafe { super::arm::validate_header_sve2(header) };
        }
        if full.neon {
            return unsafe { super::arm::validate_header_neon(header) };
        }
    }

    scalar::validate_header(header)
}
