//! Extracted SIMD `transport` submodule (TODO-563).

use super::*;

/// Encode QUIC variable-length integer into buf; returns bytes used.
/// Encoding per RFC 9000: 00=1 byte (6 bits), 01=2 bytes (14 bits),
/// 10=4 bytes (30 bits), 11=8 bytes (62 bits). Big-endian.
#[inline(always)]
pub fn encode_varint(val: u64, buf: &mut [u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
        // Callees validate `buf.len()` and return `None` if too short.
        let features = FeatureDetector::instance();
        if features.has_feature(CpuFeature::AVX512F) {
            if let Some(len) = unsafe { super::x86::encode_varint_avx512(val, buf) } {
                return len;
            }
        }
        if features.has_feature(CpuFeature::AVX2) {
            if let Some(len) = unsafe { super::x86::encode_varint_avx2(val, buf) } {
                return len;
            }
        }
        if features.has_feature(CpuFeature::SSE2) {
            if let Some(len) = unsafe { super::x86::encode_varint_sse2(val, buf) } {
                return len;
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance();
        if features.has_feature(CpuFeature::SVE2) {
            #[cfg(target_feature = "sve2")]
            {
                return crate::simd::arm_varint::encode_varint_sve2(val, buf);
            }
        }
        if features.has_feature(CpuFeature::NEON) {
            #[cfg(target_feature = "neon")]
            {
                return crate::simd::arm_varint::encode_varint_neon(val, buf);
            }
        }
    }

    encode_varint_scalar(val, buf)
}

#[inline(always)]
fn encode_varint_scalar(val: u64, buf: &mut [u8]) -> usize {
    let (len, prefix) = match quic_varint_len_prefix(val) {
        Some(lp) => lp,
        None => return 0,
    };

    if buf.len() < len {
        return 0;
    }

    let mut bytes = val.to_be_bytes();
    let start = 8 - len;
    bytes[start] = (bytes[start] & 0x3F) | (prefix << 6);
    buf[..len].copy_from_slice(&bytes[start..start + len]);
    len
}

/// Decode QUIC variable-length integer; returns (value, bytes used).
#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    crate::simd::arm_varint::decode_varint_sve2(buf)
}

/// Decode QUIC variable-length integer using NEON (aarch64 without SVE2).
#[cfg(all(target_arch = "aarch64", not(target_feature = "sve2"), target_feature = "neon"))]
#[inline(always)]
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    crate::simd::arm_varint::decode_varint_neon(buf)
}

/// Decode QUIC variable-length integer (scalar fallback for non-NEON targets).
#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
#[inline(always)]
pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => {
            debug_assert!(false, "invalid QUIC varint prefix");
            return None;
        }
    };
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3F) as u64;
    for byte in buf.iter().take(len).skip(1) {
        value = (value << 8) | (*byte as u64);
    }
    Some((value, len))
}
