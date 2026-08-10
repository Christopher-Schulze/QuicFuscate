//! ARM NEON-optimized QUIC varint encoding/decoding
//! Uses NEON vtbl for fast table lookups

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

/// NEON-optimized QUIC varint encoding
/// Uses vtbl for length determination and bit manipulation
///
/// # Safety
/// Caller must ensure NEON target feature is available at runtime.
/// The function validates `buf.len() >= len` before any NEON store,
/// so pointer arithmetic stays within the slice allocation.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn encode_varint_neon_impl(mut val: u64, buf: &mut [u8]) -> usize {
    // Determine length (same logic as scalar)
    let (len, prefix): (usize, u8) = if val < (1u64 << 6) {
        (1, 0b00)
    } else if val < (1u64 << 14) {
        (2, 0b01)
    } else if val < (1u64 << 30) {
        (4, 0b10)
    } else if val < (1u64 << 62) {
        (8, 0b11)
    } else {
        return 0;
    };

    if buf.len() < len {
        return 0;
    }

    // NEON optimization for 2/4/8 byte cases
    match len {
        1 => {
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        2 => {
            // SAFETY: `buf.len() >= 2` checked above. The temporary array is stack-local
            // with 8 bytes, so `vld1_u8` reads 8 valid bytes. `vst1_lane_u16` writes
            // exactly 2 bytes to `buf`, which is within bounds.
            val &= (1u64 << 14) - 1;
            let bytes = val.to_be_bytes();
            let vec = vld1_u8([(prefix << 6) | bytes[6], bytes[7], 0, 0, 0, 0, 0, 0].as_ptr());
            vst1_lane_u16::<0>(buf.as_mut_ptr() as *mut u16, vreinterpret_u16_u8(vec));
        }
        4 => {
            // SAFETY: `buf.len() >= 4` checked above. The 16-byte array literal is
            // stack-local, so `vld1q_u8` reads 16 valid bytes. `vst1q_lane_u32`
            // writes exactly 4 bytes to `buf`, which is within bounds.
            val &= (1u64 << 30) - 1;
            let bytes = val.to_be_bytes();
            let vec = vld1q_u8(
                [
                    (prefix << 6) | bytes[4],
                    bytes[5],
                    bytes[6],
                    bytes[7],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
                .as_ptr(),
            );
            vst1q_lane_u32::<0>(buf.as_mut_ptr() as *mut u32, vreinterpretq_u32_u8(vec));
        }
        8 => {
            // SAFETY: `buf.len() >= 8` checked above. The 16-byte array literal is
            // stack-local, so `vld1q_u8` reads 16 valid bytes. `vst1q_lane_u64`
            // writes exactly 8 bytes to `buf`, which is within bounds.
            val &= (1u64 << 62) - 1;
            let bytes = val.to_be_bytes();
            let vec = vld1q_u8(
                [
                    (prefix << 6) | bytes[0],
                    bytes[1],
                    bytes[2],
                    bytes[3],
                    bytes[4],
                    bytes[5],
                    bytes[6],
                    bytes[7],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ]
                .as_ptr(),
            );
            vst1q_lane_u64::<0>(buf.as_mut_ptr() as *mut u64, vreinterpretq_u64_u8(vec));
        }
        _ => {
            debug_assert!(false, "invalid varint encoded length");
            return 0;
        }
    }
    len
}

/// SVE2-optimized QUIC varint encoding (VL-scalable)
///
/// # Safety
/// Caller must ensure SVE2 target feature is available at runtime.
/// Buffer length is validated before each SVE store, so writes
/// stay within the slice allocation.
#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn encode_varint_sve2_impl(mut val: u64, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    let (len, prefix): (usize, u8) = if val < (1u64 << 6) {
        (1, 0b00)
    } else if val < (1u64 << 14) {
        (2, 0b01)
    } else if val < (1u64 << 30) {
        (4, 0b10)
    } else if val < (1u64 << 62) {
        (8, 0b11)
    } else {
        return 0;
    };

    if buf.len() < len {
        return 0;
    }

    match len {
        1 => {
            buf[0] = (prefix << 6) | (val as u8 & 0x3F);
        }
        2 => {
            // SAFETY: `buf.len() >= 2` checked above. The predicate `pg` activates
            // exactly 1 u16 lane, so `svst1_u16` writes 2 bytes within bounds.
            // Alignment is not required for SVE predicated stores.
            val &= (1u64 << 14) - 1;
            let encoded = (((prefix as u16) << 14) | (val as u16)).to_be();
            let lane = svdup_n_u16(encoded);
            let pg = svwhilelt_b16(0_u64, 1_u64);
            svst1_u16(pg, buf.as_mut_ptr() as *mut u16, lane);
        }
        4 => {
            // SAFETY: `buf.len() >= 4` checked above. The predicate activates 1 u32
            // lane, so `svst1_u32` writes 4 bytes within bounds.
            val &= (1u64 << 30) - 1;
            let encoded = (((prefix as u32) << 30) | (val as u32)).to_be();
            let lane = svdup_n_u32(encoded);
            let pg = svwhilelt_b32(0_u64, 1_u64);
            svst1_u32(pg, buf.as_mut_ptr() as *mut u32, lane);
        }
        8 => {
            // SAFETY: `buf.len() >= 8` checked above. The predicate activates 1 u64
            // lane, so `svst1_u64` writes 8 bytes within bounds.
            val &= (1u64 << 62) - 1;
            let encoded = (((prefix as u64) << 62) | val).to_be();
            let lane = svdup_n_u64(encoded);
            let pg = svwhilelt_b64(0_u64, 1_u64);
            svst1_u64(pg, buf.as_mut_ptr() as *mut u64, lane);
        }
        _ => {
            debug_assert!(false, "invalid varint encoded length");
            return 0;
        }
    }

    len
}

/// NEON-optimized QUIC varint decoding
/// Uses vtbl for efficient byte extraction
///
/// # Safety
/// Caller must ensure NEON target feature is available at runtime.
/// All NEON loads use bounded temporaries (`copy_from_slice` into stack arrays),
/// so no out-of-bounds pointer access occurs.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn decode_varint_neon_impl(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }

    let first = buf[0];
    let prefix = first >> 6;

    let len = match prefix {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => {
            debug_assert!(false, "invalid QUIC varint prefix");
            return None;
        }
    };

    if buf.len() < len {
        return None;
    }

    let val = match len {
        1 => (first & 0x3F) as u64,
        2 => {
            // NEON 2-byte extract with bounded load
            let mut tmp = [0u8; 8];
            tmp[..2].copy_from_slice(&buf[..2]);
            let vec = vld1_u8(tmp.as_ptr());
            let shifted = vreinterpret_u16_u8(vec);
            let raw = vget_lane_u16::<0>(shifted);
            let val = u16::from_be(raw) & 0x3FFF;
            val as u64
        }
        4 => {
            // NEON 4-byte extract with bounded load
            let mut tmp = [0u8; 16];
            tmp[..4].copy_from_slice(&buf[..4]);
            let vec = vld1q_u8(tmp.as_ptr());
            let shifted = vreinterpretq_u32_u8(vec);
            let raw = vgetq_lane_u32::<0>(shifted);
            let val = u32::from_be(raw) & 0x3FFFFFFF;
            val as u64
        }
        8 => {
            // NEON 8-byte extract with bounded load
            let mut tmp = [0u8; 16];
            tmp[..8].copy_from_slice(&buf[..8]);
            let vec = vld1q_u8(tmp.as_ptr());
            let shifted = vreinterpretq_u64_u8(vec);
            let raw = vgetq_lane_u64::<0>(shifted);
            u64::from_be(raw) & 0x3FFFFFFFFFFFFFFF
        }
        _ => {
            debug_assert!(false, "invalid varint encoded length");
            return None;
        }
    };

    Some((val, len))
}

/// SVE2-optimized QUIC varint decoding (VL-scalable)
///
/// # Safety
/// Caller must ensure SVE2 target feature is available at runtime.
/// `buf.len() >= len` is checked before each SVE load. The predicate
/// restricts the load to exactly 1 element, so reads stay in bounds.
/// Casting `buf.as_ptr()` to wider integer pointer types relies on the
/// SVE load being predicated (only 1 active lane), so alignment does
/// not matter for correctness on AArch64.
#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn decode_varint_sve2_impl(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }

    let first = buf[0];
    let prefix = first >> 6;

    let len = match prefix {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => {
            debug_assert!(false, "invalid QUIC varint prefix");
            return None;
        }
    };

    if buf.len() < len {
        return None;
    }

    let value = match len {
        1 => (first & 0x3F) as u64,
        2 => {
            let pg = svwhilelt_b16(0_u64, 1_u64);
            let data = svld1_u16(pg, buf.as_ptr() as *const u16);
            let raw = svlasta_u16(pg, data);
            (u16::from_be(raw) & 0x3FFF) as u64
        }
        4 => {
            let pg = svwhilelt_b32(0_u64, 1_u64);
            let data = svld1_u32(pg, buf.as_ptr() as *const u32);
            let raw = svlasta_u32(pg, data);
            (u32::from_be(raw) & 0x3FFF_FFFF) as u64
        }
        8 => {
            let pg = svwhilelt_b64(0_u64, 1_u64);
            let data = svld1_u64(pg, buf.as_ptr() as *const u64);
            let raw = svlasta_u64(pg, data);
            u64::from_be(raw) & ((1u64 << 62) - 1)
        }
        _ => {
            debug_assert!(false, "invalid varint encoded length");
            return None;
        }
    };

    Some((value, len))
}

#[inline(always)]
pub(crate) fn encode_varint_neon(val: u64, buf: &mut [u8]) -> usize {
    // SAFETY: This module is compiled only on aarch64 where NEON is baseline.
    // The impl function validates buffer length before writing.
    unsafe { encode_varint_neon_impl(val, buf) }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
pub(crate) fn encode_varint_sve2(val: u64, buf: &mut [u8]) -> usize {
    // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl validates
    // buffer length before any SVE store instruction.
    unsafe { encode_varint_sve2_impl(val, buf) }
}

#[inline(always)]
pub(crate) fn decode_varint_neon(buf: &[u8]) -> Option<(u64, usize)> {
    // SAFETY: This module is compiled only on aarch64 where NEON is baseline.
    // The impl function validates buffer length before any NEON load and uses
    // bounded stack copies to avoid out-of-bounds reads.
    unsafe { decode_varint_neon_impl(buf) }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[inline(always)]
pub(crate) fn decode_varint_sve2(buf: &[u8]) -> Option<(u64, usize)> {
    // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl validates
    // buffer length before any SVE predicated load.
    unsafe { decode_varint_sve2_impl(buf) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_neon_varint_roundtrip() {
        let test_values = [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1u64 << 62) - 1];

        for &val in &test_values {
            let mut buf = [0u8; 8];
            let encoded_len = encode_varint_neon(val, &mut buf);
            assert!(encoded_len > 0, "Encoding failed for {}", val);

            let decoded = decode_varint_neon(&buf);
            assert!(decoded.is_some(), "Decoding failed for {}", val);

            let (decoded_val, decoded_len) = decoded.unwrap();
            assert_eq!(decoded_val, val, "Value mismatch for {}", val);
            assert_eq!(decoded_len, encoded_len, "Length mismatch for {}", val);
        }
    }

    #[test]
    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    fn test_sve2_varint_roundtrip() {
        let test_values = [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, (1u64 << 62) - 1];

        for &val in &test_values {
            let mut buf = [0u8; 8];
            let encoded_len = encode_varint_sve2(val, &mut buf);
            assert!(encoded_len > 0, "Encoding failed for {}", val);

            let decoded = decode_varint_sve2(&buf);
            assert!(decoded.is_some(), "Decoding failed for {}", val);

            let (decoded_val, decoded_len) = decoded.unwrap();
            assert_eq!(decoded_val, val, "Value mismatch for {}", val);
            assert_eq!(decoded_len, encoded_len, "Length mismatch for {}", val);
        }
    }
}
