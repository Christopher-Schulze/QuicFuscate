//! optimize::simd::core (TODO-563).

use super::super::telemetry;
use super::super::{FeatureDetector, SimdDispatch};

/// Central XOR blocks implementation - used by FEC, Crypto, everywhere!
#[inline(always)]
pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
    SimdDispatch::xor_blocks(dst, src);
}

/// Central population count - used for statistics, pattern matching
#[inline(always)]
pub fn popcnt(data: &[u8]) -> usize {
    SimdDispatch::popcnt(data)
}

/// IEEE CRC-32 computation with hardware acceleration where the polynomial matches.
#[inline(always)]
pub fn crc32(data: &[u8], initial: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance().features_full();
        if features.crc32 {
            // SAFETY: Runtime feature detection matches the callee's target feature.
            // ARM's CRC32 instructions implement the IEEE polynomial used here.
            return unsafe { crc32_armv8(data, initial) };
        }
    }

    // x86 SSE4.2 CRC instructions implement CRC32C (Castagnoli), not IEEE CRC-32.
    crc32_scalar(data, initial)
}

/// Ultra-fast CRC32 with ARMv8 CRC32 instructions (aarch64)
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
/// # Safety
///
/// The caller must execute this function only when the AArch64 CRC extension
/// is available. `data` must remain a valid immutable slice for the duration of
/// the call; all fixed-width reads are guarded before conversion.
unsafe fn crc32_armv8(data: &[u8], mut crc: u32) -> u32 {
    use std::arch::aarch64::*;

    crc = !crc; // CRC32 uses inverted initial value
    let mut i = 0;
    let len = data.len();

    // Process 8 bytes at a time with CRC32X instruction
    while i + 8 <= len {
        let chunk = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        crc = __crc32d(crc, chunk);
        i += 8;
    }

    // Process 4 bytes
    if i + 4 <= len {
        let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        crc = __crc32w(crc, chunk);
        i += 4;
    }

    // Process 2 bytes
    if i + 2 <= len {
        let chunk = u16::from_le_bytes([data[i], data[i + 1]]);
        crc = __crc32h(crc, chunk);
        i += 2;
    }

    // Process remaining byte
    if i < len {
        crc = __crc32b(crc, data[i]);
    }

    telemetry::CRC32_ARM_OPS.inc();
    !crc // Return with final inversion
}

/// Scalar CRC32 fallback implementation
#[inline(always)]
fn crc32_scalar(data: &[u8], mut crc: u32) -> u32 {
    // CRC32 polynomial: 0x04C11DB7 (Ethernet, PNG, etc.)
    const CRC32_TABLE: [u32; 256] = generate_crc32_table();

    crc = !crc; // CRC32 uses inverted initial value

    for &byte in data {
        let table_idx = ((crc ^ byte as u32) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[table_idx];
    }

    telemetry::CRC32_SCALAR_OPS.inc();
    !crc // Return with final inversion
}

/// Generate CRC32 lookup table at compile time
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;

    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;

        while j < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320; // Reversed polynomial
            } else {
                crc >>= 1;
            }
            j += 1;
        }

        table[i] = crc;
        i += 1;
    }

    table
}
