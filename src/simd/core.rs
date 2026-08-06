//! Extracted SIMD `core` submodule (TODO-563).

use super::*;

/// XOR blocks - up to 64 bytes at once
#[inline(always)]
pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by a runtime feature check that matches
    // the `#[target_feature]` attribute on the callee. The callees operate on
    // the provided slices and do not require additional pointer invariants
    // beyond what the borrow checker already guarantees.
    #[cfg(target_arch = "x86_64")]
    {
        let full = features.features_full();
        if full.avx512f {
            unsafe { super::x86::xor_blocks_avx512(dst, src) };
            return;
        }
        if full.simd_dispatch_matrix().avx2 {
            unsafe { super::x86::xor_blocks_avx2(dst, src) };
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            unsafe { arm::xor_blocks_sve2(dst, src) };
            return;
        }
        if full.neon {
            unsafe { arm::xor_blocks_neon(dst, src) };
            return;
        }
    }

    scalar::xor_blocks(dst, src)
}

/// IEEE CRC-32 with hardware acceleration where the instruction polynomial matches.
#[inline(always)]
pub fn crc32(data: &[u8], initial: u32) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        let features = FeatureDetector::instance();
        if features.features_full().crc32 {
            // SAFETY: Runtime feature detection matches the callee's target feature.
            // The ARM CRC32 instructions implement the IEEE polynomial used here.
            return unsafe { arm::crc32_arm(data, initial) };
        }
    }

    // x86 SSE4.2 CRC instructions implement CRC32C (Castagnoli), not IEEE CRC-32.
    scalar::crc32(data, initial)
}

/// Population count
#[inline(always)]
pub fn popcnt(data: &[u8]) -> usize {
    let features = FeatureDetector::instance();

    // SAFETY: Runtime feature check matches the callee's `#[target_feature]`.
    // All callees only read `data` and return a count - no pointer invariants.
    #[cfg(target_arch = "x86_64")]
    if features.features_full().popcnt {
        return unsafe { super::x86::popcnt_hw(data) };
    }

    #[cfg(target_arch = "aarch64")]
    {
        let full = features.features_full();
        if full.sve2 {
            return unsafe { arm::popcnt_sve2(data) };
        }
        if full.neon {
            return unsafe { arm::popcnt_neon(data) };
        }
    }

    scalar::popcnt(data)
}
