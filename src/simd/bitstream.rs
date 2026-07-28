//! Extracted SIMD `bitstream` submodule (TODO-563).

use super::*;

/// Pack bits with BMI2 acceleration when available.
#[inline(always)]
pub fn pack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    if !(1..=8).contains(&bit_width) {
        return 0;
    }

    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. Callees read from `src` and write to `dst`
    // with internal bounds tracking to prevent out-of-bounds access.
    #[cfg(target_arch = "x86_64")]
    {
        if features.has_feature(CpuFeature::BMI2) {
            return unsafe { super::x86::pack_bits_bmi2(src, bit_width, dst) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.has_feature(CpuFeature::SVE2) {
            return unsafe { super::arm::pack_bits_sve2(src, bit_width, dst) };
        }
        if features.has_feature(CpuFeature::NEON) {
            return unsafe { super::arm::pack_bits_neon(src, bit_width, dst) };
        }
    }

    scalar::pack_bits(src, bit_width, dst)
}

/// Unpack bits with BMI2 acceleration when available.
#[inline(always)]
pub fn unpack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
    if !(1..=8).contains(&bit_width) {
        return 0;
    }

    let features = FeatureDetector::instance();

    // SAFETY: Each branch is guarded by runtime feature detection matching the
    // callee's `#[target_feature]`. Callees track bit/byte positions internally.
    #[cfg(target_arch = "x86_64")]
    {
        if features.has_feature(CpuFeature::BMI2) {
            return unsafe { super::x86::unpack_bits_bmi2(src, bit_width, dst) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if features.has_feature(CpuFeature::SVE2) {
            return unsafe { super::arm::unpack_bits_sve2(src, bit_width, dst) };
        }
        if features.has_feature(CpuFeature::NEON) {
            return unsafe { super::arm::unpack_bits_neon(src, bit_width, dst) };
        }
    }

    scalar::unpack_bits(src, bit_width, dst)
}
