use std::sync::atomic::Ordering;

use super::CPU_FEATURE_MASK;

pub(crate) const CPU_MASK_SSE2: i64 = 1 << 0;
const CPU_MASK_SSSE3: i64 = 1 << 1;
const CPU_MASK_SSE42: i64 = 1 << 2;
const CPU_MASK_AVX: i64 = 1 << 3;
pub(crate) const CPU_MASK_AVX2: i64 = 1 << 4;
pub(crate) const CPU_MASK_AVX512: i64 = 1 << 5;
const CPU_MASK_VAES: i64 = 1 << 6;
pub(crate) const CPU_MASK_GFNI: i64 = 1 << 7;
const CPU_MASK_AVX10_256: i64 = 1 << 8;
pub(crate) const CPU_MASK_AVX10_512: i64 = 1 << 9;
pub(crate) const CPU_MASK_NEON: i64 = 1 << 10;
const CPU_MASK_AES: i64 = 1 << 11;
const CPU_MASK_PMULL: i64 = 1 << 12;
const CPU_MASK_SVE2: i64 = 1 << 13;
// Apple Silicon profile metadata only; this bit is not proof of active AMX arithmetic.
const CPU_MASK_APPLE_AMX: i64 = 1 << 14;
pub(crate) const CPU_MASK_RVV: i64 = 1 << 15;
pub(crate) const CPU_MASK_SCALAR: i64 = 1 << 16;

/// Stable profile identifiers used by the telemetry boundary.
///
/// The optimizer owns the richer runtime `CpuProfile` enum. Telemetry only needs the stable
/// identity used in its exported bitmask, so the child crate keeps this compact, dependency-free
/// representation and the root adapter performs the conversion.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CpuProfileId {
    Scalar = 1,
    X86_P0a = 2,
    X86_P0b = 3,
    X86_P1a = 4,
    X86_P1b = 5,
    X86_P1f = 6,
    X86_P2a = 7,
    X86_P2b = 8,
    X86_P3a = 9,
    X86_P3b = 10,
    X86_P3c = 11,
    X86_P3d = 12,
    X86_P3e = 13,
    X86_P4a = 14,
    X86_P4b = 15,
    ARM_A0 = 16,
    ARM_A1a = 17,
    ARM_A1b = 18,
    ARM_A1c = 19,
    ARM_A1d = 20,
    ARM_A2 = 21,
    Apple_M = 22,
    RVV = 23,
}

/// Convert a stable profile identifier to a bitmask of CPU feature flags.
pub fn cpu_profile_mask_for_id(profile: CpuProfileId) -> i64 {
    match profile {
        CpuProfileId::X86_P0a => CPU_MASK_SSE2,
        CpuProfileId::X86_P0b => CPU_MASK_SSE2 | CPU_MASK_SSSE3,
        CpuProfileId::X86_P1a => CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42,
        CpuProfileId::X86_P1b => CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42 | CPU_MASK_AES,
        CpuProfileId::X86_P1f => {
            CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42 | CPU_MASK_AES | CPU_MASK_AVX
        }
        CpuProfileId::X86_P2a | CpuProfileId::X86_P2b => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
        }
        CpuProfileId::X86_P3a => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
        }
        CpuProfileId::X86_P3b | CpuProfileId::X86_P3c | CpuProfileId::X86_P3d => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_VAES
        }
        CpuProfileId::X86_P3e => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_VAES
                | CPU_MASK_GFNI
        }
        CpuProfileId::X86_P4a => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX10_256
        }
        CpuProfileId::X86_P4b => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_AVX10_256
                | CPU_MASK_AVX10_512
        }
        CpuProfileId::ARM_A0 | CpuProfileId::ARM_A1a => CPU_MASK_NEON,
        CpuProfileId::ARM_A1b => CPU_MASK_NEON | CPU_MASK_AES,
        CpuProfileId::ARM_A1c | CpuProfileId::ARM_A1d => {
            CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL
        }
        CpuProfileId::ARM_A2 => CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL | CPU_MASK_SVE2,
        CpuProfileId::Apple_M => CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL | CPU_MASK_APPLE_AMX,
        CpuProfileId::RVV => CPU_MASK_RVV,
        CpuProfileId::Scalar => CPU_MASK_SCALAR,
    }
}

/// Compute and publish a stable CPU profile mask to the global telemetry gauge.
pub fn publish_cpu_profile_mask_for_id(profile: CpuProfileId) -> i64 {
    let mask = cpu_profile_mask_for_id(profile);
    CPU_FEATURE_MASK.store(mask, Ordering::Relaxed);
    mask
}
