//! CPU feature detection, cache-aware dispatch, and low-level SIMD policy contracts.
//!
//! This workspace leaf owns runtime hardware capability observation and the pure policy
//! selectors consumed by crypto, FEC, transport, and optimization code. It has no dependency on
//! any product subsystem; environment values and metrics cross the boundary through qf-common
//! and qf-telemetry.

use log::warn;
use qf_common::env_utils::EnvSnapshot;
use qf_telemetry as telemetry;
use std::any::Any;
#[cfg(any(test, feature = "rust-tests"))]
use std::cell::RefCell;
use std::collections::HashSet;

/// The active AMX arithmetic implementation is intentionally fail-closed until TODO-818 lands
/// with verified instruction, tile-state, and parity evidence.
pub const VERIFIED_BACKEND: bool = false;

/// Configuration for optimization parameters passed from the CLI.
#[derive(Clone, Copy)]
pub struct OptimizeConfig {
    /// Maximum number of pooled memory blocks.
    pub pool_capacity: usize,
    /// Size of each pooled block in bytes.
    pub block_size: usize,
}

impl Default for OptimizeConfig {
    fn default() -> Self {
        Self { pool_capacity: 512, block_size: 65536 }
    }
}

impl OptimizeConfig {
    /// Validate configuration parameters, returning an error on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if self.pool_capacity == 0 {
            return Err("pool_capacity must be > 0".into());
        }
        if self.block_size == 0 {
            return Err("block_size must be > 0".into());
        }
        Ok(())
    }
}

/// Unified AEAD plan for the data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAeadPlan {
    /// Single-lane AEGIS-128L (best for small payloads).
    Aegis128L,
    /// Four-lane parallel AEGIS-128L (mid-size payloads, requires AES-NI or NEON-AES).
    Aegis128X4,
    /// Eight-lane parallel AEGIS-128L (large payloads, requires VAES + AVX2/AVX-512).
    Aegis128X8,
    /// MORUS-1280-128 fallback when hardware AES is unavailable.
    Morus,
}

/// Representative 1-RTT payload length used by the AEAD planner.
pub const DEFAULT_DATA_PLANE_AEAD_LEN: usize = 1400;

/// Count ASCII printable bytes (`0x20..=0x7E`) with the scalar implementation.
#[inline(always)]
pub fn count_ascii_printable(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| matches!(byte, 0x20..=0x7E)).count()
}

/// Runtime-dispatched ASCII append and integer formatting.
pub mod ascii;
/// SIMD byte classification for compression preprocessing.
pub mod compression;
/// SIMD-accelerated iterator reductions.
pub mod iter;
/// Hardware-aware acceleration planner.
pub mod planner;
/// Compatibility profile aliases for the AEAD planner.
pub mod profile;
/// SIMD histograms and pattern search for compression heuristics.
pub mod simd_compress;
/// SIMD-aware sorting and argsort helpers.
pub mod sort;
/// Runtime-accelerated substring search.
pub mod string;
/// SIMD-accelerated transport aggregation and packet-number helpers.
pub mod transport;

impl CryptoAeadPlan {
    /// Profile-based default (no message length), used when size is unknown.
    pub fn select() -> Self {
        if Self::morus_forced() {
            return Self::record_selection(Self::Morus, false);
        }

        let plans = planner::AccelerationPlanner::global();
        Self::record_selection(plans.crypto_default_aead(), false)
    }

    /// Full heuristic with message length thresholds.
    pub fn select_for_len(len: usize) -> Self {
        if Self::morus_forced() {
            return Self::record_selection(Self::Morus, true);
        }

        let plans = planner::AccelerationPlanner::global();
        Self::record_selection(plans.crypto_aead_for_len(len), true)
    }

    fn morus_forced() -> bool {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            if let Ok(value) = std::env::var("QUICFUSCATE_MORUS") {
                let value = value.to_ascii_lowercase();
                return value == "1" || value == "true" || value == "force";
            }
            false
        }
        #[cfg(not(any(test, feature = "rust-tests")))]
        {
            false
        }
    }

    #[inline(always)]
    fn record_selection(plan: Self, len_based: bool) -> Self {
        telemetry::PLAN_DECISIONS_TOTAL.inc();
        if len_based {
            telemetry::PLAN_DECISIONS_LEN.inc();
        } else {
            telemetry::PLAN_DECISIONS_DEFAULT.inc();
        }
        match plan {
            Self::Aegis128L => telemetry::PLAN_DECISIONS_L.inc(),
            Self::Aegis128X4 => {
                telemetry::PLAN_DECISIONS_L.inc();
                telemetry::PLAN_DECISIONS_X4.inc();
                #[cfg(target_arch = "aarch64")]
                telemetry::PLAN_DECISIONS_NEON_L.inc();
            }
            Self::Aegis128X8 => {
                telemetry::PLAN_DECISIONS_L.inc();
                telemetry::PLAN_DECISIONS_X8.inc();
            }
            Self::Morus => telemetry::PLAN_DECISIONS_MORUS.inc(),
        }
        plan
    }
}

/// Hint type for cache prefetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefetchHint {
    /// Hint the line into the closest cache (L1).
    T0,
    /// Hint the line into the next cache level (L2).
    T1,
}

/// Issue a best-effort hardware prefetch for the supplied pointer.
///
/// # Contract
///
/// This is a pure hint and never a load. Every supported lane compiles to a genuinely
/// non-faulting instruction: `PRFM PLDL1KEEP` on AArch64 and `PREFETCHh` through `_mm_prefetch`
/// on x86_64. Both are architecturally defined to have no effect other than a possible cache
/// line fill, and neither signals on an unmapped, unaligned, or permission-denied address.
/// Unsupported architectures compile to nothing.
///
/// Callers therefore do not owe a readable span. `ptr` may be dangling, one past the end of an
/// allocation, or derived from an empty slice. The null check is a cheap filter for the common
/// uninitialised case, not a safety requirement.
///
/// What callers still owe is provenance discipline for the pointer arithmetic that produced
/// `ptr`: computing an out-of-bounds address with `ptr::add` is undefined regardless of what this
/// function does with the result. Offset and allocation-lifetime proof stays with each caller and
/// its owner, and this facade deliberately makes no claim about it.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[cfg_attr(feature = "aggressive_inline", inline(always))]
pub fn prefetch(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(feature = "prefetch")]
    {
        if ptr.is_null() {
            return;
        }
        unsafe { prefetch_impl(ptr, hint) };
    }
    #[cfg(not(feature = "prefetch"))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

/// # Safety
///
/// `ptr` must be a pointer value the caller was allowed to compute. It does not need to be
/// readable, aligned, or inside a live allocation: every lane below emits a non-faulting hint
/// instruction rather than a load, so no memory is accessed through it. See [`prefetch`] for the
/// full contract.
#[cfg(feature = "prefetch")]
#[cfg_attr(feature = "aggressive_inline", inline(always))]
unsafe fn prefetch_impl(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0, _MM_HINT_T1};
        match hint {
            PrefetchHint::T0 => _mm_prefetch::<_MM_HINT_T0>(ptr as *const i8),
            PrefetchHint::T1 => _mm_prefetch::<_MM_HINT_T1>(ptr as *const i8),
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        core::arch::asm!(
            "prfm pldl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        let _ = hint;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

// ============================================================================
// CPU FEATURE DETECTION SYSTEM
// ============================================================================

/// Complete CPU feature set for ALL platforms - MAXIMALE COVERAGE!
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    /// x86_64: SSE2 (128-bit integer SIMD).
    pub sse2: bool,
    /// x86_64: SSE3 (horizontal ops, complex arithmetic).
    pub sse3: bool,
    /// x86_64: Supplemental SSE3 (shuffle, alignment).
    pub ssse3: bool,
    /// x86_64: SSE4.1 (blend, round, insert/extract).
    pub sse41: bool,
    /// x86_64: SSE4.2 (string compare, CRC32).
    pub sse42: bool,
    /// x86_64: Population count instruction.
    pub popcnt: bool,
    /// x86_64: Leading zero count instruction.
    pub lzcnt: bool,

    /// x86_64: AVX (256-bit float SIMD).
    pub avx: bool,
    /// x86_64: AVX2 (256-bit integer SIMD).
    pub avx2: bool,
    /// x86_64: Fused multiply-add (3 operand).
    pub fma3: bool,
    /// x86_64: Bit manipulation instructions set 1.
    pub bmi1: bool,
    /// x86_64: Bit manipulation instructions set 2.
    pub bmi2: bool,

    /// x86_64: AVX-512 Foundation (512-bit SIMD).
    pub avx512f: bool,
    /// x86_64: AVX-512 Byte and Word operations.
    pub avx512bw: bool,
    /// x86_64: AVX-512 Conflict Detection.
    pub avx512cd: bool,
    /// x86_64: AVX-512 Doubleword and Quadword operations.
    pub avx512dq: bool,
    /// x86_64: AVX-512 Vector Length extensions.
    pub avx512vl: bool,
    /// x86_64: AVX-512 Vector Byte Manipulation.
    pub avx512vbmi: bool,
    /// x86_64: AVX-512 Vector Byte Manipulation 2.
    pub avx512vbmi2: bool,
    /// x86_64: AVX-512 Vector Neural Network Instructions.
    pub avx512vnni: bool,
    /// x86_64: AVX-512 Vector Population Count DW/QW.
    pub avx512vpopcntdq: bool,
    /// x86_64: AVX10.1 support projected onto the legacy 256-bit flag.
    pub avx10_1_256: bool,
    /// x86_64: AVX10.1 support projected onto the legacy 512-bit flag.
    pub avx10_1_512: bool,

    /// x86_64: AVX-512 BFloat16 instructions.
    pub avx512bf16: bool,
    /// x86_64: AVX-512 FP16 instructions.
    pub avx512fp16: bool,
    /// x86_64: AVX Vector Neural Network Instructions (non-512).
    pub avx_vnni: bool,
    /// x86_64: Advanced Matrix Extensions tile control.
    pub amx_tile: bool,
    /// x86_64: AMX INT8 matrix multiply.
    pub amx_int8: bool,
    /// x86_64: AMX BFloat16 matrix multiply.
    pub amx_bf16: bool,

    /// x86_64: AES-NI hardware encryption.
    pub aesni: bool,
    /// x86_64: Vector AES (256/512-bit parallel AES).
    pub vaes: bool,
    /// x86_64: Vector CLMUL (256/512-bit carry-less multiply).
    pub vpclmulqdq: bool,
    /// x86_64: Scalar-width carry-less multiply.
    pub pclmulqdq: bool,
    /// x86_64: SHA-1/SHA-256 hardware acceleration.
    pub sha: bool,
    /// x86_64: Galois Field New Instructions (GF(2^8) native).
    pub gfni: bool,
    /// x86_64: Hardware random number generator.
    pub rdrand: bool,
    /// x86_64: Hardware random seed generator.
    pub rdseed: bool,

    /// ARM64: NEON SIMD (128-bit).
    pub neon: bool,
    /// ARM64: CRC32 hardware acceleration.
    pub crc32: bool,
    /// ARM64: Large System Extensions (atomic ops).
    pub atomics: bool,
    /// ARM64: Half-precision floating point.
    pub fp16: bool,
    /// ARM64: Dot product instructions.
    pub dotprod: bool,

    /// ARM64: AES hardware encryption.
    pub aes: bool,
    /// ARM64: Polynomial multiplication (carry-less multiply).
    pub pmull: bool,
    /// ARM64: SHA-1 hardware acceleration.
    pub sha1: bool,
    /// ARM64: SHA-256 hardware acceleration.
    pub sha2: bool,
    /// ARM64: SHA-3 hardware acceleration.
    pub sha3: bool,
    /// ARM64: SHA-512 hardware acceleration.
    pub sha512: bool,
    /// ARM64: SM3 hash hardware acceleration.
    pub sm3: bool,
    /// ARM64: SM4 cipher hardware acceleration.
    pub sm4: bool,

    /// ARM64: Scalable Vector Extension.
    pub sve: bool,
    /// ARM64: Scalable Vector Extension 2.
    pub sve2: bool,
    /// ARM64: SVE AES instructions.
    pub sve_aes: bool,
    /// ARM64: SVE polynomial multiply.
    pub sve_pmull: bool,
    /// ARM64: SVE bit permutation instructions.
    pub sve_bitperm: bool,

    /// Apple Silicon: platform matrix-capability metadata; no active AMX arithmetic backend.
    pub apple_amx: bool,
    /// Apple Silicon: M1 generation detected.
    pub apple_m1: bool,
    /// Apple Silicon: M2 generation detected.
    pub apple_m2: bool,
    /// Apple Silicon: M3 generation detected.
    pub apple_m3: bool,

    /// RISC-V: Vector extension.
    pub rvv: bool,
    /// RISC-V: Vector Byte/Bit manipulation.
    pub rvv_zvbb: bool,
    /// RISC-V: Vector Carry-less multiply.
    pub rvv_zvbc: bool,
    /// RISC-V: Vector GCM/GMAC.
    pub rvv_zvkg: bool,

    /// L1 data cache size in bytes.
    pub l1d_cache: usize,
    /// L1 instruction cache size in bytes.
    pub l1i_cache: usize,
    /// L2 unified cache size in bytes.
    pub l2_cache: usize,
    /// L3 shared cache size in bytes.
    pub l3_cache: usize,
    /// Cache line size in bytes.
    pub cache_line: usize,
}

/// Exact runtime feature intersections required by SIMD target-feature
/// functions. This matrix deliberately uses only CPU-reported capabilities;
/// callers still need the compiler target-feature contract provided by each
/// callee's `#[target_feature]` annotation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimdFeatureMatrix {
    /// AVX2 integer SIMD.
    pub avx2: bool,
    /// AVX-512 ACK canonicalization: Foundation plus Vector Length.
    pub avx512_ack: bool,
    /// AVX-512 byte/word operations.
    pub avx512_bw: bool,
    /// AVX-512 VBMI byte permutation.
    pub avx512_vbmi: bool,
    /// AVX-512 VBMI2 byte compress/expand operations.
    pub avx512_vbmi2: bool,
    /// AVX-512 vector population count.
    pub avx512_vpopcnt: bool,
    /// SHA-256 VNNI path.
    pub sha256_vnni: bool,
    /// Single-block VAES path delegated to AES-NI.
    pub vaes_aes: bool,
    /// GF(2^16) VPCLMUL path.
    pub gf16_vpclmul: bool,
    /// GF(2^16) PCLMUL path.
    pub gf16_pclmul: bool,
    /// AVX-512 FMA neural path.
    pub neural_avx512: bool,
    /// AVX2 FMA neural path.
    pub neural_avx2: bool,
    /// AVX ChaCha path.
    pub chacha_avx: bool,
    /// Runtime SVE2 availability.
    pub sve2: bool,
    /// Runtime NEON availability.
    pub neon: bool,
}

impl CpuFeatures {
    /// Compute the exact runtime feature intersections used by SIMD dispatch.
    pub fn simd_dispatch_matrix(&self) -> SimdFeatureMatrix {
        SimdFeatureMatrix {
            avx2: self.avx2,
            avx512_ack: self.avx512f && self.avx512vl,
            avx512_bw: self.avx512f && self.avx512bw,
            avx512_vbmi: self.avx512f && self.avx512vbmi,
            avx512_vbmi2: self.avx512f && self.avx512bw && self.avx512vbmi2,
            avx512_vpopcnt: self.avx512f && self.avx512cd && self.avx512vpopcntdq,
            sha256_vnni: self.avx512f && self.avx512vl && self.avx512vnni,
            vaes_aes: self.avx512f && self.vaes && self.aesni && self.sse2,
            gf16_vpclmul: self.avx512f && self.vpclmulqdq && self.sse41,
            gf16_pclmul: self.pclmulqdq && self.sse41,
            neural_avx512: self.avx512f && self.fma3,
            neural_avx2: self.avx2 && self.fma3,
            chacha_avx: self.avx && self.sse41 && self.ssse3,
            sve2: self.sve2,
            neon: self.neon,
        }
    }
}

/// Evidence collected for Intel AMX without enabling a product dispatch path.
///
/// CPU instruction support, OS tile-state permission, compiler target features,
/// and product eligibility are intentionally separate. `None` for
/// `os_tile_state_permitted` means that no platform-specific permission probe
/// has established tile-state access. Product dispatch therefore remains
/// fail-closed until a verified backend and permission proof exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmxCapability {
    /// CPU-reported AMX-TILE support from in-process feature detection.
    pub cpu_tile: bool,
    /// CPU-reported AMX-INT8 support from in-process feature detection.
    pub cpu_int8: bool,
    /// CPU-reported AMX-BF16 support from in-process feature detection.
    pub cpu_bf16: bool,
    /// OS tile-state permission: `Some(true)` proven, `Some(false)` denied,
    /// or `None` not probed.
    pub os_tile_state_permitted: Option<bool>,
    /// Whether AMX-TILE was enabled in the compiler target features.
    pub compiler_target_tile: bool,
    /// Whether AMX-INT8 was enabled in the compiler target features.
    pub compiler_target_int8: bool,
    /// Whether AMX-BF16 was enabled in the compiler target features.
    pub compiler_target_bf16: bool,
    /// Whether the repository contains a verified AMX arithmetic backend.
    pub verified_backend: bool,
    /// Whether the product has a verified, eligible AMX dispatch path.
    pub product_dispatch_eligible: bool,
}

#[derive(Debug, Clone, Copy)]
struct AmxSignals {
    cpu_tile: bool,
    cpu_int8: bool,
    cpu_bf16: bool,
    os_tile_state_permitted: Option<bool>,
    compiler_target_tile: bool,
    compiler_target_int8: bool,
    compiler_target_bf16: bool,
    verified_backend: bool,
}

impl AmxCapability {
    fn from_signals(signals: AmxSignals) -> Self {
        let product_dispatch_eligible = signals.verified_backend
            && signals.cpu_tile
            && signals.cpu_int8
            && signals.compiler_target_tile
            && signals.compiler_target_int8
            && signals.os_tile_state_permitted == Some(true);
        Self {
            cpu_tile: signals.cpu_tile,
            cpu_int8: signals.cpu_int8,
            cpu_bf16: signals.cpu_bf16,
            os_tile_state_permitted: signals.os_tile_state_permitted,
            compiler_target_tile: signals.compiler_target_tile,
            compiler_target_int8: signals.compiler_target_int8,
            compiler_target_bf16: signals.compiler_target_bf16,
            verified_backend: signals.verified_backend,
            product_dispatch_eligible,
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "amx-tile", target_feature = "amx-int8"))]
fn amx_backend_verified() -> bool {
    VERIFIED_BACKEND
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "amx-tile", target_feature = "amx-int8")))]
fn amx_backend_verified() -> bool {
    false
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn probe_amx_os_tile_state(cpu_tile: bool, cpu_int8: bool) -> Option<bool> {
    if !cpu_tile || !cpu_int8 {
        return None;
    }

    // Linux grants AMX tile state to the current thread through arch_prctl.
    // The request is idempotent and does not execute an AMX instruction.
    const ARCH_REQ_XCOMP_PERM: libc::c_long = 0x1023;
    const XFEATURE_XTILEDATA: libc::c_long = 18;
    let result = unsafe {
        libc::syscall(libc::SYS_arch_prctl as libc::c_long, ARCH_REQ_XCOMP_PERM, XFEATURE_XTILEDATA)
    };
    Some(result == 0)
}

#[cfg(all(target_arch = "x86_64", not(target_os = "linux")))]
fn probe_amx_os_tile_state(_cpu_tile: bool, _cpu_int8: bool) -> Option<bool> {
    None
}

#[cfg(any(target_arch = "x86_64", test))]
fn decode_amx_cpuid_leaf7(edx: u32) -> (bool, bool, bool) {
    const AMX_BF16: u32 = 1 << 22;
    const AMX_TILE: u32 = 1 << 24;
    const AMX_INT8: u32 = 1 << 25;

    (edx & AMX_TILE != 0, edx & AMX_INT8 != 0, edx & AMX_BF16 != 0)
}

#[cfg(any(target_arch = "x86_64", test))]
fn decode_avx10_1_support(
    avx10_feature: bool,
    max_avx10_subleaf: u32,
    avx10_version: u8,
    xcr0: u64,
) -> bool {
    const REQUIRED_XCR0_STATE: u64 = (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 7);

    avx10_feature
        && max_avx10_subleaf >= 1
        && avx10_version >= 1
        && xcr0 & REQUIRED_XCR0_STATE == REQUIRED_XCR0_STATE
}

#[cfg(all(target_arch = "x86_64", not(target_env = "sgx"), feature = "internal_avx10_preview"))]
fn detect_avx10_1_support() -> bool {
    use std::arch::x86_64::{__cpuid, __cpuid_count, __get_cpuid_max, _xgetbv};

    const AVX10_FEATURE: u32 = 1 << 19;
    const XSAVE: u32 = 1 << 26;
    const OSXSAVE: u32 = 1 << 27;
    const AVX10_CPUID_LEAF: u32 = 0x24;

    let max_basic_leaf = __get_cpuid_max(0).0;
    if max_basic_leaf < AVX10_CPUID_LEAF {
        return false;
    }

    let leaf7 = __cpuid_count(7, 0);
    if leaf7.eax < 1 {
        return false;
    }

    let leaf1 = __cpuid(1);
    if leaf1.ecx & (XSAVE | OSXSAVE) != XSAVE | OSXSAVE {
        return false;
    }

    let avx10_feature = __cpuid_count(7, 1).edx & AVX10_FEATURE != 0;
    let avx10_leaf = __cpuid_count(AVX10_CPUID_LEAF, 0);
    let avx10_version = (avx10_leaf.ebx & 0xff) as u8;
    // SAFETY: CPUID.01H reports both XSAVE and OSXSAVE, which proves that the
    // processor and operating system permit reading XCR0 with XGETBV.
    let xcr0 = unsafe { _xgetbv(0) };

    decode_avx10_1_support(avx10_feature, avx10_leaf.eax, avx10_version, xcr0)
}

#[cfg(all(target_arch = "x86_64", target_env = "sgx", feature = "internal_avx10_preview"))]
fn detect_avx10_1_support() -> bool {
    false
}

#[cfg(all(target_arch = "x86_64", not(target_env = "sgx")))]
fn detect_amx_cpu_support() -> (bool, bool, bool) {
    use std::arch::x86_64::{__cpuid_count, __get_cpuid_max};

    if __get_cpuid_max(0).0 < 7 {
        return (false, false, false);
    }

    decode_amx_cpuid_leaf7(__cpuid_count(7, 0).edx)
}

#[cfg(all(target_arch = "x86_64", target_env = "sgx"))]
fn detect_amx_cpu_support() -> (bool, bool, bool) {
    (false, false, false)
}

#[cfg(target_arch = "x86_64")]
fn detect_amx_capability() -> AmxCapability {
    let (cpu_tile, cpu_int8, cpu_bf16) = detect_amx_cpu_support();
    AmxCapability::from_signals(AmxSignals {
        cpu_tile,
        cpu_int8,
        cpu_bf16,
        os_tile_state_permitted: probe_amx_os_tile_state(cpu_tile, cpu_int8),
        compiler_target_tile: cfg!(target_feature = "amx-tile"),
        compiler_target_int8: cfg!(target_feature = "amx-int8"),
        compiler_target_bf16: cfg!(target_feature = "amx-bf16"),
        verified_backend: amx_backend_verified(),
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_amx_capability() -> AmxCapability {
    AmxCapability::from_signals(AmxSignals {
        cpu_tile: false,
        cpu_int8: false,
        cpu_bf16: false,
        os_tile_state_permitted: None,
        compiler_target_tile: false,
        compiler_target_int8: false,
        compiler_target_bf16: false,
        verified_backend: amx_backend_verified(),
    })
}

/// CPU Performance Profile for optimized dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum CpuProfile {
    /// SSE2 baseline (no AES acceleration).
    X86_P0a,
    /// SSSE3 baseline (byte-shuffle; no AES acceleration).
    X86_P0b,
    /// SSE4.2 baseline.
    X86_P1a,
    /// P1a + AES-NI + PCLMUL (~2010 baseline).
    X86_P1b,
    /// P1b + AVX (float upgrade).
    X86_P1f,
    /// P1b + AVX2 (256-bit integer SIMD).
    X86_P2a,
    /// P2a + BMI2 + LZCNT.
    X86_P2b,
    /// AVX-512F baseline.
    X86_P3a,
    /// P3a + VAES + VPCLMULQDQ.
    X86_P3b,
    /// P3b + VBMI2.
    X86_P3c,
    /// P3c + VPOPCNTDQ.
    X86_P3d,
    /// P3d + GFNI (native GF(2^8) multiply).
    X86_P3e,
    /// Legacy AVX10.1 256-bit compatibility profile.
    X86_P4a,
    /// AVX10.1 profile selected by the current versioned enumeration.
    X86_P4b,

    /// ARM64: NEON baseline.
    ARM_A0,
    /// ARM64: NEON + CRC32.
    ARM_A1a,
    /// ARM64: A1a + AES.
    ARM_A1b,
    /// ARM64: A1b + PMULL (fast GCM).
    ARM_A1c,
    /// ARM64: A1c + SHA.
    ARM_A1d,
    /// ARM64: SVE2 + optional crypto.
    ARM_A2,

    /// Apple Silicon: NEON + Crypto profile; the Apple matrix marker is metadata only.
    Apple_M,

    /// RISC-V: Vector extension baseline.
    RVV,

    /// Scalar fallback (no SIMD).
    Scalar,
}

/// Ultra-comprehensive CPU feature enum for runtime detection and dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CpuFeature {
    // -- x86_64 Basic Features --
    /// SSE2 (128-bit integer SIMD).
    SSE2,
    /// SSE3 (horizontal add/sub, complex arithmetic).
    SSE3,
    /// Supplemental SSE3 (byte shuffle, alignment).
    SSSE3,
    /// SSE4.1 (blend, rounding, dot product).
    SSE41,
    /// SSE4.2 (string compare, CRC32 instruction).
    SSE42,
    /// AVX (256-bit float SIMD, VEX encoding).
    AVX,
    /// AVX2 (256-bit integer SIMD).
    AVX2,
    /// AVX-512 Foundation (512-bit vectors, opmask).
    AVX512F,
    /// AVX-512 Byte/Word (512-bit 8/16-bit operations).
    AVX512BW,
    /// AVX-512 Vector Length (128/256-bit AVX-512 ops).
    AVX512VL,
    /// BMI1 (bit manipulation: ANDN, BEXTR, BLSI).
    BMI1,
    /// BMI2 (PDEP, PEXT, SHRX).
    BMI2,
    /// AES-NI (hardware AES rounds).
    AESNI,
    /// PCLMULQDQ (carry-less multiplication for GCM).
    PCLMULQDQ,
    /// RDRAND (hardware random number generator).
    RDRAND,
    /// RDSEED (hardware entropy seed).
    RDSEED,
    /// SHA Extensions (hardware SHA-1/SHA-256).
    SHA,

    // -- x86_64 Ultra Features --
    /// VAES (vectorized AES on 256/512-bit registers).
    VAES,
    /// VPCLMULQDQ (vectorized carry-less multiply).
    VPCLMULQDQ,
    /// GFNI (native GF(2^8) multiply instruction).
    GFNI,
    /// AVX-512 VBMI (byte permute across lanes).
    AVX512VBMI,
    /// AVX-512 VBMI2 (compress/expand byte/word).
    AVX512VBMI2,
    /// AVX-512 VNNI (8/16-bit integer dot product).
    AVX512VNNI,
    /// AVX-512 BF16 (bfloat16 conversion/dot product).
    AVX512BF16,
    /// AVX-512 FP16 (native half-precision float).
    AVX512FP16,
    /// AVX-512 CD (conflict detection for scatter).
    AVX512CD,
    /// AVX-512 DQ (doubleword/quadword operations).
    AVX512DQ,
    /// AVX-512 VPOPCNTDQ (vector population count).
    AVX512VPOPCNTDQ,
    /// Legacy AVX10.1 256-bit compatibility marker.
    AVX10_1_256,
    /// AVX10.1 runtime support under the current versioned enumeration.
    AVX10_1_512,
    /// AVX-VNNI (256-bit integer neural network).
    AVXVNNI,
    /// AMX Tile (tile register infrastructure).
    AMX_TILE,
    /// AMX INT8 (8-bit integer tile multiply).
    AMX_INT8,
    /// AMX BF16 (bfloat16 tile multiply).
    AMX_BF16,

    // -- ARM64 Basic Features --
    /// ARM NEON (128-bit SIMD, mandatory on AArch64).
    NEON,
    /// ARM CRC32 instruction.
    CRC32,
    /// ARM LSE atomics (compare-and-swap, fetch-add).
    ATOMICS,
    /// ARM FP16 (half-precision float arithmetic).
    FP16,
    /// ARM dot product (8-bit integer dot product).
    DOTPROD,

    // -- ARM64 Crypto Features --
    /// ARM AES instruction (single-round AES).
    AES,
    /// ARM PMULL (polynomial multiply for GCM).
    PMULL,
    /// ARM SHA-1 hardware acceleration.
    SHA1,
    /// ARM SHA-2 hardware acceleration.
    SHA2,
    /// ARM SHA-3 hardware acceleration.
    SHA3,
    /// ARM SHA-256 dedicated instructions.
    SHA256,
    /// ARM SHA-512 dedicated instructions.
    SHA512,
    /// ARM SM3 (Chinese national hash standard).
    SM3,
    /// ARM SM4 (Chinese national block cipher).
    SM4,
    /// ARM NEON + Crypto combined capability.
    NEON_CRYPTO,

    // -- ARM64 SVE Features --
    /// ARM SVE (Scalable Vector Extension).
    SVE,
    /// ARM SVE2 (enhanced scalable SIMD).
    SVE2,
    /// SVE2 AES crypto extension.
    SVE_AES,
    /// SVE2 polynomial multiply extension.
    SVE_PMULL,
    /// SVE2 bit permutation extension.
    SVE_BITPERM,

    // -- Apple Silicon Features --
    /// Apple Silicon matrix-capability metadata; no active AMX arithmetic caller.
    APPLE_AMX,
    /// Apple M1 generation detected.
    APPLE_M1,
    /// Apple M2 generation detected.
    APPLE_M2,
    /// Apple M3 generation detected.
    APPLE_M3,

    // -- RISC-V Features --
    /// RISC-V Vector Extension baseline.
    RVV,
    /// RISC-V Zvbb (vector bit manipulation).
    RVV_ZVBB,
    /// RISC-V Zvbc (vector carry-less multiply).
    RVV_ZVBC,
    /// RISC-V Zvkg (vector GCM/GHASH).
    RVV_ZVKG,

    // -- Generic Features --
    /// Hardware population count instruction.
    POPCNT,
    /// Hardware leading zero count instruction.
    LZCNT,
    /// Fused multiply-add (3-operand FMA).
    FMA3,
}

/// CPU feature detector with ULTRA-SOPHISTICATED detection!
pub struct FeatureDetector {
    features: HashSet<CpuFeature>,
    features_full: CpuFeatures,
    /// Cached automatic profile selected from the detected feature set.
    profile: CpuProfile,
    amx_capability: AmxCapability,
    cache_line_size: usize,
    has_avx512: bool,
    optimal_simd_width: usize,
}

static DETECTOR: std::sync::OnceLock<FeatureDetector> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "rust-tests"))]
std::thread_local! {
    static PROFILE_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
#[cfg(any(test, feature = "rust-tests"))]
static PROFILE_OVERRIDE_ENV: std::sync::OnceLock<Option<CpuProfile>> = std::sync::OnceLock::new();

impl FeatureDetector {
    /// Returns a static reference to the `FeatureDetector` singleton.
    /// The first call will initialize the detector.
    pub fn instance() -> &'static Self {
        DETECTOR.get_or_init(|| {
            let detector = Self::detect();

            // Log detected features for telemetry
            log::info!("CPU Features detected:");
            #[cfg(target_arch = "x86_64")]
            {
                if detector.features_full.avx512f && detector.features_full.vaes {
                    log::info!("  AVX-512 + VAES: high-throughput crypto capable");
                } else if detector.features_full.avx2 && detector.features_full.aesni {
                    log::info!("  AVX2 + AES-NI: high-throughput crypto capable");
                } else if detector.features_full.aesni {
                    log::info!("  AES-NI: accelerated crypto capable");
                }

                if detector.features_full.gfni {
                    log::info!("  GFNI: accelerated Galois field operations available");
                }

                if detector.features_full.avx512vbmi2 {
                    log::info!("  AVX-512 VBMI2: accelerated pattern matching available");
                }

                let amx = detector.amx_capability;
                log::info!(
                    "  AMX contract: cpu_tile={}, cpu_int8={}, cpu_bf16={}, os_tile_state_permitted={:?}, compiler_target_tile={}, compiler_target_int8={}, compiler_target_bf16={}, verified_backend={}, product_dispatch_eligible={}",
                    amx.cpu_tile,
                    amx.cpu_int8,
                    amx.cpu_bf16,
                    amx.os_tile_state_permitted,
                    amx.compiler_target_tile,
                    amx.compiler_target_int8,
                    amx.compiler_target_bf16,
                    amx.verified_backend,
                    amx.product_dispatch_eligible,
                );
            }

            #[cfg(target_arch = "aarch64")]
            {
                if detector.features_full.sve2 {
                    log::info!("  ARM SVE2: accelerated SIMD available");
                } else if detector.features_full.neon && detector.features_full.aes {
                    log::info!("  NEON + AES: accelerated crypto capable");
                }

                #[cfg(target_os = "macos")]
                if detector.features_full.apple_amx {
                    log::info!(
                        "  Apple matrix capability metadata present; no active AMX backend"
                    );
                }
            }

            log::info!("  Optimal SIMD width: {} bytes", detector.optimal_simd_width);
            log::info!("  Cache line: {} bytes", detector.cache_line_size);

            detector
        })
    }

    /// Detect ALL CPU features - ULTRA COMPLETE!
    fn detect() -> Self {
        let mut features = HashSet::new();
        let mut features_full = CpuFeatures::default();
        let amx_capability = detect_amx_capability();
        #[cfg(target_arch = "aarch64")]
        let cache_line_size: usize = 128;
        #[cfg(not(target_arch = "aarch64"))]
        let cache_line_size: usize = 64;
        let mut optimal_simd_width = 16;

        #[cfg(target_arch = "x86_64")]
        {
            // ULTRA COMPLETE x86_64 detection
            // Include SSE2 explicitly for MORUS SIMD gating
            if is_x86_feature_detected!("sse2") {
                features.insert(CpuFeature::SSE2);
                features_full.sse2 = true;
            }
            if is_x86_feature_detected!("sse3") {
                features.insert(CpuFeature::SSE3);
                features_full.sse3 = true;
            }
            if is_x86_feature_detected!("ssse3") {
                features.insert(CpuFeature::SSSE3);
                features_full.ssse3 = true;
            }
            if is_x86_feature_detected!("sse4.1") {
                features.insert(CpuFeature::SSE41);
                features_full.sse41 = true;
            }
            if is_x86_feature_detected!("sse4.2") {
                features.insert(CpuFeature::SSE42);
                features_full.sse42 = true;
            }
            if is_x86_feature_detected!("avx") {
                features.insert(CpuFeature::AVX);
                features_full.avx = true;
            }
            if is_x86_feature_detected!("avx2") {
                features.insert(CpuFeature::AVX2);
                features_full.avx2 = true;
                optimal_simd_width = 32;
            }
            if is_x86_feature_detected!("avx512f") {
                features.insert(CpuFeature::AVX512F);
                features_full.avx512f = true;
                optimal_simd_width = 64;
            }
            if is_x86_feature_detected!("avx512bw") {
                features.insert(CpuFeature::AVX512BW);
                features_full.avx512bw = true;
            }
            if is_x86_feature_detected!("avx512vl") {
                features.insert(CpuFeature::AVX512VL);
                features_full.avx512vl = true;
            }
            if is_x86_feature_detected!("avx512vbmi") {
                features.insert(CpuFeature::AVX512VBMI);
                features_full.avx512vbmi = true;
            }
            if is_x86_feature_detected!("avx512vbmi2") {
                features.insert(CpuFeature::AVX512VBMI2);
                features_full.avx512vbmi2 = true;
            }
            if is_x86_feature_detected!("bmi1") {
                features.insert(CpuFeature::BMI1);
                features_full.bmi1 = true;
            }
            if is_x86_feature_detected!("bmi2") {
                features.insert(CpuFeature::BMI2);
                features_full.bmi2 = true;
            }
            if is_x86_feature_detected!("aes") {
                features.insert(CpuFeature::AESNI);
                features_full.aesni = true;
            }
            if is_x86_feature_detected!("pclmulqdq") {
                features.insert(CpuFeature::PCLMULQDQ);
                features_full.pclmulqdq = true;
                features_full.vpclmulqdq = is_x86_feature_detected!("vpclmulqdq");
            }
            if is_x86_feature_detected!("sha") {
                features.insert(CpuFeature::SHA);
                features_full.sha = true;
            }
            if is_x86_feature_detected!("popcnt") {
                features.insert(CpuFeature::POPCNT);
                features_full.popcnt = true;
            }
            if is_x86_feature_detected!("lzcnt") {
                features.insert(CpuFeature::LZCNT);
                features_full.lzcnt = true;
            }
            if is_x86_feature_detected!("rdrand") {
                features.insert(CpuFeature::RDRAND);
                features_full.rdrand = true;
            }
            if is_x86_feature_detected!("rdseed") {
                features.insert(CpuFeature::RDSEED);
                features_full.rdseed = true;
            }

            // ULTRA features
            // ULTRA features (runtime detection only; no cfg gates)
            if is_x86_feature_detected!("vaes") {
                features.insert(CpuFeature::VAES);
                features_full.vaes = true;
            }
            if is_x86_feature_detected!("gfni") {
                features.insert(CpuFeature::GFNI);
                features_full.gfni = true;
            }
            if is_x86_feature_detected!("vpclmulqdq") {
                features.insert(CpuFeature::VPCLMULQDQ);
                features_full.vpclmulqdq = true;
            }

            // Advanced AVX-512 features - NO COMPILE-TIME GATES!
            if is_x86_feature_detected!("avx512cd") {
                features.insert(CpuFeature::AVX512CD);
                features_full.avx512cd = true;
            }
            if is_x86_feature_detected!("avx512dq") {
                features.insert(CpuFeature::AVX512DQ);
                features_full.avx512dq = true;
            }
            if is_x86_feature_detected!("avx512vnni") {
                features.insert(CpuFeature::AVX512VNNI);
                features_full.avx512vnni = true;
            }
            if is_x86_feature_detected!("avx512vpopcntdq") {
                features.insert(CpuFeature::AVX512VPOPCNTDQ);
                features_full.avx512vpopcntdq = true;
            }

            // Current AVX10 enumeration is versioned and no longer reports
            // separate 256-bit and 512-bit capability flags. Preserve both
            // historical fields as compatibility projections of AVX10.1.
            #[cfg(feature = "internal_avx10_preview")]
            {
                if detect_avx10_1_support() {
                    features.insert(CpuFeature::AVX10_1_512);
                    features_full.avx10_1_512 = true;
                    features_full.avx512f = true;
                    optimal_simd_width = optimal_simd_width.max(64);
                    features.insert(CpuFeature::AVX10_1_256);
                    features_full.avx10_1_256 = true;
                    features_full.avx2 = true;
                }
            }

            // Next-Gen x86_64 Extensions - ULTRA MODERN!
            if is_x86_feature_detected!("avx512bf16") {
                features.insert(CpuFeature::AVX512BF16);
                features_full.avx512bf16 = true;
            }
            if is_x86_feature_detected!("avx512fp16") {
                features.insert(CpuFeature::AVX512FP16);
                features_full.avx512fp16 = true;
            }
            if is_x86_feature_detected!("avxvnni") {
                features.insert(CpuFeature::AVXVNNI);
                features_full.avx_vnni = true;
            }

            // AMX instruction support is detected in-process. OS tile-state
            // permission and a verified product backend remain separate gates.
            if amx_capability.cpu_tile {
                features.insert(CpuFeature::AMX_TILE);
                features_full.amx_tile = true;
            }
            if amx_capability.cpu_int8 {
                features.insert(CpuFeature::AMX_INT8);
                features_full.amx_int8 = true;
            }
            if amx_capability.cpu_bf16 {
                features.insert(CpuFeature::AMX_BF16);
                features_full.amx_bf16 = true;
            }

            if is_x86_feature_detected!("fma") {
                features_full.fma3 = true;
            }

            features_full.cache_line = 64;
            features_full.l1d_cache = 32 * 1024;
            features_full.l1i_cache = 32 * 1024;
            features_full.l2_cache = 256 * 1024;
            features_full.l3_cache = 8 * 1024 * 1024;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // NEON is mandatory on AArch64
            features.insert(CpuFeature::NEON);
            features_full.neon = true;

            // Platform-specific detection
            #[cfg(target_os = "macos")]
            {
                // All Apple Silicon has comprehensive crypto and SIMD extensions
                features.insert(CpuFeature::AES);
                features.insert(CpuFeature::PMULL);
                features.insert(CpuFeature::NEON_CRYPTO);
                features.insert(CpuFeature::CRC32);
                features.insert(CpuFeature::SHA1);
                features.insert(CpuFeature::SHA2);
                features.insert(CpuFeature::SHA256);
                features.insert(CpuFeature::ATOMICS);
                features.insert(CpuFeature::FP16);
                features.insert(CpuFeature::DOTPROD);
                features.insert(CpuFeature::APPLE_AMX);

                features_full.aes = true;
                features_full.pmull = true;
                features_full.sha1 = true;
                features_full.sha2 = true;
                features_full.sha2 = true;
                features_full.crc32 = true;
                features_full.atomics = true;
                features_full.fp16 = true;
                features_full.dotprod = true;
                features_full.apple_amx = true;

                // Detect specific Apple Silicon generation
                use std::process::Command;
                if let Ok(output) =
                    Command::new("sysctl").arg("-n").arg("machdep.cpu.brand_string").output()
                {
                    let brand = String::from_utf8_lossy(&output.stdout);
                    if brand.contains("M1") {
                        features_full.apple_m1 = true;
                    } else if brand.contains("M2") {
                        features_full.apple_m2 = true;
                        features_full.apple_amx = true;
                    } else if brand.contains("M3") {
                        features_full.apple_m3 = true;
                        features_full.apple_amx = true;
                        optimal_simd_width = 32; // M3 has wider SIMD
                    }
                }

                features_full.cache_line = 128;
                features_full.l1d_cache = 128 * 1024;
                features_full.l1i_cache = 192 * 1024;
                features_full.l2_cache = 4 * 1024 * 1024;
            }

            #[cfg(target_os = "linux")]
            {
                use std::fs;
                if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                    // Crypto extensions
                    if cpuinfo.contains("aes") {
                        features.insert(CpuFeature::AES);
                        features_full.aes = true;
                    }
                    if cpuinfo.contains("pmull") {
                        features.insert(CpuFeature::PMULL);
                        features.insert(CpuFeature::NEON_CRYPTO);
                        features_full.pmull = true;
                    }

                    // SHA extensions
                    if cpuinfo.contains("sha1") {
                        features.insert(CpuFeature::SHA1);
                        features_full.sha1 = true;
                    }
                    if cpuinfo.contains("sha2") {
                        features.insert(CpuFeature::SHA2);
                        features_full.sha2 = true;
                    }
                    if cpuinfo.contains("sha256") {
                        features.insert(CpuFeature::SHA256);
                        features_full.sha2 = true;
                    }
                    if cpuinfo.contains("sha3") {
                        features.insert(CpuFeature::SHA3);
                        features_full.sha3 = true;
                    }
                    if cpuinfo.contains("sha512") {
                        features.insert(CpuFeature::SHA512);
                        features_full.sha512 = true;
                    }
                    if cpuinfo.contains("sm3") {
                        features.insert(CpuFeature::SM3);
                        features_full.sm3 = true;
                    }
                    if cpuinfo.contains("sm4") {
                        features.insert(CpuFeature::SM4);
                        features_full.sm4 = true;
                    }

                    // Other extensions
                    if cpuinfo.contains("crc32") {
                        features.insert(CpuFeature::CRC32);
                        features_full.crc32 = true;
                    }
                    if cpuinfo.contains("atomics") {
                        features.insert(CpuFeature::ATOMICS);
                        features_full.atomics = true;
                    }
                    if cpuinfo.contains("fp16") {
                        features.insert(CpuFeature::FP16);
                        features_full.fp16 = true;
                    }
                    if cpuinfo.contains("dotprod") {
                        features.insert(CpuFeature::DOTPROD);
                        features_full.dotprod = true;
                    }
                    if cpuinfo.contains("sve") && !cpuinfo.contains("sve2") {
                        features.insert(CpuFeature::SVE);
                        features_full.sve = true;
                        optimal_simd_width = 64; // SVE can be up to 2048 bits
                    }
                    if cpuinfo.contains("sve2") {
                        features.insert(CpuFeature::SVE);
                        features.insert(CpuFeature::SVE2);
                        features_full.sve = true;
                        features_full.sve2 = true;
                        optimal_simd_width = 64;
                    }
                    // SVE2 crypto extensions - with HashSet.
                    if cpuinfo.contains("sveaes") || cpuinfo.contains("sve2-aes") {
                        features_full.sve_aes = true;
                        features.insert(CpuFeature::SVE_AES);
                    }
                    if cpuinfo.contains("svepmull") || cpuinfo.contains("sve2-pmull") {
                        features_full.sve_pmull = true;
                        features.insert(CpuFeature::SVE_PMULL);
                    }
                    if cpuinfo.contains("svebitperm") || cpuinfo.contains("sve2-bitperm") {
                        features_full.sve_bitperm = true;
                        features.insert(CpuFeature::SVE_BITPERM);
                    }
                }
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            use std::arch::is_riscv_feature_detected;

            if is_riscv_feature_detected!("v") {
                features_full.rvv = true;
                features.insert(CpuFeature::RVV);
                optimal_simd_width = optimal_simd_width.max(64);
            }
            if is_riscv_feature_detected!("zvbb") {
                features_full.rvv_zvbb = true;
                features.insert(CpuFeature::RVV_ZVBB);
            }
            if is_riscv_feature_detected!("zvbc") {
                features_full.rvv_zvbc = true;
                features.insert(CpuFeature::RVV_ZVBC);
            }
            if is_riscv_feature_detected!("zvkg") {
                features_full.rvv_zvkg = true;
                features.insert(CpuFeature::RVV_ZVKG);
            }
        }

        // Determine capabilities
        let has_avx512 =
            features.contains(&CpuFeature::AVX512F) || features.contains(&CpuFeature::AVX10_1_512);
        let profile = Self::profile_from_features(features_full);

        Self {
            features,
            features_full,
            profile,
            amx_capability,
            cache_line_size,
            has_avx512,
            optimal_simd_width,
        }
    }

    /// Get full CPU features struct
    pub fn features_full(&self) -> &CpuFeatures {
        &self.features_full
    }

    /// Returns the separated CPU, OS, compiler, and product AMX evidence.
    pub fn amx_capability(&self) -> AmxCapability {
        self.amx_capability
    }

    /// Get optimal SIMD width in bytes
    pub fn optimal_simd_width(&self) -> usize {
        self.optimal_simd_width
    }

    /// Determine CPU profile from detected features
    pub fn profile(&self) -> CpuProfile {
        #[cfg(any(test, feature = "rust-tests"))]
        if let Some(override_profile) = self.profile_override() {
            return override_profile;
        }

        self.profile
    }

    /// Select the automatic profile from an exact feature snapshot.
    fn profile_from_features(features: CpuFeatures) -> CpuProfile {
        #[cfg(target_arch = "x86_64")]
        {
            let matrix = features.simd_dispatch_matrix();

            if features.avx10_1_512 {
                return CpuProfile::X86_P4b;
            }
            if features.avx10_1_256 {
                return CpuProfile::X86_P4a;
            }

            // Check from highest to lowest capability
            if features.avx512f {
                if features.gfni {
                    return CpuProfile::X86_P3e;
                }
                if matrix.avx512_vpopcnt {
                    return CpuProfile::X86_P3d;
                }
                if matrix.avx512_vbmi2 {
                    return CpuProfile::X86_P3c;
                }
                if features.vaes && features.vpclmulqdq {
                    return CpuProfile::X86_P3b;
                }
                return CpuProfile::X86_P3a;
            }

            if features.avx2 {
                if features.bmi2 {
                    return CpuProfile::X86_P2b;
                }
                return CpuProfile::X86_P2a;
            }

            if features.avx {
                return CpuProfile::X86_P1f;
            }

            if features.aesni && features.pclmulqdq {
                return CpuProfile::X86_P1b;
            }

            if features.sse42 {
                return CpuProfile::X86_P1a;
            }

            // Legacy fallbacks
            if features.ssse3 {
                return CpuProfile::X86_P0b;
            }
            if features.sse2 {
                return CpuProfile::X86_P0a;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(target_os = "macos")]
            if features.apple_amx {
                return CpuProfile::Apple_M;
            }

            if features.sve2 {
                return CpuProfile::ARM_A2;
            }

            if features.neon {
                if features.aes
                    && features.pmull
                    && (features.sha1 || features.sha2 || features.sha512)
                {
                    return CpuProfile::ARM_A1d;
                }
                if features.aes && features.pmull {
                    return CpuProfile::ARM_A1c;
                }
                if features.aes {
                    return CpuProfile::ARM_A1b;
                }
                if features.crc32 {
                    return CpuProfile::ARM_A1a;
                }
                return CpuProfile::ARM_A0;
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            if features.rvv {
                return CpuProfile::RVV;
            }
        }

        CpuProfile::Scalar
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn profile_override(&self) -> Option<CpuProfile> {
        let requested = match PROFILE_OVERRIDE.with(std::cell::Cell::get) {
            0 => *PROFILE_OVERRIDE_ENV.get_or_init(parse_profile_override_env),
            value => profile_override_from_u64(value),
        };

        let profile = requested?;

        if profile == CpuProfile::Scalar {
            return Some(profile);
        }

        if self.profile_override_supported(profile) {
            return Some(profile);
        }

        log::warn!("Profile override {:?} rejected due to missing CPU features", profile);
        None
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn profile_override_supported(&self, profile: CpuProfile) -> bool {
        let features = self.features_full;
        let matrix = features.simd_dispatch_matrix();

        match profile {
            CpuProfile::Scalar => true,
            CpuProfile::X86_P0a => features.sse2,
            CpuProfile::X86_P0b => features.ssse3,
            CpuProfile::X86_P1a => features.sse42,
            CpuProfile::X86_P1b => features.aesni && features.pclmulqdq,
            CpuProfile::X86_P1f => features.avx,
            CpuProfile::X86_P2a => matrix.avx2,
            CpuProfile::X86_P2b => matrix.avx2 && features.bmi2,
            CpuProfile::X86_P3a => features.avx512f,
            CpuProfile::X86_P3b => features.avx512f && features.vaes && features.vpclmulqdq,
            CpuProfile::X86_P3c => matrix.avx512_vbmi2,
            CpuProfile::X86_P3d => matrix.avx512_vpopcnt,
            CpuProfile::X86_P3e => features.avx512f && features.gfni,
            CpuProfile::X86_P4a => features.avx10_1_256,
            CpuProfile::X86_P4b => features.avx10_1_512,
            CpuProfile::ARM_A0 => features.neon,
            CpuProfile::ARM_A1a => features.neon && features.crc32,
            CpuProfile::ARM_A1b => features.neon && features.aes,
            CpuProfile::ARM_A1c => features.neon && features.aes && features.pmull,
            CpuProfile::ARM_A1d => {
                features.neon
                    && features.aes
                    && features.pmull
                    && (features.sha1 || features.sha2 || features.sha512)
            }
            CpuProfile::ARM_A2 => features.sve2,
            CpuProfile::Apple_M => features.apple_amx,
            CpuProfile::RVV => features.rvv,
        }
    }

    /// Get cache line size
    pub fn cache_line_size(&self) -> usize {
        self.cache_line_size
    }

    /// Check if AVX-512 is available
    pub fn has_avx512(&self) -> bool {
        self.has_avx512
    }

    /// Check if AVX2 is available  
    pub fn has_avx2(&self) -> bool {
        self.features_full.avx2
            || self.features.contains(&CpuFeature::AVX10_1_256)
            || self.features.contains(&CpuFeature::AVX10_1_512)
    }

    /// Checks if a specific CPU feature is supported.
    pub fn has_feature(&self, feature: CpuFeature) -> bool {
        match feature {
            CpuFeature::AVX512F => {
                self.features.contains(&CpuFeature::AVX512F)
                    || self.features.contains(&CpuFeature::AVX10_1_512)
            }
            CpuFeature::AVX2 => {
                self.features.contains(&CpuFeature::AVX2)
                    || self.features.contains(&CpuFeature::AVX10_1_256)
                    || self.features.contains(&CpuFeature::AVX10_1_512)
            }
            _ => self.features.contains(&feature),
        }
    }

    /// Checks if any of the provided features is supported.
    pub fn has_any(&self, feats: &[CpuFeature]) -> bool {
        feats.iter().any(|f| self.has_feature(*f))
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn parse_profile_override_env() -> Option<CpuProfile> {
    let raw = std::env::var("QUICFUSCATE_PROFILE_OVERRIDE").ok()?;
    parse_profile_override(&raw)
}

#[cfg(any(test, feature = "rust-tests"))]
fn parse_profile_override(value: &str) -> Option<CpuProfile> {
    let key = value.trim().to_lowercase().replace('-', "_");
    if key.is_empty() || key == "auto" || key == "detected" {
        return None;
    }
    match key.as_str() {
        "scalar" => Some(CpuProfile::Scalar),
        "x86_p0a" | "sse2" => Some(CpuProfile::X86_P0a),
        "x86_p0b" | "ssse3" => Some(CpuProfile::X86_P0b),
        "x86_p1a" | "sse4_2" | "sse42" => Some(CpuProfile::X86_P1a),
        "x86_p1b" | "aesni" => Some(CpuProfile::X86_P1b),
        "x86_p1f" | "avx" => Some(CpuProfile::X86_P1f),
        "x86_p2a" | "avx2" => Some(CpuProfile::X86_P2a),
        "x86_p2b" | "bmi2" => Some(CpuProfile::X86_P2b),
        "x86_p3a" | "avx512" => Some(CpuProfile::X86_P3a),
        "x86_p3b" => Some(CpuProfile::X86_P3b),
        "x86_p3c" => Some(CpuProfile::X86_P3c),
        "x86_p3d" => Some(CpuProfile::X86_P3d),
        "x86_p3e" => Some(CpuProfile::X86_P3e),
        "x86_p4a" | "avx10_256" => Some(CpuProfile::X86_P4a),
        "x86_p4b" | "avx10_512" => Some(CpuProfile::X86_P4b),
        "arm_a0" | "neon" => Some(CpuProfile::ARM_A0),
        "arm_a1a" => Some(CpuProfile::ARM_A1a),
        "arm_a1b" => Some(CpuProfile::ARM_A1b),
        "arm_a1c" => Some(CpuProfile::ARM_A1c),
        "arm_a1d" => Some(CpuProfile::ARM_A1d),
        "arm_a2" | "sve2" => Some(CpuProfile::ARM_A2),
        "apple_m" | "apple" => Some(CpuProfile::Apple_M),
        "rvv" => Some(CpuProfile::RVV),
        _ => None,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn profile_override_from_u64(value: u64) -> Option<CpuProfile> {
    match value {
        1 => Some(CpuProfile::Scalar),
        2 => Some(CpuProfile::X86_P0a),
        3 => Some(CpuProfile::X86_P0b),
        4 => Some(CpuProfile::X86_P1a),
        5 => Some(CpuProfile::X86_P1b),
        6 => Some(CpuProfile::X86_P1f),
        7 => Some(CpuProfile::X86_P2a),
        8 => Some(CpuProfile::X86_P2b),
        9 => Some(CpuProfile::X86_P3a),
        10 => Some(CpuProfile::X86_P3b),
        11 => Some(CpuProfile::X86_P3c),
        12 => Some(CpuProfile::X86_P3d),
        13 => Some(CpuProfile::X86_P3e),
        14 => Some(CpuProfile::X86_P4a),
        15 => Some(CpuProfile::X86_P4b),
        16 => Some(CpuProfile::ARM_A0),
        17 => Some(CpuProfile::ARM_A1a),
        18 => Some(CpuProfile::ARM_A1b),
        19 => Some(CpuProfile::ARM_A1c),
        20 => Some(CpuProfile::ARM_A1d),
        21 => Some(CpuProfile::ARM_A2),
        22 => Some(CpuProfile::Apple_M),
        23 => Some(CpuProfile::RVV),
        _ => None,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn profile_override_to_u64(profile: CpuProfile) -> u64 {
    match profile {
        CpuProfile::Scalar => 1,
        CpuProfile::X86_P0a => 2,
        CpuProfile::X86_P0b => 3,
        CpuProfile::X86_P1a => 4,
        CpuProfile::X86_P1b => 5,
        CpuProfile::X86_P1f => 6,
        CpuProfile::X86_P2a => 7,
        CpuProfile::X86_P2b => 8,
        CpuProfile::X86_P3a => 9,
        CpuProfile::X86_P3b => 10,
        CpuProfile::X86_P3c => 11,
        CpuProfile::X86_P3d => 12,
        CpuProfile::X86_P3e => 13,
        CpuProfile::X86_P4a => 14,
        CpuProfile::X86_P4b => 15,
        CpuProfile::ARM_A0 => 16,
        CpuProfile::ARM_A1a => 17,
        CpuProfile::ARM_A1b => 18,
        CpuProfile::ARM_A1c => 19,
        CpuProfile::ARM_A1d => 20,
        CpuProfile::ARM_A2 => 21,
        CpuProfile::Apple_M => 22,
        CpuProfile::RVV => 23,
    }
}

/// Overrides the detected CPU profile for test isolation. Returns false if unsupported.
#[cfg(any(test, feature = "rust-tests"))]
pub fn set_profile_override_for_tests(profile: CpuProfile) -> bool {
    let detector = FeatureDetector::instance();
    if profile != CpuProfile::Scalar && !detector.profile_override_supported(profile) {
        return false;
    }
    PROFILE_OVERRIDE.with(|value| value.set(profile_override_to_u64(profile)));
    true
}

/// Clears any active CPU profile override, restoring auto-detection.
#[cfg(any(test, feature = "rust-tests"))]
pub fn clear_profile_override_for_tests() {
    PROFILE_OVERRIDE.with(|value| value.set(0));
}

// ============================================================================
// CENTRAL SIMD SYSTEM
// ============================================================================

/// 3-Level Cache Hierarchy for optimal performance - ZENTRALE DEFINITION
pub struct CacheLevel {
    /// Total cache size in bytes.
    pub size: usize,
    /// Cache line size in bytes (typically 64 or 128).
    pub line_size: usize,
    /// Set associativity (number of ways).
    pub ways: usize,
    /// Approximate access latency in CPU cycles.
    pub latency_cycles: usize,
}

/// Detected 3-level cache hierarchy with prefetch tuning parameters.
pub struct CacheHierarchy {
    /// L1 data cache parameters.
    pub l1_data: CacheLevel,
    /// L1 instruction cache parameters.
    pub l1_inst: CacheLevel,
    /// Unified L2 cache parameters.
    pub l2_unified: CacheLevel,
    /// Shared L3 cache parameters.
    pub l3_shared: CacheLevel,
    /// Optimal software prefetch distance in bytes.
    pub prefetch_distance: usize,
    /// Optimal tile size for cache-blocked algorithms.
    pub blocking_factor: usize,
}

impl CacheHierarchy {
    /// Detect cache hierarchy at runtime
    pub fn detect() -> Self {
        let features = FeatureDetector::instance().features_full();

        // Intel/AMD x86_64 typical
        #[cfg(target_arch = "x86_64")]
        if features.avx512f {
            return Self {
                l1_data: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l2_unified: CacheLevel {
                    size: 1048576,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 12,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 40,
                },
                prefetch_distance: 512, // Prefetch 8 cache lines ahead
                blocking_factor: 256,   // Tile size for cache blocking
            };
        }

        // Apple Silicon M-series
        #[cfg(target_arch = "aarch64")]
        if features.apple_m1 || features.apple_m2 || features.apple_m3 {
            return Self {
                l1_data: CacheLevel { size: 131072, line_size: 128, ways: 8, latency_cycles: 3 },
                l1_inst: CacheLevel { size: 196608, line_size: 128, ways: 6, latency_cycles: 3 },
                l2_unified: CacheLevel {
                    size: 4194304,
                    line_size: 128,
                    ways: 12,
                    latency_cycles: 15,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 128,
                    ways: 16,
                    latency_cycles: 50,
                },
                prefetch_distance: 1024, // More aggressive prefetch
                blocking_factor: 512,    // Larger tiles for bigger caches
            };
        }

        // Default conservative
        Self {
            l1_data: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l2_unified: CacheLevel { size: 262144, line_size: 64, ways: 8, latency_cycles: 12 },
            l3_shared: CacheLevel { size: 4194304, line_size: 64, ways: 16, latency_cycles: 40 },
            prefetch_distance: 256,
            blocking_factor: 128,
        }
    }

    /// Calculate optimal tile size for matrix operations
    pub fn optimal_tile_size(&self, element_size: usize) -> usize {
        // Use 1/2 of L1 cache for working set
        let working_set = self.l1_data.size / 2;
        let elements = working_set / element_size;
        // Square root for square tiles
        (elements as f64).sqrt() as usize
    }
}

// ============================================================================
// SIMD DISPATCH - DUPLICATE MODULE REMOVED!
// ============================================================================

/// SIMD operations dispatcher - selects optimal implementation at runtime
pub struct SimdDispatch;

impl SimdDispatch {
    /// XOR blocks with optimal SIMD - up to 64 bytes at once!
    #[inline(always)]
    pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx512f {
                telemetry::AVX512_OPS.inc();
                return Self::xor_blocks_avx512(dst, src);
            }
            if features.avx2 {
                telemetry::AVX2_OPS.inc();
                return Self::xor_blocks_avx2(dst, src);
            }
            // SSE2 removed - fallback to scalar
            // Baseline is SSE4.2 but we only have AVX2/AVX512 SIMD implementations
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                telemetry::SVE2_OPS.inc();
                return Self::xor_blocks_sve2(dst, src);
            }
            if features.neon {
                telemetry::NEON_OPS.inc();
                return Self::xor_blocks_neon(dst, src);
            }
        }

        telemetry::SCALAR_OPS.inc();
        Self::xor_blocks_scalar(dst, src);
    }

    /// Population count with optimal instruction
    #[inline(always)]
    pub fn popcnt(data: &[u8]) -> usize {
        let mut count = 0;

        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance().features_full();
            if features.popcnt {
                for chunk in data.chunks_exact(8) {
                    let mut word = [0u8; 8];
                    word.copy_from_slice(chunk);
                    let val = u64::from_le_bytes(word);
                    count += val.count_ones() as usize;
                }
                for &byte in data.chunks_exact(8).remainder() {
                    count += byte.count_ones() as usize;
                }
                return count;
            }
        }

        // Fallback
        for &byte in data {
            count += byte.count_ones() as usize;
        }
        count
    }

    // x86_64 implementations
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 64-byte chunks
        while i + 64 <= len {
            let a = _mm512_loadu_si512(dst[i..].as_ptr() as *const __m512i);
            let b = _mm512_loadu_si512(src[i..].as_ptr() as *const __m512i);
            let c = _mm512_xor_si512(a, b);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, c);
            i += 64;
        }

        // AVX-512F does not imply AVX2. Keep the remainder scalar so this
        // function's target-feature contract remains self-contained.
        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 32-byte chunks
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst[i..].as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            let c = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, c);
            i += 32;
        }

        // Process remainder with SSE2
        while i + 16 <= len {
            let a = _mm_loadu_si128(dst[i..].as_ptr() as *const __m128i);
            let b = _mm_loadu_si128(src[i..].as_ptr() as *const __m128i);
            let c = _mm_xor_si128(a, b);
            _mm_storeu_si128(dst[i..].as_mut_ptr() as *mut __m128i, c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    // SSE2 xor_blocks removed - baseline is SSE4.2

    // ARM64 implementations
    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_neon(dst: &mut [u8], src: &[u8]) {
        use std::arch::aarch64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        while i + 16 <= len {
            let a = vld1q_u8(dst[i..].as_ptr());
            let b = vld1q_u8(src[i..].as_ptr());
            let c = veorq_u8(a, b);
            vst1q_u8(dst[i..].as_mut_ptr(), c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_sve2(dst: &mut [u8], src: &[u8]) {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let len = dst.len().min(src.len());
            let mut offset = 0usize;

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                let dst_chunk = svld1_u8(pg, dst.as_ptr().add(offset));
                let src_chunk = svld1_u8(pg, src.as_ptr().add(offset));
                let xor_chunk = sveor_u8_z(pg, dst_chunk, src_chunk);
                svst1_u8(pg, dst.as_mut_ptr().add(offset), xor_chunk);
                offset += svcntb() as usize;
            }
            return;
        }

        Self::xor_blocks_neon(dst, src);
    }

    // Scalar fallback
    fn xor_blocks_scalar(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }
}

/// Represents the execution policy for SIMD operations.
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}

/// Marker struct for AVX-512 execution.
pub struct Avx512;
impl SimdPolicy for Avx512 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX2 execution.
pub struct Avx2;
impl SimdPolicy for Avx2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for SSE2 execution.
pub struct Sse2;
impl SimdPolicy for Sse2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// SSE2 marker removed - baseline is SSE4.2

/// Marker struct for PCLMULQDQ execution.
pub struct Pclmulqdq;
impl SimdPolicy for Pclmulqdq {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON execution.
pub struct Neon;
impl SimdPolicy for Neon {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512GFNI execution (Galois Field New Instructions).
pub struct Avx512Gfni;
impl SimdPolicy for Avx512Gfni {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512VBMI2 execution.
pub struct Avx512Vbmi2;
impl SimdPolicy for Avx512Vbmi2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE2 execution.
pub struct Sve2;
impl SimdPolicy for Sve2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE execution.
pub struct Sve;
impl SimdPolicy for Sve {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON Crypto execution.
pub struct NeonCrypto;
impl SimdPolicy for NeonCrypto {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for scalar (non-SIMD) execution.
pub struct Scalar;
impl SimdPolicy for Scalar {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Dispatches to the best available SIMD implementation at runtime.
/// The policies are ordered from most to least performant.
pub fn dispatch<F, R>(f: F) -> R
where
    F: Fn(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();
    let features = detector.features_full();
    let matrix = features.simd_dispatch_matrix();
    let has_avx10_512 = detector.features.contains(&CpuFeature::AVX10_1_512);
    let has_avx10_256 = detector.features.contains(&CpuFeature::AVX10_1_256);

    // Priority order: GFNI > VBMI2 > VBMI > AVX2 > SSE2 > SVE2 > SVE > NEON
    if features.avx512f && features.gfni {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Gfni)
    } else if matrix.avx512_vbmi2 {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Vbmi2)
    } else if matrix.avx512_vbmi {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512)
    } else if matrix.avx2 {
        telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if has_avx10_256 {
            telemetry::SIMD_USAGE_AVX10_256.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx2)
    // SSE2 removed - fallback directly to scalar
    } else if features.pclmulqdq {
        f(&Pclmulqdq)
    } else if matrix.sve2 {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve2)
    } else if features.sve {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve)
    } else if features.neon && features.aes && features.pmull {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&NeonCrypto)
    } else if matrix.neon {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Neon)
    } else {
        telemetry::SIMD_USAGE_SCALAR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Scalar)
    }
}

/// Dispatches specifically for GF bitsliced operations. AVX-512/AVX2/SSE2 and
/// the ARM NEON/SVE2 families are considered; all other architectures fall back
/// to scalar code.
static FEC_KERNEL_OVERRIDE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "rust-tests"))]
std::thread_local! {
    static TEST_FEC_KERNEL_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Test-only: overrides the FEC kernel SIMD dispatch policy.
#[cfg(any(test, feature = "rust-tests"))]
pub fn __test_set_fec_kernel_override(val: Option<&str>) {
    TEST_FEC_KERNEL_OVERRIDE.with(|value| {
        *value.borrow_mut() = val.map(str::to_lowercase);
    });
}

/// Dispatch a FEC bitslice operation through the selected SIMD policy.
pub fn dispatch_bitslice<F, R>(mut f: F) -> R
where
    F: FnMut(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();
    let features = detector.features_full();
    let matrix = features.simd_dispatch_matrix();

    // Resolve optional runtime override (test override takes precedence)
    let ov: Option<String> = {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            if let Some(s) = TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone()) {
                Some(s)
            } else {
                FEC_KERNEL_OVERRIDE
                    .get_or_init(|| {
                        EnvSnapshot::capture()
                            .first(["QUICFUSCATE_FEC_KERNEL"])
                            .map(|value| value.to_ascii_lowercase())
                    })
                    .clone()
            }
        }
        #[cfg(not(any(test, feature = "rust-tests")))]
        {
            FEC_KERNEL_OVERRIDE
                .get_or_init(|| {
                    EnvSnapshot::capture()
                        .first(["QUICFUSCATE_FEC_KERNEL"])
                        .map(|value| value.to_ascii_lowercase())
                })
                .clone()
        }
    };

    // If a valid override is present and supported, honor it; otherwise, warn and fall back
    if let Some(ref mode) = ov {
        match mode.as_str() {
            "ref" | "scalar" => {
                return f(&Scalar);
            }
            "avx512vbmi2" => {
                if matrix.avx512_vbmi2 {
                    return f(&Avx512Vbmi2);
                } else {
                    warn!(
                        "QUICFUSCATE_FEC_KERNEL=avx512vbmi2 requested but unsupported; falling back to auto"
                    );
                }
            }
            "avx512" => {
                if matrix.avx512_vbmi {
                    return f(&Avx512);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx512 requested but unsupported; falling back to auto");
                }
            }
            "avx2" => {
                if matrix.avx2 {
                    return f(&Avx2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx2 requested but unsupported; falling back to auto");
                }
            }
            "neon" => {
                if matrix.neon {
                    return f(&Neon);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=neon requested but unsupported; falling back to auto");
                }
            }
            "sve2" => {
                if matrix.sve2 {
                    return f(&Sve2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=sve2 requested but unsupported; falling back to auto");
                }
            }
            other => {
                warn!("Unknown QUICFUSCATE_FEC_KERNEL='{}'; falling back to auto", other);
            }
        }
    }

    // Default automatic selection path (unchanged ordering)
    if matrix.avx512_vbmi2 {
        f(&Avx512Vbmi2)
    } else if matrix.avx512_vbmi {
        f(&Avx512)
    } else if matrix.avx2 {
        f(&Avx2)
    } else if features.sse2 {
        f(&Sse2)
    } else if matrix.sve2 {
        f(&Sve2)
    } else if matrix.neon {
        f(&Neon)
    } else {
        f(&Scalar)
    }
}

/// Helper to return a short, human-readable tag of the active bitslice policy.
#[cfg(test)]
fn bitslice_policy_tag(p: &dyn SimdPolicy) -> &'static str {
    if p.as_any().is::<Avx512Vbmi2>() {
        "avx512vbmi2"
    } else if p.as_any().is::<Avx512>() {
        "avx512"
    } else if p.as_any().is::<Avx2>() {
        "avx2"
    } else if p.as_any().is::<Sse2>() {
        "sse2"
    } else if p.as_any().is::<Sve2>() {
        "sve2"
    } else if p.as_any().is::<Neon>() {
        "neon"
    } else {
        "scalar"
    }
}

// (tests consolidated below)

#[cfg(test)]
fn with_override<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
    struct OverrideGuard(Option<String>);

    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            TEST_FEC_KERNEL_OVERRIDE.with(|value| {
                *value.borrow_mut() = self.0.take();
            });
        }
    }

    let previous = TEST_FEC_KERNEL_OVERRIDE
        .with(|value| std::mem::replace(&mut *value.borrow_mut(), val.map(str::to_lowercase)));
    let _guard = OverrideGuard(previous);
    f()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::CpuFeature;
    use super::{
        bitslice_policy_tag, dispatch_bitslice, with_override, AmxCapability, AmxSignals,
        CpuFeatures, CpuProfile, FeatureDetector, PROFILE_OVERRIDE, TEST_FEC_KERNEL_OVERRIDE,
    };
    use std::sync::{Arc, Barrier};

    #[test]
    fn test_dispatch_overrides_are_thread_local() {
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            with_override(Some("ref"), || {
                first_barrier.wait();
                TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone())
            })
        });
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            with_override(Some("avx2"), || {
                second_barrier.wait();
                TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone())
            })
        });

        barrier.wait();
        assert_eq!(first.join().expect("first override thread"), Some("ref".to_string()));
        assert_eq!(second.join().expect("second override thread"), Some("avx2".to_string()));
        assert_eq!(TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone()), None);
    }

    #[test]
    fn test_profile_override_is_thread_local() {
        let barrier = Arc::new(Barrier::new(2));
        let child_barrier = Arc::clone(&barrier);
        let child = std::thread::spawn(move || {
            assert!(super::set_profile_override_for_tests(CpuProfile::Scalar));
            child_barrier.wait();
            FeatureDetector::instance().profile()
        });

        barrier.wait();
        assert_eq!(PROFILE_OVERRIDE.with(std::cell::Cell::get), 0);
        assert_eq!(child.join().expect("profile override thread"), CpuProfile::Scalar);
    }

    #[test]
    fn amx_detection_is_process_free_and_product_fail_closed() {
        let detector = FeatureDetector::instance();
        let capability = detector.amx_capability();

        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        if capability.cpu_tile && capability.cpu_int8 {
            assert!(capability.os_tile_state_permitted.is_some());
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
        assert_eq!(capability.os_tile_state_permitted, None);
        assert!(!capability.verified_backend);
        assert!(!capability.product_dispatch_eligible);
        assert_eq!(detector.features_full().amx_tile, capability.cpu_tile);
        assert_eq!(detector.features_full().amx_int8, capability.cpu_int8);
        assert_eq!(detector.features_full().amx_bf16, capability.cpu_bf16);
    }

    #[test]
    fn amx_cpuid_leaf7_decodes_each_feature_bit_independently() {
        assert_eq!(super::decode_amx_cpuid_leaf7(0), (false, false, false));
        assert_eq!(super::decode_amx_cpuid_leaf7(1 << 24), (true, false, false));
        assert_eq!(super::decode_amx_cpuid_leaf7(1 << 25), (false, true, false));
        assert_eq!(super::decode_amx_cpuid_leaf7(1 << 22), (false, false, true));
        assert_eq!(
            super::decode_amx_cpuid_leaf7((1 << 22) | (1 << 24) | (1 << 25)),
            (true, true, true)
        );
    }

    #[test]
    fn avx10_1_cpuid_requires_feature_version_subleaf_and_complete_xcr0_state() {
        const REQUIRED_XCR0_STATE: u64 = 0xe6;

        assert!(super::decode_avx10_1_support(true, 1, 1, REQUIRED_XCR0_STATE));
        assert!(super::decode_avx10_1_support(true, 4, 2, u64::MAX));
        assert!(!super::decode_avx10_1_support(false, 1, 1, REQUIRED_XCR0_STATE));
        assert!(!super::decode_avx10_1_support(true, 0, 1, REQUIRED_XCR0_STATE));
        assert!(!super::decode_avx10_1_support(true, 1, 0, REQUIRED_XCR0_STATE));

        for state_bit in [1, 2, 5, 6, 7] {
            assert!(!super::decode_avx10_1_support(
                true,
                1,
                1,
                REQUIRED_XCR0_STATE & !(1 << state_bit)
            ));
        }
    }

    #[test]
    fn amx_product_eligibility_requires_cpu_os_compiler_and_backend_proof() {
        let all_proven = AmxCapability::from_signals(AmxSignals {
            cpu_tile: true,
            cpu_int8: true,
            cpu_bf16: true,
            os_tile_state_permitted: Some(true),
            compiler_target_tile: true,
            compiler_target_int8: true,
            compiler_target_bf16: true,
            verified_backend: true,
        });
        assert!(all_proven.product_dispatch_eligible);

        let without_bf16 = AmxCapability::from_signals(AmxSignals {
            cpu_bf16: false,
            compiler_target_bf16: false,
            ..AmxSignals {
                cpu_tile: true,
                cpu_int8: true,
                cpu_bf16: true,
                os_tile_state_permitted: Some(true),
                compiler_target_tile: true,
                compiler_target_int8: true,
                compiler_target_bf16: true,
                verified_backend: true,
            }
        });
        assert!(without_bf16.product_dispatch_eligible);

        let missing_os = AmxCapability::from_signals(AmxSignals {
            os_tile_state_permitted: None,
            ..AmxSignals {
                cpu_tile: true,
                cpu_int8: true,
                cpu_bf16: true,
                os_tile_state_permitted: Some(true),
                compiler_target_tile: true,
                compiler_target_int8: true,
                compiler_target_bf16: true,
                verified_backend: true,
            }
        });
        assert!(!missing_os.product_dispatch_eligible);

        let missing_compiler = AmxCapability::from_signals(AmxSignals {
            compiler_target_tile: false,
            ..AmxSignals {
                cpu_tile: true,
                cpu_int8: true,
                cpu_bf16: true,
                os_tile_state_permitted: Some(true),
                compiler_target_tile: true,
                compiler_target_int8: true,
                compiler_target_bf16: true,
                verified_backend: true,
            }
        });
        assert!(!missing_compiler.product_dispatch_eligible);

        let missing_backend = AmxCapability::from_signals(AmxSignals {
            verified_backend: false,
            ..AmxSignals {
                cpu_tile: true,
                cpu_int8: true,
                cpu_bf16: true,
                os_tile_state_permitted: Some(true),
                compiler_target_tile: true,
                compiler_target_int8: true,
                compiler_target_bf16: true,
                verified_backend: true,
            }
        });
        assert!(!missing_backend.product_dispatch_eligible);
    }

    #[test]
    fn simd_dispatch_matrix_requires_every_target_feature() {
        let mut features = CpuFeatures { avx512f: true, ..CpuFeatures::default() };

        assert!(!features.simd_dispatch_matrix().avx512_ack);
        features.avx512vl = true;
        assert!(features.simd_dispatch_matrix().avx512_ack);

        features.avx512bw = true;
        features.avx512vbmi2 = true;
        assert!(features.simd_dispatch_matrix().avx512_vbmi2);
        features.avx512f = false;
        assert!(!features.simd_dispatch_matrix().avx512_vbmi2);
        features.avx512f = true;

        features.avx512cd = true;
        assert!(!features.simd_dispatch_matrix().avx512_vpopcnt);
        features.avx512vpopcntdq = true;
        assert!(features.simd_dispatch_matrix().avx512_vpopcnt);

        features.avx512vnni = true;
        assert!(features.simd_dispatch_matrix().sha256_vnni);
        features.avx512vl = false;
        assert!(!features.simd_dispatch_matrix().sha256_vnni);
        features.avx512vl = true;

        features.vaes = true;
        features.aesni = true;
        assert!(!features.simd_dispatch_matrix().vaes_aes);
        features.sse2 = true;
        assert!(features.simd_dispatch_matrix().vaes_aes);

        features.vpclmulqdq = true;
        features.sse41 = true;
        assert!(features.simd_dispatch_matrix().gf16_vpclmul);
        features.pclmulqdq = true;
        assert!(features.simd_dispatch_matrix().gf16_pclmul);

        features.fma3 = true;
        assert!(features.simd_dispatch_matrix().neural_avx512);
        features.avx2 = true;
        assert!(features.simd_dispatch_matrix().neural_avx2);

        features.avx = true;
        features.ssse3 = true;
        assert!(features.simd_dispatch_matrix().chacha_avx);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_profile_selection_keeps_bmi2_explicit() {
        let cases = [
            ("p0a", CpuFeatures { sse2: true, ..CpuFeatures::default() }, CpuProfile::X86_P0a),
            ("p0b", CpuFeatures { ssse3: true, ..CpuFeatures::default() }, CpuProfile::X86_P0b),
            ("p1a", CpuFeatures { sse42: true, ..CpuFeatures::default() }, CpuProfile::X86_P1a),
            (
                "p1b",
                CpuFeatures { aesni: true, pclmulqdq: true, ..CpuFeatures::default() },
                CpuProfile::X86_P1b,
            ),
            ("p1f", CpuFeatures { avx: true, ..CpuFeatures::default() }, CpuProfile::X86_P1f),
            ("p3a", CpuFeatures { avx512f: true, ..CpuFeatures::default() }, CpuProfile::X86_P3a),
            (
                "p3b",
                CpuFeatures {
                    avx512f: true,
                    vaes: true,
                    vpclmulqdq: true,
                    ..CpuFeatures::default()
                },
                CpuProfile::X86_P3b,
            ),
            (
                "p3c",
                CpuFeatures {
                    avx512f: true,
                    avx512bw: true,
                    avx512vbmi2: true,
                    ..CpuFeatures::default()
                },
                CpuProfile::X86_P3c,
            ),
            (
                "p3d",
                CpuFeatures {
                    avx512f: true,
                    avx512cd: true,
                    avx512vpopcntdq: true,
                    ..CpuFeatures::default()
                },
                CpuProfile::X86_P3d,
            ),
            (
                "p3e",
                CpuFeatures { avx512f: true, gfni: true, ..CpuFeatures::default() },
                CpuProfile::X86_P3e,
            ),
            (
                "p4a",
                CpuFeatures { avx10_1_256: true, ..CpuFeatures::default() },
                CpuProfile::X86_P4a,
            ),
            (
                "p4b",
                CpuFeatures { avx10_1_512: true, ..CpuFeatures::default() },
                CpuProfile::X86_P4b,
            ),
        ];

        for (name, features, expected) in cases {
            let without_bmi2 = CpuFeatures { bmi2: false, ..features };
            assert_eq!(
                FeatureDetector::profile_from_features(without_bmi2),
                expected,
                "automatic profile {name} must be selected without BMI2"
            );

            let with_bmi2 = CpuFeatures { bmi2: true, ..features };
            assert_eq!(
                FeatureDetector::profile_from_features(with_bmi2),
                expected,
                "automatic profile {name} must not gain a BMI2-dependent meaning"
            );
        }

        let p2a = CpuFeatures { avx2: true, ..CpuFeatures::default() };
        assert_eq!(FeatureDetector::profile_from_features(p2a), CpuProfile::X86_P2a);

        let p2b = CpuFeatures { avx2: true, bmi2: true, ..CpuFeatures::default() };
        assert_eq!(FeatureDetector::profile_from_features(p2b), CpuProfile::X86_P2b);
    }

    #[test]
    fn override_ref_selects_scalar() {
        let tag = with_override(Some("ref"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        assert_eq!(tag, "scalar");
    }

    #[test]
    fn override_invalid_value_graceful_fallback() {
        let tag = with_override(Some("definitely-not-a-kernel"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()), "unexpected policy tag: {}", tag);
    }

    #[test]
    fn override_avx2_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("avx2"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.features_full().simd_dispatch_matrix().avx2 {
            assert_eq!(tag, "avx2");
        } else {
            let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_avx512_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("avx512"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.features_full().simd_dispatch_matrix().avx512_vbmi {
            assert_eq!(tag, "avx512");
        } else {
            let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_neon_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("neon"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.features_full().neon && det.features_full().aes && det.features_full().pmull {
            assert_eq!(tag, "neon");
        } else {
            let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_sve2_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("sve2"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.has_feature(CpuFeature::SVE2) {
            assert_eq!(tag, "sve2");
        } else {
            let allowed = ["avx512vbmi2", "avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn ascii_printable_count_matches_scalar_reference() {
        let data: Vec<u8> = (0..=u8::MAX).collect();
        let expected = data.iter().filter(|byte| matches!(byte, 0x20..=0x7E)).count();
        assert_eq!(super::count_ascii_printable(&data), expected);
    }

    #[test]
    fn ascii_printable_count_handles_empty_input() {
        assert_eq!(super::count_ascii_printable(&[]), 0);
    }
}
