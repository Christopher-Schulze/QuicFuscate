//! CPU feature detection, cache-aware dispatch, and low-level SIMD policy contracts.
//!
//! This workspace leaf owns runtime hardware capability observation and the pure policy
//! selectors consumed by crypto, FEC, transport, and optimization code. It has no dependency on
//! any product subsystem; environment values and metrics cross the boundary through qf-common
//! and qf-telemetry.

use qf_telemetry as telemetry;

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

#[cfg(any(test, all(target_arch = "x86_64", feature = "internal_avx10_preview")))]
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

mod feature_detection;
pub use feature_detection::FeatureDetector;
#[cfg(test)]
pub(crate) use feature_detection::PROFILE_OVERRIDE;
#[cfg(any(test, feature = "rust-tests"))]
pub use feature_detection::{clear_profile_override_for_tests, set_profile_override_for_tests};
mod simd_dispatch;
pub use simd_dispatch::{CacheHierarchy, CacheLevel, SimdDispatch};
mod simd_policy;
#[cfg(any(test, feature = "rust-tests"))]
pub use simd_policy::__test_set_fec_kernel_override;
#[cfg(test)]
pub(crate) use simd_policy::TEST_FEC_KERNEL_OVERRIDE;
#[cfg(test)]
pub(crate) use simd_policy::{bitslice_policy_tag, with_override};
pub use simd_policy::{
    dispatch, dispatch_bitslice, Avx2, Avx512, Avx512Gfni, Avx512Vbmi2, Neon, NeonCrypto,
    Pclmulqdq, Scalar, SimdPolicy, Sse2, Sve, Sve2,
};

#[cfg(test)]
mod tests;
