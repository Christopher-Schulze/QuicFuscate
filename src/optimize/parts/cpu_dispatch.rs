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
    /// x86_64: AVX10.1 256-bit support.
    pub avx10_1_256: bool,
    /// x86_64: AVX10.1 512-bit support.
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

    /// Apple Silicon: Apple Matrix Extensions.
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

/// CPU Performance Profile for optimized dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum CpuProfile {
    /// SSE2 baseline (no AES acceleration).
    X86_P0a,
    /// SSSE3 baseline (byte-shuffle; no AES acceleration).
    X86_P0b,
    /// SSE4.2 + POPCNT + CRC32 (no crypto).
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
    /// AVX10.1 256-bit baseline.
    X86_P4a,
    /// AVX10.1 512-bit baseline (full-width vectors).
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

    /// Apple Silicon: NEON + Crypto + AMX.
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
    /// AVX10.1 256-bit baseline.
    AVX10_1_256,
    /// AVX10.1 512-bit baseline (full-width vectors).
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
    /// Apple AMX (matrix coprocessor).
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
                    log::info!("  Apple AMX: matrix acceleration available");
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

            // AVX10 detection (1.1 preview flags exposed by rustc 1.86)
            #[cfg(feature = "internal_avx10_preview")]
            {
                let has_avx10_512 = is_x86_feature_detected!("avx10.1-512");
                if has_avx10_512 {
                    features.insert(CpuFeature::AVX10_1_512);
                    features_full.avx10_1_512 = true;
                    features_full.avx512f = true;
                    optimal_simd_width = optimal_simd_width.max(64);
                }
                let has_avx10_256 = has_avx10_512 || is_x86_feature_detected!("avx10.1-256");
                if has_avx10_256 {
                    features.insert(CpuFeature::AVX10_1_256);
                    features_full.avx10_1_256 = true;
                    features_full.avx2 = true;
                    optimal_simd_width = optimal_simd_width.max(32);
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

            // AMX Tile Extensions - Intel 4th Gen Xeon and beyond!
            // Note: AMX detection requires special OS support and may not be available via is_x86_feature_detected!
            // For now, we detect based on CPU model and OS support
            if let Ok(cpuid) = std::process::Command::new("cpuid").output() {
                let output = String::from_utf8_lossy(&cpuid.stdout);
                if output.contains("AMX-TILE") || output.contains("amx_tile") {
                    features.insert(CpuFeature::AMX_TILE);
                    features_full.amx_tile = true;
                }
                if output.contains("AMX-INT8") || output.contains("amx_int8") {
                    features.insert(CpuFeature::AMX_INT8);
                    features_full.amx_int8 = true;
                }
                if output.contains("AMX-BF16") || output.contains("amx_bf16") {
                    features.insert(CpuFeature::AMX_BF16);
                    features_full.amx_bf16 = true;
                }
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

        Self { features, features_full, cache_line_size, has_avx512, optimal_simd_width }
    }

    /// Get full CPU features struct
    pub fn features_full(&self) -> &CpuFeatures {
        &self.features_full
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

        #[cfg(target_arch = "x86_64")]
        {
            if self.has_feature(CpuFeature::AVX10_1_512) {
                return CpuProfile::X86_P4b;
            }
            if self.has_feature(CpuFeature::AVX10_1_256) {
                return CpuProfile::X86_P4a;
            }

            // Check from highest to lowest capability
            if self.has_feature(CpuFeature::AVX512F) {
                if self.has_feature(CpuFeature::GFNI) {
                    return CpuProfile::X86_P3e;
                }
                if self.has_feature(CpuFeature::AVX512VPOPCNTDQ) {
                    return CpuProfile::X86_P3d;
                }
                if self.has_feature(CpuFeature::AVX512VBMI2) {
                    return CpuProfile::X86_P3c;
                }
                if self.has_feature(CpuFeature::VAES) && self.has_feature(CpuFeature::VPCLMULQDQ) {
                    return CpuProfile::X86_P3b;
                }
                return CpuProfile::X86_P3a;
            }

            if self.has_feature(CpuFeature::AVX2) {
                if self.has_feature(CpuFeature::BMI2) {
                    return CpuProfile::X86_P2b;
                }
                return CpuProfile::X86_P2a;
            }

            if self.has_feature(CpuFeature::AVX) {
                return CpuProfile::X86_P1f;
            }

            if self.has_feature(CpuFeature::AESNI) && self.has_feature(CpuFeature::PCLMULQDQ) {
                return CpuProfile::X86_P1b;
            }

            if self.has_feature(CpuFeature::SSE42) {
                return CpuProfile::X86_P1a;
            }

            // Legacy fallbacks
            if self.has_feature(CpuFeature::SSSE3) {
                return CpuProfile::X86_P0b;
            }
            if self.has_feature(CpuFeature::SSE2) {
                return CpuProfile::X86_P0a;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(target_os = "macos")]
            if self.has_feature(CpuFeature::APPLE_AMX) {
                return CpuProfile::Apple_M;
            }

            if self.has_feature(CpuFeature::SVE2) {
                return CpuProfile::ARM_A2;
            }

            if self.has_feature(CpuFeature::NEON) {
                if self.has_feature(CpuFeature::SHA256) || self.has_feature(CpuFeature::SHA512) {
                    return CpuProfile::ARM_A1d;
                }
                if self.has_feature(CpuFeature::PMULL) {
                    return CpuProfile::ARM_A1c;
                }
                if self.has_feature(CpuFeature::AES) {
                    return CpuProfile::ARM_A1b;
                }
                if self.has_feature(CpuFeature::CRC32) {
                    return CpuProfile::ARM_A1a;
                }
                return CpuProfile::ARM_A0;
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            if self.has_feature(CpuFeature::RVV) {
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
        match profile {
            CpuProfile::Scalar => true,
            CpuProfile::X86_P0a => self.has_feature(CpuFeature::SSE2),
            CpuProfile::X86_P0b => self.has_feature(CpuFeature::SSSE3),
            CpuProfile::X86_P1a => self.has_feature(CpuFeature::SSE42),
            CpuProfile::X86_P1b => {
                self.has_feature(CpuFeature::AESNI) && self.has_feature(CpuFeature::PCLMULQDQ)
            }
            CpuProfile::X86_P1f => self.has_feature(CpuFeature::AVX),
            CpuProfile::X86_P2a => self.has_feature(CpuFeature::AVX2),
            CpuProfile::X86_P2b => {
                self.has_feature(CpuFeature::AVX2) && self.has_feature(CpuFeature::BMI2)
            }
            CpuProfile::X86_P3a => self.has_feature(CpuFeature::AVX512F),
            CpuProfile::X86_P3b => {
                self.has_feature(CpuFeature::AVX512F)
                    && self.has_feature(CpuFeature::VAES)
                    && self.has_feature(CpuFeature::VPCLMULQDQ)
            }
            CpuProfile::X86_P3c => {
                self.has_feature(CpuFeature::AVX512F) && self.has_feature(CpuFeature::AVX512VBMI2)
            }
            CpuProfile::X86_P3d => {
                self.has_feature(CpuFeature::AVX512F)
                    && self.has_feature(CpuFeature::AVX512VPOPCNTDQ)
            }
            CpuProfile::X86_P3e => {
                self.has_feature(CpuFeature::AVX512F) && self.has_feature(CpuFeature::GFNI)
            }
            CpuProfile::X86_P4a => self.has_feature(CpuFeature::AVX10_1_256),
            CpuProfile::X86_P4b => self.has_feature(CpuFeature::AVX10_1_512),
            CpuProfile::ARM_A0 => self.has_feature(CpuFeature::NEON),
            CpuProfile::ARM_A1a => {
                self.has_feature(CpuFeature::NEON) && self.has_feature(CpuFeature::CRC32)
            }
            CpuProfile::ARM_A1b => self.has_feature(CpuFeature::AES),
            CpuProfile::ARM_A1c => {
                self.has_feature(CpuFeature::AES) && self.has_feature(CpuFeature::PMULL)
            }
            CpuProfile::ARM_A1d => {
                self.has_feature(CpuFeature::AES)
                    && self.has_feature(CpuFeature::PMULL)
                    && (self.has_feature(CpuFeature::SHA1) || self.has_feature(CpuFeature::SHA2))
            }
            CpuProfile::ARM_A2 => self.has_feature(CpuFeature::SVE2),
            CpuProfile::Apple_M => self.has_feature(CpuFeature::APPLE_AMX),
            CpuProfile::RVV => self.has_feature(CpuFeature::RVV),
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

        // Process remainder with AVX2
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst[i..].as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            let c = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, c);
            i += 32;
        }

        // Process remainder scalar
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
    let has_avx10_512 = detector.features.contains(&CpuFeature::AVX10_1_512);
    let has_avx10_256 = detector.features.contains(&CpuFeature::AVX10_1_256);
    let has_avx512 = has_avx10_512 || detector.features.contains(&CpuFeature::AVX512F);
    let has_avx2 = detector.features.contains(&CpuFeature::AVX2) || has_avx10_256 || has_avx10_512;

    // Priority order: GFNI > VBMI2 > VBMI > AVX2 > SSE2 > SVE2 > SVE > NEON
    if has_avx512 && detector.has_feature(CpuFeature::GFNI) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Gfni)
    } else if has_avx512 && detector.has_feature(CpuFeature::AVX512VBMI2) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Vbmi2)
    } else if has_avx512 && detector.has_feature(CpuFeature::AVX512VBMI) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512)
    } else if has_avx2 {
        telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if has_avx10_256 {
            telemetry::SIMD_USAGE_AVX10_256.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx2)
    // SSE2 removed - fallback directly to scalar
    } else if detector.has_feature(CpuFeature::PCLMULQDQ) {
        f(&Pclmulqdq)
    } else if detector.has_feature(CpuFeature::SVE2) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve2)
    } else if detector.has_feature(CpuFeature::SVE) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve)
    } else if detector.has_feature(CpuFeature::NEON_CRYPTO) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&NeonCrypto)
    } else if detector.has_feature(CpuFeature::NEON) {
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

#[cfg(test)]
std::thread_local! {
    static TEST_FEC_KERNEL_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Test-only: overrides the FEC kernel SIMD dispatch policy.
#[cfg(test)]
pub fn __test_set_fec_kernel_override(val: Option<&str>) {
    TEST_FEC_KERNEL_OVERRIDE.with(|value| {
        *value.borrow_mut() = val.map(str::to_lowercase);
    });
}

pub(crate) fn dispatch_bitslice<F, R>(mut f: F) -> R
where
    F: FnMut(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();

    // Resolve optional runtime override (test override takes precedence)
    let ov: Option<String> = {
        #[cfg(test)]
        {
            if let Some(s) = TEST_FEC_KERNEL_OVERRIDE.with(|value| value.borrow().clone()) {
                Some(s)
            } else {
                FEC_KERNEL_OVERRIDE
                    .get_or_init(|| {
                        crate::env_utils::EnvSnapshot::capture()
                            .first(["QUICFUSCATE_FEC_KERNEL"])
                            .map(|value| value.to_ascii_lowercase())
                    })
                    .clone()
            }
        }
        #[cfg(not(test))]
        {
            FEC_KERNEL_OVERRIDE
                .get_or_init(|| {
                    crate::env_utils::EnvSnapshot::capture()
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
                if detector.has_feature(CpuFeature::AVX512F)
                    && detector.has_feature(CpuFeature::AVX512VBMI2)
                    && detector.has_feature(CpuFeature::AVX512BW)
                {
                    return f(&Avx512Vbmi2);
                } else {
                    warn!(
                        "QUICFUSCATE_FEC_KERNEL=avx512vbmi2 requested but unsupported; falling back to auto"
                    );
                }
            }
            "avx512" => {
                if detector.has_feature(CpuFeature::AVX512F)
                    && detector.has_feature(CpuFeature::AVX512VBMI)
                    && detector.has_feature(CpuFeature::PCLMULQDQ)
                {
                    return f(&Avx512);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx512 requested but unsupported; falling back to auto");
                }
            }
            "avx2" => {
                if detector.has_feature(CpuFeature::AVX2)
                    && detector.has_feature(CpuFeature::PCLMULQDQ)
                {
                    return f(&Avx2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx2 requested but unsupported; falling back to auto");
                }
            }
            "neon" => {
                if detector.has_feature(CpuFeature::NEON)
                    && detector.has_feature(CpuFeature::NEON_CRYPTO)
                {
                    return f(&Neon);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=neon requested but unsupported; falling back to auto");
                }
            }
            "sve2" => {
                if detector.has_feature(CpuFeature::SVE2) {
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
    if detector.has_feature(CpuFeature::AVX512F)
        && detector.has_feature(CpuFeature::AVX512VBMI2)
        && detector.has_feature(CpuFeature::AVX512BW)
    {
        f(&Avx512Vbmi2)
    } else if detector.has_feature(CpuFeature::AVX512F)
        && detector.has_feature(CpuFeature::AVX512VBMI)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2) && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2) {
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::SVE2) {
        f(&Sve2)
    } else if detector.has_feature(CpuFeature::NEON)
        && detector.has_feature(CpuFeature::NEON_CRYPTO)
    {
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
    use super::{
        bitslice_policy_tag, dispatch_bitslice, with_override, PROFILE_OVERRIDE,
        TEST_FEC_KERNEL_OVERRIDE,
    };
    use crate::simd::{CpuFeature, FeatureDetector};
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
            assert!(super::set_profile_override_for_tests(crate::simd::CpuProfile::Scalar));
            child_barrier.wait();
            FeatureDetector::instance().profile()
        });

        barrier.wait();
        assert_eq!(PROFILE_OVERRIDE.with(std::cell::Cell::get), 0);
        assert_eq!(child.join().expect("profile override thread"), crate::simd::CpuProfile::Scalar);
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
        if det.has_feature(CpuFeature::AVX2) && det.has_feature(CpuFeature::PCLMULQDQ) {
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
        if det.has_feature(CpuFeature::AVX512F)
            && det.has_feature(CpuFeature::AVX512VBMI)
            && det.has_feature(CpuFeature::PCLMULQDQ)
        {
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
        if det.has_feature(CpuFeature::NEON) && det.has_feature(CpuFeature::NEON_CRYPTO) {
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
}
