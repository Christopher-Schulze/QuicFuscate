use super::*;
use std::collections::HashSet;

/// CPU feature detector with ULTRA-SOPHISTICATED detection!
pub struct FeatureDetector {
    pub(super) features: HashSet<CpuFeature>,
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
    pub(crate) static PROFILE_OVERRIDE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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
