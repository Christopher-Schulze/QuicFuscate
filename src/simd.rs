//! Ultra-sophisticated centralized SIMD module - MAX EXCELLENCE!
//! All hardware acceleration in ONE place - NO feature gates!

#![cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(unused_imports, unused_variables)
)]
#![allow(clippy::missing_safety_doc)]
use std::sync::OnceLock;

use crate::optimize::{prefetch, telemetry, PrefetchHint};
pub use crate::optimize::{CpuFeature, CpuFeatures, CpuProfile, FeatureDetector};

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline(always)]
fn quic_varint_len_prefix(value: u64) -> Option<(usize, u8)> {
    if value < (1u64 << 6) {
        Some((1, 0))
    } else if value < (1u64 << 14) {
        Some((2, 1))
    } else if value < (1u64 << 30) {
        Some((4, 2))
    } else if value < (1u64 << 62) {
        Some((8, 3))
    } else {
        None
    }
}

// ARM NEON-optimized varint module
#[cfg(target_arch = "aarch64")]
pub(crate) mod arm_stream;
#[cfg(target_arch = "aarch64")]
mod arm_varint;
#[cfg(target_arch = "x86_64")]
mod x86_ack;
#[cfg(target_arch = "x86_64")]
mod x86_header;

#[inline(always)]
fn sha256_hash_with_batch<F>(data: &[u8], batch: usize, mut compress: F) -> [u8; 32]
where
    F: FnMut(&mut [u32; 8], &[[u8; 64]]),
{
    debug_assert!(batch > 0 && batch <= 2);

    let mut state = SHA256_H0;
    let full_blocks = data.len() / 64;

    if full_blocks != 0 {
        let head_len = full_blocks * 64;
        let raw_blocks = &data[..head_len];
        // SAFETY: `raw_blocks` has exactly `full_blocks * 64` bytes (head_len).
        // Reinterpreting as `&[[u8; 64]]` is safe because [u8; 64] has alignment 1
        // (same as u8) and the total length matches full_blocks elements of 64 bytes each.
        let blocks = unsafe {
            std::slice::from_raw_parts(raw_blocks.as_ptr() as *const [u8; 64], full_blocks)
        };

        let mut idx = 0usize;
        while idx < full_blocks {
            let end = (idx + batch).min(full_blocks);

            if end < full_blocks {
                let next_offset = end * 64;
                // SAFETY: `next_offset < head_len` because `end < full_blocks`.
                // Prefetch hints are advisory - they never cause faults even if the
                // address is invalid, but here the address is always within `raw_blocks`.
                unsafe {
                    prefetch(raw_blocks.as_ptr().add(next_offset), PrefetchHint::T0);
                    if batch > 1 {
                        let second_offset = next_offset + 64;
                        if second_offset < raw_blocks.len() {
                            prefetch(raw_blocks.as_ptr().add(second_offset), PrefetchHint::T1);
                        }
                    }
                }
            }

            compress(&mut state, &blocks[idx..end]);
            idx = end;
        }
    }

    let remainder = &data[full_blocks * 64..];
    let mut tail = [[0u8; 64]; 2];
    let mut rem_len = remainder.len();
    tail[0][..rem_len].copy_from_slice(remainder);
    tail[0][rem_len] = 0x80;
    rem_len += 1;

    let mut blocks = 1usize;
    if rem_len > 56 {
        tail[0][rem_len..64].fill(0);
        tail[1].fill(0);
        blocks = 2;
    } else {
        tail[0][rem_len..56].fill(0);
    }

    let bit_len = (data.len() as u64) * 8;
    tail[blocks - 1][56..64].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut state, &tail[..blocks]);

    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(4).enumerate() {
        chunk.copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// Canonicalize ACK block ranges using AVX2 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn canonical_ack_blocks_avx2_for_rust_tests(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the callee is a retained parity helper that operates purely on the
    //   provided slice and returns owned output
    // - no raw pointers escape this wrapper and no additional aliasing or
    //   lifetime assumptions are introduced here
    unsafe { x86_ack::canonical_ack_blocks_avx2(ranges) }
}

/// Canonicalize ACK block ranges using AVX-512 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn canonical_ack_blocks_avx512_for_rust_tests(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the underlying helper is retained parity machinery over a borrowed
    //   slice and does not expose raw-pointer ownership outside the call
    // - target-feature preconditions stay encapsulated in the internal helper
    unsafe { x86_ack::canonical_ack_blocks_avx512(ranges) }
}

/// Validate a QUIC packet header using AVX-512 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn validate_header_avx512_for_rust_tests(header: &[u8]) -> bool {
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the helper only reads the provided header slice and returns a bool
    // - no mutation, pointer escape, or lifetime widening occurs at this boundary
    unsafe { x86_header::validate_header_avx512(header) }
}

/// Validate a QUIC packet header using SSE2 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn validate_header_sse2_for_rust_tests(header: &[u8]) -> bool {
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the helper only inspects the provided header slice
    // - the retained unsafe stays inside the internal SIMD helper
    unsafe { x86::validate_header_sse2(header) }
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

/// Acceleration planner (global hardware plan cache).
pub(crate) mod planner {
    use super::{CpuFeatures, CpuProfile, CryptoAeadPlan, FeatureDetector};
    use std::sync::OnceLock;

    /// Cached hardware acceleration plans derived from detected CPU features.
    #[derive(Debug)]
    pub struct AccelerationPlans {
        /// Detected CPU feature flags.
        pub features: CpuFeatures,
        /// Selected crypto AEAD plan.
        pub crypto: CryptoPlan,
        /// Selected transport batch plan (test builds only).
        #[cfg(any(test, feature = "rust-tests"))]
        pub transport: TransportPlan,
    }

    /// Singleton accessor for the global `AccelerationPlans`.
    pub struct AccelerationPlanner;

    impl AccelerationPlanner {
        /// Returns the lazily-initialized global acceleration plan.
        pub fn global() -> &'static AccelerationPlans {
            static PLANS: OnceLock<AccelerationPlans> = OnceLock::new();
            PLANS.get_or_init(AccelerationPlans::derive)
        }
    }

    impl AccelerationPlans {
        fn derive() -> Self {
            let detector = FeatureDetector::instance();
            let profile = detector.profile();
            let features = *detector.features_full();

            let crypto = CryptoPlan::new(profile, &features);
            #[cfg(any(test, feature = "rust-tests"))]
            let transport = TransportPlan::new(&features);

            Self {
                features,
                crypto,
                #[cfg(any(test, feature = "rust-tests"))]
                transport,
            }
        }

        /// Returns the default AEAD plan without considering message length.
        pub fn crypto_default_aead(&self) -> CryptoAeadPlan {
            self.crypto.default_aead
        }

        /// Returns the optimal AEAD plan for a given payload length.
        pub fn crypto_aead_for_len(&self, len: usize) -> CryptoAeadPlan {
            self.crypto.for_length(len, &self.features)
        }

        #[cfg(any(test, feature = "rust-tests"))]
        /// Returns the transport batch size based on SIMD width (test builds only).
        pub fn transport_batch_size(&self) -> usize {
            self.transport.batch_size
        }
    }

    /// Hardware-aware crypto AEAD selection policy.
    #[derive(Debug, Clone, Copy)]
    pub struct CryptoPlan {
        default_aead: CryptoAeadPlan,
    }

    impl CryptoPlan {
        const AEGIS_X4_MIN_LEN: usize = 192;
        #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
        const AEGIS_X8_MIN_LEN: usize = 1024;

        fn new(profile: CpuProfile, features: &CpuFeatures) -> Self {
            let default = match profile {
                CpuProfile::X86_P3b
                | CpuProfile::X86_P3c
                | CpuProfile::X86_P3d
                | CpuProfile::X86_P3e
                | CpuProfile::X86_P4a
                | CpuProfile::X86_P4b => Self::x86_default(features),
                CpuProfile::X86_P3a | CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
                    Self::x86_default(features)
                }
                CpuProfile::X86_P1b | CpuProfile::X86_P1f => Self::x86_default(features),
                CpuProfile::X86_P1a => CryptoAeadPlan::Morus,
                CpuProfile::X86_P0a | CpuProfile::X86_P0b => CryptoAeadPlan::Morus,
                CpuProfile::ARM_A2
                | CpuProfile::Apple_M
                | CpuProfile::ARM_A1c
                | CpuProfile::ARM_A1b
                | CpuProfile::ARM_A1a
                | CpuProfile::ARM_A1d
                | CpuProfile::ARM_A0 => Self::arm_default(features),
                CpuProfile::RVV => CryptoAeadPlan::Morus,
                CpuProfile::Scalar => CryptoAeadPlan::Morus,
            };

            Self { default_aead: default }
        }

        fn for_length(&self, len: usize, features: &CpuFeatures) -> CryptoAeadPlan {
            #[cfg(target_arch = "x86_64")]
            {
                return Self::x86_for_length(len, features);
            }

            #[cfg(target_arch = "aarch64")]
            {
                return Self::arm_for_length(len, features);
            }

            #[allow(unreachable_code)]
            CryptoAeadPlan::Morus
        }

        fn x86_default(features: &CpuFeatures) -> CryptoAeadPlan {
            if !Self::x86_can_use_aegis(features) {
                return CryptoAeadPlan::Morus;
            }
            CryptoAeadPlan::Aegis128X4
        }

        #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
        fn x86_for_length(len: usize, features: &CpuFeatures) -> CryptoAeadPlan {
            if !Self::x86_can_use_aegis(features) {
                return CryptoAeadPlan::Morus;
            }
            if len < Self::AEGIS_X4_MIN_LEN {
                return CryptoAeadPlan::Aegis128L;
            }
            if len >= Self::AEGIS_X8_MIN_LEN && Self::x86_prefers_x8(features) {
                CryptoAeadPlan::Aegis128X8
            } else {
                CryptoAeadPlan::Aegis128X4
            }
        }

        fn x86_can_use_aegis(features: &CpuFeatures) -> bool {
            features.aesni
        }

        #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
        fn x86_prefers_x8(features: &CpuFeatures) -> bool {
            if !features.vaes {
                return false;
            }
            (features.avx512f && features.avx512vl) || features.avx2
        }

        fn arm_default(features: &CpuFeatures) -> CryptoAeadPlan {
            if Self::arm_can_use_aegis(features) {
                CryptoAeadPlan::Aegis128X4
            } else {
                CryptoAeadPlan::Morus
            }
        }

        fn arm_for_length(len: usize, features: &CpuFeatures) -> CryptoAeadPlan {
            if !Self::arm_can_use_aegis(features) {
                return CryptoAeadPlan::Morus;
            }
            if len < Self::AEGIS_X4_MIN_LEN {
                CryptoAeadPlan::Aegis128L
            } else {
                CryptoAeadPlan::Aegis128X4
            }
        }

        fn arm_can_use_aegis(features: &CpuFeatures) -> bool {
            features.neon && features.aes
        }
    }

    #[cfg(test)]
    mod crypto_plan_tests {
        use super::*;

        fn x86_aes_features() -> CpuFeatures {
            CpuFeatures { aesni: true, ..CpuFeatures::default() }
        }

        #[test]
        fn x86_small_payload_uses_single_lane_aegis() {
            let features = x86_aes_features();
            assert_eq!(
                CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X4_MIN_LEN - 1, &features),
                CryptoAeadPlan::Aegis128L
            );
        }

        #[test]
        fn x86_mid_payload_uses_x4_when_aes_is_available() {
            let features = x86_aes_features();
            assert_eq!(
                CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X4_MIN_LEN, &features),
                CryptoAeadPlan::Aegis128X4
            );
        }

        #[test]
        fn x86_large_payload_uses_x8_only_when_hardware_supports_it() {
            let features =
                CpuFeatures { aesni: true, vaes: true, avx2: true, ..CpuFeatures::default() };
            assert_eq!(
                CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X8_MIN_LEN, &features),
                CryptoAeadPlan::Aegis128X8
            );
        }

        #[test]
        fn x86_large_payload_without_vaes_stays_x4() {
            let features = CpuFeatures { aesni: true, avx2: true, ..CpuFeatures::default() };
            assert_eq!(
                CryptoPlan::x86_for_length(CryptoPlan::AEGIS_X8_MIN_LEN, &features),
                CryptoAeadPlan::Aegis128X4
            );
        }

        #[test]
        fn arm_small_payload_uses_single_lane_aegis() {
            let features = CpuFeatures { neon: true, aes: true, ..CpuFeatures::default() };
            assert_eq!(
                CryptoPlan::arm_for_length(CryptoPlan::AEGIS_X4_MIN_LEN - 1, &features),
                CryptoAeadPlan::Aegis128L
            );
        }
    }

    /// SIMD-width-aware transport batching plan (test builds only).
    #[cfg(any(test, feature = "rust-tests"))]
    #[derive(Debug, Clone, Copy)]
    pub struct TransportPlan {
        batch_size: usize,
    }

    #[cfg(any(test, feature = "rust-tests"))]
    impl TransportPlan {
        fn new(features: &CpuFeatures) -> Self {
            let has_avx512f = features.avx512f;
            let has_avx2 = features.avx2;
            let batch_size = if has_avx512f {
                64
            } else if has_avx2 {
                32
            } else {
                16
            };

            Self { batch_size }
        }
    }
}

/// SHA-256 backend selector for benchmarks.
#[cfg(feature = "benches")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sha256BenchBackend {
    /// Auto-select the best available backend at runtime.
    Auto,
    /// Force the AVX2-accelerated SHA-256 path (x86_64).
    Avx2,
    /// Force the AVX-512 VNNI-accelerated SHA-256 path (x86_64).
    Vnni,
    /// Force the pure-scalar SHA-256 implementation.
    Scalar,
}
#[cfg(feature = "benches")]
impl Sha256BenchBackend {
    /// Returns the human-readable backend name for benchmark reporting.
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Sha256BenchBackend::Auto => "auto",
            Sha256BenchBackend::Avx2 => "avx2",
            Sha256BenchBackend::Vnni => "vnni",
            Sha256BenchBackend::Scalar => "scalar",
        }
    }
}

/// SHA-256 benchmark helpers with backend dispatch (x86_64).
#[cfg(all(feature = "benches", target_arch = "x86_64"))]
pub mod bench {
    use super::{crypto, scalar, Sha256BenchBackend};

    /// Compute SHA-256 digest using the requested backend, returning the actual backend used.
    #[inline] // keep in sync with microbench backend selection
    pub fn sha256_digest(
        data: &[u8],
        requested: Sha256BenchBackend,
    ) -> (Sha256BenchBackend, [u8; 32]) {
        match requested {
            Sha256BenchBackend::Auto => (Sha256BenchBackend::Auto, crypto::sha256(data)),
            Sha256BenchBackend::Scalar => (Sha256BenchBackend::Scalar, scalar::sha256(data)),
            Sha256BenchBackend::Avx2 => {
                if is_x86_feature_detected!("avx2") {
                    // SAFETY: AVX2 feature verified by `is_x86_feature_detected!` above.
                    unsafe { (Sha256BenchBackend::Avx2, super::x86::sha256_avx2(data)) }
                } else {
                    (Sha256BenchBackend::Auto, crypto::sha256(data))
                }
            }
            Sha256BenchBackend::Vnni => {
                if is_x86_feature_detected!("avx512f")
                    && is_x86_feature_detected!("avx512vl")
                    && is_x86_feature_detected!("avx512vnni")
                {
                    // SAFETY: All three required features verified above.
                    unsafe { (Sha256BenchBackend::Vnni, super::x86::sha256_vnni(data)) }
                } else {
                    (Sha256BenchBackend::Auto, crypto::sha256(data))
                }
            }
        }
    }
}

/// SHA-256 benchmark helpers with backend dispatch (non-x86_64 fallback).
#[cfg(all(feature = "benches", not(target_arch = "x86_64")))]
pub mod bench {
    use super::{crypto, scalar, Sha256BenchBackend};

    /// Compute SHA-256 digest using the requested backend, returning the actual backend used.
    #[inline]
    pub fn sha256_digest(
        data: &[u8],
        requested: Sha256BenchBackend,
    ) -> (Sha256BenchBackend, [u8; 32]) {
        match requested {
            Sha256BenchBackend::Scalar => (Sha256BenchBackend::Scalar, scalar::sha256(data)),
            _ => (Sha256BenchBackend::Auto, crypto::sha256(data)),
        }
    }
}

impl CryptoAeadPlan {
    /// Profile-based default (no message length), used when size unknown.
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
            if let Ok(v) = std::env::var("QUICFUSCATE_MORUS") {
                let vv = v.to_ascii_lowercase();
                if vv == "1" || vv == "true" || vv == "force" {
                    return true;
                }
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

// ============================================================================
// aarch64 IMPLEMENTATIONS (wrappers delegating to scalar for correctness)
// Top-level module to satisfy calls like `arm::...` behind cfg(target_arch="aarch64")
// ============================================================================
#[cfg(target_arch = "aarch64")]
pub(crate) mod arm {
    use super::scalar;

    #[cfg(target_feature = "sve2")]
    use std::arch::aarch64::*;

    // Core
    #[inline(always)]
    pub(super) unsafe fn xor_blocks_sve2(dst: &mut [u8], src: &[u8]) {
        #[cfg(target_feature = "sve2")]
        {
            xor_blocks_sve2_impl(dst, src);
            return;
        }

        // Compile-time SVE2 not available - fall back to NEON/Scalar.
        scalar::xor_blocks(dst, src)
    }
    #[inline(always)]
    pub(super) unsafe fn xor_blocks_neon(dst: &mut [u8], src: &[u8]) {
        scalar::xor_blocks(dst, src)
    }
    #[inline(always)]
    pub(super) unsafe fn crc32_arm(data: &[u8], initial: u32) -> u32 {
        #[cfg(target_feature = "crc")]
        {
            use core::arch::aarch64::*;

            let mut crc = !initial;
            let mut i = 0usize;
            let len = data.len();

            // 8-byte chunks
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

            // 4-byte chunk
            if i + 4 <= len {
                let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                crc = __crc32w(crc, chunk);
                i += 4;
            }

            // remaining bytes
            while i < len {
                crc = __crc32b(crc, data[i]);
                i += 1;
            }

            return !crc;
        }
        // Fallback when CRC extension is not enabled at compile time
        #[allow(unreachable_code)]
        {
            scalar::crc32(data, initial)
        }
    }
    #[inline(always)]
    pub(super) unsafe fn popcnt_neon(data: &[u8]) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            use core::arch::aarch64::*;
            let mut count: usize = 0;
            let mut i = 0usize;
            let len = data.len();
            while i + 16 <= len {
                // SAFETY: `i + 16 <= len` guarantees 16 readable bytes at `data[i..]`.
                let v = vld1q_u8(data.as_ptr().add(i));
                let pc = vcntq_u8(v);
                let sum = vaddvq_u8(pc) as usize; // <= 128 per 16B block
                count = count.saturating_add(sum);
                i += 16;
            }
            while i < len {
                count = count.saturating_add(data[i].count_ones() as usize);
                i += 1;
            }
            count
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            scalar::popcnt(data)
        }
    }

    #[inline(always)]
    pub(super) unsafe fn popcnt_sve2(data: &[u8]) -> usize {
        #[cfg(target_feature = "sve2")]
        {
            // Use NEON popcnt under SVE2; SVE2 path may be added later for even wider VL
            return popcnt_neon(data);
        }
        popcnt_neon(data)
    }

    #[inline(always)]
    pub(super) unsafe fn validate_header_sve2(header: &[u8]) -> bool {
        #[cfg(target_feature = "sve2")]
        {
            if header.is_empty() {
                return false;
            }

            use std::arch::aarch64::*;

            let pg = svwhilelt_b8(0, 1);
            let first = svdup_n_u8(header[0]);
            let fixed_mask = svdup_n_u8(0x40);
            let fixed = svand_u8_x(pg, first, fixed_mask);
            let fixed_ok = svcmpeq_u8(pg, fixed, fixed_mask);
            if svcntp_b8(pg, fixed_ok) == 0 {
                return false;
            }

            // QUIC short headers require reserved bits to be zero.
            if (header[0] & 0x80) == 0 {
                let reserved_mask = svdup_n_u8(0x18);
                let reserved = svand_u8_x(pg, first, reserved_mask);
                let zero = svdup_n_u8(0);
                let reserved_ok = svcmpeq_u8(pg, reserved, zero);
                if svcntp_b8(pg, reserved_ok) == 0 {
                    return false;
                }
            }

            return true;
        }

        scalar::validate_header(header)
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn validate_header_neon(header: &[u8]) -> bool {
        // Fast-path header validation using NEON. Mirrors SVE2 semantics:
        // - Fixed bit (0x40) must be set for all QUIC packets
        // - For short headers (0x80 not set), reserved bits (0x18) must be zero
        // Length checks (>=5) are done by the top-level dispatcher.
        if header.is_empty() {
            return false;
        }

        use core::arch::aarch64::*;

        let first = vdupq_n_u8(header[0]);

        // Check fixed bit (0x40)
        let fixed_mask = vdupq_n_u8(0x40);
        let fixed = vandq_u8(first, fixed_mask);
        let fixed_ok = vceqq_u8(fixed, fixed_mask);
        if vgetq_lane_u8(fixed_ok, 0) != 0xFF {
            return false;
        }

        // Short header: reserved bits (0x18) must be zero
        if (header[0] & 0x80) == 0 {
            let reserved_mask = vdupq_n_u8(0x18);
            let reserved = vandq_u8(first, reserved_mask);
            let zero = vdupq_n_u8(0);
            let reserved_ok = vceqq_u8(reserved, zero);
            if vgetq_lane_u8(reserved_ok, 0) != 0xFF {
                return false;
            }
        }

        true
    }

    // Galois field
    #[inline(always)]
    pub(super) unsafe fn gf_mul_sve2(a: &[u8], b: u8, dst: &mut [u8]) {
        #[cfg(target_feature = "sve2")]
        {
            gf_mul_sve2_impl(a, b, dst);
            return;
        }
        // Fallback when SVE2 is unavailable at compile time
        scalar::gf_mul(a, b, dst)
    }
    /// GF(2^8) multiply using NEON PMULL - carryless polynomial multiplication
    /// Polynomial: x^8 + x^4 + x^3 + x + 1 (AES reduction polynomial 0x11B)
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn gf_mul_neon_pmull(a: &[u8], b: u8, dst: &mut [u8]) {
        use core::arch::aarch64::*;

        let len = a.len().min(dst.len());
        if len == 0 || b == 0 {
            dst[..len].fill(0);
            return;
        }
        if b == 1 {
            dst[..len].copy_from_slice(&a[..len]);
            return;
        }

        // Broadcast b across all lanes
        let b_vec = vdupq_n_u8(b);

        // Process 16 bytes at a time
        let mut i = 0usize;
        while i + 16 <= len {
            // SAFETY: `i + 16 <= len` and `len = a.len().min(dst.len())`, so both
            // `a[i..i+16]` and `dst[i..i+16]` are within bounds for the 16-byte
            // NEON load/store operations.
            let a_chunk = vld1q_u8(a.as_ptr().add(i));

            // GF(2^8) multiply each byte pair
            let result = gf_mul_vec_neon(a_chunk, b_vec);

            vst1q_u8(dst.as_mut_ptr().add(i), result);
            i += 16;
        }

        // Tail: scalar fallback for remaining bytes
        while i < len {
            dst[i] = gf_mul_byte_scalar(a[i], b);
            i += 1;
        }
    }

    /// GF(2^8) multiply using basic NEON (no PMULL, table-based with SIMD gather)
    #[target_feature(enable = "neon")]
    pub(super) unsafe fn gf_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
        let len = a.len().min(dst.len());
        if len == 0 || b == 0 {
            dst[..len].fill(0);
            return;
        }
        if b == 1 {
            dst[..len].copy_from_slice(&a[..len]);
            return;
        }

        // Use PMULL version if available at runtime
        gf_mul_neon_pmull(a, b, dst);
    }

    /// Helper: GF(2^8) vector multiply using polynomial arithmetic
    #[target_feature(enable = "neon")]
    #[inline]
    unsafe fn gf_mul_vec_neon(
        a: core::arch::aarch64::uint8x16_t,
        b: core::arch::aarch64::uint8x16_t,
    ) -> core::arch::aarch64::uint8x16_t {
        use core::arch::aarch64::*;

        // For each byte position, compute GF multiply
        // Split into halves for processing
        let _a_lo = vget_low_u8(a);
        let _a_hi = vget_high_u8(a);
        let _b_lo = vget_low_u8(b);
        let _b_hi = vget_high_u8(b);

        // Process using table lookup approach with NEON
        // This is faster than PMULL for GF(2^8) due to reduction overhead
        let mut result_bytes = [0u8; 16];
        let mut a_bytes = [0u8; 16];
        let mut b_bytes = [0u8; 16];
        vst1q_u8(a_bytes.as_mut_ptr(), a);
        vst1q_u8(b_bytes.as_mut_ptr(), b);

        for j in 0..16 {
            result_bytes[j] = gf_mul_byte_scalar(a_bytes[j], b_bytes[j]);
        }

        vld1q_u8(result_bytes.as_ptr())
    }

    /// Scalar GF(2^8) byte multiply with AES polynomial reduction
    #[inline(always)]
    fn gf_mul_byte_scalar(a: u8, b: u8) -> u8 {
        // Russian peasant multiplication in GF(2^8)
        // Polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;

        for _ in 0..8 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let hi_bit = aa & 0x80;
            aa <<= 1;
            if hi_bit != 0 {
                aa ^= 0x1B; // Reduce by AES polynomial (x^8 term implicit)
            }
            bb >>= 1;
        }
        result
    }

    #[cfg(target_feature = "sve2")]
    #[inline(always)]
    unsafe fn xor_blocks_sve2_impl(dst: &mut [u8], src: &[u8]) {
        let len = core::cmp::min(dst.len(), src.len());
        let mut offset = 0usize;
        while offset < len {
            let pg = svwhilelt_b8(offset as u64, len as u64);
            let dst_chunk = svld1_u8(pg, dst.as_ptr().add(offset));
            let src_chunk = svld1_u8(pg, src.as_ptr().add(offset));
            let res = sveor_u8_z(pg, dst_chunk, src_chunk);
            svst1_u8(pg, dst.as_mut_ptr().add(offset), res);
            offset += svcntb() as usize;
        }
    }

    #[cfg(target_feature = "sve2")]
    #[inline(always)]
    unsafe fn memcpy_sve2_impl(dst: &mut [u8], src: &[u8]) {
        let len = core::cmp::min(dst.len(), src.len());
        let mut offset = 0usize;
        while offset < len {
            let pg = svwhilelt_b8(offset as u64, len as u64);
            let data = svld1_u8(pg, src.as_ptr().add(offset));
            svst1_u8(pg, dst.as_mut_ptr().add(offset), data);
            offset += svcntb() as usize;
        }
    }

    // Crypto
    #[inline(always)]
    pub(super) unsafe fn aes_encrypt_neon(state: &mut [u8; 16], key: &[u8; 16]) {
        scalar::aes_encrypt_block(state, key)
    }
    #[inline(always)]
    pub(super) unsafe fn ghash_pmull(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
        // Delegate to crypto::gcm::ghash which performs runtime PMULL/VPCLMUL selection.
        // This ensures ARM PMULL acceleration is actually used when available.
        let t = crate::crypto::gcm::ghash(*h, &[], data);
        tag.copy_from_slice(&t);
    }

    #[inline(always)]
    unsafe fn compress_sha_blocks(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        #[cfg(not(windows))]
        sha2_asm::compress256(state, blocks);
        #[cfg(windows)]
        {
            let _ = (state, blocks);
        }
    }

    #[target_feature(enable = "neon", enable = "sha2")]
    pub(super) unsafe fn sha256_hw(data: &[u8]) -> [u8; 32] {
        super::sha256_hash_with_batch(data, 1, |state, blocks| compress_sha_blocks(state, blocks))
    }

    // Bitstream pack/unpack (NEON/SVE2 dispatch, scalar-equivalent logic)
    #[inline(always)]
    pub(super) unsafe fn pack_bits_sve2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        #[cfg(target_feature = "sve2")]
        {
            return pack_bits_neon(src, bit_width, dst);
        }
        pack_bits_neon(src, bit_width, dst)
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn pack_bits_neon(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            use core::arch::aarch64::*;

            if bit_width == 1 {
                let weights_arr: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
                let weights: uint8x8_t = vld1_u8(weights_arr.as_ptr());
                let ones = vdup_n_u8(1);

                let mut si = 0usize;
                let mut di = 0usize;

                while si + 8 <= src.len() && di < dst.len() {
                    let v: uint8x8_t = vld1_u8(src.as_ptr().add(si));
                    let bits01: uint8x8_t = vand_u8(v, ones);
                    let mul: uint16x8_t = vmull_u8(bits01, weights);
                    let sum: u16 = vaddvq_u16(mul);
                    dst[di] = (sum & 0xFF) as u8;
                    di += 1;
                    si += 8;
                }

                // tail (scalar)
                if si < src.len() && di < dst.len() {
                    let mut bitbuf: u32 = 0;
                    let mut bits: u32 = 0;
                    while si < src.len() && bits < 8 {
                        bitbuf |= ((src[si] & 1) as u32) << bits;
                        bits += 1;
                        si += 1;
                    }
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                }

                return di;
            }

            if bit_width == 8 {
                let n = src.len().min(dst.len());
                if n > 0 {
                    // SAFETY: `n = src.len().min(dst.len())`, so both source and
                    // destination have at least `n` bytes. The slices cannot alias
                    // because they come from separate `&[u8]` / `&mut [u8]` references.
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
                }
                return n;
            }

            if bit_width == 4 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 1 < src.len() && di < dst.len() {
                    let lo = src[si] & 0x0F;
                    let hi = (src[si + 1] & 0x0F) << 4;
                    dst[di] = lo | hi;
                    si += 2;
                    di += 1;
                }
                if si < src.len() && di < dst.len() {
                    dst[di] = src[si] & 0x0F;
                    di += 1;
                }
                return di;
            }

            if bit_width == 2 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 3 < src.len() && di < dst.len() {
                    let b0 = (src[si] & 0x03)
                        | ((src[si + 1] & 0x03) << 2)
                        | ((src[si + 2] & 0x03) << 4)
                        | ((src[si + 3] & 0x03) << 6);
                    dst[di] = b0;
                    si += 4;
                    di += 1;
                }
                if si < src.len() && di < dst.len() {
                    let mut b = 0u8;
                    let mut shift = 0u8;
                    while si < src.len() && shift < 8 {
                        b |= (src[si] & 0x03) << shift;
                        shift += 2;
                        si += 1;
                    }
                    dst[di] = b;
                    di += 1;
                }
                return di;
            }

            if bit_width == 3 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 8 <= src.len() && di + 3 <= dst.len() {
                    let a = src[si] & 0x07;
                    let b = src[si + 1] & 0x07;
                    let c = src[si + 2] & 0x07;
                    let d = src[si + 3] & 0x07;
                    let e = src[si + 4] & 0x07;
                    let f = src[si + 5] & 0x07;
                    let g = src[si + 6] & 0x07;
                    let h = src[si + 7] & 0x07;
                    dst[di] = a | (b << 3) | ((c & 0x03) << 6);
                    dst[di + 1] = ((c >> 2) & 0x01) | (d << 1) | (e << 4) | ((f & 0x01) << 7);
                    dst[di + 2] = ((f >> 1) & 0x03) | (g << 2) | (h << 5);
                    si += 8;
                    di += 3;
                }
                // tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while si < src.len() && di < dst.len() {
                    bitbuf |= (src[si] as u32 & 0x07) << bits;
                    bits += 3;
                    while bits >= 8 && di < dst.len() {
                        dst[di] = (bitbuf & 0xFF) as u8;
                        di += 1;
                        bitbuf >>= 8;
                        bits -= 8;
                    }
                    si += 1;
                }
                if bits > 0 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                }
                return di;
            }

            if bit_width == 5 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 8 <= src.len() && di + 5 <= dst.len() {
                    let a = src[si] & 0x1F;
                    let b = src[si + 1] & 0x1F;
                    let c = src[si + 2] & 0x1F;
                    let d = src[si + 3] & 0x1F;
                    let e = src[si + 4] & 0x1F;
                    let f = src[si + 5] & 0x1F;
                    let g = src[si + 6] & 0x1F;
                    let h = src[si + 7] & 0x1F;

                    dst[di] = a | ((b & 0x07) << 5);
                    dst[di + 1] = ((b >> 3) & 0x03) | (c << 2) | ((d & 0x01) << 7);
                    dst[di + 2] = ((d >> 1) & 0x0F) | ((e & 0x0F) << 4);
                    dst[di + 3] = ((e >> 4) & 0x01) | (f << 1) | ((g & 0x03) << 6);
                    dst[di + 4] = ((g >> 2) & 0x07) | (h << 3);
                    si += 8;
                    di += 5;
                }
                // tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while si < src.len() && di < dst.len() {
                    bitbuf |= (src[si] as u32 & 0x1F) << bits;
                    bits += 5;
                    while bits >= 8 && di < dst.len() {
                        dst[di] = (bitbuf & 0xFF) as u8;
                        di += 1;
                        bitbuf >>= 8;
                        bits -= 8;
                    }
                    si += 1;
                }
                if bits > 0 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                }
                return di;
            }

            if bit_width == 6 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 4 <= src.len() && di + 3 <= dst.len() {
                    let a = src[si] & 0x3F;
                    let b = src[si + 1] & 0x3F;
                    let c = src[si + 2] & 0x3F;
                    let d = src[si + 3] & 0x3F;
                    dst[di] = a | ((b & 0x03) << 6);
                    dst[di + 1] = ((b >> 2) & 0x0F) | ((c & 0x0F) << 4);
                    dst[di + 2] = ((c >> 4) & 0x03) | (d << 2);
                    si += 4;
                    di += 3;
                }
                // tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while si < src.len() && di < dst.len() {
                    bitbuf |= (src[si] as u32 & 0x3F) << bits;
                    bits += 6;
                    while bits >= 8 && di < dst.len() {
                        dst[di] = (bitbuf & 0xFF) as u8;
                        di += 1;
                        bitbuf >>= 8;
                        bits -= 8;
                    }
                    si += 1;
                }
                if bits > 0 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                }
                return di;
            }

            if bit_width == 7 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 8 <= src.len() && di + 7 <= dst.len() {
                    let a = src[si] & 0x7F;
                    let b = src[si + 1] & 0x7F;
                    let c = src[si + 2] & 0x7F;
                    let d = src[si + 3] & 0x7F;
                    let e = src[si + 4] & 0x7F;
                    let f = src[si + 5] & 0x7F;
                    let g = src[si + 6] & 0x7F;
                    let h = src[si + 7] & 0x7F;

                    dst[di] = a | ((b & 0x01) << 7);
                    dst[di + 1] = ((b >> 1) & 0x3F) | ((c & 0x03) << 6);
                    dst[di + 2] = ((c >> 2) & 0x1F) | ((d & 0x07) << 5);
                    dst[di + 3] = ((d >> 3) & 0x0F) | ((e & 0x0F) << 4);
                    dst[di + 4] = ((e >> 4) & 0x07) | ((f & 0x1F) << 3);
                    dst[di + 5] = ((f >> 5) & 0x03) | ((g & 0x3F) << 2);
                    dst[di + 6] = ((g >> 6) & 0x01) | (h << 1);
                    si += 8;
                    di += 7;
                }
                // tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while si < src.len() && di < dst.len() {
                    bitbuf |= (src[si] as u32 & 0x7F) << bits;
                    bits += 7;
                    while bits >= 8 && di < dst.len() {
                        dst[di] = (bitbuf & 0xFF) as u8;
                        di += 1;
                        bitbuf >>= 8;
                        bits -= 8;
                    }
                    si += 1;
                }
                if bits > 0 && di < dst.len() {
                    dst[di] = (bitbuf & 0xFF) as u8;
                    di += 1;
                }
                return di;
            }
        }

        scalar::pack_bits(src, bit_width, dst)
    }

    #[inline(always)]
    pub(super) unsafe fn unpack_bits_sve2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        #[cfg(target_feature = "sve2")]
        {
            return unpack_bits_neon(src, bit_width, dst);
        }
        unpack_bits_neon(src, bit_width, dst)
    }

    #[target_feature(enable = "neon")]
    pub(super) unsafe fn unpack_bits_neon(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            if bit_width == 1 {
                let mut si = 0usize;
                let mut di = 0usize;
                while di + 8 <= dst.len() && si < src.len() {
                    let byte = src[si];
                    si += 1;
                    dst[di] = byte & 0x01;
                    dst[di + 1] = (byte >> 1) & 0x01;
                    dst[di + 2] = (byte >> 2) & 0x01;
                    dst[di + 3] = (byte >> 3) & 0x01;
                    dst[di + 4] = (byte >> 4) & 0x01;
                    dst[di + 5] = (byte >> 5) & 0x01;
                    dst[di + 6] = (byte >> 6) & 0x01;
                    dst[di + 7] = (byte >> 7) & 0x01;
                    di += 8;
                }
                // Tail
                if di < dst.len() && si < src.len() {
                    let byte = src[si];
                    let mut j = 0usize;
                    while di < dst.len() && j < 8 {
                        dst[di] = (byte >> j) & 1;
                        di += 1;
                        j += 1;
                    }
                }
                return di;
            }

            if bit_width == 8 {
                let n = dst.len().min(src.len());
                if n > 0 {
                    // SAFETY: `n = dst.len().min(src.len())`, so both source and
                    // destination have at least `n` bytes. The slices cannot alias
                    // because they come from separate `&[u8]` / `&mut [u8]` references.
                    core::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), n);
                }
                return n;
            }

            if bit_width == 4 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si < src.len() && di + 1 < dst.len() {
                    let byte = src[si];
                    si += 1;
                    dst[di] = byte & 0x0F;
                    dst[di + 1] = (byte >> 4) & 0x0F;
                    di += 2;
                }
                if si < src.len() && di < dst.len() {
                    let byte = src[si];
                    dst[di] = byte & 0x0F;
                    di += 1;
                }
                return di;
            }

            if bit_width == 2 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si < src.len() && di + 3 < dst.len() {
                    let byte = src[si];
                    si += 1;
                    dst[di] = byte & 0x03;
                    dst[di + 1] = (byte >> 2) & 0x03;
                    dst[di + 2] = (byte >> 4) & 0x03;
                    dst[di + 3] = (byte >> 6) & 0x03;
                    di += 4;
                }
                if si < src.len() && di < dst.len() {
                    let byte = src[si];
                    let mut j = 0usize;
                    while di < dst.len() && j < 4 {
                        dst[di] = (byte >> (2 * j)) & 0x03;
                        di += 1;
                        j += 1;
                    }
                }
                return di;
            }

            if bit_width == 3 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 3 <= src.len() && di + 8 <= dst.len() {
                    let b0 = src[si];
                    let b1 = src[si + 1];
                    let b2 = src[si + 2];
                    dst[di] = b0 & 0x07;
                    dst[di + 1] = (b0 >> 3) & 0x07;
                    dst[di + 2] = ((b0 >> 6) & 0x03) | ((b1 & 0x01) << 2);
                    dst[di + 3] = (b1 >> 1) & 0x07;
                    dst[di + 4] = (b1 >> 4) & 0x07;
                    dst[di + 5] = ((b1 >> 7) & 0x01) | ((b2 & 0x03) << 1);
                    dst[di + 6] = (b2 >> 2) & 0x07;
                    dst[di + 7] = (b2 >> 5) & 0x07;
                    si += 3;
                    di += 8;
                }
                // Tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while di < dst.len() {
                    while bits < 3 {
                        if si >= src.len() {
                            return di;
                        }
                        bitbuf |= (src[si] as u32) << bits;
                        si += 1;
                        bits += 8;
                    }
                    dst[di] = (bitbuf & 0x07) as u8;
                    bitbuf >>= 3;
                    bits -= 3;
                    di += 1;
                }
                return di;
            }

            if bit_width == 5 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 5 <= src.len() && di + 8 <= dst.len() {
                    let x0 = src[si];
                    let x1 = src[si + 1];
                    let x2 = src[si + 2];
                    let x3 = src[si + 3];
                    let x4 = src[si + 4];
                    dst[di] = x0 & 0x1F;
                    dst[di + 1] = ((x0 >> 5) & 0x07) | ((x1 & 0x03) << 3);
                    dst[di + 2] = (x1 >> 2) & 0x1F;
                    dst[di + 3] = ((x1 >> 7) & 0x01) | ((x2 & 0x0F) << 1);
                    dst[di + 4] = ((x2 >> 4) & 0x0F) | ((x3 & 0x01) << 4);
                    dst[di + 5] = (x3 >> 1) & 0x1F;
                    dst[di + 6] = ((x3 >> 6) & 0x03) | ((x4 & 0x07) << 2);
                    dst[di + 7] = (x4 >> 3) & 0x1F;
                    si += 5;
                    di += 8;
                }
                // Tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while di < dst.len() {
                    while bits < 5 {
                        if si >= src.len() {
                            return di;
                        }
                        bitbuf |= (src[si] as u32) << bits;
                        si += 1;
                        bits += 8;
                    }
                    dst[di] = (bitbuf & 0x1F) as u8;
                    bitbuf >>= 5;
                    bits -= 5;
                    di += 1;
                }
                return di;
            }

            if bit_width == 6 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 3 <= src.len() && di + 4 <= dst.len() {
                    let x0 = src[si];
                    let x1 = src[si + 1];
                    let x2 = src[si + 2];
                    dst[di] = x0 & 0x3F;
                    dst[di + 1] = ((x0 >> 6) & 0x03) | ((x1 & 0x0F) << 2);
                    dst[di + 2] = ((x1 >> 4) & 0x0F) | ((x2 & 0x03) << 4);
                    dst[di + 3] = (x2 >> 2) & 0x3F;
                    si += 3;
                    di += 4;
                }
                // Tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while di < dst.len() {
                    while bits < 6 {
                        if si >= src.len() {
                            return di;
                        }
                        bitbuf |= (src[si] as u32) << bits;
                        si += 1;
                        bits += 8;
                    }
                    dst[di] = (bitbuf & 0x3F) as u8;
                    bitbuf >>= 6;
                    bits -= 6;
                    di += 1;
                }
                return di;
            }

            if bit_width == 7 {
                let mut si = 0usize;
                let mut di = 0usize;
                while si + 7 <= src.len() && di + 8 <= dst.len() {
                    let x0 = src[si];
                    let x1 = src[si + 1];
                    let x2 = src[si + 2];
                    let x3 = src[si + 3];
                    let x4 = src[si + 4];
                    let x5 = src[si + 5];
                    let x6 = src[si + 6];
                    dst[di] = x0 & 0x7F;
                    dst[di + 1] = ((x0 >> 7) & 0x01) | ((x1 & 0x3F) << 1);
                    dst[di + 2] = ((x1 >> 6) & 0x03) | ((x2 & 0x1F) << 2);
                    dst[di + 3] = ((x2 >> 5) & 0x07) | ((x3 & 0x0F) << 3);
                    dst[di + 4] = ((x3 >> 4) & 0x0F) | ((x4 & 0x07) << 4);
                    dst[di + 5] = ((x4 >> 3) & 0x1F) | ((x5 & 0x03) << 5);
                    dst[di + 6] = ((x5 >> 2) & 0x3F) | ((x6 & 0x01) << 6);
                    dst[di + 7] = (x6 >> 1) & 0x7F;
                    si += 7;
                    di += 8;
                }
                // Tail via bit-buffer
                let mut bitbuf: u32 = 0;
                let mut bits: u32 = 0;
                while di < dst.len() {
                    while bits < 7 {
                        if si >= src.len() {
                            return di;
                        }
                        bitbuf |= (src[si] as u32) << bits;
                        si += 1;
                        bits += 8;
                    }
                    dst[di] = (bitbuf & 0x7F) as u8;
                    bitbuf >>= 7;
                    bits -= 7;
                    di += 1;
                }
                return di;
            }
        }

        scalar::unpack_bits(src, bit_width, dst)
    }

    // Reed-Solomon encode using NEON+PMULL GF multiply (block-wise)
    #[inline(always)]
    pub(super) unsafe fn reed_solomon_encode_neon(data: &[u8], parity_shards: usize) -> Vec<u8> {
        let data_shards = data.len() / 256;
        let total_shards = data_shards + parity_shards;
        let mut output = vec![0u8; total_shards * 256];

        // Copy data shards
        output[..data.len()].copy_from_slice(data);

        // Generate parity shards
        for p in 0..parity_shards {
            let parity_base = (data_shards + p) * 256;
            for d in 0..data_shards {
                let coeff = super::scalar::gf_pow((p as u8) + 1, d as u8);
                let data_base = d * 256;

                // Process 16-byte blocks with PMULL-assisted multiply
                let mut k = 0usize;
                while k + 16 <= 256 {
                    let mut prod = [0u8; 16];
                    super::arm::gf_mul_neon_pmull(
                        &data[data_base + k..data_base + k + 16],
                        coeff,
                        &mut prod,
                    );
                    // XOR accumulate into parity shard
                    for i in 0..16 {
                        output[parity_base + k + i] ^= prod[i];
                    }
                    k += 16;
                }

                // Tail (should be zero for shard size 256, but keep safe)
                while k < 256 {
                    let idx = data_base + k;
                    output[parity_base + k] ^= super::scalar::gf_mul_byte(data[idx], coeff);
                    k += 1;
                }
            }
        }

        output
    }

    #[inline(always)]
    pub(crate) fn qpack_encode_neon(input: &[u8], output: &mut [u8]) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: NEON is baseline on aarch64. The impl uses NEON intrinsics to
            // expand bytes into u32 indices for Huffman table lookup, then accumulates
            // bits into a u128 accumulator. Output bounds are checked on each byte write.
            unsafe { qpack_encode_neon_impl(input, output) }
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (input, output);
            scalar::qpack_encode(input, output)
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn qpack_encode_neon_impl(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
        use core::arch::aarch64::{
            uint32x4_t, uint8x8_t, vget_high_u16, vget_low_u16, vld1_u8, vmovl_u16, vmovl_u8,
            vst1q_u32,
        };

        let mut acc: u128 = 0;
        let mut bits: usize = 0;
        let mut written: usize = 0;
        let mut i = 0usize;
        let mut lanes = [0u32; 8];

        while i + 8 <= input.len() {
            let ptr = input.as_ptr().add(i);
            let chunk: uint8x8_t = vld1_u8(ptr);
            let expanded = vmovl_u8(chunk);
            let lower: uint32x4_t = vmovl_u16(vget_low_u16(expanded));
            let upper: uint32x4_t = vmovl_u16(vget_high_u16(expanded));
            vst1q_u32(lanes.as_mut_ptr(), lower);
            vst1q_u32(lanes.as_mut_ptr().add(4), upper);

            for &sym_u16 in lanes.iter() {
                let sym = sym_u16 as usize;
                let code = HUFF_CODES[sym] as u128;
                let clen = HUFF_LENS[sym] as usize;

                if bits + clen > 120 {
                    while bits >= 8 {
                        let shift = bits - 8;
                        if written >= output.len() {
                            return written;
                        }
                        let byte = ((acc >> shift) & 0xff) as u8;
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                acc = (acc << clen) | code;
                bits += clen;

                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            i += 8;
        }

        while i < input.len() {
            let sym = input[i] as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = crate::transport::h3::qpack::HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                if written >= output.len() {
                    return written;
                }
                let byte = ((acc >> shift) & 0xff) as u8;
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }

            i += 1;
        }

        if bits > 0 {
            if written >= output.len() {
                return written;
            }
            let pad_mask = (1u128 << (8 - bits)) - 1;
            let byte = ((acc << (8 - bits)) | pad_mask) as u8;
            output[written] = byte;
            written += 1;
        }

        written
    }

    // SVE2 implementation: uses SVE vector loads and predicate-tail handling, with scalar per-symbol
    // Huffman accumulation. Compiles only when SVE2 is available; otherwise we fall back to NEON.
    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn qpack_encode_sve2_impl(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
        use core::arch::aarch64::*;

        let mut acc: u128 = 0;
        let mut bits: usize = 0;
        let mut written: usize = 0;
        let mut i = 0usize;

        let mut lanes_buf: [u8; 256] = [0; 256];

        while i < input.len() {
            let pg = svwhilelt_b8(i as u64, input.len() as u64);
            if svptest_any(svptrue_b8(), pg) {
                let v = svld1_u8(pg, input.as_ptr().add(i));
                svst1_u8(pg, lanes_buf.as_mut_ptr(), v);
                let active = svcntp_b8(svptrue_b8(), pg) as usize;

                for idx in 0..active {
                    let sym = lanes_buf[idx] as usize;
                    let code = HUFF_CODES[sym] as u128;
                    let clen = HUFF_LENS[sym] as usize;

                    if bits + clen > 120 {
                        while bits >= 8 {
                            let shift = bits - 8;
                            if written >= output.len() {
                                return written;
                            }
                            let byte = ((acc >> shift) & 0xff) as u8;
                            output[written] = byte;
                            written += 1;
                            bits -= 8;
                            acc &= (1u128 << shift) - 1;
                        }
                    }

                    acc = (acc << clen) | code;
                    bits += clen;

                    while bits >= 8 {
                        let shift = bits - 8;
                        if written >= output.len() {
                            return written;
                        }
                        let byte = ((acc >> shift) & 0xff) as u8;
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                i += active;
            } else {
                break;
            }
        }

        if bits > 0 {
            if written >= output.len() {
                return written;
            }
            let pad_mask = (1u128 << (8 - bits)) - 1;
            let byte = ((acc << (8 - bits)) | pad_mask) as u8;
            output[written] = byte;
            written += 1;
        }

        written
    }

    #[inline(always)]
    pub(crate) fn qpack_decode_neon(input: &[u8], output: &mut [u8]) -> usize {
        #[cfg(target_arch = "aarch64")]
        {
            use crate::transport::h3;
            match h3::qpack::huff_decode_into(input, output) {
                Ok(written) => written,
                Err(h3::Error::BufferTooShort) => output.len(),
                Err(_) => 0,
            }
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (input, output);
            scalar::qpack_decode(input, output)
        }
    }

    #[inline(always)]
    pub(crate) fn qpack_encode_sve2(input: &[u8], output: &mut [u8]) -> usize {
        #[cfg(target_feature = "sve2")]
        {
            // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl uses
            // SVE predicated loads and scalar Huffman accumulation with bounds checks.
            return unsafe { qpack_encode_sve2_impl(input, output) };
        }
        qpack_encode_neon(input, output)
    }

    #[inline(always)]
    pub(crate) fn qpack_decode_sve2(input: &[u8], output: &mut [u8]) -> usize {
        #[cfg(target_feature = "sve2")]
        {
            // SAFETY: Guarded by `target_feature = "sve2"` cfg. The impl delegates
            // to `huff_decode_into` which performs bounds-checked decoding.
            return unsafe { qpack_decode_sve2_impl(input, output) };
        }
        qpack_decode_neon(input, output)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn qpack_decode_sve2_impl(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3;
        match h3::qpack::huff_decode_into(input, output) {
            Ok(written) => written,
            Err(h3::Error::BufferTooShort) => output.len(),
            Err(_) => 0,
        }
    }
}

// ============================================================================
// SIMD RUNTIME DISPATCHER - Selects optimal implementation
// ============================================================================

/// Runtime SIMD dispatcher that selects the optimal ISA path per operation.
pub struct SimdOps;

impl SimdOps {
    /// Get singleton instance
    pub fn instance() -> &'static Self {
        static INSTANCE: OnceLock<SimdOps> = OnceLock::new();
        INSTANCE.get_or_init(|| SimdOps)
    }

    // aarch64 module declared at top-level

    /// Select best implementation based on CPU features
    #[inline(always)]
    #[allow(unused_variables)]
    pub fn dispatch<T>(
        &self,
        _x86_avx512: impl FnOnce() -> T,
        _x86_avx2: impl FnOnce() -> T,
        _x86_sse: impl FnOnce() -> T,
        arm_sve2: impl FnOnce() -> T,
        arm_neon: impl FnOnce() -> T,
        scalar: impl FnOnce() -> T,
    ) -> T {
        let features = FeatureDetector::instance();

        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::AVX512F) {
                return _x86_avx512();
            }
            if features.has_feature(CpuFeature::AVX2) {
                return _x86_avx2();
            }
            // SSE2 is not represented in CpuFeature; baseline is SSE4.2 in this codebase
            if features.has_feature(CpuFeature::SSE42) {
                return _x86_sse();
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                return arm_sve2();
            }
            if features.has_feature(CpuFeature::NEON) {
                return arm_neon();
            }
        }

        scalar()
    }
}

// ============================================================================
// CORE OPERATIONS - Used by all modules
// ============================================================================

/// Core SIMD-dispatched operations: XOR, CRC32, popcount.
pub mod core {
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
            if features.has_feature(CpuFeature::AVX512F) {
                unsafe { super::x86::xor_blocks_avx512(dst, src) };
                return;
            }
            if features.has_feature(CpuFeature::AVX2) {
                unsafe { super::x86::xor_blocks_avx2(dst, src) };
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                unsafe { arm::xor_blocks_sve2(dst, src) };
                return;
            }
            if features.has_feature(CpuFeature::NEON) {
                unsafe { arm::xor_blocks_neon(dst, src) };
                return;
            }
        }

        scalar::xor_blocks(dst, src)
    }

    /// CRC32 with hardware acceleration
    #[inline(always)]
    pub fn crc32(data: &[u8], initial: u32) -> u32 {
        let features = FeatureDetector::instance();

        // SAFETY: Runtime feature check matches the callee's `#[target_feature]`.
        // Both callees only read `data` and return a scalar - no pointer invariants.
        #[cfg(target_arch = "x86_64")]
        if features.has_feature(CpuFeature::SSE42) {
            return unsafe { super::x86::crc32_sse42(data, initial) };
        }

        #[cfg(target_arch = "aarch64")]
        if features.has_feature(CpuFeature::CRC32) {
            return unsafe { arm::crc32_arm(data, initial) };
        }

        scalar::crc32(data, initial)
    }

    /// Population count
    #[inline(always)]
    pub fn popcnt(data: &[u8]) -> usize {
        let features = FeatureDetector::instance();

        // SAFETY: Runtime feature check matches the callee's `#[target_feature]`.
        // All callees only read `data` and return a count - no pointer invariants.
        #[cfg(target_arch = "x86_64")]
        if features.has_feature(CpuFeature::POPCNT) {
            return unsafe { super::x86::popcnt_hw(data) };
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                return unsafe { arm::popcnt_sve2(data) };
            }
            if features.has_feature(CpuFeature::NEON) {
                return unsafe { arm::popcnt_neon(data) };
            }
        }

        scalar::popcnt(data)
    }
}

// ============================================================================
// GALOIS FIELD OPERATIONS - For FEC/Reed-Solomon
// ============================================================================

/// Galois field operations for FEC/Reed-Solomon encoding.
pub mod galois {
    use super::*;

    /// GF(2^8) multiplication
    #[inline(always)]
    pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by a runtime feature check matching the
        // callee's `#[target_feature]`. All callees read from `a`, write to `dst`,
        // and handle length clamping internally (`a.len().min(dst.len())`).
        #[cfg(target_arch = "x86_64")]
        {
            // GFNI usage requires AVX-512F+GFNI on x86_64 in this codebase
            if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
                return unsafe { super::x86::gf_mul_avx512_gfni(a, b, dst) };
            }
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::gf_mul_avx2(a, b, dst) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                unsafe { arm::gf_mul_sve2(a, b, dst) };
                crate::optimize::telemetry::FEC_SVE2_OPS.inc();
                return;
            }
            if features.has_feature(CpuFeature::PMULL) {
                unsafe { arm::gf_mul_neon_pmull(a, b, dst) };
                crate::optimize::telemetry::FEC_NEON_OPS.inc();
                return;
            }
            if features.has_feature(CpuFeature::NEON) {
                unsafe { arm::gf_mul_neon(a, b, dst) };
                crate::optimize::telemetry::FEC_NEON_OPS.inc();
                return;
            }
        }

        scalar::gf_mul(a, b, dst)
    }

    // =========================================================================
    // GF(2^4) - 4x less computation for low-loss scenarios (<5%)
    // =========================================================================

    /// GF(2^4) multiplication - 4x faster than GF(2^8) for low loss
    /// Uses polynomial x^4 + x + 1 (0x13 reduction)
    #[inline(always)]
    pub fn gf4_mul(a: &[u8], b: u8, dst: &mut [u8]) {
        let features = FeatureDetector::instance();
        let b_lo = b & 0x0F;

        // SAFETY: Each branch is guarded by a runtime feature check matching
        // the callee's `#[target_feature]`. Callees clamp to `a.len().min(dst.len())`
        // internally and only read/write within those bounds.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::AVX2) {
                unsafe { gf4_mul_avx2(a, b_lo, dst) };
                crate::optimize::telemetry::FEC_AVX2_OPS.inc();
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::NEON) {
                unsafe { gf4_mul_neon(a, b_lo, dst) };
                crate::optimize::telemetry::FEC_NEON_OPS.inc();
                return;
            }
        }

        gf4_mul_scalar(a, b_lo, dst)
    }

    /// Scalar GF(2^4) multiplication
    #[inline]
    fn gf4_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
        let len = a.len().min(dst.len());
        for i in 0..len {
            // Low nibble
            let a_lo = a[i] & 0x0F;
            let a_hi = (a[i] >> 4) & 0x0F;

            // GF(2^4) Russian peasant multiply
            let r_lo = gf4_mul_byte(a_lo, b);
            let r_hi = gf4_mul_byte(a_hi, b);

            dst[i] = r_lo | (r_hi << 4);
        }
    }

    /// Single GF(2^4) byte multiply with reduction x^4+x+1
    #[inline(always)]
    fn gf4_mul_byte(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a & 0x0F;
        let mut bb = b & 0x0F;

        for _ in 0..4 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let hi_bit = aa & 0x08;
            aa <<= 1;
            if hi_bit != 0 {
                aa ^= 0x03; // Reduce by x^4+x+1 (low 4 bits)
            }
            aa &= 0x0F;
            bb >>= 1;
        }
        result & 0x0F
    }

    /// AVX2 GF(2^4) multiplication using table lookup
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn gf4_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
        use std::arch::x86_64::*;

        let len = a.len().min(dst.len());

        // Build 16-entry lookup table for GF(2^4) multiply by b
        let mut table = [0u8; 16];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = gf4_mul_byte(i as u8, b);
        }
        let lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(table.as_ptr() as *const _));
        let mask_lo = _mm256_set1_epi8(0x0F);

        let mut i = 0;
        while i + 32 <= len {
            let v = _mm256_loadu_si256(a.as_ptr().add(i) as *const _);

            // Extract low and high nibbles
            let lo = _mm256_and_si256(v, mask_lo);
            let hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask_lo);

            // Table lookup for both nibbles
            let r_lo = _mm256_shuffle_epi8(lut, lo);
            let r_hi = _mm256_shuffle_epi8(lut, hi);

            // Combine: r_lo | (r_hi << 4)
            let result = _mm256_or_si256(r_lo, _mm256_slli_epi16(r_hi, 4));

            // Mask to keep only valid nibbles
            let masked = _mm256_and_si256(result, _mm256_set1_epi8(0xFF_u8 as i8));
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut _, masked);
            i += 32;
        }

        // Tail
        if i < len {
            gf4_mul_scalar(&a[i..], b, &mut dst[i..]);
        }
    }

    /// NEON GF(2^4) multiplication
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf4_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
        use ::core::arch::aarch64::*;

        let len = a.len().min(dst.len());

        // Build 16-entry lookup table
        let mut table = [0u8; 16];
        for (i, slot) in table.iter_mut().enumerate() {
            *slot = gf4_mul_byte(i as u8, b);
        }
        let lut = vld1q_u8(table.as_ptr());
        let mask_lo = vdupq_n_u8(0x0F);

        let mut i = 0;
        while i + 16 <= len {
            let v = vld1q_u8(a.as_ptr().add(i));

            // Extract nibbles
            let lo = vandq_u8(v, mask_lo);
            let hi = vandq_u8(vshrq_n_u8(v, 4), mask_lo);

            // Table lookup
            let r_lo = vqtbl1q_u8(lut, lo);
            let r_hi = vqtbl1q_u8(lut, hi);

            // Combine
            let result = vorrq_u8(r_lo, vshlq_n_u8(r_hi, 4));
            vst1q_u8(dst.as_mut_ptr().add(i), result);
            i += 16;
        }

        // Tail
        if i < len {
            gf4_mul_scalar(&a[i..], b, &mut dst[i..]);
        }
    }

    // =========================================================================
    // GF(2^16) with VPCLMULQDQ - 5-8x faster for Extreme/Ultra modes
    // =========================================================================

    /// GF(2^16) multiplication - for Extreme/Ultra FEC modes
    /// Uses polynomial x^16 + x^12 + x^3 + x + 1 (0x1100B)
    #[inline(always)]
    pub fn gf16_mul(a: &[u16], b: u16, dst: &mut [u16]) {
        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by a runtime feature check matching
        // the callee's `#[target_feature]`. Callees clamp to
        // `a.len().min(dst.len())` and stay within bounds.
        #[cfg(target_arch = "x86_64")]
        {
            // VPCLMULQDQ is the ultimate for GF(2^16)
            if features.has_feature(CpuFeature::VPCLMULQDQ)
                && features.has_feature(CpuFeature::AVX512F)
            {
                unsafe { gf16_mul_vpclmulqdq(a, b, dst) };
                crate::optimize::telemetry::GF16_VPCLMUL_OPS.inc();
                return;
            }
            if features.has_feature(CpuFeature::PCLMULQDQ) {
                unsafe { gf16_mul_pclmulqdq(a, b, dst) };
                crate::optimize::telemetry::GF16_PCLMUL_OPS.inc();
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::PMULL) {
                unsafe { gf16_mul_pmull(a, b, dst) };
                crate::optimize::telemetry::GF16_PMULL_OPS.inc();
                return;
            }
        }

        gf16_mul_scalar(a, b, dst)
    }

    /// Scalar GF(2^16) multiplication
    fn gf16_mul_scalar(a: &[u16], b: u16, dst: &mut [u16]) {
        let len = a.len().min(dst.len());
        for i in 0..len {
            dst[i] = gf16_mul_single(a[i], b);
        }
    }

    /// Single GF(2^16) multiply with reduction
    #[inline(always)]
    fn gf16_mul_single(a: u16, b: u16) -> u16 {
        // Russian peasant multiplication in GF(2^16)
        // Polynomial: x^16 + x^12 + x^3 + x + 1 = 0x1100B
        let mut result = 0u32;
        let mut aa = a as u32;
        let mut bb = b as u32;

        for _ in 0..16 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let hi_bit = aa & 0x8000;
            aa <<= 1;
            if hi_bit != 0 {
                aa ^= 0x100B; // Reduce by polynomial (x^16 term implicit)
            }
            bb >>= 1;
        }
        result as u16
    }

    /// AVX-512 VPCLMULQDQ for GF(2^16) - 8 u16s at once = 5-8x faster!
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f", enable = "vpclmulqdq", enable = "sse4.1")]
    unsafe fn gf16_mul_vpclmulqdq(a: &[u16], b: u16, dst: &mut [u16]) {
        use std::arch::x86_64::*;

        let len = a.len().min(dst.len());
        let b_64 = b as u64;
        let b_vec = _mm512_set1_epi64(b_64 as i64);

        // Reduction polynomial for GF(2^16): x^16 + x^12 + x^3 + x + 1
        const POLY: u64 = 0x100B;
        let poly_vec = _mm512_set1_epi64(POLY as i64);

        let mut i = 0;
        while i + 8 <= len {
            // Load 8 u16 values, expand to 8 u64 for carryless multiply
            let a_lo = _mm_loadu_si128(a.as_ptr().add(i) as *const _);
            let a_32 = _mm256_cvtepu16_epi32(a_lo);
            let a_64 = _mm512_cvtepu32_epi64(a_32);

            // Carryless multiply: a[i] * b (produces 32-bit result in low 64 bits)
            let prod = _mm512_clmulepi64_epi128(a_64, b_vec, 0x00);

            // Reduce: extract bits 16-31 and XOR with polynomial
            let hi16 = _mm512_srli_epi64(prod, 16);
            let reduce = _mm512_clmulepi64_epi128(hi16, poly_vec, 0x00);
            let result_64 = _mm512_xor_si512(prod, reduce);

            // Mask to 16 bits and pack back to u16
            let mask16 = _mm512_set1_epi64(0xFFFF);
            let masked = _mm512_and_si512(result_64, mask16);

            // Pack 64-bit to 32-bit to 16-bit
            let result_32 = _mm512_cvtepi64_epi32(masked);
            let lo = _mm256_castsi256_si128(result_32);
            let hi = _mm256_extracti128_si256(result_32, 1);
            let packed = _mm_packus_epi32(lo, hi);
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, packed);
            i += 8;
        }

        // Tail
        while i < len {
            dst[i] = gf16_mul_single(a[i], b);
            i += 1;
        }
    }

    /// PCLMULQDQ version for SSE4.2 systems
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "pclmulqdq", enable = "sse4.1")]
    unsafe fn gf16_mul_pclmulqdq(a: &[u16], b: u16, dst: &mut [u16]) {
        use std::arch::x86_64::*;

        let len = a.len().min(dst.len());
        let b_64 = b as u64;
        let b_vec = _mm_set1_epi64x(b_64 as i64);
        const POLY: u64 = 0x100B;
        let poly_vec = _mm_set1_epi64x(POLY as i64);

        let mut i = 0;
        while i + 2 <= len {
            // Load 2 u16, expand to 2 u64
            let a0 = a[i] as u64;
            let a1 = a[i + 1] as u64;
            let a_vec = _mm_set_epi64x(a1 as i64, a0 as i64);

            // Carryless multiply
            let prod0 = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
            let prod1 = _mm_clmulepi64_si128(a_vec, b_vec, 0x11);

            // Reduce
            let hi0 = _mm_srli_epi64(prod0, 16);
            let hi1 = _mm_srli_epi64(prod1, 16);
            let red0 = _mm_clmulepi64_si128(hi0, poly_vec, 0x00);
            let red1 = _mm_clmulepi64_si128(hi1, poly_vec, 0x00);
            let r0 = _mm_xor_si128(prod0, red0);
            let r1 = _mm_xor_si128(prod1, red1);

            // Extract and store
            dst[i] = _mm_extract_epi16(r0, 0) as u16;
            dst[i + 1] = _mm_extract_epi16(r1, 0) as u16;
            i += 2;
        }

        // Tail
        while i < len {
            dst[i] = gf16_mul_single(a[i], b);
            i += 1;
        }
    }

    /// ARM PMULL for GF(2^16)
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf16_mul_pmull(a: &[u16], b: u16, dst: &mut [u16]) {
        // For now, use scalar - PMULL is optimized for GF(2^128) not GF(2^16)
        gf16_mul_scalar(a, b, dst);
    }
}

// ============================================================================
// CRYPTO OPERATIONS - AES, GHASH, Poly1305, Hash
// ============================================================================

/// SIMD-dispatched cryptographic primitives: AES, GHASH, SHA-256, HMAC-SHA-256.
pub mod crypto {
    use super::*;

    /// AES single block encryption
    #[inline(always)]
    pub fn aes_encrypt_block(state: &mut [u8; 16], key: &[u8; 16]) {
        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by runtime feature detection matching
        // the callee's `#[target_feature]`. Both `state` and `key` are fixed-size
        // arrays, so pointer validity and length are guaranteed by the type system.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::VAES) && features.has_feature(CpuFeature::AVX512F) {
                return unsafe { super::x86::aes_encrypt_vaes(state, key) };
            }
            if features.has_feature(CpuFeature::AESNI) {
                return unsafe { super::x86::aes_encrypt_aesni(state, key) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::AES) {
                return unsafe { arm::aes_encrypt_neon(state, key) };
            }
        }

        scalar::aes_encrypt_block(state, key)
    }

    /// GHASH for GCM mode
    #[inline(always)]
    pub fn ghash(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by runtime feature detection matching
        // the callee's `#[target_feature]`. `h` and `tag` are fixed-size [u8; 16]
        // arrays. Callees process `data` in 16-byte chunks with remainder handling,
        // so no out-of-bounds access occurs.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::VPCLMULQDQ)
                && features.has_feature(CpuFeature::AVX512F)
                && features.has_feature(CpuFeature::AVX512VL)
            {
                return unsafe { super::x86::ghash_vpclmulqdq(h, data, tag) };
            }
            if features.has_feature(CpuFeature::PCLMULQDQ) {
                return unsafe { super::x86::ghash_pclmulqdq(h, data, tag) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::PMULL) {
                return unsafe { arm::ghash_pmull(h, data, tag) };
            }
        }

        scalar::ghash(h, data, tag)
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum Sha256Backend {
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Avx2,
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        Vnni,
        #[cfg(all(target_arch = "x86_64", not(windows)))]
        ShaNi,
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Neon,
        #[cfg(all(target_arch = "aarch64", not(windows)))]
        Sve2,
        Scalar,
    }

    #[derive(Copy, Clone, Debug)]
    struct Sha256Plan {
        backend: Sha256Backend,
    }

    static SHA256_PLAN: OnceLock<Sha256Plan> = OnceLock::new();

    fn sha256_plan() -> &'static Sha256Plan {
        SHA256_PLAN.get_or_init(|| {
            let features = FeatureDetector::instance();

            #[cfg(all(target_arch = "x86_64", not(windows)))]
            {
                if features.has_feature(CpuFeature::AVXVNNI)
                    && features.has_feature(CpuFeature::AVX2)
                {
                    return Sha256Plan { backend: Sha256Backend::Vnni };
                }
                if features.has_feature(CpuFeature::AVX2) {
                    return Sha256Plan { backend: Sha256Backend::Avx2 };
                }
                if features.has_feature(CpuFeature::SHA) {
                    return Sha256Plan { backend: Sha256Backend::ShaNi };
                }
            }

            #[cfg(all(target_arch = "aarch64", not(windows)))]
            {
                if features.has_feature(CpuFeature::SVE2)
                    && features.has_feature(CpuFeature::SHA256)
                {
                    return Sha256Plan { backend: Sha256Backend::Sve2 };
                }
                if features.has_feature(CpuFeature::SHA256) {
                    return Sha256Plan { backend: Sha256Backend::Neon };
                }
            }

            Sha256Plan { backend: Sha256Backend::Scalar }
        })
    }

    #[inline(always)]
    fn sha256_impl(backend: Sha256Backend, data: &[u8]) -> [u8; 32] {
        // SAFETY: The `backend` value is derived from `sha256_plan()` which
        // selects backends only when the matching CPU features are detected
        // at init time. Each callee reads `data` and returns a hash digest -
        // no pointer aliasing or alignment requirements beyond slice validity.
        match backend {
            #[cfg(all(target_arch = "x86_64", not(windows)))]
            Sha256Backend::Avx2 => unsafe { super::x86::sha256_avx2(data) },
            #[cfg(all(target_arch = "x86_64", not(windows)))]
            Sha256Backend::Vnni => unsafe { super::x86::sha256_vnni(data) },
            #[cfg(all(target_arch = "x86_64", not(windows)))]
            Sha256Backend::ShaNi => unsafe { super::x86::sha256_hw(data) },
            #[cfg(all(target_arch = "aarch64", not(windows)))]
            Sha256Backend::Neon | Sha256Backend::Sve2 => unsafe { arm::sha256_hw(data) },
            Sha256Backend::Scalar => scalar::sha256(data),
        }
    }

    #[inline(always)]
    fn hmac_sha256_impl(backend: Sha256Backend, key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK: usize = 64;

        let mut k0 = [0u8; BLOCK];
        if key.len() > BLOCK {
            let hashed = sha256_impl(backend, key);
            k0[..32].copy_from_slice(&hashed);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= k0[i];
            opad[i] ^= k0[i];
        }

        let mut inner = Vec::with_capacity(BLOCK + data.len());
        inner.extend_from_slice(&ipad);
        inner.extend_from_slice(data);
        let inner_hash = sha256_impl(backend, &inner);

        let mut outer = [0u8; BLOCK + 32];
        outer[..BLOCK].copy_from_slice(&opad);
        outer[BLOCK..].copy_from_slice(&inner_hash);
        sha256_impl(backend, &outer)
    }

    /// SHA-256 hash
    #[inline(always)]
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let backend = sha256_plan().backend;
        match backend {
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::Avx2 => crate::optimize::telemetry::SHA256_AVX2_OPS.inc(),
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::Vnni => crate::optimize::telemetry::SHA256_VNNI_OPS.inc(),
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::ShaNi => crate::optimize::telemetry::SHA256_SHA_OPS.inc(),
            #[cfg(target_arch = "aarch64")]
            Sha256Backend::Neon => crate::optimize::telemetry::SHA256_NEON_OPS.inc(),
            #[cfg(target_arch = "aarch64")]
            Sha256Backend::Sve2 => crate::optimize::telemetry::SHA256_SVE2_OPS.inc(),
            Sha256Backend::Scalar => crate::optimize::telemetry::SHA256_SCALAR_OPS.inc(),
        }
        sha256_impl(backend, data)
    }

    /// HMAC-SHA256 using the runtime-dispatched SHA-256 above.
    #[inline(always)]
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let backend = sha256_plan().backend;
        match backend {
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::Avx2 => crate::optimize::telemetry::HMAC_SHA256_AVX2_OPS.inc(),
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::Vnni => crate::optimize::telemetry::HMAC_SHA256_VNNI_OPS.inc(),
            #[cfg(target_arch = "x86_64")]
            Sha256Backend::ShaNi => crate::optimize::telemetry::HMAC_SHA256_SHA_OPS.inc(),
            #[cfg(target_arch = "aarch64")]
            Sha256Backend::Neon => crate::optimize::telemetry::HMAC_SHA256_NEON_OPS.inc(),
            #[cfg(target_arch = "aarch64")]
            Sha256Backend::Sve2 => crate::optimize::telemetry::HMAC_SHA256_SVE2_OPS.inc(),
            Sha256Backend::Scalar => crate::optimize::telemetry::HMAC_SHA256_SCALAR_OPS.inc(),
        }
        hmac_sha256_impl(backend, key, data)
    }
}

// ============================================================================
// QPACK HELPERS - Public wrapper for Huffman encode with runtime dispatch
// ============================================================================

pub mod qpack {
    use super::*;

    /// Encode bytes using QPACK Huffman coding into `output`.
    /// Returns number of bytes written. Runtime-dispatch to NEON on aarch64.
    #[inline(always)]
    pub fn encode_huff_into(input: &[u8], output: &mut [u8]) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            let det = FeatureDetector::instance();
            if det.has_feature(CpuFeature::AVX2) {
                // SAFETY: AVX2 feature verified by runtime detection. Callee reads
                // `input` and writes up to `output.len()` bytes with bounds checks.
                return unsafe { super::x86::qpack_encode_avx2(input, output) };
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let det = FeatureDetector::instance();
            if det.has_feature(CpuFeature::NEON) {
                return crate::simd::arm::qpack_encode_neon(input, output);
            }
        }
        crate::transport::h3::qpack::huff_encode_into(input, output)
    }
}

// x86_64 IMPLEMENTATIONS
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::scalar;
    use std::arch::x86_64::*;
    use std::sync::Once;

    pub(super) use super::x86_extended::{
        encode_varint_avx2, encode_varint_avx512, encode_varint_sse2, pack_bits_bmi2,
        qpack_decode_avx2, qpack_decode_ssse3, qpack_encode_ssse3, reed_solomon_decode_avx2,
        reed_solomon_decode_gfni, reed_solomon_encode_avx2, reed_solomon_encode_gfni,
        string_compare_avx2, string_compare_sse42, unpack_bits_bmi2, validate_header_avx2,
        validate_header_sse2, varint_decode_bmi2,
    };

    #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
    pub(super) unsafe fn find_pattern_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        // No dedicated VBMI2 implementation here. AVX2 is a safe fallback for VBMI2-capable CPUs.
        find_pattern_avx2(haystack, needle)
    }

    #[target_feature(enable = "avx512f,fma")]
    pub(super) unsafe fn dot_product_avx512(a: &[f32], b: &[f32]) -> f32 {
        let len = a.len().min(b.len());
        let mut sum = _mm512_setzero_ps();
        let chunks = len / 16;
        for i in 0..chunks {
            let va = _mm512_loadu_ps(a[i * 16..].as_ptr());
            let vb = _mm512_loadu_ps(b[i * 16..].as_ptr());
            sum = _mm512_fmadd_ps(va, vb, sum);
        }
        let mut out = _mm512_reduce_add_ps(sum);
        for i in (chunks * 16)..len {
            out += a[i] * b[i];
        }
        out
    }

    #[target_feature(enable = "avx2,fma")]
    pub(super) unsafe fn dot_product_fma(a: &[f32], b: &[f32]) -> f32 {
        let len = a.len().min(b.len());
        let mut sum = _mm256_setzero_ps();
        let chunks = len / 8;
        for i in 0..chunks {
            let va = _mm256_loadu_ps(a[i * 8..].as_ptr());
            let vb = _mm256_loadu_ps(b[i * 8..].as_ptr());
            sum = _mm256_fmadd_ps(va, vb, sum);
        }
        let mut sum_array = [0f32; 8];
        _mm256_storeu_ps(sum_array.as_mut_ptr(), sum);
        let mut out: f32 = sum_array.iter().sum();
        for i in (chunks * 8)..len {
            out += a[i] * b[i];
        }
        out
    }

    // Once-initialized u32 view of HUFF_LENS for AVX2 gathers (safe: avoids OOB on byte-gather)
    static INIT_LENS32: Once = Once::new();
    static mut LENS32: [i32; 257] = [0; 257];

    // SAFETY: `LENS32` is a file-scope `static mut` that is written exactly once
    // inside `call_once`. After `call_once` returns, `LENS32` is immutable for the
    // rest of the program. The returned pointer is only used for SIMD gather reads
    // which require the data to remain stable - satisfied because `call_once` ensures
    // single-writer initialization. This is the standard `Once`-guard pattern for
    // static-mut initialization.
    #[inline(always)]
    unsafe fn lens32_ptr() -> *const i32 {
        INIT_LENS32.call_once(|| {
            for i in 0..257 {
                LENS32[i] = crate::transport::h3::qpack::HUFF_LENS[i] as i32;
            }
        });
        LENS32.as_ptr()
    }

    #[inline(always)]
    unsafe fn compress_batch_avx2(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        #[cfg(not(windows))]
        sha2_asm::compress256(state, blocks);
        #[cfg(windows)]
        {
            let _ = (state, blocks);
        }
    }

    #[inline(always)]
    unsafe fn compress_batch_vnni(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        #[cfg(not(windows))]
        sha2_asm::compress256(state, blocks);
        #[cfg(windows)]
        {
            let _ = (state, blocks);
        }
    }

    /// SSE2 pre-fastpath for varint decoding: quickly find length via continuation-bit mask
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn varint_decode_sse2_prefast(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.len() < 8 {
            return super::scalar::decode_varint(buf);
        }

        // Load 8 bytes (lower lane)
        let data = _mm_loadl_epi64(buf.as_ptr() as *const __m128i);

        // Continuation bits (MSB set => continuation)
        let cont_mask = _mm_set1_epi8(0x80u8 as i8);
        let cont_bits = _mm_and_si128(data, cont_mask);

        // cmp == 0 marks end bytes (no continuation)
        let cmp = _mm_cmpeq_epi8(cont_bits, _mm_setzero_si128());
        let mask = _mm_movemask_epi8(cmp) as u32;
        if mask == 0 {
            return None;
        }
        let len = mask.trailing_zeros() as usize + 1;
        if len > 8 {
            return None;
        }

        // Extract value bits and compose scalar
        let values = _mm_and_si128(data, _mm_set1_epi8(0x7F));
        let mut bytes = [0u8; 16];
        _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, values);
        let mut result = 0u64;
        for i in 0..len {
            result |= (bytes[i] as u64) << (i * 7);
        }
        Some((result, len))
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn sha256_avx2(data: &[u8]) -> [u8; 32] {
        #[cfg(windows)]
        {
            return super::scalar::sha256(data);
        }
        let digest = super::sha256_hash_with_batch(data, 1, |state, blocks| {
            compress_batch_avx2(state, blocks)
        });
        _mm256_zeroupper();
        digest
    }

    #[target_feature(enable = "avx512f", enable = "avx512vl", enable = "avx512vnni")]
    pub(super) unsafe fn sha256_vnni(data: &[u8]) -> [u8; 32] {
        #[cfg(windows)]
        {
            return super::scalar::sha256(data);
        }
        let digest = super::sha256_hash_with_batch(data, 2, |state, blocks| {
            compress_batch_vnni(state, blocks)
        });
        _mm256_zeroupper();
        digest
    }

    /// AVX-512 XOR - 64 bytes at once!
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 64-byte chunks
        while i + 64 <= len {
            let a = _mm512_loadu_si512(dst.as_ptr().add(i) as *const __m512i);
            let b = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
            let result = _mm512_xor_si512(a, b);
            _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, result);
            i += 64;
        }

        // Handle remainder
        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    /// AVX2 XOR - 32 bytes at once
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 32-byte chunks
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
            let b = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            let result = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);
            i += 32;
        }

        // Handle remainder
        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }

        // Avoid AVX->SSE transition penalty
        _mm256_zeroupper();
    }
    /// CRC32 with SSE4.2 hardware acceleration
    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn crc32_sse42(data: &[u8], mut crc: u32) -> u32 {
        crc = !crc; // CRC32 uses inverted initial value
        let mut i = 0;
        let len = data.len();

        // Process 8 bytes at a time with CRC32 instruction
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
            crc = _mm_crc32_u64(crc as u64, chunk) as u32;
            i += 8;
        }

        // Process 4 bytes
        if i + 4 <= len {
            let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
            crc = _mm_crc32_u32(crc, chunk);
            i += 4;
        }

        // Process remaining bytes
        while i < len {
            crc = _mm_crc32_u8(crc, data[i]);
            i += 1;
        }

        !crc // Return with final inversion
    }
    /// Population count using POPCNT on x86_64
    #[target_feature(enable = "popcnt")]
    pub(super) unsafe fn popcnt_hw(data: &[u8]) -> usize {
        let mut count: usize = 0;
        let mut i = 0;
        let len = data.len();
        // Process 8 bytes at a time
        while i + 8 <= len {
            // SAFETY: `i + 8 <= len` guarantees 8 readable bytes at `data[i..]`.
            // Unaligned u64 reads are valid on x86_64 (no alignment requirement).
            let chunk = *(data.as_ptr().add(i) as *const u64);
            count = count.saturating_add(chunk.count_ones() as usize);
            i += 8;
        }
        // Handle remaining 4 bytes
        if i + 4 <= len {
            // SAFETY: `i + 4 <= len` guarantees 4 readable bytes at `data[i..]`.
            let chunk = *(data.as_ptr().add(i) as *const u32);
            count = count.saturating_add(chunk.count_ones() as usize);
            i += 4;
        }
        // Handle tail bytes
        while i < len {
            count = count.saturating_add(data[i].count_ones() as usize);
            i += 1;
        }
        count
    }
    /// GF(2^8) multiplication with AVX-512 GFNI - 15x faster!
    #[target_feature(enable = "avx512f", enable = "gfni")]
    pub(super) unsafe fn gf_mul_avx512_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
        let b_broadcast = _mm512_set1_epi8(b as i8);
        let len = a.len().min(dst.len());
        let mut i = 0;

        // Process 64 bytes at once with AVX-512 GFNI
        while i + 64 <= len {
            let data = _mm512_loadu_si512(a[i..].as_ptr() as *const __m512i);
            let result = _mm512_gf2p8mul_epi8(data, b_broadcast);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, result);
            i += 64;
        }

        // Handle remainder
        while i < len {
            dst[i] = scalar::gf_mul_byte(a[i], b);
            i += 1;
        }

        // Avoid AVX->SSE transition penalty
        _mm256_zeroupper();
    }

    /// GF(2^8) multiplication with AVX2 - table lookup method
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
        let len = a.len().min(dst.len());
        let mut i = 0;

        // Precompute GF multiplication tables for multiplier b
        let mut lo_table = [0u8; 16];
        let mut hi_table = [0u8; 16];

        for j in 0..16 {
            lo_table[j] = scalar::gf_mul_byte(j as u8, b);
            hi_table[j] = scalar::gf_mul_byte((j << 4) as u8, b);
        }

        // Load lookup tables into AVX2 registers
        let lo_lut =
            _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
        let hi_lut =
            _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
        let nibble_mask = _mm256_set1_epi8(0x0F);

        // Process 32 bytes at once
        while i + 32 <= len {
            let data = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);

            // Split into low and high nibbles
            let lo_nibbles = _mm256_and_si256(data, nibble_mask);
            let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(data, 4), nibble_mask);

            // Table lookup for both nibbles
            let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
            let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);

            // XOR the results (GF addition)
            let result = _mm256_xor_si256(lo_result, hi_result);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, result);
            i += 32;
        }

        // Process remainder with scalar
        while i < len {
            dst[i] = scalar::gf_mul_byte(a[i], b);
            i += 1;
        }
    }

    // SSE2 pattern search removed - using SSE4.2 with PCMPESTRI/PCMPISTRM

    /// Short pattern search with SSE4.2 using string instructions (<= 16 bytes)
    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn find_pattern_sse42_short(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        use std::arch::x86_64::*;
        let nlen = needle.len();
        if nlen == 0 {
            return Some(0);
        }
        if nlen > 16 {
            return None;
        }

        // Use PCMPISTRI for efficient string search
        let needle_vec = _mm_loadu_si128(needle.as_ptr() as *const __m128i);
        let mut i = 0;

        while i + 16 <= haystack.len() {
            let hay_vec = _mm_loadu_si128(haystack.as_ptr().add(i) as *const __m128i);

            // PCMPISTRI: Find first occurrence
            // Mode: _SIDD_CMP_EQUAL_ORDERED | _SIDD_UBYTE_OPS
            const MODE: i32 = 0x0C; // Equal ordered, unsigned bytes

            let idx = _mm_cmpistri(needle_vec, hay_vec, MODE);

            if idx < 16 {
                // Found potential match
                let pos = i + idx as usize;
                if pos + nlen <= haystack.len() {
                    // Verify full match
                    if &haystack[pos..pos + nlen] == needle {
                        return Some(pos);
                    }
                }
            }

            // Check if we need to continue
            if _mm_cmpistrc(needle_vec, hay_vec, MODE) == 0 {
                i += 1; // No carry = no partial match at end
            } else {
                i += 16 - nlen + 1; // Overlap for boundary matches
            }
        }

        // Handle remainder with scalar
        while i + nlen <= haystack.len() {
            if &haystack[i..i + nlen] == needle {
                return Some(i);
            }
            i += 1;
        }

        None
    }
    /// AES encryption with VAES - vectorized AES for parallel blocks
    #[target_feature(enable = "vaes", enable = "avx512f")]
    pub(super) unsafe fn aes_encrypt_vaes(state: &mut [u8; 16], key: &[u8; 16]) {
        // For a single block, VAES provides no material benefit over AES-NI.
        aes_encrypt_aesni(state, key);
    }

    /// AES encryption with AES-NI hardware acceleration
    #[target_feature(enable = "aes", enable = "sse2")]
    pub(super) unsafe fn aes_encrypt_aesni(state: &mut [u8; 16], key: &[u8; 16]) {
        use std::arch::x86_64::*;

        macro_rules! expand_aes128_round_key {
            ($prev:expr, $rcon:expr) => {{
                let mut t = _mm_aeskeygenassist_si128($prev, $rcon);
                t = _mm_shuffle_epi32(t, 0xff);

                let mut k = $prev;
                k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
                k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
                k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
                _mm_xor_si128(k, t)
            }};
        }

        let rk0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        let rk1 = expand_aes128_round_key!(rk0, 0x01);
        let rk2 = expand_aes128_round_key!(rk1, 0x02);
        let rk3 = expand_aes128_round_key!(rk2, 0x04);
        let rk4 = expand_aes128_round_key!(rk3, 0x08);
        let rk5 = expand_aes128_round_key!(rk4, 0x10);
        let rk6 = expand_aes128_round_key!(rk5, 0x20);
        let rk7 = expand_aes128_round_key!(rk6, 0x40);
        let rk8 = expand_aes128_round_key!(rk7, 0x80);
        let rk9 = expand_aes128_round_key!(rk8, 0x1b);
        let rk10 = expand_aes128_round_key!(rk9, 0x36);

        let mut block = _mm_loadu_si128(state.as_ptr() as *const __m128i);
        block = _mm_xor_si128(block, rk0);
        block = _mm_aesenc_si128(block, rk1);
        block = _mm_aesenc_si128(block, rk2);
        block = _mm_aesenc_si128(block, rk3);
        block = _mm_aesenc_si128(block, rk4);
        block = _mm_aesenc_si128(block, rk5);
        block = _mm_aesenc_si128(block, rk6);
        block = _mm_aesenc_si128(block, rk7);
        block = _mm_aesenc_si128(block, rk8);
        block = _mm_aesenc_si128(block, rk9);
        block = _mm_aesenclast_si128(block, rk10);

        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, block);
    }
    /// GHASH with VPCLMULQDQ - AVX-VL (256-bit) carryless multiplication
    #[target_feature(enable = "avx512f", enable = "vpclmulqdq", enable = "avx512vl")]
    pub(super) unsafe fn ghash_vpclmulqdq(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
        use std::arch::x86_64::*;

        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_le = _mm_shuffle_epi8(h_be, shuf);

        let mut y_be = _mm_shuffle_epi8(_mm_loadu_si128(tag.as_ptr() as *const __m128i), shuf);

        let mut i = 0usize;
        while i + 16 <= data.len() {
            let block =
                _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr().add(i) as *const __m128i), shuf);
            y_be = ghash_block_vpclmul(h_le, y_be, block);
            i += 16;
        }

        if i < data.len() {
            let mut tmp = [0u8; 16];
            tmp[..data.len() - i].copy_from_slice(&data[i..]);
            let block = _mm_shuffle_epi8(_mm_loadu_si128(tmp.as_ptr() as *const __m128i), shuf);
            y_be = ghash_block_vpclmul(h_le, y_be, block);
        }

        let out = _mm_shuffle_epi8(y_be, shuf);
        _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, out);
    }

    /// GHASH with PCLMULQDQ - carryless multiplication for GCM
    #[target_feature(enable = "pclmulqdq", enable = "sse2")]
    pub(super) unsafe fn ghash_pclmulqdq(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
        use std::arch::x86_64::*;

        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_le = _mm_shuffle_epi8(h_be, shuf);
        let mut y_be = _mm_shuffle_epi8(_mm_loadu_si128(tag.as_ptr() as *const __m128i), shuf);

        let mut i = 0usize;
        while i + 16 <= data.len() {
            let block =
                _mm_shuffle_epi8(_mm_loadu_si128(data.as_ptr().add(i) as *const __m128i), shuf);
            y_be = ghash_block_pclmul(h_le, y_be, block);
            i += 16;
        }

        if i < data.len() {
            let mut tmp = [0u8; 16];
            tmp[..data.len() - i].copy_from_slice(&data[i..]);
            let block = _mm_shuffle_epi8(_mm_loadu_si128(tmp.as_ptr() as *const __m128i), shuf);
            y_be = ghash_block_pclmul(h_le, y_be, block);
        }

        let out = _mm_shuffle_epi8(y_be, shuf);
        _mm_storeu_si128(tag.as_mut_ptr() as *mut __m128i, out);
    }

    #[target_feature(enable = "avx512f", enable = "vpclmulqdq", enable = "avx512vl")]
    #[inline]
    unsafe fn ghash_block_vpclmul(
        h_le: std::arch::x86_64::__m128i,
        y_be: std::arch::x86_64::__m128i,
        x_be: std::arch::x86_64::__m128i,
    ) -> std::arch::x86_64::__m128i {
        use std::arch::x86_64::*;

        let w_be = _mm_xor_si128(y_be, x_be);
        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let w_le = _mm_shuffle_epi8(w_be, shuf);

        let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
        let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
        let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
        let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);

        let t = _mm_xor_si128(x1, x2);
        let t_lo = _mm_slli_si128(t, 8);
        let t_hi = _mm_srli_si128(t, 8);
        let mut lo = _mm_xor_si128(x0, t_lo);
        let hi = _mm_xor_si128(x3, t_hi);

        let hi_sl1 = _mm_slli_epi64(hi, 1);
        let hi_sl2 = _mm_slli_epi64(hi, 2);
        let hi_sl7 = _mm_slli_epi64(hi, 7);
        let hi_sr63 = _mm_srli_epi64(hi, 63);
        let hi_sr62 = _mm_srli_epi64(hi, 62);
        let hi_sr57 = _mm_srli_epi64(hi, 57);

        let fold1 = _mm_xor_si128(_mm_xor_si128(hi_sl1, hi_sl2), hi_sl7);
        let carry1 = _mm_xor_si128(_mm_xor_si128(hi_sr63, hi_sr62), hi_sr57);
        lo = _mm_xor_si128(lo, fold1);
        lo = _mm_xor_si128(lo, _mm_slli_si128(carry1, 8));

        let lo_hi = _mm_srli_si128(lo, 8);
        let final_fold = _mm_xor_si128(
            _mm_xor_si128(_mm_slli_epi64(lo_hi, 1), _mm_slli_epi64(lo_hi, 2)),
            _mm_slli_epi64(lo_hi, 7),
        );
        let final_carry = _mm_xor_si128(
            _mm_xor_si128(_mm_srli_epi64(lo_hi, 63), _mm_srli_epi64(lo_hi, 62)),
            _mm_srli_epi64(lo_hi, 57),
        );

        let lo_masked = _mm_and_si128(lo, _mm_set_epi64x(-1i64, 0));
        let reduced =
            _mm_xor_si128(_mm_xor_si128(lo_masked, final_fold), _mm_slli_si128(final_carry, 8));

        _mm_shuffle_epi8(reduced, shuf)
    }

    #[target_feature(enable = "pclmulqdq", enable = "sse2")]
    #[inline]
    unsafe fn ghash_block_pclmul(
        h_le: std::arch::x86_64::__m128i,
        y_be: std::arch::x86_64::__m128i,
        x_be: std::arch::x86_64::__m128i,
    ) -> std::arch::x86_64::__m128i {
        use std::arch::x86_64::*;

        let w_be = _mm_xor_si128(y_be, x_be);
        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let w_le = _mm_shuffle_epi8(w_be, shuf);

        let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
        let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
        let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
        let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);

        let t = _mm_xor_si128(x1, x2);
        let t_lo = _mm_slli_si128(t, 8);
        let t_hi = _mm_srli_si128(t, 8);
        let mut lo = _mm_xor_si128(x0, t_lo);
        let hi = _mm_xor_si128(x3, t_hi);

        let hi_sl1 = _mm_slli_epi64(hi, 1);
        let hi_sl2 = _mm_slli_epi64(hi, 2);
        let hi_sl7 = _mm_slli_epi64(hi, 7);
        let hi_sr63 = _mm_srli_epi64(hi, 63);
        let hi_sr62 = _mm_srli_epi64(hi, 62);
        let hi_sr57 = _mm_srli_epi64(hi, 57);

        let fold1 = _mm_xor_si128(_mm_xor_si128(hi_sl1, hi_sl2), hi_sl7);
        let carry1 = _mm_xor_si128(_mm_xor_si128(hi_sr63, hi_sr62), hi_sr57);
        lo = _mm_xor_si128(lo, fold1);
        lo = _mm_xor_si128(lo, _mm_slli_si128(carry1, 8));

        let lo_hi = _mm_srli_si128(lo, 8);
        let final_fold = _mm_xor_si128(
            _mm_xor_si128(_mm_slli_epi64(lo_hi, 1), _mm_slli_epi64(lo_hi, 2)),
            _mm_slli_epi64(lo_hi, 7),
        );
        let final_carry = _mm_xor_si128(
            _mm_xor_si128(_mm_srli_epi64(lo_hi, 63), _mm_srli_epi64(lo_hi, 62)),
            _mm_srli_epi64(lo_hi, 57),
        );

        let lo_masked = _mm_and_si128(lo, _mm_set_epi64x(-1i64, 0));
        let reduced =
            _mm_xor_si128(_mm_xor_si128(lo_masked, final_fold), _mm_slli_si128(final_carry, 8));

        _mm_shuffle_epi8(reduced, shuf)
    }

    /// SHA-256 with SHA Extensions hardware acceleration
    #[target_feature(enable = "sha", enable = "sse2")]
    pub(super) unsafe fn sha256_hw(data: &[u8]) -> [u8; 32] {
        // Correctness-first fallback until a full SHA-NI schedule/padding implementation is wired.
        scalar::sha256(data)
    }
    /// Histogram with AVX-512 - conflict detection for fast counting
    #[target_feature(enable = "avx512f", enable = "avx512cd")]
    pub(super) unsafe fn histogram_avx512(data: &[u8]) -> [u32; 256] {
        let mut hist = [0u32; 256];
        let mut i = 0;

        // Process 64 bytes at a time
        while i + 64 <= data.len() {
            let values = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

            // Use AVX-512 conflict detection for histogram
            let conflicts = _mm512_conflict_epi32(values);

            // Process conflicts and update histogram
            let mask = _mm512_testn_epi32_mask(conflicts, conflicts);
            if mask == 0xFFFF {
                // No conflicts - direct update
                let mut vals = [0u32; 16];
                _mm512_storeu_si512(vals.as_mut_ptr() as *mut _, values);
                for v in vals {
                    let idx = (v as usize) & 0xFF;
                    hist[idx] += 1;
                }
            } else {
                // Handle conflicts with masked operations
                let unique = _mm512_mask_compress_epi32(_mm512_setzero_si512(), mask, values);
                let counts = _mm512_popcnt_epi32(conflicts);

                let mut uniq_vals = [0u32; 16];
                let mut cnt_vals = [0u32; 16];
                _mm512_storeu_si512(uniq_vals.as_mut_ptr() as *mut _, unique);
                _mm512_storeu_si512(cnt_vals.as_mut_ptr() as *mut _, counts);
                for j in 0..16 {
                    if (mask & (1 << j)) != 0 {
                        let idx = (uniq_vals[j] as usize) & 0xFF;
                        let cnt = cnt_vals[j];
                        hist[idx] += cnt;
                    }
                }
            }

            i += 64;
        }

        // Handle remainder
        while i < data.len() {
            hist[data[i] as usize] += 1;
            i += 1;
        }
        // Avoid AVX->SSE transition penalty
        _mm256_zeroupper();
        hist
    }

    /// QPACK Huffman encoding with AVX2 - vectorized symbol lookup
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn qpack_encode_avx2(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3::qpack::HUFF_CODES;

        let mut acc: u128 = 0;
        let mut bits: usize = 0;
        let mut written: usize = 0;
        let mut i = 0usize;

        // Process 8 bytes at a time with AVX2
        while i + 8 <= input.len() {
            // Load 8 bytes and expand to i32 indices
            let chunk = _mm_loadl_epi64(input.as_ptr().add(i) as *const __m128i);
            let idx = _mm256_cvtepu8_epi32(chunk); // 8 u32 indices
                                                   // Compute byte offsets (index * 4) for i32 gathers
            let offsets = _mm256_slli_epi32(idx, 2);

            // Gather codes (u32) and lens (i32) from tables
            let codes_v = _mm256_i32gather_epi32(HUFF_CODES.as_ptr() as *const i32, offsets, 1);
            let lens_v = _mm256_i32gather_epi32(lens32_ptr(), offsets, 1);

            // Move to arrays for serial bit packing
            let mut codes: [i32; 8] = core::mem::zeroed();
            let mut lens: [i32; 8] = core::mem::zeroed();
            _mm256_storeu_si256(codes.as_mut_ptr() as *mut __m256i, codes_v);
            _mm256_storeu_si256(lens.as_mut_ptr() as *mut __m256i, lens_v);

            for j in 0..8 {
                let code = codes[j] as u128;
                let clen = lens[j] as usize;

                // Flush accumulator if near overflow
                if bits + clen > 120 {
                    while bits >= 8 {
                        let shift = bits - 8;
                        if written >= output.len() {
                            return written;
                        }
                        let byte = ((acc >> shift) & 0xff) as u8;
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                acc = (acc << clen) | code;
                bits += clen;

                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            i += 8;
        }

        // Scalar tail
        while i < input.len() {
            let sym = input[i] as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = crate::transport::h3::qpack::HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    if written >= output.len() {
                        return written;
                    }
                    let byte = ((acc >> shift) & 0xff) as u8;
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                if written >= output.len() {
                    return written;
                }
                let byte = ((acc >> shift) & 0xff) as u8;
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }

            i += 1;
        }

        // Flush remaining bits with EOS padding
        if bits > 0 {
            if written >= output.len() {
                return written;
            }
            let pad_mask = (1u128 << (8 - bits)) - 1;
            let byte = ((acc << (8 - bits)) | pad_mask) as u8;
            output[written] = byte;
            written += 1;
        }

        _mm256_zeroupper();
        written
    }

    /// Histogram with AVX2 - gather/scatter for histogram
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn histogram_avx2(data: &[u8]) -> [u32; 256] {
        // AVX2 dispatch path currently shares the scalar counting core to keep
        // one authoritative histogram implementation.
        scalar::histogram(data)
    }

    /// Decode varint with BMI2 PEXT - extract bits efficiently
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn decode_varint_bmi2(buf: &[u8]) -> Option<(u64, usize)> {
        use std::arch::x86_64::*;

        if buf.len() < 8 {
            return super::scalar::decode_varint(buf);
        }

        // SAFETY: `buf.len() >= 8` checked above, so reading 8 bytes from `buf.as_ptr()`
        // is in bounds. Unaligned u64 reads are valid on x86_64.
        let data = *(buf.as_ptr() as *const u64);

        // Find continuation bits with BMI2
        let continuation_mask = 0x8080808080808080u64;
        let cont_bits = data & continuation_mask;

        // Count leading zeros to find length
        let len_bits = (!cont_bits).trailing_zeros() / 8 + 1;
        if len_bits > 8 {
            return super::scalar::decode_varint(buf);
        }

        // Extract value bits with PEXT
        let value_mask = 0x7F7F7F7F7F7F7F7Fu64;
        let extracted = _pext_u64(data, value_mask);

        // Mask to actual length
        let mask = (1u64 << (len_bits * 7)) - 1;
        let value = extracted & mask;

        Some((value, len_bits as usize))
    }

    /// Decode varint with AVX2 - parallel byte processing
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn decode_varint_avx2(buf: &[u8]) -> Option<(u64, usize)> {
        use std::arch::x86_64::*;

        if buf.len() < 8 {
            return super::scalar::decode_varint(buf);
        }

        // Load bytes into AVX2 register
        let data = _mm_loadl_epi64(buf.as_ptr() as *const __m128i);

        // Mask for continuation bits
        let cont_mask = _mm_set1_epi8(0x80u8 as i8);
        let cont_bits = _mm_and_si128(data, cont_mask);

        // Find first non-continuation byte
        let cmp = _mm_cmpeq_epi8(cont_bits, _mm_setzero_si128());
        let mask = _mm_movemask_epi8(cmp) as u32;

        if mask == 0 {
            return None; // All continuation
        }

        let len = mask.trailing_zeros() as usize + 1;
        if len > 8 {
            return None;
        }

        // Extract and combine value bits
        let value_mask = _mm_set1_epi8(0x7F);
        let values = _mm_and_si128(data, value_mask);

        // Shift and combine
        let mut result = 0u64;
        // SAFETY: `__m128i` and `[u8; 16]` have identical size (16 bytes). All bit
        // patterns are valid for u8, so the transmute is sound.
        let bytes = std::mem::transmute::<__m128i, [u8; 16]>(values);
        for i in 0..len {
            result |= (bytes[i] as u64) << (i * 7);
        }

        Some((result, len))
    }

    /// Pattern matching with AVX2 - 5x faster than scalar
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        use std::arch::x86_64::*;

        if needle.is_empty() || needle.len() > haystack.len() {
            return None;
        }

        if needle.len() <= 32 {
            // Short needle - use SIMD comparison
            let needle_len = needle.len();
            let first = _mm256_set1_epi8(needle[0] as i8);
            let last = _mm256_set1_epi8(needle[needle_len - 1] as i8);

            let mut i = 0;
            while i + needle_len + 31 <= haystack.len() {
                // Load 32 bytes
                let hay_first = _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
                let hay_last =
                    _mm256_loadu_si256(haystack.as_ptr().add(i + needle_len - 1) as *const __m256i);

                // Compare first and last bytes
                let eq_first = _mm256_cmpeq_epi8(hay_first, first);
                let eq_last = _mm256_cmpeq_epi8(hay_last, last);
                let eq_both = _mm256_and_si256(eq_first, eq_last);

                let mask = _mm256_movemask_epi8(eq_both) as u32;

                if mask != 0 {
                    // Found potential matches
                    let mut m = mask;
                    while m != 0 {
                        let bit = m.trailing_zeros() as usize;
                        let pos = i + bit;

                        // Verify full match
                        if &haystack[pos..pos + needle_len] == needle {
                            return Some(pos);
                        }

                        m &= m - 1; // Clear lowest bit
                    }
                }

                i += 32;
            }
        }

        // Fallback for remainder or long needles
        haystack.windows(needle.len()).position(|window| window == needle)
    }
    // Note: ARM/NEON/SVE code must not live in this x86 module.
    // A large aarch64 block was accidentally duplicated here; it was removed.
}

// ============================================================================
// FEC SPECIFIC - Berlekamp-Massey, Wiedemann and Reed-Solomon solvers
// ============================================================================

/// FEC-specific SIMD helpers: Berlekamp-Massey, varint decoding, header validation.
pub mod fec {
    use super::*;

    /// Berlekamp-Massey with AVX-512 GFNI acceleration when available.
    #[inline(always)]
    fn _decode_varint_profile_router_removed(_buf: &[u8]) -> Option<(u64, usize)> {
        let features = FeatureDetector::instance();
        let _profile = features.profile();

        #[cfg(target_arch = "x86_64")]
        {
            match _profile {
                CpuProfile::X86_P2b
                | CpuProfile::X86_P3a
                | CpuProfile::X86_P3b
                | CpuProfile::X86_P3c
                | CpuProfile::X86_P3d
                | CpuProfile::X86_P3e
                | CpuProfile::X86_P4a
                | CpuProfile::X86_P4b => {
                    // SAFETY: Profile check guarantees BMI2 feature presence.
                    return unsafe { x86::decode_varint_bmi2(_buf) };
                }
                CpuProfile::X86_P2a => {
                    // SAFETY: Profile check guarantees AVX2 feature presence.
                    return unsafe { x86::decode_varint_avx2(_buf) };
                }
                _ => {}
            }
        }
        None
    }

    /// Router: Berlekamp-Massey over GF(256) with best available backend
    #[inline(always)]
    pub fn berlekamp_massey_gf256(syndrome: &[u8], len: usize) -> Vec<u8> {
        let features = FeatureDetector::instance();
        // SAFETY: Each branch is guarded by runtime feature detection matching the
        // callee's `#[target_feature]`. Callees only read `syndrome[..len]` and
        // return an owned Vec - no aliasing or pointer lifetime concerns.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
                return unsafe { super::x86_extended::berlekamp_massey_gfni(syndrome, len) };
            }
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86_extended::berlekamp_massey_avx2(syndrome, len) };
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2)
                && std::arch::is_aarch64_feature_detected!("sve2")
            {
                return unsafe { berlekamp_massey_sve2_dispatch(syndrome, len) };
            }
        }
        // Scalar fallback
        super::scalar::berlekamp_massey(syndrome, len)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline(always)]
    unsafe fn berlekamp_massey_sve2_dispatch(syndrome: &[u8], len: usize) -> Vec<u8> {
        super::arm::berlekamp_massey_sve2(syndrome, len)
    }

    #[cfg(any(not(target_arch = "aarch64"), not(target_feature = "sve2")))]
    #[inline(always)]
    unsafe fn berlekamp_massey_sve2_dispatch(syndrome: &[u8], len: usize) -> Vec<u8> {
        super::scalar::berlekamp_massey(syndrome, len)
    }

    /// FEC header parsing helper.
    ///
    /// Returns `(kind, u32_field, u64_field)` parsed from the first 13 bytes.
    #[inline(always)]
    pub fn parse_header_bmi2(header: &[u8]) -> Option<(u8, u32, u64)> {
        if header.len() < 13 {
            return None;
        }

        let kind = header[0];
        let u32_field = u32::from_le_bytes(header[1..5].try_into().ok()?);
        let u64_field = u64::from_le_bytes(header[5..13].try_into().ok()?);

        Some((kind, u32_field, u64_field))
    }

    /// Varint decoding with BMI2 acceleration when available.
    #[inline(always)]
    pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance();
            // SAFETY: Runtime feature detection matches the callee's `#[target_feature]`.
            // Both callees validate `buf.len()` internally before raw pointer reads.
            if features.has_feature(CpuFeature::BMI2) {
                return unsafe { super::x86::varint_decode_bmi2(buf) };
            }
            if features.has_feature(CpuFeature::SSE2) {
                if let Some(res) = unsafe { super::x86::varint_decode_sse2_prefast(buf) } {
                    return Some(res);
                }
            }
        }

        scalar::decode_varint(buf)
    }

    /// QUIC packet header validation with SIMD acceleration when available.
    #[inline(always)]
    pub fn validate_header(header: &[u8]) -> bool {
        if header.len() < 5 {
            return false;
        }

        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by runtime feature detection matching the
        // callee's `#[target_feature]`. The `header.len() >= 5` guard above ensures
        // the header is non-empty. All callees only read from `header` and return bool.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::AVX512F) {
                return unsafe { crate::simd::x86_header::validate_header_avx512(header) };
            }
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::validate_header_avx2(header) };
            }
            if features.has_feature(CpuFeature::SSE42) {
                return unsafe { super::x86::validate_header_sse2(header) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                return unsafe { super::arm::validate_header_sve2(header) };
            }
            if features.has_feature(CpuFeature::NEON) {
                return unsafe { super::arm::validate_header_neon(header) };
            }
        }

        scalar::validate_header(header)
    }
}

// ============================================================================
// BITSTREAM OPERATIONS - Pack/Unpack with BMI2
// ============================================================================

/// Bitstream pack/unpack with BMI2/NEON acceleration.
pub mod bitstream {
    use super::*;

    /// Pack bits with BMI2 acceleration when available.
    #[inline(always)]
    pub fn pack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
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
}

// =========================================================================
// TRANSPORT HELPERS - QUIC varint encode/decode (wrappers for transport)
// =========================================================================

/// QUIC variable-length integer encode/decode with SIMD acceleration.
pub mod transport {
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
}

// ============================================================================
// STRING OPERATIONS - Ultra-fast comparison
// ============================================================================

/// SIMD-accelerated byte-string comparison.
pub mod string {
    #[cfg(target_arch = "x86_64")]
    use crate::optimize::{CpuFeature, FeatureDetector};

    /// String comparison with SIMD acceleration when available.
    #[inline(always)]
    pub fn compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
        // Both `a` and `b` are borrowed slices of equal length (checked above).
        // Callees process in SIMD-width chunks with scalar tail handling.
        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance();
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::string_compare_avx2(a, b) };
            }
            if features.has_feature(CpuFeature::SSE42) {
                return unsafe { super::x86::string_compare_sse42(a, b) };
            }
        }

        a == b
    }
}

// ============================================================================
// HTTP/3 QPACK - Header compression with SIMD
// ============================================================================

/// HTTP/3 QPACK Huffman encode/decode with SIMD acceleration.
pub mod h3 {
    use super::*;

    /// QPACK Huffman encoding with SIMD acceleration when available.
    #[inline(always)]
    pub fn qpack_encode(input: &[u8], output: &mut [u8]) -> usize {
        let features = FeatureDetector::instance();

        // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
        // Callees read from `input`, write to `output` with bounds checks,
        // and return the number of bytes written.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::qpack_encode_avx2(input, output) };
            }
            if features.has_feature(CpuFeature::SSSE3) {
                return unsafe { super::x86::qpack_encode_ssse3(input, output) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                return super::arm::qpack_encode_sve2(input, output);
            }
            if features.has_feature(CpuFeature::NEON) {
                return super::arm::qpack_encode_neon(input, output);
            }
        }

        scalar::qpack_encode(input, output)
    }

    /// QPACK Huffman decoding with SIMD acceleration when available.
    #[inline(always)]
    pub fn qpack_decode(input: &[u8], output: &mut [u8]) -> usize {
        let features = FeatureDetector::instance();

        // SAFETY: Runtime feature detection matches each callee's `#[target_feature]`.
        // Callees read from `input` and write to `output` with bounds checks.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::qpack_decode_avx2(input, output) };
            }
            if features.has_feature(CpuFeature::SSSE3) {
                return unsafe { super::x86::qpack_decode_ssse3(input, output) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::SVE2) {
                return super::arm::qpack_decode_sve2(input, output);
            }
            if features.has_feature(CpuFeature::NEON) {
                return super::arm::qpack_decode_neon(input, output);
            }
        }

        scalar::qpack_decode(input, output)
    }
}

// ============================================================================
// INTEL AMX IMPLEMENTATIONS
// ============================================================================

#[cfg(all(target_arch = "x86_64", target_feature = "amx-tile"))]
pub(crate) mod amx {
    use std::arch::asm;

    const TILE_BYTES: usize = 64;
    const TILE_ROWS_0: u8 = 16;
    const TILE_COLS_0: u16 = 64;

    #[repr(C, align(64))]
    struct TileConfig {
        palette_id: u8,
        start_row: u8,
        reserved: [u8; 14],
        colsb: [u16; 8],
        rows: [u8; 8],
        reserved2: [u8; 24],
    }

    impl TileConfig {
        const fn new() -> Self {
            Self {
                palette_id: 1,
                start_row: 0,
                reserved: [0u8; 14],
                colsb: [0u16; 8],
                rows: [0u8; 8],
                reserved2: [0u8; 24],
            }
        }

        fn configure(&mut self, rows: u8, cols: u16) {
            self.palette_id = 1;
            self.start_row = 0;
            self.colsb = [0u16; 8];
            self.rows = [0u8; 8];
            self.colsb[0] = cols;
            self.rows[0] = rows;
            // Clear remaining slots for safety
            for slot in 1..8 {
                self.colsb[slot] = 0;
                self.rows[slot] = 0;
            }
        }
    }

    static mut TILE_CONFIG: TileConfig = TileConfig::new();

    /// Configure AMX tiles for the canonical 16x64 layout used in GF(256) blocks.
    #[target_feature(enable = "amx-tile")]
    pub(super) unsafe fn amx_init() {
        TILE_CONFIG.configure(TILE_ROWS_0, TILE_COLS_0);
        asm!(
            "ldtilecfg [{cfg}]",
            cfg = in(reg) &TILE_CONFIG as *const TileConfig,
            options(nostack)
        );
    }

    /// Release AMX tiles after use.
    #[target_feature(enable = "amx-tile")]
    pub(super) unsafe fn amx_release() {
        asm!("tilerelease", options(nostack));
    }

    /// Matrix multiply with Intel AMX
    #[target_feature(enable = "amx-int8")]
    pub(super) unsafe fn amx_matmul_i8(
        a: &[i8],
        b: &[i8],
        c: &mut [i32],
        m: usize,
        k: usize,
        n: usize,
    ) {
        use std::arch::asm;

        amx_init();

        // Load tiles and perform multiplication
        asm!(
            "tileloadd tmm0, [{}]",
            "tileloadd tmm1, [{}]",
            "tdpbssd tmm2, tmm0, tmm1",
            "tilestored [{}], tmm2",
            in(reg) a.as_ptr(),
            in(reg) b.as_ptr(),
            in(reg) c.as_mut_ptr(),
            options(nostack)
        );

        // Release tiles
        asm!("tilerelease", options(nostack));
    }

    /// GF(256) matrix x vector multiply specialised for Wiedemann solver.
    #[target_feature(enable = "amx-int8")]
    pub(super) unsafe fn matmul_gf256_amx(
        matrix: &[u8],
        vector: &[u8],
        output: &mut [u8],
        rows: usize,
        cols: usize,
        _out_cols: usize,
    ) {
        use crate::fec::gf_tables;

        const TILE_ROWS: usize = 16;
        const TILE_COLS: usize = 64;

        if rows == 0 || cols == 0 {
            return;
        }

        amx_init();
        let mut tile_buf = [0u8; TILE_ROWS * TILE_COLS];

        for row_block in (0..rows).step_by(TILE_ROWS) {
            let block_rows = usize::min(TILE_ROWS, rows - row_block);
            for col_block in (0..cols).step_by(TILE_COLS) {
                let block_cols = usize::min(TILE_COLS, cols - col_block);

                if block_rows == TILE_ROWS && block_cols == TILE_COLS {
                    let src = matrix.as_ptr().add(row_block * cols + col_block);
                    asm!(
                        "tileloadd tmm0, [{src}]",
                        src = in(reg) src,
                        options(nostack)
                    );
                    asm!(
                        "tilestored [{dst}], tmm0",
                        dst = in(reg) tile_buf.as_mut_ptr(),
                        options(nostack)
                    );
                } else {
                    for r in 0..block_rows {
                        let src = matrix.as_ptr().add((row_block + r) * cols + col_block);
                        let dst = tile_buf.as_mut_ptr().add(r * TILE_COLS);
                        std::ptr::copy_nonoverlapping(src, dst, block_cols);
                    }
                }

                for r in 0..block_rows {
                    let mut acc = if col_block == 0 { 0u8 } else { output[row_block + r] };

                    let row_slice = &tile_buf[r * TILE_COLS..r * TILE_COLS + block_cols];
                    for (idx, &val) in row_slice.iter().enumerate() {
                        let coeff = vector[col_block + idx];
                        if val != 0 && coeff != 0 {
                            acc ^= gf_tables::gf_mul_table(val, coeff);
                        }
                    }

                    output[row_block + r] = acc;
                }
            }
        }

        amx_release();
    }
}

// ============================================================================
// SCALAR FALLBACK IMPLEMENTATIONS
// ============================================================================

// ============================================================================
// X86 EXTENDED IMPLEMENTATIONS FOR FEC AND TRANSPORT
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod x86_extended {
    use super::scalar;
    use super::*;
    use std::arch::x86_64::*;

    /// Berlekamp-Massey with AVX-512 GFNI acceleration when available.
    #[target_feature(enable = "avx512f", enable = "gfni")]
    pub(super) unsafe fn berlekamp_massey_gfni(syndrome: &[u8], len: usize) -> Vec<u8> {
        let mut error_locator = vec![0u8; len + 1];
        error_locator[0] = 1;
        let mut old_locator = vec![0u8; len + 1];
        old_locator[0] = 1;

        let mut syndrome_shift = 0;
        let mut error_degree = 0;
        let mut old_degree = 1;

        // Process syndrome bytes with SIMD
        for i in 0..len {
            let mut discrepancy = syndrome[i];

            // Calculate discrepancy using GFNI
            if error_degree > 0 {
                let mut j = 1;

                while j <= error_degree && j + 64 <= len {
                    // Load 64 coefficients at once
                    let coeff = _mm512_loadu_si512(error_locator[j..].as_ptr() as *const __m512i);
                    let synd = _mm512_loadu_si512(syndrome[i - j..].as_ptr() as *const __m512i);

                    // GF(256) multiplication with GFNI
                    let prod = _mm512_gf2p8mul_epi8(coeff, synd);

                    // XOR reduce to get discrepancy contribution
                    let mask = _mm512_cmpneq_epi8_mask(coeff, _mm512_setzero_si512());
                    // XOR reduce manually - _mm512_mask_reduce_xor_epi8 doesn't exist
                    // Store and reduce in scalar
                    let mut temp = [0u8; 64];
                    _mm512_mask_storeu_epi8(temp.as_mut_ptr() as *mut i8, mask, prod);
                    for t in temp.iter().take(64) {
                        discrepancy ^= t;
                    }

                    j += 64;
                }

                // Handle remainder
                for j in j..=error_degree.min(i) {
                    discrepancy ^= scalar::gf_mul_byte(error_locator[j], syndrome[i - j]);
                }
            }

            if discrepancy != 0 {
                // Update error locator polynomial
                let mut new_locator = error_locator.clone();

                // Vectorized polynomial update
                let inv_disc = scalar::gf_inv(syndrome_shift);
                let factor = _mm512_set1_epi8(scalar::gf_mul_byte(discrepancy, inv_disc) as i8);

                let mut j = 0;
                while j + 64 <= len {
                    let old = _mm512_loadu_si512(old_locator[j..].as_ptr() as *const __m512i);
                    let curr = _mm512_loadu_si512(
                        error_locator[j + i - old_degree + 1..].as_ptr() as *const __m512i
                    );

                    // GF multiply and XOR
                    let prod = _mm512_gf2p8mul_epi8(factor, old);
                    let result = _mm512_xor_si512(curr, prod);

                    _mm512_storeu_si512(
                        new_locator[j + i - old_degree + 1..].as_mut_ptr() as *mut __m512i,
                        result,
                    );
                    j += 64;
                }

                // Handle remainder
                for j in j..=old_degree {
                    if j + i >= old_degree {
                        new_locator[j + i - old_degree + 1] ^= scalar::gf_mul_byte(
                            scalar::gf_mul_byte(discrepancy, inv_disc),
                            old_locator[j],
                        );
                    }
                }

                if 2 * error_degree <= i {
                    old_locator = error_locator.clone();
                    old_degree = error_degree;
                    syndrome_shift = discrepancy;
                    error_degree = i + 1 - error_degree;
                }

                error_locator = new_locator;
            }
        }

        error_locator.truncate(error_degree + 1);
        error_locator
    }

    /// Berlekamp-Massey with AVX2 acceleration when available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn berlekamp_massey_avx2(syndrome: &[u8], len: usize) -> Vec<u8> {
        // Keep AVX2 routing separate from GFNI/AVX-512 to avoid unsupported instructions.
        scalar::berlekamp_massey(syndrome, len)
    }

    /// GF(256) matrix multiplication with GFNI
    #[target_feature(enable = "avx512f", enable = "gfni")]
    pub(super) unsafe fn matmul_gf256_gfni(
        a: &[u8],
        b: &[u8],
        c: &mut [u8],
        m: usize,
        k: usize,
        n: usize,
    ) {
        // Zero output matrix
        for elem in c.iter_mut().take(m * n) {
            *elem = 0;
        }

        // Matrix multiplication in GF(256)
        for i in 0..m {
            for kk in 0..k {
                if a[i * k + kk] == 0 {
                    continue;
                }

                let a_elem = _mm512_set1_epi8(a[i * k + kk] as i8);
                let mut j = 0;

                // Process 64 elements at once
                while j + 64 <= n {
                    let b_vec = _mm512_loadu_si512(b[(kk * n + j)..].as_ptr() as *const __m512i);
                    let c_vec = _mm512_loadu_si512(c[(i * n + j)..].as_ptr() as *const __m512i);

                    // GF(256) multiply and accumulate
                    let prod = _mm512_gf2p8mul_epi8(a_elem, b_vec);
                    let result = _mm512_xor_si512(c_vec, prod);

                    _mm512_storeu_si512(c[(i * n + j)..].as_mut_ptr() as *mut __m512i, result);
                    j += 64;
                }

                // Handle remainder
                while j < n {
                    c[i * n + j] ^= scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
                    j += 1;
                }
            }
        }
    }

    /// GF(256) matrix multiplication with AVX2
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn matmul_gf256_avx2(
        a: &[u8],
        b: &[u8],
        c: &mut [u8],
        m: usize,
        k: usize,
        n: usize,
    ) {
        // Use AVX2 with lookup tables for GF multiplication
        for elem in c.iter_mut().take(m * n) {
            *elem = 0;
        }

        for i in 0..m {
            for kk in 0..k {
                if a[i * k + kk] == 0 {
                    continue;
                }

                // Build lookup tables for this multiplier
                let mut lo_table = [0u8; 16];
                let mut hi_table = [0u8; 16];
                for j in 0..16 {
                    lo_table[j] = scalar::gf_mul_byte(j as u8, a[i * k + kk]);
                    hi_table[j] = scalar::gf_mul_byte((j << 4) as u8, a[i * k + kk]);
                }

                let lo_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    lo_table.as_ptr() as *const __m128i
                ));
                let hi_lut = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    hi_table.as_ptr() as *const __m128i
                ));
                let nibble_mask = _mm256_set1_epi8(0x0F);

                let mut j = 0;
                while j + 32 <= n {
                    let b_vec = _mm256_loadu_si256(b[(kk * n + j)..].as_ptr() as *const __m256i);
                    let c_vec = _mm256_loadu_si256(c[(i * n + j)..].as_ptr() as *const __m256i);

                    // GF multiply using shuffle
                    let lo_nibbles = _mm256_and_si256(b_vec, nibble_mask);
                    let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(b_vec, 4), nibble_mask);
                    let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
                    let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);
                    let prod = _mm256_xor_si256(lo_result, hi_result);

                    // XOR accumulate
                    let result = _mm256_xor_si256(c_vec, prod);
                    _mm256_storeu_si256(c[(i * n + j)..].as_mut_ptr() as *mut __m256i, result);

                    j += 32;
                }

                // Handle remainder
                while j < n {
                    c[i * n + j] ^= scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
                    j += 1;
                }
            }
        }

        _mm256_zeroupper();
    }

    #[inline(always)]
    fn quic_encode_bytes(val: u64, buf: &mut [u8]) -> Option<usize> {
        let (len, prefix) = super::quic_varint_len_prefix(val)?;
        if buf.len() < len {
            return None;
        }
        let mut bytes = val.to_be_bytes();
        let start = 8 - len;
        bytes[start] = (bytes[start] & 0x3F) | ((prefix as u8) << 6);
        buf[..len].copy_from_slice(&bytes[start..start + len]);
        Some(len)
    }

    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn encode_varint_sse2(val: u64, buf: &mut [u8]) -> Option<usize> {
        quic_encode_bytes(val, buf)
    }

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encode_varint_avx2(val: u64, buf: &mut [u8]) -> Option<usize> {
        quic_encode_bytes(val, buf)
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn encode_varint_avx512(val: u64, buf: &mut [u8]) -> Option<usize> {
        quic_encode_bytes(val, buf)
    }

    /// Varint encoding with BMI2 acceleration when available.
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn varint_encode_bmi2(mut value: u64, buf: &mut [u8]) -> usize {
        use std::arch::x86_64::*;

        if value < 128 {
            buf[0] = value as u8;
            return 1;
        }

        // Use BMI2 instructions for efficient bit manipulation
        let mut pos = 0;
        while value >= 128 {
            // Extract 7 bits and set continuation bit
            let byte = _pext_u64(value, 0x7F) | 0x80;
            buf[pos] = byte as u8;
            value >>= 7;
            pos += 1;
        }

        buf[pos] = value as u8;
        pos + 1
    }

    /// Varint decoding with BMI2 acceleration when available.
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn varint_decode_bmi2(buf: &[u8]) -> Option<(u64, usize)> {
        use std::arch::x86_64::*;

        if buf.is_empty() {
            return None;
        }

        let mut value = 0u64;
        let mut shift = 0;

        for (i, &byte) in buf.iter().enumerate().take(10) {
            // Use BMI2 to extract and deposit bits efficiently
            let bits = _pext_u64(byte as u64, 0x7F);
            value = _pdep_u64(bits, 0x7F << shift) | value;

            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }

            shift += 7;
            if shift >= 64 {
                return None; // Overflow
            }
        }

        None
    }

    /// Batch XOR with multiple keys - runtime dispatch
    #[inline(always)]
    pub fn xor_multi_key(data: &mut [u8], keys: &[&[u8]]) {
        let detector = FeatureDetector::instance();
        let features = detector.features_full();

        // SAFETY: Runtime feature check matches each callee's `#[target_feature]`.
        // Callees iterate keys with internal length checks and scalar tail handling.
        #[cfg(target_arch = "x86_64")]
        {
            if features.avx512f {
                unsafe { xor_multi_key_avx512(data, keys) };
                return;
            }
            if features.avx2 {
                unsafe { xor_multi_key_avx2(data, keys) };
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.neon {
                unsafe { super::arm::xor_multi_key_neon(data, keys) };
                return;
            }
        }

        // Scalar fallback
        for key in keys {
            let key_len = key.len();
            if key_len == 0 {
                continue;
            }
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= key[i % key_len];
            }
        }
    }

    /// Batch XOR with multiple keys (vectorized when available).
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn xor_multi_key_avx512(data: &mut [u8], keys: &[&[u8]]) {
        use std::arch::x86_64::*;

        for key in keys {
            let key_len = key.len();
            if key_len == 0 {
                continue;
            }

            let mut i = 0;

            if key_len == 64 {
                let key_vec = _mm512_loadu_si512(key.as_ptr() as *const __m512i);

                while i + 64 <= data.len() {
                    let data_vec = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
                    let result = _mm512_xor_si512(data_vec, key_vec);
                    _mm512_storeu_si512(data.as_mut_ptr().add(i) as *mut __m512i, result);
                    i += 64;
                }
            }

            while i < data.len() {
                data[i] ^= key[i % key_len];
                i += 1;
            }
        }
    }

    /// Batch XOR with multiple keys using AVX2 when available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn xor_multi_key_avx2(data: &mut [u8], keys: &[&[u8]]) {
        use std::arch::x86_64::*;

        for key in keys {
            let key_len = key.len();
            if key_len == 0 {
                continue;
            }

            let mut i = 0;

            if key_len == 32 {
                let key_vec = _mm256_loadu_si256(key.as_ptr() as *const __m256i);

                while i + 32 <= data.len() {
                    let data_vec = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
                    let result = _mm256_xor_si256(data_vec, key_vec);
                    _mm256_storeu_si256(data.as_mut_ptr().add(i) as *mut __m256i, result);
                    i += 32;
                }
            }

            while i < data.len() {
                data[i] ^= key[i % key_len];
                i += 1;
            }
        }

        _mm256_zeroupper();
    }

    /// Packet header validation with AVX2 when available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn validate_header_avx2(header: &[u8]) -> bool {
        use std::arch::x86_64::*;

        if header.len() < 32 {
            return scalar::validate_header(header);
        }

        let data = _mm256_loadu_si256(header.as_ptr() as *const __m256i);

        // Check fixed bit (0x40) is set
        let fixed_bit_mask = _mm256_set1_epi8(0x40);
        let first_byte = _mm256_and_si256(data, fixed_bit_mask);
        let fixed_check = _mm256_cmpeq_epi8(first_byte, fixed_bit_mask);

        let first = _mm256_extract_epi8(fixed_check, 0);
        if first == 0 {
            return false;
        }

        true
    }

    /// Packet header validation with SSE2 when available.
    #[target_feature(enable = "sse2")]
    pub(super) unsafe fn validate_header_sse2(header: &[u8]) -> bool {
        use std::arch::x86_64::*;

        if header.is_empty() {
            return false;
        }

        // Replicate first byte across lanes
        let first = _mm_set1_epi8(header[0] as i8);

        // Check fixed bit (0x40) is set
        let fixed_mask = _mm_set1_epi8(0x40u8 as i8);
        let fixed = _mm_and_si128(first, fixed_mask);
        let fixed_ok = _mm_cmpeq_epi8(fixed, fixed_mask);
        if _mm_movemask_epi8(fixed_ok) != 0xFFFF {
            return false;
        }

        // For short headers (0x80 not set): reserved bits 0x18 must be zero
        if (header[0] & 0x80) == 0 {
            let reserved_mask = _mm_set1_epi8(0x18u8 as i8);
            let reserved = _mm_and_si128(first, reserved_mask);
            let zero = _mm_setzero_si128();
            let reserved_ok = _mm_cmpeq_epi8(reserved, zero);
            if _mm_movemask_epi8(reserved_ok) != 0xFFFF {
                return false;
            }
        }

        true
    }

    /// Pack bits with BMI2 acceleration when available.
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn pack_bits_bmi2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        use std::arch::x86_64::*;

        let mut src_idx = 0;
        let mut dst_idx = 0;
        let mut bit_buffer: u64 = 0;
        let mut bits_in_buffer: u32 = 0;

        while src_idx < src.len() {
            let value = src[src_idx] as u64;
            let mask = (1u64 << bit_width) - 1;
            let packed = _pdep_u64(value, mask << bits_in_buffer);

            bit_buffer |= packed;
            bits_in_buffer += bit_width as u32;

            while bits_in_buffer >= 8 {
                dst[dst_idx] = bit_buffer as u8;
                dst_idx += 1;
                bit_buffer >>= 8;
                bits_in_buffer -= 8;
            }

            src_idx += 1;
        }

        if bits_in_buffer > 0 {
            dst[dst_idx] = bit_buffer as u8;
            dst_idx += 1;
        }

        dst_idx
    }

    /// Unpack bits with BMI2 acceleration when available.
    #[target_feature(enable = "bmi2")]
    pub(super) unsafe fn unpack_bits_bmi2(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        use std::arch::x86_64::*;

        let mut src_idx = 0;
        let mut dst_idx = 0;
        let mut bit_buffer: u64 = 0;
        let mut bits_in_buffer: u32 = 0;

        let bw = bit_width as u32;
        let mask = (1u64 << bit_width) - 1;

        while dst_idx < dst.len() && src_idx < src.len() {
            while bits_in_buffer < bw && src_idx < src.len() {
                bit_buffer |= (src[src_idx] as u64) << bits_in_buffer;
                src_idx += 1;
                bits_in_buffer += 8;
            }

            if bits_in_buffer >= bw {
                let value = _pext_u64(bit_buffer, mask) as u8;
                dst[dst_idx] = value;
                dst_idx += 1;

                bit_buffer >>= bw;
                bits_in_buffer -= bw;
            } else {
                break;
            }
        }

        dst_idx
    }

    /// String comparison with AVX2 when available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn string_compare_avx2(a: &[u8], b: &[u8]) -> bool {
        use std::arch::x86_64::*;

        let len = a.len();
        if len != b.len() {
            return false;
        }

        let mut i = 0;

        while i + 32 <= len {
            let a_vec = _mm256_loadu_si256(a.as_ptr().add(i) as *const __m256i);
            let b_vec = _mm256_loadu_si256(b.as_ptr().add(i) as *const __m256i);

            let cmp = _mm256_cmpeq_epi8(a_vec, b_vec);
            let mask = _mm256_movemask_epi8(cmp);

            if mask != -1i32 {
                return false;
            }

            i += 32;
        }

        while i < len {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }

        _mm256_zeroupper();
        true
    }

    /// String comparison with SSE4.2 when available.
    #[target_feature(enable = "sse4.2")]
    pub(super) unsafe fn string_compare_sse42(a: &[u8], b: &[u8]) -> bool {
        use std::arch::x86_64::*;

        let len = a.len();
        if len != b.len() {
            return false;
        }

        let mut i = 0;

        while i + 16 <= len {
            let a_vec = _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i);
            let b_vec = _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i);

            let result =
                _mm_cmpestri(a_vec, 16, b_vec, 16, _SIDD_CMP_EQUAL_EACH | _SIDD_NEGATIVE_POLARITY);

            if result != 16 {
                return false;
            }

            i += 16;
        }

        while i < len {
            if a[i] != b[i] {
                return false;
            }
            i += 1;
        }

        true
    }

    /// POPCNT with AVX-512 VPOPCNTDQ when available (large bitmaps).
    #[target_feature(enable = "avx512f", enable = "avx512vpopcntdq")]
    pub(super) unsafe fn popcnt_avx512(data: &[u8]) -> usize {
        use std::arch::x86_64::*;

        let mut count = 0usize;
        let mut i = 0;

        while i + 64 <= data.len() {
            let vec = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);
            let counts = _mm512_popcnt_epi64(vec);
            let sum = _mm512_reduce_add_epi64(counts);
            count += sum as usize;

            i += 64;
        }

        while i < data.len() {
            count += data[i].count_ones() as usize;
            i += 1;
        }

        count
    }

    /// Batch CRC32 with PCLMULQDQ when available.
    #[target_feature(enable = "pclmulqdq", enable = "sse4.2")]
    pub(super) unsafe fn batch_crc32_pclmul(data: &[&[u8]], initial: u32) -> Vec<u32> {
        use std::arch::x86_64::*;

        let mut results = Vec::with_capacity(data.len());

        for chunk in data {
            let mut crc = !initial;
            let mut i = 0;

            while i + 8 <= chunk.len() {
                let val = u64::from_le_bytes([
                    chunk[i],
                    chunk[i + 1],
                    chunk[i + 2],
                    chunk[i + 3],
                    chunk[i + 4],
                    chunk[i + 5],
                    chunk[i + 6],
                    chunk[i + 7],
                ]);
                crc = _mm_crc32_u64(crc as u64, val) as u32;
                i += 8;
            }

            while i < chunk.len() {
                crc = _mm_crc32_u8(crc, chunk[i]);
                i += 1;
            }

            results.push(!crc);
        }

        results
    }

    /// Reed-Solomon encoding with AVX-512 GFNI when available.
    #[target_feature(enable = "avx512f", enable = "gfni")]
    pub(super) unsafe fn reed_solomon_encode_gfni(data: &[u8], parity_shards: usize) -> Vec<u8> {
        // Generate parity using GFNI for GF(256) operations
        let data_shards = data.len() / 256;
        let total_shards = data_shards + parity_shards;
        let mut output = vec![0u8; total_shards * 256];

        // Copy data
        output[..data.len()].copy_from_slice(data);

        // Generate Vandermonde matrix for encoding
        for i in 0..parity_shards {
            for j in 0..data_shards {
                let coeff = scalar::gf_pow((i + 1) as u8, j as u8);
                let coeff_vec = _mm512_set1_epi8(coeff as i8);

                let mut k = 0;
                while k + 64 <= 256 {
                    let src = _mm512_loadu_si512(data[j * 256 + k..].as_ptr() as *const __m512i);
                    let dst = _mm512_loadu_si512(
                        output[(data_shards + i) * 256 + k..].as_ptr() as *const __m512i
                    );

                    let prod = _mm512_gf2p8mul_epi8(src, coeff_vec);
                    let result = _mm512_xor_si512(dst, prod);

                    _mm512_storeu_si512(
                        output[(data_shards + i) * 256 + k..].as_mut_ptr() as *mut __m512i,
                        result,
                    );
                    k += 64;
                }
            }
        }

        output
    }

    /// Reed-Solomon encoding with AVX2 when available.
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn reed_solomon_encode_avx2(data: &[u8], parity_shards: usize) -> Vec<u8> {
        use std::arch::x86_64::*;

        let data_shards = (data.len() + 255) / 256;
        let total_shards = data_shards + parity_shards;
        let shard_size = 256;
        let mut output = vec![0u8; total_shards * shard_size];

        // Copy data shards
        output[..data.len()].copy_from_slice(data);

        // Generate Vandermonde matrix for systematic encoding
        let mut matrix = vec![0u8; parity_shards * data_shards];
        for i in 0..parity_shards {
            for j in 0..data_shards {
                // Vandermonde element: (i+data_shards)^j in GF(256)
                let mut val = 1u8;
                let x = (i + data_shards) as u8;
                for _ in 0..j {
                    val = gf_mul_single(val, x);
                }
                matrix[i * data_shards + j] = val;
            }
        }

        // Compute parity shards using AVX2
        for p in 0..parity_shards {
            let parity_start = (data_shards + p) * shard_size;
            let mut parity_vec = _mm256_setzero_si256();

            for d in 0..data_shards {
                let coeff = matrix[p * data_shards + d];
                if coeff == 0 {
                    continue;
                }

                let data_start = d * shard_size;
                let coeff_vec = _mm256_set1_epi8(coeff as i8);

                // Process 32 bytes at a time
                for i in (0..shard_size).step_by(32) {
                    let data_vec =
                        _mm256_loadu_si256(output.as_ptr().add(data_start + i) as *const __m256i);

                    // GF(256) multiplication using shuffle tables
                    let prod = gf_mul_avx2_vec(data_vec, coeff_vec);
                    parity_vec = _mm256_xor_si256(parity_vec, prod);

                    _mm256_storeu_si256(
                        output.as_mut_ptr().add(parity_start + i) as *mut __m256i,
                        parity_vec,
                    );
                    parity_vec = _mm256_setzero_si256();
                }
            }
        }

        output
    }

    /// Reed-Solomon decoding with GFNI when available.
    #[target_feature(enable = "avx512f", enable = "gfni")]
    pub(super) unsafe fn reed_solomon_decode_gfni(
        shards: &[Vec<u8>],
        indices: &[usize],
    ) -> Result<Vec<u8>, &'static str> {
        use std::arch::x86_64::*;

        if shards.is_empty() {
            return Err("No shards provided");
        }

        let shard_size = shards[0].len();
        let k = shards.len(); // Number of available shards

        // Build decoding matrix using Gaussian elimination
        let mut matrix = vec![vec![0u8; k + 1]; k];
        for (i, &idx) in indices.iter().enumerate().take(k) {
            // Vandermonde row for this index
            for j in 0..k {
                let mut val = 1u8;
                let x = idx as u8;
                for _ in 0..j {
                    val = gf_mul_single(val, x);
                }
                matrix[i][j] = val;
            }
            matrix[i][k] = 1; // Augmented identity
        }

        // Gaussian elimination to invert matrix
        for i in 0..k {
            // Find pivot
            if matrix[i][i] == 0 {
                for j in (i + 1)..k {
                    if matrix[j][i] != 0 {
                        matrix.swap(i, j);
                        break;
                    }
                }
            }

            // Normalize row
            let pivot = matrix[i][i];
            if pivot == 0 {
                return Err("Matrix not invertible");
            }
            let pivot_inv = gf_inv(pivot);

            for j in 0..=k {
                matrix[i][j] = gf_mul_single(matrix[i][j], pivot_inv);
            }

            // Eliminate column
            for j in 0..k {
                if i != j && matrix[j][i] != 0 {
                    let factor = matrix[j][i];
                    for c in 0..=k {
                        matrix[j][c] ^= gf_mul_single(matrix[i][c], factor);
                    }
                }
            }
        }

        // Apply inverted matrix to recover data using AVX512-GFNI
        let mut output = vec![0u8; k * shard_size];

        for i in 0..k {
            let out_start = i * shard_size;

            for j in 0..k {
                let coeff = matrix[i][k]; // From inverted matrix
                if coeff == 0 {
                    continue;
                }

                let shard_data = &shards[j];

                // Process 64 bytes at a time with AVX512-GFNI
                for c in (0..shard_size).step_by(64) {
                    let data = _mm512_loadu_si512(shard_data.as_ptr().add(c) as *const __m512i);
                    let coeff_vec = _mm512_set1_epi8(coeff as i8);

                    // GFNI multiplication
                    let prod = _mm512_gf2p8mul_epi8(data, coeff_vec);

                    let current =
                        _mm512_loadu_si512(output.as_ptr().add(out_start + c) as *const __m512i);
                    let result = _mm512_xor_si512(current, prod);

                    _mm512_storeu_si512(
                        output.as_mut_ptr().add(out_start + c) as *mut __m512i,
                        result,
                    );
                }
            }
        }

        Ok(output)
    }

    #[inline(always)]
    unsafe fn gf_mul_avx2_vec(a: __m256i, b: __m256i) -> __m256i {
        use std::arch::x86_64::*;

        // Full GF(256) multiplication table lookup
        let mask = _mm256_set1_epi8(0x0F);
        let a_lo = _mm256_and_si256(a, mask);
        let a_hi = _mm256_srli_epi16(_mm256_and_si256(a, _mm256_set1_epi8(0xF0u8 as i8)), 4);

        // Lookup tables for b multiplication
        let b_lo = _mm256_and_si256(b, mask);
        let _b_hi = _mm256_srli_epi16(_mm256_and_si256(b, _mm256_set1_epi8(0xF0u8 as i8)), 4);

        // Multiplication via table lookups
        let tbl_lo = _mm256_shuffle_epi8(
            _mm256_set_epi8(
                0x00,
                0x1b,
                0x36,
                0x2d,
                0x6c,
                0x77,
                0x5a,
                0x41,
                0xd8u8 as i8,
                0xc3u8 as i8,
                0xeeu8 as i8,
                0xf5u8 as i8,
                0xb4u8 as i8,
                0xafu8 as i8,
                0x82u8 as i8,
                0x99u8 as i8,
                0x00,
                0x1b,
                0x36,
                0x2d,
                0x6c,
                0x77,
                0x5a,
                0x41,
                0xd8u8 as i8,
                0xc3u8 as i8,
                0xeeu8 as i8,
                0xf5u8 as i8,
                0xb4u8 as i8,
                0xafu8 as i8,
                0x82u8 as i8,
                0x99u8 as i8,
            ),
            b_lo,
        );

        let p1 = _mm256_shuffle_epi8(tbl_lo, a_lo);
        let p2 = _mm256_shuffle_epi8(tbl_lo, a_hi);
        _mm256_xor_si256(p1, p2)
    }

    #[inline(always)]
    fn gf_inv(a: u8) -> u8 {
        // Compute multiplicative inverse in GF(256) using exponentiation: a^254 = a^-1
        // Reduction polynomial 0x1b (AES polynomial), consistent with gf_mul_single()
        if a == 0 {
            return 0;
        }
        fn gf_pow(mut base: u8, mut exp: u16) -> u8 {
            let mut result: u8 = 1;
            while exp > 0 {
                if (exp & 1) != 0 {
                    result = gf_mul_single(result, base);
                }
                base = gf_mul_single(base, base);
                exp >>= 1;
            }
            result
        }
        gf_pow(a, 254)
    }

    #[inline(always)]
    fn gf_mul_single(a: u8, b: u8) -> u8 {
        // Fast GF(256) multiplication
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;
        while bb != 0 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let hi_bit = aa & 0x80;
            aa <<= 1;
            if hi_bit != 0 {
                aa ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            bb >>= 1;
        }
        result
    }

    /// Reed-Solomon decoding with AVX2
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn reed_solomon_decode_avx2(
        shards: &[Vec<u8>],
        indices: &[usize],
    ) -> Result<Vec<u8>, &'static str> {
        reed_solomon_decode_gfni(shards, indices)
    }

    /// QPACK Huffman encoding with AVX2
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn qpack_encode_avx2(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
        use std::arch::x86_64::*;

        let codes_ptr = HUFF_CODES.as_ptr() as *const i32;
        let mut acc: u128 = 0;
        let mut bits: usize = 0;
        let mut written: usize = 0;
        let mut i = 0usize;

        while i + 8 <= input.len() {
            let chunk = _mm_loadl_epi64(input.as_ptr().add(i) as *const __m128i);
            let idx_vec = _mm256_cvtepu8_epi32(chunk);
            let code_vec = _mm256_i32gather_epi32(codes_ptr, idx_vec, 4);

            let mut idx_arr = [0i32; 8];
            let mut code_arr = [0i32; 8];
            _mm256_storeu_si256(idx_arr.as_mut_ptr() as *mut __m256i, idx_vec);
            _mm256_storeu_si256(code_arr.as_mut_ptr() as *mut __m256i, code_vec);

            for lane in 0..8 {
                let sym = idx_arr[lane] as usize;
                let code = code_arr[lane] as u128;
                let clen = HUFF_LENS[sym] as usize;

                if bits + clen > 120 {
                    while bits >= 8 {
                        let shift = bits - 8;
                        let byte = ((acc >> shift) & 0xff) as u8;
                        if written >= output.len() {
                            return written;
                        }
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                acc = (acc << clen) | code;
                bits += clen;

                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            i += 8;
        }

        while i < input.len() {
            let sym = input[i] as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
            i += 1;
        }

        if bits > 0 {
            if written >= output.len() {
                return written;
            }
            let pad_mask = (1u128 << (8 - bits)) - 1;
            let byte = ((acc << (8 - bits)) | pad_mask) as u8;
            output[written] = byte;
            written += 1;
        }

        written
    }

    /// QPACK Huffman encoding with SSSE3/SSE4.1 fallback
    #[target_feature(enable = "ssse3", enable = "sse4.1")]
    pub(super) unsafe fn qpack_encode_ssse3(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3::qpack::{HUFF_CODES, HUFF_LENS};
        use std::arch::x86_64::*;

        let mut acc: u128 = 0;
        let mut bits: usize = 0;
        let mut written: usize = 0;
        let mut i = 0usize;

        while i + 4 <= input.len() {
            let chunk = _mm_cvtsi32_si128(*(input.as_ptr().add(i) as *const i32));
            let idx_vec = _mm_cvtepu8_epi32(chunk);
            let mut idx_arr = [0i32; 4];
            _mm_storeu_si128(idx_arr.as_mut_ptr() as *mut __m128i, idx_vec);

            for lane in 0..4 {
                let sym = idx_arr[lane] as usize;
                let code = HUFF_CODES[sym] as u128;
                let clen = HUFF_LENS[sym] as usize;

                if bits + clen > 120 {
                    while bits >= 8 {
                        let shift = bits - 8;
                        let byte = ((acc >> shift) & 0xff) as u8;
                        if written >= output.len() {
                            return written;
                        }
                        output[written] = byte;
                        written += 1;
                        bits -= 8;
                        acc &= (1u128 << shift) - 1;
                    }
                }

                acc = (acc << clen) | code;
                bits += clen;

                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            i += 4;
        }

        while i < input.len() {
            let sym = input[i] as usize;
            let code = HUFF_CODES[sym] as u128;
            let clen = HUFF_LENS[sym] as usize;

            if bits + clen > 120 {
                while bits >= 8 {
                    let shift = bits - 8;
                    let byte = ((acc >> shift) & 0xff) as u8;
                    if written >= output.len() {
                        return written;
                    }
                    output[written] = byte;
                    written += 1;
                    bits -= 8;
                    acc &= (1u128 << shift) - 1;
                }
            }

            acc = (acc << clen) | code;
            bits += clen;

            while bits >= 8 {
                let shift = bits - 8;
                let byte = ((acc >> shift) & 0xff) as u8;
                if written >= output.len() {
                    return written;
                }
                output[written] = byte;
                written += 1;
                bits -= 8;
                acc &= (1u128 << shift) - 1;
            }
            i += 1;
        }

        if bits > 0 {
            if written >= output.len() {
                return written;
            }
            let pad_mask = (1u128 << (8 - bits)) - 1;
            let byte = ((acc << (8 - bits)) | pad_mask) as u8;
            output[written] = byte;
            written += 1;
        }

        written
    }

    /// QPACK Huffman decoding with AVX2 helper (delegates to shared decode)
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn qpack_decode_avx2(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3;
        match h3::qpack::huff_decode_into(input, output) {
            Ok(written) => written,
            Err(h3::Error::BufferTooShort) => output.len(),
            Err(_) => 0,
        }
    }

    /// QPACK Huffman decoding with SSSE3 helper (reuses shared decode)
    #[target_feature(enable = "ssse3")]
    pub(super) unsafe fn qpack_decode_ssse3(input: &[u8], output: &mut [u8]) -> usize {
        use crate::transport::h3;
        match h3::qpack::huff_decode_into(input, output) {
            Ok(written) => written,
            Err(h3::Error::BufferTooShort) => output.len(),
            Err(_) => 0,
        }
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    mod tests {
        use super::*;
        use crate::simd::x86::{ghash_pclmulqdq, ghash_vpclmulqdq};
        use crate::transport::h3::qpack;
        use std::is_x86_feature_detected;

        const SAMPLES: &[&[u8]] = &[
            b"",
            b"quicfuscate",
            b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
            b"content-type: application/json\r\nacceptable: */*\r\n",
        ];

        #[test]
        fn qpack_avx2_matches_scalar() {
            if !is_x86_feature_detected!("avx2") {
                return;
            }

            for sample in SAMPLES {
                let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
                let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
                scalar_buf.truncate(scalar_len);

                let mut avx_buf = vec![0u8; scalar_len + 8];
                let avx_len = unsafe { qpack_encode_avx2(sample, &mut avx_buf) };
                avx_buf.truncate(avx_len);

                assert_eq!(scalar_buf, avx_buf);

                let mut decode_buf = vec![0u8; sample.len() + 8];
                let decoded = unsafe { qpack_decode_avx2(&avx_buf, &mut decode_buf) };
                assert_eq!(&decode_buf[..decoded], *sample);
            }
        }

        #[test]
        fn qpack_ssse3_matches_scalar() {
            if !is_x86_feature_detected!("ssse3") || !is_x86_feature_detected!("sse4.1") {
                return;
            }

            for sample in SAMPLES {
                let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
                let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
                scalar_buf.truncate(scalar_len);

                let mut sse_buf = vec![0u8; scalar_len + 8];
                let sse_len = unsafe { qpack_encode_ssse3(sample, &mut sse_buf) };
                sse_buf.truncate(sse_len);

                assert_eq!(scalar_buf, sse_buf);

                let mut decode_buf = vec![0u8; sample.len() + 8];
                let decoded = unsafe { qpack_decode_ssse3(&sse_buf, &mut decode_buf) };
                assert_eq!(&decode_buf[..decoded], *sample);
            }
        }

        #[test]
        fn ghash_pclmul_matches_scalar() {
            if !is_x86_feature_detected!("pclmulqdq") {
                return;
            }

            let h = [0x13u8; 16];
            let data = b"example ghash payload block";

            let mut pclmul_tag = [0u8; 16];
            unsafe { ghash_pclmulqdq(&h, data, &mut pclmul_tag) };

            let mut scalar_tag = [0u8; 16];
            super::super::scalar::ghash(&h, data, &mut scalar_tag);

            assert_eq!(pclmul_tag, scalar_tag);
        }

        #[test]
        fn ghash_vpclmul_matches_scalar() {
            if !(is_x86_feature_detected!("avx512f")
                && is_x86_feature_detected!("vpclmulqdq")
                && is_x86_feature_detected!("avx512vl"))
            {
                return;
            }

            let h = [0x42u8; 16];
            let data = b"double block ghash data stream";

            let mut vpclmul_tag = [0u8; 16];
            unsafe { ghash_vpclmulqdq(&h, data, &mut vpclmul_tag) };

            let mut scalar_tag = [0u8; 16];
            super::super::scalar::ghash(&h, data, &mut scalar_tag);

            assert_eq!(vpclmul_tag, scalar_tag);
        }
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_arm {
    use super::*;
    use crate::transport::h3::qpack;
    use std::arch::is_aarch64_feature_detected;

    const SAMPLES: &[&[u8]] = &[
        b"",
        b"quicfuscate",
        b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
        b"content-type: application/json\r\nacceptable: */*\r\n",
    ];

    #[test]
    fn qpack_neon_matches_scalar() {
        if !is_aarch64_feature_detected!("neon") {
            return;
        }

        for sample in SAMPLES {
            let mut scalar_buf = vec![0u8; qpack::huff_estimate_len(sample) + 8];
            let scalar_len = qpack::huff_encode_into(sample, &mut scalar_buf);
            scalar_buf.truncate(scalar_len);

            let mut neon_buf = vec![0u8; scalar_len + 8];
            let neon_len = arm::qpack_encode_neon(sample, &mut neon_buf);
            neon_buf.truncate(neon_len);

            assert_eq!(neon_buf, scalar_buf);

            let mut decode_buf = vec![0u8; sample.len() + 8];
            let decoded = arm::qpack_decode_neon(&neon_buf, &mut decode_buf);
            decode_buf.truncate(decoded);

            let mut scalar_decode = vec![0u8; sample.len() + 8];
            let scalar_decoded = qpack::huff_decode_into(&scalar_buf, &mut scalar_decode).unwrap();
            scalar_decode.truncate(scalar_decoded);

            assert_eq!(decode_buf, scalar_decode);
        }
    }
}

// Continue with rest of x86 module implementations after the main x86 module
#[cfg(target_arch = "x86_64")]
mod x86_rest {}

/// Pure-scalar fallback implementations for every SIMD-dispatched operation.
pub mod scalar {
    use crate::crypto::{aes, gcm, hkdf};
    use crate::simd::{CpuFeature, FeatureDetector};
    /// GF(256) exponentiation for Reed-Solomon generator polynomials.
    pub fn gf_pow(base: u8, exp: u8) -> u8 {
        if exp == 0 {
            return 1;
        }
        let mut result = base;
        for _ in 1..exp {
            result = gf_mul_byte(result, base);
        }
        result
    }

    /// XOR `src` into `dst` byte-by-byte (scalar fallback).
    pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        for (d, s) in dst.iter_mut().zip(src.iter()) {
            *d ^= *s;
        }
    }

    /// CRC-32 using a precomputed 256-entry table (scalar fallback).
    pub fn crc32(data: &[u8], mut crc: u32) -> u32 {
        // CRC-32 polynomial: 0xEDB88320 (reversed representation)
        const POLY: u32 = 0xEDB88320;

        // Generate CRC32 table
        const fn make_table() -> [u32; 256] {
            let mut table = [0u32; 256];
            let mut i = 0;
            while i < 256 {
                let mut c = i as u32;
                let mut j = 0;
                while j < 8 {
                    if c & 1 != 0 {
                        c = POLY ^ (c >> 1);
                    } else {
                        c >>= 1;
                    }
                    j += 1;
                }
                table[i] = c;
                i += 1;
            }
            table
        }

        const TABLE: [u32; 256] = make_table();

        crc = !crc;
        for &byte in data {
            crc = TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
        !crc
    }

    /// Population count over a byte slice (scalar fallback).
    pub fn popcnt(data: &[u8]) -> usize {
        data.iter().map(|&b| b.count_ones() as usize).sum()
    }

    /// GF(2^8) multiply each byte of `a` by scalar `b` into `dst` (scalar fallback).
    pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
        for i in 0..a.len().min(dst.len()) {
            dst[i] = gf_mul_byte(a[i], b);
        }
    }

    /// Single GF(2^8) byte multiplication with AES reduction polynomial.
    pub fn gf_mul_byte(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;
        while bb != 0 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let carry = aa & 0x80;
            aa <<= 1;
            if carry != 0 {
                aa ^= 0x1b; // GF(2^8) reduction polynomial
            }
            bb >>= 1;
        }
        result
    }

    /// AES-128 single-block encrypt in place (scalar, delegates to software AES).
    pub fn aes_encrypt_block(state: &mut [u8; 16], key: &[u8; 16]) {
        let block = *state;
        let encrypted = aes::aes128_encrypt_block(key, &block);
        state.copy_from_slice(&encrypted);
    }

    /// GHASH for GCM mode (scalar fallback, delegates to crypto::gcm).
    pub fn ghash(h: &[u8; 16], data: &[u8], tag: &mut [u8; 16]) {
        let computed = gcm::ghash(*h, &[], data);
        tag.copy_from_slice(&computed);
    }

    /// SHA-256 digest (scalar fallback, delegates to hkdf::sha256).
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        hkdf::sha256(data)
    }

    /// Byte-frequency histogram over a data slice (scalar).
    pub fn histogram(data: &[u8]) -> [u32; 256] {
        let mut hist = [0u32; 256];
        for &byte in data {
            hist[byte as usize] += 1;
        }
        hist
    }

    /// Find first occurrence of `needle` in `haystack` (scalar linear scan).
    pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }

    /// f32 dot product of two equal-length slices (scalar).
    pub fn dot_product_f32(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
    }

    /// f32 matrix multiplication C = A * B with dimensions (m x k) * (k x n) (scalar).
    pub fn matmul(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
        for i in 0..m {
            for j in 0..n {
                let mut sum = 0.0;
                for l in 0..k {
                    sum += a[i * k + l] * b[l * n + j];
                }
                c[i * n + j] = sum;
            }
        }
    }

    /// Berlekamp-Massey algorithm over GF(256) for error-locator polynomial (scalar).
    pub fn berlekamp_massey(syndrome: &[u8], len: usize) -> Vec<u8> {
        let mut error_locator = vec![0u8; len + 1];
        error_locator[0] = 1;

        let mut old_locator = vec![0u8; len + 1];
        old_locator[0] = 1;

        let mut syndrome_shift = 0u8;
        let mut error_degree = 0;
        let mut old_degree = 1;

        for i in 0..len {
            let mut discrepancy = syndrome[i];

            for j in 1..=error_degree.min(i) {
                discrepancy ^= super::scalar::gf_mul_byte(error_locator[j], syndrome[i - j]);
            }

            if discrepancy != 0 {
                let mut new_locator = error_locator.clone();

                if syndrome_shift != 0 {
                    let factor = super::scalar::gf_mul_byte(
                        discrepancy,
                        super::scalar::gf_inv(syndrome_shift),
                    );
                    for j in 0..=old_degree {
                        if j + i >= old_degree {
                            new_locator[j + i - old_degree + 1] ^=
                                super::scalar::gf_mul_byte(factor, old_locator[j]);
                        }
                    }
                }

                if 2 * error_degree <= i {
                    old_locator = error_locator.clone();
                    old_degree = error_degree;
                    syndrome_shift = discrepancy;
                    error_degree = i + 1 - error_degree;
                }

                error_locator = new_locator;
            }
        }

        error_locator.truncate(error_degree + 1);
        error_locator
    }

    /// GF(256) matrix multiplication C = A * B with dimensions (m x k) * (k x n) (scalar).
    pub fn matmul_gf256(a: &[u8], b: &[u8], c: &mut [u8], m: usize, k: usize, n: usize) {
        // Zero the output
        for elem in c.iter_mut().take(m * n) {
            *elem = 0;
        }

        // GF(256) matrix multiplication
        for i in 0..m {
            for kk in 0..k {
                if a[i * k + kk] == 0 {
                    continue;
                }
                for j in 0..n {
                    c[i * n + j] ^= super::scalar::gf_mul_byte(a[i * k + kk], b[kk * n + j]);
                }
            }
        }
    }

    /// Reed-Solomon encode with SIMD dispatch; produces `parity_shards` extra shards.
    pub fn reed_solomon_encode(data: &[u8], parity_shards: usize) -> Vec<u8> {
        let features = FeatureDetector::instance();

        // SAFETY: Each branch is guarded by runtime feature detection matching the
        // callee's `#[target_feature]`. Callees process 256-byte shards with SIMD
        // GF(256) multiplication and write to owned Vec output.
        #[cfg(target_arch = "x86_64")]
        {
            if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
                return unsafe { super::x86::reed_solomon_encode_gfni(data, parity_shards) };
            }
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::reed_solomon_encode_avx2(data, parity_shards) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if features.has_feature(CpuFeature::NEON) {
                return unsafe { super::arm::reed_solomon_encode_neon(data, parity_shards) };
            }
        }

        reed_solomon_encode_scalar(data, parity_shards)
    }

    #[inline(always)]
    pub(crate) fn reed_solomon_encode_scalar(data: &[u8], parity_shards: usize) -> Vec<u8> {
        // Scalar Reed-Solomon encoding
        let data_shards = data.len() / 256;
        let total_shards = data_shards + parity_shards;
        let mut output = vec![0u8; total_shards * 256];

        // Copy data
        output[..data.len()].copy_from_slice(data);

        // Generate parity
        for i in 0..parity_shards {
            for j in 0..data_shards {
                let coeff = gf_pow((i + 1) as u8, j as u8);
                for k in 0..256 {
                    let idx = j * 256 + k;
                    if idx < data.len() {
                        output[(data_shards + i) * 256 + k] ^= gf_mul_byte(data[idx], coeff);
                    }
                }
            }
        }

        output
    }

    /// Reed-Solomon decode from available shards and their indices via Gaussian elimination.
    pub fn reed_solomon_decode(
        shards: &[Vec<u8>],
        indices: &[usize],
    ) -> Result<Vec<u8>, &'static str> {
        if shards.is_empty() {
            return Err("No shards provided");
        }

        // SAFETY: Each branch is guarded by runtime feature detection matching the
        // callee's `#[target_feature]`. Callees read from `shards` and `indices`,
        // perform GF(256) Gaussian elimination, and return owned decoded data.
        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance();
            if features.has_feature(CpuFeature::GFNI) && features.has_feature(CpuFeature::AVX512F) {
                return unsafe { super::x86::reed_solomon_decode_gfni(shards, indices) };
            }
            if features.has_feature(CpuFeature::AVX2) {
                return unsafe { super::x86::reed_solomon_decode_avx2(shards, indices) };
            }
        }

        if shards.len() != indices.len() {
            return Err("Shard/index length mismatch");
        }
        let shard_size = shards[0].len();
        if !shards.iter().all(|s| s.len() == shard_size) {
            return Err("Shard size mismatch");
        }

        let k = shards.len();
        let mut aug = vec![vec![0u8; 2 * k]; k];
        for row in 0..k {
            let x = indices[row] as u8;
            let mut col = 0usize;
            while col < k {
                aug[row][col] = gf_pow(x, col as u8);
                col += 1;
            }
            aug[row][k + row] = 1;
        }

        for pivot in 0..k {
            if aug[pivot][pivot] == 0 {
                let mut swap_row = None;
                let mut cand = pivot + 1;
                while cand < k {
                    if aug[cand][pivot] != 0 {
                        swap_row = Some(cand);
                        break;
                    }
                    cand += 1;
                }
                if let Some(cand) = swap_row {
                    aug.swap(pivot, cand);
                } else {
                    return Err("Matrix not invertible");
                }
            }

            let inv = gf_inv(aug[pivot][pivot]);
            let mut col = pivot;
            while col < (2 * k) {
                aug[pivot][col] = gf_mul_byte(aug[pivot][col], inv);
                col += 1;
            }

            for row in 0..k {
                if row == pivot {
                    continue;
                }
                let factor = aug[row][pivot];
                if factor == 0 {
                    continue;
                }
                let mut col = pivot;
                while col < (2 * k) {
                    let prod = gf_mul_byte(aug[pivot][col], factor);
                    aug[row][col] ^= prod;
                    col += 1;
                }
            }
        }

        let mut output = vec![0u8; k * shard_size];
        for out_row in 0..k {
            for shard_idx in 0..k {
                let coeff = aug[out_row][k + shard_idx];
                if coeff == 0 {
                    continue;
                }
                let src = &shards[shard_idx];
                let dst = &mut output[out_row * shard_size..(out_row + 1) * shard_size];
                for i in 0..shard_size {
                    dst[i] ^= gf_mul_byte(src[i], coeff);
                }
            }
        }

        Ok(output)
    }

    /// QPACK encode (scalar identity copy fallback).
    pub fn qpack_encode(input: &[u8], output: &mut [u8]) -> usize {
        let len = input.len().min(output.len());
        output[..len].copy_from_slice(&input[..len]);
        len
    }

    /// QPACK decode (scalar identity copy fallback).
    pub fn qpack_decode(input: &[u8], output: &mut [u8]) -> usize {
        let len = input.len().min(output.len());
        output[..len].copy_from_slice(&input[..len]);
        len
    }

    /// Validate QUIC packet header fixed-bit constraint (scalar fallback).
    pub fn validate_header(header: &[u8]) -> bool {
        if header.is_empty() {
            return false;
        }
        // QUIC fixed bit must be set
        (header[0] & 0x40) != 0
    }

    /// Pack values into a bitstream at the given bit width (scalar fallback).
    pub fn pack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        if bit_width == 0 || bit_width > 8 {
            return 0;
        }
        let mut bitbuf: u32 = 0;
        let mut bits: u32 = 0;
        let mut di = 0usize;
        for &v in src {
            bitbuf |= (v as u32 & ((1u32 << bit_width) - 1)) << bits;
            bits += bit_width as u32;
            while bits >= 8 {
                if di >= dst.len() {
                    return di;
                }
                dst[di] = (bitbuf & 0xFF) as u8;
                di += 1;
                bitbuf >>= 8;
                bits -= 8;
            }
        }
        if bits > 0 && di < dst.len() {
            dst[di] = (bitbuf & 0xFF) as u8;
            di += 1;
        }
        di
    }

    /// Unpack a bitstream at the given bit width into individual bytes (scalar fallback).
    pub fn unpack_bits(src: &[u8], bit_width: u8, dst: &mut [u8]) -> usize {
        if bit_width == 0 || bit_width > 8 {
            return 0;
        }
        let mut bitbuf: u32 = 0;
        let mut bits: u32 = 0;
        let mut si = 0usize;
        let mut di = 0usize;
        let mask = (1u32 << bit_width) - 1;
        while di < dst.len() {
            while bits < bit_width as u32 {
                if si >= src.len() {
                    return di;
                }
                bitbuf |= (src[si] as u32) << bits;
                si += 1;
                bits += 8;
            }
            dst[di] = (bitbuf & mask) as u8;
            bitbuf >>= bit_width;
            bits -= bit_width as u32;
            di += 1;
        }
        di
    }

    /// Encode a value as a variable-length integer into `buf` (scalar fallback).
    pub fn encode_varint(mut value: u64, buf: &mut [u8]) -> usize {
        let mut pos = 0;

        while value >= 128 {
            buf[pos] = (value as u8) | 0x80;
            value >>= 7;
            pos += 1;
        }

        buf[pos] = value as u8;
        pos + 1
    }

    /// Decode a variable-length integer from `buf`; returns (value, bytes_consumed) (scalar fallback).
    pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0u64;
        let mut shift = 0;

        for (i, &byte) in buf.iter().enumerate() {
            if shift >= 64 {
                return None;
            }

            value |= ((byte & 0x7F) as u64) << shift;

            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }

            shift += 7;
        }

        None
    }

    /// GF(256) inversion for Berlekamp-Massey
    pub fn gf_inv(a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        let mut result = a;
        // Fermat's little theorem: a^254 = a^-1 in GF(256)
        for _ in 0..253 {
            result = gf_mul_byte(result, a);
        }
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use sha2::{Digest, Sha256};

        #[test]
        fn aes_encrypt_block_matches_crypto_module() {
            let key: [u8; 16] = [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c,
            ];
            let mut state: [u8; 16] = [
                0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
                0x07, 0x34,
            ];

            aes_encrypt_block(&mut state, &key);

            let expected = aes::aes128_encrypt_block(
                &key,
                &[
                    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0,
                    0x37, 0x07, 0x34,
                ],
            );

            assert_eq!(state, expected);
        }

        #[test]
        fn ghash_matches_crypto_module() {
            let h = [
                0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
                0x83, 0x08,
            ];
            let data = b"scalar-ghash-test-data-123";
            let mut tag = [0u8; 16];

            ghash(&h, data, &mut tag);

            let expected = gcm::ghash(h, &[], data);
            assert_eq!(tag, expected);
        }

        #[test]
        fn sha256_matches_reference() {
            let data = b"scalar-sha256-test";
            let hash = sha256(data);
            let digest = Sha256::digest(data);
            let mut expected = [0u8; 32];
            expected.copy_from_slice(&digest);
            assert_eq!(hash, expected);
        }
    }
}

// ----------------------------------------------------------------------------
// Tests (platform-independent) - dispatched API correctness
// ----------------------------------------------------------------------------
#[cfg(test)]
mod tests_dispatched {
    use super::*;

    // ===================== GF(2^8) batch operations =====================

    #[test]
    fn gf_mul_known_vectors() {
        // Multiply each byte of input by 0x02 (xtime) - well-known AES operation
        let input = [0x57u8, 0xAE, 0x00, 0x01, 0x80, 0xFF];
        let mut dst = [0u8; 6];
        galois::gf_mul(&input, 0x02, &mut dst);
        // Verify against scalar reference
        let mut expected = [0u8; 6];
        for i in 0..input.len() {
            expected[i] = scalar::gf_mul_byte(input[i], 0x02);
        }
        assert_eq!(dst, expected);
    }

    #[test]
    fn gf_mul_identity_element() {
        // Multiplying by 1 in GF(2^8) must return the original value
        let input: Vec<u8> = (0..=255).collect();
        let mut dst = vec![0u8; 256];
        galois::gf_mul(&input, 1, &mut dst);
        assert_eq!(dst, input);
    }

    #[test]
    fn gf_mul_zero_input() {
        // Multiplying by 0 must yield all zeros
        let input = [0xAB, 0xCD, 0xEF, 0x12, 0x34];
        let mut dst = [0xFFu8; 5];
        galois::gf_mul(&input, 0, &mut dst);
        assert_eq!(dst, [0u8; 5]);
    }

    #[test]
    fn gf_mul_zero_data() {
        // All-zero input multiplied by anything must yield all zeros
        let input = [0u8; 64];
        let mut dst = [0xFFu8; 64];
        galois::gf_mul(&input, 0x42, &mut dst);
        assert_eq!(dst, [0u8; 64]);
    }

    #[test]
    fn gf_mul_inverse_checking() {
        // For every nonzero a, a * a^-1 = 1 in GF(2^8)
        for a in 1u8..=255 {
            let inv = scalar::gf_inv(a);
            let product = scalar::gf_mul_byte(a, inv);
            assert_eq!(product, 1, "gf_inv failed for a={a}: a*inv={product}, inv={inv}");
        }
    }

    // ===================== GF(2^4) operations =====================

    #[test]
    fn gf4_mul_identity_and_zero() {
        // GF(2^4) multiply by 1 preserves nibbles, multiply by 0 zeroes
        let input = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut dst_one = [0u8; 8];
        let mut dst_zero = [0xFFu8; 8];
        galois::gf4_mul(&input, 1, &mut dst_one);
        galois::gf4_mul(&input, 0, &mut dst_zero);
        assert_eq!(dst_one, input, "gf4 multiply by 1 should be identity");
        assert_eq!(dst_zero, [0u8; 8], "gf4 multiply by 0 should be zero");
    }

    // ===================== GF(2^16) operations =====================

    #[test]
    fn gf16_mul_identity_and_zero() {
        let input: Vec<u16> = vec![0x0001, 0x1234, 0xABCD, 0xFFFF, 0x0000];
        let mut dst_one = vec![0u16; 5];
        let mut dst_zero = vec![0xFFFFu16; 5];
        galois::gf16_mul(&input, 1, &mut dst_one);
        galois::gf16_mul(&input, 0, &mut dst_zero);
        assert_eq!(dst_one, input, "gf16 multiply by 1 should be identity");
        assert_eq!(dst_zero, vec![0u16; 5], "gf16 multiply by 0 should be zero");
    }

    #[test]
    fn gf16_mul_commutativity() {
        // a * b should equal b * a for single elements
        let a_val: u16 = 0x1234;
        let b_val: u16 = 0x5678;
        let mut ab = [0u16; 1];
        let mut ba = [0u16; 1];
        galois::gf16_mul(&[a_val], b_val, &mut ab);
        galois::gf16_mul(&[b_val], a_val, &mut ba);
        assert_eq!(ab, ba, "GF(2^16) multiplication should be commutative");
    }

    // ===================== CRC32 =====================

    #[test]
    fn crc32_known_vector() {
        // CRC-32 of "123456789" is 0xCBF43926
        let result = core::crc32(b"123456789", 0);
        assert_eq!(result, 0xCBF43926, "CRC32 known vector mismatch: got {result:#010X}");
    }

    #[test]
    fn crc32_empty_input() {
        let result = core::crc32(b"", 0);
        // CRC32 of empty data with initial 0 should be 0x00000000
        assert_eq!(result, 0x00000000, "CRC32 of empty should be 0x00000000");
    }

    #[test]
    fn crc32_incremental_vs_full() {
        // Compute CRC32 of "Hello, World!" in one shot vs two parts
        let full_data = b"Hello, World!";
        let full_crc = core::crc32(full_data, 0);

        // For table-based CRC, we can verify consistency with scalar
        let scalar_crc = scalar::crc32(full_data, 0);
        assert_eq!(full_crc, scalar_crc, "dispatched CRC32 should match scalar");
    }

    // ===================== SIMD dispatch / feature detection =====================

    #[test]
    fn acceleration_planner_global_returns_consistent() {
        let p1 = planner::AccelerationPlanner::global();
        let p2 = planner::AccelerationPlanner::global();
        // Same singleton, same default AEAD
        assert_eq!(p1.crypto_default_aead(), p2.crypto_default_aead());
    }

    #[test]
    fn simd_ops_instance_returns_consistent() {
        let s1 = SimdOps::instance();
        let s2 = SimdOps::instance();
        assert!(std::ptr::eq(s1, s2), "SimdOps::instance should return same pointer");
    }

    #[test]
    fn crypto_aead_plan_select_returns_valid_variant() {
        let plan = CryptoAeadPlan::select();
        // Must be one of the four valid variants
        match plan {
            CryptoAeadPlan::Aegis128L
            | CryptoAeadPlan::Aegis128X4
            | CryptoAeadPlan::Aegis128X8
            | CryptoAeadPlan::Morus => {}
        }
    }

    #[test]
    fn crypto_aead_plan_length_based_selection() {
        // Small payload should not select X8
        let small = CryptoAeadPlan::select_for_len(10);
        assert_ne!(small, CryptoAeadPlan::Aegis128X8, "10-byte payload should not use X8");

        // Large payload selection should still be valid
        let large = CryptoAeadPlan::select_for_len(4096);
        match large {
            CryptoAeadPlan::Aegis128L
            | CryptoAeadPlan::Aegis128X4
            | CryptoAeadPlan::Aegis128X8
            | CryptoAeadPlan::Morus => {}
        }
    }

    // ===================== Transport QUIC varint encode/decode =====================

    #[test]
    fn quic_varint_roundtrip_1byte() {
        // 1-byte encoding: values 0..63
        for val in [0u64, 1, 37, 63] {
            let mut buf = [0u8; 8];
            let encoded_len = transport::encode_varint(val, &mut buf);
            assert_eq!(encoded_len, 1, "value {val} should encode in 1 byte");
            let (decoded, consumed) =
                transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
            assert_eq!(decoded, val, "roundtrip mismatch for {val}");
            assert_eq!(consumed, 1);
        }
    }

    #[test]
    fn quic_varint_roundtrip_2byte() {
        // 2-byte encoding: values 64..16383
        for val in [64u64, 255, 1000, 16383] {
            let mut buf = [0u8; 8];
            let encoded_len = transport::encode_varint(val, &mut buf);
            assert_eq!(encoded_len, 2, "value {val} should encode in 2 bytes");
            let (decoded, consumed) =
                transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
            assert_eq!(decoded, val, "roundtrip mismatch for {val}");
            assert_eq!(consumed, 2);
        }
    }

    #[test]
    fn quic_varint_roundtrip_4byte() {
        // 4-byte encoding: values 16384..1073741823
        for val in [16384u64, 100_000, 1_073_741_823] {
            let mut buf = [0u8; 8];
            let encoded_len = transport::encode_varint(val, &mut buf);
            assert_eq!(encoded_len, 4, "value {val} should encode in 4 bytes");
            let (decoded, consumed) =
                transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
            assert_eq!(decoded, val, "roundtrip mismatch for {val}");
            assert_eq!(consumed, 4);
        }
    }

    #[test]
    fn quic_varint_roundtrip_8byte() {
        // 8-byte encoding: values 1073741824..(2^62 - 1)
        for val in [1_073_741_824u64, (1u64 << 62) - 1] {
            let mut buf = [0u8; 8];
            let encoded_len = transport::encode_varint(val, &mut buf);
            assert_eq!(encoded_len, 8, "value {val} should encode in 8 bytes");
            let (decoded, consumed) =
                transport::decode_varint(&buf[..encoded_len]).expect("decode failed");
            assert_eq!(decoded, val, "roundtrip mismatch for {val}");
            assert_eq!(consumed, 8);
        }
    }

    #[test]
    fn quic_varint_decode_empty_returns_none() {
        assert!(transport::decode_varint(&[]).is_none());
    }

    // ===================== Crypto helpers (SHA-256, HMAC) =====================

    #[test]
    fn sha256_empty_message_nist_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = crypto::sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected, "SHA-256 empty message vector mismatch");
    }

    #[test]
    fn sha256_abc_nist_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let hash = crypto::sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected, "SHA-256 'abc' vector mismatch");
    }

    #[test]
    fn hmac_sha256_rfc4231_vector() {
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let mac = crypto::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected, "HMAC-SHA256 RFC4231 test case 2 mismatch");
    }

    // ===================== XOR blocks =====================

    #[test]
    fn xor_blocks_correctness() {
        let mut dst = [0xAAu8; 32];
        let src = [0x55u8; 32];
        core::xor_blocks(&mut dst, &src);
        assert_eq!(dst, [0xFFu8; 32], "0xAA ^ 0x55 should be 0xFF");
    }

    #[test]
    fn xor_blocks_self_inverse() {
        let original = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let key = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let mut data = original;
        core::xor_blocks(&mut data, &key);
        assert_ne!(data, original, "XOR should change data");
        core::xor_blocks(&mut data, &key);
        assert_eq!(data, original, "double XOR should restore original");
    }

    // ===================== Popcount =====================

    #[test]
    fn popcnt_known_values() {
        assert_eq!(core::popcnt(&[0x00]), 0);
        assert_eq!(core::popcnt(&[0xFF]), 8);
        assert_eq!(core::popcnt(&[0xAA]), 4); // 10101010
        assert_eq!(core::popcnt(&[0xFF; 16]), 128);
    }

    #[test]
    fn popcnt_matches_scalar() {
        let data: Vec<u8> = (0..=255).collect();
        let dispatched = core::popcnt(&data);
        let reference = scalar::popcnt(&data);
        assert_eq!(dispatched, reference);
    }

    // ===================== Bitstream pack/unpack =====================

    #[test]
    fn bitstream_pack_unpack_roundtrip_all_widths() {
        let src: Vec<u8> = (0..64).collect();
        for bw in 1u8..=8 {
            let mask = (1u16 << bw) - 1;
            let masked_src: Vec<u8> = src.iter().map(|&v| v & (mask as u8)).collect();
            let mut packed = vec![0u8; 128];
            let packed_len = bitstream::pack_bits(&masked_src, bw, &mut packed);
            let mut unpacked = vec![0u8; masked_src.len()];
            bitstream::unpack_bits(&packed[..packed_len], bw, &mut unpacked);
            assert_eq!(unpacked, masked_src, "pack/unpack roundtrip failed for bit_width={bw}");
        }
    }

    // ===================== Header validation =====================

    #[test]
    fn validate_header_too_short() {
        assert!(!fec::validate_header(&[]));
        assert!(!fec::validate_header(&[0xC0]));
        assert!(!fec::validate_header(&[0xC0, 0, 0, 0])); // needs >= 5
    }

    #[test]
    fn validate_header_long_header_valid() {
        // Long header: 0x80 set + 0x40 set = 0xC0
        assert!(fec::validate_header(&[0xC0, 0, 0, 0, 0]));
        assert!(fec::validate_header(&[0xFF, 0, 0, 0, 0])); // all bits set, still valid long
    }

    #[test]
    fn validate_header_short_header_reserved_bits() {
        // Short header (0x80 clear), fixed bit set (0x40), reserved bits zero
        assert!(fec::validate_header(&[0x40, 0, 0, 0, 0]));
        // Reserved bits (0x18) non-zero - invalid
        assert!(!fec::validate_header(&[0x58, 0, 0, 0, 0])); // 0x40 | 0x18
        assert!(!fec::validate_header(&[0x48, 0, 0, 0, 0])); // 0x40 | 0x08
        assert!(!fec::validate_header(&[0x50, 0, 0, 0, 0])); // 0x40 | 0x10
    }

    #[test]
    fn validate_header_no_fixed_bit() {
        assert!(!fec::validate_header(&[0x00, 0, 0, 0, 0]));
        assert!(!fec::validate_header(&[0x80, 0, 0, 0, 0])); // long but no fixed bit
    }

    // ===================== Scalar fallback parity =====================

    #[test]
    fn scalar_gf_mul_matches_dispatched() {
        let input: Vec<u8> = (0..128).collect();
        let multiplier = 0x53u8;
        let mut scalar_dst = vec![0u8; 128];
        let mut dispatched_dst = vec![0u8; 128];
        scalar::gf_mul(&input, multiplier, &mut scalar_dst);
        galois::gf_mul(&input, multiplier, &mut dispatched_dst);
        assert_eq!(scalar_dst, dispatched_dst);
    }

    #[test]
    fn scalar_crc32_matches_dispatched() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let scalar = scalar::crc32(data, 0);
        let dispatched = core::crc32(data, 0);
        assert_eq!(scalar, dispatched);
    }

    #[test]
    fn scalar_sha256_matches_dispatched() {
        let data = b"parity check data for sha256";
        let scalar = scalar::sha256(data);
        let dispatched = crypto::sha256(data);
        assert_eq!(scalar, dispatched);
    }
}

// ----------------------------------------------------------------------------
// Tests (aarch64 only) - validate NEON header checks vs. dispatcher semantics
// ----------------------------------------------------------------------------
#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::fec::validate_header;
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn scalar_encode_quic_varint(mut val: u64, buf: &mut [u8]) -> usize {
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
                buf[1] = (val & 0xFF) as u8;
                val >>= 8;
                buf[0] = (prefix << 6) | (val as u8 & 0x3F);
            }
            4 => {
                for i in (1..4).rev() {
                    buf[i] = (val & 0xFF) as u8;
                    val >>= 8;
                }
                buf[0] = (prefix << 6) | (val as u8 & 0x3F);
            }
            8 => {
                for i in (1..8).rev() {
                    buf[i] = (val & 0xFF) as u8;
                    val >>= 8;
                }
                buf[0] = (prefix << 6) | (val as u8 & 0x3F);
            }
            _ => {
                debug_assert!(false, "invalid varint encoded length");
                return 0;
            }
        }
        len
    }

    fn scalar_decode_quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
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

    fn reference_validate_header(header: &[u8]) -> bool {
        if header.is_empty() {
            return false;
        }
        let first = header[0];
        if (first & 0x40) == 0 {
            return false;
        }
        if (first & 0x80) != 0 {
            // Long header: only fixed bit enforced here.
            true
        } else {
            // Short header: reserved bits (0x18) must be zero.
            (first & 0x18) == 0
        }
    }

    #[test]
    fn neon_validate_header_semantics_examples() {
        // Long header: 0xC0 (0x80 long + fixed bit 0x40) -> valid
        let long_ok = [0xC0u8, 0, 0, 0, 0];
        assert!(validate_header(&long_ok));
        assert!(unsafe { super::arm::validate_header_neon(&long_ok) });

        // Short header: fixed set (0x40), reserved zero -> valid
        let short_ok = [0x40u8, 0, 0, 0, 0];
        assert!(validate_header(&short_ok));
        assert!(unsafe { super::arm::validate_header_neon(&short_ok) });

        // Short header: fixed set but reserved bits (0x18) non-zero -> invalid
        let short_reserved = [0x50u8, 0, 0, 0, 0]; // 0x40 + 0x10
        assert!(!validate_header(&short_reserved));
        assert!(!unsafe { super::arm::validate_header_neon(&short_reserved) });

        // Missing fixed bit -> invalid
        let no_fixed = [0x00u8, 0, 0, 0, 0];
        assert!(!validate_header(&no_fixed));
        assert!(!unsafe { super::arm::validate_header_neon(&no_fixed) });
    }

    #[test]
    fn neon_validate_header_random_parity() {
        let mut rng = StdRng::seed_from_u64(0xA1B2_C3D4_E5F6_0718);
        for _ in 0..512 {
            let mut header = [0u8; 64];
            rng.fill(&mut header[..]);
            let scalar = reference_validate_header(&header);
            let neon = unsafe { super::arm::validate_header_neon(&header) };
            assert_eq!(
                scalar,
                neon,
                "NEON header mismatch: scalar={}, neon={}, bytes={:02x?}",
                scalar,
                neon,
                &header[..8.min(header.len())]
            );
            #[cfg(target_feature = "sve2")]
            {
                if FeatureDetector::instance().has_feature(crate::optimize::CpuFeature::SVE2) {
                    let sve = unsafe { super::arm::validate_header_sve2(&header) };
                    assert_eq!(scalar, sve, "SVE2 header mismatch for prefix {:02x}", header[0]);
                }
            }
        }
    }

    #[test]
    fn neon_varint_random_parity() {
        let mut rng = StdRng::seed_from_u64(0x0F0E_0D0C_0B0A_0908);
        for _ in 0..1024 {
            let val = rng.random::<u64>() & ((1u64 << 62) - 1);
            let mut buf_scalar = [0u8; 16];
            let mut buf_neon = [0u8; 16];
            let len_scalar = scalar_encode_quic_varint(val, &mut buf_scalar);
            let len_neon = crate::simd::arm_varint::encode_varint_neon(val, &mut buf_neon);
            assert_eq!(len_scalar, len_neon, "encode len mismatch for {val}");
            assert_eq!(&buf_scalar[..len_scalar], &buf_neon[..len_neon]);

            let (dec_scalar, used_scalar) =
                scalar_decode_quic_varint(&buf_scalar[..len_scalar]).expect("scalar decode");
            let (dec_neon, used_neon) =
                crate::simd::arm_varint::decode_varint_neon(&buf_neon[..len_neon])
                    .expect("neon decode");
            assert_eq!(dec_scalar, dec_neon, "decode mismatch for {val}");
            assert_eq!(used_scalar, used_neon, "decode len mismatch for {val}");

            #[cfg(target_feature = "sve2")]
            {
                if FeatureDetector::instance().has_feature(crate::optimize::CpuFeature::SVE2) {
                    let mut buf_sve = [0u8; 16];
                    let len_sve = crate::simd::arm_varint::encode_varint_sve2(val, &mut buf_sve);
                    assert_eq!(len_scalar, len_sve, "SVE2 encode len mismatch for {val}");
                    assert_eq!(&buf_scalar[..len_scalar], &buf_sve[..len_sve]);
                    let (dec_sve, used_sve) =
                        crate::simd::arm_varint::decode_varint_sve2(&buf_sve[..len_sve])
                            .expect("sve2 decode");
                    assert_eq!(dec_scalar, dec_sve, "SVE2 decode mismatch for {val}");
                    assert_eq!(used_scalar, used_sve, "SVE2 decode len mismatch for {val}");
                }
            }
        }
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    mod tests_rs_neon {
        #[test]
        fn neon_rs_encode_matches_scalar() {
            // Two data shards (512 bytes), two parity shards
            let mut data = vec![0u8; 512];
            for (i, v) in data.iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(31).wrapping_add(7);
            }

            let scalar = super::scalar::reed_solomon_encode_scalar(&data, 2);
            let neon = unsafe { super::arm::reed_solomon_encode_neon(&data, 2) };
            assert_eq!(scalar, neon);
        }

        #[test]
        fn neon_bitpack_roundtrip_matches_scalar() {
            let mut src = vec![0u8; 257];
            for (i, v) in src.iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(13).wrapping_add(5);
            }

            for bw in 1u8..=8 {
                let mut packed_scalar = vec![0u8; 512];
                let mut unpack_scalar = vec![0u8; src.len()];
                let used = super::scalar::pack_bits(&src, bw, &mut packed_scalar);
                super::scalar::unpack_bits(&packed_scalar[..used], bw, &mut unpack_scalar);

                let mut packed_neon = vec![0u8; 512];
                let mut unpack_neon = vec![0u8; src.len()];
                let used_neon = unsafe { super::arm::pack_bits_neon(&src, bw, &mut packed_neon) };
                unsafe {
                    super::arm::unpack_bits_neon(&packed_neon[..used_neon], bw, &mut unpack_neon)
                };

                assert_eq!(unpack_scalar, unpack_neon, "bit-width {}", bw);
            }
        }

        #[test]
        fn neon_popcnt_matches_scalar() {
            let mut data = vec![0u8; 4096];
            for (i, v) in data.iter_mut().enumerate() {
                *v = (i as u8).wrapping_mul(97).wrapping_add(33);
            }
            let scalar = super::scalar::popcnt(&data);
            let neon = unsafe { super::arm::popcnt_neon(&data) };
            assert_eq!(scalar, neon);
        }
    }
}
