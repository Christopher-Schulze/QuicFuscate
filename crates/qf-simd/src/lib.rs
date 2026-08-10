//! Ultra-sophisticated centralized SIMD module - MAX EXCELLENCE!
//! Hardware acceleration is centralized here; target-specific implementations
//! are gated by architecture, compiler target features, and runtime capability.

#![cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    allow(unused_imports, unused_variables)
)]
use std::sync::OnceLock;

#[cfg(not(windows))]
use qf_cpu::{prefetch, PrefetchHint};
pub use qf_cpu::{
    AmxCapability, CpuFeature, CpuFeatures, CpuProfile, CryptoAeadPlan, FeatureDetector,
};

#[cfg(not(windows))]
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
#[doc(hidden)]
#[allow(dead_code)]
pub mod arm_stream;
#[cfg(target_arch = "aarch64")]
mod arm_varint;
#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
pub mod x86_ack;
#[cfg(target_arch = "x86_64")]
mod x86_header;

#[cfg(not(windows))]
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
    if !FeatureDetector::instance().features_full().simd_dispatch_matrix().avx2 {
        return x86_ack::canonical_ack_blocks_scalar(ranges);
    }
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the callee is a retained parity helper that operates purely on the
    //   provided slice and returns owned output
    // - no raw pointers escape this wrapper and no additional aliasing or
    //   lifetime assumptions are introduced here
    x86_ack::canonical_ack_blocks_avx2(ranges)
}

/// Canonicalize ACK block ranges using AVX-512 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn canonical_ack_blocks_avx512_for_rust_tests(ranges: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if !FeatureDetector::instance().features_full().simd_dispatch_matrix().avx512_ack {
        return x86_ack::canonical_ack_blocks_scalar(ranges);
    }
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the underlying helper is retained parity machinery over a borrowed
    //   slice and does not expose raw-pointer ownership outside the call
    // - target-feature preconditions stay encapsulated in the internal helper
    x86_ack::canonical_ack_blocks_avx512(ranges)
}

/// Validate a QUIC packet header using AVX-512 SIMD. Test-only entry point (x86_64).
#[cfg(all(target_arch = "x86_64", any(test, feature = "rust-tests")))]
#[inline(always)]
pub fn validate_header_avx512_for_rust_tests(header: &[u8]) -> bool {
    if !FeatureDetector::instance().features_full().avx512f {
        return scalar::validate_header(header);
    }
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
    if !FeatureDetector::instance().features_full().sse2 {
        return scalar::validate_header(header);
    }
    // SAFETY:
    // - this rust-tests hook is compiled only on x86_64
    // - the helper only inspects the provided header slice
    // - the retained unsafe stays inside the internal SIMD helper
    unsafe { x86::validate_header_sse2(header) }
}

/// Acceleration planner (global hardware plan cache).
pub use qf_cpu::planner;

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

// ============================================================================
// aarch64 IMPLEMENTATIONS (wrappers delegating to scalar for correctness)
// Top-level module to satisfy calls like `arm::...` behind cfg(target_arch="aarch64")
// ============================================================================
#[cfg(target_arch = "aarch64")]
pub mod arm;

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
            let full = features.features_full();
            if full.avx512f {
                return _x86_avx512();
            }
            if full.simd_dispatch_matrix().avx2 {
                return _x86_avx2();
            }
            if full.sse2 {
                return _x86_sse();
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            let full = features.features_full();
            if full.sve2 {
                return arm_sve2();
            }
            if full.neon {
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
pub mod core;

// ============================================================================
// GALOIS FIELD OPERATIONS - For FEC/Reed-Solomon
// ============================================================================

/// Galois field operations for FEC/Reed-Solomon encoding.
pub mod galois;

// ============================================================================
// CRYPTO OPERATIONS - AES, GHASH, Poly1305, Hash
// ============================================================================

/// SIMD-dispatched cryptographic primitives: AES, GHASH, SHA-256, HMAC-SHA-256.
pub mod crypto;

// ============================================================================
// QPACK HELPERS - Public wrapper for Huffman encode with runtime dispatch
// ============================================================================

pub mod qpack;

// x86_64 IMPLEMENTATIONS
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod x86;

// ============================================================================
// FEC SPECIFIC - Berlekamp-Massey, Wiedemann and Reed-Solomon solvers
// ============================================================================

/// FEC-specific SIMD helpers: Berlekamp-Massey, varint decoding, header validation.
pub mod fec;

// ============================================================================
// BITSTREAM OPERATIONS - Pack/Unpack with BMI2
// ============================================================================

/// Bitstream pack/unpack with BMI2/NEON acceleration.
pub mod bitstream;

// =========================================================================
// TRANSPORT HELPERS - QUIC varint encode/decode (wrappers for transport)
// =========================================================================

/// QUIC variable-length integer encode/decode with SIMD acceleration.
pub mod transport;

// ============================================================================
// STRING OPERATIONS - Ultra-fast comparison
// ============================================================================

/// SIMD-accelerated byte-string comparison.
pub mod string;

// ============================================================================
// HTTP/3 QPACK - Header compression with SIMD
// ============================================================================

/// HTTP/3 QPACK Huffman encode/decode with SIMD acceleration.
pub mod h3;

// ============================================================================
// INTEL AMX INTEGRATION BOUNDARY
// The active FEC path remains on the checked scalar fallback until TODO-818
// proves a real AMX arithmetic kernel and its compiler/runtime contract.
// ============================================================================

#[cfg(all(target_arch = "x86_64", target_feature = "amx-tile", target_feature = "amx-int8"))]
pub mod amx;

// ============================================================================
// SCALAR FALLBACK IMPLEMENTATIONS
// ============================================================================

// ============================================================================
// X86 EXTENDED IMPLEMENTATIONS FOR FEC AND TRANSPORT
// ============================================================================

#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod x86_extended;

#[cfg(all(test, target_arch = "aarch64"))]
mod tests_arm;

// Continue with rest of x86 module implementations after the main x86 module
#[cfg(target_arch = "x86_64")]
mod x86_rest {}

/// Pure-scalar fallback implementations for every SIMD-dispatched operation.
pub mod scalar;

// ----------------------------------------------------------------------------
// Tests (platform-independent) - dispatched API correctness
// ----------------------------------------------------------------------------
#[cfg(test)]
mod tests_dispatched;

// ----------------------------------------------------------------------------
// Tests (aarch64 only) - validate NEON header checks vs. dispatcher semantics
// ----------------------------------------------------------------------------
#[cfg(all(test, target_arch = "aarch64"))]
mod tests;
