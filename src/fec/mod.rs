#![allow(clippy::module_inception)]
#![cfg_attr(any(test, feature = "rust-tests"), allow(unused_variables))]

#[cfg(test)]
use crate::accelerate;
use crate::brain::BrainFecHints;
#[cfg(target_arch = "x86_64")]
use crate::fec::gf_tables::prefetch_fec_slice;
use crate::optimize::{CpuProfile, FeatureDetector, MemoryPool};
use aligned_box::AlignedBox;
use parking_lot::{Mutex, RwLock};

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

// Global repair ID counter for fountain codes
static REPAIR_ID_COUNTER: AtomicU64 = AtomicU64::new(0);
const GF4_LIGHT_REDUNDANCY: f32 = 16.0 / 15.0;
const FOUNTAIN_LOSS_THRESHOLD: f32 = 0.25;
const FOUNTAIN_MIN_RECENT_OBSERVATIONS: u64 = 32;
const DEFAULT_FOUNTAIN_WINDOW: usize = 128;
const MAX_FOUNTAIN_WINDOW: usize = 128;
#[cfg(test)]
const MAX_FOUNTAIN_REPAIR_BURST: usize = MAX_FOUNTAIN_WINDOW * 4 + 4;
pub(crate) const DEFAULT_FOUNTAIN_SEED: u64 = 12_345;
const FOUNTAIN_SEED_LABEL: &[u8] = b"quicfuscate fec fountain v1";

/// Derive the connection-local fountain seed from the matching QUIC 1-RTT secret.
///
/// The sender's write secret is the receiver's read secret, so both endpoints
/// regenerate identical symbol sets without putting the seed on the wire.
pub(crate) fn derive_fountain_seed(secret: &[u8]) -> u64 {
    let digest = crate::crypto::hkdf::hmac_sha256(secret, FOUNTAIN_SEED_LABEL);
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(seed_bytes)
}

fn next_repair_id() -> u64 {
    REPAIR_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

use crate::env_utils::{env_flag, env_parse};

/// Pool-backed payload buffer shared across FEC packet handles via `Arc`.
#[derive(Clone)]
pub(crate) struct SharedFecBuffer {
    inner: Arc<SharedFecBufferInner>,
}

struct SharedFecBufferInner {
    buf: Option<AlignedBox<[u8]>>,
    pool: Arc<MemoryPool>,
}

impl Drop for SharedFecBufferInner {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.free(buf);
        }
    }
}

impl SharedFecBuffer {
    fn new(buf: AlignedBox<[u8]>, pool: Arc<MemoryPool>) -> Self {
        Self { inner: Arc::new(SharedFecBufferInner { buf: Some(buf), pool }) }
    }

    fn bytes(&self, len: usize) -> &[u8] {
        let buf = self.inner.buf.as_ref().expect("shared FEC buffer already freed");
        &buf[..len.min(buf.len())]
    }

    /// Number of strong references to the underlying pool buffer.
    /// Used by regression tests to prove FEC packet clones share the buffer
    /// via `Arc` rather than copying the payload (TODO-392).
    #[cfg(test)]
    fn strong_count(&self) -> usize {
        std::sync::Arc::strong_count(&self.inner)
    }
}

#[derive(Clone)]
struct FecRuntimePolicy {
    decoder_policy: String,
    lazy_enabled: bool,
    interleave_enabled: bool,
    switch_threshold_override: Option<f32>,
    switch_min_up_ms: u64,
    switch_min_down_ms: u64,
    auto_gf4_enabled: bool,
    fountain_window: usize,
    extreme_window: usize,
    fountain_symbol_size: usize,
    stream_every_override: Option<usize>,
    interleave_depth_override: Option<usize>,
    partial_enabled: bool,
    kalman_q_override: Option<f32>,
    kalman_r_override: Option<f32>,
}

impl FecRuntimePolicy {
    fn detect() -> Self {
        Self {
            decoder_policy: std::env::var("QUICFUSCATE_FEC_DECODER")
                .unwrap_or_else(|_| "auto".to_string()),
            lazy_enabled: env_flag("QUICFUSCATE_FEC_LAZY", true),
            interleave_enabled: env_flag("QUICFUSCATE_FEC_INTERLEAVE", true),
            switch_threshold_override: env_parse::<f32>("QUICFUSCATE_FEC_SWITCH_THRESH")
                .map(|value| value.clamp(0.0, 1.0)),
            switch_min_up_ms: env_parse::<u64>("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS").unwrap_or(120),
            switch_min_down_ms: env_parse::<u64>("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS")
                .unwrap_or(450),
            auto_gf4_enabled: env_flag("QUICFUSCATE_FEC_AUTO_GF4", true),
            fountain_window: env_parse::<usize>("QUICFUSCATE_FEC_FOUNTAIN_WINDOW")
                .unwrap_or(DEFAULT_FOUNTAIN_WINDOW)
                .clamp(1, MAX_FOUNTAIN_WINDOW),
            extreme_window: env_parse::<usize>("QUICFUSCATE_FEC_EXTREME_WINDOW").unwrap_or(1024),
            fountain_symbol_size: resolve_fountain_symbol_size(),
            stream_every_override: env_parse::<usize>("QUICFUSCATE_FEC_STREAM_EVERY")
                .map(|value| value.max(1)),
            interleave_depth_override: env_parse::<usize>("QUICFUSCATE_FEC_INTERLEAVE_DEPTH"),
            partial_enabled: env_flag("QUICFUSCATE_FEC_PARTIAL", true),
            kalman_q_override: env_parse::<f32>("QUICFUSCATE_KALMAN_Q"),
            kalman_r_override: env_parse::<f32>("QUICFUSCATE_KALMAN_R"),
        }
    }
}

fn resolve_fountain_symbol_size() -> usize {
    env_parse::<usize>("QUICFUSCATE_FOUNTAIN_SYMBOL")
        .or_else(|| env_parse::<usize>("QUICFUSCATE_MTU_HINT").map(|mtu| mtu.saturating_sub(80)))
        .unwrap_or(1500)
        .clamp(600, 16384)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FecBackendFamily {
    Zero,
    LowCostBlock,
    HeavyBlock,
    Streaming,
    Fountain,
}

#[derive(Debug, Clone, Copy)]
struct FecProtectionPressure {
    total: f32,
    loss: f32,
}

impl FecProtectionPressure {
    fn new(loss: f32, burst: f32) -> Self {
        let loss = loss.clamp(0.0, 1.0);
        let burst = burst.clamp(0.0, 1.0);
        let total = (loss * 0.8 + burst * 0.2).clamp(0.0, 1.0);
        Self { total, loss }
    }
}

#[derive(Debug, Clone, Copy)]
struct FecProtectionTarget {
    family: FecBackendFamily,
    redundancy: f32,
    effective_window: usize,
    stream_every: Option<usize>,
}

impl FecProtectionTarget {
    fn for_clean_link() -> Self {
        Self {
            family: FecBackendFamily::Zero,
            redundancy: 1.0,
            effective_window: 0,
            stream_every: None,
        }
    }
}

impl FecProtectionTarget {
    fn with_window(mut self, effective_window: usize) -> Self {
        self.effective_window = effective_window;
        self
    }
}

fn fec_backend_family(mode: FecMode) -> FecBackendFamily {
    match mode {
        FecMode::Zero => FecBackendFamily::Zero,
        FecMode::Light | FecMode::Normal => FecBackendFamily::LowCostBlock,
        FecMode::Medium | FecMode::Strong | FecMode::Extreme | FecMode::Ultra => {
            FecBackendFamily::HeavyBlock
        }
        FecMode::Streaming => FecBackendFamily::Streaming,
        FecMode::Fountain => FecBackendFamily::Fountain,
    }
}

fn mode_for_target(target: FecProtectionTarget, auto_gf4: bool) -> FecMode {
    match target.family {
        FecBackendFamily::Zero => FecMode::Zero,
        FecBackendFamily::LowCostBlock => {
            if auto_gf4 && target.effective_window <= 15 && target.redundancy <= 1.10 {
                FecMode::Light
            } else {
                FecMode::Normal
            }
        }
        FecBackendFamily::HeavyBlock => {
            if target.redundancy >= 3.0 {
                FecMode::Ultra
            } else if target.effective_window >= 512 {
                FecMode::Extreme
            } else if target.redundancy >= 1.5 || target.effective_window > 64 {
                FecMode::Strong
            } else {
                FecMode::Medium
            }
        }
        FecBackendFamily::Streaming => FecMode::Streaming,
        FecBackendFamily::Fountain => FecMode::Fountain,
    }
}

fn target_from_mode(mode: FecMode, default_window: usize) -> FecProtectionTarget {
    let effective_window = if default_window > 0 {
        default_window
    } else {
        match mode {
            FecMode::Zero => 0,
            FecMode::Light => 15,
            FecMode::Normal | FecMode::Streaming => 64,
            FecMode::Medium => 128,
            FecMode::Strong => 128,
            FecMode::Extreme => 512,
            FecMode::Ultra => 1024,
            FecMode::Fountain => DEFAULT_FOUNTAIN_WINDOW,
        }
    };

    let stream_every = match mode {
        FecMode::Streaming => Some(2),
        _ => None,
    };

    FecProtectionTarget {
        family: fec_backend_family(mode),
        redundancy: match mode {
            FecMode::Zero => 1.0,
            FecMode::Light => GF4_LIGHT_REDUNDANCY,
            FecMode::Normal => 1.25,
            FecMode::Medium => 1.5,
            FecMode::Strong => 2.0,
            FecMode::Extreme => 2.0,
            FecMode::Streaming => 1.2,
            FecMode::Ultra => 3.0,
            FecMode::Fountain => 5.0,
        },
        effective_window,
        stream_every,
    }
}

fn low_cost_block_uses_gf4(target: FecProtectionTarget) -> bool {
    target.family == FecBackendFamily::LowCostBlock
        && target.redundancy <= 1.10
        && target.effective_window <= 15
}

fn target_rank(target: FecProtectionTarget) -> u8 {
    match target.family {
        FecBackendFamily::Zero => 0,
        FecBackendFamily::LowCostBlock => {
            if low_cost_block_uses_gf4(target) {
                1
            } else {
                2
            }
        }
        FecBackendFamily::HeavyBlock => {
            if target.redundancy >= 3.0 {
                6
            } else if target.redundancy >= 2.0 {
                5
            } else {
                4
            }
        }
        FecBackendFamily::Streaming => 3,
        FecBackendFamily::Fountain => 7,
    }
}

fn wire_safe_encoder_params(
    mode: FecMode,
    source_count: usize,
    total_count: usize,
    requested_depth: usize,
    interleave_enabled: bool,
) -> (usize, usize, usize) {
    let depth = if mode == FecMode::Fountain || !interleave_enabled {
        1
    } else {
        requested_depth.clamp(1, 8).min(source_count.max(1))
    };
    if mode != FecMode::Streaming || source_count == 0 {
        return (source_count, total_count, depth);
    }

    let max_source_count = wire::MAX_GF8_BLOCK_SOURCE_COUNT.saturating_mul(depth);
    let bounded_source_count = source_count.min(max_source_count);
    let aligned_source_count = (bounded_source_count / depth).max(1).saturating_mul(depth);
    let scaled_total_count = aligned_source_count
        .saturating_mul(total_count)
        .div_ceil(source_count)
        .max(aligned_source_count);
    let aligned_total_count = scaled_total_count.div_ceil(depth).saturating_mul(depth);
    (aligned_source_count, aligned_total_count, depth)
}

fn continuous_fec_target(
    avg_loss: f32,
    auto_gf4: bool,
    disturbance: bool,
    fountain_window: usize,
    extreme_window: usize,
    rtt_ms: u32,
    burst_variance: f32,
) -> FecProtectionTarget {
    let clean = avg_loss < 0.001 && !disturbance;
    if clean {
        return FecProtectionTarget::for_clean_link();
    }

    let burst = if disturbance { (avg_loss.max(0.15) * 1.5).clamp(0.0, 1.0) } else { avg_loss };
    let pressure = FecProtectionPressure::new(avg_loss, burst);

    // StreamingAdaptive: select Streaming for moderate burst-loss (5-15%)
    // when burst variance is high (indicating bursty rather than uniform loss).
    // Falls back to LowCostBlock for uniform loss, escalates to HeavyBlock above 15%.
    let family = if pressure.loss >= FOUNTAIN_LOSS_THRESHOLD {
        FecBackendFamily::Fountain
    } else if disturbance && pressure.loss >= 0.15 {
        FecBackendFamily::Streaming
    } else if pressure.loss >= 0.05 && pressure.loss < 0.15 && burst_variance > 0.3 {
        // Burst-loss regime: streaming FEC is optimal for burst patterns
        FecBackendFamily::Streaming
    } else if pressure.total < 0.10 {
        FecBackendFamily::LowCostBlock
    } else {
        FecBackendFamily::HeavyBlock
    };

    let redundancy = match family {
        FecBackendFamily::Zero => 1.0,
        FecBackendFamily::LowCostBlock => {
            if pressure.total < 0.02 {
                GF4_LIGHT_REDUNDANCY
            } else {
                1.25
            }
        }
        FecBackendFamily::HeavyBlock => {
            if pressure.total < 0.22 {
                1.5
            } else if pressure.total < 0.30 {
                2.0
            } else {
                3.0
            }
        }
        FecBackendFamily::Streaming => 1.2,
        FecBackendFamily::Fountain => 5.0,
    };

    let effective_window = match family {
        FecBackendFamily::Zero => 0,
        FecBackendFamily::LowCostBlock => {
            if pressure.total < 0.02 && auto_gf4 {
                15
            } else {
                64
            }
        }
        FecBackendFamily::HeavyBlock => {
            if pressure.total < 0.22 {
                128
            } else if pressure.total < 0.30 {
                512
            } else {
                1024
            }
        }
        FecBackendFamily::Streaming => extreme_window,
        FecBackendFamily::Fountain => fountain_window,
    };

    let stream_every = match family {
        FecBackendFamily::Streaming => {
            // Base interval from pressure (higher pressure = smaller interval = faster recovery)
            let base = if pressure.total >= 0.22 {
                1
            } else if pressure.total >= 0.18 {
                2
            } else if pressure.total >= 0.15 {
                3
            } else {
                4
            };
            // RTT-coupled scaling: high RTT → larger interval (less overhead, recovery is RTT-bound)
            // Low RTT → smaller interval (faster recovery, overhead is cheap)
            // Formula: scale = clamp(rtt / reference_rtt, 0.5, 3.0), reference = 100ms
            let reference_rtt = 100u32;
            let scale = if rtt_ms > 0 {
                (rtt_ms as f32 / reference_rtt as f32).clamp(0.5, 3.0)
            } else {
                1.0
            };
            let scaled = (base as f32 * scale).round() as usize;
            Some(scaled.clamp(1, 18))
        }
        _ => None,
    };

    FecProtectionTarget { family, redundancy, effective_window, stream_every }
}

/// Portable GF(256) matrix multiplication using central SIMD gf_mul for row scaling
/// Computes C = A x B over GF(2^8), where
///  - A is M x K, B is K x N, C is M x N
///  - All inputs/outputs are byte matrices with XOR as addition and gf_mul as multiplication
#[inline]
pub fn matrix_multiply_scalar(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    matrix_multiply_accumulate(a, b, result);
}

#[inline]
fn matrix_multiply_accumulate(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    gf_tables::init_tables();
    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    #[allow(dead_code)]
    unsafe fn gf_mul_scalar_slice_ssse3(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        use std::arch::x86_64::*;
        debug_assert_eq!(src.len(), out_xor.len());

        let mut t0 = [0u8; 16];
        let mut t1 = [0u8; 16];
        for i in 0..16 {
            t0[i] = crate::fec::gf_tables::gf_mul_table(coeff, i as u8);
            t1[i] = crate::fec::gf_tables::gf_mul_table(coeff, ((i as u8) << 4) as u8);
        }

        let tbl0 = _mm_loadu_si128(t0.as_ptr() as *const __m128i);
        let tbl1 = _mm_loadu_si128(t1.as_ptr() as *const __m128i);
        let mask0f = _mm_set1_epi8(0x0f_i8);

        let pf_dist: usize = if src.len() >= 4096 {
            256
        } else if src.len() >= 1024 {
            192
        } else if src.len() >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        while i + 32 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_fec_slice(src.as_ptr().add(pf_i));
                    prefetch_fec_slice(out_xor.as_ptr().add(pf_i));
                }
            }

            let x0 = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let lo0 = _mm_and_si128(x0, mask0f);
            let hi0 = _mm_and_si128(_mm_srli_epi16(x0, 4), mask0f);
            let prod_lo0 = _mm_shuffle_epi8(tbl0, lo0);
            let prod_hi0 = _mm_shuffle_epi8(tbl1, hi0);
            let prod0 = _mm_xor_si128(prod_lo0, prod_hi0);
            let dst0 = _mm_loadu_si128(out_xor.as_ptr().add(i) as *const __m128i);
            let res0 = _mm_xor_si128(dst0, prod0);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i) as *mut __m128i, res0);

            let x1 = _mm_loadu_si128(src.as_ptr().add(i + 16) as *const __m128i);
            let lo1 = _mm_and_si128(x1, mask0f);
            let hi1 = _mm_and_si128(_mm_srli_epi16(x1, 4), mask0f);
            let prod_lo1 = _mm_shuffle_epi8(tbl0, lo1);
            let prod_hi1 = _mm_shuffle_epi8(tbl1, hi1);
            let prod1 = _mm_xor_si128(prod_lo1, prod_hi1);
            let dst1 = _mm_loadu_si128(out_xor.as_ptr().add(i + 16) as *const __m128i);
            let res1 = _mm_xor_si128(dst1, prod1);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i + 16) as *mut __m128i, res1);

            i += 32;
        }

        while i + 16 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_fec_slice(src.as_ptr().add(pf_i));
                    prefetch_fec_slice(out_xor.as_ptr().add(pf_i));
                }
            }

            let x = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let lo = _mm_and_si128(x, mask0f);
            let hi = _mm_and_si128(_mm_srli_epi16(x, 4), mask0f);
            let prod_lo = _mm_shuffle_epi8(tbl0, lo);
            let prod_hi = _mm_shuffle_epi8(tbl1, hi);
            let prod = _mm_xor_si128(prod_lo, prod_hi);
            let dst = _mm_loadu_si128(out_xor.as_ptr().add(i) as *const __m128i);
            let res = _mm_xor_si128(dst, prod);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i) as *mut __m128i, res);

            i += 16;
        }

        while i < src.len() {
            let v = src[i];
            let lo = (v & 0x0f) as usize;
            let hi = (v >> 4) as usize;
            out_xor[i] ^= t0[lo] ^ t1[hi];
            i += 1;
        }

        crate::telemetry::FEC_SSSE3_OPS.inc();
    }

    for row in result.iter_mut() {
        row.clear();
        row.resize(n, 0);
    }

    for (kk, b_row) in b.iter().take(k).enumerate() {
        let len = b_row.len().min(n);
        if len == 0 {
            continue;
        }

        for (i, res_row) in result.iter_mut().enumerate().take(m) {
            let coef = a[i][kk];
            if coef != 0 {
                gf_tables::gf_mul_scalar_slice(coef, &b_row[..len], &mut res_row[..len]);
            }
        }
    }
}

use crate::transport::TransportObserver;
use rayon::prelude::*;

#[inline(always)]
pub(crate) fn prefetch_decode_window(ptr: *const u8) {
    gf_tables::prefetch_fec_slice(ptr);
}

// Global Rayon pool initialization from env
static RAYON_INIT: std::sync::Once = std::sync::Once::new();

#[derive(Clone, Copy, Debug)]
enum FecRayonGlobalPolicy {
    Default,
    ThreadCap(usize),
}

impl FecRayonGlobalPolicy {
    fn detect() -> Self {
        env_parse::<usize>("QUICFUSCATE_RAYON_THREADS")
            .filter(|threads| *threads > 0)
            .map(Self::ThreadCap)
            .unwrap_or(Self::Default)
    }

    fn initialize(self) {
        RAYON_INIT.call_once(|| {
            if let Self::ThreadCap(threads) = self {
                let _ = rayon::ThreadPoolBuilder::new().num_threads(threads).build_global();
            }
        });
    }
}

struct FecGlobalResources {
    rayon: FecRayonGlobalPolicy,
}

impl FecGlobalResources {
    fn detect() -> Self {
        Self { rayon: FecRayonGlobalPolicy::detect() }
    }

    fn initialize(&self) {
        gf_tables::init_tables();
        self.rayon.initialize();
    }
}

const PAR_THRESHOLD: usize = 8192; // bytes; tuneable
const GF16_VBMI2_MIN_WORDS: usize = 32;
const GF16_AVX512_MIN_WORDS: usize = 64;
const GF16_AVX2_MIN_WORDS: usize = 32;
const GF16_SSE2_MIN_WORDS: usize = 16;
const GF16_SVE2_MIN_WORDS: usize = 24;
const GF16_NEON_MIN_WORDS: usize = 32;

const STREAM_ADJUST_MIN_MS: u64 = 150;

// ============================================================================
// FEC implementation with accelerated kernels where available.
// ============================================================================

/// Fast XOR helper with centralized SIMD dispatch from optimize.rs.
#[inline(always)]
fn fast_xor_inplace(src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());

    // Use the centralized SIMD dispatch from optimize.rs.
    crate::optimize::simd::core::xor_blocks(dst, src);

    crate::optimize::telemetry::FEC_SIMD_ENCODE.inc();
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod fec_stream_tests;

#[cfg(test)]
mod gf16_tests;

#[cfg(test)]
mod e2e_tests;

#[cfg(test)]
mod resource_tests;

#[cfg(test)]
mod transition_tests;

#[cfg(test)]
mod adaptive_tests;

#[cfg(test)]
mod policy_tests;
include!("parts/codecs_and_observers.rs");
include!("parts/decoders.rs");
mod internal;

pub mod wire;
include!("parts/adaptive_controller.rs");
mod fountain_codes;

#[cfg(test)]
mod adaptive_reed_solomon;

mod gf_tables;

include!("parts/gf16_and_config.rs");
#[cfg(test)]
mod tests;
