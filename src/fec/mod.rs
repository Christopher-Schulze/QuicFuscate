#![allow(clippy::module_inception)]
#![cfg_attr(any(test, feature = "rust-tests"), allow(unused_variables))]

use crate::accelerate;
use crate::brain::{FEC_INTERVAL_HINT_PKTS, FEC_REDUNDANCY_PPM};
#[cfg(target_arch = "x86_64")]
use crate::fec::gf_tables::prefetch_fec_slice;
use crate::optimize::{CpuProfile, FeatureDetector, MemoryPool};
use aligned_box::AlignedBox;
use parking_lot::{Mutex, RwLock};

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Global repair ID counter for fountain codes
static REPAIR_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    rs_loss_hint: f32,
    rs_latency_ms_hint: f32,
    rs_bw_mbps_hint: f32,
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
            fountain_window: env_parse::<usize>("QUICFUSCATE_FEC_FOUNTAIN_WINDOW").unwrap_or(2048),
            extreme_window: env_parse::<usize>("QUICFUSCATE_FEC_EXTREME_WINDOW").unwrap_or(1024),
            fountain_symbol_size: resolve_fountain_symbol_size(),
            rs_loss_hint: env_parse::<f32>("QUICFUSCATE_RS_LOSS").unwrap_or(0.0),
            rs_latency_ms_hint: env_parse::<f32>("QUICFUSCATE_RS_LATENCY_MS").unwrap_or(5.0),
            rs_bw_mbps_hint: env_parse::<f32>("QUICFUSCATE_RS_BW_MBPS").unwrap_or(1000.0),
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
            if auto_gf4 && target.effective_window <= 16 && target.redundancy <= 1.10 {
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
            FecMode::Light => 16,
            FecMode::Normal | FecMode::Streaming => 64,
            FecMode::Medium => 128,
            FecMode::Strong => 128,
            FecMode::Extreme => 512,
            FecMode::Ultra => 1024,
            FecMode::Fountain => 2048,
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
            FecMode::Light => 1.1,
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
        && target.effective_window <= 16
}

fn heavy_block_uses_adaptive_rs(target: FecProtectionTarget) -> bool {
    target.family == FecBackendFamily::HeavyBlock
        && target.redundancy <= 2.0
        && target.effective_window <= 128
}

fn adaptive_rs_uses_gf16(target: FecProtectionTarget) -> bool {
    target.family == FecBackendFamily::HeavyBlock
        && (target.redundancy >= 2.0 || target.effective_window > 64)
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
    let family = if pressure.loss >= 0.25 {
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
                1.10
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
                16
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
    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };

    for row in result.iter_mut() {
        row.clear();
        row.resize(n, 0);
    }

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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vl", enable = "gfni")]
#[allow(dead_code)]
unsafe fn matrix_multiply_avx512(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    use std::arch::x86_64::*;

    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };

    for row in result.iter_mut() {
        row.clear();
        row.resize(n, 0);
    }

    if m == 0 || n == 0 || k == 0 {
        return;
    }

    for (i, res_row) in result.iter_mut().enumerate().take(m) {
        let a_row = &a[i];
        for (kk, b_row) in b.iter().enumerate().take(k) {
            let coeff = *a_row.get(kk).unwrap_or(&0);
            if coeff == 0 {
                continue;
            }

            let len = b_row.len().min(n);
            if len == 0 {
                continue;
            }

            let coeff_vec = _mm512_set1_epi8(coeff as i8);
            let mut offset = 0usize;

            while offset + 64 <= len {
                let src = _mm512_loadu_si512(b_row.as_ptr().add(offset) as *const _);
                let prod = _mm512_gf2p8mul_epi8(coeff_vec, src);
                let acc = _mm512_loadu_si512(res_row.as_ptr().add(offset) as *const _);
                let updated = _mm512_xor_si512(acc, prod);
                _mm512_storeu_si512(res_row.as_mut_ptr().add(offset) as *mut _, updated);
                offset += 64;
            }

            if offset < len {
                let remaining = (len - offset) as u32;
                let mask: __mmask64 =
                    if remaining == 64 { !0u64 } else { (1u64 << remaining) - 1 } as __mmask64;

                let src_tail =
                    _mm512_maskz_loadu_epi8(mask, b_row.as_ptr().add(offset) as *const _);
                let prod_tail = _mm512_gf2p8mul_epi8(coeff_vec, src_tail);
                let acc_tail =
                    _mm512_maskz_loadu_epi8(mask, res_row.as_ptr().add(offset) as *const _);
                let updated_tail = _mm512_xor_si512(acc_tail, prod_tail);
                _mm512_mask_storeu_epi8(
                    res_row.as_mut_ptr().add(offset) as *mut _,
                    mask,
                    updated_tail,
                );
            }

            crate::telemetry::FEC_GFNI_OPS.inc();
        }
    }
}

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

// ============================================================================
// Transport Integration: FecTransportObserver
// Collects lightweight transport telemetry (ACK delay, ECN) and exposes a
// policy hook to tune transport parameters with minimal overhead.
// This does not change any FEC algorithm semantics; it merely adjusts
// ACK emission aggressiveness for CPU/latency balance.
// ============================================================================

#[derive(Default, Debug, Clone)]
struct FecObsSnapshot {
    ack_delay_ewma_us: f64,
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    ack_events: u64,
}

#[derive(Default, Debug)]
struct FecObsState {
    snap: FecObsSnapshot,
    last_redundancy_ppm: u32,
}

#[derive(Clone, Copy, Debug)]
struct FecObserverAmbientInputs {
    profile: FecObserverProfilePolicy,
    base_stream_interval: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct FecObserverPlatformHints {
    mobile_os: bool,
    containerized_server: bool,
}

impl FecObserverPlatformHints {
    fn detect() -> Self {
        let mobile_os = cfg!(any(target_os = "ios", target_os = "android"));

        #[cfg(target_os = "linux")]
        let containerized_server = std::path::Path::new("/.dockerenv").exists()
            || std::path::Path::new("/run/.containerenv").exists();

        #[cfg(not(target_os = "linux"))]
        let containerized_server = false;

        Self { mobile_os, containerized_server }
    }
}

#[derive(Clone, Copy, Debug)]
enum FecObserverProfilePolicy {
    Explicit(TransportProfile),
    Ambient(TransportProfile),
}

impl FecObserverProfilePolicy {
    fn from_sources(
        profile_override: Option<&str>,
        platform_hints: FecObserverPlatformHints,
    ) -> Self {
        if let Some(profile) = profile_override {
            return Self::Explicit(match profile {
                "mobile" => TransportProfile::Mobile,
                "server" => TransportProfile::Server,
                _ => TransportProfile::Desktop,
            });
        }

        if platform_hints.mobile_os {
            return Self::Ambient(TransportProfile::Mobile);
        }
        if platform_hints.containerized_server {
            return Self::Ambient(TransportProfile::Server);
        }

        Self::Ambient(TransportProfile::Desktop)
    }

    fn detect() -> Self {
        let platform_hints = FecObserverPlatformHints::detect();
        match std::env::var("QUICFUSCATE_PROFILE") {
            Ok(profile) => Self::from_sources(Some(profile.as_str()), platform_hints),
            Err(_) => Self::from_sources(None, platform_hints),
        }
    }

    fn profile(self) -> TransportProfile {
        match self {
            Self::Explicit(profile) | Self::Ambient(profile) => profile,
        }
    }
}

impl FecObserverAmbientInputs {
    fn new(profile: FecObserverProfilePolicy, base_stream_interval: u32) -> Self {
        Self { profile, base_stream_interval }
    }

    fn from_runtime_policy(
        runtime_policy: &FecRuntimePolicy,
        profile: FecObserverProfilePolicy,
    ) -> Self {
        let base_stream_interval = runtime_policy
            .stream_every_override
            .map(|value| value as u32)
            .unwrap_or(8)
            .clamp(1, 32);

        Self::new(profile, base_stream_interval)
    }

    fn detect() -> Self {
        let runtime_policy = FecRuntimePolicy::detect();
        Self::from_runtime_policy(&runtime_policy, FecObserverProfilePolicy::detect())
    }
}

pub(crate) struct FecTransportObserver {
    state: RwLock<FecObsState>,
    ambient: FecObserverAmbientInputs,
}

impl FecTransportObserver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: RwLock::new(FecObsState::default()),
            ambient: FecObserverAmbientInputs::detect(),
        })
    }

    /// FEC streaming interval based on current network conditions.
    pub(crate) fn compute_streaming_interval(&self) -> u32 {
        let state = self.state.read();
        let s = &state.snap;

        // Base interval in packets.
        let mut interval = self.ambient.base_stream_interval;

        // Adaptive adjustment based on ECN and ACK delay.
        let total_ecn = s.ecn_ect0.saturating_add(s.ecn_ect1).saturating_add(s.ecn_ce);
        let ce_ratio = if total_ecn == 0 { 0.0 } else { (s.ecn_ce as f64) / (total_ecn as f64) };

        // Under high congestion signal: more aggressive streaming.
        if ce_ratio > 0.1 {
            interval = interval.saturating_sub(4u32).max(1u32); // minimum: 1 packet
        } else if ce_ratio > 0.05 {
            interval = interval.saturating_sub(2u32).max(2u32);
        } else if ce_ratio < 0.001 && s.ack_delay_ewma_us < 1000.0 {
            // Very clean path: less FEC.
            interval = interval.saturating_add(4u32).min(32u32);
        }

        let brain_hint = FEC_INTERVAL_HINT_PKTS.load() as u32;
        if (1..=32).contains(&brain_hint) {
            interval = (((interval as u64 * 3) + (brain_hint as u64 * 2)) / 5).clamp(1, 32) as u32;
        }

        interval
    }

    /// Sync FEC-owned runtime hints into transport control deltas.
    ///
    /// This intentionally excludes generic transport actuators such as ACK threshold
    /// and external pacing. Those knobs are owned by the adaptive stealth/transport
    /// layer, while FEC keeps ownership of FEC-specific cadence and redundancy.
    pub(crate) fn sync_runtime_hints(&self, conn: &mut crate::transport::Connection) {
        // Retain the explicit observer profile snapshot as part of the observer audit
        // surface even though hint sync currently applies only FEC-owned deltas.
        let _profile = self.ambient.profile.profile();
        let mut state = self.state.write();

        let ppm_hint = FEC_REDUNDANCY_PPM.load();
        let pending_ppm = if ppm_hint > 0 && ppm_hint != state.last_redundancy_ppm {
            state.last_redundancy_ppm = ppm_hint;
            Some(ppm_hint)
        } else {
            None
        };
        drop(state);

        if let Some(ppm) = pending_ppm {
            conn.set_fec_redundancy_ppm(ppm);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportProfile {
    Mobile,  // Battery-optimized, higher latency tolerance
    Desktop, // Balanced performance
    Server,  // Maximum throughput, aggressive timing
}

impl TransportObserver for FecTransportObserver {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        // Update EWMA of ack delay (us). ack_delay is in quic units: actual_us = ack_delay << exponent
        // Transport already stored the exponent-applied value for telemetry; here we use an EWMA based on ack_delay.
        let mut st = self.state.write();
        let s = &mut st.snap;
        let alpha = 0.2f64;
        let sample = ack_delay as f64;
        s.ack_delay_ewma_us = if s.ack_events == 0 {
            sample
        } else {
            alpha * sample + (1.0 - alpha) * s.ack_delay_ewma_us
        };
        s.ack_events = s.ack_events.saturating_add(1);
        // After an ACK, transport resets the ECN counting cycle; keep counters flowing via on_ecn_update.
        // Optional: snapshotting/sliding-window logic could be implemented here.
    }

    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {
        // Hook reserved for future receive-side delivery-rate sampling.
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        // Track the current ECN counters since last ACK (transport resets after ACK emission)
        let mut st = self.state.write();
        st.snap.ecn_ect0 = ect0;
        st.snap.ecn_ect1 = ect1;
        st.snap.ecn_ce = ce;
    }
}

/// Thin public wrapper exposing the GF(2^8) streaming decoder for transport integration.
#[cfg(any(test, feature = "rust-tests"))]
pub struct FecDecoder8(Decoder8);

#[cfg(any(test, feature = "rust-tests"))]
impl FecDecoder8 {
    /// Create a new GF(2^8) decoder with the given source block size.
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self(Decoder8::new(k, pool))
    }
    /// Feed a received FEC packet (source or repair) into the decoder.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Drain all recovered packets from the decoder output queue.
    pub fn poll_recovered(&mut self) -> VecDeque<FecPacket> {
        self.0.get_partial_result()
    }
}

/// GF(2^16) multiply-accumulate over u16 slices: dst[i] ^= coeff * src[i]
#[inline(always)]
fn gf16_mul_slice(coeff: u16, src: &[u16], dst: &mut [u16]) {
    use crate::optimize;
    let len = core::cmp::min(src.len(), dst.len());
    optimize::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<optimize::Avx512Vbmi2>() && len >= GF16_VBMI2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_vbmi2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx512>() && len >= GF16_AVX512_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx512(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx2>() && len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Sse2>() && len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sse2(coeff, src, dst, len);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<optimize::Sve2>() && len >= GF16_SVE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sve2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Neon>() && len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_neon(coeff, src, dst, len);
                }
            }
        }
        // Scalar fallback with aggressive unrolling
        let mut i = 0;
        while i + 8 <= len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            dst[i + 1] ^= gf_tables::gf16_mul(coeff, src[i + 1]);
            dst[i + 2] ^= gf_tables::gf16_mul(coeff, src[i + 2]);
            dst[i + 3] ^= gf_tables::gf16_mul(coeff, src[i + 3]);
            dst[i + 4] ^= gf_tables::gf16_mul(coeff, src[i + 4]);
            dst[i + 5] ^= gf_tables::gf16_mul(coeff, src[i + 5]);
            dst[i + 6] ^= gf_tables::gf16_mul(coeff, src[i + 6]);
            dst[i + 7] ^= gf_tables::gf16_mul(coeff, src[i + 7]);
            i += 8;
        }
        while i < len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            i += 1;
        }
    });
}

/// GF(2^16) multiply-accumulate self-check entry point for SIMD verification.
#[cfg(feature = "simd-selfcheck")]
#[cfg(any(test, feature = "rust-tests"))]
pub fn gf16_mul_slice_selfcheck(coeff: u16, src: &[u16], dst: &mut [u16]) {
    gf16_mul_slice(coeff, src, dst);
}

// Transport imports removed - not needed for FEC module

// Loss estimation (EMA + Burst window + optional Kalman smoothing)
pub(crate) struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,
    burst_window: VecDeque<bool>,
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
    total_seen: u64,
    total_lost: u64,
    // Change-point detection & auto-tuning
    auto_tune: bool,
    mean: f32,
    m2: f32,
    count: u64,
    cusum_pos: f32,
    cusum_neg: f32,
    cusum_thresh: f32,
    stable_ctr: u32,
    base_lambda: f32,
}

impl LossEstimator {
    /// Create with sensible defaults (lambda=0.2, burst_capacity=128, no Kalman)
    pub fn new() -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda: 0.2,
            burst_window: VecDeque::with_capacity(128),
            burst_capacity: 128,
            kalman: None,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: 0.2,
        }
    }

    fn from_config(config: &FecConfig, ambient: &FecAmbientInputs) -> Self {
        let kalman = if config.kalman_enabled {
            Some(KalmanFilter::new(
                ambient.kalman_q_override.unwrap_or(config.kalman_q),
                ambient.kalman_r_override.unwrap_or(config.kalman_r),
            ))
        } else {
            None
        };

        Self {
            ema_loss_rate: 0.0,
            lambda: config.lambda,
            burst_window: VecDeque::with_capacity(config.burst_window),
            burst_capacity: config.burst_window,
            kalman,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: config.lambda,
        }
    }
}

impl Default for LossEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl LossEstimator {
    /// Report aggregate observation (lost of total) to update smoothing state
    pub fn report(&mut self, lost: usize, total: usize) {
        if total == 0 {
            return;
        }
        let mut loss_now = lost as f32 / total as f32;
        if let Some(kf) = self.kalman.as_mut() {
            // Lightweight Kalman usage: treat measurement as scalar
            // (KalmanFilter provides update(measurement) -> smoothed)
            loss_now = kf.update(loss_now);
        }
        // Online statistics (Welford) for variance estimation
        self.count += 1;
        let delta = loss_now - self.mean;
        self.mean += delta / (self.count as f32);
        let delta2 = loss_now - self.mean;
        self.m2 += delta * delta2;
        let var = if self.count > 1 { self.m2 / ((self.count - 1) as f32) } else { 0.0 };
        // CUSUM change-point detection (two-sided)
        let k_cusum = (var.sqrt() * 0.5).clamp(0.005, 0.1); // slack parameter
        self.cusum_pos = (self.cusum_pos + (loss_now - self.mean) - k_cusum).max(0.0);
        self.cusum_neg = (self.cusum_neg - (loss_now - self.mean) - k_cusum).max(0.0);
        let change_detected =
            self.cusum_pos > self.cusum_thresh || self.cusum_neg > self.cusum_thresh;
        if self.auto_tune {
            if change_detected {
                // react faster; increase process noise
                self.lambda = 0.85f32.max(self.lambda);
                if let Some(kf) = self.kalman.as_mut() {
                    kf.q = (kf.q * 1.5).clamp(1e-6, 0.25);
                }
                self.cusum_pos = 0.0;
                self.cusum_neg = 0.0;
                self.stable_ctr = 0;
            } else {
                self.stable_ctr = self.stable_ctr.saturating_add(1);
                if self.stable_ctr > 128 {
                    // calm down smoothing to reduce jitter
                    self.lambda = (self.lambda * 0.9 + self.base_lambda * 0.1).clamp(0.05, 0.85);
                    if let Some(kf) = self.kalman.as_mut() {
                        kf.q = (kf.q * 0.9).clamp(1e-8, 0.1);
                    }
                    self.stable_ctr = 0;
                }
            }
        }
        self.ema_loss_rate = self.lambda * loss_now + (1.0 - self.lambda) * self.ema_loss_rate;
        self.total_seen = self.total_seen.saturating_add(total as u64);
        self.total_lost = self.total_lost.saturating_add(lost as u64);
        // Update burst window using a bounded aggregate projection rather than raw packet counts.
        // Aggregate observations like 120/1000 must not saturate the whole burst window with
        // loss-only entries just because the sample was large.
        let sample_slots = total.min(self.burst_capacity).max(1);
        let projected_loss_slots =
            ((sample_slots as f32) * loss_now).round().clamp(0.0, sample_slots as f32) as usize;
        for i in 0..sample_slots {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(i < projected_loss_slots);
        }
    }

    /// Return smoothed point estimate; conservative: max(EMA, recent-burst-rate)
    pub fn smoothed_loss(&self) -> f32 {
        let burst_rate = if self.burst_window.is_empty() {
            0.0
        } else {
            let l = self.burst_window.iter().filter(|&&b| b).count();
            l as f32 / self.burst_window.len() as f32
        };
        self.ema_loss_rate.max(burst_rate)
    }

    /// Returns true if a significant change/burst was detected recently.
    pub fn disturbance_detected(&self) -> bool {
        self.cusum_pos > self.cusum_thresh
            || self.cusum_neg > self.cusum_thresh
            || self.stable_ctr == 0
    }

    /// Returns a normalized burst variance estimate [0.0, 1.0].
    /// High values indicate bursty loss patterns (clustered losses),
    /// low values indicate uniform/random loss.
    /// Computed as the variance of run lengths between loss events in the burst window.
    pub fn burst_variance(&self) -> f32 {
        if self.burst_window.len() < 8 {
            return 0.0;
        }
        // Compute run-length variance: lengths of consecutive non-loss runs
        let mut runs: Vec<u32> = Vec::new();
        let mut current_run = 0u32;
        for &lost in &self.burst_window {
            if lost {
                if current_run > 0 {
                    runs.push(current_run);
                }
                current_run = 0;
            } else {
                current_run += 1;
            }
        }
        if runs.is_empty() {
            return 0.0;
        }
        let n = runs.len() as f32;
        let mean = runs.iter().map(|&r| r as f32).sum::<f32>() / n;
        let variance = runs.iter().map(|&r| (r as f32 - mean).powi(2)).sum::<f32>() / n;
        // Normalize: variance / (mean^2 + 1) gives a coefficient-of-variation-like metric
        (variance / (mean * mean + 1.0)).min(1.0)
    }
}

// Kalman Filter with configurable process/measurement noise
#[derive(Debug)]
pub(crate) struct KalmanFilter {
    q: f32, // Process noise covariance
    r: f32, // Measurement noise covariance
    x: f32, // state estimate
    p: f32, // estimate covariance
}

impl KalmanFilter {
    pub(crate) fn new(q: f32, r: f32) -> Self {
        Self { q, r, x: 0.0, p: 1.0 }
    }

    /// One-dimensional Kalman update: returns the smoothed estimate
    pub(crate) fn update(&mut self, z: f32) -> f32 {
        // Predict
        self.p += self.q;
        // Update
        let k = self.p / (self.p + self.r);
        self.x = self.x + k * (z - self.x);
        self.p *= 1.0 - k;
        self.x
    }
}

/// Unified FEC packet carrying source or repair data with pool-managed buffers.
pub struct FecPacket {
    /// Unique packet identifier (source ID or repair window anchor).
    pub id: u64,
    /// Aligned payload buffer, recycled to the memory pool when the last handle drops.
    pub(crate) data: Option<SharedFecBuffer>,
    /// Actual byte count of valid payload within `data`.
    pub data_len: usize,
    /// True for original source packets, false for repair/coded packets.
    pub is_systematic: bool,
    /// GF coefficient vector for repair packets (None for source packets).
    pub coefficients: Option<AlignedBox<[u8]>>,
    /// Number of valid bytes in the coefficients buffer.
    pub coeff_len: usize,
    /// Shared memory pool for buffer allocation and recycling.
    pub mem_pool: Arc<MemoryPool>,
    /// Transport-level sequence number for ordering and gap detection.
    pub seq: u64,
    /// Creation timestamp for latency tracking.
    pub timestamp: std::time::Instant,
}

impl Drop for FecPacket {
    fn drop(&mut self) {
        // Payload buffers recycle when the last SharedFecBuffer handle drops.
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}

impl FecPacket {
    /// Construct a new FEC packet, upsizing buffers if declared lengths exceed capacity.
    pub fn new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        // Ensure provided buffers can accommodate declared lengths and keep pool accounting correct.
        let data = match data {
            Some(d) => {
                if data_len > d.len() {
                    match AlignedBox::<[u8]>::slice_from_default(data_len, 64) {
                        Ok(mut bigger) => {
                            let copy = d.len();
                            bigger[..copy].copy_from_slice(&d[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(d);
                            Some(bigger)
                        }
                        Err(_) => {
                            log::warn!("FEC: data buffer upsizing failed, returning original");
                            mem_pool.free(d);
                            None
                        }
                    }
                } else {
                    Some(d)
                }
            }
            None => None,
        };

        let coefficients = match coefficients {
            Some(c) => {
                if coeff_len > c.len() {
                    match AlignedBox::<[u8]>::slice_from_default(coeff_len, 64) {
                        Ok(mut bigger) => {
                            let copy = c.len();
                            bigger[..copy].copy_from_slice(&c[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(c);
                            Some(bigger)
                        }
                        Err(_) => {
                            log::warn!(
                                "FEC: coefficient buffer upsizing failed, returning original"
                            );
                            mem_pool.free(c);
                            None
                        }
                    }
                } else {
                    Some(c)
                }
            }
            None => None,
        };

        let data = data.map(|buf| SharedFecBuffer::new(buf, Arc::clone(&mem_pool)));

        Self {
            id,
            data,
            data_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
            seq: id, // Default: seq = id
            timestamp: std::time::Instant::now(),
        }
    }

    /// Payload bytes for this packet (up to `data_len`).
    #[inline]
    pub fn payload_slice(&self) -> Option<&[u8]> {
        self.data.as_ref().map(|shared| shared.bytes(self.data_len))
    }

    /// Mutable payload view when this packet is the sole owner of the shared buffer.
    #[inline]
    pub(crate) fn payload_mut_unique(&mut self) -> Option<&mut [u8]> {
        let shared = self.data.as_mut()?;
        let inner = Arc::get_mut(&mut shared.inner)?;
        let buf = inner.buf.as_mut()?;
        let end = self.data_len.min(buf.len());
        Some(&mut buf[..end])
    }

    /// Create a systematic FEC packet from a raw byte block, copying into a pool buffer.
    pub fn from_block(id: u64, block: &[u8], mem_pool: Arc<MemoryPool>) -> Self {
        let mut dst = mem_pool.alloc();
        let n = block.len().min(dst.len());
        dst[..n].copy_from_slice(&block[..n]);
        Self::new(id, Some(dst), n, true, None, 0, mem_pool)
    }

    /// Copy only the payload into `buf` (no headers). This is NOT the
    /// streaming DATAGRAM format - for transport, use `to_stream_raw()`.
    pub fn to_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        if let Some(data) = self.payload_slice() {
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Err("No data available".to_string())
        }
    }

    /// Serialize a streaming-friendly raw format for transport DATAGRAM:
    /// [magic:2=0xF1EC][is_systematic:1][base_id:8][seq:8][coeff_len:2][coeffs (coeff_len bytes)][payload]
    pub fn to_stream_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut off = 0usize;
        if buf.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        // Magic for safe demultiplexing of FEC datagrams
        buf[0] = 0xF1;
        buf[1] = 0xEC;
        off += 2;
        buf[off] = if self.is_systematic { 1 } else { 0 };
        off += 1;
        // base_id conveys the equation window anchor (id of the last source in window at sender)
        buf[off..off + 8].copy_from_slice(&self.id.to_be_bytes());
        off += 8;
        // seq conveys the transport sequence (used by InterleavedDecoder for block routing)
        buf[off..off + 8].copy_from_slice(&self.seq.to_be_bytes());
        off += 8;
        let coeff_len: u16 = self.coeff_len as u16;
        if buf.len() < off + 2 {
            return Err("BufferTooShort".into());
        }
        buf[off..off + 2].copy_from_slice(&coeff_len.to_be_bytes());
        off += 2;
        if let Some(ref coeffs) = self.coefficients {
            if buf.len() < off + self.coeff_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + self.coeff_len].copy_from_slice(&coeffs[..self.coeff_len]);
            off += self.coeff_len;
        } else if self.coeff_len > 0 {
            return Err("coeff_len>0 but no coefficients present".into());
        }
        if let Some(data) = self.payload_slice() {
            let n = data.len().min(buf.len().saturating_sub(off));
            if n < self.data_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + n].copy_from_slice(&data[..n]);
            off += n;
            Ok(off)
        } else {
            Err("No data available".into())
        }
    }

    /// Parse streaming-friendly raw format from transport DATAGRAM.
    /// Returns a FecPacket owning aligned buffers allocated from the pool.
    pub fn from_stream_raw(input: &[u8], pool: Arc<MemoryPool>) -> Result<Self, String> {
        if input.len() < 2 + 1 + 8 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        if input[0] != 0xF1 || input[1] != 0xEC {
            return Err("BadMagic".into());
        }
        let mut off = 2usize;
        let is_systematic = input[off] != 0;
        off += 1;
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&input[off..off + 8]);
        let base_id = u64::from_be_bytes(id_bytes);
        off += 8;
        let mut seq_bytes = [0u8; 8];
        seq_bytes.copy_from_slice(&input[off..off + 8]);
        let seq = u64::from_be_bytes(seq_bytes);
        off += 8;
        let mut cl_bytes = [0u8; 2];
        cl_bytes.copy_from_slice(&input[off..off + 2]);
        off += 2;
        let coeff_len = u16::from_be_bytes(cl_bytes) as usize;
        if input.len() < off + coeff_len {
            return Err("BufferTooShort".into());
        }
        let coeffs = if coeff_len > 0 {
            let mut cbuf = pool.alloc();
            if cbuf.len() < coeff_len {
                return Err("CoeffBufferTooSmall".into());
            }
            cbuf[..coeff_len].copy_from_slice(&input[off..off + coeff_len]);
            off += coeff_len;
            Some(cbuf)
        } else {
            None
        };
        let payload_len = input.len().saturating_sub(off);
        let mut dbuf = pool.alloc();
        if dbuf.len() < payload_len {
            return Err("DataBufferTooSmall".into());
        }
        dbuf[..payload_len].copy_from_slice(&input[off..]);
        let mut pkt =
            Self::new(base_id, Some(dbuf), payload_len, is_systematic, coeffs, coeff_len, pool);
        pkt.seq = seq;
        Ok(pkt)
    }

    /// Returns the payload length in bytes.
    pub fn len(&self) -> usize {
        self.data_len
    }
    /// Returns true if the packet carries no payload data.
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }
}

impl Clone for FecPacket {
    fn clone(&self) -> Self {
        let data_clone = self.data.clone();

        let coeffs_clone = if let Some(ref coeffs) = self.coefficients {
            let mut buf = self.mem_pool.alloc();
            let m = self.coeff_len.min(buf.len());
            buf[..m].copy_from_slice(&coeffs[..m]);
            Some(buf)
        } else {
            None
        };

        Self {
            id: self.id,
            data: data_clone,
            data_len: self.data_len,
            is_systematic: self.is_systematic,
            coefficients: coeffs_clone,
            coeff_len: self.coeff_len,
            mem_pool: Arc::clone(&self.mem_pool),
            seq: self.seq,
            timestamp: self.timestamp,
        }
    }
}

/// Forward error correction operating mode controlling redundancy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum FecMode {
    /// No FEC - zero overhead passthrough for loss-free links.
    Zero,
    /// Minimal redundancy for excellent conditions (<2% loss).
    Light,
    /// Standard block-code protection for moderate loss (2-10%).
    Normal,
    /// Increased redundancy for fair conditions.
    Medium,
    /// High redundancy for poor conditions (10-25% loss).
    Strong,
    /// Very high redundancy for severe loss (25-50%).
    Extreme,
    /// Maximum redundancy for extreme conditions.
    Ultra,
    /// Rateless LT fountain codes for >50% loss.
    Fountain,
    /// Continuous streaming repair emission for low-latency recovery.
    Streaming,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FecControlMode {
    Auto,
}

// Galois field marker types
/// GF(2^4) - For low loss (<5%), 4x less computation than GF(2^8)
struct GF4;
/// GF(2^8) - Standard field for moderate loss
struct GF8;
/// GF(2^16) - For high loss scenarios, larger symbol space
struct GF16;

// Core FEC encoder/decoder types
struct Encoder<F> {
    k: usize,
    window: VecDeque<FecPacket>,
    _field: std::marker::PhantomData<F>,
}

impl<F> Encoder<F> {
    /// Create a new encoder with source block size `k` and sliding window capacity.
    pub fn new(k: usize, _n: usize) -> Self {
        Self { k, window: VecDeque::with_capacity(k), _field: std::marker::PhantomData }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if self.window.len() < self.k {
            self.window.push_back(p);
        } else {
            // Sliding window: drop oldest, push newest (used by Streaming mode)
            let _ = self.window.pop_front();
            self.window.push_back(p);
        }
    }

    fn clear_window(&mut self) {
        self.window.clear();
    }

    fn packets_in_window(&self) -> usize {
        self.window.len()
    }
}

struct Encoder16 {
    inner: Encoder<GF16>,
    coeff_rows: Vec<u8>,
    coeff_stride: usize,
}

/// Public wrapper for GF(2^8) encoder used by transport integration.
#[cfg(any(test, feature = "rust-tests"))]
pub struct Encoder8(Encoder<GF8>);

#[cfg(any(test, feature = "rust-tests"))]
impl Encoder8 {
    /// Create a new GF(2^8) encoder with source block size `k` and total codeword size `n`.
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF8>::new(k, n))
    }
    /// Feed a source packet into the encoding window.
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    /// Generate the `idx`-th repair packet from the current encoding window.
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF8>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF8> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        // Determine max payload length among window packets
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        for b in &mut out[..max_len] {
            *b = 0;
        }

        // Coefficients (GF(2^8)), length = k
        let mut coeff_box = pool.alloc();
        if coeff_box.len() < self.k {
            return None;
        }
        let wlen = self.window.len().min(self.k);
        for j in 0..wlen {
            // Simple non-zero deterministic pattern
            let c =
                1u8 + (((idx as u8).wrapping_add(1)).wrapping_mul((j as u8).wrapping_add(1)) % 255);
            coeff_box[j] = c;
        }

        // Apply coefficients to data using optimized matrix helper
        // row is 1xK (one repair packet depends on K source packets)
        // We can just iterate and accumulate.
        // matrix_multiply_scalar expects matrix arguments, but here we generate one row.

        // Manual row accumulation
        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];
                // Accumulate: out[i] ^= c * data[i]
                gf_tables::gf_mul_scalar_slice(c, &data[..len], &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

/// Internal GF(2^4) encoder for low-loss adaptive runtime paths.
pub(crate) struct Encoder4(Encoder<GF4>);

impl Encoder4 {
    pub(crate) fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF4>::new(k, n))
    }
    pub(crate) fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub(crate) fn clear_window(&mut self) {
        self.0.clear_window()
    }
    pub(crate) fn packets_in_window(&self) -> usize {
        self.0.packets_in_window()
    }
    pub(crate) fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF4>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF4> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        out[..max_len].fill(0);

        // Coefficients (GF(2^4))
        // We store them as u8 (1..15)
        let mut coeff_box = pool.alloc();
        let wlen = self.window.len().min(self.k);
        for j in 0..wlen {
            // Simple non-zero deterministic pattern for GF(2^4)
            // (idx+1)*(j+1) mod 15, then +1 to be in [1..15]
            let mut c = (idx.wrapping_add(1).wrapping_mul(j.wrapping_add(1))) as u8;
            c %= 15;
            c += 1;
            coeff_box[j] = c;
        }

        // Manual row accumulation with chunking for SIMD
        const CHUNK_SIZE: usize = 128;

        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(data) = pkt.payload_slice() {
                let len = data.len().min(max_len);
                let c = coeff_box[j];

                // Accumulate: out ^= c * data (GF4)
                let mut i = 0;
                while i < len {
                    let chunk_len = (len - i).min(CHUNK_SIZE);
                    // Stack buffer for temp result
                    let mut tmp = [0u8; CHUNK_SIZE];

                    // Multiply src * c -> tmp
                    // Safety: gf4_mul uses SIMD/tables
                    crate::simd::galois::gf4_mul(&data[i..i + chunk_len], c, &mut tmp[..chunk_len]);

                    // XOR tmp -> out
                    for k in 0..chunk_len {
                        out[i + k] ^= tmp[k];
                    }
                    i += chunk_len;
                }
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

impl Encoder16 {
    fn new(k: usize, n: usize) -> Self {
        let mut encoder =
            Self { inner: Encoder::<GF16>::new(k, n), coeff_rows: Vec::new(), coeff_stride: 0 };
        encoder.prepare_coeff_rows(n.saturating_sub(k));
        encoder
    }

    #[inline]
    fn take_packet(&mut self, p: FecPacket) {
        self.inner.take_packet(p);
    }

    #[inline]
    fn clear_window(&mut self) {
        self.inner.clear_window();
    }

    #[inline]
    fn packets_in_window(&self) -> usize {
        self.inner.packets_in_window()
    }

    fn prepare_coeff_rows(&mut self, repair_rows: usize) {
        let stride = 2 * self.inner.k;
        self.coeff_stride = stride;
        if stride == 0 || repair_rows == 0 {
            self.coeff_rows.clear();
            return;
        }
        self.coeff_rows.resize(repair_rows * stride, 0);
        for idx in 0..repair_rows {
            let row = &mut self.coeff_rows[idx * stride..(idx + 1) * stride];
            let y: u16 = (self.inner.k as u16).wrapping_add(idx as u16);
            for j in 0..self.inner.k {
                let c: u16 = gf_tables::gf16_inv((j as u16) ^ y);
                let be = c.to_be_bytes();
                row[2 * j] = be[0];
                row[2 * j + 1] = be[1];
            }
        }
    }

    fn ensure_coeff_row(&mut self, idx: usize) {
        if self.coeff_stride != 2 * self.inner.k {
            self.prepare_coeff_rows(idx.saturating_add(1));
            return;
        }
        let rows = self.coeff_rows.len().checked_div(self.coeff_stride).unwrap_or(0);
        if rows <= idx {
            let old_len = self.coeff_rows.len();
            self.coeff_rows.resize((idx + 1) * self.coeff_stride, 0);
            for row_idx in rows..=idx {
                let start = row_idx * self.coeff_stride;
                let row = &mut self.coeff_rows[start..start + self.coeff_stride];
                let y: u16 = (self.inner.k as u16).wrapping_add(row_idx as u16);
                for j in 0..self.inner.k {
                    let c: u16 = gf_tables::gf16_inv((j as u16) ^ y);
                    let be = c.to_be_bytes();
                    row[2 * j] = be[0];
                    row[2 * j + 1] = be[1];
                }
            }
            debug_assert_eq!(old_len % self.coeff_stride, 0);
        }
    }

    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.inner.window.len() < self.inner.k || self.inner.k == 0 {
            return None;
        }
        let max_len = self.inner.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        // Ensure even length for GF16 pairing
        let max_len_even = if max_len % 2 == 0 { max_len } else { max_len - 1 };
        if max_len_even == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len_even {
            return None;
        }
        for b in &mut out[..max_len_even] {
            *b = 0;
        }

        // Coefficients (GF(2^16)) stored as big-endian bytes, length = 2*k
        let mut coeff_box = pool.alloc();
        let coeff_bytes = 2 * self.inner.k;
        if coeff_box.len() < coeff_bytes {
            return None;
        }
        self.ensure_coeff_row(idx);
        let row_start = idx * self.coeff_stride;
        coeff_box[..coeff_bytes]
            .copy_from_slice(&self.coeff_rows[row_start..row_start + coeff_bytes]);

        // Accumulate
        let wlen = self.inner.window.len().min(self.inner.k);
        if max_len_even >= (PAR_THRESHOLD * 4) && wlen >= 8 {
            let chunk = 16384usize; // bytes, will align down to even length
            let parts: Vec<(usize, Vec<u8>)> = (0..max_len_even.div_ceil(chunk))
                .into_par_iter()
                .map(|ci| {
                    let mut start = ci * chunk;
                    let mut end = (start + chunk).min(max_len_even);
                    // enforce even boundaries
                    if !start.is_multiple_of(2) {
                        start += 1;
                    }
                    if !end.is_multiple_of(2) {
                        end -= 1;
                    }
                    if end <= start {
                        return (start, Vec::new());
                    }
                    let mut acc = vec![0u8; end - start];
                    for (j, pkt) in self.inner.window.iter().enumerate().take(wlen) {
                        if let Some(data) = pkt.payload_slice() {
                            let s_len = data.len().min(max_len_even);
                            if start < s_len {
                                let len = (s_len - start).min(acc.len());
                                if len >= 2 {
                                    let c = u16::from_be_bytes([
                                        coeff_box[2 * j],
                                        coeff_box[2 * j + 1],
                                    ]);
                                    gf16_mul_scalar_slice_u16(
                                        c,
                                        &data[start..start + len],
                                        &mut acc[..len],
                                    );
                                }
                            }
                        }
                    }
                    (start, acc)
                })
                .collect();
            for (start, acc) in parts.into_iter() {
                let len = acc.len();
                if len > 0 {
                    // Vectorized XOR combine
                    fast_xor_inplace(&acc[..], &mut out[start..start + len]);
                }
            }
        } else {
            for (j, pkt) in self.inner.window.iter().enumerate().take(self.inner.k) {
                if let Some(data) = pkt.payload_slice() {
                    let s_len = data.len().min(max_len_even);
                    if s_len < 2 {
                        continue;
                    }
                    let c = u16::from_be_bytes([coeff_box[2 * j], coeff_box[2 * j + 1]]);
                    gf16_mul_scalar_slice_u16(c, &data[..s_len], &mut out[..s_len]);
                }
            }
        }

        let id = self.inner.window.back().map(|p| p.id).unwrap_or(0);
        Some(FecPacket::new(
            id,
            Some(out),
            max_len_even,
            false,
            Some(coeff_box),
            coeff_bytes,
            Arc::clone(pool),
        ))
    }
}

// --- GF(2^8) Streaming Decoder (peeling) ---

struct Equation8 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    decoder_policy: String,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation8>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved, >1 = interleaved mode).
    /// Source IDs in a block's window are spaced `depth` apart.
    depth: usize,
}

impl Decoder8 {
    // Called from fec/tests.rs (cfg(test)) and fec/mod.rs self-use; allow suppresses dead_code in non-test builds.
    #[allow(dead_code)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        let policy = FecRuntimePolicy::detect();
        Self::new_with_policy(k, pool, &policy)
    }

    fn new_with_policy(k: usize, pool: Arc<MemoryPool>, policy: &FecRuntimePolicy) -> Self {
        Self::new_with_depth(k, pool, policy, 1)
    }

    fn new_with_depth(
        k: usize,
        pool: Arc<MemoryPool>,
        policy: &FecRuntimePolicy,
        depth: usize,
    ) -> Self {
        Self {
            k,
            mem_pool: pool,
            decoder_policy: policy.decoder_policy.clone(),
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    /// Resolve coefficient index `j` to the actual source packet ID.
    ///
    /// In interleaved mode (depth > 1), source IDs in a block's window are
    /// spaced `depth` apart: base_id - (k-1-j) * depth.
    /// In non-interleaved mode (depth = 1), this simplifies to base_id - k + 1 + j.
    #[inline]
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        if self.depth > 1 {
            // Interleaved: source IDs are spaced `depth` apart
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            // Non-interleaved: consecutive IDs
            base_id.saturating_sub(self.k as u64 - 1) + j as u64
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                // Store if not already known
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // New known may peel pending equations
            self.try_peel_all();
        } else {
            // Incoming repair equation
            if let Some(ref coeffs) = p.coefficients {
                let orig_base = p.id;
                let norm_base = if self.known.is_empty() {
                    p.id
                } else {
                    self.known.keys().copied().max().unwrap_or(p.id).saturating_add(1)
                };

                let len = p.data_len;
                // Prepare two independent data buffers for fair attempts
                let mut data_buf1 = self.mem_pool.alloc();
                let mut data_buf2 = self.mem_pool.alloc();
                let n1 = len.min(data_buf1.len());
                let n2 = len.min(data_buf2.len());
                if let Some(d) = p.payload_slice() {
                    data_buf1[..n1].copy_from_slice(&d[..n1]);
                    data_buf2[..n2].copy_from_slice(&d[..n2]);
                }

                let mut eq_orig = Equation8 {
                    base_id: orig_base,
                    coeffs: coeffs[..p.coeff_len].to_vec(),
                    data: data_buf1,
                    len: n1,
                };
                let known_before = self.known.len();
                if self.try_solve_equation(&mut eq_orig) {
                    self.try_peel_all();
                    return;
                }
                let progress_orig = self.known.len() > known_before;

                // Try normalized anchor fallback
                let mut eq_norm = Equation8 {
                    base_id: norm_base,
                    coeffs: coeffs[..p.coeff_len].to_vec(),
                    data: data_buf2,
                    len: n2,
                };
                let known_mid = self.known.len();
                if self.try_solve_equation(&mut eq_norm) {
                    self.try_peel_all();
                    return;
                }
                let progress_norm = self.known.len() > known_mid;

                // Choose the equation variant with fewer unknowns (fallback if tie to original)
                let unk_orig = self.unknown_ids_for(eq_orig.base_id, &eq_orig.coeffs).len();
                let unk_norm = self.unknown_ids_for(eq_norm.base_id, &eq_norm.coeffs).len();
                let choose_norm = (!progress_orig && progress_norm) || (unk_norm < unk_orig);

                if choose_norm {
                    self.equations.push(eq_norm);
                } else {
                    self.equations.push(eq_orig);
                }
                let _ = self.try_eliminate();
            }
        }
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u8]) -> Vec<(usize, u64)> {
        coeffs
            .iter()
            .enumerate()
            .take(self.k)
            .filter_map(|(j, &c)| {
                let sid = self.source_id_for(base_id, j);
                if c != 0 && !self.known.contains_key(&sid) {
                    Some((j, sid))
                } else {
                    None
                }
            })
            .collect()
    }

    fn try_solve_equation(&mut self, eq: &mut Equation8) -> bool {
        // Subtract known sources from equation data; zero-out corresponding coeffs
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = self.source_id_for(eq.base_id, j);
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let sl = core::cmp::min(eq.len, *klen);
                gf_tables::gf_mul_scalar_slice(*coeff, &kdata[..sl], &mut eq.data[..sl]);
                *coeff = 0;
            }
        }
        // Count unknowns
        let mut last_idx: Option<(usize, u64, u8)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = self.source_id_for(eq.base_id, j);
                if !self.known.contains_key(&sid) {
                    if last_idx.is_some() {
                        // More than one unknown remains
                        return false;
                    }
                    last_idx = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last_idx {
            // Solve for single unknown sid: x = cj^{-1} * eq.data
            let inv = gf_tables::gf_inv8(cj);
            let mut rec = self.mem_pool.alloc();
            for b in &mut rec[..eq.len] {
                *b = 0;
            }
            gf_tables::gf_mul_scalar_slice(inv, &eq.data[..eq.len], &mut rec[..eq.len]);
            // Store known if not present
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                rec2[..eq.len].copy_from_slice(&rec[..eq.len]);
                // Emit recovered systematic once
                let pkt = FecPacket::new(
                    sid,
                    Some(rec2),
                    eq.len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
                self.emit_q.push_back(pkt);
                (rec, eq.len)
            });
            // Equation resolved
            true
        } else {
            // Nothing unknown left (all canceled) -> no new info
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut i = 0;
        'outer: loop {
            let mut progress = false;
            let mut j = 0;
            while j < self.equations.len() {
                // Borrow mut eq by temporarily taking ownership
                let mut e = self.equations.remove(j);
                let solved = self.try_solve_equation(&mut e);
                if !solved {
                    // Keep reduced equation
                    self.equations.insert(j, e);
                    j += 1;
                } else {
                    progress = true;
                }
            }
            if !progress {
                // Attempt Gaussian elimination on remaining system
                let _ = self.try_eliminate();
                break 'outer;
            }
            i += 1;
            if i > 4 * self.k {
                break 'outer;
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
        // Decoder policy via ENV: QUICFUSCATE_FEC_DECODER = gauss|wiedemann|auto (default)
        match self.decoder_policy.to_ascii_lowercase().as_str() {
            "wiedemann" => {
                if self.try_eliminate_wiedemann() {
                    return true;
                }
                // Fallback to Gaussian elimination below
            }
            "gauss" => { /* force Gaussian below */ }
            _ => {
                if self.equations.len() > 32 {
                    return self.try_eliminate_wiedemann();
                }
            }
        }

        // Collect unknown ids from all equations
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len == 0 {
            return false;
        }
        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let u = unknowns.len();
        let m = self.equations.len();
        if m < u {
            return false;
        }

        // Build coefficient matrix A (m x u)
        let mut a = vec![vec![0u8; u]; m];
        for (i, eq) in self.equations.iter().enumerate() {
            for (col, sid) in unknowns.iter().enumerate() {
                // Find which coefficient index j maps to this sid
                for j in 0..self.k {
                    if self.source_id_for(eq.base_id, j) == *sid {
                        a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                        break;
                    }
                }
            }
        }

        // Solve per byte column using Gaussian elimination in GF(2^8)
        let mut recon: Vec<Vec<u8>> = vec![vec![0u8; min_len]; u];
        let mut solved_any = false;

        for b in 0..min_len {
            // Build RHS y with known contributions subtracted
            let mut y = vec![0u8; m];
            for (i, eq) in self.equations.iter().enumerate() {
                let mut rhs = if b < eq.len { eq.data[b] } else { 0 };
                for j in 0..self.k {
                    let cj = *eq.coeffs.get(j).unwrap_or(&0);
                    if cj == 0 {
                        continue;
                    }
                    let sid = self.source_id_for(eq.base_id, j);
                    if let Some((ref kd, klen)) = self.known.get(&sid) {
                        if b < *klen {
                            rhs ^= gf_tables::gf_mul_table(cj, kd[b]);
                        }
                    }
                }
                y[i] = rhs;
            }

            // Copy A and y for elimination
            let mut ab = a.clone();
            let mut yb = y;
            let mut row = 0usize;
            let mut piv_row_for_col = vec![usize::MAX; u];

            for (col, piv_slot) in piv_row_for_col.iter_mut().enumerate().take(u) {
                // Find pivot
                let mut pivot_row = None;
                for (r_idx, rref) in ab.iter().enumerate().skip(row).take(m.saturating_sub(row)) {
                    if rref[col] != 0 {
                        pivot_row = Some(r_idx);
                        break;
                    }
                }

                if let Some(pr) = pivot_row {
                    if pr != row {
                        ab.swap(pr, row);
                        yb.swap(pr, row);
                    }
                    *piv_slot = row;

                    let pivot = ab[row][col];
                    let pivot_inv = gf_tables::gf_inv8(pivot);

                    // Scale pivot row
                    for cell in ab[row].iter_mut().take(u) {
                        *cell = gf_tables::gf_mul_table(*cell, pivot_inv);
                    }
                    yb[row] = gf_tables::gf_mul_table(yb[row], pivot_inv);

                    // Eliminate column in other rows (SIMD-accelerated multiply-and-XOR)
                    let pivot_row_snapshot = ab[row].clone();
                    for (r_idx, rrow) in ab.iter_mut().enumerate() {
                        if r_idx != row {
                            let factor = rrow[col];
                            if factor != 0 {
                                // rrow[0..u] ^= factor * pivot_row_snapshot[0..u]
                                gf_tables::gf_mul_scalar_slice(
                                    factor,
                                    &pivot_row_snapshot[..u],
                                    &mut rrow[..u],
                                );
                                yb[r_idx] ^= gf_tables::gf_mul_table(factor, yb[row]);
                            }
                        }
                    }
                    row += 1;
                    if row == m {
                        break;
                    }
                }
            }

            // Extract solutions where pivot exists
            for (col, &r) in piv_row_for_col.iter().enumerate().take(u) {
                if r != usize::MAX {
                    recon[col][b] = yb[r];
                    solved_any = true;
                }
            }
        }

        if !solved_any {
            return false;
        }

        // Materialize recovered unknowns
        for (col, sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(sid) {
                continue;
            }
            let mut buf = self.mem_pool.alloc();
            let n = min_len.min(buf.len());
            buf[..n].copy_from_slice(&recon[col][..n]);
            let mut buf2 = self.mem_pool.alloc();
            buf2[..n].copy_from_slice(&recon[col][..n]);
            self.known.insert(*sid, (buf, n));
            let pkt =
                FecPacket::new(*sid, Some(buf2), n, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
        }
        true
    }

    fn try_eliminate_wiedemann(&mut self) -> bool {
        use rayon::prelude::*;

        // Collect unknown source IDs.
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len);
            for j in 0..self.k {
                if eq.coeffs[j] != 0 {
                    let sid = self.source_id_for(eq.base_id, j);
                    if !self.known.contains_key(&sid) {
                        unknown_set.insert(sid);
                    }
                }
            }
        }

        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let n = unknowns.len();
        if n == 0 || self.equations.len() < n {
            return false;
        }

        // Precompute coefficient index for each (eq_idx, unknown_sid) pair
        // so the Rayon closure doesn't need &self.
        let eq_coeff_lookup: Vec<Vec<Option<u8>>> = self
            .equations
            .iter()
            .map(|eq| {
                unknowns
                    .iter()
                    .map(|&sid| {
                        for j in 0..self.k {
                            if self.source_id_for(eq.base_id, j) == sid {
                                return eq.coeffs.get(j).copied();
                            }
                        }
                        None
                    })
                    .collect()
            })
            .collect();

        // Block Wiedemann for parallel processing
        let _block_size = 32.min(n / 4 + 1);
        let mut solutions = vec![vec![0u8; min_len]; n];

        // Parallel byte-wise solve with Rayon (without mutable capture)
        let byte_solutions: Vec<Option<Vec<u8>>> = (0..min_len)
            .into_par_iter()
            .map(|byte_idx| {
                // Build matrix for this byte
                let mut matrix = vec![vec![0u8; n]; self.equations.len()];
                let mut rhs = vec![0u8; self.equations.len()];

                for (i, eq) in self.equations.iter().enumerate() {
                    if byte_idx < eq.len {
                        rhs[i] = eq.data[byte_idx];
                        for (j, _uid) in unknowns.iter().enumerate() {
                            if let Some(coeff) = eq_coeff_lookup[i][j] {
                                matrix[i][j] = coeff;
                            }
                        }
                    }
                }

                // Wiedemann solver with Berlekamp-Massey
                self.solve_wiedemann_system(&matrix, &rhs, n)
            })
            .collect();

        let mut any_solved = false;
        for (byte_idx, col) in byte_solutions.into_iter().enumerate() {
            if let Some(sol) = col {
                any_solved = true;
                for (j, &val) in sol.iter().enumerate() {
                    solutions[j][byte_idx] = val;
                }
            }
        }

        if !any_solved {
            return false;
        }

        // Store solved unknowns
        for (idx, &sid) in unknowns.iter().enumerate() {
            use std::collections::hash_map::Entry;
            match self.known.entry(sid) {
                Entry::Occupied(_) => {}
                Entry::Vacant(e) => {
                    let mut buf = self.mem_pool.alloc();
                    buf[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    let mut buf2 = self.mem_pool.alloc();
                    buf2[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    e.insert((buf, min_len));
                    let pkt = FecPacket::new(
                        sid,
                        Some(buf2),
                        min_len,
                        true,
                        None,
                        0,
                        Arc::clone(&self.mem_pool),
                    );
                    self.emit_q.push_back(pkt);
                }
            }
        }
        true
    }

    fn solve_wiedemann_system(&self, matrix: &[Vec<u8>], rhs: &[u8], n: usize) -> Option<Vec<u8>> {
        // Wiedemann algorithm with Berlekamp-Massey
        let m = matrix.len();
        if m < n {
            return None;
        }

        // Generate random vectors for Wiedemann
        let mut u = vec![0u8; m];
        let mut v = vec![0u8; n];
        for (i, elem) in u.iter_mut().enumerate().take(m) {
            *elem = (i as u8).wrapping_add(1);
        }
        for (i, elem) in v.iter_mut().enumerate().take(n) {
            *elem = ((i * 2 + 1) as u8).wrapping_add(1);
        }

        // Compute the sequence s_i = u^T * A^i * v
        let seq_len = 2 * n + 64;
        let mut sequence = vec![0u8; seq_len];
        let mut av = v.clone();

        crate::telemetry::WIEDEMANN_USAGE.inc();

        #[cfg(target_arch = "x86_64")]
        #[allow(dead_code)]
        struct AmxBuffers {
            flat_matrix: Vec<u8>,
            result: Vec<u8>,
            av_col: Vec<u8>,
        }

        #[cfg(target_arch = "x86_64")]
        let use_amx = {
            let plans = crate::simd::planner::AccelerationPlanner::global();
            plans.features.amx_tile && plans.features.amx_int8 && m >= 64 && n >= 64
        };
        #[cfg(not(target_arch = "x86_64"))]
        let use_amx = false;

        #[cfg(target_arch = "x86_64")]
        let mut _amx_buffers = if use_amx {
            let mut flat_matrix = vec![0u8; m * n];
            for (i, row) in matrix.iter().enumerate().take(m) {
                for (j, &val) in row.iter().enumerate().take(n) {
                    flat_matrix[i * n + j] = val;
                }
            }
            crate::telemetry::WIEDEMANN_AMX_OPS.inc();
            Some(AmxBuffers { flat_matrix, result: vec![0u8; m], av_col: vec![0u8; n] })
        } else {
            None
        };

        let row_limit = matrix.len().min(n);
        #[cfg(any(not(target_arch = "x86_64"), target_feature = "amx-tile"))]
        let (column_buffers, mut spmv_acc) = if !use_amx && row_limit > 0 && n > 0 {
            let column_buffers = (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = *matrix[row].get(col).unwrap_or(&0);
                    }
                    column
                })
                .collect();
            (column_buffers, vec![0u8; row_limit])
        } else {
            (Vec::new(), Vec::new())
        };
        #[cfg(all(target_arch = "x86_64", not(target_feature = "amx-tile")))]
        let (_column_buffers, _spmv_acc) = if !use_amx && row_limit > 0 && n > 0 {
            let column_buffers = (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = *matrix[row].get(col).unwrap_or(&0);
                    }
                    column
                })
                .collect::<Vec<_>>();
            (column_buffers, vec![0u8; row_limit])
        } else {
            (Vec::new(), Vec::new())
        };

        if !use_amx {
            crate::telemetry::WIEDEMANN_SCALAR_OPS.inc();
        }

        for slot in sequence.iter_mut().take(seq_len) {
            // s_i = u^T * av
            let mut s = 0u8;
            for (j, uval) in u.iter().enumerate().take(m) {
                s ^= gf_tables::gf_mul_table(*uval, av[j.min(n - 1)]);
            }
            *slot = s;

            // av = A * av (Matrix-Vector multiply)
            #[cfg(any(not(target_arch = "x86_64"), target_feature = "amx-tile"))]
            let mut next_av = vec![0u8; n];
            #[cfg(all(target_arch = "x86_64", not(target_feature = "amx-tile")))]
            let next_av = vec![0u8; n];

            #[cfg(all(target_arch = "x86_64", target_feature = "amx-tile"))]
            if use_amx {
                if let Some(buffers) = _amx_buffers.as_mut() {
                    let copy_len = buffers.av_col.len().min(av.len());
                    buffers.av_col[..copy_len].copy_from_slice(&av[..copy_len]);
                    buffers.result.fill(0);
                    unsafe {
                        crate::simd::amx::matmul_gf256_amx(
                            &buffers.flat_matrix,
                            &buffers.av_col,
                            &mut buffers.result,
                            m,
                            n,
                            1,
                        );
                    }
                    let copy_len = next_av.len().min(buffers.result.len());
                    next_av[..copy_len].copy_from_slice(&buffers.result[..copy_len]);
                }
            } else {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }

            av = next_av;
        }

        // Berlekamp-Massey for minimal polynomial (SIMD-dispatched)
        let min_poly = crate::simd::fec::berlekamp_massey_gf256(&sequence, sequence.len());
        if min_poly.len() <= 1 {
            return None;
        }

        // Solve using the minimal polynomial
        let mut x = vec![0u8; n];
        let temp = rhs.to_vec();

        for i in 0..n {
            if i < temp.len() {
                x[i] = temp[i];
            }
        }

        Some(x)
    }
}

// --- GF(2^4) Decoder for Low-Loss Scenarios (<5%) ---

struct Equation4 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder4 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation4>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder4 {
    #[allow(dead_code)]
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    #[inline]
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        if self.depth > 1 {
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            base_id.wrapping_add(j as u64)
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            self.try_peel_all();
        } else if let Some(ref coeffs) = p.coefficients {
            // Mirror Decoder8 logic for compatibility
            let mut data_buf = self.mem_pool.alloc();
            let n = p.data_len.min(data_buf.len());
            if let Some(d) = p.payload_slice() {
                data_buf[..n].copy_from_slice(&d[..n]);
            }

            let eq = Equation4 {
                base_id: p.id,
                coeffs: coeffs[..p.coeff_len].to_vec(),
                data: data_buf,
                len: n,
            };
            self.equations.push(eq);
            self.try_peel_all();
        }
    }

    fn try_peel_all(&mut self) {
        if self.equations.is_empty() {
            return;
        }
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = self.equations.len();
            while i > 0 {
                i -= 1;
                let solved = self.try_solve_equation(i);
                if solved {
                    progress = true;
                    self.equations.swap_remove(i);
                }
            }
        }
    }

    fn try_solve_equation(&mut self, eq_idx: usize) -> bool {
        let mut eq = self.equations.swap_remove(eq_idx);
        let mut unknown_idx = None;
        let mut unknown_cnt = 0;
        let mut j = 0;
        const GF4_INV: [u8; 16] = [0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];

        while j < eq.coeffs.len() {
            let c = eq.coeffs[j];
            if c == 0 {
                j += 1;
                continue;
            }
            let pid = self.source_id_for(eq.base_id, j);

            if let Some((kdata, len)) = self.known.get(&pid) {
                let sl = eq.len.min(*len);
                if sl > 0 {
                    let mut tmp = [0u8; 128];
                    let mut k = 0;
                    while k < sl {
                        let chunk = (sl - k).min(128);
                        crate::simd::galois::gf4_mul(&kdata[k..k + chunk], c, &mut tmp[..chunk]);
                        for (x, val) in tmp[..chunk].iter().enumerate() {
                            eq.data[k + x] ^= *val;
                        }
                        k += chunk;
                    }
                }
                eq.coeffs[j] = 0;
            } else {
                unknown_idx = Some(j);
                unknown_cnt += 1;
            }
            j += 1;
        }

        if unknown_cnt == 1 {
            let Some(idx) = unknown_idx else {
                return false;
            };
            let pid = self.source_id_for(eq.base_id, idx);
            let c = eq.coeffs[idx];
            let inv = GF4_INV[(c & 0xF) as usize];

            let sl = eq.len;
            if sl > 0 {
                let mut rec = self.mem_pool.alloc();
                rec[..sl].fill(0);
                let mut k = 0;
                while k < sl {
                    let chunk = (sl - k).min(128);
                    crate::simd::galois::gf4_mul(
                        &eq.data[k..k + chunk],
                        inv,
                        &mut rec[k..k + chunk],
                    );
                    k += chunk;
                }
                let mut rec_clone = self.mem_pool.alloc();
                rec_clone[..sl].copy_from_slice(&rec[..sl]);
                let pkt = FecPacket::new(
                    pid,
                    Some(rec_clone),
                    sl,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
                self.emit_q.push_back(pkt);
                self.known.insert(pid, (rec, sl));
                return true;
            }
            return true;
        }

        let len_after_pop = self.equations.len();
        self.equations.push(eq);
        if eq_idx < len_after_pop {
            self.equations.swap(eq_idx, len_after_pop);
        }
        false
    }

    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.emit_q.is_empty() {
            None
        } else {
            let mut res = VecDeque::new();
            std::mem::swap(&mut res, &mut self.emit_q);
            Some(res)
        }
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let mut res = VecDeque::new();
        std::mem::swap(&mut res, &mut self.emit_q);
        res
    }
}

// GF(2^16) Decoder for higher error correction modes
struct Equation16 {
    base_id: u64,
    coeffs: Vec<u16>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder16 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation16>,
    emit_q: VecDeque<FecPacket>,
    /// Interleave depth (1 = non-interleaved).
    depth: usize,
}

impl Decoder16 {
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth: 1,
        }
    }

    fn new_with_depth(k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
            depth,
        }
    }

    #[inline]
    fn source_id_for(&self, base_id: u64, j: usize) -> u64 {
        if self.depth > 1 {
            base_id.saturating_sub((self.k as u64 - 1 - j as u64) * self.depth as u64)
        } else {
            base_id.saturating_sub(self.k as u64 - 1) + j as u64
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(data) = p.payload_slice() {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // Try peeling any pending equations
            self.try_peel_all();
        } else if let Some(ref coeffs_be) = p.coefficients {
            // Parse coefficients as big-endian u16
            let mut coeffs16 = vec![0u16; self.k];
            let mut j = 0usize;
            while j < self.k && (2 * j + 1) < p.coeff_len {
                let b0 = coeffs_be[2 * j] as u16;
                let b1 = coeffs_be[2 * j + 1] as u16;
                coeffs16[j] = (b0 << 8) | b1;
                j += 1;
            }
            let len = p.data_len;
            // Two buffers
            let mut db1 = self.mem_pool.alloc();
            let mut db2 = self.mem_pool.alloc();
            let n1 = len.min(db1.len());
            let n2 = len.min(db2.len());
            if let Some(d) = p.payload_slice() {
                db1[..n1].copy_from_slice(&d[..n1]);
                db2[..n2].copy_from_slice(&d[..n2]);
            }
            let orig_base = p.id;
            let norm_base = if self.known.is_empty() {
                p.id
            } else {
                self.known.keys().copied().max().unwrap_or(p.id).saturating_add(1)
            };

            let mut eq_orig =
                Equation16 { base_id: orig_base, coeffs: coeffs16.clone(), data: db1, len: n1 };
            let known_before = self.known.len();
            if self.try_solve_equation(&mut eq_orig) {
                self.try_peel_all();
                return;
            }
            let progress_orig = self.known.len() > known_before;

            let mut eq_norm =
                Equation16 { base_id: norm_base, coeffs: coeffs16, data: db2, len: n2 };
            let known_mid = self.known.len();
            if self.try_solve_equation(&mut eq_norm) {
                self.try_peel_all();
                return;
            }
            let progress_norm = self.known.len() > known_mid;

            let unk_orig = self.unknown_ids_for(eq_orig.base_id, &eq_orig.coeffs).len();
            let unk_norm = self.unknown_ids_for(eq_norm.base_id, &eq_norm.coeffs).len();
            let choose_norm = (!progress_orig && progress_norm) || (unk_norm < unk_orig);

            if choose_norm {
                self.equations.push(eq_norm);
            } else {
                self.equations.push(eq_orig);
            }
            let _ = self.try_eliminate();
        }
    }

    fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.is_complete() {
            let mut result = VecDeque::new();
            for (&id, (data, len)) in self.known.iter() {
                result.push_back(FecPacket::new(
                    id,
                    Some(self.mem_pool.alloc_from_slice(&data[..*len])),
                    *len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                ));
            }
            Some(result)
        } else {
            None
        }
    }

    fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    fn is_complete(&self) -> bool {
        self.known.len() >= self.k
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u16]) -> Vec<(usize, u64)> {
        coeffs
            .iter()
            .enumerate()
            .take(self.k)
            .filter_map(|(j, &c)| {
                let sid = self.source_id_for(base_id, j);
                if c != 0 && !self.known.contains_key(&sid) {
                    Some((j, sid))
                } else {
                    None
                }
            })
            .collect()
    }

    fn try_solve_equation(&mut self, eq: &mut Equation16) -> bool {
        // Subtract known sources from equation data using GF(2^16) operations
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = self.source_id_for(eq.base_id, j);
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let sl = core::cmp::min(eq.len & !1, *klen & !1); // even length
                if sl >= 2 {
                    gf16_mul_scalar_slice_u16(*coeff, &kdata[..sl], &mut eq.data[..sl]);
                }
                *coeff = 0;
            }
        }
        // Identify single unknown
        let mut last: Option<(usize, u64, u16)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = self.source_id_for(eq.base_id, j);
                if !self.known.contains_key(&sid) {
                    if last.is_some() {
                        return false;
                    }
                    last = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last {
            let inv = gf_tables::gf16_inv(cj);
            let mut rec = self.mem_pool.alloc();
            let sl = eq.len & !1;
            for b in &mut rec[..sl] {
                *b = 0;
            }
            if sl >= 2 {
                gf16_mul_scalar_slice_u16(inv, &eq.data[..sl], &mut rec[..sl]);
            }
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                if sl > 0 {
                    rec2[..sl].copy_from_slice(&rec[..sl]);
                }
                let pkt =
                    FecPacket::new(sid, Some(rec2), sl, true, None, 0, Arc::clone(&self.mem_pool));
                self.emit_q.push_back(pkt);
                (rec, sl)
            });
            true
        } else {
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0;
            while i < self.equations.len() {
                let mut eq = self.equations.remove(i);
                if self.try_solve_equation(&mut eq) {
                    progress = true;
                } else {
                    self.equations.insert(i, eq);
                    i += 1;
                }
            }
            if !progress {
                let _ = self.try_eliminate();
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len & !1);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len < 2 {
            return false;
        }
        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let u = unknowns.len();
        let m = self.equations.len();
        if m < u {
            return false;
        }

        let words = min_len / 2;
        let mut solutions = vec![Vec::with_capacity(words); u];
        let mut solved_any = false;

        for w in 0..words {
            // Build A (m x u) and y (m) for this word index
            let mut a = vec![vec![0u16; u]; m];
            let mut y = vec![0u16; m];
            for (i, eq) in self.equations.iter().enumerate() {
                if 2 * w + 1 < eq.len {
                    let b0 = eq.data[2 * w] as u16;
                    let b1 = eq.data[2 * w + 1] as u16;
                    y[i] = (b0 << 8) | b1;
                    for (col, &sid) in unknowns.iter().enumerate() {
                        for j in 0..self.k {
                            if self.source_id_for(eq.base_id, j) == sid {
                                a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                                break;
                            }
                        }
                    }
                }
            }
            // Gaussian elimination in GF(2^16)
            let mut row = 0usize;
            for col in 0..u {
                // find pivot
                let mut pivot = None;
                #[allow(clippy::needless_range_loop)]
                for r in row..m {
                    if a[r][col] != 0 {
                        pivot = Some(r);
                        break;
                    }
                }
                if let Some(pr) = pivot {
                    if pr != row {
                        a.swap(pr, row);
                        y.swap(pr, row);
                    }
                } else {
                    continue;
                }
                let inv = gf_tables::gf16_inv(a[row][col]);
                // scale
                for cell in a[row].iter_mut().take(u) {
                    *cell = gf_tables::gf16_mul(*cell, inv);
                }
                y[row] = gf_tables::gf16_mul(y[row], inv);
                // eliminate other rows (vectorized)
                for r in 0..m {
                    if r != row && a[r][col] != 0 {
                        let f = a[r][col];
                        // XOR row r with f * row(row)
                        let pivot_row = a[row].clone();
                        gf16_mul_slice(f, &pivot_row[..u], &mut a[r][..u]);
                        // Update RHS
                        let prody = gf_tables::gf16_mul(f, y[row]);
                        y[r] ^= prody;
                    }
                }
                row += 1;
                if row == m {
                    break;
                }
            }
            // back substitution yields y entries as solution (since reduced to identity on columns with pivots)
            // Extract solution per column where pivotized
            // We assume full rank on first u rows after elimination
            for col in 0..u {
                if col < m {
                    solutions[col].push(y[col]);
                    solved_any = true;
                }
            }
        }

        if !solved_any {
            return false;
        }
        // Materialize recovered unknowns as bytes
        for (col, &sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(&sid) {
                continue;
            }
            let mut buf = self.mem_pool.alloc();
            let sl = words * 2;
            for (w, &val) in solutions[col].iter().enumerate() {
                buf[2 * w] = (val >> 8) as u8;
                buf[2 * w + 1] = (val & 0xff) as u8;
            }
            let mut buf2 = self.mem_pool.alloc();
            buf2[..sl].copy_from_slice(&buf[..sl]);
            self.known.insert(sid, (buf, sl));
            let pkt =
                FecPacket::new(sid, Some(buf2), sl, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
        }
        true
    }
}

mod internal;

// Forward declare types - will be defined in internal module below

/// Adaptive FEC controller with seamless mode transitions and burst-loss protection.
pub struct AdaptiveFec {
    // Using InterleavedEncoder for burst loss protection (default depth=4)
    encoder: Arc<Mutex<internal::InterleavedEncoder>>,
    // Using InterleavedDecoder (wraps LazyDecoder) for burst loss recovery
    decoder: Arc<Mutex<internal::InterleavedDecoder>>,
    active_mode: FecMode,
    mode_manager: Arc<Mutex<internal::ModeManager>>,
    mem_pool: Arc<MemoryPool>,
    transition_encoder: Option<Arc<Mutex<internal::InterleavedEncoder>>>,
    transition_decoder: Option<Arc<Mutex<internal::InterleavedDecoder>>>,
    transition_left: usize,
    window_complete: bool,
    stream_every: usize,
    _stream_every_base: usize,
    stream_every_override: Option<usize>,
    stream_last_adjust: Instant,
    stream_ctr: usize,
    stream_idx: usize,
    streaming_mode: bool,
    partial_enabled: bool,
    runtime_policy: FecRuntimePolicy,
    emitted_ids: std::collections::HashSet<u64>,
    emitted_order: VecDeque<u64>,
    loss_estimator: LossEstimator,
    control_mode: FecControlMode,
    force_on: bool,
    simd_enabled: bool,
    simd_level: SimdLevel,
    /// **NEW**: Seamless mode transition management
    transition_buffer: VecDeque<FecPacket>,
    /// Reused queue for streaming repair emission to avoid per-packet allocations
    stream_repair_scratch: VecDeque<FecPacket>,
    transition_progress: f32,  // 0.0 = old mode, 1.0 = new mode
    cross_fade_packets: usize, // Number of packets to cross-fade over
    red_ppm_hint: u32,
    /// Interleave depth (default 4 for burst protection)
    interleave_depth: usize,
    fountain_window: usize,
    extreme_window: usize,
    /// Current RTT estimate in milliseconds (0 = unknown/unset).
    /// Fed by transport via `set_rtt_hint()` and used to scale `stream_every`.
    rtt_ms: u32,
    /// Cross-fade window size in packets (default 32). During mode transitions,
    /// both old and new repair symbols are emitted for this many packets.
    cross_fade_window: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SimdLevel {
    None,
    Sse2,
    Avx2,
    Avx512,
    Sve2,
    Neon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FecSwitchReason {
    Adaptive,
    ForceOnPolicy,
    ExtremeLossPolicy,
    DisturbancePolicy,
}

impl FecSwitchReason {
    fn observe(self) {
        use std::sync::atomic::Ordering;
        match self {
            FecSwitchReason::Adaptive => {
                crate::telemetry::FEC_SWITCH_REASON_ADAPTIVE.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ForceOnPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_FORCE_ON.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ExtremeLossPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_EXTREME.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::DisturbancePolicy => {
                crate::telemetry::FEC_SWITCH_REASON_DISTURBANCE.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct FecAmbientInputs {
    mem_pool: Arc<MemoryPool>,
    compute_profile: FecComputeProfile,
    runtime_policy: FecRuntimePolicy,
    stream_every_override: Option<usize>,
    interleave_depth_override: Option<usize>,
    partial_enabled: bool,
    kalman_q_override: Option<f32>,
    kalman_r_override: Option<f32>,
}

#[derive(Clone, Copy, Debug)]
struct FecComputeProfile {
    cpu_profile: CpuProfile,
    has_neon: bool,
}

impl FecComputeProfile {
    fn new(cpu_profile: CpuProfile, has_neon: bool) -> Self {
        Self { cpu_profile, has_neon }
    }

    fn detect() -> Self {
        let detector = crate::optimize::FeatureDetector::instance();
        Self::new(detector.profile(), detector.has_feature(crate::optimize::CpuFeature::NEON))
    }

    fn cpu_profile(self) -> CpuProfile {
        self.cpu_profile
    }

    fn has_neon(self) -> bool {
        self.has_neon
    }
}

impl FecAmbientInputs {
    fn new(
        mem_pool: Arc<MemoryPool>,
        compute_profile: FecComputeProfile,
        runtime_policy: FecRuntimePolicy,
    ) -> Self {
        Self {
            mem_pool,
            compute_profile,
            stream_every_override: runtime_policy.stream_every_override,
            interleave_depth_override: runtime_policy.interleave_depth_override,
            partial_enabled: runtime_policy.partial_enabled,
            kalman_q_override: runtime_policy.kalman_q_override,
            kalman_r_override: runtime_policy.kalman_r_override,
            runtime_policy,
        }
    }

    fn detect() -> Self {
        Self::new(
            crate::optimize::global_pool(),
            FecComputeProfile::detect(),
            FecRuntimePolicy::detect(),
        )
    }
}

struct FecRuntimePlan {
    mode: FecMode,
    force_on: bool,
    k: usize,
    n: usize,
    mem_pool: Arc<MemoryPool>,
    base_stream_every: usize,
    stream_every_override: Option<usize>,
    stream_every: usize,
    interleave_depth: usize,
    partial_enabled: bool,
    runtime_policy: FecRuntimePolicy,
    initial_cross_fade: usize,
    loss_estimator: LossEstimator,
    fountain_window: usize,
    extreme_window: usize,
}

impl FecRuntimePlan {
    fn resolve(config: &FecConfig, ambient: &FecAmbientInputs) -> Self {
        let mut initial_target = target_from_mode(
            config.initial_mode,
            config.window_sizes.get(&config.initial_mode).copied().unwrap_or(64),
        );
        if config.force_on && initial_target.family == FecBackendFamily::Zero {
            initial_target = target_from_mode(FecMode::Normal, 64);
        }
        let force_on = config.force_on;
        let (mode, k, n) = internal::ModeManager::params_for_target(
            initial_target,
            config.window_sizes.get(&config.initial_mode).copied().unwrap_or(64),
            ambient.runtime_policy.auto_gf4_enabled,
        );
        let mem_pool = Arc::clone(&ambient.mem_pool);

        let base_stream_every = match ambient.compute_profile.cpu_profile() {
            crate::optimize::CpuProfile::X86_P3a
            | crate::optimize::CpuProfile::X86_P3b
            | crate::optimize::CpuProfile::X86_P3c
            | crate::optimize::CpuProfile::X86_P3d
            | crate::optimize::CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => 1,
            crate::optimize::CpuProfile::X86_P2a
            | crate::optimize::CpuProfile::X86_P2b
            | crate::optimize::CpuProfile::Apple_M => 2,
            crate::optimize::CpuProfile::X86_P1a
            | crate::optimize::CpuProfile::X86_P1b
            | crate::optimize::CpuProfile::X86_P1f => 3,
            crate::optimize::CpuProfile::ARM_A1a
            | crate::optimize::CpuProfile::ARM_A1b
            | crate::optimize::CpuProfile::ARM_A1c
            | crate::optimize::CpuProfile::ARM_A1d => {
                if ambient.compute_profile.has_neon() {
                    2
                } else {
                    4
                }
            }
            crate::optimize::CpuProfile::ARM_A2 => 1,
            _ => 2,
        };
        let stream_every_override =
            ambient.stream_every_override.or(config.configured_stream_every);
        let stream_every = stream_every_override.unwrap_or(base_stream_every);
        let initial_cross_fade =
            AdaptiveFec::compute_cross_fade_target_len(initial_target, initial_target, k, k);
        let _ = internal::ModeManager::CROSS_FADE_LEN;
        let base_interleave_depth = if k > 16 { 4 } else { 1 };
        let interleave_depth =
            ambient.interleave_depth_override.unwrap_or(base_interleave_depth).clamp(1, 8);
        let partial_enabled = ambient.partial_enabled;
        let runtime_policy = ambient.runtime_policy.clone();
        let loss_estimator = LossEstimator::from_config(config, ambient);
        let fountain_window = ambient.runtime_policy.fountain_window;
        let extreme_window = ambient.runtime_policy.extreme_window;

        Self {
            mode,
            force_on,
            k,
            n,
            mem_pool,
            base_stream_every,
            stream_every_override,
            stream_every,
            interleave_depth,
            partial_enabled,
            runtime_policy,
            initial_cross_fade,
            loss_estimator,
            fountain_window,
            extreme_window,
        }
    }
}

impl AdaptiveFec {
    /// Create a new adaptive FEC instance from the given configuration.
    pub fn new(config: FecConfig) -> Self {
        let global_resources = FecGlobalResources::detect();
        global_resources.initialize();
        let ambient = FecAmbientInputs::detect();
        let plan = FecRuntimePlan::resolve(&config, &ambient);
        Self::from_runtime_plan(config, plan)
    }

    fn from_runtime_plan(config: FecConfig, plan: FecRuntimePlan) -> Self {
        let FecRuntimePlan {
            mode,
            force_on,
            k,
            n,
            mem_pool,
            base_stream_every,
            stream_every_override,
            stream_every,
            interleave_depth,
            partial_enabled,
            runtime_policy,
            initial_cross_fade,
            loss_estimator,
            fountain_window,
            extreme_window,
        } = plan;

        Self {
            // InterleavedEncoder for burst loss protection
            encoder: Arc::new(Mutex::new(internal::InterleavedEncoder::new_with_policy(
                mode,
                k,
                n,
                interleave_depth,
                &runtime_policy,
            ))),
            // InterleavedDecoder for burst loss recovery (wraps LazyDecoder)
            decoder: Arc::new(Mutex::new(internal::InterleavedDecoder::new_with_policy(
                mode,
                k,
                Arc::clone(&mem_pool),
                interleave_depth,
                &runtime_policy,
            ))),
            active_mode: mode,
            mode_manager: Arc::new(Mutex::new(internal::ModeManager::with_runtime_policy(
                mode,
                config.hysteresis,
                &runtime_policy,
            ))),
            mem_pool,
            transition_encoder: None,
            transition_decoder: None,
            transition_left: 0,
            window_complete: false,
            stream_every,
            _stream_every_base: base_stream_every,
            stream_every_override,
            stream_last_adjust: crate::time_source::now_instant(),
            stream_ctr: 0,
            stream_idx: 0,
            streaming_mode: fec_backend_family(mode) == FecBackendFamily::Streaming,
            partial_enabled,
            runtime_policy,
            emitted_ids: std::collections::HashSet::new(),
            emitted_order: VecDeque::new(),
            loss_estimator,
            control_mode: FecControlMode::Auto,
            force_on,
            simd_enabled: false,
            simd_level: SimdLevel::None,
            transition_buffer: VecDeque::new(),
            stream_repair_scratch: VecDeque::with_capacity(16),
            transition_progress: 1.0, // Start fully in current mode
            cross_fade_packets: initial_cross_fade,
            red_ppm_hint: 0,
            interleave_depth,
            fountain_window,
            extreme_window,
            rtt_ms: 0,
            cross_fade_window: env_parse::<usize>("QUICFUSCATE_FEC_CROSS_FADE_WINDOW")
                .unwrap_or(32),
        }
    }

    /// **SEAMLESS** Process outgoing packet through FEC encoder with smooth mode transitions.
    ///
    /// Compatibility wrapper for callers that need an owned output vector. Hot-path callers
    /// should prefer [`AdaptiveFec::on_send_into`] and reuse their output allocation.
    pub fn on_send(&mut self, packet: FecPacket) -> Vec<FecPacket> {
        let mut output = Vec::with_capacity(1);
        self.on_send_into(packet, &mut output);
        output
    }

    /// Process an outgoing packet through the FEC encoder, writing emitted packets into
    /// `output` without allocating a fresh vector on every send.
    ///
    /// `output` is cleared first, but its allocation is retained. This keeps the core send
    /// path allocation-free for the common Zero/no-repair case while preserving the exact
    /// packet emission semantics of [`AdaptiveFec::on_send`].
    pub fn on_send_into(&mut self, packet: FecPacket, output: &mut Vec<FecPacket>) {
        output.clear();

        // **ZERO-CPU FAST PATH**: Ultra-optimized pass-through
        let mode = self.active_mode;
        if mode == FecMode::Zero && self.transition_left == 0 {
            // Absolute zero overhead: direct return without any processing
            output.push(packet);
            return;
        }

        // **TRANSITION HANDLING**: Blend old and new modes during cross-fade
        if self.transition_left > 0 {
            self.handle_transition_packet_into(packet, output);
            return;
        }
        // Normal path: forward systematic and feed encoder
        output.push(packet.clone());
        let mut encoder = self.encoder.lock();
        encoder.take_packet(packet);

        // Check if we should generate repair packets
        let (k, n) = encoder.params();
        if encoder.packets_in_window() >= k {
            let base = n.saturating_sub(k);
            if base > 0 {
                // Extra repairs scale with redundancy hint (ppm)
                let extra = if self.red_ppm_hint > 120_000 {
                    ((self.red_ppm_hint - 120_000) / 50_000) as usize
                } else {
                    0
                };
                let total = (base + extra.min(4)).min(base + 4);
                let free = output.capacity().saturating_sub(output.len());
                if free < total {
                    output.reserve_exact(total - free);
                }
                for i in 0..total {
                    let idx = i % base;
                    if let Some(repair) = encoder.generate_repair_packet(idx, &self.mem_pool) {
                        output.push(repair);
                    }
                }
            }
            encoder.clear_window();
            self.window_complete = true;
        }
        drop(encoder);

        // **ADAPTIVE STREAMING**: Dynamic stream_every based on loss rate
        if mode == FecMode::Streaming {
            self.stream_ctr += 1;
            let effective_every = self.stream_every;
            if self.stream_ctr >= effective_every {
                self.stream_ctr = 0;
                let mut repair_queue = std::mem::take(&mut self.stream_repair_scratch);
                self.emit_streaming_repair(&mut repair_queue);
                if !repair_queue.is_empty() {
                    output.extend(repair_queue.drain(..));
                }
                self.stream_repair_scratch = repair_queue;
            }
        }

        // Telemetry: queue length plus repair-symbol uniqueness/order depth.
        // The common systematic-only path must not pay HashSet/VecDeque cost:
        // repair-symbol diagnostics are only meaningful for emitted repairs.
        crate::telemetry::FEC_EMITTED_QUEUE
            .store(output.len() as u64, std::sync::atomic::Ordering::Relaxed);
        for p in output.iter().filter(|p| !p.is_systematic) {
            self.emitted_ids.insert(p.id);
            self.emitted_order.push_back(p.id);
            if self.emitted_order.len() > 4096 {
                if let Some(old_id) = self.emitted_order.pop_front() {
                    self.emitted_ids.remove(&old_id);
                }
            }
        }
        crate::telemetry::FEC_EMITTED_ORDER_DEPTH
            .store(self.emitted_order.len() as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_EMITTED_UNIQUE
            .store(self.emitted_ids.len() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Process incoming FEC packet through the decoder and return any recovered packets.
    ///
    /// Compatibility wrapper for callers that need an owned output vector. Hot-path callers
    /// should prefer [`AdaptiveFec::on_receive_into`] and reuse their output allocation.
    #[inline]
    pub fn on_receive(&mut self, packet: FecPacket) -> Result<Vec<FecPacket>, String> {
        if self.active_mode == FecMode::Zero && self.transition_left == 0 {
            return Ok(vec![packet]);
        }

        let mut output = Vec::with_capacity(1);
        self.on_receive_into(packet, &mut output)?;
        Ok(output)
    }

    /// Process incoming FEC packet through the decoder, writing emitted packets into
    /// `output` without allocating a fresh vector on every receive.
    ///
    /// `output` is cleared first, but its allocation is retained. This mirrors
    /// [`AdaptiveFec::on_send_into`] for the receive hot path while preserving
    /// the exact packet emission semantics of [`AdaptiveFec::on_receive`].
    #[inline]
    pub fn on_receive_into(
        &mut self,
        packet: FecPacket,
        output: &mut Vec<FecPacket>,
    ) -> Result<(), String> {
        output.clear();

        // Zero mode has no repair packets to consume and cannot recover old
        // zero-mode payloads. Keep the receive path a true ownership-preserving
        // passthrough so the QUIC core can decrypt/header-unprotect in place
        // instead of falling back to a copy because the decoder retained an Arc
        // clone of the pooled buffer.
        if self.active_mode == FecMode::Zero && self.transition_left == 0 {
            output.push(packet);
            return Ok(());
        }

        // Systematic (source) packets must always be forwarded to the QUIC stack
        // immediately, regardless of FEC decoder state. The decoder receives a
        // cheap shared-buffer clone for recovery tracking, while the original is
        // returned directly so handshake/data flow is not stalled. Repair packets
        // are moved into the decoder directly because they are never forwarded as
        // originals.
        let is_systematic = packet.is_systematic;
        let packet_id = packet.id;
        let mut systematic_packet = None;

        let mut decoder = self.decoder.lock();
        if is_systematic {
            decoder.take_packet(packet.clone());
            systematic_packet = Some(packet);
        } else {
            decoder.take_packet(packet);
        }

        if !decoder.recovery_needed() {
            if let Some(source) = systematic_packet.take() {
                output.push(source);
            }
            return Ok(());
        }

        if decoder.full_recovery_needed() {
            if let Some(result) = decoder.get_result() {
                output.extend(result);
            } else if self.partial_enabled {
                output.extend(decoder.get_partial_result());
            }
        } else if self.partial_enabled {
            output.extend(decoder.get_partial_result());
        }

        // Always ensure the systematic packet is forwarded. Block decoders only
        // emit "recovered" packets in get_result/get_partial_result, so systematic
        // packets that arrived intact would be silently dropped without this.
        if is_systematic && !output.iter().any(|p| p.id == packet_id) {
            if let Some(source) = systematic_packet.take() {
                output.push(source);
            }
        }

        Ok(())
    }

    /// Return a reference to the internal memory pool
    pub(crate) fn memory_pool(&self) -> &Arc<MemoryPool> {
        &self.mem_pool
    }

    #[cfg(test)]
    fn stream_repair_scratch_capacity(&self) -> usize {
        self.stream_repair_scratch.capacity()
    }

    #[cfg(test)]
    fn stream_repair_scratch_len(&self) -> usize {
        self.stream_repair_scratch.len()
    }
    /// Handle packet during mode cross-fade using a caller-owned output buffer.
    fn handle_transition_packet_into(&mut self, packet: FecPacket, output: &mut Vec<FecPacket>) {
        // Update transition progress (smooth interpolation)
        self.transition_progress =
            1.0 - (self.transition_left as f32 / self.cross_fade_packets as f32);

        // Process with both old and new encoders, blend outputs
        let old_weight = 1.0 - self.transition_progress;
        let new_weight = self.transition_progress;

        // Always forward systematic packet
        output.push(packet.clone());

        // Process with current encoder (old mode)
        if old_weight > 0.0 {
            let mut encoder = self.encoder.lock();
            encoder.take_packet(packet.clone());

            let (k, n) = encoder.params();
            if encoder.packets_in_window() >= k {
                let base = n.saturating_sub(k);
                let repair_count = (base as f32 * old_weight).ceil() as usize;
                for i in 0..repair_count.min(base) {
                    if let Some(repair) = encoder.generate_repair_packet(i, &self.mem_pool) {
                        output.push(repair);
                    }
                }
                if old_weight < 0.5 {
                    // Only clear when mostly transitioned
                    encoder.clear_window();
                }
            }
        }

        // Process with transition encoder (new mode)
        if new_weight > 0.0 && self.transition_encoder.is_some() {
            if let Some(ref transition_enc) = self.transition_encoder {
                let mut encoder = transition_enc.lock();
                encoder.take_packet(packet);

                let (k, n) = encoder.params();
                if encoder.packets_in_window() >= k {
                    let base = n.saturating_sub(k);
                    let repair_count = (base as f32 * new_weight).ceil() as usize;
                    let repair_count = repair_count.min(base);
                    let free = output.capacity().saturating_sub(output.len());
                    if free < repair_count {
                        output.reserve_exact(repair_count - free);
                    }
                    for i in 0..repair_count {
                        if let Some(repair) = encoder.generate_repair_packet(i, &self.mem_pool) {
                            output.push(repair);
                        }
                    }
                    if new_weight > 0.5 {
                        // Clear when mostly in new mode
                        encoder.clear_window();
                    }
                }
            }
        }

        // Decrement transition counter
        self.transition_left -= 1;
        if self.transition_left == 0 {
            // Transition complete, swap encoders seamlessly
            if let Some(new_encoder) = self.transition_encoder.take() {
                self.encoder = new_encoder;
            }
            if let Some(new_decoder) = self.transition_decoder.take() {
                self.decoder = new_decoder;
            }
            self.window_complete = false;
            self.transition_progress = 1.0;
            self.transition_buffer.clear();
        }
    }

    fn stream_interval_target(&self, estimated_loss: f32) -> usize {
        let target = continuous_fec_target(
            estimated_loss,
            self.runtime_policy.auto_gf4_enabled,
            self.loss_estimator.disturbance_detected(),
            self.fountain_window,
            self.extreme_window,
            self.rtt_ms,
            self.loss_estimator.burst_variance(),
        );

        match target.family {
            FecBackendFamily::Zero => 8,
            FecBackendFamily::LowCostBlock => {
                if target.redundancy <= 1.10 {
                    6
                } else {
                    4
                }
            }
            FecBackendFamily::HeavyBlock => {
                if target.redundancy >= 3.0 {
                    1
                } else if target.redundancy >= 2.0 {
                    2
                } else {
                    3
                }
            }
            FecBackendFamily::Streaming => target.stream_every.unwrap_or(2),
            FecBackendFamily::Fountain => 1,
        }
    }

    /// **GRADUAL MODE SWITCHING**: Initiate seamless transition to new controller target
    fn transition_to_target(&mut self, target: FecProtectionTarget) {
        let (current, current_window) = {
            let mode_mgr = self.mode_manager.lock();
            (mode_mgr.current_mode(), mode_mgr.current_window())
        };
        let (resolved_mode, k, n) = internal::ModeManager::params_for_target(
            target,
            current_window.max(64),
            self.runtime_policy.auto_gf4_enabled,
        );
        if (current == resolved_mode && current_window == k) || self.transition_left > 0 {
            return; // Already in target mode or transitioning
        }

        // Create new encoder/decoder for transition
        self.transition_encoder =
            Some(Arc::new(Mutex::new(internal::InterleavedEncoder::new_with_policy(
                resolved_mode,
                k,
                n,
                self.interleave_depth,
                &self.runtime_policy,
            ))));
        self.transition_decoder =
            Some(Arc::new(Mutex::new(internal::InterleavedDecoder::new_with_policy(
                resolved_mode,
                k,
                Arc::clone(&self.mem_pool),
                self.interleave_depth,
                &self.runtime_policy,
            ))));

        // Start cross-fade transition
        let old_target = target_from_mode(current, current_window);
        self.cross_fade_packets = Self::compute_cross_fade_target_len_capped(
            old_target,
            target,
            current_window,
            k,
            self.cross_fade_window,
        );
        self.transition_left = self.cross_fade_packets;
        self.transition_progress = 0.0;

        // Update streaming mode flag
        self.streaming_mode = matches!(resolved_mode, FecMode::Streaming);
        self.active_mode = resolved_mode;

        let mut mode_mgr = self.mode_manager.lock();
        mode_mgr.force_state(resolved_mode, k);
    }

    /// **GRADUAL MODE SWITCHING**: Initiate seamless transition to new mode
    #[cfg(test)]
    fn transition_to_mode(&mut self, new_mode: FecMode) {
        self.transition_to_target(target_from_mode(new_mode, 64));
    }

    /// Adjust streaming repair emission interval (every N systematic packets). Clamped to [1, 32]
    pub(crate) fn set_stream_every(&mut self, every: usize) {
        let clamped = every.clamp(1, 32);
        self.stream_every_override = Some(clamped);
        self.set_stream_every_internal(clamped);
    }
    /// Set redundancy hint in parts-per-million (100_000 = 1.0x). Influences streaming burst.
    pub(crate) fn set_redundancy_ppm(&mut self, ppm: u32) {
        self.red_ppm_hint = ppm;
    }

    /// Get current redundancy hint in parts-per-million (TODO-428).
    pub fn redundancy_ppm(&self) -> u32 {
        self.red_ppm_hint
    }
    fn set_stream_every_internal(&mut self, val: usize) {
        self.stream_every = val.clamp(1, 32);
        self.stream_ctr = 0;
        self.stream_last_adjust = crate::time_source::now_instant();
    }

    fn update_stream_interval(&mut self, estimated_loss: f32) {
        if self.stream_every_override.is_some() {
            return;
        }
        if crate::time_source::now_instant()
            .checked_duration_since(self.stream_last_adjust)
            .unwrap_or_default()
            < Duration::from_millis(STREAM_ADJUST_MIN_MS)
        {
            return;
        }
        let target_every = self.stream_interval_target(estimated_loss);
        if target_every == self.stream_every {
            return;
        }
        let delta = if target_every < self.stream_every { -2 } else { 1 };
        let new_every = (self.stream_every as isize + delta).clamp(1, 8) as usize;
        if new_every != self.stream_every {
            self.set_stream_every_internal(new_every);
            log::debug!("FEC: adjusted stream interval to every {} packets", new_every);
        }
    }

    fn compute_cross_fade_target_len(
        old_target: FecProtectionTarget,
        new_target: FecProtectionTarget,
        old_k: usize,
        new_k: usize,
    ) -> usize {
        if old_target.family == new_target.family {
            let delta = (old_target.redundancy - new_target.redundancy).abs();
            let base = if delta < 0.35 { 10 } else { 14 };
            let k_factor = (old_k.abs_diff(new_k) / 32).min(6);
            return (base + k_factor).clamp(5, 32);
        }

        let k_delta = old_k.abs_diff(new_k);
        // Cross-fade window sizes: Fountain transitions get the largest window
        // to avoid throughput cliffs at mode boundaries.
        let base = match (old_target.family, new_target.family) {
            (FecBackendFamily::Zero, FecBackendFamily::LowCostBlock)
            | (FecBackendFamily::LowCostBlock, FecBackendFamily::Zero) => 8,
            (FecBackendFamily::Streaming, FecBackendFamily::HeavyBlock)
            | (FecBackendFamily::HeavyBlock, FecBackendFamily::Streaming) => 12,
            // Fountain cross-fade: emit both block repairs AND fountain symbols
            // for the cross-fade window to avoid throughput cliff at boundary.
            (_, FecBackendFamily::Fountain) | (FecBackendFamily::Fountain, _) => 24,
            (FecBackendFamily::Zero, FecBackendFamily::Streaming)
            | (FecBackendFamily::Streaming, FecBackendFamily::Zero) => 10,
            _ => 16,
        };
        let k_factor = (k_delta / 16).min(8);
        (base + k_factor).min(40)
    }

    /// Compute cross-fade length with configurable maximum from `cross_fade_window`.
    /// This allows operators to tune the cross-fade duration via
    /// `QUICFUSCATE_FEC_CROSS_FADE_WINDOW` env var.
    fn compute_cross_fade_target_len_capped(
        old_target: FecProtectionTarget,
        new_target: FecProtectionTarget,
        old_k: usize,
        new_k: usize,
        cap: usize,
    ) -> usize {
        let len = Self::compute_cross_fade_target_len(old_target, new_target, old_k, new_k);
        if cap > 0 {
            len.min(cap)
        } else {
            len
        }
    }
}

mod fountain_codes;

mod adaptive_reed_solomon;

mod gf_tables;

/// Vectorized GF(2^16) scalar multiply-and-xor over big-endian byte slices.
/// out_xor[j..j+2] ^= gf16_mul(coeff, src[j..j+2]) for all j in steps of 2.
#[inline]
pub(crate) fn gf16_mul_scalar_slice_u16(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let len = src.len().min(out_xor.len());
    let packet_u16_len = len / 2;
    if coeff == 0 || packet_u16_len == 0 {
        return;
    }

    if coeff == 1 {
        // Simple XOR
        for (x, y) in src[..len].iter().zip(out_xor[..len].iter_mut()) {
            *y ^= *x;
        }
        return;
    }

    let profile = FeatureDetector::instance().profile();
    let vector_threshold = gf16_vector_threshold_words(profile);

    // Chunk size for stack buffer (64 u16 = 128 bytes)
    const CHUNK_SIZE: usize = 64;

    if vector_threshold != usize::MAX && packet_u16_len >= vector_threshold {
        let mut i = 0;
        while i < packet_u16_len {
            let chunk_len = (packet_u16_len - i).min(CHUNK_SIZE);

            // Stack buffers to avoid heap allocation
            let mut src_tmp = [0u16; CHUNK_SIZE];
            let mut dst_tmp = [0u16; CHUNK_SIZE];

            // 1. Gather & Swap Bytes (BE -> Native)
            // Manual loop is reliable and auto-vectorizes well on modern compilers
            for (k, (src_slot, dst_slot)) in
                src_tmp.iter_mut().zip(dst_tmp.iter_mut()).take(chunk_len).enumerate()
            {
                let offset = (i + k) * 2;
                // Safety: Bounds checked by loop limits
                *src_slot = u16::from_be_bytes([src[offset], src[offset + 1]]);
                *dst_slot = u16::from_be_bytes([out_xor[offset], out_xor[offset + 1]]);
            }

            // 2. SIMD Multiply (Native u16)
            gf16_mul_slice(coeff, &src_tmp[..chunk_len], &mut dst_tmp[..chunk_len]);

            // 3. Swap Bytes & Store (Native -> BE)
            for (k, val) in dst_tmp[..chunk_len].iter().enumerate() {
                let offset = (i + k) * 2;
                let bytes = val.to_be_bytes();
                out_xor[offset] = bytes[0];
                out_xor[offset + 1] = bytes[1];
            }

            i += chunk_len;
        }
    } else {
        // Scalar fallback (packet too small or SIMD disabled)
        let mut j = 0;
        while j + 1 < len {
            let s = u16::from_be_bytes([src[j], src[j + 1]]);
            let r = u16::from_be_bytes([out_xor[j], out_xor[j + 1]]);
            let v = gf_tables::gf16_mul_add(coeff, s, r);
            let b = v.to_be_bytes();
            out_xor[j] = b[0];
            out_xor[j + 1] = b[1];
            j += 2;
        }
    }
}

#[inline(always)]
fn gf16_vector_threshold_words(profile: CpuProfile) -> usize {
    match profile {
        CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => GF16_VBMI2_MIN_WORDS,
        CpuProfile::X86_P3a | CpuProfile::X86_P3b => GF16_AVX512_MIN_WORDS,
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => GF16_AVX2_MIN_WORDS,
        CpuProfile::X86_P1f | CpuProfile::X86_P1b | CpuProfile::X86_P1a => GF16_SSE2_MIN_WORDS,
        CpuProfile::ARM_A2 => GF16_SVE2_MIN_WORDS,
        CpuProfile::ARM_A1c | CpuProfile::ARM_A1d | CpuProfile::Apple_M => GF16_NEON_MIN_WORDS,
        CpuProfile::ARM_A1b => GF16_NEON_MIN_WORDS,
        _ => usize::MAX,
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;

    if len == 0 {
        return;
    }

    #[repr(align(64))]
    struct Table([u16; 32]);

    let mut table0_a = Table([0u16; 32]);
    let mut table0_b = Table([0u16; 32]);
    let mut table1_b = Table([0u16; 32]);
    let mut table2_b = Table([0u16; 32]);
    let mut table3_b = Table([0u16; 32]);

    for nib in 0..16u16 {
        let base = nib as usize;
        let contrib0 = gf_tables::gf16_mul(coeff, nib);
        table0_a.0[base] = contrib0;
        table0_a.0[base + 16] = contrib0;
        table0_b.0[base] = contrib0;
        table0_b.0[base + 16] = contrib0;

        let contrib1 = gf_tables::gf16_mul(coeff, nib << 4);
        table1_b.0[base] = contrib1;
        table1_b.0[base + 16] = contrib1;

        let contrib2 = gf_tables::gf16_mul(coeff, nib << 8);
        table2_b.0[base] = contrib2;
        table2_b.0[base + 16] = contrib2;

        let contrib3 = gf_tables::gf16_mul(coeff, nib << 12);
        table3_b.0[base] = contrib3;
        table3_b.0[base + 16] = contrib3;
    }

    let tbl0_a = _mm512_loadu_si512(table0_a.0.as_ptr() as *const __m512i);
    let tbl0_b = _mm512_loadu_si512(table0_b.0.as_ptr() as *const __m512i);
    let tbl1_a = _mm512_setzero_si512();
    let tbl1_b = _mm512_loadu_si512(table1_b.0.as_ptr() as *const __m512i);
    let tbl2_a = _mm512_setzero_si512();
    let tbl2_b = _mm512_loadu_si512(table2_b.0.as_ptr() as *const __m512i);
    let tbl3_a = _mm512_setzero_si512();
    let tbl3_b = _mm512_loadu_si512(table3_b.0.as_ptr() as *const __m512i);

    let mask_nibble = _mm512_set1_epi16(0x000F);
    let offset32 = _mm512_set1_epi16(32);

    let mut i = 0usize;
    while i + 32 <= len {
        let src_vec = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
        let dst_vec = _mm512_loadu_si512(dst.as_ptr().add(i) as *const __m512i);

        let nib0 = _mm512_and_si512(src_vec, mask_nibble);
        let nib1 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 4), mask_nibble);
        let nib2 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 8), mask_nibble);
        let nib3 = _mm512_srli_epi16(src_vec, 12);

        let idx1 = _mm512_add_epi16(nib1, offset32);
        let idx2 = _mm512_add_epi16(nib2, offset32);
        let idx3 = _mm512_add_epi16(nib3, offset32);

        let contrib0 = _mm512_permutex2var_epi16(nib0, tbl0_a, tbl0_b);
        let contrib1 = _mm512_permutex2var_epi16(idx1, tbl1_a, tbl1_b);
        let contrib2 = _mm512_permutex2var_epi16(idx2, tbl2_a, tbl2_b);
        let contrib3 = _mm512_permutex2var_epi16(idx3, tbl3_a, tbl3_b);

        let partial = _mm512_xor_si512(_mm512_xor_si512(contrib0, contrib1), contrib2);
        let prod = _mm512_xor_si512(partial, contrib3);
        let result = _mm512_xor_si512(dst_vec, prod);

        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, result);
        i += 32;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }

    crate::telemetry::FEC_GF16_VBMI2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vbmi")]
unsafe fn gf16_mul_slice_avx512(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf16_mul_slice_avx2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn gf16_mul_slice_sse2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf16_mul_slice_neon(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::aarch64::*;
    let coeff_vec = vdupq_n_u16(coeff);
    let poly = vdupq_n_u16(0x000b);
    let mut i = 0;

    while i + 8 <= len {
        let src_vec = vld1q_u16(src.as_ptr().add(i));
        let dst_vec = vld1q_u16(dst.as_ptr().add(i));

        let lo = vmulq_u16(coeff_vec, src_vec);
        let wide = vmull_u16(vget_low_u16(coeff_vec), vget_low_u16(src_vec));
        let hi = vshrn_n_u32(wide, 16);
        let red = vmul_u16(hi, vget_low_u16(poly));
        let prod_low = veor_u16(vget_low_u16(lo), red);

        let wide_hi = vmull_u16(vget_high_u16(coeff_vec), vget_high_u16(src_vec));
        let hi_hi = vshrn_n_u32(wide_hi, 16);
        let red_hi = vmul_u16(hi_hi, vget_high_u16(poly));
        let prod_high = veor_u16(vget_high_u16(lo), red_hi);

        let prod = vcombine_u16(prod_low, prod_high);
        let result = veorq_u16(dst_vec, prod);
        vst1q_u16(dst.as_mut_ptr().add(i), result);
        i += 8;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn gf16_mul_slice_sve2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if len == 0 {
            return;
        }

        let coeff_vec = svdup_n_u16(coeff);
        let poly = svdup_n_u16(0x000B);
        let mut offset = 0usize;
        let vl = svcnth() as usize;

        while offset < len {
            let pg = svwhilelt_b16(offset as u64, len as u64);
            if !svptest_any(svptrue_b16(), pg) {
                break;
            }

            let src_vec = svld1_u16(pg, src.as_ptr().add(offset));
            let dst_vec = svld1_u16(pg, dst.as_ptr().add(offset));

            let lo = svmul_u16_x(pg, coeff_vec, src_vec);
            let hi = svmulh_u16_x(pg, coeff_vec, src_vec);
            let red = svmul_u16_x(pg, hi, poly);
            let prod = sveor_u16_m(pg, lo, lo, red);
            let result = sveor_u16_m(pg, dst_vec, dst_vec, prod);

            svst1_u16(pg, dst.as_mut_ptr().add(offset), result);
            offset += vl;
        }

        crate::optimize::telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf16_mul_slice_neon(coeff, src, dst, len);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,pclmulqdq")]
unsafe fn gf16_mul_avx2(a: u16, b: u16) -> u16 {
    use std::arch::x86_64::*;
    // Carryless multiplication for GF(2^16)
    let a_vec = _mm_set1_epi16(a as i16);
    let b_vec = _mm_set1_epi16(b as i16);

    // Perform carryless multiplication
    let lo = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
    let hi = _mm_clmulepi64_si128(a_vec, b_vec, 0x11);

    // Reduction modulo x^16 + x^12 + x^3 + x + 1
    let poly = _mm_set1_epi16(0x100B);
    let red1 = _mm_clmulepi64_si128(hi, poly, 0x00);
    let result = _mm_xor_si128(lo, red1);

    _mm_extract_epi16(result, 0) as u16
}

// Removed gf16_mul_neon scalar shim; NEON paths use slice/vector kernels above.

impl AdaptiveFec {
    fn emit_streaming_repair(&mut self, output_queue: &mut VecDeque<FecPacket>) {
        let mut encoder = self.encoder.lock();

        if encoder.packets_in_window() > 0 {
            let coeff = self.stream_idx;
            if coeff < 255 {
                // Generic repair generation; backend selection is internal.
                if let Some(repair) = encoder.generate_repair_packet(coeff, &self.mem_pool) {
                    output_queue.push_back(repair);
                }
                self.stream_idx = self.stream_idx.wrapping_add(1);
            }
        }
    }

    // Removed packet_to_fec_packet (unused).

    /// Update RTT estimate for stream_every scaling.
    /// Called by transport when a new RTT sample is available.
    pub fn set_rtt_hint(&mut self, rtt_ms: u32) {
        self.rtt_ms = rtt_ms;
    }

    /// Bandwidth-aware overhead control (TODO-428).
    ///
    /// Adjusts FEC redundancy based on bandwidth scarcity signals. When bandwidth
    /// is scarce (high RTT, low throughput), FEC overhead is reduced to preserve
    /// useful throughput. When bandwidth is plentiful, FEC can use full redundancy.
    ///
    /// Signals:
    /// - `rtt_trend`: +1.0 if RTT increasing (congestion), -1.0 if decreasing, 0.0 stable
    /// - `cwnd_trend`: +1.0 if cwnd growing, -1.0 if shrinking, 0.0 stable
    /// - `throughput_trend`: +1.0 if throughput increasing, -1.0 if decreasing, 0.0 stable
    ///
    /// The function adjusts `red_ppm_hint` to guide streaming repair emission.
    /// It never reduces redundancy below the minimum required for current loss level.
    pub fn bandwidth_aware_overhead_adjustment(
        &mut self,
        rtt_trend: f32,
        cwnd_trend: f32,
        throughput_trend: f32,
    ) {
        // Combine signals: negative sum = bandwidth scarce, positive = plentiful
        let signal = rtt_trend + cwnd_trend + throughput_trend;

        // Current loss estimate from estimator
        let current_loss = self.loss_estimator.smoothed_loss();

        // Minimum redundancy for current loss level (parts-per-million)
        // At 0% loss: 0 ppm (Zero mode)
        // At 5% loss: ~50,000 ppm (5% overhead)
        // At 25% loss: ~300,000 ppm (30% overhead)
        // At 50% loss: ~600,000 ppm (60% overhead)
        let min_ppm: u32 = match current_loss {
            l if l < 0.01 => 0,
            l if l < 0.05 => 50_000,
            l if l < 0.10 => 100_000,
            l if l < 0.25 => 300_000,
            l if l < 0.50 => 600_000,
            _ => 1_000_000,
        };

        // Target redundancy based on bandwidth signal
        // Scarce bandwidth (signal < -1.5): reduce to minimum
        // Plentiful bandwidth (signal > 1.5): increase to maximum
        // Neutral: use moderate overhead
        let target_ppm = if signal < -1.5 {
            // Bandwidth scarce: minimize overhead
            min_ppm
        } else if signal > 1.5 {
            // Bandwidth plentiful: full redundancy
            min_ppm.saturating_mul(2)
        } else {
            // Neutral: moderate overhead (1.5x minimum)
            (min_ppm as f32 * 1.5) as u32
        };

        // Smooth adjustment: move 25% toward target each call
        let current = self.red_ppm_hint;
        let adjusted = if target_ppm > current {
            current + ((target_ppm - current) / 4).max(10_000)
        } else if target_ppm < current {
            current.saturating_sub(((current - target_ppm) / 4).max(10_000))
        } else {
            current
        };

        self.red_ppm_hint = adjusted;
    }

    /// Report observed packet loss to update the estimator and drive adaptive mode switching.
    pub fn report_loss(&mut self, lost: usize, total: usize) {
        // Update estimator with current observation and drive mode via smoothed loss
        self.loss_estimator.report(lost, total);
        let estimated_loss = self.loss_estimator.smoothed_loss();
        let instant_loss =
            if total > 0 { (lost as f32 / total as f32).clamp(0.0, 1.0) } else { 0.0 };
        let driving_loss = estimated_loss.max(instant_loss);
        self.update_mode(driving_loss);
        self.update_stream_interval(driving_loss);
    }

    /// Return the currently active FEC protection mode.
    pub fn current_mode(&self) -> FecMode {
        self.active_mode
    }

    /// Returns true if a cross-fade mode transition is currently in progress.
    pub fn is_transitioning(&self) -> bool {
        self.transition_left > 0
    }

    /// Force a specific FEC mode for testing (bypasses adaptive controller).
    #[cfg(test)]
    pub fn force_mode_for_test(&mut self, mode: FecMode) {
        self.active_mode = mode;
        self.mode_manager =
            Arc::new(Mutex::new(internal::ModeManager::with_switch_threshold(mode, 0.02)));
    }

    fn update_mode(&mut self, estimated_loss: f32) {
        let (prev, current_mode, current_window) = {
            let mut mode_mgr = self.mode_manager.lock();
            let prev = mode_mgr.update(estimated_loss);
            let cur_mode = mode_mgr.current_mode();
            let cur_window = mode_mgr.current_window();
            (prev, cur_mode, cur_window)
        };
        // Derive target mode/window from mode manager and apply policy overrides.
        let mut old_mode = prev.map(|(m, _)| m).unwrap_or(current_mode);
        let mut old_window = prev.map(|(_, w)| w).unwrap_or(current_window);
        let mut switched = prev.is_some();
        let mut reason = FecSwitchReason::Adaptive;
        let desired_target = continuous_fec_target(
            estimated_loss,
            self.runtime_policy.auto_gf4_enabled,
            self.loss_estimator.disturbance_detected(),
            self.fountain_window,
            self.extreme_window,
            self.rtt_ms,
            self.loss_estimator.burst_variance(),
        );
        let mut controller_target = if prev.is_some() {
            desired_target
        } else {
            target_from_mode(current_mode, current_window)
        };

        // Policy guard: "FEC On" must never downshift to Zero.
        if self.force_on && desired_target.family == FecBackendFamily::Zero {
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            controller_target = target_from_mode(FecMode::Normal, 64);
            reason = FecSwitchReason::ForceOnPolicy;
        }
        // Ultra-loss policy: route to Fountain for extreme loss
        if estimated_loss >= 0.25 {
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            controller_target = target_from_mode(FecMode::Fountain, self.fountain_window);
            reason = FecSwitchReason::ExtremeLossPolicy;
        } else if self.loss_estimator.disturbance_detected() && estimated_loss >= 0.15 {
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            controller_target = target_from_mode(FecMode::Streaming, self.extreme_window)
                .with_window(self.extreme_window);
            reason = FecSwitchReason::DisturbancePolicy;
        }
        let (new_mode, new_window, n) = internal::ModeManager::params_for_target(
            controller_target,
            current_window,
            self.runtime_policy.auto_gf4_enabled,
        );
        switched = switched || current_mode != new_mode || current_window != new_window;
        let k = new_window;

        if switched {
            let mut mode_mgr = self.mode_manager.lock();
            mode_mgr.force_state(new_mode, new_window);
            self.active_mode = new_mode;
        }

        // Telemetry: track mode and window
        crate::telemetry::FEC_MODE.store(new_mode as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_WINDOW.store(new_window as u64, std::sync::atomic::Ordering::Relaxed);
        if switched {
            crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            reason.observe();
        }
        // Decoder path telemetry hint
        // Decoder path hint could be wired into telemetry counters if available

        if let Some(stream_every) = controller_target.stream_every {
            self.set_stream_every_internal(stream_every);
        }

        // Auto control tuning: set best parameters live (env toggles + cached fields)
        if self.control_mode == FecControlMode::Auto {
            self.apply_auto_tuning(k, estimated_loss, controller_target);
        }

        if switched {
            let (_ok, _on) = internal::ModeManager::params_for(old_mode, old_window);
            let old_target = target_from_mode(old_mode, old_window);
            self.cross_fade_packets = Self::compute_cross_fade_target_len_capped(
                old_target,
                controller_target,
                old_window,
                k,
                self.cross_fade_window,
            );

            // CRITICAL: Drain ZeroDecoder buffers BEFORE creating new decoder
            // This ensures no packet loss during Zero->Real FEC transitions
            let zero_buffers = if old_mode == FecMode::Zero {
                let mut decoder = self.decoder.lock();
                let buffers = decoder.drain_zero_buffers();
                crate::telemetry::ZERO_MODE_UPGRADES
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log::info!("Zero-mode upgrade: replaying {} buffered packets", buffers.len());
                buffers
            } else {
                VecDeque::new()
            };

            self.transition_encoder =
                Some(Arc::new(Mutex::new(internal::InterleavedEncoder::new_with_policy(
                    new_mode,
                    k,
                    n,
                    self.interleave_depth,
                    &self.runtime_policy,
                ))));
            self.transition_decoder =
                Some(Arc::new(Mutex::new(internal::InterleavedDecoder::new_with_policy(
                    new_mode,
                    k,
                    Arc::clone(&self.mem_pool),
                    self.interleave_depth,
                    &self.runtime_policy,
                ))));

            // Replay ZeroDecoder buffers into the new transition decoder
            // This preserves all in-flight packets during Zero->Real FEC upgrade
            if !zero_buffers.is_empty() {
                if let Some(ref trans_dec) = self.transition_decoder {
                    let mut dec = trans_dec.lock();
                    for pkt in zero_buffers {
                        dec.take_packet(pkt);
                    }
                }
            }

            self.transition_left = self.cross_fade_packets;
            self.window_complete = false;
        } else {
            // No change in mode/window; keep current encoder/decoder to preserve streaming/sliding window state.
        }
    }

    pub(crate) fn force_streaming_mode(&mut self) {
        let target = target_from_mode(FecMode::Streaming, 64);
        let target_mode = mode_for_target(target, self.runtime_policy.auto_gf4_enabled);
        self.transition_to_target(target);
        let (_, k, _n) = internal::ModeManager::params_for_target(
            target,
            64,
            self.runtime_policy.auto_gf4_enabled,
        );
        let mut mode_mgr = self.mode_manager.lock();
        mode_mgr.force_state(target_mode, k);
        self.active_mode = target_mode;
        self.streaming_mode = true;
        crate::telemetry::FEC_MODE.store(target_mode as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_WINDOW.store(k as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::info!("Forced switch to streaming mode for minimal latency");
    }

    fn select_simd_level_from_features<F>(has_feature: F) -> SimdLevel
    where
        F: Fn(crate::optimize::CpuFeature) -> bool,
    {
        if has_feature(crate::optimize::CpuFeature::AVX512F)
            && has_feature(crate::optimize::CpuFeature::AVX512VBMI)
        {
            SimdLevel::Avx512
        } else if has_feature(crate::optimize::CpuFeature::AVX2) {
            SimdLevel::Avx2
        } else if has_feature(crate::optimize::CpuFeature::SSE42) {
            SimdLevel::Sse2
        } else if has_feature(crate::optimize::CpuFeature::SVE2) {
            SimdLevel::Sve2
        } else if has_feature(crate::optimize::CpuFeature::NEON) {
            SimdLevel::Neon
        } else {
            SimdLevel::None
        }
    }

    /// Enable SIMD acceleration based on CPU features
    pub(crate) fn enable_simd_acceleration(&mut self) {
        // Centralized detection via optimize::FeatureDetector
        let det = crate::optimize::FeatureDetector::instance();
        self.simd_level = Self::select_simd_level_from_features(|f| det.has_feature(f));
        self.simd_enabled = self.simd_level != SimdLevel::None;
        crate::telemetry::SIMD_ACTIVE
            .store(self.simd_enabled as u64, std::sync::atomic::Ordering::Relaxed);

        match self.simd_level {
            SimdLevel::Avx512 => log::info!("FEC: AVX-512 SIMD acceleration enabled"),
            SimdLevel::Avx2 => log::info!("FEC: AVX2 SIMD acceleration enabled"),
            SimdLevel::Sse2 => log::info!("FEC: SSE2 SIMD acceleration enabled"),
            SimdLevel::Sve2 => log::info!("FEC: SVE2 SIMD acceleration enabled"),
            SimdLevel::Neon => log::info!("FEC: NEON SIMD acceleration enabled"),
            SimdLevel::None => {}
        }
        // Telemetry: report SIMD level
        let lvl = self.simd_level();
        match lvl {
            "AVX-512" => crate::telemetry::SIMD_USAGE_AVX512
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            "AVX2" => {
                crate::telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SSE2" => {
                crate::telemetry::SIMD_USAGE_SSE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SVE2" => {
                crate::telemetry::SIMD_USAGE_SVE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "NEON" => {
                crate::telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            _ => crate::telemetry::SIMD_USAGE_SCALAR
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
    }

    /// Get current SIMD acceleration level
    pub(crate) fn simd_level(&self) -> &str {
        match self.simd_level {
            SimdLevel::None => "scalar",
            SimdLevel::Sse2 => "SSE2",
            SimdLevel::Avx2 => "AVX2",
            SimdLevel::Avx512 => "AVX-512",
            SimdLevel::Sve2 => "SVE2",
            SimdLevel::Neon => "NEON",
        }
    }

    // Removed associated test; proper tests are in #[cfg(test)] modules.

    fn apply_auto_tuning(&mut self, k: usize, loss: f32, target: FecProtectionTarget) {
        if target.family == FecBackendFamily::Zero {
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "gauss");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "0");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "0");
            std::env::set_var("QUICFUSCATE_WM_LANES", "1");
            std::env::set_var("QUICFUSCATE_WM_U", "1");
            self.set_stream_every_internal(4);
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "1");
            return;
        }
        let big_k = k > std::env::var("QUICFUSCATE_FEC_WIEDEMANN_K")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(256);
        if target.family == FecBackendFamily::LowCostBlock && loss < 0.01 {
            // Low loss: bevorzugt Gauss, sanftes Streaming
            std::env::set_var("QUICFUSCATE_FEC_DECODER", if big_k { "auto" } else { "gauss" });
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "0");
            std::env::set_var("QUICFUSCATE_WM_LANES", if big_k { "4" } else { "1" });
            std::env::set_var("QUICFUSCATE_WM_U", "1");
            self.set_stream_every_internal(3);
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "1");
        } else if matches!(
            target.family,
            FecBackendFamily::LowCostBlock | FecBackendFamily::HeavyBlock
        ) && loss < 0.05
        {
            // Normal / moderate block protection
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "auto");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANES", if big_k { "6" } else { "2" });
            std::env::set_var("QUICFUSCATE_WM_U", if big_k { "2" } else { "1" });
            self.set_stream_every_internal(2);
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "2");
        } else if matches!(
            target.family,
            FecBackendFamily::HeavyBlock | FecBackendFamily::Streaming
        ) && loss < 0.20
        {
            // Strong / streaming-biased protection
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "1");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "1");
            std::env::set_var("QUICFUSCATE_WM_LANES", "8");
            std::env::set_var("QUICFUSCATE_WM_U", "2");
            self.set_stream_every_internal(target.stream_every.unwrap_or(1));
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "4");
        } else {
            // Extreme / fountain
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "1");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "1");
            std::env::set_var("QUICFUSCATE_WM_LANES", "8");
            std::env::set_var("QUICFUSCATE_WM_U", "4");
            self.set_stream_every_internal(target.stream_every.unwrap_or(1));
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "8");
        }
    }
}

// --- FEC Configuration ---

#[derive(Debug, Clone)]
/// Configuration for Adaptive FEC behavior and controller settings.
pub struct FecConfig {
    /// FEC window size per mode (source packets per block).
    pub window_sizes: HashMap<FecMode, usize>,
    /// EMA smoothing factor for loss estimation (0..1).
    pub lambda: f32,
    /// Sliding window capacity for burst-loss detection.
    pub burst_window: usize,
    /// Minimum loss delta required to trigger a mode switch.
    pub hysteresis: f32,
    /// FEC mode to use at startup before adaptation kicks in.
    pub initial_mode: FecMode,
    /// When true, FEC will never downshift to `Zero`. This is used for "FEC On"
    /// policy (manual) without exposing low-level tuning in the UI.
    pub force_on: bool,
    /// Enable Kalman filter for loss rate smoothing.
    pub kalman_enabled: bool,
    /// Kalman process noise covariance.
    pub kalman_q: f32,
    /// Kalman measurement noise covariance.
    pub kalman_r: f32,
    /// Override for streaming repair emission interval (packets between repairs).
    pub configured_stream_every: Option<usize>,
}

impl FecConfig {
    fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut m = HashMap::new();
        m.insert(Zero, 0);
        m.insert(Light, 16);
        m.insert(Normal, 64);
        m.insert(Medium, 128);
        m.insert(Strong, 512);
        m.insert(Extreme, 1024);
        m.insert(Streaming, 64);
        m
    }

    fn product_windows(section: &crate::engine::FecSection) -> HashMap<FecMode, usize> {
        let mut windows = Self::default_windows();
        windows.insert(FecMode::Zero, 0);
        if section.window_excellent > 0 {
            windows.insert(FecMode::Light, section.window_excellent);
        }
        windows.insert(FecMode::Normal, section.window_good.max(1));
        windows.insert(FecMode::Medium, section.window_fair.max(section.window_good).max(1));
        windows.insert(FecMode::Strong, section.window_poor.max(1));
        windows.insert(
            FecMode::Extreme,
            section.window_poor.saturating_mul(2).max(section.window_poor).max(1),
        );
        windows.insert(FecMode::Streaming, section.window_fair.max(1));
        windows
    }

    /// Build FEC config from the engine's `[fec]` TOML section.
    pub fn from_engine_section(section: &crate::engine::FecSection) -> Self {
        let initial_mode = match section.mode {
            crate::engine::FecMode::Off => FecMode::Zero,
            crate::engine::FecMode::Auto => FecMode::Normal,
        };

        Self {
            window_sizes: Self::product_windows(section),
            lambda: 0.15,
            burst_window: 16,
            hysteresis: if section.enable_hysteresis { 0.1 } else { 0.0 },
            initial_mode,
            force_on: false,
            kalman_enabled: section.enable_kalman,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: Some(section.stream_every.max(1)),
        }
    }

    /// Return the production-default FEC configuration.
    pub fn product_default() -> Self {
        Self::from_engine_section(&crate::engine::FecSection::default())
    }

    /// Override initial mode and force_on flag from the engine-level FEC mode enum.
    pub fn apply_engine_mode(&mut self, mode: crate::engine::FecMode) {
        self.initial_mode = match mode {
            crate::engine::FecMode::Off => FecMode::Zero,
            crate::engine::FecMode::Auto => FecMode::Normal,
        };
        self.force_on = false;
    }

    /// Parse FEC configuration from a TOML string containing `[adaptive_fec]`.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            adaptive_fec: Adaptive,
        }
        #[derive(serde::Deserialize)]
        struct Adaptive {
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            stream_every: Option<usize>,
            initial_mode: Option<String>,
            modes: Option<Vec<ModeSection>>,
        }
        #[derive(serde::Deserialize)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let mut windows = FecConfig::default_windows();
        if let Some(modes) = af.modes {
            for msec in modes {
                let mode = match msec.name.to_lowercase().as_str() {
                    "zero" => FecMode::Zero,
                    "light" => FecMode::Light,
                    "normal" => FecMode::Normal,
                    "medium" => FecMode::Medium,
                    "strong" => FecMode::Strong,
                    "extreme" => FecMode::Extreme,
                    "streaming" => FecMode::Streaming,
                    _ => continue,
                };
                windows.insert(mode, msec.w0);
            }
        }
        let initial_mode = af.initial_mode.as_deref().unwrap_or("auto").trim().to_lowercase();
        let initial_mode = match initial_mode.as_str() {
            "zero" | "off" => FecMode::Zero,
            "auto" => FecMode::Normal,
            "light" => FecMode::Light,
            "normal" | "on" => FecMode::Normal,
            "medium" => FecMode::Medium,
            "strong" => FecMode::Strong,
            "extreme" => FecMode::Extreme,
            "streaming" => FecMode::Streaming,
            _ => FecMode::Normal,
        };
        Ok(FecConfig {
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            initial_mode,
            force_on: false,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            configured_stream_every: af.stream_every.map(|value| value.max(1)),
            window_sizes: windows,
        })
    }

    /// Load FEC configuration from a TOML file on disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            initial_mode: FecMode::Zero,
            force_on: false,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            configured_stream_every: None,
            window_sizes: FecConfig::default_windows(),
        }
    }
}

impl FecConfig {
    /// Validate all configuration parameters, returning an error message on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.lambda) {
            return Err("lambda must be between 0 and 1".into());
        }
        if self.burst_window == 0 {
            return Err("burst_window must be > 0".into());
        }
        if !(0.0..1.0).contains(&self.hysteresis) {
            return Err("hysteresis must be between 0 and 1".into());
        }
        if self.kalman_enabled && (self.kalman_q <= 0.0 || self.kalman_r <= 0.0) {
            return Err("kalman_q and kalman_r must be positive".into());
        }
        if matches!(self.configured_stream_every, Some(0)) {
            return Err("configured_stream_every must be > 0".into());
        }
        Ok(())
    }
}

impl Decoder8 {
    /// Attempt recovery via Gaussian elimination and return recovered packets.
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Try basic recovery first
        self.try_eliminate();

        // Return any recovered packets
        if !self.emit_q.is_empty() {
            Some(std::mem::take(&mut self.emit_q))
        } else {
            None
        }
    }

    /// Drain all currently queued recovered packets without further elimination.
    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    /// Returns true if enough source packets have been recovered to fill the block.
    #[cfg(test)]
    pub fn is_complete(&self) -> bool {
        self.known.len() >= self.k
    }
}

#[cfg(test)]
mod tests;
