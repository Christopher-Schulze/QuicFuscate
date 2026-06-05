// QuicFuscate Brain (single-file, removable feature)

#[cfg(any(test, feature = "rust-tests", feature = "orchestrator"))]
use log::info;
use log::trace;
use parking_lot::RwLock;
use std::collections::VecDeque;
#[cfg(any(test, feature = "rust-tests"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(any(test, feature = "rust-tests", feature = "orchestrator"))]
use std::sync::Mutex;
use std::time::{Duration, Instant, UNIX_EPOCH};

use crate::env_utils::env_parse;

use crate::accelerate::brain as brain_accel;
use crate::fec::KalmanFilter;
use crate::transport::{Connection, TransportObserver};

// ===== Global Hints (optional) =================================================
// Transport can consult these atomics to adapt FEC and timing without creating
// hard dependencies on Brain internals.
/// Brain-suggested FEC interval in packets (0 = no hint from brain).
pub(crate) static FEC_INTERVAL_HINT_PKTS: AtomicU64 = AtomicU64::new(0);
/// Brain-suggested FEC redundancy in parts-per-million (0 = no hint).
pub(crate) static FEC_REDUNDANCY_PPM: AtomicU32 = AtomicU32::new(0);
/// Intelligent stealth level: 0 = performance, 1 = stealth, 2 = anti-dpi.
pub(crate) static INTELLIGENT_STEALTH_LEVEL_HINT: AtomicU32 = AtomicU32::new(0);

/// Thin aggregator that forwards `TransportObserver` calls to multiple observers.
pub(crate) struct CombinedObserver {
    observers: Vec<Arc<dyn crate::transport::TransportObserver>>,
}

impl CombinedObserver {
    /// Wraps the given observers into a single `Arc<CombinedObserver>`.
    pub(crate) fn new(observers: Vec<Arc<dyn crate::transport::TransportObserver>>) -> Arc<Self> {
        Arc::new(Self { observers })
    }
}

impl crate::transport::TransportObserver for CombinedObserver {
    fn on_ack(&self, ack_delay: u64, ranges: &[(u64, u64)]) {
        for o in &self.observers {
            o.on_ack(ack_delay, ranges);
        }
    }
    fn on_packet_recv(&self, pn: u64, pt_len: usize) {
        for o in &self.observers {
            o.on_packet_recv(pn, pt_len);
        }
    }
    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        for o in &self.observers {
            o.on_ecn_update(ect0, ect1, ce);
        }
    }
    fn apply_policy(&self, conn: &mut crate::transport::Connection) {
        for o in &self.observers {
            o.apply_policy(conn);
        }
    }
}

/// Returns Intelligent mode level hint: 0=performance baseline, 1=stealth, 2=anti-dpi.
pub(crate) fn intelligent_stealth_level_hint() -> u32 {
    INTELLIGENT_STEALTH_LEVEL_HINT.load(Ordering::Relaxed)
}

/// Resets all global brain hint atomics to zero (test-only).
#[cfg(test)]
pub(crate) fn clear_runtime_hints_for_test() {
    FEC_INTERVAL_HINT_PKTS.store(0, Ordering::Relaxed);
    FEC_REDUNDANCY_PPM.store(0, Ordering::Relaxed);
    INTELLIGENT_STEALTH_LEVEL_HINT.store(0, Ordering::Relaxed);
}

#[inline]
fn elapsed_since(instant: Instant) -> Duration {
    crate::time_source::now_instant().checked_duration_since(instant).unwrap_or_default()
}

// ===== Config =================================================================
/// Configuration for the sensor-fusion stealth brain that drives adaptive transport tuning.
#[derive(Clone, Debug)]
pub struct StealthBrainConfig {
    /// Minimum ACK-eliciting threshold the brain may choose.
    pub ack_min: u64,
    /// Maximum ACK-eliciting threshold the brain may choose.
    pub ack_max: u64,
    /// Upper bound for jitter hints in microseconds (transport decides actual delay).
    pub jitter_max_us: u32,
    /// Number of bins for the packet-size histogram.
    pub size_bins: usize,
    /// Number of bins for the inter-arrival-time histogram.
    pub iat_bins: usize,
    /// Maximum DPI probes the brain may emit per minute.
    pub probe_max_per_min: u32,
    /// Minimum milliseconds between successive probe emissions.
    pub probe_cooldown_ms: u64,
    /// Minimum milliseconds between successive policy actuator changes.
    pub policy_cooldown_ms: u64,
    /// Epsilon-greedy exploration probability (0.0 - 1.0).
    pub explore_prob: f32,
    /// Exponential decay factor applied to histograms each policy tick (0.8 - 1.0).
    pub hist_decay: f32,
    /// Lower padding budget bound (bytes) for low-pressure scenarios.
    pub pad_max_low: usize,
    /// Upper padding budget bound (bytes) for high-pressure scenarios.
    pub pad_max_high: usize,
}

impl Default for StealthBrainConfig {
    fn default() -> Self {
        Self {
            ack_min: 1,
            ack_max: 12,
            jitter_max_us: 5000,
            size_bins: 16,
            iat_bins: 16,
            probe_max_per_min: 2,
            probe_cooldown_ms: 10_000,
            policy_cooldown_ms: 300,
            explore_prob: 0.02,
            hist_decay: 0.98,
            pad_max_low: 64,
            pad_max_high: 256,
        }
    }
}

impl StealthBrainConfig {
    /// Constructs a config by reading environment variable overrides on top of defaults.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Some(v) = env_parse("QUICFUSCATE_BRAIN_ACK_MAX") {
            cfg.ack_max = v;
        }
        if let Some(v) = env_parse("QUICFUSCATE_BRAIN_JITTER_MAX_US") {
            cfg.jitter_max_us = v;
        }
        if let Some(v) = env_parse::<usize>("QUICFUSCATE_BRAIN_SIZE_BINS") {
            cfg.size_bins = v.clamp(8, 64);
        }
        if let Some(v) = env_parse::<usize>("QUICFUSCATE_BRAIN_IAT_BINS") {
            cfg.iat_bins = v.clamp(8, 64);
        }
        if let Some(v) = env_parse::<u32>("QUICFUSCATE_BRAIN_PROBE_MAX_PER_MIN") {
            cfg.probe_max_per_min = v.min(30);
        }
        if let Some(v) = env_parse("QUICFUSCATE_BRAIN_PROBE_COOLDOWN_MS") {
            cfg.probe_cooldown_ms = v;
        }
        if let Some(v) = env_parse("QUICFUSCATE_BRAIN_POLICY_COOLDOWN_MS") {
            cfg.policy_cooldown_ms = v;
        }
        if let Some(v) = env_parse::<f32>("QUICFUSCATE_BRAIN_EXPLORE") {
            cfg.explore_prob = v.clamp(0.0, 0.25);
        }
        if let Some(v) = env_parse::<f32>("QUICFUSCATE_BRAIN_HIST_DECAY") {
            cfg.hist_decay = v.clamp(0.80, 0.999);
        }
        if let Some(v) = env_parse::<usize>("QUICFUSCATE_BRAIN_PAD_MAX_LOW") {
            cfg.pad_max_low = v.clamp(16, 512);
        }
        if let Some(v) = env_parse::<usize>("QUICFUSCATE_BRAIN_PAD_MAX_HIGH") {
            cfg.pad_max_high = v.max(cfg.pad_max_low).min(2048);
        }
        cfg
    }
}

// ===== State ==================================================================
#[derive(Clone, Default, Debug)]
struct Hist {
    bins: VecDeque<u64>,
    total: u64,
}
impl Hist {
    fn new(n: usize) -> Self {
        let len = n.max(1);
        let mut bins: VecDeque<u64> = VecDeque::with_capacity(len);
        bins.resize(len, 0);
        Self { bins, total: 0 }
    }

    fn add(&mut self, idx: usize) {
        let i = idx.min(self.bins.len() - 1);
        self.bins[i] = self.bins[i].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }
}

// Snapshot struct removed and archived under archive/unused_code/brain_snapshot.rs

#[derive(Debug)]
struct StealthBrainState {
    // EWMAs
    ack_delay_ewma_us: f64,
    rtt_jitter_ewma_us: f64,
    // ECN counters (since last snapshot)
    ect0: u64,
    ect1: u64,
    ce: u64,
    /// Simple 1D Kalman filter for smoothing CE ratio
    kalman_ce: Option<KalmanFilter>,
    /// Hysteresis for redundancy control
    last_red_ppm: u64,
    red_ppm_momentum: f32,
    last_fec_interval: u64,
    last_fec_update: Instant,
    // Histograms
    size: Hist,
    iat: Hist,
    last_pkt_t: Option<Instant>,
    // Probing budget
    probe_tokens: u32,
    last_probe: Instant,
    // Cooldown
    last_policy_change: Instant,
    // Compatibility-only MASQUE hint state (hysteresis)
    last_masque_hint: bool,
    last_masque_hint_change: Instant,
    // Last applied decisions to avoid oscillation & redundant calls
    last_ack_thr: u64,
    last_pacing: bool,
    last_timing_enabled: bool,
    last_jitter_hint: u32,
    last_bias: u8,
    last_gran: u16,
    last_padding_enabled: bool,
    last_padding_strategy: u8,
    last_padding_max: usize,
    last_cc_profile: crate::transport::recovery::BrowserProfile,
    // ECN deltas and trends
    prev_ect0: u64,
    prev_ect1: u64,
    prev_ce: u64,
    ce_short_ewma: f64,
    ce_long_ewma: f64,
    // ACK delay trends
    ack_delay_long_ewma_us: f64,
    // Reordering
    max_pn_seen: u64,
    reorder_count: u64,
    pkt_count: u64,
    // Throughput trend
    last_delivery_rate: u64,
    // ACK bandit (epsilon-greedy) over discrete arms
    bandit_counts: [u64; 4],
    bandit_avg_reward: [f64; 4],
    bandit_last_arm: Option<usize>,
    last_intelligent_level: u8,
    last_intelligent_level_change: Instant,
    /// Reused histogram scratch for JS divergence (avoids per-tick Vec alloc).
    size_hist_snap: Vec<u64>,
    iat_hist_snap: Vec<u64>,
}

/// Actuator decisions produced by the consolidated mutation write-lock phase.
struct PolicyActuatorSnap {
    ce_ratio_recent: f64,
    ack_us: f64,
    ack_us_long: f64,
    jitter_us: f64,
    reorder_ratio: f64,
    cooldown_ok: bool,
    fec_hint_ppm: Option<u32>,
    fec_hint_interval: Option<u64>,
    size_div: f64,
    iat_div: f64,
    thr: u64,
    do_ack: bool,
    do_pacing: bool,
    do_timing: bool,
    do_bias: bool,
    do_gran: bool,
    do_cc: bool,
    do_padding: bool,
    bias: u8,
    gran: u16,
    prefer_masque_effective: bool,
    stealth_policy: crate::transport::StealthRuntimePolicy,
}

impl StealthBrainState {
    fn new(cfg: &StealthBrainConfig) -> Self {
        let kf_enabled = true;
        Self {
            kalman_ce: if kf_enabled { Some(KalmanFilter::new(0.01, 0.1)) } else { None },
            last_red_ppm: 100_000,
            red_ppm_momentum: 0.0,
            last_fec_interval: 8,
            last_fec_update: crate::time_source::now_instant(),
            ack_delay_ewma_us: 0.0,
            rtt_jitter_ewma_us: 0.0,
            ect0: 0,
            ect1: 0,
            ce: 0,
            size: Hist::new(cfg.size_bins),
            iat: Hist::new(cfg.iat_bins),
            last_pkt_t: None,
            probe_tokens: cfg.probe_max_per_min, // filled initially
            last_probe: crate::time_source::now_instant(),
            last_policy_change: crate::time_source::now_instant(),
            last_masque_hint: false,
            last_masque_hint_change: crate::time_source::now_instant(),
            last_ack_thr: 0,
            last_pacing: false,
            last_timing_enabled: false,
            last_jitter_hint: 0,
            last_bias: 0,
            last_gran: 0,
            last_padding_enabled: false,
            last_padding_strategy: 0,
            last_padding_max: 0,
            last_cc_profile: crate::transport::recovery::BrowserProfile::Chrome,
            prev_ect0: 0,
            prev_ect1: 0,
            prev_ce: 0,
            ce_short_ewma: 0.0,
            ce_long_ewma: 0.0,
            ack_delay_long_ewma_us: 0.0,
            max_pn_seen: 0,
            reorder_count: 0,
            pkt_count: 0,
            last_delivery_rate: 0,
            bandit_counts: [0; 4],
            bandit_avg_reward: [0.0; 4],
            bandit_last_arm: None,
            last_intelligent_level: 0,
            last_intelligent_level_change: crate::time_source::now_instant(),
            size_hist_snap: vec![0; cfg.size_bins],
            iat_hist_snap: vec![0; cfg.iat_bins],
        }
    }
}

#[derive(Clone, Copy)]
enum IntelligentTransitionReason {
    Loss,
    Jitter,
    Timeout,
    Retransmit,
    Probe,
}

impl IntelligentTransitionReason {
    fn observe(self) {
        match self {
            IntelligentTransitionReason::Loss => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_LOSS.inc()
            }
            IntelligentTransitionReason::Jitter => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_JITTER.inc()
            }
            IntelligentTransitionReason::Timeout => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_TIMEOUT.inc()
            }
            IntelligentTransitionReason::Retransmit => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_RETRANSMIT.inc()
            }
            IntelligentTransitionReason::Probe => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_PROBE.inc()
            }
        }
    }
}

fn dominant_transition_reason(
    loss_pressure: f32,
    jitter_pressure: f32,
    timeout_pressure: f32,
    retransmit_pressure: f32,
    probe_pressure: f32,
) -> IntelligentTransitionReason {
    let mut best = (loss_pressure, IntelligentTransitionReason::Loss);
    for cand in [
        (jitter_pressure, IntelligentTransitionReason::Jitter),
        (timeout_pressure, IntelligentTransitionReason::Timeout),
        (retransmit_pressure, IntelligentTransitionReason::Retransmit),
        (probe_pressure, IntelligentTransitionReason::Probe),
    ] {
        if cand.0 > best.0 {
            best = cand;
        }
    }
    best.1
}

fn apply_intelligent_level_hysteresis(
    previous_level: u8,
    target_level: u8,
    composite_pressure: f32,
    probe_pressure: f32,
    loss_pressure: f32,
    elapsed: Duration,
) -> u8 {
    if (target_level > previous_level
        && elapsed >= Duration::from_millis(600)
        && (composite_pressure >= 0.42 || probe_pressure > 0.0))
        || (target_level < previous_level
            && elapsed >= Duration::from_millis(1800)
            && composite_pressure < 0.30
            && probe_pressure == 0.0
            && loss_pressure < 0.025)
    {
        target_level
    } else {
        previous_level
    }
}

#[cfg(any(test, feature = "rust-tests", feature = "orchestrator"))]
fn should_trigger_server_push_internal(
    enabled: bool,
    loss_rate_permille: u32,
    stealth_active: bool,
    cpu_usage_percent: u32,
    memory_pressure: u32,
    bandwidth_bps: u64,
    last_trigger: &Mutex<Instant>,
) -> bool {
    if !enabled {
        return false;
    }

    let loss_rate = loss_rate_permille as f32 / 1000.0;
    let bw_mbps = bandwidth_bps as f32 / 1_000_000.0;
    let high_loss = loss_rate > 0.05;
    let time_based = if let Ok(last_trigger) = last_trigger.lock() {
        elapsed_since(*last_trigger) > Duration::from_secs(30)
    } else {
        false
    };
    let cpu_ok = cpu_usage_percent < 85;
    let mem_ok = memory_pressure < 85;
    let bw_ok = bw_mbps > 5.0 || high_loss;
    let should_trigger = (high_loss || (stealth_active && time_based)) && cpu_ok && mem_ok && bw_ok;
    if should_trigger {
        if let Ok(mut last_trigger) = last_trigger.lock() {
            *last_trigger = crate::time_source::now_instant();
        }
    }
    should_trigger
}

#[cfg(any(test, feature = "rust-tests", feature = "orchestrator"))]
fn server_push_intensity_internal(loss_rate_permille: u32, bandwidth_bps: u64) -> f32 {
    let loss_rate = loss_rate_permille as f32 / 1000.0;
    let bandwidth_mbps = bandwidth_bps as f32 / 1_000_000.0;
    let loss_factor = (loss_rate * 10.0).min(1.0);
    let bandwidth_factor = (bandwidth_mbps / 100.0).min(1.0);
    (0.3 + loss_factor * 0.4 + bandwidth_factor * 0.3).min(1.0)
}

// ===== Brain ==================================================================
/// Sensor-fusion engine that observes transport signals and emits stealth policy deltas.
///
/// Consumes ACK delays, ECN counters, packet sizes, and inter-arrival times to
/// adaptively tune FEC redundancy, ACK thresholds, padding, timing, and congestion
/// control profiles via the `TransportObserver` trait.
pub struct StealthBrain {
    cfg: StealthBrainConfig,
    st: RwLock<StealthBrainState>,
    // Server Push cover-traffic knobs and telemetry inputs
    #[cfg(any(test, feature = "rust-tests"))]
    server_push_enabled: AtomicBool,
    #[cfg(any(test, feature = "rust-tests"))]
    server_push_last_trigger: Mutex<Instant>,
    #[cfg(any(test, feature = "rust-tests"))]
    stealth_active: AtomicBool,
    loss_rate: AtomicU32, // 0..1000 => 0.0%..100.0% in 0.1% units
    #[cfg(any(test, feature = "rust-tests"))]
    cpu_usage_percent: AtomicU32, // 0..100
    #[cfg(any(test, feature = "rust-tests"))]
    memory_pressure: AtomicU32, // 0..100
    #[cfg(any(test, feature = "rust-tests"))]
    bandwidth_bps: AtomicU64, // measured/estimated outbound bandwidth
}

impl StealthBrain {
    /// Creates a new brain instance with the given config, seeding global FEC hints.
    pub fn new(cfg: StealthBrainConfig) -> Arc<Self> {
        let brain = Arc::new(Self {
            st: RwLock::new(StealthBrainState::new(&cfg)),
            cfg,
            #[cfg(any(test, feature = "rust-tests"))]
            server_push_enabled: AtomicBool::new(false),
            #[cfg(any(test, feature = "rust-tests"))]
            server_push_last_trigger: Mutex::new(crate::time_source::now_instant()),
            #[cfg(any(test, feature = "rust-tests"))]
            stealth_active: AtomicBool::new(false),
            loss_rate: AtomicU32::new(0),
            #[cfg(any(test, feature = "rust-tests"))]
            cpu_usage_percent: AtomicU32::new(0),
            #[cfg(any(test, feature = "rust-tests"))]
            memory_pressure: AtomicU32::new(0),
            #[cfg(any(test, feature = "rust-tests"))]
            bandwidth_bps: AtomicU64::new(0),
        });
        FEC_INTERVAL_HINT_PKTS.store(8, Ordering::Relaxed);
        FEC_REDUNDANCY_PPM.store(100_000, Ordering::Relaxed);
        brain
    }
    /// Creates a brain with environment-derived defaults.
    pub(crate) fn new_default() -> Arc<Self> {
        Self::new(StealthBrainConfig::from_env())
    }

    fn bin_index(val: usize, max_val: usize, bins: usize) -> usize {
        if bins == 0 {
            return 0;
        }
        let v = val.min(max_val);
        let w = (max_val as f64 / bins as f64).max(1.0);
        ((v as f64) / w) as usize
    }

    fn size_profile_target(bins: usize) -> Vec<f64> {
        // Chromium-like: mild preference around MTU and small frames
        let mut t = vec![0f64; bins.max(1)];
        for (i, x) in t.iter_mut().enumerate().take(bins) {
            *x = 0.8f64.powf((bins as f64 - 1.0 - i as f64).max(0.0));
        }
        let s: f64 = t.iter().sum();
        if s > 0.0 {
            for x in &mut t {
                *x /= s;
            }
        }
        t
    }

    fn iat_profile_target(bins: usize) -> Vec<f64> {
        // Exponential-ish with light tail (typical paced browser stacks)
        let mut t = vec![0f64; bins.max(1)];
        for (i, x) in t.iter_mut().enumerate().take(bins) {
            *x = 0.85f64.powi(i as i32);
        }
        let s: f64 = t.iter().sum();
        if s > 0.0 {
            for x in &mut t {
                *x /= s;
            }
        }
        t
    }

    fn update_probing_budget(st: &mut StealthBrainState, cfg: &StealthBrainConfig) {
        // Refill tokens roughly once per minute
        if elapsed_since(st.last_probe) >= Duration::from_secs(60) {
            st.probe_tokens = cfg.probe_max_per_min;
            st.last_probe = crate::time_source::now_instant();
        }
    }

    fn maybe_emit_dpi_probe(&self, st: &mut StealthBrainState) {
        // Extremely conservative: spend at most one token per cooldown window
        if st.probe_tokens == 0 {
            return;
        }
        if elapsed_since(st.last_policy_change).as_millis() < self.cfg.policy_cooldown_ms as u128 {
            return;
        }
        // Side-effect free in MVP: only adjust hints, no active packet crafting here.
        // We vary the FEC interval hint slightly to observe CE/Drops reaction.
        let hint = FEC_INTERVAL_HINT_PKTS.load(Ordering::Relaxed);
        let varied =
            if hint > 0 { (hint as i64 + 1 - ((hint & 1) as i64 * 2)).max(1) as u64 } else { 8 };
        FEC_INTERVAL_HINT_PKTS.store(varied, Ordering::Relaxed);
        st.probe_tokens -= 1;
        st.last_policy_change = crate::time_source::now_instant();
        trace!("brain: emitted probe; fec_interval_hint={} pkts", varied);
    }
}

impl TransportObserver for StealthBrain {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        let mut st = self.st.write();
        // Simple EWMA in microseconds
        let s = ack_delay as f64; // already exponent-applied by transport telemetry path
        let a_short = 0.3;
        let a_long = 0.1;
        if st.ack_delay_ewma_us == 0.0 {
            st.ack_delay_ewma_us = s;
        } else {
            st.ack_delay_ewma_us = a_short * s + (1.0 - a_short) * st.ack_delay_ewma_us;
        }
        if st.ack_delay_long_ewma_us == 0.0 {
            st.ack_delay_long_ewma_us = s;
        } else {
            st.ack_delay_long_ewma_us = a_long * s + (1.0 - a_long) * st.ack_delay_long_ewma_us;
        }
        // Lightweight jitter proxy: absolute deviation between short and long ack EWMA
        let diff = (st.ack_delay_ewma_us - st.ack_delay_long_ewma_us).abs();
        if st.rtt_jitter_ewma_us == 0.0 {
            st.rtt_jitter_ewma_us = diff;
        } else {
            st.rtt_jitter_ewma_us = 0.1 * diff + 0.9 * st.rtt_jitter_ewma_us;
        }
        // Central RTT spike signal (rough): count when deviation exceeds 12ms
        if diff > 12_000.0 {
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES.fetch_add(1, Ordering::Relaxed);
        }
        // Budget maintenance
        Self::update_probing_budget(&mut st, &self.cfg);
    }

    fn on_packet_recv(&self, pn: u64, len: usize) {
        let mut st = self.st.write();
        let now = crate::time_source::now_instant();
        // Size histogram (cap at ~2kB for binning)
        let idx_sz = Self::bin_index(len, 2048, st.size.bins.len());
        st.size.add(idx_sz);
        // Inter-arrival histogram
        if let Some(last) = st.last_pkt_t {
            let iat_us = now.duration_since(last).as_micros() as usize;
            let idx_iat = Self::bin_index(iat_us, 100_000, st.iat.bins.len());
            st.iat.add(idx_iat);
        }
        st.last_pkt_t = Some(now);
        // Reorder detection: count out-of-order packets
        if pn < st.max_pn_seen {
            st.reorder_count = st.reorder_count.saturating_add(1);
        }
        if pn > st.max_pn_seen {
            st.max_pn_seen = pn;
        }
        st.pkt_count = st.pkt_count.saturating_add(1);
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        let mut st = self.st.write();
        st.ect0 = ect0;
        st.ect1 = ect1;
        st.ce = ce;
    }

    fn apply_policy(&self, conn: &mut Connection) {
        let signal_rtt_spikes =
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES.swap(0, Ordering::Relaxed);
        let signal_rst = crate::optimize::telemetry::STEALTH_SIGNAL_RST.swap(0, Ordering::Relaxed);
        let signal_tos =
            crate::optimize::telemetry::STEALTH_SIGNAL_TOS_ANOM.swap(0, Ordering::Relaxed);
        let signal_other =
            crate::optimize::telemetry::STEALTH_SIGNAL_OTHER.swap(0, Ordering::Relaxed);
        let dr_now = conn.delivery_rate();
        let ts = crate::time_source::now_system()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .subsec_nanos() as u64;

        let actuators = {
            let mut st = self.st.write();
            // Decay histograms to emphasize recent behavior
            let df = self.cfg.hist_decay as f64;
            {
                let bins = st.size.bins.make_contiguous();
                brain_accel::decay_histogram(bins, df);
            }
            {
                let bins = st.iat.bins.make_contiguous();
                brain_accel::decay_histogram(bins, df);
            }
            // ECN deltas
            let d_ect0 = st.ect0.saturating_sub(st.prev_ect0);
            let d_ect1 = st.ect1.saturating_sub(st.prev_ect1);
            let d_ce = st.ce.saturating_sub(st.prev_ce);
            let d_tot = d_ect0.saturating_add(d_ect1).saturating_add(d_ce).max(1);
            let ce_inst = (d_ce as f64) / (d_tot as f64);
            // EWMAs
            let a_s = 0.4;
            let a_l = 0.1;
            if st.ce_short_ewma == 0.0 {
                st.ce_short_ewma = ce_inst;
            } else {
                st.ce_short_ewma = a_s * ce_inst + (1.0 - a_s) * st.ce_short_ewma;
            }
            if st.ce_long_ewma == 0.0 {
                st.ce_long_ewma = ce_inst;
            } else {
                st.ce_long_ewma = a_l * ce_inst + (1.0 - a_l) * st.ce_long_ewma;
            }
            let ce_ratio_recent_local = st.ce_short_ewma.max(st.ce_long_ewma * 0.8);
            // Update prevs
            st.prev_ect0 = st.ect0;
            st.prev_ect1 = st.ect1;
            st.prev_ce = st.ce;
            // Reorder ratio over recent window (approx):
            let rr = if st.pkt_count > 0 {
                (st.reorder_count as f64) / (st.pkt_count as f64)
            } else {
                0.0
            };
            let size_bin_len = st.size.bins.len();
            let iat_bin_len = st.iat.bins.len();
            if st.size_hist_snap.len() != size_bin_len {
                st.size_hist_snap.resize(size_bin_len, 0);
            }
            if st.iat_hist_snap.len() != iat_bin_len {
                st.iat_hist_snap.resize(iat_bin_len, 0);
            }
            for i in 0..size_bin_len {
                st.size_hist_snap[i] = *st.size.bins.get(i).unwrap_or(&0);
            }
            for i in 0..iat_bin_len {
                st.iat_hist_snap[i] = *st.iat.bins.get(i).unwrap_or(&0);
            }

            let ce_ratio_recent = ce_ratio_recent_local;
            let ack_us = st.ack_delay_ewma_us;
            let ack_us_long = st.ack_delay_long_ewma_us;
            let jitter_us = st.rtt_jitter_ewma_us;
            let reorder_ratio = rr;
            let cooldown_ok = elapsed_since(st.last_policy_change)
                > Duration::from_millis(self.cfg.policy_cooldown_ms);
            let ce_filtered = if let Some(kf) = st.kalman_ce.as_mut() {
                kf.update(ce_ratio_recent as f32) as f64
            } else {
                ce_ratio_recent
            };
            let ce_effective = ce_filtered.max(ce_ratio_recent).min(0.5);
            if st.red_ppm_momentum == 0.0 {
                st.red_ppm_momentum = st.last_red_ppm as f32;
            }
            let jitter_ratio =
                if ack_us_long > 0.0 { (jitter_us / ack_us_long).min(0.5) } else { 0.0 };
            let signal_penalty = (signal_rtt_spikes as f64).min(8.0) * 0.02
                + (signal_rst as f64 * 0.03)
                + (signal_tos as f64 * 0.02)
                + (signal_other as f64 * 0.04);
            let desired_multiplier = (1.0
                + ce_effective * 6.5
                + reorder_ratio.min(0.06) * 6.0
                + jitter_ratio * 2.5
                + signal_penalty)
                .clamp(0.8, 3.5);
            let desired_ppm = (100_000.0 * desired_multiplier) as f32;
            st.red_ppm_momentum = st.red_ppm_momentum * 0.7 + desired_ppm * 0.3;
            let ppm_u64 = st.red_ppm_momentum.round().clamp(80_000.0, 320_000.0) as u64;

            let mut desired_interval: u64 = if ce_effective > 0.08 {
                4
            } else if ce_effective > 0.04 || reorder_ratio > 0.02 {
                6
            } else if ce_effective > 0.015 || reorder_ratio > 0.01 {
                8
            } else {
                12
            };
            if signal_other > 0 || signal_rst > 0 {
                desired_interval = desired_interval.saturating_sub(2);
            }
            desired_interval = desired_interval.clamp(3, 18);
            if st.last_fec_interval == 0 {
                st.last_fec_interval = desired_interval;
            }
            let mut interval = st.last_fec_interval as i64;
            let target_interval = desired_interval as i64;
            match target_interval.cmp(&interval) {
                std::cmp::Ordering::Greater => interval += 1,
                std::cmp::Ordering::Less => interval -= 1,
                std::cmp::Ordering::Equal => {}
            }
            interval = interval.clamp(2, 20);
            let interval_u64 = interval as u64;

            let now = crate::time_source::now_instant();
            let ppm_changed = (ppm_u64 as i64 - st.last_red_ppm as i64).abs()
                > ((st.last_red_ppm / 40).max(1500)) as i64;
            let interval_changed = interval_u64 != st.last_fec_interval;
            let due = now.duration_since(st.last_fec_update) > Duration::from_millis(300);

            let (fec_hint_ppm, fec_hint_interval) = if ppm_changed || interval_changed || due {
                st.last_red_ppm = ppm_u64;
                st.last_fec_interval = interval_u64;
                st.last_fec_update = now;
                (Some(ppm_u64 as u32), Some(interval_u64))
            } else {
                (None, None)
            };

            let size_t = Self::size_profile_target(st.size_hist_snap.len());
            let iat_t = Self::iat_profile_target(st.iat_hist_snap.len());
            let size_sum: u64 = st.size_hist_snap.iter().sum();
            let size_div =
                brain_accel::jensen_shannon_divergence(&st.size_hist_snap, size_sum, &size_t);
            let iat_sum: u64 = st.iat_hist_snap.iter().sum();
            let iat_div =
                brain_accel::jensen_shannon_divergence(&st.iat_hist_snap, iat_sum, &iat_t);

            // Derive ACK threshold: tighter under CE/jitter, looser on clean paths
            let rtt_spike_weight = (signal_rtt_spikes as f64).min(8.0);
            let mut thr = if ce_ratio_recent > 0.05 || ack_us > 12_000.0 || rtt_spike_weight >= 4.0
            {
                2
            } else if ce_ratio_recent < 0.001 && ack_us < 3_000.0 && rtt_spike_weight == 0.0 {
                8
            } else {
                4
            } as u64;
            if size_div + iat_div > 1.2 {
                thr = thr.clamp(2, 4);
            }
            thr = thr.clamp(self.cfg.ack_min, self.cfg.ack_max);
            let prefer_masque_brain = ce_ratio_recent > 0.03
                || rtt_spike_weight >= 2.0
                || signal_rst > 0
                || signal_tos > 0
                || (size_div + iat_div) > 1.6
                || reorder_ratio > 0.02;
            let loss_pressure = ce_ratio_recent.min(1.0) as f32;
            let jitter_pressure =
                (jitter_us / (self.cfg.jitter_max_us.max(1) as f64)).min(1.0) as f32;
            let timeout_pressure = ((ack_us / 12_000.0).min(1.5) / 1.5) as f32;
            let retransmit_pressure =
                (reorder_ratio * 20.0).min(1.0) as f32 + if signal_rst > 0 { 0.25 } else { 0.0 };
            let retransmit_pressure = retransmit_pressure.min(1.0);
            let probe_pressure = if signal_other > 0 || signal_rst > 0 {
                1.0
            } else if signal_tos > 0 {
                0.5
            } else {
                0.0
            };
            let composite_pressure = 0.32 * loss_pressure
                + 0.20 * jitter_pressure
                + 0.18 * timeout_pressure
                + 0.15 * retransmit_pressure
                + 0.15 * probe_pressure;
            let target_level = if composite_pressure >= 0.75
                || probe_pressure >= 0.95
                || loss_pressure >= 0.10
            {
                2u8
            } else if composite_pressure >= 0.38 || loss_pressure >= 0.03 || rtt_spike_weight >= 2.0
            {
                1u8
            } else {
                0u8
            };
            let now = crate::time_source::now_instant();
            let can_toggle =
                now.duration_since(st.last_masque_hint_change) > Duration::from_millis(800);
            let elapsed_level = now.duration_since(st.last_intelligent_level_change);
            let effective_level = apply_intelligent_level_hysteresis(
                st.last_intelligent_level,
                target_level,
                composite_pressure,
                probe_pressure,
                loss_pressure,
                elapsed_level,
            );
            if effective_level != st.last_intelligent_level {
                let previous_level = st.last_intelligent_level;
                st.last_intelligent_level = effective_level;
                st.last_intelligent_level_change = now;
                crate::optimize::telemetry::STEALTH_INTELLIGENT_TRANSITIONS_TOTAL.inc();
                if effective_level < previous_level {
                    crate::optimize::telemetry::STEALTH_INTELLIGENT_DEESCALATIONS_TOTAL.inc();
                } else {
                    dominant_transition_reason(
                        loss_pressure,
                        jitter_pressure,
                        timeout_pressure,
                        retransmit_pressure,
                        probe_pressure,
                    )
                    .observe();
                }
            }
            INTELLIGENT_STEALTH_LEVEL_HINT.store(effective_level as u32, Ordering::Relaxed);
            if can_toggle && st.last_masque_hint != prefer_masque_brain {
                st.last_masque_hint = prefer_masque_brain;
                st.last_masque_hint_change = now;
            }
            let prefer_masque_effective = st.last_masque_hint;

            let mut stealth_policy =
                crate::stealth::StealthManager::derive_intelligent_runtime_policy(
                    crate::stealth::IntelligentStealthInputs {
                        level_hint: effective_level,
                        ce_ratio_recent,
                        ack_us,
                        size_div,
                        iat_div,
                        reorder_ratio,
                        rtt_spike_weight,
                        signal_tos,
                        signal_other,
                        jitter_max_us: self.cfg.jitter_max_us,
                        pad_max_low: self.cfg.pad_max_low,
                        pad_max_high: self.cfg.pad_max_high,
                    },
                );
            let dither_pct = ((ts >> 7) % 21) as i64 - 10;
            stealth_policy.timing_max_jitter_us = ((stealth_policy.timing_max_jitter_us as i64)
                + ((stealth_policy.timing_max_jitter_us as i64 * dither_pct) / 100))
                .max(0) as u32;

            let mut thr_local = thr;
            if let Some(arm) = st.bandit_last_arm.take() {
                let n = st.bandit_counts[arm];
                let dr_prev = st.last_delivery_rate;
                let dr_gain = if dr_now > 0 {
                    (dr_now as f64 - dr_prev as f64) / (dr_now as f64)
                } else {
                    0.0
                };
                let penalty: f64 = 0.7 * ce_ratio_recent + 0.3 * (jitter_us / (ack_us.max(1.0)));
                let r = dr_gain - penalty.max(0.0);
                let new_avg = if n == 0 {
                    r
                } else {
                    ((st.bandit_avg_reward[arm] * n as f64) + r) / (n as f64 + 1.0)
                };
                st.bandit_avg_reward[arm] = new_avg;
                st.bandit_counts[arm] = n + 1;
            }
            st.last_delivery_rate = dr_now;
            let arms: [u64; 4] = [2, 3, 4, 8];
            let roll = ((ts ^ (ts.rotate_left(17))) % 10_000) as f64 / 10_000.0;
            let explore = roll
                < (self.cfg.explore_prob as f64 * if ce_ratio_recent < 0.005 { 1.0 } else { 0.5 });
            let pick = if explore {
                ((ts >> 13) as usize) & 3
            } else {
                let mut best = 0usize;
                let mut best_val = f64::NEG_INFINITY;
                for i in 0..4 {
                    if st.bandit_avg_reward[i] > best_val {
                        best = i;
                        best_val = st.bandit_avg_reward[i];
                    }
                }
                if best_val.is_finite() && best_val > f64::NEG_INFINITY / 2.0 {
                    best
                } else {
                    let mut idx = 0usize;
                    let mut diff = u64::MAX;
                    for (i, &a) in arms.iter().enumerate() {
                        let d = a.abs_diff(thr_local);
                        if d < diff {
                            diff = d;
                            idx = i;
                        }
                    }
                    idx
                }
            };
            st.bandit_last_arm = Some(pick);
            let bandit_thr = arms[pick];
            if bandit_thr != thr_local {
                thr_local = bandit_thr;
            }
            let cooldown = cooldown_ok;
            {
                use core::cmp::Ordering;
                let last = st.last_ack_thr as i64;
                let tgt = thr_local as i64;
                thr_local = match tgt.cmp(&last) {
                    Ordering::Greater => {
                        (last + 1).clamp(self.cfg.ack_min as i64, self.cfg.ack_max as i64) as u64
                    }
                    Ordering::Less => {
                        (last - 1).clamp(self.cfg.ack_min as i64, self.cfg.ack_max as i64) as u64
                    }
                    Ordering::Equal => thr_local,
                };
            }
            let do_ack = cooldown && (st.last_ack_thr != thr_local);
            if do_ack {
                st.last_ack_thr = thr_local;
            }
            let do_pacing = cooldown && (st.last_pacing != stealth_policy.external_pacing);
            if do_pacing {
                st.last_pacing = stealth_policy.external_pacing;
            }
            let j_old = st.last_jitter_hint;
            let j_new = stealth_policy.timing_max_jitter_us;
            let j_diff = if j_old == 0 || j_new == 0 {
                j_old as i64 - j_new as i64
            } else {
                (j_old as i64 - j_new as i64).abs()
            };
            let j_rel = if j_old > 0 { (j_diff.abs() as f64) / (j_old as f64) } else { 1.0 };
            let do_timing = cooldown
                && (st.last_timing_enabled != stealth_policy.timing_enabled
                    || j_old == 0
                    || j_new == 0
                    || j_rel > 0.2);
            if do_timing {
                st.last_timing_enabled = stealth_policy.timing_enabled;
                st.last_jitter_hint = j_new;
            }
            let do_bias = cooldown && (st.last_bias != stealth_policy.mimic_bias);
            if do_bias {
                st.last_bias = stealth_policy.mimic_bias;
            }
            let do_gran = cooldown && (st.last_gran != stealth_policy.adaptive_granularity);
            if do_gran {
                st.last_gran = stealth_policy.adaptive_granularity;
            }
            let do_cc = cooldown && (st.last_cc_profile != stealth_policy.cc_profile);
            if do_cc {
                st.last_cc_profile = stealth_policy.cc_profile;
            }
            let do_padding = cooldown
                && (st.last_padding_enabled != stealth_policy.padding_enabled
                    || st.last_padding_strategy != stealth_policy.padding_strategy
                    || st.last_padding_max != stealth_policy.padding_max);
            if do_padding {
                st.last_padding_enabled = stealth_policy.padding_enabled;
                st.last_padding_strategy = stealth_policy.padding_strategy;
                st.last_padding_max = stealth_policy.padding_max;
            }
            if do_ack || do_pacing || do_timing || do_bias || do_gran || do_cc || do_padding {
                st.last_policy_change = now;
            }
            Self::update_probing_budget(&mut st, &self.cfg);
            self.maybe_emit_dpi_probe(&mut st);
            PolicyActuatorSnap {
                ce_ratio_recent,
                ack_us,
                ack_us_long,
                jitter_us,
                reorder_ratio,
                cooldown_ok,
                fec_hint_ppm,
                fec_hint_interval,
                size_div,
                iat_div,
                thr: thr_local,
                do_ack,
                do_pacing,
                do_timing,
                do_bias,
                do_gran,
                do_cc,
                do_padding,
                bias: stealth_policy.mimic_bias,
                gran: stealth_policy.adaptive_granularity,
                prefer_masque_effective,
                stealth_policy,
            }
        };
        if let Some(interval) = actuators.fec_hint_interval {
            FEC_INTERVAL_HINT_PKTS.store(interval, Ordering::Relaxed);
        }
        if let Some(ppm) = actuators.fec_hint_ppm {
            FEC_REDUNDANCY_PPM.store(ppm, Ordering::Relaxed);
        }
        let ce_scaled = (actuators.ce_ratio_recent * 1000.0).clamp(0.0, 1000.0) as u32;
        self.loss_rate.store(ce_scaled, Ordering::Relaxed);
        crate::optimize::telemetry::MASQUE_HINT
            .store(if actuators.prefer_masque_effective { 1 } else { 0 }, Ordering::Relaxed);
        let ce_ratio_recent = actuators.ce_ratio_recent;
        let ack_us = actuators.ack_us;
        let ack_us_long = actuators.ack_us_long;
        let jitter_us = actuators.jitter_us;
        let reorder_ratio = actuators.reorder_ratio;
        let cooldown_ok = actuators.cooldown_ok;
        let size_div = actuators.size_div;
        let iat_div = actuators.iat_div;
        let thr = actuators.thr;
        let do_ack = actuators.do_ack;
        let do_pacing = actuators.do_pacing;
        let do_timing = actuators.do_timing;
        let do_bias = actuators.do_bias;
        let do_gran = actuators.do_gran;
        let do_cc = actuators.do_cc;
        let do_padding = actuators.do_padding;
        let bias = actuators.bias;
        let gran = actuators.gran;
        let stealth_policy = actuators.stealth_policy;

        let intelligent_runtime = conn.intelligent_stealth_runtime_enabled();
        let permissions = conn.brain_runtime_permissions();
        let mut stealth_delta = crate::transport::StealthRuntimeDelta::default();

        if permissions.ack_threshold && do_ack {
            conn.set_ack_eliciting_threshold(thr);
        }
        if intelligent_runtime && permissions.external_pacing && do_pacing {
            stealth_delta.external_pacing = Some(stealth_policy.external_pacing);
        }
        if intelligent_runtime && permissions.timing && do_timing {
            stealth_delta.timing =
                Some((stealth_policy.timing_enabled, stealth_policy.timing_max_jitter_us));
        }
        // Do not set FEC actuators from the brain anymore.
        if intelligent_runtime && permissions.mimic_bias && do_bias {
            stealth_delta.mimic_bias = Some(stealth_policy.mimic_bias);
        }
        if intelligent_runtime && permissions.granularity && do_gran {
            stealth_delta.adaptive_granularity = Some(stealth_policy.adaptive_granularity);
        }
        if intelligent_runtime && permissions.cc_profile && do_cc {
            stealth_delta.cc_profile = Some(stealth_policy.cc_profile);
        }
        if intelligent_runtime && permissions.padding && do_padding {
            stealth_delta.padding = Some((
                stealth_policy.padding_enabled,
                stealth_policy.padding_strategy,
                stealth_policy.padding_max,
            ));
        }
        if intelligent_runtime {
            conn.apply_brain_stealth_runtime_delta(stealth_delta);
        }

        if cooldown_ok && self.cfg.explore_prob > 0.0 {
            let roll = ((ts ^ (ts.rotate_left(13))) % 10_000) as f64 / 10_000.0;
            if roll < (self.cfg.explore_prob as f64) {
                let alt_thr = (thr as i64 + if (ts & 1) == 0 { 1 } else { -1 })
                    .clamp(self.cfg.ack_min as i64, self.cfg.ack_max as i64)
                    as u64;
                if permissions.ack_threshold {
                    conn.set_ack_eliciting_threshold(alt_thr);
                }
            }
        }

        trace!("brain: policy ack_thr={}{} pacing={}{} bias={}{} gran={}{} pad(strat={},max={}) intelligent_rt={} ce_recent={:.3} ack_us(s/l)={:.0}/{:.0} jitter_us~{:.0} reorder={:.3} size_div={:.3} iat_div={:.3}",
            thr, if do_ack {"*"} else {""},
            stealth_policy.external_pacing, if do_pacing {"*"} else {""},
            bias, if do_bias {"*"} else {""},
            gran, if do_gran {"*"} else {""},
            stealth_policy.padding_strategy, stealth_policy.padding_max,
            intelligent_runtime,
            ce_ratio_recent, ack_us, ack_us_long, jitter_us, reorder_ratio, size_div, iat_div);
    }
}

impl StealthBrain {
    /// **NEW**: Enable Server Push Cover Traffic coordination
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn enable_server_push(&self, enabled: bool) {
        self.server_push_enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            info!("Brain: Server Push Cover Traffic enabled");
        }
    }

    /// **NEW**: Check if Server Push should be triggered based on brain heuristics
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn should_trigger_server_push(&self) -> bool {
        let should_trigger = should_trigger_server_push_internal(
            self.server_push_enabled.load(Ordering::Relaxed),
            self.loss_rate.load(Ordering::Relaxed),
            self.stealth_active.load(Ordering::Relaxed),
            self.cpu_usage_percent.load(Ordering::Relaxed),
            self.memory_pressure.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
            &self.server_push_last_trigger,
        );
        if should_trigger {
            let loss_rate = self.loss_rate.load(Ordering::Relaxed) as f32 / 1000.0;
            let stealth_active = self.stealth_active.load(Ordering::Relaxed);
            trace!(
                "Brain: Triggering Server Push (loss_rate={:.3}, stealth={})",
                loss_rate,
                stealth_active
            );
        }

        should_trigger
    }

    /// Returns recommended server push intensity (0.0 - 1.0) based on loss and bandwidth.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_server_push_intensity(&self) -> f32 {
        server_push_intensity_internal(
            self.loss_rate.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
        )
    }
}

/// Orchestrator for cross-module runtime steering (feature-gated by `orchestrator`).
///
/// This type is intentionally lightweight and only exposes stable control signals
/// consumed from core runtime loops.
#[cfg(feature = "orchestrator")]
pub struct DeepIntegrationOrchestrator {
    _cfg: StealthBrainConfig,
    server_push_enabled: AtomicBool,
    server_push_last_trigger: Mutex<Instant>,
    stealth_active: AtomicBool,
    loss_rate: AtomicU32,         // 0..1000 => 0.0%..100.0% in 0.1% units
    cpu_usage_percent: AtomicU32, // 0..100
    memory_pressure: AtomicU32,   // 0..100
    bandwidth_bps: AtomicU64,     // outbound delivery estimate
}

#[cfg(feature = "orchestrator")]
impl DeepIntegrationOrchestrator {
    /// Creates a new orchestrator with the given brain config and pool hints.
    pub fn new(config: StealthBrainConfig, _pool_capacity: usize, _block_size: usize) -> Arc<Self> {
        Arc::new(Self {
            _cfg: config,
            server_push_enabled: AtomicBool::new(false),
            server_push_last_trigger: Mutex::new(crate::time_source::now_instant()),
            stealth_active: AtomicBool::new(false),
            loss_rate: AtomicU32::new(0),
            cpu_usage_percent: AtomicU32::new(0),
            memory_pressure: AtomicU32::new(0),
            bandwidth_bps: AtomicU64::new(0),
        })
    }

    /// Enables or disables server push cover traffic coordination.
    pub fn enable_server_push(&self, enabled: bool) {
        self.server_push_enabled.store(enabled, Ordering::Relaxed);
        if enabled {
            info!("Orchestrator: Server Push coordination enabled");
        }
    }

    /// Returns whether server push coordination is currently enabled.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn server_push_enabled(&self) -> bool {
        self.server_push_enabled.load(Ordering::Relaxed)
    }

    /// Updates runtime telemetry signals used by server push trigger heuristics.
    pub fn update_runtime_signals(
        &self,
        loss_rate_permille: u32,
        cpu_usage_percent: u32,
        memory_pressure: u32,
        bandwidth_bps: u64,
        stealth_active: bool,
    ) {
        self.loss_rate.store(loss_rate_permille.min(1000), Ordering::Relaxed);
        self.cpu_usage_percent.store(cpu_usage_percent.min(100), Ordering::Relaxed);
        self.memory_pressure.store(memory_pressure.min(100), Ordering::Relaxed);
        self.bandwidth_bps.store(bandwidth_bps, Ordering::Relaxed);
        self.stealth_active.store(stealth_active, Ordering::Relaxed);
    }

    /// Returns whether server push cover traffic should fire based on current signals.
    pub fn should_trigger_server_push(&self) -> bool {
        should_trigger_server_push_internal(
            self.server_push_enabled.load(Ordering::Relaxed),
            self.loss_rate.load(Ordering::Relaxed),
            self.stealth_active.load(Ordering::Relaxed),
            self.cpu_usage_percent.load(Ordering::Relaxed),
            self.memory_pressure.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
            &self.server_push_last_trigger,
        )
    }

    /// Returns recommended server push intensity (0.0 - 1.0) based on loss and bandwidth.
    pub fn get_server_push_intensity(&self) -> f32 {
        server_push_intensity_internal(
            self.loss_rate.load(Ordering::Relaxed),
            self.bandwidth_bps.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod intelligent_hysteresis_tests {
    use super::*;

    #[test]
    fn intelligent_hysteresis_escalates_after_holdoff() {
        let next =
            apply_intelligent_level_hysteresis(0, 1, 0.50, 0.0, 0.02, Duration::from_millis(700));
        assert_eq!(next, 1);
    }

    #[test]
    fn intelligent_hysteresis_blocks_fast_escalation() {
        let next =
            apply_intelligent_level_hysteresis(0, 2, 0.90, 1.0, 0.20, Duration::from_millis(250));
        assert_eq!(next, 0);
    }

    #[test]
    fn intelligent_hysteresis_deescalates_when_path_is_clean() {
        let next =
            apply_intelligent_level_hysteresis(2, 0, 0.20, 0.0, 0.01, Duration::from_millis(2200));
        assert_eq!(next, 0);
    }

    #[test]
    fn intelligent_hysteresis_holds_when_probe_or_loss_persists() {
        let probe_pinned =
            apply_intelligent_level_hysteresis(2, 0, 0.18, 1.0, 0.01, Duration::from_millis(3000));
        assert_eq!(probe_pinned, 2);

        let loss_pinned =
            apply_intelligent_level_hysteresis(2, 0, 0.18, 0.0, 0.05, Duration::from_millis(3000));
        assert_eq!(loss_pinned, 2);
    }

    #[test]
    fn dominant_reason_tracks_strongest_signal() {
        let reason = dominant_transition_reason(0.20, 0.10, 0.05, 0.30, 0.95);
        assert!(matches!(reason, IntelligentTransitionReason::Probe));

        let reason = dominant_transition_reason(0.88, 0.10, 0.05, 0.30, 0.20);
        assert!(matches!(reason, IntelligentTransitionReason::Loss));
    }
}

#[cfg(test)]
mod time_source_tests {
    use super::*;
    use crate::time_source::TimeSource;
    use crate::transport::{
        BrainRuntimePermissions, Config, Connection, TransportObserver, PROTOCOL_VERSION,
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::SystemTime;

    struct ManualTimeSource {
        instant_now: Mutex<Instant>,
        system_now: Mutex<SystemTime>,
    }

    impl ManualTimeSource {
        fn new(instant_now: Instant, system_now: SystemTime) -> Self {
            Self { instant_now: Mutex::new(instant_now), system_now: Mutex::new(system_now) }
        }

        fn advance(&self, delta: Duration) {
            if let Ok(mut instant_now) = self.instant_now.lock() {
                *instant_now += delta;
            }
            if let Ok(mut system_now) = self.system_now.lock() {
                *system_now += delta;
            }
        }
    }

    impl TimeSource for ManualTimeSource {
        fn now_instant(&self) -> Instant {
            *self.instant_now.lock().expect("manual instant poisoned")
        }

        fn now_system(&self) -> SystemTime {
            *self.system_now.lock().expect("manual system poisoned")
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, port))
    }

    fn test_connection(local_port: u16, peer_port: u16) -> Connection {
        let config = Config::new_with_version(PROTOCOL_VERSION).expect("config");
        Connection::new_client(&[7; 8], addr(local_port), addr(peer_port), config)
    }

    #[test]
    fn server_push_time_gate_uses_time_source() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(10);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        brain.enable_server_push(true);
        brain.stealth_active.store(true, Ordering::Relaxed);
        brain.cpu_usage_percent.store(10, Ordering::Relaxed);
        brain.memory_pressure.store(10, Ordering::Relaxed);
        brain.bandwidth_bps.store(25_000_000, Ordering::Relaxed);

        assert!(!brain.should_trigger_server_push());

        manual.advance(Duration::from_secs(31));
        assert!(brain.should_trigger_server_push());
    }

    #[test]
    fn brain_preserves_non_intelligent_preset_stealth_knobs() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(20);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        clear_runtime_hints_for_test();
        let brain = StealthBrain::new(StealthBrainConfig::default());
        let mut conn = test_connection(4460, 4461);
        conn.set_intelligent_stealth_runtime_for_test(false);
        conn.set_stealth_timing(true, 750);
        conn.set_stealth_padding(true, 4, 86);

        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert!(!conn.intelligent_stealth_runtime_enabled_for_test());
        assert!(!conn.external_pacing_enabled());
        assert!(conn.stealth_timing_enabled_for_test());
        assert_eq!(conn.stealth_timing_max_jitter_us_for_test(), 750);
        assert!(conn.stealth_padding_enabled_for_test());
        assert_eq!(conn.stealth_padding_strategy_for_test(), 4);

        clear_runtime_hints_for_test();
    }

    #[test]
    fn brain_can_steer_stealth_runtime_when_connection_is_intelligent() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(30);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        clear_runtime_hints_for_test();
        let brain = StealthBrain::new(StealthBrainConfig::default());
        let mut conn = test_connection(4462, 4463);
        conn.set_intelligent_stealth_runtime_for_test(true);

        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert!(conn.intelligent_stealth_runtime_enabled_for_test());
        assert!(conn.external_pacing_enabled());
        // Level 0 (clean path, no pressure) disables padding to keep Intelligent near-zero overhead.
        assert!(!conn.stealth_padding_enabled_for_test());

        clear_runtime_hints_for_test();
    }

    #[test]
    fn brain_respects_locked_transport_override_permissions() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(40);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        clear_runtime_hints_for_test();
        let brain = StealthBrain::new(StealthBrainConfig::default());
        let mut conn = test_connection(4464, 4465);
        conn.set_intelligent_stealth_runtime_for_test(true);
        conn.set_brain_runtime_permissions_for_test(BrainRuntimePermissions {
            ack_threshold: false,
            external_pacing: false,
            timing: false,
            padding: false,
            mimic_bias: false,
            granularity: false,
            cc_profile: false,
        });
        conn.set_ack_eliciting_threshold(7);
        conn.set_stealth_timing(true, 777);
        conn.set_stealth_padding(true, 4, 86);

        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert_eq!(conn.ack_eliciting_threshold(), 7);
        assert!(!conn.external_pacing_enabled());
        assert!(conn.stealth_timing_enabled_for_test());
        assert_eq!(conn.stealth_timing_max_jitter_us_for_test(), 777);
        assert!(conn.stealth_padding_enabled_for_test());
        assert_eq!(conn.stealth_padding_strategy_for_test(), 4);

        clear_runtime_hints_for_test();
    }
}

#[cfg(feature = "orchestrator")]
#[cfg(test)]
mod orchestrator_tests {
    use super::*;

    #[test]
    fn test_orchestrator_construction() {
        let config = StealthBrainConfig { jitter_max_us: 100, ..Default::default() };

        let orchestrator = DeepIntegrationOrchestrator::new(config, 1024, 65536);
        assert!(!orchestrator.server_push_enabled());

        // Test server push enablement
        orchestrator.enable_server_push(true);
        assert!(orchestrator.server_push_enabled());
    }

    #[test]
    fn test_server_push_intensity_calculation() {
        let config = StealthBrainConfig::default();
        let orchestrator = DeepIntegrationOrchestrator::new(config, 1024, 65536);

        // Test with different loss rates
        orchestrator.update_runtime_signals(50, 20, 20, 100_000_000, true); // 5%, 100 Mbps

        let intensity = orchestrator.get_server_push_intensity();
        assert!(intensity > 0.3 && intensity <= 1.0);
    }

    #[test]
    fn test_server_push_trigger_conditions() {
        let config = StealthBrainConfig::default();
        let orchestrator = DeepIntegrationOrchestrator::new(config, 1024, 65536);

        orchestrator.enable_server_push(true);

        // High loss should trigger
        orchestrator.update_runtime_signals(60, 50, 50, 10_000_000, true); // 6%

        let should_trigger = orchestrator.should_trigger_server_push();
        assert!(should_trigger);

        // High CPU should prevent trigger
        orchestrator.update_runtime_signals(60, 90, 50, 10_000_000, true);
        let should_not_trigger = orchestrator.should_trigger_server_push();
        assert!(!should_not_trigger);
    }
}
