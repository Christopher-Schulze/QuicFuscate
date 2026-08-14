use super::*;
use std::collections::VecDeque;

#[derive(Clone, Default, Debug)]
pub(super) struct Hist {
    pub(super) bins: VecDeque<u64>,
    pub(super) total: u64,
}

pub(super) fn new_atomic_bins(len: usize) -> Box<[AtomicU64]> {
    (0..len.max(1)).map(|_| AtomicU64::new(0)).collect()
}

impl Hist {
    pub(super) fn new(n: usize) -> Self {
        let len = n.max(1);
        let mut bins: VecDeque<u64> = VecDeque::with_capacity(len);
        bins.resize(len, 0);
        Self { bins, total: 0 }
    }

    #[cfg(test)]
    pub(super) fn add(&mut self, idx: usize) {
        let i = idx.min(self.bins.len() - 1);
        self.bins[i] = self.bins[i].saturating_add(1);
        self.total = self.total.saturating_add(1);
    }
}

#[derive(Default)]
pub(super) struct PendingAckSamples {
    pub(super) sum_us: u128,
    pub(super) count: u64,
}

#[inline]
pub(super) fn decay_histogram_and_divergence(hist: &mut Hist, target: &[f64], decay: f64) -> f64 {
    let bins = hist.bins.make_contiguous();
    brain_accel::decay_histogram(bins, decay);
    hist.total = bins.iter().copied().sum();
    brain_accel::jensen_shannon_divergence(bins, hist.total, target)
}

#[derive(Debug)]
pub(super) struct StealthBrainState {
    pub(super) ack_delay_ewma_us: f64,
    pub(super) rtt_jitter_ewma_us: f64,
    pub(super) ack_delay_sample_count: u64,
    pub(super) ect0: u64,
    pub(super) ect1: u64,
    pub(super) ce: u64,
    pub(super) kalman_ce: Option<KalmanFilter>,
    pub(super) last_red_ppm: u64,
    pub(super) red_ppm_momentum: f32,
    pub(super) last_fec_interval: u64,
    pub(super) last_fec_update: Instant,
    pub(super) size: Hist,
    pub(super) iat: Hist,
    pub(super) probe_tokens: u32,
    pub(super) last_probe: Instant,
    pub(super) last_policy_change: Instant,
    pub(super) last_masque_hint: bool,
    pub(super) last_masque_hint_change: Instant,
    pub(super) last_ack_thr: u64,
    pub(super) last_pacing: bool,
    pub(super) last_timing_enabled: bool,
    pub(super) last_jitter_hint: u32,
    pub(super) last_bias: u8,
    pub(super) last_gran: u16,
    pub(super) last_padding_enabled: bool,
    pub(super) last_padding_strategy: u8,
    pub(super) last_padding_max: usize,
    pub(super) last_padding_rate: u8,
    pub(super) last_timing_rate: u8,
    pub(super) last_cc_profile: crate::transport::recovery::BrowserProfile,
    pub(super) prev_ect0: u64,
    pub(super) prev_ect1: u64,
    pub(super) prev_ce: u64,
    pub(super) ce_short_ewma: f64,
    pub(super) ce_long_ewma: f64,
    pub(super) ack_delay_long_ewma_us: f64,
    pub(super) max_pn_seen: u64,
    pub(super) reorder_count: u64,
    pub(super) pkt_count: u64,
    pub(super) reorder_recent_count: f64,
    pub(super) reorder_recent_packets: f64,
    pub(super) reorder_window_updated_at: Instant,
    pub(super) last_delivery_rate: u64,
    pub(super) bandit_counts: [u64; 4],
    pub(super) bandit_avg_reward: [f64; 4],
    pub(super) bandit_last_arm: Option<usize>,
    pub(super) last_intelligent_level: u8,
    pub(super) last_intelligent_level_change: Instant,
    pub(super) size_profile_target: Vec<f64>,
    pub(super) iat_profile_target: Vec<f64>,
}

/// Actuator decisions produced by the consolidated mutation write-lock phase.
pub(super) struct PolicyActuatorSnap {
    pub(super) ce_ratio_recent: f64,
    pub(super) ack_us: f64,
    pub(super) ack_us_long: f64,
    pub(super) jitter_us: f64,
    pub(super) reorder_ratio: f64,
    pub(super) cooldown_ok: bool,
    pub(super) fec_hint_ppm: Option<u32>,
    pub(super) fec_hint_interval: Option<u64>,
    pub(super) size_div: f64,
    pub(super) iat_div: f64,
    pub(super) thr: u64,
    pub(super) do_ack: bool,
    pub(super) do_pacing: bool,
    pub(super) do_timing: bool,
    pub(super) do_bias: bool,
    pub(super) do_gran: bool,
    pub(super) do_cc: bool,
    pub(super) do_padding: bool,
    pub(super) do_timing_rate: bool,
    pub(super) bias: u8,
    pub(super) gran: u16,
    pub(super) prefer_masque_effective: bool,
    pub(super) stealth_policy: crate::transport::StealthRuntimePolicy,
}

impl StealthBrainState {
    pub(super) fn new(cfg: &StealthBrainConfig) -> Self {
        Self {
            kalman_ce: Some(KalmanFilter::new(0.01, 0.1)),
            last_red_ppm: 100_000,
            red_ppm_momentum: 0.0,
            last_fec_interval: 8,
            last_fec_update: crate::time_source::now_instant(),
            ack_delay_ewma_us: 0.0,
            rtt_jitter_ewma_us: 0.0,
            ack_delay_sample_count: 0,
            ect0: 0,
            ect1: 0,
            ce: 0,
            size: Hist::new(cfg.size_bins),
            iat: Hist::new(cfg.iat_bins),
            probe_tokens: cfg.probe_max_per_min,
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
            last_padding_rate: 100,
            last_timing_rate: 100,
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
            reorder_recent_count: 0.0,
            reorder_recent_packets: 0.0,
            reorder_window_updated_at: crate::time_source::now_instant(),
            last_delivery_rate: 0,
            bandit_counts: [0; 4],
            bandit_avg_reward: [0.0; 4],
            bandit_last_arm: None,
            last_intelligent_level: 0,
            last_intelligent_level_change: crate::time_source::now_instant(),
            size_profile_target: StealthBrain::size_profile_target(cfg.size_bins),
            iat_profile_target: StealthBrain::iat_profile_target(cfg.iat_bins),
        }
    }

    #[inline]
    pub(super) fn size_divergence(&mut self, decay: f64) -> f64 {
        decay_histogram_and_divergence(&mut self.size, &self.size_profile_target, decay)
    }

    #[inline]
    pub(super) fn iat_divergence(&mut self, decay: f64) -> f64 {
        decay_histogram_and_divergence(&mut self.iat, &self.iat_profile_target, decay)
    }
}

#[derive(Clone, Copy)]
pub(super) enum IntelligentTransitionReason {
    Loss,
    Jitter,
    Timeout,
    Retransmit,
    Probe,
}

impl IntelligentTransitionReason {
    pub(super) fn observe(self) {
        match self {
            Self::Loss => crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_LOSS.inc(),
            Self::Jitter => crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_JITTER.inc(),
            Self::Timeout => crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_TIMEOUT.inc(),
            Self::Retransmit => {
                crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_RETRANSMIT.inc()
            }
            Self::Probe => crate::optimize::telemetry::STEALTH_INTELLIGENT_REASON_PROBE.inc(),
        }
    }
}

pub(super) fn dominant_transition_reason(
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

#[cfg(test)]
pub(super) fn apply_intelligent_level_hysteresis(
    previous_level: u8,
    target_level: u8,
    composite_pressure: f32,
    probe_pressure: f32,
    loss_pressure: f32,
    elapsed: Duration,
) -> u8 {
    apply_intelligent_level_hysteresis_with_probe_floor(
        previous_level,
        target_level,
        composite_pressure,
        probe_pressure,
        loss_pressure,
        elapsed,
        0,
    )
}

pub(super) fn apply_intelligent_level_hysteresis_with_probe_floor(
    previous_level: u8,
    target_level: u8,
    composite_pressure: f32,
    probe_pressure: f32,
    loss_pressure: f32,
    elapsed: Duration,
    probe_level: u8,
) -> u8 {
    let probe_level = probe_level.min(2);
    if probe_level > previous_level {
        return probe_level;
    }
    let target_level = target_level.max(probe_level);
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
pub(super) fn should_trigger_server_push_internal(
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
    let time_based = {
        let last_trigger = last_trigger.lock();
        elapsed_since(*last_trigger) > Duration::from_secs(30)
    };
    let cpu_ok = cpu_usage_percent < 85;
    let mem_ok = memory_pressure < 85;
    let bw_ok = bw_mbps > 5.0 || high_loss;
    let should_trigger = (high_loss || (stealth_active && time_based)) && cpu_ok && mem_ok && bw_ok;
    if should_trigger {
        let mut last_trigger = last_trigger.lock();
        *last_trigger = crate::time_source::now_instant();
    }
    should_trigger
}

#[cfg(any(test, feature = "rust-tests", feature = "orchestrator"))]
pub(super) fn server_push_intensity_internal(loss_rate_permille: u32, bandwidth_bps: u64) -> f32 {
    let loss_rate = loss_rate_permille as f32 / 1000.0;
    let bandwidth_mbps = bandwidth_bps as f32 / 1_000_000.0;
    let loss_factor = (loss_rate * 10.0).min(1.0);
    let bandwidth_factor = (bandwidth_mbps / 100.0).min(1.0);
    (0.3 + loss_factor * 0.4 + bandwidth_factor * 0.3).min(1.0)
}
