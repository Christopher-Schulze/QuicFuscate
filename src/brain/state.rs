use super::*;
use crossbeam_utils::CachePadded;
use std::collections::VecDeque;

#[derive(Clone, Default, Debug)]
pub(super) struct Hist {
    pub(super) bins: VecDeque<u64>,
    pub(super) total: u64,
}

pub(super) fn new_atomic_bins(len: usize) -> Box<[CachePadded<AtomicU64>]> {
    (0..len.max(1)).map(|_| CachePadded::new(AtomicU64::new(0))).collect()
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
    /// Repair-ratio smoother owned by `derive_intelligent_actuators`
    /// (TODO-1060): momentum, last ppm and last interval.
    pub(super) repair_state: qf_stealth::IntelligentRepairState,
    pub(super) last_fec_update: Instant,
    pub(super) size: Hist,
    pub(super) iat: Hist,
    pub(super) probe_tokens: u32,
    pub(super) last_probe: Instant,
    pub(super) last_policy_change: Instant,
    pub(super) last_masque_hint: bool,
    pub(super) last_masque_hint_change: Instant,
    pub(super) last_ack_thr: u64,
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
    pub(super) last_intelligent_level: u8,
    pub(super) last_intelligent_level_change: Instant,
    pub(super) size_profile_target: Vec<f64>,
    pub(super) iat_profile_target: Vec<f64>,
}

/// Actuator decisions produced by the consolidated mutation write-lock phase.
///
/// TODO-1060: the only writable actuators are the repair-ratio hint
/// (`fec_hint_*`), the Reality/MASQUE armed bit (`prefer_masque_effective`)
/// and the congestion-driven ACK threshold (`thr`/`do_ack`). Everything
/// else in the snap is sensor context for telemetry.
pub(super) struct PolicyActuatorSnap {
    pub(super) ce_ratio_recent: f64,
    pub(super) fec_hint_ppm: Option<u32>,
    pub(super) fec_hint_interval: Option<u64>,
    pub(super) thr: u64,
    pub(super) do_ack: bool,
    pub(super) prefer_masque_effective: bool,
}

impl StealthBrainState {
    pub(super) fn new(cfg: &StealthBrainConfig) -> Self {
        Self {
            kalman_ce: Some(KalmanFilter::new(0.01, 0.1)),
            repair_state: qf_stealth::IntelligentRepairState::default(),
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
