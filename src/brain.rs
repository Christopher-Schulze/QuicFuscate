// QuicFuscate Brain (single-file, removable feature)

use crossbeam_utils::CachePadded;
use log::trace;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::optimize::brain as brain_accel;
use qf_fec::{BrainFecHints, KalmanFilter};
use qf_transport_types::{TransportObserver, TransportPolicyTarget};

#[cfg(feature = "orchestrator")]
mod orchestrator;
#[cfg(feature = "orchestrator")]
pub use orchestrator::DeepIntegrationOrchestrator;
mod state;
use state::*;

const PACKET_IAT_SAMPLE_INTERVAL: u64 = 8;

/// Brain and probe escalation levels for one StealthManager connection.
///
/// The two levels remain separate so a pressure decision cannot erase a
/// probe-threshold decision, and a quiet probe window cannot erase an active
/// Brain pressure decision. Consumers use the maximum of both levels.
/// Half-life of the reorder observation window.
///
/// Policy reads a decaying recent window rather than lifetime totals, so a burst of reordering
/// stops influencing decisions once it has aged out instead of being retained forever.
pub(crate) const REORDER_WINDOW_HALF_LIFE_SECS: f64 = 30.0;

/// Advance the decaying reorder window by `elapsed` and fold in the newly observed counts.
///
/// Both accumulators decay by the same factor, so the ratio between them is preserved across
/// idle time and only shifts when new observations arrive. Idle periods therefore shrink the
/// window's weight without inventing or erasing reordering. The result is clamped to be
/// non-negative and finite: a non-finite accumulator would poison every later ratio.
pub(crate) fn decay_reorder_window(
    recent_packets: f64,
    recent_reorders: f64,
    observed_packets: u64,
    observed_reorders: u64,
    elapsed: Duration,
) -> (f64, f64) {
    let decay = 0.5f64.powf(elapsed.as_secs_f64() / REORDER_WINDOW_HALF_LIFE_SECS);
    let sanitize = |value: f64| if value.is_finite() && value > 0.0 { value } else { 0.0 };
    let packets = sanitize(recent_packets) * decay + observed_packets as f64;
    let reorders = sanitize(recent_reorders) * decay + observed_reorders as f64;
    // Reordered packets can never exceed observed packets in the same window.
    (packets, reorders.min(packets))
}

/// Reorder ratio for the current window, or zero when the window holds no observations.
pub(crate) fn reorder_ratio_from_window(recent_packets: f64, recent_reorders: f64) -> f64 {
    if recent_packets > 0.0 && recent_packets.is_finite() && recent_reorders.is_finite() {
        (recent_reorders / recent_packets).clamp(0.0, 1.0)
    } else {
        0.0
    }
}

pub(crate) use qf_transport_types::IntelligentLevelHints;
pub use qf_transport_types::StealthBrainConfig;

/// Thin aggregator that forwards `TransportObserver` calls to multiple observers.
pub(crate) struct CombinedObserver {
    observers: Vec<Arc<dyn TransportObserver>>,
}

impl CombinedObserver {
    /// Wraps the given observers into a single `Arc<CombinedObserver>`.
    pub(crate) fn new(observers: Vec<Arc<dyn TransportObserver>>) -> Arc<Self> {
        Arc::new(Self { observers })
    }
}

impl TransportObserver for CombinedObserver {
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
    fn apply_policy(&self, conn: &mut dyn TransportPolicyTarget) {
        for o in &self.observers {
            o.apply_policy(conn);
        }
    }
}

#[inline]
fn elapsed_since(instant: Instant) -> Duration {
    crate::time_source::now_instant().checked_duration_since(instant).unwrap_or_default()
}

// ===== Brain ==================================================================
/// Sensor-fusion engine that observes transport signals and steers the two
/// remaining actuators (TODO-1060): the FEC repair-ratio hint and the
/// Reality/MASQUE armed bit, plus the congestion-driven ACK threshold.
///
/// Consumes ACK delays, ECN counters, packet sizes, and inter-arrival times.
/// The bandit/pattern generator that tuned padding, timing and CC profiles
/// is gone — a converging bandit is a stable fingerprint; the wire image is
/// frozen at connect (TODO-1059).
pub struct StealthBrain {
    cfg: StealthBrainConfig,
    st: RwLock<StealthBrainState>,
    fec_hints: Arc<BrainFecHints>,
    level_hints: Arc<IntelligentLevelHints>,
    // Lock-free buffers for observer callbacks - drained in apply_policy's single write lock.
    // Each per-packet counter and every histogram bin sits on its own cacheline:
    // on_packet_recv writes from the dataplane thread while apply_policy swaps the
    // same words from the housekeeping thread, so unpadded atomics would bounce one
    // cacheline between writers on every packet and policy tick (false sharing).
    pending_ecn: CachePadded<AtomicU64>, // packed: ect0 in bits 48..64, ect1 in bits 32..48, ce in bits 0..32
    pending_ack: CachePadded<Mutex<PendingAckSamples>>,
    pending_packet_count: CachePadded<AtomicU64>,
    pending_reorder_count: CachePadded<AtomicU64>,
    pending_max_pn: CachePadded<AtomicU64>,
    pending_last_packet_time_ns: CachePadded<AtomicU64>,
    packet_time_base: Instant,
    pending_size_bins: Box<[CachePadded<AtomicU64>]>,
    pending_iat_bins: Box<[CachePadded<AtomicU64>]>,
    loss_rate: AtomicU32, // 0..1000 => 0.0%..100.0% in 0.1% units
}

impl StealthBrain {
    /// Creates a new brain instance with connection-local runtime state.
    pub fn new(cfg: StealthBrainConfig) -> Arc<Self> {
        Self::new_with_level_hints(cfg, Arc::new(IntelligentLevelHints::new()))
    }

    /// Creates a brain attached to the level state owned by one StealthManager.
    pub(crate) fn new_with_level_hints(
        cfg: StealthBrainConfig,
        level_hints: Arc<IntelligentLevelHints>,
    ) -> Arc<Self> {
        let cfg = match cfg.validate() {
            Ok(()) => cfg,
            Err(error) => {
                log::warn!("Invalid StealthBrain configuration: {error}; using defaults");
                StealthBrainConfig::default()
            }
        };
        let packet_time_base = crate::time_source::now_instant();
        let size_bins = cfg.size_bins.max(1);
        let iat_bins = cfg.iat_bins.max(1);
        let fec_hints = Arc::new(BrainFecHints::new());
        Arc::new(Self {
            st: RwLock::new(StealthBrainState::new(&cfg)),
            cfg,
            fec_hints,
            level_hints,
            pending_ecn: CachePadded::new(AtomicU64::new(0)),
            pending_ack: CachePadded::new(Mutex::new(PendingAckSamples::default())),
            pending_packet_count: CachePadded::new(AtomicU64::new(0)),
            pending_reorder_count: CachePadded::new(AtomicU64::new(0)),
            pending_max_pn: CachePadded::new(AtomicU64::new(0)),
            pending_last_packet_time_ns: CachePadded::new(AtomicU64::new(0)),
            packet_time_base,
            pending_size_bins: new_atomic_bins(size_bins),
            pending_iat_bins: new_atomic_bins(iat_bins),
            loss_rate: AtomicU32::new(0),
        })
    }

    /// Returns the FEC hint state for this connection's observer.
    pub(crate) fn fec_hints(&self) -> Arc<BrainFecHints> {
        Arc::clone(&self.fec_hints)
    }
    fn bin_index(val: usize, max_val: usize, bins: usize) -> usize {
        if bins == 0 {
            return 0;
        }
        let v = val.min(max_val);
        let w = (max_val as f64 / bins as f64).max(1.0);
        (((v as f64) / w) as usize).min(bins - 1)
    }

    #[inline(always)]
    fn packet_time_stamp_ns(&self, now: Instant) -> u64 {
        let elapsed = now.checked_duration_since(self.packet_time_base).unwrap_or_default();
        let nanos = elapsed.as_nanos().min((u64::MAX - 1) as u128) as u64;
        nanos + 1
    }

    #[inline(always)]
    fn record_packet_interarrival(&self, now: Instant) {
        let current = self.packet_time_stamp_ns(now);
        let previous = self.pending_last_packet_time_ns.fetch_max(current, Ordering::Relaxed);
        if previous != 0 && current >= previous {
            let iat_us = ((current - previous) / 1_000).min(100_000) as usize;
            let idx = Self::bin_index(iat_us, 100_000, self.pending_iat_bins.len());
            self.pending_iat_bins[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline(always)]
    fn record_packet_number(&self, pn: u64) {
        let previous = self.pending_max_pn.fetch_max(pn, Ordering::Relaxed);
        if pn < previous {
            self.pending_reorder_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn drain_pending_histogram(pending: &[CachePadded<AtomicU64>], hist: &mut Hist) {
        for (index, counter) in pending.iter().enumerate() {
            let added = counter.swap(0, Ordering::Relaxed);
            if let Some(bin) = hist.bins.get_mut(index) {
                *bin = bin.saturating_add(added);
            }
        }
        hist.total = hist.bins.iter().copied().fold(0, u64::saturating_add);
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
        let hint = self.fec_hints.interval_pkts();
        let varied =
            if hint > 0 { (hint as i64 + 1 - ((hint & 1) as i64 * 2)).max(1) as u64 } else { 8 };
        self.fec_hints.set_interval_pkts(varied);
        st.probe_tokens -= 1;
        st.last_policy_change = crate::time_source::now_instant();
        trace!("brain: emitted probe; fec_interval_hint={} pkts", varied);
    }
}

impl TransportObserver for StealthBrain {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        // Aggregate every callback until apply_policy drains the batch. A mutex
        // keeps the sum/count snapshot coherent without losing samples between
        // two atomic swaps.
        let mut pending = self.pending_ack.lock();
        pending.sum_us = pending.sum_us.saturating_add(ack_delay as u128);
        pending.count = pending.count.saturating_add(1);
    }

    fn on_packet_recv(&self, pn: u64, len: usize) {
        let packet_index = self.pending_packet_count.fetch_add(1, Ordering::Relaxed);
        // Size histogram (cap at ~2kB for binning)
        let idx_sz = Self::bin_index(len, 2048, self.pending_size_bins.len());
        self.pending_size_bins[idx_sz].fetch_add(1, Ordering::Relaxed);
        self.record_packet_number(pn);
        if packet_index.is_multiple_of(PACKET_IAT_SAMPLE_INTERVAL) {
            self.record_packet_interarrival(crate::time_source::now_instant());
        }
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        // Lock-free: pack ECN counters into a single u64 for apply_policy to drain.
        let packed = (ect0.min(0xFFFF) << 48) | (ect1.min(0xFFFF) << 32) | ce.min(0xFFFFFFFF);
        self.pending_ecn.store(packed, Ordering::Relaxed);
    }

    fn apply_policy(&self, conn: &mut dyn TransportPolicyTarget) {
        let signal_rtt_spikes =
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES.swap(0, Ordering::Relaxed);
        let signal_rst = crate::optimize::telemetry::STEALTH_SIGNAL_RST.swap(0, Ordering::Relaxed);
        let signal_tos =
            crate::optimize::telemetry::STEALTH_SIGNAL_TOS_ANOM.swap(0, Ordering::Relaxed);
        let signal_other =
            crate::optimize::telemetry::STEALTH_SIGNAL_OTHER.swap(0, Ordering::Relaxed);

        let actuators = {
            let mut st = self.st.write();

            // Drain lock-free pending ECN counters (buffered by on_ecn_update).
            let ecn_packed = self.pending_ecn.swap(0, Ordering::Relaxed);
            if ecn_packed != 0 {
                st.ect0 = ecn_packed >> 48;
                st.ect1 = ecn_packed >> 32 & 0xFFFF;
                st.ce = ecn_packed & 0xFFFFFFFF;
            }

            Self::drain_pending_histogram(&self.pending_size_bins, &mut st.size);
            Self::drain_pending_histogram(&self.pending_iat_bins, &mut st.iat);
            let pending_packet_count = self.pending_packet_count.swap(0, Ordering::Relaxed);
            let pending_reorder_count = self.pending_reorder_count.swap(0, Ordering::Relaxed);
            st.pkt_count = st.pkt_count.saturating_add(pending_packet_count);
            st.reorder_count = st.reorder_count.saturating_add(pending_reorder_count);
            st.max_pn_seen = st.max_pn_seen.max(self.pending_max_pn.load(Ordering::Relaxed));

            let now = crate::time_source::now_instant();
            let elapsed =
                now.checked_duration_since(st.reorder_window_updated_at).unwrap_or_default();
            let (recent_packets, recent_reorders) = decay_reorder_window(
                st.reorder_recent_packets,
                st.reorder_recent_count,
                pending_packet_count,
                pending_reorder_count,
                elapsed,
            );
            st.reorder_recent_packets = recent_packets;
            st.reorder_recent_count = recent_reorders;
            st.reorder_window_updated_at = now;

            let pending_ack = {
                let mut pending = self.pending_ack.lock();
                std::mem::take(&mut *pending)
            };
            if pending_ack.count > 0 {
                let s = pending_ack.sum_us as f64 / pending_ack.count as f64;
                let a_short = 0.3;
                let a_long = 0.1;
                if st.ack_delay_sample_count == 0 {
                    st.ack_delay_ewma_us = s;
                } else {
                    st.ack_delay_ewma_us = a_short * s + (1.0 - a_short) * st.ack_delay_ewma_us;
                }
                if st.ack_delay_sample_count == 0 {
                    st.ack_delay_long_ewma_us = s;
                } else {
                    st.ack_delay_long_ewma_us =
                        a_long * s + (1.0 - a_long) * st.ack_delay_long_ewma_us;
                }
                st.ack_delay_sample_count =
                    st.ack_delay_sample_count.saturating_add(pending_ack.count);
                let diff = (st.ack_delay_ewma_us - st.ack_delay_long_ewma_us).abs();
                if st.rtt_jitter_ewma_us == 0.0 {
                    st.rtt_jitter_ewma_us = diff;
                } else {
                    st.rtt_jitter_ewma_us = 0.1 * diff + 0.9 * st.rtt_jitter_ewma_us;
                }
                if diff > 12_000.0 {
                    crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES
                        .fetch_add(1, Ordering::Relaxed);
                }
                Self::update_probing_budget(&mut st, &self.cfg);
            }

            // Decay histograms to emphasize recent behavior and derive divergence directly
            // from the contiguous VecDeque storage. This avoids per-tick scratch copies and
            // keeps Hist::total synchronized with decayed bins.
            let df = self.cfg.hist_decay as f64;
            let size_div = st.size_divergence(df);
            let iat_div = st.iat_divergence(df);
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
            let rr = reorder_ratio_from_window(st.reorder_recent_packets, st.reorder_recent_count);
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
            let jitter_ratio =
                if ack_us_long > 0.0 { (jitter_us / ack_us_long).min(0.5) } else { 0.0 };
            // TODO-1060: the sensors feed exactly two actuators — the
            // repair-ratio hint inside the byte cap and the Reality/MASQUE
            // armed bit. No packet shape is derived anywhere: the wire image
            // was frozen at connect (TODO-1059).
            let rtt_spike_weight = (signal_rtt_spikes as f64).min(8.0);
            let hints = qf_stealth::derive_intelligent_actuators(
                qf_stealth::IntelligentStealthInputs {
                    ce_effective,
                    ce_ratio_recent,
                    ack_us,
                    jitter_ratio,
                    reorder_ratio,
                    rtt_spike_weight,
                    size_div,
                    iat_div,
                    signal_rst,
                    signal_tos,
                    signal_other,
                    probe_level: self.level_hints.probe_level(),
                },
                &mut st.repair_state,
            );
            let ppm_u64 = hints.repair_ratio_ppm as u64;
            let interval_u64 = hints.repair_interval_pkts;

            let ppm_changed = (ppm_u64 as i64 - st.repair_state.last_red_ppm as i64).abs()
                > ((st.repair_state.last_red_ppm / 40).max(1500)) as i64;
            let interval_changed = interval_u64 != st.repair_state.last_fec_interval;
            let due = now.duration_since(st.last_fec_update) > Duration::from_millis(300);

            let (fec_hint_ppm, fec_hint_interval) = if ppm_changed || interval_changed || due {
                st.repair_state.last_red_ppm = ppm_u64;
                st.repair_state.last_fec_interval = interval_u64;
                st.last_fec_update = now;
                (Some(ppm_u64 as u32), Some(interval_u64))
            } else {
                (None, None)
            };

            // ACK threshold is a pure congestion feature: tighter under CE
            // pressure and path jitter, looser on clean paths. It changes
            // *when* ACKs are emitted, never the packet length set or the
            // framing — so it stays (TODO-1060 notes); the stealth-driven
            // divergence clamp and the epsilon-greedy bandit are gone.
            let thr = if ce_ratio_recent > 0.05 || ack_us > 12_000.0 || rtt_spike_weight >= 4.0 {
                2u64
            } else if ce_ratio_recent < 0.001 && ack_us < 3_000.0 && rtt_spike_weight == 0.0 {
                8
            } else {
                4
            }
            .clamp(self.cfg.ack_min, self.cfg.ack_max);
            let prefer_masque_brain = hints.reality_armed;
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
            let effective_level = apply_intelligent_level_hysteresis_with_probe_floor(
                st.last_intelligent_level,
                target_level,
                composite_pressure,
                probe_pressure,
                loss_pressure,
                elapsed_level,
                self.level_hints.probe_level(),
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
            self.level_hints.set_brain_level(effective_level);
            if can_toggle && st.last_masque_hint != prefer_masque_brain {
                st.last_masque_hint = prefer_masque_brain;
                st.last_masque_hint_change = now;
            }
            let prefer_masque_effective = st.last_masque_hint;

            // Step-limit the congestion-driven ACK threshold so one noisy
            // tick cannot swing the ACK cadence.
            let thr = {
                use core::cmp::Ordering;
                let last = st.last_ack_thr as i64;
                let tgt = thr as i64;
                match tgt.cmp(&last) {
                    Ordering::Greater => {
                        (last + 1).clamp(self.cfg.ack_min as i64, self.cfg.ack_max as i64) as u64
                    }
                    Ordering::Less => {
                        (last - 1).clamp(self.cfg.ack_min as i64, self.cfg.ack_max as i64) as u64
                    }
                    Ordering::Equal => thr,
                }
            };
            let do_ack = cooldown_ok && (st.last_ack_thr != thr);
            if do_ack {
                st.last_ack_thr = thr;
                st.last_policy_change = now;
            }
            Self::update_probing_budget(&mut st, &self.cfg);
            self.maybe_emit_dpi_probe(&mut st);
            PolicyActuatorSnap {
                ce_ratio_recent,
                fec_hint_ppm,
                fec_hint_interval,
                thr,
                do_ack,
                prefer_masque_effective,
            }
        };
        if let Some(interval) = actuators.fec_hint_interval {
            self.fec_hints.set_interval_pkts(interval);
        }
        if let Some(ppm) = actuators.fec_hint_ppm {
            self.fec_hints.set_redundancy_ppm(ppm);
        }
        let ce_scaled = (actuators.ce_ratio_recent * 1000.0).clamp(0.0, 1000.0) as u32;
        self.loss_rate.store(ce_scaled, Ordering::Relaxed);
        // Connection-owned preference. The global telemetry counter below is observability only
        // and is deliberately never read back for policy.
        self.level_hints.set_prefer_masque(actuators.prefer_masque_effective);
        crate::optimize::telemetry::MASQUE_HINT
            .store(u64::from(actuators.prefer_masque_effective), Ordering::Relaxed);

        // The congestion-driven ACK threshold is the only transport knob the
        // Brain still writes — gated by the operator-lock permission.
        if actuators.do_ack && conn.brain_runtime_permissions().ack_threshold {
            conn.set_ack_eliciting_threshold(actuators.thr);
        }

        trace!(
            "brain: policy ack_thr={}{} fec_ppm={:?} fec_every={:?} reality_armed={} ce_recent={:.3}",
            actuators.thr,
            if actuators.do_ack { "*" } else { "" },
            actuators.fec_hint_ppm,
            actuators.fec_hint_interval,
            actuators.prefer_masque_effective,
            actuators.ce_ratio_recent,
        );
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
    fn intelligent_hysteresis_honors_probe_threshold_floor() {
        let threshold_reached = apply_intelligent_level_hysteresis_with_probe_floor(
            0,
            0,
            0.0,
            0.0,
            0.0,
            Duration::ZERO,
            1,
        );
        assert_eq!(threshold_reached, 1);

        let threshold_floor = apply_intelligent_level_hysteresis_with_probe_floor(
            1,
            0,
            0.0,
            0.0,
            0.0,
            Duration::from_secs(10),
            1,
        );
        assert_eq!(threshold_floor, 1);

        let quiet_pressure = apply_intelligent_level_hysteresis_with_probe_floor(
            1,
            0,
            0.0,
            0.0,
            0.0,
            Duration::from_secs(10),
            0,
        );
        assert_eq!(quiet_pressure, 0);
    }

    #[test]
    fn dominant_reason_tracks_strongest_signal() {
        let reason = dominant_transition_reason(0.20, 0.10, 0.05, 0.30, 0.95);
        assert!(matches!(reason, IntelligentTransitionReason::Probe));

        let reason = dominant_transition_reason(0.88, 0.10, 0.05, 0.30, 0.20);
        assert!(matches!(reason, IntelligentTransitionReason::Loss));
    }

    #[test]
    fn histogram_divergence_keeps_total_synchronized_after_decay() {
        let config = StealthBrainConfig { size_bins: 4, iat_bins: 4, ..Default::default() };
        let mut state = StealthBrainState::new(&config);

        for _ in 0..10 {
            state.size.add(0);
        }
        for _ in 0..6 {
            state.size.add(1);
        }
        assert_eq!(state.size.total, 16);

        let _ = state.size_divergence(0.5);

        let expected_total: u64 = state.size.bins.iter().copied().sum();
        assert_eq!(state.size.total, expected_total);
        assert_eq!(state.size.total, 8);
    }

    #[test]
    fn brain_config_rejects_interdependent_ranges() {
        let invalid_ack = StealthBrainConfig { ack_min: 4, ack_max: 2, ..Default::default() };
        assert!(invalid_ack.validate().is_err());

        let invalid_bins = StealthBrainConfig { size_bins: 0, ..Default::default() };
        assert!(invalid_bins.validate().is_err());

        assert!(StealthBrainConfig::default().validate().is_ok());
    }

    #[test]
    fn brain_snapshot_retains_defaults_for_invalid_numeric_values() {
        let environment = crate::env_utils::EnvSnapshot::from_pairs([
            ("QUICFUSCATE_BRAIN_HIST_DECAY", "-inf"),
            ("QUICFUSCATE_BRAIN_ACK_MAX", "not-a-number"),
        ]);
        let config = StealthBrainConfig::from_env_with_snapshot(&environment);
        assert_eq!(config.hist_decay, StealthBrainConfig::default().hist_decay);
        assert_eq!(config.ack_max, StealthBrainConfig::default().ack_max);
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
    use std::time::{SystemTime, UNIX_EPOCH};

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
        test_connection_with(local_port, peer_port, |_| {})
    }

    fn test_connection_with(
        local_port: u16,
        peer_port: u16,
        configure: impl FnOnce(&mut Config),
    ) -> Connection {
        let mut config = Config::new_with_version(PROTOCOL_VERSION).expect("config");
        configure(&mut config);
        Connection::new_client(&[7; 8], addr(local_port), addr(peer_port), config)
            .expect("valid test connection configuration")
    }

    #[test]
    fn brain_never_touches_the_frozen_wire_shape() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(20);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        // Shape is chosen at connect time via Config — the image a `stealth`
        // connection froze. The Brain must leave every bit of it alone.
        let mut conn = test_connection_with(4460, 4461, |cfg| {
            cfg.set_stealth_timing(true, 750);
            cfg.set_stealth_padding(true, 4, 86);
        });

        // Feed sensors so the policy has real input to steer on.
        for pn in 0..64 {
            brain.on_packet_recv(pn, 96 + ((pn as usize) & 127));
        }
        brain.on_ack(9_000, &[]);
        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert!(conn.stealth_timing_enabled_for_test());
        assert_eq!(conn.stealth_timing_max_jitter_us_for_test(), 750);
        assert!(conn.stealth_padding_enabled_for_test());
        assert_eq!(conn.stealth_padding_strategy_for_test(), 4);
        assert!(
            !conn.stealth_cc_active_for_test(),
            "the Brain must never install a stealth CC wrapper"
        );

        // A clean connection without shaping stays unshaped, too.
        let mut thin = test_connection(4462, 4463);
        brain.apply_policy(&mut thin);
        assert!(!thin.stealth_timing_enabled_for_test());
        assert!(!thin.stealth_padding_enabled_for_test());
        assert!(!thin.stealth_cc_active_for_test());
    }

    /// TODO-1060 acceptance: a thousand policy ticks under shifting loss,
    /// ECN and reorder pressure must never move the frozen padding strategy
    /// or the framing.
    #[test]
    fn thousand_ticks_under_shifting_loss_never_change_shape() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(25);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        let mut conn = test_connection_with(4474, 4475, |cfg| {
            cfg.set_stealth_timing(true, 900);
            cfg.set_stealth_padding(true, 3, 96);
        });

        let mut pn = 0u64;
        for tick in 0..1000usize {
            // Oscillating loss/jitter signature across ticks.
            let burst = 8 + (tick % 24);
            for _ in 0..burst {
                pn += 1;
                // Reorder every 5th packet, vary sizes across classes.
                let observed = if pn % 5 == 0 { pn + 1 } else { pn };
                brain.on_packet_recv(observed, 64 + ((tick * 37) & 1023));
            }
            brain.on_ack(2_000 + ((tick % 9) as u64) * 2_500, &[]);
            brain.on_ecn_update(0, 0, (tick % 7) as u64);
            manual.advance(Duration::from_millis(120));
            brain.apply_policy(&mut conn);
        }

        assert!(conn.stealth_timing_enabled_for_test());
        assert_eq!(conn.stealth_timing_max_jitter_us_for_test(), 900);
        assert!(conn.stealth_padding_enabled_for_test());
        assert_eq!(conn.stealth_padding_strategy_for_test(), 3);
        assert!(!conn.stealth_cc_active_for_test());
    }

    #[test]
    fn brain_writes_repair_hints_and_ack_threshold_only() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(30);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        let fec_hints = brain.fec_hints();
        let mut conn = test_connection(4464, 4465);
        conn.set_ack_eliciting_threshold(7);

        // Long ACK delay pushes the congestion-driven threshold down and
        // emits the smoothed repair-ratio hint.
        brain.on_ack(20_000, &[]);
        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert!(
            conn.ack_eliciting_threshold() < 7,
            "congestion-driven ACK threshold must react to slow ACK cadence"
        );
        let ppm = fec_hints.redundancy_ppm();
        let every = fec_hints.interval_pkts();
        assert!((80_000..=320_000).contains(&ppm), "repair ppm in bounds: {ppm}");
        assert!((2..=20).contains(&every), "repair interval in bounds: {every}");
    }

    #[test]
    fn brain_respects_ack_threshold_lock() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(40);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        let mut conn = test_connection(4466, 4467);
        conn.set_brain_runtime_permissions_for_test(BrainRuntimePermissions {
            ack_threshold: false,
        });
        conn.set_ack_eliciting_threshold(7);

        brain.on_ack(20_000, &[]);
        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut conn);

        assert_eq!(conn.ack_eliciting_threshold(), 7, "locked ACK threshold must not move");

        // The same policy tick may still steer the unlocked actuators.
        let mut unlocked = test_connection(4468, 4469);
        unlocked.set_ack_eliciting_threshold(7);
        brain.on_ack(20_000, &[]);
        manual.advance(Duration::from_millis(400));
        brain.apply_policy(&mut unlocked);
        assert!(unlocked.ack_eliciting_threshold() < 7);
    }

    #[test]
    fn packet_observer_drains_lock_free_metadata() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(50);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual);

        let brain = StealthBrain::new(StealthBrainConfig::default());
        brain.on_packet_recv(10, 64);
        brain.on_packet_recv(8, 2048);
        brain.on_packet_recv(12, 128);

        assert_eq!(brain.pending_packet_count.load(Ordering::Relaxed), 3);
        assert_eq!(brain.pending_reorder_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            brain
                .pending_size_bins
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum::<u64>(),
            3
        );
        assert_eq!(
            brain
                .pending_iat_bins
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );

        let mut conn = test_connection(4466, 4467);
        brain.apply_policy(&mut conn);
        let state = brain.st.read();
        assert_eq!(state.pkt_count, 3);
        assert_eq!(state.reorder_count, 1);
        assert_eq!(state.max_pn_seen, 12);
        assert_eq!(state.iat.total, 0);
        assert_eq!(brain.pending_packet_count.load(Ordering::Relaxed), 0);
        assert_eq!(brain.pending_reorder_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn ack_batch_accumulates_all_samples_before_policy_tick() {
        let brain = StealthBrain::new(StealthBrainConfig::default());
        brain.on_ack(1_000, &[]);
        brain.on_ack(3_000, &[]);
        {
            let pending = brain.pending_ack.lock();
            assert_eq!(pending.count, 2);
            assert_eq!(pending.sum_us, 4_000);
        }

        let mut conn = test_connection(4470, 4471);
        brain.apply_policy(&mut conn);
        let state = brain.st.read();
        assert_eq!(state.ack_delay_sample_count, 2);
        assert_eq!(state.ack_delay_ewma_us, 2_000.0);
        assert_eq!(state.ack_delay_long_ewma_us, 2_000.0);
    }

    #[test]
    fn reorder_ratio_uses_a_decaying_recent_window() {
        let base_instant = Instant::now();
        let base_system = UNIX_EPOCH + Duration::from_secs(60);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let brain = StealthBrain::new(StealthBrainConfig::default());
        brain.on_packet_recv(10, 64);
        brain.on_packet_recv(9, 64);
        let mut conn = test_connection(4472, 4473);
        brain.apply_policy(&mut conn);
        {
            let state = brain.st.read();
            assert_eq!(state.reorder_count, 1);
            assert!(
                (state.reorder_recent_count / state.reorder_recent_packets - 0.5).abs() < 0.001
            );
        }

        manual.advance(Duration::from_secs(30));
        for pn in 11..111 {
            brain.on_packet_recv(pn, 64);
        }
        brain.apply_policy(&mut conn);
        let state = brain.st.read();
        let recent_ratio = state.reorder_recent_count / state.reorder_recent_packets;
        assert!(recent_ratio < 0.02, "recent reorder ratio remained {recent_ratio}");
        assert_eq!(state.reorder_count, 1);
    }

    #[test]
    fn packet_observer_samples_interarrival_histogram() {
        let brain = StealthBrain::new(StealthBrainConfig::default());
        for pn in 0..=8 {
            brain.on_packet_recv(pn, 128);
        }

        assert_eq!(brain.pending_packet_count.load(Ordering::Relaxed), 9);
        assert_eq!(
            brain
                .pending_iat_bins
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum::<u64>(),
            1
        );
    }

    #[test]
    fn packet_observer_accumulates_concurrent_callbacks() {
        let brain = StealthBrain::new(StealthBrainConfig::default());
        const WORKERS: usize = 4;
        const PACKETS_PER_WORKER: u64 = 512;

        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let brain = Arc::clone(&brain);
                scope.spawn(move || {
                    let base = worker as u64 * PACKETS_PER_WORKER;
                    for offset in 0..PACKETS_PER_WORKER {
                        let pn = base + offset;
                        brain.on_packet_recv(pn, 96 + ((pn as usize * 17) & 511));
                    }
                });
            }
        });

        assert_eq!(
            brain.pending_packet_count.load(Ordering::Relaxed),
            (WORKERS as u64) * PACKETS_PER_WORKER
        );
        let mut conn = test_connection(4468, 4469);
        brain.apply_policy(&mut conn);
        let state = brain.st.read();
        assert_eq!(state.pkt_count, (WORKERS as u64) * PACKETS_PER_WORKER);
        assert!(state.reorder_count <= state.pkt_count);
        assert!(state.size.total <= state.pkt_count);
        assert_eq!(
            brain
                .pending_size_bins
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .sum::<u64>(),
            0
        );
    }
}

#[cfg(test)]
mod reorder_window_tests;
