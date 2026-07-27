//! BBR v2 congestion control (IETF draft-ietf-ccwg-bbr).
//!
//! Loss-aware, model-based congestion control with 4-state machine
//! (Startup/Drain/ProbeBW/ProbeRTT). Standalone implementation following
//! the IETF specification - no external crate dependency.
//!
//! Reference: <https://datatracker.ietf.org/doc/draft-ietf-ccwg-bbr/>

use core::cmp::{max, min};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::CongestionController;

// ---------------------------------------------------------------------------
// Constants (from IETF draft-ietf-ccwg-bbr-04)
// ---------------------------------------------------------------------------

/// Startup pacing gain (probe aggressively for bandwidth).
const STARTUP_PACING_GAIN: f64 = 2.77;
/// Startup cwnd gain.
const STARTUP_CWND_GAIN: f64 = 2.0;
/// Drain pacing gain (evacuate queue after startup).
const DRAIN_PACING_GAIN: f64 = 0.35;
/// Number of rounds without 25% BW growth before exiting Startup.
const FULL_BW_ROUNDS: u32 = 3;
/// Growth threshold for full-bandwidth detection.
const FULL_BW_THRESH: f64 = 1.25;
/// Loss rate threshold for early Startup exit (2%).
const STARTUP_LOSS_THRESH: f64 = 0.02;
/// ProbeBW UP phase pacing gain.
const PROBE_BW_UP_GAIN: f64 = 1.25;
/// ProbeBW DOWN phase pacing gain.
const PROBE_BW_DOWN_GAIN: f64 = 0.90;
/// ProbeBW CRUISE phase pacing gain.
const PROBE_BW_CRUISE_GAIN: f64 = 1.0;
/// ProbeBW UP phase cwnd gain (headroom for probing).
const PROBE_BW_UP_CWND_GAIN: f64 = 2.25;
/// Default cwnd gain for non-UP phases.
const DEFAULT_CWND_GAIN: f64 = 2.0;
/// ProbeRTT pacing gain.
const PROBE_RTT_PACING_GAIN: f64 = 0.75;
/// ProbeRTT cwnd gain.
const PROBE_RTT_CWND_GAIN: f64 = 0.5;
/// ProbeRTT minimum duration.
const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
/// How often to enter ProbeRTT (at least every 5 seconds of no new min_rtt).
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);
/// Minimum pipe cwnd in MSS units.
const MIN_PIPE_CWND_PKTS: usize = 4;
/// EWMA decay for loss tracking.
const LOSS_ALPHA: f32 = 0.1;
/// Loss discount factor for conservative BW estimate.
const LOSS_BW_DISCOUNT: f64 = 0.3;

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Startup,
    Drain,
    ProbeBW(ProbeBwPhase),
    ProbeRTT,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeBwPhase {
    /// Probe for more bandwidth with elevated pacing gain.
    Up,
    /// Drain any queue built during Up.
    Down,
    /// Steady state with neutral pacing gain (cycles 2-7).
    Cruise,
}

// ---------------------------------------------------------------------------
// Windowed max bandwidth filter
// ---------------------------------------------------------------------------

/// Tracks the maximum bandwidth over a sliding window of rounds.
struct MaxBwFilter {
    /// Ring buffer of (round, bandwidth) samples.
    samples: [(u64, u64); 10],
    /// Write index.
    idx: usize,
}

impl MaxBwFilter {
    fn new() -> Self {
        Self { samples: [(0, 0); 10], idx: 0 }
    }

    /// Record a new bandwidth sample at the given round.
    fn update(&mut self, round: u64, bw: u64) {
        self.samples[self.idx] = (round, bw);
        self.idx = (self.idx + 1) % self.samples.len();
    }

    /// Return the maximum bandwidth within `window` rounds of `current_round`.
    fn max_within(&self, current_round: u64, window: u64) -> u64 {
        let cutoff = current_round.saturating_sub(window);
        self.samples.iter().filter(|(r, _)| *r >= cutoff).map(|(_, bw)| *bw).max().unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// BBR2 controller
// ---------------------------------------------------------------------------

/// BBR v2 congestion controller (IETF draft-ietf-ccwg-bbr).
pub struct Bbr2 {
    // State machine
    state: State,
    // Congestion window and flight
    cwnd: usize,
    bytes_in_flight: usize,
    mss: usize,
    // Pacing
    pacing_rate: u64,
    pacing_gain: f64,
    cwnd_gain: f64,
    // Bandwidth model
    max_bw_filter: MaxBwFilter,
    max_bw: u64,
    // RTT tracking
    min_rtt: Duration,
    rtt: Duration,
    /// EWMA RTT variance propagated from recovery (RFC 6298 `rttvar`).
    rtt_var: Duration,
    min_rtt_stamp: Instant,
    // Loss tracking (dual-timescale EWMA)
    loss_acked: f32,
    loss_lost: f32,
    loss_in_round: f32,
    round_loss_acked: f32,
    // Delivery tracking
    delivered: u64,
    delivered_time: Instant,
    app_limited: u64,
    // Round counting
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    // Startup exit detection
    full_bw_reached: bool,
    full_bw_count: u32,
    full_bw: u64,
    // ProbeBW cycling
    cycle_count: u32,
    cycle_stamp: Instant,
    // ProbeRTT
    probe_rtt_done_stamp: Option<Instant>,
    prior_cwnd: usize,
    // Misc
    idle_restart: bool,
    ack_epoch_acked: usize,
    extra_acked: usize,
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
}

impl Bbr2 {
    /// Create a new BBR2 controller with the given initial window and MSS.
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        let now = Instant::now();
        let mss = mss.max(1);
        Self {
            state: State::Startup,
            cwnd: initial_cwnd,
            bytes_in_flight: 0,
            mss,
            pacing_rate: 0,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: STARTUP_CWND_GAIN,
            max_bw_filter: MaxBwFilter::new(),
            max_bw: 0,
            min_rtt: Duration::from_millis(100),
            rtt: Duration::from_millis(100),
            rtt_var: Duration::ZERO,
            min_rtt_stamp: now,
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_in_round: 0.0,
            round_loss_acked: 0.0,
            delivered: 0,
            delivered_time: now,
            app_limited: 0,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            full_bw_reached: false,
            full_bw_count: 0,
            full_bw: 0,
            cycle_count: 0,
            cycle_stamp: now,
            probe_rtt_done_stamp: None,
            prior_cwnd: 0,
            idle_restart: false,
            ack_epoch_acked: 0,
            extra_acked: 0,
            fec_on_sent: None,
            fec_on_lost: None,
        }
    }

    /// Minimum cwnd floor: 4 * MSS.
    /// The raw pacing rate before any stealth post-processing.
    pub fn raw_pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Set the pacing rate (used by StealthShaper to apply jitter).
    pub fn set_pacing_rate(&mut self, rate: u64) {
        self.pacing_rate = rate;
    }

    fn min_pipe_cwnd(&self) -> usize {
        MIN_PIPE_CWND_PKTS * self.mss
    }

    /// Bandwidth-delay product.
    fn bdp(&self) -> usize {
        (self.max_bw as f64 * self.min_rtt.as_secs_f64()) as usize
    }

    /// Inflight target for the current state.
    fn target_inflight(&self) -> usize {
        let bdp = self.bdp();
        max((bdp as f64 * self.cwnd_gain) as usize + self.extra_acked, self.min_pipe_cwnd())
    }

    /// Current loss rate [0.0, 1.0].
    fn current_loss_rate(&self) -> f64 {
        let total = self.loss_acked + self.loss_lost;
        if total <= f32::EPSILON {
            0.0
        } else {
            (self.loss_lost / total).clamp(0.0, 1.0) as f64
        }
    }

    // -----------------------------------------------------------------------
    // Rate sampling
    // -----------------------------------------------------------------------

    fn compute_delivery_rate(&self, acked_bytes: u64, now: Instant) -> u64 {
        if now <= self.delivered_time {
            return self.max_bw;
        }
        let elapsed = now.duration_since(self.delivered_time).as_secs_f64();
        if elapsed > 0.0 {
            (acked_bytes as f64 / elapsed).max(0.0) as u64
        } else {
            self.max_bw
        }
    }

    // -----------------------------------------------------------------------
    // Model update (BBRUpdateModelAndState)
    // -----------------------------------------------------------------------

    fn update_bandwidth(&mut self, delivery_rate: u64) {
        self.max_bw_filter.update(self.round_count, delivery_rate);
        self.max_bw = self.max_bw_filter.max_within(self.round_count, 10);
    }

    fn check_full_bw_reached(&mut self, delivery_rate: u64) {
        if self.full_bw_reached {
            return;
        }
        if delivery_rate as f64 >= self.full_bw as f64 * FULL_BW_THRESH {
            self.full_bw = delivery_rate;
            self.full_bw_count = 0;
        } else {
            self.full_bw_count += 1;
            if self.full_bw_count >= FULL_BW_ROUNDS {
                self.full_bw_reached = true;
            }
        }
    }

    fn check_startup_high_loss(&self) -> bool {
        self.current_loss_rate() > STARTUP_LOSS_THRESH
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = STARTUP_CWND_GAIN;
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.state = State::ProbeBW(ProbeBwPhase::Cruise);
        self.pacing_gain = PROBE_BW_CRUISE_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.cycle_count = 0;
        self.cycle_stamp = now;
    }

    fn enter_probe_rtt(&mut self) {
        self.state = State::ProbeRTT;
        self.pacing_gain = PROBE_RTT_PACING_GAIN;
        self.cwnd_gain = PROBE_RTT_CWND_GAIN;
        self.prior_cwnd = self.cwnd;
        self.probe_rtt_done_stamp = None;
    }

    fn update_state_machine(&mut self, now: Instant) {
        match self.state {
            State::Startup => {
                if self.full_bw_reached || self.check_startup_high_loss() {
                    self.enter_drain();
                }
            }
            State::Drain => {
                if self.bytes_in_flight <= self.bdp() {
                    self.enter_probe_bw(now);
                }
            }
            State::ProbeBW(phase) => {
                self.update_probe_bw(phase, now);
            }
            State::ProbeRTT => {
                self.update_probe_rtt(now);
            }
        }
    }

    fn update_probe_bw(&mut self, phase: ProbeBwPhase, now: Instant) {
        let elapsed = now.duration_since(self.cycle_stamp);

        // Check if it's time to enter ProbeRTT
        if now.duration_since(self.min_rtt_stamp) > PROBE_RTT_INTERVAL {
            self.enter_probe_rtt();
            return;
        }

        match phase {
            ProbeBwPhase::Up => {
                // Exit UP after one min_rtt or if inflight is above target
                if elapsed > self.min_rtt || self.bytes_in_flight > self.target_inflight() {
                    self.state = State::ProbeBW(ProbeBwPhase::Down);
                    self.pacing_gain = PROBE_BW_DOWN_GAIN;
                    self.cwnd_gain = DEFAULT_CWND_GAIN;
                    self.cycle_stamp = now;
                }
            }
            ProbeBwPhase::Down => {
                // Exit DOWN after one min_rtt or if inflight drained below BDP
                if elapsed > self.min_rtt || self.bytes_in_flight <= self.bdp() {
                    self.state = State::ProbeBW(ProbeBwPhase::Cruise);
                    self.pacing_gain = PROBE_BW_CRUISE_GAIN;
                    self.cwnd_gain = DEFAULT_CWND_GAIN;
                    self.cycle_stamp = now;
                    self.cycle_count += 1;
                }
            }
            ProbeBwPhase::Cruise => {
                // After ~6 cruise cycles, probe again
                if self.cycle_count >= 6 && elapsed > self.min_rtt {
                    self.state = State::ProbeBW(ProbeBwPhase::Up);
                    self.pacing_gain = PROBE_BW_UP_GAIN;
                    self.cwnd_gain = PROBE_BW_UP_CWND_GAIN;
                    self.cycle_stamp = now;
                    self.cycle_count = 0;
                }
            }
        }
    }

    fn update_probe_rtt(&mut self, now: Instant) {
        // Reduce cwnd to minimum
        self.cwnd = self.min_pipe_cwnd();

        if self.probe_rtt_done_stamp.is_none() && self.bytes_in_flight <= self.min_pipe_cwnd() {
            // Inflight drained, start the timer
            self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
        }

        if let Some(done) = self.probe_rtt_done_stamp {
            if now >= done {
                // Restore cwnd and return to ProbeBW
                self.min_rtt_stamp = now;
                self.cwnd = max(self.prior_cwnd, self.min_pipe_cwnd());
                self.enter_probe_bw(now);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Control parameter updates
    // -----------------------------------------------------------------------

    fn update_pacing_rate(&mut self) {
        if self.max_bw == 0 {
            return;
        }
        // Conservative BW estimate discounted by loss
        let loss_discount = 1.0 - self.current_loss_rate() * LOSS_BW_DISCOUNT;
        let effective_bw = (self.max_bw as f64 * loss_discount).max(0.0);
        self.pacing_rate = (effective_bw * self.pacing_gain).max(0.0) as u64;
    }

    fn update_cwnd(&mut self) {
        let target = self.target_inflight();

        // In ProbeRTT, cwnd is managed by update_probe_rtt
        if matches!(self.state, State::ProbeRTT) {
            return;
        }

        // Ack aggregation extra headroom
        self.extra_acked = self.ack_epoch_acked.saturating_sub(self.cwnd);
        let boost = min(self.extra_acked, self.mss * 4);

        self.cwnd = max(target + boost, self.min_pipe_cwnd());
    }

    // -----------------------------------------------------------------------
    // Main ACK processing
    // -----------------------------------------------------------------------

    fn process_ack(&mut self, acked_bytes: usize, now: Instant) {
        // Delivery rate
        let delivery_rate = self.compute_delivery_rate(acked_bytes as u64, now);

        // Update bandwidth model
        self.update_bandwidth(delivery_rate);
        self.check_full_bw_reached(delivery_rate);

        // Track ack epoch
        self.ack_epoch_acked += acked_bytes;

        // Idle restart detection
        if self.bytes_in_flight == 0 {
            self.idle_restart = true;
        } else if self.idle_restart {
            self.pacing_gain = self.pacing_gain.max(1.0);
            self.idle_restart = false;
        }

        // State machine
        self.update_state_machine(now);

        // Control updates
        self.update_pacing_rate();
        self.update_cwnd();
    }
}

// ---------------------------------------------------------------------------
// CongestionController trait implementation
// ---------------------------------------------------------------------------

impl CongestionController for Bbr2 {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        self.bytes_in_flight += sent_bytes;
        self.delivered += sent_bytes as u64;
        self.delivered_time = now;

        // Round tracking
        if self.delivered >= self.next_round_delivered {
            self.round_count += 1;
            self.round_start = true;
            self.next_round_delivered = self.delivered + self.cwnd as u64;
            // Reset per-round loss tracking
            self.loss_in_round = 0.0;
            self.round_loss_acked = 0.0;
        } else {
            self.round_start = false;
        }

        // App-limited marking
        if self.bytes_in_flight < self.cwnd / 2 {
            self.app_limited = self.delivered;
        }

        if let Some(ref cb) = self.fec_on_sent {
            cb(pkt_num, sent_bytes);
        }
    }

    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        // Process BBR2 model BEFORE updating delivery timestamp so that
        // compute_delivery_rate() sees the previous delivered_time and correctly
        // computes elapsed = now - prev_delivered_time > 0.
        self.process_ack(acked_bytes, now);

        // Update delivery tracking after rate measurement
        self.delivered += acked_bytes as u64;
        self.delivered_time = now;

        // EWMA loss tracking
        let decay = 1.0 - LOSS_ALPHA;
        self.loss_acked = self.loss_acked * decay + acked_bytes as f32;
        self.loss_lost *= decay;
        self.round_loss_acked += acked_bytes as f32;
    }

    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        if let Some(ref cb) = self.fec_on_lost {
            cb(packet_num, lost_bytes);
        }

        // EWMA loss tracking
        let decay = 1.0 - LOSS_ALPHA;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;

        // Per-round loss
        self.loss_in_round += lost_bytes as f32;

        // BBR2 loss response: reduce cwnd by lost_bytes (but not below min)
        if !matches!(self.state, State::Startup) {
            self.cwnd = max(self.cwnd.saturating_sub(lost_bytes), self.min_pipe_cwnd());
        }
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
            self.min_rtt_stamp = Instant::now();
        }
    }

    fn update_rtt_var(&mut self, rtt_var: Duration) {
        self.rtt_var = rtt_var;
    }

    fn discard_in_flight(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    fn on_persistent_congestion(&mut self, min_cwnd: usize) {
        // Restart the bandwidth model (RFC 9002 §7.6 allows a full reset).
        self.state = State::Startup;
        self.max_bw = 0;
        self.cwnd = min_cwnd.max(self.mss * 2);
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd.max(self.mss * 2);
        self.min_rtt = Duration::MAX;
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    fn pacing_rate(&self) -> Option<u64> {
        if self.pacing_rate > 0 {
            Some(self.pacing_rate)
        } else {
            None
        }
    }

    fn loss_rate(&self) -> f32 {
        let total = self.loss_acked + self.loss_lost;
        if total <= f32::EPSILON {
            0.0
        } else {
            (self.loss_lost / total).clamp(0.0, 1.0)
        }
    }

    fn mss(&self) -> usize {
        self.mss
    }

    fn send_quantum(&self) -> usize {
        min(self.cwnd, 3 * self.mss)
    }

    fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    fn set_fec_callbacks(
        &mut self,
        on_sent: Arc<dyn Fn(u64, usize) + Send + Sync>,
        on_lost: Arc<dyn Fn(u64, usize) + Send + Sync>,
    ) {
        self.fec_on_sent = Some(on_sent);
        self.fec_on_lost = Some(on_lost);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_startup() {
        let bbr = Bbr2::new(12_000, 1200);
        assert_eq!(bbr.state, State::Startup);
        assert_eq!(bbr.pacing_gain, STARTUP_PACING_GAIN);
        assert_eq!(bbr.cwnd_gain, STARTUP_CWND_GAIN);
    }

    #[test]
    fn cwnd_positive_after_ack() {
        let mut bbr = Bbr2::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 1200, now);
        bbr.on_ack(1200, now);
        assert!(bbr.cwnd() >= bbr.min_pipe_cwnd());
    }

    #[test]
    fn loss_does_not_panic() {
        let mut bbr = Bbr2::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 1200, now);
        bbr.on_loss(1200, now);
        assert!(bbr.cwnd() > 0);
    }

    #[test]
    fn pacing_rate_non_zero_after_acks() {
        let mut bbr = Bbr2::new(12_000, 1200);
        let now = Instant::now();
        // Send 10 packets at 10ms intervals. Last on_packet_sent sets
        // delivered_time = now+90ms. ACK at now+100ms → elapsed = 10ms,
        // delivery_rate = 6000/0.01 = 600_000 bytes/sec → max_bw and pacing_rate must be > 0.
        for i in 0..10_u64 {
            bbr.on_packet_sent(i, 1200, now + Duration::from_millis(i * 10));
        }
        bbr.on_ack(6000, now + Duration::from_millis(100));
        assert!(
            bbr.pacing_rate().unwrap_or(0) > 0,
            "pacing_rate must be > 0 after ACKs with time delta"
        );
        assert!(bbr.cwnd() >= bbr.min_pipe_cwnd());
    }

    #[test]
    fn min_pipe_cwnd_floor() {
        let bbr = Bbr2::new(12_000, 1200);
        assert_eq!(bbr.min_pipe_cwnd(), 4 * 1200);
    }

    #[test]
    fn loss_rate_tracking() {
        let mut bbr = Bbr2::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 6000, now);
        bbr.on_ack(3000, now);
        bbr.on_loss(3000, now);
        let lr = bbr.loss_rate();
        assert!(lr > 0.0);
        assert!(lr <= 1.0);
    }

    #[test]
    fn probe_bw_phases_exist() {
        // Verify the state enum compiles with all sub-phases
        let _up = State::ProbeBW(ProbeBwPhase::Up);
        let _down = State::ProbeBW(ProbeBwPhase::Down);
        let _cruise = State::ProbeBW(ProbeBwPhase::Cruise);
    }

    #[test]
    fn fec_callbacks_work() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mut bbr = Bbr2::new(12_000, 1200);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let sp = Arc::clone(&sent_pkt);
        let lp = Arc::clone(&lost_pkt);
        bbr.set_fec_callbacks(
            Arc::new(move |pn, _| {
                sp.store(pn, Ordering::Relaxed);
            }),
            Arc::new(move |pn, _| {
                lp.store(pn, Ordering::Relaxed);
            }),
        );
        let now = Instant::now();
        bbr.on_packet_sent(42, 1200, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 42);
        bbr.on_loss_packet(99, 1200, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 99);
    }

    #[test]
    fn bdp_calculation() {
        let mut bbr = Bbr2::new(12_000, 1200);
        bbr.max_bw = 1_000_000; // 1 MB/s
        bbr.min_rtt = Duration::from_millis(50); // 50ms
                                                 // BDP = 1_000_000 * 0.05 = 50_000
        assert_eq!(bbr.bdp(), 50_000);
    }

    #[test]
    fn max_bw_updates_after_delivery_rate() {
        // max_bw must be > 0 after ACKs with real time gaps.
        // Regression guard for the delivered_time ordering fix.
        let mut bbr = Bbr2::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        for i in 0..5_u64 {
            bbr.on_packet_sent(i, 12_000, t0 + rtt * i as u32);
            bbr.on_ack(12_000, t0 + rtt * i as u32 + rtt);
        }
        assert!(bbr.max_bw > 0, "max_bw must be non-zero after ACKs with time delta");
    }

    #[test]
    fn bytes_in_flight_tracks_send_and_ack() {
        let mut bbr = Bbr2::new(50_000, 1200);
        let now = Instant::now();
        assert_eq!(bbr.bytes_in_flight(), 0);
        bbr.on_packet_sent(1, 3600, now);
        assert_eq!(bbr.bytes_in_flight(), 3600);
        bbr.on_ack(1200, now + Duration::from_millis(20));
        assert_eq!(bbr.bytes_in_flight(), 2400);
    }

    #[test]
    fn state_exits_startup_after_bandwidth_plateau() {
        // BBR2 must leave Startup once full_bw_reached (3 rounds without 25% BW growth).
        let mut bbr = Bbr2::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        for i in 0..10_u64 {
            bbr.on_packet_sent(i, 12_000, t0 + rtt * i as u32);
            bbr.on_ack(12_000, t0 + rtt * i as u32 + rtt);
        }
        assert!(
            !matches!(bbr.state, State::Startup),
            "BBR2 must exit Startup after bandwidth plateau"
        );
    }

    #[test]
    fn can_send_respects_cwnd() {
        let mut bbr = Bbr2::new(12_000, 1200);
        let now = Instant::now();
        // Fill the window
        bbr.on_packet_sent(1, 12_000, now);
        assert!(!bbr.can_send(1), "must not send when cwnd is full");
        bbr.on_ack(12_000, now + Duration::from_millis(20));
        assert!(bbr.can_send(1200), "must allow send after window clears");
    }

    #[test]
    fn send_quantum_capped_at_3mss() {
        let bbr = Bbr2::new(100_000, 1200);
        assert_eq!(bbr.send_quantum(), 3 * 1200);
    }
}
