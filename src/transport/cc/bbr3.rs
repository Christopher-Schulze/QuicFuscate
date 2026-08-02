//! BBR v3 congestion control - QuicFuscate variant.
//!
//! Four-state machine (Startup/Drain/ProbeBw/ProbeRtt) with delivery-rate-based
//! bandwidth estimation and pacing. Stealth shaping (browser gain tables, jitter)
//! is handled by [`StealthShaper`](super::stealth_shaper::StealthShaper) wrapping
//! this controller - it is not baked into the CC logic itself.

use core::cmp::min;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{configured_min_rtt_window, CongestionController, PathChangeEvent, PathChangeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
const STARTUP_GROWTH_TARGET: f64 = 1.25;
const BW_PROBE_UP_ROUNDS: u64 = 3;
const INITIAL_RTT: Duration = Duration::from_millis(100);
const STARTUP_PACING_GAIN: f64 = 2.77;

/// Default pacing gain cycle (standard BBR3 - no stealth shaping).
const DEFAULT_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

/// BBR v3 congestion controller.
pub struct Bbr3 {
    state: State,
    cwnd: usize,
    min_cwnd: usize,
    mss: usize,
    bytes_in_flight: usize,
    pacing_rate: u64,
    startup_pacing_floor: u64,
    pacing_gain: f64,
    cwnd_gain: f64,
    btlbw: u64,
    min_rtt: Duration,
    rtt: Duration,
    /// EWMA RTT variance propagated from recovery (RFC 6298 `rttvar`).
    rtt_var: Duration,
    min_rtt_window: Duration,
    min_rtt_expired: bool,
    // Loss tracking
    loss_acked: f32,
    loss_lost: f32,
    loss_alpha: f32,
    // State machine fields
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    packet_conservation: bool,
    prior_cwnd: usize,
    full_bw_reached: bool,
    full_bw: u64,
    full_bw_count: u32,
    cycle_index: usize,
    cycle_stamp: Instant,
    ack_epoch_acked: usize,
    extra_acked: usize,
    epoch_start: bool,
    idle_restart: bool,
    probe_rtt_min_us: u64,
    probe_rtt_min_stamp: Instant,
    delivered: u64,
    delivered_time: Instant,
    app_limited: u64,
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    // Gain table (overridable by StealthShaper)
    gains: [f64; 8],
}

impl Bbr3 {
    fn startup_pacing_rate(cwnd: usize, rtt: Duration, pacing_gain: f64) -> u64 {
        let rtt_seconds = rtt.max(Duration::from_millis(1)).as_secs_f64();
        ((cwnd as f64 / rtt_seconds) * pacing_gain).clamp(1.0, u64::MAX as f64) as u64
    }

    /// Create a new BBR3 controller with the given initial window and MSS.
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        let now = crate::time_source::now_instant();
        let mss = mss.max(1);
        let min_cwnd = initial_cwnd.max(mss * 4);
        let startup_pacing_floor =
            Self::startup_pacing_rate(min_cwnd, INITIAL_RTT, STARTUP_PACING_GAIN);
        Self {
            state: State::Startup,
            cwnd: min_cwnd,
            min_cwnd,
            mss,
            bytes_in_flight: 0,
            pacing_rate: startup_pacing_floor,
            startup_pacing_floor,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: 2.0,
            btlbw: 0,
            min_rtt: INITIAL_RTT,
            rtt: INITIAL_RTT,
            rtt_var: Duration::ZERO,
            min_rtt_window: configured_min_rtt_window(),
            min_rtt_expired: false,
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_alpha: 0.1,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            packet_conservation: false,
            prior_cwnd: 0,
            full_bw_reached: false,
            full_bw: 0,
            full_bw_count: 0,
            cycle_index: 0,
            cycle_stamp: now,
            ack_epoch_acked: 0,
            extra_acked: 0,
            epoch_start: false,
            idle_restart: false,
            probe_rtt_min_us: 200_000,
            probe_rtt_min_stamp: now,
            delivered: 0,
            delivered_time: now,
            app_limited: 0,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            fec_on_sent: None,
            fec_on_lost: None,
            gains: DEFAULT_GAINS,
        }
    }

    /// Mark the minimum-RTT sample stale without exposing an unbounded BDP.
    fn refresh_min_rtt_window(&mut self, now: Instant) -> bool {
        if self.min_rtt_expired {
            return true;
        }
        if now.saturating_duration_since(self.probe_rtt_min_stamp) < self.min_rtt_window {
            return false;
        }
        self.min_rtt = self.rtt;
        self.min_rtt_expired = true;
        true
    }

    /// Override the pacing gain table. Used by StealthShaper to inject
    /// browser-profile-specific gains.
    pub fn set_gains(&mut self, gains: [f64; 8]) {
        self.gains = gains;
    }

    /// The raw pacing rate before any stealth post-processing.
    pub fn raw_pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Set the pacing rate (used by StealthShaper to apply jitter).
    pub fn set_pacing_rate(&mut self, rate: u64) {
        self.pacing_rate = rate;
    }

    /// Run the BBR3 state machine on ACK.
    fn bbr3_on_ack(&mut self, acked_bytes: usize, now: Instant) {
        // `delivered_time` is an ACK clock, not a send clock. Compute the
        // delivery rate before advancing it so the interval covers the time
        // since the previous delivery sample. Updating it from on_packet_sent
        // would turn send-to-ACK latency into a false bandwidth spike.
        let delivery_rate = if now > self.delivered_time {
            let elapsed =
                now.duration_since(self.delivered_time).max(Duration::from_millis(1)).as_secs_f64();
            if elapsed > 0.0 {
                (acked_bytes as f64 / elapsed).max(0.0) as u64
            } else {
                self.btlbw
            }
        } else {
            self.btlbw
        };

        // Update delivery tracking AFTER rate computation
        self.delivered += acked_bytes as u64;
        self.delivered_time = now;
        self.round_start = self.delivered >= self.next_round_delivered;
        if self.round_start {
            self.round_count = self.round_count.saturating_add(1);
            self.next_round_delivered = self.delivered.saturating_add(self.cwnd as u64);
            self.epoch_start = true;
            self.ack_epoch_acked = 0;
        }
        self.ack_epoch_acked += acked_bytes;

        if delivery_rate > self.btlbw {
            self.btlbw = delivery_rate;
        }
        if self.round_start && !self.full_bw_reached {
            if self.full_bw == 0
                || (self.btlbw as f64) >= (self.full_bw as f64) * STARTUP_GROWTH_TARGET
            {
                self.full_bw = self.btlbw;
                self.full_bw_count = 0;
            } else {
                self.full_bw_count = self.full_bw_count.saturating_add(1);
                if self.full_bw_count >= BW_PROBE_UP_ROUNDS as u32 {
                    self.full_bw_reached = true;
                }
            }
        }

        // State machine transitions
        let min_rtt_expired = self.refresh_min_rtt_window(now);
        match self.state {
            State::Startup => {
                if self.full_bw_reached {
                    self.state = State::Drain;
                    self.pacing_gain = 0.35;
                    self.cwnd_gain = 2.0;
                    self.packet_conservation = true;
                }
            }
            State::Drain => {
                let bdp = (self.btlbw as f64 * self.min_rtt.as_secs_f64()) as usize;
                if self.bytes_in_flight <= bdp {
                    self.state = State::ProbeBw;
                    self.cycle_index = 0;
                    self.cycle_stamp = now;
                    self.pacing_gain = self.gains[0];
                    self.cwnd_gain = 2.0;
                    self.packet_conservation = false;
                }
            }
            State::ProbeBw => {
                if now.duration_since(self.cycle_stamp) > self.min_rtt {
                    let next = (self.cycle_index + 1) % 8;
                    self.cycle_index = next;
                    self.pacing_gain = self.gains[next];
                    self.cycle_stamp = now;
                }
                // PROBE_RTT shrinks cwnd to 4*MSS to re-measure min_rtt; doing
                // that while the path is unstable (high EWMA variance) would
                // sacrifice throughput without yielding a usable min sample.
                // Defer entry until rttvar settles at or below min_rtt/8.
                if (min_rtt_expired
                    || now.saturating_duration_since(self.probe_rtt_min_stamp)
                        > std::cmp::max(
                            self.min_rtt_window,
                            Duration::from_micros(self.probe_rtt_min_us),
                        ))
                    && self.rtt_var <= self.min_rtt / 8
                {
                    self.state = State::ProbeRtt;
                    self.prior_cwnd = self.cwnd;
                    self.probe_rtt_done_stamp = Some(now + PROBE_RTT_DURATION);
                }
            }
            State::ProbeRtt => {
                self.cwnd = self.mss * 4;
                if let Some(done) = self.probe_rtt_done_stamp {
                    if now >= done {
                        self.state = State::ProbeBw;
                        self.cwnd = self.prior_cwnd;
                        self.probe_rtt_min_stamp = now;
                        self.min_rtt_expired = false;
                        self.probe_rtt_round_done = true;
                    }
                }
            }
        }

        // Update cwnd
        self.extra_acked = self.ack_epoch_acked.saturating_sub(self.cwnd);
        let burst_boost = ((self.extra_acked / self.mss).min(4)) * self.mss;
        let mut target_cwnd = (self.cwnd_gain * self.btlbw as f64 * self.min_rtt.as_secs_f64())
            as usize
            + burst_boost;
        if self.epoch_start {
            target_cwnd = target_cwnd.saturating_add(self.mss);
            self.epoch_start = false;
        }
        let cwnd_floor =
            if matches!(self.state, State::ProbeRtt) { self.mss * 4 } else { self.min_cwnd };
        self.cwnd = std::cmp::max(target_cwnd, cwnd_floor);

        // Update pacing rate
        if self.bytes_in_flight == 0 {
            self.idle_restart = true;
        } else if self.idle_restart {
            self.pacing_gain = self.pacing_gain.max(1.0);
            self.idle_restart = false;
        }
        let model_rate = (self.pacing_gain * self.btlbw as f64).max(0.0) as u64;
        self.pacing_rate = if matches!(self.state, State::Startup) {
            self.startup_pacing_floor.max(model_rate)
        } else {
            model_rate
        };
    }

    fn update_rtt_at(&mut self, rtt: Duration, now: Instant) {
        self.rtt = rtt;
        let window_expired =
            now.saturating_duration_since(self.probe_rtt_min_stamp) >= self.min_rtt_window;
        if self.min_rtt_expired || window_expired || rtt < self.min_rtt {
            self.min_rtt = rtt;
            self.probe_rtt_min_stamp = now;
            self.min_rtt_expired = false;
        }
    }
}

impl CongestionController for Bbr3 {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(sent_bytes);

        if self.bytes_in_flight < self.cwnd / 2 {
            self.app_limited = self.delivered;
        }

        if let Some(ref cb) = self.fec_on_sent {
            cb(pkt_num, sent_bytes);
        }
    }

    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        self.bbr3_on_ack(acked_bytes, now);

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked = self.loss_acked * decay + acked_bytes as f32;
        self.loss_lost *= decay;
    }

    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        if let Some(ref cb) = self.fec_on_lost {
            cb(packet_num, lost_bytes);
        }

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.update_rtt_at(rtt, crate::time_source::now_instant());
    }

    fn update_rtt_var(&mut self, rtt_var: Duration) {
        self.rtt_var = rtt_var;
    }

    fn discard_in_flight(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    fn on_persistent_congestion(&mut self, min_cwnd: usize) {
        // Restart the bandwidth model from scratch (RFC 9002 §7.6 allows a full
        // reset). Keep model-reset semantics explicit instead of routing this
        // through the public window setter.
        self.state = State::Startup;
        self.btlbw = 0;
        self.full_bw = 0;
        self.full_bw_reached = false;
        self.full_bw_count = 0;
        self.cwnd = min_cwnd.max(self.mss * 2);
        self.min_cwnd = self.cwnd.max(self.mss * 4);
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.startup_pacing_floor =
            Self::startup_pacing_rate(self.cwnd, self.rtt, self.pacing_gain);
        self.pacing_rate = self.startup_pacing_floor;
        self.cwnd_gain = 2.0;
        self.packet_conservation = false;
    }

    fn on_path_change(&mut self, event: PathChangeEvent) {
        self.cwnd = event.congestion_window.max(self.mss * 2);
        self.min_cwnd = event.probe_target.max(self.cwnd).max(self.mss * 4);
        self.ack_epoch_acked = 0;
        self.extra_acked = 0;
        self.epoch_start = false;
        self.idle_restart = false;
        self.probe_rtt_done_stamp = None;
        self.probe_rtt_round_done = false;
        self.prior_cwnd = event.probe_target.max(self.cwnd);

        if event.kind == PathChangeKind::NewAddress {
            self.state = State::Startup;
            self.pacing_gain = STARTUP_PACING_GAIN;
            self.cwnd_gain = 2.0;
            self.btlbw = 0;
            self.min_rtt = event.validation_rtt;
            self.rtt = event.validation_rtt;
            self.rtt_var = event.validation_rtt / 2;
            self.loss_acked = 0.0;
            self.loss_lost = 0.0;
            self.packet_conservation = false;
            self.full_bw_reached = false;
            self.full_bw = 0;
            self.full_bw_count = 0;
            self.cycle_index = 0;
            self.cycle_stamp = event.now;
            self.probe_rtt_min_stamp = event.now;
            self.min_rtt_expired = false;
            self.delivered = 0;
            self.delivered_time = event.now;
            self.app_limited = 0;
            self.round_count = 0;
            self.round_start = false;
            self.next_round_delivered = 0;
            self.startup_pacing_floor =
                Self::startup_pacing_rate(self.cwnd, self.rtt, STARTUP_PACING_GAIN);
            self.pacing_rate = self.startup_pacing_floor;
        }
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd.max(self.mss * 2);
        self.min_cwnd = self.cwnd.max(self.mss * 4);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_in_startup() {
        let bbr = Bbr3::new(12_000, 1200);
        assert_eq!(bbr.state, State::Startup);
        assert!(bbr.cwnd() >= 12_000);
        assert_eq!(
            bbr.pacing_rate(),
            Some(Bbr3::startup_pacing_rate(12_000, INITIAL_RTT, STARTUP_PACING_GAIN))
        );
    }

    #[test]
    fn slow_first_ack_does_not_collapse_startup_pacing() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let initial_rate = bbr.pacing_rate().expect("startup pacing must be initialized");
        let now = Instant::now();

        bbr.on_packet_sent(1, 1200, now);
        bbr.on_ack(1200, now + Duration::from_secs(10));
        bbr.set_pacing_rate(1);
        bbr.on_packet_sent(2, 1200, now + Duration::from_secs(10));
        bbr.on_ack(1200, now + Duration::from_secs(20));

        assert_eq!(bbr.state, State::Startup);
        assert!(
            bbr.pacing_rate().is_some_and(|rate| rate >= initial_rate),
            "a transient slow first delivery sample must not schedule a multi-second startup stall"
        );
    }

    #[test]
    fn cwnd_positive_after_ack() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 1200, now);
        bbr.on_ack(1200, now);
        // BBR3 cwnd is BDP-based (not additive like Reno); it may shrink
        // toward the BDP estimate, but must stay >= 4*MSS minimum.
        assert!(bbr.cwnd() >= 1200 * 4);
    }

    #[test]
    fn loss_does_not_panic() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 1200, now);
        bbr.on_loss(1200, now);
        assert!(bbr.cwnd() > 0);
    }

    #[test]
    fn custom_gains_applied() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let custom: [f64; 8] = [1.5, 0.5, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
        bbr.set_gains(custom);
        assert_eq!(bbr.gains, custom);
    }

    #[test]
    fn btlbw_updates_after_delivery_rate_measurement() {
        // Verifies the delivery-rate fix: btlbw must be > 0 after ACKs with
        // real time gaps (send_time != ack_time).
        let mut bbr = Bbr3::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        for i in 0..5_u32 {
            bbr.on_packet_sent(i as u64, 12_000, t0 + rtt * i);
            bbr.on_ack(12_000, t0 + rtt * i + rtt);
        }
        assert!(bbr.btlbw > 0, "btlbw must be non-zero after ACKs with time delta");
    }

    #[test]
    fn send_events_do_not_count_as_delivered_or_reset_delivery_clock() {
        let mut bbr = Bbr3::new(50_000, 1200);
        let delivered_before = bbr.delivered;
        let delivery_clock_before = bbr.delivered_time;

        bbr.on_packet_sent(1, 12_000, delivery_clock_before + Duration::from_millis(100));

        assert_eq!(bbr.delivered, delivered_before);
        assert_eq!(bbr.delivered_time, delivery_clock_before);
    }

    #[test]
    fn send_to_ack_gap_does_not_create_a_false_bandwidth_spike() {
        let mut bbr = Bbr3::new(50_000, 1200);
        let start = bbr.delivered_time;
        bbr.on_packet_sent(1, 1200, start + Duration::from_millis(100));
        bbr.on_ack(1200, start + Duration::from_millis(101));

        assert!(bbr.btlbw < 100_000, "send timestamp must not become the delivery-rate clock");
    }

    #[test]
    fn delivery_time_advances_only_on_ack_samples() {
        let mut bbr = Bbr3::new(50_000, 1200);
        let start = bbr.delivered_time;
        let sent_at = start + Duration::from_millis(100);
        let acked_at = sent_at + Duration::from_millis(1);

        bbr.on_packet_sent(1, 1200, sent_at);
        assert_eq!(bbr.delivered_time, start);

        bbr.on_ack(1200, acked_at);
        assert_eq!(bbr.delivered_time, acked_at);
        assert!(
            (11_800..=12_000).contains(&bbr.btlbw),
            "delivery rate must use the 101 ms ACK interval, got {}",
            bbr.btlbw
        );
    }

    #[test]
    fn ordinary_ack_does_not_collapse_below_initial_window() {
        let mut bbr = Bbr3::new(50_000, 1200);
        let start = bbr.delivered_time;
        bbr.on_packet_sent(1, 1200, start);
        bbr.on_ack(1200, start + Duration::from_millis(100));

        assert_eq!(bbr.cwnd(), 50_000);
    }

    #[test]
    fn pacing_rate_nonzero_after_convergence() {
        // Pacing rate is btlbw * pacing_gain; both must be > 0 once bandwidth
        // is estimated. Regression guard for the delivered_time ordering bug.
        let mut bbr = Bbr3::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        for i in 0..10_u32 {
            bbr.on_packet_sent(i as u64, 12_000, t0 + rtt * i);
            bbr.on_ack(12_000, t0 + rtt * i + rtt);
        }
        assert!(bbr.pacing_rate().unwrap_or(0) > 0, "pacing_rate must be > 0 after enough ACKs");
    }

    #[test]
    fn state_machine_exits_startup_on_bw_plateau() {
        // After enough rounds without 25% BW growth (BW_PROBE_UP_ROUNDS = 3),
        // full_bw_reached is set and state transitions to Drain.
        let mut bbr = Bbr3::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        bbr.update_rtt(rtt);
        // Send/ACK at constant rate - no growth - should hit plateau after 3+ rounds
        for i in 0..20_u32 {
            bbr.on_packet_sent(i as u64, 12_000, t0 + rtt * i);
            bbr.on_ack(12_000, t0 + rtt * i + rtt);
        }
        // Should have left Startup (either Drain or ProbeBW/ProbeRTT)
        assert!(
            !matches!(bbr.state, State::Startup),
            "BBR3 must exit Startup after bandwidth plateau"
        );
    }

    #[test]
    fn bytes_in_flight_tracks_send_and_ack() {
        let mut bbr = Bbr3::new(50_000, 1200);
        let now = Instant::now();
        assert_eq!(bbr.bytes_in_flight(), 0);
        bbr.on_packet_sent(1, 3600, now);
        assert_eq!(bbr.bytes_in_flight(), 3600);
        bbr.on_ack(1200, now + Duration::from_millis(20));
        assert_eq!(bbr.bytes_in_flight(), 2400);
        bbr.on_ack(2400, now + Duration::from_millis(40));
        assert_eq!(bbr.bytes_in_flight(), 0);
    }

    #[test]
    fn bytes_in_flight_send_saturates_at_usize_max() {
        let mut bbr = Bbr3::new(12_000, 1200);
        bbr.bytes_in_flight = usize::MAX - 10;
        bbr.on_packet_sent(1, 20, Instant::now());
        assert_eq!(bbr.bytes_in_flight(), usize::MAX);
    }

    #[test]
    fn min_rtt_window_replaces_stale_sample() {
        let mut bbr = Bbr3::new(12_000, 1200);
        bbr.min_rtt_window = Duration::from_millis(10);
        let initial_stamp = bbr.probe_rtt_min_stamp;
        bbr.update_rtt_at(Duration::from_millis(20), initial_stamp + Duration::from_millis(1));
        let sample_stamp = bbr.probe_rtt_min_stamp;

        bbr.update_rtt_at(Duration::from_millis(50), sample_stamp + Duration::from_millis(11));

        assert_eq!(bbr.min_rtt, Duration::from_millis(50));
        assert!(!bbr.min_rtt_expired);
        assert_eq!(bbr.probe_rtt_min_stamp, sample_stamp + Duration::from_millis(11));
    }

    #[test]
    fn set_cwnd_preserves_min_rtt_sample() {
        let mut bbr = Bbr3::new(12_000, 1200);
        bbr.min_rtt = Duration::from_millis(25);
        bbr.set_cwnd(24_000);
        assert_eq!(bbr.min_rtt, Duration::from_millis(25));
    }

    #[test]
    fn can_send_respects_cwnd() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 12_000, now);
        assert!(!bbr.can_send(1), "must not send when cwnd is full");
        bbr.on_ack(12_000, now + Duration::from_millis(20));
        assert!(bbr.can_send(1200), "must allow send after window clears");
    }

    #[test]
    fn send_quantum_capped_at_3mss() {
        let bbr = Bbr3::new(100_000, 1200);
        assert_eq!(bbr.send_quantum(), 3 * 1200);
    }

    #[test]
    fn loss_rate_tracking() {
        let mut bbr = Bbr3::new(12_000, 1200);
        let now = Instant::now();
        bbr.on_packet_sent(1, 6000, now);
        bbr.on_ack(3000, now + Duration::from_millis(20));
        bbr.on_loss(3000, now + Duration::from_millis(20));
        let lr = bbr.loss_rate();
        assert!(lr > 0.0);
        assert!(lr <= 1.0);
    }

    #[test]
    fn fec_callbacks_work() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;
        let mut bbr = Bbr3::new(12_000, 1200);
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
    fn set_pacing_rate_overrides_internal() {
        let mut bbr = Bbr3::new(12_000, 1200);
        bbr.set_pacing_rate(999_999);
        assert_eq!(bbr.raw_pacing_rate(), 999_999);
    }

    #[test]
    fn probe_rtt_entered_and_cwnd_floor_holds() {
        // Verify that entering ProbeRTT does not drop cwnd below 4*MSS floor.
        // The cwnd is recalculated each on_ack cycle so the floor comes from
        // the max(target_cwnd, mss*4) at the end of bbr3_on_ack.
        let mut bbr = Bbr3::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        // Converge to ProbeBW first
        for i in 0..10_u32 {
            bbr.on_packet_sent(i as u64, 12_000, t0 + rtt * i);
            bbr.on_ack(12_000, t0 + rtt * i + rtt);
        }
        // Trigger ProbeRTT by advancing time past MIN_RTT_WIN
        let probe_offset = super::super::DEFAULT_MIN_RTT_WINDOW + Duration::from_secs(1);
        bbr.on_packet_sent(100, 1200, t0 + probe_offset);
        bbr.on_ack(1200, t0 + probe_offset + rtt);
        // cwnd must always be at or above 4*MSS regardless of state
        assert!(bbr.cwnd() >= bbr.mss * 4, "cwnd must not drop below 4*MSS floor");
    }

    #[test]
    fn drain_exits_to_probebw_when_inflight_drains() {
        // Verify that when in Drain, bytes_in_flight <= BDP triggers ProbeBW.
        let mut bbr = Bbr3::new(50_000, 1200);
        let t0 = Instant::now();
        let rtt = Duration::from_millis(20);
        bbr.update_rtt(rtt);
        // Get out of Startup
        for i in 0..20_u32 {
            bbr.on_packet_sent(i as u64, 12_000, t0 + rtt * i);
            bbr.on_ack(12_000, t0 + rtt * i + rtt);
        }
        // If we landed in Drain, ACK enough to drain inflight and trigger ProbeBW
        if matches!(bbr.state, State::Drain) {
            let ack_t = t0 + rtt * 20;
            bbr.on_ack(bbr.bytes_in_flight().saturating_sub(100), ack_t);
            // Should now be in ProbeBW
            assert!(
                matches!(bbr.state, State::ProbeBw | State::ProbeRtt),
                "BBR3 must leave Drain once inflight drops below BDP"
            );
        } else {
            // Already in ProbeBW - the drain completed during convergence
            assert!(!matches!(bbr.state, State::Startup), "BBR3 must not be stuck in Startup");
        }
    }
}
