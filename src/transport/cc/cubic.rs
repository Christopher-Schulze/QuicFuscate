//! CUBIC congestion control (RFC 9438).
//!
//! CUBIC uses a cubic function for window growth in congestion avoidance,
//! providing better RTT-fairness and high-BDP utilization than Reno AIMD.
//! On loss, the window is reduced by a factor of beta (0.7) and grows back
//! along a cubic curve W(t) = C*(t-K)^3 + W_max, where K is the time to
//! reach W_max again. A TCP-friendly estimate ensures CUBIC does not starve
//! Reno flows. HyStart++ (RFC 9406) provides early slow-start exit by
//! detecting RTT inflation. Fast convergence adapts W_max downward when the
//! link capacity decreases.
//!
//! Reference: <https://www.rfc-editor.org/rfc/rfc9438>

use core::cmp::min;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{CongestionController, PathChangeEvent, PathChangeKind};

// ---------------------------------------------------------------------------
// Constants (RFC 9438)
// ---------------------------------------------------------------------------

/// CUBIC multiplicative window decrease factor (fraction kept after loss).
/// RFC 9438 Section 5: BETA_CUBIC = 0.7.
const BETA_CUBIC: f64 = 0.7;
/// CUBIC scaling factor for the cubic window growth function.
/// RFC 9438 Section 4.1.1: C = 0.4.
const C: f64 = 0.4;
/// Initial additive factor for the RFC 9438 Reno-friendly estimate.
const ALPHA_AIMD_INITIAL: f64 = 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC);
/// RFC 9406 Section 4.3 recommended HyStart++ tuning.
const HYSTART_MIN_RTT_THRESHOLD_NS: u64 = 4_000_000;
const HYSTART_MAX_RTT_THRESHOLD_NS: u64 = 16_000_000;
const HYSTART_MIN_RTT_DIVISOR: u64 = 8;
const HYSTART_MIN_RTT_SAMPLES: u8 = 8;
const HYSTART_CSS_GROWTH_DIVISOR: usize = 4;
const HYSTART_CSS_ROUNDS: u8 = 5;
const RTT_UNSET: u64 = u64::MAX;
const RECOVERY_NOT_STARTED: u64 = u64::MAX;
/// EWMA decay factor for loss-rate tracking.
const LOSS_ALPHA: f32 = 0.1;
/// Default RTT before real measurements arrive.
const DEFAULT_RTT: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// CUBIC controller
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HystartPhase {
    Standard,
    Conservative,
    Disabled,
}

/// CUBIC congestion controller (RFC 9438).
///
/// Window growth follows a cubic curve in congestion avoidance, with a
/// TCP-friendly fallback and HyStart++ for slow-start exit.
pub struct Cubic {
    cwnd: usize,
    ssthresh: usize,
    bytes_in_flight: usize,
    mss: usize,
    rtt: Duration,
    rtt_initialized: bool,
    // CUBIC state
    /// Window size before the last reduction event, possibly fast-converged.
    w_max: f64,
    /// Window immediately before the last ssthresh update.
    cwnd_prior: f64,
    /// RFC 9438 Reno-friendly window estimate.
    w_est: f64,
    /// Current Reno-friendly additive factor.
    alpha_aimd: f64,
    /// K for the current congestion-avoidance epoch, in seconds.
    k: f64,
    /// Fractional byte credit retained across ACKs.
    cwnd_increment: f64,
    /// Beginning of the current congestion-avoidance epoch.
    t_epoch: Instant,
    epoch_initialized: bool,
    /// Application-limited time must not advance the cubic function.
    idle_started_at: Option<Instant>,
    /// QUIC congestion recovery reduces once per recovery episode.
    largest_sent_packet: u64,
    recovery_end_packet: u64,
    // HyStart++ state
    hystart_phase: HystartPhase,
    hystart_round_acked: usize,
    hystart_round_cwnd: usize,
    hystart_last_rtt_min_ns: u64,
    hystart_current_rtt_min_ns: u64,
    hystart_pending_rtt_ns: u64,
    hystart_css_baseline_ns: u64,
    hystart_rtt_samples: u8,
    hystart_css_rounds: u8,
    hystart_css_entered_this_round: bool,
    hystart_growth_remainder: usize,
    // Loss tracking (dual-timescale EWMA)
    loss_acked: f32,
    loss_lost: f32,
    loss_alpha: f32,
    pacing_rate_override: Option<u64>,
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
}

impl Cubic {
    /// Create a new CUBIC controller with the given initial window and MSS.
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        Self::new_with_clock(initial_cwnd, mss, &crate::time_source::ProtocolClock::default())
    }

    pub(crate) fn new_with_clock(
        initial_cwnd: usize,
        mss: usize,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
        let now = clock.now();
        let mss = mss.max(1);
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            mss,
            rtt: DEFAULT_RTT,
            rtt_initialized: false,
            w_max: initial_cwnd as f64,
            cwnd_prior: initial_cwnd as f64,
            w_est: initial_cwnd as f64,
            alpha_aimd: ALPHA_AIMD_INITIAL,
            k: 0.0,
            cwnd_increment: 0.0,
            t_epoch: now,
            epoch_initialized: false,
            idle_started_at: None,
            largest_sent_packet: 0,
            recovery_end_packet: RECOVERY_NOT_STARTED,
            hystart_phase: HystartPhase::Standard,
            hystart_round_acked: 0,
            hystart_round_cwnd: initial_cwnd,
            hystart_last_rtt_min_ns: RTT_UNSET,
            hystart_current_rtt_min_ns: RTT_UNSET,
            hystart_pending_rtt_ns: RTT_UNSET,
            hystart_css_baseline_ns: RTT_UNSET,
            hystart_rtt_samples: 0,
            hystart_css_rounds: 0,
            hystart_css_entered_this_round: false,
            hystart_growth_remainder: 0,
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_alpha: LOSS_ALPHA,
            pacing_rate_override: None,
            fec_on_sent: None,
            fec_on_lost: None,
        }
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// RFC 9438 Figure 2: K = cbrt((W_max - cwnd_epoch) / C).
    fn origin_point_time(w_max: f64, cwnd_epoch: f64, mss: usize) -> f64 {
        let delta_segments = ((w_max - cwnd_epoch) / mss as f64).max(0.0);
        (delta_segments / C).cbrt()
    }

    /// RFC 9438 Figure 1: W_cubic(t) = C * (t - K)^3 + W_max.
    fn cubic_window(&self, t: f64) -> f64 {
        let w_max_segments = self.w_max / self.mss as f64;
        (C * (t - self.k).powi(3) + w_max_segments).max(0.0) * self.mss as f64
    }

    fn initialize_epoch(&mut self, now: Instant) {
        self.t_epoch = now;
        self.w_max = self.cwnd as f64;
        self.cwnd_prior = self.cwnd as f64;
        self.w_est = self.cwnd as f64;
        self.alpha_aimd = ALPHA_AIMD_INITIAL;
        self.k = 0.0;
        self.cwnd_increment = 0.0;
        self.epoch_initialized = true;
    }

    fn observe_hystart_rtt(&mut self) {
        if self.hystart_pending_rtt_ns == RTT_UNSET {
            return;
        }
        self.hystart_current_rtt_min_ns =
            self.hystart_current_rtt_min_ns.min(self.hystart_pending_rtt_ns);
        self.hystart_rtt_samples = self.hystart_rtt_samples.saturating_add(1);
        self.hystart_pending_rtt_ns = RTT_UNSET;
    }

    fn maybe_enter_conservative_slow_start(&mut self) {
        if self.hystart_phase != HystartPhase::Standard
            || self.hystart_rtt_samples < HYSTART_MIN_RTT_SAMPLES
            || self.hystart_last_rtt_min_ns == RTT_UNSET
            || self.hystart_current_rtt_min_ns == RTT_UNSET
        {
            return;
        }
        let threshold = (self.hystart_last_rtt_min_ns / HYSTART_MIN_RTT_DIVISOR)
            .clamp(HYSTART_MIN_RTT_THRESHOLD_NS, HYSTART_MAX_RTT_THRESHOLD_NS);
        if self.hystart_current_rtt_min_ns < self.hystart_last_rtt_min_ns.saturating_add(threshold)
        {
            return;
        }
        self.hystart_phase = HystartPhase::Conservative;
        self.hystart_css_baseline_ns = self.hystart_current_rtt_min_ns;
        self.hystart_css_rounds = 1;
        self.hystart_css_entered_this_round = true;
    }

    fn maybe_resume_standard_slow_start(&mut self) {
        if self.hystart_phase == HystartPhase::Conservative
            && self.hystart_rtt_samples >= HYSTART_MIN_RTT_SAMPLES
            && self.hystart_current_rtt_min_ns < self.hystart_css_baseline_ns
        {
            self.hystart_phase = HystartPhase::Standard;
            self.hystart_css_baseline_ns = RTT_UNSET;
            self.hystart_css_rounds = 0;
            self.hystart_css_entered_this_round = false;
            self.hystart_growth_remainder = 0;
        }
    }

    fn finish_hystart_round(&mut self) {
        match self.hystart_phase {
            HystartPhase::Conservative => {
                if self.hystart_rtt_samples >= HYSTART_MIN_RTT_SAMPLES
                    && self.hystart_current_rtt_min_ns < self.hystart_css_baseline_ns
                {
                    self.hystart_phase = HystartPhase::Standard;
                    self.hystart_css_baseline_ns = RTT_UNSET;
                    self.hystart_css_rounds = 0;
                    self.hystart_growth_remainder = 0;
                } else if self.hystart_css_entered_this_round {
                    self.hystart_css_entered_this_round = false;
                } else {
                    self.hystart_css_rounds = self.hystart_css_rounds.saturating_add(1);
                    if self.hystart_css_rounds >= HYSTART_CSS_ROUNDS {
                        self.ssthresh = self.cwnd;
                        self.hystart_phase = HystartPhase::Disabled;
                    }
                }
            }
            HystartPhase::Standard | HystartPhase::Disabled => {}
        }
        if self.hystart_rtt_samples > 0 {
            self.hystart_last_rtt_min_ns = self.hystart_current_rtt_min_ns;
        }
        self.hystart_round_acked = 0;
        self.hystart_round_cwnd = self.cwnd.max(self.mss);
        self.hystart_current_rtt_min_ns = RTT_UNSET;
        self.hystart_rtt_samples = 0;
    }

    fn on_slow_start_ack(&mut self, acked_bytes: usize) {
        let increase = if self.hystart_phase == HystartPhase::Conservative {
            let total = self.hystart_growth_remainder.saturating_add(acked_bytes);
            self.hystart_growth_remainder = total % HYSTART_CSS_GROWTH_DIVISOR;
            total / HYSTART_CSS_GROWTH_DIVISOR
        } else {
            acked_bytes
        };
        self.cwnd = self.cwnd.saturating_add(increase);
        self.observe_hystart_rtt();
        self.maybe_resume_standard_slow_start();
        self.hystart_round_acked = self.hystart_round_acked.saturating_add(acked_bytes);
        self.maybe_enter_conservative_slow_start();
        if self.hystart_round_acked >= self.hystart_round_cwnd.max(self.mss) {
            self.finish_hystart_round();
        }
        if self.cwnd >= self.ssthresh {
            self.cwnd = self.ssthresh;
            self.hystart_phase = HystartPhase::Disabled;
        }
    }

    fn on_congestion_avoidance_ack(&mut self, acked_bytes: usize, now: Instant) {
        if !self.epoch_initialized {
            self.initialize_epoch(now);
        }
        let elapsed = now.saturating_duration_since(self.t_epoch).as_secs_f64();
        let w_cubic_now = self.cubic_window(elapsed);
        let target = self.cubic_window(elapsed + self.rtt.as_secs_f64());
        let target = target.clamp(self.cwnd as f64, self.cwnd as f64 * 1.5);

        self.w_est +=
            self.alpha_aimd * acked_bytes as f64 * self.mss as f64 / self.cwnd.max(1) as f64;
        if self.w_est >= self.cwnd_prior {
            self.alpha_aimd = 1.0;
        }

        if w_cubic_now < self.w_est {
            let represented_window = self.cwnd as f64 + self.cwnd_increment;
            self.cwnd_increment += (self.w_est - represented_window).max(0.0);
        } else {
            self.cwnd_increment +=
                acked_bytes as f64 * (target - self.cwnd as f64) / self.cwnd.max(1) as f64;
        }
        let increase = self.cwnd_increment.floor().min(usize::MAX as f64) as usize;
        self.cwnd_increment -= increase as f64;
        self.cwnd = self.cwnd.saturating_add(increase);
        self.hystart_pending_rtt_ns = RTT_UNSET;
    }

    fn reduce_for_congestion_event(
        &mut self,
        packet_num: Option<u64>,
        lost_bytes: usize,
        now: Instant,
    ) {
        if let Some(packet_num) = packet_num {
            if self.recovery_end_packet != RECOVERY_NOT_STARTED
                && packet_num <= self.recovery_end_packet
            {
                return;
            }
            self.recovery_end_packet = self.largest_sent_packet.max(packet_num);
        }

        let cwnd_before = self.cwnd;
        if (cwnd_before as f64) < self.w_max {
            self.w_max = cwnd_before as f64 * (1.0 + BETA_CUBIC) / 2.0;
        } else {
            self.w_max = cwnd_before as f64;
        }
        self.cwnd_prior = cwnd_before as f64;

        let flight_size = self.bytes_in_flight.max(lost_bytes);
        self.ssthresh =
            ((flight_size as f64 * BETA_CUBIC) as usize).max(self.mss.saturating_mul(2));
        self.cwnd = self.ssthresh;
        self.k = Self::origin_point_time(self.w_max, self.cwnd as f64, self.mss);
        self.w_est = self.cwnd as f64;
        self.alpha_aimd = ALPHA_AIMD_INITIAL;
        self.cwnd_increment *= BETA_CUBIC;
        self.t_epoch = now;
        self.epoch_initialized = true;
        self.hystart_phase = HystartPhase::Disabled;
        self.pacing_rate_override = None;
    }

    fn update_loss_rate(&mut self, lost_bytes: usize) {
        let decay = 1.0 - self.loss_alpha;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;
    }

    pub(crate) fn raw_pacing_rate(&self) -> u64 {
        let rtt_secs = self.rtt.as_secs_f64();
        if rtt_secs <= 0.0 {
            return 1;
        }
        (self.cwnd as f64 / rtt_secs).max(1.0).min(u64::MAX as f64) as u64
    }

    pub(crate) fn set_pacing_rate_override(&mut self, rate: u64) {
        self.pacing_rate_override = Some(rate.max(1));
    }

    pub(crate) fn clear_pacing_rate_override(&mut self) {
        self.pacing_rate_override = None;
    }

    #[cfg(test)]
    fn hystart_phase(&self) -> HystartPhase {
        self.hystart_phase
    }

    #[cfg(test)]
    fn begin_congestion_avoidance_for_test(&mut self, cwnd: usize, w_max: usize, now: Instant) {
        self.cwnd = cwnd;
        self.ssthresh = cwnd;
        self.cwnd_prior = w_max as f64;
        self.w_max = w_max as f64;
        self.k = Self::origin_point_time(self.w_max, self.cwnd as f64, self.mss);
        self.w_est = self.cwnd as f64;
        self.alpha_aimd = ALPHA_AIMD_INITIAL;
        self.cwnd_increment = 0.0;
        self.t_epoch = now;
        self.epoch_initialized = true;
        self.hystart_phase = HystartPhase::Disabled;
    }

    fn update_smoothed_rtt(&mut self, sample: Duration) {
        if !self.rtt_initialized {
            self.rtt = sample;
            self.rtt_initialized = true;
            return;
        }
        self.rtt = (self.rtt * 7 + sample) / 8;
    }
}

impl CongestionController for Cubic {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        if self.bytes_in_flight == 0 {
            if let Some(idle_started_at) = self.idle_started_at.take() {
                if self.epoch_initialized {
                    let idle = now.saturating_duration_since(idle_started_at);
                    if let Some(shifted) = self.t_epoch.checked_add(idle) {
                        self.t_epoch = shifted;
                    }
                }
            }
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(sent_bytes);
        self.largest_sent_packet = self.largest_sent_packet.max(pkt_num);
        if let Some(ref cb) = self.fec_on_sent {
            cb(pkt_num, sent_bytes);
        }
    }

    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        if self.bytes_in_flight == 0 {
            self.idle_started_at = Some(now);
        }
        self.pacing_rate_override = None;

        if self.in_slow_start() {
            self.on_slow_start_ack(acked_bytes);
        } else {
            self.on_congestion_avoidance_ack(acked_bytes, now);
        }

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked = self.loss_acked * decay + acked_bytes as f32;
        self.loss_lost *= decay;
    }

    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        if let Some(ref cb) = self.fec_on_lost {
            cb(0, lost_bytes);
        }
        self.reduce_for_congestion_event(None, lost_bytes, now);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if self.bytes_in_flight == 0 {
            self.idle_started_at = Some(now);
        }
        self.update_loss_rate(lost_bytes);
    }

    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        if let Some(ref cb) = self.fec_on_lost {
            cb(packet_num, lost_bytes);
        }
        self.reduce_for_congestion_event(Some(packet_num), lost_bytes, now);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if self.bytes_in_flight == 0 {
            self.idle_started_at = Some(now);
        }
        self.update_loss_rate(lost_bytes);
    }

    fn update_rtt(&mut self, rtt: Duration) {
        if rtt == Duration::ZERO {
            return;
        }
        self.update_smoothed_rtt(rtt);
        if self.hystart_phase != HystartPhase::Disabled && self.in_slow_start() {
            self.hystart_pending_rtt_ns = rtt.as_nanos().min((RTT_UNSET - 1) as u128) as u64;
        }
    }

    fn discard_in_flight(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    fn on_path_change(&mut self, event: PathChangeEvent) {
        let congestion_window = event.congestion_window.max(self.mss * 2);
        if event.kind == PathChangeKind::PortRebinding
            && congestion_window == self.cwnd
            && event.probe_target == self.cwnd
        {
            self.recovery_end_packet = RECOVERY_NOT_STARTED;
            return;
        }

        self.cwnd = congestion_window;
        self.ssthresh = if event.kind == PathChangeKind::NewAddress {
            usize::MAX / 2
        } else {
            event.probe_target.max(self.cwnd)
        };
        self.w_max = event.probe_target.max(self.cwnd) as f64;
        self.cwnd_prior = self.cwnd as f64;
        self.w_est = self.cwnd as f64;
        self.alpha_aimd = ALPHA_AIMD_INITIAL;
        self.k = 0.0;
        self.cwnd_increment = 0.0;
        self.t_epoch = event.now;
        self.epoch_initialized = false;
        self.idle_started_at = None;
        self.recovery_end_packet = RECOVERY_NOT_STARTED;
        self.pacing_rate_override = None;

        if event.kind == PathChangeKind::NewAddress {
            self.rtt = event.validation_rtt;
            self.rtt_initialized = false;
            self.hystart_phase = HystartPhase::Standard;
            self.hystart_round_acked = 0;
            self.hystart_round_cwnd = self.cwnd;
            self.hystart_last_rtt_min_ns = RTT_UNSET;
            self.hystart_current_rtt_min_ns = RTT_UNSET;
            self.hystart_pending_rtt_ns = RTT_UNSET;
            self.hystart_css_baseline_ns = RTT_UNSET;
            self.hystart_rtt_samples = 0;
            self.hystart_css_rounds = 0;
            self.hystart_css_entered_this_round = false;
            self.hystart_growth_remainder = 0;
            self.loss_acked = 0.0;
            self.loss_lost = 0.0;
        }
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd.max(self.mss * 2);
        self.w_max = self.cwnd as f64;
        self.cwnd_prior = self.cwnd as f64;
        self.w_est = self.cwnd as f64;
        self.k = 0.0;
        self.cwnd_increment = 0.0;
        self.epoch_initialized = false;
        self.pacing_rate_override = None;
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate_override.unwrap_or_else(|| self.raw_pacing_rate()))
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
    fn slow_start_doubles_cwnd() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        let initial = cubic.cwnd();
        cubic.on_ack(mss, now);
        assert_eq!(cubic.cwnd(), initial + mss);
    }

    #[test]
    fn slow_start_exits_at_ssthresh() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.ssthresh = mss * 15;
        let now = Instant::now();
        cubic.on_ack(mss * 6, now);
        assert_eq!(cubic.cwnd(), mss * 15);
        assert!(!cubic.in_slow_start());
    }

    #[test]
    fn loss_uses_flight_size_and_reduces_once_per_recovery_episode() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        cubic.set_cwnd(mss * 100);
        for packet_num in 1..=100 {
            cubic.on_packet_sent(packet_num, mss, now);
        }
        cubic.on_loss_packet(10, mss, now + Duration::from_millis(1));
        let expected = (mss as f64 * 100.0 * BETA_CUBIC) as usize;
        assert_eq!(cubic.cwnd(), expected);
        assert_eq!(cubic.ssthresh, expected);

        cubic.on_loss_packet(11, mss, now + Duration::from_millis(1));
        cubic.on_loss_packet(12, mss, now + Duration::from_millis(1));
        assert_eq!(cubic.cwnd(), expected, "one recovery episode must reduce once");
    }

    #[test]
    fn later_recovery_episode_reduces_again() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        for packet_num in 1..=10 {
            cubic.on_packet_sent(packet_num, mss, now);
        }
        cubic.on_loss_packet(2, mss, now);
        let first = cubic.cwnd();
        let first_epoch = cubic.t_epoch;
        cubic.on_packet_sent(11, mss, now + Duration::from_millis(1));
        cubic.on_loss_packet(11, mss, now + Duration::from_millis(2));
        assert!(cubic.t_epoch > first_epoch, "new recovery episode must reset the epoch");
        assert!(cubic.cwnd() <= first);
    }

    #[test]
    fn fast_convergence_lowers_w_max() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        cubic.w_max = (mss * 100) as f64;
        cubic.cwnd = mss * 50;
        for packet_num in 1..=50 {
            cubic.on_packet_sent(packet_num, mss, now);
        }
        cubic.on_loss_packet(1, mss, now);
        let expected_w_max = ((mss as f64 * 50.0) * (1.0 + BETA_CUBIC) / 2.0) as usize;
        assert_eq!(cubic.w_max as usize, expected_w_max);
    }

    #[test]
    fn rfc9438_exact_origin_and_window_vector() {
        // Independent Figure 1/2 vector: W_max=100 segments,
        // cwnd_epoch=99.6 segments, C=0.4, therefore K=1 exactly.
        let mss = 1_000;
        let now = Instant::now();
        let mut cubic = Cubic::new(99_600, mss);
        cubic.begin_congestion_avoidance_for_test(99_600, 100_000, now);
        assert!((cubic.k - 1.0).abs() < 1e-12);
        assert!((cubic.cubic_window(0.0) - 99_600.0).abs() < 1e-9);
        assert!((cubic.cubic_window(1.0) - 100_000.0).abs() < 1e-9);
        assert!((cubic.cubic_window(2.0) - 100_400.0).abs() < 1e-9);
    }

    #[test]
    fn origin_and_window_precision_stay_below_one_part_per_million() {
        let mss = 1_200;
        let w_max = 1_000_000usize * mss;
        let cwnd_epoch = 600_000usize * mss;
        let k = Cubic::origin_point_time(w_max as f64, cwnd_epoch as f64, mss);
        let relative_error = (k - 100.0).abs() / 100.0;
        assert!(relative_error < 1e-6, "K relative error: {relative_error:e}");

        let now = Instant::now();
        let mut cubic = Cubic::new(cwnd_epoch, mss);
        cubic.begin_congestion_avoidance_for_test(cwnd_epoch, w_max, now);
        let expected = 950_000usize * mss;
        let actual = cubic.cubic_window(50.0);
        let relative_error = (actual - expected as f64).abs() / expected as f64;
        assert!(relative_error < 1e-6, "window relative error: {relative_error:e}");
    }

    #[test]
    fn reno_friendly_estimate_is_stateful_per_ack() {
        let mss = 1_200;
        let now = Instant::now();
        let mut cubic = Cubic::new(mss * 70, mss);
        cubic.begin_congestion_avoidance_for_test(mss * 70, mss * 100, now);
        cubic.update_rtt(Duration::from_millis(100));
        let before = cubic.w_est;
        cubic.on_ack(mss, now + Duration::from_millis(100));
        let expected_increment = ALPHA_AIMD_INITIAL * mss as f64 * mss as f64 / (mss * 70) as f64;
        assert!((cubic.w_est - before - expected_increment).abs() < 1e-9);
    }

    #[test]
    fn congestion_avoidance_uses_next_rtt_target() {
        let mss = 1_200;
        let now = Instant::now();
        let mut cubic = Cubic::new(mss * 70, mss);
        cubic.begin_congestion_avoidance_for_test(mss * 70, mss * 100, now);
        cubic.update_rtt(Duration::from_secs(1));
        let before = cubic.cwnd();
        cubic.on_ack(mss * 70, now);
        assert!(cubic.cwnd() > before, "cwnd must grow in congestion avoidance");
        assert!(cubic.cwnd() <= before + before / 2, "target must stay capped at 1.5*cwnd");
    }

    #[test]
    fn cwnd_never_below_2mss() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 2, mss);
        let now = Instant::now();
        cubic.on_loss(mss, now);
        cubic.on_loss(mss, now);
        cubic.on_loss(mss, now);
        assert!(cubic.cwnd() >= mss * 2);
    }

    #[test]
    fn bytes_in_flight_tracks_send_and_ack() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        assert_eq!(cubic.bytes_in_flight(), 0);
        cubic.on_packet_sent(1, mss * 3, now);
        assert_eq!(cubic.bytes_in_flight(), mss * 3);
        cubic.on_ack(mss, now);
        assert_eq!(cubic.bytes_in_flight(), mss * 2);
        cubic.on_ack(mss * 2, now);
        assert_eq!(cubic.bytes_in_flight(), 0);
    }

    #[test]
    fn pacing_rate_proportional_to_cwnd_over_rtt() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.update_rtt(Duration::from_millis(100));
        let rate = cubic.pacing_rate().expect("CUBIC must provide a pacing rate");
        assert_eq!(rate, 120_000);
    }

    #[test]
    fn can_send_respects_cwnd() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 2, mss);
        let now = Instant::now();
        cubic.on_packet_sent(1, mss * 2, now);
        assert!(!cubic.can_send(1), "must not send when cwnd is full");
        cubic.on_ack(mss * 2, now);
        assert!(cubic.can_send(mss), "must allow send after window clears");
    }

    #[test]
    fn send_quantum_capped_at_3mss() {
        let mss = 1_200;
        let cubic = Cubic::new(mss * 10, mss);
        assert_eq!(cubic.send_quantum(), 3 * mss);
    }

    #[test]
    fn loss_rate_increases_with_loss() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        cubic.on_packet_sent(1, mss * 2, now);
        cubic.on_ack(mss, now);
        cubic.on_loss(mss, now);
        let lr = cubic.loss_rate();
        assert!(lr > 0.0 && lr <= 1.0, "loss_rate must be in (0, 1] after a loss");
    }

    #[test]
    fn fec_callbacks_fire_on_send_and_loss() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let sp = Arc::clone(&sent_pkt);
        let lp = Arc::clone(&lost_pkt);
        cubic.set_fec_callbacks(
            Arc::new(move |pn, _| {
                sp.store(pn, Ordering::Relaxed);
            }),
            Arc::new(move |pn, _| {
                lp.store(pn, Ordering::Relaxed);
            }),
        );
        let now = Instant::now();
        cubic.on_packet_sent(7, mss, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 7);
        cubic.on_loss_packet(13, mss, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 13);
    }

    #[test]
    fn hystart_enters_conservative_slow_start_after_two_sampled_rounds() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        for i in 0..10 {
            cubic.update_rtt(Duration::from_millis(50));
            cubic.on_ack(mss, now + Duration::from_millis(i));
        }
        for i in 0..8 {
            cubic.update_rtt(Duration::from_millis(60));
            cubic.on_ack(mss, now + Duration::from_millis(20 + i));
        }
        assert_eq!(cubic.hystart_phase(), HystartPhase::Conservative);
    }

    #[test]
    fn hystart_css_grows_at_quarter_rate_and_recovers_from_spurious_exit() {
        let mss = 1_200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        for i in 0..10 {
            cubic.update_rtt(Duration::from_millis(50));
            cubic.on_ack(mss, now + Duration::from_millis(i));
        }
        for i in 0..8 {
            cubic.update_rtt(Duration::from_millis(60));
            cubic.on_ack(mss, now + Duration::from_millis(20 + i));
        }
        let before = cubic.cwnd();
        cubic.update_rtt(Duration::from_millis(60));
        cubic.on_ack(mss * 4, now + Duration::from_millis(30));
        assert_eq!(cubic.cwnd(), before + mss);

        let remaining = cubic.hystart_round_cwnd - cubic.hystart_round_acked;
        cubic.update_rtt(Duration::from_millis(60));
        cubic.on_ack(remaining, now + Duration::from_millis(31));
        for i in 0..8 {
            cubic.update_rtt(Duration::from_millis(50));
            cubic.on_ack(mss, now + Duration::from_millis(40 + i));
        }
        assert!(cubic.hystart_round_acked < cubic.hystart_round_cwnd);
        assert_eq!(cubic.hystart_phase(), HystartPhase::Standard);
    }

    #[test]
    fn application_limited_idle_time_does_not_advance_epoch() {
        let mss = 1_200;
        let now = Instant::now();
        let mut cubic = Cubic::new(mss * 70, mss);
        cubic.begin_congestion_avoidance_for_test(mss * 70, mss * 100, now);
        cubic.on_packet_sent(1, mss, now);
        cubic.on_ack(mss, now + Duration::from_millis(10));
        let epoch_before_idle = cubic.t_epoch;
        cubic.on_packet_sent(2, mss, now + Duration::from_millis(1_010));
        assert_eq!(
            cubic.t_epoch.saturating_duration_since(epoch_before_idle),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn controller_memory_overhead_stays_below_two_hundred_bytes() {
        let cubic_size = core::mem::size_of::<Cubic>();
        let reno_size = core::mem::size_of::<super::super::reno::Reno>();
        assert!(
            cubic_size < reno_size + 200,
            "CUBIC={cubic_size}B Reno={reno_size}B overhead={}B",
            cubic_size - reno_size
        );
    }
}
