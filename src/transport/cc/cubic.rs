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

use core::cmp::{max, min};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::CongestionController;

// ---------------------------------------------------------------------------
// Constants (RFC 9438)
// ---------------------------------------------------------------------------

/// CUBIC multiplicative window decrease factor (fraction kept after loss).
/// RFC 9438 Section 5: BETA_CUBIC = 0.7.
const BETA_CUBIC: f64 = 0.7;
/// CUBIC scaling factor for the cubic window growth function.
/// RFC 9438 Section 5: C = 0.4.
const C: f64 = 0.4;
/// HyStart++ RTT increase threshold for early slow-start exit (8%).
/// RFC 9406 Section 4: L_THRESH.
const HYSTART_RTT_THRESH: f64 = 0.08;
/// EWMA decay factor for loss-rate tracking.
const LOSS_ALPHA: f32 = 0.1;
/// Default RTT before real measurements arrive.
const DEFAULT_RTT: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// CUBIC controller
// ---------------------------------------------------------------------------

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
    // CUBIC state
    /// Window size before the last reduction event (bytes).
    w_max: usize,
    /// Timestamp of the last reduction event (start of the current epoch).
    t_epoch: Instant,
    /// Whether the flow is in the TCP-friendly region (W_tcp > W_cubic).
    tcp_friendliness: bool,
    // HyStart++ state
    /// Whether HyStart++ is actively monitoring for slow-start exit.
    hystart_active: bool,
    /// Bytes ACKed in the current HyStart++ round.
    hystart_round_acked: usize,
    /// Congestion window at the start of the current HyStart++ round.
    hystart_round_cwnd: usize,
    /// Minimum RTT observed in the current HyStart++ round.
    hystart_curr_rtt_min: Duration,
    // Loss tracking (dual-timescale EWMA)
    loss_acked: f32,
    loss_lost: f32,
    loss_alpha: f32,
    // FEC callbacks
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
}

impl Cubic {
    /// Create a new CUBIC controller with the given initial window and MSS.
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        let now = Instant::now();
        let mss = mss.max(1);
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            mss,
            rtt: DEFAULT_RTT,
            w_max: initial_cwnd,
            t_epoch: now,
            tcp_friendliness: false,
            hystart_active: true,
            hystart_round_acked: 0,
            hystart_round_cwnd: initial_cwnd,
            hystart_curr_rtt_min: Duration::MAX,
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_alpha: LOSS_ALPHA,
            fec_on_sent: None,
            fec_on_lost: None,
        }
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Compute the CUBIC origin point K: the time to grow from the reduced
    /// window back to W_max.
    ///
    /// K = cbrt(W_max * (1 - beta) / C), in seconds, with W_max in segments.
    fn origin_point_time(&self) -> f64 {
        let w_max_seg = (self.w_max as f64) / (self.mss as f64);
        ((w_max_seg * (1.0 - BETA_CUBIC)) / C).cbrt()
    }

    /// Compute the CUBIC window W(t) = C*(t-K)^3 + W_max, in bytes.
    ///
    /// `t` is seconds since the last reduction event.
    fn cubic_window(&self, t: f64) -> usize {
        let k = self.origin_point_time();
        let w_max_seg = (self.w_max as f64) / (self.mss as f64);
        let w_cubic_seg = C * (t - k).powi(3) + w_max_seg;
        (w_cubic_seg * self.mss as f64).max(0.0) as usize
    }

    /// Compute the TCP-friendly window estimate, in bytes.
    ///
    /// W_tcp(t) = W_max*(1-beta) + [3*beta/(2-beta)] * t/RTT
    fn tcp_friendly_window(&self, t: f64) -> usize {
        let rtt_secs = self.rtt.as_secs_f64();
        if rtt_secs <= 0.0 {
            return self.cwnd;
        }
        let w_max_seg = (self.w_max as f64) / (self.mss as f64);
        let w_tcp_seg =
            w_max_seg * (1.0 - BETA_CUBIC) + (3.0 * BETA_CUBIC / (2.0 - BETA_CUBIC)) * t / rtt_secs;
        (w_tcp_seg * self.mss as f64).max(0.0) as usize
    }

    /// HyStart++ round boundary check: if all bytes from the round start
    /// have been ACKed, start a new round and reset the RTT filter.
    fn hystart_round_complete(&mut self) {
        if self.hystart_round_acked >= self.hystart_round_cwnd {
            self.hystart_round_acked = 0;
            self.hystart_round_cwnd = self.cwnd;
            self.hystart_curr_rtt_min = Duration::MAX;
        }
    }

    /// HyStart++ RTT sample processing: if the current RTT exceeds the
    /// round minimum by more than the threshold, exit slow start early.
    fn hystart_update(&mut self, rtt: Duration) {
        if !self.hystart_active || !self.in_slow_start() {
            return;
        }
        if rtt < self.hystart_curr_rtt_min {
            self.hystart_curr_rtt_min = rtt;
        }
        if self.hystart_curr_rtt_min < Duration::MAX {
            let min_secs = self.hystart_curr_rtt_min.as_secs_f64();
            let cur_secs = rtt.as_secs_f64();
            if min_secs > 0.0 && cur_secs > min_secs * (1.0 + HYSTART_RTT_THRESH) {
                // RTT inflated beyond threshold: exit slow start.
                // Set ssthresh to current cwnd to transition to congestion avoidance.
                self.ssthresh = self.cwnd;
                self.hystart_active = false;
            }
        }
    }
}

impl CongestionController for Cubic {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, _now: Instant) {
        self.bytes_in_flight += sent_bytes;
        if let Some(ref cb) = self.fec_on_sent {
            cb(pkt_num, sent_bytes);
        }
    }

    fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        if self.in_slow_start() {
            // Slow start: increase cwnd by acked_bytes (doubles per RTT)
            self.cwnd += acked_bytes;
            // HyStart++ round tracking
            if self.hystart_active {
                self.hystart_round_acked += acked_bytes;
                self.hystart_round_complete();
            }
            if self.cwnd >= self.ssthresh {
                self.cwnd = self.ssthresh;
                self.hystart_active = false;
            }
        } else {
            // CUBIC congestion avoidance
            let t = now.duration_since(self.t_epoch).as_secs_f64();
            let w_cubic = self.cubic_window(t);
            let w_tcp = self.tcp_friendly_window(t);

            // Use the larger of CUBIC and TCP-friendly as the target
            let target = max(w_cubic, w_tcp);
            self.tcp_friendliness = w_tcp > w_cubic;

            // Grow cwnd towards the target (never shrink on ACK)
            if target > self.cwnd {
                // Proportional increase: converge smoothly towards target
                let increase = ((target - self.cwnd) as f64
                    * (acked_bytes as f64 / self.cwnd.max(1) as f64))
                    as usize;
                self.cwnd += increase.max(1);
            }
        }

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked = self.loss_acked * decay + acked_bytes as f32;
        self.loss_lost *= decay;
    }

    fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        if let Some(ref cb) = self.fec_on_lost {
            cb(packet_num, lost_bytes);
        }

        // Fast convergence (RFC 9438 Section 5.6):
        // If cwnd has not reached W_max since the last reduction, the link
        // capacity may have decreased. Lower W_max accordingly.
        if (self.cwnd as f64) < (self.w_max as f64) {
            self.w_max = ((self.cwnd as f64) * (1.0 + BETA_CUBIC) / 2.0).max(0.0) as usize;
        } else {
            self.w_max = self.cwnd;
        }

        // Multiplicative decrease: cwnd = cwnd * beta
        self.ssthresh = ((self.cwnd as f64) * BETA_CUBIC) as usize;
        self.ssthresh = max(self.ssthresh, self.mss * 2);
        self.cwnd = self.ssthresh;

        // Start a new epoch
        self.t_epoch = now;
        self.hystart_active = false;

        // EWMA loss tracking
        let decay = 1.0 - self.loss_alpha;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        // HyStart++ RTT sample processing during slow start
        if self.hystart_active && self.in_slow_start() {
            self.hystart_update(rtt);
        }
    }

    fn cwnd(&self) -> usize {
        self.cwnd
    }

    fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd.max(self.mss * 2);
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    fn pacing_rate(&self) -> Option<u64> {
        let rtt_secs = self.rtt.as_secs_f64();
        if rtt_secs > 0.0 {
            let rate = (self.cwnd as f64 / rtt_secs) as u64;
            Some(rate.max(1))
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
    fn slow_start_doubles_cwnd() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        let now = Instant::now();
        let initial = cubic.cwnd();
        // ACK one MSS worth: cwnd increases by acked_bytes (doubles per RTT)
        cubic.on_ack(mss, now);
        assert_eq!(cubic.cwnd(), initial + mss);
    }

    #[test]
    fn slow_start_exits_at_ssthresh() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.ssthresh = mss * 15;
        let now = Instant::now();
        // ACK enough to push cwnd past ssthresh
        cubic.on_ack(mss * 6, now);
        assert_eq!(cubic.cwnd(), mss * 15);
        assert!(!cubic.in_slow_start());
    }

    #[test]
    fn loss_reduces_cwnd_by_beta() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.ssthresh = mss * 5; // force congestion avoidance
        cubic.cwnd = mss * 100;
        let now = Instant::now();
        cubic.on_loss(mss, now);
        // cwnd should be cwnd * beta = 100 * 0.7 = 70 MSS
        let expected = (mss as f64 * 100.0 * BETA_CUBIC) as usize;
        assert_eq!(cubic.cwnd(), expected);
        assert_eq!(cubic.ssthresh, expected);
    }

    #[test]
    fn loss_sets_w_max_to_cwnd() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.cwnd = mss * 100;
        let now = Instant::now();
        cubic.on_loss(mss, now);
        // cwnd (100*mss) >= w_max (initial 10*mss), so w_max = cwnd before reduction
        assert_eq!(cubic.w_max, mss * 100);
    }

    #[test]
    fn fast_convergence_lowers_w_max() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        // Simulate a prior reduction: w_max is high, cwnd is below it
        cubic.w_max = mss * 100;
        cubic.cwnd = mss * 50; // cwnd < w_max -> fast convergence
        let now = Instant::now();
        cubic.on_loss(mss, now);
        // w_max = cwnd * (1 + beta) / 2 = 50 * 1.7 / 2 = 42.5 MSS
        let expected_w_max = ((mss as f64 * 50.0) * (1.0 + BETA_CUBIC) / 2.0) as usize;
        assert_eq!(cubic.w_max, expected_w_max);
    }

    #[test]
    fn cubic_function_shape() {
        let mss = 1200;
        let cubic = Cubic::new(mss * 10, mss);
        // K = cbrt(w_max_seg * (1-beta) / C)
        let w_max_seg = 10.0;
        let k = ((w_max_seg * (1.0 - BETA_CUBIC)) / C).cbrt();
        // At t=K, W_cubic should equal W_max (the cubic curve reaches its peak)
        let w_at_k = cubic.cubic_window(k);
        assert_eq!(w_at_k, mss * 10);
        // At t=0, W_cubic should be below W_max (just after reduction)
        let w_at_zero = cubic.cubic_window(0.0);
        assert!(w_at_zero < mss * 10, "W(0) must be below W_max");
        // At t < K, W_cubic should be below W_max (growing towards it)
        let w_before = cubic.cubic_window(k * 0.5);
        assert!(w_before < mss * 10, "W(K/2) must be below W_max");
        // At t > K, W_cubic should be above W_max (past the origin point)
        let w_after = cubic.cubic_window(k * 1.5);
        assert!(w_after > mss * 10, "W(3K/2) must be above W_max");
    }

    #[test]
    fn cubic_origin_point_time_positive() {
        let mss = 1200;
        let cubic = Cubic::new(mss * 100, mss);
        let k = cubic.origin_point_time();
        assert!(k > 0.0, "K must be positive");
        // K = cbrt(100 * 0.3 / 0.4) = cbrt(75) ≈ 4.217
        let expected = ((100.0 * (1.0 - BETA_CUBIC)) / C).cbrt();
        assert!((k - expected).abs() < 0.001);
    }

    #[test]
    fn tcp_friendliness_grows_linearly() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.rtt = Duration::from_millis(100);
        cubic.w_max = mss * 100;
        // W_tcp(t) = W_max*(1-beta) + [3*beta/(2-beta)] * t/RTT
        let w_tcp_0 = cubic.tcp_friendly_window(0.0);
        let expected_0 = ((mss as f64 * 100.0) * (1.0 - BETA_CUBIC)) as usize;
        assert_eq!(w_tcp_0, expected_0);
        // At t = 1 RTT, W_tcp should increase by 3*beta/(2-beta) segments
        let w_tcp_1rtt = cubic.tcp_friendly_window(0.1);
        let slope = 3.0 * BETA_CUBIC / (2.0 - BETA_CUBIC);
        let expected_1rtt =
            ((mss as f64 * 100.0) * (1.0 - BETA_CUBIC) + slope * mss as f64) as usize;
        assert_eq!(w_tcp_1rtt, expected_1rtt);
        // W_tcp should be monotonically increasing in t
        assert!(w_tcp_1rtt > w_tcp_0);
    }

    #[test]
    fn congestion_avoidance_uses_max_of_cubic_and_tcp() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.ssthresh = mss * 5; // force congestion avoidance
        cubic.cwnd = mss * 70; // just after a reduction (100 * 0.7)
        cubic.w_max = mss * 100;
        cubic.rtt = Duration::from_millis(100);
        // Simulate time having passed since the reduction epoch so the
        // cubic curve has grown above the reduced cwnd.
        cubic.t_epoch = Instant::now() - Duration::from_millis(50);
        let now = Instant::now();
        let before = cubic.cwnd();
        // ACK one MSS in congestion avoidance
        cubic.on_ack(mss, now);
        // cwnd should increase (toward the cubic/tcp-friendly target)
        assert!(cubic.cwnd() > before, "cwnd must grow in congestion avoidance");
    }

    #[test]
    fn cwnd_never_below_2mss() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 2, mss);
        let now = Instant::now();
        // Multiple losses
        cubic.on_loss(mss, now);
        cubic.on_loss(mss, now);
        cubic.on_loss(mss, now);
        assert!(cubic.cwnd() >= mss * 2);
    }

    #[test]
    fn bytes_in_flight_tracks_send_and_ack() {
        let mss = 1200;
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
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.rtt = Duration::from_millis(100);
        // pacing_rate = cwnd / rtt = 12000 / 0.1 = 120000 bytes/sec
        let rate = cubic.pacing_rate().expect("CUBIC must provide a pacing rate");
        assert_eq!(rate, 120_000);
    }

    #[test]
    fn can_send_respects_cwnd() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 2, mss);
        let now = Instant::now();
        cubic.on_packet_sent(1, mss * 2, now);
        assert!(!cubic.can_send(1), "must not send when cwnd is full");
        cubic.on_ack(mss * 2, now);
        assert!(cubic.can_send(mss), "must allow send after window clears");
    }

    #[test]
    fn send_quantum_capped_at_3mss() {
        let mss = 1200;
        let cubic = Cubic::new(mss * 10, mss);
        assert_eq!(cubic.send_quantum(), 3 * mss);
    }

    #[test]
    fn loss_rate_increases_with_loss() {
        let mss = 1200;
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
        let mss = 1200;
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
    fn hystart_exits_slow_start_on_rtt_increase() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.ssthresh = mss * 1000; // high ssthresh so slow start can run
        let now = Instant::now();
        // Establish a baseline RTT
        cubic.update_rtt(Duration::from_millis(100));
        // ACK to advance slow start
        cubic.on_ack(mss * 5, now);
        assert!(cubic.in_slow_start());
        // RTT increases by more than 8% -> HyStart++ should exit slow start
        cubic.update_rtt(Duration::from_millis(120));
        assert!(!cubic.in_slow_start(), "HyStart++ must exit slow start on RTT inflation");
    }

    #[test]
    fn epoch_resets_on_loss() {
        let mss = 1200;
        let mut cubic = Cubic::new(mss * 10, mss);
        cubic.cwnd = mss * 100;
        let epoch_before = cubic.t_epoch;
        // Simulate time passing
        std::thread::sleep(Duration::from_millis(10));
        cubic.on_loss(mss, Instant::now());
        assert!(cubic.t_epoch > epoch_before, "epoch must reset on loss");
    }
}
