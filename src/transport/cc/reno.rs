//! TCP New Reno congestion control (RFC 6582).
//!
//! Conservative AIMD baseline: additive increase of MSS^2/cwnd per ACK in
//! congestion avoidance, multiplicative decrease to cwnd/2 on loss.
//! Slow start doubles cwnd per RTT until ssthresh is reached.

use core::cmp::min;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{CongestionController, PathChangeEvent, PathChangeKind};

/// TCP New Reno congestion controller.
pub struct Reno {
    cwnd: usize,
    ssthresh: usize,
    bytes_in_flight: usize,
    mss: usize,
    rtt: Duration,
    loss_acked: f32,
    loss_lost: f32,
    loss_alpha: f32,
    largest_sent_packet: u64,
    recovery_end_packet: Option<u64>,
    fec_on_sent: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
    fec_on_lost: Option<Arc<dyn Fn(u64, usize) + Send + Sync>>,
}

impl Reno {
    /// Create a new Reno controller with the given initial window and MSS.
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            mss: mss.max(1),
            rtt: Duration::from_millis(100),
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_alpha: 0.1,
            largest_sent_packet: 0,
            recovery_end_packet: None,
            fec_on_sent: None,
            fec_on_lost: None,
        }
    }

    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
}

impl CongestionController for Reno {
    fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(sent_bytes);
        self.largest_sent_packet = self.largest_sent_packet.max(pkt_num);
        if let Some(ref cb) = self.fec_on_sent {
            cb(pkt_num, sent_bytes);
        }
    }

    fn on_ack(&mut self, acked_bytes: usize, _now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);

        if self.in_slow_start() {
            // Slow start: increase cwnd by acked_bytes (doubles per RTT)
            self.cwnd += acked_bytes;
            if self.cwnd > self.ssthresh {
                self.cwnd = self.ssthresh;
            }
        } else {
            // Congestion avoidance: AIMD additive increase
            // Increase by MSS * acked_bytes / cwnd per ACK (roughly MSS per RTT)
            let increase =
                (self.mss as u64 * acked_bytes as u64 / self.cwnd.max(1) as u64) as usize;
            self.cwnd += increase.max(1);
        }

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

        let starts_recovery = packet_num == 0
            || self.recovery_end_packet.is_none_or(|recovery_end| packet_num > recovery_end);
        if starts_recovery {
            self.ssthresh = (self.cwnd / 2).max(self.mss * 2);
            self.cwnd = self.ssthresh;
            self.recovery_end_packet = Some(self.largest_sent_packet);
        }

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;
    }

    fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
    }

    fn discard_in_flight(&mut self, bytes: usize) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
    }

    fn on_path_change(&mut self, event: PathChangeEvent) {
        self.cwnd = event.congestion_window.max(self.mss * 2);
        self.ssthresh = if event.kind == PathChangeKind::NewAddress {
            usize::MAX / 2
        } else {
            event.probe_target.max(self.cwnd)
        };
        self.recovery_end_packet = None;
        if event.kind == PathChangeKind::NewAddress {
            self.rtt = event.validation_rtt;
            self.loss_acked = 0.0;
            self.loss_lost = 0.0;
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
        // Bounded delivery-rate pacing (RFC 9002 §7.7 recommends pacing to
        // avoid burst losses): 1.25*cwnd/SRTT, clamped to [1 MSS/RTT, 2*cwnd/RTT].
        let rtt = self.rtt.max(Duration::from_millis(1));
        let rtt_secs = rtt.as_secs_f64();
        let rate = (self.cwnd as f64 * 1.25) / rtt_secs;
        let floor = self.mss as f64 / rtt_secs;
        let ceil = (self.cwnd.max(self.mss) as f64 * 2.0) / rtt_secs;
        Some((rate.clamp(floor, ceil).max(1.0)) as u64)
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
    fn slow_start_doubles_cwnd() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        let now = Instant::now();
        let initial = reno.cwnd();
        // ACK one MSS worth
        reno.on_ack(mss, now);
        assert_eq!(reno.cwnd(), initial + mss);
    }

    #[test]
    fn loss_halves_cwnd() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        reno.ssthresh = mss * 6; // force into congestion avoidance
        reno.cwnd = mss * 10;
        let now = Instant::now();
        reno.on_loss(mss, now);
        assert_eq!(reno.cwnd(), mss * 5); // halved
        assert_eq!(reno.ssthresh, mss * 5);
    }

    #[test]
    fn packet_losses_reduce_once_per_recovery_episode() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        let now = Instant::now();
        for packet_num in 1..=10 {
            reno.on_packet_sent(packet_num, mss, now);
        }
        reno.on_loss_packet(2, mss, now);
        let reduced = reno.cwnd();
        reno.on_loss_packet(3, mss, now);
        reno.on_loss_packet(4, mss, now);
        assert_eq!(reno.cwnd(), reduced);

        reno.on_packet_sent(11, mss, now);
        reno.on_loss_packet(11, mss, now);
        assert!(reno.cwnd() < reduced);
    }

    #[test]
    fn congestion_avoidance_linear_growth() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        reno.ssthresh = mss * 5; // below cwnd -> congestion avoidance
        reno.cwnd = mss * 10;
        let now = Instant::now();
        let before = reno.cwnd();
        // ACK one MSS
        reno.on_ack(mss, now);
        let after = reno.cwnd();
        // In congestion avoidance, increase should be roughly mss * mss / cwnd
        let expected_increase = (mss as u64 * mss as u64 / before as u64) as usize;
        assert_eq!(after - before, expected_increase.max(1));
    }

    #[test]
    fn cwnd_never_below_2mss() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 2, mss);
        reno.ssthresh = mss; // minimal
        reno.cwnd = mss * 2;
        let now = Instant::now();
        // Multiple losses
        reno.on_loss(mss, now);
        reno.on_loss(mss, now);
        reno.on_loss(mss, now);
        assert!(reno.cwnd() >= mss * 2);
    }

    #[test]
    fn bytes_in_flight_tracks_send_and_ack() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        let now = Instant::now();
        assert_eq!(reno.bytes_in_flight(), 0);
        reno.on_packet_sent(1, mss * 3, now);
        assert_eq!(reno.bytes_in_flight(), mss * 3);
        reno.on_ack(mss, now);
        assert_eq!(reno.bytes_in_flight(), mss * 2);
        reno.on_ack(mss * 2, now);
        assert_eq!(reno.bytes_in_flight(), 0);
    }

    #[test]
    fn bytes_in_flight_send_saturates_at_usize_max() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        reno.bytes_in_flight = usize::MAX - 10;
        reno.on_packet_sent(1, 20, Instant::now());
        assert_eq!(reno.bytes_in_flight(), usize::MAX);
    }

    #[test]
    fn pacing_rate_is_bounded_delivery_rate() {
        // RFC 9002 §7.7 recommends pacing; Reno paces at 1.25*cwnd/SRTT,
        // clamped to [1 MSS/RTT, 2*cwnd/RTT].
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        reno.update_rtt(Duration::from_millis(100));
        // cwnd = 12_000, rtt = 100 ms -> 12_000*1.25/0.1 = 150_000 B/s.
        assert_eq!(reno.pacing_rate(), Some(150_000));
        // Extreme RTT stays within bounds; zero RTT cannot divide by zero.
        reno.update_rtt(Duration::from_millis(1));
        assert_eq!(reno.pacing_rate(), Some(15_000_000));
        reno.update_rtt(Duration::ZERO);
        assert!(reno.pacing_rate().is_some_and(|r| r > 0));
    }

    #[test]
    fn can_send_respects_cwnd() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 2, mss);
        let now = Instant::now();
        reno.on_packet_sent(1, mss * 2, now);
        assert!(!reno.can_send(1), "must not send when cwnd is full");
        reno.on_ack(mss * 2, now);
        assert!(reno.can_send(mss), "must allow send after window clears");
    }

    #[test]
    fn send_quantum_capped_at_3mss() {
        let mss = 1200;
        let reno = Reno::new(mss * 10, mss);
        // send_quantum = min(cwnd, 3*mss) = 3600 when cwnd > 3*mss
        assert_eq!(reno.send_quantum(), 3 * mss);
    }

    #[test]
    fn loss_rate_increases_with_loss() {
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        let now = Instant::now();
        reno.on_packet_sent(1, mss * 2, now);
        reno.on_ack(mss, now);
        reno.on_loss(mss, now);
        let lr = reno.loss_rate();
        assert!(lr > 0.0 && lr <= 1.0, "loss_rate must be in (0, 1] after a loss");
    }

    #[test]
    fn fec_callbacks_fire_on_send_and_loss() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let mss = 1200;
        let mut reno = Reno::new(mss * 10, mss);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let sp = Arc::clone(&sent_pkt);
        let lp = Arc::clone(&lost_pkt);
        reno.set_fec_callbacks(
            Arc::new(move |pn, _| {
                sp.store(pn, Ordering::Relaxed);
            }),
            Arc::new(move |pn, _| {
                lp.store(pn, Ordering::Relaxed);
            }),
        );
        let now = Instant::now();
        reno.on_packet_sent(7, mss, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 7);
        reno.on_loss_packet(13, mss, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 13);
    }
}
