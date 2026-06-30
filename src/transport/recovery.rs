//! QUIC loss recovery with pluggable congestion control.
//!
//! [`Recovery`] delegates congestion window and pacing decisions to the
//! [`cc`](super::cc) module's [`CongestionController`](super::cc::CongestionController)
//! implementations (Reno, BBR3) while owning PTO state, loss tracking, and the
//! memory pool reference.

use core::cmp::min;
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

pub use super::cc::stealth_shaper::BrowserProfile;
use super::cc::{self, CcImpl, CongestionController};

/// QUIC loss recovery and congestion control state.
///
/// Wraps a pluggable [`CongestionController`] and adds PTO, loss time tracking,
/// batch size, and memory pool management.
pub struct Recovery {
    /// Current congestion window in bytes (synced from CC after each operation).
    pub cwnd: usize,
    /// Slow-start threshold in bytes.
    pub ssthresh: usize,
    /// Bytes currently considered in flight (synced from CC).
    pub bytes_in_flight: usize,
    /// Smoothed round-trip time estimate (EWMA per RFC 6298).
    pub rtt: Duration,
    /// RTT variation (EWMA per RFC 6298).
    rtt_var: Duration,
    /// Minimum RTT observed (for RACK and BBR).
    min_rtt: Duration,
    /// Whether we have a valid RTT sample yet.
    rtt_initialized: bool,
    /// Probe Timeout counter (exponential backoff).
    pub pto_count: u32,
    /// Timestamp of the most recent loss event.
    pub loss_time: Option<Instant>,
    /// Whether HyStart slow-start exit is enabled.
    pub hystart: bool,
    /// Whether packet pacing is enabled.
    pub pacing: bool,
    mss: usize,
    batch_size: usize,
    cc: CcImpl,
    mem_pool: Arc<crate::optimize::MemoryPool>,
}

impl Recovery {
    /// Creates a new Recovery state with the default algorithm (BBR3).
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        Self::with_algorithm(initial_cwnd, mss, cc::Algorithm::Bbr3)
    }

    /// Creates a new Recovery state with the given algorithm.
    pub fn with_algorithm(initial_cwnd: usize, mss: usize, algo: cc::Algorithm) -> Self {
        let mss = mss.max(1);
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            rtt: Duration::from_millis(100),
            rtt_var: Duration::from_millis(50),
            min_rtt: Duration::MAX,
            rtt_initialized: false,
            pto_count: 0,
            loss_time: None,
            hystart: true,
            pacing: true,
            mss,
            batch_size: 16,
            cc: cc::create(algo, initial_cwnd, mss),
            mem_pool: crate::optimize::global_pool(),
        }
    }

    /// Creates a new Recovery state with a custom memory pool.
    pub fn with_memory_pool(
        initial_cwnd: usize,
        mss: usize,
        pool: Arc<crate::optimize::MemoryPool>,
    ) -> Self {
        let mut s = Self::new(initial_cwnd, mss);
        s.mem_pool = pool;
        s
    }

    /// Override the initial RTT estimate used before real measurements arrive.
    pub fn set_initial_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        self.cc.update_rtt(rtt);
    }

    /// Enables or disables stealth congestion shaping with the given browser profile.
    ///
    /// When enabled, wraps the current CC in a [`StealthShaper`](super::cc::stealth_shaper::StealthShaper).
    /// When disabled on an already-wrapped CC, the stealth layer is deactivated.
    pub fn set_stealth_mode(&mut self, enabled: bool, profile: BrowserProfile) {
        match &mut self.cc {
            CcImpl::StealthBbr3(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
            }
            CcImpl::StealthReno(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
            }
            CcImpl::StealthBbr2(ref mut shaper) => {
                shaper.set_enabled(enabled);
                if enabled {
                    shaper.set_profile(profile);
                }
            }
            CcImpl::Bbr3(_) if enabled => {
                let placeholder = CcImpl::Reno(cc::reno::Reno::new(self.cwnd, self.mss));
                let old = std::mem::replace(&mut self.cc, placeholder);
                if let CcImpl::Bbr3(inner) = old {
                    self.cc =
                        CcImpl::StealthBbr3(cc::stealth_shaper::StealthShaper::new(inner, profile));
                }
            }
            CcImpl::Bbr2(_) if enabled => {
                let placeholder = CcImpl::Reno(cc::reno::Reno::new(self.cwnd, self.mss));
                let old = std::mem::replace(&mut self.cc, placeholder);
                if let CcImpl::Bbr2(inner) = old {
                    self.cc =
                        CcImpl::StealthBbr2(cc::stealth_shaper::StealthShaper::new(inner, profile));
                }
            }
            CcImpl::Reno(_) if enabled => {
                let placeholder = CcImpl::Reno(cc::reno::Reno::new(self.cwnd, self.mss));
                let old = std::mem::replace(&mut self.cc, placeholder);
                if let CcImpl::Reno(inner) = old {
                    self.cc =
                        CcImpl::StealthReno(cc::stealth_shaper::StealthShaper::new(inner, profile));
                }
            }
            _ => {}
        }
    }

    /// Registers FEC integration callbacks for send and loss events.
    pub fn set_fec_callbacks<F1, F2>(&mut self, on_sent: F1, on_lost: F2)
    where
        F1: Fn(u64, usize) + Send + Sync + 'static,
        F2: Fn(u64, usize) + Send + Sync + 'static,
    {
        self.cc.set_fec_callbacks(Arc::new(on_sent), Arc::new(on_lost));
    }

    /// Sync pub fields from the inner CC after a mutation.
    #[inline(always)]
    fn sync_from_cc(&mut self) {
        self.cwnd = self.cc.cwnd();
        self.bytes_in_flight = self.cc.bytes_in_flight();
    }

    /// Returns the current pacing rate in bytes/sec, if non-zero.
    pub fn get_pacing_rate(&self) -> Option<u64> {
        self.cc.pacing_rate()
    }

    /// Smoothed loss rate based on ACK/loss updates.
    #[inline(always)]
    pub fn get_loss_rate(&self) -> f32 {
        self.cc.loss_rate()
    }

    /// Returns the current batch size for SIMD/vectorized processing.
    pub fn get_batch_size(&self) -> usize {
        self.batch_size
    }

    /// Sets the batch size for vectorized processing, clamped to [1, 64].
    pub fn set_batch_size(&mut self, size: usize) {
        self.batch_size = size.clamp(1, 64);
    }

    /// Records a sent packet for congestion control and FEC tracking.
    #[inline(always)]
    pub fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        self.cc.on_packet_sent(pkt_num, sent_bytes, now);
        self.sync_from_cc();
    }

    /// Processes an ACK, updating congestion state and loss rate.
    pub fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.cc.on_ack(acked_bytes, now);
        // Apply stealth post-processing for paced algorithms
        match &mut self.cc {
            CcImpl::StealthBbr3(shaper) => shaper.apply_stealth_post_ack(),
            CcImpl::StealthBbr2(shaper) => shaper.apply_stealth_post_ack(),
            _ => {}
        }
        self.sync_from_cc();
    }

    /// Records a loss event (packet number unknown).
    pub fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    /// Records a packet loss event with known packet number for FEC callbacks.
    pub fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        self.cc.on_loss_packet(packet_num, lost_bytes, now);
        self.loss_time = Some(now);
        self.pto_count = self.pto_count.saturating_add(1);
        self.sync_from_cc();
    }

    /// Updates the RTT estimate using EWMA smoothing per RFC 6298.
    ///
    /// On the first sample: SRTT = R, RTTVAR = R/2.
    /// On subsequent samples:
    ///   RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
    ///   SRTT = 7/8 * SRTT + 1/8 * R
    /// Also tracks min_rtt for RACK and BBR.
    pub fn update_rtt(&mut self, rtt: Duration) {
        if !self.rtt_initialized {
            // First sample: initialize SRTT and RTTVAR
            self.rtt = rtt;
            self.rtt_var = rtt / 2;
            self.min_rtt = rtt;
            self.rtt_initialized = true;
        } else {
            // EWMA smoothing per RFC 6298
            let abs_diff = rtt.abs_diff(self.rtt);
            // RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
            self.rtt_var = (self.rtt_var * 3 + abs_diff) / 4;
            // SRTT = 7/8 * SRTT + 1/8 * R
            self.rtt = (self.rtt * 7 + rtt) / 8;
            // Track min_rtt
            if rtt < self.min_rtt {
                self.min_rtt = rtt;
            }
        }
        self.cc.update_rtt(rtt);
    }

    /// Returns the maximum bytes that can be released (cwnd minus in-flight).
    pub fn max_release_into_future(&self) -> usize {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Computes the Probe Timeout deadline per RFC 9002 Section 6.2.1.
    ///
    /// PTO = SRTT + max(1*RTTVAR, granular) + max_ack_delay
    /// With exponential backoff: PTO * 2^pto_count
    pub fn pto_deadline(&self, now: Instant) -> Instant {
        let granularity = Duration::from_millis(1);
        let max_ack_delay = Duration::from_millis(25); // QUIC default
        let pto = self.rtt + self.rtt_var.max(granularity) + max_ack_delay;
        let backoff = 1u32 << self.pto_count.min(8);
        now + pto * backoff
    }

    /// Returns the send quantum (max burst size) in bytes.
    pub fn send_quantum(&self) -> usize {
        min(self.cwnd, 3 * self.mss)
    }

    /// Returns true if `sz` additional bytes fit within the congestion window.
    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    /// Returns whether packet pacing is enabled and a pacing rate is available.
    pub fn pacing_enabled(&self) -> bool {
        self.pacing && self.cc.pacing_rate().is_some()
    }

    /// Time-based loss detection deadline per RFC 9002 Section 6.2.
    ///
    /// A packet should be considered lost if it was sent more than
    /// `max(9/8 * SRTT, 1ms)` ago and a later packet was acknowledged.
    /// Returns `None` if RTT is not yet initialized.
    pub fn time_loss_deadline(&self, sent_at: Instant) -> Option<Instant> {
        if !self.rtt_initialized {
            return None;
        }
        let threshold = (self.rtt * 9) / 8;
        let threshold = threshold.max(Duration::from_millis(1));
        Some(sent_at + threshold)
    }

    /// RACK (Recent ACKnowledgement) loss detection per RFC 8985.
    ///
    /// A packet is considered lost if:
    /// 1. A later packet (higher PN) was acknowledged, AND
    /// 2. The packet was sent more than `SRTT + RTTVAR` ago (the "RACK threshold")
    ///
    /// Returns true if the packet with `sent_at` timestamp should be
    /// declared lost because a higher PN was acked at `latest_ack_time`.
    pub fn rack_is_lost(&self, sent_at: Instant, latest_ack_time: Instant) -> bool {
        if !self.rtt_initialized {
            return false;
        }
        let rack_threshold = self.rtt + self.rtt_var;
        latest_ack_time.duration_since(sent_at) > rack_threshold
    }

    /// Returns the current RTT variation (for diagnostics/testing).
    pub fn rtt_var(&self) -> Duration {
        self.rtt_var
    }

    /// Returns the minimum observed RTT (for diagnostics/testing).
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Called when the connection migrates to a new path.
    ///
    /// Instead of resetting cwnd to INITIAL_WINDOW (which causes throughput
    /// collapse), we reduce cwnd by 50% and set ssthresh to the reduced value
    /// to enter congestion avoidance directly. bytes_in_flight is preserved
    /// because the packets are still in flight on the new path (the peer will
    /// ACK or lose them). The CC implementation gets a chance to reset
    /// path-specific state (e.g. BBR3 resets min_rtt and re-enters PROBE_BW).
    pub fn on_path_change(&mut self) {
        let new_cwnd = (self.cwnd / 2).max(self.mss * 2);
        self.ssthresh = new_cwnd;
        self.cc.set_cwnd(new_cwnd);
        self.pto_count = 0;
        self.loss_time = None;
        self.sync_from_cc();
    }
}

#[cfg(test)]
mod tests {
    use super::Recovery;
    use core::time::Duration;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn test_fec_callbacks_receive_live_packet_metadata() {
        let mut recovery = Recovery::new(12_000, 1200);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let sent_bytes = Arc::new(AtomicUsize::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let lost_bytes = Arc::new(AtomicUsize::new(0));

        let sent_pkt_cb = Arc::clone(&sent_pkt);
        let sent_bytes_cb = Arc::clone(&sent_bytes);
        let lost_pkt_cb = Arc::clone(&lost_pkt);
        let lost_bytes_cb = Arc::clone(&lost_bytes);

        recovery.set_fec_callbacks(
            move |pn, bytes| {
                sent_pkt_cb.store(pn, Ordering::Relaxed);
                sent_bytes_cb.store(bytes, Ordering::Relaxed);
            },
            move |pn, bytes| {
                lost_pkt_cb.store(pn, Ordering::Relaxed);
                lost_bytes_cb.store(bytes, Ordering::Relaxed);
            },
        );

        let now = Instant::now();
        recovery.on_packet_sent(42, 1200, now);
        recovery.on_loss_packet(42, 1200, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(sent_bytes.load(Ordering::Relaxed), 1200);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 1200);

        // Legacy loss API routes through packet-based callback with packet_num=0.
        recovery.on_loss(777, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 0);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 777);
    }

    #[test]
    fn test_reno_algorithm() {
        let mut recovery = Recovery::with_algorithm(12_000, 1200, super::cc::Algorithm::Reno);
        let now = Instant::now();
        recovery.on_packet_sent(1, 1200, now);
        recovery.on_ack(1200, now);
        assert!(recovery.cwnd > 0);
    }

    #[test]
    fn test_stealth_mode_wrapping() {
        let mut recovery = Recovery::new(12_000, 1200);
        let now = Instant::now();
        recovery.on_packet_sent(1, 1200, now);
        recovery.set_stealth_mode(true, super::BrowserProfile::Firefox);
        recovery.on_ack(1200, now);
        assert!(recovery.cwnd > 0);
    }

    #[test]
    fn test_rtt_ewma_smoothing() {
        let mut recovery = Recovery::new(12_000, 1200);
        // First sample initializes
        recovery.update_rtt(Duration::from_millis(100));
        assert_eq!(recovery.rtt, Duration::from_millis(100));
        assert_eq!(recovery.rtt_var(), Duration::from_millis(50));
        // Second sample: EWMA smoothing
        recovery.update_rtt(Duration::from_millis(120));
        // SRTT = 7/8 * 100 + 1/8 * 120 = 87.5 + 15 = 102.5ms
        assert!(recovery.rtt > Duration::from_millis(100));
        assert!(recovery.rtt < Duration::from_millis(110));
        // RTTVAR = 3/4 * 50 + 1/4 * 20 = 37.5 + 5 = 42.5ms
        assert!(recovery.rtt_var() < Duration::from_millis(50));
    }

    #[test]
    fn test_rtt_min_tracking() {
        let mut recovery = Recovery::new(12_000, 1200);
        recovery.update_rtt(Duration::from_millis(100));
        recovery.update_rtt(Duration::from_millis(50));
        recovery.update_rtt(Duration::from_millis(200));
        assert_eq!(recovery.min_rtt(), Duration::from_millis(50));
    }

    #[test]
    fn test_time_based_loss_detection() {
        let mut recovery = Recovery::new(12_000, 1200);
        // Before RTT is initialized, no time-based loss detection
        let now = Instant::now();
        assert!(recovery.time_loss_deadline(now).is_none());
        // After RTT init, threshold = 9/8 * SRTT
        recovery.update_rtt(Duration::from_millis(80));
        let deadline = recovery.time_loss_deadline(now).unwrap();
        let threshold = (Duration::from_millis(80) * 9) / 8;
        assert_eq!(deadline, now + threshold);
    }

    #[test]
    fn test_rack_loss_detection() {
        let mut recovery = Recovery::new(12_000, 1200);
        recovery.update_rtt(Duration::from_millis(100));
        // Packet sent at t=0, ack at t=50ms — not lost (within RACK threshold)
        let sent_at = Instant::now();
        let ack_time = sent_at + Duration::from_millis(50);
        assert!(!recovery.rack_is_lost(sent_at, ack_time));
        // Packet sent at t=0, ack at t=200ms — lost (exceeds SRTT + RTTVAR)
        let ack_time2 = sent_at + Duration::from_millis(200);
        assert!(recovery.rack_is_lost(sent_at, ack_time2));
    }

    #[test]
    fn test_gentle_path_migration_preserves_cwnd() {
        use super::cc::Algorithm;
        let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
        // Grow cwnd via ACKs (Reno slow-start doubles cwnd each RTT).
        let now = Instant::now();
        for i in 0..20 {
            recovery.on_packet_sent(i, 1200, now);
            recovery.on_ack(1200, now);
        }
        let cwnd_before = recovery.cwnd;
        assert!(cwnd_before > 12_000, "cwnd should have grown: {cwnd_before}");
        // Path change: cwnd should be halved, not reset to INITIAL_WINDOW
        recovery.on_path_change();
        let cwnd_after = recovery.cwnd;
        assert!(cwnd_after > 2400, "not reset to minimum: {cwnd_after}");
        assert!(cwnd_after <= cwnd_before);
        assert_eq!(cwnd_after, (cwnd_before / 2).max(2400));
    }
}
