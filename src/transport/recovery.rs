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
    /// Smoothed round-trip time estimate.
    pub rtt: Duration,
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

    /// Updates the RTT estimate.
    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        self.cc.update_rtt(rtt);
    }

    /// Returns the maximum bytes that can be released (cwnd minus in-flight).
    pub fn max_release_into_future(&self) -> usize {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Computes the Probe Timeout deadline with exponential backoff.
    pub fn pto_deadline(&self, now: Instant) -> Instant {
        let base = Duration::from_millis(200);
        let pto = self.rtt.saturating_mul(2) + base;
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
}

#[cfg(test)]
mod tests {
    use super::Recovery;
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
}
