//! Root-independent traffic-shaping state used by the stealth manager.

use qf_common::time_source::ProtocolClock;
use std::time::{Duration, Instant};

/// Real-time token-bucket choker for observable packet bitrate.
#[doc(hidden)]
pub struct RateChoker {
    clock: ProtocolClock,
    target_bps: f64,
    capacity_bytes: f64,
    /// Current token balance. Public only for the historical root test contract.
    #[doc(hidden)]
    pub tokens: f64,
    /// Timestamp of the last refill. Public only for the historical root test contract.
    #[doc(hidden)]
    pub last: Instant,
}

impl RateChoker {
    /// Create a choker using the process clock.
    #[doc(hidden)]
    pub fn new(target_mbps: u32, burst_ms: u32) -> Option<Self> {
        Self::new_with_clock(target_mbps, burst_ms, &ProtocolClock::default())
    }

    /// Create a choker with an explicit protocol clock.
    #[doc(hidden)]
    pub fn new_with_clock(target_mbps: u32, burst_ms: u32, clock: &ProtocolClock) -> Option<Self> {
        if target_mbps == 0 {
            return None;
        }
        let target_bps = f64::from(target_mbps) * 1_000_000.0;
        let capacity_bytes = (target_bps / 8.0) * (f64::from(burst_ms) / 1000.0);
        Some(Self {
            clock: clock.clone(),
            target_bps,
            capacity_bytes,
            tokens: capacity_bytes,
            last: clock.now(),
        })
    }

    /// Return the delay needed to respect the configured rate for `bytes`.
    #[doc(hidden)]
    pub fn shape(&mut self, bytes: usize) -> Duration {
        let now = self.clock.now();
        let elapsed = self.clock.elapsed_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + (self.target_bps / 8.0) * elapsed).min(self.capacity_bytes);
        self.last = now;

        let required = bytes as f64;
        if self.tokens >= required {
            self.tokens -= required;
            return Duration::ZERO;
        }

        let deficit = required - self.tokens;
        let wait_seconds = (deficit * 8.0) / self.target_bps;
        self.tokens = 0.0;
        Duration::from_secs_f64(wait_seconds.max(0.0))
    }
}

#[cfg(test)]
mod tests {
    use super::RateChoker;
    use std::time::Duration;

    #[test]
    fn rate_choker_rejects_zero_target_and_shapes_deficit() {
        assert!(RateChoker::new(0, 100).is_none());
        let mut choker = RateChoker::new(1, 10).expect("positive target");
        assert_eq!(choker.shape(100), Duration::ZERO);
        choker.tokens = 0.0;
        assert!(choker.shape(100) > Duration::ZERO);
    }
}
