//! Root-independent traffic-shaping state used by the stealth manager.

use qf_common::time_source::ProtocolClock;
use std::collections::VecDeque;
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
    #[allow(dead_code)]
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

/// Trigger reason recorded for a server-push cover burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum ServerPushTriggerReason {
    Time,
    Loss,
    Gating,
}

/// Mutable server-push cover state shared by a stealth manager.
#[doc(hidden)]
pub struct ServerPushState {
    #[doc(hidden)]
    pub last_burst: Instant,
    #[doc(hidden)]
    pub active_promises: usize,
    #[doc(hidden)]
    pub total_cover_bytes: u64,
    #[doc(hidden)]
    pub current_intensity: f32,
    #[doc(hidden)]
    pub burst_window: VecDeque<Instant>,
}

impl ServerPushState {
    /// Create an empty state anchored to the supplied protocol clock.
    #[doc(hidden)]
    pub fn new_with_clock(clock: &ProtocolClock, intensity: f32) -> Self {
        Self {
            last_burst: clock.now(),
            active_promises: 0,
            total_cover_bytes: 0,
            current_intensity: intensity,
            burst_window: VecDeque::with_capacity(128),
        }
    }

    /// Record one burst and prune entries outside the telemetry window.
    #[doc(hidden)]
    pub fn record_burst(
        &mut self,
        clock: &ProtocolClock,
        promises_created: usize,
        total_bytes: u64,
    ) {
        let now = clock.now();
        self.last_burst = now;
        self.active_promises = promises_created;
        self.total_cover_bytes = self.total_cover_bytes.saturating_add(total_bytes);
        self.burst_window.push_back(now);
        while let Some(timestamp) = self.burst_window.front().copied() {
            if clock.elapsed_since(timestamp) > Duration::from_secs(60) {
                self.burst_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of bursts retained for the bounded one-minute telemetry window.
    #[doc(hidden)]
    pub fn bursts_last_minute(&self) -> usize {
        self.burst_window.len()
    }

    /// Current intensity in parts per million for telemetry.
    #[doc(hidden)]
    pub fn intensity_ppm(&self) -> u64 {
        (self.current_intensity.clamp(0.0, 1.0) * 1_000_000.0) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::{RateChoker, ServerPushState};
    use qf_common::time_source::ProtocolClock;
    use std::time::Duration;

    #[test]
    fn rate_choker_rejects_zero_target_and_shapes_deficit() {
        assert!(RateChoker::new(0, 100).is_none());
        let mut choker = RateChoker::new(1, 10).expect("positive target");
        assert_eq!(choker.shape(100), Duration::ZERO);
        choker.tokens = 0.0;
        assert!(choker.shape(100) > Duration::ZERO);
    }

    #[test]
    fn server_push_state_keeps_saturating_bytes_and_window_shape() {
        let clock = ProtocolClock::default();
        let mut state = ServerPushState::new_with_clock(&clock, 0.5);
        state.record_burst(&clock, 2, u64::MAX);
        state.record_burst(&clock, 1, 4);
        assert_eq!(state.active_promises, 1);
        assert_eq!(state.total_cover_bytes, u64::MAX);
        assert_eq!(state.bursts_last_minute(), 2);
        assert_eq!(state.intensity_ppm(), 500_000);
    }
}
