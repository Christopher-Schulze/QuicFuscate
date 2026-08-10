//! DPLPMTUD state machine for the transport recovery boundary.

use std::time::{Duration, Instant};

use super::PmtuPolicy;

/// DPLPMTUD (RFC 8899) state for packetization-layer MTU discovery.
///
/// Probes the path MTU by sending padded PING packets at increasing sizes.
/// Uses bounded binary search between the configured minimum and maximum.
/// Black hole detection falls back to the configured safe minimum.
#[derive(Clone, Debug)]
pub struct PmtuState {
    /// Current confirmed MTU (starts at PMTU_MIN).
    confirmed_mtu: usize,
    /// Current probe target (binary search between confirmed and max).
    probe_target: usize,
    /// Whether a probe is in flight (and its size).
    probe_in_flight: Option<usize>,
    /// Timestamp of the last probe send.
    last_probe_sent: Option<Instant>,
    /// First unacknowledged packet above the safe floor. Later sends must not
    /// move this timestamp or a continuously black-holed path would never age.
    above_floor_unacked_since: Option<Instant>,
    /// Whether DPLPMTUD is enabled.
    enabled: bool,
    min_mtu: usize,
    max_mtu: usize,
    probe_interval: Duration,
    black_hole_timeout: Duration,
}

impl PmtuState {
    /// Creates PMTU state from a validated DPLPMTUD policy.
    pub fn new(enabled: bool, policy: PmtuPolicy) -> Result<Self, qf_error::ConnectionError> {
        let policy = policy.validate()?;
        Ok(Self {
            confirmed_mtu: policy.min_mtu,
            probe_target: if enabled { policy.max_mtu } else { policy.min_mtu },
            probe_in_flight: None,
            last_probe_sent: None,
            above_floor_unacked_since: None,
            enabled,
            min_mtu: policy.min_mtu,
            max_mtu: policy.max_mtu,
            probe_interval: policy.probe_interval,
            black_hole_timeout: policy.black_hole_timeout,
        })
    }

    /// Returns the current effective MTU (confirmed, not probe target).
    pub fn effective_mtu(&self) -> usize {
        self.confirmed_mtu
    }

    /// Returns the configured safe MTU floor used for packetization.
    pub fn min_mtu(&self) -> usize {
        self.min_mtu
    }

    /// Sets the confirmed MTU for the root compatibility test harness.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn set_confirmed_mtu_for_test(&mut self, confirmed_mtu: usize) {
        self.confirmed_mtu = confirmed_mtu.clamp(self.min_mtu, self.max_mtu);
    }

    /// Returns true if a DPLPMTUD probe should be sent now.
    pub fn should_send_probe(&self, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        if self.probe_in_flight.is_some() {
            return false;
        }
        if self.probe_target <= self.confirmed_mtu {
            return false;
        }
        match self.last_probe_sent {
            Some(last) => now.saturating_duration_since(last) >= self.probe_interval,
            None => true,
        }
    }

    /// Returns whether a PMTU probe can bypass a closed congestion gate.
    ///
    /// RFC 8899 requires probes that are not congestion-controlled to be
    /// separated by at least one RTT. The caller still tracks an emitted probe
    /// as ack-eliciting, but only this interval makes the bypass safe.
    #[doc(hidden)]
    pub fn can_bypass_congestion(&self, rtt: Duration) -> bool {
        self.probe_interval >= rtt
    }

    /// Record that a probe of `size` bytes was sent.
    pub fn on_probe_sent(&mut self, size: usize, now: Instant) {
        if size <= self.confirmed_mtu || size > self.max_mtu {
            return;
        }
        self.probe_in_flight = Some(size);
        self.last_probe_sent = Some(now);
    }

    /// Record that a probe was ACKed - confirm the MTU.
    pub fn on_probe_acked(&mut self, _now: Instant) {
        if let Some(size) = self.probe_in_flight.take() {
            self.confirmed_mtu = size.clamp(self.min_mtu, self.max_mtu);
            self.probe_target = midpoint(self.confirmed_mtu, self.max_mtu);
            if self.probe_target == self.confirmed_mtu {
                self.probe_target = self.max_mtu;
            }
        }
        self.above_floor_unacked_since = None;
    }

    /// Record that a probe was lost - reduce probe target.
    pub fn on_probe_lost(&mut self) {
        if let Some(size) = self.probe_in_flight.take() {
            let next_target = midpoint(self.confirmed_mtu, size.min(self.max_mtu));
            self.probe_target =
                if next_target <= self.confirmed_mtu { self.max_mtu } else { next_target };
        }
    }

    /// Check for black hole (no ACKs for extended period).
    /// Returns true if MTU should be reset to minimum.
    pub fn check_black_hole(&self, now: Instant) -> bool {
        self.enabled
            && self.confirmed_mtu > self.min_mtu
            && self
                .above_floor_unacked_since
                .is_some_and(|sent| now.saturating_duration_since(sent) > self.black_hole_timeout)
    }

    /// Reset to minimum MTU (black hole detected).
    pub fn reset_to_minimum(&mut self, now: Instant) {
        self.confirmed_mtu = self.min_mtu;
        self.probe_target =
            self.min_mtu.saturating_add(self.max_mtu.saturating_sub(self.min_mtu) / 4);
        self.probe_in_flight = None;
        self.last_probe_sent = Some(now);
        self.above_floor_unacked_since = None;
    }

    /// Records the first packet that exercises capacity above the safe floor.
    pub fn on_packet_sent(&mut self, packet_size: usize, now: Instant) {
        if self.confirmed_mtu > self.min_mtu && packet_size > self.min_mtu {
            self.above_floor_unacked_since.get_or_insert(now);
        }
    }

    /// Records only ACKs that prove capacity above the safe floor remains usable.
    pub fn on_packet_acked(&mut self, packet_size: usize, _now: Instant) {
        if packet_size > self.min_mtu {
            self.above_floor_unacked_since = None;
        }
    }

    /// Returns the probe size to send (or None if no probe needed).
    pub fn probe_size(&self) -> Option<usize> {
        if self.enabled && self.probe_in_flight.is_none() && self.probe_target > self.confirmed_mtu
        {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns the current probe target regardless of whether a probe is in flight.
    pub fn probe_target(&self) -> Option<usize> {
        if self.enabled && self.probe_target > self.confirmed_mtu {
            Some(self.probe_target)
        } else {
            None
        }
    }

    /// Returns true if DPLPMTUD is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

#[inline]
fn midpoint(lower: usize, upper: usize) -> usize {
    lower.saturating_add(upper.saturating_sub(lower) / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_rejects_invalid_policy() {
        let policy = PmtuPolicy { min_mtu: 1199, ..PmtuPolicy::default() };

        let error = PmtuState::new(true, policy).expect_err("invalid PMTU policy must be rejected");

        assert!(matches!(error, qf_error::ConnectionError::Transport(_)));
    }

    #[test]
    fn earlier_probe_time_is_deterministic_and_does_not_panic() {
        let start = Instant::now();
        let mut state = PmtuState::new(true, PmtuPolicy::default()).expect("valid PMTU policy");
        state.on_probe_sent(1500, start);

        assert!(!state.should_send_probe(start - Duration::from_secs(1)));
    }

    #[test]
    fn pmtu_arithmetic_stays_within_validated_bounds() {
        let policy =
            PmtuPolicy { min_mtu: 1200, max_mtu: u16::MAX as usize, ..PmtuPolicy::default() };
        let start = Instant::now();
        let mut state = PmtuState::new(true, policy).expect("valid PMTU policy");

        state.on_probe_sent(policy.max_mtu, start);
        state.on_probe_acked(start);
        assert!(state.effective_mtu() <= policy.max_mtu);
        assert!(state.probe_target().is_none());

        state.reset_to_minimum(start);
        assert!(state
            .probe_target()
            .is_some_and(|target| { target >= policy.min_mtu && target <= policy.max_mtu }));
    }
}
