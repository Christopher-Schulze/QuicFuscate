//! Root-independent transport observation and Brain-policy target contracts.

use std::error::Error;
use std::fmt;

use crate::{BrainRuntimePermissions, StealthRuntimeDelta};

/// Failure returned when a connection cannot apply a Brain-owned runtime delta.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct TransportPolicyError {
    message: String,
}

impl TransportPolicyError {
    /// Creates a policy error from the concrete transport adapter's message.
    #[doc(hidden)]
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }

    /// Returns the adapter-provided diagnostic without exposing its concrete error type.
    #[doc(hidden)]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for TransportPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TransportPolicyError {}

/// Root-independent target that receives Brain-controlled transport mutations.
#[doc(hidden)]
pub trait TransportPolicyTarget {
    /// Returns the latest delivery-rate estimate used by Brain's bandit.
    fn delivery_rate(&self) -> u64;

    /// Reports whether this connection accepts intelligent stealth mutations.
    fn intelligent_stealth_runtime_enabled(&self) -> bool;

    /// Returns the operator/runtime permissions for Brain actuators.
    fn brain_runtime_permissions(&self) -> BrainRuntimePermissions;

    /// Sets the ACK-eliciting threshold after permission checks at the caller.
    fn set_ack_eliciting_threshold(&mut self, threshold: u64);

    /// Applies a validated stealth delta and preserves a typed boundary error.
    fn apply_brain_stealth_runtime_delta(
        &mut self,
        delta: StealthRuntimeDelta,
    ) -> Result<(), TransportPolicyError>;
}

/// Root-independent observation callbacks consumed by transport connections.
#[doc(hidden)]
pub trait TransportObserver: Send + Sync {
    /// Called when an ACK frame is emitted.
    fn on_ack(&self, _ack_delay: u64, _ranges: &[(u64, u64)]) {}

    /// Called when a packet is received after decryption.
    fn on_packet_recv(&self, _packet_number: u64, _payload_len: usize) {}

    /// Called when ECN counters are updated.
    fn on_ecn_update(&self, _ect0: u64, _ect1: u64, _ce: u64) {}

    /// Gives an observer one policy tick against the root-independent target surface.
    fn apply_policy(&self, _target: &mut dyn TransportPolicyTarget) {}
}

#[cfg(test)]
mod tests {
    use super::{TransportObserver, TransportPolicyError, TransportPolicyTarget};
    use crate::{BrainRuntimePermissions, StealthRuntimeDelta};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Target {
        delivery_rate: u64,
        intelligent: bool,
        permissions: BrainRuntimePermissions,
        threshold: u64,
        delta: Option<StealthRuntimeDelta>,
    }

    impl TransportPolicyTarget for Target {
        fn delivery_rate(&self) -> u64 {
            self.delivery_rate
        }

        fn intelligent_stealth_runtime_enabled(&self) -> bool {
            self.intelligent
        }

        fn brain_runtime_permissions(&self) -> BrainRuntimePermissions {
            self.permissions
        }

        fn set_ack_eliciting_threshold(&mut self, threshold: u64) {
            self.threshold = threshold;
        }

        fn apply_brain_stealth_runtime_delta(
            &mut self,
            delta: StealthRuntimeDelta,
        ) -> Result<(), TransportPolicyError> {
            self.delta = Some(delta);
            Ok(())
        }
    }

    struct Observer {
        acks: AtomicU64,
        packets: AtomicU64,
        ecn: AtomicU64,
    }

    impl TransportObserver for Observer {
        fn on_ack(&self, _ack_delay: u64, _ranges: &[(u64, u64)]) {
            self.acks.fetch_add(1, Ordering::Relaxed);
        }

        fn on_packet_recv(&self, _packet_number: u64, _payload_len: usize) {
            self.packets.fetch_add(1, Ordering::Relaxed);
        }

        fn on_ecn_update(&self, _ect0: u64, _ect1: u64, _ce: u64) {
            self.ecn.fetch_add(1, Ordering::Relaxed);
        }

        fn apply_policy(&self, target: &mut dyn TransportPolicyTarget) {
            target.set_ack_eliciting_threshold(7);
        }
    }

    #[test]
    fn observer_callbacks_and_policy_target_share_one_contract() {
        let observer = Observer {
            acks: AtomicU64::new(0),
            packets: AtomicU64::new(0),
            ecn: AtomicU64::new(0),
        };
        observer.on_ack(10, &[(1, 2)]);
        observer.on_packet_recv(4, 1200);
        observer.on_ecn_update(1, 0, 2);

        let mut target = Target::default();
        observer.apply_policy(&mut target);

        assert_eq!(observer.acks.load(Ordering::Relaxed), 1);
        assert_eq!(observer.packets.load(Ordering::Relaxed), 1);
        assert_eq!(observer.ecn.load(Ordering::Relaxed), 1);
        assert_eq!(target.threshold, 7);
        assert_eq!(target.delivery_rate(), 0);
        assert!(!target.intelligent_stealth_runtime_enabled());
    }

    #[test]
    fn policy_error_preserves_adapter_diagnostic() {
        let error = TransportPolicyError::new("stealth shaping unavailable");
        assert_eq!(error.message(), "stealth shaping unavailable");
        assert_eq!(error.to_string(), "stealth shaping unavailable");
    }
}
