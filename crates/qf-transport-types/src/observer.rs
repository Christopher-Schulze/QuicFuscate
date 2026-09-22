//! Root-independent transport observation and Brain-policy target contracts.

use crate::BrainRuntimePermissions;

/// Root-independent target that receives Brain-controlled transport mutations.
///
/// TODO-1060: the only mutation left is the congestion-driven ACK-eliciting
/// threshold. Repair-ratio and the Reality/MASQUE armed bit travel through
/// `IntelligentLevelHints`/FEC hints, not through this trait.
#[doc(hidden)]
pub trait TransportPolicyTarget {
    /// Returns the operator/runtime permissions for Brain actuators.
    fn brain_runtime_permissions(&self) -> BrainRuntimePermissions;

    /// Sets the ACK-eliciting threshold after permission checks at the caller.
    fn set_ack_eliciting_threshold(&mut self, threshold: u64);
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
    use super::{TransportObserver, TransportPolicyTarget};
    use crate::BrainRuntimePermissions;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Default)]
    struct Target {
        permissions: BrainRuntimePermissions,
        threshold: u64,
    }

    impl TransportPolicyTarget for Target {
        fn brain_runtime_permissions(&self) -> BrainRuntimePermissions {
            self.permissions
        }

        fn set_ack_eliciting_threshold(&mut self, threshold: u64) {
            self.threshold = threshold;
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
    }
}
