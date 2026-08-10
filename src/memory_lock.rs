//! Root compatibility adapter for the independent `qf-memory-lock` owner.

use crate::engine::SecurityConfig;

pub use qf_memory_lock::{
    current_status, lock_blocks_enabled, process_memory_lock_covers_future_allocations,
    set_lock_blocks, set_process_memory_lock_covers_future_allocations, MemoryLockFailureKind,
    MemoryLockFailurePolicy, MemoryLockLimit, MemoryLockProcessMode, MemoryLockStartupError,
    MemoryLockStartupStatus, MemoryLockState,
};

use qf_memory_lock::MemoryLockPolicy as OwnedMemoryLockPolicy;

/// Startup-owned memory-lock settings retained at the root for compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLockPolicy {
    /// Lock process memory against swap where the host supports `mlockall`.
    pub lock_memory: bool,
    /// Lock newly allocated memory-pool blocks against swap.
    pub lock_blocks: bool,
    /// Decide whether process-lock failure may degrade startup.
    pub failure_policy: MemoryLockFailurePolicy,
}

impl Default for MemoryLockPolicy {
    fn default() -> Self {
        Self {
            lock_memory: true,
            lock_blocks: true,
            failure_policy: MemoryLockFailurePolicy::BestEffort,
        }
    }
}

impl MemoryLockPolicy {
    /// Derive the startup policy from the engine security section.
    pub fn from_security(config: &SecurityConfig) -> Self {
        Self {
            lock_memory: config.lock_memory,
            lock_blocks: config.lock_blocks,
            failure_policy: config.memory_lock_failure_policy,
        }
    }

    /// Apply the process and pool policy before the server identity is loaded.
    pub fn apply_before_tls_identity(
        self,
        defer_process_memory_lock: bool,
    ) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        self.into_owned().apply_before_tls_identity(defer_process_memory_lock)
    }

    /// Apply a process-wide lock after a deferred privilege transition.
    pub fn apply_deferred_process_memory_lock(
        self,
    ) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        self.into_owned().apply_deferred_process_memory_lock()
    }

    /// Reject startup-owned lock changes during standalone runtime reload.
    pub fn reject_standalone_reload(self, candidate: Self) -> Result<(), String> {
        self.into_owned().reject_standalone_reload(candidate.into_owned())
    }

    fn into_owned(self) -> OwnedMemoryLockPolicy {
        OwnedMemoryLockPolicy {
            lock_memory: self.lock_memory,
            lock_blocks: self.lock_blocks,
            failure_policy: self.failure_policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryLockFailurePolicy, MemoryLockPolicy};
    use crate::engine::SecurityConfig;

    #[test]
    fn security_settings_map_to_startup_policy_without_normalization() {
        let config = SecurityConfig { lock_memory: false, lock_blocks: true, ..Default::default() };

        assert_eq!(
            MemoryLockPolicy::from_security(&config),
            MemoryLockPolicy {
                lock_memory: false,
                lock_blocks: true,
                failure_policy: MemoryLockFailurePolicy::BestEffort,
            }
        );
    }
}
