//! Shared startup policy for process and pooled-buffer memory locking.
//!
//! The policy is applied before server TLS identity loading. Standalone startup
//! may explicitly defer the process-wide lock until after the verified Linux
//! privilege transition; embedded server startup does not have that deferral.

use crate::engine::SecurityConfig;

/// Startup-owned memory-lock settings for a server runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLockPolicy {
    /// Lock process memory against swap where the host supports `mlockall`.
    pub lock_memory: bool,
    /// Lock newly allocated `MemoryPool` blocks against swap.
    pub lock_blocks: bool,
}

impl Default for MemoryLockPolicy {
    fn default() -> Self {
        Self { lock_memory: true, lock_blocks: true }
    }
}

impl MemoryLockPolicy {
    /// Derive the server startup policy from the engine security section.
    pub fn from_security(config: &SecurityConfig) -> Self {
        Self { lock_memory: config.lock_memory, lock_blocks: config.lock_blocks }
    }

    /// Apply the process and pool policy before the server identity is loaded.
    ///
    /// `defer_process_memory_lock` is only valid for standalone Linux startup
    /// with a configured privilege transition. In that case the individual
    /// TLS key lock remains the pre-drop protection boundary and the process
    /// lock is applied after the verified setxid transition.
    pub fn apply_before_tls_identity(self, defer_process_memory_lock: bool) {
        crate::qftls::set_process_memory_lock_covers_future_allocations(false);
        if self.lock_memory && !defer_process_memory_lock {
            #[cfg(unix)]
            apply_process_memory_lock();
            #[cfg(not(unix))]
            log::debug!("mlockall not supported on this platform; lock_memory ignored");
        } else if self.lock_memory && defer_process_memory_lock {
            log::debug!(
                "Deferring process-wide memory locking until after the verified privilege transition"
            );
        }

        crate::optimize::MemoryPool::set_lock_blocks(self.lock_blocks);
    }

    /// Apply a process-wide lock after a deferred privilege transition.
    pub fn apply_deferred_process_memory_lock(self) {
        if !self.lock_memory {
            return;
        }

        #[cfg(unix)]
        apply_process_memory_lock();
        #[cfg(not(unix))]
        log::debug!("mlockall not supported on this platform; lock_memory ignored");
    }

    /// Reject startup-owned lock changes during standalone runtime reload.
    pub fn reject_standalone_reload(self, candidate: Self) -> Result<(), String> {
        let mut changed = Vec::new();
        if self.lock_memory != candidate.lock_memory {
            changed.push("security.lock_memory");
        }
        if self.lock_blocks != candidate.lock_blocks {
            changed.push("security.lock_blocks");
        }
        if changed.is_empty() {
            return Ok(());
        }

        Err(format!(
            "{} are startup-owned and cannot change during standalone config reload; restart required",
            changed.join(" and ")
        ))
    }
}

#[cfg(unix)]
fn mlockall_flags_for_limit(current_limit: libc::rlim_t) -> libc::c_int {
    if current_limit == libc::RLIM_INFINITY {
        libc::MCL_CURRENT | libc::MCL_FUTURE
    } else {
        libc::MCL_CURRENT
    }
}

#[cfg(unix)]
fn current_memlock_limit() -> std::io::Result<libc::rlim_t> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the pointed-to rlimit structure on success.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, limit.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a zero return from getrlimit guarantees the structure was initialized.
    Ok(unsafe { limit.assume_init() }.rlim_cur)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryLockOutcome {
    flags: libc::c_int,
    current_limit: Option<libc::rlim_t>,
}

#[cfg(unix)]
fn lock_process_memory() -> std::io::Result<MemoryLockOutcome> {
    let current_limit = current_memlock_limit().ok();
    let flags = current_limit.map(mlockall_flags_for_limit).unwrap_or(libc::MCL_CURRENT);

    // SAFETY: flags contain only MCL_CURRENT and, when the process has an
    // unlimited memlock budget, MCL_FUTURE.
    if unsafe { libc::mlockall(flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(MemoryLockOutcome { flags, current_limit })
}

#[cfg(unix)]
fn apply_process_memory_lock() {
    match lock_process_memory() {
        Ok(outcome) => {
            crate::qftls::set_process_memory_lock_covers_future_allocations(
                outcome.flags & libc::MCL_FUTURE != 0,
            );
            match outcome.current_limit {
                Some(limit) if outcome.flags == libc::MCL_CURRENT => {
                    log::warn!(
                        "RLIMIT_MEMLOCK is finite ({} bytes); locking current pages only to avoid future allocation failures. Set LimitMEMLOCK=infinity for full process locking.",
                        limit
                    );
                }
                None => {
                    log::warn!(
                        "RLIMIT_MEMLOCK query failed. Locked current pages only to avoid future allocation failures."
                    );
                }
                _ => {}
            }
            log::info!("Process memory locked against swap (mlockall flags={})", outcome.flags);
        }
        Err(error) => {
            crate::qftls::set_process_memory_lock_covers_future_allocations(false);
            log::warn!(
                "mlockall failed: {}. Process memory may be swapped to disk. Set LimitMEMLOCK=infinity in systemd or run with CAP_IPC_LOCK.",
                error
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MemoryLockPolicy;
    use crate::engine::SecurityConfig;
    use crate::optimize::{MemoryPool, LOCK_BLOCKS_TEST_MUTEX};

    struct PoolLockSettingRestore(bool);

    impl Drop for PoolLockSettingRestore {
        fn drop(&mut self) {
            MemoryPool::set_lock_blocks(self.0);
        }
    }

    #[test]
    fn security_settings_map_to_startup_policy_without_normalization() {
        let config = SecurityConfig { lock_memory: false, lock_blocks: true, ..Default::default() };

        assert_eq!(
            MemoryLockPolicy::from_security(&config),
            MemoryLockPolicy { lock_memory: false, lock_blocks: true }
        );
    }

    #[test]
    fn standalone_reload_accepts_unchanged_startup_policy() {
        let policy = MemoryLockPolicy { lock_memory: true, lock_blocks: false };

        assert_eq!(policy.reject_standalone_reload(policy), Ok(()));
    }

    #[test]
    fn standalone_reload_rejects_each_changed_startup_setting() {
        let current = MemoryLockPolicy { lock_memory: true, lock_blocks: true };
        for (candidate, expected_field) in [
            (MemoryLockPolicy { lock_memory: false, lock_blocks: true }, "security.lock_memory"),
            (MemoryLockPolicy { lock_memory: true, lock_blocks: false }, "security.lock_blocks"),
            (
                MemoryLockPolicy { lock_memory: false, lock_blocks: false },
                "security.lock_memory and security.lock_blocks",
            ),
        ] {
            let error = current
                .reject_standalone_reload(candidate)
                .expect_err("startup-owned memory policy changes must require restart");
            assert!(error.starts_with(expected_field));
            assert!(error.ends_with("restart required"));
        }
    }

    #[test]
    fn embedded_startup_policy_applies_pool_setting_before_identity_boundary() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = PoolLockSettingRestore(MemoryPool::lock_blocks_enabled());

        MemoryLockPolicy { lock_memory: false, lock_blocks: false }
            .apply_before_tls_identity(false);

        assert!(!MemoryPool::lock_blocks_enabled());
    }

    #[test]
    fn standalone_restart_reapplies_pool_setting_instead_of_retaining_previous_value() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = PoolLockSettingRestore(MemoryPool::lock_blocks_enabled());

        MemoryLockPolicy { lock_memory: false, lock_blocks: false }
            .apply_before_tls_identity(false);
        assert!(!MemoryPool::lock_blocks_enabled());

        MemoryLockPolicy { lock_memory: false, lock_blocks: true }.apply_before_tls_identity(false);
        assert!(MemoryPool::lock_blocks_enabled());
    }

    #[cfg(unix)]
    #[test]
    fn finite_memlock_limit_never_enables_future_allocation_locking() {
        assert_eq!(super::mlockall_flags_for_limit(8 * 1024 * 1024), libc::MCL_CURRENT);
        assert_eq!(
            super::mlockall_flags_for_limit(libc::RLIM_INFINITY),
            libc::MCL_CURRENT | libc::MCL_FUTURE
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_memory_lock_boundary_locks_pages_or_reports_supported_limit_error() {
        match super::lock_process_memory() {
            Ok(outcome) => {
                assert_ne!(outcome.flags & libc::MCL_CURRENT, 0);

                #[cfg(target_os = "linux")]
                {
                    let status = std::fs::read_to_string("/proc/self/status")
                        .expect("read current process status after mlockall");
                    let locked_kib = status
                        .lines()
                        .find_map(|line| line.strip_prefix("VmLck:"))
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u64>().ok())
                        .expect("parse VmLck from /proc/self/status");
                    assert!(locked_kib > 0, "mlockall succeeded but VmLck stayed zero");
                }

                // SAFETY: this test owns the process-wide lock it just acquired.
                assert_eq!(unsafe { libc::munlockall() }, 0, "munlockall failed");
            }
            Err(error) => {
                let raw_error = error.raw_os_error();
                assert!(
                    matches!(raw_error, Some(code) if code == libc::EPERM || code == libc::ENOMEM || code == libc::EAGAIN || code == libc::ENOSYS),
                    "unexpected mlockall failure: {error}"
                );
            }
        }
    }
}
