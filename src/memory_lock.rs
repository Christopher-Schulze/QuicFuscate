//! Shared startup policy for process and pooled-buffer memory locking.
//!
//! The policy is applied before server TLS identity loading. Standalone startup
//! may explicitly defer the process-wide lock until after the verified Linux
//! privilege transition; embedded server startup does not have that deferral.

use crate::engine::{MemoryLockFailurePolicy, SecurityConfig};
use parking_lot::RwLock;
use std::fmt;
use std::sync::OnceLock;

/// Process-wide lock request selected after the `RLIMIT_MEMLOCK` query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLockProcessMode {
    /// No process-wide lock was requested.
    None,
    /// Only currently mapped pages were locked.
    CurrentOnly,
    /// Current pages and future allocations were locked.
    CurrentAndFuture,
    /// The process-wide call is intentionally pending the privilege boundary.
    Deferred,
}

impl MemoryLockProcessMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CurrentOnly => "current-only",
            Self::CurrentAndFuture => "current-and-future",
            Self::Deferred => "deferred",
        }
    }
}

/// Result of querying the process memory-lock budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLockLimit {
    /// The limit query failed, so only the safe current-page request is used.
    Unknown,
    /// The host returned a finite byte budget.
    Finite(u64),
    /// The host returned `RLIM_INFINITY`.
    Unlimited,
}

impl MemoryLockLimit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Finite(_) => "finite",
            Self::Unlimited => "unlimited",
        }
    }
}

/// Typed cause for a process-wide memory-lock degradation or startup failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLockFailureKind {
    /// `getrlimit(RLIMIT_MEMLOCK)` failed.
    RlimitQuery,
    /// `mlockall` failed after the request was selected.
    Mlockall,
    /// The target has no supported process-wide lock syscall.
    UnsupportedPlatform,
}

impl MemoryLockFailureKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RlimitQuery => "rlimit-query",
            Self::Mlockall => "mlockall",
            Self::UnsupportedPlatform => "unsupported-platform",
        }
    }
}

/// Observable process-wide memory-lock state for health and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryLockState {
    /// No server startup policy has been applied in this process.
    NotConfigured,
    /// The configured policy explicitly disabled process locking.
    Disabled,
    /// Startup is between the pre-drop and post-drop lock boundaries.
    Deferred,
    /// The requested process lock completed, possibly with a finite budget.
    Locked,
    /// Startup continues under an explicitly permitted best-effort policy.
    Degraded,
    /// A required lock failed and startup must not expose service readiness.
    Failed,
}

impl MemoryLockState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not-configured",
            Self::Disabled => "disabled",
            Self::Deferred => "deferred",
            Self::Locked => "locked",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

/// Typed result published by server startup after the process-lock boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLockStartupStatus {
    pub policy: MemoryLockFailurePolicy,
    pub state: MemoryLockState,
    pub process_mode: MemoryLockProcessMode,
    pub limit: MemoryLockLimit,
    pub failure: Option<MemoryLockFailureKind>,
}

impl Default for MemoryLockStartupStatus {
    fn default() -> Self {
        Self::not_configured()
    }
}

impl MemoryLockStartupStatus {
    pub const fn not_configured() -> Self {
        Self {
            policy: MemoryLockFailurePolicy::BestEffort,
            state: MemoryLockState::NotConfigured,
            process_mode: MemoryLockProcessMode::None,
            limit: MemoryLockLimit::Unknown,
            failure: None,
        }
    }

    pub const fn is_not_ready(self) -> bool {
        matches!(self.state, MemoryLockState::Deferred | MemoryLockState::Failed)
    }

    pub const fn is_degraded(self) -> bool {
        matches!(self.state, MemoryLockState::Degraded)
    }

    pub const fn health_status(self) -> &'static str {
        if self.is_not_ready() {
            "not_ready"
        } else if self.is_degraded() {
            "degraded"
        } else {
            "ok"
        }
    }

    pub fn health_json(self) -> serde_json::Value {
        serde_json::json!({
            "status": self.health_status(),
            "policy": self.policy.as_str(),
            "state": self.state.as_str(),
            "process_mode": self.process_mode.as_str(),
            "limit": self.limit.as_str(),
            "limit_bytes": match self.limit {
                MemoryLockLimit::Finite(bytes) => serde_json::Value::from(bytes),
                MemoryLockLimit::Unknown | MemoryLockLimit::Unlimited => serde_json::Value::Null,
            },
            "failure": self.failure.map(MemoryLockFailureKind::as_str),
        })
    }
}

/// Startup error for a required process-wide memory lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryLockStartupError {
    pub kind: MemoryLockFailureKind,
    pub limit: MemoryLockLimit,
    pub message: String,
}

impl fmt::Display for MemoryLockStartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "required process memory lock failed (kind={}, limit={}): {}",
            self.kind.as_str(),
            self.limit.as_str(),
            self.message
        )
    }
}

impl std::error::Error for MemoryLockStartupError {}

static PROCESS_MEMORY_LOCK_STATUS: OnceLock<RwLock<MemoryLockStartupStatus>> = OnceLock::new();

fn status_store() -> &'static RwLock<MemoryLockStartupStatus> {
    PROCESS_MEMORY_LOCK_STATUS.get_or_init(|| RwLock::new(MemoryLockStartupStatus::default()))
}

fn publish_status(status: MemoryLockStartupStatus) {
    *status_store().write() = status;
}

/// Read the last process-wide memory-lock result published by server startup.
pub fn current_status() -> MemoryLockStartupStatus {
    *status_store().read()
}

/// Startup-owned memory-lock settings for a server runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLockPolicy {
    /// Lock process memory against swap where the host supports `mlockall`.
    pub lock_memory: bool,
    /// Lock newly allocated `MemoryPool` blocks against swap.
    pub lock_blocks: bool,
    /// Decide whether process-lock failure may degrade startup.
    pub failure_policy: MemoryLockFailurePolicy,
}

impl Default for MemoryLockPolicy {
    fn default() -> Self {
        let config = SecurityConfig::default();
        Self::from_security(&config)
    }
}

impl MemoryLockPolicy {
    /// Derive the server startup policy from the engine security section.
    pub fn from_security(config: &SecurityConfig) -> Self {
        Self {
            lock_memory: config.lock_memory,
            lock_blocks: config.lock_blocks,
            failure_policy: config.memory_lock_failure_policy,
        }
    }

    /// Apply the process and pool policy before the server identity is loaded.
    ///
    /// `defer_process_memory_lock` is only valid for standalone Linux startup
    /// with a configured privilege transition. In that case the individual
    /// TLS key lock remains the pre-drop protection boundary and the process
    /// lock is applied after the verified setxid transition.
    pub fn apply_before_tls_identity(
        self,
        defer_process_memory_lock: bool,
    ) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        crate::qftls::set_process_memory_lock_covers_future_allocations(false);
        let status = if !self.lock_memory {
            MemoryLockStartupStatus {
                policy: self.failure_policy,
                state: MemoryLockState::Disabled,
                process_mode: MemoryLockProcessMode::None,
                limit: MemoryLockLimit::Unknown,
                failure: None,
            }
        } else if defer_process_memory_lock {
            log::debug!(
                "Deferring process-wide memory locking until after the verified privilege transition"
            );
            MemoryLockStartupStatus {
                policy: self.failure_policy,
                state: MemoryLockState::Deferred,
                process_mode: MemoryLockProcessMode::Deferred,
                limit: MemoryLockLimit::Unknown,
                failure: None,
            }
        } else {
            self.apply_process_memory_lock()?
        };

        publish_status(status);
        if !self.lock_memory {
            log::debug!("Process-wide memory locking disabled by security configuration");
        }
        crate::optimize::MemoryPool::set_lock_blocks(self.lock_blocks);
        Ok(status)
    }

    /// Apply a process-wide lock after a deferred privilege transition.
    pub fn apply_deferred_process_memory_lock(
        self,
    ) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        if !self.lock_memory {
            let status = MemoryLockStartupStatus {
                policy: self.failure_policy,
                state: MemoryLockState::Disabled,
                process_mode: MemoryLockProcessMode::None,
                limit: MemoryLockLimit::Unknown,
                failure: None,
            };
            publish_status(status);
            return Ok(status);
        }

        let status = self.apply_process_memory_lock()?;
        publish_status(status);
        Ok(status)
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
        if self.failure_policy != candidate.failure_policy {
            changed.push("security.memory_lock_failure_policy");
        }
        if changed.is_empty() {
            return Ok(());
        }

        Err(format!(
            "{} are startup-owned and cannot change during standalone config reload; restart required",
            changed.join(" and ")
        ))
    }

    fn apply_process_memory_lock(self) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        #[cfg(unix)]
        {
            match lock_process_memory(self.failure_policy) {
                Ok(outcome) => {
                    if outcome.limit_query_failed {
                        log::warn!(
                            "RLIMIT_MEMLOCK query failed; mlockall used MCL_CURRENT only and startup is degraded"
                        );
                    }
                    if let MemoryLockLimit::Finite(limit) = outcome.limit {
                        log::warn!(
                            "RLIMIT_MEMLOCK is finite ({} bytes); mlockall used MCL_CURRENT only. Set LimitMEMLOCK=infinity for full process locking.",
                            limit
                        );
                    }
                    let status = MemoryLockStartupStatus {
                        policy: self.failure_policy,
                        state: if outcome.limit_query_failed {
                            MemoryLockState::Degraded
                        } else {
                            MemoryLockState::Locked
                        },
                        process_mode: outcome.process_mode,
                        limit: outcome.limit,
                        failure: outcome
                            .limit_query_failed
                            .then_some(MemoryLockFailureKind::RlimitQuery),
                    };
                    crate::qftls::set_process_memory_lock_covers_future_allocations(
                        outcome.process_mode == MemoryLockProcessMode::CurrentAndFuture,
                    );
                    log::info!(
                        "Process memory lock state={} mode={} limit={}",
                        status.state.as_str(),
                        status.process_mode.as_str(),
                        status.limit.as_str()
                    );
                    Ok(status)
                }
                Err(error) => self.handle_process_memory_lock_failure(error),
            }
        }
        #[cfg(not(unix))]
        {
            self.handle_process_memory_lock_failure(MemoryLockStartupError {
                kind: MemoryLockFailureKind::UnsupportedPlatform,
                limit: MemoryLockLimit::Unknown,
                message: "process-wide memory locking is unsupported on this platform".to_string(),
            })
        }
    }

    fn handle_process_memory_lock_failure(
        self,
        error: MemoryLockStartupError,
    ) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
        match decide_process_memory_lock_failure(self.failure_policy, error.clone()) {
            Ok(status) => {
                publish_status(status);
                log::warn!(
                    "Process memory lock degraded (kind={}, limit={}): {}; continuing because security.memory_lock_failure_policy=best-effort",
                    error.kind.as_str(),
                    error.limit.as_str(),
                    error.message
                );
                Ok(status)
            }
            Err(error) => {
                let status = MemoryLockStartupStatus {
                    policy: self.failure_policy,
                    state: MemoryLockState::Failed,
                    process_mode: MemoryLockProcessMode::None,
                    limit: error.limit,
                    failure: Some(error.kind),
                };
                publish_status(status);
                log::error!(
                    "Process memory lock required and startup is aborting (kind={}, limit={}): {}",
                    error.kind.as_str(),
                    error.limit.as_str(),
                    error.message
                );
                Err(error)
            }
        }
    }
}

#[cfg(all(unix, test))]
fn mlockall_flags_for_limit(current_limit: libc::rlim_t) -> libc::c_int {
    mlockall_flags_for_budget(if current_limit == libc::RLIM_INFINITY {
        MemoryLockLimit::Unlimited
    } else {
        MemoryLockLimit::Finite(current_limit)
    })
}

#[cfg(unix)]
fn mlockall_flags_for_budget(limit: MemoryLockLimit) -> libc::c_int {
    match limit {
        MemoryLockLimit::Unlimited => libc::MCL_CURRENT | libc::MCL_FUTURE,
        MemoryLockLimit::Finite(_) | MemoryLockLimit::Unknown => libc::MCL_CURRENT,
    }
}

fn decide_process_memory_lock_failure(
    policy: MemoryLockFailurePolicy,
    error: MemoryLockStartupError,
) -> Result<MemoryLockStartupStatus, MemoryLockStartupError> {
    if policy == MemoryLockFailurePolicy::BestEffort {
        return Ok(MemoryLockStartupStatus {
            policy,
            state: MemoryLockState::Degraded,
            process_mode: MemoryLockProcessMode::None,
            limit: error.limit,
            failure: Some(error.kind),
        });
    }
    Err(error)
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
fn classify_memlock_limit(
    result: std::io::Result<libc::rlim_t>,
    failure_policy: MemoryLockFailurePolicy,
) -> Result<(MemoryLockLimit, bool), MemoryLockStartupError> {
    match result {
        Ok(current_limit) if current_limit == libc::RLIM_INFINITY => {
            Ok((MemoryLockLimit::Unlimited, false))
        }
        Ok(current_limit) => Ok((MemoryLockLimit::Finite(current_limit), false)),
        Err(error) if failure_policy == MemoryLockFailurePolicy::BestEffort => {
            log::warn!("RLIMIT_MEMLOCK query failed: {error}; using MCL_CURRENT fallback");
            Ok((MemoryLockLimit::Unknown, true))
        }
        Err(error) => Err(MemoryLockStartupError {
            kind: MemoryLockFailureKind::RlimitQuery,
            limit: MemoryLockLimit::Unknown,
            message: error.to_string(),
        }),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryLockOutcome {
    process_mode: MemoryLockProcessMode,
    limit: MemoryLockLimit,
    limit_query_failed: bool,
}

#[cfg(unix)]
fn lock_process_memory(
    failure_policy: MemoryLockFailurePolicy,
) -> Result<MemoryLockOutcome, MemoryLockStartupError> {
    let (limit, limit_query_failed) =
        classify_memlock_limit(current_memlock_limit(), failure_policy)?;
    let flags = mlockall_flags_for_budget(limit);

    // SAFETY: flags contain only MCL_CURRENT and, when the process has an
    // unlimited memlock budget, MCL_FUTURE.
    if unsafe { libc::mlockall(flags) } != 0 {
        return Err(MemoryLockStartupError {
            kind: MemoryLockFailureKind::Mlockall,
            limit,
            message: std::io::Error::last_os_error().to_string(),
        });
    }

    Ok(MemoryLockOutcome {
        process_mode: if flags & libc::MCL_FUTURE != 0 {
            MemoryLockProcessMode::CurrentAndFuture
        } else {
            MemoryLockProcessMode::CurrentOnly
        },
        limit,
        limit_query_failed,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        MemoryLockFailureKind, MemoryLockFailurePolicy, MemoryLockLimit, MemoryLockPolicy,
        MemoryLockProcessMode, MemoryLockStartupError, MemoryLockState,
    };
    use crate::engine::SecurityConfig;
    use crate::optimize::{MemoryPool, LOCK_BLOCKS_TEST_MUTEX};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
            MemoryLockPolicy {
                lock_memory: false,
                lock_blocks: true,
                failure_policy: MemoryLockFailurePolicy::BestEffort,
            }
        );
    }

    #[test]
    fn standalone_reload_accepts_unchanged_startup_policy() {
        let policy = MemoryLockPolicy {
            lock_memory: true,
            lock_blocks: false,
            failure_policy: MemoryLockFailurePolicy::FailClosed,
        };

        assert_eq!(policy.reject_standalone_reload(policy), Ok(()));
    }

    #[test]
    fn standalone_reload_rejects_each_changed_startup_setting() {
        let current = MemoryLockPolicy {
            lock_memory: true,
            lock_blocks: true,
            failure_policy: MemoryLockFailurePolicy::FailClosed,
        };
        for (candidate, expected_field) in [
            (
                MemoryLockPolicy {
                    lock_memory: false,
                    lock_blocks: true,
                    failure_policy: MemoryLockFailurePolicy::FailClosed,
                },
                "security.lock_memory",
            ),
            (
                MemoryLockPolicy {
                    lock_memory: true,
                    lock_blocks: false,
                    failure_policy: MemoryLockFailurePolicy::FailClosed,
                },
                "security.lock_blocks",
            ),
            (
                MemoryLockPolicy {
                    lock_memory: true,
                    lock_blocks: true,
                    failure_policy: MemoryLockFailurePolicy::BestEffort,
                },
                "security.memory_lock_failure_policy",
            ),
            (
                MemoryLockPolicy {
                    lock_memory: false,
                    lock_blocks: false,
                    failure_policy: MemoryLockFailurePolicy::BestEffort,
                },
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

        MemoryLockPolicy {
            lock_memory: false,
            lock_blocks: false,
            failure_policy: MemoryLockFailurePolicy::BestEffort,
        }
        .apply_before_tls_identity(false)
        .expect("disabled process memory lock should not fail");

        assert!(!MemoryPool::lock_blocks_enabled());
    }

    #[test]
    fn standalone_restart_reapplies_pool_setting_instead_of_retaining_previous_value() {
        let _guard = LOCK_BLOCKS_TEST_MUTEX.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = PoolLockSettingRestore(MemoryPool::lock_blocks_enabled());

        MemoryLockPolicy {
            lock_memory: false,
            lock_blocks: false,
            failure_policy: MemoryLockFailurePolicy::BestEffort,
        }
        .apply_before_tls_identity(false)
        .expect("disabled process memory lock should not fail");
        assert!(!MemoryPool::lock_blocks_enabled());

        MemoryLockPolicy {
            lock_memory: false,
            lock_blocks: true,
            failure_policy: MemoryLockFailurePolicy::BestEffort,
        }
        .apply_before_tls_identity(false)
        .expect("disabled process memory lock should not fail");
        assert!(MemoryPool::lock_blocks_enabled());
    }

    #[test]
    fn deferred_process_lock_status_is_explicit_before_privilege_transition() {
        let status = MemoryLockPolicy {
            lock_memory: true,
            lock_blocks: true,
            failure_policy: MemoryLockFailurePolicy::FailClosed,
        }
        .apply_before_tls_identity(true)
        .expect("deferred process lock must publish a pending status");

        assert_eq!(status.state, MemoryLockState::Deferred);
        assert_eq!(status.process_mode, MemoryLockProcessMode::Deferred);
        assert!(status.is_not_ready());
    }

    #[cfg(unix)]
    #[test]
    fn finite_memlock_limit_never_enables_future_allocation_locking() {
        assert_eq!(super::mlockall_flags_for_limit(8 * 1024 * 1024), libc::MCL_CURRENT);
        assert_eq!(
            super::mlockall_flags_for_limit(libc::RLIM_INFINITY),
            libc::MCL_CURRENT | libc::MCL_FUTURE
        );
        assert_eq!(super::mlockall_flags_for_budget(MemoryLockLimit::Unknown), libc::MCL_CURRENT);
    }

    #[cfg(unix)]
    #[test]
    fn memlock_limit_query_failure_is_typed_and_policy_specific() {
        let query_error = || std::io::Error::from_raw_os_error(libc::EIO);
        let (limit, degraded) =
            super::classify_memlock_limit(Err(query_error()), MemoryLockFailurePolicy::BestEffort)
                .expect("best-effort query failure uses the bounded current-page fallback");
        assert_eq!(limit, MemoryLockLimit::Unknown);
        assert!(degraded);

        let error =
            super::classify_memlock_limit(Err(query_error()), MemoryLockFailurePolicy::FailClosed)
                .expect_err("fail-closed query failure must abort before mlockall");
        assert_eq!(error.kind, MemoryLockFailureKind::RlimitQuery);
        assert_eq!(error.limit, MemoryLockLimit::Unknown);
    }

    #[test]
    fn failure_policy_distinguishes_best_effort_from_fail_closed() {
        let error = MemoryLockStartupError {
            kind: MemoryLockFailureKind::Mlockall,
            limit: MemoryLockLimit::Finite(4096),
            message: "permission denied".to_string(),
        };
        let best_effort = super::decide_process_memory_lock_failure(
            MemoryLockFailurePolicy::BestEffort,
            error.clone(),
        )
        .expect("best-effort must return a degraded startup result");
        assert_eq!(best_effort.state, MemoryLockState::Degraded);
        assert_eq!(best_effort.process_mode, MemoryLockProcessMode::None);
        assert_eq!(best_effort.failure, Some(MemoryLockFailureKind::Mlockall));
        assert!(super::decide_process_memory_lock_failure(
            MemoryLockFailurePolicy::FailClosed,
            error
        )
        .is_err());

        let unsupported = super::decide_process_memory_lock_failure(
            MemoryLockFailurePolicy::BestEffort,
            MemoryLockStartupError {
                kind: MemoryLockFailureKind::UnsupportedPlatform,
                limit: MemoryLockLimit::Unknown,
                message: "unsupported".to_string(),
            },
        )
        .expect("best-effort unsupported platforms must publish degraded state");
        assert_eq!(unsupported.failure, Some(MemoryLockFailureKind::UnsupportedPlatform));
    }

    #[cfg(unix)]
    #[test]
    fn production_memory_lock_boundary_locks_pages_or_reports_supported_limit_error() {
        let (_guard, _cleanup_observed) = ProcessMemoryLockGuard::new();
        match super::lock_process_memory(MemoryLockFailurePolicy::BestEffort) {
            Ok(outcome) => {
                assert_ne!(outcome.process_mode, MemoryLockProcessMode::None);

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
            }
            Err(error) => {
                assert!(matches!(
                    error.kind,
                    MemoryLockFailureKind::RlimitQuery | MemoryLockFailureKind::Mlockall
                ));
            }
        }
    }

    #[cfg(unix)]
    struct ProcessMemoryLockGuard {
        cleanup_observed: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl ProcessMemoryLockGuard {
        fn new() -> (Self, Arc<AtomicBool>) {
            let cleanup_observed = Arc::new(AtomicBool::new(false));
            (Self { cleanup_observed: cleanup_observed.clone() }, cleanup_observed)
        }
    }

    #[cfg(unix)]
    impl Drop for ProcessMemoryLockGuard {
        fn drop(&mut self) {
            // SAFETY: this test owns the process-wide lock syscall boundary; calling
            // munlockall is harmless when the preceding query or lock call failed.
            if unsafe { libc::munlockall() } != 0 {
                log::debug!(
                    "panic-safe test cleanup munlockall failed: {}",
                    std::io::Error::last_os_error()
                );
            }
            self.cleanup_observed.store(true, Ordering::Release);
        }
    }

    #[cfg(unix)]
    #[test]
    fn process_memory_lock_guard_cleans_up_during_unwind() {
        let (guard, cleanup_observed) = ProcessMemoryLockGuard::new();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = guard;
            panic!("exercise panic-safe process-lock cleanup");
        }));

        assert!(result.is_err());
        assert!(cleanup_observed.load(Ordering::Acquire));
    }
}
