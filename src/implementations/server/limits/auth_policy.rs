use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::time_source::ProtocolClock;

/// Bounded QKey authentication abuse-policy configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPolicyConfig {
    /// Disable all per-IP state and admission delays.
    pub enabled: bool,
    /// First consecutive failure that schedules exponential backoff.
    pub backoff_after_failures: u32,
    /// Initial exponential-backoff duration.
    pub backoff_base: Duration,
    /// Maximum exponential-backoff duration.
    pub backoff_max: Duration,
    /// Consecutive failure that enters the explicit blocked state.
    pub block_after_failures: u32,
    /// Duration of the explicit blocked state.
    pub block_duration: Duration,
    /// Remove inactive per-IP state after this duration.
    pub idle_timeout: Duration,
    /// Minimum interval between full-map idle-prune passes.
    pub prune_interval: Duration,
    /// Hard bound for attacker-controlled per-IP state.
    pub max_tracked_ips: usize,
    /// Hard bound for concurrent in-flight attempts from one IP.
    pub max_pending_attempts_per_ip: usize,
}

impl Default for AuthPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backoff_after_failures: 3,
            backoff_base: Duration::from_millis(250),
            backoff_max: Duration::from_secs(8),
            block_after_failures: 10,
            block_duration: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(900),
            prune_interval: Duration::from_secs(30),
            max_tracked_ips: 65_536,
            max_pending_attempts_per_ip: 4,
        }
    }
}

impl AuthPolicyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.backoff_after_failures == 0 {
            return Err("auth backoff threshold must be at least 1".to_string());
        }
        if self.block_after_failures <= self.backoff_after_failures {
            return Err("auth block threshold must exceed the backoff threshold".to_string());
        }
        if self.backoff_base.is_zero() {
            return Err("auth backoff base must be greater than zero".to_string());
        }
        if self.backoff_max < self.backoff_base {
            return Err("auth backoff maximum must not be below the base".to_string());
        }
        if self.block_duration.is_zero()
            || self.idle_timeout.is_zero()
            || self.prune_interval.is_zero()
        {
            return Err(
                "auth block, idle, and prune durations must be greater than zero".to_string()
            );
        }
        if self.max_tracked_ips == 0 || self.max_pending_attempts_per_ip == 0 {
            return Err("auth state and pending-attempt bounds must be at least 1".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthAttempt {
    id: u64,
    ip: IpAddr,
    tracked: bool,
}

impl AuthAttempt {
    #[cfg(test)]
    pub(crate) fn ip(self) -> IpAddr {
        self.ip
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthAdmission {
    Allowed(AuthAttempt),
    Backoff { retry_after: Duration },
    Blocked { retry_after: Duration },
    StateCapacity,
    PendingCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthTerminal {
    Succeeded,
    Failed,
    Abandoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthCompletion {
    Succeeded,
    Failed,
    FailedWithBackoff { delay: Duration },
    FailedAndBlocked { duration: Duration },
    Abandoned,
    Duplicate,
    Disabled,
}

#[derive(Debug)]
struct AuthIpState {
    consecutive_failures: u32,
    active_attempts: HashSet<u64>,
    backoff_until: Option<Duration>,
    blocked_until: Option<Duration>,
    last_seen: Duration,
}

impl AuthIpState {
    fn new(now: Duration) -> Self {
        Self {
            consecutive_failures: 0,
            active_attempts: HashSet::new(),
            backoff_until: None,
            blocked_until: None,
            last_seen: now,
        }
    }

    fn reset_expired_block(&mut self, now: Duration) {
        if self.blocked_until.is_some_and(|until| now >= until) {
            self.consecutive_failures = 0;
            self.backoff_until = None;
            self.blocked_until = None;
        }
    }
}

/// Monotonic, bounded per-IP QKey authentication policy.
pub(crate) struct AuthRateLimiter {
    config: AuthPolicyConfig,
    anchor: Instant,
    clock: ProtocolClock,
    last_now: Duration,
    next_prune: Duration,
    next_attempt_id: u64,
    states: HashMap<IpAddr, AuthIpState>,
}

impl AuthRateLimiter {
    #[allow(dead_code)]
    pub(crate) fn new(config: AuthPolicyConfig) -> Self {
        Self::new_with_clock(config, &ProtocolClock::default())
    }

    pub(crate) fn new_with_clock(config: AuthPolicyConfig, clock: &ProtocolClock) -> Self {
        Self {
            config,
            anchor: clock.now(),
            clock: clock.clone(),
            last_now: Duration::ZERO,
            next_prune: Duration::ZERO,
            next_attempt_id: 1,
            states: HashMap::new(),
        }
    }

    pub(crate) fn begin(&mut self, ip: IpAddr) -> AuthAdmission {
        self.begin_at(ip, self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn complete(
        &mut self,
        attempt: AuthAttempt,
        terminal: AuthTerminal,
    ) -> AuthCompletion {
        self.complete_at(attempt, terminal, self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn prune_if_due(&mut self) -> usize {
        self.prune_if_due_at(self.clock.elapsed_since(self.anchor))
    }

    pub(crate) fn tracked_ips(&self) -> usize {
        self.states.len()
    }

    fn normalize_now(&mut self, now: Duration) -> Duration {
        self.last_now = self.last_now.max(now);
        self.last_now
    }

    pub(crate) fn begin_at(&mut self, ip: IpAddr, now: Duration) -> AuthAdmission {
        let now = self.normalize_now(now);
        if !self.config.enabled {
            return AuthAdmission::Allowed(AuthAttempt { id: 0, ip, tracked: false });
        }

        self.prune_if_due_at(now);
        if !self.states.contains_key(&ip) && self.states.len() >= self.config.max_tracked_ips {
            self.prune_idle_at(now);
            if self.states.len() >= self.config.max_tracked_ips {
                return AuthAdmission::StateCapacity;
            }
        }

        let state = self.states.entry(ip).or_insert_with(|| AuthIpState::new(now));
        state.last_seen = now;
        state.reset_expired_block(now);
        if let Some(until) = state.blocked_until.filter(|until| *until > now) {
            return AuthAdmission::Blocked { retry_after: until.saturating_sub(now) };
        }
        if let Some(until) = state.backoff_until.filter(|until| *until > now) {
            return AuthAdmission::Backoff { retry_after: until.saturating_sub(now) };
        }
        state.backoff_until = None;
        if state.active_attempts.len() >= self.config.max_pending_attempts_per_ip {
            return AuthAdmission::PendingCapacity;
        }

        let id = self.next_attempt_id;
        self.next_attempt_id = self.next_attempt_id.wrapping_add(1).max(1);
        state.active_attempts.insert(id);
        AuthAdmission::Allowed(AuthAttempt { id, ip, tracked: true })
    }

    pub(crate) fn complete_at(
        &mut self,
        attempt: AuthAttempt,
        terminal: AuthTerminal,
        now: Duration,
    ) -> AuthCompletion {
        let now = self.normalize_now(now);
        if !attempt.tracked {
            return AuthCompletion::Disabled;
        }
        let Some(state) = self.states.get_mut(&attempt.ip) else {
            return AuthCompletion::Duplicate;
        };
        if !state.active_attempts.remove(&attempt.id) {
            return AuthCompletion::Duplicate;
        }
        state.last_seen = now;

        match terminal {
            AuthTerminal::Succeeded => {
                state.consecutive_failures = 0;
                state.backoff_until = None;
                state.blocked_until = None;
                if state.active_attempts.is_empty() {
                    self.states.remove(&attempt.ip);
                }
                AuthCompletion::Succeeded
            }
            AuthTerminal::Abandoned => {
                if state.active_attempts.is_empty() && state.consecutive_failures == 0 {
                    self.states.remove(&attempt.ip);
                }
                AuthCompletion::Abandoned
            }
            AuthTerminal::Failed => {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                if state.consecutive_failures >= self.config.block_after_failures {
                    state.backoff_until = None;
                    state.blocked_until = Some(now.saturating_add(self.config.block_duration));
                    return AuthCompletion::FailedAndBlocked {
                        duration: self.config.block_duration,
                    };
                }
                if state.consecutive_failures >= self.config.backoff_after_failures {
                    let exponent = state.consecutive_failures - self.config.backoff_after_failures;
                    let multiplier = 1u32.checked_shl(exponent.min(31)).unwrap_or(u32::MAX);
                    let delay = self
                        .config
                        .backoff_base
                        .checked_mul(multiplier)
                        .unwrap_or(self.config.backoff_max)
                        .min(self.config.backoff_max);
                    state.backoff_until = Some(now.saturating_add(delay));
                    return AuthCompletion::FailedWithBackoff { delay };
                }
                AuthCompletion::Failed
            }
        }
    }

    pub(crate) fn prune_if_due_at(&mut self, now: Duration) -> usize {
        let now = self.normalize_now(now);
        if now < self.next_prune {
            return 0;
        }
        self.next_prune = now.saturating_add(self.config.prune_interval);
        self.prune_idle_at(now)
    }

    fn prune_idle_at(&mut self, now: Duration) -> usize {
        let before = self.states.len();
        let idle_timeout = self.config.idle_timeout;
        self.states.retain(|_, state| {
            state.reset_expired_block(now);
            !state.active_attempts.is_empty()
                || state.blocked_until.is_some_and(|until| until > now)
                || state.backoff_until.is_some_and(|until| until > now)
                || now.saturating_sub(state.last_seen) < idle_timeout
        });
        before.saturating_sub(self.states.len())
    }
}
