//! Bounded cleanup contract for resources exclusively owned by QuicFuscate.

use std::time::Duration;

/// Exact class of an operating-system resource owned by QuicFuscate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnedResourceKind {
    #[cfg(any(target_os = "linux", test))]
    NftTable,
    #[cfg(any(target_os = "linux", test))]
    IptablesChain,
    #[cfg(any(target_os = "linux", test))]
    IptablesRule,
    #[cfg(any(target_os = "macos", test))]
    PfAnchor,
    #[cfg(any(target_os = "windows", test))]
    WindowsFirewallRule,
    #[cfg(any(target_os = "windows", test))]
    WindowsNat,
}

/// Stable identity used in cleanup results and errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedResourceId {
    kind: OwnedResourceKind,
    name: String,
}

impl OwnedResourceId {
    pub(crate) fn new(kind: OwnedResourceKind, name: impl Into<String>) -> Self {
        Self { kind, name: name.into() }
    }
}

impl std::fmt::Display for OwnedResourceId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:?}:{}", self.kind, self.name)
    }
}

/// Whether cleanup changed operating-system state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupDisposition {
    AlreadyAbsent,
    Removed,
}

/// Verified cleanup result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanupOutcome {
    pub(crate) resource: OwnedResourceId,
    pub(crate) disposition: CleanupDisposition,
    pub(crate) attempts: u8,
}

impl CleanupOutcome {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn removed(&self) -> bool {
        self.disposition == CleanupDisposition::Removed
    }
}

/// Operation that exhausted the bounded cleanup policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupPhase {
    Inspect,
    Remove,
    Verify,
}

/// Exact permanent cleanup failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanupError {
    pub(crate) resource: OwnedResourceId,
    pub(crate) attempts: u8,
    pub(crate) phase: CleanupPhase,
    pub(crate) detail: String,
}

impl std::fmt::Display for CleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} cleanup failed during {:?} after {} attempt(s): {}",
            self.resource, self.phase, self.attempts, self.detail
        )
    }
}

impl std::error::Error for CleanupError {}

/// Bounded retry policy shared by native cleanup paths.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CleanupPolicy {
    max_attempts: u8,
    retry_delay: Duration,
}

impl CleanupPolicy {
    pub(crate) const fn standard() -> Self {
        Self { max_attempts: 3, retry_delay: Duration::from_millis(100) }
    }

    #[cfg(test)]
    const fn immediate(max_attempts: u8) -> Self {
        Self { max_attempts, retry_delay: Duration::ZERO }
    }
}

/// Remove one exact owned resource and verify its absence.
///
/// The injected operations make transient, permanent, and postcondition
/// failures deterministic in unit tests without mocking product behavior.
pub(crate) fn cleanup_owned_resource<Inspect, Remove, Sleep>(
    resource: OwnedResourceId,
    policy: CleanupPolicy,
    mut inspect: Inspect,
    mut remove: Remove,
    mut sleep: Sleep,
) -> Result<CleanupOutcome, CleanupError>
where
    Inspect: FnMut() -> Result<bool, String>,
    Remove: FnMut() -> Result<(), String>,
    Sleep: FnMut(Duration),
{
    let max_attempts = policy.max_attempts.max(1);
    let mut removal_attempted = false;
    let mut last_failure = (CleanupPhase::Inspect, "resource was not inspected".to_string());

    for attempt in 1..=max_attempts {
        match inspect() {
            Ok(false) => {
                return Ok(CleanupOutcome {
                    resource,
                    disposition: if removal_attempted {
                        CleanupDisposition::Removed
                    } else {
                        CleanupDisposition::AlreadyAbsent
                    },
                    attempts: attempt,
                });
            }
            Ok(true) => {
                removal_attempted = true;
                let removal_failure = remove().err();

                match inspect() {
                    Ok(false) => {
                        return Ok(CleanupOutcome {
                            resource,
                            disposition: CleanupDisposition::Removed,
                            attempts: attempt,
                        });
                    }
                    Ok(true) => {
                        last_failure = removal_failure.map_or_else(
                            || {
                                (
                                    CleanupPhase::Verify,
                                    "resource remains present after removal".to_string(),
                                )
                            },
                            |detail| (CleanupPhase::Remove, detail),
                        );
                    }
                    Err(detail) => {
                        last_failure = match removal_failure {
                            Some(remove_detail) => (
                                CleanupPhase::Verify,
                                format!(
                                    "postcondition inspection failed: {detail}; removal failed: {remove_detail}"
                                ),
                            ),
                            None => (CleanupPhase::Verify, detail),
                        };
                    }
                }
            }
            Err(detail) => {
                last_failure = (CleanupPhase::Inspect, detail);
            }
        }

        if attempt < max_attempts {
            sleep(policy.retry_delay);
        }
    }

    Err(CleanupError {
        resource,
        attempts: max_attempts,
        phase: last_failure.0,
        detail: last_failure.1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn resource() -> OwnedResourceId {
        OwnedResourceId::new(OwnedResourceKind::NftTable, "inet quicfuscate_test")
    }

    #[test]
    fn absent_resource_is_idempotent_without_remove() {
        let mut removes = 0;
        let outcome = cleanup_owned_resource(
            resource(),
            CleanupPolicy::immediate(3),
            || Ok(false),
            || {
                removes += 1;
                Ok(())
            },
            |_| {},
        )
        .unwrap();

        assert_eq!(outcome.disposition, CleanupDisposition::AlreadyAbsent);
        assert_eq!(outcome.attempts, 1);
        assert_eq!(removes, 0);
    }

    #[test]
    fn successful_remove_requires_absent_postcondition() {
        let mut states = VecDeque::from([Ok(true), Ok(false)]);
        let outcome = cleanup_owned_resource(
            resource(),
            CleanupPolicy::immediate(3),
            || states.pop_front().unwrap_or(Ok(false)),
            || Ok(()),
            |_| {},
        )
        .unwrap();

        assert_eq!(outcome.disposition, CleanupDisposition::Removed);
        assert_eq!(outcome.attempts, 1);
        assert!(states.is_empty());
    }

    #[test]
    fn transient_remove_failure_retries_and_verifies() {
        let mut states = VecDeque::from([Ok(true), Ok(true), Ok(true), Ok(false)]);
        let mut removes = VecDeque::from([Err("busy".to_string()), Ok(())]);
        let mut sleeps = 0;
        let outcome = cleanup_owned_resource(
            resource(),
            CleanupPolicy::immediate(3),
            || states.pop_front().unwrap_or(Ok(false)),
            || removes.pop_front().unwrap_or(Ok(())),
            |_| sleeps += 1,
        )
        .unwrap();

        assert_eq!(outcome.disposition, CleanupDisposition::Removed);
        assert_eq!(outcome.attempts, 2);
        assert_eq!(sleeps, 1);
    }

    #[test]
    fn persistent_postcondition_failure_is_exact() {
        let error = cleanup_owned_resource(
            resource(),
            CleanupPolicy::immediate(3),
            || Ok(true),
            || Ok(()),
            |_| {},
        )
        .unwrap_err();

        assert_eq!(error.phase, CleanupPhase::Verify);
        assert_eq!(error.attempts, 3);
        assert!(error.detail.contains("remains present"));
        assert!(error.to_string().contains("inet quicfuscate_test"));
    }

    #[test]
    fn successful_effect_wins_over_nonzero_remove_result() {
        let mut states = VecDeque::from([Ok(true), Ok(false)]);
        let outcome = cleanup_owned_resource(
            resource(),
            CleanupPolicy::immediate(3),
            || states.pop_front().unwrap_or(Ok(false)),
            || Err("command lost its response".to_string()),
            |_| {},
        )
        .unwrap();

        assert_eq!(outcome.disposition, CleanupDisposition::Removed);
        assert_eq!(outcome.attempts, 1);
    }

    #[test]
    fn owned_resource_taxonomy_and_standard_policy_are_exercised() {
        let kinds = [
            OwnedResourceKind::NftTable,
            OwnedResourceKind::IptablesChain,
            OwnedResourceKind::IptablesRule,
            OwnedResourceKind::PfAnchor,
            OwnedResourceKind::WindowsFirewallRule,
            OwnedResourceKind::WindowsNat,
        ];
        for kind in kinds {
            let outcome = CleanupOutcome {
                resource: OwnedResourceId::new(kind, "owned"),
                disposition: CleanupDisposition::Removed,
                attempts: CleanupPolicy::standard().max_attempts,
            };
            assert!(outcome.removed());
            assert_eq!(outcome.attempts, 3);
        }
    }
}
