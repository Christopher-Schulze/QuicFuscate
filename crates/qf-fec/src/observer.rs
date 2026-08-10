//! Transport telemetry and FEC-owned runtime hints.
//!
//! The observer keeps only connection-local FEC state. The product root adapts
//! its callbacks to the root transport observer trait and applies the returned
//! redundancy delta to a live connection.

use crate::{BrainFecHints, FecRuntimePolicy};
use parking_lot::RwLock;
use qf_common::env_utils::EnvSnapshot;
use qf_transport_types::TransportObserver;
use std::sync::{Arc, OnceLock};

#[derive(Default, Debug, Clone)]
struct FecObserverSnapshot {
    ack_delay_ewma_us: f64,
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    ack_events: u64,
}

#[derive(Default, Debug)]
struct FecObserverState {
    snapshot: FecObserverSnapshot,
    last_redundancy_ppm: u32,
}

/// Platform hints used to select the observer's ambient transport profile.
#[derive(Clone, Copy, Debug, Default)]
#[doc(hidden)]
pub struct FecObserverPlatformHints {
    pub mobile_os: bool,
    pub containerized_server: bool,
}

impl FecObserverPlatformHints {
    /// Detect platform hints without reading product configuration.
    #[doc(hidden)]
    pub fn detect() -> Self {
        let mobile_os = cfg!(any(target_os = "ios", target_os = "android"));

        #[cfg(target_os = "linux")]
        let containerized_server = std::path::Path::new("/run/.containerenv").exists();

        #[cfg(not(target_os = "linux"))]
        let containerized_server = false;

        Self { mobile_os, containerized_server }
    }
}

/// Ambient or explicitly selected transport persona used by FEC cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum TransportProfile {
    Mobile,
    Desktop,
    Server,
}

/// Profile policy resolved from configuration and platform hints.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub enum FecObserverProfilePolicy {
    Explicit(TransportProfile),
    Ambient(TransportProfile),
}

impl FecObserverProfilePolicy {
    /// Resolve an explicit profile first, then platform-derived defaults.
    #[doc(hidden)]
    pub fn from_sources(
        profile_override: Option<&str>,
        platform_hints: FecObserverPlatformHints,
    ) -> Self {
        if let Some(profile) = profile_override {
            return Self::Explicit(match profile {
                "mobile" => TransportProfile::Mobile,
                "server" => TransportProfile::Server,
                _ => TransportProfile::Desktop,
            });
        }

        if platform_hints.mobile_os {
            return Self::Ambient(TransportProfile::Mobile);
        }
        if platform_hints.containerized_server {
            return Self::Ambient(TransportProfile::Server);
        }

        Self::Ambient(TransportProfile::Desktop)
    }

    /// Resolve the profile from one immutable environment snapshot.
    #[doc(hidden)]
    pub fn detect_with_snapshot(environment: &EnvSnapshot) -> Self {
        let platform_hints = FecObserverPlatformHints::detect();
        match environment.first(["QUICFUSCATE_PROFILE"]) {
            None => Self::from_sources(None, platform_hints),
            Some(profile) if matches!(profile.as_str(), "mobile" | "server" | "desktop") => {
                Self::from_sources(Some(profile.as_str()), platform_hints)
            }
            Some(profile) => {
                log::warn!(
                    "Invalid QUICFUSCATE_PROFILE value '{profile}'; retaining detected platform profile"
                );
                Self::from_sources(None, platform_hints)
            }
        }
    }

    /// Return the selected profile independent of whether it was explicit.
    #[doc(hidden)]
    pub fn profile(self) -> TransportProfile {
        match self {
            Self::Explicit(profile) | Self::Ambient(profile) => profile,
        }
    }
}

/// Immutable ambient inputs captured for one observer instance.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct FecObserverAmbientInputs {
    pub profile: FecObserverProfilePolicy,
    pub base_stream_interval: u32,
}

impl FecObserverAmbientInputs {
    /// Build bounded ambient inputs from a policy snapshot.
    #[doc(hidden)]
    pub fn new(profile: FecObserverProfilePolicy, base_stream_interval: u32) -> Self {
        Self { profile, base_stream_interval }
    }

    /// Resolve the cadence input from the runtime FEC policy.
    #[doc(hidden)]
    pub fn from_runtime_policy(
        runtime_policy: &FecRuntimePolicy,
        profile: FecObserverProfilePolicy,
    ) -> Self {
        let base_stream_interval = runtime_policy
            .stream_every_override
            .map(|value| value as u32)
            .unwrap_or(8)
            .clamp(1, 32);

        Self::new(profile, base_stream_interval)
    }

    /// Resolve all ambient inputs from one immutable environment snapshot.
    #[doc(hidden)]
    pub fn detect_with_snapshot(environment: &EnvSnapshot) -> Self {
        let runtime_policy = FecRuntimePolicy::detect_with_snapshot(environment);
        Self::from_runtime_policy(
            &runtime_policy,
            FecObserverProfilePolicy::detect_with_snapshot(environment),
        )
    }
}

/// Connection-local FEC telemetry and Brain hint bridge.
#[doc(hidden)]
pub struct FecObserver {
    state: RwLock<FecObserverState>,
    ambient: FecObserverAmbientInputs,
    brain_hints: OnceLock<Arc<BrainFecHints>>,
}

impl FecObserver {
    /// Construct an observer from the process environment.
    #[doc(hidden)]
    pub fn new() -> Self {
        let environment = EnvSnapshot::capture();
        Self::new_with_snapshot(&environment)
    }

    /// Construct an observer from one immutable environment snapshot.
    #[doc(hidden)]
    pub fn new_with_snapshot(environment: &EnvSnapshot) -> Self {
        Self {
            state: RwLock::new(FecObserverState::default()),
            ambient: FecObserverAmbientInputs::detect_with_snapshot(environment),
            brain_hints: OnceLock::new(),
        }
    }

    /// Attach the Brain hints belonging to this connection.
    #[doc(hidden)]
    pub fn attach_brain_hints(&self, hints: Arc<BrainFecHints>) {
        let _ = self.brain_hints.set(hints);
    }

    /// Return the immutable base streaming interval captured at construction.
    #[doc(hidden)]
    pub fn base_stream_interval(&self) -> u32 {
        self.ambient.base_stream_interval
    }

    /// Compute the FEC-owned streaming interval from transport evidence.
    #[doc(hidden)]
    pub fn compute_streaming_interval(&self) -> u32 {
        let state = self.state.read();
        let snapshot = &state.snapshot;

        let mut interval = self.ambient.base_stream_interval;
        let total_ecn =
            snapshot.ecn_ect0.saturating_add(snapshot.ecn_ect1).saturating_add(snapshot.ecn_ce);
        let ce_ratio = if total_ecn == 0 { 0.0 } else { snapshot.ecn_ce as f64 / total_ecn as f64 };

        if ce_ratio > 0.1 {
            interval = interval.saturating_sub(4).max(1);
        } else if ce_ratio > 0.05 {
            interval = interval.saturating_sub(2).max(2);
        } else if ce_ratio < 0.001 && snapshot.ack_delay_ewma_us < 1000.0 {
            interval = interval.saturating_add(4).min(32);
        }

        let brain_hint = self.brain_hints.get().map(|hints| hints.interval_pkts()).unwrap_or(0);
        if (1..=32).contains(&brain_hint) {
            interval = (((interval as u64 * 3) + (brain_hint * 2)) / 5).clamp(1, 32) as u32;
        }

        interval
    }

    /// Return a changed Brain redundancy hint once, if one is pending.
    #[doc(hidden)]
    pub fn take_redundancy_hint(&self) -> Option<u32> {
        let _profile = self.ambient.profile.profile();
        let mut state = self.state.write();
        let ppm_hint = self.brain_hints.get().map(|hints| hints.redundancy_ppm()).unwrap_or(0);
        if ppm_hint > 0 && ppm_hint != state.last_redundancy_ppm {
            state.last_redundancy_ppm = ppm_hint;
            Some(ppm_hint)
        } else {
            None
        }
    }

    /// Record one transport ACK delay sample.
    #[doc(hidden)]
    pub fn on_ack(&self, ack_delay: u64) {
        let mut state = self.state.write();
        let snapshot = &mut state.snapshot;
        let sample = ack_delay as f64;
        snapshot.ack_delay_ewma_us = if snapshot.ack_events == 0 {
            sample
        } else {
            0.2 * sample + 0.8 * snapshot.ack_delay_ewma_us
        };
        snapshot.ack_events = snapshot.ack_events.saturating_add(1);
    }

    /// Record the current transport ECN counters.
    #[doc(hidden)]
    pub fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        let mut state = self.state.write();
        state.snapshot.ecn_ect0 = ect0;
        state.snapshot.ecn_ect1 = ect1;
        state.snapshot.ecn_ce = ce;
    }
}

impl Default for FecObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportObserver for FecObserver {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        FecObserver::on_ack(self, ack_delay);
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        FecObserver::on_ecn_update(self, ect0, ect1, ce);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FecObserver, FecObserverAmbientInputs, FecObserverProfilePolicy, FecObserverState,
        TransportProfile,
    };
    use qf_transport_types::TransportObserver;
    use std::sync::OnceLock;

    #[test]
    fn transport_trait_callbacks_update_the_child_owned_observer() {
        let observer = FecObserver {
            state: parking_lot::RwLock::new(FecObserverState::default()),
            ambient: FecObserverAmbientInputs::new(
                FecObserverProfilePolicy::Ambient(TransportProfile::Desktop),
                8,
            ),
            brain_hints: OnceLock::new(),
        };

        TransportObserver::on_ack(&observer, 500, &[(1, 2)]);
        TransportObserver::on_ecn_update(&observer, 80, 0, 20);

        assert_eq!(observer.compute_streaming_interval(), 4);
    }
}
