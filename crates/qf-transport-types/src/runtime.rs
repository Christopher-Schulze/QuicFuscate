//! Root-independent transport control contracts.

use std::sync::atomic::{AtomicU32, Ordering};

/// Pending FEC parameter changes consumed by the adaptive FEC controller.
#[derive(Debug, Clone, Copy, Default)]
#[doc(hidden)]
pub struct FecControlDelta {
    /// Override for the streaming FEC emission interval.
    pub stream_every: Option<usize>,
    /// Override for FEC redundancy in parts-per-million.
    pub redundancy_ppm: Option<u32>,
    /// Force FEC into streaming mode for minimal latency.
    pub force_streaming: bool,
}

/// Per-connection permission flags controlling Brain stealth actuators.
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct BrainRuntimePermissions {
    /// Allow Brain to adjust the ACK-eliciting threshold.
    pub ack_threshold: bool,
    /// Allow Brain to toggle external pacing control.
    pub external_pacing: bool,
    /// Allow Brain to adjust stealth timing jitter.
    pub timing: bool,
    /// Allow Brain to adjust stealth padding parameters.
    pub padding: bool,
    /// Allow Brain to change the browser mimic bias code.
    pub mimic_bias: bool,
    /// Allow Brain to adjust adaptive padding granularity.
    pub granularity: bool,
    /// Allow Brain to switch the congestion control browser profile.
    pub cc_profile: bool,
}

impl Default for BrainRuntimePermissions {
    fn default() -> Self {
        Self {
            ack_threshold: true,
            external_pacing: true,
            timing: true,
            padding: true,
            mimic_bias: true,
            granularity: true,
            cc_profile: true,
        }
    }
}

/// Connection-local Brain and probe escalation levels shared by policy consumers.
#[derive(Debug)]
#[doc(hidden)]
pub struct IntelligentLevelHints {
    brain_level: AtomicU32,
    probe_level: AtomicU32,
    prefer_masque: AtomicU32,
    /// Last downstream density (`ack_us`) published by the Brain, microseconds.
    last_ack_us: AtomicU32,
    /// Last upstream density (`up_us`) published by the Brain, microseconds.
    last_up_us: AtomicU32,
    /// Last derived padding rate (0-100) after the direction-aware table.
    last_padding_rate: AtomicU32,
    /// Last derived outbound jitter ceiling, microseconds.
    last_jitter_us: AtomicU32,
}

impl IntelligentLevelHints {
    /// Creates an inactive hint state.
    #[doc(hidden)]
    pub fn new() -> Self {
        Self {
            brain_level: AtomicU32::new(0),
            probe_level: AtomicU32::new(0),
            prefer_masque: AtomicU32::new(0),
            last_ack_us: AtomicU32::new(0),
            last_up_us: AtomicU32::new(0),
            last_padding_rate: AtomicU32::new(0),
            last_jitter_us: AtomicU32::new(0),
        }
    }

    /// Sets the Brain pressure level, bounded to the supported range.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_brain_level(&self, level: u8) {
        self.brain_level.store(level.min(2) as u32, Ordering::Relaxed);
    }

    /// Test-only compatibility hook for injecting a Brain level.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn set_brain_level_for_test(&self, level: u8) {
        self.set_brain_level(level);
    }

    /// Records this connection's MASQUE preference.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_prefer_masque(&self, prefer: bool) {
        self.prefer_masque.store(u32::from(prefer), Ordering::Relaxed);
    }

    /// Returns whether this connection prefers MASQUE.
    #[inline(always)]
    #[doc(hidden)]
    pub fn prefer_masque(&self) -> bool {
        self.prefer_masque.load(Ordering::Relaxed) == 1
    }

    /// Sets the active-probe escalation level, bounded to the supported range.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_probe_level(&self, level: u8) {
        self.probe_level.store(level.min(2) as u32, Ordering::Relaxed);
    }

    /// Returns the active-probe escalation level.
    #[inline(always)]
    #[doc(hidden)]
    pub fn probe_level(&self) -> u8 {
        self.probe_level.load(Ordering::Relaxed).min(2) as u8
    }

    /// Returns the strongest Brain or active-probe escalation level.
    #[inline(always)]
    #[doc(hidden)]
    pub fn effective_level(&self) -> u32 {
        self.brain_level
            .load(Ordering::Relaxed)
            .max(self.probe_level.load(Ordering::Relaxed))
            .min(2)
    }

    /// Publishes the last Tamaraw direction-table inputs and derived knobs.
    #[inline(always)]
    #[doc(hidden)]
    pub fn set_tamaraw_snapshot(&self, ack_us: u32, up_us: u32, padding_rate: u8, jitter_us: u32) {
        self.last_ack_us.store(ack_us, Ordering::Relaxed);
        self.last_up_us.store(up_us, Ordering::Relaxed);
        self.last_padding_rate.store(u32::from(padding_rate), Ordering::Relaxed);
        self.last_jitter_us.store(jitter_us, Ordering::Relaxed);
    }

    /// Downstream ACK-cadence density in microseconds.
    #[inline(always)]
    #[doc(hidden)]
    pub fn last_ack_us(&self) -> u32 {
        self.last_ack_us.load(Ordering::Relaxed)
    }

    /// Upstream delivery-rate density in microseconds.
    #[inline(always)]
    #[doc(hidden)]
    pub fn last_up_us(&self) -> u32 {
        self.last_up_us.load(Ordering::Relaxed)
    }

    /// Last derived padding rate after the downstream phase row.
    #[inline(always)]
    #[doc(hidden)]
    pub fn last_padding_rate(&self) -> u8 {
        self.last_padding_rate.load(Ordering::Relaxed).min(100) as u8
    }

    /// Last derived outbound jitter ceiling after the upstream phase row.
    #[inline(always)]
    #[doc(hidden)]
    pub fn last_jitter_us(&self) -> u32 {
        self.last_jitter_us.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::{BrainRuntimePermissions, FecControlDelta, IntelligentLevelHints};

    #[test]
    fn default_fec_delta_is_inert() {
        let delta = FecControlDelta::default();
        assert_eq!(delta.stream_every, None);
        assert_eq!(delta.redundancy_ppm, None);
        assert!(!delta.force_streaming);
    }

    #[test]
    fn default_brain_permissions_allow_all_actuators() {
        let permissions = BrainRuntimePermissions::default();
        assert!(permissions.ack_threshold);
        assert!(permissions.external_pacing);
        assert!(permissions.timing);
        assert!(permissions.padding);
        assert!(permissions.mimic_bias);
        assert!(permissions.granularity);
        assert!(permissions.cc_profile);
    }

    #[test]
    fn intelligent_levels_are_bounded_and_connection_local() {
        let first = IntelligentLevelHints::new();
        first.set_brain_level(7);
        first.set_probe_level(3);
        first.set_prefer_masque(true);
        assert_eq!(first.effective_level(), 2);
        assert_eq!(first.probe_level(), 2);
        assert!(first.prefer_masque());

        let second = IntelligentLevelHints::new();
        assert_eq!(second.effective_level(), 0);
        assert!(!second.prefer_masque());
        first.set_tamaraw_snapshot(1_000, 12_000, 20, 850);
        assert_eq!(first.last_ack_us(), 1_000);
        assert_eq!(first.last_up_us(), 12_000);
        assert_eq!(first.last_padding_rate(), 20);
        assert_eq!(first.last_jitter_us(), 850);
        assert_eq!(second.last_ack_us(), 0);
        assert_eq!(second.last_up_us(), 0);
    }
}
