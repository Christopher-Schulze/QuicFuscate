//! Root-independent transport stealth value contracts.

/// Browser congestion fingerprint used by the transport congestion shaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProfile {
    /// Chromium/Chrome congestion signature.
    Chrome,
    /// Firefox congestion signature.
    Firefox,
    /// Safari/WebKit congestion signature.
    Safari,
    /// Microsoft Edge congestion signature (same gain table as Chrome).
    Edge,
}

/// Snapshot of all stealth runtime parameters for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StealthRuntimePolicy {
    /// Whether external pacing control is active.
    pub external_pacing: bool,
    /// Whether stealth timing jitter injection is enabled.
    pub timing_enabled: bool,
    /// Maximum timing jitter in microseconds.
    pub timing_max_jitter_us: u32,
    /// Browser mimic bias code (1=Safari, 2=Firefox, 3=Chromium, 4=Android).
    pub mimic_bias: u8,
    /// Adaptive padding granularity in bytes.
    pub adaptive_granularity: u16,
    /// Congestion control browser profile for traffic shaping.
    pub cc_profile: BrowserProfile,
    /// Whether stealth padding is enabled.
    pub padding_enabled: bool,
    /// Padding strategy (0=off, 1=random, 2=fixed, 3=adaptive, 4=browser-mimic).
    pub padding_strategy: u8,
    /// Maximum padding size in bytes.
    pub padding_max: usize,
    /// Padding application rate (0-100%): fraction of packets that receive padding.
    /// 100 = every packet, 50 = half of the packets, 0 = no padding.
    pub padding_rate: u8,
    /// Timing obfuscation rate (0-100%): scales the jitter magnitude.
    /// 100 = full jitter, 50 = half jitter, 0 = no jitter.
    pub timing_rate: u8,
}

/// Incremental stealth parameter update emitted by the Brain sensor-fusion engine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StealthRuntimeDelta {
    /// New external pacing toggle, if changed.
    pub external_pacing: Option<bool>,
    /// New timing (enabled, max_jitter_us) pair, if changed.
    pub timing: Option<(bool, u32)>,
    /// New browser mimic bias code, if changed.
    pub mimic_bias: Option<u8>,
    /// New adaptive padding granularity in bytes, if changed.
    pub adaptive_granularity: Option<u16>,
    /// New congestion control browser profile, if changed.
    pub cc_profile: Option<BrowserProfile>,
    /// New padding (enabled, strategy, max_size) triple, if changed.
    pub padding: Option<(bool, u8, usize)>,
    /// New padding application rate (0-100), if changed.
    pub padding_rate: Option<u8>,
    /// New timing obfuscation rate (0-100), if changed.
    pub timing_rate: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::{BrowserProfile, StealthRuntimeDelta};

    #[test]
    fn browser_profiles_are_distinct_transport_contracts() {
        assert_ne!(BrowserProfile::Chrome, BrowserProfile::Firefox);
        assert_ne!(BrowserProfile::Safari, BrowserProfile::Edge);
    }

    #[test]
    fn stealth_delta_defaults_to_no_changes() {
        let delta = StealthRuntimeDelta::default();
        assert_eq!(delta.external_pacing, None);
        assert_eq!(delta.timing, None);
        assert_eq!(delta.cc_profile, None);
        assert_eq!(delta.padding, None);
    }
}
