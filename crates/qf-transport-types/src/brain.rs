//! Root-independent configuration contract for the adaptive stealth Brain.

use qf_common::env_utils::EnvSnapshot;

/// Configuration for the sensor-fusion stealth brain that drives adaptive transport tuning.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct StealthBrainConfig {
    /// Minimum ACK-eliciting threshold the brain may choose.
    pub ack_min: u64,
    /// Maximum ACK-eliciting threshold the brain may choose.
    pub ack_max: u64,
    /// Upper bound for jitter hints in microseconds (transport decides actual delay).
    pub jitter_max_us: u32,
    /// Number of bins for the packet-size histogram.
    pub size_bins: usize,
    /// Number of bins for the inter-arrival-time histogram.
    pub iat_bins: usize,
    /// Maximum DPI probes the brain may emit per minute.
    pub probe_max_per_min: u32,
    /// Minimum milliseconds between successive probe emissions.
    pub probe_cooldown_ms: u64,
    /// Minimum milliseconds between successive policy actuator changes.
    pub policy_cooldown_ms: u64,
    /// Exponential decay factor applied to histograms each policy tick (0.8 - 1.0).
    pub hist_decay: f32,
}

impl Default for StealthBrainConfig {
    fn default() -> Self {
        Self {
            ack_min: 1,
            ack_max: 12,
            jitter_max_us: 5000,
            size_bins: 16,
            iat_bins: 16,
            probe_max_per_min: 2,
            probe_cooldown_ms: 10_000,
            policy_cooldown_ms: 300,
            hist_decay: 0.98,
        }
    }
}

impl StealthBrainConfig {
    /// Constructs a config by reading environment variable overrides on top of defaults.
    #[doc(hidden)]
    pub fn from_env() -> Self {
        let environment = EnvSnapshot::capture();
        Self::from_env_with_snapshot(&environment)
    }

    /// Constructs a config from one captured environment snapshot, falling back to defaults on
    /// invalid cross-field values.
    #[doc(hidden)]
    pub fn from_env_with_snapshot(environment: &EnvSnapshot) -> Self {
        match Self::try_from_env_with_snapshot(environment) {
            Ok(config) => config,
            Err(error) => {
                log::warn!(
                    "Invalid StealthBrain environment configuration: {error}; using defaults"
                );
                Self::default()
            }
        }
    }

    /// Constructs and validates a config from environment variable overrides.
    #[doc(hidden)]
    pub fn try_from_env() -> Result<Self, String> {
        let environment = EnvSnapshot::capture();
        Self::try_from_env_with_snapshot(&environment)
    }

    /// Constructs and validates a config from one captured environment snapshot.
    #[doc(hidden)]
    pub fn try_from_env_with_snapshot(environment: &EnvSnapshot) -> Result<Self, String> {
        let mut config = Self::default();
        if let Some(value) = environment.parse("QUICFUSCATE_BRAIN_ACK_MAX") {
            config.ack_max = value;
        }
        if let Some(value) = environment.parse("QUICFUSCATE_BRAIN_JITTER_MAX_US") {
            config.jitter_max_us = value;
        }
        if let Some(value) = environment.parse::<usize>("QUICFUSCATE_BRAIN_SIZE_BINS") {
            config.size_bins = value.clamp(8, 64);
        }
        if let Some(value) = environment.parse::<usize>("QUICFUSCATE_BRAIN_IAT_BINS") {
            config.iat_bins = value.clamp(8, 64);
        }
        if let Some(value) = environment.parse::<u32>("QUICFUSCATE_BRAIN_PROBE_MAX_PER_MIN") {
            config.probe_max_per_min = value.min(30);
        }
        if let Some(value) = environment.parse("QUICFUSCATE_BRAIN_PROBE_COOLDOWN_MS") {
            config.probe_cooldown_ms = value;
        }
        if let Some(value) = environment.parse("QUICFUSCATE_BRAIN_POLICY_COOLDOWN_MS") {
            config.policy_cooldown_ms = value;
        }
        if let Some(value) = environment.parse_finite_f32("QUICFUSCATE_BRAIN_HIST_DECAY") {
            let clamped = value.clamp(0.80, 0.999);
            if clamped != value {
                log::warn!(
                    "QUICFUSCATE_BRAIN_HIST_DECAY must be between 0.80 and 0.999; clamping override"
                );
            }
            config.hist_decay = clamped;
        }
        config.validate()?;
        Ok(config)
    }

    /// Validates constraints that span multiple Brain configuration fields.
    #[doc(hidden)]
    pub fn validate(&self) -> Result<(), String> {
        if self.ack_min == 0 {
            return Err("ack_min must be greater than zero".to_string());
        }
        if self.ack_min > self.ack_max {
            return Err(format!(
                "ack_min ({}) must not exceed ack_max ({})",
                self.ack_min, self.ack_max
            ));
        }
        if self.ack_max > i64::MAX as u64 {
            return Err("ack_max exceeds the supported signed threshold range".to_string());
        }
        if !(1..=64).contains(&self.size_bins) || !(1..=64).contains(&self.iat_bins) {
            return Err("histogram bin counts must be between 1 and 64".to_string());
        }
        if self.probe_max_per_min > 30 {
            return Err("probe_max_per_min must not exceed 30".to_string());
        }
        if !self.hist_decay.is_finite() || !(0.80..=0.999).contains(&self.hist_decay) {
            return Err("hist_decay must be finite and between 0.80 and 0.999".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::StealthBrainConfig;
    use qf_common::env_utils::EnvSnapshot;

    #[test]
    fn defaults_are_valid_and_keep_brain_bounds() {
        let config = StealthBrainConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.ack_min, 1);
        assert_eq!(config.ack_max, 12);
        assert_eq!(config.size_bins, 16);
    }

    #[test]
    fn validation_rejects_interdependent_ranges() {
        let invalid_ack = StealthBrainConfig { ack_min: 4, ack_max: 2, ..Default::default() };
        assert!(invalid_ack.validate().is_err());

        let zero_ack = StealthBrainConfig { ack_min: 0, ..Default::default() };
        assert!(zero_ack.validate().is_err());
    }

    #[test]
    fn environment_overrides_are_bounded_and_invalid_values_keep_defaults() {
        let environment = EnvSnapshot::from_pairs([
            ("QUICFUSCATE_BRAIN_ACK_MAX", "not-a-number"),
            ("QUICFUSCATE_BRAIN_SIZE_BINS", "1024"),
            ("QUICFUSCATE_BRAIN_HIST_DECAY", "NaN"),
        ]);
        let config = StealthBrainConfig::from_env_with_snapshot(&environment);
        assert_eq!(config.ack_max, StealthBrainConfig::default().ack_max);
        assert_eq!(config.size_bins, 64);
        assert_eq!(config.hist_decay, StealthBrainConfig::default().hist_decay);
    }
}
