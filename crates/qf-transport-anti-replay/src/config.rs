use serde::{Deserialize, Serialize};

/// 0-RTT anti-replay protection settings.
///
/// When enabled, a strike register rejects replayed 0-RTT packets per
/// RFC 8446 Section 8 and RFC 9001 Section 9.2.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AntiReplaySection {
    /// Enable 0-RTT anti-replay protection (server mode only).
    pub enabled: bool,
    /// Maximum ticket age in seconds before 0-RTT is rejected (default: 10).
    pub max_ticket_age_secs: u64,
    /// Maximum entries in the strike register (default: 100000).
    pub max_entries: usize,
    /// Maximum early data size in bytes per connection (default: 16384).
    pub max_early_data_size: u32,
}

impl Default for AntiReplaySection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_ticket_age_secs: 10,
            max_entries: 100_000,
            max_early_data_size: 16_384,
        }
    }
}

impl AntiReplaySection {
    /// Validate the operator-facing anti-replay section before runtime setup.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_ticket_age_secs == 0 {
            return Err("anti_replay.max_ticket_age_secs must be > 0 when anti-replay is enabled"
                .to_string());
        }
        if self.max_entries == 0 {
            return Err(
                "anti_replay.max_entries must be > 0 when anti-replay is enabled".to_string()
            );
        }
        if self.max_early_data_size == 0 {
            return Err("anti_replay.max_early_data_size must be > 0 when anti-replay is enabled"
                .to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::AntiReplaySection;

    #[test]
    fn defaults_are_valid_and_enabled() {
        let section = AntiReplaySection::default();

        assert!(section.enabled);
        assert_eq!(section.max_ticket_age_secs, 10);
        assert_eq!(section.max_entries, 100_000);
        assert_eq!(section.max_early_data_size, 16_384);
        assert!(section.validate().is_ok());
    }

    #[test]
    fn disabled_section_skips_runtime_limits() {
        let section = AntiReplaySection {
            enabled: false,
            max_ticket_age_secs: 0,
            max_entries: 0,
            max_early_data_size: 0,
        };

        assert!(section.validate().is_ok());
    }

    #[test]
    fn enabled_section_rejects_zero_limits() {
        let cases = [
            AntiReplaySection { max_ticket_age_secs: 0, ..AntiReplaySection::default() },
            AntiReplaySection { max_entries: 0, ..AntiReplaySection::default() },
            AntiReplaySection { max_early_data_size: 0, ..AntiReplaySection::default() },
        ];

        for section in cases {
            assert!(section.validate().is_err());
        }
    }
}
