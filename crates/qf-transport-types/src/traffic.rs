//! Root-independent traffic-analysis defense policy contracts.

/// Traffic analysis defense mode.
///
/// The modes are ordered by increasing protection and bandwidth overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub enum TrafficAnalysisDefense {
    /// Preserve the existing probabilistic padding behavior.
    #[serde(alias = "off", alias = "Off", alias = "disabled")]
    #[default]
    Off,
    /// Pad every outgoing 1-RTT packet to the configured maximum payload size.
    #[serde(alias = "full", alias = "Full", alias = "full-padding", alias = "FullPadding")]
    FullPadding,
    /// Pad consistently and inject chaff to maintain a fixed target rate.
    #[serde(
        alias = "constant",
        alias = "Constant",
        alias = "constant-rate",
        alias = "ConstantRate"
    )]
    ConstantRate,
}

impl TrafficAnalysisDefense {
    /// Parse a mode from a case-insensitive string identifier.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" | "" => Some(Self::Off),
            "full" | "full-padding" | "fullpadding" => Some(Self::FullPadding),
            "constant" | "constant-rate" | "constantrate" => Some(Self::ConstantRate),
            _ => None,
        }
    }

    const fn protection_level(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::FullPadding => 1,
            Self::ConstantRate => 2,
        }
    }
}

/// Complete traffic-analysis policy for one transport connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficAnalysisPolicy {
    pub defense: TrafficAnalysisDefense,
    pub chaff_rate_pps: u32,
    pub chaff_size_bytes: u32,
    pub constant_rate_pps: u32,
    pub idle_timeout_ms: u64,
    pub ramp_down_ms: u64,
}

impl Default for TrafficAnalysisPolicy {
    fn default() -> Self {
        Self {
            defense: TrafficAnalysisDefense::Off,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1280,
            constant_rate_pps: 100,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        }
    }
}

impl TrafficAnalysisPolicy {
    pub const MAX_CHAFF_RATE_PPS: u32 = 10_000;
    pub const MAX_CONSTANT_RATE_PPS: u32 = 1_000;
    pub const MIN_CHAFF_SIZE_BYTES: u32 = 64;
    pub const MAX_CHAFF_SIZE_BYTES: u32 = 65_535;
    pub const MAX_IDLE_TIMEOUT_MS: u64 = 3_600_000;
    pub const MAX_RAMP_DOWN_MS: u64 = 60_000;

    /// Hard upper bound used for authenticated per-QKey policy requests.
    pub const fn safety_ceiling() -> Self {
        Self {
            defense: TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: Self::MAX_CHAFF_RATE_PPS,
            chaff_size_bytes: Self::MAX_CHAFF_SIZE_BYTES,
            constant_rate_pps: Self::MAX_CONSTANT_RATE_PPS,
            idle_timeout_ms: Self::MAX_IDLE_TIMEOUT_MS,
            ramp_down_ms: Self::MAX_RAMP_DOWN_MS,
        }
    }

    /// Reject malformed or intrinsically unsafe policy values.
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.chaff_rate_pps > Self::MAX_CHAFF_RATE_PPS {
            return Err("chaff_rate_pps exceeds 10000");
        }
        if self.constant_rate_pps > Self::MAX_CONSTANT_RATE_PPS {
            return Err("constant_rate_pps exceeds 1000");
        }
        if !(Self::MIN_CHAFF_SIZE_BYTES..=Self::MAX_CHAFF_SIZE_BYTES)
            .contains(&self.chaff_size_bytes)
        {
            return Err("chaff_size_bytes must be between 64 and 65535");
        }
        if self.idle_timeout_ms > Self::MAX_IDLE_TIMEOUT_MS {
            return Err("idle_timeout_ms exceeds 3600000");
        }
        if self.ramp_down_ms > Self::MAX_RAMP_DOWN_MS {
            return Err("ramp_down_ms exceeds 60000");
        }
        if self.defense == TrafficAnalysisDefense::ConstantRate && self.constant_rate_pps == 0 {
            return Err("constant-rate defense requires constant_rate_pps > 0");
        }
        Ok(self)
    }

    /// Intersect a requested policy with an independently configured ceiling.
    pub fn bounded_by(self, ceiling: Self) -> Self {
        let defense = if self.defense.protection_level() <= ceiling.defense.protection_level() {
            self.defense
        } else {
            ceiling.defense
        };
        let rate_pps = self.rate_ceiling_for(defense).min(ceiling.rate_ceiling_for(defense));
        let mut bounded = Self {
            defense,
            chaff_rate_pps: rate_pps,
            chaff_size_bytes: self.chaff_size_bytes.min(ceiling.chaff_size_bytes),
            constant_rate_pps: rate_pps,
            idle_timeout_ms: self.idle_timeout_ms.min(ceiling.idle_timeout_ms),
            ramp_down_ms: self.ramp_down_ms.min(ceiling.ramp_down_ms),
        };
        match bounded.defense {
            TrafficAnalysisDefense::Off => {
                bounded.chaff_rate_pps = 0;
                bounded.constant_rate_pps = 0;
            }
            TrafficAnalysisDefense::FullPadding => bounded.constant_rate_pps = 0,
            TrafficAnalysisDefense::ConstantRate => bounded.chaff_rate_pps = 0,
        }
        bounded
    }

    const fn rate_ceiling_for(self, defense: TrafficAnalysisDefense) -> u32 {
        match (self.defense, defense) {
            (_, TrafficAnalysisDefense::Off) | (TrafficAnalysisDefense::Off, _) => 0,
            (TrafficAnalysisDefense::FullPadding, TrafficAnalysisDefense::FullPadding) => {
                self.chaff_rate_pps
            }
            (TrafficAnalysisDefense::ConstantRate, TrafficAnalysisDefense::FullPadding)
            | (TrafficAnalysisDefense::ConstantRate, TrafficAnalysisDefense::ConstantRate) => {
                self.constant_rate_pps
            }
            (TrafficAnalysisDefense::FullPadding, TrafficAnalysisDefense::ConstantRate) => 0,
        }
    }

    /// Return the maximum configured wire cost before IP/UDP overhead.
    pub fn estimated_max_bits_per_second(self, max_udp_payload_size: u32) -> u64 {
        let (rate, target_size) = match self.defense {
            TrafficAnalysisDefense::Off => (0, 0),
            TrafficAnalysisDefense::FullPadding => (self.chaff_rate_pps, max_udp_payload_size),
            TrafficAnalysisDefense::ConstantRate => {
                (self.constant_rate_pps, self.chaff_size_bytes.min(max_udp_payload_size))
            }
        };
        u64::from(rate).saturating_mul(u64::from(target_size)).saturating_mul(8)
    }
}

#[cfg(test)]
mod tests {
    use super::{TrafficAnalysisDefense, TrafficAnalysisPolicy};

    #[test]
    fn policy_defaults_and_parsing_are_stable() {
        assert_eq!(TrafficAnalysisPolicy::default().chaff_size_bytes, 1280);
        assert_eq!(
            TrafficAnalysisDefense::parse("Full"),
            Some(TrafficAnalysisDefense::FullPadding)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("constant-rate"),
            Some(TrafficAnalysisDefense::ConstantRate)
        );
        assert_eq!(TrafficAnalysisDefense::parse("invalid"), None);
    }

    #[test]
    fn policy_validation_rejects_unsafe_values() {
        let invalid = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            constant_rate_pps: TrafficAnalysisPolicy::MAX_CONSTANT_RATE_PPS + 1,
            ..TrafficAnalysisPolicy::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn policy_ceiling_and_cost_are_mode_specific() {
        let requested = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1400,
            constant_rate_pps: 100,
            ..TrafficAnalysisPolicy::default()
        };
        let ceiling = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 8,
            chaff_size_bytes: 1280,
            constant_rate_pps: 80,
            ..TrafficAnalysisPolicy::default()
        };
        let bounded = requested.bounded_by(ceiling);
        assert_eq!(bounded.defense, TrafficAnalysisDefense::FullPadding);
        assert_eq!(bounded.chaff_rate_pps, 8);
        assert_eq!(bounded.constant_rate_pps, 0);

        let constant = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            constant_rate_pps: 100,
            chaff_size_bytes: 1280,
            ..TrafficAnalysisPolicy::default()
        };
        assert_eq!(constant.estimated_max_bits_per_second(1200), 960_000);
    }

    #[test]
    fn defense_serde_accepts_wire_aliases() {
        let full: TrafficAnalysisDefense = serde_json::from_str("\"full-padding\"").unwrap();
        assert_eq!(full, TrafficAnalysisDefense::FullPadding);
        assert_eq!(serde_json::to_string(&full).unwrap(), "\"FullPadding\"");
    }
}
