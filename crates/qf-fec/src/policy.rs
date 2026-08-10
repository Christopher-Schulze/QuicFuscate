//! Environment-derived FEC runtime policy.
//!
//! This policy contains only bounded configuration snapshots. Decoder and
//! packet ownership remain in the product root.

use crate::target::{DEFAULT_FOUNTAIN_WINDOW, MAX_FOUNTAIN_WINDOW};
use qf_common::env_utils::EnvSnapshot;

#[derive(Clone)]
#[doc(hidden)]
pub struct FecRuntimePolicy {
    pub decoder_policy: String,
    pub lazy_enabled: bool,
    pub interleave_enabled: bool,
    pub switch_threshold_override: Option<f32>,
    pub switch_min_up_ms: u64,
    pub switch_min_down_ms: u64,
    pub auto_gf4_enabled: bool,
    pub fountain_window: usize,
    pub extreme_window: usize,
    pub fountain_symbol_size: usize,
    pub stream_every_override: Option<usize>,
    pub interleave_depth_override: Option<usize>,
    pub partial_enabled: bool,
    pub kalman_q_override: Option<f32>,
    pub kalman_r_override: Option<f32>,
}

impl FecRuntimePolicy {
    pub fn detect() -> Self {
        let environment = EnvSnapshot::capture();
        Self::detect_with_snapshot(&environment)
    }

    pub fn detect_with_snapshot(environment: &EnvSnapshot) -> Self {
        let decoder_policy = match environment
            .first(["QUICFUSCATE_FEC_DECODER"])
            .map(|value| value.to_ascii_lowercase())
        {
            None => "auto".to_string(),
            Some(value) if matches!(value.as_str(), "auto" | "gauss" | "wiedemann") => value,
            Some(value) => {
                log::warn!(
                    "Invalid QUICFUSCATE_FEC_DECODER value '{value}'; retaining default auto"
                );
                "auto".to_string()
            }
        };
        Self {
            decoder_policy,
            lazy_enabled: environment.flag("QUICFUSCATE_FEC_LAZY", true),
            interleave_enabled: environment.flag("QUICFUSCATE_FEC_INTERLEAVE", true),
            switch_threshold_override: environment
                .parse_finite_f32("QUICFUSCATE_FEC_SWITCH_THRESH")
                .map(|value| {
                    let clamped = value.clamp(0.0, 1.0);
                    if clamped != value {
                        log::warn!(
                            "QUICFUSCATE_FEC_SWITCH_THRESH must be between 0.0 and 1.0; clamping override"
                        );
                    }
                    clamped
                }),
            switch_min_up_ms: environment
                .parse::<u64>("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS")
                .unwrap_or(120)
                .clamp(0, 3_600_000),
            switch_min_down_ms: environment
                .parse::<u64>("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS")
                .unwrap_or(450)
                .clamp(0, 3_600_000),
            auto_gf4_enabled: environment.flag("QUICFUSCATE_FEC_AUTO_GF4", true),
            fountain_window: environment
                .parse::<usize>("QUICFUSCATE_FEC_FOUNTAIN_WINDOW")
                .unwrap_or(DEFAULT_FOUNTAIN_WINDOW)
                .clamp(1, MAX_FOUNTAIN_WINDOW),
            extreme_window: environment
                .parse::<usize>("QUICFUSCATE_FEC_EXTREME_WINDOW")
                .unwrap_or(1024)
                .clamp(1, crate::wire::MAX_SOURCE_COUNT as usize),
            fountain_symbol_size: resolve_fountain_symbol_size(environment),
            stream_every_override: environment
                .parse::<usize>("QUICFUSCATE_FEC_STREAM_EVERY")
                .map(|value| value.clamp(1, 32)),
            interleave_depth_override: environment
                .parse::<usize>("QUICFUSCATE_FEC_INTERLEAVE_DEPTH")
                .map(|value| value.clamp(1, 8)),
            partial_enabled: environment.flag("QUICFUSCATE_FEC_PARTIAL", true),
            kalman_q_override: environment.parse_positive_f32("QUICFUSCATE_KALMAN_Q"),
            kalman_r_override: environment.parse_positive_f32("QUICFUSCATE_KALMAN_R"),
        }
    }
}

fn resolve_fountain_symbol_size(environment: &EnvSnapshot) -> usize {
    environment
        .parse::<usize>("QUICFUSCATE_FOUNTAIN_SYMBOL")
        .or_else(|| {
            environment.parse::<usize>("QUICFUSCATE_MTU_HINT").map(|mtu| mtu.saturating_sub(80))
        })
        .unwrap_or(1500)
        .clamp(600, 16384)
}

#[cfg(test)]
mod tests {
    use super::FecRuntimePolicy;
    use qf_common::env_utils::EnvSnapshot;

    #[test]
    fn defaults_are_bounded_and_deterministic() {
        let policy = FecRuntimePolicy::detect_with_snapshot(&EnvSnapshot::from_pairs([]));
        assert_eq!(policy.decoder_policy, "auto");
        assert_eq!(policy.fountain_window, 128);
        assert_eq!(policy.extreme_window, 1024);
        assert_eq!(policy.fountain_symbol_size, 1500);
        assert!(policy.lazy_enabled);
        assert!(policy.partial_enabled);
    }

    #[test]
    fn overrides_are_clamped_or_rejected_at_the_boundary() {
        let policy = FecRuntimePolicy::detect_with_snapshot(&EnvSnapshot::from_pairs([
            ("QUICFUSCATE_FEC_DECODER", "WIEDEMANN"),
            ("QUICFUSCATE_FEC_SWITCH_THRESH", "2.5"),
            ("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "999999999"),
            ("QUICFUSCATE_FEC_INTERLEAVE_DEPTH", "99"),
            ("QUICFUSCATE_FOUNTAIN_SYMBOL", "1"),
        ]));
        assert_eq!(policy.decoder_policy, "wiedemann");
        assert_eq!(policy.switch_threshold_override, Some(1.0));
        assert_eq!(policy.switch_min_up_ms, 3_600_000);
        assert_eq!(policy.interleave_depth_override, Some(8));
        assert_eq!(policy.fountain_symbol_size, 600);
    }
}
