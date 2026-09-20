use qf_common::env_utils::EnvSnapshot;
use qf_transport_types::{BrowserProfile, StealthRuntimePolicy};

/// Snapshot of brain-derived signals consumed by the Intelligent-mode policy derivation.
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct IntelligentStealthInputs {
    /// Brain-derived escalation level hint: 0=clean-path, 1=stealth, 2=anti-dpi pressure.
    pub level_hint: u8,
    /// Recent ECN-CE ratio (0.0-1.0) indicating congestion.
    pub ce_ratio_recent: f64,
    /// Smoothed ACK inter-arrival time in microseconds. The ACK delay we
    /// emit tracks inbound packet cadence, so this is the *downstream*
    /// density signal of the direction-aware phase table.
    pub ack_us: f64,
    /// Outbound packet inter-arrival estimate in microseconds, derived by
    /// the brain from the congestion controller's delivery rate
    /// (TODO-1019 direction split: the *upstream* density signal). A
    /// value <= 0 means no upload estimate exists yet (cold start /
    /// handshake) and the table falls back to the symmetric row.
    pub up_us: f64,
    /// Jensen-Shannon divergence of packet-size histogram vs baseline.
    pub size_div: f64,
    /// Jensen-Shannon divergence of inter-arrival-time histogram vs baseline.
    pub iat_div: f64,
    /// Fraction of out-of-order packets (0.0-1.0).
    pub reorder_ratio: f64,
    /// Accumulated RTT spike weight from Kalman filter outliers.
    pub rtt_spike_weight: f64,
    /// Count of ToS/DSCP anomaly signals in the current window.
    pub signal_tos: u64,
    /// Count of unclassified anomaly signals in the current window.
    pub signal_other: u64,
    /// Maximum jitter budget in microseconds for timing obfuscation.
    pub jitter_max_us: u32,
    /// Low-mode padding ceiling in bytes.
    pub pad_max_low: usize,
    /// High-mode padding ceiling in bytes.
    pub pad_max_high: usize,
}

/// Traffic-phase classification for the adaptive-Tamaraw policy table
/// (TODO-1010): one coherent (padding, jitter) parameter pair per phase
/// instead of independent thresholds. ACK-clocked density is the
/// discriminator - the brain already EMA-smooths `ack_us`, which provides
/// the hysteresis Tamaraw needs without extra state here.
///
/// TODO-1019 direction axis: the table is evaluated once per direction.
/// `ack_us` is the downstream density (our emitted ACK delay follows the
/// inbound packet cadence); `up_us` is the upstream density (delivery
/// rate folded to an inter-arrival). Upstream rows steer outbound
/// jitter/pacing - the only timing we control - while downstream rows
/// steer padding/chaff, since we cannot delay inbound packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrafficPhase {
    /// Dense ACK-clocked flow (ack_us < 3ms): real traffic already carries
    /// the cover structure - buy minimal chaff, keep timing tight.
    Dense,
    /// Moderate activity: baseline defense parameters.
    Sparse,
    /// Idle/bursty phase (ack_us > 8ms): burst edges are the fingerprint -
    /// maximal jitter variance and full padding are what mask them.
    BurstEdge,
}

fn classify_density(density_us: f64) -> TrafficPhase {
    if density_us < 3_000.0 {
        TrafficPhase::Dense
    } else if density_us <= 8_000.0 {
        TrafficPhase::Sparse
    } else {
        TrafficPhase::BurstEdge
    }
}

fn classify_phase(inputs: &IntelligentStealthInputs) -> TrafficPhase {
    classify_density(inputs.ack_us)
}

/// Derive the concrete transport policy for one Intelligent-mode signal snapshot.
#[doc(hidden)]
pub fn derive_intelligent_runtime_policy(
    inputs: IntelligentStealthInputs,
    environment: &EnvSnapshot,
) -> StealthRuntimePolicy {
    let external_pacing =
        inputs.ce_ratio_recent < 0.01 && inputs.ack_us < 8_000.0 && inputs.rtt_spike_weight == 0.0;
    // Direction-aware rows (TODO-1019): the downstream phase comes from
    // the ACK-cadence signal as before; the upstream phase comes from the
    // delivery-rate estimate. Without an upstream estimate (up_us <= 0,
    // cold start / handshake) the table keeps the symmetric row.
    let down_phase = classify_phase(&inputs);
    let up_phase = if inputs.up_us > 0.0 { classify_density(inputs.up_us) } else { down_phase };

    // Adaptive Tamaraw (TODO-1010): congestion/anomaly overrides keep their
    // defense priority; otherwise the upstream phase row picks the jitter
    // scale - it is outbound timing we reshape. Dense upload stays tight
    // (the real stream masks itself), sparse gets the baseline, and
    // idle/bursty phases get the full range because burst edges are
    // exactly where the fingerprint lives.
    let timing_max_jitter_us = if inputs.ce_ratio_recent > 0.05 || inputs.rtt_spike_weight >= 4.0 {
        (inputs.jitter_max_us as f64 * 0.85) as u32
    } else {
        let scale = match up_phase {
            TrafficPhase::Dense => 0.4,
            TrafficPhase::Sparse if external_pacing => 0.6,
            TrafficPhase::Sparse => 0.4,
            TrafficPhase::BurstEdge => 0.85,
        };
        (inputs.jitter_max_us as f64 * scale) as u32
    };

    let tos_anomaly = inputs.signal_tos > 0;
    let (padding_enabled, padding_strategy, padding_max) = if inputs.level_hint == 0
        && inputs.ce_ratio_recent < 0.01
        && inputs.signal_other == 0
        && !tos_anomaly
    {
        (false, 0, 0)
    } else if inputs.ce_ratio_recent > 0.08
        || inputs.reorder_ratio > 0.02
        || inputs.signal_other > 0
    {
        (true, 1, inputs.pad_max_low)
    } else if inputs.size_div + inputs.iat_div > 1.4 || tos_anomaly {
        (true, 3, inputs.pad_max_high.min(512))
    } else {
        (true, 4, inputs.pad_max_low)
    };

    let mimic_bias =
        if inputs.ce_ratio_recent > 0.05 || inputs.iat_div > 1.0 || inputs.signal_other > 0 {
            1
        } else if inputs.size_div > 1.0 {
            2
        } else if inputs.ack_us < 3_000.0 {
            4
        } else {
            3
        };

    let adaptive_granularity = if inputs.ce_ratio_recent > 0.10 || inputs.signal_other > 0 {
        32
    } else if inputs.ce_ratio_recent < 0.001 {
        128
    } else {
        64
    };

    let cc_profile = match mimic_bias {
        1 => BrowserProfile::Safari,
        2 => BrowserProfile::Firefox,
        4 => BrowserProfile::Edge,
        _ => BrowserProfile::Chrome,
    };

    let padding_rate = if !padding_enabled {
        0
    } else {
        let base = match inputs.level_hint {
            0 => 0,
            1 => environment.parse::<u8>("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1").unwrap_or(50),
            _ => 100,
        };
        // ChameleonFlow principle (TODO-1010): when the downstream
        // ACK-clocked activity is dense, the return stream already carries
        // burst structure, so purchased padding buys nothing and only
        // widens the bandwidth footprint. The halving keys on the
        // *downstream* density (TODO-1019): a dense upload alone must not
        // shrink this row - upstream density steers jitter, downstream
        // density steers padding/chaff. Sparse and burst-edge phases keep
        // the full rate: with little real traffic, padding is the only
        // cover.
        if down_phase == TrafficPhase::Dense {
            base / 2
        } else {
            base
        }
    };
    let timing_rate = match inputs.level_hint {
        0 | 1 => 0,
        _ => 100,
    };

    StealthRuntimePolicy {
        external_pacing,
        timing_enabled: !external_pacing,
        timing_max_jitter_us,
        mimic_bias,
        adaptive_granularity,
        cc_profile,
        padding_enabled,
        padding_strategy,
        padding_max,
        padding_rate,
        timing_rate,
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_intelligent_runtime_policy, IntelligentStealthInputs};
    use qf_common::env_utils::EnvSnapshot;
    use qf_transport_types::BrowserProfile;

    fn inputs() -> IntelligentStealthInputs {
        IntelligentStealthInputs {
            level_hint: 0,
            ce_ratio_recent: 0.0,
            ack_us: 2_400.0,
            up_us: 0.0,
            size_div: 0.2,
            iat_div: 0.3,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            signal_tos: 0,
            signal_other: 0,
            jitter_max_us: 1_000,
            pad_max_low: 128,
            pad_max_high: 640,
        }
    }

    #[test]
    fn clean_level_uses_external_pacing_without_padding() {
        // Dense clean traffic (ack_us=2400): the real stream masks itself,
        // so the phase table keeps timing tight (0.4) rather than paying the
        // old flat external-pacing scale.
        let policy = derive_intelligent_runtime_policy(inputs(), &EnvSnapshot::default());

        assert!(policy.external_pacing);
        assert!(!policy.timing_enabled);
        assert_eq!(policy.timing_max_jitter_us, 400);
        assert!(!policy.padding_enabled);
        assert_eq!(policy.padding_rate, 0);
        assert_eq!(policy.cc_profile, BrowserProfile::Edge);
    }

    #[test]
    fn tamaraw_phase_table_scales_jitter_by_density() {
        // Sparse clean traffic keeps the 0.6 external-pacing baseline...
        let sparse = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { ack_us: 5_000.0, ..inputs() },
            &EnvSnapshot::default(),
        );
        assert!(sparse.external_pacing);
        assert_eq!(sparse.timing_max_jitter_us, 600);

        // ...while idle/bursty traffic (ack_us > 8ms) gets the full range:
        // burst edges carry the fingerprint, so masking them costs the most.
        let bursty = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { ack_us: 12_000.0, level_hint: 1, ..inputs() },
            &EnvSnapshot::default(),
        );
        assert!(!bursty.external_pacing);
        assert_eq!(bursty.timing_max_jitter_us, 850);
    }

    #[test]
    fn pressure_raises_jitter_and_uses_random_padding() {
        let policy = derive_intelligent_runtime_policy(
            IntelligentStealthInputs {
                level_hint: 2,
                ce_ratio_recent: 0.12,
                ack_us: 14_500.0,
                up_us: 0.0,
                size_div: 1.6,
                iat_div: 1.1,
                reorder_ratio: 0.03,
                rtt_spike_weight: 5.0,
                signal_tos: 1,
                signal_other: 1,
                jitter_max_us: 1_200,
                pad_max_low: 96,
                pad_max_high: 700,
            },
            &EnvSnapshot::default(),
        );

        assert!(!policy.external_pacing);
        assert_eq!(policy.timing_max_jitter_us, 1_020);
        assert_eq!(policy.padding_strategy, 1);
        assert_eq!(policy.padding_max, 96);
        assert_eq!(policy.padding_rate, 100);
        assert_eq!(policy.timing_rate, 100);
        assert_eq!(policy.cc_profile, BrowserProfile::Safari);
    }

    #[test]
    fn level_one_padding_rate_uses_captured_override() {
        let environment =
            EnvSnapshot::from_pairs([("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1", "37")]);
        let policy = derive_intelligent_runtime_policy(
            IntelligentStealthInputs {
                level_hint: 1,
                signal_tos: 1,
                // Sparse traffic keeps the full configured rate.
                ack_us: 12_000.0,
                ..inputs()
            },
            &environment,
        );

        assert_eq!(policy.padding_strategy, 3);
        assert_eq!(policy.padding_max, 512);
        assert_eq!(policy.padding_rate, 37);
        assert_eq!(policy.timing_rate, 0);
    }

    #[test]
    fn dense_traffic_halves_padding_rate() {
        // ChameleonFlow principle (TODO-1010): dense ACK-clocked traffic
        // already carries burst structure, so the purchased padding rate is
        // halved instead of widening the bandwidth footprint.
        let environment =
            EnvSnapshot::from_pairs([("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1", "40")]);
        let dense = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { level_hint: 1, signal_tos: 1, ack_us: 1_000.0, ..inputs() },
            &environment,
        );
        let sparse = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { level_hint: 1, signal_tos: 1, ack_us: 12_000.0, ..inputs() },
            &environment,
        );
        assert_eq!(dense.padding_rate, 20);
        assert_eq!(sparse.padding_rate, 40);
    }

    #[test]
    fn direction_split_uses_upstream_density_for_jitter() {
        // Downstream idle/bursty (ack_us=12ms) but a dense upload
        // (up_us=200us): the jitter scale must come from the upstream
        // row (Dense -> 0.4), not the symmetric burst-edge row (0.85).
        let policy = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { ack_us: 12_000.0, up_us: 200.0, ..inputs() },
            &EnvSnapshot::default(),
        );
        assert_eq!(policy.timing_max_jitter_us, 400);
    }

    #[test]
    fn direction_split_keeps_downstream_density_for_padding() {
        // Dense download (ack_us=1ms -> down Dense) with an idle upload
        // (up_us=12ms -> up BurstEdge): padding halves on the downstream
        // density while jitter comes from the upstream burst-edge row.
        let environment =
            EnvSnapshot::from_pairs([("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1", "40")]);
        let policy = derive_intelligent_runtime_policy(
            IntelligentStealthInputs {
                level_hint: 1,
                signal_tos: 1,
                ack_us: 1_000.0,
                up_us: 12_000.0,
                ..inputs()
            },
            &environment,
        );
        assert_eq!(policy.padding_rate, 20);
        assert_eq!(policy.timing_max_jitter_us, 850);
    }

    #[test]
    fn dense_upload_alone_does_not_halve_padding() {
        // Inverted split: idle download (down BurstEdge) but dense upload.
        // Upstream density steers jitter - it must NOT halve the
        // downstream-keyed padding row.
        let environment =
            EnvSnapshot::from_pairs([("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1", "40")]);
        let policy = derive_intelligent_runtime_policy(
            IntelligentStealthInputs {
                level_hint: 1,
                signal_tos: 1,
                ack_us: 12_000.0,
                up_us: 500.0,
                ..inputs()
            },
            &environment,
        );
        assert_eq!(policy.padding_rate, 40);
        assert_eq!(policy.timing_max_jitter_us, 400);
    }

    #[test]
    fn missing_upstream_signal_falls_back_to_symmetric_row() {
        // up_us = 0 (cold start): identical inputs must produce the
        // symmetric-table result, i.e. the downstream phase drives both.
        let environment =
            EnvSnapshot::from_pairs([("QUICFUSCATE_STEALTH_PADDING_RATE_LEVEL1", "40")]);
        let cold = derive_intelligent_runtime_policy(
            IntelligentStealthInputs { level_hint: 1, signal_tos: 1, ack_us: 1_000.0, ..inputs() },
            &environment,
        );
        assert_eq!(cold.timing_max_jitter_us, 400);
        assert_eq!(cold.padding_rate, 20);
    }
}
