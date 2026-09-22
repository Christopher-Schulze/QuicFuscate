//! Intelligent-mode actuator derivation (TODO-1060).
//!
//! The Brain's sensors still feed two — and only two — actuators:
//!
//! - a repair-ratio hint (`repair_ratio_ppm` + `repair_interval_pkts`) that
//!   stays inside the shared wire byte cap from TODO-1052, and
//! - a Reality/MASQUE armed bit (`reality_armed`).
//!
//! No packet shape is derived here. The epsilon-greedy padding strategy,
//! the bandit-chosen jitter amplitude, the Tamaraw phase table, the mimic
//! bias, the granularity and the CC-profile selector were removed: a
//! converging bandit is a stable pattern, and a stable pattern is a
//! fingerprint. The wire image is frozen at connect (TODO-1059); anything
//! beyond these hints belongs to the Maybenot machine (TODO-1061).

/// Snapshot of brain-derived signals consumed by the actuator derivation.
///
/// Every field is a *sensor*: loss, CE, RTT/jitter, reordering, divergence
/// and probe/anomaly counters. None of them describes a packet shape.
#[derive(Debug, Clone, Copy)]
#[doc(hidden)]
pub struct IntelligentStealthInputs {
    /// Kalman-filtered ECN-CE ratio blended with the raw recent ratio
    /// (`ce_effective` in the Brain, clamped to 0.5).
    pub ce_effective: f64,
    /// Recent ECN-CE ratio (0.0-1.0).
    pub ce_ratio_recent: f64,
    /// Smoothed ACK inter-arrival time in microseconds — the downstream
    /// density signal of the connection.
    pub ack_us: f64,
    /// RTT jitter relative to the long ACK cadence (0.0-0.5).
    pub jitter_ratio: f64,
    /// Fraction of out-of-order packets (0.0-1.0).
    pub reorder_ratio: f64,
    /// Accumulated RTT spike weight from Kalman filter outliers.
    pub rtt_spike_weight: f64,
    /// Jensen-Shannon divergence of packet-size histogram vs baseline.
    pub size_div: f64,
    /// Jensen-Shannon divergence of inter-arrival-time histogram vs baseline.
    pub iat_div: f64,
    /// Count of RST anomaly signals in the current window.
    pub signal_rst: u64,
    /// Count of ToS/DSCP anomaly signals in the current window.
    pub signal_tos: u64,
    /// Count of unclassified anomaly signals in the current window.
    pub signal_other: u64,
    /// Probe-escalation level published by the manager (0-2). This is the
    /// channel through which confirmed DPI probes may raise the repair
    /// hint — it never reaches a packet-shape actuator.
    pub probe_level: u8,
}

/// Stateful smoother for the repair-ratio hint.
///
/// Repair ratio must not jump per tick — a jumping redundancy is itself a
/// signal. Momentum blends 30% of the desired value per tick, and the
/// repair interval walks one packet at a time toward its target.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct IntelligentRepairState {
    /// EMA of the desired redundancy in parts-per-million.
    pub red_ppm_momentum: f32,
    /// Last emitted repair ratio, parts-per-million.
    pub last_red_ppm: u64,
    /// Last emitted repair interval in packets.
    pub last_fec_interval: u64,
}

impl Default for IntelligentRepairState {
    fn default() -> Self {
        // `last_fec_interval: 0` lets the first tick adopt `desired_interval`
        // directly — the step limit only applies to subsequent changes.
        Self { red_ppm_momentum: 0.0, last_red_ppm: 100_000, last_fec_interval: 0 }
    }
}

/// The complete Intelligent-mode actuator output.
///
/// This is the whole contract: a repair-ratio hint and a Reality/MASQUE
/// armed bit. There is deliberately no field that could carry a padding
/// strategy, a jitter amplitude, a length set, or a framing choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct IntelligentActuatorHints {
    /// Repair ratio in parts-per-million, inside the TODO-1052 byte cap.
    /// Bounded to 80_000..=320_000 (8%-32% redundancy).
    pub repair_ratio_ppm: u32,
    /// Repair grouping interval in packets, bounded to 2..=20.
    pub repair_interval_pkts: u64,
    /// Whether the Reality/MASQUE relay should be armed for this connection.
    pub reality_armed: bool,
}

/// Derive the allowed actuators for one Intelligent-mode signal snapshot.
///
/// `state` carries the repair-ratio smoother across ticks and is mutated in
/// place; the Brain owns its own rate-limit on top (it only forwards a hint
/// when the ppm moved enough or a publication is due).
#[doc(hidden)]
pub fn derive_intelligent_actuators(
    inputs: IntelligentStealthInputs,
    state: &mut IntelligentRepairState,
) -> IntelligentActuatorHints {
    // --- Repair ratio (loss-driven redundancy inside the byte cap) ---
    let signal_penalty = inputs.rtt_spike_weight.min(8.0) * 0.02
        + (inputs.signal_rst as f64 * 0.03)
        + (inputs.signal_tos as f64 * 0.02)
        + (inputs.signal_other as f64 * 0.04);
    let desired_multiplier = (1.0
        + inputs.ce_effective * 6.5
        + inputs.reorder_ratio.min(0.06) * 6.0
        + inputs.jitter_ratio.min(0.5) * 2.5
        + f64::from(inputs.probe_level) * 0.08
        + signal_penalty)
        .clamp(0.8, 3.5);
    let desired_ppm = (100_000.0 * desired_multiplier) as f32;
    if state.red_ppm_momentum == 0.0 {
        state.red_ppm_momentum = state.last_red_ppm as f32;
    }
    state.red_ppm_momentum = state.red_ppm_momentum * 0.7 + desired_ppm * 0.3;
    let repair_ratio_ppm = state.red_ppm_momentum.round().clamp(80_000.0, 320_000.0) as u32;

    let mut desired_interval: u64 = if inputs.ce_effective > 0.08 {
        4
    } else if inputs.ce_effective > 0.04 || inputs.reorder_ratio > 0.02 {
        6
    } else if inputs.ce_effective > 0.015 || inputs.reorder_ratio > 0.01 {
        8
    } else {
        12
    };
    if inputs.signal_other > 0 || inputs.signal_rst > 0 {
        desired_interval = desired_interval.saturating_sub(2);
    }
    if inputs.probe_level >= 2 {
        desired_interval = desired_interval.saturating_sub(1);
    }
    desired_interval = desired_interval.clamp(3, 18);
    if state.last_fec_interval == 0 {
        state.last_fec_interval = desired_interval;
    }
    let mut interval = state.last_fec_interval as i64;
    match desired_interval as i64 {
        target if target > interval => interval += 1,
        target if target < interval => interval -= 1,
        _ => {}
    }
    let repair_interval_pkts = interval.clamp(2, 20) as u64;

    // --- Reality/MASQUE armed bit ---
    let reality_armed = inputs.ce_ratio_recent > 0.03
        || inputs.rtt_spike_weight >= 2.0
        || inputs.probe_level > 0
        || inputs.signal_rst > 0
        || inputs.signal_tos > 0
        || (inputs.size_div + inputs.iat_div) > 1.6
        || inputs.reorder_ratio > 0.02;

    IntelligentActuatorHints { repair_ratio_ppm, repair_interval_pkts, reality_armed }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_intelligent_actuators, IntelligentActuatorHints, IntelligentRepairState,
        IntelligentStealthInputs,
    };

    fn inputs() -> IntelligentStealthInputs {
        IntelligentStealthInputs {
            ce_effective: 0.0,
            ce_ratio_recent: 0.0,
            ack_us: 2_400.0,
            jitter_ratio: 0.0,
            reorder_ratio: 0.0,
            rtt_spike_weight: 0.0,
            size_div: 0.2,
            iat_div: 0.3,
            signal_rst: 0,
            signal_tos: 0,
            signal_other: 0,
            probe_level: 0,
        }
    }

    #[test]
    fn clean_path_emits_baseline_repair_and_disarms() {
        let mut state = IntelligentRepairState::default();
        let hints = derive_intelligent_actuators(inputs(), &mut state);

        assert_eq!(hints.repair_ratio_ppm, 100_000);
        assert_eq!(hints.repair_interval_pkts, 12);
        assert!(!hints.reality_armed);
    }

    #[test]
    fn loss_moves_the_repair_ratio_inside_its_bounds() {
        let mut state = IntelligentRepairState::default();
        let clean = derive_intelligent_actuators(inputs(), &mut state);
        let pressured = derive_intelligent_actuators(
            IntelligentStealthInputs {
                ce_effective: 0.12,
                ce_ratio_recent: 0.12,
                reorder_ratio: 0.04,
                jitter_ratio: 0.3,
                ..inputs()
            },
            &mut state,
        );

        assert!(pressured.repair_ratio_ppm > clean.repair_ratio_ppm);
        assert!(pressured.repair_ratio_ppm <= 320_000);
        assert!(pressured.repair_interval_pkts <= clean.repair_interval_pkts);
        assert!(pressured.reality_armed);
    }

    #[test]
    fn repair_ratio_is_smoothed_not_jumpy() {
        let mut state = IntelligentRepairState::default();
        let first = derive_intelligent_actuators(
            IntelligentStealthInputs { ce_effective: 0.5, ..inputs() },
            &mut state,
        );
        // Momentum blends only 30% of the jump per tick.
        assert!(first.repair_ratio_ppm < 200_000);
    }

    #[test]
    fn probes_arm_reality_without_loss() {
        let mut state = IntelligentRepairState::default();
        let probed = derive_intelligent_actuators(
            IntelligentStealthInputs { signal_rst: 1, ..inputs() },
            &mut state,
        );
        assert!(probed.reality_armed);
        // Probe pressure also tightens the repair interval by two packets.
        assert_eq!(probed.repair_interval_pkts, 10);
    }

    #[test]
    fn probe_escalation_raises_repair_hint_and_arms_reality() {
        // TODO-1059/1060: probe escalation is the one channel that may move
        // the repair-ratio hint — inside the byte cap, never a shape.
        let mut state = IntelligentRepairState::default();
        let baseline = derive_intelligent_actuators(inputs(), &mut state);
        let probed = derive_intelligent_actuators(
            IntelligentStealthInputs { probe_level: 2, ..inputs() },
            &mut state,
        );
        assert!(probed.repair_ratio_ppm >= baseline.repair_ratio_ppm);
        assert!(probed.repair_interval_pkts <= baseline.repair_interval_pkts);
        assert!(probed.reality_armed);
    }

    #[test]
    fn the_hint_contract_has_no_shape_fields() {
        // Compile-time contract: the actuator struct can only ever carry the
        // repair hint and the armed bit. Adding a shape field here is the
        // regression this TODO removes.
        let hints = IntelligentActuatorHints {
            repair_ratio_ppm: 100_000,
            repair_interval_pkts: 8,
            reality_armed: false,
        };
        assert_eq!(hints.repair_ratio_ppm, 100_000);
    }
}
