use super::test_support::{acquire_env_lock, mk_src_packet, EnvGuard};
use super::{
    target_from_mode, AdaptiveFec, FecConfig, FecControlPolicy, FecMode, FecSwitchReason,
    DEFAULT_FOUNTAIN_WINDOW, MAX_FOUNTAIN_REPAIR_BURST, MAX_FOUNTAIN_WINDOW,
};
use crate::fec::wire::{WireError, WireReceiveReport};

fn off_config() -> FecConfig {
    FecConfig {
        control_policy: FecControlPolicy::Off,
        initial_mode: FecMode::Streaming,
        ..FecConfig::default()
    }
}

#[test]
fn public_mode_mapping_is_exact_and_stable() {
    let expected = [
        (0, "zero"),
        (1, "light"),
        (2, "normal"),
        (3, "medium"),
        (4, "strong"),
        (5, "extreme"),
        (6, "ultra"),
        (7, "fountain"),
        (8, "streaming"),
    ];
    let actual = FecMode::ALL.map(|mode| (mode.telemetry_id(), mode.telemetry_name()));

    assert_eq!(actual, expected);
    assert_eq!(crate::telemetry::FEC_MODE_MAPPING, expected);
}

#[test]
fn engine_mode_sets_policy_independently_from_codec_bootstrap() {
    let mut config = FecConfig::product_default();
    assert_eq!(config.control_policy, FecControlPolicy::Auto);

    config.apply_engine_mode(crate::engine::FecMode::Off);
    assert_eq!(config.control_policy, FecControlPolicy::Off);
    assert_eq!(config.initial_mode, FecMode::Zero);

    config.apply_engine_mode(crate::engine::FecMode::Auto);
    assert_eq!(config.control_policy, FecControlPolicy::Auto);
    assert_eq!(config.initial_mode, FecMode::Zero);
}

#[test]
fn active_auto_to_off_retires_all_controller_and_codec_state_at_ack() {
    let process_policy_transitions =
        crate::telemetry::FEC_POLICY_TRANSITIONS.load(std::sync::atomic::Ordering::Relaxed);
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig {
        control_policy: FecControlPolicy::Auto,
        initial_mode: FecMode::Normal,
        ..FecConfig::default()
    });
    let mut output = Vec::new();
    fec.on_send_into(mk_src_packet(1, 128, &pool), &mut output);
    fec.set_redundancy_ppm(900_000);
    assert!(fec.encoder.lock().packets_in_window() > 0);

    let change = fec.set_control_policy(FecControlPolicy::Off);
    let snapshot = fec.telemetry_snapshot();

    assert_eq!(change.previous_policy, FecControlPolicy::Auto);
    assert_eq!(change.previous_mode, FecMode::Normal);
    assert_eq!(change.effective_policy, FecControlPolicy::Off);
    assert_eq!(change.effective_mode, FecMode::Zero);
    assert_eq!(snapshot.control_policy, FecControlPolicy::Off);
    assert_eq!(snapshot.active_mode, FecMode::Zero);
    assert_eq!(snapshot.effective_window, 0);
    assert_eq!(snapshot.mode_transitions, 1);
    assert_eq!(snapshot.policy_transitions, 1);
    assert_eq!(fec.encoder.lock().packets_in_window(), 0);
    assert_eq!(fec.redundancy_ppm(), 0);
    assert!(!fec.is_transitioning());
    assert!(fec.emitted_ids.is_empty());
    assert!(fec.emitted_order.is_empty());
    assert!(
        crate::telemetry::FEC_POLICY_TRANSITIONS.load(std::sync::atomic::Ordering::Relaxed)
            > process_policy_transitions
    );
}

#[test]
fn active_off_to_auto_bootstraps_zero_without_stale_loss_or_repair_state() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    for _ in 0..16 {
        fec.report_transport_loss(32, 0, 32, 1.0);
    }
    assert_ne!(fec.current_mode(), FecMode::Zero);

    let off = fec.set_control_policy(FecControlPolicy::Off);
    assert_eq!(off.effective_policy, FecControlPolicy::Off);
    assert_eq!(off.effective_mode, FecMode::Zero);
    for _ in 0..16 {
        fec.report_transport_loss(32, 0, 32, 1.0);
    }
    let before = fec.telemetry_snapshot();

    let change = fec.set_control_policy(FecControlPolicy::Auto);
    let after = fec.telemetry_snapshot();

    assert_eq!(change.previous_policy, FecControlPolicy::Off);
    assert_eq!(change.effective_policy, FecControlPolicy::Auto);
    assert_eq!(change.effective_mode, FecMode::Zero);
    assert_eq!(after.observed_packets, before.observed_packets);
    assert_eq!(after.observed_lost_packets, before.observed_lost_packets);
    assert_eq!(after.mode_transitions, before.mode_transitions);
    assert_eq!(after.policy_transitions, before.policy_transitions + 1);
    assert_eq!(fec.current_mode(), FecMode::Zero);
    assert_eq!(fec.encoder.lock().packets_in_window(), 0);
    assert!(!fec.is_transitioning());

    fec.report_transport_loss(1, 1, 0, 0.0);
    assert_eq!(
        fec.current_mode(),
        FecMode::Zero,
        "one fresh clean observation must not replay stale Off-era loss"
    );
}

#[test]
fn repeated_active_policy_command_is_idempotent_and_preserves_live_auto_state() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    for _ in 0..12 {
        fec.report_transport_loss(32, 16, 16, 0.50);
    }
    let before = fec.telemetry_snapshot();
    assert_ne!(before.active_mode, FecMode::Zero);

    let change = fec.set_control_policy(FecControlPolicy::Auto);
    let after = fec.telemetry_snapshot();

    assert_eq!(change.previous_mode, before.active_mode);
    assert_eq!(change.effective_mode, before.active_mode);
    assert_eq!(after, before);
}

#[test]
fn off_policy_rejects_every_adaptive_and_observer_control_input() {
    let _env_lock = acquire_env_lock();
    let mut fec = AdaptiveFec::new(off_config());
    fec.telemetry.enabled = true;

    for _ in 0..32 {
        fec.report_loss(100, 100);
        fec.force_streaming_mode();
        fec.set_stream_every(1);
        fec.set_redundancy_ppm(1_000_000);
        fec.set_rtt_hint(10_000);
        fec.bandwidth_aware_overhead_adjustment(1.0, 1.0, 1.0);
    }

    assert_eq!(fec.control_policy(), FecControlPolicy::Off);
    assert_eq!(fec.current_mode(), FecMode::Zero);
    assert_eq!(fec.redundancy_ppm(), 0);
    assert!(!fec.is_transitioning());
    assert_eq!(fec.telemetry_snapshot().mode_transitions, 0);
    assert_eq!(fec.wire_profile(1), Err(WireError::ZeroModeMustRemainRaw));
    assert_eq!(fec.encoder.lock().packets_in_window(), 0);
}

#[test]
fn off_policy_emits_only_raw_source_packets_under_sustained_loss() {
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(off_config());
    let mut output = Vec::with_capacity(1);

    for id in 0..4096 {
        fec.report_loss(1, 1);
        fec.on_send_into(mk_src_packet(id, 1400, &pool), &mut output);
        assert_eq!(output.len(), 1);
        assert!(output[0].is_systematic);
    }

    assert_eq!(fec.current_mode(), FecMode::Zero);
    assert_eq!(fec.encoder.lock().packets_in_window(), 0);
    assert!(fec.emitted_ids.is_empty());
    assert!(fec.emitted_order.is_empty());
}

#[test]
fn auto_policy_still_escalates_from_zero_under_severe_loss() {
    let _env_lock = acquire_env_lock();
    let mut fec = AdaptiveFec::new(FecConfig {
        control_policy: FecControlPolicy::Auto,
        initial_mode: FecMode::Zero,
        ..FecConfig::default()
    });

    for _ in 0..8 {
        fec.report_loss(40, 100);
    }

    assert_eq!(fec.control_policy(), FecControlPolicy::Auto);
    assert_ne!(fec.current_mode(), FecMode::Zero);
}

#[test]
fn auto_transport_feedback_rejects_delayed_loss_as_fountain_evidence() {
    let _env_lock = acquire_env_lock();
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    fec.telemetry.enabled = true;

    fec.report_transport_loss(160, 158, 2, 0.02);
    fec.report_transport_loss(0, 0, 1, 0.10);

    let snapshot = fec.telemetry_snapshot();
    assert_eq!(snapshot.observed_packets, 160);
    assert_eq!(snapshot.observed_lost_packets, 3);
    assert_ne!(fec.current_mode(), FecMode::Fountain);
}

#[test]
fn auto_transport_feedback_enters_fountain_only_after_sustained_extreme_loss() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());

    fec.report_transport_loss(1, 0, 1, 1.0);
    assert_ne!(fec.current_mode(), FecMode::Fountain);

    for _ in 0..12 {
        fec.report_transport_loss(32, 16, 16, 0.50);
    }
    assert_eq!(fec.current_mode(), FecMode::Fountain);
}

#[test]
fn fountain_rescue_window_and_synchronous_repair_burst_are_bounded() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_window = EnvGuard::set("QUICFUSCATE_FEC_FOUNTAIN_WINDOW", "2048");
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    let mut output = Vec::new();

    for _ in 0..12 {
        fec.report_transport_loss(32, 16, 16, 0.50);
    }

    assert_eq!(fec.current_mode(), FecMode::Fountain);
    assert_eq!(DEFAULT_FOUNTAIN_WINDOW, MAX_FOUNTAIN_WINDOW);
    assert_eq!(fec.telemetry_snapshot().effective_window, MAX_FOUNTAIN_WINDOW);

    let mut repair_packets = 0;
    for id in 0..MAX_FOUNTAIN_WINDOW as u64 {
        fec.on_send_into(mk_src_packet(id, 128, &pool), &mut output);
        assert_eq!(output.iter().filter(|packet| packet.is_systematic).count(), 1);
        repair_packets += output.iter().filter(|packet| !packet.is_systematic).count();
    }

    assert!(repair_packets > 0);
    assert!(repair_packets <= MAX_FOUNTAIN_REPAIR_BURST);
}

#[test]
fn auto_transport_feedback_returns_to_zero_despite_smoothed_loss_residue() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());

    for _ in 0..12 {
        fec.report_transport_loss(32, 16, 16, 0.50);
    }
    assert_eq!(fec.current_mode(), FecMode::Fountain);

    for _ in 0..64 {
        fec.report_transport_loss(32, 0, 0, 0.10);
    }
    assert_ne!(
        fec.current_mode(),
        FecMode::Zero,
        "sent packets must not masquerade as clean delivery evidence"
    );

    for _ in 0..31 {
        fec.report_transport_loss(0, 1, 0, 0.10);
    }
    assert_ne!(
        fec.current_mode(),
        FecMode::Zero,
        "the clean-link override must require the complete observation streak"
    );

    for _ in 0..10 {
        fec.report_transport_loss(0, 1, 0, 0.10);
    }
    assert_eq!(
        fec.current_mode(),
        FecMode::Zero,
        "raw clean transport observations must outlive residual smoothed CC loss"
    );
}

#[test]
fn transition_telemetry_changes_only_after_block_boundary_commit() {
    let pool = crate::optimize::global_pool();
    let mut fec =
        AdaptiveFec::new(FecConfig { initial_mode: FecMode::Light, ..FecConfig::default() });
    fec.telemetry.enabled = true;
    let mut output = Vec::new();
    let initial_mode = fec.current_mode();
    let initial_window = fec.telemetry_snapshot().effective_window;
    assert!(initial_window > 0);

    fec.on_send_into(mk_src_packet(0, 128, &pool), &mut output);
    fec.transition_to_target_with_reason(
        target_from_mode(FecMode::Fountain, 64),
        FecSwitchReason::ExtremeLossPolicy,
    );
    assert_eq!(fec.current_mode(), initial_mode);
    assert_eq!(fec.telemetry_snapshot().mode_transitions, 0);
    assert!(fec.is_transitioning());

    for id in 1..initial_window as u64 {
        fec.on_send_into(mk_src_packet(id, 128, &pool), &mut output);
    }
    assert_eq!(fec.current_mode(), initial_mode);
    assert_eq!(fec.telemetry_snapshot().mode_transitions, 0);

    fec.wire_profile(1).expect("pending target must commit at block boundary");
    assert_eq!(fec.current_mode(), FecMode::Fountain);
    assert_eq!(fec.telemetry_snapshot().mode_transitions, 1);
    assert!(!fec.is_transitioning());
}

#[test]
fn clean_ack_proof_allows_zero_to_retire_a_partial_repair_window() {
    let _env_lock = acquire_env_lock();
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig {
        control_policy: FecControlPolicy::Auto,
        initial_mode: FecMode::Normal,
        ..FecConfig::default()
    });
    let mut output = Vec::new();

    fec.on_send_into(mk_src_packet(0, 128, &pool), &mut output);
    fec.transition_to_target_with_reason(
        target_from_mode(FecMode::Zero, 0),
        FecSwitchReason::Adaptive,
    );

    assert!(fec.is_transitioning());
    assert_eq!(fec.current_mode(), FecMode::Normal);
    assert!(fec.wire_profile(1).is_ok(), "unproven Zero must wait for the active block");

    fec.report_transport_loss(0, 32, 0, 0.10);
    for _ in 0..3 {
        fec.report_transport_loss(0, 1, 0, 0.10);
    }

    assert!(fec.loss_estimator.clean_link_confirmed());
    assert_eq!(fec.wire_profile(2), Err(WireError::ZeroModeMustRemainRaw));
    assert_eq!(fec.current_mode(), FecMode::Zero);
    assert_eq!(fec.encoder.lock().packets_in_window(), 0);
    assert!(!fec.is_transitioning());
}

#[test]
fn connection_local_wire_metrics_have_positive_and_negative_controls() {
    let mut fec = AdaptiveFec::new(FecConfig::default());
    fec.telemetry.enabled = true;
    let initial = fec.telemetry_snapshot();

    fec.observe_wire_send(true, 100, 100);
    fec.observe_wire_send(false, 0, 132);
    fec.observe_wire_receive(WireReceiveReport::raw_source(100));
    fec.observe_wire_receive(WireReceiveReport {
        systematic: false,
        source_payload_bytes: 0,
        wire_bytes: 132,
        decoded_packets: 2,
        recovered_packets: 2,
        recovered_payload_bytes: 180,
    });

    let snapshot = fec.telemetry_snapshot();
    assert_eq!(snapshot.source_packets_sent - initial.source_packets_sent, 1);
    assert_eq!(snapshot.repair_packets_sent - initial.repair_packets_sent, 1);
    assert_eq!(snapshot.source_payload_bytes_sent - initial.source_payload_bytes_sent, 100);
    assert_eq!(snapshot.source_wire_bytes_sent - initial.source_wire_bytes_sent, 100);
    assert_eq!(snapshot.repair_wire_bytes_sent - initial.repair_wire_bytes_sent, 132);
    assert_eq!(snapshot.source_packets_received - initial.source_packets_received, 1);
    assert_eq!(snapshot.repair_packets_received - initial.repair_packets_received, 1);
    assert_eq!(snapshot.decoded_packets - initial.decoded_packets, 3);
    assert_eq!(snapshot.recovered_packets - initial.recovered_packets, 2);
    assert_eq!(snapshot.recovered_payload_bytes - initial.recovered_payload_bytes, 180);
}

#[test]
fn auto_tuning_is_connection_local_and_never_mutates_process_environment() {
    let _env_lock = acquire_env_lock();
    let _decoder = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "auto");
    let _threshold = EnvGuard::set("QUICFUSCATE_FEC_WIEDEMANN_K", "17");
    let former_runtime_outputs = [
        ("QUICFUSCATE_WM_BITSLICE", "sentinel-bitslice"),
        ("QUICFUSCATE_WM_LANE_PAR", "sentinel-lane-par"),
        ("QUICFUSCATE_WM_LANES", "sentinel-lanes"),
        ("QUICFUSCATE_WM_U", "sentinel-u"),
        ("QUICFUSCATE_FEC_STREAM_BURST", "sentinel-burst"),
    ];
    let _guards: Vec<_> =
        former_runtime_outputs.iter().map(|(key, value)| EnvGuard::set(key, value)).collect();
    let mut fec = AdaptiveFec::new(FecConfig::product_default());

    fec.apply_auto_tuning(128, 0.50, target_from_mode(FecMode::Fountain, 128));
    assert_eq!(fec.runtime_policy.decoder_policy, "wiedemann");
    assert_eq!(fec.stream_every, 1);

    fec.apply_auto_tuning(0, 0.0, target_from_mode(FecMode::Zero, 0));
    assert_eq!(fec.runtime_policy.decoder_policy, "gauss");
    assert_eq!(fec.stream_every, 4);

    assert_eq!(std::env::var("QUICFUSCATE_FEC_DECODER").as_deref(), Ok("auto"));
    assert_eq!(std::env::var("QUICFUSCATE_FEC_WIEDEMANN_K").as_deref(), Ok("17"));
    for (key, expected) in former_runtime_outputs {
        assert_eq!(std::env::var(key).as_deref(), Ok(expected));
    }
}

#[test]
fn decoder_override_remains_immutable_during_auto_tuning() {
    let _env_lock = acquire_env_lock();
    let _decoder = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "gauss");
    let _switch = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());

    for _ in 0..12 {
        fec.report_transport_loss(32, 16, 16, 0.50);
    }

    assert_eq!(fec.current_mode(), FecMode::Fountain);
    assert_eq!(fec.runtime_policy.decoder_policy, "gauss");
    assert_eq!(std::env::var("QUICFUSCATE_FEC_DECODER").as_deref(), Ok("gauss"));
}

#[test]
fn wiedemann_threshold_is_snapshotted_before_feedback_processing() {
    let _env_lock = acquire_env_lock();
    let _decoder = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "auto");
    let _initial_threshold = EnvGuard::set("QUICFUSCATE_FEC_WIEDEMANN_K", "8");
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    let _changed_threshold = EnvGuard::set("QUICFUSCATE_FEC_WIEDEMANN_K", "4096");

    fec.apply_auto_tuning(64, 0.005, target_from_mode(FecMode::Normal, 64));

    assert_eq!(fec.wiedemann_threshold, 8);
    assert_eq!(fec.runtime_policy.decoder_policy, "auto");
    assert_eq!(std::env::var("QUICFUSCATE_FEC_WIEDEMANN_K").as_deref(), Ok("4096"));
}
