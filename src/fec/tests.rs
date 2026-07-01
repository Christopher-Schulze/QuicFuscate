#[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
fn has_amx_runtime() -> bool {
    std::arch::is_x86_feature_detected!("amx_int8")
        && std::arch::is_x86_feature_detected!("amx_tile")
        && std::arch::is_x86_feature_detected!("amx_bf16")
}

use super::test_support::*;
use super::{
    adaptive_rs_uses_gf16, continuous_fec_target, heavy_block_uses_adaptive_rs,
    low_cost_block_uses_gf4, mode_for_target, target_from_mode, target_rank, AdaptiveFec,
    CpuProfile, Decoder8, FecAmbientInputs, FecBackendFamily, FecComputeProfile, FecConfig,
    FecMode, FecObserverPlatformHints, FecObserverProfilePolicy, FecPacket, FecRuntimePlan,
    FecRuntimePolicy, FecTransportObserver, SimdLevel, TransportProfile,
};
#[cfg(target_arch = "x86_64")]
use super::{matrix_multiply_avx512, matrix_multiply_scalar};
use crate::optimize::telemetry;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[test]
fn test_auto_mode_streaming_selection() {
    let _env_lock = acquire_env_lock();
    let _g_burst = EnvGuard::unset("QUICFUSCATE_FEC_STREAM_BURST");
    let _g = EnvGuard::set("QUICFUSCATE_FEC_AUTO_STREAM", "true");
    let _pool = crate::optimize::global_pool();
    let config = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(config);
    fec.report_loss(0, 10000);
    assert_eq!(fec.current_mode(), FecMode::Zero);
    fec.report_loss(15, 1000);
    for _ in 0..5 {
        fec.report_loss(15, 1000);
    }
    let mode = fec.current_mode();
    // Light (GF4) is now auto-selected for ultra-low loss (<2%), Streaming/Normal for higher
    assert!(matches!(mode, FecMode::Light | FecMode::Streaming | FecMode::Normal));
}

#[test]
fn test_zero_mode_receive_preserves_unique_payload_owner() {
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });
    let mut block = pool.alloc();
    block[..16].copy_from_slice(b"zero-mode-packet");
    let pkt = FecPacket::new(7, Some(block), 16, true, None, 0, Arc::clone(&pool));

    let mut out = fec.on_receive(pkt).expect("zero mode receive must pass through");

    assert_eq!(out.len(), 1);
    assert!(
        out[0].payload_mut_unique().is_some(),
        "zero mode receive must not retain a decoder Arc clone that forces core copy fallback"
    );
}

#[test]
fn test_on_receive_into_zero_mode_reuses_output_allocation() {
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });
    let mut block = pool.alloc();
    block[..16].copy_from_slice(b"zero-recv-packet");
    let pkt = FecPacket::new(9, Some(block), 16, true, None, 0, Arc::clone(&pool));
    let mut output = Vec::with_capacity(8);
    output.push(FecPacket::new(999, None, 0, true, None, 0, Arc::clone(&pool)));
    let initial_capacity = output.capacity();

    fec.on_receive_into(pkt, &mut output).expect("zero mode receive_into must pass through");

    assert_eq!(output.len(), 1);
    assert_eq!(output[0].id, 9);
    assert!(
        output[0].payload_mut_unique().is_some(),
        "zero mode receive_into must preserve unique payload ownership"
    );
    assert_eq!(
        output.capacity(),
        initial_capacity,
        "on_receive_into must clear and reuse the caller allocation"
    );
}

#[test]
fn test_on_send_into_zero_mode_reuses_output_allocation() {
    let pool = crate::optimize::global_pool();
    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });
    let mut block = pool.alloc();
    block[..16].copy_from_slice(b"zero-send-packet");
    let pkt = FecPacket::new(11, Some(block), 16, true, None, 0, Arc::clone(&pool));
    let mut output = Vec::with_capacity(8);
    output.push(FecPacket::new(999, None, 0, true, None, 0, Arc::clone(&pool)));
    let initial_capacity = output.capacity();

    fec.on_send_into(pkt, &mut output);

    assert_eq!(output.len(), 1);
    assert_eq!(output[0].id, 11);
    assert_eq!(
        output.capacity(),
        initial_capacity,
        "on_send_into must clear and reuse the caller allocation"
    );
}

#[test]
fn test_on_send_into_matches_on_send_first_packet() {
    let pool = crate::optimize::global_pool();
    let config = FecConfig { initial_mode: FecMode::Normal, ..Default::default() };
    let mut wrapper_fec = AdaptiveFec::new(config.clone());
    let mut reusable_fec = AdaptiveFec::new(config);

    let mut wrapper_block = pool.alloc();
    wrapper_block[..15].copy_from_slice(b"normal-send-one");
    let wrapper_pkt = FecPacket::new(12, Some(wrapper_block), 15, true, None, 0, Arc::clone(&pool));

    let mut reusable_block = pool.alloc();
    reusable_block[..15].copy_from_slice(b"normal-send-one");
    let reusable_pkt =
        FecPacket::new(12, Some(reusable_block), 15, true, None, 0, Arc::clone(&pool));

    let wrapper_output = wrapper_fec.on_send(wrapper_pkt);
    let mut reusable_output = Vec::with_capacity(1);
    reusable_fec.on_send_into(reusable_pkt, &mut reusable_output);

    assert_eq!(reusable_output.len(), wrapper_output.len());
    assert_eq!(
        reusable_output.iter().map(|pkt| pkt.id).collect::<Vec<_>>(),
        wrapper_output.iter().map(|pkt| pkt.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_on_receive_into_matches_on_receive_first_packet() {
    let pool = crate::optimize::global_pool();
    let config = FecConfig { initial_mode: FecMode::Normal, ..Default::default() };
    let mut wrapper_fec = AdaptiveFec::new(config.clone());
    let mut reusable_fec = AdaptiveFec::new(config);

    let mut wrapper_block = pool.alloc();
    wrapper_block[..17].copy_from_slice(b"normal-recv-one!!");
    let wrapper_pkt = FecPacket::new(14, Some(wrapper_block), 17, true, None, 0, Arc::clone(&pool));

    let mut reusable_block = pool.alloc();
    reusable_block[..17].copy_from_slice(b"normal-recv-one!!");
    let reusable_pkt =
        FecPacket::new(14, Some(reusable_block), 17, true, None, 0, Arc::clone(&pool));

    let wrapper_output = wrapper_fec.on_receive(wrapper_pkt).expect("wrapper receive");
    let mut reusable_output = Vec::with_capacity(1);
    reusable_fec.on_receive_into(reusable_pkt, &mut reusable_output).expect("reusable receive");

    assert_eq!(reusable_output.len(), wrapper_output.len());
    assert_eq!(
        reusable_output.iter().map(|pkt| pkt.id).collect::<Vec<_>>(),
        wrapper_output.iter().map(|pkt| pkt.id).collect::<Vec<_>>()
    );
}

#[test]
fn test_strong_receive_into_recovers_single_source_loss() {
    let _env_lock = acquire_env_lock();
    let pool = crate::optimize::global_pool();
    let mut config = FecConfig::product_default();
    config.initial_mode = FecMode::Strong;
    config.window_sizes.insert(FecMode::Strong, 16);

    let mut sender = AdaptiveFec::new(config.clone());
    let mut receiver = AdaptiveFec::new(config);
    let mut send_output = Vec::with_capacity(40);
    let mut receive_output = Vec::with_capacity(8);
    let mut emitted = Vec::new();
    let missing_id = 7_u64;

    for id in 0..16_u64 {
        let pkt = mk_src_packet(id, 100, &pool);
        sender.on_send_into(pkt, &mut send_output);
        for packet in send_output.drain(..) {
            if packet.is_systematic && packet.id == missing_id {
                continue;
            }
            receiver
                .on_receive_into(packet, &mut receive_output)
                .expect("strong receive_into must accept packet");
            emitted.append(&mut receive_output);
        }
    }

    assert!(
        emitted.iter().any(|packet| packet.id == missing_id && packet.len() == 100),
        "strong receive_into must recover dropped source packet {missing_id}"
    );
}

#[test]
fn test_continuous_target_keeps_clean_link_zero_family() {
    let target = continuous_fec_target(0.0, true, false, 2048, 1024, 0, 0.0);
    assert_eq!(target.family, FecBackendFamily::Zero);
    assert_eq!(target.effective_window, 0);
    assert_eq!(target.stream_every, None);
}

#[test]
fn test_continuous_target_escalates_to_streaming_under_disturbance() {
    let target = continuous_fec_target(0.16, true, true, 2048, 1024, 0, 0.0);
    assert_eq!(target.family, FecBackendFamily::Streaming);
    assert_eq!(target.effective_window, 1024);
    assert!(target.stream_every.is_some());
}

#[test]
fn test_continuous_target_escalates_to_fountain_under_extreme_loss() {
    let target = continuous_fec_target(0.30, true, false, 2048, 1024, 0, 0.0);
    assert_eq!(target.family, FecBackendFamily::Fountain);
    assert_eq!(target.effective_window, 2048);
    assert!(target.redundancy >= 5.0);
}

#[test]
fn test_mode_manager_params_follow_controller_target() {
    let target = continuous_fec_target(0.18, true, true, 2048, 1024, 0, 0.0);
    let (mode, k, n) = super::internal::ModeManager::params_for_target(target, 64, true);
    assert_eq!(mode, FecMode::Streaming);
    assert_eq!(k, 1024);
    assert!(n >= ((k as f32) * target.redundancy).ceil() as usize);
}

#[test]
fn test_mode_manager_overhead_matches_target_mapping() {
    let target = target_from_mode(FecMode::Ultra, 1024);
    let mode = mode_for_target(target, true);
    assert_eq!(mode, FecMode::Ultra);
    assert_eq!(super::internal::ModeManager::overhead_for(mode), target.redundancy);
}

#[test]
fn test_stream_interval_target_tracks_controller_target() {
    let _env_lock = acquire_env_lock();
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    for _ in 0..5 {
        fec.report_loss(0, 1000);
    }
    assert!(fec.stream_interval_target(0.0) >= 6);
    assert_eq!(fec.stream_interval_target(0.30), 1);

    fec.report_loss(160, 1000);
    let target_every = fec.stream_interval_target(0.16);
    assert!(target_every <= 3);
}

#[test]
fn test_backend_family_mapping_preserves_low_cost_gf4_path() {
    let target = target_from_mode(FecMode::Light, 16);
    assert!(low_cost_block_uses_gf4(target));
    let encoder = super::internal::EncoderVariant::new(FecMode::Light, 16, 18);
    let decoder = super::internal::DecoderVariant::new(
        FecMode::Light,
        16,
        Arc::clone(&crate::optimize::global_pool()),
    );
    assert!(matches!(encoder, super::internal::EncoderVariant::GF4(_)));
    assert!(matches!(decoder, super::internal::DecoderVariant::GF4(_)));
}

#[test]
fn test_backend_family_mapping_preserves_heavy_block_adaptive_rs_path() {
    let target = target_from_mode(FecMode::Strong, 128);
    assert!(heavy_block_uses_adaptive_rs(target));
    let encoder = super::internal::EncoderVariant::new(FecMode::Strong, 128, 256);
    let decoder = super::internal::DecoderVariant::new(
        FecMode::Strong,
        128,
        Arc::clone(&crate::optimize::global_pool()),
    );
    assert_eq!(encoder.backend_kind(), "adaptive-rs");
    assert_eq!(decoder.backend_kind(), "adaptive-rs");
}

#[test]
fn test_target_rank_monotonic_from_clean_to_extreme() {
    let clean = continuous_fec_target(0.0, true, false, 2048, 1024, 0, 0.0);
    let low = target_from_mode(FecMode::Normal, 64);
    let heavy = target_from_mode(FecMode::Strong, 128);
    let fountain = continuous_fec_target(0.30, true, false, 2048, 1024, 0, 0.0);

    assert!(target_rank(clean) < target_rank(low));
    assert!(target_rank(low) < target_rank(heavy));
    assert!(target_rank(heavy) < target_rank(fountain));
}

#[test]
fn test_streaming_adaptive_selected_for_burst_loss_5_to_15_percent() {
    // 10% loss with high burst variance → StreamingAdaptive (Streaming family)
    let target = continuous_fec_target(0.10, true, false, 2048, 1024, 0, 0.5);
    assert_eq!(target.family, FecBackendFamily::Streaming);
    assert!(target.stream_every.is_some());
}

#[test]
fn test_streaming_adaptive_falls_back_to_lowcost_for_uniform_loss() {
    // 8% loss with low burst variance (uniform) → LowCostBlock, not Streaming
    let target = continuous_fec_target(0.08, true, false, 2048, 1024, 0, 0.1);
    assert_eq!(target.family, FecBackendFamily::LowCostBlock);
}

#[test]
fn test_streaming_adaptive_escalates_to_heavyblock_above_15_percent() {
    // 18% loss → HeavyBlock (not Streaming, even with high burst variance)
    let target = continuous_fec_target(0.18, true, false, 2048, 1024, 0, 0.5);
    assert_eq!(target.family, FecBackendFamily::HeavyBlock);
}

#[test]
fn test_stream_every_scales_with_rtt() {
    // Low RTT (20ms) → smaller stream_every (faster recovery)
    let low_rtt = continuous_fec_target(0.16, true, true, 2048, 1024, 20, 0.0);
    // High RTT (300ms) → larger stream_every (less overhead)
    let high_rtt = continuous_fec_target(0.16, true, true, 2048, 1024, 300, 0.0);
    let low_interval = low_rtt.stream_every.unwrap();
    let high_interval = high_rtt.stream_every.unwrap();
    assert!(
        high_interval > low_interval,
        "high RTT should produce larger stream_every: {} > {}",
        high_interval,
        low_interval
    );
}

#[test]
fn test_stream_every_clamped_to_bounds() {
    // Very high RTT → stream_every should be clamped to max 18
    let target = continuous_fec_target(0.16, true, true, 2048, 1024, 10000, 0.0);
    let interval = target.stream_every.unwrap();
    assert!(interval <= 18, "stream_every should be clamped to max 18, got {}", interval);
    assert!(interval >= 1, "stream_every should be at least 1, got {}", interval);
}

#[test]
fn test_runtime_plan_force_on_promotes_zero_target() {
    let mut cfg = FecConfig { initial_mode: FecMode::Zero, force_on: true, ..Default::default() };
    cfg.window_sizes.insert(FecMode::Zero, 0);
    let ambient = FecAmbientInputs::detect();
    let plan = FecRuntimePlan::resolve(&cfg, &ambient);
    assert_ne!(plan.mode, FecMode::Zero);
    assert!(plan.k > 0);
}

#[test]
fn test_adaptive_rs_gf16_selection_comes_from_target_truth() {
    let medium_target = target_from_mode(FecMode::Medium, 64);
    let strong_target = target_from_mode(FecMode::Strong, 128);

    assert!(!adaptive_rs_uses_gf16(medium_target));
    assert!(adaptive_rs_uses_gf16(strong_target));
}

#[test]
fn test_product_fec_default_is_auto_and_stream_every_is_explicit() {
    let cfg = FecConfig::product_default();
    assert_eq!(cfg.initial_mode, FecMode::Normal);
    assert_eq!(cfg.window_sizes.get(&FecMode::Zero), Some(&0));
    assert_eq!(cfg.configured_stream_every, Some(5));
}

#[test]
fn test_mode_does_not_downshift_on_single_low_loss_sample() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "600");
    let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
    let cfg = FecConfig { initial_mode: FecMode::Strong, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    for _ in 0..12 {
        fec.report_loss(220, 1000);
    }
    let before = fec.current_mode();
    fec.report_loss(0, 1000);
    assert_eq!(
        fec.current_mode(),
        before,
        "single low-loss sample must not immediately downshift protection mode"
    );
}

#[test]
fn test_mode_boundaries_progress_deterministically() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
    let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    for _ in 0..12 {
        fec.report_loss(0, 1000);
    }
    assert_eq!(fec.current_mode(), FecMode::Zero);

    for _ in 0..16 {
        fec.report_loss(15, 1000);
    }
    assert_eq!(fec.current_mode(), FecMode::Light);

    for _ in 0..16 {
        fec.report_loss(120, 1000);
    }
    assert_eq!(fec.current_mode(), FecMode::Strong);

    for _ in 0..20 {
        fec.report_loss(350, 1000);
    }
    assert_eq!(fec.current_mode(), FecMode::Fountain);
}

#[test]
fn test_extreme_loss_switch_reason_telemetry_increments() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
    let mut fec = AdaptiveFec::new(FecConfig::default());
    let before = telemetry::FEC_SWITCH_REASON_EXTREME.load(std::sync::atomic::Ordering::Relaxed);
    for _ in 0..20 {
        fec.report_loss(400, 1000);
    }
    let after = telemetry::FEC_SWITCH_REASON_EXTREME.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        after > before,
        "extreme-loss reason counter did not increment (before={}, after={})",
        before,
        after
    );
}

#[test]
fn test_prolonged_extreme_loss_stays_in_high_resilience_mode() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "500");
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    // Prolonged very high loss should converge to fountain and remain there.
    for _ in 0..120 {
        fec.report_loss(650, 1000);
    }
    assert_eq!(fec.current_mode(), FecMode::Fountain);

    for _ in 0..40 {
        fec.report_loss(620, 1000);
        assert_eq!(
            fec.current_mode(),
            FecMode::Fountain,
            "mode must remain in strongest resilience profile under sustained extreme loss"
        );
    }
}

#[test]
fn test_bursty_jitter_trace_remains_in_resilient_modes() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "250");
    let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    let bursty_trace = [650usize, 40, 620, 55, 600, 80, 500, 60];
    for _ in 0..40 {
        for &lost in &bursty_trace {
            fec.report_loss(lost, 1000);
        }
    }

    assert!(
        matches!(
            fec.current_mode(),
            FecMode::Strong | FecMode::Extreme | FecMode::Fountain | FecMode::Streaming
        ),
        "bursty high-loss/jitter trace should not converge to weak protection mode"
    );
}

#[test]
fn test_long_running_mixed_loss_trace_stays_operational() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    for i in 0..5000usize {
        let lost = if i % 17 == 0 {
            700
        } else if i % 5 == 0 {
            220
        } else {
            60
        };
        fec.report_loss(lost, 1000);
        assert!(
            matches!(
                fec.current_mode(),
                FecMode::Zero
                    | FecMode::Light
                    | FecMode::Normal
                    | FecMode::Strong
                    | FecMode::Extreme
                    | FecMode::Fountain
                    | FecMode::Streaming
            ),
            "mode left supported enum set during long-running adaptation trace"
        );
    }

    assert_ne!(
        fec.current_mode(),
        FecMode::Zero,
        "long-running mixed-loss trace must not collapse to zero protection"
    );
}

#[test]
fn test_replayed_loss_trace_drives_end_to_end_adaptation() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
    let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
    let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);

    let mut visited = std::collections::HashSet::new();
    visited.insert(fec.current_mode());

    for _ in 0..16 {
        fec.report_loss(15, 1000);
        visited.insert(fec.current_mode());
    }
    for _ in 0..16 {
        fec.report_loss(120, 1000);
        visited.insert(fec.current_mode());
    }
    for _ in 0..20 {
        fec.report_loss(350, 1000);
        visited.insert(fec.current_mode());
    }
    for _ in 0..20 {
        fec.report_loss(0, 1000);
        visited.insert(fec.current_mode());
    }

    assert!(visited.contains(&FecMode::Zero), "trace must include Zero mode");
    assert!(visited.contains(&FecMode::Light), "trace must include Light mode");
    assert!(visited.contains(&FecMode::Strong), "trace must include Strong mode");
    assert!(visited.contains(&FecMode::Fountain), "trace must include Fountain mode");
}

#[test]
fn test_transition_safety_for_all_start_modes_under_replay_trace() {
    let _env_lock = acquire_env_lock();
    let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
    let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");

    let all_modes = [
        FecMode::Zero,
        FecMode::Light,
        FecMode::Normal,
        FecMode::Strong,
        FecMode::Extreme,
        FecMode::Fountain,
        FecMode::Streaming,
    ];
    let replay = [0usize, 20, 60, 150, 300, 450, 80, 30, 5, 0];

    for start_mode in all_modes {
        let cfg = FecConfig { initial_mode: start_mode, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);
        if start_mode == FecMode::Streaming {
            fec.force_streaming_mode();
        }
        for &lost in &replay {
            fec.report_loss(lost, 1000);
            assert!(
                matches!(
                    fec.current_mode(),
                    FecMode::Zero
                        | FecMode::Light
                        | FecMode::Normal
                        | FecMode::Strong
                        | FecMode::Extreme
                        | FecMode::Fountain
                        | FecMode::Streaming
                ),
                "mode must remain within supported transition set (start_mode={:?})",
                start_mode
            );
        }
    }
}

#[test]
fn test_enable_simd_acceleration_updates_telemetry() {
    let cfg = FecConfig::default();
    let mut fec = AdaptiveFec::new(cfg);

    let before = telemetry::SIMD_USAGE_AVX512.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_AVX2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SSE2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SVE2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_NEON.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SCALAR.load(std::sync::atomic::Ordering::Relaxed);

    fec.enable_simd_acceleration();

    let after = telemetry::SIMD_USAGE_AVX512.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_AVX2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SSE2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SVE2.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_NEON.load(std::sync::atomic::Ordering::Relaxed)
        + telemetry::SIMD_USAGE_SCALAR.load(std::sync::atomic::Ordering::Relaxed);

    assert!(
        after > before,
        "expected SIMD activation telemetry update (before={}, after={})",
        before,
        after
    );
}

#[test]
fn test_simd_dispatch_selection_covers_scalar_avx_neon_sve() {
    let avx = AdaptiveFec::select_simd_level_from_features(|f| {
        matches!(f, crate::optimize::CpuFeature::AVX512F | crate::optimize::CpuFeature::AVX512VBMI)
    });
    assert_eq!(avx, SimdLevel::Avx512);

    let avx2 = AdaptiveFec::select_simd_level_from_features(|f| {
        matches!(f, crate::optimize::CpuFeature::AVX2)
    });
    assert_eq!(avx2, SimdLevel::Avx2);

    let sve2 = AdaptiveFec::select_simd_level_from_features(|f| {
        matches!(f, crate::optimize::CpuFeature::SVE2)
    });
    assert_eq!(sve2, SimdLevel::Sve2);

    let neon = AdaptiveFec::select_simd_level_from_features(|f| {
        matches!(f, crate::optimize::CpuFeature::NEON)
    });
    assert_eq!(neon, SimdLevel::Neon);

    let scalar = AdaptiveFec::select_simd_level_from_features(|_| false);
    assert_eq!(scalar, SimdLevel::None);
}

#[test]
fn test_update_stream_interval_decreases_under_high_loss() {
    let cfg = FecConfig::default();
    let mut fec = AdaptiveFec::new(cfg);
    fec.stream_every_override = None;
    fec.stream_every = 8;
    fec.stream_last_adjust =
        crate::time_source::now_instant() - std::time::Duration::from_millis(1000);

    fec.update_stream_interval(0.25);
    assert!(
        fec.stream_every <= 6,
        "high loss should reduce stream interval aggressively (got {})",
        fec.stream_every
    );
}

#[test]
fn test_update_stream_interval_relaxes_under_low_loss() {
    let cfg = FecConfig::default();
    let mut fec = AdaptiveFec::new(cfg);
    fec.stream_every_override = None;
    fec.stream_every = 2;
    fec.stream_last_adjust =
        crate::time_source::now_instant() - std::time::Duration::from_millis(1000);

    fec.update_stream_interval(0.0);
    assert!(
        fec.stream_every >= 3,
        "low loss should relax stream interval for efficiency (got {})",
        fec.stream_every
    );
}

#[test]
fn test_update_stream_interval_respects_time_source_gate() {
    use crate::time_source::TimeSource;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, Instant, SystemTime};

    struct ManualTimeSource {
        instant_now: Mutex<Instant>,
        system_now: Mutex<SystemTime>,
    }

    impl ManualTimeSource {
        fn new(instant_now: Instant, system_now: SystemTime) -> Self {
            Self { instant_now: Mutex::new(instant_now), system_now: Mutex::new(system_now) }
        }

        fn advance(&self, delta: Duration) {
            if let Ok(mut instant_now) = self.instant_now.lock() {
                *instant_now += delta;
            }
            if let Ok(mut system_now) = self.system_now.lock() {
                *system_now += delta;
            }
        }
    }

    impl TimeSource for ManualTimeSource {
        fn now_instant(&self) -> Instant {
            *self.instant_now.lock().expect("manual instant poisoned")
        }

        fn now_system(&self) -> SystemTime {
            *self.system_now.lock().expect("manual system poisoned")
        }
    }

    let base_instant = Instant::now();
    let base_system = std::time::UNIX_EPOCH + Duration::from_secs(1);
    let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
    let _time_guard = crate::time_source::install_for_test(manual.clone());

    let cfg = FecConfig::default();
    let mut fec = AdaptiveFec::new(cfg);
    fec.stream_every_override = None;
    fec.stream_every = 8;
    fec.stream_last_adjust = base_instant;

    fec.update_stream_interval(0.25);
    assert_eq!(fec.stream_every, 8);

    manual.advance(Duration::from_millis(super::STREAM_ADJUST_MIN_MS + 5));
    fec.update_stream_interval(0.25);
    assert!(fec.stream_every <= 6);
}

#[test]
fn test_streaming_repair_scratch_queue_reused_under_load() {
    let pool = make_pool();
    let cfg = FecConfig { initial_mode: FecMode::Streaming, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    fec.set_stream_every(1);

    let cap_before = fec.stream_repair_scratch_capacity();
    for i in 0..256u64 {
        let pkt = mk_src_packet(i + 1, 256, &pool);
        let _ = fec.on_send(pkt);
        assert_eq!(fec.stream_repair_scratch_len(), 0, "scratch queue must be drained each send");
    }
    let cap_after = fec.stream_repair_scratch_capacity();
    assert_eq!(
        cap_after, cap_before,
        "streaming scratch queue capacity should remain stable for allocation reuse"
    );
}

#[test]
fn test_lazy_decoder_pending_repair_ring_reuse_under_load() {
    let pool = make_pool();
    let mut dec = super::internal::LazyDecoder::new(FecMode::Normal, 8, Arc::clone(&pool));
    let cap_before = dec.pending_repairs_capacity();

    for i in 0..256u64 {
        let mut data = pool.alloc();
        let len = 64usize;
        for (j, b) in data.iter_mut().take(len).enumerate() {
            *b = (i as u8).wrapping_add(j as u8);
        }
        let mut coeffs = pool.alloc();
        for (j, b) in coeffs.iter_mut().take(8).enumerate() {
            *b = (j as u8).wrapping_add(1);
        }
        let repair =
            FecPacket::new(10_000 + i, Some(data), len, false, Some(coeffs), 8, Arc::clone(&pool));
        dec.take_packet(repair);
        assert!(
            dec.pending_repairs_len() <= dec.pending_repairs_max(),
            "pending repair ring must stay bounded"
        );
    }

    let cap_after = dec.pending_repairs_capacity();
    assert!(
        cap_after >= cap_before,
        "pending repair ring capacity should be reused (before={}, after={})",
        cap_before,
        cap_after
    );
}

#[test]
fn test_interleaved_decoder_get_result_skips_idle_lazy_blocks() {
    let pool = make_pool();
    let mut decoder =
        super::internal::InterleavedDecoder::new(FecMode::Streaming, 8, Arc::clone(&pool), 2);

    let mut idle_source = mk_src_packet(1, 64, &pool);
    idle_source.seq = 1;
    decoder.take_packet(idle_source);

    let mut idle_data = pool.alloc();
    idle_data[..64].fill(0x5A);
    let mut idle_coeffs = pool.alloc();
    idle_coeffs[..4].fill(1);
    let mut idle_repair =
        FecPacket::new(100, Some(idle_data), 64, false, Some(idle_coeffs), 4, Arc::clone(&pool));
    idle_repair.seq = 1;
    decoder.take_packet(idle_repair);
    assert_eq!(decoder.block_pending_repairs_len(1), Some(1));

    let mut lossy_source = mk_src_packet(0, 64, &pool);
    lossy_source.seq = 0;
    decoder.take_packet(lossy_source);

    let mut lossy_data = pool.alloc();
    lossy_data[..64].fill(0xA5);
    let mut lossy_coeffs = pool.alloc();
    lossy_coeffs[..4].fill(1);
    let mut lossy_repair =
        FecPacket::new(200, Some(lossy_data), 64, false, Some(lossy_coeffs), 4, Arc::clone(&pool));
    lossy_repair.seq = 0;
    decoder.take_packet(lossy_repair);

    let mut later_lossy_source = mk_src_packet(4, 64, &pool);
    later_lossy_source.seq = 4;
    decoder.take_packet(later_lossy_source);
    assert!(decoder.full_recovery_needed());

    let _ = decoder.get_result();
    assert_eq!(
        decoder.block_pending_repairs_len(1),
        Some(1),
        "full recovery in one interleave lane must not flush idle clean-lane repair buffers"
    );
}

#[test]
fn test_streaming_repairs_have_nonzero_coeffs() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    for i in 0..k_stream as u64 {
        let pkt = mk_src_packet(10 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert!(!repairs.is_empty(), "streaming emitted no repairs");
    for rp in repairs.iter() {
        assert!(!rp.is_systematic);
        let coeffs = rp.coefficients.as_ref().expect("repair must carry coefficients");
        let coeff_slice: &[u8] = &coeffs[..rp.coeff_len];
        assert!(
            coeff_slice.iter().any(|&b| b != 0),
            "repair with all-zero coeffs should not be emitted"
        );
    }
}

#[test]
fn test_wiedemann_scalar_telemetry_increments() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();
    let decoder = Decoder8::new(2, pool.clone());

    let matrix = vec![vec![1u8, 0u8], vec![0u8, 1u8]];
    let rhs = vec![5u8, 9u8];

    let usage_before = telemetry::WIEDEMANN_USAGE.get();
    let scalar_before = telemetry::WIEDEMANN_SCALAR_OPS.get();

    let solution = decoder
        .solve_wiedemann_system(&matrix, &rhs, 2)
        .expect("identity system should be solvable");

    assert_eq!(solution, rhs, "identity system must return RHS");

    let usage_after = telemetry::WIEDEMANN_USAGE.get();
    let scalar_after = telemetry::WIEDEMANN_SCALAR_OPS.get();

    assert!(usage_after > usage_before, "usage counter should increase");
    assert!(scalar_after > scalar_before, "scalar counter should increase");
}

#[test]
#[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
fn test_wiedemann_amx_telemetry_increments() {
    if !has_amx_runtime() {
        println!("AMX runtime support not available; skipping test");
        return;
    }

    let _env_lock = acquire_env_lock();
    let pool = make_pool();
    let mut decoder = Decoder8::new(64, pool.clone());

    let dim = 64;
    let mut matrix = vec![vec![0u8; dim]; dim];
    for i in 0..dim {
        matrix[i][i] = 1;
    }

    let rhs = vec![0xAAu8; dim];

    let usage_before = telemetry::WIEDEMANN_USAGE.get();
    let amx_before = telemetry::WIEDEMANN_AMX_OPS.get();

    let solution =
        decoder.solve_wiedemann_system(&matrix, &rhs, dim).expect("AMX solve should succeed");
    assert_eq!(solution, rhs, "AMX path must match RHS for identity matrix");

    let usage_after = telemetry::WIEDEMANN_USAGE.get();
    let amx_after = telemetry::WIEDEMANN_AMX_OPS.get();

    assert!(usage_after >= usage_before + 1, "usage counter should increase");
    assert!(amx_after >= amx_before + 1, "amx counter should increase");
}

#[test]
#[cfg(target_arch = "x86_64")]
fn matrix_multiply_avx512_matches_scalar_when_available() {
    if !(std::arch::is_x86_feature_detected!("avx512f")
        && std::arch::is_x86_feature_detected!("avx512bw")
        && std::arch::is_x86_feature_detected!("avx512vl")
        && std::arch::is_x86_feature_detected!("gfni"))
    {
        println!("AVX-512 GFNI not available; skipping test");
        return;
    }

    use rand::{Rng, SeedableRng};

    let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeed_cafe);
    let rows = 8usize;
    let cols = 8usize;
    let shared = 8usize;

    let mut a = vec![vec![0u8; shared]; rows];
    for row in &mut a {
        for val in row.iter_mut() {
            *val = rng.random();
        }
    }

    let mut b = vec![vec![0u8; cols]; shared];
    for row in &mut b {
        for val in row.iter_mut() {
            *val = rng.random();
        }
    }

    let mut scalar = vec![Vec::new(); rows];
    matrix_multiply_scalar(&a, &b, &mut scalar);

    let mut avx512 = vec![Vec::new(); rows];
    unsafe {
        matrix_multiply_avx512(&a, &b, &mut avx512);
    }

    assert_eq!(scalar, avx512, "AVX-512 GFNI result must match scalar reference");
}

#[test]
#[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
fn test_amx_matmul_matches_scalar() {
    if !std::arch::is_x86_feature_detected!("amx_int8")
        || !std::arch::is_x86_feature_detected!("amx_tile")
    {
        println!("AMX runtime support unavailable; skipping test");
        return;
    }

    use crate::simd::amx::matmul_gf256_amx;

    const ROWS: usize = 64;
    const COLS: usize = 64;

    let mut matrix = vec![0u8; ROWS * COLS];
    for r in 0..ROWS {
        for c in 0..COLS {
            matrix[r * COLS + c] = ((r * 29 + c * 7 + (r ^ c)) & 0xFF) as u8;
        }
    }
    let mut vector = vec![0u8; COLS];
    for c in 0..COLS {
        vector[c] = (c as u8).wrapping_mul(53).wrapping_add(11);
    }

    let mut amx_out = vec![0u8; ROWS];
    let mut scalar_out = vec![0u8; ROWS];

    unsafe { matmul_gf256_amx(&matrix, &vector, &mut amx_out, ROWS, COLS, 1) };

    for r in 0..ROWS {
        let mut acc = 0u8;
        for c in 0..COLS {
            let a = matrix[r * COLS + c];
            let b = vector[c];
            if a != 0 && b != 0 {
                acc ^= gf_tables::gf_mul_table(a, b);
            }
        }
        scalar_out[r] = acc;
    }

    assert_eq!(amx_out, scalar_out, "AMX matmul must match scalar reference");
}

#[test]
fn test_streaming_emit_every_n() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "2");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    for i in 0..5u64 {
        let pkt = mk_src_packet(1 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), 2, "expected 2 streaming repair packets");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k_stream, "G8 coeff len == k in streaming");
    }
}

#[test]
fn test_streaming_env_cached() {
    // Set before construction to 3; then change to 1 after construction.
    // Behavior should remain every 3 due to caching in AdaptiveFec::new.
    let _env_lock = acquire_env_lock();
    let _g1 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "3");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    // Change env after construction; should not affect cached value
    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");

    let mut q = VecDeque::new();
    for i in 0..6u64 {
        let pkt = mk_src_packet(500 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), 2, "should emit every 3 packets despite env change");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k_stream, "G8 coeff len == k in streaming");
    }
}

#[test]
fn test_streaming_env_snapshot_is_per_instance() {
    let _env_lock = acquire_env_lock();
    let _g1 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "3");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };
    let mut first = AdaptiveFec::new(cfg.clone());

    let mut q = VecDeque::new();
    for i in 0..2u64 {
        let pkt = mk_src_packet(700 + i, 100, &pool);
        for pkt in first.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), 0, "first instance should still wait for 3 packets");

    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let mut second = AdaptiveFec::new(cfg);

    for i in 0..4u64 {
        let pkt = mk_src_packet(800 + i, 100, &pool);
        for pkt in first.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), 2, "first instance must keep the original every-3 snapshot");

    for i in 0..2u64 {
        let pkt = mk_src_packet(900 + i, 100, &pool);
        for pkt in second.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), 2, "second instance must observe the new every-1 snapshot");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k_stream, "G8 coeff len == k in streaming");
    }
}

#[test]
fn test_observer_streaming_interval_snapshot_is_per_instance() {
    let _env_lock = acquire_env_lock();

    let _g1 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "6");
    let first = FecTransportObserver::new();

    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "2");
    let second = FecTransportObserver::new();

    assert_eq!(first.ambient.base_stream_interval, 6);
    assert_eq!(second.ambient.base_stream_interval, 2);
}

#[test]
fn test_observer_sync_runtime_hints_only_pushes_fec_owned_deltas() {
    let mut cfg = crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
        .expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = crate::transport::ConnectionId::from_ref(&[7u8; 8]);
    let mut conn = crate::transport::packet::connect(None, scid.as_ref(), local, peer, &mut cfg)
        .expect("connect");
    let observer = FecTransportObserver::new();

    conn.set_ack_eliciting_threshold(9);
    conn.set_external_pacing_for_test(true);
    crate::brain::FEC_REDUNDANCY_PPM.store(180_000, std::sync::atomic::Ordering::Relaxed);

    observer.sync_runtime_hints(&mut conn);
    let delta = conn.take_fec_control_delta();

    assert_eq!(conn.ack_eliciting_threshold(), 9);
    assert!(conn.external_pacing_enabled());
    assert_eq!(delta.redundancy_ppm, Some(180_000));
    assert_eq!(delta.stream_every, None);
    assert!(!delta.force_streaming);

    observer.sync_runtime_hints(&mut conn);
    let delta = conn.take_fec_control_delta();
    assert_eq!(delta.redundancy_ppm, None);
}

#[test]
fn test_observer_profile_policy_prefers_explicit_override() {
    let policy = FecObserverProfilePolicy::from_sources(
        Some("server"),
        FecObserverPlatformHints { mobile_os: true, containerized_server: true },
    );

    assert!(matches!(policy, FecObserverProfilePolicy::Explicit(TransportProfile::Server)));
}

#[test]
fn test_observer_profile_policy_uses_platform_hints_without_override() {
    let mobile = FecObserverProfilePolicy::from_sources(
        None,
        FecObserverPlatformHints { mobile_os: true, containerized_server: false },
    );
    let server = FecObserverProfilePolicy::from_sources(
        None,
        FecObserverPlatformHints { mobile_os: false, containerized_server: true },
    );
    let desktop = FecObserverProfilePolicy::from_sources(None, FecObserverPlatformHints::default());

    assert!(matches!(mobile, FecObserverProfilePolicy::Ambient(TransportProfile::Mobile)));
    assert!(matches!(server, FecObserverProfilePolicy::Ambient(TransportProfile::Server)));
    assert!(matches!(desktop, FecObserverProfilePolicy::Ambient(TransportProfile::Desktop)));
}

#[test]
fn test_runtime_plan_uses_explicit_compute_profile_snapshot() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();
    let cfg = FecConfig { initial_mode: FecMode::Streaming, ..Default::default() };

    let slow_ambient = FecAmbientInputs::new(
        Arc::clone(&pool),
        FecComputeProfile::new(CpuProfile::ARM_A1a, false),
        FecRuntimePolicy::detect(),
    );
    let fast_ambient = FecAmbientInputs::new(
        pool,
        FecComputeProfile::new(CpuProfile::ARM_A1a, true),
        FecRuntimePolicy::detect(),
    );

    let slow_plan = FecRuntimePlan::resolve(&cfg, &slow_ambient);
    let fast_plan = FecRuntimePlan::resolve(&cfg, &fast_ambient);

    assert_eq!(slow_plan.base_stream_every, 4);
    assert_eq!(fast_plan.base_stream_every, 2);
}

#[test]
fn test_decoder_policy_snapshot_is_per_instance() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();

    let _g1 = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "gauss");
    let first = Decoder8::new(8, Arc::clone(&pool));

    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "auto");
    let second = Decoder8::new(8, pool);

    assert_eq!(first.decoder_policy, "gauss");
    assert_eq!(second.decoder_policy, "auto");
}

#[test]
fn test_fountain_symbol_snapshot_is_per_instance() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();

    let _g1 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "1200");
    let first_encoder = super::internal::EncoderVariant::new(FecMode::Fountain, 8, 8);
    let first_decoder =
        super::internal::DecoderVariant::new(FecMode::Fountain, 8, Arc::clone(&pool));

    let _g2 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "900");
    let second_encoder = super::internal::EncoderVariant::new(FecMode::Fountain, 8, 8);
    let second_decoder = super::internal::DecoderVariant::new(FecMode::Fountain, 8, pool);

    match first_encoder {
        super::internal::EncoderVariant::Fountain(enc) => assert_eq!(enc.symbol_size(), 1200),
        _ => panic!("expected fountain encoder"),
    }
    match first_decoder {
        super::internal::DecoderVariant::Fountain(dec) => assert_eq!(dec.symbol_size(), 1200),
        _ => panic!("expected fountain decoder"),
    }
    match second_encoder {
        super::internal::EncoderVariant::Fountain(enc) => assert_eq!(enc.symbol_size(), 900),
        _ => panic!("expected fountain encoder"),
    }
    match second_decoder {
        super::internal::DecoderVariant::Fountain(dec) => assert_eq!(dec.symbol_size(), 900),
        _ => panic!("expected fountain decoder"),
    }
}

#[test]
fn test_transition_decoder_uses_instance_policy_snapshot() {
    let _env_lock = acquire_env_lock();
    let _g1 = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "gauss");
    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });

    let _g3 = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "auto");
    fec.transition_to_mode(FecMode::Normal);

    let transition_decoder =
        fec.transition_decoder.as_ref().expect("transition decoder must exist").lock();
    assert_eq!(transition_decoder.first_block_decoder_policy(), Some("gauss"));
}

#[test]
fn test_transition_fountain_uses_instance_policy_snapshot() {
    let _env_lock = acquire_env_lock();
    let _g1 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "1200");
    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });

    let _g3 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "900");
    fec.transition_to_mode(FecMode::Fountain);

    let transition_encoder =
        fec.transition_encoder.as_ref().expect("transition encoder must exist").lock();
    assert_eq!(transition_encoder.first_block_fountain_symbol_size(), Some(1200));

    let transition_decoder =
        fec.transition_decoder.as_ref().expect("transition decoder must exist").lock();
    assert_eq!(transition_decoder.first_block_fountain_symbol_size(), Some(1200));
}

#[test]
fn test_batch_normal_seq_counts() {
    // QUICFUSCATE_FEC_PARALLEL is set for benchmarking (main.rs run_fec_bench) but
    // not read by AdaptiveFec::new - kept here for env isolation consistency.
    let _env_lock = acquire_env_lock();
    let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k = 8usize; // Normal mode window (k)
    windows.insert(FecMode::Normal, k);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    for i in 0..k as u64 {
        let pkt = mk_src_packet(100 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), (k as f32 * 1.15).ceil() as usize - k, "n-k repairs");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode");
    }
}

#[test]
fn test_batch_normal_par_counts() {
    // QUICFUSCATE_FEC_PARALLEL is set for benchmarking (main.rs run_fec_bench) but
    // not read by AdaptiveFec::new - kept here for env isolation consistency.
    let _env_lock = acquire_env_lock();
    let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k = 8usize; // Normal mode window (k)
    windows.insert(FecMode::Normal, k);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    for i in 0..k as u64 {
        let pkt = mk_src_packet(200 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    assert_eq!(repairs.len(), (k as f32 * 1.15).ceil() as usize - k, "n-k repairs (parallel)");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode (parallel)");
    }
}

#[test]
fn test_batch_extreme_gf16_coeff_len() {
    // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k = 8usize; // Extreme mode window (k)
    windows.insert(FecMode::Extreme, k);

    let cfg =
        FecConfig { initial_mode: FecMode::Extreme, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    for i in 0..k as u64 {
        let pkt = mk_src_packet(300 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }

    let repairs = drain_repairs(&mut q);
    let expected = ((k as f32) * 2.0).ceil() as usize - k; // n - k with ratio 2.0
    assert_eq!(repairs.len(), expected, "Extreme mode should emit n-k repairs");
    for rp in repairs {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, 2 * k, "GF16 coeff len == 2*k in Extreme mode");
    }
}

#[test]
fn test_batch_window_cleared_no_extra_repairs() {
    // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k = 8usize;
    windows.insert(FecMode::Normal, k);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    // Fill one full batch to trigger repair emission and window clear
    for i in 0..k as u64 {
        let pkt = mk_src_packet(400 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs1 = drain_repairs(&mut q);
    let expected = (k as f32 * 1.15).ceil() as usize - k;
    assert_eq!(repairs1.len(), expected, "n-k repairs in batch");

    // After clear, fewer than k new packets must not emit repairs
    let pkt2 = mk_src_packet(4999, 100, &pool);
    for pkt in fec.on_send(pkt2) {
        q.push_back(pkt);
    }
    let repairs2 = drain_repairs(&mut q);
    assert_eq!(repairs2.len(), 0, "no extra repairs after window clear and <k new packets");
}

#[test]
fn test_decoder_elimination_paths() {
    let pool = crate::optimize::global_pool();
    let k = 8;

    // Test Gauss elimination (forced via ENV)
    std::env::set_var("QUICFUSCATE_FEC_DECODER", "gauss");
    let mut decoder_gauss = Decoder8::new(k, Arc::clone(&pool));

    // Add k-1 systematic packets
    for i in 0..k - 1 {
        let mut data = pool.alloc();
        data[0] = i as u8;
        let pkt = FecPacket::new(i as u64, Some(data), 1, true, None, 0, Arc::clone(&pool));
        decoder_gauss.take_packet(pkt);
    }

    // Add one repair packet anchored to base_id = k-1 so sids map to 0..k-1
    let mut repair_data = pool.alloc();
    repair_data[0] = 42; // arbitrary byte; single-equation solve expected
    let mut coeffs = pool.alloc();
    for j in 0..k {
        coeffs[j] = (j + 1) as u8;
    }
    let repair = FecPacket::new(
        (k as u64) - 1,
        Some(repair_data),
        1,
        false,
        Some(coeffs),
        k,
        Arc::clone(&pool),
    );
    decoder_gauss.take_packet(repair);

    // Should be able to decode
    assert!(decoder_gauss.is_complete());

    // Test Wiedemann (if feature enabled)
    #[cfg(feature = "internal_wiedemann")]
    {
        std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
        let mut decoder_wm = Decoder8::new(k, Arc::clone(&pool));

        // Same setup
        for i in 0..k - 1 {
            let mut data = pool.alloc();
            data[0] = i as u8;
            let pkt = FecPacket::new(i as u64, Some(data), 1, true, None, 0, Arc::clone(&pool));
            decoder_wm.take_packet(pkt);
        }

        let mut repair_data = pool.alloc();
        repair_data[0] = 42;
        let mut coeffs = pool.alloc();
        for j in 0..k {
            coeffs[j] = (j + 1) as u8;
        }
        let repair =
            FecPacket::new(100, Some(repair_data), 1, false, Some(coeffs), k, Arc::clone(&pool));
        decoder_wm.take_packet(repair);

        assert!(decoder_wm.is_complete());
    }

    // Test auto mode with large k (should prefer Wiedemann if available)
    std::env::set_var("QUICFUSCATE_FEC_DECODER", "auto");
    let large_k = 128;
    let _decoder_auto = Decoder8::new(large_k, Arc::clone(&pool));
    // Construction succeeded; additional properties are validated in dedicated decoder tests.
}

#[test]
fn test_batch_toggle_parallel_between_batches() {
    // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _gp1 = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k = 8usize; // Normal mode window (k)
    windows.insert(FecMode::Normal, k);

    let cfg =
        FecConfig { initial_mode: FecMode::Normal, window_sizes: windows, ..Default::default() };
    let mut fec = AdaptiveFec::new(cfg);
    let mut q = VecDeque::new();

    // Batch 1 (sequential)
    for i in 0..k as u64 {
        let pkt = mk_src_packet(600 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs1 = drain_repairs(&mut q);
    let expected = (k as f32 * 1.15).ceil() as usize - k;
    assert_eq!(repairs1.len(), expected, "n-k repairs in batch 1 (seq)");

    // Toggle to parallel for next batch
    drop(_gp1);
    let _gp2 = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "1");

    // Batch 2 (parallel)
    for i in 0..k as u64 {
        let pkt = mk_src_packet(700 + i, 100, &pool);
        for pkt in fec.on_send(pkt) {
            q.push_back(pkt);
        }
    }
    let repairs2 = drain_repairs(&mut q);
    assert_eq!(repairs2.len(), expected, "n-k repairs in batch 2 (par)");

    // Properties identical
    for rp in repairs1.into_iter().chain(repairs2) {
        assert!(!rp.is_systematic);
        assert!(rp.coefficients.is_some());
        assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode");
    }
}

#[test]
fn test_streaming_tetrys_style_recovery_single_loss() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    // Independent sender/receiver to mirror real flow
    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

    // Drop the last source in the window to simplify decoder window alignment
    let missing_id = 1 + (k_stream as u64) - 1;

    for i in 0..k_stream as u64 {
        let id = 1 + i;
        let pkt_tx = mk_src_packet(id, 100, &pool);
        for pkt in sender.on_send(pkt_tx) {
            tx_q.push_back(pkt);
        }

        // Receiver gets all but the missing packet (fresh instance for receiver)
        if id != missing_id {
            let pkt_rx = mk_src_packet(id, 100, &pool);
            let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
            rx_recovered_total.extend(res);
        }

        // Deliver any streaming repairs generated so far
        let mut tmp = VecDeque::new();
        std::mem::swap(&mut tx_q, &mut tmp);
        while let Some(pkt) = tmp.pop_front() {
            if !pkt.is_systematic {
                let res = receiver.on_receive(pkt).expect("receiver accept repair");
                rx_recovered_total.extend(res);
            }
        }
    }

    // Verify that the single missing source was recovered
    assert!(
        rx_recovered_total.iter().any(|p| p.id == missing_id && p.len() == 100),
        "expected recovery of the single lost source packet"
    );
}

#[test]
fn test_streaming_tetrys_multi_loss_uniform_recovery() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 10usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

    // Choose two losses that are spaced apart but near the tail to keep them in-window
    let missing_a = 1 + (k_stream as u64) - 3; // k-2
    let missing_b = 1 + (k_stream as u64) - 1; // k-0

    for i in 0..k_stream as u64 {
        let id = 1 + i;
        let pkt_tx = mk_src_packet(id, 100, &pool);
        for pkt in sender.on_send(pkt_tx) {
            tx_q.push_back(pkt);
        }

        // Deliver source if not dropped
        if id != missing_a && id != missing_b {
            let pkt_rx = mk_src_packet(id, 100, &pool);
            let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
            rx_recovered_total.extend(res);
        }

        // Deliver repairs as they are generated
        let mut tmp = VecDeque::new();
        std::mem::swap(&mut tx_q, &mut tmp);
        while let Some(pkt) = tmp.pop_front() {
            if !pkt.is_systematic {
                let res = receiver.on_receive(pkt).expect("receiver accept repair");
                rx_recovered_total.extend(res);
            }
        }
    }

    // Verify both missing packets recovered
    let has_a = rx_recovered_total.iter().any(|p| p.id == missing_a && p.len() == 100);
    let has_b = rx_recovered_total.iter().any(|p| p.id == missing_b && p.len() == 100);
    assert!(has_a && has_b, "expected recovery of both non-consecutive lost sources");
}

#[test]
fn test_streaming_tetrys_burst_loss_recovery() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 12usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

    // Drop a burst of three at the tail: k-3, k-2, k-1
    let miss1 = 1 + (k_stream as u64) - 3;
    let miss2 = 1 + (k_stream as u64) - 2;
    let miss3 = 1 + (k_stream as u64) - 1;

    for i in 0..k_stream as u64 {
        let id = 1 + i;
        let pkt_tx = mk_src_packet(id, 100, &pool);
        for pkt in sender.on_send(pkt_tx) {
            tx_q.push_back(pkt);
        }

        if id != miss1 && id != miss2 && id != miss3 {
            let pkt_rx = mk_src_packet(id, 100, &pool);
            let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
            rx_recovered_total.extend(res);
        }

        let mut tmp = VecDeque::new();
        std::mem::swap(&mut tx_q, &mut tmp);
        while let Some(pkt) = tmp.pop_front() {
            if !pkt.is_systematic {
                let res = receiver.on_receive(pkt).expect("receiver accept repair");
                rx_recovered_total.extend(res);
            }
        }
    }

    // Verify all three missing packets recovered
    let has1 = rx_recovered_total.iter().any(|p| p.id == miss1 && p.len() == 100);
    let has2 = rx_recovered_total.iter().any(|p| p.id == miss2 && p.len() == 100);
    let has3 = rx_recovered_total.iter().any(|p| p.id == miss3 && p.len() == 100);
    assert!(has1 && has2 && has3, "expected recovery of burst of three lost sources");
}

#[test]
fn test_streaming_rank_progression_monotonic() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 9usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let mut seen_ids: std::collections::HashSet<u64> = Default::default();
    let mut monotonic: Vec<usize> = Vec::new();

    // Drop two sources near the tail
    let miss_a = 1 + (k_stream as u64) - 2;
    let miss_b = 1 + (k_stream as u64) - 1;

    for i in 0..k_stream as u64 {
        let id = 1 + i;
        let pkt_tx = mk_src_packet(id, 100, &pool);
        for pkt in sender.on_send(pkt_tx) {
            tx_q.push_back(pkt);
        }

        if id != miss_a && id != miss_b {
            let pkt_rx = mk_src_packet(id, 100, &pool);
            for p in receiver.on_receive(pkt_rx).expect("rx src") {
                seen_ids.insert(p.id);
            }
        }

        // Deliver repairs and observe cumulative recovered size progression
        let mut tmp = VecDeque::new();
        std::mem::swap(&mut tx_q, &mut tmp);
        while let Some(pkt) = tmp.pop_front() {
            if !pkt.is_systematic {
                for p in receiver.on_receive(pkt).expect("rx repair") {
                    seen_ids.insert(p.id);
                }
                monotonic.push(seen_ids.len());
            }
        }
    }

    // Check monotonic non-decreasing sequence
    for w in monotonic.windows(2) {
        if let [a, b] = w {
            assert!(b >= a, "recovered set size should be non-decreasing");
        }
    }

    // Final set includes both missing sources
    assert!(
        seen_ids.contains(&miss_a) && seen_ids.contains(&miss_b),
        "final recovered set should include both missing sources"
    );
}

#[test]
fn test_streaming_dedup_across_calls() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 8usize;
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let missing_id = 42u64; // deterministic choice beyond initial window base

    let mut seen_missing = 0usize;

    // Send a sequence with periodic repairs; always drop "missing_id" source
    for i in 1..(k_stream as u64 * 4) {
        let id = i;
        let pkt_tx = mk_src_packet(id, 80, &pool);
        for pkt in sender.on_send(pkt_tx) {
            tx_q.push_back(pkt);
        }

        // deliver source if not the missing one
        if id != missing_id {
            let pkt_rx = mk_src_packet(id, 80, &pool);
            for p in receiver.on_receive(pkt_rx).expect("rx src") {
                if p.id == missing_id {
                    seen_missing += 1;
                }
            }
        }

        // deliver any generated repairs immediately
        let mut repairs = VecDeque::new();
        std::mem::swap(&mut tx_q, &mut repairs);
        while let Some(rp) = repairs.pop_front() {
            if !rp.is_systematic {
                for p in receiver.on_receive(rp).expect("rx repair") {
                    if p.id == missing_id {
                        seen_missing += 1;
                    }
                }
            }
        }
    }

    // Dedup guarantee: even if decoder could surface the same id across calls, we emit it once.
    assert!(
        seen_missing <= 1,
        "recovered packet with same id must be emitted at most once, got {}",
        seen_missing
    );
}

#[test]
fn test_streaming_dedup_window_bounding() {
    // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
    let _env_lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
    let pool = make_pool();

    let mut windows = HashMap::new();
    let k_stream = 4usize; // small window, bound becomes max(4*k, 256) = 256
    windows.insert(FecMode::Streaming, k_stream);

    let cfg =
        FecConfig { initial_mode: FecMode::Streaming, window_sizes: windows, ..Default::default() };

    let mut sender = AdaptiveFec::new(cfg.clone());
    let mut receiver = AdaptiveFec::new(cfg);

    let mut tx_q = VecDeque::new();
    let bound = 256usize; // max(4*4, 256)

    // Generate > bound unique recoveries by repeatedly dropping the last id of each k-window
    let total_iters = bound + 32; // exceed bound to force eviction
    for batch in 0..total_iters {
        let base = (batch as u64) * (k_stream as u64);
        let miss = base + (k_stream as u64); // drop last in this batch
        for j in 1..=k_stream as u64 {
            let id = base + j;
            let pkt_tx = mk_src_packet(id, 60, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }
            if id != miss {
                let pkt_rx = mk_src_packet(id, 60, &pool);
                let _ = receiver.on_receive(pkt_rx).expect("rx src");
            }
            // deliver repairs
            let mut repairs = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut repairs);
            while let Some(rp) = repairs.pop_front() {
                if !rp.is_systematic {
                    let _ = receiver.on_receive(rp).expect("rx repair");
                }
            }
        }
    }

    // Test-only: the emitted cache length should not exceed bound
    #[cfg(test)]
    fn emitted_len(fec: &AdaptiveFec) -> usize {
        fec.emitted_order.len()
    }
    let len = emitted_len(&receiver);
    assert!(len <= bound, "emitted cache should be bounded ({} <= {})", len, bound);
}

#[test]
fn test_env_guard_unset_functionality() {
    let test_key = "QUICFUSCATE_TEST_UNSET";

    // Set initial value
    std::env::set_var(test_key, "initial_value");
    assert_eq!(std::env::var(test_key).unwrap(), "initial_value");

    // Test unset() method
    {
        let _guard = EnvGuard::unset(test_key);
        assert!(std::env::var(test_key).is_err()); // Should be unset
    }
    // Guard drops, should restore original value
    assert_eq!(std::env::var(test_key).unwrap(), "initial_value");

    // Cleanup
    std::env::remove_var(test_key);
}

// TODO-392: regression guard — cloning a source (systematic) FEC packet must
// share the payload buffer via Arc (refcount bump), never copy the datagram.
// The send hot path relies on this to forward the packet to the wire while the
// encoder retains a handle for repair generation, without a full-payload copy.
#[test]
fn source_packet_clone_shares_buffer_via_arc() {
    let pool = crate::optimize::global_pool();
    let mut data = pool.alloc();
    for (i, b) in data.iter_mut().enumerate() {
        *b = i as u8;
    }
    let pkt = FecPacket::new(42, Some(data), 128, true, None, 0, Arc::clone(&pool));

    let buf_ref = pkt.data.as_ref().expect("source packet has data buffer");
    let count_before = buf_ref.strong_count();
    assert_eq!(count_before, 1, "fresh packet owns a single buffer handle");

    let pkt_clone = pkt.clone();
    let count_after = buf_ref.strong_count();
    assert_eq!(
        count_after,
        count_before + 1,
        "clone must bump the Arc refcount, not allocate a new buffer"
    );

    // The cloned packet must observe the same payload bytes (shared buffer).
    let clone_ref = pkt_clone.data.as_ref().expect("clone retains data buffer");
    assert_eq!(clone_ref.bytes(128), buf_ref.bytes(128));

    // Dropping the clone must return to the original refcount (no leak/double-free).
    drop(pkt_clone);
    assert_eq!(buf_ref.strong_count(), count_before);
}
