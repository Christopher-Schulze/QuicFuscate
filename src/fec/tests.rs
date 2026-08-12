use super::test_support::*;
use super::{
    continuous_fec_target, fec_simd_level_for_features, gf16_mul_slice,
    gf16_vector_threshold_words_for_features, low_cost_block_uses_gf4, matrix_multiply_scalar,
    mode_for_target, target_from_mode, target_rank, AdaptiveFec, CpuProfile, Decoder8,
    FecAmbientInputs, FecBackendFamily, FecComputeProfile, FecConfig, FecMode,
    FecObserverPlatformHints, FecObserverProfilePolicy, FecPacket, FecRuntimePlan,
    FecRuntimePolicy, FecTransportObserver, MatrixError, SimdLevel, TransportProfile,
    GF16_AVX2_MIN_WORDS, GF16_AVX512_MIN_WORDS, GF16_NEON_MIN_WORDS, GF16_SSE2_MIN_WORDS,
    GF16_SVE2_MIN_WORDS, GF16_VBMI2_MIN_WORDS,
};
use crate::{fec::gf_tables, optimize::telemetry};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[test]
fn matrix_multiply_rejects_malformed_shapes() {
    let mut result = vec![vec![0u8; 1]];
    assert_eq!(matrix_multiply_scalar(&[], &[vec![1]], &mut result), Err(MatrixError::EmptyInput));
    assert_eq!(
        matrix_multiply_scalar(&[vec![1], vec![]], &[vec![1]], &mut result),
        Err(MatrixError::RaggedA)
    );
    assert_eq!(
        matrix_multiply_scalar(&[vec![1, 2]], &[vec![1], vec![2, 3]], &mut result),
        Err(MatrixError::RaggedB)
    );
    assert_eq!(
        matrix_multiply_scalar(&[vec![1]], &[vec![1]], &mut [vec![0], vec![0]]),
        Err(MatrixError::DimensionMismatch)
    );
    assert_eq!(
        matrix_multiply_scalar(&[vec![1]], &[vec![1]], &mut [vec![0, 0], vec![0]]),
        Err(MatrixError::RaggedResult)
    );

    let mut valid = vec![vec![0u8; 1]];
    matrix_multiply_scalar(&[vec![1, 2]], &[vec![3], vec![4]], &mut valid)
        .expect("valid matrix dimensions");
    assert_eq!(valid, vec![vec![11]]);
}

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
    let target = target_from_mode(FecMode::Light, 15);
    assert!(low_cost_block_uses_gf4(target));
    assert_eq!(super::internal::ModeManager::params_for(FecMode::Light, 15), (15, 16));
    let encoder = super::internal::EncoderVariant::new(FecMode::Light, 15, 16);
    let decoder = super::internal::DecoderVariant::new(
        FecMode::Light,
        15,
        Arc::clone(&crate::optimize::global_pool()),
    );
    assert!(matches!(encoder, super::internal::EncoderVariant::GF4(_)));
    assert!(matches!(decoder, super::internal::DecoderVariant::GF4(_)));
}

#[test]
fn test_light_wire_profile_advertises_exact_single_repair_capacity() {
    let _env_lock = acquire_env_lock();
    let _interleave = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");
    let config = FecConfig { initial_mode: FecMode::Light, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    let profile = fec.wire_profile(9).expect("Light wire profile");

    assert_eq!(profile.codec, super::wire::WireCodec::Gf4);
    assert_eq!(profile.source_count, 15);
    assert_eq!(profile.total_count, 16);
    assert_eq!(profile.interleave_depth, 1);
}

#[test]
fn test_backend_family_mapping_uses_gf8_for_sub_256_heavy_blocks() {
    let encoder = super::internal::EncoderVariant::new(FecMode::Strong, 128, 256);
    let decoder = super::internal::DecoderVariant::new(
        FecMode::Strong,
        128,
        Arc::clone(&crate::optimize::global_pool()),
    );
    assert_eq!(encoder.backend_kind(), "gf8");
    assert_eq!(decoder.backend_kind(), "gf8");
}

#[test]
fn test_gf16_encoder_uses_expected_cauchy_coefficients() {
    let pool = crate::optimize::global_pool();
    let mut encoder = super::Encoder16::new(4, 8);
    for id in 0..4 {
        encoder.take_packet(mk_src_packet(id, 64, &pool));
    }

    let repair = encoder.generate_repair_packet(2, &pool).expect("repair packet");
    let coeffs = repair.coefficients.as_ref().expect("gf16 repair coefficients");
    assert_eq!(repair.coeff_len, 8);
    for j in 0..4 {
        let expected =
            super::gf_tables::gf16_inv((j as u16) ^ ((4usize + 2usize) as u16)).to_be_bytes();
        assert_eq!(&coeffs[2 * j..2 * j + 2], &expected);
    }
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
fn test_wire_codec_selection_comes_from_block_width() {
    assert_eq!(super::wire::codec_for_mode(FecMode::Strong, 128), Ok(super::wire::WireCodec::Gf8));
    assert_eq!(super::wire::codec_for_mode(FecMode::Ultra, 256), Ok(super::wire::WireCodec::Gf16));
}

#[test]
fn test_product_fec_default_is_auto_and_stream_every_is_explicit() {
    let cfg = FecConfig::product_default();
    assert_eq!(cfg.initial_mode, FecMode::Zero);
    assert_eq!(cfg.window_sizes.get(&FecMode::Zero), Some(&0));
    assert_eq!(cfg.configured_stream_every, Some(5));
}

#[test]
fn standalone_fec_parser_rejects_unknown_mode_values() {
    let unknown_initial = FecConfig::from_toml(
        r#"
[adaptive_fec]
initial_mode = "norml"
"#,
    )
    .expect_err("unknown initial mode must be rejected");
    assert!(unknown_initial.to_string().contains("initial_mode"));
    assert!(unknown_initial.to_string().contains("norml"));

    let unknown_window_mode = FecConfig::from_toml(
        r#"
[adaptive_fec]
[[adaptive_fec.modes]]
name = "norml"
w0 = 64
"#,
    )
    .expect_err("unknown mode entry must be rejected");
    assert!(unknown_window_mode.to_string().contains("modes[].name"));
    assert!(unknown_window_mode.to_string().contains("norml"));

    let unknown_field = FecConfig::from_toml(
        r#"
[adaptive_fec]
unexpected = true
"#,
    )
    .expect_err("unknown standalone FEC field must be rejected");
    assert!(unknown_field.to_string().contains("unexpected"));
}

#[test]
fn standalone_fec_parser_accepts_all_public_modes_and_preserves_zero_stream_interval() {
    let config = FecConfig::from_toml(
        r#"
[adaptive_fec]
control_policy = "auto"
initial_mode = "fountain"
stream_every = 0

[[adaptive_fec.modes]]
name = "ultra"
w0 = 1024

[[adaptive_fec.modes]]
name = "fountain"
w0 = 128
"#,
    )
    .expect("valid custom FEC configuration");

    assert_eq!(config.initial_mode, FecMode::Fountain);
    assert_eq!(config.window_sizes.get(&FecMode::Ultra), Some(&1024));
    assert_eq!(config.window_sizes.get(&FecMode::Fountain), Some(&128));
    assert_eq!(config.configured_stream_every, Some(0));
    let error = config.validate().expect_err("stream_every=0 must fail validation");
    assert!(error.contains("configured_stream_every"));
}

#[test]
fn standalone_fec_validation_rejects_invalid_numeric_and_window_values() {
    let invalid_lambda = FecConfig { lambda: 1.1, ..FecConfig::default() };
    assert!(invalid_lambda.validate().unwrap_err().contains("lambda"));

    let invalid_burst_window = FecConfig { burst_window: 0, ..FecConfig::default() };
    assert!(invalid_burst_window.validate().unwrap_err().contains("burst_window"));

    let invalid_kalman = FecConfig { kalman_q: 0.0, ..FecConfig::default() };
    assert!(invalid_kalman.validate().unwrap_err().contains("kalman_q"));

    let mut zero_mode_window = FecConfig::default();
    zero_mode_window.window_sizes.insert(FecMode::Zero, 1);
    assert!(zero_mode_window.validate().unwrap_err().contains("window_sizes.Zero"));

    let mut empty_mode_window = FecConfig::default();
    empty_mode_window.window_sizes.insert(FecMode::Normal, 0);
    assert!(empty_mode_window.validate().unwrap_err().contains("window_sizes.Normal"));

    let mut oversized_window = FecConfig::default();
    oversized_window.window_sizes.insert(FecMode::Normal, 2049);
    assert!(oversized_window.validate().unwrap_err().contains("2048"));

    let mut oversized_fountain_window = FecConfig::default();
    oversized_fountain_window.window_sizes.insert(FecMode::Fountain, 129);
    assert!(oversized_fountain_window.validate().unwrap_err().contains("Fountain"));
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
fn test_simd_dispatch_selection_matches_feature_matrix_and_thresholds() {
    use crate::optimize::CpuFeatures;

    let mut vbmi2 =
        CpuFeatures { avx512f: true, avx512bw: true, avx512vbmi2: true, ..CpuFeatures::default() };
    assert_eq!(fec_simd_level_for_features(&vbmi2), SimdLevel::Avx512Vbmi2);
    assert_eq!(gf16_vector_threshold_words_for_features(&vbmi2), GF16_VBMI2_MIN_WORDS);

    vbmi2.avx512vbmi2 = false;
    vbmi2.avx512vbmi = true;
    assert_eq!(fec_simd_level_for_features(&vbmi2), SimdLevel::Avx512Vbmi);
    assert_eq!(gf16_vector_threshold_words_for_features(&vbmi2), GF16_AVX512_MIN_WORDS);

    let avx2 = CpuFeatures { avx2: true, ..CpuFeatures::default() };
    assert_eq!(fec_simd_level_for_features(&avx2), SimdLevel::Avx2);
    assert_eq!(gf16_vector_threshold_words_for_features(&avx2), GF16_AVX2_MIN_WORDS);

    let sse2 = CpuFeatures { sse2: true, ..CpuFeatures::default() };
    assert_eq!(fec_simd_level_for_features(&sse2), SimdLevel::Sse2);
    assert_eq!(gf16_vector_threshold_words_for_features(&sse2), GF16_SSE2_MIN_WORDS);

    let sve2 = CpuFeatures { sve2: true, ..CpuFeatures::default() };
    assert_eq!(fec_simd_level_for_features(&sve2), SimdLevel::Sve2);
    assert_eq!(gf16_vector_threshold_words_for_features(&sve2), GF16_SVE2_MIN_WORDS);

    let neon = CpuFeatures { neon: true, ..CpuFeatures::default() };
    assert_eq!(fec_simd_level_for_features(&neon), SimdLevel::Neon);
    assert_eq!(gf16_vector_threshold_words_for_features(&neon), GF16_NEON_MIN_WORDS);

    let incomplete_vbmi2 =
        CpuFeatures { avx512f: true, avx512vbmi2: true, ..CpuFeatures::default() };
    assert!(
        !incomplete_vbmi2.simd_dispatch_matrix().avx512_vbmi2,
        "VBMI2 must require AVX512F, AVX512BW, and AVX512VBMI2"
    );
    assert_eq!(fec_simd_level_for_features(&incomplete_vbmi2), SimdLevel::None);
    assert_eq!(gf16_vector_threshold_words_for_features(&incomplete_vbmi2), usize::MAX);

    let scalar = CpuFeatures::default();
    assert_eq!(fec_simd_level_for_features(&scalar), SimdLevel::None);
    assert_eq!(gf16_vector_threshold_words_for_features(&scalar), usize::MAX);
}

#[test]
fn test_gf16_slice_dispatch_clamps_unequal_lengths_and_tails() {
    let coefficient = 0x7a31;
    let gf16_mul_reference = |a: u16, b: u16| {
        let mut multiplicand = a;
        let mut factor = b;
        let mut result = 0u16;
        while factor != 0 {
            if factor & 1 != 0 {
                result ^= multiplicand;
            }
            factor >>= 1;
            let carry = multiplicand & 0x8000 != 0;
            multiplicand <<= 1;
            if carry {
                multiplicand ^= 0x100b;
            }
        }
        result
    };
    for source_len in [0usize, 1, 2, 15, 16, 23, 24, 31, 32, 63, 64, 95, 96] {
        let destination_len = source_len.saturating_sub(3).max(1);
        let source: Vec<u16> =
            (0..source_len).map(|index| (index as u16).wrapping_mul(0x219d) ^ 0xa55a).collect();
        let initial: Vec<u16> = (0..destination_len)
            .map(|index| (index as u16).wrapping_mul(0x1041) ^ 0x5aa5)
            .collect();
        let mut actual = initial.clone();
        let mut expected = initial;
        let len = source.len().min(expected.len());
        for index in 0..len {
            expected[index] ^= gf16_mul_reference(coefficient, source[index]);
        }

        gf16_mul_slice(coefficient, &source, &mut actual);
        assert_eq!(actual, expected, "GF16 dispatch mismatch at source_len={source_len}");
    }
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
    let _env_lock = acquire_env_lock();
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
    super::gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(2, pool.clone());

    let matrix = vec![vec![1u8, 0u8], vec![0u8, 1u8]];
    let rhs = vec![5u8, 9u8];

    let usage_before = telemetry::WIEDEMANN_USAGE.get();
    let scalar_before = telemetry::WIEDEMANN_SCALAR_OPS.get();
    let krylov_before = telemetry::WIEDEMANN_KRYLOV_ALLOCS.get();
    let iteration_before = telemetry::WIEDEMANN_ITERATION_ALLOCS.get();
    let candidate_before = telemetry::WIEDEMANN_CANDIDATE_ALLOCS.get();
    let mut scratch = super::WiedemannScratch::from_matrix(&matrix, 2);

    let solution = decoder
        .solve_wiedemann_system(&matrix, &rhs, 2, &mut scratch)
        .expect("identity system should be solvable");

    assert_eq!(solution, rhs, "identity system must return RHS");

    let usage_after = telemetry::WIEDEMANN_USAGE.get();
    let scalar_after = telemetry::WIEDEMANN_SCALAR_OPS.get();
    let krylov_after = telemetry::WIEDEMANN_KRYLOV_ALLOCS.get();
    let iteration_after = telemetry::WIEDEMANN_ITERATION_ALLOCS.get();
    let candidate_after = telemetry::WIEDEMANN_CANDIDATE_ALLOCS.get();

    assert!(usage_after > usage_before, "usage counter should increase");
    assert!(scalar_after > scalar_before, "scalar counter should increase");
    assert!(krylov_after >= krylov_before + 3, "Krylov allocation accounting should increase");
    assert!(iteration_after > iteration_before, "iteration allocation accounting should increase");
    assert!(
        candidate_after >= candidate_before + 2,
        "candidate allocation accounting should increase"
    );
}

/// GF(256) matrix-vector product used as an independent reference in the solver tests.
fn wiedemann_reference_multiply(matrix: &[Vec<u8>], vector: &[u8]) -> Vec<u8> {
    matrix
        .iter()
        .map(|row| {
            row.iter().zip(vector.iter()).fold(0u8, |acc, (&coefficient, &value)| {
                acc ^ gf_tables::gf_mul_table(coefficient, value)
            })
        })
        .collect()
}

/// The core correctness contract. Before this, `solve_wiedemann_system` computed a Krylov
/// sequence and a minimal polynomial and then returned a copy of the right-hand side, so it was
/// only ever "right" when the matrix happened to be the identity.
#[test]
fn test_wiedemann_solves_non_identity_systems_where_solution_differs_from_rhs() {
    gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(8, pool);

    // Lower unitriangular with non-trivial off-diagonal entries: invertible over GF(256) by
    // construction, and far from a permutation of the right-hand side.
    let matrix = vec![
        vec![1u8, 0u8, 0u8, 0u8],
        vec![0x1Du8, 1u8, 0u8, 0u8],
        vec![0x8Eu8, 0x2Au8, 1u8, 0u8],
        vec![0x40u8, 0xB3u8, 0x77u8, 1u8],
    ];
    let expected = vec![0x11u8, 0x22u8, 0x33u8, 0x44u8];
    let rhs = wiedemann_reference_multiply(&matrix, &expected);
    assert_ne!(rhs, expected, "the fixture must not be a system whose solution equals its RHS");

    let mut scratch = super::WiedemannScratch::from_matrix(&matrix, 4);
    let solution = decoder
        .solve_wiedemann_system(&matrix, &rhs, 4, &mut scratch)
        .expect("a full-rank non-identity system must be solvable");

    assert_eq!(solution, expected, "solver must return the true solution, not the RHS");
    assert_eq!(
        wiedemann_reference_multiply(&matrix, &solution),
        rhs,
        "A x = b must hold byte for byte over GF(256)"
    );
}

/// A diagonal system with non-unit entries is the smallest case that distinguishes a real solve
/// from returning the right-hand side: every component is scaled by a known inverse.
#[test]
fn test_wiedemann_solves_diagonal_and_permutation_systems() {
    gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(8, pool);

    let diagonal = vec![vec![0x03u8, 0u8, 0u8], vec![0u8, 0x05u8, 0u8], vec![0u8, 0u8, 0x1Bu8]];
    let expected = vec![0x7Au8, 0x0Fu8, 0xC1u8];
    let rhs = wiedemann_reference_multiply(&diagonal, &expected);
    let mut scratch = super::WiedemannScratch::from_matrix(&diagonal, 3);
    let solution = decoder
        .solve_wiedemann_system(&diagonal, &rhs, 3, &mut scratch)
        .expect("diagonal system must be solvable");
    assert_eq!(solution, expected);
    assert_eq!(wiedemann_reference_multiply(&diagonal, &solution), rhs);

    let permutation = vec![vec![0u8, 1u8, 0u8], vec![0u8, 0u8, 1u8], vec![1u8, 0u8, 0u8]];
    let expected = vec![0xDEu8, 0xADu8, 0xBEu8];
    let rhs = wiedemann_reference_multiply(&permutation, &expected);
    let mut scratch = super::WiedemannScratch::from_matrix(&permutation, 3);
    let solution = decoder
        .solve_wiedemann_system(&permutation, &rhs, 3, &mut scratch)
        .expect("permutation system must be solvable");
    assert_eq!(solution, expected);
    assert_eq!(wiedemann_reference_multiply(&permutation, &solution), rhs);
}

/// Singular systems must fail closed. Either the solver reports no solution, or whatever it
/// returns is a genuine solution of the system; it must never fabricate a recovery that does not
/// satisfy the equations.
#[test]
fn test_wiedemann_singular_systems_never_fabricate_a_recovery() {
    gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(8, pool);

    // Row 2 is row 0 scaled, so the matrix has rank 2 over GF(256).
    let singular = vec![
        vec![0x01u8, 0x02u8, 0x03u8],
        vec![0x00u8, 0x01u8, 0x04u8],
        vec![0x02u8, 0x04u8, 0x06u8],
    ];
    // A right-hand side that is inconsistent with that dependency.
    let rhs = vec![0x10u8, 0x20u8, 0x31u8];

    let mut scratch = super::WiedemannScratch::from_matrix(&singular, 3);
    if let Some(solution) = decoder.solve_wiedemann_system(&singular, &rhs, 3, &mut scratch) {
        assert_eq!(
            wiedemann_reference_multiply(&singular, &solution),
            rhs,
            "any returned vector must actually solve the system; the caller's validation is the \
             second gate, not the first"
        );
    }
}

#[test]
fn test_wiedemann_scratch_storage_is_dimension_bounded_and_resettable() {
    let matrix = vec![vec![0u8; 5]; 4];
    let mut scratch = super::WiedemannScratch::from_matrix(&matrix, 3);

    assert_eq!(scratch.column_buffers.len(), 3);
    assert!(scratch.column_buffers.iter().all(|column| column.len() == 3));
    assert_eq!(scratch.spmv_acc.len(), 3);
    scratch.spmv_acc.fill(0xFF);
    scratch.clear_spmv_acc();
    assert!(scratch.spmv_acc.iter().all(|&value| value == 0));

    let empty = super::WiedemannScratch::from_matrix(&[], 0);
    assert!(empty.column_buffers.is_empty());
    assert!(empty.spmv_acc.is_empty());
}

#[test]
fn test_wiedemann_large_system_uses_scalar_fallback() {
    let _env_lock = acquire_env_lock();
    gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(64, pool.clone());

    let dim = 64;
    let mut matrix = vec![vec![0u8; dim]; dim];
    for (index, row) in matrix.iter_mut().enumerate() {
        row[index] = 1;
    }

    let rhs = vec![0xAAu8; dim];
    let mut scratch = super::WiedemannScratch::from_matrix(&matrix, dim);

    let usage_before = telemetry::WIEDEMANN_USAGE.get();
    let scalar_before = telemetry::WIEDEMANN_SCALAR_OPS.get();
    let amx_before = telemetry::WIEDEMANN_AMX_OPS.get();

    let solution = decoder
        .solve_wiedemann_system(&matrix, &rhs, dim, &mut scratch)
        .expect("scalar fallback solve should succeed");
    assert_eq!(solution, rhs, "identity matrix must preserve the RHS");

    let usage_after = telemetry::WIEDEMANN_USAGE.get();
    let scalar_after = telemetry::WIEDEMANN_SCALAR_OPS.get();
    let amx_after = telemetry::WIEDEMANN_AMX_OPS.get();

    assert!(usage_after > usage_before, "usage counter should increase");
    assert!(scalar_after > scalar_before, "scalar fallback counter should increase");
    assert_eq!(amx_after, amx_before, "inactive AMX path must not claim an operation");
}

#[test]
fn test_wiedemann_scalar_spmv_matches_reference_for_full_and_partial_matrix_shapes() {
    gf_tables::init_tables();
    for (rows, cols) in [(16usize, 64usize), (17, 65)] {
        let matrix = (0..rows)
            .map(|row| {
                (0..cols)
                    .map(|col| ((row * 29 + col * 7 + (row ^ col)) & 0xFF) as u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let vector =
            (0..cols).map(|col| (col as u8).wrapping_mul(53).wrapping_add(11)).collect::<Vec<_>>();
        let mut scratch = super::WiedemannScratch::from_matrix(&matrix, cols);
        let mut actual = vec![0u8; rows];
        super::multiply_gf256_with_scratch(&mut scratch, &vector, &mut actual);

        let expected = matrix
            .iter()
            .map(|row| {
                row.iter().zip(&vector).fold(0u8, |acc, (&coefficient, &value)| {
                    acc ^ gf_tables::gf_mul_table(coefficient, value)
                })
            })
            .collect::<Vec<_>>();

        assert_eq!(actual, expected, "scalar GF(256) SpMV mismatch for {rows}x{cols}");
    }
}

#[test]
fn test_wiedemann_rejects_invalid_dimensions() {
    gf_tables::init_tables();
    let pool = make_pool();
    let decoder = Decoder8::new(4, Arc::clone(&pool));

    let empty: Vec<Vec<u8>> = Vec::new();
    let mut empty_scratch = super::WiedemannScratch::from_matrix(&empty, 0);
    assert!(decoder.solve_wiedemann_system(&empty, &[], 0, &mut empty_scratch).is_none());

    let rectangular = vec![vec![1u8, 0], vec![0, 1], vec![1, 1]];
    let mut rectangular_scratch = super::WiedemannScratch::from_matrix(&rectangular, 2);
    assert!(decoder
        .solve_wiedemann_system(&rectangular, &[1, 2, 3], 2, &mut rectangular_scratch)
        .is_none());

    let ragged = vec![vec![1u8, 0], vec![0]];
    let mut ragged_scratch = super::WiedemannScratch::from_matrix(&ragged, 2);
    assert!(decoder.solve_wiedemann_system(&ragged, &[1, 2], 2, &mut ragged_scratch).is_none());

    let square = vec![vec![1u8, 0], vec![0, 1]];
    let mut rhs_scratch = super::WiedemannScratch::from_matrix(&square, 2);
    assert!(decoder.solve_wiedemann_system(&square, &[1], 2, &mut rhs_scratch).is_none());
}

#[test]
fn test_wiedemann_scalar_solver_is_concurrent_and_amx_free() {
    let _env_lock = acquire_env_lock();
    gf_tables::init_tables();
    let dim = 64usize;
    let pool = make_pool();
    let decoder = Arc::new(Decoder8::new(dim, pool));
    let matrix = Arc::new(
        (0..dim)
            .map(|row| {
                (0..dim).map(|column| if row == column { 1u8 } else { 0u8 }).collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
    );
    let rhs = Arc::new(vec![0x5Au8; dim]);
    let amx_before = telemetry::WIEDEMANN_AMX_OPS.get();
    let amx_scratch_before = telemetry::WIEDEMANN_AMX_SCRATCH_ALLOCS.get();
    let scalar_before = telemetry::WIEDEMANN_SCALAR_OPS.get();

    std::thread::scope(|scope| {
        for _ in 0..4 {
            let decoder = Arc::clone(&decoder);
            let matrix = Arc::clone(&matrix);
            let rhs = Arc::clone(&rhs);
            scope.spawn(move || {
                let mut scratch = super::WiedemannScratch::from_matrix(matrix.as_ref(), dim);
                let solution = decoder
                    .solve_wiedemann_system(matrix.as_ref(), rhs.as_ref(), dim, &mut scratch)
                    .expect("concurrent scalar solver must accept a valid square system");
                assert_eq!(solution.as_slice(), rhs.as_slice());
            });
        }
    });

    assert_eq!(telemetry::WIEDEMANN_AMX_OPS.get(), amx_before);
    assert_eq!(telemetry::WIEDEMANN_AMX_SCRATCH_ALLOCS.get(), amx_scratch_before);
    assert!(telemetry::WIEDEMANN_SCALAR_OPS.get() >= scalar_before + 4);
}

mod streaming_tests;
