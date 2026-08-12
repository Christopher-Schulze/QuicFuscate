use super::*;

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

    assert_eq!(first.base_stream_interval(), 6);
    assert_eq!(second.base_stream_interval(), 2);
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
    let brain_hints = Arc::new(qf_fec::BrainFecHints::new());
    observer.attach_brain_hints(brain_hints.clone());

    conn.set_ack_eliciting_threshold(9);
    conn.set_external_pacing_for_test(true);
    brain_hints.set_redundancy_ppm(180_000);

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
fn test_observer_runtime_hints_are_connection_local() {
    let mut cfg = crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
        .expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = crate::transport::ConnectionId::from_ref(&[8u8; 8]);
    let mut first_conn =
        crate::transport::packet::connect(None, scid.as_ref(), local, peer, &mut cfg)
            .expect("first connection");
    let mut second_conn =
        crate::transport::packet::connect(None, scid.as_ref(), local, peer, &mut cfg)
            .expect("second connection");

    let first_observer = FecTransportObserver::new();
    let second_observer = FecTransportObserver::new();
    let first_hints = Arc::new(qf_fec::BrainFecHints::new());
    let second_hints = Arc::new(qf_fec::BrainFecHints::new());
    first_hints.set_redundancy_ppm(120_000);
    second_hints.set_redundancy_ppm(280_000);
    first_observer.attach_brain_hints(first_hints);
    second_observer.attach_brain_hints(second_hints);

    first_observer.sync_runtime_hints(&mut first_conn);
    second_observer.sync_runtime_hints(&mut second_conn);
    assert_eq!(first_conn.take_fec_control_delta().redundancy_ppm, Some(120_000));
    assert_eq!(second_conn.take_fec_control_delta().redundancy_ppm, Some(280_000));
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
    let first_encoder = super::super::internal::EncoderVariant::new(FecMode::Fountain, 8, 8);
    let first_decoder =
        super::super::internal::DecoderVariant::new(FecMode::Fountain, 8, Arc::clone(&pool));

    let _g2 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "900");
    let second_encoder = super::super::internal::EncoderVariant::new(FecMode::Fountain, 8, 8);
    let second_decoder = super::super::internal::DecoderVariant::new(FecMode::Fountain, 8, pool);

    match first_encoder {
        super::super::internal::EncoderVariant::Fountain(enc) => {
            assert_eq!(enc.symbol_size(), 1200)
        }
        _ => panic!("expected fountain encoder"),
    }
    match first_decoder {
        super::super::internal::DecoderVariant::Fountain(dec) => {
            assert_eq!(dec.symbol_size(), 1200)
        }
        _ => panic!("expected fountain decoder"),
    }
    match second_encoder {
        super::super::internal::EncoderVariant::Fountain(enc) => assert_eq!(enc.symbol_size(), 900),
        _ => panic!("expected fountain encoder"),
    }
    match second_decoder {
        super::super::internal::DecoderVariant::Fountain(dec) => assert_eq!(dec.symbol_size(), 900),
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

    let decoder = fec.decoder.lock();
    assert_eq!(decoder.first_block_decoder_policy(), Some("gauss"));
}

#[test]
fn test_transition_fountain_uses_instance_policy_snapshot() {
    let _env_lock = acquire_env_lock();
    let _g1 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "1200");
    let _g2 = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let mut fec = AdaptiveFec::new(FecConfig { initial_mode: FecMode::Zero, ..Default::default() });

    let _g3 = EnvGuard::set("QUICFUSCATE_FOUNTAIN_SYMBOL", "900");
    fec.transition_to_mode(FecMode::Fountain);

    let encoder = fec.encoder.lock();
    assert_eq!(encoder.first_block_fountain_symbol_size(), Some(1200));

    let decoder = fec.decoder.lock();
    assert_eq!(decoder.first_block_fountain_symbol_size(), Some(1200));
}

#[test]
fn test_wire_profile_switch_commits_only_after_source_block_boundary() {
    let pool = make_pool();
    let mut windows = HashMap::new();
    windows.insert(FecMode::Normal, 4);
    let mut fec = AdaptiveFec::new(FecConfig {
        initial_mode: FecMode::Normal,
        window_sizes: windows,
        ..Default::default()
    });
    let initial_profile = fec.wire_profile(1).expect("initial wire profile");
    assert_eq!(initial_profile.source_count, 4);

    for id in 0..2 {
        let _ = fec.on_send(mk_src_packet(id, 64, &pool));
    }
    fec.transition_to_target(target_from_mode(FecMode::Strong, 8));
    assert!(fec.is_transitioning());
    assert_eq!(fec.current_mode(), FecMode::Normal);
    assert_eq!(fec.wire_profile(1).expect("old wire profile"), initial_profile);

    let _ = fec.on_send(mk_src_packet(2, 64, &pool));
    let boundary_output = fec.on_send(mk_src_packet(3, 64, &pool));
    assert!(boundary_output.iter().all(|packet| {
        packet.is_systematic || packet.coeff_len == initial_profile.block_source_count() as usize
    }));

    let next_profile = fec.wire_profile(2).expect("next wire profile");
    assert!(!fec.is_transitioning());
    assert_eq!(fec.current_mode(), FecMode::Strong);
    assert_eq!(next_profile.source_count, 8);
    assert_eq!(next_profile.epoch, 2);
}

#[test]
fn test_forced_streaming_wire_profile_waits_for_large_source_block_boundary() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();
    let mut windows = HashMap::new();
    windows.insert(FecMode::Extreme, 1024);
    let mut fec = AdaptiveFec::new(FecConfig {
        initial_mode: FecMode::Extreme,
        window_sizes: windows,
        ..Default::default()
    });
    let initial_profile = fec.wire_profile(1).expect("initial wire profile");
    assert_eq!(initial_profile.codec, super::super::wire::WireCodec::Gf16);
    assert_eq!(initial_profile.block_source_count(), 256);

    let _ = fec.on_send(mk_src_packet(0, 64, &pool));
    fec.force_streaming_mode();

    assert!(fec.is_transitioning());
    assert_eq!(fec.current_mode(), FecMode::Extreme);
    assert_eq!(fec.wire_profile(1).expect("active block wire profile"), initial_profile);

    fec.encoder.lock().clear_window();
    let streaming_profile = fec.wire_profile(2).expect("streaming wire profile");
    assert!(!fec.is_transitioning());
    assert_eq!(fec.current_mode(), FecMode::Streaming);
    assert_eq!(streaming_profile.codec, super::super::wire::WireCodec::StreamingGf8);
    assert!(streaming_profile.block_source_count() <= 255);
}

#[test]
fn test_extreme_disturbance_streaming_target_is_gf8_wire_safe() {
    let _env_lock = acquire_env_lock();
    let pool = make_pool();
    let mut windows = HashMap::new();
    windows.insert(FecMode::Extreme, 1024);
    let mut fec = AdaptiveFec::new(FecConfig {
        initial_mode: FecMode::Extreme,
        window_sizes: windows,
        ..Default::default()
    });
    let _ = fec.on_send(mk_src_packet(0, 64, &pool));
    fec.transition_to_target(target_from_mode(FecMode::Streaming, 1024).with_window(1024));

    assert!(fec.is_transitioning());
    fec.encoder.lock().clear_window();
    let profile = fec.wire_profile(2).expect("bounded streaming wire profile");

    assert_eq!(fec.current_mode(), FecMode::Streaming);
    assert_eq!(profile.codec, super::super::wire::WireCodec::StreamingGf8);
    assert_eq!(profile.source_count, 1020);
    assert_eq!(profile.interleave_depth, 4);
    assert_eq!(profile.block_source_count(), 255);
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
fn test_batch_extreme_uses_gf8_for_small_block() {
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
        assert_eq!(rp.coeff_len, k, "GF8 coeff len == k for sub-256 Extreme blocks");
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
    let _env_lock = acquire_env_lock();
    crate::fec::gf_tables::init_tables();
    let pool = crate::optimize::global_pool();
    let k = 8;

    // Test Gauss elimination (forced via ENV)
    let _g_decoder_gauss = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "gauss");
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
        let _g_decoder_wiedemann = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "wiedemann");
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
        let repair = FecPacket::new(
            (k as u64) - 1,
            Some(repair_data),
            1,
            false,
            Some(coeffs),
            k,
            Arc::clone(&pool),
        );
        decoder_wm.take_packet(repair);

        assert!(decoder_wm.is_complete());
    }

    // Test auto mode with large k (should prefer Wiedemann if available)
    let _g_decoder_auto = EnvGuard::set("QUICFUSCATE_FEC_DECODER", "auto");
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
    // Must lie inside the transmitted range below, past the first stream window, so the
    // receiver actually has to recover it. A value outside the range would never be dropped
    // and would make the dedup assertion vacuous.
    let missing_id = 10u64;

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

    // The dropped source must actually be recovered, otherwise the dedup guarantee below is
    // never exercised and the test would pass vacuously.
    assert_eq!(
        seen_missing, 1,
        "dropped source {missing_id} must be recovered and emitted exactly once, got {seen_missing}"
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
    let _env_lock = acquire_env_lock();
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

// TODO-392: regression guard - cloning a source (systematic) FEC packet must
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
