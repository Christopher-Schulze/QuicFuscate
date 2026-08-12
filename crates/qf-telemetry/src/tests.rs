use super::CpuProfileId;
use super::*;

#[test]
fn cpu_profile_mask_monotonic_x86_path() {
    let p0 = cpu_profile_mask_for_id(CpuProfileId::X86_P0a);
    let p2 = cpu_profile_mask_for_id(CpuProfileId::X86_P2b);
    let p3 = cpu_profile_mask_for_id(CpuProfileId::X86_P3e);
    let p4 = cpu_profile_mask_for_id(CpuProfileId::X86_P4b);

    assert_ne!(p0 & CPU_MASK_SSE2, 0);
    assert_ne!(p2 & CPU_MASK_AVX2, 0);
    assert_ne!(p3 & CPU_MASK_GFNI, 0);
    assert_ne!(p4 & CPU_MASK_AVX10_512, 0);
    assert_eq!(p0 & CPU_MASK_AVX2, 0);
    assert_eq!(p0 & CPU_MASK_AVX512, 0);
}

#[test]
fn telemetry_config_preserves_defaults_and_validation() {
    let config = TelemetryConfig::default();
    assert_eq!(config.export_interval, 60);
    assert!(config.validate().is_ok());

    let encoded = serde_json::to_string(&config).expect("telemetry config serializes");
    let decoded: TelemetryConfig = serde_json::from_str(&encoded).expect("telemetry config parses");
    assert_eq!(decoded, config);

    let mut invalid = config;
    invalid.export_interval = 0;
    assert_eq!(
        invalid.validate(),
        Err("telemetry.export_interval must be > 0 when telemetry is enabled".to_string())
    );
}

#[test]
fn publish_cpu_profile_mask_updates_gauge() {
    CPU_FEATURE_MASK.store(0, Ordering::Relaxed);
    let expected = cpu_profile_mask_for_id(CpuProfileId::ARM_A2);
    let published = publish_cpu_profile_mask_for_id(CpuProfileId::ARM_A2);
    assert_eq!(published, expected);
    assert_eq!(CPU_FEATURE_MASK.load(Ordering::Relaxed), expected);
}

#[test]
fn cpu_profile_mask_covers_all_profiles() {
    let profiles = [
        CpuProfileId::X86_P0a,
        CpuProfileId::X86_P0b,
        CpuProfileId::X86_P1a,
        CpuProfileId::X86_P1b,
        CpuProfileId::X86_P1f,
        CpuProfileId::X86_P2a,
        CpuProfileId::X86_P2b,
        CpuProfileId::X86_P3a,
        CpuProfileId::X86_P3b,
        CpuProfileId::X86_P3c,
        CpuProfileId::X86_P3d,
        CpuProfileId::X86_P3e,
        CpuProfileId::X86_P4a,
        CpuProfileId::X86_P4b,
        CpuProfileId::ARM_A0,
        CpuProfileId::ARM_A1a,
        CpuProfileId::ARM_A1b,
        CpuProfileId::ARM_A1c,
        CpuProfileId::ARM_A1d,
        CpuProfileId::ARM_A2,
        CpuProfileId::Apple_M,
        CpuProfileId::RVV,
        CpuProfileId::Scalar,
    ];
    for profile in profiles {
        let mask = cpu_profile_mask_for_id(profile);
        assert_ne!(mask, 0, "mask must be non-zero for {:?}", profile);
    }
}

#[test]
fn server_push_metrics_exported_in_telemetry_text() {
    SERVER_PUSH_BURSTS_TOTAL.store(7, Ordering::Relaxed);
    SERVER_PUSH_TOTAL_COVER_BYTES.store(12345, Ordering::Relaxed);
    SERVER_PUSH_BURSTS_LAST_MINUTE.store(3, Ordering::Relaxed);
    SERVER_PUSH_CURRENT_INTENSITY_PPM.store(650_000, Ordering::Relaxed);
    SERVER_PUSH_TRIGGER_LOSS_TOTAL.store(2, Ordering::Relaxed);
    SERVER_PUSH_TRIGGER_TIME_TOTAL.store(4, Ordering::Relaxed);
    SERVER_PUSH_TRIGGER_GATING_TOTAL.store(1, Ordering::Relaxed);

    let out = export_telemetry_text();
    assert!(out.contains("quicfuscate_server_push_bursts_total 7"));
    assert!(out.contains("quicfuscate_server_push_total_cover_bytes 12345"));
    assert!(out.contains("quicfuscate_server_push_bursts_last_minute 3"));
    assert!(out.contains("quicfuscate_server_push_current_intensity_ppm 650000"));
    assert!(out.contains("quicfuscate_server_push_trigger_loss_total 2"));
    assert!(out.contains("quicfuscate_server_push_trigger_time_total 4"));
    assert!(out.contains("quicfuscate_server_push_trigger_gating_total 1"));
}

#[test]
fn io_uring_counters_exported_in_telemetry_text() {
    let calls_before = IO_URING_SUBMIT_CALLS.get();
    let packets_before = IO_URING_SUBMIT_PACKETS.get();
    let fallbacks_before = IO_URING_FALLBACKS.get();

    IO_URING_SUBMIT_CALLS.inc();
    IO_URING_SUBMIT_PACKETS.inc_by(42);
    IO_URING_FALLBACKS.inc();

    let out = export_telemetry_text();
    assert!(out.contains(&format!("quicfuscate_io_uring_submit_calls_total {}", calls_before + 1)));
    assert!(
        out.contains(&format!("quicfuscate_io_uring_submit_packets_total {}", packets_before + 42))
    );
    assert!(out.contains(&format!("quicfuscate_io_uring_fallbacks_total {}", fallbacks_before + 1)));
}

#[test]
fn crypto_backend_selection_metrics_exported_in_telemetry_text() {
    let plan_x4_before = PLAN_DECISIONS_X4.get();
    let plan_x8_before = PLAN_DECISIONS_X8.get();
    let aegis_l_before = DATA_AEAD_BACKEND_AEGIS_L_TOTAL.get();
    let aegis_x4_before = DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.get();
    let aegis_x8_before = DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.get();
    let morus_before = DATA_AEAD_BACKEND_MORUS_TOTAL.get();

    PLAN_DECISIONS_X4.inc();
    PLAN_DECISIONS_X8.inc();
    DATA_AEAD_BACKEND_AEGIS_L_TOTAL.inc();
    DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.inc();
    DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.inc();
    DATA_AEAD_BACKEND_MORUS_TOTAL.inc();

    let out = export_telemetry_text();
    assert!(out.contains(&format!("quicfuscate_plan_select_x4_total {}", plan_x4_before + 1)));
    assert!(out.contains(&format!("quicfuscate_plan_select_x8_total {}", plan_x8_before + 1)));
    assert!(out
        .contains(&format!("quicfuscate_data_aead_backend_aegis_l_total {}", aegis_l_before + 1)));
    assert!(out.contains(&format!(
        "quicfuscate_data_aead_backend_aegis_x4_total {}",
        aegis_x4_before + 1
    )));
    assert!(out.contains(&format!(
        "quicfuscate_data_aead_backend_aegis_x8_total {}",
        aegis_x8_before + 1
    )));
    assert!(
        out.contains(&format!("quicfuscate_data_aead_backend_morus_total {}", morus_before + 1))
    );
}

#[test]
fn test_cpu_profile_mask_arm_profiles_nonzero() {
    let arm_profiles = [
        CpuProfileId::ARM_A0,
        CpuProfileId::ARM_A1a,
        CpuProfileId::ARM_A1b,
        CpuProfileId::ARM_A1c,
        CpuProfileId::ARM_A1d,
        CpuProfileId::ARM_A2,
        CpuProfileId::Apple_M,
    ];
    for profile in arm_profiles {
        let mask = cpu_profile_mask_for_id(profile);
        assert_ne!(mask, 0, "ARM profile {:?} must produce a non-zero mask", profile);
        // All ARM profiles must include NEON at minimum
        assert_ne!(mask & CPU_MASK_NEON, 0, "ARM profile {:?} must include NEON", profile);
    }
}

#[test]
fn test_cpu_profile_mask_scalar_and_rv() {
    let scalar_mask = cpu_profile_mask_for_id(CpuProfileId::Scalar);
    assert_ne!(scalar_mask, 0, "Scalar profile must produce a non-zero mask");
    assert_ne!(scalar_mask & CPU_MASK_SCALAR, 0, "Scalar profile must set SCALAR bit");
    // Scalar must NOT set any SIMD bits
    assert_eq!(scalar_mask & CPU_MASK_AVX2, 0, "Scalar must not have AVX2");
    assert_eq!(scalar_mask & CPU_MASK_NEON, 0, "Scalar must not have NEON");

    let rvv_mask = cpu_profile_mask_for_id(CpuProfileId::RVV);
    assert_ne!(rvv_mask, 0, "RVV profile must produce a non-zero mask");
    assert_ne!(rvv_mask & CPU_MASK_RVV, 0, "RVV profile must set RVV bit");
    // RVV must NOT set x86 or ARM bits
    assert_eq!(rvv_mask & CPU_MASK_AVX2, 0, "RVV must not have AVX2");
    assert_eq!(rvv_mask & CPU_MASK_NEON, 0, "RVV must not have NEON");
}

#[test]
fn test_publish_cpu_profile_mask_idempotent() {
    let first = publish_cpu_profile_mask_for_id(CpuProfileId::X86_P3e);
    let second = publish_cpu_profile_mask_for_id(CpuProfileId::X86_P3e);
    assert_eq!(first, second, "same profile must produce identical mask");
    assert_eq!(
        CPU_FEATURE_MASK.load(Ordering::Relaxed),
        first,
        "gauge must reflect the published value"
    );
}

#[test]
fn test_export_telemetry_text_returns_string() {
    let text = export_telemetry_text();
    assert!(!text.is_empty(), "telemetry text must not be empty");
    // Must contain at least one metric line
    assert!(text.contains("quicfuscate_"), "output must contain metric lines");
}

#[test]
fn test_export_telemetry_text_contains_header_line() {
    let text = export_telemetry_text();
    // The very first line should be the xdp_active gauge
    let first_line = text.lines().next().unwrap_or("");
    assert!(
        first_line.starts_with("quicfuscate_xdp_active "),
        "first line must start with 'quicfuscate_xdp_active ', got: {}",
        first_line
    );
    // Every non-empty line must follow the "metric_name value" format
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        assert!(
            line.starts_with("quicfuscate_"),
            "each metric line must start with 'quicfuscate_', got: {}",
            line
        );
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        assert_eq!(parts.len(), 2, "metric line must have 'name value' format: {}", line);
    }
}

#[test]
fn fec_decoder_telemetry_is_exported() {
    let text = export_telemetry_text();
    for metric in [
        "quicfuscate_fec_decoder_equations_total ",
        "quicfuscate_fec_decoder_solve_attempts_total ",
        "quicfuscate_fec_decoder_solve_successes_total ",
        "quicfuscate_fec_decoder_solve_success_ratio_ppm ",
        "quicfuscate_fec_decoder_solve_time_ns_total ",
        "quicfuscate_fec_decoder_dedup_evictions_total ",
        "quicfuscate_fec_fountain_decoder_evictions_total ",
        "quicfuscate_fec_fountain_decoder_admission_rejections_total ",
        "quicfuscate_fec_fountain_decoder_propagation_work_total ",
        "quicfuscate_wiedemann_column_buffer_allocations_total ",
        "quicfuscate_wiedemann_spmv_accumulator_allocations_total ",
        "quicfuscate_wiedemann_matrix_rhs_allocations_total ",
        "quicfuscate_wiedemann_krylov_allocations_total ",
        "quicfuscate_wiedemann_iteration_allocations_total ",
        "quicfuscate_wiedemann_candidate_allocations_total ",
        "quicfuscate_wiedemann_amx_scratch_allocations_total ",
    ] {
        assert!(text.contains(metric), "missing FEC decoder telemetry metric: {metric}");
    }
}

#[test]
fn memory_usage_publisher_preserves_bytes() {
    const EXPECTED_BYTES: u64 = 123_456_789;

    publish_memory_usage_bytes(EXPECTED_BYTES);

    assert!(
        MEMORY_USAGE_BYTES.load(Ordering::Relaxed) == EXPECTED_BYTES,
        "resident memory must remain in the byte unit returned by sysinfo"
    );
}

#[test]
fn resource_refresh_slot_is_process_wide_and_rate_limited() {
    let last_refresh_ms = AtomicU64::new(RESOURCE_REFRESH_UNSET);

    assert!(claim_resource_refresh(&last_refresh_ms, 0));
    assert!(!claim_resource_refresh(&last_refresh_ms, 999));
    assert!(claim_resource_refresh(&last_refresh_ms, 1_000));
    assert!(!claim_resource_refresh(&last_refresh_ms, 1_999));
    assert!(claim_resource_refresh(&last_refresh_ms, 2_000));
}

#[test]
fn fec_export_declares_exact_mode_mapping_and_truthful_units() {
    let text = export_telemetry_text();

    for &(mode_id, mode_name) in &FEC_MODE_MAPPING {
        assert!(
            text.contains(&format!(
                "quicfuscate_fec_active_connections{{mode=\"{mode_name}\",mode_id=\"{mode_id}\"}} "
            )),
            "missing FEC mode mapping for {mode_name}={mode_id}"
        );
    }
    for metric in [
        "quicfuscate_fec_observed_packets_total ",
        "quicfuscate_fec_observed_lost_packets_total ",
        "quicfuscate_fec_observed_loss_ppm ",
        "quicfuscate_fec_policy_transitions_total ",
        "quicfuscate_fec_source_packets_sent_total ",
        "quicfuscate_fec_repair_packets_sent_total ",
        "quicfuscate_fec_source_payload_bytes_sent_total ",
        "quicfuscate_fec_source_wire_bytes_sent_total ",
        "quicfuscate_fec_repair_wire_bytes_sent_total ",
        "quicfuscate_fec_wire_overhead_sent_ppm ",
        "quicfuscate_fec_decoded_packets_total ",
        "quicfuscate_fec_recovered_packets_total ",
    ] {
        assert!(text.contains(metric), "missing FEC metric {metric}");
    }
    assert!(!text.contains("quicfuscate_fec_loss_rate "));
    assert!(!text.contains("quicfuscate_fec_mode "));
    assert!(!text.contains("quicfuscate_fec_window "));
}
