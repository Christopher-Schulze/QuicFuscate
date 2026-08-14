//! Plain-text telemetry export owned by the telemetry crate.

use super::*;

/// Export a subset of metrics in a plain text telemetry format.
/// This intentionally covers the most relevant hot-path counters to keep overhead minimal.
/// Respects per-category flags (COLLECT_PACKET_STATS, etc.) to filter output.
pub fn export_telemetry_text() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let get = |v: &AtomicU64| v.load(Ordering::Relaxed);
    let packets = COLLECT_PACKET_STATS.load(Ordering::Relaxed);
    let congestion = COLLECT_CONGESTION_STATS.load(Ordering::Relaxed);
    let fec = COLLECT_FEC_STATS.load(Ordering::Relaxed);
    let stealth = COLLECT_STEALTH_STATS.load(Ordering::Relaxed);

    let _ = writeln!(out, "quicfuscate_xdp_active {}", get(&XDP_ACTIVE));

    // Memory Pool metrics
    let _ = writeln!(out, "quicfuscate_mem_pool_capacity {}", get(&MEM_POOL_CAPACITY));
    let _ = writeln!(out, "quicfuscate_mem_pool_in_use {}", get(&MEM_POOL_IN_USE));
    let _ = writeln!(out, "quicfuscate_mem_pool_usage_bytes {}", get(&MEM_POOL_USAGE_BYTES));
    let _ =
        writeln!(out, "quicfuscate_mem_pool_utilization_percent {}", get(&MEM_POOL_UTILIZATION));
    let _ = writeln!(out, "quicfuscate_mem_pool_block_size_bytes {}", get(&MEM_POOL_BLOCK_SIZE));
    let _ = writeln!(
        out,
        "quicfuscate_mem_pool_allocations_total{{source=\"thread_local\"}} {}",
        MEM_POOL_HITS_TLS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_mem_pool_allocations_total{{source=\"shared_queue\"}} {}",
        MEM_POOL_HITS_QUEUE.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_mem_pool_allocations_total{{source=\"grow\"}} {}",
        MEM_POOL_ALLOC_GROW.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_mem_pool_allocations_total{{source=\"ephemeral\"}} {}",
        MEM_POOL_ALLOC_EPHEMERAL.get()
    );
    let _ = writeln!(out, "quicfuscate_body_pool_allocations_total {}", BODY_POOL_ALLOCS.get());

    // SIMD usage summary
    let _ = writeln!(out, "quicfuscate_simd_usage_avx512 {}", get(&SIMD_USAGE_AVX512));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx2 {}", get(&SIMD_USAGE_AVX2));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx10_256 {}", get(&SIMD_USAGE_AVX10_256));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx10_512 {}", get(&SIMD_USAGE_AVX10_512));
    let _ = writeln!(out, "quicfuscate_simd_usage_neon {}", get(&SIMD_USAGE_NEON));
    let _ = writeln!(out, "quicfuscate_simd_usage_sve2 {}", get(&SIMD_USAGE_SVE2));
    let _ = writeln!(out, "quicfuscate_simd_usage_scalar {}", get(&SIMD_USAGE_SCALAR));
    let _ = writeln!(out, "quicfuscate_simd_usage_rvv {}", get(&SIMD_USAGE_RVV));
    let _ = writeln!(out, "quicfuscate_simd_active {}", get(&SIMD_ACTIVE));
    let _ =
        writeln!(out, "quicfuscate_cpu_feature_mask {}", CPU_FEATURE_MASK.load(Ordering::Relaxed));
    #[cfg(target_arch = "x86_64")]
    let _ =
        writeln!(out, "quicfuscate_stealth_padding_gfni_bytes {}", STEALTH_PADDING_GFNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_congestion_vnni_batches {}", CONGESTION_VNNI_BATCHES.get());
    let _ = writeln!(out, "quicfuscate_congestion_avx2_batches {}", CONGESTION_AVX2_BATCHES.get());
    let _ = writeln!(out, "quicfuscate_congestion_neon_batches {}", CONGESTION_NEON_BATCHES.get());

    // TLS provider
    let _ = writeln!(out, "quicfuscate_tls_provider_kind {}", TLS_PROVIDER_KIND.get());
    let _ = writeln!(
        out,
        "quicfuscate_quic_packet_key_installs_total{{level=\"handshake\",owner=\"rustls-standard\",suite=\"tls-aes-128-gcm-sha256\"}} {}",
        QUIC_HANDSHAKE_AES128_KEY_INSTALLS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_quic_packet_key_installs_total{{level=\"handshake\",owner=\"rustls-standard\",suite=\"tls-aes-256-gcm-sha384\"}} {}",
        QUIC_HANDSHAKE_AES256_KEY_INSTALLS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_quic_packet_key_installs_total{{level=\"one-rtt\",owner=\"rustls-standard\",suite=\"tls-aes-128-gcm-sha256\"}} {}",
        QUIC_ONE_RTT_AES128_KEY_INSTALLS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_quic_packet_key_installs_total{{level=\"one-rtt\",owner=\"rustls-standard\",suite=\"tls-aes-256-gcm-sha384\"}} {}",
        QUIC_ONE_RTT_AES256_KEY_INSTALLS.get()
    );

    // TLS Cover cipher usage
    let _ = writeln!(out, "quicfuscate_tls-cover_chacha_ops {}", FAKETLS_CHACHA_OPS.get());
    let _ = writeln!(out, "quicfuscate_tls-cover_aes_gcm_ops {}", FAKETLS_AES_GCM_OPS.get());
    let _ =
        writeln!(out, "quicfuscate_tls-cover_cipher_failures {}", FAKETLS_CIPHER_FAILURES.get());
    let _ = writeln!(out, "quicfuscate_aes_block_aesni_ops {}", AES_BLOCK_AESNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_vaes_ops {}", AES_BLOCK_VAES_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_aese_ops {}", AES_BLOCK_AESE_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_ssse3_ops {}", AES_BLOCK_SSSE3_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_sve_ops {}", AES_BLOCK_SVE_OPS.get());
    let _ =
        writeln!(out, "quicfuscate_aes_block_neon_table_ops {}", AES_BLOCK_NEON_TABLE_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_scalar_ops {}", AES_BLOCK_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_sha256_avx2_ops {}", SHA256_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_sha256_vnni_ops {}", SHA256_VNNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_sha256_neon_ops {}", SHA256_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_sha256_sve2_ops {}", SHA256_SVE2_OPS.get());
    let _ = writeln!(out, "quicfuscate_sha256_scalar_ops {}", SHA256_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_hmac_sha256_avx2_ops {}", HMAC_SHA256_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_hmac_sha256_vnni_ops {}", HMAC_SHA256_VNNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_hmac_sha256_neon_ops {}", HMAC_SHA256_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_hmac_sha256_sve2_ops {}", HMAC_SHA256_SVE2_OPS.get());
    let _ = writeln!(out, "quicfuscate_hmac_sha256_scalar_ops {}", HMAC_SHA256_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_avx2_ops {}", CHACHA20_X4_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_avx_ops {}", CHACHA20_X4_AVX_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_sse41_ops {}", CHACHA20_X4_SSE41_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_neon_ops {}", CHACHA20_X4_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_scalar_ops {}", CHACHA20_X4_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_ctr_aesni_ops {}", AES_CTR_AESNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_ctr_aese_ops {}", AES_CTR_AESE_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_ctr_sve_ops {}", AES_CTR_SVE_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_ctr_ssse3_ops {}", AES_CTR_SSSE3_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_ctr_scalar_ops {}", AES_CTR_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_avx512_ops {}", POLY1305_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_avx2_ops {}", POLY1305_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_sse2_ops {}", POLY1305_SSE2_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_sve_ops {}", POLY1305_SVE_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_neon_ops {}", POLY1305_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_poly1305_scalar_ops {}", POLY1305_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_avx512_ops {}", ITER_SUM_F32_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_avx2_ops {}", ITER_SUM_F32_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_neon_ops {}", ITER_SUM_F32_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_scalar_ops {}", ITER_SUM_F32_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_rvv_ops {}", ITER_SUM_F32_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_avx512_ops {}", ITER_SUM_U32_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_avx2_ops {}", ITER_SUM_U32_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_neon_ops {}", ITER_SUM_U32_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_scalar_ops {}", ITER_SUM_U32_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_rvv_ops {}", ITER_SUM_U32_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_avx512_ops {}", ITER_SUM_U64_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_avx2_ops {}", ITER_SUM_U64_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_neon_ops {}", ITER_SUM_U64_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_scalar_ops {}", ITER_SUM_U64_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_rvv_ops {}", ITER_SUM_U64_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_usage {}", WIEDEMANN_USAGE.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_amx_ops {}", WIEDEMANN_AMX_OPS.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_scalar_ops {}", WIEDEMANN_SCALAR_OPS.get());
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_column_buffer_allocations_total {}",
        WIEDEMANN_COLUMN_BUFFER_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_spmv_accumulator_allocations_total {}",
        WIEDEMANN_SPMV_ACCUMULATOR_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_matrix_rhs_allocations_total {}",
        WIEDEMANN_MATRIX_RHS_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_krylov_allocations_total {}",
        WIEDEMANN_KRYLOV_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_iteration_allocations_total {}",
        WIEDEMANN_ITERATION_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_candidate_allocations_total {}",
        WIEDEMANN_CANDIDATE_ALLOCS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_wiedemann_amx_scratch_allocations_total {}",
        WIEDEMANN_AMX_SCRATCH_ALLOCS.get()
    );
    if fec {
        for &(mode_id, mode_name) in &FEC_MODE_MAPPING {
            let active = FEC_ACTIVE_CONNECTIONS_BY_MODE[mode_id as usize].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "quicfuscate_fec_active_connections{{mode=\"{mode_name}\",mode_id=\"{mode_id}\"}} {active}"
            );
        }
        let _ = writeln!(
            out,
            "quicfuscate_fec_active_connections_total {}",
            get(&FEC_ACTIVE_CONNECTIONS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_effective_window_source_packets_sum {}",
            get(&FEC_ACTIVE_WINDOW_SUM)
        );
        let observed_packets = FEC_OBSERVED_PACKETS.get();
        let observed_lost_packets = FEC_OBSERVED_LOST_PACKETS.get();
        let observed_loss_ppm = if observed_packets == 0 {
            0
        } else {
            ((observed_lost_packets as u128)
                .saturating_mul(1_000_000)
                .checked_div(observed_packets as u128)
                .unwrap_or(0)
                .min(1_000_000)) as u64
        };
        let _ = writeln!(out, "quicfuscate_fec_observed_packets_total {observed_packets}");
        let _ =
            writeln!(out, "quicfuscate_fec_observed_lost_packets_total {observed_lost_packets}");
        let _ = writeln!(out, "quicfuscate_fec_observed_loss_ppm {observed_loss_ppm}");
        let _ = writeln!(out, "quicfuscate_fec_mode_switches_total {}", get(&FEC_MODE_SWITCHES));
        let _ = writeln!(
            out,
            "quicfuscate_fec_switch_reason_adaptive_total {}",
            get(&FEC_SWITCH_REASON_ADAPTIVE)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_switch_reason_force_on_total {}",
            get(&FEC_SWITCH_REASON_FORCE_ON)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_switch_reason_extreme_total {}",
            get(&FEC_SWITCH_REASON_EXTREME)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_switch_reason_disturbance_total {}",
            get(&FEC_SWITCH_REASON_DISTURBANCE)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_switch_reason_streaming_hint_total {}",
            get(&FEC_SWITCH_REASON_STREAMING_HINT)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_policy_transitions_total {}",
            get(&FEC_POLICY_TRANSITIONS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_packets_sent_total {}",
            FEC_SOURCE_PACKETS_SENT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_repair_packets_sent_total {}",
            FEC_REPAIR_PACKETS_SENT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_payload_bytes_sent_total {}",
            FEC_SOURCE_PAYLOAD_BYTES_SENT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_wire_bytes_sent_total {}",
            FEC_SOURCE_WIRE_BYTES_SENT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_repair_wire_bytes_sent_total {}",
            FEC_REPAIR_WIRE_BYTES_SENT.get()
        );
        let sent_source_payload = FEC_SOURCE_PAYLOAD_BYTES_SENT.get();
        let sent_wire =
            FEC_SOURCE_WIRE_BYTES_SENT.get().saturating_add(FEC_REPAIR_WIRE_BYTES_SENT.get());
        let sent_overhead_ppm = fec_wire_overhead_ppm(sent_source_payload, sent_wire);
        let _ = writeln!(out, "quicfuscate_fec_wire_overhead_sent_ppm {sent_overhead_ppm}");
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_packets_received_total {}",
            FEC_SOURCE_PACKETS_RECEIVED.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_repair_packets_received_total {}",
            FEC_REPAIR_PACKETS_RECEIVED.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_payload_bytes_received_total {}",
            FEC_SOURCE_PAYLOAD_BYTES_RECEIVED.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_source_wire_bytes_received_total {}",
            FEC_SOURCE_WIRE_BYTES_RECEIVED.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_repair_wire_bytes_received_total {}",
            FEC_REPAIR_WIRE_BYTES_RECEIVED.get()
        );
        let received_source_payload = FEC_SOURCE_PAYLOAD_BYTES_RECEIVED.get();
        let received_wire = FEC_SOURCE_WIRE_BYTES_RECEIVED
            .get()
            .saturating_add(FEC_REPAIR_WIRE_BYTES_RECEIVED.get());
        let received_overhead_ppm = fec_wire_overhead_ppm(received_source_payload, received_wire);
        let _ = writeln!(out, "quicfuscate_fec_wire_overhead_received_ppm {received_overhead_ppm}");
        let _ =
            writeln!(out, "quicfuscate_fec_decoded_packets_total {}", FEC_DECODED_PACKETS.get());
        let _ = writeln!(
            out,
            "quicfuscate_fec_recovered_packets_total {}",
            FEC_RECOVERED_PACKETS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_recovered_payload_bytes_total {}",
            FEC_RECOVERED_PAYLOAD_BYTES.get()
        );
        let decoder_solve_attempts = FEC_DECODER_SOLVE_ATTEMPTS.get();
        let decoder_solve_successes = FEC_DECODER_SOLVE_SUCCESSES.get();
        let decoder_solve_success_ratio_ppm = if decoder_solve_attempts == 0 {
            0
        } else {
            (decoder_solve_successes as u128)
                .saturating_mul(1_000_000)
                .checked_div(decoder_solve_attempts as u128)
                .unwrap_or(0)
                .min(1_000_000) as u64
        };
        let _ = writeln!(
            out,
            "quicfuscate_fec_decoder_equations_total {}",
            FEC_DECODER_EQUATIONS.get()
        );
        let _ =
            writeln!(out, "quicfuscate_fec_decoder_solve_attempts_total {decoder_solve_attempts}");
        let _ = writeln!(
            out,
            "quicfuscate_fec_decoder_solve_successes_total {decoder_solve_successes}"
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_decoder_solve_success_ratio_ppm {decoder_solve_success_ratio_ppm}"
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_decoder_solve_time_ns_total {}",
            FEC_DECODER_SOLVE_TIME_NS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_decoder_dedup_evictions_total {}",
            FEC_DECODER_DEDUP_EVICTIONS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_fountain_decoder_evictions_total {}",
            FEC_FOUNTAIN_DECODER_EVICTIONS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_fountain_decoder_admission_rejections_total {}",
            FEC_FOUNTAIN_DECODER_ADMISSION_REJECTIONS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_fec_fountain_decoder_propagation_work_total {}",
            FEC_FOUNTAIN_DECODER_PROPAGATION_WORK.get()
        );
    } // end fec

    // MASQUE
    let _ = writeln!(out, "quicfuscate_masque_active {}", get(&MASQUE_ACTIVE));
    let _ = writeln!(out, "quicfuscate_masque_hint {}", get(&MASQUE_HINT));

    // AEGIS plan
    let _ = writeln!(out, "quicfuscate_aegis_plan {}", get(&AEGIS_PLAN));

    if congestion {
        // Plan selection metrics
        let _ = writeln!(out, "quicfuscate_plan_decisions_total {}", PLAN_DECISIONS_TOTAL.get());
        let _ =
            writeln!(out, "quicfuscate_plan_decisions_default {}", PLAN_DECISIONS_DEFAULT.get());
        let _ = writeln!(out, "quicfuscate_plan_decisions_len {}", PLAN_DECISIONS_LEN.get());
        let _ = writeln!(out, "quicfuscate_plan_select_l_total {}", PLAN_DECISIONS_L.get());
        let _ = writeln!(out, "quicfuscate_plan_select_x4_total {}", PLAN_DECISIONS_X4.get());
        let _ = writeln!(out, "quicfuscate_plan_select_x8_total {}", PLAN_DECISIONS_X8.get());
        let _ =
            writeln!(out, "quicfuscate_plan_select_neon_l_total {}", PLAN_DECISIONS_NEON_L.get());
        let _ = writeln!(out, "quicfuscate_plan_select_morus_total {}", PLAN_DECISIONS_MORUS.get());
        let _ = writeln!(
            out,
            "quicfuscate_data_aead_backend_aegis_l_total {}",
            DATA_AEAD_BACKEND_AEGIS_L_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_data_aead_backend_aegis_x4_total {}",
            DATA_AEAD_BACKEND_AEGIS_X4_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_data_aead_backend_aegis_x8_total {}",
            DATA_AEAD_BACKEND_AEGIS_X8_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_data_aead_backend_morus_total {}",
            DATA_AEAD_BACKEND_MORUS_TOTAL.get()
        );
        let _ = writeln!(out, "quicfuscate_morus1280_scalar_ops {}", MORUS1280_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_morus1280_sse2_ops {}", MORUS1280_SSE2_OPS.get());
        let _ = writeln!(out, "quicfuscate_morus1280_ssse3_ops {}", MORUS1280_SSSE3_OPS.get());
        let _ = writeln!(out, "quicfuscate_morus1280_sse41_ops {}", MORUS1280_SSE41_OPS.get());
        let _ = writeln!(out, "quicfuscate_morus1280_sse42_ops {}", MORUS1280_SSE42_OPS.get());
        let _ = writeln!(out, "quicfuscate_morus1280_neon_ops {}", MORUS1280_NEON_OPS.get());
    } // end congestion (plan/aead)

    if congestion {
        // Compression decision metrics
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_total {}",
            COMPRESS_DECISIONS_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_allow {}",
            COMPRESS_DECISIONS_ALLOW.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_len {}",
            COMPRESS_DECISIONS_SKIP_LEN.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_loss {}",
            COMPRESS_DECISIONS_SKIP_LOSS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_profile {}",
            COMPRESS_DECISIONS_SKIP_PROFILE.get()
        );
    } // end congestion (compression)

    // GHASH backend metrics
    let _ = writeln!(out, "quicfuscate_ghash_pclmul_ops {}", GHASH_PCLMUL_OPS.get());
    let _ = writeln!(out, "quicfuscate_ghash_vpclmul_ops {}", GHASH_VPCLMUL_OPS.get());
    let _ = writeln!(out, "quicfuscate_ghash_pmull_ops {}", GHASH_PMULL_OPS.get());
    let _ = writeln!(out, "quicfuscate_ghash_neon_ops {}", GHASH_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_ghash_sse_ops {}", GHASH_SSE_OPS.get());

    // GHASH scalar fallback metrics
    let _ = writeln!(out, "quicfuscate_ghash_scalar_ops_total {}", GHASH_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_ghash_scalar_calls_total {}", GHASH_SCALAR_CALLS.get());
    let _ = writeln!(out, "quicfuscate_ghash_scalar_bytes_total {}", GHASH_SCALAR_BYTES.get());

    if packets {
        // H3
        let _ = writeln!(out, "quicfuscate_h3_frames_total {}", get(&H3_FRAMES));
        let _ = writeln!(out, "quicfuscate_h3_headers_total {}", get(&H3_HEADERS));
        let _ = writeln!(out, "quicfuscate_h3_data_bytes_total {}", get(&H3_DATA_BYTES));
        let _ = writeln!(out, "quicfuscate_h3_errors_total {}", get(&H3_ERRORS));

        // IP/TUN
        let _ = writeln!(out, "quicfuscate_ip_v4_packets_total {}", get(&IP_V4_PACKETS));
        let _ = writeln!(out, "quicfuscate_ip_v6_packets_total {}", get(&IP_V6_PACKETS));
        let _ = writeln!(out, "quicfuscate_ip_tos_sum {}", get(&IP_TOS_SUM));
        let _ = writeln!(out, "quicfuscate_ip_tos_samples {}", get(&IP_TOS_SAMPLES));
        let _ = writeln!(
            out,
            "quicfuscate_tun_fastpath_attempts_total {}",
            get(&TUN_FASTPATH_ATTEMPTS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_tun_fastpath_direct_writes_total {}",
            get(&TUN_FASTPATH_DIRECT_WRITES)
        );
        let _ = writeln!(
            out,
            "quicfuscate_tun_requirement_rejects_total {}",
            get(&TUN_REQUIREMENT_REJECTS)
        );
        let _ = writeln!(out, "quicfuscate_tun_config_rejects_total {}", get(&TUN_CONFIG_REJECTS));
        let _ = writeln!(
            out,
            "quicfuscate_tun_permission_rejects_total {}",
            get(&TUN_PERMISSION_REJECTS)
        );
        let _ = writeln!(out, "quicfuscate_io_driver_copy_ops_total {}", get(&IO_DRIVER_COPY_OPS));
        let _ =
            writeln!(out, "quicfuscate_io_driver_copy_bytes_total {}", get(&IO_DRIVER_COPY_BYTES));
        let _ = writeln!(
            out,
            "quicfuscate_io_driver_batch_drain_packets_total {}",
            get(&IO_DRIVER_BATCH_DRAIN_PACKETS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_driver_sendmmsg_calls_total {}",
            get(&IO_DRIVER_SENDMMSG_CALLS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_driver_sendmmsg_packets_total {}",
            get(&IO_DRIVER_SENDMMSG_PACKETS)
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_submit_calls_total {}",
            IO_URING_SUBMIT_CALLS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_submit_packets_total {}",
            IO_URING_SUBMIT_PACKETS.get()
        );
        let _ = writeln!(out, "quicfuscate_io_uring_fallbacks_total {}", IO_URING_FALLBACKS.get());
        let _ =
            writeln!(out, "quicfuscate_io_uring_sqpoll_active {}", get(&IO_URING_SQPOLL_ACTIVE));
        let _ = writeln!(out, "quicfuscate_io_uring_zc_sends_total {}", IO_URING_ZC_SENDS.get());
        let _ = writeln!(out, "quicfuscate_io_uring_zc_notifs_total {}", IO_URING_ZC_NOTIFS.get());
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_server_submit_calls_total {}",
            IO_URING_SERVER_SUBMIT_CALLS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_server_packets_total {}",
            IO_URING_SERVER_PACKETS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_recv_batches_total {}",
            IO_URING_RECV_BATCHES.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_io_uring_recv_packets_total {}",
            IO_URING_RECV_PACKETS.get()
        );
        let _ = writeln!(out, "quicfuscate_io_uring_recv_active {}", get(&IO_URING_RECV_ACTIVE));
    } // end packets

    if stealth {
        // Stealth signals
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_rtt_spikes_total {}",
            get(&STEALTH_SIGNAL_RTT_SPIKES)
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_ecn_ce_total {}",
            get(&STEALTH_SIGNAL_ECN_CE)
        );
        let _ = writeln!(out, "quicfuscate_stealth_signal_rst_total {}", get(&STEALTH_SIGNAL_RST));
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_tos_anom_total {}",
            get(&STEALTH_SIGNAL_TOS_ANOM)
        );
        let _ =
            writeln!(out, "quicfuscate_stealth_signal_other_total {}", get(&STEALTH_SIGNAL_OTHER));
        let _ = writeln!(
            out,
            "quicfuscate_server_push_bursts_total {}",
            get(&SERVER_PUSH_BURSTS_TOTAL)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_total_cover_bytes {}",
            get(&SERVER_PUSH_TOTAL_COVER_BYTES)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_bursts_last_minute {}",
            get(&SERVER_PUSH_BURSTS_LAST_MINUTE)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_current_intensity_ppm {}",
            get(&SERVER_PUSH_CURRENT_INTENSITY_PPM)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_trigger_loss_total {}",
            get(&SERVER_PUSH_TRIGGER_LOSS_TOTAL)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_trigger_time_total {}",
            get(&SERVER_PUSH_TRIGGER_TIME_TOTAL)
        );
        let _ = writeln!(
            out,
            "quicfuscate_server_push_trigger_gating_total {}",
            get(&SERVER_PUSH_TRIGGER_GATING_TOTAL)
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_probe_detected_total {}",
            STEALTH_PROBE_DETECTED.get()
        );
        let _ =
            writeln!(out, "quicfuscate_stealth_probe_switch_total {}", STEALTH_PROBE_SWITCH.get());
        let _ = writeln!(out, "quicfuscate_stealth_probe_fake_total {}", STEALTH_PROBE_FAKE.get());
        let _ =
            writeln!(out, "quicfuscate_stealth_probe_block_total {}", STEALTH_PROBE_BLOCK.get());
        let _ = writeln!(
            out,
            "quicfuscate_stealth_mode_escalated_total {}",
            STEALTH_MODE_ESCALATED.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_transitions_total {}",
            STEALTH_INTELLIGENT_TRANSITIONS_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_reason_loss_total {}",
            STEALTH_INTELLIGENT_REASON_LOSS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_reason_jitter_total {}",
            STEALTH_INTELLIGENT_REASON_JITTER.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_reason_timeout_total {}",
            STEALTH_INTELLIGENT_REASON_TIMEOUT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_reason_retransmit_total {}",
            STEALTH_INTELLIGENT_REASON_RETRANSMIT.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_reason_probe_total {}",
            STEALTH_INTELLIGENT_REASON_PROBE.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_intelligent_deescalations_total {}",
            STEALTH_INTELLIGENT_DEESCALATIONS_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_ascii_simd_avx2_bytes_total {}",
            STEALTH_ASCII_SIMD_AVX2_BYTES.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_ascii_simd_sse2_bytes_total {}",
            STEALTH_ASCII_SIMD_SSE2_BYTES.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_ascii_simd_neon_bytes_total {}",
            STEALTH_ASCII_SIMD_NEON_BYTES.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_ascii_scalar_bytes_total {}",
            STEALTH_ASCII_SCALAR_BYTES.get()
        );
    } // end stealth

    let _ = writeln!(out, "quicfuscate_admin_csrf_reject_total {}", ADMIN_CSRF_REJECT_TOTAL.get());
    let _ =
        writeln!(out, "quicfuscate_admin_origin_reject_total {}", ADMIN_ORIGIN_REJECT_TOTAL.get());
    let _ = writeln!(out, "quicfuscate_qkey_path_rebind_total {}", QKEY_PATH_REBIND_TOTAL.get());
    let _ = writeln!(
        out,
        "quicfuscate_engine_handshake_timeout_total {}",
        ENGINE_HANDSHAKE_TIMEOUT_TOTAL.get()
    );

    out
}
