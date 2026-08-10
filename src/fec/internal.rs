#![allow(private_interfaces)]
#[cfg(test)]
use super::*;
#[cfg(test)]
use std::sync::Arc;

#[cfg(test)]
pub(crate) use super::ModeManager;
#[cfg(test)]
pub(crate) use qf_fec::{DecoderVariant, EncoderVariant, LazyDecoder};
#[cfg(test)]
pub(crate) use qf_fec::{InterleavedDecoder, InterleavedEncoder};

// =========================================================================
// LAZY DECODING: 0 CPU when no packet loss detected
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::test_support::*;

    fn test_policy() -> FecRuntimePolicy {
        FecRuntimePolicy {
            decoder_policy: "auto".to_string(),
            lazy_enabled: false,
            interleave_enabled: false,
            switch_threshold_override: None,
            switch_min_up_ms: 0,
            switch_min_down_ms: 0,
            auto_gf4_enabled: true,
            fountain_window: 2048,
            extreme_window: 1024,
            fountain_symbol_size: 1500,
            stream_every_override: None,
            interleave_depth_override: None,
            partial_enabled: true,
            kalman_q_override: None,
            kalman_r_override: None,
        }
    }

    // --- ZeroEncoder tests ---

    #[test]
    fn test_zero_encoder_never_generates_repairs() {
        let pool = make_pool();
        let mut enc = ZeroEncoder::new(64, 80);
        for i in 0..10 {
            let pkt = mk_src_packet(i, 100, &pool);
            enc.take_packet(pkt);
        }
        // Zero encoder should never produce repair packets
        for i in 0..10 {
            assert!(enc.generate_repair_packet(i, &pool).is_none());
        }
    }

    #[test]
    fn test_zero_encoder_window_always_zero() {
        let mut enc = ZeroEncoder::new(64, 80);
        assert_eq!(enc.packets_in_window(), 0);
        let pool = make_pool();
        enc.take_packet(mk_src_packet(0, 100, &pool));
        // Window is always 0 - zero mode tracks nothing
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn test_zero_encoder_clear_resets_counter() {
        let pool = make_pool();
        let mut enc = ZeroEncoder::new(64, 80);
        enc.take_packet(mk_src_packet(0, 100, &pool));
        enc.take_packet(mk_src_packet(1, 100, &pool));
        assert_eq!(enc.packets_passed, 2);
        enc.clear_window();
        assert_eq!(enc.packets_passed, 0);
    }

    // --- ZeroDecoder tests ---

    #[test]
    fn test_zero_decoder_no_loss_returns_packets() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        // Feed contiguous source packets (seq 1, 2, 3)
        for seq in 1..=3 {
            let mut pkt = mk_src_packet(seq, 100, &pool);
            pkt.seq = seq;
            pkt.is_systematic = true;
            dec.take_packet(pkt);
        }
        let result = dec.get_result();
        assert!(result.is_some());
        assert_eq!(result.as_ref().map(|r| r.len()), Some(3));
    }

    #[test]
    fn test_zero_decoder_gap_triggers_loss_detection() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        // Feed seq 1, then skip to seq 5 (gap of 3)
        let mut p1 = mk_src_packet(1, 100, &pool);
        p1.seq = 1;
        p1.is_systematic = true;
        dec.take_packet(p1);

        let mut p2 = mk_src_packet(5, 100, &pool);
        p2.seq = 5;
        p2.is_systematic = true;
        dec.take_packet(p2);

        // Loss detected - get_result returns None (needs upgrade)
        assert!(dec.get_result().is_none());
    }

    #[test]
    fn test_zero_decoder_partial_result_drains_buffer() {
        let pool = make_pool();
        let mut dec = ZeroDecoder::new(64, pool.clone());
        let mut pkt = mk_src_packet(1, 100, &pool);
        pkt.seq = 1;
        pkt.is_systematic = true;
        dec.take_packet(pkt);
        let partial = dec.get_partial_result();
        assert_eq!(partial.len(), 1);
        // Buffer should be drained after get_partial_result
        let partial2 = dec.get_partial_result();
        assert_eq!(partial2.len(), 0);
    }

    // --- EncoderVariant tests ---

    #[test]
    fn test_encoder_variant_zero_backend_kind() {
        let policy = test_policy();
        let enc = EncoderVariant::new_with_policy(FecMode::Zero, 0, 0, &policy);
        assert_eq!(enc.backend_kind(), "zero");
    }

    #[test]
    fn test_encoder_variant_gf8_takes_and_counts_packets() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = EncoderVariant::new_with_policy(FecMode::Normal, 4, 6, &policy);
        assert_eq!(enc.packets_in_window(), 0);

        for i in 0..4 {
            enc.take_packet(mk_src_packet(i, 100, &pool));
        }
        assert_eq!(enc.packets_in_window(), 4);

        enc.clear_window();
        assert_eq!(enc.packets_in_window(), 0);
    }

    // --- DecoderVariant tests ---

    #[test]
    fn test_decoder_variant_zero_backend_kind() {
        let pool = make_pool();
        let policy = test_policy();
        let dec = DecoderVariant::new_with_policy(FecMode::Zero, 0, pool, &policy);
        assert_eq!(dec.backend_kind(), "zero");
    }

    // --- LazyDecoder tests ---

    #[test]
    fn test_lazy_decoder_buffers_repairs_until_loss() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        // Feed a repair packet (non-systematic) - should be buffered
        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);
        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "buffered repair alone must not force recovery");

        // Feed contiguous source packet - no gap, pending repairs get cleared
        let mut src = mk_src_packet(1, 100, &pool);
        src.is_systematic = true;
        src.seq = 1;
        dec.take_packet(src);
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 1);
        assert!(!dec.recovery_needed(), "contiguous source path must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_flushes_on_gap() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        // Feed source seq=1
        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        // Feed a buffered repair
        let mut repair = mk_src_packet(200, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 200;
        dec.take_packet(repair);
        assert_eq!(dec.pending_repairs_len(), 1);

        // Feed source seq=5 (gap: 2,3,4 missing)
        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        // Gap detected -> repairs flushed to inner decoder
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 0);
        assert!(dec.recovery_needed(), "gap must enable recovery polling");
        assert!(dec.full_recovery_pending(), "flushed repair must request full recovery");
    }

    #[test]
    fn test_lazy_decoder_gap_without_repair_stays_lazy() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        assert_eq!(
            dec.pending_sources_len(),
            2,
            "gap without repair should retain bounded source context"
        );
        assert!(
            !dec.recovery_needed(),
            "gap without repair should stay lazy because no recovery is possible yet"
        );
        assert!(
            !dec.partial_recovery_pending(),
            "gap without repair must not trigger partial decoder polling"
        );
        assert!(
            !dec.full_recovery_pending(),
            "gap without new repair must not trigger full matrix recovery"
        );
    }

    #[test]
    fn test_lazy_decoder_repair_after_gap_requests_full_recovery_once() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        let mut s1 = mk_src_packet(1, 100, &pool);
        s1.is_systematic = true;
        s1.seq = 1;
        dec.take_packet(s1);

        let mut s5 = mk_src_packet(5, 100, &pool);
        s5.is_systematic = true;
        s5.seq = 5;
        dec.take_packet(s5);

        let mut repair = mk_src_packet(200, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 200;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 0, "repair should flush after a known gap");
        assert!(dec.full_recovery_pending(), "new repair must request full recovery");

        let _ = dec.get_result();
        assert!(
            !dec.full_recovery_pending(),
            "full recovery request must be consumed after one get_result call"
        );
    }

    #[test]
    fn test_lazy_decoder_prunes_clean_complete_blocks() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        for seq in 1..=4u64 {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }

        assert_eq!(dec.seen_seqs_len(), 0, "complete clean block should be pruned");
        assert_eq!(dec.pending_sources_len(), 0, "complete clean block should drop source buffer");

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "repair after clean full block must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_depth_normalizes_interleaved_clean_sources() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_depth(FecMode::Normal, 4, pool.clone(), &policy, 4);

        for seq in [0_u64, 4, 8, 12] {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
            assert!(
                !dec.recovery_needed(),
                "interleaved clean source sequence {seq} must not look like a loss gap"
            );
        }

        assert_eq!(dec.seen_seqs_len(), 0, "complete interleaved clean block should be pruned");
        assert_eq!(
            dec.pending_sources_len(),
            0,
            "complete interleaved clean block should drop source buffer"
        );

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert!(!dec.recovery_needed(), "repair after interleaved clean block must stay lazy");
    }

    #[test]
    fn test_lazy_decoder_tail_loss_replays_buffered_sources_on_recovery() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let mut dec = LazyDecoder::new_with_policy(FecMode::Normal, 4, pool.clone(), &policy);

        for seq in 1..=3u64 {
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }
        assert_eq!(dec.pending_sources_len(), 3);

        let mut repair = mk_src_packet(100, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 100;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 1);
        assert_eq!(dec.pending_sources_len(), 3);
        assert!(dec.full_recovery_pending(), "tail-loss repair must request full recovery");

        let _ = dec.get_result();

        assert_eq!(dec.pending_sources_len(), 0, "get_result must replay buffered sources");
        assert_eq!(dec.pending_repairs_len(), 0, "get_result must replay buffered repairs");
        assert!(
            !dec.full_recovery_pending(),
            "full recovery request must be consumed after get_result"
        );
    }

    #[test]
    fn test_lazy_decoder_streaming_repair_requests_immediate_recovery() {
        let pool = make_pool();
        let mut policy = test_policy();
        policy.lazy_enabled = true;

        let profile = wire::WireProfile {
            epoch: 1,
            codec: wire::WireCodec::StreamingGf8,
            source_count: 4,
            total_count: 8,
            interleave_depth: 1,
        };
        let mut dec = LazyDecoder::new_for_wire(
            profile.codec,
            profile.block_source_count() as usize,
            pool.clone(),
            &policy,
            profile.interleave_depth as usize,
            DEFAULT_FOUNTAIN_SEED,
            0,
        );

        {
            let seq = 0_u64;
            let mut src = mk_src_packet(seq, 100, &pool);
            src.is_systematic = true;
            src.seq = seq;
            dec.take_packet(src);
        }
        assert_eq!(dec.pending_sources_len(), 1);

        let mut repair = mk_src_packet(1, 50, &pool);
        repair.is_systematic = false;
        repair.seq = 0;
        dec.take_packet(repair);

        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.pending_sources_len(), 0);
        assert!(
            dec.full_recovery_pending(),
            "wire-filtered streaming repair must request immediate recovery"
        );
        assert!(
            dec.recovery_needed(),
            "streaming loss evidence must wake the decoder without waiting for block end"
        );
    }

    // --- ModeManager tests ---

    #[test]
    fn test_mode_manager_initial_state() {
        let policy = test_policy();
        let mgr = ModeManager::with_runtime_policy(FecMode::Normal, 0.05, &policy);
        assert_eq!(mgr.current_mode(), FecMode::Normal);
        assert!(mgr.current_window() > 0);
    }

    #[test]
    fn test_mode_manager_force_state() {
        let policy = test_policy();
        let mut mgr = ModeManager::with_runtime_policy(FecMode::Normal, 0.05, &policy);
        mgr.force_state(FecMode::Strong, 256);
        assert_eq!(mgr.current_mode(), FecMode::Strong);
        assert_eq!(mgr.current_window(), 256);
    }

    #[test]
    fn test_mode_manager_params_for_zero_mode() {
        let (k, n) = ModeManager::params_for(FecMode::Zero, 0);
        // Zero mode: no window needed
        assert_eq!(k, 0);
        assert_eq!(n, 0);
    }

    #[test]
    fn test_mode_manager_params_for_normal_mode() {
        let (k, n) = ModeManager::params_for(FecMode::Normal, 64);
        // Normal mode with default window 64: n >= k (redundancy >= 1.0)
        assert!(k > 0);
        assert!(n >= k, "n={} must be >= k={}", n, k);
    }

    // --- InterleavedEncoder tests ---

    #[test]
    fn test_interleaved_encoder_round_robin_distribution() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);

        // Feed 4 packets - should distribute 2 per block
        for i in 0..4 {
            enc.take_packet(mk_src_packet(i, 100, &pool));
        }
        assert_eq!(enc.packets_in_window(), 4);

        enc.clear_window();
        assert_eq!(enc.packets_in_window(), 0);
    }

    #[test]
    fn test_interleaved_encoder_params() {
        let policy = test_policy();
        let enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);
        let (k, n) = enc.params();
        assert_eq!(k, 8);
        assert_eq!(n, 12);
    }

    #[test]
    fn test_interleaved_encoder_reports_the_shape_it_actually_represents() {
        let mut policy = test_policy();
        policy.interleave_enabled = true;

        // 10 sources over 4 lanes floors to 2 per lane, so only 8 are represented. Reporting the
        // request here would emit a wire source_count that its own interleave depth cannot divide.
        let enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 10, 14, 4, &policy);
        assert_eq!(enc.params(), (8, 12), "params must describe the represented lanes");
        let (represented_k, _) = enc.params();
        assert_eq!(
            represented_k % enc.depth(),
            0,
            "represented sources must divide by depth so the wire profile cannot report an \
             uneven interleave"
        );

        // A divisible request is represented exactly.
        let exact = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 4, &policy);
        assert_eq!(exact.params(), (8, 12));
    }

    #[test]
    fn test_interleaved_encoder_refuses_aliasing_repair_ordinals() {
        let policy = test_policy();
        let pool = make_pool();
        let mut enc = InterleavedEncoder::new_with_policy(FecMode::Normal, 8, 12, 2, &policy);

        // `i / depth` is the ordinal and `i % depth` the lane. An ordinal above the representable
        // range would shift out of the u64 identity and collide with an unrelated repair.
        let aliasing_index = ((crate::fec::MAX_REPAIR_ORDINAL as usize) + 1)
            .saturating_mul(enc.depth())
            .saturating_add(1);
        assert!(
            enc.generate_repair_packet(aliasing_index, &pool).is_none(),
            "out-of-range repair ordinal must be refused, not aliased"
        );
    }

    #[test]
    fn test_params_for_target_rejects_non_finite_redundancy() {
        let base = FecProtectionTarget {
            family: FecBackendFamily::HeavyBlock,
            redundancy: 1.5,
            effective_window: 16,
            stream_every: None,
        };

        let (_, k, n) = ModeManager::params_for_target(base, 16, false);
        assert_eq!(k, 16);
        assert_eq!(n, 24, "a finite ratio still scales the total count");

        // NaN previously survived `f32::min`, which returns the other operand for NaN, so the
        // clamp produced MAX_TOTAL_COUNT: the most expensive possible repair budget.
        for broken in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let target = FecProtectionTarget { redundancy: broken, ..base };
            let (_, k, n) = ModeManager::params_for_target(target, 16, false);
            assert_eq!(k, 16);
            assert_eq!(
                n, k,
                "non-finite redundancy {broken} must fall back to systematic-only, not to the maximum"
            );
        }
    }

    #[test]
    fn test_mode_manager_force_state_preserves_zero_semantics() {
        let policy = test_policy();
        let mut mgr = ModeManager::with_runtime_policy(FecMode::Zero, 0.1, &policy);
        mgr.force_state(FecMode::Zero, 5);
        assert_eq!(mgr.current_window(), 0);
        mgr.force_state(FecMode::Zero, 0);
        assert_eq!(mgr.current_window(), 0);
        mgr.force_state(FecMode::Normal, 0);
        assert_eq!(mgr.current_window(), 1);
        mgr.force_state(FecMode::Strong, crate::fec::wire::MAX_SOURCE_COUNT as usize + 10);
        assert_eq!(mgr.current_window(), crate::fec::wire::MAX_SOURCE_COUNT as usize);
    }

    #[test]
    fn test_lazy_decoder_rejected_zero_does_not_buffer() {
        let mut policy = test_policy();
        policy.lazy_enabled = true;
        let pool = make_pool();
        let mut dec = LazyDecoder::new_with_policy(FecMode::Zero, 0, Arc::clone(&pool), &policy);

        for i in 0..100u64 {
            dec.take_packet(mk_src_packet(i, 100, &pool));
        }

        for i in 0..50u64 {
            let repair = FecPacket::new(1000 + i, None, 0, false, None, 0, Arc::clone(&pool));
            dec.take_packet(repair);
        }

        assert_eq!(dec.pending_sources_len(), 0);
        assert_eq!(dec.pending_repairs_len(), 0);
        assert_eq!(dec.seen_seqs_len(), 0);
        assert!(dec.get_result().is_some_and(|v| v.is_empty()));
        assert!(dec.get_partial_result().is_empty());
    }

    #[test]
    fn test_interleaved_decoder_routes_large_source_sequences_in_u64() {
        let mut policy = test_policy();
        policy.interleave_enabled = true;
        policy.lazy_enabled = true;
        let pool = make_pool();
        let mut dec =
            InterleavedDecoder::new_with_policy(FecMode::Normal, 4, Arc::clone(&pool), 2, &policy);

        // u64::MAX is odd, so with depth 2 it must route to block 1.
        dec.take_packet(mk_src_packet(u64::MAX, 100, &pool));
        assert_eq!(dec.block_pending_sources_len(1), Some(1));
        assert_eq!(dec.block_pending_sources_len(0), Some(0));

        // u64::MAX - 1 is even, so it must route to block 0.
        dec.take_packet(mk_src_packet(u64::MAX - 1, 100, &pool));
        assert_eq!(dec.block_pending_sources_len(0), Some(1));
        assert_eq!(dec.block_pending_sources_len(1), Some(1));
    }
}
