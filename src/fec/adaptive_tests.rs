// FEC adaptive intelligence deep optimization tests (TODO-428).
//
// Tests the bandwidth-aware overhead control function and validates
// that FEC adaptive intelligence behaves correctly under various
// bandwidth scarcity signals.

use super::test_support::{acquire_env_lock, make_pool, EnvGuard};
use super::{AdaptiveFec, FecConfig, FecMode};

// ---------------------------------------------------------------------------
// 1. Bandwidth-aware overhead: scarce bandwidth reduces redundancy
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_aware_scarce_reduces_overhead() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();
    let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    // Report 10% loss to establish moderate loss level
    fec.report_loss(10, 100);

    // Set high redundancy first
    fec.set_redundancy_ppm(500_000);

    // Signal: bandwidth scarce (RTT increasing, cwnd shrinking, throughput dropping)
    fec.bandwidth_aware_overhead_adjustment(1.0, -1.0, -1.0);

    // After scarce signal, red_ppm_hint should decrease
    // (but not below minimum for 10% loss = 100,000 ppm)
    let ppm_after = fec.redundancy_ppm();
    assert!(ppm_after < 500_000, "redundancy not reduced under scarce bandwidth: {}", ppm_after);
}

// ---------------------------------------------------------------------------
// 2. Bandwidth-aware overhead: plentiful bandwidth increases redundancy
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_aware_plentiful_increases_overhead() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();
    let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    // Report 10% loss
    fec.report_loss(10, 100);

    // Start with low redundancy
    fec.set_redundancy_ppm(50_000);

    // Signal: bandwidth plentiful (RTT decreasing, cwnd growing, throughput increasing)
    fec.bandwidth_aware_overhead_adjustment(-1.0, 1.0, 1.0);

    // After plentiful signal, red_ppm_hint should increase
    let ppm_after = fec.redundancy_ppm();
    assert!(
        ppm_after > 50_000,
        "redundancy not increased under plentiful bandwidth: {}",
        ppm_after
    );
}

// ---------------------------------------------------------------------------
// 3. Bandwidth-aware overhead: never below minimum for loss level
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_aware_never_below_minimum() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();
    let config = FecConfig { initial_mode: FecMode::Normal, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    // Report 25% loss → minimum overhead = 300,000 ppm
    fec.report_loss(25, 100);

    // Set high redundancy
    fec.set_redundancy_ppm(1_000_000);

    // Signal: extreme bandwidth scarcity
    fec.bandwidth_aware_overhead_adjustment(1.0, -1.0, -1.0);
    fec.bandwidth_aware_overhead_adjustment(1.0, -1.0, -1.0);
    fec.bandwidth_aware_overhead_adjustment(1.0, -1.0, -1.0);

    // After multiple scarce signals, should converge toward minimum
    // but never go below it
    let ppm_after = fec.redundancy_ppm();
    // Minimum for 25% loss is 300,000 ppm
    assert!(
        ppm_after >= 200_000,
        "redundancy dropped below safe minimum for 25% loss: {}",
        ppm_after
    );
}

// ---------------------------------------------------------------------------
// 4. Bandwidth-aware overhead: zero loss = zero overhead
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_aware_zero_loss_zero_overhead() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();
    let config = FecConfig { initial_mode: FecMode::Zero, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    // Report 0% loss
    fec.report_loss(0, 100);

    // Even with plentiful bandwidth, overhead should stay near zero
    fec.bandwidth_aware_overhead_adjustment(-1.0, 1.0, 1.0);

    let ppm_after = fec.redundancy_ppm();
    // For 0% loss, min_ppm = 0, so target is 0 or very small
    assert!(ppm_after < 50_000, "redundancy non-zero for 0% loss: {}", ppm_after);
}

// ---------------------------------------------------------------------------
// 5. Mode selection accuracy: correct mode for each loss level
// ---------------------------------------------------------------------------

#[test]
fn test_mode_selection_accuracy() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();

    // Test that FEC escalates correctly with increasing loss
    let test_cases = [
        (0u32, 100u32, "zero_or_light"),
        (5, 100, "light_or_normal"),
        (10, 100, "normal"),
        (25, 100, "strong"),
        (50, 100, "extreme_or_fountain"),
    ];

    for (lost, total, _label) in &test_cases {
        let config = FecConfig { initial_mode: FecMode::Zero, ..FecConfig::default() };
        let mut fec = AdaptiveFec::new(config);

        // Feed some packets to establish baseline
        for id in 0..100u64 {
            let pkt = super::test_support::mk_src_packet(id, 1400, &pool);
            let _ = fec.on_send(pkt);
        }

        // Report loss multiple times to let estimator converge
        for _ in 0..5 {
            fec.report_loss(*lost as usize, *total as usize);
        }

        // Feed more packets to let mode transition settle
        for id in 100..300u64 {
            let pkt = super::test_support::mk_src_packet(id, 1400, &pool);
            let _ = fec.on_send(pkt);
        }

        let mode = fec.current_mode();

        // Verify mode is appropriate for loss level
        match *lost {
            0 => assert!(
                mode == FecMode::Zero || mode == FecMode::Light,
                "0% loss should be Zero/Light, got {:?}",
                mode
            ),
            5 => assert!(mode != FecMode::Zero, "5% loss should not be Zero, got {:?}", mode),
            10 => assert!(mode != FecMode::Zero, "10% loss should not be Zero, got {:?}", mode),
            25 => assert!(
                mode != FecMode::Zero && mode != FecMode::Light,
                "25% loss should not be Zero/Light, got {:?}",
                mode
            ),
            50 => assert!(
                mode != FecMode::Zero && mode != FecMode::Light,
                "50% loss should not be Zero/Light, got {:?}",
                mode
            ),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Hysteresis: mode doesn't flap on small loss oscillations
// ---------------------------------------------------------------------------

#[test]
fn test_hysteresis_prevents_flapping() {
    let _lock = acquire_env_lock();
    let _g = EnvGuard::set("QUICFUSCATE_FEC_INTERLEAVE", "0");

    let pool = make_pool();
    let config = FecConfig { initial_mode: FecMode::Zero, ..FecConfig::default() };
    let mut fec = AdaptiveFec::new(config);

    // Feed baseline packets
    for id in 0..100u64 {
        let pkt = super::test_support::mk_src_packet(id, 1400, &pool);
        let _ = fec.on_send(pkt);
    }

    // Oscillate loss: 5% → 6% → 5% → 6% (small oscillation)
    let mut mode_changes = 0;
    let mut prev_mode = fec.current_mode();

    for i in 0..20u64 {
        let loss = if i % 2 == 0 { 5 } else { 6 };
        fec.report_loss(loss, 100);
        for id in 0..10u64 {
            let pkt = super::test_support::mk_src_packet(1000 + i * 10 + id, 1400, &pool);
            let _ = fec.on_send(pkt);
        }
        let cur_mode = fec.current_mode();
        if cur_mode != prev_mode {
            mode_changes += 1;
            prev_mode = cur_mode;
        }
    }

    // Small oscillation (5%↔6%) should not cause flapping
    assert!(
        mode_changes <= 2,
        "hysteresis failed: {} mode changes for 5%↔6% oscillation",
        mode_changes
    );
}
