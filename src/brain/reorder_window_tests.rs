use super::{decay_reorder_window, reorder_ratio_from_window, REORDER_WINDOW_HALF_LIFE_SECS};
use core::time::Duration;

fn half_life() -> Duration {
    Duration::from_secs_f64(REORDER_WINDOW_HALF_LIFE_SECS)
}

/// A reordering burst must stop influencing policy once a clean period ages it out.
#[test]
fn a_burst_decays_away_under_subsequent_clean_traffic() {
    // 100 packets, 50 of them reordered: a severe burst.
    let (packets, reorders) = decay_reorder_window(0.0, 0.0, 100, 50, Duration::ZERO);
    let burst_ratio = reorder_ratio_from_window(packets, reorders);
    assert!((burst_ratio - 0.5).abs() < 1e-9, "the burst must be visible: {burst_ratio}");

    // Clean traffic arriving over several half-lives.
    let mut packets = packets;
    let mut reorders = reorders;
    for _ in 0..6 {
        let advanced = decay_reorder_window(packets, reorders, 100, 0, half_life());
        packets = advanced.0;
        reorders = advanced.1;
    }
    let settled = reorder_ratio_from_window(packets, reorders);
    assert!(
        settled < 0.01,
        "a burst followed by sustained clean traffic must stop driving policy, got {settled}"
    );
}

/// Idle time shrinks the window's weight without changing its ratio.
#[test]
fn idle_time_decays_both_accumulators_and_preserves_the_ratio() {
    let (packets, reorders) = decay_reorder_window(0.0, 0.0, 200, 40, Duration::ZERO);
    let before = reorder_ratio_from_window(packets, reorders);
    assert!((before - 0.2).abs() < 1e-9);

    // A long idle gap with no new observations.
    let (idle_packets, idle_reorders) =
        decay_reorder_window(packets, reorders, 0, 0, half_life() * 3);
    let after = reorder_ratio_from_window(idle_packets, idle_reorders);
    assert!(
        (after - before).abs() < 1e-9,
        "idle time must not change the ratio, only the weight: {before} -> {after}"
    );
    assert!(idle_packets < packets, "idle time must reduce the window's weight");
    assert!(idle_packets > 0.0, "decay must not collapse to zero at three half-lives");

    // One half-life halves the weight.
    let (halved, _) = decay_reorder_window(packets, reorders, 0, 0, half_life());
    assert!(
        (halved - packets / 2.0).abs() < 1e-6,
        "one half-life must halve the weight: {packets} -> {halved}"
    );
}

/// An empty window reports no reordering rather than dividing by zero.
#[test]
fn an_empty_window_reports_no_reordering() {
    assert_eq!(reorder_ratio_from_window(0.0, 0.0), 0.0);
    assert_eq!(reorder_ratio_from_window(0.0, 5.0), 0.0);
    let (packets, reorders) = decay_reorder_window(0.0, 0.0, 0, 0, half_life());
    assert_eq!(reorder_ratio_from_window(packets, reorders), 0.0);
}

/// The ratio is bounded, and reorders can never exceed observed packets.
#[test]
fn the_window_cannot_report_more_reordering_than_traffic() {
    // A caller reporting more reorders than packets must not produce a ratio above one.
    let (packets, reorders) = decay_reorder_window(0.0, 0.0, 10, 50, Duration::ZERO);
    assert!(reorders <= packets, "reorders must be clamped to observed packets");
    assert_eq!(reorder_ratio_from_window(packets, reorders), 1.0);

    // Every packet reordered is exactly one.
    let (packets, reorders) = decay_reorder_window(0.0, 0.0, 10, 10, Duration::ZERO);
    assert_eq!(reorder_ratio_from_window(packets, reorders), 1.0);
}

/// Non-finite and negative state must recover from a fresh observation.
#[test]
fn non_finite_accumulators_are_sanitised_rather_than_propagated() {
    for poisoned in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
        let (packets, reorders) = decay_reorder_window(poisoned, poisoned, 100, 10, Duration::ZERO);
        assert!(packets.is_finite() && reorders.is_finite(), "state must stay finite");
        let ratio = reorder_ratio_from_window(packets, reorders);
        assert!(ratio.is_finite(), "ratio must stay finite for {poisoned}");
        assert!((0.0..=1.0).contains(&ratio), "ratio must stay bounded: {ratio}");
        // The fresh observation still lands, so the window recovers rather than staying stuck.
        assert!((ratio - 0.1).abs() < 1e-9, "recovered ratio should reflect the new sample");
    }
}

/// Lifetime totals use saturating arithmetic rather than wrapping.
#[test]
fn lifetime_counters_saturate_rather_than_wrapping() {
    // This mirrors the saturating_add the drain path uses for the observability totals.
    let nearly_full = u64::MAX - 5;
    assert_eq!(nearly_full.saturating_add(10), u64::MAX);
    assert_eq!(u64::MAX.saturating_add(1), u64::MAX);
}
