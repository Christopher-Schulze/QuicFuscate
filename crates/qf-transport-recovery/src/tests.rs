use super::Recovery;
use core::time::Duration;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_fec_callbacks_receive_live_packet_metadata() {
    let mut recovery = Recovery::new(12_000, 1200);
    let sent_pkt = Arc::new(AtomicU64::new(0));
    let sent_bytes = Arc::new(AtomicUsize::new(0));
    let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
    let lost_bytes = Arc::new(AtomicUsize::new(0));

    let sent_pkt_cb = Arc::clone(&sent_pkt);
    let sent_bytes_cb = Arc::clone(&sent_bytes);
    let lost_pkt_cb = Arc::clone(&lost_pkt);
    let lost_bytes_cb = Arc::clone(&lost_bytes);

    recovery.set_fec_callbacks(
        move |pn, bytes| {
            sent_pkt_cb.store(pn, Ordering::Relaxed);
            sent_bytes_cb.store(bytes, Ordering::Relaxed);
        },
        move |pn, bytes| {
            lost_pkt_cb.store(pn, Ordering::Relaxed);
            lost_bytes_cb.store(bytes, Ordering::Relaxed);
        },
    );

    let now = Instant::now();
    recovery.on_packet_sent(42, 1200, now);
    recovery.on_loss_packet(42, 1200, now);
    assert_eq!(sent_pkt.load(Ordering::Relaxed), 42);
    assert_eq!(sent_bytes.load(Ordering::Relaxed), 1200);
    assert_eq!(lost_pkt.load(Ordering::Relaxed), 42);
    assert_eq!(lost_bytes.load(Ordering::Relaxed), 1200);

    // Legacy loss API routes through packet-based callback with packet_num=0.
    recovery.on_loss(777, now);
    assert_eq!(lost_pkt.load(Ordering::Relaxed), 0);
    assert_eq!(lost_bytes.load(Ordering::Relaxed), 777);
}

#[test]
fn pmtu_policy_defaults_and_validation_are_bounded() {
    let policy = super::PmtuPolicy::default();
    assert_eq!(policy.min_mtu, 1280);
    assert_eq!(policy.max_mtu, 1500);
    assert!(policy.validate().is_ok());
    assert!(super::PmtuPolicy { min_mtu: 1199, ..policy }.validate().is_err());
    assert!(super::PmtuPolicy { max_mtu: 1200, ..policy }.validate().is_err());
}

#[test]
fn test_reno_algorithm() {
    let mut recovery = Recovery::with_algorithm(12_000, 1200, super::cc::Algorithm::Reno);
    let now = Instant::now();
    recovery.on_packet_sent(1, 1200, now);
    recovery.on_ack(1200, now);
    assert!(recovery.cwnd > 0);
}

#[test]
fn test_stealth_mode_wrapping() {
    let mut recovery = Recovery::new(12_000, 1200);
    let now = Instant::now();
    recovery.on_packet_sent(1, 1200, now);
    recovery
        .set_stealth_mode(true, super::BrowserProfile::Firefox)
        .expect("secure entropy must be available");
    recovery.on_ack(1200, now);
    assert!(recovery.cwnd > 0);
}

#[test]
fn stealth_seed_failure_retains_each_paced_controller() {
    let previous = qf_common::rng::test_force_secure_entropy_failure(true);
    for algorithm in
        [super::cc::Algorithm::Bbr3, super::cc::Algorithm::Bbr2, super::cc::Algorithm::Cubic]
    {
        let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
        assert!(recovery.set_stealth_mode(true, super::BrowserProfile::Chrome).is_err());
        match (algorithm, &recovery.cc) {
            (super::cc::Algorithm::Bbr3, super::cc::CcImpl::Bbr3(_))
            | (super::cc::Algorithm::Bbr2, super::cc::CcImpl::Bbr2(_))
            | (super::cc::Algorithm::Cubic, super::cc::CcImpl::Cubic(_)) => {}
            _ => panic!("failed stealth activation must retain the base controller"),
        }
    }
    qf_common::rng::test_force_secure_entropy_failure(previous);
}

#[test]
fn reno_stealth_wrapper_does_not_require_entropy() {
    let previous = qf_common::rng::test_force_secure_entropy_failure(true);
    let mut recovery = Recovery::with_algorithm(12_000, 1200, super::cc::Algorithm::Reno);
    let result = recovery.set_stealth_mode(true, super::BrowserProfile::Chrome);
    qf_common::rng::test_force_secure_entropy_failure(previous);

    assert!(result.is_ok(), "Reno has no randomized stealth post-processing path");
    assert!(matches!(recovery.cc, super::cc::CcImpl::StealthReno(_)));
}

#[test]
fn test_rtt_ewma_smoothing() {
    let mut recovery = Recovery::new(12_000, 1200);
    // First sample initializes
    recovery.update_rtt(Duration::from_millis(100));
    assert_eq!(recovery.rtt, Duration::from_millis(100));
    assert_eq!(recovery.rtt_var(), Duration::from_millis(50));
    // Second sample: EWMA smoothing
    recovery.update_rtt(Duration::from_millis(120));
    // SRTT = 7/8 * 100 + 1/8 * 120 = 87.5 + 15 = 102.5ms
    assert!(recovery.rtt > Duration::from_millis(100));
    assert!(recovery.rtt < Duration::from_millis(110));
    // RTTVAR = 3/4 * 50 + 1/4 * 20 = 37.5 + 5 = 42.5ms
    assert!(recovery.rtt_var() < Duration::from_millis(50));
}

#[test]
fn test_rtt_min_tracking() {
    let mut recovery = Recovery::new(12_000, 1200);
    recovery.update_rtt(Duration::from_millis(100));
    recovery.update_rtt(Duration::from_millis(50));
    recovery.update_rtt(Duration::from_millis(200));
    assert_eq!(recovery.min_rtt(), Duration::from_millis(50));
}

#[test]
fn test_time_based_loss_detection() {
    let mut recovery = Recovery::new(12_000, 1200);
    // Before RTT is initialized, no time-based loss detection
    let now = Instant::now();
    assert!(recovery.time_loss_deadline(now).is_none());
    // After RTT init, threshold = 9/8 * SRTT
    recovery.update_rtt(Duration::from_millis(80));
    let deadline = recovery.time_loss_deadline(now).unwrap();
    let threshold = (Duration::from_millis(80) * 9) / 8;
    assert_eq!(deadline, now + threshold);
}

#[test]
fn test_gentle_path_migration_preserves_cwnd() {
    use super::cc::{Algorithm, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget};
    let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
    // Grow cwnd via ACKs (Reno slow-start doubles cwnd each RTT).
    let now = Instant::now();
    for i in 0..20 {
        recovery.on_packet_sent(i, 1200, now);
        recovery.on_ack(1200, now);
    }
    let cwnd_before = recovery.cwnd;
    assert!(cwnd_before > 12_000, "cwnd should have grown: {cwnd_before}");
    let policy = MigrationPolicy {
        port_rebinding_cwnd_factor: 0.5,
        cooldown: Duration::ZERO,
        probe_target: MigrationProbeTarget::PreviousWindow,
    };
    recovery.on_path_change(PathChangeKind::PortRebinding, Duration::from_millis(20), policy, now);
    let cwnd_after = recovery.cwnd;
    assert!(cwnd_after > 2400, "not reset to minimum: {cwnd_after}");
    assert!(cwnd_after <= cwnd_before);
    assert_eq!(cwnd_after, (cwnd_before / 2).max(2400));
    assert_eq!(recovery.ssthresh, cwnd_before);
}

#[test]
fn exact_port_rebinding_vectors_reach_every_controller() {
    use super::cc::{Algorithm, CongestionController, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget};

    for algorithm in [Algorithm::Reno, Algorithm::Cubic, Algorithm::Bbr2, Algorithm::Bbr3] {
        for (factor, expected) in [(0.5, 50_000), (0.25, 25_000), (1.0, 100_000)] {
            let mut recovery = Recovery::with_algorithm(100_000, 1200, algorithm);
            let now = Instant::now();
            recovery.on_packet_sent(1, 1200, now);
            let event = recovery.on_path_change(
                PathChangeKind::PortRebinding,
                Duration::from_millis(17),
                MigrationPolicy {
                    port_rebinding_cwnd_factor: factor,
                    cooldown: Duration::ZERO,
                    probe_target: MigrationProbeTarget::PreviousWindow,
                },
                now,
            );
            assert_eq!(event.congestion_window, expected, "{algorithm:?} factor={factor}");
            assert_eq!(event.probe_target, 100_000, "{algorithm:?} factor={factor}");
            assert_eq!(recovery.cwnd, expected, "{algorithm:?} factor={factor}");
            assert_eq!(recovery.ssthresh, 100_000, "{algorithm:?} factor={factor}");
            assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?} factor={factor}");
        }

        let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
        recovery.cc.set_cwnd(100_000);
        recovery.sync_from_cc();
        recovery.on_packet_sent(1, 1200, Instant::now());
        let event = recovery.on_path_change(
            PathChangeKind::PortRebinding,
            Duration::from_millis(17),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 0.0,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::PreviousWindow,
            },
            Instant::now(),
        );
        assert_eq!(event.congestion_window, 12_000, "{algorithm:?} factor=0");
        assert_eq!(event.probe_target, 12_000, "{algorithm:?} factor=0");
        assert_eq!(recovery.cwnd, 12_000, "{algorithm:?} factor=0");
        assert_eq!(recovery.ssthresh, 12_000, "{algorithm:?} factor=0");
        assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?} factor=0");
    }
}

#[test]
fn reduced_window_policy_sets_the_avoidance_boundary() {
    use super::cc::{Algorithm, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget};

    let mut recovery = Recovery::with_algorithm(100_000, 1200, Algorithm::Reno);
    recovery.on_path_change(
        PathChangeKind::PortRebinding,
        Duration::from_millis(10),
        MigrationPolicy {
            port_rebinding_cwnd_factor: 0.5,
            cooldown: Duration::ZERO,
            probe_target: MigrationProbeTarget::ReducedWindow,
        },
        Instant::now(),
    );
    assert_eq!(recovery.cwnd, 50_000);
    assert_eq!(recovery.ssthresh, 50_000);
}

#[test]
fn old_path_ack_releases_flight_without_updating_new_path_cc_or_rtt() {
    use super::cc::{Algorithm, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget, PacketSpace};

    let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
    let start = Instant::now();
    recovery.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, true, true, None, start);
    recovery.on_path_change(
        PathChangeKind::NewAddress,
        Duration::from_millis(40),
        MigrationPolicy {
            port_rebinding_cwnd_factor: 1.0,
            cooldown: Duration::ZERO,
            probe_target: MigrationProbeTarget::PreviousWindow,
        },
        start + Duration::from_millis(40),
    );

    let old_outcome = recovery.on_ack_received(
        PacketSpace::Application,
        &[(0, 1)],
        Duration::ZERO,
        true,
        false,
        start + Duration::from_millis(100),
    );
    assert_eq!(old_outcome.rtt_sample, None);
    assert_eq!(recovery.rtt, Duration::from_millis(40));
    assert_eq!(recovery.cwnd, 12_000);
    assert_eq!(recovery.bytes_in_flight, 0);

    recovery.on_packet_sent_in_space(
        PacketSpace::Application,
        1,
        1200,
        true,
        true,
        None,
        start + Duration::from_millis(110),
    );
    let new_outcome = recovery.on_ack_received(
        PacketSpace::Application,
        &[(1, 2)],
        Duration::ZERO,
        true,
        false,
        start + Duration::from_millis(140),
    );
    assert_eq!(new_outcome.rtt_sample, Some(Duration::from_millis(30)));
    assert_eq!(recovery.rtt, Duration::from_millis(30));
    assert_eq!(recovery.cwnd, 13_200);
}

#[test]
fn old_path_loss_releases_flight_without_reducing_new_path_cc() {
    use super::cc::{Algorithm, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget, PacketSpace};

    let mut recovery = Recovery::with_algorithm(12_000, 1200, Algorithm::Reno);
    let start = Instant::now();
    seed_space(&mut recovery, PacketSpace::Application, 5, start);
    recovery.on_path_change(
        PathChangeKind::NewAddress,
        Duration::from_millis(40),
        MigrationPolicy {
            port_rebinding_cwnd_factor: 1.0,
            cooldown: Duration::ZERO,
            probe_target: MigrationProbeTarget::PreviousWindow,
        },
        start + Duration::from_millis(40),
    );

    let outcome = recovery.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        start + Duration::from_millis(100),
    );
    assert_eq!(outcome.newly_acked, vec![(4, 1200)]);
    assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200), (2, 1200), (3, 1200)]);
    assert_eq!(outcome.rtt_sample, None);
    assert_eq!(recovery.rtt, Duration::from_millis(40));
    assert_eq!(recovery.cwnd, 12_000);
    assert_eq!(recovery.bytes_in_flight, 0);
    assert_eq!(recovery.pto_count, 0);
}

#[test]
fn new_address_resets_every_controller_to_a_fresh_path_model() {
    use super::cc::{Algorithm, CongestionController, PathChangeKind};
    use super::{MigrationPolicy, MigrationProbeTarget};

    for algorithm in [Algorithm::Reno, Algorithm::Cubic, Algorithm::Bbr2, Algorithm::Bbr3] {
        let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
        let start = Instant::now();
        recovery.cc.set_cwnd(100_000);
        recovery.sync_from_cc();
        recovery.update_rtt(Duration::from_millis(100));
        recovery.on_packet_sent(1, 1200, start);
        recovery.pto_count = 4;

        let event = recovery.on_path_change(
            PathChangeKind::NewAddress,
            Duration::from_millis(25),
            MigrationPolicy {
                port_rebinding_cwnd_factor: 1.0,
                cooldown: Duration::ZERO,
                probe_target: MigrationProbeTarget::PreviousWindow,
            },
            start + Duration::from_millis(25),
        );

        assert_eq!(event.congestion_window, 12_000, "{algorithm:?}");
        assert_eq!(event.probe_target, 12_000, "{algorithm:?}");
        assert_eq!(event.validation_rtt, Duration::from_millis(25), "{algorithm:?}");
        assert_eq!(recovery.cwnd, 12_000, "{algorithm:?}");
        assert_eq!(recovery.ssthresh, usize::MAX / 2, "{algorithm:?}");
        assert_eq!(recovery.bytes_in_flight, 1200, "{algorithm:?}");
        assert_eq!(recovery.rtt, Duration::from_millis(25), "{algorithm:?}");
        assert_eq!(recovery.rtt_var(), Duration::from_micros(12_500), "{algorithm:?}");
        assert_eq!(recovery.min_rtt(), Duration::MAX, "{algorithm:?}");
        assert_eq!(recovery.latest_rtt, None, "{algorithm:?}");
        assert!(!recovery.rtt_initialized, "{algorithm:?}");
        assert_eq!(recovery.first_rtt_sample, None, "{algorithm:?}");
        assert_eq!(recovery.path_epoch, 1, "{algorithm:?}");
        assert_eq!(recovery.pto_count, 0, "{algorithm:?}");

        match algorithm {
            Algorithm::Reno | Algorithm::Cubic => {
                recovery.on_ack(1200, start + Duration::from_millis(50));
                assert_eq!(recovery.cwnd, 13_200, "{algorithm:?} must restart slow start");
            }
            Algorithm::Bbr2 | Algorithm::Bbr3 => {
                assert!(
                    recovery.cc.pacing_rate().is_some_and(|rate| rate > 0),
                    "{algorithm:?} must restart with a live pacing model"
                );
            }
        }
    }
}

use super::{PacketSpace, SentPacketContents};

/// Sends `count` ack-eliciting in-flight packets of 1200 bytes spaced 10 ms
/// apart starting at `t0` in the given space.
fn seed_space(rec: &mut Recovery, space: PacketSpace, count: u64, t0: Instant) {
    for pn in 0..count {
        rec.on_packet_sent_in_space(
            space,
            pn,
            1200,
            true,
            true,
            None,
            t0 + Duration::from_millis(pn * 10),
        );
    }
}

/// The loss set is a contiguous prefix, so the scan must stop at the first survivor.
///
/// Before this, every retained packet number up to `largest_acked` was materialized into a
/// vector and the declared losses were sorted, so the work and the temporary allocation scaled
/// with the in-flight window rather than with the losses.
#[test]
fn loss_detection_returns_a_contiguous_prefix_in_send_order() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(25)); // loss_delay = 9/8 * 25 = 28.125 ms
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 12, t0);

    // Acknowledge the newest packet. Everything at least K_PACKET_THRESHOLD below it is lost,
    // and the older packets are also past the time threshold at t0 + 110 ms.
    let now = t0 + Duration::from_millis(110);
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(11, 12)],
        Duration::ZERO,
        true,
        false,
        now,
    );

    assert!(!outcome.lost.is_empty(), "the fixture must declare losses");
    let lost_pns: Vec<u64> = outcome.lost.iter().map(|(pn, _)| *pn).collect();

    // Ascending packet numbers already give ascending send times; no sort is involved.
    let mut sorted = lost_pns.clone();
    sorted.sort_unstable();
    assert_eq!(lost_pns, sorted, "declared losses must come back in send order");

    // Contiguity: the loss set is a prefix starting at the oldest retained packet.
    let expected: Vec<u64> = (0..lost_pns.len() as u64).collect();
    assert_eq!(lost_pns, expected, "the loss set must be a contiguous prefix");
}

/// Retention is bounded per space, and the eviction is observable.
#[test]
fn sent_packet_retention_is_bounded_per_space() {
    let mut rec = Recovery::new(1_000_000_000, 1200);
    let t0 = Instant::now();
    let evictions_before = qf_telemetry::RECOVERY_SENT_RETENTION_EVICTIONS.get();

    // Send well past the packet cap without ever acknowledging anything.
    let overshoot = (super::MAX_RETAINED_SENT_PACKETS_PER_SPACE + 500) as u64;
    for pn in 0..overshoot {
        rec.on_packet_sent_in_space(PacketSpace::Application, pn, 1200, true, true, None, t0);
    }

    let retained = rec.spaces[PacketSpace::Application.index()].sent.len();
    assert!(
        retained <= super::MAX_RETAINED_SENT_PACKETS_PER_SPACE,
        "retained packets {retained} must stay within the per-space budget"
    );
    assert!(
        qf_telemetry::RECOVERY_SENT_RETENTION_EVICTIONS.get() > evictions_before,
        "hitting the budget must be observable in telemetry"
    );

    // Eviction removes the oldest, so the newest packet is always still tracked.
    assert!(
        rec.spaces[PacketSpace::Application.index()].sent.contains_key(&(overshoot - 1)),
        "the newest packet must never be the one evicted"
    );

    // Byte accounting tracks the retained set rather than everything ever sent.
    let accounted = rec.spaces[PacketSpace::Application.index()].retained_bytes;
    assert!(
        accounted <= super::MAX_RETAINED_SENT_BYTES_PER_SPACE,
        "retained bytes {accounted} must stay within the per-space budget"
    );
    assert_eq!(accounted, retained * 1200, "byte accounting must match the retained set");
}

/// Terminal discard must retire every space at once and stay idempotent.
#[test]
fn discard_all_spaces_retires_every_packet_number_space() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
        seed_space(&mut rec, space, 4, t0);
    }
    rec.update_rtt(Duration::from_millis(25));
    // Arm a time-threshold timer so there is something to cancel.
    let _ = rec.on_ack_received(
        PacketSpace::Application,
        &[(3, 4)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(5),
    );
    rec.pto_count = 3;

    assert!(rec.bytes_in_flight > 0, "the fixture must have packets in flight");

    rec.discard_all_spaces();

    for space in [PacketSpace::Initial, PacketSpace::Handshake, PacketSpace::Application] {
        let sp = &rec.spaces[space.index()];
        assert!(sp.sent.is_empty(), "{space:?} must retain no packets");
        assert_eq!(sp.retained_bytes, 0, "{space:?} byte accounting must be retired");
        assert!(sp.loss_time.is_none(), "{space:?} time-threshold timer must be cancelled");
        assert!(sp.time_of_last_ack_eliciting.is_none(), "{space:?} PTO base must be retired");
        assert!(sp.largest_acked.is_none(), "{space:?} largest-acked mark must be retired");
    }
    assert_eq!(rec.pto_count, 0, "PTO backoff must not survive a terminal discard");
    assert_eq!(rec.bytes_in_flight, 0, "in-flight accounting must be retired");

    // Idempotent: a second discard finds nothing and changes nothing.
    rec.discard_all_spaces();
    assert_eq!(rec.bytes_in_flight, 0);
    assert_eq!(rec.pto_count, 0);
}

/// Nothing may remain that could produce a later loss callback or probe.
#[test]
fn nothing_is_declared_lost_after_a_terminal_discard() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(25));
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 12, t0);

    rec.discard_all_spaces();

    // An ACK arriving after the discard cannot resurrect losses for retired packets.
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(11, 12)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(500),
    );
    assert!(outcome.lost.is_empty(), "a retired space must not declare losses");
    assert!(outcome.newly_acked.is_empty(), "a retired space has nothing left to acknowledge");
}

#[test]
fn packet_threshold_declares_loss() {
    let mut rec = Recovery::new(120_000, 1200);
    // High pre-seeded RTT keeps the time threshold (9/8 * 1 s) out of scope,
    // isolating the packet-threshold path.
    rec.update_rtt(Duration::from_millis(1000));
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 5, t0);
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(50),
    );
    assert_eq!(outcome.newly_acked, vec![(4, 1200)]);
    // pn <= largest(4) - kPacketThreshold(3) = 1 -> packets 0 and 1 lost.
    assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
    assert_eq!(outcome.rtt_sample, Some(Duration::from_millis(10)));
    // Packets 2 and 3 remain tracked and in flight.
    assert_eq!(rec.bytes_in_flight, 2400);
}

#[test]
fn pmtu_probe_loss_does_not_feed_congestion_control() {
    let mut with_probes = Recovery::new(12_000, 1200);
    let mut control = Recovery::new(12_000, 1200);
    with_probes.update_rtt(Duration::from_secs(1));
    control.update_rtt(Duration::from_secs(1));
    let now = Instant::now();

    for pn in 0..4 {
        with_probes.on_pmtu_probe_sent_in_space(
            PacketSpace::Application,
            pn,
            1400,
            now + Duration::from_millis(pn * 10),
        );
    }
    with_probes.on_packet_sent_in_space(
        PacketSpace::Application,
        4,
        1200,
        true,
        true,
        None,
        now + Duration::from_millis(40),
    );
    control.on_packet_sent_in_space(
        PacketSpace::Application,
        4,
        1200,
        true,
        true,
        None,
        now + Duration::from_millis(40),
    );

    let with_probe_outcome = with_probes.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        now + Duration::from_millis(50),
    );
    let control_outcome = control.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        now + Duration::from_millis(50),
    );

    assert_eq!(with_probe_outcome.lost, vec![(0, 1400), (1, 1400)]);
    assert!(with_probe_outcome.persistent_congestion_evidence.is_none());
    assert!(control_outcome.lost.is_empty());
    assert_eq!(with_probes.cwnd, control.cwnd);
    assert_eq!(with_probes.bytes_in_flight, control.bytes_in_flight);
}

#[test]
fn time_threshold_declares_loss_and_arms_timer() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(25)); // loss_delay = 9/8*25 = 28.125 ms
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 5, t0);
    // ACK at t0+45: pn 2 (age 25 ms) and pn 3 (age 15 ms) are below 28.125 ms.
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(45),
    );
    // Packet threshold only: pn 0 and pn 1 are declared lost here.
    // The ACK's own 5 ms sample updates SRTT to 22.5 ms first (RFC order:
    // sample before loss detection), so loss_delay = 9/8*22.5 = 25.3125 ms.
    // loss_time armed for pn 2: sent at t0+20 ms -> deadline t0+45.3125 ms.
    // The armed loss timer takes precedence over any PTO (RFC 9002 §6.2.1).
    assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
    let deadline = rec.loss_detection_timeout(true, false, true);
    assert_eq!(deadline, Some(t0 + Duration::from_nanos(45_312_500)));
}

#[test]
fn time_threshold_fires_on_timeout() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(25)); // loss_delay = 28.125 ms
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 5, t0);
    let _ = rec.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(45),
    );
    // Fire the armed loss timer: pn 2 (sent t0+20) expires at t0+45.3125 ms.
    let outcome = rec.on_loss_detection_timeout(true, false, t0 + Duration::from_millis(49));
    assert_eq!(outcome.probe_spaces.len(), 0);
    assert_eq!(outcome.lost, vec![(PacketSpace::Application, 2, 1200)]);
    // pn 3 (sent t0+30) expires at t0+55.3125 ms and remains tracked.
    assert_eq!(rec.bytes_in_flight, 1200);
}

#[test]
fn rtt_sample_requires_ack_eliciting_and_new_largest() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    // Non-ack-eliciting packet: ACK must not generate a sample (RFC 9002 §5.1).
    rec.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, false, true, None, t0);
    let out = rec.on_ack_received(
        PacketSpace::Application,
        &[(0, 1)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(40),
    );
    assert_eq!(out.rtt_sample, None);
    // Ack-eliciting packet: sample appears exactly once per new largest.
    rec.on_packet_sent_in_space(PacketSpace::Application, 1, 1200, true, true, None, t0);
    let out1 = rec.on_ack_received(
        PacketSpace::Application,
        &[(1, 2)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(50),
    );
    assert_eq!(out1.rtt_sample, Some(Duration::from_millis(50)));
    let out2 = rec.on_ack_received(
        PacketSpace::Application,
        &[(1, 2)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(60),
    );
    assert_eq!(out2.rtt_sample, None);
}

#[test]
fn ack_delay_adjustment_follows_confirmation_rules() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    // Post-confirmation: ack_delay above max_ack_delay is capped at 25 ms.
    rec.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, true, true, None, t0);
    let out = rec.on_ack_received(
        PacketSpace::Application,
        &[(0, 1)],
        Duration::from_millis(500),
        true,
        false,
        t0 + Duration::from_millis(100),
    );
    assert_eq!(out.rtt_sample, Some(Duration::from_millis(100)));
    // First sample: no adjustment possible (min_rtt unset) -> rtt = 100 ms.
    assert_eq!(rec.rtt, Duration::from_millis(100));
    // Second sample at 80 ms with delay 25: latest < min_rtt + delay -> no subtraction.
    rec.on_packet_sent_in_space(
        PacketSpace::Application,
        1,
        1200,
        true,
        true,
        None,
        t0 + Duration::from_millis(100),
    );
    let _ = rec.on_ack_received(
        PacketSpace::Application,
        &[(1, 2)],
        Duration::from_millis(25),
        true,
        false,
        t0 + Duration::from_millis(180),
    );
    // SRTT = 7/8*100 + 1/8*80 = 97.5 ms (unadjusted 80 ms sample).
    assert_eq!(rec.rtt, Duration::from_micros(97_500));
    // Third sample 120 ms with delay 500 (capped at 25): 120 >= min_rtt(80)+25
    // -> adjusted = 95 ms; SRTT = 7/8*97.5 + 1/8*95 = 97.1875 ms.
    rec.on_packet_sent_in_space(
        PacketSpace::Application,
        2,
        1200,
        true,
        true,
        None,
        t0 + Duration::from_millis(180),
    );
    let _ = rec.on_ack_received(
        PacketSpace::Application,
        &[(2, 3)],
        Duration::from_millis(500),
        true,
        false,
        t0 + Duration::from_millis(300),
    );
    assert_eq!(rec.rtt, Duration::from_nanos(97_187_500));
    assert_eq!(rec.min_rtt(), Duration::from_millis(80));
}

#[test]
fn pto_fire_increments_backoff_and_requests_probe() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 1, t0);
    // Initial PTO = 333 + 4*166.5 + 25 = 1024 ms after the last send.
    let deadline = rec.loss_detection_timeout(true, false, true);
    assert_eq!(deadline, Some(t0 + Duration::from_millis(1024)));
    let out = rec.on_loss_detection_timeout(true, false, t0 + Duration::from_millis(1024));
    assert_eq!(rec.pto_count, 1);
    assert_eq!(out.probe_spaces, vec![PacketSpace::Application]);
    assert!(out.lost.is_empty());
    // Backoff doubles the next deadline.
    let deadline2 = rec.loss_detection_timeout(true, false, true);
    assert_eq!(deadline2, Some(t0 + Duration::from_millis(2048)));
}

#[test]
fn application_pto_requires_handshake_confirmation() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 1, t0);
    // Pre-confirmation: Application space must not arm a PTO (RFC 9002 §6.2.1).
    assert_eq!(rec.loss_detection_timeout(false, false, true), None);
    // Initial space arms without max_ack_delay: 333 + 666 = 999 ms.
    rec.on_packet_sent_in_space(PacketSpace::Initial, 0, 1200, true, true, Some((0, 300)), t0);
    let deadline = rec.loss_detection_timeout(false, false, true);
    assert_eq!(deadline, Some(t0 + Duration::from_millis(999)));
}

#[test]
fn pto_backoff_reset_rules() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    // Client, Initial space: backoff is NOT reset by Initial ACKs (§6.2.1).
    rec.on_packet_sent_in_space(PacketSpace::Initial, 0, 1200, true, true, None, t0);
    let _ = rec.on_loss_detection_timeout(false, false, t0 + Duration::from_millis(999));
    assert_eq!(rec.pto_count, 1);
    let _ = rec.on_ack_received(
        PacketSpace::Initial,
        &[(0, 1)],
        Duration::ZERO,
        false,
        false,
        t0 + Duration::from_millis(1000),
    );
    assert_eq!(rec.pto_count, 1);
    // Handshake ACK (still client): backoff resets on non-Initial spaces.
    rec.on_packet_sent_in_space(PacketSpace::Handshake, 0, 1200, true, true, None, t0);
    let _ = rec.on_ack_received(
        PacketSpace::Handshake,
        &[(0, 1)],
        Duration::ZERO,
        false,
        false,
        t0 + Duration::from_millis(2000),
    );
    assert_eq!(rec.pto_count, 0);
}

#[test]
fn pto_backoff_cap_bounds_deadline_growth() {
    // A nested-tunnel recovery owner lowers the exponent ceiling; probe
    // deadlines must stop growing once pto_count exceeds the cap instead of
    // compounding toward the RFC-default 2^16 multiplier.
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(40));
    rec.set_pto_backoff_cap(3);
    let t0 = Instant::now();

    rec.pto_count = 3;
    let capped = rec.pto_deadline(t0).duration_since(t0);
    rec.pto_count = 4;
    let beyond = rec.pto_deadline(t0).duration_since(t0);
    rec.pto_count = 16;
    let far_beyond = rec.pto_deadline(t0).duration_since(t0);
    assert_eq!(beyond, capped);
    assert_eq!(far_beyond, capped);

    // The timer deadline used by the loss-detection loop honors the same cap.
    rec.on_packet_sent_in_space(PacketSpace::Application, 0, 1200, true, true, None, t0);
    let deadline_at_cap = rec.loss_detection_timeout(true, false, true);
    rec.pto_count = 10;
    let deadline_far = rec.loss_detection_timeout(true, false, true);
    assert_eq!(deadline_far, deadline_at_cap);
}

#[test]
fn pto_backoff_cap_is_clamped_to_valid_range() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.set_pto_backoff_cap(0);
    assert_eq!(rec.pto_deadline_growth_cap(), 1);
    rec.set_pto_backoff_cap(99);
    assert_eq!(rec.pto_deadline_growth_cap(), super::K_PTO_BACKOFF_CAP_DEFAULT);
}

#[test]
fn default_backoff_keeps_rfc_ceiling() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(40));
    let t0 = Instant::now();
    rec.pto_count = 15;
    let high = rec.pto_deadline(t0).duration_since(t0);
    rec.pto_count = 16;
    let higher = rec.pto_deadline(t0).duration_since(t0);
    rec.pto_count = 17;
    let ceiling = rec.pto_deadline(t0).duration_since(t0);
    assert_eq!(higher, high * 2);
    assert_eq!(ceiling, higher);
}

#[test]
fn persistent_congestion_collapses_cwnd() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10)); // PC period = (10+20+25)*3 = 165 ms
    let t0 = Instant::now();
    // 21 packets spaced 10 ms apart -> loss run spans 200 ms >= 165 ms.
    seed_space(&mut rec, PacketSpace::Application, 21, t0);
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(20, 21)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(210),
    );
    assert!(outcome.persistent_congestion);
    let evidence = outcome
        .persistent_congestion_evidence
        .expect("persistent congestion must retain its decision evidence");
    assert_eq!(evidence.largest_acked, 20);
    assert_eq!(evidence.triggering_ack_delay, Duration::ZERO);
    assert_eq!(evidence.largest_acked_packet_age, Some(Duration::from_millis(10)));
    assert_eq!(evidence.run_start_pn, 0);
    assert_eq!(evidence.run_min_packet_size, 1200);
    assert_eq!(evidence.run_max_packet_size, 1200);
    assert_eq!(evidence.run_control_packets, 16);
    assert_eq!(evidence.run_stream_packets, 0);
    assert_eq!(evidence.run_stream_fresh_packets, 0);
    assert_eq!(evidence.run_stream_retransmission_packets, 0);
    assert_eq!(evidence.run_datagram_packets, 0);
    assert_eq!(evidence.terminal_lost_pn, 15);
    assert_eq!(evidence.lost_packet_count, 16);
    assert_eq!(evidence.triggering_ack_newly_acked_packets, 1);
    assert!(evidence.triggering_ack_lost_packets >= evidence.lost_packet_count);
    assert_eq!(evidence.triggering_ack_packet_threshold_losses, 18);
    assert_eq!(evidence.triggering_ack_time_threshold_losses, 20);
    assert!(evidence.terminal_loss_by_packet_threshold);
    assert!(evidence.terminal_loss_by_time_threshold);
    assert_eq!(evidence.loss_delay, rec.loss_delay());
    assert_eq!(evidence.smoothed_rtt, rec.rtt);
    assert_eq!(evidence.rtt_variance, rec.rtt_var);
    assert_eq!(evidence.run_start, t0);
    assert_eq!(evidence.run_end, t0 + Duration::from_millis(150));
    assert_eq!(evidence.period, Duration::from_millis(150));
    // Collapsed from 120_000 to the controller minimum: RFC kMinimumWindow
    // (2*MSS = 2400) is passed in, BBR3 floors at its 4*MSS operational min.
    assert!(rec.cwnd <= 4800, "cwnd must collapse, got {}", rec.cwnd);
    assert_eq!(rec.min_rtt(), Duration::from_millis(10));
}

#[test]
fn persistent_congestion_provenance_counts_application_frame_classes() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10));
    let t0 = Instant::now();
    for pn in 0..21 {
        let contents = match pn {
            0..=3 => SentPacketContents::CONTROL,
            4..=6 => SentPacketContents::STREAM,
            7..=9 => SentPacketContents {
                stream: true,
                stream_retransmission: true,
                ..SentPacketContents::default()
            },
            _ => SentPacketContents::DATAGRAM,
        };
        rec.on_packet_sent_with_contents_in_space(
            PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            contents,
            t0 + Duration::from_millis(pn * 10),
        );
    }
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(20, 21)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(210),
    );
    let evidence = outcome
        .persistent_congestion_evidence
        .expect("persistent congestion must retain packet-content provenance");
    assert_eq!(evidence.lost_packet_count, 16);
    assert_eq!(evidence.run_control_packets, 4);
    assert_eq!(evidence.run_stream_packets, 6);
    assert_eq!(evidence.run_stream_fresh_packets, 3);
    assert_eq!(evidence.run_stream_retransmission_packets, 3);
    assert_eq!(evidence.run_datagram_packets, 6);
}

#[test]
fn ack_inside_loss_run_invalidates_persistent_congestion() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10));
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 21, t0);
    // ACK pn 10 (inside the would-be loss window) plus the tail pn 20.
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(10, 11), (20, 21)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(210),
    );
    assert!(!outcome.persistent_congestion);
    assert!(rec.cwnd > 2400);
}

#[test]
fn acknowledged_packet_after_prior_loss_window_breaks_persistent_congestion() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10));
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 21, t0);

    let first = rec.on_ack_received(
        PacketSpace::Application,
        &[(10, 11)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(100),
    );
    assert!(!first.persistent_congestion);

    let acknowledged_between_losses = rec.on_ack_received(
        PacketSpace::Application,
        &[(8, 9)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(110),
    );
    assert!(!acknowledged_between_losses.persistent_congestion);

    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(20, 21)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(210),
    );
    assert!(!outcome.persistent_congestion);
    assert!(rec.cwnd > 2400);
}

#[test]
fn reordered_ack_for_prior_lost_packet_breaks_persistent_congestion() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10));
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 22, t0);

    let first = rec.on_ack_received(
        PacketSpace::Application,
        &[(10, 11)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(110),
    );
    assert!(!first.persistent_congestion);

    let reordered = rec.on_ack_received(
        PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(120),
    );
    assert!(!reordered.persistent_congestion);

    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(21, 22)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(220),
    );
    assert!(!outcome.persistent_congestion);
    assert!(rec.cwnd > 2400);
}

#[test]
fn losses_sent_before_first_rtt_sample_cannot_establish_persistent_congestion() {
    let mut rec = Recovery::new(120_000, 1200);
    let now = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 21, now - Duration::from_millis(300));
    rec.update_rtt(Duration::from_millis(10));

    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(20, 21)],
        Duration::ZERO,
        true,
        false,
        now,
    );
    assert!(!outcome.persistent_congestion);
    assert!(rec.cwnd > 2400);
}

#[test]
fn ack_only_losses_cannot_establish_persistent_congestion() {
    let mut rec = Recovery::new(120_000, 1200);
    rec.update_rtt(Duration::from_millis(10));
    let t0 = Instant::now();
    let cwnd_before = rec.cwnd;
    for pn in 0..21 {
        rec.on_packet_sent_in_space(
            PacketSpace::Application,
            pn,
            64,
            false,
            false,
            None,
            t0 + Duration::from_millis(pn * 10),
        );
    }

    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(20, 21)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(210),
    );
    assert!(!outcome.persistent_congestion);
    assert_eq!(rec.cwnd, cwnd_before);
}

#[test]
fn discard_space_removes_without_loss_response() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    let cwnd_before = rec.cwnd;
    seed_space(&mut rec, PacketSpace::Handshake, 3, t0);
    assert_eq!(rec.bytes_in_flight, 3600);
    rec.discard_space(PacketSpace::Handshake);
    assert_eq!(rec.bytes_in_flight, 0);
    assert_eq!(rec.cwnd, cwnd_before); // no loss response
    assert_eq!(rec.loss_detection_timeout(false, true, false), None);
}

#[test]
fn crypto_ranges_tracked_through_ack_and_loss() {
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    for pn in 0..=4 {
        let range = match pn {
            0 => Some((0, 300)),
            1 => Some((300, 200)),
            _ => None,
        };
        rec.on_packet_sent_in_space(PacketSpace::Initial, pn, 1200, true, true, range, t0);
    }
    let outcome = rec.on_ack_received(
        PacketSpace::Initial,
        &[(4, 5)],
        Duration::ZERO,
        false,
        true,
        t0 + Duration::from_millis(50),
    );
    assert!(outcome.crypto_acked.is_empty());
    // pn 0 and 1 lost via packet threshold: both crypto ranges requeued.
    assert_eq!(outcome.crypto_lost, vec![(0, 300), (300, 200)]);
    assert_eq!(outcome.lost, vec![(0, 1200), (1, 1200)]);
}

#[test]
fn migration_clears_timers_but_keeps_sent_state() {
    use super::cc::PathChangeKind;
    use super::{MigrationPolicy, MigrationProbeTarget};
    let mut rec = Recovery::new(120_000, 1200);
    let t0 = Instant::now();
    seed_space(&mut rec, PacketSpace::Application, 2, t0);
    assert!(rec.loss_detection_timeout(true, false, true).is_some());
    rec.on_path_change(
        PathChangeKind::NewAddress,
        Duration::from_millis(25),
        MigrationPolicy {
            port_rebinding_cwnd_factor: 0.5,
            cooldown: Duration::ZERO,
            probe_target: MigrationProbeTarget::PreviousWindow,
        },
        t0 + Duration::from_millis(25),
    );
    assert_eq!(rec.loss_detection_timeout(true, false, true), None);
    // Sent packets survive migration and can still be acked.
    let outcome = rec.on_ack_received(
        PacketSpace::Application,
        &[(0, 2)],
        Duration::ZERO,
        true,
        false,
        t0 + Duration::from_millis(100),
    );
    assert_eq!(outcome.newly_acked.len(), 2);
}
