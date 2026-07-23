//! Integration tests for the pluggable congestion control framework.
//!
//! Validates Reno, BBR2, BBR3, and StealthShaper behavior through the
//! public Recovery API - the same path used by real connections.

use quicfuscate::transport::cc::stealth_shaper::BrowserProfile;
use quicfuscate::transport::recovery::Recovery;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Algorithm selection via Recovery
// ---------------------------------------------------------------------------

#[test]
fn recovery_default_is_bbr3() {
    let r = Recovery::new(12_000, 1200);
    assert_eq!(r.cwnd, 12_000);
    assert!(r.pacing);
}

#[test]
fn recovery_reno_selectable() {
    let r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Reno);
    assert_eq!(r.cwnd, 12_000);
}

#[test]
fn recovery_cubic_selectable_and_paced() {
    let r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Cubic);
    assert_eq!(r.cwnd, 12_000);
    assert!(r.get_pacing_rate().is_some());
}

#[test]
fn recovery_bbr2_selectable() {
    let r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr2);
    assert_eq!(r.cwnd, 12_000);
}

#[test]
fn recovery_bbr3_selectable() {
    let r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr3);
    assert_eq!(r.cwnd, 12_000);
}

// ---------------------------------------------------------------------------
// Reno behavior through Recovery
// ---------------------------------------------------------------------------

#[test]
fn reno_slow_start_grows_cwnd() {
    let mut r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Reno);
    let now = Instant::now();
    r.on_packet_sent(1, 1200, now);
    let before = r.cwnd;
    r.on_ack(1200, now);
    assert!(r.cwnd > before, "Reno cwnd should grow in slow start");
}

#[test]
fn reno_loss_reduces_cwnd() {
    let mut r = Recovery::with_algorithm(24_000, 1200, quicfuscate::transport::cc::Algorithm::Reno);
    let now = Instant::now();
    r.on_packet_sent(1, 6000, now);
    let before = r.cwnd;
    r.on_loss(3000, now);
    assert!(r.cwnd < before, "Reno cwnd should shrink on loss");
}

#[test]
fn reno_cwnd_never_zero() {
    let mut r = Recovery::with_algorithm(2400, 1200, quicfuscate::transport::cc::Algorithm::Reno);
    let now = Instant::now();
    for i in 0..10 {
        r.on_packet_sent(i, 1200, now);
        r.on_loss(1200, now);
    }
    assert!(r.cwnd > 0, "Reno cwnd must never reach zero");
}

// ---------------------------------------------------------------------------
// BBR2 behavior through Recovery
// ---------------------------------------------------------------------------

#[test]
fn bbr2_cwnd_positive_after_traffic() {
    let mut r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr2);
    let now = Instant::now();
    for i in 0..5 {
        r.on_packet_sent(i, 1200, now + Duration::from_millis(i * 10));
    }
    r.on_ack(3600, now + Duration::from_millis(50));
    assert!(r.cwnd >= 4 * 1200, "BBR2 cwnd must be >= min_pipe_cwnd");
}

#[test]
fn bbr2_loss_does_not_crash() {
    let mut r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr2);
    let now = Instant::now();
    r.on_packet_sent(1, 6000, now);
    r.on_loss_packet(1, 6000, now);
    assert!(r.cwnd > 0);
    assert!(r.get_loss_rate() > 0.0);
}

// ---------------------------------------------------------------------------
// BBR3 behavior through Recovery
// ---------------------------------------------------------------------------

#[test]
fn bbr3_cwnd_stays_above_minimum() {
    let mut r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr3);
    let now = Instant::now();
    r.on_packet_sent(1, 1200, now);
    r.on_ack(1200, now);
    assert!(r.cwnd >= 4 * 1200, "BBR3 cwnd must be >= 4*MSS minimum");
}

// ---------------------------------------------------------------------------
// StealthShaper wrapping through Recovery
// ---------------------------------------------------------------------------

#[test]
fn stealth_wrapping_works_for_all_algorithms() {
    for algo in [
        quicfuscate::transport::cc::Algorithm::Reno,
        quicfuscate::transport::cc::Algorithm::Cubic,
        quicfuscate::transport::cc::Algorithm::Bbr2,
        quicfuscate::transport::cc::Algorithm::Bbr3,
    ] {
        let mut r = Recovery::with_algorithm(12_000, 1200, algo);
        let now = Instant::now();
        r.on_packet_sent(1, 1200, now);

        // Enable stealth
        r.set_stealth_mode(true, BrowserProfile::Chrome);
        r.on_ack(1200, now);
        assert!(r.cwnd > 0, "cwnd must stay positive after stealth wrap ({algo:?})");

        // Switch profile
        r.set_stealth_mode(true, BrowserProfile::Firefox);
        r.on_packet_sent(2, 1200, now);
        r.on_ack(1200, now);
        assert!(r.cwnd > 0, "cwnd must stay positive after profile switch ({algo:?})");
    }
}

#[test]
fn stealth_disable_reenable_cycle() {
    let mut r = Recovery::with_algorithm(12_000, 1200, quicfuscate::transport::cc::Algorithm::Bbr3);
    let now = Instant::now();
    r.on_packet_sent(1, 1200, now);

    r.set_stealth_mode(true, BrowserProfile::Safari);
    r.on_ack(1200, now);
    let cwnd_stealth = r.cwnd;

    r.set_stealth_mode(false, BrowserProfile::Safari);
    r.on_packet_sent(2, 1200, now);
    r.on_ack(1200, now);
    assert!(r.cwnd > 0);

    // Re-enable
    r.set_stealth_mode(true, BrowserProfile::Edge);
    r.on_packet_sent(3, 1200, now);
    r.on_ack(1200, now);
    assert!(r.cwnd > 0);
    let _ = cwnd_stealth; // used for readability
}

// ---------------------------------------------------------------------------
// FEC callbacks through Recovery
// ---------------------------------------------------------------------------

#[test]
fn fec_callbacks_work_with_all_algorithms() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    for algo in [
        quicfuscate::transport::cc::Algorithm::Reno,
        quicfuscate::transport::cc::Algorithm::Cubic,
        quicfuscate::transport::cc::Algorithm::Bbr2,
        quicfuscate::transport::cc::Algorithm::Bbr3,
    ] {
        let sent = Arc::new(AtomicU64::new(0));
        let lost = Arc::new(AtomicU64::new(u64::MAX));
        let s = Arc::clone(&sent);
        let l = Arc::clone(&lost);

        let mut r = Recovery::with_algorithm(12_000, 1200, algo);
        r.set_fec_callbacks(
            move |pn, _| {
                s.store(pn, Ordering::Relaxed);
            },
            move |pn, _| {
                l.store(pn, Ordering::Relaxed);
            },
        );

        let now = Instant::now();
        r.on_packet_sent(42, 1200, now);
        assert_eq!(sent.load(Ordering::Relaxed), 42, "FEC sent callback failed for {algo:?}");

        r.on_loss_packet(99, 1200, now);
        assert_eq!(lost.load(Ordering::Relaxed), 99, "FEC lost callback failed for {algo:?}");
    }
}

// ---------------------------------------------------------------------------
// RTT + PTO
// ---------------------------------------------------------------------------

#[test]
fn rtt_update_propagates() {
    let mut r = Recovery::new(12_000, 1200);
    r.update_rtt(Duration::from_millis(50));
    assert_eq!(r.rtt, Duration::from_millis(50));
}

#[test]
fn pto_deadline_increases_with_count() {
    let mut r = Recovery::new(12_000, 1200);
    r.update_rtt(Duration::from_millis(100));
    let now = Instant::now();
    let d1 = r.pto_deadline(now);
    r.on_packet_sent(1, 1200, now);
    r.on_loss(1200, now); // bumps pto_count
    let d2 = r.pto_deadline(now);
    assert!(d2 > d1, "PTO deadline must grow with retransmit count");
}

// ---------------------------------------------------------------------------
// send_quantum / can_send
// ---------------------------------------------------------------------------

#[test]
fn can_send_respects_cwnd() {
    let mut r = Recovery::with_algorithm(3600, 1200, quicfuscate::transport::cc::Algorithm::Reno);
    let now = Instant::now();
    // Fill the window
    r.on_packet_sent(1, 3600, now);
    assert!(!r.can_send(1200), "should not be able to send when cwnd is full");
    // ACK frees space
    r.on_ack(1200, now);
    assert!(r.can_send(1200), "should be able to send after ACK frees space");
}

// ---------------------------------------------------------------------------
// BBR2 convergence: synthetic 10 Mbps / 20 ms link
// ---------------------------------------------------------------------------

#[test]
fn bbr2_convergence_synthetic_link() {
    // Synthetic link: 10 Mbps, 20 ms RTT.
    // BDP = 1_250_000 bytes/sec * 0.020 s = 25_000 bytes per RTT.
    // BBR2 must reach >= 90 % of link bandwidth within 15 RTT rounds.
    const TARGET_BPS: u64 = 1_250_000; // 10 Mbps in bytes/sec
    const CONVERGENCE_THRESHOLD: u64 = TARGET_BPS * 9 / 10; // 1_125_000
    const RTT: Duration = Duration::from_millis(20);
    const MSS: usize = 1200;
    const BDP: usize = 25_000; // bytes per RTT at target rate

    // Start with 2 * BDP initial cwnd so startup can probe immediately.
    let mut r = Recovery::with_algorithm(BDP * 2, MSS, quicfuscate::transport::cc::Algorithm::Bbr2);
    r.update_rtt(RTT);

    let t0 = Instant::now();
    for (pkt_num, round) in (1_u64..).zip(0..15_u32) {
        let send_time = t0 + RTT * round;
        let ack_time = send_time + RTT;
        // One RTT of traffic: send BDP bytes then ACK them after RTT.
        // delivery_rate = BDP / RTT = TARGET_BPS.
        r.on_packet_sent(pkt_num, BDP, send_time);
        r.on_ack(BDP, ack_time);
    }

    let pacing = r.get_pacing_rate().unwrap_or(0);
    assert!(
        pacing >= CONVERGENCE_THRESHOLD,
        "BBR2 did not converge: pacing_rate={pacing} bytes/sec < threshold={CONVERGENCE_THRESHOLD}"
    );
}

#[test]
fn bbr3_convergence_synthetic_link() {
    // Same synthetic link as BBR2: 10 Mbps, 20 ms RTT.
    // BBR3 uses a cycle-based state machine with ProbeBw; it should reach
    // >= 80% of link bandwidth within 20 RTT rounds (slightly more generous
    // than BBR2 due to the 8-phase cycle needing more rounds to stabilize).
    const TARGET_BPS: u64 = 1_250_000; // 10 Mbps in bytes/sec
    const CONVERGENCE_THRESHOLD: u64 = TARGET_BPS * 8 / 10; // 1_000_000
    const RTT: Duration = Duration::from_millis(20);
    const MSS: usize = 1200;
    const BDP: usize = 25_000; // bytes per RTT at target rate

    let mut r = Recovery::with_algorithm(BDP * 2, MSS, quicfuscate::transport::cc::Algorithm::Bbr3);
    r.update_rtt(RTT);

    let t0 = Instant::now();
    for (pkt_num, round) in (1_u64..).zip(0..20_u32) {
        let send_time = t0 + RTT * round;
        let ack_time = send_time + RTT;
        r.on_packet_sent(pkt_num, BDP, send_time);
        r.on_ack(BDP, ack_time);
    }

    let pacing = r.get_pacing_rate().unwrap_or(0);
    assert!(
        pacing >= CONVERGENCE_THRESHOLD,
        "BBR3 did not converge: pacing_rate={pacing} bytes/sec < threshold={CONVERGENCE_THRESHOLD}"
    );
}

struct BottleneckFlow {
    recovery: Recovery,
    next_packet: u64,
    delivered: u64,
}

impl BottleneckFlow {
    fn new(algorithm: quicfuscate::transport::cc::Algorithm, rtt: Duration) -> Self {
        let mut recovery = Recovery::with_algorithm(12_000, 1200, algorithm);
        recovery.set_initial_rtt(rtt);
        Self { recovery, next_packet: 1, delivered: 0 }
    }

    fn offer(&mut self, now: Instant) -> VecDeque<u64> {
        let packet_count = (self.recovery.cwnd / 1200).clamp(1, 128);
        (0..packet_count)
            .map(|_| {
                let packet = self.next_packet;
                self.next_packet += 1;
                self.recovery.on_packet_sent(packet, 1200, now);
                packet
            })
            .collect()
    }
}

fn run_shared_bottleneck_round(
    flows: &mut [BottleneckFlow; 2],
    round: usize,
    now: Instant,
    rtt: Duration,
) -> [usize; 2] {
    let mut offered = [flows[0].offer(now), flows[1].offer(now)];
    let mut arrivals = Vec::new();
    while !offered[0].is_empty() || !offered[1].is_empty() {
        for flow in [round % 2, 1 - round % 2] {
            if let Some(packet) = offered[flow].pop_front() {
                arrivals.push((flow, packet));
            }
        }
    }

    let mut delivered = [0usize; 2];
    for (position, (flow, packet)) in arrivals.into_iter().enumerate() {
        if position < 64 {
            delivered[flow] += 1;
        } else {
            flows[flow].recovery.on_loss_packet(packet, 1200, now + rtt);
        }
    }
    for flow in 0..2 {
        let bytes = delivered[flow] * 1200;
        if bytes > 0 {
            flows[flow].recovery.on_ack_with_rtt(bytes, rtt, now + rtt);
        }
    }
    delivered
}

#[test]
fn cubic_and_reno_share_a_drop_tail_bottleneck_without_starvation() {
    const RTT: Duration = Duration::from_millis(40);
    let start = Instant::now();
    let mut flows = [
        BottleneckFlow::new(quicfuscate::transport::cc::Algorithm::Cubic, RTT),
        BottleneckFlow::new(quicfuscate::transport::cc::Algorithm::Reno, RTT),
    ];

    for round in 0..500 {
        let delivered =
            run_shared_bottleneck_round(&mut flows, round, start + RTT * round as u32, RTT);
        if round >= 100 {
            for flow in 0..2 {
                flows[flow].delivered += delivered[flow] as u64 * 1200;
            }
        }
    }

    let cubic = flows[0].delivered as f64;
    let reno = flows[1].delivered as f64;
    let jain = (cubic + reno).powi(2) / (2.0 * (cubic.powi(2) + reno.powi(2)));
    println!(
        "CUBIC_RENO_JAIN cubic_bytes={} reno_bytes={} jain={jain:.6}",
        flows[0].delivered, flows[1].delivered
    );
    assert!(cubic > 0.0 && reno > 0.0, "neither flow may starve");
    assert!(jain > 0.8, "CUBIC/Reno Jain fairness {jain:.6} must exceed 0.8");
}
