#![cfg(feature = "rust-tests")]

use quicfuscate::transport::recovery::{BrowserProfile, Recovery};
use std::time::{Duration, Instant};

#[test]
fn recovery_counters_and_pto_progression() {
    let mut rec = Recovery::new(1200, 0);
    assert_eq!(rec.cwnd, 1200);
    assert_eq!(rec.bytes_in_flight, 0);
    assert_eq!(rec.pto_count, 0);

    // mss should clamp to >= 1, making send_quantum min(cwnd, 3 * mss) == 3.
    assert_eq!(rec.send_quantum(), 3);

    rec.set_batch_size(0);
    assert_eq!(rec.get_batch_size(), 1);
    rec.set_batch_size(100);
    assert_eq!(rec.get_batch_size(), 64);

    let now = Instant::now();
    rec.on_packet_sent(1, 500, now);
    assert_eq!(rec.bytes_in_flight, 500);
    assert!(rec.can_send(700));
    assert!(!rec.can_send(800));

    rec.on_ack(200, now + Duration::from_millis(10));
    assert_eq!(rec.bytes_in_flight, 300);

    rec.on_loss(100, now + Duration::from_millis(20));
    assert_eq!(rec.bytes_in_flight, 200);
    // RFC 9002 §6.2.1: pto_count grows on PTO firings, not on loss events.
    assert_eq!(rec.pto_count, 0);
    let timeout_outcome =
        rec.on_loss_detection_timeout(true, false, now + Duration::from_millis(30));
    assert_eq!(rec.pto_count, 1);
    assert!(timeout_outcome.lost.is_empty());

    rec.update_rtt(Duration::from_millis(50));
    assert_eq!(rec.rtt, Duration::from_millis(50));

    let deadline = rec.pto_deadline(now);
    assert!(deadline > now);
}

#[test]
fn recovery_stealth_mode_is_safe() {
    let mut rec = Recovery::new(1200, 1200);
    rec.set_stealth_mode(true, BrowserProfile::Firefox);
    rec.set_stealth_mode(false, BrowserProfile::Chrome);
}
