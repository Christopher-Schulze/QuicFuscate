#![cfg(feature = "rust-tests")]

use quicfuscate::transport::pn::pnspace::PktNumSpace;

#[test]
fn ack_elicitation_threshold_and_ranges() {
    let mut space = PktNumSpace::new();

    // First packet always triggers ACK (overdue path).
    space.on_packet_recv(10);
    space.note_ack_eliciting(10_000, 2);
    let (_delay, ranges) = space.take_ack(0).expect("ack after first packet");
    assert!(ranges.iter().any(|r| r.0 <= 10 && 10 < r.1));
    assert!(space.contains(10));

    // Below threshold should not elicit ACK when not overdue.
    space.on_packet_recv(11);
    space.note_ack_eliciting(10_000, 2);
    assert!(space.take_ack(0).is_none(), "no ACK before threshold");

    // Second packet meets threshold and should elicit ACK.
    space.on_packet_recv(12);
    space.note_ack_eliciting(10_000, 2);
    let (_delay2, ranges2) = space.take_ack(0).expect("ack at threshold");
    assert!(ranges2.iter().any(|r| r.0 <= 10 && 12 < r.1));
}

#[test]
fn ack_ranges_merge_contiguous_packets() {
    let mut space = PktNumSpace::new();
    space.on_packet_recv(20);
    space.on_packet_recv(18);
    space.on_packet_recv(19);

    let ranges = space.ack_ranges_vec();
    assert_eq!(ranges, vec![(18, 21)], "contiguous ranges should merge");
    assert!(space.contains(18));
    assert!(space.contains(19));
    assert!(space.contains(20));
    assert!(!space.contains(21));
}

#[test]
fn ack_only_packet_is_recorded_without_scheduling_ack_of_ack() {
    let mut space = PktNumSpace::new();
    space.on_packet_recv(7);

    assert!(space.contains(7));
    assert!(space.take_ack(0).is_none());
}

#[test]
fn delayed_ack_deadline_releases_single_tail_packet() {
    let mut space = PktNumSpace::new();
    space.on_packet_recv(1);
    space.note_ack_eliciting(25, 2);
    assert!(space.take_ack(0).is_some());

    space.on_packet_recv(2);
    space.note_ack_eliciting(1, 2);
    assert!(!space.has_pending_ack());
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(space.take_ack(0).is_some());
}
