use super::*;

#[test]
fn ack_updates_rtt_from_send_time() {
    // RFC 9000 §5.1: RTT sample = now - send_time - ack_delay.
    // This test verifies that ACK processing generates a valid RTT sample
    // from the largest acknowledged PN's send time.
    let mut c = make_conn();
    let initial_rtt = c.rtt;

    // Simulate sending packet PN=0 with a known send time in the past.
    let send_time = Instant::now() - Duration::from_millis(50);
    c.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        0,
        1200,
        true,
        true,
        None,
        send_time,
    );

    // Process an ACK acknowledging PN=0 (range 0..1).
    let ranges = vec![(0u64, 1u64)];
    let now = Instant::now();
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        Duration::ZERO,
        true,
        c.is_server,
        now,
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    // RTT should now be updated to ~50ms (now - send_time), not the initial value.
    assert!(
        c.rtt < initial_rtt + Duration::from_millis(100),
        "RTT should be updated from ACK sample, not inflated. Got {:?}, initial {:?}",
        c.rtt,
        initial_rtt
    );
    assert!(c.rtt >= Duration::from_millis(40), "RTT sample should be ~50ms. Got {:?}", c.rtt);
}

#[test]
fn fec_feedback_counts_only_transport_classified_acknowledgements_as_clean() {
    let mut c = make_conn();
    let sent_at = Instant::now() - Duration::from_millis(10);
    for packet_number in 0..3 {
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            packet_number,
            1200,
            true,
            true,
            None,
            sent_at,
        );
    }

    let sent_feedback = c.take_fec_callback_feedback();
    assert_eq!(sent_feedback.sent_packets, 3);
    assert_eq!(sent_feedback.acked_packets, 0);
    assert_eq!(sent_feedback.lost_packets, 0);

    let now = Instant::now();
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(0, 2)],
        Duration::ZERO,
        true,
        c.is_server,
        now,
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    let ack_feedback = c.take_fec_callback_feedback();
    assert_eq!(ack_feedback.sent_packets, 0);
    assert_eq!(ack_feedback.acked_packets, 2);
    assert_eq!(ack_feedback.lost_packets, 0);
}

#[test]
fn ack_with_delay_subtracts_ack_delay() {
    // RTT sample should subtract the peer's ack_delay (RFC 9000 §19.3).
    let mut c = make_conn();
    let send_time = Instant::now() - Duration::from_millis(100);
    c.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        0,
        1200,
        true,
        true,
        None,
        send_time,
    );

    let ranges = vec![(0u64, 1u64)];
    let ack_delay = Duration::from_millis(30);
    let now = Instant::now();
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        ack_delay,
        true,
        c.is_server,
        now,
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    // RFC 9002 §5.2/§5.3: the first sample sets min_rtt = latest_rtt, so the
    // adjustment guard (latest >= min_rtt + delay) can never fire for it -
    // the first sample is NOT ack-delay adjusted (RTT ~= 100 ms, not 70 ms).
    assert!(
        c.rtt >= Duration::from_millis(90) && c.rtt <= Duration::from_millis(110),
        "first RTT sample must be unadjusted (~100ms). Got {:?}",
        c.rtt
    );
}

#[test]
fn lost_stream_range_is_retransmitted_with_identical_payload_and_offset() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.server.pmtu = pmtu_state(false, PmtuPolicy::default());
    let payload = b"reliable stream payload across a dropped QUIC packet";
    pair.client.stream_send(0, payload, false).unwrap();
    let mut first_packet = [0u8; 1500];
    let first_pn = pair.client.next_send_pn_by_space[2];
    let (first_size, _) = pair.client.send(&mut first_packet).unwrap();

    pair.client.lose_stream_transmission_packet(first_pn);
    pair.client.recovery.on_loss_packet(first_pn, first_size, Instant::now());

    let mut retransmitted_packet = [0u8; 1500];
    let retransmitted_pn = pair.client.next_send_pn_by_space[2];
    let (retransmitted_len, _) = pair.client.send(&mut retransmitted_packet).unwrap();
    pair.server.recv(&mut retransmitted_packet[..retransmitted_len], &pair.recv_info).unwrap();

    let mut received = vec![0u8; payload.len()];
    let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
    assert_eq!(&received[..received_len], payload);
    assert!(!fin);
    assert_eq!(pair.client.stream_transmissions.len(), 1);
    assert!(pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
}

#[test]
fn confirmed_pmtu_packets_split_exactly_on_floor_retransmission() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1500;
    pair.server.dgram_send_max_size = 1500;
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.pmtu.set_confirmed_mtu_for_test(1500);
    pair.server.pmtu = pmtu_state(false, PmtuPolicy::default());
    let payload = (0..1400).map(|index| (index % 251) as u8).collect::<Vec<_>>();
    pair.client.stream_send(0, &payload, false).unwrap();

    let mut packet = [0u8; 1500];
    let original_pn = pair.client.next_send_pn_by_space[2];
    let (original_len, _) = pair.client.send(&mut packet).unwrap();
    assert!(original_len > pair.client.pmtu.min_mtu());
    pair.client.lose_stream_transmission_packet(original_pn);
    pair.client.recovery.on_loss_packet(original_pn, original_len, Instant::now());
    pair.client.pmtu.set_confirmed_mtu_for_test(pair.client.pmtu.min_mtu());

    let mut retransmitted_packet_numbers = Vec::new();
    while !pair.client.stream_retransmit_queue.is_empty() {
        let packet_number = pair.client.next_send_pn_by_space[2];
        let (packet_len, _) = pair.client.send(&mut packet).unwrap();
        assert!(packet_len <= pair.client.pmtu.min_mtu());
        pair.server.recv(&mut packet[..packet_len], &pair.recv_info).unwrap();
        retransmitted_packet_numbers.push(packet_number);
    }
    assert_eq!(retransmitted_packet_numbers.len(), 2);

    let mut received = vec![0u8; payload.len()];
    let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
    assert_eq!(received_len, payload.len());
    assert_eq!(received, payload);
    assert!(!fin);

    for packet_number in retransmitted_packet_numbers {
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(packet_number, packet_number + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
    }
    assert!(pair.client.stream_transmissions.is_empty());
    assert_eq!(pair.client.stream_retransmit_bytes, 0);
}

#[test]
fn late_ack_of_pre_split_packet_retires_every_retransmission_segment() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1500;
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.pmtu.set_confirmed_mtu_for_test(1500);
    pair.client.stream_send(0, &[0xA5; 1400], false).unwrap();

    let mut packet = [0u8; 1500];
    let original_pn = pair.client.next_send_pn_by_space[2];
    let (original_size, _) = pair.client.send(&mut packet).unwrap();
    pair.client.lose_stream_transmission_packet(original_pn);
    pair.client.recovery.on_loss_packet(original_pn, original_size, Instant::now());
    pair.client.pmtu.set_confirmed_mtu_for_test(pair.client.pmtu.min_mtu());

    let retransmitted_pn = pair.client.next_send_pn_by_space[2];
    pair.client.send(&mut packet).unwrap();
    assert_eq!(pair.client.stream_transmissions.len(), 2);
    assert_eq!(pair.client.stream_retransmit_queue.len(), 1);

    pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
    let now = Instant::now();
    let outcome = pair.client.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(original_pn, original_pn + 1)],
        Duration::ZERO,
        true,
        pair.client.is_server,
        now,
    );
    pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    assert!(pair.client.stream_transmissions.is_empty());
    assert!(pair.client.stream_retransmit_queue.is_empty());
    assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
    assert!(!pair.client.lost_stream_transmission_by_pn.contains_key(&original_pn));
    assert_eq!(pair.client.stream_retransmit_bytes, 0);
}

#[test]
fn late_ack_of_lost_copy_retires_active_retransmission_exactly_once() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.stream_send(0, b"late ACK retirement", false).unwrap();
    let mut packet = [0u8; 1500];
    let original_pn = pair.client.next_send_pn_by_space[2];
    pair.client.send(&mut packet).unwrap();

    pair.client.lose_stream_transmission_packet(original_pn);
    let retransmitted_pn = pair.client.next_send_pn_by_space[2];
    pair.client.send(&mut packet).unwrap();
    assert_eq!(pair.client.stream_transmissions.len(), 1);

    pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
    let now = Instant::now();
    let outcome = pair.client.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(original_pn, original_pn + 1)],
        Duration::ZERO,
        true,
        pair.client.is_server,
        now,
    );
    pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    assert!(pair.client.stream_transmissions.is_empty());
    assert!(pair.client.stream_retransmit_queue.is_empty());
    assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
    let now = Instant::now();
    let outcome = pair.client.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(retransmitted_pn, retransmitted_pn + 1)],
        Duration::ZERO,
        true,
        pair.client.is_server,
        now,
    );
    pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
    assert!(pair.client.stream_transmissions.is_empty());
}

#[test]
fn send_info_keeps_ack_only_packets_out_of_external_pacing() {
    let mut pair = bench_paired_1rtt_connections();
    pair.server.pmtu = pmtu_state(false, PmtuPolicy::default());
    assert!(pair.server.pkt_spaces[2].on_packet_recv(7));
    pair.server.pkt_spaces[2].note_ack_eliciting(0, 1);
    let bytes_in_flight = pair.server.recovery.bytes_in_flight;
    let mut packet = [0u8; 1500];

    let (_, send_info) = pair.server.send(&mut packet).expect("ACK must serialize");

    assert!(!send_info.congestion_controlled);
    assert_eq!(pair.server.recovery.bytes_in_flight, bytes_in_flight);
}

#[test]
fn traffic_analysis_off_mode_never_constructs_a_scheduler() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    config.set_chaff_rate_pps(10);
    config.set_traffic_analysis_defense(crate::transport::config::TrafficAnalysisDefense::Off);

    let connection =
        Connection::new_with_role(b"traffic-analysis-off", local(), peer(), config, false)
            .expect("valid test connection configuration");

    assert!(connection.traffic_analysis.is_none());
    assert!(connection.traffic_analysis_deadline().is_none());
}

#[test]
fn traffic_analysis_policy_applies_atomically_to_a_live_connection() {
    let mut pair = bench_paired_1rtt_connections();
    let policy = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        chaff_rate_pps: 0,
        chaff_size_bytes: 1200,
        constant_rate_pps: 80,
        idle_timeout_ms: 20_000,
        ramp_down_ms: 2_000,
    };

    pair.client.apply_traffic_analysis_policy(policy).expect("valid live policy");

    assert_eq!(pair.client.config.traffic_analysis_policy(), policy);
    assert!(pair.client.traffic_analysis_deadline().is_some());

    pair.client
        .apply_traffic_analysis_policy(crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::Off,
            ..policy
        })
        .expect("off policy");
    assert!(pair.client.traffic_analysis.is_none());
    assert!(pair.client.traffic_analysis_deadline().is_none());
}

#[test]
fn invalid_live_traffic_analysis_policy_preserves_the_active_scheduler() {
    let mut pair = bench_paired_1rtt_connections();
    let policy = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        chaff_rate_pps: 0,
        chaff_size_bytes: 1200,
        constant_rate_pps: 80,
        idle_timeout_ms: 20_000,
        ramp_down_ms: 2_000,
    };
    pair.client.apply_traffic_analysis_policy(policy).expect("valid live policy");
    let deadline = pair.client.traffic_analysis_deadline();

    let invalid = crate::transport::config::TrafficAnalysisPolicy {
        constant_rate_pps: crate::transport::config::TrafficAnalysisPolicy::MAX_CONSTANT_RATE_PPS
            + 1,
        ..policy
    };
    assert!(pair.client.apply_traffic_analysis_policy(invalid).is_err());

    assert_eq!(pair.client.config.traffic_analysis_policy(), policy);
    assert_eq!(pair.client.traffic_analysis_deadline(), deadline);
}

#[test]
fn intelligent_traffic_analysis_escalation_is_fail_closed_until_authorized() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    let escalation = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
        chaff_rate_pps: 10,
        chaff_size_bytes: 1200,
        constant_rate_pps: 0,
        idle_timeout_ms: 30_000,
        ramp_down_ms: 5_000,
    };
    config.set_intelligent_traffic_analysis_ceiling(escalation).expect("valid escalation ceiling");
    let mut connection =
        Connection::new_with_role(b"intelligent-auth", local(), peer(), config, true)
            .expect("valid test connection configuration");

    connection
        .apply_intelligent_traffic_analysis_level(2)
        .expect("unauthorized transition is a no-op");
    assert_eq!(
        connection.traffic_analysis_policy().defense,
        crate::transport::config::TrafficAnalysisDefense::Off
    );

    connection.authorize_intelligent_traffic_analysis(None).expect("authorization");
    connection.apply_intelligent_traffic_analysis_level(2).expect("authorized escalation");
    assert_eq!(connection.traffic_analysis_policy(), escalation);
    assert!(connection.traffic_analysis.is_some());

    connection.apply_intelligent_traffic_analysis_level(0).expect("de-escalation");
    assert_eq!(
        connection.traffic_analysis_policy().defense,
        crate::transport::config::TrafficAnalysisDefense::Off
    );
    assert!(connection.traffic_analysis.is_none());
}

#[test]
fn traffic_analysis_chaff_is_congestion_deferred_exact_sized_and_sequential() {
    let mut pair = bench_paired_1rtt_connections();
    let first_deadline = enable_test_traffic_analysis(
        &mut pair.client,
        crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        100,
        1200,
    );
    pair.client.on_traffic_analysis_timeout(first_deadline);
    assert!(pair
        .client
        .traffic_analysis
        .as_ref()
        .is_some_and(|scheduler| scheduler.has_pending_chaff()));

    pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
    let first_packet_number = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1500];
    assert_eq!(pair.client.send(&mut packet).unwrap_err(), ConnectionError::Done);
    assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number);
    assert!(pair
        .client
        .traffic_analysis
        .as_ref()
        .is_some_and(|scheduler| scheduler.has_pending_chaff()));

    pair.client.recovery.cwnd = 64 * 1024;
    let (first_len, first_info) = pair.client.send(&mut packet).expect("first chaff");
    assert_eq!(first_len, 1200);
    assert!(first_info.congestion_controlled);
    assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number + 1);
    pair.server.recv(&mut packet[..first_len], &pair.recv_info).expect("first chaff decrypts");

    let second_deadline = pair.client.traffic_analysis_deadline().expect("second chaff deadline");
    pair.client.on_traffic_analysis_timeout(second_deadline);
    let (second_len, second_info) = pair.client.send(&mut packet).expect("second chaff");
    assert_eq!(second_len, 1200);
    assert!(second_info.congestion_controlled);
    assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number + 2);
    pair.server.recv(&mut packet[..second_len], &pair.recv_info).expect("second chaff decrypts");
}

#[test]
fn traffic_analysis_chaff_ack_releases_congestion_budget() {
    let mut pair = bench_paired_1rtt_connections();
    let deadline = enable_test_traffic_analysis(
        &mut pair.client,
        crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        100,
        1200,
    );
    pair.client.on_traffic_analysis_timeout(deadline);
    let mut packet = [0u8; 1500];
    let (chaff_len, _) = pair.client.send(&mut packet).expect("chaff");
    pair.server.recv(&mut packet[..chaff_len], &pair.recv_info).expect("chaff decrypts");
    assert!(pair.client.recovery.bytes_in_flight > 0);
    assert!(pair.server.has_pending_application_ack());

    let (ack_len, ack_info) = pair.server.send(&mut packet).expect("ACK");
    assert!(!ack_info.congestion_controlled);
    pair.client
        .recv(
            &mut packet[..ack_len],
            &RecvInfo { from: pair.server.local_addr, to: pair.client.local_addr, ecn: None },
        )
        .expect("ACK decrypts");

    assert_eq!(pair.client.recovery.bytes_in_flight, 0);
}

#[test]
fn full_padding_chaff_uses_the_complete_udp_payload_budget() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.config.set_max_send_udp_payload_size(1500);
    pair.client.dgram_send_max_size = 1500;
    pair.server.config.set_max_recv_udp_payload_size(1500);
    pair.client.pmtu = pmtu_state(true, PmtuPolicy::default());
    let probe_time = Instant::now();
    pair.client.pmtu.on_probe_sent(1500, probe_time);
    pair.client.pmtu.on_probe_acked(probe_time);
    pair.client
        .apply_traffic_analysis_policy(crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1280,
            constant_rate_pps: 100,
            idle_timeout_ms: 60_000,
            ramp_down_ms: 5_000,
        })
        .expect("full-padding policy");
    let deadline = pair.client.traffic_analysis_deadline().expect("deadline");
    pair.client.on_traffic_analysis_timeout(deadline);
    let scheduler = pair.client.traffic_analysis.as_ref().expect("scheduler");
    assert_eq!(scheduler.chaff_size_bytes(), 1500);

    let mut packet = [0u8; 1500];
    let (packet_len, _) = pair.client.send(&mut packet).expect("full-padding chaff");
    assert_eq!(packet_len, 1500);
    pair.server.recv(&mut packet, &pair.recv_info).expect("full-padding chaff decrypts");
}

#[test]
fn traffic_analysis_pending_slot_never_turns_ack_only_into_chaff() {
    let mut pair = bench_paired_1rtt_connections();
    let deadline = enable_test_traffic_analysis(
        &mut pair.server,
        crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        100,
        1200,
    );
    pair.server.on_traffic_analysis_timeout(deadline);
    assert!(pair.server.pkt_spaces[2].on_packet_recv(7));
    pair.server.pkt_spaces[2].note_ack_eliciting(0, 1);
    let bytes_in_flight = pair.server.recovery.bytes_in_flight;
    let mut packet = [0u8; 1500];

    let (packet_len, send_info) = pair.server.send(&mut packet).expect("ACK must serialize");

    assert_eq!(packet_len, 1200);
    assert!(!send_info.congestion_controlled);
    assert_eq!(pair.server.recovery.bytes_in_flight, bytes_in_flight);
    assert!(pair
        .server
        .traffic_analysis
        .as_ref()
        .is_some_and(|scheduler| !scheduler.has_pending_chaff()));
    pair.client.recv(&mut packet[..packet_len], &pair.recv_info).expect("ACK decrypts");
}

#[test]
fn traffic_analysis_real_stream_data_consumes_the_due_slot_first() {
    let mut pair = bench_paired_1rtt_connections();
    let deadline = enable_test_traffic_analysis(
        &mut pair.client,
        crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        100,
        1200,
    );
    pair.client.on_traffic_analysis_timeout(deadline);
    let payload = b"real data must win over a due chaff slot";
    pair.client.stream_send(0, payload, false).expect("stream enqueue");
    let packet_number = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1500];

    let (packet_len, send_info) = pair.client.send(&mut packet).expect("stream packet");

    assert_eq!(packet_len, 1200);
    assert!(send_info.congestion_controlled);
    assert_eq!(pair.client.next_send_pn_by_space[2], packet_number + 1);
    assert!(pair
        .client
        .traffic_analysis
        .as_ref()
        .is_some_and(|scheduler| !scheduler.has_pending_chaff()));
    pair.server.recv(&mut packet[..packet_len], &pair.recv_info).expect("stream decrypts");
    let mut received = vec![0u8; payload.len()];
    let (received_len, fin) = pair.server.stream_recv(0, &mut received).expect("stream receive");
    assert_eq!(&received[..received_len], payload);
    assert!(!fin);
    assert_eq!(pair.client.send(&mut packet).unwrap_err(), ConnectionError::Done);
}

#[test]
fn traffic_analysis_connection_shutdown_cancels_deadline_and_pending_slot() {
    let mut pair = bench_paired_1rtt_connections();
    let deadline = enable_test_traffic_analysis(
        &mut pair.client,
        crate::transport::config::TrafficAnalysisDefense::FullPadding,
        10,
        1200,
    );
    pair.client.on_traffic_analysis_timeout(deadline);
    pair.client.close(true, 0, b"shutdown").expect("close");

    let scheduler = pair.client.traffic_analysis.as_ref().expect("scheduler retained");
    assert_eq!(scheduler.phase(), qf_stealth::TrafficAnalysisPhase::Cancelled);
    assert!(!scheduler.has_pending_chaff());
    assert!(pair.client.traffic_analysis_deadline().is_none());
}

#[test]
fn send_info_marks_stream_packets_for_external_pacing() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.stream_send(0, b"paced stream", false).unwrap();
    let mut packet = [0u8; 1500];

    let (_, send_info) = pair.client.send(&mut packet).expect("STREAM must serialize");

    assert!(send_info.congestion_controlled);
}

#[test]
fn pto_probe_then_time_threshold_requeues_tail_packet() {
    // Canonical RFC 9002 flow for a tail loss without a higher ACK: the PTO
    // fires a probe, the probe's ACK advances largest_acked, and the time
    // threshold then declares the tail packet lost.
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.stream_send(0, b"tail loss", false).unwrap();
    let mut packet = [0u8; 1500];
    let packet_number = pair.client.next_send_pn_by_space[2];
    let (packet_size, _) = pair.client.send(&mut packet).unwrap();
    // Age the tail packet beyond the initial loss_delay (9/8 * 333 ms).
    pair.client.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        packet_number,
        packet_size,
        true,
        true,
        None,
        Instant::now() - Duration::from_secs(1),
    );

    // 1. Recovery timeout fires the PTO: an Application probe is queued,
    //    nothing is declared lost (RFC 9002 §6.2.4).
    pair.client.on_recovery_timeout(Instant::now());
    assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
    assert!(pair
        .client
        .recovery
        .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));

    // 2. The probe (a later packet) is sent and acknowledged; the time
    //    threshold now declares the aged tail packet lost.
    let probe_pn = packet_number + 1;
    pair.client.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        probe_pn,
        1200,
        true,
        true,
        None,
        Instant::now(),
    );
    let now = Instant::now();
    let outcome = pair.client.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(probe_pn, probe_pn + 1)],
        Duration::ZERO,
        true,
        pair.client.is_server,
        now,
    );
    pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    assert!(!pair
        .client
        .recovery
        .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
    assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
    assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&packet_number));
}

#[test]
fn aged_datagram_survives_pto_without_being_declared_lost() {
    // RFC 9002 §6.2.4: a PTO firing sends probes - it never declares loss.
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(16, 16);
    pair.client.dgram_send(b"unreliable tail").unwrap();
    let mut packet = [0u8; 1500];
    let packet_number = pair.client.next_send_pn_by_space[2];
    let (packet_size, _) = pair.client.send(&mut packet).unwrap();
    // Age the recorded packet so a time-threshold timer would be expired,
    // then verify the PTO path still does not declare loss (RFC 9002 §6.2.4).
    pair.client.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        packet_number,
        packet_size,
        true,
        true,
        None,
        Instant::now() - Duration::from_secs(1),
    );
    let bytes_in_flight_before = pair.client.recovery.bytes_in_flight;

    pair.client.on_recovery_timeout(Instant::now());

    assert!(pair
        .client
        .recovery
        .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
    assert_eq!(pair.client.recovery.bytes_in_flight, bytes_in_flight_before);
    assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
}

#[test]
fn dgram_queue_full_is_retryable_after_send_drains_queue() {
    // A full QUIC DATAGRAM send queue must return DgramQueueFull, not a
    // terminal error, and a subsequent dgram_send must succeed once send()
    // has serialized the queued frame (TODO-559).
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(0, 1);
    assert_eq!(pair.client.dgram_send_queue_len(), 0);

    pair.client.dgram_send(b"one").unwrap();
    assert_eq!(pair.client.dgram_send_queue_len(), 1);

    let err = pair.client.dgram_send(b"two").unwrap_err();
    assert!(matches!(err, ConnectionError::DgramQueueFull));

    let mut packet = [0u8; 1500];
    let (written, _) = pair.client.send(&mut packet).unwrap();
    assert!(written > 0);
    assert_eq!(pair.client.dgram_send_queue_len(), 0);

    pair.client.dgram_send(b"two").unwrap();
    assert_eq!(pair.client.dgram_send_queue_len(), 1);
}

#[test]
fn datagrams_remain_queued_when_short_header_seal_fails() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.server.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(16, 16);
    let first = b"first datagram".to_vec();
    let second = b"second datagram".to_vec();
    pair.client.dgram_send(&first).expect("first datagram enqueue");
    pair.client.dgram_send(&second).expect("second datagram enqueue");
    assert_eq!(pair.client.stats.dgram_sent, 0);

    let (write_seal, write_hp) = {
        let crypto = pair.client.crypto.read();
        (crypto.seal_1rtt.clone(), crypto.hp_1rtt.clone())
    };
    {
        let mut crypto = pair.client.crypto.write();
        crypto.seal_1rtt = None;
        crypto.hp_1rtt = None;
    }
    pair.client.refresh_short_header_tag_reserve();

    let mut packet = [0u8; 1500];
    let error = pair.client.send(&mut packet).expect_err("missing sealer must fail send");
    assert!(matches!(error, ConnectionError::TlsError(_)));
    assert_eq!(pair.client.dgram_send_queue_len(), 2);
    assert_eq!(pair.client.dgram_send_queue_byte_size(), first.len() + second.len());
    assert_eq!(pair.client.stats.dgram_sent, 0);

    {
        let mut crypto = pair.client.crypto.write();
        crypto.seal_1rtt = write_seal;
        crypto.hp_1rtt = Some(std::sync::Arc::new(FailingHeaderProtector));
    }
    pair.client.refresh_short_header_tag_reserve();

    let error =
        pair.client.send(&mut packet).expect_err("header protection failure must fail send");
    assert!(matches!(error, ConnectionError::CryptoError(_)));
    assert_eq!(pair.client.dgram_send_queue_len(), 2);
    assert_eq!(pair.client.stats.dgram_sent, 0);

    {
        let mut crypto = pair.client.crypto.write();
        crypto.hp_1rtt = write_hp;
    }
    pair.client.refresh_short_header_tag_reserve();

    let (written, _) = pair.client.send(&mut packet).expect("retry first datagram");
    pair.server.recv(&mut packet[..written], &pair.recv_info).expect("receive first datagram");
    assert_eq!(pair.server.dgram_recv_vec().expect("first datagram delivery"), first);
    assert_eq!(pair.client.dgram_send_queue_len(), 1);
    assert_eq!(pair.client.stats.dgram_sent, 1);

    let (written, _) = pair.client.send(&mut packet).expect("retry second datagram");
    pair.server.recv(&mut packet[..written], &pair.recv_info).expect("receive second datagram");
    assert_eq!(pair.server.dgram_recv_vec().expect("second datagram delivery"), second);
    assert_eq!(pair.client.dgram_send_queue_len(), 0);
    assert_eq!(pair.client.stats.dgram_sent, 2);
}

#[test]
fn pto_probe_bypasses_congestion_gate_and_emits_ack_eliciting_packet() {
    // RFC 9002 §7.5/§6.2.4: a PTO probe bypasses the congestion gate but
    // still counts as in flight (tracked ack-eliciting packet).
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(16, 16);
    pair.client.dgram_send(b"unreliable tail").unwrap();
    let mut packet = [0u8; 1500];
    pair.client.send(&mut packet).unwrap();
    // Close the congestion gate: no headroom left in cwnd.
    pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
    assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

    // Without a pending probe the gate rejects the send.
    assert_eq!(pair.client.send(&mut packet).unwrap_err(), crate::error::ConnectionError::Done);

    // A PTO firing queues the probe; the next send emits it despite the gate.
    pair.client.on_recovery_timeout(Instant::now());
    let tracked_before =
        pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
    let (probe_len, probe_info) = pair.client.send(&mut packet).expect("probe must emit");
    assert!(probe_len > 0);
    assert!(probe_info.congestion_controlled); // probes count as in flight (§7.5)
    assert!(!pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
    let tracked_after =
        pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
    assert_eq!(tracked_after, tracked_before + 1);
}

#[test]
fn packet_threshold_loss_requeues_stream_range() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.stream_send(0, b"packet threshold loss", false).unwrap();
    let mut packet = [0u8; 1500];
    let stream_packet_number = pair.client.next_send_pn_by_space[2];
    pair.client.send(&mut packet).unwrap();
    let now = Instant::now();
    // The stream packet (PN 0) is already recorded by send(); seed PNs 1-4
    // so that an ACK for PN 4 advances largest_acked and declares PN 0 lost.
    for pn in 1..=4 {
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            now,
        );
    }

    let outcome = pair.client.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &[(4, 5)],
        Duration::ZERO,
        true,
        pair.client.is_server,
        now,
    );
    pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

    assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
    assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&stream_packet_number));
}

#[test]
fn full_stream_ledger_backpressures_without_emitting_empty_packets() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.stream_send(0, b"bounded", false).unwrap();
    pair.client.stream_retransmit_bytes = MAX_STREAM_RETRANSMIT_BYTES;
    let packet_number = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1500];

    let error = pair.client.send(&mut packet).unwrap_err();

    assert_eq!(error, crate::error::ConnectionError::Done);
    assert_eq!(pair.client.next_send_pn_by_space[2], packet_number);
    assert!(pair.client.stream_transmissions.is_empty());
}

#[test]
fn sparse_ack_accounting_removes_acked_and_prunes_packet_threshold_losses() {
    let mut c = make_conn();
    let send_time = Instant::now() - Duration::from_millis(50);
    for pn in 0..12 {
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            send_time,
        );
    }

    let ranges = vec![(0u64, 1u64), (4, 5), (8, 9)];
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        Duration::ZERO,
        true,
        c.is_server,
        Instant::now(),
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

    assert_eq!(c.stats.acked_bytes, 3600);
    assert_eq!(c.stats.lost, 4);
    assert_eq!(c.stats.lost_bytes, 4800);
    let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
    assert_eq!(remaining, vec![6, 7, 9, 10, 11]);
}

#[test]
fn sparse_ack_prefix_classification_preserves_ack_loss_and_tail() {
    let mut c = make_conn();
    let send_time = Instant::now() - Duration::from_millis(50);
    for pn in 0..64 {
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            send_time,
        );
    }

    let ranges = (0u64..64).step_by(4).map(|pn| (pn, pn + 1)).collect::<Vec<_>>();
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        Duration::ZERO,
        true,
        c.is_server,
        Instant::now(),
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

    assert_eq!(c.stats.acked_bytes, 16 * 1200);
    assert_eq!(c.stats.lost, 43);
    assert_eq!(c.stats.lost_bytes, 43 * 1200);
    let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
    assert_eq!(remaining, vec![58, 59, 61, 62, 63]);
}

#[test]
fn large_contiguous_ack_uses_split_drain_and_preserves_tail() {
    let mut c = make_conn();
    let send_time = Instant::now() - Duration::from_millis(50);
    for pn in 0..96 {
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            send_time,
        );
    }

    let ranges = vec![(16u64, 80u64)];
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        Duration::ZERO,
        true,
        c.is_server,
        Instant::now(),
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

    assert_eq!(c.stats.acked_bytes, 64 * 1200);
    let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
    assert_eq!(remaining, (80..96).collect::<Vec<_>>());
}

#[test]
fn large_loss_prefix_uses_split_drain_and_preserves_unlost_tail() {
    let mut c = make_conn();
    let send_time = Instant::now() - Duration::from_millis(50);
    for pn in 0..128 {
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            1200,
            true,
            true,
            None,
            send_time,
        );
    }

    let ranges = vec![(127u64, 128u64)];
    let outcome = c.recovery.on_ack_received(
        recovery::PacketSpace::Application,
        &ranges,
        Duration::ZERO,
        true,
        c.is_server,
        Instant::now(),
    );
    c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

    assert_eq!(c.stats.acked_bytes, 1200);
    assert_eq!(c.stats.lost, 125);
    assert_eq!(c.stats.lost_bytes, 125 * 1200);
    let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
    assert_eq!(remaining, vec![125, 126]);
}

#[test]
fn timeout_does_not_inflate_rtt_repeatedly() {
    // Verify that repeated timeouts do NOT cause monotonic RTT inflation.
    // This is the regression test for the 0→385ms loopback RTT bug.
    let mut c = make_conn();
    let rtt_before = c.rtt;
    for _ in 0..10 {
        c.on_timeout();
    }
    assert_eq!(
        c.rtt, rtt_before,
        "10 timeouts must not inflate RTT. Got {:?}, expected {:?}",
        c.rtt, rtt_before
    );
}
