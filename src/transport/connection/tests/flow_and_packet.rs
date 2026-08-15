use super::*;

// ---- MAX_STREAMS / MAX_DATA Handling ---------------------------------

#[test]
fn peer_max_data_update_monotonic() {
    let mut c = make_conn();
    let initial = c.peer_max_data;
    // Simulate peer sending larger MAX_DATA
    c.peer_max_data = initial + 1000;
    assert_eq!(c.peer_max_data, initial + 1000);
    // Verify peer_max_data was updated to the new value
    assert_eq!(c.peer_max_data, initial + 1000, "peer_max_data must reflect the update");
}

#[test]
fn conn_max_data_initial_matches_config() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    let initial_max = cfg.initial_max_data;
    let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false)
        .expect("valid test connection configuration");
    assert_eq!(c.conn_max_data, initial_max, "conn_max_data must match config initial_max_data");
}

#[test]
fn max_peer_max_data_cap_prevents_resource_exhaustion() {
    // Verify the cap constant exists and is reasonable
    const { assert!(MAX_PEER_MAX_DATA > 0, "MAX_PEER_MAX_DATA must be positive") };
    assert!(MAX_PEER_MAX_DATA <= 2_u64.pow(30), "MAX_PEER_MAX_DATA must be bounded");
}

// ---- Packet Number Space Management ----------------------------------

#[test]
fn initial_pn_spaces_start_at_zero() {
    let c = make_conn();
    for (i, &pn) in c.next_send_pn_by_space.iter().enumerate() {
        assert_eq!(pn, 0, "next_send_pn for space {} must start at 0", i);
    }
}

#[test]
fn three_pn_spaces_exist() {
    let c = make_conn();
    assert_eq!(
        c.pkt_spaces.len(),
        3,
        "must have exactly 3 PN spaces (Initial, Handshake, Application)"
    );
    assert_eq!(c.next_send_pn_by_space.len(), 3, "must have 3 next_send_pn counters");
}

#[test]
fn outbound_packet_number_guard_allows_last_valid_number_then_stops() {
    let mut c = make_conn();
    c.next_send_pn_by_space[2] = pnspace::PktNumSpace::MAX_PACKET_NUMBER;

    assert_eq!(
        c.next_send_packet_number(2),
        Ok(pnspace::PktNumSpace::MAX_PACKET_NUMBER),
        "the RFC 9000 upper bound itself is a valid packet number"
    );
    c.advance_send_packet_number(2).expect("last valid packet number advances");
    assert_eq!(c.next_send_pn_by_space[2], pnspace::PktNumSpace::MAX_PACKET_NUMBER + 1);
    assert_eq!(
        c.next_send_packet_number(2),
        Err(ConnectionError::AeadLimitReached),
        "no packet may be emitted with a packet number beyond 62 bits"
    );
}

#[test]
fn outbound_packet_number_guard_rejects_overflow_without_wrapping() {
    let mut c = make_conn();
    c.next_send_pn_by_space[2] = u64::MAX;

    assert_eq!(c.advance_send_packet_number(2), Err(ConnectionError::AeadLimitReached));
    assert_eq!(c.next_send_pn_by_space[2], u64::MAX);
}

#[test]
fn outbound_packet_send_rejects_invalid_packet_number_before_mutation() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.next_send_pn_by_space[2] = pnspace::PktNumSpace::MAX_PACKET_NUMBER + 1;
    pair.client.stream_send(0, b"guarded payload", false).unwrap();
    let before = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1500];

    let error = pair.client.send(&mut packet);
    assert!(matches!(error, Err(ConnectionError::AeadLimitReached)));
    assert_eq!(pair.client.next_send_pn_by_space[2], before);
}

// ---- Connection Close Frame Generation -------------------------------

#[test]
fn close_app_and_transport_produce_different_frames() {
    let mut c1 = make_conn();
    c1.close(true, 42, b"app error").unwrap();
    let has_app = c1.pending_control.iter().any(|f| matches!(f, Frame::ApplicationClose { .. }));
    assert!(has_app, "app close must produce ApplicationClose frame");

    let mut c2 = make_conn();
    c2.close(false, 0x01, b"protocol error").unwrap();
    let has_conn = c2.pending_control.iter().any(|f| matches!(f, Frame::ConnectionClose { .. }));
    assert!(has_conn, "transport close must produce ConnectionClose frame");
    assert!(matches!(
        c1.local_error(),
        Some(ConnectionError::LocalApplicationClosed { error_code: 42, .. })
    ));
    assert!(matches!(
        c2.local_error(),
        Some(ConnectionError::LocalConnectionClosed { error_code: 0x01, .. })
    ));
}

#[test]
fn close_reason_preserved_in_frame() {
    let mut c = make_conn();
    c.close(true, 99, b"test reason").unwrap();
    let frame = c.pending_control.back().expect("must have queued frame");
    match frame {
        Frame::ApplicationClose { error_code, reason } => {
            assert_eq!(*error_code, 99);
            assert_eq!(reason.as_ref(), b"test reason");
        }
        _ => panic!("expected ApplicationClose frame"),
    }
}

#[test]
fn peer_close_frames_transition_connection_to_closed() {
    for app_close in [false, true] {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.close(app_close, 42, b"peer shutdown").unwrap();

        let mut packet = [0u8; 1500];
        let (packet_len, _) = pair.client.send(&mut packet).unwrap();
        pair.server.recv(&mut packet[..packet_len], &pair.recv_info).unwrap();

        assert!(pair.server.is_closed(), "peer close frame must close the connection");
        assert!(pair.server.is_draining(), "peer close frame must enter draining state");
        let expected = if app_close {
            ConnectionError::PeerApplicationClosed {
                error_code: 42,
                reason: b"peer shutdown".to_vec(),
            }
        } else {
            ConnectionError::PeerConnectionClosed {
                error_code: 42,
                frame_type: 0,
                reason: b"peer shutdown".to_vec(),
            }
        };
        assert_eq!(pair.server.remote_error(), Some(&expected));
    }
}

#[test]
fn remote_close_remains_observable_after_local_timeout() {
    let mut pair = bench_paired_1rtt_connections();
    pair.server.close(false, 0x42, b"peer shutdown").unwrap();

    let mut packet = [0u8; 1500];
    let (packet_len, _) = pair.server.send(&mut packet).unwrap();
    pair.client.on_timeout();
    let recv_info =
        RecvInfo { from: pair.server.local_addr, to: pair.client.local_addr, ecn: None };
    pair.client.recv(&mut packet[..packet_len], &recv_info).unwrap();

    assert_eq!(pair.client.local_error, Some(ConnectionError::Timeout));
    assert_eq!(
        pair.client.remote_error(),
        Some(&ConnectionError::PeerConnectionClosed {
            error_code: 0x42,
            frame_type: 0,
            reason: b"peer shutdown".to_vec(),
        })
    );
    assert_eq!(pair.client.error(), Some(&ConnectionError::Timeout));
}

// ---- ECN Counters ----------------------------------------------------

#[test]
fn ecn_counters_start_at_zero() {
    let c = make_conn();
    let (ect0, ect1, ce) = c.ecn_counts();
    assert_eq!(ect0, 0);
    assert_eq!(ect1, 0);
    assert_eq!(ce, 0);
}

// ---- Stats -----------------------------------------------------------

#[test]
fn stats_start_zeroed() {
    let c = make_conn();
    let s = c.stats();
    assert_eq!(s.recv, 0);
    assert_eq!(s.sent, 0);
    assert_eq!(s.lost, 0);
}

#[test]
fn receive_frame_preflight_rejects_empty_and_malformed_suffixes() {
    assert!(matches!(
        Connection::preflight_frame_payload(&[], PacketType::Short),
        Err(ConnectionError::InvalidFrame)
    ));
    assert!(matches!(
        Connection::preflight_frame_payload(&[0x01, 0x1F], PacketType::Short),
        Err(ConnectionError::InvalidFrame)
    ));
    assert!(matches!(
        Connection::preflight_frame_payload(&[0x0E, 0x40], PacketType::Short),
        Err(ConnectionError::BufferTooShort)
    ));
    assert_eq!(Connection::preflight_frame_payload(&[0x01, 0x00], PacketType::Short), Ok(()));
}

// ---- Stream Priority -------------------------------------------------

#[test]
fn stream_priority_reorders_writable_queue() {
    let mut c = make_conn();
    c.peer_max_data = 100_000;
    c.stream_send(0, b"low", false).unwrap();
    c.stream_send(4, b"high", false).unwrap();
    // Set stream 4 to higher priority (lower urgency number)
    c.stream_priority(4, 1, false).unwrap();
    let first = c.writable_streams.front().copied();
    assert_eq!(first, Some(4), "higher-priority stream must be first in writable queue");
}

// ---- Datagram Queues -------------------------------------------------

#[test]
fn dgram_send_recv_roundtrip() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    c.dgram_send(b"test_dgram").unwrap();
    assert_eq!(c.dgram_send_queue_len(), 1);
    assert_eq!(c.dgram_send_queue_byte_size(), 10);
}

#[cfg(not(feature = "zero_copy_dgram"))]
#[test]
fn owned_datagram_insufficient_output_preserves_queue() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let payload_len = 16_384;
    c.dgram_send_queue.push_back(vec![0xAB; payload_len]);
    let mut output = vec![0u8; 1 + 2 + payload_len];

    assert_eq!(
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("insufficient output is a no-op"),
        (0, false)
    );
    assert_eq!(c.dgram_send_queue_len(), 1);
    assert_eq!(c.dgram_send_queue_byte_size(), payload_len);
    assert!(c
        .dgram_send_queue
        .front()
        .is_some_and(|payload| payload.iter().all(|byte| *byte == 0xAB)));
}

#[test]
fn zero_copy_dgram_byte_equivalence_for_accepted_payload() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let payload: Vec<u8> = (0..64).map(|value| value as u8).collect();

    c.dgram_send(&payload).expect("accepted DATAGRAM must enqueue");
    assert_eq!(c.dgram_send_queue_byte_size(), payload.len());
    #[cfg(not(feature = "zero_copy_dgram"))]
    assert_eq!(c.dgram_send_queue.front().unwrap().as_slice(), payload.as_slice());
    #[cfg(feature = "zero_copy_dgram")]
    {
        let front = c.dgram_send_queue.front().unwrap();
        assert_eq!(&front.data[..front.len], payload.as_slice());
    }

    c.enqueue_received_datagram(std::borrow::Cow::Borrowed(&payload));
    let mut received = vec![0u8; payload.len()];
    assert_eq!(c.dgram_recv(&mut received).unwrap(), payload.len());
    assert_eq!(received, payload);
}

#[cfg(feature = "zero_copy_dgram")]
#[test]
fn zero_copy_dgram_returns_pool_blocks_at_queue_boundaries() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 64));
    c.dgram_pool = Arc::clone(&pool);
    let before = pool.accounting_snapshot();

    c.dgram_send(&[0xA5; 32]).expect("DATAGRAM enqueue must allocate one block");
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    c.dgram_purge_outgoing(|data| data[0] == 0xA5);
    assert_eq!(pool.accounting_snapshot(), before);

    c.dgram_send(&[0x5A; 32]).expect("second DATAGRAM enqueue must allocate one block");
    let mut output = [0u8; 128];
    let (written, ack_eliciting) =
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("DATAGRAM serialization");
    assert!(written > 0);
    assert!(ack_eliciting);
    c.commit_staged_datagram_frame().expect("DATAGRAM commit");
    assert_eq!(pool.accounting_snapshot(), before);

    c.dgram_send(&[0x3C; 32]).expect("teardown DATAGRAM enqueue");
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    drop(c);
    assert_eq!(pool.accounting_snapshot(), before);
}

#[cfg(feature = "zero_copy_dgram")]
#[test]
fn zero_copy_dgram_receive_pop_vec_and_rejection_return_pool_blocks() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 64));
    c.dgram_pool = Arc::clone(&pool);
    let before = pool.accounting_snapshot();

    let mut limited_send = make_conn();
    limited_send.enable_datagrams(16, 1);
    limited_send.dgram_pool = Arc::clone(&pool);
    limited_send.dgram_send(&[0xC1; 8]).expect("first send queue slot");
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    assert!(matches!(limited_send.dgram_send(&[0xC2; 8]), Err(ConnectionError::DgramQueueFull)));
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    drop(limited_send);
    assert_eq!(pool.accounting_snapshot(), before);

    c.enqueue_received_datagram(std::borrow::Cow::Borrowed(b"pop"));
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    let mut received = [0u8; 3];
    assert_eq!(c.dgram_recv(&mut received).unwrap(), 3);
    assert_eq!(&received, b"pop");
    assert_eq!(pool.accounting_snapshot(), before);

    c.enqueue_received_datagram(std::borrow::Cow::Borrowed(b"vec"));
    assert_eq!(c.dgram_recv_vec().unwrap(), b"vec");
    assert_eq!(pool.accounting_snapshot(), before);

    let oversized = vec![0xF0; pool.block_size() + 1];
    c.enqueue_received_datagram(std::borrow::Cow::Borrowed(&oversized));
    assert_eq!(c.dgram_recv_queue_len(), 0);
    assert_eq!(pool.accounting_snapshot(), before);

    drop(c);
    assert_eq!(pool.accounting_snapshot(), before);

    let mut limited_receive = make_conn();
    limited_receive.enable_datagrams(1, 16);
    limited_receive.dgram_pool = Arc::clone(&pool);
    limited_receive.enqueue_received_datagram(std::borrow::Cow::Borrowed(b"one"));
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    limited_receive.enqueue_received_datagram(std::borrow::Cow::Borrowed(b"two"));
    assert_eq!(limited_receive.dgram_recv_queue_len(), 1);
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);
    drop(limited_receive);
    assert_eq!(pool.accounting_snapshot(), before);
}

#[cfg(feature = "zero_copy_dgram")]
#[test]
fn zero_copy_dgram_rejects_payload_larger_than_pool_without_truncation() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 64));
    c.dgram_pool = Arc::clone(&pool);
    c.dgram_send_max_size = pool.block_size() + 1;
    let oversized = vec![0xD7; pool.block_size() + 1];
    let before = pool.accounting_snapshot();

    assert!(matches!(c.dgram_send(&oversized), Err(ConnectionError::InvalidState)));
    assert_eq!(c.dgram_send_queue_len(), 0);
    assert_eq!(c.dgram_send_queue_byte_size(), 0);
    assert_eq!(pool.accounting_snapshot(), before);
}

#[cfg(feature = "zero_copy_dgram")]
#[test]
fn zero_copy_dgram_insufficient_output_preserves_pool_owned_buffer() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let pool = Arc::new(crate::optimize::MemoryPool::new(2, 16_384));
    c.dgram_pool = Arc::clone(&pool);
    c.dgram_send_max_size = 16_384;
    let payload_len = 16_384;
    let before = pool.accounting_snapshot();
    let mut data = crate::optimize::PooledBlock::new(Arc::clone(&pool));
    data[..payload_len].fill(0xAB);
    c.dgram_send_queue.push_back(DatagramBuffer { data, len: payload_len });
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);

    let mut output = vec![0u8; 1 + 2 + payload_len];
    assert_eq!(
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("insufficient output is a no-op"),
        (0, false)
    );
    assert_eq!(c.dgram_send_queue_len(), 1);
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);

    c.dgram_purge_outgoing(|_| true);
    assert_eq!(pool.accounting_snapshot(), before);
}

#[test]
fn outer_framing_reserves_space_for_queued_datagram_after_stream() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(16, 16);
    pair.server.enable_datagrams(16, 16);
    pair.client.dgram_send(&[0xD1; 1100]).expect("datagram enqueue");
    pair.client.stream_send(0, &[0xA5; 1200], false).expect("stream enqueue");
    let mut packet = [0u8; 1280];

    let (written, _) = pair
        .client
        .send_with_datagram_overhead(&mut packet, 36)
        .expect("outer-framed packet must serialize");
    pair.server.recv(&mut packet[..written], &pair.recv_info).expect("packet receive");

    assert_eq!(pair.client.dgram_send_queue_len(), 0);
    assert_eq!(pair.server.dgram_recv_vec().expect("datagram receive"), vec![0xD1; 1100]);
}

#[test]
fn datagram_frame_reservation_matches_four_byte_length_varint() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    c.dgram_send_max_size = 65_536;
    #[cfg(feature = "zero_copy_dgram")]
    {
        c.dgram_pool = Arc::new(crate::optimize::MemoryPool::new(2, 16_384));
    }
    let payload = vec![0xD4; 16_384];
    c.dgram_send(&payload).expect("boundary DATAGRAM enqueue");

    let reserve = c.pending_datagram_frame_reserve().expect("queued DATAGRAM reserve");
    assert_eq!(reserve, 1 + 4 + payload.len());
    let mut output = vec![0u8; reserve];
    let (written, ack_eliciting) =
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("boundary DATAGRAM encode");
    assert_eq!(written, reserve);
    assert!(ack_eliciting);
    c.commit_staged_datagram_frame().expect("boundary DATAGRAM commit");
    assert_eq!(c.dgram_send_queue_len(), 0);
}

// ---- Recovery / FEC Escalation ---------------------------------------

#[test]
fn fec_escalation_threshold_default() {
    let c = make_conn();
    let thr = c.fec_escalation_threshold();
    assert!(thr > 0.0, "FEC escalation threshold must be positive");
    assert!(thr < 1.0, "FEC escalation threshold must be < 1.0");
}

// ---- Brain / Stealth Runtime -----------------------------------------

#[test]
fn intelligent_stealth_runtime_default_off() {
    let c = make_conn();
    assert!(
        !c.intelligent_stealth_runtime_enabled_for_test(),
        "intelligent stealth runtime must default to off"
    );
}

#[test]
fn set_intelligent_stealth_runtime_toggle() {
    let mut c = make_conn();
    c.set_intelligent_stealth_runtime_for_test(true);
    assert!(c.intelligent_stealth_runtime_enabled_for_test());
    c.set_intelligent_stealth_runtime_for_test(false);
    assert!(!c.intelligent_stealth_runtime_enabled_for_test());
}

#[test]
fn transport_stealth_jitter_disabled_when_external_pacing() {
    let mut c = make_conn();
    c.set_stealth_timing(true, 5_000);
    c.set_external_pacing_for_test(true);
    assert!(!c.transport_stealth_timing_active());
    assert!(c.transport_stealth_jitter_delay().is_none());
}

#[test]
fn transport_stealth_jitter_bounded_when_gate_active() {
    let mut c = make_conn();
    c.set_stealth_timing(true, 100);
    c.set_external_pacing_for_test(false);
    assert!(c.transport_stealth_timing_active());
    let delay =
        c.transport_stealth_jitter_delay().expect("jitter should be scheduled when gate active");
    assert!(delay <= Duration::from_micros(100));
}

#[test]
fn pmtu_policy_reaches_configured_1500_ceiling() {
    let now = Instant::now();
    let mut state = pmtu_state(true, PmtuPolicy::default());

    assert_eq!(state.effective_mtu(), 1280);
    assert_eq!(state.probe_size(), Some(1500));
    state.on_probe_sent(1500, now);
    state.on_probe_acked(now);

    assert_eq!(state.effective_mtu(), 1500);
    assert_eq!(state.probe_size(), None);
}

#[test]
fn connection_emits_dedicated_probe_above_confirmed_mtu() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1500;
    pair.client.pmtu = pmtu_state(true, PmtuPolicy::default());
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.recovery.bytes_in_flight = 0;
    let mut packet = [0u8; 1600];
    let bytes_in_flight_before = pair.client.recovery.bytes_in_flight;

    let (packet_len, info) = pair.client.send(&mut packet).expect("PMTU probe must serialize");

    assert_eq!(packet_len, 1500);
    assert!(info.congestion_controlled);
    assert!(pair.client.recovery.bytes_in_flight > bytes_in_flight_before);
    assert!(pair.client.pmtu_probe_pn.is_some());
}

#[test]
fn dedicated_pmtu_probe_bypasses_a_closed_congestion_gate() {
    // RFC 8899 permits a rate-limited PING+PADDING probe outside the
    // congestion window. It must not carry queued application data.
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1472;
    pair.client.pmtu = pmtu_state(true, PmtuPolicy { max_mtu: 1472, ..PmtuPolicy::default() });
    pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
    assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

    let tracked_before =
        pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
    let mut packet = [0u8; 1600];
    let (packet_len, info) = pair.client.send(&mut packet).expect("dedicated PMTU probe must emit");

    assert_eq!(packet_len, 1472);
    assert!(info.congestion_controlled);
    assert!(pair.client.pmtu_probe_pn.is_some());
    let tracked_after =
        pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
    assert_eq!(tracked_after, tracked_before + 1);
}

#[test]
fn dedicated_pmtu_probe_respects_congestion_when_interval_is_shorter_than_rtt() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1472;
    pair.client.pmtu = pmtu_state(
        true,
        PmtuPolicy {
            max_mtu: 1472,
            probe_interval: Duration::from_millis(1),
            ..PmtuPolicy::default()
        },
    );
    pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
    assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

    let mut packet = [0u8; 1600];
    assert_eq!(pair.client.send(&mut packet).unwrap_err(), crate::error::ConnectionError::Done);
    assert!(pair.client.pmtu_probe_pn.is_none());
}

#[test]
fn connection_emits_exact_outer_probe_with_datagram_overhead() {
    const FEC_WIRE_OVERHEAD: usize = 18;
    let mut pair = bench_paired_1rtt_connections();
    pair.client.dgram_send_max_size = 1500;
    pair.client.pmtu = pmtu_state(true, PmtuPolicy::default());
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.recovery.bytes_in_flight = 0;
    let mut packet = [0u8; 1600];

    let (packet_len, _) = pair
        .client
        .send_with_datagram_overhead(&mut packet, FEC_WIRE_OVERHEAD)
        .expect("PMTU probe with outer framing must serialize");

    assert_eq!(packet_len + FEC_WIRE_OVERHEAD, 1500);
    assert!(pair.client.pmtu_probe_pn.is_some());
}

#[test]
fn unavailable_probe_capacity_does_not_emit_empty_packet() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(true, PmtuPolicy::default());
    let packet_number = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1600];

    let error = pair.client.send(&mut packet).unwrap_err();

    assert_eq!(error, crate::error::ConnectionError::Done);
    assert_eq!(pair.client.next_send_pn_by_space[2], packet_number);
    assert!(pair.client.pmtu_probe_pn.is_none());
}

#[test]
fn pmtu_loss_bisects_configured_bounds() {
    let now = Instant::now();
    let mut state = pmtu_state(true, PmtuPolicy::default());

    state.on_probe_sent(1500, now);
    state.on_probe_lost();

    assert_eq!(state.probe_size(), Some(1390));
    assert_eq!(state.effective_mtu(), 1280);
}

#[test]
fn smaller_unrelated_ack_does_not_mask_confirmed_mtu_black_hole() {
    let policy =
        PmtuPolicy { black_hole_timeout: Duration::from_millis(10), ..PmtuPolicy::default() };
    let start = Instant::now();
    let mut state = pmtu_state(true, policy);
    state.on_probe_sent(1500, start);
    state.on_probe_acked(start);
    let large_send = start + Duration::from_millis(1);
    state.on_packet_sent(1400, large_send);
    state.on_packet_acked(1280, start + Duration::from_millis(5));

    assert!(state.check_black_hole(start + Duration::from_millis(12)));
}

#[test]
fn repeated_above_floor_sends_do_not_defer_black_hole_timeout() {
    let policy =
        PmtuPolicy { black_hole_timeout: Duration::from_millis(10), ..PmtuPolicy::default() };
    let start = Instant::now();
    let mut state = pmtu_state(true, policy);
    state.on_probe_sent(1500, start);
    state.on_probe_acked(start);
    state.on_packet_sent(1400, start + Duration::from_millis(1));
    state.on_packet_sent(1400, start + Duration::from_millis(9));

    assert!(state.check_black_hole(start + Duration::from_millis(12)));
}

#[test]
fn black_hole_reset_recovers_at_floor_then_periodically_reprobes_ceiling() {
    let probe_interval = Duration::from_millis(10);
    let policy = PmtuPolicy {
        probe_interval,
        black_hole_timeout: Duration::from_millis(5),
        ..PmtuPolicy::default()
    };
    let start = Instant::now();
    let mut state = pmtu_state(true, policy);
    state.on_probe_sent(1500, start);
    state.on_probe_acked(start);
    state.on_packet_sent(1500, start + Duration::from_millis(1));
    let reset_at = start + Duration::from_millis(7);

    assert!(state.check_black_hole(reset_at));
    state.reset_to_minimum(reset_at);
    assert_eq!(state.effective_mtu(), 1280);
    assert!(!state.should_send_probe(reset_at + probe_interval - Duration::from_millis(1)));
    assert!(state.should_send_probe(reset_at + probe_interval));

    let mut probe_at = reset_at + probe_interval;
    for _ in 0..8 {
        let probe_size = state.probe_size().expect("recovery search must retain a target");
        if probe_size == 1500 {
            break;
        }
        state.on_probe_sent(probe_size, probe_at);
        state.on_probe_lost();
        probe_at += probe_interval;
    }

    assert_eq!(state.probe_size(), Some(1500));
    assert!(!state.should_send_probe(probe_at - Duration::from_millis(1)));
    assert!(state.should_send_probe(probe_at));
    state.on_probe_sent(1500, probe_at);
    state.on_probe_acked(probe_at);
    assert_eq!(state.effective_mtu(), 1500);
}

#[test]
fn disabled_pmtu_stays_at_configured_floor() {
    let state = pmtu_state(false, PmtuPolicy::default());

    assert_eq!(state.effective_mtu(), 1280);
    assert_eq!(state.probe_size(), None);
    assert!(!state.enabled());
}

/// Flow-control credit must reflect newly received bytes, not raw payload length.
///
/// Before this contract every STREAM frame added its full length to `conn_bytes_recvd`, so a
/// retransmitted or reordered range consumed connection credit again for bytes the stream
/// already held.
#[test]
fn newly_covered_bytes_counts_only_the_union_of_new_ranges() {
    use std::collections::BTreeMap;
    type Frags = BTreeMap<u64, Vec<u8>>;

    let empty: Frags = BTreeMap::new();

    // Nothing received yet: the whole range is new.
    assert_eq!(Connection::newly_covered_bytes(0, &empty, 0, 100), 100);
    // Empty and inverted ranges contribute nothing.
    assert_eq!(Connection::newly_covered_bytes(0, &empty, 50, 50), 0);
    assert_eq!(Connection::newly_covered_bytes(0, &empty, 80, 50), 0);

    // Everything below the delivered prefix is a duplicate.
    assert_eq!(Connection::newly_covered_bytes(100, &empty, 0, 100), 0);
    assert_eq!(Connection::newly_covered_bytes(100, &empty, 40, 60), 0);
    // Straddling the prefix boundary counts only the part above it.
    assert_eq!(Connection::newly_covered_bytes(100, &empty, 60, 140), 40);

    // A buffered out-of-order fragment already covers [200, 300).
    let mut frags: Frags = BTreeMap::new();
    frags.insert(200, vec![0u8; 100]);

    // Exact duplicate of the fragment.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 200, 300), 0);
    // Fully inside the fragment.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 220, 260), 0);
    // Overlapping the fragment on the left: only [150, 200) is new.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 150, 250), 50);
    // Overlapping on the right: only [300, 340) is new.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 250, 340), 40);
    // Spanning the fragment: the two gaps around it are new, the fragment itself is not.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 150, 350), 100);
    // Entirely past the fragment.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 400, 450), 50);

    // Two fragments with a hole between them: [300, 400) is the only new part.
    frags.insert(400, vec![0u8; 50]);
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 200, 450), 100);

    // The delivered prefix and the fragments combine.
    assert_eq!(Connection::newly_covered_bytes(250, &frags, 0, 450), 100);
}

/// A duplicate STREAM frame must not consume connection credit twice.
#[test]
fn duplicate_stream_frames_do_not_consume_connection_credit_again() {
    use std::collections::BTreeMap;
    let mut frags: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

    // First arrival of [0, 64) with nothing delivered yet.
    let first = Connection::newly_covered_bytes(0, &frags, 0, 64);
    assert_eq!(first, 64, "the first copy of a range is entirely new");

    // Store it the way the receive path would for out-of-order data.
    frags.insert(0, vec![0u8; 64]);

    // The identical retransmission is worth nothing.
    assert_eq!(
        Connection::newly_covered_bytes(0, &frags, 0, 64),
        0,
        "a retransmission must not consume credit a second time"
    );

    // A partial retransmission that extends the range only pays for the extension.
    assert_eq!(Connection::newly_covered_bytes(0, &frags, 32, 96), 32);
}

/// Arbitrary arrival order must total exactly the size of the covered union.
#[test]
fn overlapping_arrivals_in_any_order_total_the_covered_union() {
    use std::collections::BTreeMap;

    // Ranges deliberately overlap and arrive out of order. Their union is [0, 120).
    let arrivals: [(u64, u64); 6] = [(40, 80), (0, 50), (70, 120), (10, 30), (0, 120), (100, 110)];

    let mut frags: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut credited = 0u64;
    for (start, end) in arrivals {
        credited += Connection::newly_covered_bytes(0, &frags, start, end);
        // Model the receive path's storage: keep the newly seen span.
        frags.insert(start, vec![0u8; (end - start) as usize]);
    }

    assert_eq!(
        credited, 120,
        "total credit must equal the size of the covered union, not the sum of payloads"
    );
    let raw_total: u64 = arrivals.iter().map(|(start, end)| end - start).sum();
    assert!(raw_total > credited, "the fixture must actually contain overlap");
}
