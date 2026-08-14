use super::dns_and_packets::test_ipv4_udp_packet;
use super::*;

#[test]
fn stateless_version_negotiation_skips_fec_envelopes() {
    let meta = crate::fec::wire::WirePacketMeta {
        profile: crate::fec::wire::WireProfile {
            epoch: 1,
            codec: crate::fec::wire::WireCodec::Gf8,
            source_count: 4,
            total_count: 5,
            interleave_depth: 1,
        },
        window: 0,
        sequence: 3,
        repair_index: 0,
        block_index: 0,
        systematic: false,
    };
    let payload = vec![0; crate::transport::MIN_CLIENT_INITIAL_LEN - crate::fec::wire::HEADER_LEN];
    let mut datagram = vec![0; crate::transport::MIN_CLIENT_INITIAL_LEN];
    let written = crate::fec::wire::write_packet(meta, &payload, &mut datagram)
        .expect("FEC envelope must serialize");
    let datagram = &datagram[..written];
    let supported_versions = [crate::transport::PROTOCOL_VERSION];

    assert!(crate::fec::wire::is_framed(datagram));
    assert!(crate::transport::packet::server_version_negotiation_response(
        datagram,
        &supported_versions,
    )
    .expect("FEC bytes can resemble an unsupported long header")
    .is_some());
    assert!(stateless_version_negotiation_response(datagram, &supported_versions)
        .expect("FEC envelope must bypass stateless version negotiation")
        .is_none());
}

#[test]
fn pending_tun_downlinks_bound_admission_and_preserve_ownership() {
    let first_target: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let second_target: SocketAddr = "127.0.0.1:41002".parse().unwrap();
    let migrated_target: SocketAddr = "127.0.0.1:41003".parse().unwrap();
    let now = Instant::now();
    let first_session = SessionId::from_u64(1);
    let second_session = SessionId::from_u64(2);
    let third_session = SessionId::from_u64(3);

    let mut per_target = PendingTunDownlinks::with_limits(4, 64, 1);
    per_target.enqueue(first_target, first_session, 1, vec![1], now).unwrap();
    assert_eq!(
        per_target.enqueue(first_target, first_session, 1, vec![2], now),
        Err(PendingTunDownlinkReject::PerTarget)
    );

    let mut by_count = PendingTunDownlinks::with_limits(2, 64, 2);
    by_count.enqueue(first_target, first_session, 1, vec![1], now).unwrap();
    by_count.enqueue(second_target, second_session, 1, vec![2], now).unwrap();
    assert_eq!(
        by_count.enqueue(migrated_target, third_session, 1, vec![3], now),
        Err(PendingTunDownlinkReject::Queue)
    );

    let mut by_bytes = PendingTunDownlinks::with_limits(4, 3, 4);
    by_bytes.enqueue(first_target, first_session, 1, vec![1, 2, 3], now).unwrap();
    assert_eq!(
        by_bytes.enqueue(second_target, second_session, 1, vec![4], now),
        Err(PendingTunDownlinkReject::Bytes)
    );

    let mut queue = PendingTunDownlinks::with_limits(4, 64, 4);
    assert!(!queue.uses_shared_capacity());
    assert!(!queue.contains_session(first_session));
    queue.enqueue(first_target, first_session, 1, vec![10], now).unwrap();
    assert!(queue.contains_session(first_session));
    queue.enqueue(second_target, second_session, 1, vec![20], now).unwrap();
    queue.rebind_target(first_target, migrated_target);

    let first = queue.pop_next(&std::collections::HashSet::new()).unwrap();
    assert_eq!(first.target, migrated_target);
    assert_eq!(first.packet, vec![10]);
    assert!(!first.is_expired(now));
    queue.requeue_front(first, 1);

    let (discarded_packets, discarded_bytes) = queue.discard_target(second_target);
    assert_eq!((discarded_packets, discarded_bytes), (1, 1));
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.bytes(), 1);

    let expired = PendingTunDownlink {
        target: migrated_target,
        session_id: first_session,
        packet: vec![30],
        queued_at: now - MAX_PENDING_TUN_DOWNLINK_AGE,
        bandwidth_accounted: false,
    };
    assert!(expired.is_expired(now));

    let mut shaped = PendingTunDownlinks::with_limits_and_capacity(4, 64, 4, 1_000, 1_000);
    assert!(shaped.uses_shared_capacity());
    shaped.enqueue_with_accounting(first_target, first_session, 1, vec![40], now, true).unwrap();
    assert!(shaped.pop_next(&std::collections::HashSet::new()).unwrap().bandwidth_accounted);
}

#[test]
fn live_tun_fault_recording_is_first_wins_and_shutdown_safe() {
    let fault_slot = Arc::new(Mutex::new(None));
    let notify = Arc::new(tokio::sync::Notify::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let first = DataPlaneFault::TunWrite {
        component: "server MASQUE downlink".to_string(),
        error: "device closed".to_string(),
    };

    record_live_tun_fault(&fault_slot, &notify, &shutdown, first.clone());
    record_live_tun_fault(
        &fault_slot,
        &notify,
        &shutdown,
        DataPlaneFault::ChannelDisconnected { component: "server TUN reader channel".to_string() },
    );
    assert_eq!(fault_slot.lock().as_ref(), Some(&first));

    shutdown.store(true, Ordering::Release);
    record_live_tun_fault(
        &fault_slot,
        &notify,
        &shutdown,
        DataPlaneFault::TransportSend {
            component: "server UDP downlink".to_string(),
            error: "socket closed".to_string(),
        },
    );
    assert_eq!(fault_slot.lock().as_ref(), Some(&first));
}

#[test]
fn pending_tun_downlinks_drr_is_equal_without_starvation() {
    let now = Instant::now();
    let mut queue = PendingTunDownlinks::with_limits(300, 360_000, 100);
    for client in 1..=3u64 {
        let target: SocketAddr = format!("127.0.0.1:{}", 41_000 + client).parse().unwrap();
        for _ in 0..100 {
            queue
                .enqueue(target, SessionId::from_u64(client), 1, vec![client as u8; 1_200], now)
                .unwrap();
        }
    }

    let mut served = [0usize; 3];
    for _ in 0..30 {
        let entry = queue.pop_next(&std::collections::HashSet::new()).unwrap();
        served[entry.session_id.as_u64() as usize - 1] += 1;
    }
    assert_eq!(served, [10, 10, 10]);
}

#[test]
fn pending_tun_downlinks_drr_honors_one_two_one_weights() {
    let now = Instant::now();
    let mut queue = PendingTunDownlinks::with_limits(300, 360_000, 100);
    for (client, weight) in [(1u64, 1u16), (2, 2), (3, 1)] {
        let target: SocketAddr = format!("127.0.0.1:{}", 42_000 + client).parse().unwrap();
        for _ in 0..100 {
            queue
                .enqueue(
                    target,
                    SessionId::from_u64(client),
                    weight,
                    vec![client as u8; 1_200],
                    now,
                )
                .unwrap();
        }
    }

    let mut served = [0usize; 3];
    for _ in 0..40 {
        let entry = queue.pop_next(&std::collections::HashSet::new()).unwrap();
        served[entry.session_id.as_u64() as usize - 1] += 1;
    }
    assert_eq!(served, [10, 20, 10]);
}

#[test]
fn pending_tun_downlinks_skip_excluded_sessions_without_capacity_scaled_scans() {
    let now = Instant::now();
    let mut queue = PendingTunDownlinks::with_limits(256, 384 * 1024, 32);
    let mut excluded = std::collections::HashSet::new();
    for client in 1..=3u64 {
        let session_id = SessionId::from_u64(client);
        let target: SocketAddr = format!("127.0.0.1:{}", 43_000 + client).parse().unwrap();
        queue.enqueue(target, session_id, 1, vec![0; 1_280], now).unwrap();
        excluded.insert(session_id);
    }

    assert_eq!(queue.pop_visit_budget(&excluded), 0);
    assert!(queue.pop_next(&excluded).is_none());

    excluded.remove(&SessionId::from_u64(2));
    assert_eq!(queue.pop_visit_budget(&excluded), 12);
    assert_eq!(queue.pop_next(&excluded).unwrap().session_id, SessionId::from_u64(2));
}

#[test]
fn intentional_downlink_overload_is_rejected_and_exported_by_cause() {
    let first_target: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let second_target: SocketAddr = "127.0.0.1:41002".parse().unwrap();
    let now = Instant::now();
    let metrics = Metrics::new();
    let first_session = SessionId::from_u64(1);
    let second_session = SessionId::from_u64(2);

    let mut by_count = PendingTunDownlinks::with_limits(1, 64, 2);
    assert!(enqueue_pending_tun_downlink(
        &mut by_count,
        first_target,
        first_session,
        1,
        vec![1],
        now,
        &metrics,
    )
    .is_ok());
    assert_eq!(
        enqueue_pending_tun_downlink(
            &mut by_count,
            second_target,
            second_session,
            1,
            vec![2],
            now,
            &metrics,
        ),
        Err(PendingTunDownlinkReject::Queue)
    );
    assert_eq!((by_count.len(), by_count.bytes()), (1, 1));

    let mut by_bytes = PendingTunDownlinks::with_limits(4, 1, 4);
    assert!(enqueue_pending_tun_downlink(
        &mut by_bytes,
        first_target,
        first_session,
        1,
        vec![1],
        now,
        &metrics,
    )
    .is_ok());
    assert_eq!(
        enqueue_pending_tun_downlink(
            &mut by_bytes,
            second_target,
            second_session,
            1,
            vec![2],
            now,
            &metrics,
        ),
        Err(PendingTunDownlinkReject::Bytes)
    );
    assert_eq!((by_bytes.len(), by_bytes.bytes()), (1, 1));

    let mut per_target = PendingTunDownlinks::with_limits(4, 64, 1);
    assert!(enqueue_pending_tun_downlink(
        &mut per_target,
        first_target,
        first_session,
        1,
        vec![1],
        now,
        &metrics,
    )
    .is_ok());
    assert_eq!(
        enqueue_pending_tun_downlink(
            &mut per_target,
            first_target,
            first_session,
            1,
            vec![2],
            now,
            &metrics,
        ),
        Err(PendingTunDownlinkReject::PerTarget)
    );
    assert_eq!((per_target.len(), per_target.bytes()), (1, 1));

    let responses =
        Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueDownlinkQueue::new(1, 64)));
    enqueue_routing_response(&responses, &metrics, vec![3]);
    enqueue_routing_response(&responses, &metrics, vec![4]);

    let output = metrics.export();
    assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_packets 1"));
    assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_bytes 1"));
    assert!(
        output.contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 3")
    );
    for event in ["drop_queue_capacity", "drop_byte_capacity", "drop_per_target_capacity"] {
        assert!(output.contains(&format!(
            "quicfuscate_tun_downlink_backpressure_events_total{{event=\"{event}\"}} 1"
        )));
    }
    assert!(output.contains(
        "quicfuscate_masque_downlink_response_events_total{event=\"drop_packet_capacity\"} 1"
    ));
}

#[test]
fn client_fanout_queue_accepts_only_broadcast_and_multicast() {
    let queue = new_client_fanout_queue();
    let metrics = Metrics::new();
    let source = "127.0.0.1:4433".parse().unwrap();
    let packet = [0x45, 0, 0, 20];
    enqueue_client_fanout(
        &queue,
        &metrics,
        source,
        UplinkRoute::Broadcast {
            source: Ipv4Addr::new(10, 0, 1, 2),
            destination: Ipv4Addr::new(10, 0, 1, 255),
        },
        &packet,
    );
    enqueue_client_fanout(
        &queue,
        &metrics,
        source,
        UplinkRoute::Internet {
            source: Ipv4Addr::new(10, 0, 1, 2).into(),
            destination: Ipv4Addr::new(1, 1, 1, 1).into(),
        },
        &packet,
    );

    let mut queue = queue.lock().unwrap();
    assert_eq!(queue.len(), 1);
    let fanout = queue.pop_front().unwrap();
    assert_eq!(fanout.source, source);
    assert_eq!(fanout.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 255)));
    assert_eq!(fanout.packet, packet);
}

#[test]
fn client_fanout_queue_bounds_admission_and_preserves_accounting() {
    let queue = new_client_fanout_queue();
    let metrics = Metrics::new();
    let source = "127.0.0.1:4433".parse().unwrap();
    let packet = [0x45, 0, 0, 20];
    let route = || UplinkRoute::Broadcast {
        source: Ipv4Addr::new(10, 0, 1, 2),
        destination: Ipv4Addr::new(10, 0, 1, 255),
    };

    for _ in 0..MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE {
        enqueue_client_fanout(&queue, &metrics, source, route(), &packet);
    }
    enqueue_client_fanout(&queue, &metrics, source, route(), &packet);

    {
        let queue = queue.lock().unwrap();
        assert_eq!(queue.len(), MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE);
        assert_eq!(queue.bytes(), MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE * packet.len());
    }
    assert_eq!(metrics.client_fanout_dropped.load(Ordering::Relaxed), 1);

    {
        let mut queue = queue.lock().unwrap();
        assert!(queue.pop_front().is_some());
        assert_eq!(queue.len(), MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE - 1);
        assert_eq!(queue.bytes(), (MAX_CLIENT_FANOUT_ENTRIES_PER_SOURCE - 1) * packet.len());
    }
    enqueue_client_fanout(&queue, &metrics, source, route(), &packet);
    {
        let mut queue = queue.lock().unwrap();
        while queue.pop_front().is_some() {}
        assert!(queue.is_empty());
        assert_eq!(queue.bytes(), 0);
    }

    let mut byte_limited = ClientFanoutQueueState::with_limits(4, 5, 4, 5);
    assert!(byte_limited
        .enqueue(source, IpAddr::V4(Ipv4Addr::LOCALHOST), &[1, 2, 3, 4, 5])
        .is_ok());
    assert_eq!(
        byte_limited.enqueue(source, IpAddr::V4(Ipv4Addr::LOCALHOST), &[6]),
        Err(ClientFanoutReject::Bytes)
    );
    assert!(byte_limited.pop_front().is_some());
    assert_eq!(byte_limited.len(), 0);
    assert_eq!(byte_limited.bytes(), 0);

    let mut source_byte_limited = ClientFanoutQueueState::with_limits(4, 100, 4, 5);
    assert!(source_byte_limited
        .enqueue(source, IpAddr::V4(Ipv4Addr::LOCALHOST), &[1, 2, 3, 4, 5])
        .is_ok());
    assert_eq!(
        source_byte_limited.enqueue(source, IpAddr::V4(Ipv4Addr::LOCALHOST), &[6]),
        Err(ClientFanoutReject::PerSourceBytes)
    );
}

#[tokio::test]
async fn housekeeping_tick_drains_client_fanout_without_udp_input() {
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let accept_loop = AcceptLoop::new(AcceptConfig::default());
    let metrics = Metrics::new();
    let mut out = [0; 1460];
    let source = "127.0.0.1:4433".parse().unwrap();
    enqueue_client_fanout(
        &live_state.fanout_queue,
        &metrics,
        source,
        UplinkRoute::Broadcast {
            source: Ipv4Addr::new(10, 0, 1, 2),
            destination: Ipv4Addr::new(10, 0, 1, 255),
        },
        &[0x45, 0, 0, 20],
    );

    live_state
        .run_housekeeping_tick(&socket, &mut out, &metrics, &accept_loop)
        .await
        .expect("housekeeping should drain fan-out without UDP input");

    let queue = live_state.fanout_queue.lock().unwrap();
    assert!(queue.is_empty());
    assert_eq!(queue.bytes(), 0);
}

#[test]
fn authenticated_server_uplink_is_typed_as_local() {
    let server_ip = Ipv4Addr::new(10, 0, 1, 1);
    let client_ip = Ipv4Addr::new(10, 0, 1, 2);
    let forwarding_policy =
        ClientIsolationManager::with_network(server_ip, Ipv4Addr::new(255, 255, 255, 0), false);
    let assigned = AssignedClientIps { ipv4: client_ip, ipv6: None };
    forwarding_policy.assign_client("client", assigned);
    let metrics = Metrics::new();
    let responses =
        Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueDownlinkQueue::new(8, 4096)));
    let packet = test_ipv4_udp_packet(client_ip, server_ip, 40_000, 53, &[1]);

    let route = allow_client_uplink(
        &forwarding_policy,
        &metrics,
        Some(assigned),
        &packet,
        OsFingerprintProfile::Linux,
        ServerTunIps { ipv4: server_ip, ipv6: None },
        1280,
        &responses,
    );

    assert!(matches!(route, Some(UplinkRoute::Local { .. })));
    assert_eq!(metrics.routing_local.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.routing_internet.load(Ordering::Relaxed), 0);
}

#[test]
fn oversized_ipv4_packets_get_ptb_before_any_tun_write_for_both_df_states() {
    let server_ip = Ipv4Addr::new(10, 0, 1, 1);
    let client_ip = Ipv4Addr::new(10, 0, 1, 2);
    let destination_ip = Ipv4Addr::new(198, 51, 100, 2);
    let forwarding_policy =
        ClientIsolationManager::with_network(server_ip, Ipv4Addr::new(255, 255, 255, 0), false);
    let assigned = AssignedClientIps { ipv4: client_ip, ipv6: None };
    forwarding_policy.assign_client("client", assigned);
    let payload = vec![0xAB; 1_400];

    for dont_fragment in [false, true] {
        let metrics = Metrics::new();
        let responses =
            Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueDownlinkQueue::new(8, 4096)));
        let mut packet = test_ipv4_udp_packet(client_ip, destination_ip, 40_000, 53, &payload);
        if dont_fragment {
            packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        }
        assert_eq!(packet.len(), 1_428);

        let route = allow_client_uplink(
            &forwarding_policy,
            &metrics,
            Some(assigned),
            &packet,
            OsFingerprintProfile::Linux,
            ServerTunIps { ipv4: server_ip, ipv6: None },
            1_400,
            &responses,
        );

        assert!(route.is_none(), "DF={dont_fragment} must not reach a TUN write");
        assert_eq!(metrics.routing_internet.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.routing_packet_too_big.load(Ordering::Relaxed), 1);

        let response = responses
            .lock()
            .expect("response queue must not be poisoned")
            .pop_front()
            .expect("oversized IPv4 packet must enqueue PTB");
        assert_eq!(response.len(), 56);
        assert_eq!(response[0] >> 4, 4);
        assert_eq!(response[8], OsFingerprintProfile::Linux.ttl());
        assert_eq!(response[9], 1);
        assert_eq!(&response[12..16], &server_ip.octets());
        assert_eq!(&response[16..20], &client_ip.octets());
        assert_eq!(response[20], icmp::icmp_type::DESTINATION_UNREACHABLE);
        assert_eq!(response[21], icmp::icmp_code::FRAGMENTATION_NEEDED);
        assert_eq!(u16::from_be_bytes([response[26], response[27]]), 1_400);
        assert_eq!(&response[28..], &packet[..28]);
        assert_eq!(ones_complement_checksum(&response[..20]), 0);
        assert_eq!(ones_complement_checksum(&response[20..]), 0);
        assert!(responses.lock().expect("response queue must not be poisoned").is_empty());
    }
}

#[test]
fn expiring_ipv4_tunnel_ingress_is_routed_before_fingerprint_normalization() {
    let server_ip = Ipv4Addr::new(10, 0, 1, 1);
    let client_ip = Ipv4Addr::new(10, 0, 1, 2);
    let destination_ip = Ipv4Addr::new(198, 51, 100, 1);
    let forwarding_policy =
        ClientIsolationManager::with_network(server_ip, Ipv4Addr::new(255, 255, 255, 0), false);
    let assigned = AssignedClientIps { ipv4: client_ip, ipv6: None };
    forwarding_policy.assign_client("client", assigned);
    let mut packet = test_ipv4_udp_packet(client_ip, destination_ip, 40_000, 33434, &[1]);
    packet[8] = 1;
    packet[10..12].fill(0);
    let checksum = ones_complement_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let original = packet.clone();
    let normalizer =
        crate::stealth::fingerprint::PacketNormalizer::new(OsFingerprintProfile::Windows);

    assert_eq!(
        normalizer.normalize_tunnel_ingress_vec(&mut packet),
        crate::stealth::fingerprint::NormalizeResult::Passthrough
    );
    let metrics = Metrics::new();
    let responses =
        Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueDownlinkQueue::new(8, 4096)));
    let route = allow_client_uplink(
        &forwarding_policy,
        &metrics,
        Some(assigned),
        &packet,
        OsFingerprintProfile::Windows,
        ServerTunIps { ipv4: server_ip, ipv6: None },
        1280,
        &responses,
    );

    assert!(route.is_none());
    assert_eq!(metrics.routing_time_exceeded.load(Ordering::Relaxed), 1);
    let response = responses
        .lock()
        .expect("response queue must not be poisoned")
        .pop_front()
        .expect("expired IPv4 packet must enqueue Time Exceeded");
    assert_eq!(response[8], OsFingerprintProfile::Windows.ttl());
    assert_eq!(response[20], icmp::icmp_type::TIME_EXCEEDED);
    assert_eq!(response[21], 0);
    assert_eq!(&response[28..], &original[..28]);
}
