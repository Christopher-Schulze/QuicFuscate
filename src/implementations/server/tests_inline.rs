use super::*;
use std::io::Write as _;

fn begin_test_auth_attempt(
    live_state: &LiveServerState,
    ip: IpAddr,
) -> crate::implementations::server::limits::AuthAttempt {
    let mut limiter =
        live_state.auth_rate_limiter.lock().unwrap_or_else(|error| error.into_inner());
    match limiter.begin(ip) {
        crate::implementations::server::limits::AuthAdmission::Allowed(attempt) => attempt,
        other => panic!("test auth attempt was not admitted: {other:?}"),
    }
}

#[cfg(feature = "rate_limiter")]
fn admission_allowed(domain: &LiveServerDomain, remote_addr: SocketAddr, packet: &[u8]) -> bool {
    let metrics = Metrics::new();
    matches!(
        domain.admit_incoming_datagram(remote_addr, packet, true, true, &metrics),
        crate::implementations::server::ddos::IncomingDatagramAdmission::Allow
    )
}

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

#[test]
fn test_server_config_default() {
    let config = ServerConfig::default();
    assert_eq!(config.max_clients, 100);
    assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
    // IPv6 defaults
    assert!(config.ipv6_server_ip.is_some());
    assert_eq!(config.ipv6_server_ip.unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
    assert_eq!(config.ipv6_prefix_len, 64);
    assert_eq!(
        config.revocation_retention_secs,
        crate::implementations::server::revocation::DEFAULT_REVOCATION_RETENTION_SECS
    );
    assert!(config.validate_revocation_retention().is_ok());
    let invalid = ServerConfig { revocation_retention_secs: 0, ..config };
    assert!(invalid.validate_revocation_retention().is_err());
}

#[test]
fn test_parse_ipv6_dest_valid() {
    // Construct a minimal IPv6 packet header (40 bytes)
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60; // version 6
                   // Destination at offset 24-39: fd00::1
    pkt[24] = 0xfd;
    pkt[39] = 0x01;
    let dest = parse_ipv6_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
}

#[test]
fn test_parse_ipv6_dest_too_short() {
    let pkt = vec![0u8; 30];
    assert!(parse_ipv6_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv6_dest_wrong_version() {
    let mut pkt = [0u8; 40];
    pkt[0] = 0x45; // IPv4
    assert!(parse_ipv6_dest(&pkt).is_none());
}

#[test]
fn test_parse_ip_dest_dispatches_v4_and_v6() {
    // IPv4 packet
    let mut pkt4 = [0u8; 20];
    pkt4[0] = 0x45;
    pkt4[16] = 10;
    pkt4[17] = 8;
    pkt4[18] = 0;
    pkt4[19] = 2;
    match parse_ip_dest(&pkt4) {
        Some(std::net::IpAddr::V4(v4)) => assert_eq!(v4, Ipv4Addr::new(10, 8, 0, 2)),
        other => panic!("expected V4, got {:?}", other),
    }

    // IPv6 packet
    let mut pkt6 = [0u8; 40];
    pkt6[0] = 0x60;
    pkt6[24] = 0xfd;
    pkt6[39] = 0x01;
    match parse_ip_dest(&pkt6) {
        Some(std::net::IpAddr::V6(v6)) => {
            assert_eq!(v6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001))
        }
        other => panic!("expected V6, got {:?}", other),
    }
}

fn test_dns_query_payload() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&0x1234u16.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    for label in ["example", "com"] {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt
}

fn test_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    let udp_checksum = ipv4_udp_checksum(src_ip, dst_ip, &pkt[20..]);
    pkt[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    pkt
}

fn test_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut pkt = vec![0u8; 40 + udp_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());
    pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
    pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[48..].copy_from_slice(payload);
    let udp_checksum = ipv6_udp_checksum(src_ip, dst_ip, &pkt[40..]);
    pkt[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    pkt
}

fn refresh_ipv4_header_checksum(pkt: &mut [u8]) {
    pkt[10..12].fill(0);
    let checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
}

#[test]
fn test_parse_ipv4_udp_dns_query_detects_port_53_payload() {
    let payload = test_dns_query_payload();
    let pkt = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );
    let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
    assert_eq!(query.src_ip, Ipv4Addr::new(10, 8, 0, 2));
    assert_eq!(query.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(query.src_port, 53000);
    assert_eq!(query.dst_port, 53);
    assert_eq!(query.payload, payload.as_slice());
}

#[test]
fn test_parse_ipv6_udp_dns_query_detects_port_53_payload() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
    let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
    assert_eq!(query.src_ip, src_ip);
    assert_eq!(query.dst_ip, dst_ip);
    assert_eq!(query.src_port, 53000);
    assert_eq!(query.dst_port, 53);
    assert_eq!(query.payload, payload.as_slice());
}

#[test]
fn test_parse_ipv4_udp_dns_query_rejects_fragment_length_trailing_and_checksum_errors() {
    let payload = test_dns_query_payload();
    let base = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );

    let mut fragmented = base.clone();
    fragmented[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    refresh_ipv4_header_checksum(&mut fragmented);
    assert!(parse_ipv4_udp_dns_query(&fragmented).is_none());

    let mut offset_fragment = base.clone();
    offset_fragment[6..8].copy_from_slice(&1u16.to_be_bytes());
    refresh_ipv4_header_checksum(&mut offset_fragment);
    assert!(parse_ipv4_udp_dns_query(&offset_fragment).is_none());

    let mut bad_ip_checksum = base.clone();
    bad_ip_checksum[10] ^= 0x01;
    assert!(parse_ipv4_udp_dns_query(&bad_ip_checksum).is_none());

    let mut bad_udp_checksum = base.clone();
    bad_udp_checksum[26] ^= 0x01;
    assert!(parse_ipv4_udp_dns_query(&bad_udp_checksum).is_none());

    let mut bad_udp_length = base.clone();
    bad_udp_length[24..26].copy_from_slice(&((8 + payload.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv4_udp_dns_query(&bad_udp_length).is_none());

    let mut bad_total_length = base.clone();
    bad_total_length[2..4].copy_from_slice(&((base.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv4_udp_dns_query(&bad_total_length).is_none());

    let mut trailing = base.clone();
    trailing.push(0);
    assert!(parse_ipv4_udp_dns_query(&trailing).is_none());

    let mut omitted_udp_checksum = base;
    omitted_udp_checksum[26..28].fill(0);
    assert!(parse_ipv4_udp_dns_query(&omitted_udp_checksum).is_some());
}

#[test]
fn test_parse_ipv6_udp_dns_query_rejects_length_and_checksum_errors() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let base = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);

    let mut bad_checksum = base.clone();
    bad_checksum[46] ^= 0x01;
    assert!(parse_ipv6_udp_dns_query(&bad_checksum).is_none());

    let mut zero_checksum = base.clone();
    zero_checksum[46..48].fill(0);
    assert!(parse_ipv6_udp_dns_query(&zero_checksum).is_none());

    let mut bad_udp_length = base.clone();
    bad_udp_length[44..46].copy_from_slice(&((8 + payload.len() - 1) as u16).to_be_bytes());
    assert!(parse_ipv6_udp_dns_query(&bad_udp_length).is_none());

    let mut trailing = base.clone();
    trailing.push(0);
    assert!(parse_ipv6_udp_dns_query(&trailing).is_none());
}

#[test]
fn test_build_ipv4_udp_dns_response_packet_swaps_tuple() {
    let payload = test_dns_query_payload();
    let pkt = test_ipv4_udp_packet(
        Ipv4Addr::new(10, 8, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        53000,
        53,
        &payload,
    );
    let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
    let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
    let dns_response = crate::dns::build_dns_nxdomain(&parsed);
    let response =
        build_ipv4_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
            .expect("DNS response packet must build");
    assert_eq!(parse_ipv4_dest(&response), Some(Ipv4Addr::new(10, 8, 0, 2)));
    assert_eq!(
        Ipv4Addr::new(response[12], response[13], response[14], response[15]),
        Ipv4Addr::new(1, 1, 1, 1)
    );
    assert_eq!(u16::from_be_bytes([response[20], response[21]]), 53);
    assert_eq!(u16::from_be_bytes([response[22], response[23]]), 53000);
    assert_eq!(ones_complement_checksum_raw(&response[..20]), 0);
    assert!(ipv4_udp_checksum_is_valid(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(10, 8, 0, 2),
        &response[20..]
    ));
    assert_eq!(&response[28..], dns_response.as_slice());
}

#[test]
fn test_build_ipv6_udp_dns_response_packet_swaps_tuple() {
    let payload = test_dns_query_payload();
    let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
    let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
    let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
    let dns_response = crate::dns::build_dns_nxdomain(&parsed);
    let response =
        build_ipv6_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
            .expect("IPv6 DNS response packet must build");
    assert_eq!(parse_ipv6_dest(&response), Some(src_ip));
    assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap()), dst_ip);
    assert_eq!(u16::from_be_bytes([response[40], response[41]]), 53);
    assert_eq!(u16::from_be_bytes([response[42], response[43]]), 53000);
    assert!(ipv6_udp_checksum_is_valid(dst_ip, src_ip, &response[40..]));
    assert_eq!(&response[48..], dns_response.as_slice());
}

#[test]
fn test_server_dns_upstream_failure_returns_servfail() {
    let payload = test_dns_query_payload();
    let response = resolve_dns_query_via_upstream(&payload, &[]);
    assert!(!response.is_empty(), "server failure must remain a DNS response");
    assert_eq!(response[3] & 0x0f, 2, "upstream failure must be SERVFAIL");
    let parsed = crate::dns::parse_dns_query(&payload).expect("query must parse");
    let mut pos = 12;
    loop {
        let label_len = response[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        pos += label_len;
    }
    assert_eq!(u16::from_be_bytes([response[pos], response[pos + 1]]), parsed.raw_qtype);
}

#[test]
fn test_server_dns_genuine_nxdomain_passes_through_unchanged() {
    let payload = test_dns_query_payload();
    let parsed = crate::dns::parse_dns_query(&payload).expect("query must parse");
    let genuine_nxdomain = crate::dns::build_dns_nxdomain(&parsed);
    let response = response_from_dns_upstream_result(&payload, Ok(genuine_nxdomain.clone()));

    assert_eq!(response, genuine_nxdomain);
    assert_eq!(response[3] & 0x0f, 3, "genuine upstream NXDOMAIN must remain NXDOMAIN");
}

#[test]
fn test_parse_ipv4_dest_valid() {
    // Construct a minimal IPv4 packet with dest 10.8.0.2
    let mut pkt = [0u8; 20];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[16] = 10;
    pkt[17] = 8;
    pkt[18] = 0;
    pkt[19] = 2;
    let dest = parse_ipv4_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv4Addr::new(10, 8, 0, 2));
}

#[test]
fn test_parse_ipv4_dest_too_short() {
    let pkt = [0u8; 10];
    assert!(parse_ipv4_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv4_dest_not_ipv4() {
    // IPv6 packet (version 6)
    let mut pkt = [0u8; 40];
    pkt[0] = 0x60; // version 6
    assert!(parse_ipv4_dest(&pkt).is_none());
}

#[test]
fn test_parse_ipv4_dest_with_options() {
    // IPv4 packet with IHL=6 (24 bytes header)
    let mut pkt = [0u8; 24];
    pkt[0] = 0x46; // version 4, IHL 6
    pkt[16] = 192;
    pkt[17] = 168;
    pkt[18] = 1;
    pkt[19] = 100;
    let dest = parse_ipv4_dest(&pkt).unwrap();
    assert_eq!(dest, Ipv4Addr::new(192, 168, 1, 100));
}

#[test]
fn test_parse_ipv4_dest_invalid_ihl() {
    let mut pkt = [0u8; 20];
    pkt[0] = 0x40; // IHL=0, invalid
    assert!(parse_ipv4_dest(&pkt).is_none());
}

#[test]
fn test_server_runtime_new() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config);
    assert!(runtime.is_ok());
}

#[test]
fn server_runtime_accepts_matching_embedded_tun_override() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)));
    engine_config.interface.tun_netmask = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));
    engine_config.interface.tun_ip6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    engine_config.interface.tun_prefix6 = Some(64);

    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config.clone())
        .expect("matching embedded server TUN override must be accepted");
    let tun_config = server_config.server_tun_config(Some("qfserver0".to_string()), 1500, true);
    assert_eq!(tun_config.ip, Some(IpAddr::V4(server_config.server_ip)));
    assert_eq!(tun_config.netmask, Some(IpAddr::V4(server_config.server_netmask)));
    assert_eq!(tun_config.ip6, server_config.ipv6_server_ip);
    assert_eq!(tun_config.prefix6, Some(server_config.ipv6_prefix_len));

    let (_, _, assigned) = runtime
        .domain
        .accept("127.0.0.1:54323".parse().unwrap())
        .expect("default client pool must allocate on the effective network");
    assert_eq!(assigned.ipv4, server_config.ip_pool_start);
    assert_eq!(assigned.ipv6, server_config.ipv6_pool_start);
}

#[test]
fn server_runtime_rejects_conflicting_embedded_tun_override_before_start() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)));
    engine_config.interface.tun_netmask = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));

    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("conflicting embedded server TUN override must fail closed"),
        Err(error) => error,
    };
    match error {
        EngineError::Config(message) => {
            assert!(message.contains("server TUN IPv4 conflict"));
            assert!(message.contains("ServerConfig is authoritative"));
        }
        other => panic!("unexpected error for conflicting embedded TUN: {other:?}"),
    }
}

#[test]
fn server_runtime_rejects_conflicting_embedded_ipv6_tun_override_before_start() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1));
    engine_config.interface.tun_prefix6 = Some(64);

    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("conflicting embedded IPv6 TUN override must fail closed"),
        Err(error) => error,
    };
    assert!(
        matches!(error, EngineError::Config(message) if message.contains("server TUN IPv6 conflict"))
    );
}

#[test]
fn standalone_tun_config_is_reconciled_to_server_network() {
    let server_config = ServerConfig::default();
    let tun_config = server_config
        .reconcile_standalone_tun_config(TunConfig {
            name: Some("qfserver0".to_string()),
            ip: Some(IpAddr::V4(server_config.server_ip)),
            netmask: Some(IpAddr::V4(server_config.server_netmask)),
            mtu: 1500,
            ip6: server_config.ipv6_server_ip,
            prefix6: server_config.ipv6_server_ip.map(|_| server_config.ipv6_prefix_len),
            ..TunConfig::default()
        })
        .expect("standalone TUN config without address overrides must inherit ServerConfig");
    assert_eq!(tun_config.ip, Some(IpAddr::V4(server_config.server_ip)));
    assert_eq!(tun_config.netmask, Some(IpAddr::V4(server_config.server_netmask)));
    assert_eq!(tun_config.ip6, server_config.ipv6_server_ip);
    assert_eq!(tun_config.prefix6, Some(server_config.ipv6_prefix_len));
}

#[test]
fn standalone_lifecycle_rejects_conflicting_tun_config_before_open() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let error = match ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        Some(TunConfig {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            ..TunConfig::default()
        }),
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    ) {
        Ok(_) => panic!("conflicting standalone TUN override must fail before opening TUN"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("standalone server TUN IPv4 conflict"));
}

#[test]
fn server_runtime_rejects_ipv4_pool_outside_effective_tun_network() {
    let server_config = ServerConfig {
        ip_pool_start: Ipv4Addr::new(10, 9, 0, 2),
        ip_pool_end: Ipv4Addr::new(10, 9, 0, 254),
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("client pool outside the server TUN network must fail closed"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected pool validation error: {other:?}"),
    };
    assert!(error.contains("IPv4 client pool"));
    assert!(error.contains("outside server network"));
}

#[test]
fn server_runtime_rejects_ipv6_pool_outside_effective_tun_network() {
    let server_config = ServerConfig {
        ipv6_pool_start: Some("fd01::2".parse().unwrap()),
        ipv6_pool_end: Some("fd01::fe".parse().unwrap()),
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("IPv6 client pool outside the server TUN network must fail closed"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected IPv6 pool validation error: {other:?}"),
    };
    assert!(error.contains("IPv6 client pool"));
    assert!(error.contains("outside server network"));
}

#[test]
fn test_server_runtime_rejects_invalid_engine_projection() {
    let mut engine_config = EngineConfig::default();
    engine_config.stealth.padding_strategy = "invalid".to_string();
    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("invalid stealth must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, EngineError::Config(_)));
}

#[test]
fn test_server_runtime_traffic_snapshot_aggregates_session_stats() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
    let session_id = runtime.accept_client("127.0.0.1:54321".parse().unwrap()).unwrap();
    assert!(runtime.domain.sessions.read().bandwidth_stats(session_id).is_some());
    let stats = runtime.session_stats(session_id).unwrap();
    stats.record_received(120);
    stats.record_sent(64);
    stats.record_sent(32);

    let snapshot = runtime.traffic_snapshot();
    assert_eq!(snapshot.active_connections, 1);
    assert_eq!(snapshot.total_connections, 1);
    assert_eq!(snapshot.bytes_in, 120);
    assert_eq!(snapshot.bytes_out, 96);
    assert_eq!(snapshot.packets_in, 1);
    assert_eq!(snapshot.packets_out, 2);
}

#[test]
fn test_server_runtime_reaps_expired_sessions() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
    let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
    runtime.accept_client("127.0.0.1:54322".parse().unwrap()).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(runtime.session_count(), 1);
    assert_eq!(runtime.reap_expired_sessions(), 1);
    assert_eq!(runtime.session_count(), 0);
}

#[test]
fn test_live_server_domain_resolves_session_identity_to_remote_addr() {
    let remote_addr = "127.0.0.1:54322".parse().unwrap();
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let (session_id, _, _) = domain.accept(remote_addr).unwrap();

    assert!(domain.shared.sessions.read().bandwidth_stats(session_id).is_none());
    assert_eq!(
        domain.remote_addr_for_identity(&ClientIdentity::Session(session_id)),
        Some(remote_addr)
    );
    assert_eq!(domain.session_id_by_remote(remote_addr), Some(session_id));
}

#[test]
fn test_live_state_kick_client_accepts_canonical_session_identity() {
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
    let accept_loop = AcceptLoop::new(AcceptConfig::default());
    let metrics = Metrics::new();
    let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
    let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
    let mut transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let connection = create_live_server_connection(
        local_addr,
        remote_addr,
        &mut transport,
        StealthConfig::default(),
        FecConfig::default(),
        OptimizeConfig::default(),
        &crate::transport::ConnectionId::from_ref(b"admin-kick-sess-id"),
    )
    .expect("live server connection must be creatable");

    live_state.clients.insert(remote_addr, connection);
    live_state.kick_client(&ClientIdentity::Session(session_id), &accept_loop, &metrics);

    assert!(!live_state.clients.contains_key(&remote_addr));
    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
    assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_live_server_domain_remove_remote_clears_packet_rate_limit_ip_state() {
    let remote_addr = "127.0.0.1:54323".parse().unwrap();
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let _ = domain.accept(remote_addr).unwrap();
    *domain.shared.packet_rate_limiter.lock() = PacketRateLimiterDomain {
        limiter: RateLimiter::new(crate::implementations::server::limits::RateLimitConfig {
            max_pps: 1,
            max_bps: 0,
            refill_interval: Duration::from_secs(60),
            burst_size: 1,
        }),
        last_prune: Instant::now(),
        last_sample: Instant::now(),
    };

    let packet = [0u8; 64];
    assert!(admission_allowed(&domain, remote_addr, &packet));
    assert!(!admission_allowed(&domain, remote_addr, &packet));

    domain.remove_remote(remote_addr);

    assert!(admission_allowed(&domain, remote_addr, &packet));
}

#[tokio::test]
async fn test_housekeeping_tick_reaps_expired_sessions_from_runtime_lifecycle() {
    let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
    let mut live_state = LiveServerState::try_new(server_config)
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
    let remote_addr = "127.0.0.1:54324".parse().unwrap();
    let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let accept_loop = AcceptLoop::new(AcceptConfig::default());
    let metrics = Metrics::new();
    let mut out = [0; 1460];

    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), Some(session_id));
    tokio::time::sleep(Duration::from_secs(2)).await;

    live_state
        .run_housekeeping_tick(&socket, &mut out, &metrics, &accept_loop)
        .await
        .expect("housekeeping should not fail with no active clients");

    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
    assert_eq!(live_state.domain.active_session_count(), 0);
    assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
}

#[test]
fn test_live_udp_datagram_buffer_serializes_full_1500_byte_fec_envelope() {
    let profile = crate::fec::wire::WireProfile {
        epoch: 1,
        codec: crate::fec::wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 6,
        interleave_depth: 1,
    };
    let metadata = crate::fec::wire::WirePacketMeta {
        profile,
        window: 0,
        sequence: 0,
        repair_index: crate::fec::wire::SYSTEMATIC_REPAIR_INDEX,
        block_index: 0,
        systematic: true,
    };
    let payload = vec![0u8; 1500 - crate::fec::wire::HEADER_LEN];
    let mut output = vec![0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];

    let written = crate::fec::wire::write_packet(metadata, &payload, &mut output)
        .expect("1500-byte FEC envelope must fit the live server UDP buffer");

    assert_eq!(written, 1500);
}

#[tokio::test]
async fn test_standalone_runtime_shutdown_trips_registered_service_signals() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();
    let admin = Arc::new(AtomicBool::new(false));
    let admin_web = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(AtomicBool::new(false));

    runtime.register_admin_shutdown(admin.clone());
    runtime.register_admin_web_shutdown(admin_web.clone());
    runtime.register_metrics_shutdown(metrics.clone());
    runtime.shutdown_live(b"test_shutdown");

    assert!(admin.load(Ordering::SeqCst));
    assert!(admin_web.load(Ordering::SeqCst));
    assert!(metrics.load(Ordering::SeqCst));
}

/// Direct `stop()` must signal every auxiliary service, not only the drain paths.
///
/// The async drain and live-shutdown paths already called `shutdown_all()`, but direct stop
/// did not, so admin, web, and metrics listeners could stay alive holding their ports and
/// serving stale state while the runtime published Stopped.
#[tokio::test]
async fn direct_stop_signals_every_registered_service_and_is_idempotent() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();

    let admin = Arc::new(AtomicBool::new(false));
    let admin_web = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(AtomicBool::new(false));
    runtime.register_admin_shutdown(admin.clone());
    runtime.register_admin_web_shutdown(admin_web.clone());
    runtime.register_metrics_shutdown(metrics.clone());

    runtime.stop().expect("direct stop");

    assert!(admin.load(Ordering::SeqCst), "direct stop must signal the admin service");
    assert!(admin_web.load(Ordering::SeqCst), "direct stop must signal the web service");
    assert!(metrics.load(Ordering::SeqCst), "direct stop must signal the metrics service");

    // A service registered after the first stop must still be signalled by a repeated stop,
    // and the repeat itself must stay successful.
    let late = Arc::new(AtomicBool::new(false));
    runtime.register_admin_shutdown(late.clone());
    runtime.stop().expect("repeated stop stays successful");
    assert!(late.load(Ordering::SeqCst), "a repeated stop must not skip signalling");
}

#[tokio::test]
async fn test_standalone_runtime_drain_rejects_new_clients_and_reports_lifecycle() {
    let engine_config = EngineConfig {
        engine: qf_engine_types::EngineSection {
            shutdown_timeout_ms: 250,
            ..qf_engine_types::EngineSection::default()
        },
        ..EngineConfig::default()
    };
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        engine_config,
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();

    runtime.start().unwrap();
    assert!(runtime.initiate_drain(b"test_drain"));
    assert!(!runtime.initiate_drain(b"duplicate_drain"));
    assert_eq!(runtime.state(), ServerState::Draining);
    assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Draining);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(250));
    assert!(runtime.live().accept_loop.is_shutdown());
    assert_eq!(
        runtime.live().accept_loop.should_accept(
            "127.0.0.1:54321".parse().unwrap(),
            0,
            runtime.live().accept_max_clients,
        ),
        AcceptDecision::Reject(RejectReason::Shutdown)
    );
    let status = runtime.graceful_shutdown.status_json(3);
    assert_eq!(status["state"], "draining");
    assert_eq!(status["active_connections"], 3);
    assert_eq!(status["grace_period_ms"], 250);

    runtime.stop().unwrap();
    assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Stopped);
}

#[tokio::test]
async fn test_runtime_reload_updates_shutdown_grace_without_stopping_server() {
    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let config_path = std::env::temp_dir().join(format!(
        "quicfuscate-reload-grace-{}-{}.toml",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut config_file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
    config_file.write_all(b"[engine]\nshutdown_timeout_ms = 175\n").unwrap();
    drop(config_file);

    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();
    let transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let mut runtime_config = PreparedStandaloneRuntimeConfig::new(
        Some(config_path.clone()),
        transport,
        FecConfig::default(),
        OptimizeConfig::default(),
        StealthConfig::default(),
        None,
        vec![FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Linux)],
        0,
        OwnedRuntimeStealthPolicy::from_runtime_policy(RuntimeStealthPolicy {
            profile: BrowserProfile::Chrome,
            os: OsProfile::Linux,
            disable_doh: true,
            doh_provider: "",
            disable_fronting: true,
            front_domain: &[],
            disable_http3: true,
        }),
        false,
    );
    runtime.sync_standalone_runtime_metadata(&runtime_config.standalone_runtime_metadata);
    runtime.start().unwrap();

    runtime.reload_standalone_runtime(&mut runtime_config, "test");

    assert_eq!(runtime.state(), ServerState::Running);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(175));
    assert_eq!(runtime_config.runtime_policy_generation.current(), 2);
    runtime.stop().unwrap();
    std::fs::remove_file(config_path).unwrap();
}

#[tokio::test]
async fn test_runtime_reload_rejects_startup_owned_memory_settings() {
    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let config_path = std::env::temp_dir().join(format!(
        "quicfuscate-reload-memory-lock-{}-{}.toml",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut config_file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
    config_file.write_all(b"[security]\nlock_memory = false\nlock_blocks = false\n").unwrap();
    drop(config_file);

    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();
    let transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let mut runtime_config = PreparedStandaloneRuntimeConfig::new(
        Some(config_path.clone()),
        transport,
        FecConfig::default(),
        OptimizeConfig::default(),
        StealthConfig::default(),
        None,
        vec![FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Linux)],
        0,
        OwnedRuntimeStealthPolicy::from_runtime_policy(RuntimeStealthPolicy {
            profile: BrowserProfile::Chrome,
            os: OsProfile::Linux,
            disable_doh: true,
            doh_provider: "",
            disable_fronting: true,
            front_domain: &[],
            disable_http3: true,
        }),
        false,
    );
    runtime.sync_standalone_runtime_metadata(&runtime_config.standalone_runtime_metadata);
    runtime.start().unwrap();

    runtime.reload_standalone_runtime(&mut runtime_config, "test");

    assert_eq!(runtime.state(), ServerState::Running);
    assert!(runtime.engine_config.security.lock_memory);
    assert!(runtime.engine_config.security.lock_blocks);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_secs(5));
    runtime.stop().unwrap();
    std::fs::remove_file(config_path).unwrap();
}

#[test]
fn test_server_config_from_listen_addr_resolves_socket() {
    let config = server_config_from_listen_addr(
        "127.0.0.1:4433",
        crate::firewall::FirewallBackend::Iptables,
    )
    .unwrap();
    assert_eq!(config.listen, "127.0.0.1:4433".parse().unwrap());
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_server_config_carries_geoip_and_blacklist_defaults() {
    // Default config should have GeoIP disabled and no blacklist sync URL.
    let config = ServerConfig::default();
    assert!(!config.geoip.is_enabled(), "default geoip should be disabled");
    assert!(config.blacklist.sync_url.is_none(), "default blacklist should have no sync URL");
}

#[cfg(feature = "rate_limiter")]
#[test]
fn blacklist_config_rejects_values_above_absolute_resource_caps() {
    use crate::implementations::server::limits;

    let config = BlacklistConfig {
        default_ttl_secs: limits::MAX_BLACKLIST_TTL_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        sync_interval_secs: limits::MAX_BLACKLIST_SYNC_INTERVAL_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        max_body_bytes: limits::MAX_BLACKLIST_BODY_BYTES + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        max_entries: limits::MAX_BLACKLIST_ENTRIES + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        request_timeout_secs: limits::MAX_BLACKLIST_REQUEST_TIMEOUT_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_shared_server_domain_uses_configured_blacklist() {
    // When ServerConfig has a blacklist sync URL, SharedServerDomain
    // should construct a BlacklistSync with that URL (has_sync_url=true).
    let config = ServerConfig {
        #[cfg(feature = "rate_limiter")]
        blacklist: BlacklistConfig {
            default_ttl_secs: 60,
            sync_url: Some("https://example.com/blocklist".to_string()),
            sync_interval_secs: 300,
            cache_path: None,
            ..BlacklistConfig::default()
        },
        ..ServerConfig::default()
    };
    let domain = SharedServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("shared server domain construction failed: {error}"));
    assert!(domain.blacklist.has_sync_url());
    assert_eq!(domain.blacklist.sync_interval(), Duration::from_secs(300));
}

#[cfg(feature = "rate_limiter")]
#[tokio::test]
async fn blacklist_worker_owner_claims_once_and_cancels_on_stop() {
    let metrics = Metrics::new();
    metrics.configure_blacklist_sync(true, Duration::from_secs(60));
    let owner = BlacklistSyncOwner::new();
    let blacklist = Arc::new(BlacklistSync::manual_only(Duration::from_secs(60)));

    assert_eq!(
        owner.claim_and_spawn(Arc::clone(&blacklist), Duration::from_secs(60)),
        BlacklistSyncClaim::Claimed
    );
    assert_eq!(
        owner.claim_and_spawn(blacklist, Duration::from_secs(60)),
        BlacklistSyncClaim::InFlight
    );
    owner.abandon(&metrics);

    assert!(!owner.has_task());
    assert_eq!(metrics.blacklist_sync_cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_in_flight.load(Ordering::Acquire), 0);

    let completing_owner = BlacklistSyncOwner::new();
    let completing_blacklist = Arc::new(BlacklistSync::manual_only(Duration::from_secs(60)));
    assert_eq!(
        completing_owner.claim_and_spawn(completing_blacklist, Duration::from_secs(60)),
        BlacklistSyncClaim::Claimed
    );
    tokio::task::yield_now().await;
    completing_owner.observe_finished(&metrics).await;
    assert_eq!(metrics.blacklist_sync_failed.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_retry_scheduled.load(Ordering::Relaxed), 1);
    assert_eq!(
        completing_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::NotDue
    );
    assert!(!completing_owner.has_task());

    let shutdown_owner = BlacklistSyncOwner::new();
    assert_eq!(
        shutdown_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::Claimed
    );
    shutdown_owner.shutdown(&metrics).await;
    assert!(!shutdown_owner.has_task());
    assert_eq!(
        shutdown_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::Closed
    );
}

#[cfg(feature = "rate_limiter")]
#[tokio::test]
async fn blacklist_shutdown_retains_owned_publication_past_deadline() {
    let owner = Arc::new(BlacklistSyncOwner::new());
    let metrics = Arc::new(Metrics::new());
    metrics.configure_blacklist_sync(true, Duration::from_secs(60));
    let control = Arc::new(crate::implementations::server::limits::BlacklistSyncControl::new());
    assert!(control.begin_publication());
    let release = Arc::new(tokio::sync::Notify::new());
    let release_for_task = Arc::clone(&release);
    let control_for_task = Arc::clone(&control);
    let handle = tokio::spawn(async move {
        release_for_task.notified().await;
        control_for_task.finish();
        Err(crate::implementations::server::limits::BlacklistError::Cancelled)
    });
    owner.state.lock().task = Some(BlacklistSyncTask { handle, control });

    let owner_for_shutdown = Arc::clone(&owner);
    let metrics_for_shutdown = Arc::clone(&metrics);
    let shutdown = tokio::spawn(async move {
        owner_for_shutdown.shutdown(&metrics_for_shutdown).await;
    });
    tokio::time::sleep(BLACKLIST_SYNC_SHUTDOWN_TIMEOUT + Duration::from_millis(25)).await;

    assert!(!shutdown.is_finished(), "publication task was detached at the deadline");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("owned publication shutdown timed out")
        .expect("owned publication shutdown task panicked");
    assert!(!owner.has_task());
    assert_eq!(metrics.blacklist_sync_cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_shutdown_expired.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_shared_server_domain_uses_configured_geoip() {
    use crate::implementations::server::limits::GeoIpConfig;
    use std::collections::HashSet;
    use std::path::PathBuf;

    let mut countries = HashSet::new();
    countries.insert("XX".to_string());
    let config = ServerConfig {
        #[cfg(feature = "rate_limiter")]
        geoip: GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: countries,
        },
        ..ServerConfig::default()
    };
    let error = match SharedServerDomain::try_new(&config) {
        Ok(_) => panic!("missing GeoIP database must fail domain construction"),
        Err(error) => error,
    };
    assert!(error.contains("GeoIP activation failed"));
    assert!(error.contains("missing"));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn server_runtime_rejects_invalid_geoip_before_live_resources() {
    use crate::implementations::server::limits::GeoIpConfig;
    use std::collections::HashSet;
    use std::path::PathBuf;

    let server_config = ServerConfig {
        geoip: GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: ["GB".to_string()].into_iter().collect::<HashSet<_>>(),
        },
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("configured missing GeoIP database must reject runtime startup"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected GeoIP startup error: {other:?}"),
    };
    assert!(error.contains("GeoIP activation failed"));
    assert!(error.contains("missing"));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn sustained_admission_retries_new_initials_and_preserves_established_traffic() {
    use crate::implementations::server::ddos::{DdosDropReason, IncomingDatagramAdmission};
    use crate::implementations::server::limits::DdosPolicyConfig;
    use crate::transport::packet::{format_header, parse_header, verify_retry_tag, Header};

    fn initial_packet(dcid: Vec<u8>, scid: Vec<u8>, token: Vec<u8>) -> Vec<u8> {
        let header = Header {
            ty: crate::transport::PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(token),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 256];
        let length = format_header(&header, &mut storage).expect("Initial header");
        storage[..length].to_vec()
    }

    let config = ServerConfig {
        ddos_policy: DdosPolicyConfig {
            activation_window: Duration::from_secs(1),
            clear_window: Duration::from_secs(5),
            ..DdosPolicyConfig::default()
        },
        blacklist: BlacklistConfig { cache_path: None, ..BlacklistConfig::default() },
        ..ServerConfig::default()
    };
    let domain = LiveServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let metrics = Metrics::new();
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(100, Duration::ZERO),
        crate::implementations::server::limits::DdosTransition::Unchanged
    );
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(1_000, Duration::from_secs(1)),
        crate::implementations::server::limits::DdosTransition::Unchanged
    );
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(1_000, Duration::from_secs(2)),
        crate::implementations::server::limits::DdosTransition::Activated
    );

    let remote: SocketAddr = "203.0.113.9:44321".parse().expect("remote address");
    let original_dcid = vec![1, 2, 3, 4];
    let client_scid = vec![5, 6, 7, 8];
    let credential = b"a1b2c3d4e5f6".to_vec();
    let initial = initial_packet(original_dcid.clone(), client_scid.clone(), credential.clone());
    let retry_packet = match domain.admit_incoming_datagram(remote, &initial, false, true, &metrics)
    {
        IncomingDatagramAdmission::Retry(packet) => packet,
        _ => panic!("enhanced admission did not issue Retry"),
    };
    let (retry, _) = parse_header(&retry_packet, 0).expect("Retry header");
    verify_retry_tag(&retry_packet, &original_dcid, crate::transport::PROTOCOL_VERSION)
        .expect("Retry integrity");
    let retry_token = retry.token.clone().expect("Retry token");
    let retried_initial = initial_packet(retry.scid.clone(), client_scid, retry_token.clone());

    assert!(matches!(
        domain.admit_incoming_datagram(remote, &retried_initial, false, true, &metrics),
        IncomingDatagramAdmission::RetryValidated
    ));
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &initial, true, true, &metrics),
        IncomingDatagramAdmission::Allow
    ));
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &initial, false, false, &metrics),
        IncomingDatagramAdmission::Allow
    ));

    let mut tampered_token = retry_token;
    let last = tampered_token.len() - 1;
    tampered_token[last] ^= 1;
    let tampered = initial_packet(retry.scid, vec![9, 10], tampered_token);
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &tampered, false, true, &metrics),
        IncomingDatagramAdmission::Drop(DdosDropReason::InvalidRetry)
    ));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn validated_retry_uses_retry_scid_for_initial_keys_and_restores_qkey_identity() {
    use crate::implementations::server::ddos::RetryTokenManager;
    use crate::implementations::server::limits::{
        AuthAdmission, AuthPolicyConfig, AuthRateLimiter,
    };
    use crate::transport::packet::{format_header, parse_header, Header};

    fn initial_packet(dcid: Vec<u8>, scid: Vec<u8>, token: Vec<u8>) -> Vec<u8> {
        let header = Header {
            ty: crate::transport::PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(token),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 256];
        let length = format_header(&header, &mut storage).expect("Initial header");
        storage[..length].to_vec()
    }

    let token_hex = "a".repeat(64);
    let qkey = qf_engine_types::generate(
        &qf_engine_types::QKeyConfig::new("127.0.0.1:4433", "example.com")
            .with_stealth("auto")
            .with_fec("auto")
            .with_token(&token_hex),
    );
    let qkey_id = qkey_registry::qkey_id(&qkey);
    let mut registry = QKeyRegistry::new_in_memory(4, None);
    registry.insert(qkey, token_hex.into(), Some("retry-proof".to_string())).expect("QKey insert");
    let registry = std::sync::Mutex::new(registry);

    let remote: SocketAddr = "203.0.113.10:44321".parse().expect("remote address");
    let original_dcid = vec![1, 2, 3, 4];
    let client_scid = vec![5, 6, 7, 8];
    let initial =
        initial_packet(original_dcid.clone(), client_scid.clone(), qkey_id.as_bytes().to_vec());
    let manager = RetryTokenManager::new_with_clock(
        Duration::from_secs(10),
        &crate::time_source::ProtocolClock::default(),
    )
    .expect("Retry manager");
    let issue = manager.issue_for_initial(&initial, remote.ip()).expect("Retry issue");
    let (retry, _) = parse_header(&issue.packet, 0).expect("Retry header");
    let retry_scid = retry.scid.clone();
    let retried = initial_packet(retry.scid, client_scid, retry.token.expect("Retry token"));

    let mut limiter = AuthRateLimiter::new(AuthPolicyConfig::default());
    let attempt = match limiter.begin(remote.ip()) {
        AuthAdmission::Allowed(attempt) => attempt,
        _ => panic!("auth attempt was not admitted"),
    };
    let context = parse_live_server_initial_auth(
        &retried,
        remote.ip(),
        Some(&manager),
        &registry,
        &crate::implementations::server::revocation::RevocationManager::new(),
        attempt,
    )
    .expect("retried Initial authentication");

    assert_eq!(context.initial_key_dcid.as_ref(), retry_scid);
    assert_eq!(context.qkey_record.expect("QKey record").id, qkey_id);
    assert!(context.pending_qkey_auth.is_some());
}

#[test]
fn test_apply_runtime_profile_identity_updates_browser_and_os() {
    let mut stealth = StealthConfig::default();
    apply_runtime_profile_identity(&mut stealth, BrowserProfile::Firefox, OsProfile::Linux);
    assert_eq!(stealth.initial_browser, BrowserProfile::Firefox);
    assert_eq!(stealth.initial_os, OsProfile::Linux);
}

#[test]
fn test_runtime_profile_slots_accept_canonical_at_syntax_only() {
    let at = parse_runtime_profile_entry("safari@macos", OsProfile::Windows)
        .expect("canonical profile slot");
    assert_eq!(at.browser, BrowserProfile::Safari);
    assert_eq!(at.os, OsProfile::MacOS);

    let default_os = parse_runtime_profile_entry("firefox", OsProfile::Linux)
        .expect("browser-only profile slot");
    assert_eq!(default_os.browser, BrowserProfile::Firefox);
    assert_eq!(default_os.os, OsProfile::Linux);

    assert!(parse_runtime_profile_entry("firefox:linux", OsProfile::Windows).is_none());
    assert!(parse_runtime_profile_entry("chrome@windows@linux", OsProfile::Windows).is_none());
    assert!(parse_runtime_profile_entry("safari@windows", OsProfile::Windows).is_none());
}

#[test]
fn runtime_profile_resolution_rejects_invalid_slots_instead_of_dropping_them() {
    let invalid = vec!["firefox@linux".to_string(), "chrome:windows".to_string()];
    let error =
        resolve_runtime_profiles(BrowserProfile::Chrome, OsProfile::Windows, &invalid, true)
            .expect_err("an invalid slot must fail the whole sequence");
    assert!(error.contains("chrome:windows"));

    let empty = resolve_runtime_profiles(BrowserProfile::Chrome, OsProfile::Windows, &[], false)
        .expect("an explicitly empty optional sequence is representable");
    assert!(empty.is_empty());

    let fallback = resolve_runtime_profiles(BrowserProfile::Firefox, OsProfile::Linux, &[], true)
        .expect("empty server sequence falls back to the initial profile");
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback[0].browser, BrowserProfile::Firefox);
    assert_eq!(fallback[0].os, OsProfile::Linux);
}

#[path = "tests_inline/policy_and_runtime.rs"]
mod policy_and_runtime;
#[path = "tests_inline/qkey_and_persistence.rs"]
mod qkey_and_persistence;
