#[cfg(test)]
mod tests {
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
    fn admission_allowed(
        domain: &LiveServerDomain,
        remote_addr: SocketAddr,
        packet: &[u8],
    ) -> bool {
        matches!(
            domain.admit_incoming_datagram(remote_addr, packet, true, true),
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
        let payload =
            vec![0; crate::transport::MIN_CLIENT_INITIAL_LEN - crate::fec::wire::HEADER_LEN];
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
        shaped
            .enqueue_with_accounting(first_target, first_session, 1, vec![40], now, true)
            .unwrap();
        assert!(shaped.pop_next(&std::collections::HashSet::new()).unwrap().bandwidth_accounted);
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
            Arc::new(std::sync::Mutex::new(crate::core::MasqueDownlinkQueue::new(1, 64)));
        enqueue_routing_response(&responses, &metrics, vec![3]);
        enqueue_routing_response(&responses, &metrics, vec![4]);

        let output = metrics.export();
        assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_packets 1"));
        assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_bytes 1"));
        assert!(output
            .contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 3"));
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
        let queue = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let source = "127.0.0.1:4433".parse().unwrap();
        let packet = [0x45, 0, 0, 20];
        enqueue_client_fanout(
            &queue,
            source,
            UplinkRoute::Broadcast {
                source: Ipv4Addr::new(10, 0, 1, 2),
                destination: Ipv4Addr::new(10, 0, 1, 255),
            },
            &packet,
        );
        enqueue_client_fanout(
            &queue,
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
    fn authenticated_server_uplink_is_typed_as_local() {
        let server_ip = Ipv4Addr::new(10, 0, 1, 1);
        let client_ip = Ipv4Addr::new(10, 0, 1, 2);
        let forwarding_policy =
            ClientIsolationManager::with_network(server_ip, Ipv4Addr::new(255, 255, 255, 0), false);
        let assigned = AssignedClientIps { ipv4: client_ip, ipv6: None };
        forwarding_policy.assign_client("client", assigned);
        let metrics = Metrics::new();
        let responses =
            Arc::new(std::sync::Mutex::new(crate::core::MasqueDownlinkQueue::new(8, 4096)));
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
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.max_clients, 100);
        assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
        // IPv6 defaults
        assert!(config.ipv6_server_ip.is_some());
        assert_eq!(config.ipv6_server_ip.unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
        assert_eq!(config.ipv6_prefix_len, 64);
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
        assert_eq!(&response[48..], dns_response.as_slice());
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
        let domain = LiveServerDomain::new(&ServerConfig::default());
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
        let mut live_state = LiveServerState::new(ServerConfig::default());
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
        let domain = LiveServerDomain::new(&ServerConfig::default());
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
        let mut live_state = LiveServerState::new(server_config);
        let remote_addr = "127.0.0.1:54324".parse().unwrap();
        let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let mut out = [0; 1460];

        assert_eq!(live_state.domain.session_id_by_remote(remote_addr), Some(session_id));
        tokio::time::sleep(Duration::from_secs(2)).await;

        live_state.run_housekeeping_tick(&socket, &mut out, &metrics, &accept_loop).await;

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

    #[tokio::test]
    async fn test_standalone_runtime_drain_rejects_new_clients_and_reports_lifecycle() {
        let engine_config = EngineConfig {
            engine: crate::engine::EngineSection {
                shutdown_timeout_ms: 250,
                ..crate::engine::EngineSection::default()
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
        let domain = SharedServerDomain::new(&config);
        assert!(domain.blacklist.has_sync_url());
        assert_eq!(domain.blacklist.sync_interval(), Duration::from_secs(300));
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
        let domain = SharedServerDomain::new(&config);
        // The blocker should be enabled (config has db_path + countries),
        // but gracefully degrade (missing db → is_blocked returns false).
        assert!(domain.geoip_blocker.is_enabled());
        assert!(!domain.geoip_blocker.is_blocked("1.2.3.4".parse().unwrap()));
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
        let domain = LiveServerDomain::new(&config);
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
        let initial =
            initial_packet(original_dcid.clone(), client_scid.clone(), credential.clone());
        let retry_packet = match domain.admit_incoming_datagram(remote, &initial, false, true) {
            IncomingDatagramAdmission::Retry(packet) => packet,
            _ => panic!("enhanced admission did not issue Retry"),
        };
        let (retry, _) = parse_header(&retry_packet, 0).expect("Retry header");
        verify_retry_tag(&retry_packet, &original_dcid, crate::transport::PROTOCOL_VERSION)
            .expect("Retry integrity");
        let retry_token = retry.token.clone().expect("Retry token");
        let retried_initial = initial_packet(retry.scid.clone(), client_scid, retry_token.clone());

        assert!(matches!(
            domain.admit_incoming_datagram(remote, &retried_initial, false, true),
            IncomingDatagramAdmission::RetryValidated
        ));
        assert!(matches!(
            domain.admit_incoming_datagram(remote, &initial, true, true),
            IncomingDatagramAdmission::Allow
        ));
        assert!(matches!(
            domain.admit_incoming_datagram(remote, &initial, false, false),
            IncomingDatagramAdmission::Allow
        ));

        let mut tampered_token = retry_token;
        let last = tampered_token.len() - 1;
        tampered_token[last] ^= 1;
        let tampered = initial_packet(retry.scid, vec![9, 10], tampered_token);
        assert!(matches!(
            domain.admit_incoming_datagram(remote, &tampered, false, true),
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
        let qkey = crate::engine::qkey::generate(
            &crate::engine::qkey::QKeyConfig::new("127.0.0.1:4433", "example.com")
                .with_stealth("auto")
                .with_fec("auto")
                .with_token(&token_hex),
        );
        let qkey_id = qkey_registry::qkey_id(&qkey);
        let mut registry = QKeyRegistry::new_in_memory(4, None);
        registry
            .insert(qkey, token_hex.into(), Some("retry-proof".to_string()))
            .expect("QKey insert");
        let registry = std::sync::Mutex::new(registry);

        let remote: SocketAddr = "203.0.113.10:44321".parse().expect("remote address");
        let original_dcid = vec![1, 2, 3, 4];
        let client_scid = vec![5, 6, 7, 8];
        let initial =
            initial_packet(original_dcid.clone(), client_scid.clone(), qkey_id.as_bytes().to_vec());
        let manager = RetryTokenManager::new(Duration::from_secs(10)).expect("Retry manager");
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
    fn test_resolve_qkey_ttl_secs_zero_disables_registry_expiry() {
        assert_eq!(resolve_qkey_ttl_secs(Some(0)), None);
        assert_eq!(resolve_qkey_ttl_secs(Some(120)), Some(120));
    }

    #[test]
    fn test_normalize_qkey_fec_rejects_unknown_mode() {
        assert!(normalize_qkey_fec(Some("turbo")).is_err());
        assert!(normalize_qkey_fec(Some("manual")).is_err());
        assert!(normalize_qkey_fec(Some("on")).is_err());
    }

    #[test]
    fn test_resolve_admin_web_auth_rejects_weak_defaults_without_override() {
        let err = resolve_admin_web_auth(Some("admin".to_string()), Some("123".to_string()))
            .expect_err("weak defaults must be rejected unless explicitly enabled");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("Refusing weak default admin credentials [admin/123]"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_resolve_admin_auth_store_path_defaults_under_config_local() {
        let path = resolve_admin_auth_store_path(None);
        assert_eq!(path, std::path::PathBuf::from("config/local/admin-auth.json"));
    }

    #[test]
    fn test_resolve_qkey_store_path_defaults_under_config_local() {
        let path = resolve_qkey_store_path(None, None);
        assert_eq!(path, std::path::PathBuf::from("config/local/qkeys.json"));
    }

    #[test]
    fn test_load_persisted_blocked_ips_defaults_empty_without_config() {
        assert!(load_persisted_blocked_ips(None).is_empty());
    }

    #[test]
    fn test_load_persisted_logging_mode_defaults_to_normal_without_config() {
        assert_eq!(load_persisted_logging_mode(None), "normal");
    }

    #[test]
    fn test_auth_policy_metrics_distinguish_terminal_and_admission_outcomes() {
        let metrics = Metrics::new();
        metrics.record_auth_attempt();
        metrics.record_auth_failure();
        metrics.record_auth_backoff_rejection();
        metrics.record_auth_blocked_rejection();
        metrics.record_auth_capacity_rejection();

        assert_eq!(metrics.auth_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_backoff_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_blocked_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_capacity_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.rate_limited.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn server_runtime_rejects_invalid_auth_policy_before_resource_setup() {
        let mut server_config = ServerConfig::default();
        server_config.auth_policy.backoff_after_failures = 0;

        let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
            Ok(_) => panic!("invalid auth policy must fail runtime construction"),
            Err(error) => error,
        };
        assert!(matches!(error, EngineError::Config(_)));
    }

    #[test]
    fn auth_policy_rejects_before_qkey_registry_lookup() {
        let policy = AuthPolicyConfig {
            backoff_after_failures: 1,
            block_after_failures: 2,
            backoff_base: Duration::from_secs(60),
            backoff_max: Duration::from_secs(60),
            ..AuthPolicyConfig::default()
        };
        let auth_rate_limiter = Arc::new(std::sync::Mutex::new(
            crate::implementations::server::limits::AuthRateLimiter::new(policy),
        ));
        let remote_addr: SocketAddr = "192.0.2.10:54321".parse().unwrap();
        {
            let mut limiter = auth_rate_limiter.lock().unwrap_or_else(|error| error.into_inner());
            let attempt = match limiter.begin(remote_addr.ip()) {
                crate::implementations::server::limits::AuthAdmission::Allowed(attempt) => attempt,
                other => panic!("first attempt must be admitted: {other:?}"),
            };
            assert_eq!(
                limiter.complete(
                    attempt,
                    crate::implementations::server::limits::AuthTerminal::Failed
                ),
                crate::implementations::server::limits::AuthCompletion::FailedWithBackoff {
                    delay: Duration::from_secs(60)
                }
            );
        }

        let qkey_registry = std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None));
        let revocation_manager =
            crate::implementations::server::revocation::RevocationManager::new();
        let metrics = Metrics::new();
        let stealth_config = Arc::new(std::sync::Mutex::new(StealthConfig::default()));
        let fec_config = Arc::new(std::sync::Mutex::new(FecConfig::default()));
        let optimize_config =
            Arc::new(std::sync::Mutex::new(crate::optimize::OptimizeConfig::default()));
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();

        let result = build_live_server_client_init(LiveClientBuildRequest {
            packet: b"not-a-valid-initial",
            local_addr: "127.0.0.1:4433".parse().unwrap(),
            remote_addr,
            qkey_registry: &qkey_registry,
            revocation_manager: &revocation_manager,
            metrics: &metrics,
            stealth_config: &stealth_config,
            fec_cfg_shared: &fec_config,
            opt_params_shared: &optimize_config,
            transport_config: &mut transport,
            stealth_runtime: None,
            auth_rate_limiter,
            retry_token_manager: None,
        });

        assert!(result.is_none());
        assert_eq!(
            qkey_registry.lock().unwrap_or_else(|error| error.into_inner()).initial_lookup_count(),
            0
        );
        assert_eq!(metrics.auth_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_backoff_rejected.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_enforce_qkey_auth_timeouts_updates_exported_auth_failed_metrics() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54325".parse().unwrap();
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"auth-metric-timeout"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = metrics.auth_failed.load(Ordering::Relaxed);

        live_state.clients.insert(remote_addr, connection);
        let auth_attempt = begin_test_auth_attempt(&live_state, remote_addr.ip());
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "test-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                authed: false,
                post_handshake_started_at: Some(
                    Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(1)),
                ),
                auth_attempt: Some(auth_attempt),
            },
        );

        live_state.enforce_qkey_auth_timeouts(&metrics);

        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before + 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), auth_failed_before + 1);
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
    }

    #[test]
    fn test_qkey_auth_success_associates_session_and_revocation_closes_client() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
        let (session_id, _, _) = live_state.domain.accept(remote_addr).expect("session accepted");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"auth-revoke-close"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let qkey_policy = BandwidthPolicy {
            rate_bytes_per_second: 1_250_000,
            burst_bytes: 1_250_000,
            daily_quota_bytes: 10_000_000,
            monthly_quota_bytes: 100_000_000,
            weight: 2,
        };
        let traffic_analysis_policy = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);

        assert_eq!(
            connection.conn.traffic_analysis_policy().defense,
            crate::transport::config::TrafficAnalysisDefense::Off
        );
        live_state.clients.insert(remote_addr, connection);
        let auth_attempt = begin_test_auth_attempt(&live_state, remote_addr.ip());
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "test-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                bandwidth_policy: Some(qkey_policy.clone()),
                traffic_analysis_policy: Some(traffic_analysis_policy),
                authed: false,
                post_handshake_started_at: Some(Instant::now()),
                auth_attempt: Some(auth_attempt),
            },
        );

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), true)),
            &accept_loop,
            &metrics,
        );

        let bandwidth_stats =
            live_state.domain.shared.sessions.read().bandwidth_stats(session_id).unwrap();
        assert_eq!(bandwidth_stats.policy, qkey_policy);
        assert_eq!(
            live_state
                .clients
                .get(&remote_addr)
                .expect("authenticated client")
                .conn
                .traffic_analysis_policy(),
            traffic_analysis_policy
        );
        assert_eq!(
            live_state.qkey_tracker.key_for_connection(session_id.as_u64()).as_deref(),
            Some("test-key")
        );

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), true)),
            &accept_loop,
            &metrics,
        );

        assert!(live_state.clients.contains_key(&remote_addr));
        assert_eq!(
            live_state.domain.shared.sessions.read().bandwidth_stats(session_id).unwrap().policy,
            qkey_policy
        );
        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before);

        live_state.revoke_qkey_now("test-key", "test", &accept_loop, &metrics);

        assert!(live_state.revocation_manager.is_revoked("test-key"));
        assert!(!live_state.clients.contains_key(&remote_addr));
        assert!(live_state.domain.session_id_by_remote(remote_addr).is_none());
        assert!(live_state.qkey_tracker.connections_for_key("test-key").is_empty());
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
    }

    #[test]
    fn failed_qkey_auth_never_activates_pending_traffic_analysis_policy() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54328".parse().unwrap();
        live_state.domain.accept(remote_addr).expect("session accepted");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"failed-policy-auth"),
        )
        .expect("live server connection");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let pending_policy = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };

        live_state.clients.insert(remote_addr, connection);
        let auth_attempt = begin_test_auth_attempt(&live_state, remote_addr.ip());
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "failed-policy-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                bandwidth_policy: None,
                traffic_analysis_policy: Some(pending_policy),
                authed: false,
                post_handshake_started_at: Some(Instant::now()),
                auth_attempt: Some(auth_attempt),
            },
        );

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), false)),
            &accept_loop,
            &metrics,
        );

        assert!(!live_state.qkey_auth.contains_key(&conn_id));
        assert_eq!(
            live_state
                .clients
                .get(&remote_addr)
                .expect("connection remains until caller reconciliation")
                .conn
                .traffic_analysis_policy()
                .defense,
            crate::transport::config::TrafficAnalysisDefense::Off
        );
    }

    #[test]
    fn test_pending_qkey_auth_cannot_complete_after_revocation() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54327".parse().unwrap();
        live_state.domain.accept(remote_addr).expect("session accepted");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"pending-revoked"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = metrics.auth_failed.load(Ordering::Relaxed);

        live_state.clients.insert(remote_addr, connection);
        let auth_attempt = begin_test_auth_attempt(&live_state, remote_addr.ip());
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "pending-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                authed: false,
                post_handshake_started_at: Some(Instant::now()),
                auth_attempt: Some(auth_attempt),
            },
        );
        live_state.revocation_manager.revoke("pending-key", "test");

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), true)),
            &accept_loop,
            &metrics,
        );

        assert!(!live_state.clients.contains_key(&remote_addr));
        assert!(live_state.domain.session_id_by_remote(remote_addr).is_none());
        assert!(live_state.qkey_tracker.connections_for_key("pending-key").is_empty());
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before + 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), auth_failed_before + 1);
    }

    #[test]
    fn test_read_logging_mode_reports_current_mode() {
        let logging_mode = parking_lot::RwLock::new("minimal".to_string());
        let response = read_logging_mode(&logging_mode);
        assert!(response.success);
        assert_eq!(
            response.data.as_ref().and_then(|v| v.get("mode")),
            Some(&serde_json::json!("minimal"))
        );
    }

    #[tokio::test]
    async fn test_run_loop_stops_from_admin_shutdown_without_start() {
        let server_config =
            ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
        let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
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
            None,
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
        let shutdown_sender = runtime.admin_actions_sender();

        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            shutdown_sender.send(AdminAction::Shutdown).expect("admin sender closed");
        });

        let run_loop_result =
            tokio::time::timeout(Duration::from_secs(1), runtime.run_loop(&mut runtime_config))
                .await;

        assert!(trigger.await.is_ok());
        let result = run_loop_result.expect("run loop should finish within timeout");
        assert!(result.is_ok());
        assert_eq!(runtime.state, ServerState::Stopped);
    }

    // --- Session lifecycle tests ---

    #[test]
    fn test_accept_client_assigns_unique_session_ids() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:10001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:10002".parse().unwrap()).unwrap();
        let id3 = runtime.accept_client("127.0.0.1:10003".parse().unwrap()).unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
        assert_eq!(runtime.session_count(), 3);
    }

    #[test]
    fn test_remove_client_decrements_session_count() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:20001".parse().unwrap()).unwrap();
        let _id2 = runtime.accept_client("127.0.0.1:20002".parse().unwrap()).unwrap();
        assert_eq!(runtime.session_count(), 2);

        runtime.remove_client(id1);
        assert_eq!(runtime.session_count(), 1);
    }

    #[test]
    fn test_session_stats_returns_none_for_unknown_id() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        assert!(runtime.session_stats(SessionId::from_u64(99999)).is_none());
    }

    #[test]
    fn test_session_stats_tracks_bytes_after_accept() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let session_id = runtime.accept_client("127.0.0.1:30001".parse().unwrap()).unwrap();
        let stats = runtime.session_stats(session_id).unwrap();
        stats.record_received(256);
        stats.record_sent(128);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 256);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 128);
    }

    // --- Connection limits tests ---

    #[test]
    fn test_accept_rejects_when_max_clients_reached() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 2, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        runtime.accept_client("127.0.0.1:40001".parse().unwrap()).unwrap();
        runtime.accept_client("127.0.0.1:40002".parse().unwrap()).unwrap();

        let result = runtime.accept_client("127.0.0.1:40003".parse().unwrap());
        assert!(result.is_err(), "third client should be rejected");
        if let Err(AcceptError::MaxClientsReached) = result {
            // expected
        } else {
            panic!("expected MaxClientsReached, got {:?}", result.err());
        }
    }

    #[test]
    fn test_accept_rejects_per_ip_limit() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 100, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        // Accept connections from the same IP with different ports up to the per-IP limit.
        // DEFAULT_MAX_CONNECTIONS_PER_IP is typically small (e.g. 5).
        let limit = DEFAULT_MAX_CONNECTIONS_PER_IP;
        for port in 0..limit {
            let addr_str = format!("10.0.0.1:{}", 50000 + port);
            runtime.accept_client(addr_str.parse().unwrap()).unwrap();
        }

        let over_limit = format!("10.0.0.1:{}", 50000 + limit);
        let result = runtime.accept_client(over_limit.parse().unwrap());
        assert!(result.is_err(), "should reject after per-IP limit exceeded");
        if let Err(AcceptError::TooManyConnectionsPerIp) = result {
            // expected
        } else {
            panic!("expected TooManyConnectionsPerIp, got {:?}", result.err());
        }
    }

    // --- Graceful shutdown tests ---

    #[test]
    fn test_server_runtime_start_stop_lifecycle() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        assert_eq!(runtime.state(), ServerState::Stopped);
        assert!(!runtime.is_shutdown());
    }

    #[test]
    fn test_remove_all_clients_clears_session_count_to_zero() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:14001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:14002".parse().unwrap()).unwrap();
        assert_eq!(runtime.session_count(), 2);

        runtime.remove_client(id1);
        runtime.remove_client(id2);
        assert_eq!(runtime.session_count(), 0);
    }

    // --- Metrics / ServerStats tests ---

    #[test]
    fn test_server_stats_rejected_counter_increments_on_limit() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 1, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        runtime.accept_client("127.0.0.1:15001".parse().unwrap()).unwrap();
        let _ = runtime.accept_client("127.0.0.1:15002".parse().unwrap());

        assert!(runtime.stats().connections_rejected.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn test_traffic_snapshot_multiple_sessions() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:16001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:16002".parse().unwrap()).unwrap();
        let stats1 = runtime.session_stats(id1).unwrap();
        let stats2 = runtime.session_stats(id2).unwrap();
        stats1.record_received(100);
        stats1.record_sent(50);
        stats2.record_received(200);
        stats2.record_sent(75);

        let snapshot = runtime.traffic_snapshot();
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.bytes_in, 300);
        assert_eq!(snapshot.bytes_out, 125);
        assert_eq!(snapshot.packets_in, 2);
        assert_eq!(snapshot.packets_out, 2);
    }

    // --- Admin core tests ---

    #[test]
    fn test_server_admin_core_block_unblock_ip() {
        let metrics = Arc::new(Metrics::new());
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let client_snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
        let qkeys = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
        let core = ServerAdminCore::new(
            metrics,
            blocked_ips.clone(),
            client_snapshots,
            Arc::new(RwLock::new(SessionManager::new(16))),
            ServerAdminControlPlane {
                actions: tx,
                listen_addr: "127.0.0.1:4433".to_string(),
                front_domain: vec![],
                qkeys,
                graceful_shutdown: Arc::new(GracefulShutdown::new(5_000)),
            },
        );

        let resp = core.block_ip("10.0.0.1");
        assert!(resp.success);
        assert!(blocked_ips.read().contains("10.0.0.1"));

        let resp = core.unblock_ip("10.0.0.1");
        assert!(resp.success);
        assert!(!blocked_ips.read().contains("10.0.0.1"));

        // Unblock non-existent IP should fail
        let resp = core.unblock_ip("10.0.0.99");
        assert!(!resp.success);
    }

    #[test]
    fn test_server_admin_core_list_blocked_ips() {
        let metrics = Arc::new(Metrics::new());
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let client_snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
        let qkeys = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
        let core = ServerAdminCore::new(
            metrics,
            blocked_ips,
            client_snapshots,
            Arc::new(RwLock::new(SessionManager::new(16))),
            ServerAdminControlPlane {
                actions: tx,
                listen_addr: "127.0.0.1:4433".to_string(),
                front_domain: vec![],
                qkeys,
                graceful_shutdown: Arc::new(GracefulShutdown::new(5_000)),
            },
        );

        core.block_ip("10.0.0.3");
        core.block_ip("10.0.0.1");
        core.block_ip("10.0.0.2");

        let resp = core.list_blocked_ips();
        assert!(resp.success);
        let ips = resp.data.as_ref().unwrap()["ips"].as_array().unwrap();
        // Should be sorted
        let ips_vec: Vec<&str> = ips.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(ips_vec, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    // --- Config / path resolution helpers ---

    #[test]
    fn test_resolve_admin_auth_store_path_with_config_path() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_admin_auth_store_path(Some(cfg));
        assert_eq!(path, std::path::PathBuf::from("/etc/quicfuscate/admin-auth.json"));
    }

    #[test]
    fn test_resolve_qkey_store_path_with_override() {
        let override_path = std::path::PathBuf::from("/custom/path/keys.json");
        let path = resolve_qkey_store_path(
            Some(std::path::Path::new("/etc/conf.toml")),
            Some(override_path.clone()),
        );
        assert_eq!(path, override_path);
    }

    #[test]
    fn test_resolve_qkey_store_path_from_config_path() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_qkey_store_path(Some(cfg), None);
        assert_eq!(path, std::path::PathBuf::from("/etc/quicfuscate/server.qkeys.json"));
    }

    #[test]
    fn test_resolve_blocked_ips_store_path_none_without_config() {
        assert!(resolve_blocked_ips_store_path(None).is_none());
    }

    #[test]
    fn test_resolve_blocked_ips_store_path_with_config() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_blocked_ips_store_path(Some(cfg));
        assert_eq!(path, Some(std::path::PathBuf::from("/etc/quicfuscate/server.blocked.json")));
    }

    // --- QKey helper tests ---

    #[test]
    fn test_normalize_qkey_fec_accepts_valid_presets() {
        assert_eq!(normalize_qkey_fec(Some("auto")).unwrap(), "auto");
        assert_eq!(normalize_qkey_fec(Some("off")).unwrap(), "off");
        assert_eq!(normalize_qkey_fec(Some("zero")).unwrap(), "off");
        assert_eq!(normalize_qkey_fec(None).unwrap(), "auto");
        assert_eq!(normalize_qkey_fec(Some("  ")).unwrap(), "auto");
    }

    #[test]
    fn test_normalize_qkey_stealth_accepts_valid_presets() {
        assert_eq!(normalize_qkey_stealth(Some("auto")).unwrap(), "auto");
        assert_eq!(normalize_qkey_stealth(Some("max")).unwrap(), "max");
        assert_eq!(normalize_qkey_stealth(Some("manual")).unwrap(), "manual");
        assert_eq!(normalize_qkey_stealth(Some("off")).unwrap(), "off");
        assert_eq!(normalize_qkey_stealth(None).unwrap(), "auto");
    }

    #[test]
    fn test_normalize_qkey_stealth_rejects_unknown() {
        assert!(normalize_qkey_stealth(Some("turbo")).is_err());
    }

    #[test]
    fn test_normalize_qkey_name_validates_length_and_chars() {
        assert_eq!(normalize_qkey_name(None).unwrap(), None);
        assert_eq!(normalize_qkey_name(Some("  ")).unwrap(), None);
        assert_eq!(normalize_qkey_name(Some("my-key")).unwrap(), Some("my-key".to_string()));

        // Too long
        let long_name = "a".repeat(65);
        assert!(normalize_qkey_name(Some(&long_name)).is_err());

        // Control chars
        assert!(normalize_qkey_name(Some("bad\x00name")).is_err());
    }

    // --- SNI / domain fronting helpers ---

    #[test]
    fn test_is_valid_sni_host_rejects_bad_values() {
        assert!(!is_valid_sni_host(""));
        assert!(!is_valid_sni_host("  "));
        assert!(!is_valid_sni_host("host:443"));
        assert!(!is_valid_sni_host("https://host.com"));
        assert!(!is_valid_sni_host("host.com/path"));
        assert!(!is_valid_sni_host("host?q=1"));
        assert!(!is_valid_sni_host("user@host"));
        assert!(is_valid_sni_host("cdn.cloudflare.com"));
    }

    #[test]
    fn test_extract_host_from_endpoint_various_formats() {
        assert_eq!(extract_host_from_endpoint("example.com:4433"), Some("example.com".to_string()));
        assert_eq!(
            extract_host_from_endpoint("[::1]:4433"),
            None // IPv6 addresses are not valid SNI hostnames
        );
        assert_eq!(extract_host_from_endpoint(""), None);
        assert_eq!(
            extract_host_from_endpoint("cdn.cloudflare.com"),
            Some("cdn.cloudflare.com".to_string())
        );
    }

    // --- QKeyAuthState tests ---

    #[test]
    fn qkey_auth_timeout_starts_only_after_handshake() {
        let mut state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            bandwidth_policy: None,
            traffic_analysis_policy: None,
            authed: false,
            post_handshake_started_at: None,
            auth_attempt: None,
        };

        assert!(!state.is_expired());
        state.begin_post_handshake_timeout();
        let started_at = state.post_handshake_started_at;
        assert!(started_at.is_some());
        state.begin_post_handshake_timeout();
        assert_eq!(state.post_handshake_started_at, started_at);
        assert!(!state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_is_expired_when_not_authed_past_timeout() {
        let state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            bandwidth_policy: None,
            traffic_analysis_policy: None,
            authed: false,
            post_handshake_started_at: Some(
                Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(1)),
            ),
            auth_attempt: None,
        };
        assert!(state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_authed() {
        let state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            bandwidth_policy: None,
            traffic_analysis_policy: None,
            authed: true,
            post_handshake_started_at: Some(
                Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(10)),
            ),
            auth_attempt: None,
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_recent() {
        let state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            bandwidth_policy: None,
            traffic_analysis_policy: None,
            authed: false,
            post_handshake_started_at: Some(Instant::now()),
            auth_attempt: None,
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn qkey_datagram_auth_result_preserves_pending_state() {
        let conn_id = b"pending-auth";

        assert_eq!(qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Pending), None);
        assert_eq!(
            qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Authenticated),
            Some((conn_id.to_vec(), true))
        );
        assert_eq!(
            qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Rejected),
            Some((conn_id.to_vec(), false))
        );
    }

    #[test]
    fn qkey_http3_authentication_is_fail_closed() {
        let valid_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected = qkey_registry::token_sha256_hex_from_token_hex(valid_token)
            .expect("valid QKey token must hash");
        let cases = [
            ("auth disabled", Vec::new(), None, false, QKeyHeaderAuthOutcome::Unchanged),
            (
                "already authenticated",
                Vec::new(),
                Some(expected.as_str()),
                true,
                QKeyHeaderAuthOutcome::Unchanged,
            ),
            (
                "missing header",
                Vec::new(),
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied"),
            ),
            (
                "invalid UTF-8",
                vec![crate::transport::h3::Header::new(b"x-qf-auth", &[0xff])],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied"),
            ),
            (
                "wrong bearer",
                vec![crate::transport::h3::Header::new(
                    b"x-qf-auth",
                    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"qkey_auth_denied"),
            ),
            (
                "valid bearer",
                vec![crate::transport::h3::Header::new(
                    b"X-QF-AUTH",
                    format!("  {}  ", valid_token).as_bytes(),
                )],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Authenticated,
            ),
        ];

        for (name, headers, expected_hash, already_authed, expected_outcome) in cases {
            let outcome = evaluate_qkey_http3_headers(&headers, expected_hash, already_authed);
            match (outcome, expected_outcome) {
                (QKeyHeaderAuthOutcome::Unchanged, QKeyHeaderAuthOutcome::Unchanged)
                | (QKeyHeaderAuthOutcome::Authenticated, QKeyHeaderAuthOutcome::Authenticated) => {}
                (
                    QKeyHeaderAuthOutcome::Reject(actual),
                    QKeyHeaderAuthOutcome::Reject(expected),
                ) => {
                    assert_eq!(actual, expected, "{name}");
                }
                _ => panic!("unexpected QKey auth outcome for {name}"),
            }
        }
    }

    #[test]
    fn qkey_payload_gate_blocks_every_protected_path_until_authentication() {
        let cases = [
            ("auth disabled", false, false, true),
            ("auth disabled and authenticated", false, true, true),
            ("auth required but pending", true, false, false),
            ("auth required and complete", true, true, true),
        ];

        for (name, require_auth, authenticated, expected) in cases {
            assert_eq!(qkey_payload_allowed(require_auth, authenticated), expected, "{name}");
        }
    }

    // --- Logging mode tests ---

    #[test]
    fn test_write_logging_mode_rejects_invalid_mode() {
        let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
        let logging_mode = parking_lot::RwLock::new("normal".to_string());
        let response = write_logging_mode(None, &logging_mode, &log_buffer, "debug");
        assert!(!response.success);
        assert!(response.message.as_deref().unwrap_or("").contains("Invalid logging mode"));
    }

    #[test]
    fn test_write_logging_mode_accepts_valid_modes() {
        let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
        let logging_mode = parking_lot::RwLock::new("normal".to_string());
        for mode in &["verbose", "normal", "minimal", "no-log"] {
            let response = write_logging_mode(None, &logging_mode, &log_buffer, mode);
            assert!(response.success, "mode '{}' should be valid", mode);
            assert_eq!(*logging_mode.read(), *mode);
        }
    }

    #[test]
    fn standalone_reload_scope_never_claims_active_session_mutation() {
        let outcome = StandaloneReloadOutcome {
            scope: StandaloneReloadScope::NextConnectionOnly,
            active_sessions_unchanged: 7,
        };

        assert_eq!(outcome.scope, StandaloneReloadScope::NextConnectionOnly);
        assert_eq!(outcome.active_sessions_unchanged, 7);
    }

    // --- resolve_qkey_remote tests ---

    #[test]
    fn test_resolve_qkey_remote_without_port_override() {
        let result = resolve_qkey_remote("1.2.3.4:4433", None).unwrap();
        assert_eq!(result, "1.2.3.4:4433");
    }

    #[test]
    fn test_resolve_qkey_remote_with_port_override() {
        let result = resolve_qkey_remote("1.2.3.4:4433", Some(8443)).unwrap();
        assert_eq!(result, "1.2.3.4:8443");
    }

    #[test]
    fn test_resolve_qkey_remote_ipv6_with_port_override() {
        let result = resolve_qkey_remote("[::1]:4433", Some(9999)).unwrap();
        assert_eq!(result, "[::1]:9999");
    }

    #[test]
    fn test_resolve_qkey_remote_empty_address_error() {
        let result = resolve_qkey_remote("", Some(4433));
        assert!(result.is_err());
    }

    // --- apply_runtime_stealth_overrides test ---

    #[test]
    fn test_apply_runtime_stealth_overrides_sets_all_fields() {
        let mut sc = StealthConfig::default();
        let front_domains = vec!["cdn.cloudflare.com".to_string()];
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Firefox,
            OsProfile::Windows,
            true, // disable_doh
            "custom-doh",
            false, // disable_fronting
            &front_domains,
            true, // disable_http3
        );
        assert_eq!(sc.initial_browser, BrowserProfile::Firefox);
        assert_eq!(sc.initial_os, OsProfile::Windows);
        assert!(!sc.enable_doh);
        assert_eq!(sc.doh_provider, "custom-doh");
        assert!(sc.enable_domain_fronting);
        assert_eq!(sc.fronting_domains, front_domains);
        assert!(!sc.enable_http3_masquerading);
    }

    #[test]
    fn test_apply_runtime_stealth_overrides_keeps_fronting_explicit_only() {
        let mut sc = StealthConfig::default();
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Chrome,
            OsProfile::Windows,
            false,
            "https://cloudflare-dns.com/dns-query",
            false,
            &[],
            false,
        );
        assert!(!sc.enable_domain_fronting);

        sc.mode = StealthMode::AntiDpi;
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Chrome,
            OsProfile::Windows,
            false,
            "https://cloudflare-dns.com/dns-query",
            false,
            &[],
            false,
        );
        assert!(sc.enable_domain_fronting);
    }

    // --- LiveServerDomain session tracking ---

    #[test]
    fn test_live_server_domain_accept_tracks_multiple_remotes() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr1: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:5002".parse().unwrap();
        let (id1, _, _) = domain.accept(addr1).unwrap();
        let (id2, _, _) = domain.accept(addr2).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(domain.active_session_count(), 2);
        assert_eq!(domain.session_id_by_remote(addr1), Some(id1));
        assert_eq!(domain.session_id_by_remote(addr2), Some(id2));
    }

    #[test]
    fn test_live_server_domain_remove_remote_clears_session() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr: SocketAddr = "10.0.0.1:5003".parse().unwrap();
        let (id, _, _) = domain.accept(addr).unwrap();
        assert_eq!(domain.session_id_by_remote(addr), Some(id));

        domain.remove_remote(addr);
        assert_eq!(domain.session_id_by_remote(addr), None);
        assert_eq!(domain.active_session_count(), 0);
    }

    #[test]
    fn test_live_server_domain_synchronizes_forwarding_policy_lifecycle() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let remote: SocketAddr = "10.0.0.1:5004".parse().unwrap();
        let (_, _, assigned_ips) = domain.accept(remote).unwrap();

        assert_eq!(domain.shared.forwarding_policy.assigned_address_count(), 2);
        assert_eq!(
            domain.shared.forwarding_policy.client_for_ip(assigned_ips.ipv4.into()),
            domain.session_id_by_remote(remote).map(|id| id.as_u64().to_string())
        );

        domain.remove_remote(remote);
        assert_eq!(domain.shared.forwarding_policy.assigned_address_count(), 0);
    }

    // --- ServerConfig defaults ---

    #[test]
    fn test_server_config_default_dns_servers() {
        let config = ServerConfig::default();
        assert_eq!(config.dns_servers.len(), 2);
        assert_eq!(config.dns_servers[0], Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.dns_servers[1], Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn test_server_config_retains_resolved_firewall_backend() {
        let config = server_config_from_listen_addr(
            "127.0.0.1:4433",
            crate::firewall::FirewallBackend::Nftables,
        )
        .unwrap();
        assert_eq!(config.firewall_backend, crate::firewall::FirewallBackend::Nftables);
    }

    #[test]
    fn test_server_config_from_listen_addr_rejects_invalid() {
        let result = server_config_from_listen_addr(
            "not_a_valid_address",
            crate::firewall::FirewallBackend::Iptables,
        );
        assert!(result.is_err());
    }

    // --- AcceptError Display ---

    #[test]
    fn test_accept_error_display_variants() {
        assert_eq!(AcceptError::MaxClientsReached.to_string(), "Maximum clients reached");
        assert_eq!(
            AcceptError::TooManyConnectionsPerIp.to_string(),
            "Too many connections from this IP"
        );
        assert_eq!(AcceptError::IpPoolExhausted.to_string(), "IP pool exhausted");
        assert_eq!(
            AcceptError::SessionError("test".to_string()).to_string(),
            "Session error: test"
        );
    }

    // --- validate_transport_overrides_from_toml ---

    #[test]
    fn test_validate_transport_overrides_empty_toml_ok() {
        assert!(validate_transport_overrides_from_toml("").is_ok());
    }

    #[test]
    fn test_validate_transport_overrides_valid_cc_algorithm() {
        for algorithm in ["reno", "cubic", "bbr2", "bbr3"] {
            let toml_str = format!(
                r#"
[transport]
cc_algorithm = "{algorithm}"
"#
            );
            assert!(validate_transport_overrides_from_toml(&toml_str).is_ok());
        }
    }

    #[test]
    fn test_validate_transport_overrides_invalid_cc_algorithm() {
        let toml_str = r#"
[transport]
cc_algorithm = "not-a-controller"
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }

    #[test]
    fn test_transport_overrides_apply_ordered_quic_versions() {
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let contents = r#"
[transport]
quic_versions = ["v2", "v1"]
"#;

        apply_transport_overrides_from_toml(
            std::path::Path::new("test.toml"),
            contents,
            &mut transport,
        );

        assert_eq!(transport.version(), crate::transport::PROTOCOL_VERSION_V2);
        assert_eq!(
            transport.supported_versions(),
            &[crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION]
        );
        assert!(validate_transport_overrides_from_toml(
            "[transport]\nquic_versions = [\"v2\", \"v2\"]"
        )
        .is_err());
    }

    #[test]
    fn test_validate_transport_overrides_mtu_out_of_range() {
        let toml_str = r#"
[transport]
mtu = 500
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }

    #[test]
    fn test_transport_overrides_apply_dplpmtud_policy() {
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let contents = r#"
[transport]
pmtu_min_mtu = 1260
pmtu_max_mtu = 1460
pmtu_probe_interval_ms = 2500
pmtu_black_hole_timeout_ms = 7500
"#;

        apply_transport_overrides_from_toml(
            std::path::Path::new("test.toml"),
            contents,
            &mut transport,
        );

        let policy = transport.pmtu_policy();
        assert_eq!(policy.min_mtu, 1260);
        assert_eq!(policy.max_mtu, 1460);
        assert_eq!(policy.probe_interval, Duration::from_millis(2500));
        assert_eq!(policy.black_hole_timeout, Duration::from_millis(7500));
    }

    #[test]
    fn test_validate_transport_overrides_rejects_zero_pmtud_timer() {
        let contents = r#"
[transport]
pmtu_probe_interval_ms = 0
"#;

        assert!(validate_transport_overrides_from_toml(contents).is_err());
    }

    #[test]
    fn transport_overrides_apply_independent_traffic_analysis_policies() {
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let contents = r#"
[transport.traffic_analysis]
defense = "off"
chaff_rate_pps = 0
chaff_size_bytes = 1200
constant_rate_pps = 100
idle_timeout_ms = 30000
ramp_down_ms = 5000

[transport.qkey_traffic_analysis_ceiling]
defense = "constant-rate"
chaff_rate_pps = 0
chaff_size_bytes = 1280
constant_rate_pps = 100
idle_timeout_ms = 30000
ramp_down_ms = 5000

[transport.intelligent_traffic_analysis_ceiling]
defense = "full-padding"
chaff_rate_pps = 10
chaff_size_bytes = 1200
constant_rate_pps = 0
idle_timeout_ms = 30000
ramp_down_ms = 5000
"#;

        apply_transport_overrides_from_toml(
            std::path::Path::new("test.toml"),
            contents,
            &mut transport,
        );

        assert_eq!(
            transport.traffic_analysis_policy().defense,
            crate::transport::config::TrafficAnalysisDefense::Off
        );
        assert_eq!(transport.qkey_traffic_analysis_ceiling().constant_rate_pps, 100);
        assert_eq!(transport.intelligent_traffic_analysis_ceiling().chaff_rate_pps, 10);
    }

    #[test]
    fn transport_overrides_reject_unsafe_traffic_analysis_policy() {
        let contents = r#"
[transport.qkey_traffic_analysis_ceiling]
defense = "constant-rate"
constant_rate_pps = 1001
"#;

        assert!(validate_transport_overrides_from_toml(contents).is_err());
    }

    #[test]
    fn test_accept_session_dual_stack_allocates_ipv6() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut v6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0005),
        );
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        let result = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            remote,
            10,
            30,
        );
        assert!(result.is_ok());
        let (session_id, _, assigned_ips) = result.unwrap();
        assert_eq!(assigned_ips.ipv4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(assigned_ips.ipv6, Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)));

        // Verify the session has an IPv6 address
        let session = sessions.get(session_id).unwrap();
        assert!(session.client_ipv6().is_some());
        assert_eq!(session.client_ipv6().unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002));
    }

    #[test]
    fn test_accept_session_no_ipv6_pool_when_none() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        let result = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            None,
            &mut limiter,
            remote,
            10,
            30,
        );
        assert!(result.is_ok());
        let (session_id, _, _) = result.unwrap();

        // Session should NOT have an IPv6 address
        let session = sessions.get(session_id).unwrap();
        assert!(session.client_ipv6().is_none());
    }

    #[test]
    fn test_remove_session_releases_ipv6() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut v6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0003),
        );
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        // Accept a session
        let (session_id, _, _) = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            remote,
            10,
            30,
        )
        .unwrap();

        // IPv6 pool should have 1 allocated
        assert_eq!(v6_pool.allocated_count(), 1);
        assert_eq!(v6_pool.available(), 1);

        // Remove the session
        let removed = remove_session_from_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            session_id,
        );
        assert!(removed.is_some());

        // IPv6 pool should be fully available again
        assert_eq!(v6_pool.allocated_count(), 0);
        assert_eq!(v6_pool.available(), 2);
    }

    #[test]
    fn test_shared_server_domain_creates_ipv6_pool() {
        let config = ServerConfig::default();
        let domain = SharedServerDomain::new(&config);
        // Default config has IPv6 pool start/end configured
        assert!(domain.ipv6_pool.is_some());
    }

    #[test]
    fn test_shared_server_domain_no_ipv6_pool_when_disabled() {
        let config = ServerConfig {
            ipv6_pool_start: None,
            ipv6_pool_end: None,
            ipv6_server_ip: None,
            ..Default::default()
        };
        let domain = SharedServerDomain::new(&config);
        // IPv6 pool should not be created
        assert!(domain.ipv6_pool.is_none());
    }

    #[test]
    fn test_routing_manager_new_dual_stack() {
        let mgr = RoutingManager::new_dual_stack(
            "tun0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001),
            64,
        );
        assert!(mgr.is_ipv6_enabled());
    }

    #[test]
    fn test_routing_manager_new_no_ipv6() {
        let mgr = RoutingManager::new(
            "tun0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        assert!(!mgr.is_ipv6_enabled());
    }
}
