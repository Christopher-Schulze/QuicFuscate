use super::*;

fn test_connection() -> QuicFuscateConnection {
    test_connection_with(StealthConfig::default())
}

fn test_connection_with(stealth: StealthConfig) -> QuicFuscateConnection {
    let pair = crate::transport::connection::bench_paired_1rtt_connections();
    let optimization_manager = Arc::new(OptimizationManager::from_cfg(OptimizeConfig::default()));
    let stealth_manager = Arc::new(StealthManager::new(
        stealth,
        Arc::clone(&optimization_manager),
        Arc::new(CryptoManager::new()),
    ));
    QuicFuscateConnection::new(ConnectionParams {
        clock: crate::time_source::ProtocolClock::default(),
        conn: Box::new(pair.client),
        local_addr: "127.0.0.1:29101".parse().unwrap(),
        peer_addr: "127.0.0.1:29102".parse().unwrap(),
        host_header: String::new(),
        sni_host: None,
        qkey_auth_token_hex: None,
        stealth_manager,
        optimization_manager,
        fec_config: FecConfig::default(),
        tunnel_ingress_normalizer: PacketNormalizer::new(OsFingerprintProfile::Disabled),
        private_packet_protection_mode: qf_crypto::PacketProtectionMode::Auto,
        private_packet_protection_family: None,
        private_protocol_shape: crate::qftls::PrivateProtocolShape::canonical(),
    })
}

fn framed_tunnel_packet(packet: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(H3_TUNNEL_FRAME_HEADER_LEN + packet.len());
    frame.extend_from_slice(H3_TUNNEL_FRAME_MAGIC);
    frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    frame.extend_from_slice(packet);
    frame
}

fn fec_packet(id: u64, payload: &[u8], coefficients: Option<&[u8]>) -> FecPacket {
    let pool = crate::optimize::global_pool();
    let data = pool.alloc_from_slice(payload);
    let coeff_len = coefficients.map_or(0, <[u8]>::len);
    let coeffs = coefficients.map(|values| pool.alloc_from_slice(values));
    FecPacket::new(id, Some(data), payload.len(), coefficients.is_none(), coeffs, coeff_len, pool)
}

/// Wire source-symbol layout: u16 length prefix + datagram payload.
fn protected_datagram(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(wire::SOURCE_LENGTH_LEN + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn test_send_info() -> crate::transport::SendInfo {
    crate::transport::SendInfo {
        from: "127.0.0.1:29101".parse().unwrap(),
        to: "127.0.0.1:29102".parse().unwrap(),
        at: Instant::now(),
        congestion_controlled: true,
        path_control: false,
        bulk_only: false,
    }
}

#[test]
fn connection_stats_default_zeroed() {
    let stats = ConnectionStats::default();
    assert_eq!(stats.rtt, 0.0);
    assert_eq!(stats.loss_rate, 0.0);
    assert_eq!(stats.packets_sent, 0);
    assert_eq!(stats.packets_lost, 0);
    assert_eq!(stats.congestion_cwnd, 0);
    assert_eq!(stats.congestion_bytes_in_flight, 0);
    assert_eq!(stats.congestion_delivery_rate, 0);
    assert_eq!(stats.congestion_lost, 0);
    assert_eq!(stats.congestion_score, 0);
    assert_eq!(stats.congestion_sample_count(), 0);
}

#[test]
fn asymmetric_stealth_server_emits_no_raw_h3_cover_stream() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};

    let BenchConnectionPair { client, server, recv_info } = bench_paired_1rtt_connections();
    let wrap = |conn, local_addr, peer_addr, stealth_config| {
        let optimization_manager =
            Arc::new(OptimizationManager::from_cfg(OptimizeConfig::default()));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            Arc::clone(&optimization_manager),
            Arc::new(CryptoManager::new()),
        ));
        let mut fec_config = FecConfig::product_default();
        fec_config.apply_engine_mode(qf_engine_types::FecMode::Off);
        QuicFuscateConnection::new(ConnectionParams {
            clock: crate::time_source::ProtocolClock::default(),
            conn: Box::new(conn),
            local_addr,
            peer_addr,
            host_header: String::new(),
            sni_host: None,
            qkey_auth_token_hex: None,
            stealth_manager,
            optimization_manager,
            fec_config,
            tunnel_ingress_normalizer: PacketNormalizer::new(OsFingerprintProfile::Disabled),
            private_packet_protection_mode: qf_crypto::PacketProtectionMode::Auto,
            private_packet_protection_family: None,
            private_protocol_shape: crate::qftls::PrivateProtocolShape::canonical(),
        })
    };

    let mut server_config = StealthConfig::stealth();
    server_config.enable_timing_obfuscation = false;
    server_config.enable_traffic_padding = false;
    let mut server = wrap(server, recv_info.to, recv_info.from, server_config);
    let mut client = wrap(client, recv_info.from, recv_info.to, StealthConfig::performance());
    server.init_http3().expect("server H3 initialization");
    client.init_http3().expect("client H3 initialization");

    let mut packet = [0u8; 2048];
    let (len, send_info) = server.send_with_info(&mut packet).expect("server cover PING send");
    client
        .recv_on_path(&packet[..len], send_info.from, send_info.to)
        .expect("client receives server cover PING");

    assert_eq!(
        client.conn.stream_readable_next(),
        None,
        "QUIC cover PING must not create an unframed H3 stream"
    );
    client.poll_http3().expect("asymmetric H3 poll must remain valid");
}

#[test]
fn masque_request_headers_bind_auth_and_connection_generation() {
    let mut connection = test_connection();
    connection.qkey_auth_token_hex =
        Some(qf_engine_types::QKeyToken::from("00112233445566778899aabbccddeeff"));
    connection.set_client_connection_generation(47);

    let headers = connection.build_masque_request_headers();

    assert_eq!(headers.len(), 2);
    assert!(headers.iter().any(|header| {
        header.name() == b"x-qf-auth" && header.value() == b"00112233445566778899aabbccddeeff"
    }));
    assert!(headers
        .iter()
        .any(|header| { header.name() == b"x-qf-generation" && header.value() == b"47" }));
}

#[test]
fn circuit_headers_roundtrip_a_bounded_identity_without_path_disclosure() {
    let mut connection = test_connection();
    let circuit_id = [0xab; 16];
    connection.set_circuit_context(circuit_id, 3);

    let headers = connection.build_masque_request_headers();

    assert_eq!(QuicFuscateConnection::peer_circuit(&headers), Ok(Some((circuit_id, 3))));
    assert_eq!(
        headers
            .iter()
            .filter(|header| header.name().eq_ignore_ascii_case(b"x-qf-circuit-id"))
            .count(),
        1
    );
    assert!(!headers.iter().any(|header| {
        header.name().eq_ignore_ascii_case(b"x-qf-circuit-path")
            || header.name().eq_ignore_ascii_case(b"x-qf-circuit-depth")
    }));
}

#[test]
fn circuit_headers_reject_missing_duplicate_and_out_of_range_budgets() {
    let id =
        crate::transport::h3::Header::new(b"x-qf-circuit-id", b"abababababababababababababababab");
    assert!(QuicFuscateConnection::peer_circuit(std::slice::from_ref(&id)).is_err());
    let invalid_budget = crate::transport::h3::Header::new(b"x-qf-hop-budget", b"9");
    assert!(QuicFuscateConnection::peer_circuit(&[id.clone(), invalid_budget]).is_err());
    let valid_budget = crate::transport::h3::Header::new(b"x-qf-hop-budget", b"1");
    assert!(QuicFuscateConnection::peer_circuit(&[id.clone(), id, valid_budget]).is_err());
}

#[test]
fn send_only_feedback_does_not_replay_stale_loss_into_auto_fec() {
    let mut fec = AdaptiveFec::new(FecConfig::product_default());
    let send_only = crate::transport::connection::FecCallbackFeedback {
        sent_packets: 1,
        acked_packets: 0,
        lost_packets: 0,
    };

    for _ in 0..64 {
        QuicFuscateConnection::apply_fec_transport_feedback(&mut fec, send_only, 1.0, false);
    }

    assert_eq!(
        fec.current_mode(),
        crate::fec::FecMode::Zero,
        "send callbacks alone must not turn a stale CC loss rate into FEC repair pressure"
    );
}

#[test]
fn h3_tunnel_decoder_reassembles_segmented_packet() {
    let packet = [0x45, 0, 0, 20, 1, 2, 3, 4];
    let frame = framed_tunnel_packet(&packet);
    let mut decoder = H3TunnelFrameDecoder::default();
    let mut decoded = Vec::new();

    decoder.push(&frame[..3], |value| decoded.push(value.to_vec())).unwrap();
    decoder.push(&frame[3..7], |value| decoded.push(value.to_vec())).unwrap();
    decoder.push(&frame[7..], |value| decoded.push(value.to_vec())).unwrap();

    assert_eq!(decoded, vec![packet.to_vec()]);
    assert!(decoder.pending.is_empty());
}

#[test]
fn h3_tunnel_decoder_splits_coalesced_packets() {
    let ipv4 = [0x45, 0, 0, 20];
    let ipv6 = [0x60, 0, 0, 0, 0, 0, 59, 64];
    let mut data = framed_tunnel_packet(&ipv4);
    data.extend_from_slice(&framed_tunnel_packet(&ipv6));
    let mut decoder = H3TunnelFrameDecoder::default();
    let mut decoded = Vec::new();

    decoder.push(&data, |value| decoded.push(value.to_vec())).unwrap();

    assert_eq!(decoded, vec![ipv4.to_vec(), ipv6.to_vec()]);
    assert!(decoder.pending.is_empty());
}

#[test]
fn h3_tunnel_decoder_rejects_unframed_body() {
    let mut decoder = H3TunnelFrameDecoder::default();
    let error = decoder.push(&[0x45, 0, 0, 20, 1, 2], |_| {}).unwrap_err();

    assert_eq!(error, "invalid H3 tunnel frame magic");
    assert!(decoder.pending.is_empty());
}

#[test]
fn h3_tunnel_decoder_rejects_empty_non_ip_and_oversized_input() {
    let mut decoder = H3TunnelFrameDecoder::default();
    let empty = framed_tunnel_packet(&[]);
    assert_eq!(decoder.push(&empty, |_| {}).unwrap_err(), "empty H3 tunnel packet");

    let non_ip = framed_tunnel_packet(&[0x30, 1, 2]);
    assert_eq!(
        decoder.push(&non_ip, |_| {}).unwrap_err(),
        "H3 tunnel frame does not contain an IP packet"
    );

    let oversized = vec![0u8; MAX_H3_TUNNEL_PENDING_LEN + 1];
    assert_eq!(
        decoder.push(&oversized, |_| {}).unwrap_err(),
        "H3 tunnel frame buffer exceeded its bounded capacity"
    );
}

#[test]
fn masque_downlink_queue_bounds_bytes_and_preserves_fifo() {
    let mut queue = MasqueDownlinkQueue::new(2, 4);
    queue.enqueue(vec![1, 2]).unwrap();
    queue.enqueue(vec![3]).unwrap();
    assert_eq!(queue.enqueue(vec![4]), Err(MasqueDownlinkQueueReject::PacketCapacity));

    assert_eq!(queue.pop_front(), Some(vec![1, 2]));
    assert_eq!(queue.enqueue(vec![4, 5, 6, 7]), Err(MasqueDownlinkQueueReject::ByteCapacity));
    assert_eq!(queue.pop_front(), Some(vec![3]));
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.bytes(), 0);

    queue.enqueue(vec![6, 7]).unwrap();
    assert_eq!(queue.discard_all(), (1, 2));
    assert_eq!(queue.bytes(), 0);
}

#[test]
fn masque_downlink_retry_precedes_later_responses_and_shutdown_discards_all_ownership() {
    let mut connection = test_connection();
    let queue = Arc::new(std::sync::Mutex::new(MasqueDownlinkQueue::new(4, 64)));
    {
        let mut pending = queue.lock().unwrap();
        pending.enqueue(vec![1]).unwrap();
        pending.enqueue(vec![2]).unwrap();
    }
    connection.set_masque_downlink_queue(Arc::clone(&queue));

    let first = connection.pop_masque_downlink_packet().unwrap();
    connection.retry_masque_downlink_packet(first);
    assert_eq!(connection.pop_masque_downlink_packet(), Some(vec![1]));
    assert_eq!(connection.pop_masque_downlink_packet(), Some(vec![2]));

    queue.lock().unwrap().enqueue(vec![3, 4]).unwrap();
    connection.retry_masque_downlink_packet(vec![5, 6, 7]);
    assert_eq!(connection.discard_masque_downlink_packets(), (2, 5));
    assert!(connection.pop_masque_downlink_packet().is_none());
}

#[test]
fn next_hop_masque_payload_bypasses_ip_normalization_byte_exactly() {
    let target = MasqueUdpTarget::parse_authority("relay.example:443").expect("valid relay target");
    let binding = MasqueFlowBinding {
        stream_id: 4,
        target: Some(target.clone()),
        purpose: MasqueFlowPurpose::NextHopUdp,
        generation: Some(7),
        circuit_id: Some([1; 16]),
        hop_budget: Some(1),
        accepted: true,
        control_sent: false,
    };
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let relay: MasqueRelayHandler =
        Arc::new(std::sync::Mutex::new(Box::new(move |flow_id, received_target, payload| {
            observed_clone.lock().unwrap().push((
                flow_id,
                received_target.clone(),
                payload.to_vec(),
            ));
        })));
    let mut opaque_inner_quic = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let payload_len = opaque_inner_quic.len();

    QuicFuscateConnection::dispatch_bound_masque_payload(
        9,
        Some(&binding),
        &mut opaque_inner_quic,
        payload_len,
        &None,
        &None,
        &None,
        &Some(relay),
        &PacketNormalizer::new(OsFingerprintProfile::Disabled),
    );

    assert_eq!(
        observed.lock().unwrap().as_slice(),
        &[(9, target, vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01])]
    );
}

#[test]
fn tun_ip_masque_payload_rejects_the_same_non_ip_bytes() {
    let binding = MasqueFlowBinding {
        stream_id: 4,
        target: None,
        purpose: MasqueFlowPurpose::TunIp,
        generation: Some(7),
        circuit_id: None,
        hop_budget: None,
        accepted: true,
        control_sent: false,
    };
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let datagram: DatagramHandler = Arc::new(std::sync::Mutex::new(Box::new(move |payload| {
        observed_clone.lock().unwrap().push(payload.to_vec());
    })));
    let mut non_ip = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
    let payload_len = non_ip.len();

    QuicFuscateConnection::dispatch_bound_masque_payload(
        9,
        Some(&binding),
        &mut non_ip,
        payload_len,
        &Some(datagram),
        &None,
        &None,
        &None,
        &PacketNormalizer::new(OsFingerprintProfile::Disabled),
    );

    assert!(observed.lock().unwrap().is_empty());
}

#[test]
fn peer_connect_ip_flow_active_ignores_relay_flows() {
    let mut connection = test_connection();
    connection.masque_peer_flows.insert(
        1,
        MasqueFlowBinding {
            stream_id: 4,
            target: Some(MasqueUdpTarget::parse_authority("relay.example:443").unwrap()),
            purpose: MasqueFlowPurpose::NextHopUdp,
            generation: Some(7),
            circuit_id: Some([1; 16]),
            hop_budget: Some(1),
            accepted: true,
            control_sent: false,
        },
    );
    assert!(!connection.peer_connect_ip_flow_active());

    connection.masque_peer_flows.insert(
        2,
        MasqueFlowBinding {
            stream_id: 8,
            target: None,
            purpose: MasqueFlowPurpose::TunIp,
            generation: Some(7),
            circuit_id: None,
            hop_budget: None,
            accepted: true,
            control_sent: false,
        },
    );
    assert!(connection.peer_connect_ip_flow_active());
}

#[test]
fn outgoing_zero_mode_packet_preserves_raw_quic_datagram() {
    let payload = [0x40, 0x11, 0x22, 0x33];
    let outgoing = OutgoingFecPacket {
        packet: fec_packet(7, &payload, None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    };
    let mut wire = [0u8; 64];

    let written = outgoing.write_to(&mut wire).expect("raw packet must serialize");

    assert_eq!(&wire[..written], &payload);
}

#[test]
fn outgoing_repair_packet_preserves_fec_wire_metadata() {
    let payload = [0x91, 0x82, 0x73, 0x64];
    let coefficients = [1, 3, 5, 7];
    let mut packet = fec_packet(43, &payload, Some(&coefficients));
    packet.seq = 2 << 4;
    let meta = WirePacketMeta {
        profile: WireProfile {
            epoch: 1,
            codec: wire::WireCodec::Gf8,
            source_count: 4,
            total_count: 7,
            interleave_depth: 1,
        },
        window: 10,
        sequence: 43,
        repair_index: 2,
        block_index: 0,
        systematic: false,
        sliding: false,
    };
    let outgoing = OutgoingFecPacket {
        packet,
        wire_meta: Some(meta),
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    };
    let mut wire = [0u8; 128];

    let written = outgoing.write_to(&mut wire).expect("FEC packet must serialize");
    let decoded = wire::parse_packet(&wire[..written]).expect("FEC packet must parse");

    assert_eq!(written, wire::HEADER_LEN + payload.len());
    assert_eq!(decoded.meta, meta);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn outgoing_systematic_packet_preserves_protected_quic_datagram() {
    let quic_payload = [0x40, 0x11, 0x22, 0x33];
    let mut protected_payload = Vec::with_capacity(wire::SOURCE_LENGTH_LEN + quic_payload.len());
    protected_payload.extend_from_slice(&(quic_payload.len() as u16).to_be_bytes());
    protected_payload.extend_from_slice(&quic_payload);
    let mut source_symbol = Vec::with_capacity(wire::SOURCE_LENGTH_LEN + protected_payload.len());
    source_symbol.extend_from_slice(&(protected_payload.len() as u16).to_be_bytes());
    source_symbol.extend_from_slice(&protected_payload);
    let meta = WirePacketMeta {
        profile: WireProfile {
            epoch: 1,
            codec: wire::WireCodec::Gf8,
            source_count: 4,
            total_count: 7,
            interleave_depth: 1,
        },
        window: 0,
        sequence: 0,
        repair_index: wire::SYSTEMATIC_REPAIR_INDEX,
        block_index: 0,
        systematic: true,
        sliding: false,
    };
    let outgoing = OutgoingFecPacket {
        packet: fec_packet(0, &source_symbol, None),
        wire_meta: Some(meta),
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    };
    let mut wire_datagram = [0u8; 128];

    let written = outgoing.write_to(&mut wire_datagram).expect("FEC packet must serialize");
    let decoded = wire::parse_packet(&wire_datagram[..written]).expect("FEC packet must parse");
    let mut receiver = WireFecReceiver::new(crate::optimize::global_pool());
    let mut output = Vec::new();
    let report =
        receiver.receive(&wire_datagram[..written], &mut output).expect("FEC packet must decode");

    assert_eq!(decoded.meta, meta);
    assert_eq!(decoded.payload, protected_payload);
    assert_eq!(report.source_payload_bytes, quic_payload.len());
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].payload_slice(), Some(&quic_payload[..]));
}

/// A queued FEC packet must survive a failed write instead of being silently discarded.
///
/// The send path previously popped the packet before `write_to()` could fail, so an
/// output-capacity failure lost application data while backpressure counters stayed at zero.
#[test]
fn buffered_fec_packet_survives_an_output_capacity_failure() {
    let mut connection = test_connection();
    *connection.conn = crate::transport::connection::bench_paired_1rtt_connections().client;

    let payload = [0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(7, &payload, None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(8, &payload, None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });

    // A buffer far too small for the packet forces the write to fail.
    let mut tiny = [0u8; 2];
    assert!(
        connection.send_with_info(&mut tiny).is_err(),
        "an undersized output buffer must fail rather than truncate"
    );
    assert_eq!(
        connection.outgoing_fec_packets.len(),
        2,
        "a failed write must leave both packets queued"
    );

    // The retry with adequate capacity emits the same first packet, preserving FIFO order.
    let mut wire = [0u8; 2048];
    let (written, _) = connection.send_with_info(&mut wire).expect("retry must succeed");
    assert!(written > 0);
    assert_eq!(
        connection.outgoing_fec_packets.len(),
        1,
        "exactly one packet is committed per successful send"
    );

    let (second, _) = connection.send_with_info(&mut wire).expect("second retry");
    assert!(second > 0);
    assert!(
        connection.outgoing_fec_packets.is_empty(),
        "the queue drains in order once capacity allows"
    );
}

#[test]
fn pending_path_control_preempts_buffered_fec_datagram() {
    let mut connection = test_connection();
    *connection.conn = crate::transport::connection::bench_paired_1rtt_connections().client;
    let new_local: SocketAddr = "127.0.0.1:29103".parse().unwrap();
    let new_peer: SocketAddr = "127.0.0.1:29104".parse().unwrap();
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(99, &[0x40, 0x01, 0x02, 0x03], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    connection.conn.migrate(new_local, new_peer).expect("migration candidate");
    assert_eq!(
        connection
            .conn
            .pending_path_validation_for_test()
            .map(|(_, local, peer, _)| { (local, peer) }),
        Some((new_local, new_peer))
    );
    assert!(connection.conn.has_sendable_path_control());
    let mut wire = [0u8; 2048];

    let (written, send_info) =
        connection.send_with_info(&mut wire).expect("path control must serialize");

    assert!(written > 0);
    assert_eq!(
        (
            send_info.from,
            send_info.to,
            send_info.path_control,
            connection.conn.has_sendable_path_control(),
            connection.outgoing_fec_packets.len(),
        ),
        (new_local, new_peer, true, false, 1)
    );
    assert!(!wire::is_framed(&wire[..written]));
}

/// TODO-1006 end-to-end at connection scope: a decoder recovery on the
/// reporter side drains into one repair-ACK wire datagram, and the peer
/// consumes it as an unmasked wire loss for congestion control and the
/// adaptive-FEC callback counters.
#[test]
fn repair_ack_round_trip_reports_masked_wire_loss_to_cc() {
    let mut reporter = test_connection_with(StealthConfig::performance());
    let mut sender = test_connection_with(StealthConfig::performance());
    let profile = WireProfile {
        epoch: 11,
        codec: wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 6,
        interleave_depth: 1,
    };
    let pool = reporter.optimization_manager.memory_pool();
    let sources = [vec![0x10u8; 31], vec![0x20; 47], vec![0x30; 63], vec![0x40; 79]];
    let protected: Vec<Vec<u8>> = sources.iter().map(|source| protected_datagram(source)).collect();
    let mut encoder = qf_fec::Encoder8::new(4, 6);
    for (id, protected_source) in protected.iter().enumerate() {
        // The encoder codes source symbols (length prefix + protected
        // datagram); the wire carries only the protected datagram.
        let mut symbol_buf = vec![0u8; wire::SOURCE_LENGTH_LEN + protected_source.len()];
        let symbol_len =
            wire::write_source_symbol(protected_source, &mut symbol_buf).expect("source symbol");
        encoder.take_packet(fec_packet(id as u64, &symbol_buf[..symbol_len], None));
    }
    let repair = encoder.generate_repair_packet(0, &pool).expect("repair packet");

    // Sources 0, 2, 3 arrive framed; source 1 is the wire loss the
    // decoder repairs - exactly the masked-loss case from TODO-1006.
    // `framed_wire_report` drives the wire receiver directly so the test
    // does not need deliverable QUIC payloads.
    let mut wire_buf = vec![0u8; 256];
    let mut scratch = Vec::new();
    for source_id in [0usize, 2, 3] {
        let meta = WirePacketMeta {
            profile,
            window: 0,
            sequence: source_id as u64,
            repair_index: wire::SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
            sliding: false,
        };
        let written =
            wire::write_packet(meta, &protected[source_id], &mut wire_buf).expect("source wire");
        reporter.framed_wire_report(&wire_buf[..written], &mut scratch).expect("source receive");
    }
    let repair_meta = WirePacketMeta {
        profile,
        window: 0,
        sequence: repair.id,
        repair_index: 0,
        block_index: 0,
        systematic: false,
        sliding: false,
    };
    let repair_payload = repair.payload_slice().expect("repair payload").to_vec();
    let written = wire::write_packet(repair_meta, &repair_payload, &mut wire_buf).expect("repair");
    let mut decoded = Vec::new();
    reporter.fec_wire_receiver.receive(&wire_buf[..written], &mut decoded).expect("repair receive");

    assert!(reporter.fec_wire_receiver.has_pending_recovered());

    // The production call site gates on `is_established`, which needs a
    // completed TLS handshake the bench pair does not have; the enqueue +
    // emission mechanics under test are identical.
    reporter.enqueue_repair_ack_report().expect("enqueue report");
    assert!(!reporter.fec_wire_receiver.has_pending_recovered());

    let mut out = [0u8; 2048];
    let mut report_len = None;
    for _ in 0..8 {
        let (written, _info) = reporter.send_with_info(&mut out).expect("send poll");
        if wire::is_repair_ack(&out[..written]) {
            report_len = Some(written);
            break;
        }
    }
    let written = report_len.expect("emitted datagrams must include the repair-ACK report");
    let parsed = wire::parse_repair_ack(&out[..written]).expect("report parses");
    assert_eq!(
        parsed.entries().collect::<Vec<_>>(),
        [wire::RepairAckEntry { id: 1, payload_len: sources[1].len() as u16 }]
    );

    // Sender side: the report's epoch must match the active send profile.
    // Baseline first: the bench pair's own recovery can already hold
    // declared losses - the report must add exactly the one recovery.
    sender.fec_tx_profile = Some(profile);
    let baseline = sender.conn.take_fec_callback_feedback().lost_packets;
    sender
        .recv_on_path(&out[..written], sender.peer_addr, sender.local_addr)
        .expect("repair-ack consume");
    let feedback = sender.conn.take_fec_callback_feedback();
    assert_eq!(
        feedback.lost_packets,
        baseline + 1,
        "the recovered wire loss must reach the sender-side loss accounting"
    );
}

/// A report stamped with an epoch the sender already rotated away from
/// must be dropped without touching loss accounting (TODO-1006).
#[test]
fn repair_ack_stale_epoch_is_dropped() {
    let mut sender = test_connection_with(StealthConfig::performance());
    sender.fec_tx_profile = Some(WireProfile {
        epoch: 12,
        codec: wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 6,
        interleave_depth: 1,
    });
    let mut out = [0u8; 128];
    let entries = [wire::RepairAckEntry { id: 1, payload_len: 1200 }];
    let written = wire::write_repair_ack(11, &entries, &mut out).expect("repair ack");
    let baseline = sender.conn.take_fec_callback_feedback().lost_packets;
    sender
        .recv_on_path(&out[..written], sender.peer_addr, sender.local_addr)
        .expect("stale consume");
    assert_eq!(sender.conn.take_fec_callback_feedback().lost_packets, baseline);
}

#[test]
fn path_control_metadata_survives_raw_fec_queueing() {
    let payload = [0x40, 0x01, 0x02, 0x03];
    let mut send_info = test_send_info();
    send_info.path_control = true;
    let outgoing = OutgoingFecPacket {
        packet: fec_packet(99, &payload, None),
        wire_meta: None,
        send_info,
        congestion_controlled: true,
        paired: false,
    };
    let mut wire = [0u8; 64];

    let written = outgoing.write_to(&mut wire).expect("path control packet must serialize");

    assert_eq!(&wire[..written], &payload);
    assert!(!wire::is_framed(&wire[..written]));
    assert!(outgoing.send_info.path_control);
}

#[test]
fn path_control_bypass_moves_reserved_quic_datagram_and_disables_fec() {
    let profile = WireProfile {
        epoch: 1,
        codec: wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 7,
        interleave_depth: 1,
    };
    let payload = [0x40, 0x01, 0x02, 0x03];
    let mut send_buffer = [0xAA; 64];
    let quic_offset = 2 * wire::SOURCE_LENGTH_LEN;
    send_buffer[quic_offset..quic_offset + payload.len()].copy_from_slice(&payload);
    let mut send_info = test_send_info();
    send_info.path_control = true;

    let effective_profile = QuicFuscateConnection::strip_framing_headroom(
        Some(profile),
        send_info.path_control || send_info.bulk_only,
        &mut send_buffer,
        payload.len(),
    )
    .expect("path control bypass");

    assert!(effective_profile.is_none());
    assert_eq!(&send_buffer[..payload.len()], &payload);
}

#[test]
fn bulk_only_strips_framing_headroom_and_disables_fec() {
    let profile = WireProfile {
        epoch: 1,
        codec: wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 7,
        interleave_depth: 1,
    };
    let payload = [0x40, 0x01, 0x02, 0x03];
    let mut send_buffer = [0xAA; 64];
    let quic_offset = 2 * wire::SOURCE_LENGTH_LEN;
    send_buffer[quic_offset..quic_offset + payload.len()].copy_from_slice(&payload);
    let mut send_info = test_send_info();
    send_info.bulk_only = true;

    let effective_profile = QuicFuscateConnection::strip_framing_headroom(
        Some(profile),
        send_info.path_control || send_info.bulk_only,
        &mut send_buffer,
        payload.len(),
    )
    .expect("bulk-only unframing");

    assert!(effective_profile.is_none());
    assert_eq!(&send_buffer[..payload.len()], &payload);
}

#[test]
fn active_fec_off_preserves_queued_sources_and_discards_only_repairs() {
    let mut connection = test_connection();
    let profile = WireProfile {
        epoch: 9,
        codec: wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 7,
        interleave_depth: 1,
    };
    for (id, systematic) in [(10, true), (11, false), (12, true)] {
        connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
            packet: fec_packet(id, &[id as u8; 8], (!systematic).then_some(&[1, 2, 3, 4])),
            wire_meta: Some(WirePacketMeta {
                profile,
                window: 2,
                sequence: id,
                repair_index: if systematic { wire::SYSTEMATIC_REPAIR_INDEX } else { 0 },
                block_index: 0,
                systematic,
                sliding: false,
            }),
            send_info: test_send_info(),
            congestion_controlled: true,
            paired: false,
        });
    }
    connection.fec_tx_profile = Some(profile);
    connection.fec_tx_sequence = 13;
    connection.fec_tx_active = true;
    let expected_sources = connection
        .outgoing_fec_packets
        .iter()
        .filter(|packet| packet.wire_meta.is_some_and(|meta| meta.systematic))
        .map(|packet| {
            (
                packet.packet.id,
                packet.packet.payload_slice().expect("queued source payload").to_vec(),
            )
        })
        .collect::<Vec<_>>();

    let change = connection.set_fec_control_policy(crate::fec::FecControlPolicy::Off);

    assert_eq!(change.queued_sources_preserved, 2);
    assert_eq!(change.queued_repairs_discarded, 1);
    assert_eq!(connection.outgoing_fec_packets.len(), 2);
    assert!(connection
        .outgoing_fec_packets
        .iter()
        .all(|packet| packet.wire_meta.is_some_and(|meta| meta.systematic)));
    let retained_sources = connection
        .outgoing_fec_packets
        .iter()
        .map(|packet| {
            (
                packet.packet.id,
                packet.packet.payload_slice().expect("retained source payload").to_vec(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(retained_sources, expected_sources);
    assert_eq!(connection.fec.control_policy(), crate::fec::FecControlPolicy::Off);
    assert_eq!(connection.fec.current_mode(), crate::fec::FecMode::Zero);
    assert!(connection.fec_tx_profile.is_none());
    assert_eq!(connection.fec_tx_sequence, 0);
    assert!(!connection.fec_tx_active);
}

#[test]
fn active_fec_policy_commands_are_last_wins_and_idempotent() {
    let mut connection = test_connection();

    let off = connection.set_fec_control_policy(crate::fec::FecControlPolicy::Off);
    let repeated_off = connection.set_fec_control_policy(crate::fec::FecControlPolicy::Off);
    let auto = connection.set_fec_control_policy(crate::fec::FecControlPolicy::Auto);

    assert_eq!(off.controller.effective_policy, crate::fec::FecControlPolicy::Off);
    assert_eq!(repeated_off.controller.previous_policy, crate::fec::FecControlPolicy::Off);
    assert_eq!(repeated_off.queued_repairs_discarded, 0);
    assert_eq!(auto.controller.effective_policy, crate::fec::FecControlPolicy::Auto);
    assert_eq!(auto.controller.effective_mode, crate::fec::FecMode::Zero);
    assert_eq!(connection.fec.control_policy(), crate::fec::FecControlPolicy::Auto);
}

#[test]
fn connection_mutex_serializes_concurrent_fec_commands_with_last_accepted_winning() {
    let connection = Arc::new(parking_lot::Mutex::new(test_connection()));
    let (off_done_tx, off_done_rx) = std::sync::mpsc::channel();
    let off_connection = Arc::clone(&connection);
    let off_thread = std::thread::spawn(move || {
        let change =
            off_connection.lock().set_fec_control_policy(crate::fec::FecControlPolicy::Off);
        off_done_tx.send(change).expect("publish Off acknowledgement");
    });
    let auto_connection = Arc::clone(&connection);
    let auto_thread = std::thread::spawn(move || {
        let off = off_done_rx.recv().expect("wait for accepted Off command");
        assert_eq!(off.controller.effective_policy, crate::fec::FecControlPolicy::Off);
        auto_connection.lock().set_fec_control_policy(crate::fec::FecControlPolicy::Auto)
    });

    off_thread.join().expect("Off command thread");
    let auto = auto_thread.join().expect("Auto command thread");
    let snapshot = connection.lock().fec_telemetry_snapshot();

    assert_eq!(auto.controller.previous_policy, crate::fec::FecControlPolicy::Off);
    assert_eq!(auto.controller.effective_policy, crate::fec::FecControlPolicy::Auto);
    assert_eq!(snapshot.control_policy, crate::fec::FecControlPolicy::Auto);
    assert_eq!(snapshot.active_mode, crate::fec::FecMode::Zero);
    assert_eq!(snapshot.policy_transitions, 2);
}

#[test]
fn connection_stats_congestion_update_window_rotation() {
    let mut stats = ConnectionStats::default();
    let cap = transport_accel::CONGESTION_WINDOW_SIZE;
    for i in 0..(cap + 5) {
        let sample = CongestionSample {
            cwnd: (i as u32) * 1000,
            bytes_in_flight: (i as u32) * 500,
            delivery_rate: (i as u32) * 100,
            lost_packets: i as u32,
        };
        stats.record_congestion_sample(sample);
    }
    assert_eq!(stats.congestion_sample_count(), cap);
}

#[test]
fn env_optional_trimmed_returns_none_for_missing() {
    let result =
        QuicFuscateConnection::env_optional_trimmed("QUICFUSCATE_TEST_NONEXISTENT_VAR_XYZ");
    assert!(result.is_none());
}

#[test]
fn env_optional_trimmed_trims_whitespace() {
    let _env_lock = crate::env_utils::test_support::acquire_env_lock();
    let key = "QUICFUSCATE_TEST_TRIM_WS";
    std::env::set_var(key, "  hello  ");
    let result = QuicFuscateConnection::env_optional_trimmed(key);
    assert_eq!(result, Some("hello".to_string()));
    std::env::remove_var(key);
}

#[test]
fn env_optional_trimmed_returns_none_for_empty() {
    let _env_lock = crate::env_utils::test_support::acquire_env_lock();
    let key = "QUICFUSCATE_TEST_TRIM_EMPTY";
    std::env::set_var(key, "   ");
    let result = QuicFuscateConnection::env_optional_trimmed(key);
    assert!(result.is_none());
    std::env::remove_var(key);
}

#[test]
fn inject_qkey_auth_header_adds_header() {
    let mut headers = vec![];
    QuicFuscateConnection::inject_qkey_auth_header(Some("abc123"), &mut headers);
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].name(), b"x-qf-auth");
    assert_eq!(headers[0].value(), b"abc123");
}

#[test]
fn inject_qkey_auth_header_skips_empty_token() {
    let mut headers = vec![];
    QuicFuscateConnection::inject_qkey_auth_header(Some("  "), &mut headers);
    assert!(headers.is_empty());
}

#[test]
fn inject_qkey_auth_header_replaces_existing() {
    let mut headers = vec![
        crate::transport::h3::Header::new(b"x-qf-auth", b"old"),
        crate::transport::h3::Header::new(b"content-type", b"text"),
    ];
    QuicFuscateConnection::inject_qkey_auth_header(Some("new_token"), &mut headers);
    assert_eq!(headers.len(), 2);
    let auth = headers.iter().find(|h| h.name() == b"x-qf-auth").unwrap();
    assert_eq!(auth.value(), b"new_token");
}

#[test]
fn inject_qkey_auth_header_noop_without_token() {
    let mut headers = vec![crate::transport::h3::Header::new(b"host", b"example.com")];
    QuicFuscateConnection::inject_qkey_auth_header(None, &mut headers);
    assert_eq!(headers.len(), 1);
}

#[test]
fn outbound_stealth_release_merges_to_single_latest_deadline() {
    let now = Instant::now();
    let manager_delay = Duration::from_millis(8);
    let transport_jitter = Duration::from_millis(3);
    let release = QuicFuscateConnection::compute_outbound_stealth_release(
        now,
        Some(manager_delay),
        Some(transport_jitter),
    )
    .expect("both delays should produce a release");
    assert_eq!(release, now + manager_delay);

    let jitter_only =
        QuicFuscateConnection::compute_outbound_stealth_release(now, None, Some(transport_jitter))
            .expect("transport jitter alone should schedule release");
    assert_eq!(jitter_only, now + transport_jitter);
}

#[test]
fn outbound_stealth_release_none_when_no_delays() {
    let now = Instant::now();
    assert!(QuicFuscateConnection::compute_outbound_stealth_release(now, None, None).is_none());
}

#[test]
fn outbound_pacer_releases_one_quantum_at_estimated_rate() {
    let now = Instant::now();
    let mut pacer = OutboundPacer::default();

    pacer.record_send(now, 1500, 4500, 3_000_000);
    pacer.record_send(now, 1500, 4500, 3_000_000);
    assert!(!pacer.is_blocked(now));

    pacer.record_send(now, 1500, 4500, 3_000_000);
    assert!(pacer.is_blocked(now + Duration::from_micros(1499)));
    assert!(!pacer.is_blocked(now + Duration::from_micros(1500)));
}

#[test]
fn next_send_deadline_includes_outer_pacer_release() {
    let mut connection = test_connection();
    let now = Instant::now();
    connection.outbound_pacer.next_release = Some(now);
    let recovery_deadline = connection.conn.recovery_deadline();

    assert_eq!(connection.next_outbound_release_deadline(), Some(now));
    assert_eq!(
        connection.next_send_deadline(),
        Some(recovery_deadline.map_or(now, |d| now.min(d)))
    );
}

#[test]
fn next_send_deadline_includes_full_padding_cadence() {
    let mut connection = test_connection();
    *connection.conn = crate::transport::connection::bench_paired_1rtt_connections().client;
    connection
        .conn
        .apply_traffic_analysis_policy(crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1500,
            constant_rate_pps: 0,
            idle_timeout_ms: 60_000,
            ramp_down_ms: 5_000,
        })
        .expect("valid full-padding policy");
    let traffic_deadline =
        connection.conn.traffic_analysis_deadline().expect("traffic-analysis deadline");
    let recovery_deadline = connection.conn.recovery_deadline();

    assert!(recovery_deadline.is_none_or(|deadline| traffic_deadline < deadline));
    assert_eq!(connection.next_send_deadline(), Some(traffic_deadline));
}

#[test]
fn next_send_deadline_includes_tls_handshake_readiness() {
    let mut connection = test_connection();
    connection.conn.enable_tls("unified").expect("unified TLS provider");
    let mut profile = qf_stealth::TlsProfile::chrome_130();
    // Wide margin: the provider clock is the real system clock, and a stalled
    // CI scheduler slice could otherwise eat a sub-second window between
    // configure_tls and the readiness read (observed as a CI flake).
    profile.timing_jitter = Some(Duration::from_secs(30));
    connection.conn.configure_tls(&profile, "example.com").expect("TLS profile");

    let ready_at = connection
        .conn
        .handshake_send_ready_at()
        .expect("profile jitter must arm a handshake readiness deadline");

    assert!(ready_at > Instant::now());
    assert_eq!(connection.next_send_deadline(), Some(ready_at));
}

#[test]
fn outbound_pacer_reset_removes_release_and_partial_burst() {
    let now = Instant::now();
    let mut pacer = OutboundPacer::default();
    pacer.record_send(now, 4500, 4500, 1_000_000);

    pacer.reset();

    assert!(!pacer.is_blocked(now));
    assert_eq!(pacer.burst_bytes, 0);
    assert!(pacer.burst_last_at.is_none());
    assert!(pacer.next_release.is_none());
}

#[test]
fn outbound_pacer_decays_partial_burst_after_elapsed_time() {
    let now = Instant::now();
    let mut pacer = OutboundPacer::default();

    pacer.record_send(now, 4_000, 4_500, 1_000_000);
    pacer.record_send(now + Duration::from_millis(2), 1_000, 4_500, 1_000_000);

    assert!(pacer.next_release.is_none());
    assert_eq!(pacer.burst_bytes, 3_000);
}

// ---------------------------------------------------------------------------
// TODO-1015: ChameleonFlow bounded reorder window on bulk datagrams
// ---------------------------------------------------------------------------

fn bulk_send_info() -> crate::transport::SendInfo {
    let mut info = test_send_info();
    info.bulk_only = true;
    info
}

#[test]
fn reorder_window_permutates_ripe_bulk_run() {
    let mut connection = test_connection();
    // Join-time swaps permute the bulk run while every displacement
    // stays bounded to <= 1 position: each packet's join index vs its
    // final queue position must never differ by more than one slot -
    // the invariant that keeps reorder below QUIC's packet-threshold
    // loss detection (k = 3, TODO-1017). Over 64 trains the fair coin
    // must fire at least once and the order must actually change.
    let mut saw_permutation = false;
    for _ in 0..64 {
        connection.outgoing_fec_packets.clear();
        for id in 0..6u64 {
            connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
                packet: fec_packet(id, &[id as u8; 8], None),
                wire_meta: None,
                send_info: bulk_send_info(),
                congestion_controlled: true,
                paired: false,
            });
            connection.pair_swap_on_join();
        }
        for (position, entry) in connection.outgoing_fec_packets.iter().enumerate() {
            let join_index = entry.packet.id as usize;
            assert!(
                position.abs_diff(join_index) <= 1,
                "reorder displacement must stay below the loss threshold"
            );
            if position != join_index {
                saw_permutation = true;
            }
        }
    }
    assert!(saw_permutation, "the fair coin must swap at least once over 64 trains");
}

#[test]
fn reorder_paired_member_never_swaps_twice() {
    let mut connection = test_connection();
    // A `paired` entry already spent its one allowed swap: a fresh bulk
    // datagram joining behind it must not swap with it, so a displaced
    // packet can never slip a second position (TODO-1017).
    for (id, paired) in [(0u64, true), (1, true)] {
        connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
            packet: fec_packet(id, &[id as u8; 8], None),
            wire_meta: None,
            send_info: bulk_send_info(),
            congestion_controlled: true,
            paired,
        });
    }
    for _ in 0..64 {
        connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
            packet: fec_packet(99, &[0x99; 8], None),
            wire_meta: None,
            send_info: bulk_send_info(),
            congestion_controlled: true,
            paired: false,
        });
        connection.pair_swap_on_join();
        assert_eq!(
            connection.outgoing_fec_packets.back().map(|entry| entry.packet.id),
            Some(99),
            "a paired predecessor must not swap - the displaced member stays put"
        );
        connection.outgoing_fec_packets.pop_back();
    }
}

#[test]
fn reorder_window_control_head_keeps_fifo_priority() {
    let mut connection = test_connection();
    // A control/ACK queue head keeps strict FIFO priority even when a
    // bulk train joins behind it - swaps only ever touch bulk pairs, so
    // the non-bulk entry never leaves its absolute position.
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(1, &[0xAA; 8], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    for id in 2..6u64 {
        connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
            packet: fec_packet(id, &[id as u8; 8], None),
            wire_meta: None,
            send_info: bulk_send_info(),
            congestion_controlled: true,
            paired: false,
        });
        connection.pair_swap_on_join();
    }
    assert_eq!(
        connection.outgoing_fec_packets.front().map(|entry| entry.packet.id),
        Some(1),
        "a non-bulk head emits first no matter how the bulk train permutes"
    );
    // The bulk train behind it may permute but must keep every member
    // within one slot of its join index.
    for (position, entry) in connection.outgoing_fec_packets.iter().enumerate().skip(1) {
        assert!(position.abs_diff(entry.packet.id as usize - 1) <= 1);
    }
}

#[test]
fn deferral_window_opens_as_timer_and_surfaces_deadline() {
    let connection = test_connection();
    let now = Instant::now();
    let edge = now + Duration::from_millis(2);

    assert!(!connection.deferral_window_open(now), "no window armed yet");
    connection.bulk_window_release.set(Some(edge));

    assert!(
        connection.deferral_window_open(now),
        "an armed bulk window must stall production until its edge"
    );
    assert_eq!(
        connection.next_outbound_release_deadline(),
        Some(edge),
        "the runtime must wake at the window edge, not a fixed tick"
    );
    assert!(
        !connection.deferral_window_open(edge),
        "the window is consumed at its edge, never held past it"
    );

    // The stealth window participates in the same stall + deadline merge.
    connection.bulk_window_release.set(None);
    connection.stealth_window_release.set(Some(edge));
    assert!(connection.deferral_window_open(now));
    assert_eq!(connection.next_outbound_release_deadline(), Some(edge));
}

#[test]
fn reorder_window_tick_arms_gather_timer_not_packet_hold() {
    let mut connection = test_connection();
    let now = Instant::now();
    let bulk = bulk_send_info();

    // Disabled stealth timing never arms a window, even inside a burst.
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(9, &[0xCC; 8], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    connection.reorder_window_tick(&bulk, now);
    assert!(connection.bulk_window_release.get().is_none());

    // Enabled stealth timing still skips a lone bulk packet. The bench pair
    // runs with external pacing on, which gates the jitter path off.
    connection.conn.set_external_pacing(false);
    connection.conn.set_stealth_timing(true, 5_000);
    connection.outgoing_fec_packets.clear();
    connection.reorder_window_tick(&bulk, now);
    assert!(
        connection.bulk_window_release.get().is_none(),
        "a lone bulk packet pays latency with zero redistribution gain"
    );

    // With a queued burst the window arms, bounded by the ceiling. A zero
    // draw legitimately arms nothing (~1/3001 chance), so retry ticks.
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(10, &[0xDD; 8], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    let mut armed_at = None;
    for _ in 0..64 {
        if connection.bulk_window_release.get().is_none() {
            connection.reorder_window_tick(&bulk, now);
        }
        if let Some(edge) = connection.bulk_window_release.get() {
            armed_at = Some(edge);
            break;
        }
    }
    let edge = armed_at.expect("burst-context bulk must arm the gather window");
    assert!(edge > now);
    assert!(edge - now <= Duration::from_micros(QuicFuscateConnection::REORDER_HOLD_MAX_US));

    // A mid-window tick keeps the timer without re-arming or clearing.
    connection.reorder_window_tick(&bulk, now + Duration::from_micros(10));
    assert_eq!(connection.bulk_window_release.get(), Some(edge));
    assert!(!connection.burst_draining.get());

    // The first tick past the edge consumes the window and arms the drain
    // instead of opening a new window for that packet.
    connection.reorder_window_tick(&bulk, edge + Duration::from_micros(1));
    assert!(connection.bulk_window_release.get().is_none());
    assert!(connection.burst_draining.get(), "the edge must arm the drain phase");

    // Non-bulk traffic never arms a window even mid-burst.
    connection.burst_draining.set(false);
    connection.reorder_window_tick(&test_send_info(), now);
    assert!(connection.bulk_window_release.get().is_none());
}

#[test]
fn reorder_quiet_phase_blocks_immediate_rearming() {
    let mut connection = test_connection();
    connection.conn.set_external_pacing(false);
    connection.conn.set_stealth_timing(true, 5_000);
    let bulk = bulk_send_info();
    let now = Instant::now();
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(10, &[0xDD; 8], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });

    // Arm a window, then tick past its edge: the drain arms and the
    // quiet phase opens.
    let mut edge = None;
    for _ in 0..64 {
        if connection.bulk_window_release.get().is_none() {
            connection.reorder_window_tick(&bulk, now);
        }
        if let Some(e) = connection.bulk_window_release.get() {
            edge = Some(e);
            break;
        }
    }
    let edge = edge.expect("burst-context bulk must arm the gather window");
    connection.reorder_window_tick(&bulk, edge + Duration::from_micros(1));
    assert!(connection.burst_draining.get());
    let quiet_until =
        connection.reorder_quiet_until.get().expect("the window edge must open the quiet phase");
    assert!(quiet_until >= edge);

    // During the quiet phase no new window arms even with a live burst.
    connection.burst_draining.set(false);
    let mid_quiet = edge + Duration::from_nanos(500);
    assert!(mid_quiet < quiet_until);
    connection.reorder_window_tick(&bulk, mid_quiet);
    assert!(connection.bulk_window_release.get().is_none());
    assert!(!connection.burst_draining.get());

    // Once the quiet phase ends the train may gather again.
    let after_quiet = quiet_until + Duration::from_millis(1);
    connection.last_bulk_queued.set(Some(after_quiet));
    let mut rearmed = false;
    for _ in 0..64 {
        if connection.bulk_window_release.get().is_none() {
            connection.reorder_window_tick(&bulk, after_quiet);
        }
        if connection.bulk_window_release.get().is_some() {
            rearmed = true;
            break;
        }
    }
    assert!(rearmed, "a train after the quiet phase must be able to arm a window");
}

#[test]
fn reorder_window_marks_burst_trains_by_time() {
    let mut connection = test_connection();
    connection.conn.set_external_pacing(false);
    connection.conn.set_stealth_timing(true, 5_000);
    let bulk = bulk_send_info();
    let t0 = Instant::now();

    // Head of a train: nothing queued, no recent bulk -> no window.
    connection.reorder_window_tick(&bulk, t0);
    assert!(connection.bulk_window_release.get().is_none());

    // A follower inside REORDER_BURST_WINDOW joins the burst even with
    // empty queues - the timer gathers the train for the permuted drain.
    let t1 = t0 + Duration::from_millis(5);
    let mut armed = false;
    for _ in 0..64 {
        if connection.bulk_window_release.get().is_none() {
            connection.reorder_window_tick(&bulk, t1);
        }
        if connection.bulk_window_release.get().is_some() {
            armed = true;
            break;
        }
    }
    assert!(armed, "a train follower inside the window must arm the gather timer");

    // After a quiet gap beyond the window the next bulk is a new train
    // head and again passes without arming.
    connection.burst_draining.set(false);
    connection.bulk_window_release.set(None);
    let t2 = t1 + QuicFuscateConnection::REORDER_BURST_WINDOW + Duration::from_millis(5);
    connection.reorder_window_tick(&bulk, t2);
    assert!(connection.bulk_window_release.get().is_none());
}

#[test]
fn stealth_window_tick_arms_timer_and_edge_arms_drain() {
    let connection = test_connection();
    let now = Instant::now();
    let edge = now + Duration::from_millis(2);

    // No draw and a sub-granularity draw both arm nothing.
    connection.stealth_window_tick(None, now);
    connection.stealth_window_tick(Some(now + QuicFuscateConnection::STEALTH_MIN_WINDOW / 2), now);
    assert!(connection.stealth_window_release.get().is_none());

    // A real draw arms the gather timer; the packet itself rides out.
    connection.stealth_window_tick(Some(edge), now);
    assert_eq!(connection.stealth_window_release.get(), Some(edge));

    // Mid-window draws keep the shared edge instead of staggering per
    // packet deadlines.
    connection.stealth_window_tick(Some(now + Duration::from_millis(10)), now);
    assert_eq!(connection.stealth_window_release.get(), Some(edge));

    // The first tick past the edge consumes it and arms the drain.
    connection.stealth_window_tick(Some(edge + Duration::from_millis(5)), edge);
    assert!(connection.stealth_window_release.get().is_none());
    assert!(connection.burst_draining.get());

    // During the drain no new window arms - members ride the burst.
    connection.stealth_window_tick(Some(edge + Duration::from_millis(9)), edge);
    assert!(connection.stealth_window_release.get().is_none());
}

#[test]
fn empty_transport_backlog_ends_the_drain_epoch() {
    let mut connection = test_connection();
    connection.burst_draining.set(true);
    connection.drain_budget.set(4);
    let mut wire = [0u8; 2048];
    // The bench transport has nothing pending: send_with_info hits the
    // transport-Done path, which must release the drain flag once the
    // backlog is actually empty.
    let _ = connection.send_with_info(&mut wire);
    assert!(!connection.burst_draining.get(), "an emptied backlog ends the drain epoch");
}

#[test]
fn reorder_window_tick_arms_under_committed_wire_fec() {
    let mut connection = test_connection();
    connection.conn.set_external_pacing(false);
    connection.conn.set_stealth_timing(true, 5_000);
    let now = Instant::now();
    let framed = test_send_info();
    assert!(!framed.bulk_only);
    assert!(framed.congestion_controlled);

    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(10, &[0xDD; 8], None),
        wire_meta: Some(WirePacketMeta {
            profile: WireProfile {
                epoch: 1,
                codec: wire::WireCodec::StreamingGf8,
                source_count: 4,
                total_count: 8,
                interleave_depth: 1,
            },
            window: 0,
            sequence: 0,
            repair_index: wire::SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
            sliding: false,
        }),
        send_info: framed,
        congestion_controlled: true,
        paired: false,
    });

    connection.reorder_window_tick(&framed, now);
    assert!(
        connection.bulk_window_release.get().is_none(),
        "raw-path bulk_only gate must not arm framed FEC traffic"
    );

    let mut armed_at = None;
    for _ in 0..64 {
        if connection.bulk_window_release.get().is_none() {
            connection.reorder_window_tick_framed_source(&framed, now);
        }
        if let Some(edge) = connection.bulk_window_release.get() {
            armed_at = Some(edge);
            break;
        }
    }
    let edge = armed_at.expect("committed wire-FEC systematic burst must arm the gather window");
    assert!(edge > now);
    assert!(edge - now <= Duration::from_micros(QuicFuscateConnection::REORDER_HOLD_MAX_US));

    connection.bulk_window_release.set(None);
    let mut path_control = framed;
    path_control.path_control = true;
    connection.reorder_window_tick_framed_source(&path_control, now);
    assert!(
        connection.bulk_window_release.get().is_none(),
        "path-control framed packets must never arm a reorder window"
    );

    let mut repair_like = framed;
    repair_like.congestion_controlled = false;
    connection.reorder_window_tick_framed_source(&repair_like, now);
    assert!(
        connection.bulk_window_release.get().is_none(),
        "repairs must never arm or extend the gather window"
    );
}

fn enqueue_dgrams(connection: &mut QuicFuscateConnection, n: usize) {
    for _ in 0..n {
        connection.conn.dgram_send_parts(b"", b"pressure-probe").expect("dgram enqueue");
    }
}

#[test]
fn deferral_window_skips_arm_under_dgram_pressure() {
    let mut connection = test_connection();
    connection.conn.set_external_pacing(false);
    connection.conn.set_stealth_timing(true, 5_000);
    let bulk = bulk_send_info();
    let now = Instant::now();
    connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
        packet: fec_packet(10, &[0xDD; 8], None),
        wire_meta: None,
        send_info: test_send_info(),
        congestion_controlled: true,
        paired: false,
    });
    enqueue_dgrams(&mut connection, QuicFuscateConnection::WINDOW_PRESSURE_DEPTH);
    assert!(connection.gather_pressure());

    for _ in 0..64 {
        connection.reorder_window_tick(&bulk, now);
    }
    assert!(
        connection.bulk_window_release.get().is_none(),
        "a gathered train must FIFO-drain instead of arming another stall"
    );

    connection.stealth_window_tick(Some(now + Duration::from_millis(2)), now);
    assert!(
        connection.stealth_window_release.get().is_none(),
        "stealth jitter must not stall on top of an already-gathered train"
    );
}

#[test]
fn stealth_window_edge_opens_shared_quiet_phase() {
    let connection = test_connection();
    let now = Instant::now();
    let edge = now + Duration::from_millis(2);

    connection.stealth_window_tick(Some(edge), now);
    assert_eq!(connection.stealth_window_release.get(), Some(edge));

    connection.stealth_window_tick(Some(edge + Duration::from_millis(5)), edge);
    assert!(connection.stealth_window_release.get().is_none());
    assert!(connection.burst_draining.get());
    let quiet_until =
        connection.reorder_quiet_until.get().expect("stealth edge must share the quiet phase");
    assert!(quiet_until >= edge);

    connection.burst_draining.set(false);
    let mid_quiet = edge + Duration::from_nanos(500);
    assert!(mid_quiet < quiet_until);
    connection.stealth_window_tick(Some(mid_quiet + Duration::from_millis(5)), mid_quiet);
    assert!(
        connection.stealth_window_release.get().is_none(),
        "stealth must not punch through the shared quiet gap"
    );
}

#[test]
fn drain_budget_refills_under_dgram_pressure() {
    let mut connection = test_connection();
    connection.burst_draining.set(true);
    connection.drain_budget.set(0);
    enqueue_dgrams(&mut connection, 20);
    connection.refresh_drain_budget();
    assert_eq!(connection.drain_budget.get(), 20);
}

#[test]
fn open_window_aborts_when_dgram_queue_hits_abort_depth() {
    let mut connection = test_connection();
    let now = Instant::now();
    connection.bulk_window_release.set(Some(now + Duration::from_millis(5)));
    enqueue_dgrams(&mut connection, QuicFuscateConnection::WINDOW_ABORT_DEPTH);
    connection.maybe_abort_window_under_pressure(now);
    assert!(connection.bulk_window_release.get().is_none());
    assert!(connection.burst_draining.get());
    assert!(connection.drain_budget.get() > 0);
}

#[test]
fn stealth_drops_cleartext_fec_wrapper() {
    let mut conn = test_connection();
    assert_eq!(conn.fec_framing(), crate::engine::FecFraming::QuicFrame);
    let packet = [0xF1u8, 0xEC, 0x01, 0x00];
    conn.recv_on_path(&packet, conn.peer_addr, conn.local_addr).expect("drop wrapper");
    assert_eq!(conn.fec_wrapper_drops(), 1);
    let mut performance = test_connection_with(StealthConfig::performance());
    assert_eq!(performance.fec_framing(), crate::engine::FecFraming::Wrapper);
    performance
        .recv_on_path(&packet, performance.peer_addr, performance.local_addr)
        .expect("wrapper mode still accepts the prefix");
    assert_eq!(performance.fec_wrapper_drops(), 0);
}

#[test]
fn quic_repair_from_previous_epoch_is_rejected() {
    let mut conn = test_connection();
    conn.fence_fec_symbol_epoch(8);
    let meta = wire::WirePacketMeta {
        profile: wire::WireProfile {
            epoch: 4,
            codec: wire::WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        },
        window: 0,
        sequence: 1,
        repair_index: wire::SYSTEMATIC_REPAIR_INDEX,
        block_index: 0,
        systematic: true,
        sliding: false,
    };
    let mut symbol = vec![0u8; wire::SYMBOL_HEADER_LEN + 4];
    let written = wire::write_symbol(meta, &[1, 2, 3, 4], &mut symbol).expect("symbol");
    let mut blob = vec![wire::QUIC_REPAIR_DISCRIMINATOR];
    blob.extend_from_slice(&symbol[..written]);
    conn.conn.enqueue_received_datagram(std::borrow::Cow::Borrowed(&blob));
    conn.absorb_quic_fec_datagrams();
    assert_eq!(conn.fec_epoch_rejects(), 1);
    assert_eq!(conn.conn.dgram_recv_queue_len(), 0);
}
