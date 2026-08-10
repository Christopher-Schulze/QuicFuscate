#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> QuicFuscateConnection {
        let pair = crate::transport::connection::bench_paired_1rtt_connections();
        let optimization_manager =
            Arc::new(OptimizationManager::from_cfg(OptimizeConfig::default()));
        let stealth_manager = Arc::new(StealthManager::new(
            StealthConfig::default(),
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
        FecPacket::new(
            id,
            Some(data),
            payload.len(),
            coefficients.is_none(),
            coeffs,
            coeff_len,
            pool,
        )
    }

    fn test_send_info() -> crate::transport::SendInfo {
        crate::transport::SendInfo {
            from: "127.0.0.1:29101".parse().unwrap(),
            to: "127.0.0.1:29102".parse().unwrap(),
            at: Instant::now(),
            congestion_controlled: true,
            path_control: false,
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
        connection.qkey_auth_token_hex = Some(qf_engine_types::QKeyToken::from(
            "00112233445566778899aabbccddeeff",
        ));
        connection.set_client_connection_generation(47);

        let headers = connection.build_masque_request_headers();

        assert_eq!(headers.len(), 2);
        assert!(headers.iter().any(|header| {
            header.name() == b"x-qf-auth"
                && header.value() == b"00112233445566778899aabbccddeeff"
        }));
        assert!(headers.iter().any(|header| {
            header.name() == b"x-qf-generation" && header.value() == b"47"
        }));
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
    fn outgoing_zero_mode_packet_preserves_raw_quic_datagram() {
        let payload = [0x40, 0x11, 0x22, 0x33];
        let outgoing = OutgoingFecPacket {
            packet: fec_packet(7, &payload, None),
            wire_meta: None,
            send_info: test_send_info(),
            congestion_controlled: true,
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
        };
        let outgoing = OutgoingFecPacket {
            packet,
            wire_meta: Some(meta),
            send_info: test_send_info(),
            congestion_controlled: true,
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
        let mut protected_payload =
            Vec::with_capacity(wire::SOURCE_LENGTH_LEN + quic_payload.len());
        protected_payload.extend_from_slice(&(quic_payload.len() as u16).to_be_bytes());
        protected_payload.extend_from_slice(&quic_payload);
        let mut source_symbol =
            Vec::with_capacity(wire::SOURCE_LENGTH_LEN + protected_payload.len());
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
        };
        let outgoing = OutgoingFecPacket {
            packet: fec_packet(0, &source_symbol, None),
            wire_meta: Some(meta),
            send_info: test_send_info(),
            congestion_controlled: true,
        };
        let mut wire_datagram = [0u8; 128];

        let written = outgoing.write_to(&mut wire_datagram).expect("FEC packet must serialize");
        let decoded = wire::parse_packet(&wire_datagram[..written]).expect("FEC packet must parse");
        let mut receiver = WireFecReceiver::new(crate::optimize::global_pool());
        let mut output = Vec::new();
        let report = receiver
            .receive(&wire_datagram[..written], &mut output)
            .expect("FEC packet must decode");

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
        });
        connection.outgoing_fec_packets.push_back(OutgoingFecPacket {
            packet: fec_packet(8, &payload, None),
            wire_meta: None,
            send_info: test_send_info(),
            congestion_controlled: true,
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

        let effective_profile = QuicFuscateConnection::bypass_fec_for_path_control(
            Some(profile),
            &send_info,
            &mut send_buffer,
            payload.len(),
        )
        .expect("path control bypass");

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
                }),
                send_info: test_send_info(),
                congestion_controlled: true,
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

        let jitter_only = QuicFuscateConnection::compute_outbound_stealth_release(
            now,
            None,
            Some(transport_jitter),
        )
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
}
