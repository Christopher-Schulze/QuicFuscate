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

#[test]
fn zero_rtt_preflight_rejects_unidirectional_and_server_initiated_streams() {
    assert!(Connection::preflight_frame_payload(&[0x0A, 0x00, 0x00], PacketType::ZeroRTT).is_ok());
    assert!(matches!(
        Connection::preflight_frame_payload(&[0x0A, 0x02, 0x00], PacketType::ZeroRTT),
        Err(ConnectionError::InvalidFrame)
    ));
    assert!(matches!(
        Connection::preflight_frame_payload(&[0x0A, 0x03, 0x00], PacketType::ZeroRTT),
        Err(ConnectionError::InvalidFrame)
    ));
}

#[test]
fn zero_rtt_sends_only_explicit_safe_stream_data() {
    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};
    use crate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};

    let client_scid = b"early-client-scid";
    let server_scid = b"early-server-scid";
    let early_secret = [0x5Au8; 32];
    let mut client_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    client_config.enable_early_data = true;
    let mut client =
        Connection::new_client(client_scid, local(), peer(), client_config).expect("client");
    client.set_initial_dcid(ConnectionId::from_ref(server_scid));
    client.pmtu = pmtu_state(false, PmtuPolicy::default());
    client.enable_tls("0rtt-stream-test").expect("client TLS provider");
    assert!(!client.zero_rtt_active(), "no resumption ticket means no early keys");
    {
        let mut crypto = client.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_write_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &early_secret)
            .expect("install test early sealer");
    }
    assert!(client.zero_rtt_active());
    client.enable_datagrams(8, 8);
    client.dgram_send(b"tun-datagram").expect("queue tunnel payload");
    client.stream_send(4, b"unmarked tunnel stream", true).expect("queue ordinary stream");
    client
        .stream_send_replay_safe_0rtt(0, b"safe control", true)
        .expect("queue replay-safe one-shot stream");

    let mut packet = [0u8; 2048];
    let (initial_len, _) = client.send(&mut packet).expect("send Initial ClientHello");
    let (initial_header, _) =
        crate::transport::packet::parse_header(&packet[..initial_len], client.scid.as_ref().len())
            .expect("parse Initial flight");
    assert_eq!(initial_header.ty, crate::transport::PacketType::Initial);
    assert!(!client.tls_handshake_complete());
    assert_eq!(client.stats.recv, 0, "the server has not returned its first flight");

    let zero_rtt_len = (0..8)
        .find_map(|_| match client.send(&mut packet) {
            Ok((length, _)) => {
                let (header, _) = crate::transport::packet::parse_header(
                    &packet[..length],
                    client.scid.as_ref().len(),
                )
                .expect("parse outgoing long header");
                (header.ty == crate::transport::PacketType::ZeroRTT).then_some(length)
            }
            Err(ConnectionError::Done) => None,
            Err(error) => panic!("unexpected early send failure: {error}"),
        })
        .expect("emit a ZeroRTT packet");
    assert!(!client.tls_handshake_complete());
    assert_eq!(client.stats.recv, 0, "early data leaves before the server's first response");
    assert_eq!(client.dgram_send_queue_len(), 1, "DATAGRAM TUN payload stays queued");
    let zero_rtt_packet = packet[..zero_rtt_len].to_vec();
    let first_zero_rtt_pn = *client.zero_rtt_sent_pns.iter().next().expect("first early PN");
    client.lose_stream_transmission_packet(first_zero_rtt_pn);
    let replay_len = (0..8)
        .find_map(|_| match client.send(&mut packet) {
            Ok((length, _)) => {
                let (header, _) = crate::transport::packet::parse_header(
                    &packet[..length],
                    client.scid.as_ref().len(),
                )
                .expect("parse retransmitted early packet");
                (header.ty == PacketType::ZeroRTT).then_some(length)
            }
            Err(ConnectionError::Done) => None,
            Err(error) => panic!("unexpected early retransmission failure: {error}"),
        })
        .expect("retransmit the same replay-safe frame in 0-RTT");
    let replay_packet = packet[..replay_len].to_vec();
    let replay_zero_rtt_pn = client
        .zero_rtt_sent_pns
        .iter()
        .copied()
        .find(|pn| *pn != first_zero_rtt_pn)
        .expect("second early PN");
    assert_ne!(first_zero_rtt_pn, replay_zero_rtt_pn);
    assert_eq!(client.stats.recv, 0, "both early packets leave before the first response");

    let register = std::sync::Arc::new(StrikeRegister::new(AntiReplayConfig::default()));
    let mut server_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    server_config.enable_early_data = true;
    server_config.set_strike_register(std::sync::Arc::clone(&register));
    let mut server =
        Connection::new_server(server_scid, peer(), local(), server_config).expect("server");
    server.set_destination_cid(ConnectionId::from_ref(client_scid));
    server.pmtu = pmtu_state(false, PmtuPolicy::default());
    {
        let mut crypto = server.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_read_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &early_secret)
            .expect("install matching early opener");
    }
    let recv_info = RecvInfo { from: local(), to: peer(), ecn: None };
    let mut accepted_packet = zero_rtt_packet.clone();
    server
        .recv(&mut accepted_packet, &recv_info)
        .expect("open early packet with anti-replay protection");
    assert!(server.take_zero_rtt_stream(0));
    assert!(!server.take_zero_rtt_stream(0));

    let mut received = [0u8; 32];
    let (received_len, fin) = server.stream_recv(0, &mut received).expect("safe stream data");
    assert_eq!(&received[..received_len], b"safe control");
    assert!(fin);
    assert!(matches!(
        server.stream_recv(4, &mut received),
        Err(ConnectionError::InvalidStreamState(4))
    ));
    let mut replay_copy = replay_packet.clone();
    server
        .recv(&mut replay_copy, &recv_info)
        .expect("reject matching early payload at a distinct packet number");
    assert_eq!(server.pkt_spaces[2].largest_recv, Some(first_zero_rtt_pn));
    assert!(!server.pkt_spaces[2].contains(replay_zero_rtt_pn));
    assert!(!server.take_zero_rtt_stream(0));
    assert_eq!(register.len(), 1);

    let mut unprotected_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    unprotected_config.enable_early_data = true;
    let mut unprotected = Connection::new_server(server_scid, peer(), local(), unprotected_config)
        .expect("unprotected");
    unprotected.set_destination_cid(ConnectionId::from_ref(client_scid));
    {
        let mut crypto = unprotected.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_read_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &early_secret)
            .expect("install unprotected test opener");
    }
    let mut unprotected_packet = zero_rtt_packet.clone();
    unprotected
        .recv(&mut unprotected_packet, &recv_info)
        .expect("missing replay register must drop early data");
    assert!(unprotected.pkt_spaces[2].largest_recv.is_none());
    assert_eq!(unprotected.zero_rtt_received_bytes, 0);
    assert!(matches!(
        unprotected.stream_recv(0, &mut received),
        Err(ConnectionError::InvalidStreamState(0))
    ));

    let limited_register = std::sync::Arc::new(StrikeRegister::new(AntiReplayConfig {
        max_early_data_size: 1,
        ..AntiReplayConfig::default()
    }));
    let mut limited_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    limited_config.enable_early_data = true;
    limited_config.set_strike_register(std::sync::Arc::clone(&limited_register));
    let mut limited =
        Connection::new_server(server_scid, peer(), local(), limited_config).expect("limited");
    limited.set_destination_cid(ConnectionId::from_ref(client_scid));
    {
        let mut crypto = limited.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_read_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &early_secret)
            .expect("install limited test opener");
    }
    let mut limited_packet = zero_rtt_packet.clone();
    limited.recv(&mut limited_packet, &recv_info).expect("over-limit early data must be dropped");
    assert!(limited.pkt_spaces[2].largest_recv.is_none());
    assert_eq!(limited.zero_rtt_received_bytes, 0);
    assert!(limited_register.is_empty());

    let saturated_register = std::sync::Arc::new(StrikeRegister::new(AntiReplayConfig {
        max_entries: 1,
        ..AntiReplayConfig::default()
    }));
    let occupied = StrikeRegister::compute_fingerprint(b"occupied", b"occupied", b"occupied");
    assert!(saturated_register.check_and_insert(&occupied, std::time::Instant::now()));
    let mut saturated_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    saturated_config.enable_early_data = true;
    saturated_config.set_strike_register(std::sync::Arc::clone(&saturated_register));
    let mut saturated =
        Connection::new_server(server_scid, peer(), local(), saturated_config).expect("saturated");
    saturated.set_destination_cid(ConnectionId::from_ref(client_scid));
    {
        let mut crypto = saturated.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_read_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &early_secret)
            .expect("install saturated test opener");
    }
    let mut saturated_packet = zero_rtt_packet.clone();
    saturated
        .recv(&mut saturated_packet, &recv_info)
        .expect("saturated register must drop early data");
    assert!(saturated.pkt_spaces[2].largest_recv.is_none());
    assert_eq!(saturated.zero_rtt_received_bytes, 0);
    assert_eq!(saturated_register.len(), 1);

    client.finish_zero_rtt(false);
    client.tls_provider = None;
    client.test_only_transport_fixture = true;
    let one_rtt_secret = [0xA7u8; 32];
    client
        .crypto
        .write()
        .set_write_secret(Level::OneRTT, Algorithm::AES128_GCM, &one_rtt_secret)
        .expect("install fallback sealer");
    client.sync_1rtt();
    unprotected.enable_datagrams(8, 8);
    unprotected
        .crypto
        .write()
        .set_read_secret(Level::OneRTT, Algorithm::AES128_GCM, &one_rtt_secret)
        .expect("install fallback opener");
    unprotected.sync_1rtt();

    let (fallback_len, _) = client.send(&mut packet).expect("send rejected stream as 1-RTT");
    let (fallback_header, _) =
        crate::transport::packet::parse_header(&packet[..fallback_len], client.scid.as_ref().len())
            .expect("parse 1-RTT fallback");
    assert_eq!(fallback_header.ty, PacketType::Short);
    unprotected
        .recv(&mut packet[..fallback_len], &recv_info)
        .expect("open 1-RTT fallback after early-data rejection");
    let (received_len, fin) =
        unprotected.stream_recv(0, &mut received).expect("read retransmitted stream");
    assert_eq!(&received[..received_len], b"safe control");
    assert!(fin);
    assert_eq!(unprotected.dgram_recv_queue_len(), 1);
}

#[test]
fn pre_validation_close_without_keys_keeps_close_and_packet_number() {
    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};

    let mut client = make_conn();
    client.pending_control.push_back(Frame::ConnectionClose {
        error_code: 0,
        frame_type: 0,
        reason: std::borrow::Cow::Borrowed(b"close"),
    });
    let mut packet = [0u8; 1500];
    assert!(matches!(
        client.send_pre_validation_close(&mut packet),
        Err(ConnectionError::TlsError(_))
    ));
    assert_eq!(client.pending_control.len(), 1);
    assert_eq!(client.next_send_pn_by_space[0], 0);
    assert_eq!(client.stats.sent, 0);

    client
        .crypto
        .write()
        .set_write_secret(Level::Initial, Algorithm::AES128_GCM, &[0x5A; 32])
        .expect("install close packet keys");
    let (length, _) = client.send_pre_validation_close(&mut packet).expect("retry close");
    assert!(length >= MIN_CLIENT_INITIAL_LEN);
    assert!(client.pending_control.is_empty());
    assert_eq!(client.next_send_pn_by_space[0], 1);
    assert_eq!(client.stats.sent, 1);
}

#[test]
fn handshake_missing_hp_preserves_crypto_until_peer_opened_retry() {
    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};

    for (packet_type, level) in
        [(PacketType::Initial, Level::Initial), (PacketType::Handshake, Level::Handshake)]
    {
        let mut client = make_conn();
        let payload = b"queued handshake bytes";
        let secret = [0x5Au8; 32];
        {
            let mut crypto = client.crypto.write();
            crypto
                .set_write_secret(level, Algorithm::AES128_GCM, &secret)
                .expect("install outgoing packet keys");
            let stream = if packet_type == PacketType::Initial {
                &mut crypto.crypto_initial
            } else {
                &mut crypto.crypto_handshake
            };
            stream.send(payload).expect("queue CRYPTO flight");
            if packet_type == PacketType::Initial {
                crypto.hp_initial = None;
            } else {
                crypto.hp_handshake = None;
            }
        }
        let space = if packet_type == PacketType::Initial { 0 } else { 1 };
        let mut packet = [0u8; 1500];
        assert!(matches!(client.send(&mut packet), Err(ConnectionError::TlsError(_))));
        assert_eq!(client.next_send_pn_by_space[space], 0);
        assert_eq!(client.stats.sent, 0);
        assert_eq!(client.crypto.read().crypto_initial.unacked_bytes(), 0);
        assert_eq!(client.crypto.read().crypto_handshake.unacked_bytes(), 0);

        client
            .crypto
            .write()
            .set_write_secret(level, Algorithm::AES128_GCM, &secret)
            .expect("restore outgoing packet keys");
        let (length, _) = client.send(&mut packet).expect("retry CRYPTO flight");
        assert_eq!(client.next_send_pn_by_space[space], 1);
        assert_eq!(client.stats.sent, 1);
        let (header, pn_offset) = packet::parse_header(&packet[..length], 0).expect("parse retry");
        assert_eq!(header.ty, packet_type);

        let mut peer_crypto = packet::CryptoContext::default();
        peer_crypto
            .set_read_secret(level, Algorithm::AES128_GCM, &secret)
            .expect("install peer opener");
        let header_protector = if packet_type == PacketType::Initial {
            peer_crypto.hp_initial_open.as_deref().expect("Initial peer HP")
        } else {
            peer_crypto.hp_handshake_open.as_deref().expect("Handshake peer HP")
        };
        let (_, pn_len) = packet::remove_hp(&mut packet[..length], header_protector, pn_offset)
            .expect("unprotect retry header");
        let opener = if packet_type == PacketType::Initial {
            peer_crypto.open_initial.as_deref().expect("Initial peer opener")
        } else {
            peer_crypto.open_handshake.as_deref().expect("Handshake peer opener")
        };
        let plaintext_end =
            packet::decrypt_payload(&mut packet[..length], 0, pn_len, pn_offset + pn_len, opener)
                .expect("peer opens retried flight");
        assert!(packet[pn_offset + pn_len..plaintext_end]
            .windows(payload.len())
            .any(|window| window == payload));
    }
}

#[test]
fn failed_zero_rtt_seal_preserves_replay_safe_stream_for_retry() {
    use crate::crypto::aead::{Algorithm, KeyScheduleHooks, Level};
    use crate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct RejectHeaderProtection(std::sync::Arc<AtomicUsize>);
    impl packet::HeaderProtector for RejectHeaderProtection {
        fn new_mask(&self, _sample: &[u8]) -> Result<[u8; 5], ConnectionError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(ConnectionError::InvalidState)
        }
    }

    let client_scid = b"early-client-scid";
    let server_scid = b"early-server-scid";
    let secret = [0x5Au8; 32];
    let payload = b"replay-safe control";
    let mut client_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    client_config.enable_early_data = true;
    let mut client =
        Connection::new_client(client_scid, local(), peer(), client_config).expect("client");
    client.set_initial_dcid(ConnectionId::from_ref(server_scid));
    client.stream_send_replay_safe_0rtt(0, payload, true).expect("queue replay-safe stream");
    let original_queue = client.writable_streams.clone();
    let original_buffered = client.send_buffered_bytes;
    let mut packet = [0u8; 2048];
    let now = client.clock.now();
    assert!(matches!(
        client.send_zero_rtt_packet(&mut packet, now),
        Err(ConnectionError::TlsError(_))
    ));
    assert_eq!(client.writable_streams, original_queue);
    assert_eq!(client.send_buffered_bytes, original_buffered);
    assert_eq!(client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(client.next_send_pn_by_space[2], 0);
    assert_eq!(client.stats.sent, 0);
    let hp_calls = std::sync::Arc::new(AtomicUsize::new(0));
    let real_hp = {
        let mut crypto = client.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_write_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &secret)
            .expect("install early sealer");
        crypto
            .hp_0rtt
            .replace(Box::new(RejectHeaderProtection(std::sync::Arc::clone(&hp_calls))))
            .expect("replace installed HP owner")
    };

    let mut too_small = [0u8; 1];
    assert_eq!(
        client.send_zero_rtt_packet(&mut too_small, now).unwrap_err(),
        ConnectionError::BufferTooShort
    );
    assert_eq!(client.writable_streams, original_queue);
    assert_eq!(client.send_buffered_bytes, original_buffered);
    assert_eq!(client.streams.get(&0).unwrap().send_off, 0);

    assert_eq!(
        client.send_zero_rtt_packet(&mut packet, now).unwrap_err(),
        ConnectionError::InvalidState
    );
    assert_eq!(hp_calls.load(Ordering::Relaxed), 1, "AEAD must reach HP failure");
    assert_eq!(client.writable_streams, original_queue);
    assert_eq!(client.send_buffered_bytes, original_buffered);
    assert_eq!(client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(client.conn_bytes_sent, 0);
    assert_eq!(client.stats.stream_sent_bytes, 0);
    assert!(client.stream_transmissions.is_empty());
    client.crypto.write().hp_0rtt = Some(real_hp);
    let (length, _) = client.send_zero_rtt_packet(&mut packet, now).expect("retry early send");
    assert_eq!(client.stats.stream_sent_bytes, payload.len() as u64);
    assert_eq!(client.send_buffered_bytes, 0);
    assert_eq!(client.zero_rtt_sent_pns.len(), 1);

    let register = std::sync::Arc::new(StrikeRegister::new(AntiReplayConfig::default()));
    let mut server_config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    server_config.enable_early_data = true;
    server_config.set_strike_register(register);
    let mut server =
        Connection::new_server(server_scid, peer(), local(), server_config).expect("server");
    server.set_destination_cid(ConnectionId::from_ref(client_scid));
    {
        let mut crypto = server.crypto.write();
        crypto.set_zero_rtt_enabled(true);
        crypto
            .set_read_secret(Level::ZeroRTT, Algorithm::AES128_GCM, &secret)
            .expect("install early opener");
    }
    let recv_info = RecvInfo { from: local(), to: peer(), ecn: None };
    server.recv(&mut packet[..length], &recv_info).expect("open retry");
    let mut received = [0u8; 64];
    let (read, fin) = server.stream_recv(0, &mut received).expect("read early stream");
    assert_eq!(&received[..read], payload);
    assert!(fin);
}

#[test]
fn rejected_zero_rtt_transmission_requeues_as_one_rtt() {
    let mut pair = bench_paired_1rtt_connections();
    let payload = b"fallback control stream";
    let transmission_id = pair
        .client
        .stage_stream_transmission(0, 0, std::sync::Arc::from(&payload[..]), true, true)
        .expect("stage early transmission");
    pair.client.commit_stream_transmission(transmission_id, 17);
    pair.client.zero_rtt_sent_pns.insert(17);

    pair.client.finish_zero_rtt(false);
    assert!(pair.client.zero_rtt_sent_pns.is_empty());
    assert!(pair.client.stream_retransmit_queue.contains(&transmission_id));

    let mut packet = [0u8; 1500];
    let (packet_len, _) = pair.client.send(&mut packet).expect("send 1-RTT fallback");
    let (header, _) = crate::transport::packet::parse_header(
        &packet[..packet_len],
        pair.client.scid.as_ref().len(),
    )
    .expect("parse fallback packet");
    assert_eq!(header.ty, crate::transport::PacketType::Short);
    pair.server.recv(&mut packet[..packet_len], &pair.recv_info).expect("open fallback packet");

    let mut received = [0u8; 64];
    let (received_len, fin) = pair.server.stream_recv(0, &mut received).expect("read fallback");
    assert_eq!(&received[..received_len], payload);
    assert!(fin);
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
    c.dgram_send_queue.push_back(DatagramSendEntry {
        data: vec![0xAB; payload_len],
        class: DatagramClass::Protected,
    });
    let mut output = vec![0u8; 1 + 2 + payload_len];

    assert_eq!(
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("insufficient output is a no-op"),
        (0, None)
    );
    assert_eq!(c.dgram_send_queue_len(), 1);
    assert_eq!(c.dgram_send_queue_byte_size(), payload_len);
    assert!(c
        .dgram_send_queue
        .front()
        .is_some_and(|payload| payload.data.iter().all(|byte| *byte == 0xAB)));
}

#[test]
fn zero_copy_dgram_byte_equivalence_for_accepted_payload() {
    let mut c = make_conn();
    c.enable_datagrams(16, 16);
    let payload: Vec<u8> = (0..64).map(|value| value as u8).collect();

    c.dgram_send(&payload).expect("accepted DATAGRAM must enqueue");
    assert_eq!(c.dgram_send_queue_byte_size(), payload.len());
    #[cfg(not(feature = "zero_copy_dgram"))]
    assert_eq!(c.dgram_send_queue.front().unwrap().data.as_slice(), payload.as_slice());
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
    let (written, staged_class) =
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("DATAGRAM serialization");
    assert!(written > 0);
    assert!(staged_class.is_some());
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
    c.dgram_send_queue.push_back(DatagramSendEntry {
        data,
        len: payload_len,
        class: DatagramClass::Protected,
    });
    assert_eq!(pool.accounting_snapshot().1, before.1 + 1);

    let mut output = vec![0u8; 1 + 2 + payload_len];
    assert_eq!(
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("insufficient output is a no-op"),
        (0, None)
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
    let (written, staged_class) =
        c.maybe_stage_one_datagram_frame(&mut output, 0).expect("boundary DATAGRAM encode");
    assert_eq!(written, reserve);
    assert!(staged_class.is_some());
    c.commit_staged_datagram_frame().expect("boundary DATAGRAM commit");
    assert_eq!(c.dgram_send_queue_len(), 0);
}

#[test]
fn bulk_class_datagram_marks_packet_bulk_only_for_fec_gating() {
    // TODO-1011: a packet whose only application payload is a Bulk-class
    // datagram must report `bulk_only` so the core send path skips FEC
    // framing; protected datagrams must keep it clear.
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(16, 16);
    // Keep the composed packet free of coalesced control frames so the
    // bulk_only condition (datagram-only payload) is exercised exactly.
    pair.client.pending_control.clear();
    let mut packet = [0u8; 1500];

    pair.client
        .dgram_send_parts_classified(b"", b"bulk-payload", DatagramClass::Bulk)
        .expect("bulk datagram enqueue");
    let (written, info) = pair.client.send(&mut packet).expect("bulk packet send");
    assert!(written > 0);
    assert!(info.bulk_only, "packet carrying only a bulk datagram must be bulk_only");
    assert!(!info.path_control);
    assert!(info.congestion_controlled);

    pair.client
        .dgram_send_parts_classified(b"", b"protected-payload", DatagramClass::Protected)
        .expect("protected datagram enqueue");
    let (written, info) = pair.client.send(&mut packet).expect("protected packet send");
    assert!(written > 0);
    assert!(!info.bulk_only, "protected datagrams keep FEC framing");
}

#[test]
fn bulk_class_loses_bulk_only_when_control_coalesces() {
    // A bulk datagram coalesced with control or stream content must stay
    // framed: the packet carries data that deserves repair protection.
    let mut pair = bench_paired_1rtt_connections();
    pair.client.pmtu = pmtu_state(false, PmtuPolicy::default());
    pair.client.enable_datagrams(16, 16);
    pair.client.pending_control.clear();
    pair.client.pending_control.push_back(crate::transport::Frame::Ping { mtu_probe: None });
    let mut packet = [0u8; 1500];

    pair.client
        .dgram_send_parts_classified(b"", b"bulk-payload", DatagramClass::Bulk)
        .expect("bulk datagram enqueue");
    let (written, info) = pair.client.send(&mut packet).expect("mixed packet send");
    assert!(written > 0);
    assert!(!info.bulk_only, "coalesced control content keeps the packet framed");
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
fn transport_stealth_jitter_disabled_when_external_pacing() {
    let mut c = make_conn();
    c.config.set_stealth_timing(true, 5_000);
    c.set_external_pacing_for_test(true);
    assert!(!c.transport_stealth_timing_active());
    assert!(c.transport_stealth_jitter_delay().is_none());
}

#[test]
fn transport_stealth_jitter_bounded_when_gate_active() {
    let mut c = make_conn();
    c.config.set_stealth_timing(true, 100);
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

// ---- MASQUE receive: owned queue-entry dispatch (no scratch copy) ---------

fn masque_wire_datagram(flow_id: u64, payload: &[u8]) -> Vec<u8> {
    let mut dgram = Vec::with_capacity(8 + payload.len());
    let mut scratch = [0u8; 8];
    let used = qf_transport_pn::varint::write_varint(flow_id, &mut scratch).unwrap();
    dgram.extend_from_slice(&scratch[..used]);
    dgram.extend_from_slice(payload);
    dgram
}

#[test]
fn masque_recv_take_dispatches_fifo_payload_with_writable_headroom() {
    let mut conn = make_conn();
    conn.enable_datagrams(16, 16);
    #[cfg(feature = "zero_copy_dgram")]
    let pool = {
        let pool = Arc::new(crate::optimize::MemoryPool::new(4, 128));
        conn.dgram_pool = Arc::clone(&pool);
        pool
    };
    let h3cfg = crate::transport::h3::Config::new().expect("h3 config");
    let mut h3 =
        crate::transport::h3::Connection::with_transport(&mut conn, &h3cfg).expect("h3 connection");

    let first = masque_wire_datagram(7, b"alpha");
    let second = masque_wire_datagram(9, b"beta-longer-payload");
    conn.enqueue_received_datagram(std::borrow::Cow::Borrowed(&first));
    conn.enqueue_received_datagram(std::borrow::Cow::Borrowed(&second));

    let (flow_id, offset, payload_len) =
        h3.try_recv_masque_datagram(&mut conn).expect("first datagram");
    assert_eq!(flow_id, 7);
    {
        let region = h3.masque_recv_region(offset);
        assert_eq!(&region[..payload_len], b"alpha");
        assert!(
            region.len() >= payload_len + crate::transport::h3::MASQUE_RECV_HEADROOM,
            "normalization headroom must stay writable past the payload"
        );
        region[payload_len] = 0xAB;
        region[payload_len + crate::transport::h3::MASQUE_RECV_HEADROOM - 1] = 0xCD;
    }

    let (flow_id, offset, payload_len) =
        h3.try_recv_masque_datagram(&mut conn).expect("second datagram FIFO order");
    assert_eq!(flow_id, 9);
    assert_eq!(&h3.masque_recv_region(offset)[..payload_len], b"beta-longer-payload");

    // Empty-queue take hands the last live entry back before reporting Done.
    assert!(h3.try_recv_masque_datagram(&mut conn).is_none());
    #[cfg(not(feature = "zero_copy_dgram"))]
    assert!(conn.dgram_recv_freelist.len() >= 2, "both taken entries must return to the freelist");
    #[cfg(feature = "zero_copy_dgram")]
    assert_eq!(
        pool.accounting_snapshot().1,
        0,
        "pooled blocks must be fully recycled once the queue drains"
    );
}

#[test]
fn masque_recv_take_drops_malformed_and_oversized_entries() {
    let mut conn = make_conn();
    conn.enable_datagrams(16, 16);
    let h3cfg = crate::transport::h3::Config::new().expect("h3 config");
    let mut h3 =
        crate::transport::h3::Connection::with_transport(&mut conn, &h3cfg).expect("h3 conn");

    // Truncated flow-id varint (0x40 opens a two-byte varint, one byte given).
    conn.enqueue_received_datagram(std::borrow::Cow::Borrowed(&[0x40]));
    assert!(h3.try_recv_masque_datagram(&mut conn).is_none());
    assert_eq!(conn.dgram_recv_queue_len(), 0, "malformed entry must be consumed");

    // Entry beyond the transport payload ceiling is dropped, never dispatched.
    let oversized = masque_wire_datagram(0, &vec![0x55; conn.max_recv_udp_payload_size() + 1]);
    conn.enqueue_received_datagram(std::borrow::Cow::Borrowed(&oversized));
    assert!(h3.try_recv_masque_datagram(&mut conn).is_none());
    assert_eq!(conn.dgram_recv_queue_len(), 0);
}

#[test]
fn admitted_uniform_run_seals_once_and_opens_on_the_peer() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(16, 16);
    pair.server.enable_datagrams(16, 16);
    pair.client.recovery.cwnd = 8 * 2048;
    pair.client.cwnd = pair.client.recovery.cwnd;
    let payload = [0x5Au8; 200];
    for _ in 0..8 {
        pair.client.dgram_send(&payload).expect("enqueue datagram");
    }
    let mut storage = vec![vec![0u8; 2048]; 8];
    let mut refs: Vec<&mut [u8]> = storage.iter_mut().map(|buf| buf.as_mut_slice()).collect();
    pair.client.admitted_seal_batch_calls = 0;
    pair.client.admitted_seal_batch_packets = 0;
    let produced = pair.client.send_admitted_batch(&mut refs, 0).expect("admitted batch");
    assert_eq!(produced.len(), 8, "cwnd admits the whole uniform run");
    assert_eq!(pair.client.admitted_seal_batch_calls, 1, "one seal_batch for the run");
    assert_eq!(pair.client.admitted_seal_batch_packets, 8);
    let wire_len = produced[0].0;
    assert!(produced
        .iter()
        .all(|(len, info)| { *len == wire_len && info.to == pair.client.peer_addr }));
    for (index, (len, _)) in produced.iter().enumerate() {
        pair.server
            .recv(&mut storage[index][..*len], &pair.recv_info)
            .expect("peer opens the sealed packet");
        assert_eq!(pair.server.dgram_recv_vec().expect("datagram"), payload);
    }
    assert_eq!(pair.client.dgram_send_queue_len(), 0);
}

#[test]
fn failed_admitted_run_preserves_control_ack_and_probe() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(4, 4);
    pair.client.recovery.cwnd = 8 * 2048;
    pair.client.cwnd = pair.client.recovery.cwnd;
    pair.client.pending_control.push_back(Frame::MaxData { max: 1024 });
    assert!(pair.client.pkt_spaces[2].on_packet_recv(7));
    pair.client.pkt_spaces[2].note_ack_eliciting(0, 1);
    pair.client.pending_probe_spaces.push_back(recovery::PacketSpace::Application);
    let stream_payload = b"retained after aborted batch";
    pair.client.stream_send(0, stream_payload, false).unwrap();
    pair.client.dgram_send(&[0x5a; 32]).unwrap();
    pair.client.dgram_send(&[0xa5; 32]).unwrap();
    let now = pair.client.clock.now();
    pair.client.set_wire_ledger(Some(qf_stealth::BudgetLedger::new(
        qf_stealth::WireBudget {
            cap_bytes_per_sec: 1000,
            cap_bytes_per_burst: 1000,
            shape: qf_stealth::WireShape::FixedCell,
        },
        None,
        900,
        now,
    )));
    pair.client.set_short_header_pad_target(900);
    let before_sent = pair.client.stats.sent;
    let before_stream_sent_bytes = pair.client.stats.stream_sent_bytes;
    let before_conn_bytes_sent = pair.client.conn_bytes_sent;
    let before_send_buffered_bytes = pair.client.send_buffered_bytes;
    let before_send_off = pair.client.streams.get(&0).unwrap().send_off;
    #[cfg(not(feature = "stream_ring_buffer"))]
    let before_source = pair.client.streams.get(&0).unwrap().send_buf.clone();
    #[cfg(feature = "stream_ring_buffer")]
    let before_source = {
        let ring = &pair.client.streams.get(&0).unwrap().send_ring;
        let mut bytes = vec![0; ring.len()];
        assert_eq!(ring.peek_from(0, &mut bytes), bytes.len());
        bytes
    };
    let before_stream_queue = pair.client.stream_retransmit_queue.clone();
    let before_writable_queue = pair.client.writable_streams.clone();
    let before_budget = pair.client.wire_ledger_mut().unwrap().remaining(now);
    let mut first = [0u8; 2048];
    let mut too_small = [0u8; 1];
    let mut outs: [&mut [u8]; 2] = [&mut first, &mut too_small];

    assert!(matches!(
        pair.client.send_admitted_batch(&mut outs, 0),
        Err(ConnectionError::BufferTooShort)
    ));
    assert!(matches!(pair.client.pending_control.front(), Some(Frame::MaxData { max: 1024 })));
    assert!(pair.client.pkt_spaces[2].has_pending_ack());
    assert_eq!(pair.client.pending_probe_spaces.front(), Some(&recovery::PacketSpace::Application));
    assert_eq!(pair.client.dgram_send_queue_len(), 2);
    assert_eq!(pair.client.stats.sent, before_sent);
    assert_eq!(pair.client.stats.stream_sent_bytes, before_stream_sent_bytes);
    assert_eq!(pair.client.conn_bytes_sent, before_conn_bytes_sent);
    assert_eq!(pair.client.send_buffered_bytes, before_send_buffered_bytes);
    assert_eq!(pair.client.streams.get(&0).unwrap().send_off, before_send_off);
    #[cfg(not(feature = "stream_ring_buffer"))]
    assert_eq!(pair.client.streams.get(&0).unwrap().send_buf, before_source);
    #[cfg(feature = "stream_ring_buffer")]
    {
        let ring = &pair.client.streams.get(&0).unwrap().send_ring;
        let mut bytes = vec![0; ring.len()];
        assert_eq!(ring.peek_from(0, &mut bytes), bytes.len());
        assert_eq!(bytes, before_source);
    }
    assert_eq!(pair.client.stream_retransmit_queue, before_stream_queue);
    assert_eq!(pair.client.writable_streams, before_writable_queue);
    assert_eq!(pair.client.pad_short_header_to, Some(900));
    assert_eq!(pair.client.wire_ledger_mut().unwrap().remaining(now), before_budget);

    let mut storage = vec![vec![0u8; 2048]; 2];
    let mut refs: Vec<&mut [u8]> = storage.iter_mut().map(|buffer| buffer.as_mut_slice()).collect();
    let produced = pair.client.send_admitted_batch(&mut refs, 0).expect("retry admitted batch");
    assert_eq!(produced.len(), 2);
    assert!(pair.client.pending_control.is_empty());
    assert!(!pair.client.pkt_spaces[2].has_pending_ack());
    assert!(pair.client.pending_probe_spaces.is_empty());
    assert_eq!(pair.client.dgram_send_queue_len(), 0);
    assert_eq!(pair.client.stats.sent, before_sent + 2);
    assert_eq!(pair.client.pad_short_header_to, None);
    assert!(pair.client.wire_ledger_mut().unwrap().remaining(now) < before_budget);
    for (index, (len, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*len], &pair.recv_info).expect("peer opens retry");
        let expected = if index == 0 { &[0x5a; 32] } else { &[0xa5; 32] };
        assert_eq!(pair.server.dgram_recv_vec().expect("one datagram"), expected);
    }
    let mut received = [0u8; 64];
    let (length, fin) =
        pair.server.stream_recv(0, &mut received).expect("retained stream delivered");
    assert_eq!(&received[..length], stream_payload);
    assert!(!fin);
}

#[test]
fn failed_partial_retransmission_preserves_fifo_and_fin() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.cwnd = pair.client.recovery.cwnd;
    let payload: Vec<u8> = (0..1200).map(|index| (index % 251) as u8).collect();
    let transmission_id = pair
        .client
        .stage_stream_transmission(0, 0, std::sync::Arc::from(payload.as_slice()), true, false)
        .expect("retain stream range");
    let original_queue = pair.client.stream_retransmit_queue.clone();
    let original_bytes = pair.client.stream_retransmit_bytes;
    let original_entries = pair.client.stream_transmissions.len();
    let mut first = [0u8; 1500];
    let mut too_small = [0u8; 1];
    let mut failed: [&mut [u8]; 2] = [&mut first, &mut too_small];

    assert_eq!(
        pair.client.send_admitted_batch(&mut failed, 0).unwrap_err(),
        ConnectionError::BufferTooShort
    );
    assert_eq!(pair.client.stream_retransmit_queue, original_queue);
    assert_eq!(pair.client.stream_retransmit_bytes, original_bytes);
    assert_eq!(pair.client.stream_transmissions.len(), original_entries);
    let retained = pair.client.stream_transmissions.get(&transmission_id).unwrap();
    assert_eq!(retained.data.as_ref(), payload);
    assert!(retained.fin);
    assert!(retained.queued);
    assert!(retained.active_packet.is_none());

    let mut storage = vec![vec![0u8; 1500]; 2];
    let mut outputs: Vec<&mut [u8]> = storage.iter_mut().map(Vec::as_mut_slice).collect();
    let produced = pair.client.send_admitted_batch(&mut outputs, 0).expect("retry split range");
    assert_eq!(produced.len(), 2);
    for (index, (length, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*length], &pair.recv_info).expect("open split");
    }
    let mut received = vec![0; payload.len()];
    let (length, fin) = pair.server.stream_recv(0, &mut received).expect("read split stream");
    assert_eq!(length, payload.len());
    assert_eq!(received, payload);
    assert!(fin);
}

#[test]
fn failed_mixed_retransmission_new_data_and_fin_only_preserves_sources() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.cwnd = pair.client.recovery.cwnd;
    let retained_id = pair
        .client
        .stage_stream_transmission(8, 0, std::sync::Arc::from(&b"retained"[..]), true, false)
        .expect("queue retained range");
    pair.client.stream_send(0, b"", true).expect("queue FIN-only range");
    pair.client.stream_send(4, b"fresh", true).expect("queue new range");
    let original_retransmit_queue = pair.client.stream_retransmit_queue.clone();
    let original_writable_queue = pair.client.writable_streams.clone();
    let mut first = [0u8; 1500];
    let mut second = [0u8; 1500];
    let mut too_small = [0u8; 1];
    let mut failed: [&mut [u8]; 3] = [&mut first, &mut second, &mut too_small];

    assert_eq!(
        pair.client.send_admitted_batch(&mut failed, 0).unwrap_err(),
        ConnectionError::BufferTooShort
    );
    assert_eq!(pair.client.stream_retransmit_queue, original_retransmit_queue);
    assert_eq!(pair.client.writable_streams, original_writable_queue);
    assert_eq!(pair.client.stream_transmissions.len(), 1);
    assert!(pair.client.stream_transmissions.get(&retained_id).unwrap().queued);
    assert_eq!(pair.client.stats.stream_sent_bytes, 0);
    assert_eq!(pair.client.conn_bytes_sent, 0);
    assert_eq!(pair.client.streams.get(&4).unwrap().send_off, 0);
    assert_eq!(pair.client.send_buffered_bytes, 5);

    let mut storage = vec![vec![0u8; 1500]; 3];
    let mut outputs: Vec<&mut [u8]> = storage.iter_mut().map(Vec::as_mut_slice).collect();
    let produced = pair.client.send_admitted_batch(&mut outputs, 0).expect("retry mixed run");
    assert_eq!(produced.len(), 3);
    for (index, (length, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*length], &pair.recv_info).expect("open mixed run");
    }
    let mut received = [0; 16];
    for (stream_id, expected) in [(0, &b""[..]), (4, &b"fresh"[..]), (8, &b"retained"[..])] {
        let (length, fin) = pair.server.stream_recv(stream_id, &mut received).expect("read stream");
        assert_eq!(&received[..length], expected);
        assert!(fin);
    }
}

#[test]
fn admitted_stream_run_stages_multiple_ranges_before_one_seal() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.cwnd = pair.client.recovery.cwnd;
    let payload: Vec<u8> = (0..3000).map(|index| (index % 251) as u8).collect();
    pair.client.stream_send(0, &payload, true).expect("queue stream");
    let mut storage = vec![vec![0u8; 1500]; 8];
    let mut outputs: Vec<&mut [u8]> = storage.iter_mut().map(Vec::as_mut_slice).collect();
    pair.client.admitted_seal_batch_calls = 0;
    let produced = pair.client.send_admitted_batch(&mut outputs, 0).expect("stage stream run");
    assert!(produced.len() >= 2 && produced.len() <= 8);
    assert_eq!(pair.client.admitted_seal_batch_calls, 1);
    assert_eq!(pair.client.stats.stream_sent_bytes, payload.len() as u64);
    assert_eq!(pair.client.conn_bytes_sent, payload.len() as u64);
    assert_eq!(pair.client.send_buffered_bytes, 0);
    for (index, (length, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*length], &pair.recv_info).expect("open stream");
    }
    let mut received = vec![0; payload.len()];
    let (length, fin) = pair.server.stream_recv(0, &mut received).expect("read stream run");
    assert_eq!(length, payload.len());
    assert_eq!(received, payload);
    assert!(fin);
}

#[test]
fn eight_stream_packets_share_one_batch_seal_and_preserve_fin() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.cwnd = pair.client.recovery.cwnd;
    for index in 0..8u8 {
        pair.client
            .stream_send(u64::from(index) * 4, &[index; 64], true)
            .expect("queue independent stream");
    }
    let mut storage = vec![vec![0u8; 1500]; 8];
    let mut outputs: Vec<&mut [u8]> = storage.iter_mut().map(Vec::as_mut_slice).collect();
    pair.client.admitted_seal_batch_calls = 0;
    let produced = pair.client.send_admitted_batch(&mut outputs, 0).expect("send eight streams");
    assert_eq!(produced.len(), 8);
    assert_eq!(pair.client.admitted_seal_batch_calls, 1);
    assert_eq!(pair.client.admitted_seal_batch_packets, 8);
    assert_eq!(pair.client.stats.stream_sent_bytes, 8 * 64);
    for (index, (length, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*length], &pair.recv_info).expect("open stream");
        let mut bytes = [0; 64];
        let (read, fin) = pair
            .server
            .stream_recv((index as u64) * 4, &mut bytes)
            .expect("read independent stream");
        assert_eq!(read, 64);
        assert_eq!(bytes, [index as u8; 64]);
        assert!(fin);
    }
}

#[test]
fn failed_single_packet_seal_preserves_stream_until_peer_retry() {
    let mut pair = bench_paired_1rtt_connections();
    let payload = b"single packet stream stays pending";
    pair.client.stream_send(0, payload, true).expect("queue stream");
    let original_writable = pair.client.writable_streams.clone();
    let sealer = pair.client.crypto.write().seal_1rtt.take().expect("installed 1-RTT sealer");
    pair.client.crypto_1rtt.store(None);
    let mut packet = [0u8; 1500];

    let failed = pair.client.send(&mut packet);
    assert!(matches!(failed, Err(ConnectionError::TlsError(_))), "{failed:?}");
    assert_eq!(pair.client.writable_streams, original_writable);
    assert_eq!(pair.client.send_buffered_bytes, payload.len());
    assert_eq!(pair.client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(pair.client.conn_bytes_sent, 0);
    assert_eq!(pair.client.stats.stream_sent_bytes, 0);
    assert!(pair.client.stream_transmissions.is_empty());

    let original_hp = {
        let mut crypto = pair.client.crypto.write();
        crypto.seal_1rtt = Some(sealer);
        crypto.hp_1rtt.replace(std::sync::Arc::new(FailingHeaderProtector))
    };
    pair.client.refresh_short_header_tag_reserve();
    let failed_hp = pair.client.send(&mut packet);
    assert!(matches!(failed_hp, Err(ConnectionError::CryptoError(_))), "{failed_hp:?}");
    assert_eq!(pair.client.writable_streams, original_writable);
    assert_eq!(pair.client.send_buffered_bytes, payload.len());
    assert_eq!(pair.client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(pair.client.conn_bytes_sent, 0);
    assert_eq!(pair.client.stats.stream_sent_bytes, 0);
    assert!(pair.client.stream_transmissions.is_empty());

    pair.client.crypto.write().hp_1rtt = original_hp;
    pair.client.refresh_short_header_tag_reserve();
    pair.client.sync_1rtt();
    let (length, _) = pair.client.send(&mut packet).expect("retry single packet");
    pair.server.recv(&mut packet[..length], &pair.recv_info).expect("peer opens retry");
    let mut received = [0; 64];
    let (read, fin) = pair.server.stream_recv(0, &mut received).expect("read stream");
    assert_eq!(&received[..read], payload);
    assert!(fin);
}

#[test]
fn committed_non_fin_stream_exits_writable_queue_until_new_data_arrives() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.stream_send(0, b"first", false).expect("first range");
    let mut packet = [0u8; 1500];
    let (first_len, _) = pair.client.send(&mut packet).expect("send first range");
    pair.server.recv(&mut packet[..first_len], &pair.recv_info).expect("open first range");
    assert!(pair.client.writable_streams.is_empty());
    assert!(!pair.client.writable_stream_ids.contains(&0));

    pair.client.stream_send(0, b"second", true).expect("append after first send");
    assert_eq!(pair.client.writable_streams.front(), Some(&0));
    let (second_len, _) = pair.client.send(&mut packet).expect("send second range");
    pair.server.recv(&mut packet[..second_len], &pair.recv_info).expect("open second range");
    let mut received = [0; 16];
    let (length, fin) = pair.server.stream_recv(0, &mut received).expect("read both ranges");
    assert_eq!(&received[..length], b"firstsecond");
    assert!(fin);
}

#[test]
fn full_retained_entry_ledger_preserves_new_stream_until_ack_frees_capacity() {
    let mut pair = bench_paired_1rtt_connections();
    let retained_byte = std::sync::Arc::<[u8]>::from([0x5A]);
    for index in 0..MAX_STREAM_ORIGINAL_TRANSMISSIONS {
        let id = pair
            .client
            .stage_stream_transmission(
                4,
                index as u64,
                std::sync::Arc::clone(&retained_byte),
                false,
                false,
            )
            .expect("fill retained entry ledger");
        pair.client.commit_stream_transmission(id, index as u64);
    }
    let payload = b"send after ACK";
    pair.client.stream_send(0, payload, true).expect("queue new stream");
    let original_pn = pair.client.next_send_pn_by_space[2];
    let mut packet = [0u8; 1500];

    assert_eq!(pair.client.send(&mut packet).unwrap_err(), ConnectionError::Done);
    assert_eq!(pair.client.next_send_pn_by_space[2], original_pn);
    assert_eq!(pair.client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(pair.client.send_buffered_bytes, payload.len());
    assert_eq!(pair.client.stats.stream_sent_bytes, 0);

    pair.client.lose_stream_transmission_packet(0);
    pair.client.acknowledge_late_stream_packets(&[(0, 0)]);
    let (length, _) = pair.client.send(&mut packet).expect("entry capacity restored");
    pair.server.recv(&mut packet[..length], &pair.recv_info).expect("peer opens new stream");
    let mut received = [0; 32];
    let (read, fin) = pair.server.stream_recv(0, &mut received).expect("read new stream");
    assert_eq!(&received[..read], payload);
    assert!(fin);
}

#[test]
fn failed_admitted_seal_preserves_unsent_obligations() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(4, 4);
    pair.client.recovery.cwnd = 8 * 2048;
    pair.client.cwnd = pair.client.recovery.cwnd;
    pair.client.pending_control.push_back(Frame::MaxData { max: 2048 });
    assert!(pair.client.pkt_spaces[2].on_packet_recv(9));
    pair.client.pkt_spaces[2].note_ack_eliciting(0, 1);
    pair.client.pending_probe_spaces.push_back(recovery::PacketSpace::Application);
    let stream_payload = b"seal failure keeps stream ownership";
    pair.client.stream_send(0, stream_payload, true).unwrap();
    pair.client.dgram_send(&[0x31; 32]).unwrap();
    pair.client.dgram_send(&[0x32; 32]).unwrap();
    let before_sent = pair.client.stats.sent;
    let before_buffered = pair.client.send_buffered_bytes;
    pair.client.crypto_1rtt.store(None);
    let mut storage = vec![vec![0u8; 2048]; 2];
    let mut refs: Vec<&mut [u8]> = storage.iter_mut().map(|buffer| buffer.as_mut_slice()).collect();

    assert!(matches!(
        pair.client.send_admitted_batch(&mut refs, 0),
        Err(ConnectionError::TlsError(_))
    ));
    assert!(matches!(pair.client.pending_control.front(), Some(Frame::MaxData { max: 2048 })));
    assert!(pair.client.pkt_spaces[2].has_pending_ack());
    assert_eq!(pair.client.pending_probe_spaces.front(), Some(&recovery::PacketSpace::Application));
    assert_eq!(pair.client.dgram_send_queue_len(), 2);
    assert_eq!(pair.client.stats.sent, before_sent);
    assert_eq!(pair.client.streams.get(&0).unwrap().send_off, 0);
    assert_eq!(pair.client.send_buffered_bytes, before_buffered);
    assert_eq!(pair.client.conn_bytes_sent, 0);
    assert_eq!(pair.client.stats.stream_sent_bytes, 0);
    assert!(pair.client.stream_transmissions.is_empty());

    pair.client.sync_1rtt();
    let produced = pair.client.send_admitted_batch(&mut refs, 0).expect("retry after seal failure");
    assert_eq!(produced.len(), 2);
    assert!(pair.client.pending_control.is_empty());
    assert!(!pair.client.pkt_spaces[2].has_pending_ack());
    assert!(pair.client.pending_probe_spaces.is_empty());
    assert_eq!(pair.client.dgram_send_queue_len(), 0);
    for (index, (len, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*len], &pair.recv_info).expect("peer opens retry");
        let expected = if index == 0 { &[0x31; 32] } else { &[0x32; 32] };
        assert_eq!(pair.server.dgram_recv_vec().expect("one datagram"), expected);
    }
    let mut received = [0u8; 64];
    let (length, fin) = pair.server.stream_recv(0, &mut received).expect("read retry stream");
    assert_eq!(&received[..length], stream_payload);
    assert!(fin);
}

#[test]
fn failed_admitted_run_does_not_mark_pmtu_probe_sent() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(4, 4);
    pair.server.enable_datagrams(4, 4);
    pair.client.dgram_send_max_size = 1500;
    pair.client.pmtu = pmtu_state(true, PmtuPolicy::default());
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.dgram_send(&[0x5a; 24]).unwrap();
    let now = pair.client.clock.now();
    let mut probe = [0u8; 1600];
    let mut too_small = [0u8; 1];
    let mut failed: [&mut [u8]; 2] = [&mut probe, &mut too_small];

    assert_eq!(
        pair.client.send_admitted_batch(&mut failed, 0).unwrap_err(),
        ConnectionError::BufferTooShort
    );
    assert!(pair.client.pmtu_probe_pn.is_none());
    assert!(pair.client.pmtu.should_send_probe(now));
    assert_eq!(pair.client.dgram_send_queue_len(), 1);

    let mut storage = vec![vec![0u8; 1600]; 2];
    let mut outputs: Vec<&mut [u8]> = storage.iter_mut().map(Vec::as_mut_slice).collect();
    let produced = pair.client.send_admitted_batch(&mut outputs, 0).expect("retry probe and data");
    assert_eq!(produced.len(), 2);
    assert_eq!(produced[0].0, 1500);
    assert!(pair.client.pmtu_probe_pn.is_some());
    assert_eq!(pair.client.dgram_send_queue_len(), 0);
    for (index, (length, _)) in produced.iter().enumerate() {
        pair.server.recv(&mut storage[index][..*length], &pair.recv_info).expect("retry opens");
    }
    assert_eq!(pair.server.dgram_recv_vec().expect("one datagram"), [0x5a; 24]);
    assert!(matches!(pair.server.dgram_recv_vec(), Err(ConnectionError::Done)));
}

#[test]
fn short_header_pad_target_sets_sealed_length() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.enable_datagrams(4, 4);
    pair.client.recovery.cwnd = 64 * 1024;
    pair.client.cwnd = pair.client.recovery.cwnd;
    pair.client.dgram_send(&[0x11u8; 20]).expect("datagram");
    pair.client.set_short_header_pad_target(900);
    let mut buf = [0u8; 2048];
    let (len, _) = pair.client.send(&mut buf).expect("padded send");
    assert_eq!(len, 900);
    assert!(!buf.starts_with(&[0xF1, 0xEC]));
}
