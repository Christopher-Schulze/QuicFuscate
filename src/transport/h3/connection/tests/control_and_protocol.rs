use super::*;

// ---- Control Stream --------------------------------------------------

#[test]
fn client_h3_initializes_control_stream() {
    let mut conn = make_conn(); // client
    let cfg = Config::new().expect("cfg");
    let h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    assert!(h3.control_stream_id.is_some(), "client must initialize control stream");
    let csid = h3.control_stream_id.unwrap();
    assert!(h3.streams.contains_key(&csid), "control stream must be registered");
}

#[test]
fn client_and_server_use_peer_owned_unidirectional_control_ids() {
    use crate::transport::connection::bench_paired_1rtt_connections;
    let crate::transport::connection::BenchConnectionPair { mut client, mut server, .. } =
        bench_paired_1rtt_connections();
    let cfg = Config::new().expect("cfg");
    let client_h3 = super::h3::Connection::with_transport(&mut client, &cfg).expect("client h3");
    let server_h3 = super::h3::Connection::with_transport(&mut server, &cfg).expect("server h3");

    assert_eq!(client_h3.control_stream_id, Some(2));
    assert_eq!(server_h3.control_stream_id, Some(3));
    assert!(client_h3.streams.get(&2).is_some_and(|stream| stream.settings_received));
    assert!(server_h3.streams.get(&3).is_some_and(|stream| stream.settings_received));
}

#[test]
fn duplicate_peer_control_stream_is_rejected() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let _client_h3 = Connection::with_transport(&mut client, &Config::new().unwrap()).unwrap();
    let mut server_h3 = Connection::with_transport(&mut server, &Config::new().unwrap()).unwrap();
    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    let _ = server_h3.poll(&mut server);

    client.stream_send(6, &[0x00, 0x04, 0x00], false).expect("queue duplicate control stream");
    let (len, _) = client.send(&mut packet).expect("send duplicate control stream");
    server.recv(&mut packet[..len], &recv_info).expect("server recv");
    assert!(matches!(server_h3.poll(&mut server), Err(Error::StreamCreationError)));
}

#[test]
fn control_stream_rejects_data_after_settings() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let _client_h3 = Connection::with_transport(&mut client, &Config::new().unwrap()).unwrap();
    let mut server_h3 = Connection::with_transport(&mut server, &Config::new().unwrap()).unwrap();
    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    let _ = server_h3.poll(&mut server);

    client.stream_send(2, &[0x00, 0x00], false).expect("queue invalid control frame");
    let (len, _) = client.send(&mut packet).expect("send invalid control frame");
    server.recv(&mut packet[..len], &recv_info).expect("server recv");
    assert!(matches!(server_h3.poll(&mut server), Err(Error::FrameUnexpected)));
}

#[test]
fn settings_reject_reserved_and_duplicate_identifiers() {
    let mut conn = make_conn();
    let config = must_succeed(Config::new());
    let _h3 = must_succeed(Connection::with_transport(&mut conn, &config));

    let mut reserved = Vec::new();
    Connection::encode_varint(0x02, &mut reserved);
    Connection::encode_varint(0, &mut reserved);
    assert!(matches!(Connection::parse_settings_payload(&reserved), Err(Error::SettingsError)));

    let mut duplicate = Vec::new();
    for value in [0, 1] {
        Connection::encode_varint(0x01, &mut duplicate);
        Connection::encode_varint(value, &mut duplicate);
    }
    assert!(matches!(Connection::parse_settings_payload(&duplicate), Err(Error::SettingsError)));

    assert!(matches!(Connection::parse_settings_payload(&[0x01]), Err(Error::SettingsError)));
}

#[test]
fn settings_parse_current_webtransport_draft_contract() {
    let mut payload = Vec::new();
    for (setting, value) in [
        (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
        (SETTINGS_H3_DATAGRAM, 1),
        (SETTINGS_WT_ENABLED, 1),
        (SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI),
        (SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI),
        (SETTINGS_WT_INITIAL_MAX_DATA, WEBTRANSPORT_INITIAL_MAX_DATA),
    ] {
        Connection::encode_varint(setting, &mut payload);
        Connection::encode_varint(value, &mut payload);
    }
    let settings = must_succeed(Connection::parse_settings_payload(&payload));
    assert!(settings.enable_connect_protocol);
    assert!(settings.h3_datagram);
    assert!(settings.webtransport_enabled);
    assert_eq!(settings.webtransport_initial_max_streams_uni, WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI);
    assert_eq!(
        settings.webtransport_initial_max_streams_bidi,
        WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI
    );
    assert_eq!(settings.webtransport_initial_max_data, WEBTRANSPORT_INITIAL_MAX_DATA);

    let mut invalid = Vec::new();
    Connection::encode_varint(SETTINGS_WT_ENABLED, &mut invalid);
    Connection::encode_varint(2, &mut invalid);
    assert!(matches!(Connection::parse_settings_payload(&invalid), Err(Error::SettingsError)));
}

#[test]
fn fixed_control_frame_payload_requires_exactly_one_varint() {
    assert!(matches!(Connection::decode_single_varint_payload(&[]), Err(Error::FrameError)));
    assert!(matches!(
        Connection::decode_single_varint_payload(&[0x01, 0x00]),
        Err(Error::FrameError)
    ));
    assert_eq!(Connection::decode_single_varint_payload(&[0x01]), Ok(1));
}

#[test]
fn frame_placement_rejects_reserved_and_cross_stream_frames() {
    let (client, server, _, _, _) = make_paired_h3_connections();
    assert!(matches!(
        Connection::validate_frame_placement(
            &server,
            StreamType::Request,
            0x02,
            false,
            ReceiveMessageState::AwaitingHeaders,
        ),
        Err(Error::FrameUnexpected)
    ));
    assert!(matches!(
        Connection::validate_frame_placement(
            &server,
            StreamType::Request,
            0x07,
            false,
            ReceiveMessageState::AwaitingHeaders,
        ),
        Err(Error::FrameUnexpected)
    ));
    assert!(matches!(
        Connection::validate_frame_placement(
            &client,
            StreamType::Control,
            0x0d,
            true,
            ReceiveMessageState::AwaitingHeaders,
        ),
        Err(Error::FrameUnexpected)
    ));
    assert!(matches!(
        Connection::validate_frame_placement(
            &server,
            StreamType::Control,
            0x05,
            true,
            ReceiveMessageState::AwaitingHeaders,
        ),
        Err(Error::FrameUnexpected)
    ));
    assert!(matches!(
        Connection::validate_frame_placement(
            &server,
            StreamType::Request,
            0x00,
            false,
            ReceiveMessageState::AwaitingHeaders,
        ),
        Err(Error::FrameUnexpected)
    ));
    assert!(matches!(
        Connection::validate_frame_placement(
            &server,
            StreamType::Request,
            0x00,
            false,
            ReceiveMessageState::Trailers,
        ),
        Err(Error::FrameUnexpected)
    ));
}

#[test]
fn client_rejects_server_initiated_bidirectional_stream() {
    let (mut client, mut server, recv_info, mut client_h3, _server_h3) =
        make_paired_h3_connections();
    server.stream_send(1, &[0x01, 0x00], false).expect("server bidi stream");
    let mut packet = [0u8; 2048];
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(client_h3.poll(&mut client), Err(Error::StreamCreationError)));
}

#[test]
fn unknown_unidirectional_stream_discards_every_chunk() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    let mut packet = [0u8; 2048];

    client.stream_send(6, &[0x21], false).expect("unknown stream type");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert!(server_h3
        .streams
        .get(&6)
        .is_some_and(|stream| stream._stream_type == StreamType::UnknownUnidirectional));

    let malformed_h3 = [0x00, 0x80, 0x10, 0x00, 0x01];
    client.stream_send(6, &malformed_h3, true).expect("discarded payload");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
}

#[test]
fn fragmented_multibyte_unidirectional_type_is_retained_then_discarded() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    let mut stream_type = Vec::new();
    Connection::encode_varint(0x40, &mut stream_type);
    assert_eq!(stream_type.len(), 2);
    let mut packet = [0u8; 2048];

    client.stream_send(10, &stream_type[..1], false).expect("first type byte");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert_eq!(
        server_h3.streams.get(&10).map(|stream| stream.frame_buffer.as_slice()),
        Some(&stream_type[..1])
    );

    let second = [stream_type[1], 0xff, 0x00, 0xaa];
    client.stream_send(10, &second, true).expect("remaining unknown stream");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
}

#[test]
fn qpack_streams_are_unique_and_critical() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    let mut packet = [0u8; 2048];
    client.stream_send(6, &[0x02], false).expect("QPACK encoder stream");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert_eq!(server_h3.peer_qpack_encoder_stream_id, Some(6));

    client.stream_send(10, &[0x02], false).expect("duplicate QPACK encoder");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::StreamCreationError)));

    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    client.stream_send(6, &[0x03], true).expect("closed QPACK decoder");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::ClosedCriticalStream)));
}

#[test]
fn zero_capacity_static_roundtrip_creates_no_qpack_instruction_streams() {
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections();
    let headers = [
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":path", b"/"),
    ];
    let request_stream_id = must_succeed(client_h3.send_request(&mut client, &headers, true));
    let mut packet = [0u8; 2048];
    let mut received_headers = None;

    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match server_h3.poll(&mut server) {
                Ok(Some((stream_id, Event::Headers { list, .. }))) => {
                    assert_eq!(stream_id, request_stream_id);
                    received_headers = Some(list);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("server H3 poll failed: {error:?}"),
            }
        }
        if received_headers.is_some() {
            break;
        }
    }

    assert!(received_headers.as_deref().is_some_and(|received| headers_equal(received, &headers)));
    assert!(client_h3.qpack_encoder_stream_id.is_none());
    assert!(client_h3.qpack_decoder_stream_id.is_none());
    assert!(server_h3.peer_qpack_encoder_stream_id.is_none());
    assert!(server_h3.peer_qpack_decoder_stream_id.is_none());
}

#[test]
fn paired_dynamic_roundtrip_synchronizes_and_releases_qpack_state() {
    let mut client_config = must_succeed(Config::new());
    client_config.set_qpack_max_table_capacity(220);
    client_config.set_qpack_blocked_streams(1);
    let mut server_config = must_succeed(Config::new());
    server_config.set_qpack_max_table_capacity(220);
    server_config.set_qpack_blocked_streams(1);
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections_with_configs(&client_config, &server_config);
    let headers = [
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":path", b"/"),
        Header::new(b"x-qpack-roundtrip", b"synchronized"),
    ];
    let request_stream_id = must_succeed(client_h3.send_request(&mut client, &headers, true));
    let mut packet = [0u8; 2048];
    let mut received_headers = None;

    for _ in 0..16 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        for (h3, transport, capture_headers) in
            [(&mut server_h3, &mut server, true), (&mut client_h3, &mut client, false)]
        {
            loop {
                match h3.poll(transport) {
                    Ok(Some((stream_id, Event::Headers { list, .. }))) if capture_headers => {
                        assert_eq!(stream_id, request_stream_id);
                        received_headers = Some(list);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(Error::Done) => break,
                    Err(error) => panic!("H3 dynamic roundtrip failed: {error:?}"),
                }
            }
        }
        if received_headers.is_some()
            && client_h3.encoder.known_received_count() == 1
            && client_h3.encoder.outstanding_section_count() == 0
        {
            break;
        }
    }

    assert!(received_headers.as_deref().is_some_and(|received| headers_equal(received, &headers)));
    assert_eq!(client_h3.encoder.known_received_count(), 1);
    assert_eq!(client_h3.encoder.outstanding_section_count(), 0);
    assert!(client_h3.qpack_encoder_stream_id.is_some());
    assert_eq!(client_h3.qpack_encoder_stream_id, server_h3.peer_qpack_encoder_stream_id);
    assert!(server_h3.qpack_decoder_stream_id.is_some());
    assert_eq!(server_h3.qpack_decoder_stream_id, client_h3.peer_qpack_decoder_stream_id);
}

#[test]
fn paired_qpack_encoder_stream_retains_fragmented_instructions() {
    let client_config = must_succeed(Config::new());
    let mut server_config = must_succeed(Config::new());
    server_config.set_qpack_max_table_capacity(64);
    server_config.set_qpack_blocked_streams(1);
    let (mut client, mut server, recv_info, client_h3, mut server_h3) =
        make_paired_h3_connections_with_configs(&client_config, &server_config);
    let encoder_stream_id = client_h3.next_uni_stream_id;
    let fragments: &[&[u8]] = &[&[0x02, 0x3f], &[0x21, 0x41], b"a", &[0x01], b"1"];
    let mut packet = [0u8; 2048];

    for fragment in fragments {
        assert_eq!(
            must_succeed(client.stream_send(encoder_stream_id, fragment, false)),
            fragment.len()
        );
        assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
        assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    }

    assert_eq!(server_h3.peer_qpack_encoder_stream_id, Some(encoder_stream_id));
    assert_eq!(server_h3.decoder.insert_count(), 1);
    assert!(server_h3.qpack_decoder_stream_id.is_some());
}

#[test]
fn paired_qpack_capacity_violation_maps_to_encoder_stream_error() {
    let (mut client, mut server, recv_info, client_h3, mut server_h3) =
        make_paired_h3_connections();
    let encoder_stream_id = client_h3.next_uni_stream_id;
    let invalid_capacity = [0x02, 0x21];
    assert_eq!(
        must_succeed(client.stream_send(encoder_stream_id, &invalid_capacity, false)),
        invalid_capacity.len()
    );
    let mut packet = [0u8; 2048];
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::QpackEncoderStreamError)));
}

#[test]
fn duplicate_push_stream_identifier_is_rejected() {
    let (mut client, mut server, recv_info, mut client_h3, _server_h3) =
        make_paired_h3_connections();
    let mut packet = [0u8; 2048];
    server.stream_send(7, &[0x01, 0x00], false).expect("first push stream");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(client_h3.poll(&mut client), Err(Error::Done)));

    server.stream_send(11, &[0x01, 0x00], false).expect("duplicate push id");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(client_h3.poll(&mut client), Err(Error::IdError)));
}

#[test]
fn fragmented_push_stream_identifier_is_retained() {
    let (mut client, mut server, recv_info, mut client_h3, _server_h3) =
        make_paired_h3_connections();
    let mut packet = [0u8; 2048];
    server.stream_send(7, &[0x01], false).expect("push stream type");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(client_h3.poll(&mut client), Err(Error::Done)));
    assert_eq!(
        client_h3.streams.get(&7).map(|stream| stream.frame_buffer.as_slice()),
        Some(&[0x01][..])
    );

    server.stream_send(7, &[42], false).expect("push identifier");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(client_h3.poll(&mut client), Err(Error::Done)));
    assert!(client_h3.received_push_ids.contains(&42));
    assert!(client_h3
        .streams
        .get(&7)
        .is_some_and(|stream| stream._stream_type == StreamType::Push));
}

#[test]
fn decreasing_max_push_id_is_rejected() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    assert_eq!(server_h3.peer_max_push_id, Some(MAX_STEALTH_PUSH_ID));
    let mut payload = Vec::new();
    Connection::encode_varint(MAX_STEALTH_PUSH_ID - 1, &mut payload);
    let mut frame = Vec::new();
    Connection::encode_varint(0x0d, &mut frame);
    Connection::encode_varint(payload.len() as u64, &mut frame);
    frame.extend_from_slice(&payload);
    client.stream_send(2, &frame, false).expect("decreasing MAX_PUSH_ID");
    let mut packet = [0u8; 2048];
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::IdError)));
}

#[test]
fn increasing_goaway_identifier_is_rejected() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    let mut packet = [0u8; 2048];
    for (identifier, expected_error) in [(10, false), (11, true)] {
        let mut payload = Vec::new();
        Connection::encode_varint(identifier, &mut payload);
        let mut frame = Vec::new();
        Connection::encode_varint(0x07, &mut frame);
        Connection::encode_varint(payload.len() as u64, &mut frame);
        frame.extend_from_slice(&payload);
        client.stream_send(2, &frame, false).expect("GOAWAY frame");
        assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
        let result = server_h3.poll(&mut server);
        if expected_error {
            assert!(matches!(result, Err(Error::IdError)));
        } else {
            assert!(matches!(result, Ok(Some((2, Event::GoAway)))));
        }
    }
}

#[test]
fn server_push_uses_distinct_push_and_unidirectional_stream_ids() {
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections();
    let request_stream_id = client_h3
        .send_request(
            &mut client,
            &[
                Header::new(b":method", b"GET"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"example.test"),
                Header::new(b":path", b"/"),
            ],
            false,
        )
        .expect("request");
    let mut packet = [0u8; 4096];
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(
        server_h3.poll(&mut server),
        Ok(Some((id, Event::Headers { .. }))) if id == request_stream_id
    ));
    assert_eq!(server_h3.peer_request_stream_id, Some(request_stream_id));

    let push_id =
        server_h3.create_stealth_push_promise("/cover.css", "text/css", 256).expect("push promise");
    server_h3.push_streams.get_mut(&push_id).unwrap().scheduled_at =
        std::time::Instant::now() - std::time::Duration::from_millis(1);
    server_h3.process_scheduled_push_streams(&mut server);

    let promise = server_h3.push_streams.get(&push_id).expect("promise state");
    let push_stream_id = promise.push_stream_id.expect("allocated push stream");
    assert_eq!(push_id, 0);
    assert_eq!(push_stream_id, 7);
    assert_ne!(Some(push_stream_id), server_h3.control_stream_id);
    assert_eq!(promise.state, PushState::DataSending);
    assert!(server_h3
        .streams
        .get(&push_stream_id)
        .is_some_and(|stream| stream._stream_type == StreamType::Push));

    let mut promise_seen = false;
    let mut push_headers_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match client_h3.poll(&mut client) {
                Ok(Some((id, Event::PushPromise { push_id: received, .. }))) => {
                    assert_eq!(id, request_stream_id);
                    assert_eq!(received, push_id);
                    promise_seen = true;
                }
                Ok(Some((id, Event::Headers { .. }))) if id == push_stream_id => {
                    push_headers_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("client push processing failed: {error:?}"),
            }
        }
        if promise_seen && push_headers_seen {
            break;
        }
    }
    assert!(promise_seen, "PUSH_PROMISE must arrive on the request stream");
    assert!(push_headers_seen, "push stream must carry its response HEADERS");
}

#[test]
fn webtransport_unidirectional_payload_is_not_parsed_as_h3_frames() {
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3, session_id) =
        make_established_webtransport_connections();
    let stream_id = must_succeed(client_h3.send_webtransport_unidirectional_stream(
        &mut client,
        session_id,
        b"raw-webtransport",
        true,
    ));
    let mut packet = [0u8; 2048];
    let mut data_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        if matches!(
            server_h3.poll(&mut server),
            Ok(Some((event_stream_id, Event::Data))) if event_stream_id == stream_id
        ) {
            data_seen = true;
            break;
        }
    }
    assert!(data_seen, "raw WebTransport data must publish a Data event");
    let mut body = [0u8; 32];
    let read = must_succeed(server_h3.recv_body(&mut server, stream_id, &mut body));
    assert_eq!(&body[..read], b"raw-webtransport");
    assert_eq!(server_h3.webtransport_session_ids.get(&stream_id), Some(&session_id));
}

#[test]
fn webtransport_payload_waits_for_its_established_session() {
    let mut client_config = must_succeed(Config::new());
    client_config.set_webtransport_enabled(true);
    let mut server_config = must_succeed(Config::new());
    server_config.set_webtransport_enabled(true);
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections_with_configs(&client_config, &server_config);
    let session_id = must_succeed(client_h3.open_webtransport_cover_session(
        &mut client,
        "cdn.example.com",
        "/assets/wt/session",
    ));
    let mut packet = [0u8; 2048];
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        if matches!(
            server_h3.poll(&mut server),
            Ok(Some((stream_id, Event::Headers { .. }))) if stream_id == session_id
        ) {
            break;
        }
    }
    assert!(server_h3.webtransport_session_pending(session_id));

    let stream_id = client_h3.next_uni_stream_id;
    let mut payload = Vec::new();
    Connection::encode_varint(WEBTRANSPORT_UNI_STREAM_TYPE, &mut payload);
    Connection::encode_varint(session_id, &mut payload);
    payload.extend_from_slice(b"buffered");
    must_succeed(client.stream_send(stream_id, &payload, false));
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert!(server_h3.pending_webtransport_streams.contains(&stream_id));
    assert!(server_h3.pending_events.is_empty());

    must_succeed(server_h3.accept_webtransport_cover_session(&mut server, session_id));
    assert!(matches!(
        server_h3.pending_events.pop_front(),
        Some((event_stream_id, Event::Data)) if event_stream_id == stream_id
    ));
    assert!(!server_h3.pending_webtransport_streams.contains(&stream_id));
}

#[test]
fn webtransport_bidirectional_streams_roundtrip_from_both_endpoints() {
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3, session_id) =
        make_established_webtransport_connections();
    let client_stream_id = must_succeed(client_h3.send_webtransport_bidirectional_stream(
        &mut client,
        session_id,
        b"client-bidi",
        true,
    ));
    let server_stream_id = must_succeed(server_h3.send_webtransport_bidirectional_stream(
        &mut server,
        session_id,
        b"server-bidi",
        true,
    ));
    let mut packet = [0u8; 2048];
    let mut server_data_seen = false;
    let mut client_data_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match server_h3.poll(&mut server) {
                Ok(Some((stream_id, Event::Data))) if stream_id == client_stream_id => {
                    server_data_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("server bidirectional stream failed: {error:?}"),
            }
        }
        loop {
            match client_h3.poll(&mut client) {
                Ok(Some((stream_id, Event::Data))) if stream_id == server_stream_id => {
                    client_data_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("client bidirectional stream failed: {error:?}"),
            }
        }
        if server_data_seen && client_data_seen {
            break;
        }
    }
    assert!(server_data_seen);
    assert!(client_data_seen);

    let mut client_body = [0u8; 16];
    let client_body_len =
        must_succeed(server_h3.recv_body(&mut server, client_stream_id, &mut client_body));
    assert_eq!(&client_body[..client_body_len], b"client-bidi");
    let mut server_body = [0u8; 16];
    let server_body_len =
        must_succeed(client_h3.recv_body(&mut client, server_stream_id, &mut server_body));
    assert_eq!(&server_body[..server_body_len], b"server-bidi");
}

#[test]
fn webtransport_bidirectional_prefix_retains_fragment_boundaries() {
    let (mut client, mut server, recv_info, client_h3, mut server_h3, session_id) =
        make_established_webtransport_connections();
    let stream_id = client_h3.next_stream_id;
    let mut signal = Vec::new();
    Connection::encode_varint(WEBTRANSPORT_STREAM_SIGNAL, &mut signal);
    must_succeed(client.stream_send(stream_id, &signal, false));
    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert_eq!(
        server_h3.streams.get(&stream_id).map(|stream| stream.frame_buffer.as_slice()),
        Some(signal.as_slice())
    );

    let mut remainder = Vec::new();
    Connection::encode_varint(session_id, &mut remainder);
    remainder.extend_from_slice(b"fragmented-bidi");
    must_succeed(client.stream_send(stream_id, &remainder, true));
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    assert!(matches!(
        server_h3.poll(&mut server),
        Ok(Some((event_stream_id, Event::Data))) if event_stream_id == stream_id
    ));
    let mut body = [0u8; 32];
    let body_len = must_succeed(server_h3.recv_body(&mut server, stream_id, &mut body));
    assert_eq!(&body[..body_len], b"fragmented-bidi");
}

#[test]
fn webtransport_streams_reject_unnegotiated_and_unknown_sessions() {
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections();
    let mut payload = Vec::new();
    Connection::encode_varint(WEBTRANSPORT_STREAM_SIGNAL, &mut payload);
    Connection::encode_varint(0, &mut payload);
    must_succeed(client.stream_send(0, &payload, false));
    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    assert!(matches!(server_h3.poll(&mut server), Err(Error::SettingsError)));

    let mut client_config = must_succeed(Config::new());
    client_config.set_webtransport_enabled(true);
    let mut server_config = must_succeed(Config::new());
    server_config.set_webtransport_enabled(true);
    let (mut client, mut server, recv_info, _client_h3, mut server_h3) =
        make_paired_h3_connections_with_configs(&client_config, &server_config);
    must_succeed(client.stream_send(0, &payload, false));
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    assert!(matches!(server_h3.poll(&mut server), Err(Error::IdError)));
}

#[test]
fn webtransport_stream_limits_and_duplicate_acceptance_fail_closed() {
    let (mut client, mut server, _recv_info, mut client_h3, mut server_h3, session_id) =
        make_established_webtransport_connections();
    assert!(matches!(
        server_h3.accept_webtransport_cover_session(&mut server, session_id),
        Err(Error::FrameUnexpected)
    ));
    for _ in 0..WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI {
        must_succeed(client_h3.send_webtransport_bidirectional_stream(
            &mut client,
            session_id,
            &[],
            true,
        ));
    }
    assert!(matches!(
        client_h3.send_webtransport_bidirectional_stream(&mut client, session_id, &[], true,),
        Err(Error::ExcessiveLoad)
    ));
}

#[test]
fn fragmented_h3_frame_body_is_retained_until_complete() {
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections();
    let stream_id = client_h3
        .send_request(
            &mut client,
            &[
                Header::new(b":method", b"POST"),
                Header::new(b":scheme", b"https"),
                Header::new(b":authority", b"example.test"),
                Header::new(b":path", b"/upload"),
            ],
            false,
        )
        .expect("request");
    let mut packet = [0u8; 2048];
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(
        matches!(server_h3.poll(&mut server), Ok(Some((id, Event::Headers { .. }))) if id == stream_id)
    );

    client.stream_send(stream_id, &[0x00, 0x03, 0xaa], false).expect("partial DATA");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Err(Error::Done)));
    assert_eq!(
        server_h3.streams.get(&stream_id).map(|stream| stream.frame_buffer.as_slice()),
        Some(&[0x00, 0x03, 0xaa][..])
    );

    client.stream_send(stream_id, &[0xbb, 0xcc], false).expect("remaining DATA");
    assert!(pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet));
    assert!(matches!(server_h3.poll(&mut server), Ok(Some((id, Event::Data))) if id == stream_id));
    let mut body = [0u8; 3];
    assert_eq!(server_h3.recv_body(&mut server, stream_id, &mut body).unwrap(), 3);
    assert_eq!(body, [0xaa, 0xbb, 0xcc]);
}

#[test]
fn h3_config_default_field_section_size() {
    let cfg = Config::new().expect("default H3 config must succeed");
    assert!(cfg.max_field_section_size() > 0, "default field section size must be positive");
}

#[test]
fn masque_connect_udp_request_roundtrip_over_paired_1rtt() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();

    let mut client_h3_cfg = Config::new().expect("cfg");
    client_h3_cfg.set_max_field_section_size(1024 * 1024);
    let mut client_h3 = super::h3::Connection::with_transport(&mut client, &client_h3_cfg).unwrap();

    let mut server_h3_cfg = Config::new().expect("cfg");
    server_h3_cfg.set_max_field_section_size(1024 * 1024);
    let mut server_h3 = super::h3::Connection::with_transport(&mut server, &server_h3_cfg).unwrap();

    let sid = client_h3
        .connect_udp_with_headers(&mut client, "proxy.test", "target.test:443", &[])
        .expect("connect_udp");
    client_h3.enable_masque_datagram(&mut client, sid).expect("enable_masque_datagram");
    client_h3.register_datagram_context(&mut client, sid, 1, 0).expect("register_datagram_context");

    let mut packet = [0u8; 2048];
    let mut request_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        match server_h3.poll(&mut server) {
            Ok(Some((rx_sid, Event::Headers { list, .. }))) => {
                assert_eq!(rx_sid, sid, "server must see the same request stream id");
                assert!(
                    list.iter().any(|h| {
                        h.name().eq_ignore_ascii_case(b":method")
                            && h.value().eq_ignore_ascii_case(b"CONNECT")
                    }),
                    "expected CONNECT method in request headers"
                );
                request_seen = true;
                break;
            }
            Ok(_) | Err(Error::Done) => {}
            Err(error) => panic!("server H3 poll failed: {:?}", error),
        }
    }
    assert!(request_seen, "request headers must reach the peer");

    assert!(
        server_h3.accept_masque_connect(&mut server, sid).expect("accept CONNECT-UDP"),
        "first accept must emit the readiness response"
    );
    assert!(server_h3.masque_established(sid));
    assert!(
        !server_h3.accept_masque_connect(&mut server, sid).expect("idempotent accept"),
        "accepted flow must not emit duplicate responses"
    );

    let mut response_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        match client_h3.poll(&mut client) {
            Ok(Some((rx_sid, Event::Headers { list, .. }))) => {
                assert_eq!(rx_sid, sid);
                assert!(list
                    .iter()
                    .any(|header| { header.name() == b":status" && header.value() == b"200" }));
                response_seen = true;
                break;
            }
            Ok(_) | Err(Error::Done) => {}
            Err(error) => panic!("client H3 poll failed: {:?}", error),
        }
    }
    assert!(response_seen, "response headers must reach the peer");
    assert!(client_h3.masque_established(sid), "client readiness requires the peer's 2xx response");
}

#[test]
fn masque_connect_udp_roundtrip_drains_all_peer_events_without_error() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let mut client_config = Config::new().expect("client config");
    client_config.set_qpack_max_table_capacity(64 * 1024);
    client_config.set_qpack_blocked_streams(16);
    let mut client_h3 = Connection::with_transport(&mut client, &client_config).expect("client h3");
    let sid = client_h3
        .connect_udp_with_headers(
            &mut client,
            "proxy.test",
            "target.test:443",
            &[
                Header::new(b"x-qf-auth", b"00112233445566778899aabbccddeeff"),
                Header::new(b"x-qf-generation", b"47"),
            ],
        )
        .expect("connect_udp");
    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    let mut server_config = Config::new().expect("server config");
    server_config.set_qpack_max_table_capacity(64 * 1024);
    server_config.set_qpack_blocked_streams(16);
    let mut server_h3 = Connection::with_transport(&mut server, &server_config).expect("server h3");

    let mut request_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match server_h3.poll(&mut server) {
                Ok(Some((rx_sid, Event::Headers { .. }))) => {
                    assert_eq!(rx_sid, sid);
                    request_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("server H3 full drain failed: {:?}", error),
            }
        }
        if request_seen {
            break;
        }
    }
    assert!(request_seen, "request headers must reach the peer");

    assert!(
        server_h3.accept_masque_connect(&mut server, sid).expect("accept CONNECT-UDP"),
        "first accept must emit the readiness response"
    );

    let mut response_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match client_h3.poll(&mut client) {
                Ok(Some((rx_sid, Event::Headers { .. }))) => {
                    assert_eq!(rx_sid, sid);
                    response_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("client H3 full drain failed: {:?}", error),
            }
        }
        if response_seen {
            break;
        }
    }
    assert!(response_seen, "response headers must reach the peer");
}

#[test]
fn masque_connect_udp_rejection_never_establishes_client_flow() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let mut client_h3 =
        Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
    let mut server_h3 =
        Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

    let sid =
        client_h3.connect_udp(&mut client, "proxy.test", "target.test:443").expect("connect_udp");
    let mut packet = [0u8; 2048];
    let mut request_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        match server_h3.poll(&mut server) {
            Ok(Some((_, Event::Headers { .. }))) => {
                request_seen = true;
                break;
            }
            Ok(_) | Err(Error::Done) => {}
            Err(error) => panic!("server H3 poll failed: {:?}", error),
        }
    }
    assert!(request_seen, "request headers must reach the peer");

    server_h3
        .send_response(&mut server, sid, &[Header::new(b":status", b"403")], false)
        .expect("reject CONNECT-UDP");
    let mut response_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        match client_h3.poll(&mut client) {
            Ok(Some((_, Event::Headers { .. }))) => {
                response_seen = true;
                break;
            }
            Ok(_) | Err(Error::Done) => {}
            Err(error) => panic!("client H3 poll failed: {:?}", error),
        }
    }
    assert!(response_seen, "response headers must reach the peer");
    assert!(!client_h3.masque_established(sid), "non-2xx response must keep the data plane closed");
}

#[test]
fn masque_data_frame_rejects_truncated_suffix_without_partial_event() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let _client_h3 =
        Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
    let mut server_h3 =
        Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    let _ = server_h3.poll(&mut server);

    const STREAM_ID: u64 = 248;
    server_h3.streams.insert(
        STREAM_ID,
        StreamState {
            _headers: Vec::new(),
            body_buffer: Vec::new(),
            frame_buffer: Vec::new(),
            _received_bytes: 0,
            _stream_type: StreamType::Masque,
            sent_bytes: 0,
            fin_sent: false,
            fin_received: false,
            masque_established: true,
            masque_capsule_buffer: Vec::new(),
            settings_received: false,
            receive_message_state: ReceiveMessageState::Body,
        },
    );

    let mut capsule_data = Connection::encode_capsule(0x00, b"valid");
    capsule_data.extend_from_slice(&[0x00, 0x40]);
    let mut frame = vec![0x00];
    Connection::encode_varint(capsule_data.len() as u64, &mut frame);
    frame.extend_from_slice(&capsule_data);
    client.stream_send(STREAM_ID, &frame, true).expect("send malformed MASQUE DATA frame");

    let (len, _) = client.send(&mut packet).expect("client send");
    server.recv(&mut packet[..len], &recv_info).expect("server recv");

    assert!(matches!(server_h3.poll(&mut server), Err(Error::FrameError)));
    assert!(server_h3
        .pending_events
        .iter()
        .all(|(_, event)| { !matches!(event, Event::MasqueCapsule { .. }) }));
    assert_eq!(
        server_h3.streams.get(&STREAM_ID).map(|stream| stream.masque_capsule_buffer.as_slice()),
        Some(&[0x00, 0x40][..])
    );
}

#[test]
fn raw_non_h3_stream_data_is_rejected() {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();

    let _client_h3 =
        Connection::with_transport(&mut client, &Config::new().unwrap()).expect("client h3");
    let mut server_h3 =
        Connection::with_transport(&mut server, &Config::new().unwrap()).expect("server h3");

    let mut packet = [0u8; 2048];
    let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
    let _ = server_h3.poll(&mut server);

    const RAW_STREAM_ID: u64 = 248;
    // DATA with a 1,048,577-byte length is a malformed bounded frame, not an
    // unknown extension. The parser must reject it before waiting for that body.
    let raw = vec![0x00, 0x80, 0x10, 0x00, 0x01];
    client.stream_send(RAW_STREAM_ID, &raw, false).expect("send malformed H3 stream data");

    let (len, _) = client.send(&mut packet).expect("client send");
    server.recv(&mut packet[..len], &recv_info).expect("server recv");

    let result = server_h3.poll(&mut server);
    assert!(matches!(result, Err(Error::ExcessiveLoad)));
}
