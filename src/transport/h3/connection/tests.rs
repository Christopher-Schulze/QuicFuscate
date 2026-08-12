use super::*;
use crate::transport::PROTOCOL_VERSION;

fn must_succeed<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("operation failed: {error:?}"),
    }
}

fn headers_equal(actual: &[Header], expected: &[Header]) -> bool {
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(actual, expected)| {
            actual.name() == expected.name() && actual.value() == expected.value()
        })
}

fn make_conn() -> super::super::super::Connection {
    let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let scid = [0u8; 8];
    crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
}

fn make_conn_with_limits(
    initial_max_data: u64,
    initial_max_stream_data_remote: u64,
) -> super::super::super::Connection {
    let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
    cfg.set_initial_max_data(initial_max_data);
    cfg.set_initial_max_stream_data_bidi_remote(initial_max_stream_data_remote);
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let scid = [1u8; 8];
    crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
}

fn make_conn_with_max_udp_payload_size(
    max_udp_payload_size: usize,
) -> super::super::super::Connection {
    let mut cfg = crate::transport::Config::new_with_version(PROTOCOL_VERSION).unwrap();
    cfg.set_max_recv_udp_payload_size(max_udp_payload_size);
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let scid = [2u8; 8];
    crate::transport::packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
}

fn pump_paired_1rtt_once(
    client: &mut super::super::super::Connection,
    server: &mut super::super::super::Connection,
    recv_info: &crate::transport::RecvInfo,
    packet: &mut [u8],
) -> bool {
    let mut progress = false;
    match client.send(packet) {
        Ok((len, _)) => {
            server.recv(&mut packet[..len], recv_info).expect("server recv");
            progress = true;
        }
        Err(crate::error::ConnectionError::Done) => {}
        Err(error) => panic!("client send failed: {:?}", error),
    }
    let reverse = crate::transport::RecvInfo { from: recv_info.to, to: recv_info.from, ecn: None };
    match server.send(packet) {
        Ok((len, _)) => {
            client.recv(&mut packet[..len], &reverse).expect("client recv");
            progress = true;
        }
        Err(crate::error::ConnectionError::Done) => {}
        Err(error) => panic!("server send failed: {:?}", error),
    }
    progress
}

fn make_paired_h3_connections() -> (
    super::super::super::Connection,
    super::super::super::Connection,
    crate::transport::RecvInfo,
    Connection,
    Connection,
) {
    let client_config = must_succeed(Config::new());
    let server_config = must_succeed(Config::new());
    make_paired_h3_connections_with_configs(&client_config, &server_config)
}

fn make_paired_h3_connections_with_configs(
    client_config: &Config,
    server_config: &Config,
) -> (
    super::super::super::Connection,
    super::super::super::Connection,
    crate::transport::RecvInfo,
    Connection,
    Connection,
) {
    use crate::transport::connection::{bench_paired_1rtt_connections, BenchConnectionPair};
    let BenchConnectionPair { mut client, mut server, recv_info } = bench_paired_1rtt_connections();
    let mut client_h3 = must_succeed(Connection::with_transport(&mut client, client_config));
    let mut server_h3 = must_succeed(Connection::with_transport(&mut server, server_config));
    let mut packet = [0u8; 2048];
    for _ in 0..4 {
        if !pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet) {
            break;
        }
        for (h3, transport) in [(&mut client_h3, &mut client), (&mut server_h3, &mut server)] {
            loop {
                match h3.poll(transport) {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(Error::Done) => break,
                    Err(error) => panic!("H3 startup drain failed: {error:?}"),
                }
            }
        }
    }
    (client, server, recv_info, client_h3, server_h3)
}

fn make_established_webtransport_connections() -> (
    super::super::super::Connection,
    super::super::super::Connection,
    crate::transport::RecvInfo,
    Connection,
    Connection,
    u64,
) {
    let mut client_config = must_succeed(Config::new());
    client_config.set_webtransport_enabled(true);
    let mut server_config = must_succeed(Config::new());
    server_config.set_webtransport_enabled(true);
    let (mut client, mut server, recv_info, mut client_h3, mut server_h3) =
        make_paired_h3_connections_with_configs(&client_config, &server_config);
    assert!(client_h3.peer_supports_webtransport());
    assert!(server_h3.peer_supports_webtransport());

    let session_id = must_succeed(client_h3.open_webtransport_cover_session(
        &mut client,
        "cdn.example.com",
        "/assets/wt/session",
    ));
    let mut packet = [0u8; 2048];
    let mut request_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match server_h3.poll(&mut server) {
                Ok(Some((stream_id, Event::Headers { list, .. }))) if stream_id == session_id => {
                    assert!(list.iter().any(|header| {
                        header.name() == b":protocol" && header.value() == b"webtransport-h3"
                    }));
                    request_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("server WebTransport setup failed: {error:?}"),
            }
        }
        if request_seen {
            break;
        }
    }
    assert!(request_seen, "WebTransport CONNECT request must reach the server");
    assert!(server_h3.webtransport_session_pending(session_id));
    must_succeed(server_h3.accept_webtransport_cover_session(&mut server, session_id));

    let mut response_seen = false;
    for _ in 0..8 {
        let _ = pump_paired_1rtt_once(&mut client, &mut server, &recv_info, &mut packet);
        loop {
            match client_h3.poll(&mut client) {
                Ok(Some((stream_id, Event::Headers { list, .. }))) if stream_id == session_id => {
                    assert!(list
                        .iter()
                        .any(|header| { header.name() == b":status" && header.value() == b"200" }));
                    response_seen = true;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(Error::Done) => break,
                Err(error) => panic!("client WebTransport setup failed: {error:?}"),
            }
        }
        if response_seen {
            break;
        }
    }
    assert!(response_seen, "WebTransport response must reach the client");
    assert!(client_h3.webtransport_session_established(session_id));
    assert!(server_h3.webtransport_session_established(session_id));
    (client, server, recv_info, client_h3, server_h3, session_id)
}

fn current_rss_bytes() -> Option<u64> {
    #[cfg(unix)]
    {
        let pid = std::process::id().to_string();
        let output =
            std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let rss_kib = String::from_utf8(output.stdout).ok()?.trim().parse::<u64>().ok()?;
        rss_kib.checked_mul(1024)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[test]
fn scheduled_push_stays_pending_when_promise_send_fails() {
    let mut conn = make_conn_with_limits(0, 0);
    let mut cfg = super::Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    h3.is_server = true;
    h3.next_uni_stream_id = 7;
    h3.peer_request_stream_id = Some(0);
    h3.peer_max_push_id = Some(MAX_STEALTH_PUSH_ID);

    let push_id = h3.create_stealth_push_promise("/blocked.css", "text/css", 512).expect("push");
    if let Some(promise) = h3.push_streams.get_mut(&push_id) {
        promise.scheduled_at = std::time::Instant::now() - std::time::Duration::from_millis(1);
    }

    h3.process_scheduled_push_streams(&mut conn);

    assert_eq!(h3.push_streams.get(&push_id).map(|p| p.state), Some(PushState::PendingPromise));
    assert!(!h3.streams.contains_key(&push_id));
    assert!(!h3.pending_events.iter().any(|(sid, _)| *sid == push_id));
}

#[test]
fn push_data_progress_tracks_payload_bytes() {
    const CHUNK: usize = 16 * 1024;
    let mut conn = make_conn();
    let mut cfg = super::Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    h3.is_server = true;
    h3.next_uni_stream_id = 7;
    h3.peer_request_stream_id = Some(0);
    h3.peer_max_push_id = Some(MAX_STEALTH_PUSH_ID);

    let push_id = h3
        .create_stealth_push_promise("/big.js", "application/javascript", CHUNK + 10)
        .expect("push");
    if let Some(promise) = h3.push_streams.get_mut(&push_id) {
        promise.scheduled_at = std::time::Instant::now() - std::time::Duration::from_millis(1);
    }

    h3.process_scheduled_push_streams(&mut conn);
    h3.process_push_data(&mut conn);

    let push_stream_id = h3
        .push_streams
        .get(&push_id)
        .and_then(|promise| promise.push_stream_id)
        .expect("push stream id");
    let st = h3.streams.get(&push_stream_id).expect("push stream");
    assert_eq!(st.sent_bytes, CHUNK);
    assert!(!st.fin_sent);
}

#[test]
fn poll_gc_prunes_auxiliary_state_under_stream_churn() {
    const ITERATIONS: u64 = 96;
    const COVER_BYTES: usize = 320 * 1024;

    let mut conn = make_conn();
    let cfg = super::Config::new().expect("cfg");
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let rss_before = current_rss_bytes();

    for iteration in 0..ITERATIONS {
        let stream_id = 10_000 + iteration * 4;
        h3.streams.insert(
            stream_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::Masque,
                sent_bytes: 0,
                fin_sent: true,
                fin_received: true,
                masque_established: true,
                masque_capsule_buffer: Vec::new(),
                settings_received: false,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        h3.finished_streams.insert(stream_id);
        h3.masque_flow.insert(stream_id, iteration);

        let push_id = 1_000_000 + iteration * 4;
        h3.push_streams.insert(
            push_id,
            PushPromise {
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_stream_id: 0,
                push_stream_id: Some(push_id),
                state: PushState::Complete,
                cover_payload: vec![0u8; COVER_BYTES],
                scheduled_at: std::time::Instant::now(),
            },
        );
        h3.streams.insert(
            push_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: vec![0u8; COVER_BYTES],
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::Push,
                sent_bytes: COVER_BYTES,
                fin_sent: true,
                fin_received: false,
                masque_established: false,
                masque_capsule_buffer: Vec::new(),
                settings_received: false,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        h3.finished_streams.insert(push_id);
        h3.masque_flow.insert(push_id, iteration);

        let _ = h3.poll(&mut conn);
        assert!(!h3.streams.contains_key(&stream_id));
        assert!(!h3.streams.contains_key(&push_id));
        assert!(!h3.finished_streams.contains(&stream_id));
        assert!(!h3.finished_streams.contains(&push_id));
        assert!(!h3.masque_flow.contains_key(&stream_id));
        assert!(!h3.masque_flow.contains_key(&push_id));
        assert!(!h3.push_streams.contains_key(&push_id));
    }

    assert!(h3.finished_streams.is_empty(), "finished stream IDs must not accumulate");
    assert!(h3.masque_flow.is_empty(), "MASQUE flow IDs must not accumulate");
    assert!(h3.push_streams.is_empty(), "completed push promises must be released");
    assert!(
        h3.streams.keys().all(|id| Some(*id) == h3.control_stream_id),
        "only the client control stream may remain"
    );

    if let (Some(before), Some(after)) = (rss_before, current_rss_bytes()) {
        const RSS_GROWTH_LIMIT: u64 = 32 * 1024 * 1024;
        assert!(
            after <= before.saturating_add(RSS_GROWTH_LIMIT),
            "H3 churn RSS grew from {before} to {after} bytes"
        );
    }
}

#[test]
fn h3_constructor_does_not_mutate_fec_environment() {
    let _env_lock = crate::env_utils::test_support::acquire_env_lock();
    let before = std::env::var_os("QUICFUSCATE_FEC_SWITCH_THRESH");
    let mut conn = make_conn();
    let cfg = super::Config::new().expect("cfg");
    let _h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    assert_eq!(std::env::var_os("QUICFUSCATE_FEC_SWITCH_THRESH"), before);
}

#[test]
fn h3_receive_buffers_follow_transport_payload_limits() {
    const MAX_PAYLOAD: usize = 16 * 1024;
    let mut conn = make_conn_with_max_udp_payload_size(MAX_PAYLOAD);
    let cfg = super::Config::new().expect("cfg");
    let h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

    assert_eq!(conn.max_recv_udp_payload_size(), MAX_PAYLOAD);
    assert_eq!(h3.masque_recv_buffer.len(), MAX_PAYLOAD);
    assert_eq!(h3.stream_recv_buffer.len(), 64 * 1024);
}

#[test]
fn stealth_cover_resource_plan_varies_by_seed_with_bounds() {
    let a =
        super::h3::Connection::build_stealth_cover_resource_plan("/assets", 0x1234_5678_9abc_def0);
    let b =
        super::h3::Connection::build_stealth_cover_resource_plan("/assets", 0x9876_5432_10fe_dcba);

    assert_ne!(a, b, "cover resource plans should vary by seed");
    for plan in [&a, &b] {
        assert!((3..=7).contains(&plan.len()), "cover plan size out of bounds");
        for (path, content_type, size) in plan {
            assert!(path.starts_with("/assets/"));
            assert!(!content_type.is_empty());
            assert!((1024..=320_000).contains(size));
        }
    }
}

#[test]
fn webtransport_cover_session_requires_negotiated_peer_settings() {
    let mut conn = make_conn();
    let mut cfg = must_succeed(super::Config::new());
    cfg.set_max_field_section_size(1024 * 1024);
    cfg.set_webtransport_enabled(true);
    let mut h3 = must_succeed(super::h3::Connection::with_transport(&mut conn, &cfg));

    assert!(matches!(
        h3.open_webtransport_cover_session(&mut conn, "cdn.example.com", "/assets/wt/session"),
        Err(Error::SettingsError)
    ));
    assert!(h3.webtransport_sessions.is_empty());
}

mod masque;

// ---- QPACK Encode/Decode Tests ---------------------------------------

#[test]
fn qpack_encode_decode_static_table_hit() {
    let mut enc = qpack::Encoder::new();
    let mut dec = qpack::Decoder::new();
    let headers = vec![
        Header::new(b":method", b"GET"),
        Header::new(b":scheme", b"https"),
        Header::new(b":path", b"/"),
    ];
    let plan = must_succeed(enc.prepare(0, &headers));
    assert!(plan.encoder_instructions.is_empty());
    assert_eq!(plan.field_section, [0x00, 0x00, 0xd1, 0xd7, 0xc1]);
    let (field_section, _, _) = plan.commit(&mut enc);
    let decoded = match must_succeed(dec.decode(0, &field_section)) {
        qpack::DecodeOutcome::Decoded(headers) => headers,
        qpack::DecodeOutcome::Blocked => panic!("static field section cannot block"),
    };
    assert_eq!(decoded.len(), 3, "must decode 3 headers");
    assert_eq!(decoded[0].name(), b":method");
    assert_eq!(decoded[0].value(), b"GET");
}

#[test]
fn qpack_encode_decode_literal_header() {
    let mut enc = qpack::Encoder::new();
    let mut dec = qpack::Decoder::new();
    let headers = vec![Header::new(b"x-custom-header", b"custom-value-123")];
    let plan = must_succeed(enc.prepare(0, &headers));
    assert!(plan.field_section.len() > 2);
    assert!(plan.encoder_instructions.is_empty());
    let (field_section, _, _) = plan.commit(&mut enc);
    let decoded = match must_succeed(dec.decode(0, &field_section)) {
        qpack::DecodeOutcome::Decoded(headers) => headers,
        qpack::DecodeOutcome::Blocked => panic!("literal field section cannot block"),
    };
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name(), b"x-custom-header");
    assert_eq!(decoded[0].value(), b"custom-value-123");
}

#[test]
fn qpack_encode_empty_headers_produces_minimal_output() {
    let enc = qpack::Encoder::new();
    let headers: Vec<Header> = vec![];
    let plan = must_succeed(enc.prepare(0, &headers));
    assert_eq!(plan.field_section, [0x00, 0x00]);
    assert!(plan.encoder_instructions.is_empty());
}

#[test]
fn qpack_truncated_field_section_fails_decompression() {
    let mut dec = qpack::Decoder::new();
    assert!(matches!(dec.decode(0, &[0x00]), Err(Error::QpackDecompressionFailed)));
}

// ---- HTTP/3 Frame Parsing: HEADERS, DATA, SETTINGS -------------------

#[test]
fn parse_frame_header_data_type() {
    // DATA frame: type=0x00, length=5
    let mut buf = vec![0x00]; // type
    Connection::encode_varint(5, &mut buf);
    buf.extend_from_slice(&[1, 2, 3, 4, 5]);
    let (frame_type, frame_len, header_offset) =
        Connection::parse_frame_header(&buf).expect("parse");
    assert_eq!(frame_type, 0x00, "frame type must be DATA");
    assert_eq!(frame_len, 5, "frame length must be 5");
    assert!(header_offset > 0, "header offset must be positive");
}

#[test]
fn parse_frame_header_headers_type() {
    let mut buf = vec![0x01]; // HEADERS type
    Connection::encode_varint(10, &mut buf);
    buf.extend_from_slice(&[0u8; 10]);
    let (frame_type, frame_len, _) = Connection::parse_frame_header(&buf).expect("parse");
    assert_eq!(frame_type, 0x01, "frame type must be HEADERS");
    assert_eq!(frame_len, 10);
}

#[test]
fn parse_frame_header_settings_type() {
    let mut buf = vec![0x04]; // SETTINGS type
    Connection::encode_varint(0, &mut buf);
    let (frame_type, frame_len, _) = Connection::parse_frame_header(&buf).expect("parse");
    assert_eq!(frame_type, 0x04, "frame type must be SETTINGS");
    assert_eq!(frame_len, 0);
}

#[test]
fn parse_frame_header_decodes_multibyte_frame_type() {
    let mut buf = Vec::new();
    Connection::encode_varint(0x40, &mut buf);
    Connection::encode_varint(3, &mut buf);
    buf.extend_from_slice(&[1, 2, 3]);
    let (frame_type, frame_len, header_len) =
        Connection::parse_frame_header(&buf).expect("parse extension frame");
    assert_eq!(frame_type, 0x40);
    assert_eq!(frame_len, 3);
    assert_eq!(header_len, 3);
}

#[test]
fn parse_frame_header_empty_buffer_returns_error() {
    let buf: Vec<u8> = vec![];
    let result = Connection::parse_frame_header(&buf);
    assert!(matches!(result, Err(Error::BufferTooShort)));
}

// ---- Stream Type Identification --------------------------------------

#[test]
fn connect_udp_assigns_masque_stream_type() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let sid = h3.connect_udp(&mut conn, "proxy.test", "target.test:443").expect("connect_udp");
    let st = h3.streams.get(&sid).expect("stream state");
    assert!(matches!(st._stream_type, StreamType::Masque));
}

#[test]
fn send_response_assigns_response_stream_type() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let headers = vec![Header::new(b":status", b"200")];
    h3.send_response(&mut conn, 0, &headers, false).expect("send_response");
    let st = h3.streams.get(&0).expect("stream state");
    assert!(matches!(st._stream_type, StreamType::Response));
    assert!(st.sent_bytes > 0, "response HEADERS must reach the transport stream");
}

// ---- Settings Frame Encode/Decode ------------------------------------

#[test]
fn config_new_defaults_are_valid_for_with_transport() {
    let mut conn = make_conn();
    let cfg = Config::new().expect("cfg");
    // Default config has max_field_section_size = 1MiB which is valid
    let h3 = super::h3::Connection::with_transport(&mut conn, &cfg);
    assert!(h3.is_ok(), "default Config must produce valid H3 connection");
}

#[test]
fn config_zero_max_field_section_rejects() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(0);
    let result = super::h3::Connection::with_transport(&mut conn, &cfg);
    assert!(
        matches!(result, Err(Error::ExcessiveLoad)),
        "zero max_field_section_size must be rejected"
    );
}

#[test]
fn config_excessive_max_field_section_rejects() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(32 * 1024 * 1024); // 32 MiB > 16 MiB limit
    let result = super::h3::Connection::with_transport(&mut conn, &cfg);
    assert!(
        matches!(result, Err(Error::ExcessiveLoad)),
        "excessive max_field_section_size must be rejected"
    );
}

#[test]
fn config_excessive_qpack_table_capacity_rejects() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_qpack_max_table_capacity(MAX_H3_SETTING_VALUE + 1);
    let result = super::h3::Connection::with_transport(&mut conn, &cfg);
    assert!(
        matches!(result, Err(Error::ExcessiveLoad)),
        "excessive QPACK table capacity must be rejected"
    );
}

#[test]
fn config_excessive_qpack_blocked_streams_rejects() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_qpack_blocked_streams(MAX_LOCAL_QPACK_BLOCKED_STREAMS + 1);
    let result = super::h3::Connection::with_transport(&mut conn, &cfg);
    assert!(
        matches!(result, Err(Error::ExcessiveLoad)),
        "excessive QPACK blocked-stream count must be rejected"
    );
}

// ---- GOAWAY Handling -------------------------------------------------

#[test]
fn goaway_blocks_new_requests() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    h3.goaway_sent = true;
    let result = h3.send_request(&mut conn, &[Header::new(b":method", b"GET")], true);
    assert!(
        matches!(result, Err(Error::ClosedCriticalStream)),
        "send_request after GOAWAY must fail"
    );
}

#[test]
fn goaway_received_blocks_new_requests() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    h3.goaway_received = true;
    let result = h3.send_request(&mut conn, &[Header::new(b":method", b"GET")], true);
    assert!(matches!(result, Err(Error::ClosedCriticalStream)));
}

// ---- Error Code Mapping ----------------------------------------------

#[test]
fn h3_error_from_transport_error() {
    let h3e: Error = Error::from(super::super::super::Error::BufferTooShort);
    assert!(matches!(h3e, Error::TransportError(_)));
    // Display works
    let s = format!("{}", h3e);
    assert!(!s.is_empty());
}

#[test]
fn h3_error_display_variants() {
    let variants = vec![
        Error::Done,
        Error::BufferTooShort,
        Error::InternalError,
        Error::ExcessiveLoad,
        Error::IdError,
        Error::StreamCreationError,
        Error::ClosedCriticalStream,
        Error::FrameUnexpected,
        Error::FrameError,
        Error::SettingsError,
        Error::QpackDecompressionFailed,
        Error::QpackEncoderStreamError,
        Error::QpackDecoderStreamError,
    ];
    for err in variants {
        let s = format!("{}", err);
        assert!(!s.is_empty(), "Display must produce non-empty string for {:?}", err);
    }
}

// ---- Request/Response Header Formatting ------------------------------

#[test]
fn send_request_allocates_stream_id() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let headers = vec![
        Header::new(b":method", b"GET"),
        Header::new(b":path", b"/"),
        Header::new(b":scheme", b"https"),
    ];
    let sid = h3.send_request(&mut conn, &headers, true).expect("send_request");
    assert!(h3.streams.contains_key(&sid));
    let st = h3.streams.get(&sid).expect("stream");
    assert!(matches!(st._stream_type, StreamType::Request));
    assert!(st.fin_sent, "fin must be set when fin=true");
}

#[test]
fn send_body_on_finished_stream_returns_done() {
    let mut conn = make_conn();
    let mut cfg = Config::new().expect("cfg");
    cfg.set_max_field_section_size(1024 * 1024);
    let mut h3 = super::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");
    let headers = vec![Header::new(b":method", b"GET")];
    let sid = h3.send_request(&mut conn, &headers, true).expect("send_request");
    // Stream is finished (fin_sent=true)
    let result = h3.send_body(&mut conn, sid, b"body", false);
    assert!(matches!(result, Err(Error::Done)), "send_body on finished stream must return Done");
}

// ---- Huffman Encoding ------------------------------------------------

#[test]
fn huffman_encode_decode_roundtrip() {
    let input = b"content-type";
    let est = qpack::huff_estimate_len(input);
    let mut encoded = vec![0u8; est + 8];
    let enc_len = qpack::huff_encode_into(input, &mut encoded);
    let mut decoded = vec![0u8; input.len() + 16];
    let dec_len = qpack::huff_decode_into(&encoded[..enc_len], &mut decoded).expect("huff decode");
    assert_eq!(&decoded[..dec_len], input);
}

#[test]
fn huffman_all_byte_values_roundtrip() {
    let input: Vec<u8> = (0u8..=u8::MAX).collect();
    let mut encoded = vec![0u8; qpack::huff_estimate_len(&input)];
    let enc_len = qpack::huff_encode_into(&input, &mut encoded);
    assert_eq!(enc_len, encoded.len());

    let mut decoded = vec![0u8; input.len()];
    let dec_len = qpack::huff_decode_into(&encoded, &mut decoded).expect("huff decode");
    assert_eq!(dec_len, input.len());
    assert_eq!(decoded, input);
}

#[test]
fn huffman_rfc_tail_symbols_encode_exactly() {
    let mut encoded = [0u8; 8];
    let len_228 = qpack::huff_encode_into(&[228], &mut encoded);
    assert_eq!(&encoded[..len_228], &[0xff, 0xff, 0xa7]);

    let len_255 = qpack::huff_encode_into(&[255], &mut encoded);
    assert_eq!(&encoded[..len_255], &[0xff, 0xff, 0xfb, 0xbf]);
}

#[test]
fn huffman_rejects_eos_and_invalid_padding() {
    let mut decoded = [0u8; 16];
    assert!(matches!(
        qpack::huff_decode_into(&[0xff, 0xff, 0xff, 0xff], &mut decoded),
        Err(Error::QpackDecompressionFailed)
    ));
    assert!(matches!(
        qpack::huff_decode_into(&[0x1e], &mut decoded),
        Err(Error::QpackDecompressionFailed)
    ));
}

#[test]
fn huffman_encode_ascii_range() {
    // Test encoding of common ASCII printable characters
    let input = b"GET /index.html HTTP/1.1";
    let est = qpack::huff_estimate_len(input);
    assert!(est > 0, "huffman estimate must be positive for non-empty input");
    assert!(est <= input.len(), "huffman should compress common HTTP text");
}

// ---- Varint Encoding/Decoding ----------------------------------------

#[test]
fn varint_roundtrip_small_values() {
    for val in [0u64, 1, 63, 127, 255] {
        let mut buf = Vec::new();
        Connection::encode_varint(val, &mut buf);
        let (decoded, used) = Connection::decode_varint(&buf).expect("decode");
        assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
        assert_eq!(used, buf.len());
    }
}

#[test]
fn varint_roundtrip_large_values() {
    for val in [16383u64, 16384, 1_000_000, u32::MAX as u64] {
        let mut buf = Vec::new();
        Connection::encode_varint(val, &mut buf);
        let (decoded, _) = Connection::decode_varint(&buf).expect("decode");
        assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
    }
}

// ---- Cover Traffic Generation ----------------------------------------

#[test]
fn fake_css_generates_correct_size() {
    let css = generate_fake_css(1000);
    assert_eq!(css.len(), 1000);
    // Should contain CSS-like content
    assert!(
        css.windows(4).any(|w| w == b"body" || w == b".rul"),
        "generated CSS must contain CSS-like text"
    );
}

#[test]
fn fake_js_generates_correct_size() {
    let js = generate_fake_js(500);
    assert_eq!(js.len(), 500);
}

#[test]
fn fake_image_starts_with_jpeg_magic() {
    let img = generate_fake_image_data(100);
    assert_eq!(&img[..2], &[0xFF, 0xD8], "fake image must start with JPEG magic bytes");
}

// ---- Header from_parts -----------------------------------------------

#[test]
fn header_from_parts_avoids_copy() {
    let name = b"x-test".to_vec();
    let value = b"value".to_vec();
    let h = Header::from_parts(name, value);
    assert_eq!(h.name(), b"x-test");
    assert_eq!(h.value(), b"value");
}

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
