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

mod control_and_protocol;
