// ============================================================================
// Inline unit tests – no real network or TLS required.
//
// All tests construct a Connection via new_with_role() and exercise internal
// state directly. Private fields are accessible from this child module.
// ============================================================================
use super::*;
use crate::error::ConnectionError;
use crate::transport::config::Config;
use crate::transport::PROTOCOL_VERSION;
#[cfg(feature = "zero_copy_dgram")]
use std::sync::Arc;

fn local() -> std::net::SocketAddr {
    "127.0.0.1:10000".parse().unwrap()
}
fn peer() -> std::net::SocketAddr {
    "127.0.0.1:10001".parse().unwrap()
}
fn recv_info() -> RecvInfo {
    RecvInfo { from: peer(), to: local(), ecn: None }
}

fn pmtu_state(enabled: bool, policy: PmtuPolicy) -> PmtuState {
    PmtuState::new(enabled, policy).expect("valid test PMTU policy")
}

/// Minimal connection used across tests; does not require TLS or sockets.
fn make_conn() -> Connection {
    Connection::new_with_role(
        b"test_scid_0123456789",
        local(),
        peer(),
        Config::new_with_version(PROTOCOL_VERSION).unwrap(),
        false, // client
    )
    .expect("valid test connection configuration")
}

fn encode_transport_parameter(parameter_id: u64, value: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(value.len() + 16);
    let mut scratch = [0u8; 8];
    let id_len = qf_transport_pn::varint::write_varint(parameter_id, &mut scratch).unwrap();
    encoded.extend_from_slice(&scratch[..id_len]);
    let value_len =
        qf_transport_pn::varint::write_varint(value.len() as u64, &mut scratch).unwrap();
    encoded.extend_from_slice(&scratch[..value_len]);
    encoded.extend_from_slice(value);
    encoded
}

fn max_udp_payload_transport_parameter(value: u64) -> Vec<u8> {
    let mut encoded_value = [0u8; 8];
    let value_len = qf_transport_pn::varint::write_varint(value, &mut encoded_value).unwrap();
    encode_transport_parameter(0x03, &encoded_value[..value_len])
}

fn enable_test_traffic_analysis(
    connection: &mut Connection,
    mode: crate::transport::config::TrafficAnalysisDefense,
    rate_pps: u32,
    target_size: u32,
) -> Instant {
    let constant_rate =
        matches!(mode, crate::transport::config::TrafficAnalysisDefense::ConstantRate);
    connection.config.set_traffic_analysis_defense(mode);
    connection.config.set_chaff_size_bytes(target_size);
    connection.pmtu = pmtu_state(false, PmtuPolicy::default());
    connection.traffic_analysis = Some(qf_stealth::TrafficAnalysisScheduler::with_lifecycle(
        rate_pps,
        target_size,
        true,
        constant_rate,
        Duration::from_secs(60),
        Duration::from_secs(5),
    ));
    connection.traffic_analysis_deadline().expect("established scheduler deadline")
}

#[test]
fn last_activity_marker_matches_the_heartbeat_activity_source() {
    let mut connection = make_conn();
    assert_eq!(connection.last_activity_marker(), connection.last_activity);

    connection.last_activity = Instant::now();
    assert_eq!(connection.last_activity_marker(), connection.last_activity);
}

/// Install a dummy 32-byte 1-RTT write secret so key_update() can toggle
/// key_phase without a real TLS handshake.
fn install_write_secret(c: &mut Connection) {
    c.crypto.write().write_secret_1rtt =
        Some(crate::secret::SecretBytes::new(vec![0u8; 32], "tls_1rtt_write_secret"));
}

struct FailingHeaderProtector;

impl crate::transport::packet::HeaderProtector for FailingHeaderProtector {
    fn new_mask(&self, _sample: &[u8]) -> Result<[u8; 5], ConnectionError> {
        Err(ConnectionError::CryptoError("injected header-protection failure".into()))
    }
}

fn make_v2_client() -> Connection {
    let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
    config
        .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
        .unwrap();
    let mut connection = Connection::new_with_role(b"client-scid", local(), peer(), config, false)
        .expect("valid test connection configuration");
    connection.set_initial_dcid(ConnectionId::from_ref(b"client-dcid"));
    connection
}

fn assert_reno_window_grows(connection: &mut Connection) {
    let initial_cwnd = connection.recovery.cwnd;
    let now = Instant::now();
    connection.recovery.on_packet_sent(1, 1200, now);
    connection.recovery.on_ack(1200, now);
    assert!(
        connection.recovery.cwnd > initial_cwnd,
        "configured Reno controller must grow its live congestion window after an ACK"
    );
}

#[test]
fn configured_reno_controller_drives_live_connection() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    config.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno);
    let mut connection = Connection::new_with_role(b"client-scid", local(), peer(), config, false)
        .expect("valid test connection configuration");

    assert_reno_window_grows(&mut connection);
}

#[test]
fn version_negotiation_restart_preserves_configured_reno_controller() {
    let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
    config
        .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
        .unwrap();
    config.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno);
    let mut connection = Connection::new_with_role(b"client-scid", local(), peer(), config, false)
        .expect("valid test connection configuration");
    connection.set_initial_dcid(ConnectionId::from_ref(b"client-dcid"));

    let mut vn = packet::generate_version_negotiation_packet(
        &[],
        &[PROTOCOL_VERSION],
        connection.scid.as_ref(),
        connection.initial_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(connection.recv(&mut vn, &recv_info()), Ok(vn.len()));
    assert_eq!(connection.config.version(), PROTOCOL_VERSION);
    assert_reno_window_grows(&mut connection);
}

#[test]
fn valid_vn_restarts_once_with_preferred_common_version_and_fresh_cids() {
    let mut client = make_v2_client();
    let original_scid = client.scid;
    let original_dcid = client.initial_dcid;
    client.recovery.on_packet_sent_in_space(
        recovery::PacketSpace::Application,
        0,
        1200,
        true,
        true,
        None,
        Instant::now(),
    );
    client.bytes_in_flight = 1200;
    let mut vn = packet::generate_version_negotiation_packet(
        &[],
        &[PROTOCOL_VERSION, super::super::version::generate_reserved_version()],
        original_scid.as_ref(),
        original_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut vn, &recv_info()), Ok(vn.len()));
    assert_eq!(client.config.version(), PROTOCOL_VERSION);
    assert!(client.version_negotiation.reacted_to_vn);
    assert_ne!(client.scid, original_scid);
    assert_ne!(client.initial_dcid, original_dcid);
    assert!(client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).is_empty());
    assert_eq!(client.bytes_in_flight, 0);

    let selected_scid = client.scid;
    let selected_dcid = client.initial_dcid;
    let mut second = packet::generate_version_negotiation_packet(
        &[],
        &[crate::transport::PROTOCOL_VERSION_V2],
        selected_scid.as_ref(),
        selected_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut second, &recv_info()), Ok(second.len()));
    assert_eq!(client.config.version(), PROTOCOL_VERSION);
}

#[test]
fn version_negotiation_restart_restores_local_datagram_ceiling() {
    let mut client = make_v2_client();
    client.config.set_max_send_udp_payload_size(1500);
    client.dgram_send_max_size = 1413;

    let mut vn = packet::generate_version_negotiation_packet(
        &[],
        &[PROTOCOL_VERSION],
        client.scid.as_ref(),
        client.initial_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut vn, &recv_info()), Ok(vn.len()));
    assert_eq!(client.dgram_send_max_size, 1500);
}

#[test]
fn peer_transport_limit_clamps_datagram_packetization() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    config.set_max_send_udp_payload_size(1500);
    let mut connection = Connection::new_with_role(b"client-scid", local(), peer(), config, false)
        .expect("valid test connection configuration");

    assert_eq!(connection.dgram_send_max_size, 1500);
    connection
        .apply_peer_transport_limits(&max_udp_payload_transport_parameter(1413))
        .expect("valid peer max_udp_payload_size");
    assert_eq!(connection.dgram_send_max_size, 1413);
    assert_eq!(connection.dgram_send(&vec![0u8; 1413]), Ok(()));
    assert_eq!(connection.dgram_send(&vec![0u8; 1414]), Err(ConnectionError::InvalidState));
}

#[test]
fn peer_transport_limit_rejects_malformed_duplicate_and_out_of_range_parameters() {
    let mut connection = make_conn();
    let initial_max = connection.dgram_send_max_size;

    assert_eq!(
        connection.apply_peer_transport_limits(&[0x03, 0x02, 0x40]),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(connection.dgram_send_max_size, initial_max);

    let mut duplicate = max_udp_payload_transport_parameter(1413);
    duplicate.extend(max_udp_payload_transport_parameter(1414));
    assert_eq!(
        connection.apply_peer_transport_limits(&duplicate),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(connection.dgram_send_max_size, initial_max);

    assert_eq!(
        connection.apply_peer_transport_limits(&max_udp_payload_transport_parameter(1199)),
        Err(ConnectionError::InvalidPacket)
    );
    assert_eq!(connection.dgram_send_max_size, initial_max);
}

#[test]
fn valid_retry_moves_token_adopts_cid_and_resets_initial_space() {
    let mut client = make_conn();
    let original_dcid = ConnectionId::from_ref(b"original-dcid");
    let retry_scid = b"retry-scid";
    let token = vec![0x10, 0x20, 0x30, 0x40];
    client.set_initial_dcid(original_dcid);
    client.next_send_pn_by_space[0] = 9;
    assert!(client.pkt_spaces[0].on_packet_recv(9));

    let header = packet::Header {
        ty: PacketType::Retry,
        version: PROTOCOL_VERSION,
        dcid: client.scid.as_ref().to_vec(),
        scid: retry_scid.to_vec(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: Some(token.clone()),
        versions: None,
        key_phase: false,
    };
    let mut storage = [0u8; 256];
    let header_len = packet::format_header(&header, &mut storage).expect("format Retry header");
    let mut retry = storage[..header_len].to_vec();
    packet::append_retry_tag(&mut retry, original_dcid.as_ref(), PROTOCOL_VERSION)
        .expect("append Retry integrity tag");

    let retry_len = retry.len();
    assert_eq!(client.recv(&mut retry, &recv_info()), Ok(retry_len));

    let expected_dcid = ConnectionId::from_ref(retry_scid);
    assert_eq!(client.config.initial_token, Some(token));
    assert_eq!(client.dcid, expected_dcid);
    assert!(client.dest_cids.contains(&expected_dcid));
    assert_eq!(client.next_send_pn_by_space[0], 0);
    assert!(client.pkt_spaces[0].largest_recv.is_none());
    assert!(!client.pkt_spaces[0].contains(9));
}

#[test]
fn spoofed_or_original_version_vn_is_ignored() {
    let mut client = make_v2_client();
    let original_dcid = client.initial_dcid;
    let mut wrong_cid = packet::generate_version_negotiation_packet(
        &[],
        &[PROTOCOL_VERSION],
        b"wrong",
        original_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut wrong_cid, &recv_info()), Ok(wrong_cid.len()));
    assert!(!client.version_negotiation.reacted_to_vn);

    let mut injected = packet::generate_version_negotiation_packet(
        &[],
        &[crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
        client.scid.as_ref(),
        original_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut injected, &recv_info()), Ok(injected.len()));
    assert!(!client.version_negotiation.reacted_to_vn);
    assert_eq!(client.config.version(), crate::transport::PROTOCOL_VERSION_V2);
}

#[test]
fn vn_without_common_version_terminates_connection() {
    let mut client = make_v2_client();
    let mut vn = packet::generate_version_negotiation_packet(
        &[],
        &[super::super::version::generate_reserved_version()],
        client.scid.as_ref(),
        client.initial_dcid.as_ref(),
    )
    .expect("generate VN");
    assert_eq!(client.recv(&mut vn, &recv_info()), Err(ConnectionError::VersionMismatch));
    assert!(client.is_closed);
}

#[test]
fn authenticated_version_information_rejects_injected_downgrade() {
    let mut client = make_v2_client();
    client.config.select_version(PROTOCOL_VERSION).unwrap();
    client.version_negotiation.chosen = PROTOCOL_VERSION;
    client.version_negotiation.negotiated = PROTOCOL_VERSION;
    client.version_negotiation.reacted_to_vn = true;
    let parameters = super::super::version::VersionInformation {
        chosen: PROTOCOL_VERSION,
        available: vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
    }
    .encode_parameter()
    .unwrap();

    assert!(client.validate_peer_version_information(Some(parameters)).is_err());
    assert!(client.pending_control.iter().any(|frame| matches!(
        frame,
        Frame::ConnectionClose { error_code, .. }
            if *error_code == super::super::version::VERSION_NEGOTIATION_ERROR_CODE
    )));
}

#[test]
fn v2_requires_authenticated_version_information() {
    let mut client = make_v2_client();
    assert!(client.validate_peer_version_information(Some(Vec::new())).is_err());
    assert!(client.is_closed);
}

#[test]
fn server_may_accept_missing_version_information_and_client_accepts_retiring_choice() {
    let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
    config
        .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
        .unwrap();
    let mut server = Connection::new_with_role(b"server-scid", local(), peer(), config, true)
        .expect("valid test connection configuration");
    assert_eq!(server.validate_peer_version_information(Some(Vec::new())), Ok(()));

    let mut client = make_v2_client();
    let parameters = super::super::version::VersionInformation {
        chosen: crate::transport::PROTOCOL_VERSION_V2,
        available: vec![PROTOCOL_VERSION],
    }
    .encode_parameter()
    .unwrap();
    assert_eq!(client.validate_peer_version_information(Some(parameters)), Ok(()));
}

#[test]
fn v1_fallback_accepts_legacy_server_without_version_information() {
    let mut client = make_v2_client();
    client.config.select_version(PROTOCOL_VERSION).unwrap();
    client.version_negotiation.chosen = PROTOCOL_VERSION;
    client.version_negotiation.negotiated = PROTOCOL_VERSION;
    client.version_negotiation.reacted_to_vn = true;
    assert_eq!(client.validate_peer_version_information(Some(Vec::new())), Ok(()));
    assert!(client.version_negotiation.peer_information_validated);
}

// ---- Priority 1: Flow Control ----------------------------------------

#[test]
fn flow_control_send_blocked_by_peer_max_data() {
    let mut c = make_conn();
    // Force connection window to 10 bytes – smaller than the send payload.
    c.peer_max_data = 10;
    let result = c.stream_send(0, &[0u8; 100], false);
    assert!(result.is_err(), "stream_send must fail when payload exceeds peer_max_data");
}

#[test]
fn flow_control_window_update_unblocks_send() {
    let mut c = make_conn();
    c.peer_max_data = 10;
    assert!(c.stream_send(0, &[0u8; 100], false).is_err(), "precondition: blocked");
    // Simulate peer sending MAX_DATA that opens the window.
    c.peer_max_data = 10_000;
    let sent = c.stream_send(0, &[0u8; 100], false).expect("should succeed after window update");
    assert_eq!(sent, 100);
}

#[test]
fn flow_control_data_blocked_frame_queued_on_block() {
    let mut c = make_conn();
    c.peer_max_data = 10;
    let _ = c.stream_send(0, &[0u8; 100], false);
    let has_data_blocked = c.pending_control.iter().any(|f| matches!(f, Frame::DataBlocked { .. }));
    assert!(
        has_data_blocked,
        "DataBlocked frame must be queued when connection window is exhausted"
    );
}

#[test]
fn repeated_connection_window_blocks_coalesce() {
    let mut c = make_conn();
    c.peer_max_data = 10;
    for _ in 0..8 {
        assert!(c.stream_send(0, &[0u8; 100], false).is_err());
    }

    assert_eq!(
        c.pending_control.iter().filter(|frame| matches!(frame, Frame::DataBlocked { .. })).count(),
        1,
        "retries in one connection window must retain one DataBlocked frame"
    );
}

#[test]
fn flow_control_stream_window_blocks_independently() {
    let mut c = make_conn();
    // Connection window is generous; stream window is the bottleneck.
    c.peer_max_data = 10_000;
    // Create the stream entry with a send call that succeeds, then tighten stream window.
    c.stream_send(0, b"", false).ok();
    if let Some(s) = c.streams.get_mut(&0) {
        s.max_stream_data_tx = 5;
    }
    let result = c.stream_send(0, &[0u8; 100], false);
    assert!(
        result.is_err(),
        "stream_send must fail when payload exceeds per-stream max_stream_data_tx"
    );
}

#[test]
fn flow_control_stream_data_blocked_frame_queued() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(0, b"", false).ok();
    if let Some(s) = c.streams.get_mut(&0) {
        s.max_stream_data_tx = 5;
    }
    let _ = c.stream_send(0, &[0u8; 100], false);
    let has_stream_blocked =
        c.pending_control.iter().any(|f| matches!(f, Frame::StreamDataBlocked { .. }));
    assert!(
        has_stream_blocked,
        "StreamDataBlocked frame must be queued when stream window is exhausted"
    );
}

#[test]
fn repeated_stream_window_blocks_coalesce_per_stream() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(0, b"", false).ok();
    if let Some(s) = c.streams.get_mut(&0) {
        s.max_stream_data_tx = 5;
    }
    for _ in 0..8 {
        assert!(c.stream_send(0, &[0u8; 100], false).is_err());
    }

    assert_eq!(
        c.pending_control
            .iter()
            .filter(|frame| matches!(frame, Frame::StreamDataBlocked { stream_id: 0, .. }))
            .count(),
        1,
        "retries in one stream window must retain one StreamDataBlocked frame"
    );
}

#[test]
fn pending_control_coalesces_latest_window_updates() {
    let mut c = make_conn();
    Connection::queue_control_frame(&mut c.pending_control, Frame::MaxData { max: 100 });
    Connection::queue_control_frame(&mut c.pending_control, Frame::MaxData { max: 200 });
    Connection::queue_control_frame(
        &mut c.pending_control,
        Frame::MaxStreamData { stream_id: 4, max: 10 },
    );
    Connection::queue_control_frame(
        &mut c.pending_control,
        Frame::MaxStreamData { stream_id: 4, max: 20 },
    );
    Connection::queue_control_frame(
        &mut c.pending_control,
        Frame::MaxStreamData { stream_id: 8, max: 30 },
    );

    assert_eq!(
        c.pending_control.iter().filter(|frame| matches!(frame, Frame::MaxData { .. })).count(),
        1
    );
    assert_eq!(
        c.pending_control
            .iter()
            .filter(|frame| matches!(frame, Frame::MaxStreamData { stream_id: 4, .. }))
            .count(),
        1
    );
    assert!(c.pending_control.iter().any(|frame| matches!(frame, Frame::MaxData { max: 200 })));
    assert!(c
        .pending_control
        .iter()
        .any(|frame| matches!(frame, Frame::MaxStreamData { stream_id: 4, max: 20 })));
    assert!(c
        .pending_control
        .iter()
        .any(|frame| matches!(frame, Frame::MaxStreamData { stream_id: 8, max: 30 })));
}

#[test]
fn pending_control_is_bounded_and_preserves_close_admission() {
    let mut c = make_conn();
    for probe in 0..(MAX_PENDING_CONTROL_FRAMES + 32) {
        Connection::queue_control_frame(
            &mut c.pending_control,
            Frame::Ping { mtu_probe: Some(probe) },
        );
    }
    assert_eq!(c.pending_control.len(), MAX_PENDING_CONTROL_FRAMES);

    Connection::queue_control_frame(
        &mut c.pending_control,
        Frame::ApplicationClose {
            error_code: 7,
            reason: std::borrow::Cow::Owned(b"overload".to_vec()),
        },
    );
    assert_eq!(c.pending_control.len(), MAX_PENDING_CONTROL_FRAMES);
    assert!(c
        .pending_control
        .iter()
        .any(|frame| matches!(frame, Frame::ApplicationClose { error_code: 7, .. })));
}

// ---- Priority 2: State Transitions ------------------------------------

#[test]
fn close_sets_closed_and_draining() {
    let mut c = make_conn();
    assert!(!c.is_closed(), "must not be closed initially");
    assert!(!c.is_draining, "must not be draining initially");
    c.close(true, 0, b"done").unwrap();
    assert!(c.is_closed(), "is_closed must be true after close()");
    assert!(c.is_draining, "is_draining must be true after close()");
}

#[test]
fn close_queues_application_close_frame() {
    let mut c = make_conn();
    c.close(true, 42, b"reason").unwrap();
    let has_app_close = c
        .pending_control
        .iter()
        .any(|f| matches!(f, Frame::ApplicationClose { error_code: 42, .. }));
    assert!(has_app_close, "close(app=true) must queue ApplicationClose frame");
}

#[test]
fn on_timeout_closes_connection_and_sets_timeout_error() {
    let mut c = make_conn();
    assert!(!c.is_draining());
    assert!(!c.is_timed_out());
    c.on_timeout();
    assert!(c.is_closed(), "idle timeout must make the connection reapable");
    assert!(c.is_draining(), "on_timeout() must set is_draining");
    assert!(c.is_timed_out(), "on_timeout() must make is_timed_out() return true");
    assert_eq!(c.local_error, Some(ConnectionError::Timeout));
}

#[test]
fn local_error_preserves_first_tls_provider_failure() {
    let mut c = make_conn();
    let provider_error = ConnectionError::TlsError("provider failure".to_string());
    c.record_local_error(provider_error.clone());
    c.record_local_error(ConnectionError::Transport("later shutdown error".to_string()));

    assert_eq!(c.local_error, Some(provider_error.clone()));
    assert_eq!(c.error(), Some(&provider_error));
}

/// Terminal timeout must retire recovery state, not only the connection's own counters.
/// A terminal close must not sit behind ordinary control traffic.
///
/// Under congestion bypass the control flush stops at the first ack-eliciting frame, so a
/// PING or MAX_DATA queued earlier used to hide a later CONNECTION_CLOSE until congestion
/// reopened or the idle timeout fired.
#[test]
fn queued_close_is_hoisted_ahead_of_ack_eliciting_control_frames() {
    let mut c = make_conn();

    c.pending_control.push_back(Frame::Ping { mtu_probe: None });
    c.pending_control.push_back(Frame::MaxData { max: 1_000_000 });
    c.pending_control.push_back(Frame::ConnectionClose {
        error_code: 0,
        frame_type: 0,
        reason: std::borrow::Cow::Borrowed(&[]),
    });
    c.pending_control.push_back(Frame::Ping { mtu_probe: None });

    let mut out = [0u8; 512];
    let (off, wrote_ack_eliciting) =
        c.flush_pending_control_frames(&mut out, 0, true).expect("bypass flush must succeed");

    assert!(off > 0, "the close must be emitted under congestion bypass");
    assert!(
        !wrote_ack_eliciting,
        "congestion bypass must not emit unrelated ack-eliciting control frames"
    );
    assert!(
        !c.pending_control.iter().any(|f| matches!(f, Frame::ConnectionClose { .. })),
        "the close must be consumed, not left queued behind the PING"
    );
    // The ack-eliciting frames stay queued for a later send that respects the cwnd.
    assert_eq!(
        c.pending_control.len(),
        3,
        "only the close is emitted under bypass; the rest remain queued in order"
    );
    assert!(matches!(c.pending_control.front(), Some(Frame::Ping { .. })));
}

/// Hoisting must preserve the relative order of everything else.
#[test]
fn hoisting_a_close_preserves_the_order_of_remaining_control_frames() {
    let mut c = make_conn();
    c.pending_control.push_back(Frame::MaxData { max: 1 });
    c.pending_control.push_back(Frame::MaxData { max: 2 });
    c.pending_control.push_back(Frame::ApplicationClose {
        error_code: 7,
        reason: std::borrow::Cow::Borrowed(&[]),
    });
    c.pending_control.push_back(Frame::MaxData { max: 3 });

    c.hoist_pending_close_to_front();

    assert!(matches!(c.pending_control.front(), Some(Frame::ApplicationClose { .. })));
    let remaining: Vec<u64> = c
        .pending_control
        .iter()
        .filter_map(|f| match f {
            Frame::MaxData { max } => Some(*max),
            _ => None,
        })
        .collect();
    assert_eq!(remaining, vec![1, 2, 3], "non-close frames keep their relative order");

    // Idempotent: a close already at the front stays there.
    c.hoist_pending_close_to_front();
    assert!(matches!(c.pending_control.front(), Some(Frame::ApplicationClose { .. })));
}

#[test]
fn on_timeout_retires_recovery_state_and_is_idempotent() {
    let mut conn = make_conn();
    conn.bytes_in_flight = 4800;

    conn.on_timeout();

    assert!(conn.is_closed, "terminal timeout closes the connection");
    assert!(conn.is_draining);
    assert_eq!(conn.bytes_in_flight, 0);
    assert_eq!(
        conn.recovery.bytes_in_flight, 0,
        "recovery in-flight accounting must be retired with the connection"
    );
    assert_eq!(conn.recovery.pto_count, 0, "no PTO backoff survives a terminal timeout");

    // A repeated timeout must not double-count or resurrect state.
    let lost_before = conn.stats.lost;
    conn.on_timeout();
    assert_eq!(conn.bytes_in_flight, 0);
    assert_eq!(conn.recovery.bytes_in_flight, 0);
    assert_eq!(
        conn.stats.lost, lost_before,
        "a second terminal timeout must not count another in-flight loss"
    );
}

#[test]
fn on_timeout_clears_bytes_in_flight() {
    let mut c = make_conn();
    c.bytes_in_flight = 4800;
    c.on_timeout();
    assert_eq!(c.bytes_in_flight, 0, "on_timeout() must zero bytes_in_flight");
}

// ---- Priority 3: Key Update ------------------------------------------

#[test]
fn key_phase_starts_false() {
    let c = make_conn();
    assert!(!c.key_phase, "initial key_phase must be false (RFC 9001 §5.4)");
}

#[test]
fn key_update_toggles_phase_with_installed_secret() {
    let mut c = make_conn();
    install_write_secret(&mut c);
    assert!(!c.key_phase);
    c.key_update().expect("transport-owned key update");
    assert!(c.key_phase, "key_update() must flip key_phase to true when write secret is present");
}

#[test]
fn key_update_twice_restores_phase() {
    let mut c = make_conn();
    install_write_secret(&mut c);
    c.key_update().expect("first transport-owned key update");
    assert!(c.key_phase, "after first update: key_phase = true");
    // The second update derives from the rotated secret – re-install a known secret
    // so the derivation chain can continue without panicking.
    install_write_secret(&mut c);
    c.key_update().expect("second transport-owned key update");
    assert!(!c.key_phase, "after second update: key_phase must return to false");
}

#[test]
fn key_update_preserves_packet_number_for_the_new_traffic_secret() {
    let mut c = make_conn();
    c.next_send_pn_by_space[2] = 1234;
    install_write_secret(&mut c);

    c.key_update().expect("transport-owned key update");

    assert_eq!(c.next_send_pn_by_space[2], 1234);
}

#[test]
fn key_update_does_not_fallback_when_provider_rejects() {
    let mut c = make_conn();
    c.enable_tls("chrome").expect("test rustls provider");
    install_write_secret(&mut c);
    let (secret_before, generation_before) = {
        let crypto = c.crypto.read();
        (
            crypto.write_secret_1rtt.as_ref().map(|secret| secret.as_slice().to_vec()),
            crypto.write_generation_1rtt,
        )
    };

    let error = c.key_update().expect_err("incomplete provider must reject key update");

    assert!(matches!(error, ConnectionError::TlsError(_)));
    assert!(!c.key_phase, "provider failure must not toggle the key phase");
    let crypto = c.crypto.read();
    assert_eq!(
        crypto.write_secret_1rtt.as_ref().map(|secret| secret.as_slice().to_vec()),
        secret_before,
        "provider failure must not rotate the transport write secret"
    );
    assert_eq!(
        crypto.write_generation_1rtt, generation_before,
        "provider failure must not rotate the transport write generation"
    );
    assert_eq!(c.local_error, Some(error));
}

#[test]
fn tls_crypto_failure_queues_connection_close() {
    let mut c = make_conn();
    c.enable_tls("chrome").expect("test rustls provider");

    let result = c.process_crypto_frame(
        qf_transport_types::QuicEncryptionLevel::Initial,
        0,
        std::borrow::Cow::Owned(vec![0xff; 64]),
    );

    assert!(matches!(result, Err(ConnectionError::TlsError(_))));
    assert!(c.is_closed(), "TLS failure must close the connection");
    assert!(matches!(c.local_error(), Some(ConnectionError::TlsError(_))));
    assert!(c.pending_control.iter().any(|frame| matches!(
        frame,
        Frame::ConnectionClose { error_code, .. } if (0x0100..=0x01ff).contains(error_code)
    )));
}

// ---- Priority 4: In-Flight / Congestion Control ----------------------

#[test]
fn can_send_allows_when_below_cwnd() {
    let c = make_conn();
    // Fresh connection: bytes_in_flight = 0, cwnd = INITIAL_WINDOW.
    assert!(c.can_send(100), "can_send(100) must be true on fresh connection");
}

#[test]
fn can_send_blocks_when_bytes_exceed_cwnd() {
    let mut c = make_conn();
    c.bytes_in_flight = c.cwnd + 1;
    assert!(!c.can_send(1), "can_send must return false when bytes_in_flight exceeds cwnd");
}

#[test]
fn bytes_in_flight_cleared_by_timeout_restores_can_send() {
    let mut c = make_conn();
    // Saturate the congestion window.
    c.bytes_in_flight = c.cwnd + 1;
    assert!(!c.can_send(1), "precondition: window saturated");
    c.on_timeout();
    assert_eq!(c.bytes_in_flight, 0, "on_timeout must clear bytes_in_flight");
    assert!(c.can_send(1), "can_send must be true after timeout clears in-flight");
}

// ---- Connection State Transitions ------------------------------------

#[test]
fn new_connection_starts_unestablished() {
    let c = make_conn();
    assert!(!c.is_established(), "fresh connection must not be established");
    assert!(!c.is_closed(), "fresh connection must not be closed");
    assert!(!c.is_draining, "fresh connection must not be draining");
}

#[test]
fn client_keeps_handshake_keys_after_half_rtt() {
    let mut connection = make_conn();
    connection
        .crypto
        .write()
        .install_aes_gcm_handshake(&[0x11u8; 32])
        .expect("install client handshake keys");
    connection.on_peer_one_rtt_packet();
    assert!(
        connection.crypto.read().seal_handshake.is_some(),
        "0.5-RTT must not drop the client's Handshake keys"
    );
    assert!(
        connection.crypto.read().seal_initial.is_none(),
        "Initial keys may be discarded once 1-RTT is in use"
    );
}

#[test]
fn client_discards_handshake_keys_after_handshake_ack() {
    let mut connection = make_conn();
    connection
        .crypto
        .write()
        .install_aes_gcm_handshake(&[0x22u8; 32])
        .expect("install client handshake keys");
    connection.confirm_client_handshake();
    assert!(
        connection.crypto.read().seal_handshake.is_none(),
        "a Handshake ACK confirms Finished and must drop Handshake keys"
    );
}

#[test]
fn server_keeps_handshake_keys_after_one_rtt() {
    let mut connection = Connection::new_with_role(
        b"test_scid_0123456789",
        local(),
        peer(),
        Config::new_with_version(PROTOCOL_VERSION).unwrap(),
        true,
    )
    .expect("valid test server connection");
    connection
        .crypto
        .write()
        .install_aes_gcm_handshake(&[0x33u8; 32])
        .expect("install server handshake keys");
    connection.on_peer_one_rtt_packet();
    assert!(
        connection.crypto.read().seal_handshake.is_some(),
        "server must keep Handshake keys so Finished can still be ACKed"
    );
}

#[test]
fn handshake_done_control_frames_coalesce() {
    let mut connection = make_conn();
    Connection::queue_control_frame(&mut connection.pending_control, Frame::HandshakeDone);
    Connection::queue_control_frame(&mut connection.pending_control, Frame::HandshakeDone);
    assert_eq!(
        connection
            .pending_control
            .iter()
            .filter(|frame| matches!(frame, Frame::HandshakeDone))
            .count(),
        1,
        "HANDSHAKE_DONE must be queued at most once"
    );
}

#[test]
fn post_handshake_envelope_waits_for_pending_handshake_flight() {
    let mut c = make_conn();
    c.is_established = true;
    c.crypto.write().crypto_handshake.send(b"client-finished").expect("queue handshake flight");

    assert!(!c.post_handshake_datagram_ready().expect("readiness probe"));

    let (_, flight) = c
        .next_crypto_frame(qf_transport_types::QuicEncryptionLevel::Handshake, usize::MAX)
        .expect("next handshake frame")
        .expect("pending handshake flight");
    assert_eq!(flight, b"client-finished");
    assert!(c.post_handshake_datagram_ready().expect("readiness probe"));
}

#[test]
fn server_role_sets_is_server_flag() {
    let s = Connection::new_with_role(
        b"server_cid_12345678",
        local(),
        peer(),
        Config::new_with_version(PROTOCOL_VERSION).unwrap(),
        true,
    )
    .expect("valid test connection configuration");
    assert!(s.is_server(), "server connection must report is_server=true");
}

#[test]
fn close_transport_queues_connection_close_frame() {
    let mut c = make_conn();
    c.close(false, 0x0a, b"flow_control").unwrap();
    let has_conn_close = c
        .pending_control
        .iter()
        .any(|f| matches!(f, Frame::ConnectionClose { error_code: 0x0a, .. }));
    assert!(has_conn_close, "close(app=false) must queue ConnectionClose frame");
}

#[test]
fn double_close_is_idempotent() {
    let mut pair = bench_paired_1rtt_connections();
    pair.client.close(false, 1, b"first").unwrap();
    pair.client.close(true, 2, b"second").unwrap();

    assert!(pair.client.is_closed(), "connection must remain closed after double close");
    assert!(pair.client.is_draining(), "connection must remain draining after double close");
    assert_eq!(pair.client.pending_control.len(), 1, "exactly one close frame must be queued");
    assert!(matches!(
        pair.client.pending_control.front(),
        Some(Frame::ConnectionClose { error_code: 1, reason, .. })
            if reason.as_ref() == b"first"
    ));

    let mut packet = [0u8; 1500];
    let (packet_len, _) = pair.client.send(&mut packet).expect("first close must serialize");
    assert!(pair.client.pending_control.is_empty(), "close frame must be removed after send");
    pair.server.recv(&mut packet[..packet_len], &pair.recv_info).expect("close must decrypt");
    assert_eq!(
        pair.server.remote_error(),
        Some(&ConnectionError::PeerConnectionClosed {
            error_code: 1,
            frame_type: 0,
            reason: b"first".to_vec(),
        })
    );
    assert!(matches!(pair.client.send(&mut packet), Err(ConnectionError::Done)));
}

// ---- Stream Open/Close and Flow Control ------------------------------

#[test]
fn stream_send_creates_stream_entry() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(4, b"hello", false).unwrap();
    assert!(c.streams.contains_key(&4), "stream_send must create stream entry");
}

#[test]
fn stream_send_with_fin_marks_send_fin() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(4, b"done", true).unwrap();
    let s = c.streams.get(&4).expect("stream must exist");
    assert!(s.send_fin, "stream must have send_fin set after fin=true");
}

#[test]
fn stream_send_after_fin_returns_final_size_error() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(4, b"done", true).unwrap();
    let err = c.stream_send(4, b"more", false).unwrap_err();
    assert!(
        matches!(err, crate::error::ConnectionError::FinalSize),
        "sending after FIN must return FinalSize error, got {:?}",
        err
    );
}

#[test]
fn stream_writable_list_tracks_active_streams() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(0, b"a", false).unwrap();
    c.stream_send(4, b"b", false).unwrap();
    assert!(c.writable_streams.contains(&0), "stream 0 must be writable");
    assert!(c.writable_streams.contains(&4), "stream 4 must be writable");
    assert!(c.writable_stream_ids.contains(&0));
    assert!(c.writable_stream_ids.contains(&4));
}

#[test]
fn stream_membership_sets_follow_queue_pop_lifecycle() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    c.stream_send(0, b"a", false).unwrap();
    assert_eq!(c.stream_writable_next(), Some(0));
    assert!(!c.writable_stream_ids.contains(&0));

    assert!(c.readable_stream_ids.insert(4));
    c.readable_streams.push_back(4);
    assert!(!c.readable_stream_ids.insert(4), "readable membership must deduplicate");
    assert_eq!(c.stream_readable_next(), Some(4));
    assert!(!c.readable_stream_ids.contains(&4));

    assert_eq!(c.enqueue_peer_stream_reset(8, 42), Ok(()));
    assert_eq!(c.enqueue_peer_stream_reset(8, 99), Ok(()));
    assert_eq!(c.stream_reset_next(), Some((8, 42)));
    assert!(!c.reset_stream_ids.contains(&8));
}

#[test]
fn peer_stream_reset_notifications_are_bounded_before_publication() {
    let mut c = make_conn();
    for stream_id in 0..MAX_PENDING_STREAM_RESETS as u64 {
        assert_eq!(c.enqueue_peer_stream_reset(stream_id, 7), Ok(()));
    }
    assert_eq!(
        c.enqueue_peer_stream_reset(MAX_PENDING_STREAM_RESETS as u64, 7),
        Err(crate::error::ConnectionError::ProtocolViolation)
    );
    assert!(!c.reset_stream_ids.contains(&(MAX_PENDING_STREAM_RESETS as u64)));
}

// ---- Error Handling: Transport Errors, Reset -------------------------

#[test]
fn local_error_none_on_fresh_connection() {
    let c = make_conn();
    assert!(c.local_error.is_none(), "fresh connection must not have local_error");
    assert!(c.remote_error.is_none(), "fresh connection must not have remote_error");
    assert!(c.error().is_none(), "fresh connection must not expose an error");
}

#[test]
fn close_sets_structured_local_application_error() {
    let mut c = make_conn();
    c.close(true, 7, b"bye").unwrap();
    assert!(
        matches!(
            c.local_error,
            Some(crate::error::ConnectionError::LocalApplicationClosed {
                error_code: 7,
                reason,
            }) if reason == b"bye"
        ),
        "application close must preserve its structured local error"
    );
}

#[test]
fn close_sets_structured_local_transport_error() {
    let mut c = make_conn();
    c.close(false, 9, b"transport bye").unwrap();
    assert_eq!(
        c.local_error(),
        Some(&crate::error::ConnectionError::LocalConnectionClosed {
            error_code: 9,
            frame_type: 0,
            reason: b"transport bye".to_vec(),
        })
    );
}

#[test]
fn close_preserves_earlier_tls_root_cause() {
    let mut c = make_conn();
    let root = ConnectionError::TlsError("provider failure".to_string());
    c.record_local_error(root.clone());
    c.close(false, 0x100, b"tls shutdown").unwrap();
    assert_eq!(c.local_error(), Some(&root));
    assert_eq!(c.error(), Some(&root));
}

#[test]
fn timeout_increments_lost_stats() {
    let mut c = make_conn();
    c.peer_max_data = 10_000;
    // Queue some data to trigger the lost counter in on_timeout
    c.stream_send(0, b"some data for timeout test", false).unwrap();
    let lost_before = c.stats.lost;
    c.on_timeout();
    assert!(
        c.stats.lost > lost_before,
        "on_timeout must increment lost stats when streams have pending data"
    );
}

// ---- 0-RTT Early Data Paths ------------------------------------------

#[test]
fn is_in_early_data_when_configured() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    cfg.enable_early_data = true;
    let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false)
        .expect("valid test connection configuration");
    assert!(c.is_in_early_data(), "connection with enable_early_data must report is_in_early_data");
}

#[test]
fn not_in_early_data_when_established() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    cfg.enable_early_data = true;
    let mut c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false)
        .expect("valid test connection configuration");
    c.is_established = true;
    assert!(!c.is_in_early_data(), "established connection must not be in early data");
}

#[test]
fn not_in_early_data_when_disabled() {
    let c = make_conn();
    assert!(
        !c.is_in_early_data(),
        "connection without enable_early_data must not be in early data"
    );
}

// ---- Idle Timeout and Keepalive --------------------------------------

#[test]
fn timeout_returns_some_duration() {
    let c = make_conn();
    let t = c.timeout();
    assert!(t.is_some(), "timeout() must return Some");
    assert!(t.unwrap() > Duration::from_secs(0), "timeout must be positive");
}

#[test]
fn timeout_uses_configured_max_idle_timeout() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    config.set_max_idle_timeout(1_234);
    let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), config, false)
        .expect("valid test connection configuration");

    assert_eq!(c.timeout(), Some(Duration::from_millis(1_234)));
}

#[test]
fn zero_max_idle_timeout_disables_idle_expiry() {
    let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
    config.set_max_idle_timeout(0);
    let mut c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), config, false)
        .expect("valid test connection configuration");
    c.last_activity = Instant::now() - Duration::from_secs(60);

    assert_eq!(c.timeout(), None);
    assert!(!c.idle_timeout_elapsed());
}

#[test]
fn on_timeout_does_not_inflate_rtt() {
    // RFC 9000 §5.1: RTT estimate is only updated from ACK samples,
    // not from timeout events. The previous code added 100ms on every
    // timeout, causing monotonic RTT inflation (0→385ms on loopback).
    // This test verifies the fix: on_timeout must NOT change self.rtt.
    let mut c = make_conn();
    let rtt_before = c.rtt;
    c.on_timeout();
    assert_eq!(
        c.rtt, rtt_before,
        "on_timeout must NOT inflate RTT - only ACK samples update RTT (RFC 9000 §5.1)"
    );
}

#[test]
fn multiple_timeouts_accumulate() {
    let mut c = make_conn();
    c.on_timeout();
    c.on_timeout();
    assert!(c.timeout_count >= 2, "multiple on_timeout calls must accumulate timeout_count");
}

mod flow_and_packet;
mod recovery_and_scheduling;
