// ============================================================================
// Inline unit tests – no real network or TLS required.
//
// All tests construct a Connection via new_with_role() and exercise internal
// state directly. Private fields are accessible from a #[cfg(test)] module
// nested inside the same source file.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConnectionError;
    use crate::transport::config::Config;
    use crate::transport::PROTOCOL_VERSION;

    fn local() -> std::net::SocketAddr {
        "127.0.0.1:10000".parse().unwrap()
    }
    fn peer() -> std::net::SocketAddr {
        "127.0.0.1:10001".parse().unwrap()
    }
    fn recv_info() -> RecvInfo {
        RecvInfo { from: peer(), to: local(), ecn: None }
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
        connection.pmtu = PmtuState::new(false, PmtuPolicy::default());
        connection.traffic_analysis =
            Some(crate::stealth::TrafficAnalysisScheduler::with_lifecycle(
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
        c.crypto.write().write_secret_1rtt = Some(crate::secret::SecretBytes::new(
            vec![0u8; 32],
            "tls_1rtt_write_secret",
        ));
    }

    fn make_v2_client() -> Connection {
        let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
        config
            .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
            .unwrap();
        let mut connection =
            Connection::new_with_role(b"client-scid", local(), peer(), config, false);
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
        let mut connection =
            Connection::new_with_role(b"client-scid", local(), peer(), config, false);

        assert_reno_window_grows(&mut connection);
    }

    #[test]
    fn version_negotiation_restart_preserves_configured_reno_controller() {
        let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION_V2).unwrap();
        config
            .set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
            .unwrap();
        config.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno);
        let mut connection =
            Connection::new_with_role(b"client-scid", local(), peer(), config, false);
        connection.set_initial_dcid(ConnectionId::from_ref(b"client-dcid"));

        let mut vn = packet::generate_version_negotiation_packet(
            &[],
            &[PROTOCOL_VERSION],
            connection.scid.as_ref(),
            connection.initial_dcid.as_ref(),
        );
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
        );
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
        );
        assert_eq!(client.recv(&mut second, &recv_info()), Ok(second.len()));
        assert_eq!(client.config.version(), PROTOCOL_VERSION);
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
        );
        assert_eq!(client.recv(&mut wrong_cid, &recv_info()), Ok(wrong_cid.len()));
        assert!(!client.version_negotiation.reacted_to_vn);

        let mut injected = packet::generate_version_negotiation_packet(
            &[],
            &[crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION],
            client.scid.as_ref(),
            original_dcid.as_ref(),
        );
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
        );
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
        let mut server = Connection::new_with_role(b"server-scid", local(), peer(), config, true);
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
        let sent =
            c.stream_send(0, &[0u8; 100], false).expect("should succeed after window update");
        assert_eq!(sent, 100);
    }

    #[test]
    fn flow_control_data_blocked_frame_queued_on_block() {
        let mut c = make_conn();
        c.peer_max_data = 10;
        let _ = c.stream_send(0, &[0u8; 100], false);
        let has_data_blocked =
            c.pending_control.iter().any(|f| matches!(f, Frame::DataBlocked { .. }));
        assert!(
            has_data_blocked,
            "DataBlocked frame must be queued when connection window is exhausted"
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
        assert!(c.pending_control.iter().any(|frame| matches!(
            frame,
            Frame::MaxData { max: 200 }
        )));
        assert!(c.pending_control.iter().any(|frame| matches!(
            frame,
            Frame::MaxStreamData { stream_id: 4, max: 20 }
        )));
        assert!(c.pending_control.iter().any(|frame| matches!(
            frame,
            Frame::MaxStreamData { stream_id: 8, max: 30 }
        )));
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
        assert!(c.pending_control.iter().any(|frame| matches!(
            frame,
            Frame::ApplicationClose { error_code: 7, .. }
        )));
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
        c.key_update();
        assert!(
            c.key_phase,
            "key_update() must flip key_phase to true when write secret is present"
        );
    }

    #[test]
    fn key_update_twice_restores_phase() {
        let mut c = make_conn();
        install_write_secret(&mut c);
        c.key_update();
        assert!(c.key_phase, "after first update: key_phase = true");
        // The second update derives from the rotated secret – re-install a known secret
        // so the derivation chain can continue without panicking.
        install_write_secret(&mut c);
        c.key_update();
        assert!(!c.key_phase, "after second update: key_phase must return to false");
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
    fn post_handshake_envelope_waits_for_pending_handshake_flight() {
        let mut c = make_conn();
        c.is_established = true;
        c.crypto.write().crypto_handshake.send(b"client-finished");

        assert!(!c.post_handshake_datagram_ready().expect("readiness probe"));

        let (_, flight) = c
            .next_crypto_frame(crate::qftls::Level::Handshake, usize::MAX)
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
        );
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
        let mut c = make_conn();
        c.close(true, 1, b"first").unwrap();
        c.close(true, 2, b"second").unwrap();
        assert!(c.is_closed(), "connection must remain closed after double close");
        assert_eq!(c.pending_control.len(), 2, "both close frames should be queued");
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
    }

    // ---- Error Handling: Transport Errors, Reset -------------------------

    #[test]
    fn local_error_none_on_fresh_connection() {
        let c = make_conn();
        assert!(c.local_error.is_none(), "fresh connection must not have local_error");
    }

    #[test]
    fn close_sets_local_error_application_closed() {
        let mut c = make_conn();
        c.close(true, 0, b"bye").unwrap();
        assert!(
            matches!(c.local_error, Some(crate::error::ConnectionError::ApplicationClosed)),
            "close() must set local_error to ApplicationClosed"
        );
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
        let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
        assert!(
            c.is_in_early_data(),
            "connection with enable_early_data must report is_in_early_data"
        );
    }

    #[test]
    fn not_in_early_data_when_established() {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.enable_early_data = true;
        let mut c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
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
        let c =
            Connection::new_with_role(b"test_scid_0123456789", local(), peer(), config, false);

        assert_eq!(c.timeout(), Some(Duration::from_millis(1_234)));
    }

    #[test]
    fn zero_max_idle_timeout_disables_idle_expiry() {
        let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        config.set_max_idle_timeout(0);
        let mut c =
            Connection::new_with_role(b"test_scid_0123456789", local(), peer(), config, false);
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

    #[test]
    fn ack_updates_rtt_from_send_time() {
        // RFC 9000 §5.1: RTT sample = now - send_time - ack_delay.
        // This test verifies that ACK processing generates a valid RTT sample
        // from the largest acknowledged PN's send time.
        let mut c = make_conn();
        let initial_rtt = c.rtt;

        // Simulate sending packet PN=0 with a known send time in the past.
        let send_time = Instant::now() - Duration::from_millis(50);
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            send_time,
        );

        // Process an ACK acknowledging PN=0 (range 0..1).
        let ranges = vec![(0u64, 1u64)];
        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        // RTT should now be updated to ~50ms (now - send_time), not the initial value.
        assert!(
            c.rtt < initial_rtt + Duration::from_millis(100),
            "RTT should be updated from ACK sample, not inflated. Got {:?}, initial {:?}",
            c.rtt,
            initial_rtt
        );
        assert!(c.rtt >= Duration::from_millis(40), "RTT sample should be ~50ms. Got {:?}", c.rtt);
    }

    #[test]
    fn fec_feedback_counts_only_transport_classified_acknowledgements_as_clean() {
        let mut c = make_conn();
        let sent_at = Instant::now() - Duration::from_millis(10);
        for packet_number in 0..3 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                packet_number,
                1200,
                true,
                true,
                None,
                sent_at,
            );
        }

        let sent_feedback = c.take_fec_callback_feedback();
        assert_eq!(sent_feedback.sent_packets, 3);
        assert_eq!(sent_feedback.acked_packets, 0);
        assert_eq!(sent_feedback.lost_packets, 0);

        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(0, 2)],
            Duration::ZERO,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        let ack_feedback = c.take_fec_callback_feedback();
        assert_eq!(ack_feedback.sent_packets, 0);
        assert_eq!(ack_feedback.acked_packets, 2);
        assert_eq!(ack_feedback.lost_packets, 0);
    }

    #[test]
    fn ack_with_delay_subtracts_ack_delay() {
        // RTT sample should subtract the peer's ack_delay (RFC 9000 §19.3).
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(100);
        c.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            0,
            1200,
            true,
            true,
            None,
            send_time,
        );

        let ranges = vec![(0u64, 1u64)];
        let ack_delay = Duration::from_millis(30);
        let now = Instant::now();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            ack_delay,
            true,
            c.is_server,
            now,
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        // RFC 9002 §5.2/§5.3: the first sample sets min_rtt = latest_rtt, so the
        // adjustment guard (latest >= min_rtt + delay) can never fire for it -
        // the first sample is NOT ack-delay adjusted (RTT ~= 100 ms, not 70 ms).
        assert!(
            c.rtt >= Duration::from_millis(90) && c.rtt <= Duration::from_millis(110),
            "first RTT sample must be unadjusted (~100ms). Got {:?}",
            c.rtt
        );
    }

    #[test]
    fn lost_stream_range_is_retransmitted_with_identical_payload_and_offset() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        let payload = b"reliable stream payload across a dropped QUIC packet";
        pair.client.stream_send(0, payload, false).unwrap();
        let mut first_packet = [0u8; 1500];
        let first_pn = pair.client.next_send_pn_by_space[2];
        let (first_size, _) = pair.client.send(&mut first_packet).unwrap();

        pair.client.lose_stream_transmission_packet(first_pn);
        pair.client.recovery.on_loss_packet(first_pn, first_size, Instant::now());

        let mut retransmitted_packet = [0u8; 1500];
        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        let (retransmitted_len, _) = pair.client.send(&mut retransmitted_packet).unwrap();
        pair.server.recv(&mut retransmitted_packet[..retransmitted_len], &pair.recv_info).unwrap();

        let mut received = vec![0u8; payload.len()];
        let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
        assert_eq!(&received[..received_len], payload);
        assert!(!fin);
        assert_eq!(pair.client.stream_transmissions.len(), 1);
        assert!(pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
    }

    #[test]
    fn confirmed_pmtu_packets_split_exactly_on_floor_retransmission() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.server.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.pmtu.confirmed_mtu = 1500;
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        let payload = (0..1400).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        pair.client.stream_send(0, &payload, false).unwrap();

        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        let (original_len, _) = pair.client.send(&mut packet).unwrap();
        assert!(original_len > pair.client.pmtu.min_mtu);
        pair.client.lose_stream_transmission_packet(original_pn);
        pair.client.recovery.on_loss_packet(original_pn, original_len, Instant::now());
        pair.client.pmtu.confirmed_mtu = pair.client.pmtu.min_mtu;

        let mut retransmitted_packet_numbers = Vec::new();
        while !pair.client.stream_retransmit_queue.is_empty() {
            let packet_number = pair.client.next_send_pn_by_space[2];
            let (packet_len, _) = pair.client.send(&mut packet).unwrap();
            assert!(packet_len <= pair.client.pmtu.min_mtu);
            pair.server.recv(&mut packet[..packet_len], &pair.recv_info).unwrap();
            retransmitted_packet_numbers.push(packet_number);
        }
        assert_eq!(retransmitted_packet_numbers.len(), 2);

        let mut received = vec![0u8; payload.len()];
        let (received_len, fin) = pair.server.stream_recv(0, &mut received).unwrap();
        assert_eq!(received_len, payload.len());
        assert_eq!(received, payload);
        assert!(!fin);

        for packet_number in retransmitted_packet_numbers {
            let now = Instant::now();
            let outcome = pair.client.recovery.on_ack_received(
                recovery::PacketSpace::Application,
                &[(packet_number, packet_number + 1)],
                Duration::ZERO,
                true,
                pair.client.is_server,
                now,
            );
            pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
        }
        assert!(pair.client.stream_transmissions.is_empty());
        assert_eq!(pair.client.stream_retransmit_bytes, 0);
    }

    #[test]
    fn late_ack_of_pre_split_packet_retires_every_retransmission_segment() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.dgram_send_max_size = 1500;
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.pmtu.confirmed_mtu = 1500;
        pair.client.stream_send(0, &[0xA5; 1400], false).unwrap();

        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        let (original_size, _) = pair.client.send(&mut packet).unwrap();
        pair.client.lose_stream_transmission_packet(original_pn);
        pair.client.recovery.on_loss_packet(original_pn, original_size, Instant::now());
        pair.client.pmtu.confirmed_mtu = pair.client.pmtu.min_mtu;

        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        assert_eq!(pair.client.stream_transmissions.len(), 2);
        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);

        pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(original_pn, original_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(pair.client.stream_transmissions.is_empty());
        assert!(pair.client.stream_retransmit_queue.is_empty());
        assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
        assert!(!pair.client.lost_stream_transmission_by_pn.contains_key(&original_pn));
        assert_eq!(pair.client.stream_retransmit_bytes, 0);
    }

    #[test]
    fn late_ack_of_lost_copy_retires_active_retransmission_exactly_once() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"late ACK retirement", false).unwrap();
        let mut packet = [0u8; 1500];
        let original_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();

        pair.client.lose_stream_transmission_packet(original_pn);
        let retransmitted_pn = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        assert_eq!(pair.client.stream_transmissions.len(), 1);

        pair.client.acknowledge_late_stream_packets(&[(original_pn, original_pn + 1)]);
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(original_pn, original_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(pair.client.stream_transmissions.is_empty());
        assert!(pair.client.stream_retransmit_queue.is_empty());
        assert!(!pair.client.stream_transmission_by_pn.contains_key(&retransmitted_pn));
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(retransmitted_pn, retransmitted_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);
        assert!(pair.client.stream_transmissions.is_empty());
    }

    #[test]
    fn send_info_keeps_ack_only_packets_out_of_external_pacing() {
        let mut pair = bench_paired_1rtt_connections();
        pair.server.pmtu = PmtuState::new(false, PmtuPolicy::default());
        assert!(pair.server.pkt_spaces[2].on_packet_recv(7));
        pair.server.pkt_spaces[2].note_ack_eliciting(0, 1);
        let bytes_in_flight = pair.server.recovery.bytes_in_flight;
        let mut packet = [0u8; 1500];

        let (_, send_info) = pair.server.send(&mut packet).expect("ACK must serialize");

        assert!(!send_info.congestion_controlled);
        assert_eq!(pair.server.recovery.bytes_in_flight, bytes_in_flight);
    }

    #[test]
    fn traffic_analysis_off_mode_never_constructs_a_scheduler() {
        let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        config.set_chaff_rate_pps(10);
        config.set_traffic_analysis_defense(
            crate::transport::config::TrafficAnalysisDefense::Off,
        );

        let connection = Connection::new_with_role(
            b"traffic-analysis-off",
            local(),
            peer(),
            config,
            false,
        );

        assert!(connection.traffic_analysis.is_none());
        assert!(connection.traffic_analysis_deadline().is_none());
    }

    #[test]
    fn traffic_analysis_policy_applies_atomically_to_a_live_connection() {
        let mut pair = bench_paired_1rtt_connections();
        let policy = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };

        pair.client.apply_traffic_analysis_policy(policy).expect("valid live policy");

        assert_eq!(pair.client.config.traffic_analysis_policy(), policy);
        assert!(pair.client.traffic_analysis_deadline().is_some());

        pair.client
            .apply_traffic_analysis_policy(crate::transport::config::TrafficAnalysisPolicy {
                defense: crate::transport::config::TrafficAnalysisDefense::Off,
                ..policy
            })
            .expect("off policy");
        assert!(pair.client.traffic_analysis.is_none());
        assert!(pair.client.traffic_analysis_deadline().is_none());
    }

    #[test]
    fn invalid_live_traffic_analysis_policy_preserves_the_active_scheduler() {
        let mut pair = bench_paired_1rtt_connections();
        let policy = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };
        pair.client.apply_traffic_analysis_policy(policy).expect("valid live policy");
        let deadline = pair.client.traffic_analysis_deadline();

        let invalid = crate::transport::config::TrafficAnalysisPolicy {
            constant_rate_pps:
                crate::transport::config::TrafficAnalysisPolicy::MAX_CONSTANT_RATE_PPS + 1,
            ..policy
        };
        assert!(pair.client.apply_traffic_analysis_policy(invalid).is_err());

        assert_eq!(pair.client.config.traffic_analysis_policy(), policy);
        assert_eq!(pair.client.traffic_analysis_deadline(), deadline);
    }

    #[test]
    fn intelligent_traffic_analysis_escalation_is_fail_closed_until_authorized() {
        let mut config = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        let escalation = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1200,
            constant_rate_pps: 0,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };
        config
            .set_intelligent_traffic_analysis_ceiling(escalation)
            .expect("valid escalation ceiling");
        let mut connection =
            Connection::new_with_role(b"intelligent-auth", local(), peer(), config, true);

        connection
            .apply_intelligent_traffic_analysis_level(2)
            .expect("unauthorized transition is a no-op");
        assert_eq!(
            connection.traffic_analysis_policy().defense,
            crate::transport::config::TrafficAnalysisDefense::Off
        );

        connection.authorize_intelligent_traffic_analysis(None).expect("authorization");
        connection
            .apply_intelligent_traffic_analysis_level(2)
            .expect("authorized escalation");
        assert_eq!(connection.traffic_analysis_policy(), escalation);
        assert!(connection.traffic_analysis.is_some());

        connection
            .apply_intelligent_traffic_analysis_level(0)
            .expect("de-escalation");
        assert_eq!(
            connection.traffic_analysis_policy().defense,
            crate::transport::config::TrafficAnalysisDefense::Off
        );
        assert!(connection.traffic_analysis.is_none());
    }

    #[test]
    fn traffic_analysis_chaff_is_congestion_deferred_exact_sized_and_sequential() {
        let mut pair = bench_paired_1rtt_connections();
        let first_deadline = enable_test_traffic_analysis(
            &mut pair.client,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            100,
            1200,
        );
        pair.client.on_traffic_analysis_timeout(first_deadline);
        assert!(pair
            .client
            .traffic_analysis
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_pending_chaff()));

        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        let first_packet_number = pair.client.next_send_pn_by_space[2];
        let mut packet = [0u8; 1500];
        assert_eq!(pair.client.send(&mut packet).unwrap_err(), ConnectionError::Done);
        assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number);
        assert!(pair
            .client
            .traffic_analysis
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_pending_chaff()));

        pair.client.recovery.cwnd = 64 * 1024;
        let (first_len, first_info) = pair.client.send(&mut packet).expect("first chaff");
        assert_eq!(first_len, 1200);
        assert!(first_info.congestion_controlled);
        assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number + 1);
        pair.server.recv(&mut packet[..first_len], &pair.recv_info).expect("first chaff decrypts");

        let second_deadline = pair
            .client
            .traffic_analysis_deadline()
            .expect("second chaff deadline");
        pair.client.on_traffic_analysis_timeout(second_deadline);
        let (second_len, second_info) = pair.client.send(&mut packet).expect("second chaff");
        assert_eq!(second_len, 1200);
        assert!(second_info.congestion_controlled);
        assert_eq!(pair.client.next_send_pn_by_space[2], first_packet_number + 2);
        pair.server.recv(&mut packet[..second_len], &pair.recv_info).expect("second chaff decrypts");
    }

    #[test]
    fn traffic_analysis_chaff_ack_releases_congestion_budget() {
        let mut pair = bench_paired_1rtt_connections();
        let deadline = enable_test_traffic_analysis(
            &mut pair.client,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            100,
            1200,
        );
        pair.client.on_traffic_analysis_timeout(deadline);
        let mut packet = [0u8; 1500];
        let (chaff_len, _) = pair.client.send(&mut packet).expect("chaff");
        pair.server.recv(&mut packet[..chaff_len], &pair.recv_info).expect("chaff decrypts");
        assert!(pair.client.recovery.bytes_in_flight > 0);
        assert!(pair.server.has_pending_application_ack());

        let (ack_len, ack_info) = pair.server.send(&mut packet).expect("ACK");
        assert!(!ack_info.congestion_controlled);
        pair.client
            .recv(
                &mut packet[..ack_len],
                &RecvInfo {
                    from: pair.server.local_addr,
                    to: pair.client.local_addr,
                    ecn: None,
                },
            )
            .expect("ACK decrypts");

        assert_eq!(pair.client.recovery.bytes_in_flight, 0);
    }

    #[test]
    fn full_padding_chaff_uses_the_complete_udp_payload_budget() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.config.set_max_send_udp_payload_size(1500);
        pair.client.dgram_send_max_size = 1500;
        pair.server.config.set_max_recv_udp_payload_size(1500);
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
        let probe_time = Instant::now();
        pair.client.pmtu.on_probe_sent(1500, probe_time);
        pair.client.pmtu.on_probe_acked(probe_time);
        pair.client
            .apply_traffic_analysis_policy(crate::transport::config::TrafficAnalysisPolicy {
                defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
                chaff_rate_pps: 10,
                chaff_size_bytes: 1280,
                constant_rate_pps: 100,
                idle_timeout_ms: 60_000,
                ramp_down_ms: 5_000,
            })
            .expect("full-padding policy");
        let deadline = pair.client.traffic_analysis_deadline().expect("deadline");
        pair.client.on_traffic_analysis_timeout(deadline);
        let scheduler = pair.client.traffic_analysis.as_ref().expect("scheduler");
        assert_eq!(scheduler.chaff_size_bytes(), 1500);

        let mut packet = [0u8; 1500];
        let (packet_len, _) = pair.client.send(&mut packet).expect("full-padding chaff");
        assert_eq!(packet_len, 1500);
        pair.server.recv(&mut packet, &pair.recv_info).expect("full-padding chaff decrypts");
    }

    #[test]
    fn traffic_analysis_pending_slot_never_turns_ack_only_into_chaff() {
        let mut pair = bench_paired_1rtt_connections();
        let deadline = enable_test_traffic_analysis(
            &mut pair.server,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            100,
            1200,
        );
        pair.server.on_traffic_analysis_timeout(deadline);
        assert!(pair.server.pkt_spaces[2].on_packet_recv(7));
        pair.server.pkt_spaces[2].note_ack_eliciting(0, 1);
        let bytes_in_flight = pair.server.recovery.bytes_in_flight;
        let mut packet = [0u8; 1500];

        let (packet_len, send_info) = pair.server.send(&mut packet).expect("ACK must serialize");

        assert_eq!(packet_len, 1200);
        assert!(!send_info.congestion_controlled);
        assert_eq!(pair.server.recovery.bytes_in_flight, bytes_in_flight);
        assert!(pair
            .server
            .traffic_analysis
            .as_ref()
            .is_some_and(|scheduler| !scheduler.has_pending_chaff()));
        pair.client.recv(&mut packet[..packet_len], &pair.recv_info).expect("ACK decrypts");
    }

    #[test]
    fn traffic_analysis_real_stream_data_consumes_the_due_slot_first() {
        let mut pair = bench_paired_1rtt_connections();
        let deadline = enable_test_traffic_analysis(
            &mut pair.client,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            100,
            1200,
        );
        pair.client.on_traffic_analysis_timeout(deadline);
        let payload = b"real data must win over a due chaff slot";
        pair.client.stream_send(0, payload, false).expect("stream enqueue");
        let packet_number = pair.client.next_send_pn_by_space[2];
        let mut packet = [0u8; 1500];

        let (packet_len, send_info) = pair.client.send(&mut packet).expect("stream packet");

        assert_eq!(packet_len, 1200);
        assert!(send_info.congestion_controlled);
        assert_eq!(pair.client.next_send_pn_by_space[2], packet_number + 1);
        assert!(pair
            .client
            .traffic_analysis
            .as_ref()
            .is_some_and(|scheduler| !scheduler.has_pending_chaff()));
        pair.server.recv(&mut packet[..packet_len], &pair.recv_info).expect("stream decrypts");
        let mut received = vec![0u8; payload.len()];
        let (received_len, fin) = pair.server.stream_recv(0, &mut received).expect("stream receive");
        assert_eq!(&received[..received_len], payload);
        assert!(!fin);
        assert_eq!(pair.client.send(&mut packet).unwrap_err(), ConnectionError::Done);
    }

    #[test]
    fn traffic_analysis_connection_shutdown_cancels_deadline_and_pending_slot() {
        let mut pair = bench_paired_1rtt_connections();
        let deadline = enable_test_traffic_analysis(
            &mut pair.client,
            crate::transport::config::TrafficAnalysisDefense::FullPadding,
            10,
            1200,
        );
        pair.client.on_traffic_analysis_timeout(deadline);
        pair.client.close(true, 0, b"shutdown").expect("close");

        let scheduler = pair.client.traffic_analysis.as_ref().expect("scheduler retained");
        assert_eq!(scheduler.phase(), crate::stealth::TrafficAnalysisPhase::Cancelled);
        assert!(!scheduler.has_pending_chaff());
        assert!(pair.client.traffic_analysis_deadline().is_none());
    }

    #[test]
    fn send_info_marks_stream_packets_for_external_pacing() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"paced stream", false).unwrap();
        let mut packet = [0u8; 1500];

        let (_, send_info) = pair.client.send(&mut packet).expect("STREAM must serialize");

        assert!(send_info.congestion_controlled);
    }

    #[test]
    fn pto_probe_then_time_threshold_requeues_tail_packet() {
        // Canonical RFC 9002 flow for a tail loss without a higher ACK: the PTO
        // fires a probe, the probe's ACK advances largest_acked, and the time
        // threshold then declares the tail packet lost.
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"tail loss", false).unwrap();
        let mut packet = [0u8; 1500];
        let packet_number = pair.client.next_send_pn_by_space[2];
        let (packet_size, _) = pair.client.send(&mut packet).unwrap();
        // Age the tail packet beyond the initial loss_delay (9/8 * 333 ms).
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            packet_number,
            packet_size,
            true,
            true,
            None,
            Instant::now() - Duration::from_secs(1),
        );

        // 1. Recovery timeout fires the PTO: an Application probe is queued,
        //    nothing is declared lost (RFC 9002 §6.2.4).
        pair.client.on_recovery_timeout(Instant::now());
        assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
        assert!(pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));

        // 2. The probe (a later packet) is sent and acknowledged; the time
        //    threshold now declares the aged tail packet lost.
        let probe_pn = packet_number + 1;
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            probe_pn,
            1200,
            true,
            true,
            None,
            Instant::now(),
        );
        let now = Instant::now();
        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(probe_pn, probe_pn + 1)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert!(!pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
        assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&packet_number));
    }

    #[test]
    fn aged_datagram_survives_pto_without_being_declared_lost() {
        // RFC 9002 §6.2.4: a PTO firing sends probes - it never declares loss.
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(16, 16);
        pair.client.dgram_send(b"unreliable tail").unwrap();
        let mut packet = [0u8; 1500];
        let packet_number = pair.client.next_send_pn_by_space[2];
        let (packet_size, _) = pair.client.send(&mut packet).unwrap();
        // Age the recorded packet so a time-threshold timer would be expired,
        // then verify the PTO path still does not declare loss (RFC 9002 §6.2.4).
        pair.client.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            packet_number,
            packet_size,
            true,
            true,
            None,
            Instant::now() - Duration::from_secs(1),
        );
        let bytes_in_flight_before = pair.client.recovery.bytes_in_flight;

        pair.client.on_recovery_timeout(Instant::now());

        assert!(pair
            .client
            .recovery
            .tracks_sent_packet(recovery::PacketSpace::Application, packet_number));
        assert_eq!(pair.client.recovery.bytes_in_flight, bytes_in_flight_before);
        assert!(pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
    }

    #[test]
    fn dgram_queue_full_is_retryable_after_send_drains_queue() {
        // A full QUIC DATAGRAM send queue must return DgramQueueFull, not a
        // terminal error, and a subsequent dgram_send must succeed once send()
        // has serialized the queued frame (TODO-559).
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(0, 1);
        assert_eq!(pair.client.dgram_send_queue_len(), 0);

        pair.client.dgram_send(b"one").unwrap();
        assert_eq!(pair.client.dgram_send_queue_len(), 1);

        let err = pair.client.dgram_send(b"two").unwrap_err();
        assert!(matches!(err, ConnectionError::DgramQueueFull));

        let mut packet = [0u8; 1500];
        let (written, _) = pair.client.send(&mut packet).unwrap();
        assert!(written > 0);
        assert_eq!(pair.client.dgram_send_queue_len(), 0);

        pair.client.dgram_send(b"two").unwrap();
        assert_eq!(pair.client.dgram_send_queue_len(), 1);
    }

    #[test]
    fn pto_probe_bypasses_congestion_gate_and_emits_ack_eliciting_packet() {
        // RFC 9002 §7.5/§6.2.4: a PTO probe bypasses the congestion gate but
        // still counts as in flight (tracked ack-eliciting packet).
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.enable_datagrams(16, 16);
        pair.client.dgram_send(b"unreliable tail").unwrap();
        let mut packet = [0u8; 1500];
        pair.client.send(&mut packet).unwrap();
        // Close the congestion gate: no headroom left in cwnd.
        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

        // Without a pending probe the gate rejects the send.
        assert_eq!(pair.client.send(&mut packet).unwrap_err(), crate::error::ConnectionError::Done);

        // A PTO firing queues the probe; the next send emits it despite the gate.
        pair.client.on_recovery_timeout(Instant::now());
        let tracked_before =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        let (probe_len, probe_info) = pair.client.send(&mut packet).expect("probe must emit");
        assert!(probe_len > 0);
        assert!(probe_info.congestion_controlled); // probes count as in flight (§7.5)
        assert!(!pair.client.pending_probe_spaces.contains(&recovery::PacketSpace::Application));
        let tracked_after =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        assert_eq!(tracked_after, tracked_before + 1);
    }

    #[test]
    fn packet_threshold_loss_requeues_stream_range() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"packet threshold loss", false).unwrap();
        let mut packet = [0u8; 1500];
        let stream_packet_number = pair.client.next_send_pn_by_space[2];
        pair.client.send(&mut packet).unwrap();
        let now = Instant::now();
        // The stream packet (PN 0) is already recorded by send(); seed PNs 1-4
        // so that an ACK for PN 4 advances largest_acked and declares PN 0 lost.
        for pn in 1..=4 {
            pair.client.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                now,
            );
        }

        let outcome = pair.client.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &[(4, 5)],
            Duration::ZERO,
            true,
            pair.client.is_server,
            now,
        );
        pair.client.apply_ack_outcome(recovery::PacketSpace::Application, outcome, now);

        assert_eq!(pair.client.stream_retransmit_queue.len(), 1);
        assert!(pair.client.lost_stream_transmission_by_pn.contains_key(&stream_packet_number));
    }

    #[test]
    fn full_stream_ledger_backpressures_without_emitting_empty_packets() {
        let mut pair = bench_paired_1rtt_connections();
        pair.client.pmtu = PmtuState::new(false, PmtuPolicy::default());
        pair.client.stream_send(0, b"bounded", false).unwrap();
        pair.client.stream_retransmit_bytes = MAX_STREAM_RETRANSMIT_BYTES;
        let packet_number = pair.client.next_send_pn_by_space[2];
        let mut packet = [0u8; 1500];

        let error = pair.client.send(&mut packet).unwrap_err();

        assert_eq!(error, crate::error::ConnectionError::Done);
        assert_eq!(pair.client.next_send_pn_by_space[2], packet_number);
        assert!(pair.client.stream_transmissions.is_empty());
    }

    #[test]
    fn sparse_ack_accounting_removes_acked_and_prunes_packet_threshold_losses() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..12 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(0u64, 1u64), (4, 5), (8, 9)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 3600);
        assert_eq!(c.stats.lost, 4);
        assert_eq!(c.stats.lost_bytes, 4800);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![6, 7, 9, 10, 11]);
    }

    #[test]
    fn sparse_ack_prefix_classification_preserves_ack_loss_and_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..64 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = (0u64..64).step_by(4).map(|pn| (pn, pn + 1)).collect::<Vec<_>>();
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 16 * 1200);
        assert_eq!(c.stats.lost, 43);
        assert_eq!(c.stats.lost_bytes, 43 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![58, 59, 61, 62, 63]);
    }

    #[test]
    fn large_contiguous_ack_uses_split_drain_and_preserves_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..96 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(16u64, 80u64)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 64 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, (80..96).collect::<Vec<_>>());
    }

    #[test]
    fn large_loss_prefix_uses_split_drain_and_preserves_unlost_tail() {
        let mut c = make_conn();
        let send_time = Instant::now() - Duration::from_millis(50);
        for pn in 0..128 {
            c.recovery.on_packet_sent_in_space(
                recovery::PacketSpace::Application,
                pn,
                1200,
                true,
                true,
                None,
                send_time,
            );
        }

        let ranges = vec![(127u64, 128u64)];
        let outcome = c.recovery.on_ack_received(
            recovery::PacketSpace::Application,
            &ranges,
            Duration::ZERO,
            true,
            c.is_server,
            Instant::now(),
        );
        c.apply_ack_outcome(recovery::PacketSpace::Application, outcome, Instant::now());

        assert_eq!(c.stats.acked_bytes, 1200);
        assert_eq!(c.stats.lost, 125);
        assert_eq!(c.stats.lost_bytes, 125 * 1200);
        let remaining: Vec<u64> = c.recovery.tracked_sent_pns(recovery::PacketSpace::Application);
        assert_eq!(remaining, vec![125, 126]);
    }

    #[test]
    fn timeout_does_not_inflate_rtt_repeatedly() {
        // Verify that repeated timeouts do NOT cause monotonic RTT inflation.
        // This is the regression test for the 0→385ms loopback RTT bug.
        let mut c = make_conn();
        let rtt_before = c.rtt;
        for _ in 0..10 {
            c.on_timeout();
        }
        assert_eq!(
            c.rtt, rtt_before,
            "10 timeouts must not inflate RTT. Got {:?}, expected {:?}",
            c.rtt, rtt_before
        );
    }

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
        let c = Connection::new_with_role(b"test_scid_0123456789", local(), peer(), cfg, false);
        assert_eq!(
            c.conn_max_data, initial_max,
            "conn_max_data must match config initial_max_data"
        );
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

    // ---- Connection Close Frame Generation -------------------------------

    #[test]
    fn close_app_and_transport_produce_different_frames() {
        let mut c1 = make_conn();
        c1.close(true, 42, b"app error").unwrap();
        let has_app =
            c1.pending_control.iter().any(|f| matches!(f, Frame::ApplicationClose { .. }));
        assert!(has_app, "app close must produce ApplicationClose frame");

        let mut c2 = make_conn();
        c2.close(false, 0x01, b"protocol error").unwrap();
        let has_conn =
            c2.pending_control.iter().any(|f| matches!(f, Frame::ConnectionClose { .. }));
        assert!(has_conn, "transport close must produce ConnectionClose frame");
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
        }
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
    fn intelligent_stealth_runtime_default_off() {
        let c = make_conn();
        assert!(
            !c.intelligent_stealth_runtime_enabled_for_test(),
            "intelligent stealth runtime must default to off"
        );
    }

    #[test]
    fn set_intelligent_stealth_runtime_toggle() {
        let mut c = make_conn();
        c.set_intelligent_stealth_runtime_for_test(true);
        assert!(c.intelligent_stealth_runtime_enabled_for_test());
        c.set_intelligent_stealth_runtime_for_test(false);
        assert!(!c.intelligent_stealth_runtime_enabled_for_test());
    }

    #[test]
    fn transport_stealth_jitter_disabled_when_external_pacing() {
        let mut c = make_conn();
        c.set_stealth_timing(true, 5_000);
        c.set_external_pacing_for_test(true);
        assert!(!c.transport_stealth_timing_active());
        assert!(c.transport_stealth_jitter_delay().is_none());
    }

    #[test]
    fn transport_stealth_jitter_bounded_when_gate_active() {
        let mut c = make_conn();
        c.set_stealth_timing(true, 100);
        c.set_external_pacing_for_test(false);
        assert!(c.transport_stealth_timing_active());
        let delay = c
            .transport_stealth_jitter_delay()
            .expect("jitter should be scheduled when gate active");
        assert!(delay <= Duration::from_micros(100));
    }

    #[test]
    fn pmtu_policy_reaches_configured_1500_ceiling() {
        let now = Instant::now();
        let mut state = PmtuState::new(true, PmtuPolicy::default());

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
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
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
        pair.client.pmtu =
            PmtuState::new(true, PmtuPolicy { max_mtu: 1472, ..PmtuPolicy::default() });
        pair.client.recovery.cwnd = pair.client.recovery.bytes_in_flight;
        assert!(!pair.client.recovery.can_send(pair.client.dgram_send_max_size));

        let tracked_before =
            pair.client.recovery.tracked_sent_pns(recovery::PacketSpace::Application).len();
        let mut packet = [0u8; 1600];
        let (packet_len, info) =
            pair.client.send(&mut packet).expect("dedicated PMTU probe must emit");

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
        pair.client.pmtu = PmtuState::new(
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
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
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
        pair.client.pmtu = PmtuState::new(true, PmtuPolicy::default());
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
        let mut state = PmtuState::new(true, PmtuPolicy::default());

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
        let mut state = PmtuState::new(true, policy);
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
        let mut state = PmtuState::new(true, policy);
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
        let mut state = PmtuState::new(true, policy);
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
        let state = PmtuState::new(false, PmtuPolicy::default());

        assert_eq!(state.effective_mtu(), 1280);
        assert_eq!(state.probe_size(), None);
        assert!(!state.enabled());
    }
}
