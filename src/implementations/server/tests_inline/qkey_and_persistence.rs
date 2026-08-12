use super::*;
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
            (QKeyHeaderAuthOutcome::Reject(actual), QKeyHeaderAuthOutcome::Reject(expected)) => {
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

fn logging_test_config_path(label: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("quicfuscate-logging-{label}-{}-{sequence}.toml", std::process::id()))
}

fn cleanup_logging_test_files(config_path: &std::path::Path) {
    for path in [
        config_path.to_path_buf(),
        config_path.with_extension("logging.json"),
        config_path.with_extension("qkeys.json"),
    ] {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&path);
    }
}

fn logging_test_guard() -> parking_lot::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<parking_lot::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| parking_lot::Mutex::new(())).lock()
}

#[test]
fn logging_mode_persistence_round_trips_and_restores_on_restart() {
    let _guard = logging_test_guard();
    let modes = [
        (qf_logging::LoggingMode::Verbose, "verbose"),
        (qf_logging::LoggingMode::Normal, "normal"),
        (qf_logging::LoggingMode::Minimal, "minimal"),
        (qf_logging::LoggingMode::NoLog, "no-log"),
    ];

    for (index, (expected_mode, expected_name)) in modes.into_iter().enumerate() {
        let config_path = logging_test_config_path(&format!("roundtrip-{index}"));
        let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
        let logging_mode = parking_lot::RwLock::new("normal".to_string());
        let response =
            write_logging_mode(Some(&config_path), &logging_mode, &log_buffer, expected_name);
        assert!(response.success, "mode '{expected_name}' must persist");
        assert_eq!(*logging_mode.read(), expected_name);
        assert_eq!(
            load_persisted_logging_mode(Some(&config_path)).expect("persisted mode must load"),
            PersistedLoggingModeState::Valid(expected_mode)
        );

        let bootstrap = initialize_standalone_server_bootstrap(
            Some(&config_path),
            Some(std::sync::Arc::new(
                crate::implementations::server::admin_logs::AdminLogBuffer::new(64),
            )),
            Some(60),
            Some(config_path.with_extension("qkeys.json")),
        )
        .expect("valid persisted mode must not block restart");
        assert_eq!(bootstrap.initial_logging_mode, expected_name);
        cleanup_logging_test_files(&config_path);
    }
    log::set_max_level(log::LevelFilter::Info);
}

#[test]
fn standalone_bootstrap_uses_normal_mode_when_logging_state_is_absent() {
    let _guard = logging_test_guard();
    let config_path = logging_test_config_path("absent");
    log::set_max_level(log::LevelFilter::Off);
    let bootstrap = initialize_standalone_server_bootstrap(
        Some(&config_path),
        Some(std::sync::Arc::new(crate::implementations::server::admin_logs::AdminLogBuffer::new(
            64,
        ))),
        Some(60),
        Some(config_path.with_extension("qkeys.json")),
    )
    .expect("absent logging state must use the normal startup mode");

    assert_eq!(bootstrap.initial_logging_mode, "normal");
    assert_eq!(log::max_level(), log::LevelFilter::Info);
    cleanup_logging_test_files(&config_path);
}

#[test]
fn logging_mode_persistence_distinguishes_malformed_missing_and_unsupported_state() {
    let cases = [
        ("malformed", br#"{"mode":"normal""# as &[u8], "logging state invalid"),
        ("missing-mode", br#"{}"# as &[u8], "logging state invalid"),
        ("unsupported", br#"{"mode":"debug"}"# as &[u8], "logging state invalid"),
        ("unknown-field", br#"{"mode":"normal","extra":true}"# as &[u8], "logging state invalid"),
    ];

    for (label, contents, expected_message) in cases {
        let config_path = logging_test_config_path(label);
        let logging_path = resolve_logging_store_path(Some(&config_path))
            .expect("config path must resolve a logging state path");
        std::fs::write(&logging_path, contents).expect("write invalid logging fixture");
        let error = load_persisted_logging_mode(Some(&config_path))
            .expect_err("invalid logging state must fail closed");
        assert!(error.to_string().contains(expected_message));
        cleanup_logging_test_files(&config_path);
    }
}

#[test]
fn logging_mode_persistence_reports_unreadable_state_and_startup_fails_closed() {
    let config_path = logging_test_config_path("unreadable");
    let logging_path = resolve_logging_store_path(Some(&config_path))
        .expect("config path must resolve a logging state path");
    std::fs::create_dir(&logging_path).expect("create unreadable logging fixture");

    let read_error = load_persisted_logging_mode(Some(&config_path))
        .expect_err("directory at logging state path must be a read error");
    assert!(read_error.to_string().contains("logging state read failed"));

    let startup_result = initialize_standalone_server_bootstrap(
        Some(&config_path),
        None,
        Some(60),
        Some(config_path.with_extension("qkeys.json")),
    );
    let startup_error = match startup_result {
        Ok(_) => panic!("startup must reject unreadable logging state"),
        Err(error) => error,
    };
    assert!(startup_error.to_string().contains("logging state read failed"));
    cleanup_logging_test_files(&config_path);
}

#[test]
fn logging_mode_update_persists_before_publishing_and_preserves_live_state_on_failure() {
    let config_path = logging_test_config_path("write-failure");
    let logging_path = resolve_logging_store_path(Some(&config_path))
        .expect("config path must resolve a logging state path");
    std::fs::create_dir(&logging_path).expect("create blocking logging destination");
    let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
    let logging_mode = parking_lot::RwLock::new("normal".to_string());

    let response = write_logging_mode(Some(&config_path), &logging_mode, &log_buffer, "verbose");

    assert!(!response.success);
    assert!(response.message.as_deref().unwrap_or("").contains("persistence failed"));
    assert_eq!(logging_mode.read().as_str(), "normal");
    cleanup_logging_test_files(&config_path);
}

#[test]
fn logging_mode_update_without_config_is_explicitly_live_only() {
    let _guard = logging_test_guard();
    let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
    let logging_mode = parking_lot::RwLock::new("normal".to_string());
    let response = write_logging_mode(None, &logging_mode, &log_buffer, "minimal");

    assert!(response.success);
    assert!(response.message.as_deref().unwrap_or("").contains("live-only"));
    assert_eq!(logging_mode.read().as_str(), "minimal");
    log::set_max_level(log::LevelFilter::Info);
}

#[test]
fn no_log_mode_clears_the_admin_buffer_and_persists_the_privacy_mode() {
    let _guard = logging_test_guard();
    let config_path = logging_test_config_path("no-log");
    let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
    log_buffer.push(log::Level::Info, "must be cleared");
    let logging_mode = parking_lot::RwLock::new("normal".to_string());

    let response = write_logging_mode(Some(&config_path), &logging_mode, &log_buffer, "no-log");

    assert!(response.success);
    assert_eq!(logging_mode.read().as_str(), "no-log");
    assert!(log_buffer.since(0, "no-log", 64).0.is_empty());
    assert_eq!(
        load_persisted_logging_mode(Some(&config_path)).expect("no-log must persist"),
        PersistedLoggingModeState::Valid(qf_logging::LoggingMode::NoLog)
    );
    cleanup_logging_test_files(&config_path);
    log::set_max_level(log::LevelFilter::Info);
}

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
    let _guard = logging_test_guard();
    let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
    let logging_mode = parking_lot::RwLock::new("normal".to_string());
    for mode in &["verbose", "normal", "minimal", "no-log"] {
        let response = write_logging_mode(None, &logging_mode, &log_buffer, mode);
        assert!(response.success, "mode '{}' should be valid", mode);
        assert_eq!(*logging_mode.read(), *mode);
    }
    log::set_max_level(log::LevelFilter::Info);
}

#[test]
fn standalone_reload_scope_never_claims_active_session_mutation() {
    let outcome = StandaloneReloadOutcome {
        scope: StandaloneReloadScope::NextConnectionOnly,
        active_sessions_unchanged: 7,
        runtime_generation: 2,
    };

    assert_eq!(outcome.scope, StandaloneReloadScope::NextConnectionOnly);
    assert_eq!(outcome.active_sessions_unchanged, 7);
    assert_eq!(outcome.runtime_generation, 2);
}

#[test]
fn runtime_policy_generation_hides_partial_publication_from_readers() {
    let generation = RuntimePolicyGeneration::new();
    let domains = Arc::new(std::sync::Mutex::new([0u8; 4]));
    let (writer_ready_tx, writer_ready_rx) = std::sync::mpsc::sync_channel(0);
    let (continue_tx, continue_rx) = std::sync::mpsc::sync_channel(0);
    let writer_generation = generation.clone();
    let writer_domains = domains.clone();
    let writer = std::thread::spawn(move || {
        let mut guard = writer_generation.write_guard();
        writer_domains.lock().unwrap()[0] = 1;
        writer_ready_tx.send(()).unwrap();
        continue_rx.recv().unwrap();
        let mut values = writer_domains.lock().unwrap();
        values[1..].fill(1);
        RuntimePolicyGeneration::advance(&mut guard);
    });

    writer_ready_rx.recv().unwrap();
    let (reader_started_tx, reader_started_rx) = std::sync::mpsc::sync_channel(0);
    let reader_generation = generation.clone();
    let reader_domains = domains.clone();
    let reader = std::thread::spawn(move || {
        reader_started_tx.send(()).unwrap();
        let guard = reader_generation.read_guard();
        let values = *reader_domains.lock().unwrap();
        (*guard, values)
    });
    reader_started_rx.recv().unwrap();
    continue_tx.send(()).unwrap();

    writer.join().unwrap();
    let (observed_generation, observed_domains) = reader.join().unwrap();
    assert_eq!(observed_generation, 2);
    assert_eq!(observed_domains, [1, 1, 1, 1]);
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
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
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
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let addr: SocketAddr = "10.0.0.1:5003".parse().unwrap();
    let (id, _, _) = domain.accept(addr).unwrap();
    assert_eq!(domain.session_id_by_remote(addr), Some(id));

    domain.remove_remote(addr);
    assert_eq!(domain.session_id_by_remote(addr), None);
    assert_eq!(domain.active_session_count(), 0);
}

#[test]
fn test_live_server_domain_synchronizes_forwarding_policy_lifecycle() {
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
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
    assert_eq!(AcceptError::SessionError("test".to_string()).to_string(), "Session error: test");
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
fn negative_transport_overrides_are_rejected_instead_of_clamped_to_zero() {
    // Clamping turned an operator typo into a legal value with different runtime
    // semantics: a zero idle timeout disables liveness detection and a zero
    // flow-control limit permits no data, and the reload reported success either
    // way. Each field must name itself so the typo is findable.
    for key in [
        "max_idle_timeout",
        "initial_max_data",
        "initial_max_stream_data_bidi_local",
        "initial_max_stream_data_bidi_remote",
        "initial_max_stream_data_uni",
        "initial_max_streams_bidi",
        "initial_max_streams_uni",
        "dgram_recv_queue_len",
        "dgram_send_queue_len",
    ] {
        let contents = format!("[transport]\n{key} = -1\n");
        let error = validate_transport_overrides_from_toml(&contents)
            .expect_err("a negative value must be rejected");
        assert!(
            error.contains(key) && error.contains("negative"),
            "{key} must name itself and the defect, got {error}"
        );

        // Zero is a value the operator can mean, so it stays acceptable; only the
        // negative that used to become zero is rejected.
        validate_transport_overrides_from_toml(&format!("[transport]\n{key} = 0\n"))
            .unwrap_or_else(|error| panic!("{key} = 0 must remain accepted, got {error}"));

        // A value that cannot be encoded as a QUIC varint is a configuration error,
        // not a large limit.
        let over = format!("[transport]\n{key} = {}\n", MAX_TRANSPORT_VARINT + 1);
        let error = validate_transport_overrides_from_toml(&over)
            .expect_err("an unencodable value must be rejected");
        assert!(
            error.contains(key),
            "{key} must name itself when out of varint range, got {error}"
        );

        // The varint maximum itself is the boundary and stays legal.
        validate_transport_overrides_from_toml(&format!(
            "[transport]\n{key} = {MAX_TRANSPORT_VARINT}\n"
        ))
        .unwrap_or_else(|error| panic!("{key} at the varint maximum must be accepted: {error}"));
    }
}

#[test]
fn a_negative_value_rejects_the_whole_override_set_before_any_mutation() {
    let mut transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let before = transport.max_udp_payload_size();
    let contents = r#"
[transport]
mtu = 1400
max_idle_timeout = -1
"#;

    let error = apply_transport_overrides_from_toml(
        std::path::Path::new("test.toml"),
        contents,
        &mut transport,
    )
    .expect_err("a negative value must abort the whole set");
    assert!(error.contains("max_idle_timeout"), "the failure must name the field: {error}");
    assert_eq!(
        transport.max_udp_payload_size(),
        before,
        "no transport policy may be mutated after a rejected value"
    );
}

#[test]
fn a_setter_rejection_returns_an_error_and_leaves_the_live_config_untouched() {
    // Every transport key is currently pre-validated before this helper runs, so
    // this rejection is not reachable through the reload path today. That is
    // exactly why it must not be logged and skipped: the safety depends on two
    // validators staying in step with the setters, and nothing enforces that. The
    // parser accepts a lone minimum MTU because it checks each key in isolation;
    // only the setter compares it against the live maximum.
    let mut transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let before = transport.pmtu_policy();
    let contents = r#"
[transport]
mtu = 1400
pmtu_min_mtu = 9000
"#;

    let error = apply_transport_overrides_from_toml(
        std::path::Path::new("test.toml"),
        contents,
        &mut transport,
    )
    .expect_err("a rejected setter must be returned, not logged");
    assert!(error.contains("rejected"), "the failure must name the rejection, got {error}");

    let after = transport.pmtu_policy();
    assert_eq!(after.min_mtu, before.min_mtu);
    assert_eq!(after.max_mtu, before.max_mtu);
    assert_ne!(
        transport.max_udp_payload_size(),
        1400,
        "an earlier setter in the same file must not survive a later rejection"
    );
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
    )
    .expect("valid transport overrides apply");

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
    )
    .expect("valid transport overrides apply");

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
    )
    .expect("valid transport overrides apply");

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
        &crate::time_source::ProtocolClock::default(),
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
        &crate::time_source::ProtocolClock::default(),
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
        &crate::time_source::ProtocolClock::default(),
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
    let domain = SharedServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("shared server domain construction failed: {error}"));
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
    let domain = SharedServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("shared server domain construction failed: {error}"));
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
