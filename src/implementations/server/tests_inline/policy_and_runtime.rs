use super::*;
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
    assert_eq!(
        load_persisted_blocked_ips(None).expect("no configured path is not an error"),
        PersistedBlockedIpsState::Absent
    );
}

/// A config path whose sibling blocked-IP store this test owns for its duration.
fn blocked_ips_fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let config_path =
        std::env::temp_dir().join(format!("qf-blocked-{name}-{}-{id}.toml", std::process::id()));
    let store = resolve_blocked_ips_store_path(Some(config_path.as_path()))
        .expect("a config path resolves a blocked-IP store");
    let _ = std::fs::remove_file(&store);
    (config_path, store)
}

#[test]
fn an_absent_blocked_ip_store_is_distinct_from_an_explicitly_empty_one() {
    // These look identical in memory. Collapsing them is what let an unreadable
    // policy become allow-all, so the loader keeps them apart.
    let (config_path, store) = blocked_ips_fixture("absent");
    assert_eq!(
        load_persisted_blocked_ips(Some(config_path.as_path())).expect("absent is not an error"),
        PersistedBlockedIpsState::Absent
    );

    std::fs::write(&store, b"[]").expect("write empty policy");
    assert_eq!(
        load_persisted_blocked_ips(Some(config_path.as_path())).expect("empty is valid"),
        PersistedBlockedIpsState::Valid(std::collections::HashSet::new())
    );
    let _ = std::fs::remove_file(&store);
}

#[test]
fn a_valid_blocked_ip_policy_round_trips_through_persistence() {
    let (config_path, store) = blocked_ips_fixture("roundtrip");
    let mut policy = std::collections::HashSet::new();
    policy.insert("203.0.113.7".to_string());
    policy.insert("2001:db8::1".to_string());
    persist_blocked_ips(&store, &policy).expect("persist policy");

    let loaded = load_persisted_blocked_ips(Some(config_path.as_path())).expect("valid policy");
    assert_eq!(loaded, PersistedBlockedIpsState::Valid(policy));
    let _ = std::fs::remove_file(&store);
}

#[test]
fn an_unusable_blocked_ip_policy_is_an_error_and_never_an_empty_set() {
    // Every one of these used to produce an empty allow-all set, silently readmitting
    // every address the operator had denied.
    for (label, contents) in [
        ("malformed JSON", "{ not json".to_string()),
        ("a JSON object instead of a list", "{\"a\":1}".to_string()),
        ("a non-string entry", "[1]".to_string()),
        ("an entry that is not an address", "[\"definitely-not-an-ip\"]".to_string()),
        ("an empty entry", "[\"\"]".to_string()),
    ] {
        let (config_path, store) = blocked_ips_fixture("invalid");
        std::fs::write(&store, contents.as_bytes()).expect("write policy");

        let error = load_persisted_blocked_ips(Some(config_path.as_path()))
            .expect_err(&format!("{label} must be rejected"));
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidData,
            "{label} must be reported as invalid data"
        );
        assert!(
            error.to_string().contains(&store.display().to_string()),
            "{label} must name the file, got {error}"
        );
        let _ = std::fs::remove_file(&store);
    }
}

#[cfg(unix)]
#[test]
fn an_unreadable_blocked_ip_policy_is_an_error_and_never_an_empty_set() {
    use std::os::unix::fs::PermissionsExt;
    let (config_path, store) = blocked_ips_fixture("unreadable");
    std::fs::write(&store, b"[\"203.0.113.7\"]").expect("write policy");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o000)).expect("deny reads");

    let result = load_persisted_blocked_ips(Some(config_path.as_path()));
    // A privileged runner can read it anyway; then the policy must still load intact
    // rather than be silently emptied. Either way the empty-set outcome is excluded.
    match result {
        Err(error) => assert!(
            error.to_string().contains("read failed"),
            "an unreadable policy must say so, got {error}"
        ),
        Ok(PersistedBlockedIpsState::Valid(blocked)) => {
            assert!(blocked.contains("203.0.113.7"), "a readable policy must load intact")
        }
        Ok(other) => panic!("an unreadable policy must never become {other:?}"),
    }

    let _ = std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600));
    let _ = std::fs::remove_file(&store);
}

#[test]
fn test_load_persisted_logging_mode_defaults_to_normal_without_config() {
    assert_eq!(
        load_persisted_logging_mode(None).expect("missing config path is not an error"),
        PersistedLoggingModeState::Absent
    );
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
            limiter.complete(attempt, crate::implementations::server::limits::AuthTerminal::Failed),
            crate::implementations::server::limits::AuthCompletion::FailedWithBackoff {
                delay: Duration::from_secs(60)
            }
        );
    }

    let qkey_registry = std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None));
    let revocation_manager = crate::implementations::server::revocation::RevocationManager::new();
    let metrics = Metrics::new();
    let stealth_config = Arc::new(std::sync::Mutex::new(StealthConfig::default()));
    let fec_config = Arc::new(std::sync::Mutex::new(FecConfig::default()));
    let optimize_config =
        Arc::new(std::sync::Mutex::new(crate::optimize::OptimizeConfig::default()));
    let transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let runtime_policy_generation = RuntimePolicyGeneration::new();

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
        transport_config: &transport,
        runtime_policy_generation: &runtime_policy_generation,
        stealth_runtime: None,
        auth_rate_limiter,
        retry_token_manager: None,
        clock: crate::time_source::ProtocolClock::default(),
        crypto_config: &qf_crypto::CryptoConfig::default(),
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
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
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
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
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

    live_state.commit_qkey_auth_result(None, Some((conn_id.clone(), true)), &accept_loop, &metrics);

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

    live_state.commit_qkey_auth_result(None, Some((conn_id.clone(), true)), &accept_loop, &metrics);

    assert!(live_state.clients.contains_key(&remote_addr));
    assert_eq!(
        live_state.domain.shared.sessions.read().bandwidth_stats(session_id).unwrap().policy,
        qkey_policy
    );
    assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before);

    live_state.revoke_qkey_now("test-key", "test", &accept_loop, &metrics).expect("revoke qkey");

    assert!(live_state.revocation_manager.is_revoked("test-key"));
    assert!(live_state
        .clients
        .get(&remote_addr)
        .is_some_and(|connection| connection.conn.is_closed()));
    live_state.reconcile(&accept_loop, &metrics);
    assert!(!live_state.clients.contains_key(&remote_addr));
    assert!(live_state.domain.session_id_by_remote(remote_addr).is_none());
    assert!(live_state.qkey_tracker.connections_for_key("test-key").is_empty());
    assert!(!live_state.qkey_auth.contains_key(&conn_id));
}

#[test]
fn failed_qkey_auth_never_activates_pending_traffic_analysis_policy() {
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
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
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
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
    live_state.revocation_manager.revoke("pending-key", "test").expect("revoke pending key");

    live_state.commit_qkey_auth_result(None, Some((conn_id.clone(), true)), &accept_loop, &metrics);

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
        tokio::time::timeout(Duration::from_secs(1), runtime.run_loop(&mut runtime_config)).await;

    assert!(trigger.await.is_ok());
    let result = run_loop_result.expect("run loop should finish within timeout");
    assert!(result.is_ok());
    assert_eq!(runtime.state, ServerState::Stopped);
}

#[tokio::test]
async fn test_dns_workers_close_before_standalone_drain_finishes() {
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
    runtime.start().expect("standalone runtime must start");

    let metrics = runtime.standalone_metrics();
    let owner = Arc::new(DnsInterceptWorkerOwner::new(Arc::clone(&metrics)));
    runtime.dns_intercept_workers = Some(Arc::clone(&owner));
    let queue =
        Arc::new(std::sync::Mutex::new(qf_transport_types::MasqueDownlinkQueue::new(1, 1024)));
    let worker_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_worker = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_state = Arc::clone(&owner.state);
    let worker_queue = Arc::clone(&queue);
    let worker_started_for_worker = Arc::clone(&worker_started);
    let release_worker_for_worker = Arc::clone(&release_worker);
    owner
        .spawn(move || {
            worker_started_for_worker.store(true, std::sync::atomic::Ordering::Release);
            while !release_worker_for_worker.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
            publish_dns_intercept_response(&worker_state, &worker_queue, vec![7, 8, 9])
        })
        .expect("standalone DNS worker must be accepted");
    while !worker_started.load(std::sync::atomic::Ordering::Acquire) {
        tokio::task::yield_now().await;
    }

    assert!(runtime.initiate_drain(b"test_dns_worker_drain"));
    release_worker.store(true, std::sync::atomic::Ordering::Release);
    let socket = runtime.socket();
    let mut out = [0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
    runtime
        .finish_drain(socket.as_ref(), &mut out, metrics.as_ref(), b"test_dns_worker_drain")
        .await;

    assert_eq!(
        metrics.dns_intercept_worker_late_publication.load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(queue.lock().unwrap().len(), 0);
    assert!(runtime.dns_intercept_workers.is_none());
    runtime.stop().expect("standalone runtime must stop");
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
fn graceful_shutdown_drain_uses_live_runtime_clock() {
    let source = crate::time_source::test_support::ManualTimeSource::new(
        Instant::now(),
        std::time::SystemTime::UNIX_EPOCH,
    );
    let _guard = crate::time_source::install_for_test(source);
    let shutdown = GracefulShutdown::new(20);
    shutdown.set_running();
    assert!(shutdown.begin_drain());

    std::thread::sleep(Duration::from_millis(40));

    assert!(shutdown.deadline_reached());
}

fn blocked_ip_handler(
    blocked_ips_path: Option<std::path::PathBuf>,
) -> (ServerAdminHttpRuntimeHandler, Arc<parking_lot::RwLock<std::collections::HashSet<String>>>) {
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
    let core = ServerAdminCore::new(
        Arc::new(Metrics::new()),
        blocked_ips.clone(),
        Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        Arc::new(RwLock::new(SessionManager::new(16))),
        ServerAdminControlPlane {
            actions: tx,
            listen_addr: "127.0.0.1:4433".to_string(),
            front_domain: vec![],
            qkeys: Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None))),
            graceful_shutdown: Arc::new(GracefulShutdown::new(5_000)),
        },
        #[cfg(feature = "rate_limiter")]
        GeoIpStatus::Disabled,
    );
    let handler = ServerAdminHttpRuntimeHandler::new(
        core,
        blocked_ips_path,
        None,
        Arc::new(parking_lot::RwLock::new("normal".to_string())),
        Arc::new(crate::implementations::server::admin_logs::AdminLogBuffer::new(16)),
    );
    (handler, blocked_ips)
}

#[test]
fn a_blocked_ip_change_that_cannot_be_persisted_is_not_reported_as_success() {
    // The caller used to receive success while the change lived only in this process
    // and would vanish on restart, which is exactly the evidence a security policy
    // change must not fabricate.
    // The atomic writer creates missing parent directories, so a merely absent path
    // is not a failure. A parent that exists as a regular file is one that cannot be
    // created, which is what makes this reach the error branch.
    let blocking_file = std::env::temp_dir().join(format!(
        "qf-blocked-parent-{}-{:?}.dat",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&blocking_file, b"not a directory").expect("occupy the parent name");
    let unwritable = blocking_file.join("state.blocked.json");
    let (handler, blocked_ips) = blocked_ip_handler(Some(unwritable.clone()));

    let response = handler.handle_block("203.0.113.7");
    assert!(!response.success, "an unpersisted block must not report success");
    let message = response.message.clone().expect("the failure must explain itself");
    assert!(message.contains("203.0.113.7"), "the failure must name the address: {message}");
    assert!(
        message.contains("running server") && message.contains("lost on restart"),
        "the failure must state the live consequence: {message}"
    );

    // The live block deliberately stands. Rolling it back would readmit the address
    // the operator just denied, which is the worse of the two outcomes.
    assert!(
        blocked_ips.read().contains("203.0.113.7"),
        "the requested denial must remain in force"
    );

    let response = handler.handle_unblock("203.0.113.7");
    assert!(!response.success, "an unpersisted unblock must not report success");
    assert!(
        !blocked_ips.read().contains("203.0.113.7"),
        "the requested release must remain in force"
    );

    let _ = std::fs::remove_file(&blocking_file);
}

#[test]
fn a_durable_blocked_ip_change_reports_success_and_survives_a_reload() {
    let (config_path, store) = blocked_ips_fixture("durable");
    let (handler, _blocked_ips) = blocked_ip_handler(Some(store.clone()));

    assert!(handler.handle_block("203.0.113.7").success);
    assert_eq!(
        load_persisted_blocked_ips(Some(config_path.as_path())).expect("policy loads"),
        PersistedBlockedIpsState::Valid(["203.0.113.7".to_string()].into_iter().collect())
    );

    assert!(handler.handle_unblock("203.0.113.7").success);
    assert_eq!(
        load_persisted_blocked_ips(Some(config_path.as_path())).expect("policy loads"),
        PersistedBlockedIpsState::Valid(std::collections::HashSet::new())
    );

    // An address that was never blocked is still an error, and must not be reported
    // as a durable change either.
    assert!(!handler.handle_unblock("203.0.113.8").success);
    let _ = std::fs::remove_file(&store);
}

#[test]
fn test_server_admin_core_block_unblock_ip() {
    let metrics = Arc::new(Metrics::new());
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let client_snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
    let qkeys = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut core = ServerAdminCore::new(
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
        #[cfg(feature = "rate_limiter")]
        GeoIpStatus::Disabled,
    );

    let diagnostics = AdminHttpOperationDiagnostics::new(MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS)
        .expect("admin HTTP diagnostics");
    core.set_admin_http_operation_diagnostics(diagnostics);
    assert_eq!(
        core.base_status_json()["admin_http"]["timeout_ms"],
        MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS
    );
    assert_eq!(core.health_json()["admin_http"]["timeout_ms"], MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS);
    assert_eq!(core.base_status_json()["memory_lock"]["state"], "not-configured");
    assert_eq!(core.health_json()["memory_lock"]["state"], "not-configured");

    #[cfg(feature = "rate_limiter")]
    {
        assert_eq!(core.base_status_json()["geoip"]["status"], "disabled");
        assert_eq!(core.base_status_json()["geoip"]["active"], false);
        assert_eq!(core.health_json()["geoip_status"], "disabled");
    }

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
        #[cfg(feature = "rate_limiter")]
        GeoIpStatus::Disabled,
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
fn runtime_config_rejects_invalid_candidates_before_replacement() {
    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let config_path = std::env::temp_dir().join(format!(
        "quicfuscate-config-validation-{}-{}.toml",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let original = b"[engine]\nshutdown_timeout_ms = 175\n";
    let mut config_file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
    config_file.write_all(original).unwrap();
    drop(config_file);

    let (mut handler, _) = blocked_ip_handler(None);
    handler.config_path = Some(config_path.clone());

    for (candidate, expected_error) in [
        ("[engine", "Config parse failed"),
        ("[transport]\nmax_idle_timeout = 4611686018427387904\n", "Config validation failed"),
    ] {
        let response = handler.handle_write_config(candidate);
        assert!(!response.success, "invalid config must be rejected: {candidate}");
        assert!(
            response.message.as_deref().is_some_and(|message| message.contains(expected_error)),
            "rejection must identify the failed validation boundary: {:?}",
            response.message
        );
        assert_eq!(
            std::fs::read(&config_path).unwrap(),
            original,
            "rejected config must not replace the durable target"
        );
    }

    std::fs::remove_file(config_path).unwrap();
}

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
