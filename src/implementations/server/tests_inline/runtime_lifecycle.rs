use super::*;
#[test]
fn test_server_runtime_new() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config);
    assert!(runtime.is_ok());
}

#[test]
fn server_runtime_accepts_matching_embedded_tun_override() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)));
    engine_config.interface.tun_netmask = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));
    engine_config.interface.tun_ip6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
    engine_config.interface.tun_prefix6 = Some(64);

    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config.clone())
        .expect("matching embedded server TUN override must be accepted");
    let tun_config = server_config.server_tun_config(Some("qfserver0".to_string()), 1500, true);
    assert_eq!(tun_config.ip, Some(IpAddr::V4(server_config.server_ip)));
    assert_eq!(tun_config.netmask, Some(IpAddr::V4(server_config.server_netmask)));
    assert_eq!(tun_config.ip6, server_config.ipv6_server_ip);
    assert_eq!(tun_config.prefix6, Some(server_config.ipv6_prefix_len));

    let (_, _, assigned) = runtime
        .domain
        .accept("127.0.0.1:54323".parse().unwrap())
        .expect("default client pool must allocate on the effective network");
    assert_eq!(assigned.ipv4, server_config.ip_pool_start);
    assert_eq!(assigned.ipv6, server_config.ipv6_pool_start);
}

#[test]
fn server_runtime_rejects_conflicting_embedded_tun_override_before_start() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)));
    engine_config.interface.tun_netmask = Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)));

    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("conflicting embedded server TUN override must fail closed"),
        Err(error) => error,
    };
    match error {
        EngineError::Config(message) => {
            assert!(message.contains("server TUN IPv4 conflict"));
            assert!(message.contains("ServerConfig is authoritative"));
        }
        other => panic!("unexpected error for conflicting embedded TUN: {other:?}"),
    }
}

#[test]
fn server_runtime_rejects_conflicting_embedded_ipv6_tun_override_before_start() {
    let mut engine_config = EngineConfig::default();
    engine_config.interface.tun_ip6 = Some(Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1));
    engine_config.interface.tun_prefix6 = Some(64);

    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("conflicting embedded IPv6 TUN override must fail closed"),
        Err(error) => error,
    };
    assert!(
        matches!(error, EngineError::Config(message) if message.contains("server TUN IPv6 conflict"))
    );
}

#[test]
fn standalone_tun_config_is_reconciled_to_server_network() {
    let server_config = ServerConfig::default();
    let tun_config = server_config
        .reconcile_standalone_tun_config(TunConfig {
            name: Some("qfserver0".to_string()),
            ip: Some(IpAddr::V4(server_config.server_ip)),
            netmask: Some(IpAddr::V4(server_config.server_netmask)),
            mtu: 1500,
            ip6: server_config.ipv6_server_ip,
            prefix6: server_config.ipv6_server_ip.map(|_| server_config.ipv6_prefix_len),
            ..TunConfig::default()
        })
        .expect("standalone TUN config without address overrides must inherit ServerConfig");
    assert_eq!(tun_config.ip, Some(IpAddr::V4(server_config.server_ip)));
    assert_eq!(tun_config.netmask, Some(IpAddr::V4(server_config.server_netmask)));
    assert_eq!(tun_config.ip6, server_config.ipv6_server_ip);
    assert_eq!(tun_config.prefix6, Some(server_config.ipv6_prefix_len));
}

#[test]
fn standalone_lifecycle_rejects_conflicting_tun_config_before_open() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let error = match ServerRuntime::new_standalone_default(
        EngineConfig::default(),
        server_config,
        Some(TunConfig {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1))),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            ..TunConfig::default()
        }),
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    ) {
        Ok(_) => panic!("conflicting standalone TUN override must fail before opening TUN"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("standalone server TUN IPv4 conflict"));
}

#[test]
fn server_runtime_rejects_ipv4_pool_outside_effective_tun_network() {
    let server_config = ServerConfig {
        ip_pool_start: Ipv4Addr::new(10, 9, 0, 2),
        ip_pool_end: Ipv4Addr::new(10, 9, 0, 254),
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("client pool outside the server TUN network must fail closed"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected pool validation error: {other:?}"),
    };
    assert!(error.contains("IPv4 client pool"));
    assert!(error.contains("outside server network"));
}

#[test]
fn server_runtime_rejects_ipv6_pool_outside_effective_tun_network() {
    let server_config = ServerConfig {
        ipv6_pool_start: Some("fd01::2".parse().unwrap()),
        ipv6_pool_end: Some("fd01::fe".parse().unwrap()),
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("IPv6 client pool outside the server TUN network must fail closed"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected IPv6 pool validation error: {other:?}"),
    };
    assert!(error.contains("IPv6 client pool"));
    assert!(error.contains("outside server network"));
}

#[test]
fn test_server_runtime_rejects_invalid_engine_projection() {
    let mut engine_config = EngineConfig::default();
    engine_config.stealth.padding_strategy = "invalid".to_string();
    let error = match ServerRuntime::new(engine_config, ServerConfig::default()) {
        Ok(_) => panic!("invalid stealth must fail closed"),
        Err(error) => error,
    };
    assert!(matches!(error, EngineError::Config(_)));
}

#[test]
fn test_server_runtime_traffic_snapshot_aggregates_session_stats() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig::default();
    let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
    let session_id = runtime.accept_client("127.0.0.1:54321".parse().unwrap()).unwrap();
    assert!(runtime.domain.sessions.read().bandwidth_stats(session_id).is_some());
    let stats = runtime.session_stats(session_id).unwrap();
    stats.record_received(120);
    stats.record_sent(64);
    stats.record_sent(32);

    let snapshot = runtime.traffic_snapshot();
    assert_eq!(snapshot.active_connections, 1);
    assert_eq!(snapshot.total_connections, 1);
    assert_eq!(snapshot.bytes_in, 120);
    assert_eq!(snapshot.bytes_out, 96);
    assert_eq!(snapshot.packets_in, 1);
    assert_eq!(snapshot.packets_out, 2);
}

#[test]
fn test_server_runtime_reaps_expired_sessions() {
    let engine_config = EngineConfig::default();
    let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
    let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
    runtime.accept_client("127.0.0.1:54322".parse().unwrap()).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(runtime.session_count(), 1);
    assert_eq!(runtime.reap_expired_sessions(), 1);
    assert_eq!(runtime.session_count(), 0);
}

#[test]
fn test_live_server_domain_resolves_session_identity_to_remote_addr() {
    let remote_addr = "127.0.0.1:54322".parse().unwrap();
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let (session_id, _, _) = domain.accept(remote_addr).unwrap();

    assert!(domain.shared.sessions.read().bandwidth_stats(session_id).is_none());
    assert_eq!(
        domain.remote_addr_for_identity(&ClientIdentity::Session(session_id)),
        Some(remote_addr)
    );
    assert_eq!(domain.session_id_by_remote(remote_addr), Some(session_id));
}

#[test]
fn test_live_state_kick_client_accepts_canonical_session_identity() {
    let mut live_state = LiveServerState::try_new(ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
    let accept_loop = AcceptLoop::new(AcceptConfig::default());
    let metrics = Metrics::new();
    let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
    let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
    let mut transport =
        crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
    let connection = create_live_server_connection(
        local_addr,
        remote_addr,
        &mut transport,
        StealthConfig::default(),
        FecConfig::default(),
        OptimizeConfig::default(),
        &crate::transport::ConnectionId::from_ref(b"admin-kick-sess-id"),
    )
    .expect("live server connection must be creatable");

    live_state.clients.insert(remote_addr, connection);
    live_state.kick_client(&ClientIdentity::Session(session_id), &accept_loop, &metrics);

    assert!(!live_state.clients.contains_key(&remote_addr));
    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
    assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_live_server_domain_remove_remote_clears_packet_rate_limit_ip_state() {
    let remote_addr = "127.0.0.1:54323".parse().unwrap();
    let domain = LiveServerDomain::try_new(&ServerConfig::default())
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let _ = domain.accept(remote_addr).unwrap();
    *domain.shared.packet_rate_limiter.lock() = PacketRateLimiterDomain {
        limiter: RateLimiter::new(crate::implementations::server::limits::RateLimitConfig {
            max_pps: 1,
            max_bps: 0,
            refill_interval: Duration::from_secs(60),
            burst_size: 1,
        }),
        last_prune: Instant::now(),
        last_sample: Instant::now(),
    };

    let packet = [0u8; 64];
    assert!(admission_allowed(&domain, remote_addr, &packet));
    assert!(!admission_allowed(&domain, remote_addr, &packet));

    domain.remove_remote(remote_addr);

    assert!(admission_allowed(&domain, remote_addr, &packet));
}

#[tokio::test]
async fn test_housekeeping_tick_reaps_expired_sessions_from_runtime_lifecycle() {
    let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
    let mut live_state = LiveServerState::try_new(server_config)
        .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
    let remote_addr = "127.0.0.1:54324".parse().unwrap();
    let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let accept_loop = AcceptLoop::new(AcceptConfig::default());
    let metrics = Metrics::new();
    let mut out = [0; 1460];

    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), Some(session_id));
    tokio::time::sleep(Duration::from_secs(2)).await;

    live_state
        .run_housekeeping_tick(&socket, &mut out, &metrics, &accept_loop)
        .await
        .expect("housekeeping should not fail with no active clients");

    assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
    assert_eq!(live_state.domain.active_session_count(), 0);
    assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
}

#[test]
fn test_live_udp_datagram_buffer_serializes_full_1500_byte_fec_envelope() {
    let profile = crate::fec::wire::WireProfile {
        epoch: 1,
        codec: crate::fec::wire::WireCodec::Gf8,
        source_count: 4,
        total_count: 6,
        interleave_depth: 1,
    };
    let metadata = crate::fec::wire::WirePacketMeta {
        profile,
        window: 0,
        sequence: 0,
        repair_index: crate::fec::wire::SYSTEMATIC_REPAIR_INDEX,
        block_index: 0,
        systematic: true,
    };
    let payload = vec![0u8; 1500 - crate::fec::wire::HEADER_LEN];
    let mut output = vec![0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];

    let written = crate::fec::wire::write_packet(metadata, &payload, &mut output)
        .expect("1500-byte FEC envelope must fit the live server UDP buffer");

    assert_eq!(written, 1500);
}

#[tokio::test]
async fn test_standalone_runtime_shutdown_trips_registered_service_signals() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
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
    let admin = Arc::new(AtomicBool::new(false));
    let admin_web = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(AtomicBool::new(false));

    runtime.register_admin_shutdown(admin.clone());
    runtime.register_admin_web_shutdown(admin_web.clone());
    runtime.register_metrics_shutdown(metrics.clone());
    runtime.shutdown_live(b"test_shutdown");

    assert!(admin.load(Ordering::SeqCst));
    assert!(admin_web.load(Ordering::SeqCst));
    assert!(metrics.load(Ordering::SeqCst));
}

/// Direct `stop()` must signal every auxiliary service, not only the drain paths.
///
/// The async drain and live-shutdown paths already called `shutdown_all()`, but direct stop
/// did not, so admin, web, and metrics listeners could stay alive holding their ports and
/// serving stale state while the runtime published Stopped.
#[tokio::test]
async fn direct_stop_signals_every_registered_service_and_is_idempotent() {
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
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

    let admin = Arc::new(AtomicBool::new(false));
    let admin_web = Arc::new(AtomicBool::new(false));
    let metrics = Arc::new(AtomicBool::new(false));
    runtime.register_admin_shutdown(admin.clone());
    runtime.register_admin_web_shutdown(admin_web.clone());
    runtime.register_metrics_shutdown(metrics.clone());

    runtime.stop().expect("direct stop");

    assert!(admin.load(Ordering::SeqCst), "direct stop must signal the admin service");
    assert!(admin_web.load(Ordering::SeqCst), "direct stop must signal the web service");
    assert!(metrics.load(Ordering::SeqCst), "direct stop must signal the metrics service");

    // A service registered after the first stop must still be signalled by a repeated stop,
    // and the repeat itself must stay successful.
    let late = Arc::new(AtomicBool::new(false));
    runtime.register_admin_shutdown(late.clone());
    runtime.stop().expect("repeated stop stays successful");
    assert!(late.load(Ordering::SeqCst), "a repeated stop must not skip signalling");
}

#[tokio::test]
async fn test_standalone_runtime_drain_rejects_new_clients_and_reports_lifecycle() {
    let engine_config = EngineConfig {
        engine: qf_engine_types::EngineSection {
            shutdown_timeout_ms: 250,
            ..qf_engine_types::EngineSection::default()
        },
        ..EngineConfig::default()
    };
    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
    let mut runtime = ServerRuntime::new_standalone_default(
        engine_config,
        server_config,
        None,
        crate::optimize::OptimizeConfig::default(),
        blocked_ips,
        qkey_registry,
        StandaloneAdminWebBootstrap::default(),
    )
    .unwrap();

    runtime.start().unwrap();
    assert!(runtime.initiate_drain(b"test_drain"));
    assert!(!runtime.initiate_drain(b"duplicate_drain"));
    assert_eq!(runtime.state(), ServerState::Draining);
    assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Draining);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(250));
    assert!(runtime.live().accept_loop.is_shutdown());
    assert_eq!(
        runtime.live().accept_loop.should_accept(
            "127.0.0.1:54321".parse().unwrap(),
            0,
            runtime.live().accept_max_clients,
        ),
        AcceptDecision::Reject(RejectReason::Shutdown)
    );
    let status = runtime.graceful_shutdown.status_json(3);
    assert_eq!(status["state"], "draining");
    assert_eq!(status["active_connections"], 3);
    assert_eq!(status["grace_period_ms"], 250);

    runtime.stop().unwrap();
    assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Stopped);
}

#[tokio::test]
async fn test_runtime_reload_updates_shutdown_grace_without_stopping_server() {
    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let config_path = std::env::temp_dir().join(format!(
        "quicfuscate-reload-grace-{}-{}.toml",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut config_file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
    config_file.write_all(b"[engine]\nshutdown_timeout_ms = 175\n").unwrap();
    drop(config_file);

    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
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
        Some(config_path.clone()),
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
    runtime.sync_standalone_runtime_metadata(&runtime_config.standalone_runtime_metadata);
    runtime.start().unwrap();

    runtime.reload_standalone_runtime(&mut runtime_config, "test");

    assert_eq!(runtime.state(), ServerState::Running);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(175));
    assert_eq!(runtime_config.runtime_policy_generation.current(), 2);
    runtime.stop().unwrap();
    std::fs::remove_file(config_path).unwrap();
}

#[tokio::test]
async fn test_runtime_reload_rejects_startup_owned_memory_settings() {
    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let config_path = std::env::temp_dir().join(format!(
        "quicfuscate-reload-memory-lock-{}-{}.toml",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut config_file =
        std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
    config_file.write_all(b"[security]\nlock_memory = false\nlock_blocks = false\n").unwrap();
    drop(config_file);

    let server_config =
        ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new_in_memory(16, None)));
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
        Some(config_path.clone()),
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
    runtime.sync_standalone_runtime_metadata(&runtime_config.standalone_runtime_metadata);
    runtime.start().unwrap();

    runtime.reload_standalone_runtime(&mut runtime_config, "test");

    assert_eq!(runtime.state(), ServerState::Running);
    assert!(runtime.engine_config.security.lock_memory);
    assert!(runtime.engine_config.security.lock_blocks);
    assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_secs(5));
    runtime.stop().unwrap();
    std::fs::remove_file(config_path).unwrap();
}
