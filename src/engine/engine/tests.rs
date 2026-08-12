use super::*;
use crate::engine::FecMode;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

static ENGINE_TUN_TEST_LOCK: StdMutex<()> = StdMutex::new(());

fn engine_tun_test_guard() -> StdMutexGuard<'static, ()> {
    ENGINE_TUN_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn engine_tun_test_config() -> EngineConfig {
    let mut config = EngineConfig::default();
    config.interface.tun_name.clear();
    config
}

#[test]
fn test_engine_lifecycle() {
    let _tun_guard = engine_tun_test_guard();
    if !crate::tun_available_for_engine_tests() {
        return;
    }
    let config = engine_tun_test_config();
    let mut engine = QuicFuscateEngine::new(config).unwrap();

    assert_eq!(engine.state(), EngineState::Created);

    engine.start().unwrap();
    assert_eq!(engine.state(), EngineState::Running);

    engine.stop().unwrap();
    assert_eq!(engine.state(), EngineState::Stopped);
}

#[test]
fn fec_policy_command_without_connection_reports_next_connection_scope() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");

    let result = engine.set_fec_mode(FecMode::Off).expect("policy command");

    assert_eq!(result.requested, FecMode::Off);
    assert_eq!(result.configured, FecMode::Off);
    assert_eq!(result.effective, None);
    assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
    assert_eq!(engine.fec_mode(), FecMode::Off);
    assert_eq!(engine.active_fec_mode(), None);
}

#[test]
fn structured_fec_command_returns_policy_acknowledgement() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");

    let result =
        engine.apply_command(EngineCommand::SetFecMode(FecMode::Off)).expect("policy command");

    let EngineCommandResult::FecPolicy(result) = result else {
        panic!("FEC command must return a typed policy acknowledgement");
    };
    assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
    assert_eq!(result.effective, None);
}

#[test]
fn next_connection_fec_command_updates_started_client_runtime_config() {
    let config = EngineConfig::default();
    let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.client_runtime = Some(runtime);
    engine.state = EngineState::Running;

    let result = engine.set_fec_mode(FecMode::Off).expect("policy command");

    assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
    assert_eq!(engine.client_runtime.as_ref().expect("runtime").next_fec_mode(), FecMode::Off);
}

#[test]
fn started_client_setters_update_the_next_connection_projection() {
    let config = EngineConfig::default();
    let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.client_runtime = Some(runtime);
    engine.state = EngineState::Running;

    engine.set_stealth_mode(crate::engine::StealthMode::AntiDpi).expect("stealth update");
    engine.set_cc_algorithm(crate::engine::CcAlgorithm::Cubic).expect("congestion-control update");
    engine.set_traffic_padding(true).expect("padding update");
    engine.set_timing_obfuscation(true).expect("timing update");
    engine.set_0rtt(false).expect("0-RTT update");

    let next = engine.client_runtime.as_ref().expect("client runtime").next_config();
    assert_eq!(next.stealth.mode, crate::engine::StealthMode::AntiDpi);
    assert_eq!(next.transport.cc_algorithm, crate::engine::CcAlgorithm::Cubic);
    assert!(next.stealth.enable_traffic_padding);
    assert!(next.stealth.enable_timing_obfuscation);
    assert!(!next.connection.enable_0rtt);
}

#[test]
fn started_client_rejects_startup_owned_config_changes() {
    let config = EngineConfig::default();
    let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.client_runtime = Some(runtime);
    engine.state = EngineState::Running;
    let before = toml::to_string(engine.config()).expect("serialize config");

    let error = engine
        .update_config(|candidate| candidate.interface.tun_mtu = 1400)
        .expect_err("started client must reject TUN replacement");

    assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
    assert_eq!(toml::to_string(engine.config()).expect("serialize config"), before);
    assert_eq!(
        toml::to_string(engine.client_runtime.as_ref().expect("client runtime").next_config())
            .expect("serialize next config"),
        before
    );
}

#[test]
fn started_client_rejects_fingerprint_rotation_policy_changes() {
    let config = EngineConfig::default();
    let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.client_runtime = Some(runtime);
    engine.state = EngineState::Running;
    let before = toml::to_string(engine.config()).expect("serialize config");

    let error = engine
        .update_config(|candidate| {
            candidate.fingerprint_rotation.enabled = true;
            candidate.fingerprint_rotation.interval_secs = 60;
            candidate.fingerprint_rotation.mode = crate::engine::RotationMode::Slots;
            candidate.fingerprint_rotation.profile_slots =
                vec!["chrome@windows".to_string(), "firefox@windows".to_string()];
        })
        .expect_err("started client must reject rotation policy replacement");

    match error {
        EngineError::InvalidState(EngineState::Running, message) => {
            assert!(message.contains("fingerprint rotation policy"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(toml::to_string(engine.config()).expect("serialize config"), before);
    assert_eq!(
        toml::to_string(engine.client_runtime.as_ref().expect("client runtime").next_config())
            .expect("serialize next config"),
        before
    );
}

#[test]
fn running_generic_server_rejects_control_plane_config_mutation() {
    let mut config = EngineConfig::default();
    config.engine.mode = EngineMode::Server;
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.state = EngineState::Running;

    let error = engine
        .set_traffic_padding(true)
        .expect_err("running generic server must reject client-style mutation");

    assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
    assert!(!engine.config().stealth.enable_traffic_padding);
}

#[test]
fn file_reload_replaces_created_config_and_rejects_invalid_candidate() {
    let root = std::env::temp_dir()
        .join(format!("quicfuscate-engine-reload-{}-file-reload", std::process::id()));
    let valid_path = root.with_extension("valid.toml");
    let invalid_path = root.with_extension("invalid.toml");

    let mut replacement = EngineConfig::default();
    replacement.connection.remote = "127.0.0.1:9443".to_string();
    replacement.stealth.enable_traffic_padding = true;
    std::fs::write(&valid_path, toml::to_string(&replacement).expect("serialize valid config"))
        .expect("write valid config");

    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
    engine.reload_config_from_file(&valid_path).expect("valid reload");
    assert_eq!(engine.config().connection.remote, "127.0.0.1:9443");
    assert!(engine.config().stealth.enable_traffic_padding);

    let before_invalid = toml::to_string(engine.config()).expect("serialize current config");
    std::fs::write(&invalid_path, "[transport]\nmtu = 100\n").expect("write invalid config");
    assert!(engine.reload_config_from_file(&invalid_path).is_err());
    assert_eq!(toml::to_string(engine.config()).expect("serialize current config"), before_invalid);

    let missing_path = root.with_extension("missing.toml");
    assert!(engine.reload_config_from_file(&missing_path).is_err());
    assert_eq!(toml::to_string(engine.config()).expect("serialize current config"), before_invalid);

    let _ = std::fs::remove_file(valid_path);
    let _ = std::fs::remove_file(invalid_path);
}

#[test]
fn running_server_rejects_engine_fec_mutation_without_changing_configured_state() {
    let mut config = EngineConfig::default();
    config.engine.mode = EngineMode::Server;
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    engine.state = EngineState::Running;

    let error =
        engine.set_fec_mode(FecMode::Off).expect_err("running server mutation must be rejected");

    assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
    assert_eq!(engine.fec_mode(), FecMode::Auto);
}

#[test]
fn test_engine_connect_disconnect() {
    let _tun_guard = engine_tun_test_guard();
    if !crate::tun_available_for_engine_tests() {
        return;
    }
    let mut config = engine_tun_test_config();
    config.connection.remote = "127.0.0.1:4433".to_string();

    let mut engine = QuicFuscateEngine::new(config).unwrap();

    engine.start().unwrap();
    match engine.connect() {
        Ok(()) => {
            assert_eq!(engine.state(), EngineState::Connected);
            engine.disconnect().unwrap();
            assert_eq!(engine.state(), EngineState::Running);
        }
        Err(_) => {
            // On hosts without a reachable test server, connect must fail closed and
            // never leave the engine in a connected state.
            assert_eq!(engine.state(), EngineState::Running);
        }
    }

    engine.stop().unwrap();
}

#[test]
fn test_runtime_transport_config_respects_enable_migration() {
    let mut enabled = EngineConfig::default();
    enabled.connection.enable_migration = true;
    let enabled_transport = build_runtime_transport_config(&enabled).expect("transport config");
    assert!(!enabled_transport.disable_active_migration);

    let mut disabled = EngineConfig::default();
    disabled.connection.enable_migration = false;
    let disabled_transport = build_runtime_transport_config(&disabled).expect("transport config");
    assert!(disabled_transport.disable_active_migration);
}

#[test]
fn test_runtime_transport_config_carries_migration_policy() {
    let mut config = EngineConfig::default();
    config.connection.migration_cwnd_reduction_factor = 0.25;
    config.connection.migration_cooldown_ms = 0;
    config.connection.migration_probe_target =
        crate::transport::MigrationProbeTarget::ReducedWindow;

    let transport = build_runtime_transport_config(&config).expect("transport config");
    let policy = transport.migration_policy();
    assert_eq!(policy.port_rebinding_cwnd_factor, 0.25);
    assert_eq!(policy.cooldown, Duration::ZERO);
    assert_eq!(policy.probe_target, crate::transport::MigrationProbeTarget::ReducedWindow);
}

#[test]
fn test_runtime_transport_config_rejects_missing_ca_file() {
    let mut config = EngineConfig::default();
    config.connection.ca_file = std::env::temp_dir()
        .join(format!("quicfuscate-missing-engine-ca-{}.pem", std::process::id()))
        .to_string_lossy()
        .into_owned();

    let error = match build_runtime_transport_config(&config) {
        Err(error) => error,
        Ok(_) => panic!("a configured CA path must fail closed when it cannot be loaded"),
    };
    assert!(matches!(error, EngineError::Config(_)));
}

#[test]
fn test_runtime_transport_config_carries_nat_traversal_policy() {
    let mut config = EngineConfig::default();
    config.nat_traversal.enabled = true;
    config.nat_traversal.mode = crate::transport::NatTraversalMode::Roaming;
    config.nat_traversal.ice_enabled = true;
    config.nat_traversal.stun_servers = vec!["203.0.113.1:3478".to_string()];
    config.nat_traversal.max_candidates = 4;

    let transport = build_runtime_transport_config(&config).expect("transport config");
    let nat = transport.nat_traversal();
    assert!(nat.enabled);
    assert_eq!(nat.mode, crate::transport::NatTraversalMode::Roaming);
    assert!(nat.ice_enabled);
    assert_eq!(nat.max_candidates, 4);
    assert_eq!(nat.stun_servers.len(), 1);
}

#[test]
fn test_runtime_transport_config_carries_all_traffic_analysis_policies() {
    let active = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
        chaff_rate_pps: 25,
        chaff_size_bytes: 1200,
        constant_rate_pps: 0,
        idle_timeout_ms: 30_000,
        ramp_down_ms: 5_000,
    };
    let qkey_ceiling = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
        chaff_rate_pps: 500,
        chaff_size_bytes: 1400,
        constant_rate_pps: 100,
        idle_timeout_ms: 60_000,
        ramp_down_ms: 10_000,
    };
    let intelligent_ceiling = crate::transport::config::TrafficAnalysisPolicy {
        defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
        chaff_rate_pps: 10,
        chaff_size_bytes: 1000,
        constant_rate_pps: 0,
        idle_timeout_ms: 20_000,
        ramp_down_ms: 2_000,
    };
    let mut config = EngineConfig::default();
    config.transport.traffic_analysis = active;
    config.transport.qkey_traffic_analysis_ceiling = qkey_ceiling;
    config.transport.intelligent_traffic_analysis_ceiling = intelligent_ceiling;

    let transport = build_runtime_transport_config(&config).expect("transport config");
    assert_eq!(transport.traffic_analysis_policy(), active);
    assert_eq!(transport.qkey_traffic_analysis_ceiling(), qkey_ceiling);
    assert_eq!(transport.intelligent_traffic_analysis_ceiling(), intelligent_ceiling);
}

/// A stop that cannot reap the server loop must not report a clean shutdown.
///
/// The join previously timed out with a warning and the engine still published `Stopped`,
/// while the loop could still hold listeners, sessions, and descriptors.
#[test]
fn stop_reports_an_error_when_the_server_loop_cannot_be_reaped() {
    let mut engine = QuicFuscateEngine::new(engine_tun_test_config()).expect("engine");
    engine.set_state(EngineState::Running);
    // A loop that never exits, standing in for a runtime that outlived its shutdown budget.
    let (block_tx, block_rx) = crossbeam_channel::bounded::<()>(1);
    engine.server_loop_handle = Some(
        std::thread::Builder::new()
            .name("test-unreapable-server-loop".to_string())
            .spawn(move || {
                let _ = block_rx.recv();
            })
            .expect("spawn test loop"),
    );
    engine.config.engine.shutdown_timeout_ms = 50;

    let outcome = engine.stop();

    assert!(
        outcome.is_err(),
        "an unreaped server loop must surface as an error, not a clean Stopped"
    );
    assert_eq!(
        engine.state(),
        EngineState::Error,
        "the published state must not claim the engine stopped"
    );

    // Release the loop so the test leaves no live thread behind.
    let _ = block_tx.send(());
}

#[test]
fn test_engine_server_start_stop_runs_standalone_runtime() {
    let _tun_guard = engine_tun_test_guard();
    let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config/local/dev-certs/admin-local-20260208_213140.crt");
    let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("config/local/dev-certs/admin-local-20260208_213140.key");
    if !cert_path.exists() || !key_path.exists() {
        return;
    }
    if !crate::tun_available_for_engine_tests() {
        return;
    }

    let mut config = engine_tun_test_config();
    config.engine.mode = EngineMode::Server;
    config.connection.remote = "127.0.0.1:0".to_string();
    config.connection.cert_file = cert_path.to_string_lossy().into_owned();
    config.connection.key_file = key_path.to_string_lossy().into_owned();
    let mut engine = QuicFuscateEngine::new(config).unwrap();
    engine.start().unwrap();
    assert_eq!(engine.state(), EngineState::Running);
    assert!(engine.server_loop_handle.is_some());
    assert!(engine.server_loop_shutdown_tx.is_some());
    assert!(engine.server_metrics.is_some());
    std::thread::sleep(std::time::Duration::from_millis(25));
    assert!(engine.is_running());

    engine.stop().unwrap();
    assert_eq!(engine.state(), EngineState::Stopped);
    assert!(!engine.is_running());
}

#[test]
fn test_engine_start_failure_enters_error_state() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();
    engine.config.engine.mode = EngineMode::Server;
    engine.config.connection.remote = "not-a-socket-address".to_string();

    assert!(matches!(engine.start(), Err(EngineError::Config(_))));
    assert_eq!(engine.state(), EngineState::Error);
    engine.stop().unwrap();
    assert_eq!(engine.state(), EngineState::Stopped);
}

#[test]
fn test_invalid_state_transitions() {
    let _tun_guard = engine_tun_test_guard();
    if !crate::tun_available_for_engine_tests() {
        return;
    }
    let config = engine_tun_test_config();
    let mut engine = QuicFuscateEngine::new(config).unwrap();

    // Can't connect before start
    assert!(engine.connect().is_err());

    // Can't disconnect before connect
    engine.start().unwrap();
    assert!(engine.disconnect().is_err());
}

struct TestCallback {
    state_changed: Arc<AtomicBool>,
}

impl EngineCallback for TestCallback {
    fn on_state_change(&self, _old: EngineState, _new: EngineState) {
        self.state_changed.store(true, Ordering::SeqCst);
    }
}

#[test]
fn test_callbacks() {
    let _tun_guard = engine_tun_test_guard();
    if !crate::tun_available_for_engine_tests() {
        return;
    }
    let config = engine_tun_test_config();
    let mut engine = QuicFuscateEngine::new(config).unwrap();

    let state_changed = Arc::new(AtomicBool::new(false));
    let callback = TestCallback { state_changed: state_changed.clone() };

    engine.add_callback(callback);
    engine.start().unwrap();

    assert!(state_changed.load(Ordering::SeqCst));
}

#[test]
fn test_server_refresh_stats_projects_runtime_owned_server_metrics() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
    let server_metrics = Arc::new(Metrics::new());
    server_metrics.record_egress_datagram(100);
    server_metrics.record_egress_datagram(10);
    server_metrics.record_egress_datagram(1);
    server_metrics.record_ingress_datagram(200);
    server_metrics.record_ingress_datagram(20);
    server_metrics.record_ingress_datagram(1);
    server_metrics.record_ingress_datagram(1);
    server_metrics.clients_active.store(5, Ordering::Relaxed);
    engine.server_metrics = Some(server_metrics.clone());

    let global = crate::instrumentation::global();
    global.transport.record_rtt(123_000);
    global.transport.record_packet_out();
    global.transport.record_packet_loss();

    engine.refresh_stats();

    assert_eq!(engine.stats.bytes_sent.load(Ordering::Relaxed), 111);
    assert_eq!(engine.stats.bytes_received.load(Ordering::Relaxed), 222);
    assert_eq!(engine.stats.packets_sent.load(Ordering::Relaxed), 3);
    assert_eq!(engine.stats.packets_received.load(Ordering::Relaxed), 4);
    assert_eq!(engine.stats.active_streams.load(Ordering::Relaxed), 5);
    assert_eq!(engine.stats.rtt_ms.load(Ordering::Relaxed), 0);
    assert_eq!(engine.stats.loss_percent.load(Ordering::Relaxed), 0);
    assert_eq!(engine.stats.data_plane_ready.load(Ordering::Relaxed), 1);
    assert_eq!(engine.stats.data_plane_faults.load(Ordering::Relaxed), 0);

    server_metrics.record_tun_data_plane_fault();
    engine.refresh_stats();
    assert_eq!(engine.stats.data_plane_ready.load(Ordering::Relaxed), 0);
    assert_eq!(engine.stats.data_plane_faults.load(Ordering::Relaxed), 1);
}

#[test]
fn data_plane_faults_are_typed_and_displayable() {
    let fault = DataPlaneFault::TunWrite {
        component: "server MASQUE downlink".to_string(),
        error: "device closed".to_string(),
    };

    assert_eq!(fault.to_string(), "TUN write failed (server MASQUE downlink): device closed");
    assert_eq!(
        EngineError::DataPlane(fault.clone()).to_string(),
        "Data-plane error: TUN write failed (server MASQUE downlink): device closed"
    );
    assert_eq!(DisconnectReason::DataPlane(fault.clone()), DisconnectReason::DataPlane(fault));
}

#[test]
fn test_check_heartbeat_returns_false_when_not_connected() {
    let mut config = EngineConfig::default();
    config.security.heartbeat_timeout_ms = 1000;
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    // Engine is in Created state, not Connected
    assert!(!engine.check_heartbeat());
}

#[test]
fn test_check_heartbeat_disabled_when_timeout_zero() {
    let mut config = EngineConfig::default();
    config.security.heartbeat_timeout_ms = 0;
    let mut engine = QuicFuscateEngine::new(config).expect("engine");
    // Even if we forced state to Connected, heartbeat=0 means disabled
    engine.state = EngineState::Connected;
    assert!(!engine.check_heartbeat());
}

#[test]
fn test_security_config_defaults() {
    let config = EngineConfig::default();
    // Kill switch disabled by default (safe default)
    assert!(!config.security.kill_switch);
    // Heartbeat timeout default is 30s
    assert_eq!(config.security.heartbeat_timeout_ms, 30_000);
    // Cleanup on start disabled by default
    assert!(!config.security.cleanup_firewall_on_start);
}

#[test]
fn test_handle_connection_loss_no_op_when_not_connected() {
    let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
    // Engine is in Created state - handle_connection_loss should be a no-op
    engine.handle_connection_loss(DisconnectReason::Timeout);
    // State should remain Created
    assert_eq!(engine.state(), EngineState::Created);
}
