use super::*;

#[test]
fn lifecycle_display_is_stable() {
    assert_eq!(EngineState::Created.to_string(), "Created");
    assert_eq!(EngineState::Connected.to_string(), "Connected");
    assert_eq!(EngineState::Error.to_string(), "Error");
}

#[test]
fn runtime_policy_generation_is_shared_and_saturating() {
    let generation = RuntimePolicyGeneration::new();
    let observer = generation.clone();
    assert_eq!(observer.current(), 1);

    let mut guard = generation.write_guard();
    RuntimePolicyGeneration::advance(&mut guard);
    assert_eq!(*guard, 2);
    *guard = u64::MAX;
    RuntimePolicyGeneration::advance(&mut guard);
    drop(guard);

    assert_eq!(observer.current(), u64::MAX);
}

#[test]
fn engine_mode_defaults_match_configuration_contract() {
    assert_eq!(EngineMode::default(), EngineMode::Client);
    assert_eq!(StealthMode::default(), StealthMode::Dynamic);
    assert_eq!(FecMode::default(), FecMode::Auto);
    assert!(qf_fec::EngineFecMode::adaptive_requested(FecMode::Auto));
    assert!(!qf_fec::EngineFecMode::adaptive_requested(FecMode::Off));
    assert_ne!(EngineMode::Client, EngineMode::Server);
    assert_ne!(StealthMode::Off, StealthMode::StealthMax);
}

#[test]
fn engine_section_defaults_and_validation_match_configuration_contract() {
    let section = EngineSection::default();
    assert_eq!(section.mode, EngineMode::Client);
    assert_eq!(section.log_level, "info");
    assert!(section.validate().is_ok());

    let mut invalid_level = section.clone();
    invalid_level.log_level = "verbose".to_string();
    assert_eq!(
        invalid_level.validate().expect_err("invalid log level must fail"),
        "Invalid log_level: verbose. Must be one of: [\"trace\", \"debug\", \"info\", \"warn\", \"error\"]"
    );

    let mut invalid_timeout = section;
    invalid_timeout.shutdown_timeout_ms = 0;
    assert_eq!(
        invalid_timeout.validate().expect_err("zero timeout must fail"),
        "engine.shutdown_timeout_ms must be > 0"
    );
}

#[test]
fn fec_section_defaults_and_runtime_projection_match_engine_contract() {
    let section = FecSection::default();
    assert_eq!(section.mode, FecMode::Auto);
    assert_eq!(section.initial_mode, "auto");
    assert_eq!(section.window_good, 10);
    assert_eq!(section.window_fair, 30);
    assert_eq!(section.window_poor, 50);
    assert!(section.validate().is_ok());

    let runtime = section.to_runtime_config().expect("default FEC section projects");
    assert_eq!(runtime.control_policy, qf_fec::FecControlPolicy::Auto);
    assert_eq!(runtime.initial_mode, qf_fec::FecMode::Zero);
    assert_eq!(runtime.configured_stream_every, Some(5));
    assert_eq!(runtime.window_sizes[&qf_fec::FecMode::Normal], 10);
    assert_eq!(runtime.window_sizes[&qf_fec::FecMode::Medium], 30);
    assert_eq!(runtime.window_sizes[&qf_fec::FecMode::Strong], 50);
}

#[test]
fn fec_section_off_mode_projects_a_disabled_policy() {
    let section = FecSection { mode: FecMode::Off, ..FecSection::default() };
    let runtime = section.to_runtime_config().expect("off FEC section projects");
    assert_eq!(runtime.control_policy, qf_fec::FecControlPolicy::Off);
    assert_eq!(runtime.initial_mode, qf_fec::FecMode::Zero);
    assert!(!runtime.force_on);
}

#[test]
fn fec_section_rejects_invalid_projection_inputs() {
    let section = FecSection { initial_mode: "streaming".to_string(), ..FecSection::default() };
    assert_eq!(
        section.validate().expect_err("unsupported initial mode must fail").to_string(),
        "fec.initial_mode has unsupported value 'streaming'; use 'auto' or 'off'"
    );

    let section = FecSection { window_good: 0, ..FecSection::default() };
    assert_eq!(
        section.validate().expect_err("zero good window must fail").to_string(),
        "fec.window_good, fec.window_fair, and fec.window_poor must be > 0"
    );

    let section = FecSection { enable_partial: false, ..FecSection::default() };
    assert!(section
        .to_runtime_config()
        .expect_err("disabled partial recovery must fail")
        .to_string()
        .contains("fec.enable_partial=false"));
}

#[test]
fn security_config_defaults_preserve_engine_startup_contract() {
    let config = SecurityConfig::default();
    assert!(!config.kill_switch);
    assert_eq!(config.heartbeat_timeout_ms, 30_000);
    assert!(!config.cleanup_firewall_on_start);
    assert_eq!(config.firewall, FirewallConfig::default());
    assert!(config.lock_memory);
    assert_eq!(config.memory_lock_failure_policy, MemoryLockFailurePolicy::BestEffort);
    assert!(config.lock_blocks);
}

#[test]
fn optimization_config_projects_the_runtime_pool_contract() {
    let config = OptimizationConfig {
        memory_pool_size: 16 * 1024 * 1024,
        memory_pool_alignment: 64,
        num_worker_threads: 0,
    };
    let runtime = config.to_runtime_config().expect("optimization config projects");
    assert_eq!(runtime.block_size, 65_536);
    assert_eq!(runtime.pool_capacity, 256);
    config.validate().expect("projected optimization config validates");
}

#[test]
fn optimization_config_preserves_scaling_and_validation_contract() {
    assert_eq!(scaled_memory_pool_size(128 * 1024 * 1024), MIN_POOL_BYTES);
    assert_eq!(scaled_memory_pool_size(2 * 1024 * 1024 * 1024), MAX_POOL_BYTES);
    assert_eq!(scaled_memory_pool_size(usize::MAX), MAX_POOL_BYTES);

    let invalid_alignment =
        OptimizationConfig { memory_pool_alignment: 0, ..OptimizationConfig::default() };
    assert_eq!(
        invalid_alignment.validate().expect_err("zero alignment must fail").to_string(),
        "optimization.memory_pool_alignment must be > 0"
    );

    let invalid_threads =
        OptimizationConfig { num_worker_threads: 257, ..OptimizationConfig::default() };
    assert_eq!(
        invalid_threads.validate().expect_err("excessive worker count must fail").to_string(),
        "optimization.num_worker_threads must be 0 or <= 256"
    );
}

#[test]
fn transport_config_defaults_and_validation_match_engine_contract() {
    let config = TransportConfig::default();
    assert_eq!(
        config.quic_versions,
        [qf_transport_version::QuicVersion::V2, qf_transport_version::QuicVersion::V1]
    );
    assert_eq!(config.cc_algorithm, qf_transport_cc::cc::Algorithm::Bbr3);
    assert_eq!(config.mtu, 1500);
    assert_eq!(config.pmtu_min_mtu, 1280);
    assert_eq!(config.pmtu_max_mtu, 1500);
    assert!(config.validate().is_ok());

    let duplicate = TransportConfig {
        quic_versions: vec![qf_transport_version::QuicVersion::V2; 2],
        ..config.clone()
    };
    assert_eq!(
        duplicate.validate().expect_err("duplicate versions must fail").to_string(),
        "quic_versions must not contain duplicates"
    );

    let invalid_mtu = TransportConfig { mtu: 1199, ..config };
    assert_eq!(
        invalid_mtu.validate().expect_err("sub-floor MTU must fail").to_string(),
        "transport.mtu must be at least 1200, got 1199"
    );
}

#[test]
fn connection_config_defaults_and_validation_match_engine_contract() {
    let config = ConnectionConfig::default();
    assert_eq!(config.remote, "0.0.0.0:4433");
    assert_eq!(config.alpn, ["h3", "quicfuscate"]);
    assert_eq!(config.migration_cooldown_ms, 750);
    assert!(config.validate().is_ok());

    let invalid_remote =
        ConnectionConfig { remote: "not-an-address".to_string(), ..config.clone() };
    assert!(invalid_remote
        .validate()
        .expect_err("invalid remote must fail")
        .to_string()
        .starts_with("connection.remote must be a host:port or [ipv6]:port authority:"));

    let invalid_qkey_id = ConnectionConfig { qkey_id: Some("abc".to_string()), ..config };
    assert_eq!(
        invalid_qkey_id.validate().expect_err("invalid qkey id must fail").to_string(),
        "qkey_id must be 12 hex chars"
    );
}

#[test]
fn qkey_token_debug_is_redacted_and_value_access_is_explicit() {
    let token = QKeyToken::from("sensitive-token");
    assert_eq!(token.as_ref(), "sensitive-token");
    assert_eq!(format!("{token:?}"), "QKeyToken([REDACTED])");
}

#[test]
fn qkey_config_checksum_binds_all_serialized_fields() {
    let config = QKeyConfig::new("192.168.1.1:4433", "example.com")
        .with_stealth("stealth")
        .with_fec("auto")
        .with_extra("profile=default")
        .with_token("sensitive-token");
    assert!(config.validate());

    let mut tampered = config.clone();
    tampered.remote.push_str(".invalid");
    assert!(!tampered.validate());
}

#[test]
fn authenticated_transcript_hash_matches_token_and_registry_views() {
    let token = "11".repeat(32);
    let token_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update([0x11u8; 32]);
        format!("{:x}", hasher.finalize())
    };
    assert_eq!(
        authenticated_transcript_hash_from_token_hex(&token),
        authenticated_transcript_hash_from_verifier_hash_hex(&token_hash)
    );
    assert_eq!(
        QKeyToken::from(token).authenticated_transcript_hash(),
        authenticated_transcript_hash_from_verifier_hash_hex(&token_hash)
    );
}

#[test]
fn authenticated_transcript_hash_rejects_non_hex_or_wrong_length() {
    assert!(authenticated_transcript_hash_from_token_hex("not-a-token").is_none());
    assert!(authenticated_transcript_hash_from_verifier_hash_hex("00").is_none());
}

#[test]
fn stats_snapshot_projects_atomic_values() {
    let stats = EngineStats::default();
    stats.bytes_sent.store(11, Ordering::Relaxed);
    stats.packets_received.store(7, Ordering::Relaxed);
    stats.data_plane_ready.store(1, Ordering::Relaxed);
    assert_eq!(
        stats.snapshot(),
        StatsSnapshot {
            bytes_sent: 11,
            packets_received: 7,
            data_plane_ready: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[test]
fn typed_fault_and_error_display_are_stable() {
    let fault =
        DataPlaneFault::TunWrite { component: "tun".to_string(), error: "closed".to_string() };
    assert_eq!(fault.to_string(), "TUN write failed (tun): closed");
    assert_eq!(
        EngineError::DataPlane(fault).to_string(),
        "Data-plane error: TUN write failed (tun): closed"
    );
    assert_eq!(EngineError::Backpressure.to_string(), "Connection backpressure");
}

#[test]
fn config_error_display_preserves_stable_categories() {
    assert_eq!(ConfigError::Io("missing".to_string()).to_string(), "IO error: missing");
    assert_eq!(ConfigError::Parse("invalid".to_string()).to_string(), "Parse error: invalid");
    assert_eq!(
        ConfigError::Validation("bad mtu".to_string()).to_string(),
        "Validation error: bad mtu"
    );
}

#[test]
fn outer_hop_none_is_default_and_rejects_stray_relay() {
    let config = ConnectionConfig::default();
    assert_eq!(config.outer_hop, OuterHop::None);
    assert!(config.outer_hop_relay.is_none());
    config.validate().expect("default connection validates");

    let stray = ConnectionConfig {
        outer_hop_relay: Some(circuit::HopConfig::default()),
        ..ConnectionConfig::default()
    };
    assert!(stray.validate().is_err(), "a relay without masque mode is contradictory");
}

#[test]
fn outer_hop_masque_requires_relay_with_relay_role() {
    let mut config =
        ConnectionConfig { outer_hop: OuterHop::Masque, ..ConnectionConfig::default() };
    assert!(config.validate().is_err(), "masque without a relay description fails");

    let mut relay = circuit::HopConfig {
        label: "edge".to_string(),
        endpoint: "relay.example.com:4433".to_string(),
        sni: "relay.example.com".to_string(),
        qkey_id: "0123456789ab".to_string(),
        qkey_token_ref: "env:QF_RELAY_QKEY".to_string(),
        ..circuit::HopConfig::default()
    };
    config.outer_hop_relay = Some(relay.clone());
    assert!(
        config.validate().is_err(),
        "default exit role must be rejected for the outer relay hop"
    );

    relay.role = circuit::HopRole::Relay;
    config.outer_hop_relay = Some(relay);
    config.validate().expect("masque with a relay hop validates");
}

#[test]
fn outer_hop_tls_http_is_reserved_and_fails_validation() {
    let config = ConnectionConfig { outer_hop: OuterHop::TlsHttp, ..ConnectionConfig::default() };
    let error = config.validate().expect_err("tls_http is reserved, not implemented");
    assert!(error.to_string().contains("tls_http"), "{error}");
}

#[test]
fn outer_hop_engine_rules_gate_circuits_server_and_qkey() {
    let relay = circuit::HopConfig {
        label: "edge".to_string(),
        endpoint: "relay.example.com:4433".to_string(),
        sni: "relay.example.com".to_string(),
        qkey_id: "0123456789ab".to_string(),
        qkey_token_ref: "env:QF_RELAY_QKEY".to_string(),
        role: circuit::HopRole::Relay,
        ..circuit::HopConfig::default()
    };

    // Missing connection QKey: the synthesized exit hop could not authenticate.
    let mut no_qkey = EngineConfig::default();
    no_qkey.engine.mode = EngineMode::Client;
    no_qkey.connection.outer_hop = OuterHop::Masque;
    no_qkey.connection.outer_hop_relay = Some(relay.clone());
    assert!(no_qkey.validate().is_err());

    // Armed fallback plus explicit circuit: contradictory topology owners.
    let mut with_circuit = no_qkey.clone();
    with_circuit.connection.qkey_token = Some(crate::QKeyToken::new("ab".repeat(16)));
    with_circuit.circuit = Some(circuit::CircuitConfig {
        hops: vec![circuit::HopConfig {
            label: "exit".to_string(),
            endpoint: "exit.example.com:4433".to_string(),
            sni: "exit.example.com".to_string(),
            qkey_id: "0123456789ab".to_string(),
            qkey_token_ref: "env:QF_EXIT_QKEY".to_string(),
            ..circuit::HopConfig::default()
        }],
        ..circuit::CircuitConfig::default()
    });
    assert!(with_circuit.validate().is_err());

    // Server mode never arms a client dial fallback.
    let mut server = EngineConfig::default();
    server.engine.mode = EngineMode::Server;
    server.connection.outer_hop = OuterHop::Masque;
    server.connection.outer_hop_relay = Some(relay.clone());
    server.connection.qkey_token = Some(crate::QKeyToken::new("cd".repeat(16)));
    assert!(server.validate().is_err());

    // Well-formed client arming validates.
    let mut client = EngineConfig::default();
    client.engine.mode = EngineMode::Client;
    client.connection.qkey_token = Some(crate::QKeyToken::new("ef".repeat(16)));
    client.connection.outer_hop = OuterHop::Masque;
    client.connection.outer_hop_relay = Some(relay);
    client.validate().expect("armed masque fallback validates");
}

#[test]
fn outer_hop_roundtrips_through_engine_toml() {
    let config = EngineConfig::from_toml(
        "[connection]\n\
         remote = \"203.0.113.10:4433\"\n\
         qkey_token = \"00112233445566778899aabbccddeeff\"\n\
         outer_hop = \"masque\"\n\
         [connection.outer_hop_relay]\n\
         label = \"edge\"\n\
         endpoint = \"relay.example.com:4433\"\n\
         sni = \"relay.example.com\"\n\
         qkey_id = \"0123456789ab\"\n\
         qkey_token_ref = \"env:QF_RELAY_QKEY\"\n\
         role = \"relay\"\n",
    )
    .expect("outer hop TOML parses");
    assert_eq!(config.connection.outer_hop, OuterHop::Masque);
    let relay = config.connection.outer_hop_relay.as_ref().expect("relay hop");
    assert_eq!(relay.role, circuit::HopRole::Relay);
    assert_eq!(relay.endpoint, "relay.example.com:4433");

    let encoded = toml::to_string(&config).expect("serialize");
    let decoded = EngineConfig::from_toml(&encoded).expect("roundtrip");
    assert_eq!(decoded.connection.outer_hop, OuterHop::Masque);
    assert!(decoded.connection.outer_hop_relay.is_some());
}

#[test]
fn advanced_required_rejects_standard_pinned_stealth_and_multi_hop() {
    let mut base = EngineConfig::default();
    base.crypto.packet_protection_mode = PacketProtectionMode::AdvancedRequired;
    base.crypto.aead_preference = AeadPreference::Aegis128L;

    // The default stealth mode (dynamic) pins the standard wire baseline.
    let error = base.validate().expect_err("standard-pinned stealth must fail");
    assert!(error.to_string().contains("stealth"), "{error}");

    // Private-capable stealth modes validate the explicit opt-in.
    base.stealth.mode = StealthMode::Performance;
    base.validate().expect("performance stealth plus explicit family validates");
    base.stealth.mode = StealthMode::Manual;
    base.validate().expect("manual stealth plus explicit family validates");

    // Multi-hop paths never propagate the private policy onto hop connections.
    base.connection.outer_hop = OuterHop::Masque;
    base.connection.qkey_token = Some(crate::QKeyToken::new("cd".repeat(16)));
    base.connection.outer_hop_relay = Some(circuit::HopConfig {
        label: "edge".to_string(),
        endpoint: "relay.example.com:4433".to_string(),
        sni: "relay.example.com".to_string(),
        qkey_id: "0123456789ab".to_string(),
        qkey_token_ref: "env:QF_RELAY_QKEY".to_string(),
        role: circuit::HopRole::Relay,
        ..circuit::HopConfig::default()
    });
    let error = base.validate().expect_err("multi-hop advanced-required must fail");
    assert!(error.to_string().contains("advanced-required"), "{error}");
}
