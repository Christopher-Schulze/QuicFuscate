use super::runtime::{
    apply_standalone_tun_server_config, classify_client_tun_packet, client_packet_too_big_response,
    client_startup_error_with_cleanup, client_tun_activation_ready, derive_client_pool_for_tun,
    heartbeat_probe_interval, initial_client_packet_constructed, initial_client_packet_sent,
    load_client_ca_file, load_runtime_profiles, new_runtime_transport_config,
    record_standalone_client_tun_fault, resolve_client_target, runtime_optimize_config,
    spawn_client_tun_reader, ClientTargetSource, ClientTunPacketDisposition,
    InitialClientPacketEvidence,
};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 1, 2]);
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    packet
}

fn ipv6_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    packet
}

#[test]
fn heartbeat_probe_runs_three_times_inside_the_watchdog_window() {
    assert_eq!(heartbeat_probe_interval(0), None);
    assert_eq!(heartbeat_probe_interval(30_000), Some(Duration::from_secs(10)));
    assert_eq!(heartbeat_probe_interval(2), Some(Duration::from_millis(1)));
}

#[test]
fn initial_client_packet_construction_failure_is_propagated() {
    let error = initial_client_packet_constructed(Err(ConnectionError::Transport(
        "crypto state unavailable".to_string(),
    )))
    .expect_err("initial packet construction failure must stop startup");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert!(error.to_string().contains("initial client packet construction failed"));
    assert!(error.to_string().contains("crypto state unavailable"));
}

#[test]
fn initial_client_packet_without_datagram_is_rejected() {
    let error = initial_client_packet_constructed(Ok(0))
        .expect_err("startup must not continue without an initial datagram");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("produced no datagram"));
}

#[test]
fn initial_client_socket_send_failure_is_propagated() {
    let error = initial_client_packet_sent(
        1200,
        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket closed")),
    )
    .expect_err("initial socket send failure must stop startup");

    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    assert!(error.to_string().contains("initial client handshake datagram send failed"));
    assert!(error.to_string().contains("socket closed"));
}

#[test]
fn initial_client_packet_evidence_separates_construction_and_socket_send() {
    let evidence = initial_client_packet_sent(1200, Ok(()))
        .expect("successful socket send must produce complete initial evidence");

    assert_eq!(evidence, InitialClientPacketEvidence { constructed_bytes: 1200, sent_bytes: 1200 });
}

#[test]
fn client_startup_cleanup_preserves_primary_tun_failure() {
    let primary = std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "client TUN open failed: unsupported backend",
    );
    let combined = client_startup_error_with_cleanup(
        primary,
        vec!["kill switch fail-closed cleanup failed: permission denied".to_string()],
    );

    assert_eq!(combined.kind(), std::io::ErrorKind::Unsupported);
    assert!(combined.to_string().contains("client TUN open failed"));
    assert!(combined.to_string().contains("kill switch fail-closed cleanup failed"));
}

#[test]
fn client_tun_reader_spawn_failure_is_propagated() {
    let error = spawn_client_tun_reader(
        |_| Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "reader limit")),
        || {},
    )
    .expect_err("reader spawn failure must not disable TUN silently");

    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert!(error.to_string().contains("client TUN reader spawn failed"));
    assert!(error.to_string().contains("reader limit"));
}

#[test]
fn client_tun_reader_spawn_success_joins_owned_reader() {
    let ran = Arc::new(AtomicBool::new(false));
    let ran_in_reader = Arc::clone(&ran);
    let reader = spawn_client_tun_reader(
        |reader| {
            std::thread::Builder::new().name("test-client-tun-reader".to_string()).spawn(reader)
        },
        move || ran_in_reader.store(true, Ordering::Release),
    )
    .expect("valid reader spawn must return an owned handle");

    reader.join().expect("reader thread must join");
    assert!(ran.load(Ordering::Acquire));
}

#[test]
fn client_tun_readiness_requires_every_owned_resource() {
    assert!(client_tun_activation_ready(false, false, false, false, false));
    assert!(client_tun_activation_ready(true, true, true, true, true));
    assert!(!client_tun_activation_ready(true, false, true, true, true));
    assert!(!client_tun_activation_ready(true, true, false, true, true));
    assert!(!client_tun_activation_ready(true, true, true, false, true));
    assert!(!client_tun_activation_ready(true, true, true, true, false));
}

#[test]
fn standalone_client_tun_fault_is_first_wins_and_shutdown_safe() {
    let fault_slot = Arc::new(parking_lot::Mutex::new(None));
    let notify = Arc::new(tokio::sync::Notify::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let first = quicfuscate::engine::DataPlaneFault::ReaderStopped {
        component: "standalone client TUN reader".to_string(),
        error: "device closed".to_string(),
    };
    let second = quicfuscate::engine::DataPlaneFault::ChannelDisconnected {
        component: "standalone client TUN reader channel".to_string(),
    };

    record_standalone_client_tun_fault(&fault_slot, &notify, &shutdown, first.clone());
    record_standalone_client_tun_fault(&fault_slot, &notify, &shutdown, second);
    assert_eq!(fault_slot.lock().as_ref(), Some(&first));

    shutdown.store(true, Ordering::Release);
    record_standalone_client_tun_fault(
        &fault_slot,
        &notify,
        &shutdown,
        quicfuscate::engine::DataPlaneFault::TunWrite {
            component: "standalone client HTTP/3 downlink".to_string(),
            error: "device closed".to_string(),
        },
    );
    assert_eq!(fault_slot.lock().as_ref(), Some(&first));
}

#[test]
fn client_tun_open_rejects_invalid_activation_configuration() {
    let error = quicfuscate::interface::TunInterface::open(
        quicfuscate::interface::TunConfig { mtu: 575, ..Default::default() },
        quicfuscate::optimize::global_pool(),
    )
    .expect_err("invalid TUN configuration must fail before backend activation");

    assert!(matches!(error, quicfuscate::interface::TunError::Config(_)));
}

#[test]
fn client_target_defaults_when_url_is_omitted() {
    let target = resolve_client_target(None, "127.0.0.1:4433").expect("default client target");

    assert_eq!(target.source, ClientTargetSource::Default);
    assert_eq!(target.host, "cloudflare-dns.com");
    assert_eq!(target.authority, "cloudflare-dns.com");
    assert_eq!(target.port, 443);
    assert_eq!(target.request_path, "/");
    assert_eq!(target.transport_destination, "127.0.0.1:4433".parse().unwrap());
    assert_eq!(target.alternate_transport_ip, None);
}

#[test]
fn client_target_accepts_https_host_and_normalizes_empty_path() {
    let target = resolve_client_target(Some("https://example.com"), "127.0.0.1:4433")
        .expect("explicit HTTPS host should be valid");

    assert_eq!(target.source, ClientTargetSource::Explicit);
    assert_eq!(target.host, "example.com");
    assert_eq!(target.authority, "example.com");
    assert_eq!(target.port, 443);
    assert_eq!(target.request_path, "/");
}

#[test]
fn client_target_preserves_ipv4_query_and_explicit_port() {
    let target =
        resolve_client_target(Some("https://192.0.2.10:8443/status?probe=1"), "127.0.0.1:4433")
            .expect("IPv4 target should be valid");

    assert_eq!(target.host, "192.0.2.10");
    assert_eq!(target.authority, "192.0.2.10:8443");
    assert_eq!(target.port, 8443);
    assert_eq!(target.request_path, "/status?probe=1");
}

#[test]
fn client_target_brackets_ipv6_authority_without_bracketing_sni_host() {
    let target =
        resolve_client_target(Some("https://[2001:db8::1]:8443/health"), "[2001:db8::1]:4433")
            .expect("IPv6 target should be valid");

    assert_eq!(target.host, "2001:db8::1");
    assert_eq!(target.authority, "[2001:db8::1]:8443");
    assert_eq!(target.port, 8443);
    assert_eq!(target.request_path, "/health");
    assert_eq!(target.transport_destination, "[2001:db8::1]:4433".parse().unwrap());
    assert_eq!(target.alternate_transport_ip, None);
}

fn assert_invalid_client_target(raw_url: &str) {
    let error = resolve_client_target(Some(raw_url), "127.0.0.1:4433")
        .expect_err("target must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().starts_with("invalid client URL:"));
}

#[test]
fn invalid_client_target_fails_before_remote_resolution() {
    let error = resolve_client_target(Some("http://example.com/health"), "not-an-address")
        .expect_err("invalid URL must fail before remote resolution");

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("unsupported scheme"));
}

#[test]
fn client_target_rejects_invalid_host_scheme_authority_credentials_and_fragment() {
    for raw_url in [
        "https://[broken",
        "https:/health",
        "https:///health",
        "https://",
        "http://example.com/health",
        "https://:443/health",
        "https://user:password@example.com/health",
        "https://example.com/health#fragment",
    ] {
        assert_invalid_client_target(raw_url);
    }
}

#[test]
fn client_ipv4_packet_too_big_response_advertises_tunnel_mtu() {
    let response = client_packet_too_big_response(&ipv4_packet(1400), 1280);

    assert_eq!(response[20], 3);
    assert_eq!(response[21], 4);
    assert_eq!(u16::from_be_bytes([response[26], response[27]]), 1280);
    assert_eq!(&response[16..20], &[10, 0, 1, 2]);
}

#[test]
fn client_ipv6_packet_too_big_response_advertises_tunnel_mtu() {
    let response = client_packet_too_big_response(&ipv6_packet(1400), 1280);

    assert_eq!(response[40], 2);
    assert_eq!(u32::from_be_bytes(response[44..48].try_into().unwrap()), 1280);
    assert_eq!(&response[24..40], &"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
}

#[test]
fn client_uplink_uses_carrier_mtu_after_live_tun_mtu_override() {
    let configured_tun_mtu = 1280;
    let carrier_mtu = 1372;
    let probe_len = 1328;

    assert!(probe_len > configured_tun_mtu);
    assert_eq!(
        classify_client_tun_packet(probe_len, carrier_mtu),
        ClientTunPacketDisposition::Tunnel
    );
    assert_eq!(
        classify_client_tun_packet(carrier_mtu + 1, carrier_mtu),
        ClientTunPacketDisposition::RespondPacketTooBig { mtu: carrier_mtu }
    );
}

#[test]
fn normalize_runtime_optimize_config_preserves_runtime_values() {
    let normalized = quicfuscate::implementations::server::normalize_runtime_optimize_config(
        OptimizeConfig { pool_capacity: 64, block_size: 65_536 },
        "test",
    );
    assert_eq!(normalized.pool_capacity, 64);
    assert_eq!(normalized.block_size, 65_536);
}

#[test]
fn runtime_transport_defaults_prefer_v2_with_v1_fallback() {
    let transport = new_runtime_transport_config().expect("runtime transport config");

    assert_eq!(transport.version(), quicfuscate::transport::PROTOCOL_VERSION_V2);
    assert_eq!(
        transport.supported_versions(),
        &[quicfuscate::transport::PROTOCOL_VERSION_V2, quicfuscate::transport::PROTOCOL_VERSION]
    );
}

#[test]
fn load_runtime_profiles_bootstraps_auto_fec_in_zero_without_config_file() {
    let (fec, stealth, optimize, _) =
        load_runtime_profiles(None, &None, None).expect("default runtime profiles");
    let default_stealth = StealthConfig::default();
    let default_optimize = OptimizeConfig::default();
    assert_eq!(fec.initial_mode, quicfuscate::fec::FecMode::Zero);
    assert_eq!(stealth.initial_browser, default_stealth.initial_browser);
    assert_eq!(stealth.initial_os, default_stealth.initial_os);
    assert_eq!(stealth.enable_http3_masquerading, default_stealth.enable_http3_masquerading);
    assert_eq!(optimize.pool_capacity, default_optimize.pool_capacity);
    assert_eq!(optimize.block_size, default_optimize.block_size);
}

#[test]
fn load_client_ca_file_fails_closed_for_missing_and_malformed_input() {
    let missing = std::env::temp_dir().join(format!(
        "qf-missing-client-ca-{}-{}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    let mut config =
        quicfuscate::transport::Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION)
            .expect("transport config");
    let missing_error =
        load_client_ca_file(&mut config, &missing).expect_err("missing CA file must fail closed");
    assert!(missing_error.to_string().contains("failed to load CA file"));
    assert!(missing_error.to_string().contains(missing.to_string_lossy().as_ref()));

    let malformed = write_temp_config("not a certificate");
    let malformed_path = malformed.to_string_lossy().into_owned();
    let malformed_error = load_client_ca_file(&mut config, &malformed)
        .expect_err("malformed CA file must fail closed");
    assert!(malformed_error.to_string().contains("failed to load CA file"));
    assert!(malformed_error.to_string().contains(&malformed_path));
    assert!(!malformed_error.to_string().contains("not a certificate"));
}

#[test]
fn load_runtime_profiles_rejects_missing_explicit_fec_file() {
    let path = std::env::temp_dir().join(format!(
        "qf-missing-fec-config-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    let fec_config = Some(path.clone());
    let error = load_runtime_profiles(None, &fec_config, None)
        .err()
        .expect("missing explicit FEC file must fail closed");
    assert!(error.to_string().contains("explicit FEC configuration"));
    assert!(error.to_string().contains(path.to_string_lossy().as_ref()));
}

#[test]
fn load_runtime_profiles_rejects_malformed_and_invalid_explicit_fec_files() {
    let malformed = write_temp_config("[adaptive_fec\ninitial_mode = \"auto\"");
    let malformed_error = load_runtime_profiles(None, &Some(malformed.clone()), None)
        .err()
        .expect("malformed explicit FEC file must fail closed");
    assert!(malformed_error.to_string().contains("explicit FEC configuration"));
    assert!(malformed_error.to_string().contains("server.toml"));

    let invalid = write_temp_config(
        r#"
[adaptive_fec]
initial_mode = "normal"

[[adaptive_fec.modes]]
name = "normal"
w0 = 0
"#,
    );
    let invalid_error = load_runtime_profiles(None, &Some(invalid), None)
        .err()
        .expect("invalid explicit FEC file must fail closed");
    assert!(invalid_error.to_string().contains("window_sizes.Normal"));
}

#[test]
fn load_runtime_profiles_accepts_valid_custom_fec_file_without_defaulting() {
    let path = write_temp_config(
        r#"
[adaptive_fec]
control_policy = "auto"
initial_mode = "strong"
lambda = 0.25
burst_window = 32
hysteresis = 0.05
stream_every = 3

[[adaptive_fec.modes]]
name = "normal"
w0 = 80
"#,
    );
    let fec_config = Some(path);
    let (fec, _, _, _) =
        load_runtime_profiles(None, &fec_config, None).expect("valid explicit FEC file");
    assert_eq!(fec.initial_mode, quicfuscate::fec::FecMode::Strong);
    assert_eq!(fec.window_sizes.get(&quicfuscate::fec::FecMode::Normal), Some(&80));
    assert_eq!(fec.configured_stream_every, Some(3));
}

#[test]
fn load_runtime_profiles_rejects_ambiguous_unified_and_standalone_fec_sources() {
    let unified = write_temp_config("");
    let standalone = Some(unified.clone());
    let error = load_runtime_profiles(Some(&unified), &standalone, None)
        .err()
        .expect("two FEC sources must not silently discard one");
    assert!(error.to_string().contains("mutually exclusive"));
}

#[test]
fn runtime_optimize_config_uses_cli_values_without_config_file() {
    let resolved = runtime_optimize_config(
        None,
        OptimizeConfig { pool_capacity: 1, block_size: 2 },
        96,
        32_768,
        "test",
    );
    assert_eq!(resolved.pool_capacity, 96);
    assert_eq!(resolved.block_size, 32_768);
}

#[test]
fn derive_client_pool_for_tun_uses_hosts_after_server_ip_when_possible() {
    let pool =
        derive_client_pool_for_tun(Ipv4Addr::new(10, 0, 1, 1), Ipv4Addr::new(255, 255, 255, 0))
            .expect("pool");
    assert_eq!(pool.0, Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(pool.1, Ipv4Addr::new(10, 0, 1, 254));
}

#[test]
fn derive_client_pool_for_tun_uses_hosts_before_server_ip_at_subnet_end() {
    let pool =
        derive_client_pool_for_tun(Ipv4Addr::new(10, 0, 1, 254), Ipv4Addr::new(255, 255, 255, 0))
            .expect("pool");
    assert_eq!(pool.0, Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(pool.1, Ipv4Addr::new(10, 0, 1, 253));
}

#[test]
fn apply_standalone_tun_server_config_aligns_server_ip_and_pool() {
    let mut config = quicfuscate::implementations::server::ServerConfig::default();
    apply_standalone_tun_server_config(
        &mut config,
        Some("10.0.1.1"),
        Some("255.255.255.0"),
        None,
        None,
    )
    .expect("apply tun config");
    assert_eq!(config.server_ip, Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(config.server_netmask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(config.ip_pool_start, Ipv4Addr::new(10, 0, 1, 2));
    assert_eq!(config.ip_pool_end, Ipv4Addr::new(10, 0, 1, 254));
}

#[test]
fn apply_standalone_tun_server_config_aligns_ipv6_server_and_dense_pool() {
    let mut config = quicfuscate::implementations::server::ServerConfig::default();
    apply_standalone_tun_server_config(&mut config, None, None, Some("fd42:53::1"), Some(64))
        .expect("apply IPv6 TUN config");

    assert_eq!(config.ipv6_server_ip, Some("fd42:53::1".parse().unwrap()));
    assert_eq!(config.ipv6_prefix_len, 64);
    assert_eq!(config.ipv6_pool_start, Some("fd42:53::2".parse().unwrap()));
    assert_eq!(config.ipv6_pool_end, Some("fd42:53::fe".parse().unwrap()));
}

#[test]
fn malformed_tun_addresses_are_rejected_and_name_their_flag() {
    // These used to be reparsed at TUN construction with `parse().ok()`, which turned
    // a typo into an absent field. One validated parse means a bad value can only
    // stop startup, never quietly change the interface contract.
    for (label, ip, netmask, ip6, prefix6) in [
        ("--tun-ip", Some("10.0.1.256"), None, None, None),
        ("--tun-netmask", Some("10.0.1.1"), Some("not-a-mask"), None, None),
        ("--tun-ip6", None, None, Some("fd42::zz"), None),
    ] {
        let mut config = quicfuscate::implementations::server::ServerConfig::default();
        let error = apply_standalone_tun_server_config(&mut config, ip, netmask, ip6, prefix6)
            .expect_err("a malformed address must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains(label), "the failure must name {label}, got {error}");
        let untouched = quicfuscate::implementations::server::ServerConfig::default();
        assert_eq!(config.server_ip, untouched.server_ip, "{label} must change nothing");
        assert_eq!(config.ipv6_server_ip, untouched.ipv6_server_ip);
    }
}

#[test]
fn a_netmask_without_an_address_is_rejected_rather_than_half_applied() {
    // The IPv4 branch only runs when an address is supplied, so a lone netmask never
    // reached the server configuration while the old TUN construction still parsed
    // and used it. The two would then describe different interfaces.
    let mut config = quicfuscate::implementations::server::ServerConfig::default();
    let error =
        apply_standalone_tun_server_config(&mut config, None, Some("255.255.255.0"), None, None)
            .expect_err("a lone netmask must be rejected");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("--tun-netmask requires --tun-ip"));
    assert_eq!(
        config.server_netmask,
        quicfuscate::implementations::server::ServerConfig::default().server_netmask
    );
}

#[test]
fn valid_dual_stack_and_omitted_values_keep_their_current_meaning() {
    let mut config = quicfuscate::implementations::server::ServerConfig::default();
    apply_standalone_tun_server_config(
        &mut config,
        Some("10.9.0.1"),
        Some("255.255.255.0"),
        Some("fd42:99::1"),
        Some(64),
    )
    .expect("a valid dual-stack set applies");
    assert_eq!(config.server_ip, Ipv4Addr::new(10, 9, 0, 1));
    assert_eq!(config.server_netmask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(config.ipv6_server_ip, Some("fd42:99::1".parse().unwrap()));
    assert_eq!(config.ipv6_prefix_len, 64);

    // Omitting everything must leave the defaults exactly as they were.
    let mut untouched = quicfuscate::implementations::server::ServerConfig::default();
    let defaults = quicfuscate::implementations::server::ServerConfig::default();
    apply_standalone_tun_server_config(&mut untouched, None, None, None, None)
        .expect("omitted values are the default path");
    assert_eq!(untouched.server_ip, defaults.server_ip);
    assert_eq!(untouched.server_netmask, defaults.server_netmask);
    assert_eq!(untouched.ipv6_server_ip, defaults.ipv6_server_ip);
}

fn write_temp_config(contents: &str) -> std::path::PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "qf-reload-test-{}-{}-{}",
        std::process::id(),
        id,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_millis()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("server.toml");
    std::fs::write(&path, contents).expect("write config");
    path
}

#[test]
fn runtime_config_reload_updates_shared_state_and_transport_overrides() {
    let cfg_path = write_temp_config(
        r#"
[fec]
mode = "auto"
initial_mode = "auto"
window_good = 10
window_fair = 30
window_poor = 50

[stealth]
mode = "max"
enable_doh = true
doh_provider = "https://example.invalid/dns-query"
enable_domain_fronting = true
enable_http3_masquerading = true

[optimization]
memory_pool_size = 7274496

[transport]
mtu = 1400
pmtu_max_mtu = 1400
cc_algorithm = "bbr3"
enable_pacing = false
"#,
    );

    let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
    let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
    let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
    let mut transport =
        quicfuscate::transport::Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION)
            .expect("transport config");

    // Keep runtime overrides strict to prove merge behavior.
    let front_domains = vec!["front.example".to_string()];
    quicfuscate::implementations::server::apply_runtime_config_reload(
        &cfg_path,
        Some(quicfuscate::engine::FecMode::Auto), // CLI override should win over config's initial mode
        &mut transport,
        &fec_shared,
        &opt_shared,
        &stealth_shared,
        quicfuscate::implementations::server::RuntimeStealthPolicy {
            profile: BrowserProfile::Chrome,
            os: OsProfile::MacOS,
            disable_doh: true, // disable DoH
            doh_provider: "runtime-doh",
            disable_fronting: true, // disable fronting
            front_domain: &front_domains,
            disable_http3: true, // disable http3 masquerade
        },
    )
    .expect("reload ok");

    let fec = fec_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(fec.initial_mode, quicfuscate::fec::FecMode::Zero);

    let opt = *opt_shared.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(opt.pool_capacity, 111);
    assert_eq!(opt.block_size, 65_536);

    let sc = stealth_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(sc.initial_browser, BrowserProfile::Chrome);
    assert_eq!(sc.initial_os, OsProfile::MacOS);
    assert!(!sc.enable_doh);
    assert_eq!(sc.doh_provider, "runtime-doh");
    assert!(!sc.enable_domain_fronting);
    assert_eq!(sc.fronting_domains, front_domains);
    assert!(!sc.enable_http3_masquerading);

    assert_eq!(transport.max_udp_payload_size(), 1400);
    assert_eq!(transport.cc_algorithm(), quicfuscate::transport::CongestionControlAlgorithm::BBR3);
    assert!(!transport.pacing_enabled());
}

#[test]
fn runtime_config_reload_rejects_invalid_transport_section() {
    let cfg_path = write_temp_config(
        r#"
[fec]
mode = "auto"
initial_mode = "auto"

[stealth]
mode = "auto"

[optimization]
memory_pool_size = 655360

[transport]
mtu = 100
"#,
    );

    let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
    let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
    let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
    let mut transport =
        quicfuscate::transport::Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION)
            .expect("transport config");
    let before = transport.max_udp_payload_size();

    let err = quicfuscate::implementations::server::apply_runtime_config_reload(
        &cfg_path,
        Some(quicfuscate::engine::FecMode::Off),
        &mut transport,
        &fec_shared,
        &opt_shared,
        &stealth_shared,
        quicfuscate::implementations::server::RuntimeStealthPolicy {
            profile: BrowserProfile::Chrome,
            os: OsProfile::MacOS,
            disable_doh: false,
            doh_provider: "runtime-doh",
            disable_fronting: false,
            front_domain: &[],
            disable_http3: false,
        },
    )
    .unwrap_err();
    assert!(err.to_ascii_lowercase().contains("transport.mtu must be at least 1200"));
    assert_eq!(transport.max_udp_payload_size(), before);
}

#[test]
fn a_rejected_reload_leaves_every_domain_on_the_prior_generation() {
    // Nothing may be published unless every domain succeeds. Today's rejection
    // still comes from the pre-validators, so this guards the publication contract
    // rather than the ordering itself; the ordering is proven at the helper
    // boundary, where a setter rejection is actually reachable.
    let cfg_path = write_temp_config(
        r#"
[fec]
mode = "auto"
initial_mode = "zero"

[stealth]
mode = "auto"
initial_browser = "firefox"

[optimization]
memory_pool_size = 655360

[transport]
mtu = 100
"#,
    );

    let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
    let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
    let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
    let fec_before = fec_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let opt_before = *opt_shared.lock().unwrap_or_else(|e| e.into_inner());
    let stealth_before = stealth_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut transport =
        quicfuscate::transport::Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION)
            .expect("transport config");

    quicfuscate::implementations::server::apply_runtime_config_reload(
        &cfg_path,
        None,
        &mut transport,
        &fec_shared,
        &opt_shared,
        &stealth_shared,
        quicfuscate::implementations::server::RuntimeStealthPolicy {
            profile: BrowserProfile::Chrome,
            os: OsProfile::MacOS,
            disable_doh: false,
            doh_provider: "runtime-doh",
            disable_fronting: false,
            front_domain: &[],
            disable_http3: false,
        },
    )
    .expect_err("a rejected reload must not publish anything");

    assert_eq!(
        fec_shared.lock().unwrap_or_else(|e| e.into_inner()).initial_mode,
        fec_before.initial_mode,
        "FEC must stay on the prior generation"
    );
    let opt_after = *opt_shared.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        (opt_after.pool_capacity, opt_after.block_size),
        (opt_before.pool_capacity, opt_before.block_size),
        "optimization must stay on the prior generation"
    );
    assert_eq!(
        stealth_shared.lock().unwrap_or_else(|e| e.into_inner()).initial_browser,
        stealth_before.initial_browser,
        "stealth must stay on the prior generation"
    );
}

#[test]
fn a_present_but_invalid_transport_override_file_fails_closed_at_startup() {
    // Startup used to log this and continue, so the process ran with transport
    // defaults while the operator's file said otherwise and startup reported
    // success. Absence is the only acceptable reason to keep the defaults.
    let cfg_path = write_temp_config(
        r#"
[transport]
quic_versions = ["not-a-quic-version"]
"#,
    );
    let mut transport =
        quicfuscate::transport::Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION)
            .expect("transport config");

    let err = quicfuscate::implementations::server::apply_transport_overrides_from_file(
        &cfg_path,
        &mut transport,
    )
    .expect_err("an invalid override file must not be downgraded to defaults");
    assert!(
        err.contains(&cfg_path.display().to_string()),
        "the failure must name the file, got {err}"
    );

    let missing = cfg_path.with_extension("absent");
    quicfuscate::implementations::server::apply_transport_overrides_from_file(
        &missing,
        &mut transport,
    )
    .expect("a missing override file keeps the configured defaults");
}
