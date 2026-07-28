#[cfg(test)]
mod runtime_reload_tests {
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
            &[
                quicfuscate::transport::PROTOCOL_VERSION_V2,
                quicfuscate::transport::PROTOCOL_VERSION
            ]
        );
    }

    #[test]
    fn load_runtime_profiles_bootstraps_auto_fec_in_zero_without_config_file() {
        let (fec, stealth, optimize, _) = load_runtime_profiles(None, &None, None);
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
        let pool = derive_client_pool_for_tun(
            Ipv4Addr::new(10, 0, 1, 254),
            Ipv4Addr::new(255, 255, 255, 0),
        )
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
cc_algorithm = "bbr3"
enable_pacing = false
"#,
        );

        let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
        let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
        let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
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
        assert_eq!(
            transport.cc_algorithm(),
            quicfuscate::transport::CongestionControlAlgorithm::BBR3
        );
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
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
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
        assert!(err.to_ascii_lowercase().contains("transport.mtu"));
        assert_eq!(transport.max_udp_payload_size(), before);
    }
}

#[cfg(unix)]
fn mlockall_flags_for_limit(current_limit: libc::rlim_t) -> libc::c_int {
    if current_limit == libc::RLIM_INFINITY {
        libc::MCL_CURRENT | libc::MCL_FUTURE
    } else {
        libc::MCL_CURRENT
    }
}

#[cfg(unix)]
fn current_memlock_limit() -> std::io::Result<libc::rlim_t> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: getrlimit initializes the pointed-to rlimit structure on success.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, limit.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a zero return from getrlimit guarantees the structure was initialized.
    Ok(unsafe { limit.assume_init() }.rlim_cur)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MemoryLockOutcome {
    flags: libc::c_int,
    current_limit: Option<libc::rlim_t>,
}

#[cfg(unix)]
fn lock_process_memory() -> std::io::Result<MemoryLockOutcome> {
    let current_limit = current_memlock_limit().ok();
    let flags = current_limit.map(mlockall_flags_for_limit).unwrap_or(libc::MCL_CURRENT);

    // SAFETY: flags contain only MCL_CURRENT and, when the process has an
    // unlimited memlock budget, MCL_FUTURE.
    if unsafe { libc::mlockall(flags) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(MemoryLockOutcome { flags, current_limit })
}

#[cfg(all(test, unix))]
mod memory_lock_tests {
    use super::*;

    #[test]
    fn finite_memlock_limit_never_enables_future_allocation_locking() {
        assert_eq!(mlockall_flags_for_limit(8 * 1024 * 1024), libc::MCL_CURRENT);
        assert_eq!(
            mlockall_flags_for_limit(libc::RLIM_INFINITY),
            libc::MCL_CURRENT | libc::MCL_FUTURE
        );
    }

    #[test]
    fn production_memory_lock_boundary_locks_pages_or_reports_supported_limit_error() {
        match lock_process_memory() {
            Ok(outcome) => {
                assert_ne!(outcome.flags & libc::MCL_CURRENT, 0);

                #[cfg(target_os = "linux")]
                {
                    let status = std::fs::read_to_string("/proc/self/status")
                        .expect("read current process status after mlockall");
                    let locked_kib = status
                        .lines()
                        .find_map(|line| line.strip_prefix("VmLck:"))
                        .and_then(|value| value.split_whitespace().next())
                        .and_then(|value| value.parse::<u64>().ok())
                        .expect("parse VmLck from /proc/self/status");
                    assert!(locked_kib > 0, "mlockall succeeded but VmLck stayed zero");
                }

                // SAFETY: this test owns the process-wide lock it just acquired.
                assert_eq!(unsafe { libc::munlockall() }, 0, "munlockall failed");
            }
            Err(error) => {
                let raw_error = error.raw_os_error();
                assert!(
                    matches!(raw_error, Some(code) if code == libc::EPERM || code == libc::ENOMEM || code == libc::EAGAIN || code == libc::ENOSYS),
                    "unexpected mlockall failure: {error}"
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: Option<quicfuscate::engine::FecMode>,
    pool_capacity: usize,
    pool_block: usize,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    disable_doh: bool,
    disable_fronting: bool,
    disable_http3: bool,
    cc_algorithm: CcAlgorithm,
    tun_enable: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
    tun_ip6: Option<String>,
    tun_prefix6: Option<u8>,
    admin_socket: Option<PathBuf>,
    metrics_port: Option<u16>,
    admin_web: Option<std::net::SocketAddr>,
    admin_web_root: PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    qkey_ttl_secs: Option<u64>,
    qkey_store: Option<PathBuf>,
    allow_client_to_client: bool,
    no_drop_privileges: bool,
    audit_log_path: Option<PathBuf>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    let config_path_ref = config_path.map(PathBuf::as_path);

    // Initialize the global audit log (TODO-515).
    quicfuscate::audit::init_audit_log(audit_log_path.clone());
    quicfuscate::audit::audit(
        quicfuscate::audit::AuditEventType::ServerStarted,
        quicfuscate::audit::AuditSeverity::Info,
        None,
        None,
        &format!("Server starting on {listen_addr}"),
    );

    let (fec_cfg, stealth_cfg, opt_cfg, anti_replay_section) =
        load_runtime_profiles(config_path, fec_config, fec_mode);

    // Parse the TOML config file once and reuse for telemetry, logging, and
    // memory-locking settings (TODO-515/516). CLI flags take precedence over
    // config-file values where applicable.
    let engine_cfg_opt = config_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|c| quicfuscate::engine::EngineConfig::from_toml(&c).ok());

    // Apply telemetry.enabled and logging.level from TOML config file when present.
    // CLI --telemetry flag (already applied above) takes precedence; config only adds enablement.
    if let Some(engine_cfg) = engine_cfg_opt.as_ref() {
        if engine_cfg.telemetry.enabled {
            use quicfuscate::telemetry::TELEMETRY_ENABLED;
            TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        }
        // Apply per-category telemetry export gates
        {
            use quicfuscate::telemetry::{
                COLLECT_CONGESTION_STATS, COLLECT_FEC_STATS, COLLECT_PACKET_STATS,
                COLLECT_STEALTH_STATS, COLLECT_STREAM_STATS,
            };
            COLLECT_PACKET_STATS
                .store(engine_cfg.telemetry.collect_packet_stats, Ordering::Relaxed);
            COLLECT_STREAM_STATS
                .store(engine_cfg.telemetry.collect_stream_stats, Ordering::Relaxed);
            COLLECT_CONGESTION_STATS
                .store(engine_cfg.telemetry.collect_congestion_stats, Ordering::Relaxed);
            COLLECT_FEC_STATS.store(engine_cfg.telemetry.collect_fec_stats, Ordering::Relaxed);
            COLLECT_STEALTH_STATS
                .store(engine_cfg.telemetry.collect_stealth_stats, Ordering::Relaxed);
        }
        // Apply logging config: effective() applies mode overrides (Verbose/Minimal/NoLog),
        // then engine.log_level overrides the result when explicitly different.
        let effective_logging = engine_cfg.logging.effective();
        let effective_level = if engine_cfg.engine.log_level != "info"
            && engine_cfg.engine.log_level != effective_logging.level
        {
            engine_cfg.engine.log_level.clone()
        } else {
            effective_logging.level.clone()
        };
        let level_filter = match effective_level.to_ascii_lowercase().as_str() {
            "error" => Some(log::LevelFilter::Error),
            "warn" => Some(log::LevelFilter::Warn),
            "info" => Some(log::LevelFilter::Info),
            "debug" => Some(log::LevelFilter::Debug),
            "trace" => Some(log::LevelFilter::Trace),
            _ => None,
        };
        if let Some(filter) = level_filter {
            log::set_max_level(filter);
        }
        // Apply log_to_stdout: when mode=no-log disables stdout, suppress output
        if !effective_logging.log_to_stdout {
            log::set_max_level(log::LevelFilter::Off);
        }
    }

    // Apply memory-locking settings from SecurityConfig (TODO-516).
    // mlockall must be called before any key material is loaded so that
    // MCL_FUTURE locks all future allocations. MemoryPool::set_lock_blocks
    // must be called before the pool is created so blocks are mlocked on alloc.
    let (lock_memory, lock_blocks) = engine_cfg_opt
        .as_ref()
        .map(|cfg| (cfg.security.lock_memory, cfg.security.lock_blocks))
        .unwrap_or((true, true)); // defaults: lock on server
    if lock_memory {
        #[cfg(unix)]
        {
            match lock_process_memory() {
                Ok(outcome) => {
                    match outcome.current_limit {
                        Some(limit) if outcome.flags == libc::MCL_CURRENT => {
                            log::warn!(
                                "RLIMIT_MEMLOCK is finite ({} bytes); locking current pages only to avoid future allocation failures. Set LimitMEMLOCK=infinity for full process locking.",
                                limit
                            );
                        }
                        None => {
                            log::warn!(
                                "RLIMIT_MEMLOCK query failed. Locked current pages only to avoid future allocation failures."
                            );
                        }
                        _ => {}
                    }
                    info!("Process memory locked against swap (mlockall flags={})", outcome.flags);
                }
                Err(error) => {
                    log::warn!(
                        "mlockall failed: {}. Process memory may be swapped to disk. \
                         Set LimitMEMLOCK=infinity in systemd or run with CAP_IPC_LOCK.",
                        error
                    );
                }
            }
        }
        #[cfg(not(unix))]
        {
            log::debug!("mlockall not supported on this platform; lock_memory ignored");
        }
    }
    quicfuscate::optimize::MemoryPool::set_lock_blocks(lock_blocks);

    let mut config = match new_runtime_transport_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create server transport config: {}", e);
            return Err(std::io::Error::other("server transport config init failed"));
        }
    };
    apply_runtime_transport_defaults(&mut config, cc_algorithm);
    quicfuscate::implementations::server::load_server_identity(&mut config, cert_path, key_path)?;

    if let Some(cfg_path) = config_path.as_ref() {
        quicfuscate::implementations::server::apply_transport_overrides_from_file(
            cfg_path,
            &mut config,
        );
    }

    let mut server_config =
        quicfuscate::implementations::server::server_config_from_listen_addr(listen_addr)
            .map_err(std::io::Error::other)?;
    server_config.allow_client_to_client = allow_client_to_client;
    if tun_enable {
        apply_standalone_tun_server_config(
            &mut server_config,
            tun_ip.as_deref(),
            tun_netmask.as_deref(),
            tun_ip6.as_deref(),
            tun_prefix6,
        )?;
    }
    let opt_params = runtime_optimize_config(
        config_path,
        opt_cfg,
        pool_capacity,
        pool_block,
        "server runtime config",
    );
    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, seq, false)
        }
        None => {
            quicfuscate::implementations::server::resolve_runtime_profiles(profile, os, &[], true)
        }
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    let standalone_tun_config = if tun_enable {
        Some(quicfuscate::interface::TunConfig {
            name: tun_name,
            ip: tun_ip.and_then(|s| s.parse().ok()),
            netmask: tun_netmask.and_then(|s| s.parse().ok()),
            mtu: tun_mtu.unwrap_or(1500),
            ip6: server_config.ipv6_server_ip,
            prefix6: Some(server_config.ipv6_prefix_len),
            ..Default::default()
        })
    } else {
        None
    };
    let runtime_engine_config = engine_cfg_opt.unwrap_or_default();
    let mut runtime = ServerRuntime::new_initialized_standalone_default(
        runtime_engine_config,
        server_config,
        standalone_tun_config,
        opt_params,
        config_path_ref,
        ADMIN_LOG_BUFFER.get().cloned(),
        qkey_ttl_secs,
        qkey_store,
    )?;
    let fec_mode_override = fec_mode;
    let mut launch =
        quicfuscate::implementations::server::PreparedStandaloneLaunch::new_with_runtime_stealth(
            metrics_port,
            admin_socket,
            admin_web,
            admin_web_root,
            admin_web_user,
            admin_web_password,
            config_path.cloned(),
            config,
            fec_cfg,
            opt_params,
            stealth_cfg,
            fec_mode_override,
            profiles,
            profile_interval,
            quicfuscate::implementations::server::RuntimeStealthPolicy {
                profile,
                os,
                disable_doh,
                doh_provider,
                disable_fronting,
                front_domain,
                disable_http3,
            },
            tun_enable,
        );
    launch.set_anti_replay_section(anti_replay_section);
    let local_addr = runtime.local_addr();
    info!("Server listening on {}", local_addr);

    // Drop root privileges after all privileged setup (socket bind, TUN,
    // routing, iptables) is complete. File descriptors survive the UID/GID
    // change, so the server can continue operating unprivileged.
    if !no_drop_privileges {
        let cap_report = quicfuscate::privilege::check_capabilities();
        if cap_report.is_root {
            if tun_enable {
                runtime.stop().map_err(std::io::Error::other)?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to drop root after TUN routing setup because shutdown could not remove owned firewall rules; run as the quicfuscate systemd user with AmbientCapabilities or use --no-drop-privileges only in an isolated test environment",
                ));
            }
            info!("Dropping root privileges to quicfuscate:quicfuscate");
            match quicfuscate::privilege::drop_privileges("quicfuscate", "quicfuscate") {
                Ok(()) => {
                    info!("Privileges dropped - running as unprivileged user");
                    quicfuscate::audit::audit(
                        quicfuscate::audit::AuditEventType::PrivilegesDropped,
                        quicfuscate::audit::AuditSeverity::Info,
                        None,
                        None,
                        "Root privileges dropped to quicfuscate:quicfuscate",
                    );
                }
                Err(e) => {
                    error!("Failed to drop privileges: {} - refusing to continue as root", e);
                    quicfuscate::audit::audit(
                        quicfuscate::audit::AuditEventType::PrivilegeDropFailed,
                        quicfuscate::audit::AuditSeverity::Critical,
                        None,
                        None,
                        &format!("Privilege drop failed: {e}"),
                    );
                    return Err(std::io::Error::other("privilege drop failed"));
                }
            }
        }
    }

    runtime.run_standalone(launch).await?;

    Ok(())
}
