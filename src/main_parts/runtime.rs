#[cfg(target_os = "windows")]
const WINDOWS_APPLICATION_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(target_os = "windows")]
fn main() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("quicfuscate-main".to_string())
        .stack_size(WINDOWS_APPLICATION_STACK_BYTES)
        .spawn(application_main)?
        .join()
        .map_err(|_| std::io::Error::other("QuicFuscate application thread panicked"))?
}

#[cfg(not(target_os = "windows"))]
fn main() -> std::io::Result<()> {
    application_main()
}

fn application_main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--verbose" || a == "-v") {
        std::env::set_var("RUST_LOG", "info");
    }
    let cli = Cli::parse();
    if let Commands::Capabilities { json, user, group, tun, listen_port } = &cli.command {
        return run_capabilities_report(*json, user, group, *tun, *listen_port);
    }
    let startup_engine_config = load_startup_engine_config(&cli)?;
    let worker_threads = startup_engine_config
        .as_ref()
        .map(|config| config.optimization.num_worker_threads)
        .filter(|threads| *threads > 0)
        .unwrap_or(8);
    let harden_server_runtime =
        matches!(&cli.command, Commands::Server { no_drop_privileges: false, .. });
    #[cfg(target_os = "linux")]
    if harden_server_runtime {
        quicfuscate::privilege::enable_no_new_privileges()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }
    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.worker_threads(worker_threads).enable_all();
    #[cfg(target_os = "linux")]
    if harden_server_runtime {
        runtime_builder.on_thread_start(|| {
            if let Err(error) = quicfuscate::privilege::harden_runtime_worker_thread() {
                eprintln!("fatal: Tokio worker privilege hardening failed: {error}");
                std::process::abort();
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    let _ = harden_server_runtime;
    let runtime = runtime_builder.build()?;
    runtime.block_on(async_main(cli, startup_engine_config))
}

fn command_config_path(cli: &Cli) -> Option<&Path> {
    match &cli.command {
        Commands::Client { shared, .. } | Commands::Server { shared, .. } => {
            shared.config.as_deref()
        }
        _ => None,
    }
}

fn load_startup_engine_config(
    cli: &Cli,
) -> std::io::Result<Option<quicfuscate::engine::EngineConfig>> {
    let Some(path) = command_config_path(cli) else {
        return Ok(None);
    };
    let config = quicfuscate::engine::EngineConfig::from_file(path).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid configuration {}: {error}", path.display()),
        )
    })?;
    config.validate().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid configuration {}: {error}", path.display()),
        )
    })?;
    Ok(Some(config))
}

async fn async_main(
    cli: Cli,
    startup_engine_config: Option<quicfuscate::engine::EngineConfig>,
) -> std::io::Result<()> {
    let mut logging_config = startup_engine_config
        .as_ref()
        .map(|config| config.logging.effective())
        .unwrap_or_default();
    if let Some(engine_config) = startup_engine_config.as_ref() {
        if engine_config.logging.mode != quicfuscate::engine::LoggingMode::NoLog
            && engine_config.engine.log_level != "info"
        {
            logging_config.level.clone_from(&engine_config.engine.log_level);
        }
    }
    if cli.verbose
        && startup_engine_config
            .as_ref()
            .is_none_or(|config| config.logging.mode != quicfuscate::engine::LoggingMode::NoLog)
    {
        logging_config.level = "debug".to_string();
    }
    let admin_log_buffer = Arc::new(
        quicfuscate::implementations::server::admin_logs::AdminLogBuffer::new(
            logging_config.ring_buffer_capacity,
        ),
    );
    if ADMIN_LOG_BUFFER.set(admin_log_buffer.clone()).is_err() {
        log::debug!("ADMIN_LOG_BUFFER already initialized, reusing existing buffer");
    }
    // Register the Admin UI ring buffer as a secondary log sink so it keeps
    // receiving entries regardless of the configured output format.
    quicfuscate::logging::set_admin_sink(admin_log_buffer.clone());
    quicfuscate::logging::init(&logging_config)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let _logging_flush_guard = quicfuscate::logging::FlushGuard::new();

    // One-time validation of consolidated in-memory profiles.
    // Logs warnings for any profile that doesn't pass the sanity checks.
    {
        // Validate profiles using the deterministic ClientHello profile catalog.
        let results = quicfuscate::stealth::TlsClientHelloProfileCatalog::available_profiles()
            .into_iter()
            .map(|(b, o)| {
                // Simple validation - check if we can generate a ClientHello
                let ch =
                    quicfuscate::stealth::tls_cover::TlsCover::generate_client_hello(b, o, None);
                let res: Result<(), String> =
                    if ch.len() > 100 { Ok(()) } else { Err("ClientHello too short".into()) };
                (b, o, res)
            })
            .collect::<Vec<_>>();
        let mut failures = 0usize;
        for (b, o, res) in results {
            if let Err(e) = res {
                failures += 1;
                warn!("profile validation failed for {:?}/{:?}: {}", b, o, e);
            }
        }
        if failures > 0 {
            warn!("{} profile(s) had validation issues; proceeding with best-effort.", failures);
        } else {
            info!("All consolidated browser profiles passed validation.");
        }
    }
    if cli.telemetry {
        use quicfuscate::telemetry::TELEMETRY_ENABLED;
        TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        // Spawn minimal telemetry HTTP server at /telemetry
        quicfuscate::metrics::spawn_telemetry_server();
    }
    let requested_firewall_backend =
        startup_engine_config.as_ref().and_then(|config| config.security.firewall.backend);

    match cli.command {
        Commands::Client {
            remote,
            local,
            url,
            shared,
            ca_file,
            no_utls,
            debug_tls,
            list_fingerprints,
            verify_peer,
            qkey,
        } => {
            let fec_mode = resolve_cli_fec_mode_override(shared.fec_mode);
            let firewall_backend = if shared.kill_switch && !shared.cleanup_firewall {
                quicfuscate::firewall::resolve_backend(requested_firewall_backend)
                    .map_err(|error| std::io::Error::other(error.to_string()))?
            } else {
                requested_firewall_backend.unwrap_or_default()
            };
            run_client(
                remote.as_str(),
                local.as_str(),
                url.as_deref(),
                shared.profile,
                shared.os,
                &shared.profile_seq,
                shared.profile_interval,
                fec_mode,
                shared.pool_capacity,
                shared.pool_block,
                &shared.config,
                &shared.fec_config,
                shared.doh_provider.as_str(),
                &shared.front_domain,
                &ca_file,
                no_utls,
                debug_tls,
                list_fingerprints,
                verify_peer,
                shared.disable_doh,
                shared.disable_fronting,
                shared.disable_http3,
                shared.cc_algorithm,
                shared.tun,
                shared.tun_name,
                shared.tun_mtu,
                shared.tun_ip,
                shared.tun_netmask,
                shared.tun_ip6,
                shared.tun_prefix6,
                qkey.as_deref(),
                shared.kill_switch,
                shared.cleanup_firewall,
                firewall_backend,
                &shared.vpn_dns,
                shared.heartbeat_timeout_ms,
            )
            .await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            shared,
            admin_socket,
            metrics_port,
            admin_web,
            admin_web_max_connections,
            admin_web_operation_timeout_ms,
            admin_web_root,
            admin_web_user,
            admin_web_password,
            qkey_ttl_secs,
            qkey_store,
            allow_client_to_client,
            no_drop_privileges,
            drop_user,
            drop_group,
            audit_log,
        } => {
            let fec_mode = resolve_cli_fec_mode_override(shared.fec_mode);
            run_server(
                listen.as_str(),
                cert.as_path(),
                key.as_path(),
                shared.profile,
                shared.os,
                &shared.profile_seq,
                shared.profile_interval,
                fec_mode,
                shared.pool_capacity,
                shared.pool_block,
                &shared.config,
                &shared.fec_config,
                shared.doh_provider.as_str(),
                &shared.front_domain,
                shared.disable_doh,
                shared.disable_fronting,
                shared.disable_http3,
                shared.cc_algorithm,
                shared.tun,
                shared.tun_name,
                shared.tun_mtu,
                shared.tun_ip,
                shared.tun_netmask,
                shared.tun_ip6,
                shared.tun_prefix6,
                admin_socket,
                metrics_port,
                admin_web,
                admin_web_max_connections,
                admin_web_operation_timeout_ms,
                admin_web_root,
                admin_web_user,
                admin_web_password,
                qkey_ttl_secs,
                qkey_store,
                allow_client_to_client,
                no_drop_privileges,
                &drop_user,
                &drop_group,
                audit_log,
                startup_engine_config,
            )
            .await?;
        }
        Commands::VerifyAuditLog { path } => {
            quicfuscate::audit::AuditLog::verify_chain(&path)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            println!("Audit log chain valid: {}", path.display());
        }
        Commands::CrossFadeSim {} => {
            run_crossfade_sim()?;
        }
        Commands::HighLossSim {} => {
            run_high_loss_sim()?;
        }
        Commands::OptimizeProbe {} => {
            run_optimize_probe()?;
        }
        #[cfg(feature = "benches")]
        Commands::FecBench { packets, payload, mode, pool_capacity, block_size, warmup, json } => {
            run_fec_bench(packets, payload, mode, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::PoolBench { iterations, payload, pool_capacity, block_size, warmup, json } => {
            run_pool_bench(iterations, payload, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::CryptoBench { iterations, payload, mode, warmup, json } => {
            run_crypto_bench(iterations, payload, mode, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::NetBench { iterations, payload, warmup, json } => {
            run_net_bench(iterations, payload, warmup, json)?;
        }
        Commands::Capabilities { json, user, group, tun, listen_port } => {
            run_capabilities_report(json, &user, &group, tun, listen_port)?;
        }
    }

    use quicfuscate::telemetry::TELEMETRY_ENABLED;
    if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        quicfuscate::telemetry::flush();
    }
    quicfuscate::logging::flush()?;
    Ok(())
}

fn run_capabilities_report(
    json: bool,
    user: &str,
    group: &str,
    tun: bool,
    listen_port: u16,
) -> std::io::Result<()> {
    let requirements = quicfuscate::privilege::CapabilityRequirements {
        tun,
        privileged_bind: listen_port < 1024,
        privilege_finalize: true,
        audit_owner: false,
    };
    let target = quicfuscate::privilege::inspect_identity(user, group);
    let mut report =
        quicfuscate::privilege::try_check_capabilities(target.identity.as_ref(), requirements)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    report.target_user_exists = target.user_exists;
    report.target_group_exists = target.group_exists;
    if json {
        let mut value = serde_json::to_value(&report)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if let serde_json::Value::Object(fields) = &mut value {
            fields.insert(
                "target_error".to_string(),
                target
                    .error
                    .as_ref()
                    .map_or(serde_json::Value::Null, |error| {
                        serde_json::Value::String(error.clone())
                    }),
            );
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&value)
                .map_err(|error| std::io::Error::other(error.to_string()))?
        );
    } else {
        println!(
            "identity uid={}/{}/{:?} gid={}/{}/{:?} groups={:?}",
            report.real_uid,
            report.effective_uid,
            report.saved_uid,
            report.real_gid,
            report.effective_gid,
            report.saved_gid,
            report.supplementary_groups
        );
        println!(
            "capabilities effective={:#x} permitted={:#x} inheritable={:#x} ambient={:#x} bounding={:#x}",
            report.effective_capabilities,
            report.permitted_capabilities,
            report.inheritable_capabilities,
            report.ambient_capabilities,
            report.bounding_capabilities
        );
        println!(
            "target user_exists={} group_exists={} match={} requested_ready={}{}",
            report.target_user_exists,
            report.target_group_exists,
            report.target_matches_current_identity,
            report.ready_for_requested_operations,
            target
                .error
                .as_ref()
                .map_or(String::new(), |error| format!(" error={error}"))
        );
    }
    Ok(())
}

fn run_crossfade_sim() -> std::io::Result<()> {
    println!("[compat] Cross-fade simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);

    let phases: &[(usize, usize, usize)] = &[
        (0, 100, 16),  // clean
        (10, 100, 16), // light loss
        (30, 100, 24), // moderate
        (50, 100, 24), // heavy
        (10, 100, 16), // recover
    ];
    for (lost, total, iters) in phases {
        for _ in 0..*iters {
            fec.report_loss(*lost, *total);
            let m = fec.current_mode();
            if m != last_mode || fec.is_transitioning() {
                println!(
                    " mode: {:?}  transitioning: {}  (loss={}/{})",
                    m,
                    fec.is_transitioning(),
                    lost,
                    total
                );
                last_mode = m;
            }
        }
    }
    println!("[compat] Cross-fade simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_high_loss_sim() -> std::io::Result<()> {
    println!("[compat] High-loss simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);
    for _ in 0..64 {
        fec.report_loss(70, 100);
        let m = fec.current_mode();
        if m != last_mode || fec.is_transitioning() {
            println!(" mode: {:?}  transitioning: {}", m, fec.is_transitioning());
            last_mode = m;
        }
    }
    println!("[compat] High-loss simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_optimize_probe() -> std::io::Result<()> {
    println!("[compat] Optimization probe starting...");
    let opt = OptimizationManager::new_with_config(64, 4096);
    println!(" xdp_compat_request_normalized=false active=false");
    // Exercise the memory pool
    let b1 = opt.alloc_block();
    let b2 = opt.alloc_block();
    println!(" allocated two blocks: {} + {} bytes", b1.len(), b2.len());
    // Touch memory to exercise NUMA moves where applicable
    let mut b1 = b1;
    let mut b2 = b2;
    if !b1.is_empty() {
        b1[0] = 1;
    }
    if !b2.is_empty() {
        b2[0] = 2;
    }
    opt.free_block(b1);
    opt.free_block(b2);
    // Adjust capacity dynamically
    let pool = opt.memory_pool();
    pool.set_capacity(128);
    println!(" pool capacity adjusted to 128 (probe)");
    println!("[compat] Optimization probe complete.");
    Ok(())
}

fn load_runtime_profiles(
    config_path: Option<&PathBuf>,
    fec_config: &Option<PathBuf>,
    fec_mode_override: Option<quicfuscate::engine::FecMode>,
) -> std::io::Result<(
    FecConfig,
    StealthConfig,
    OptimizeConfig,
    quicfuscate::engine::AntiReplaySection,
)> {
    if config_path.is_some() && fec_config.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--config and --fec-config are mutually exclusive; the explicit FEC file would otherwise be ignored",
        ));
    }

    let (mut fec, stealth, optimize, anti_replay, source) = if let Some(cfg) = config_path {
        let app_config = AppConfig::from_file(cfg).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to load unified configuration {}: {error}", cfg.display()),
            )
        })?;
        app_config.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid unified configuration {}: {error}", cfg.display()),
            )
        })?;
        let (fec, stealth, optimize, anti_replay) =
            quicfuscate::implementations::server::runtime_components_from_app_config(
                app_config,
                fec_mode_override,
            );
        (fec, stealth, optimize, anti_replay, format!("unified-config:{}", cfg.display()))
    } else if let Some(path) = fec_config {
        let fec = FecConfig::from_file(path).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to load explicit FEC configuration {}: {error}", path.display()),
            )
        })?;
        fec.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid explicit FEC configuration {}: {error}", path.display()),
            )
        })?;
        (
            fec,
            StealthConfig::default(),
            OptimizeConfig::default(),
            quicfuscate::engine::AntiReplaySection::default(),
            format!("standalone-file:{}", path.display()),
        )
    } else {
        let fec = FecConfig::product_default();
        fec.validate().map_err(|error| {
            std::io::Error::other(format!("invalid product-default FEC configuration: {error}"))
        })?;
        (
            fec,
            StealthConfig::default(),
            OptimizeConfig::default(),
            quicfuscate::engine::AntiReplaySection::default(),
            "product-default".to_string(),
        )
    };

    info!("Accepted FEC policy source={source}");

    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }

    fec.validate().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("effective FEC policy failed validation after CLI override: {error}"),
        )
    })?;

    Ok((fec, stealth, optimize, anti_replay))
}

fn apply_runtime_transport_defaults(
    config: &mut quicfuscate::transport::Config,
    cc_algorithm: CcAlgorithm,
) {
    config.set_cc_algorithm(cc_algorithm.into());
    if let Err(e) =
        config.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"])
    {
        warn!("Failed to set application protos: {}", e);
    }
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1500);
    config.set_max_send_udp_payload_size(1500);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
}

fn new_runtime_transport_config(
) -> Result<quicfuscate::transport::Config, quicfuscate::error::ConnectionError> {
    let mut config = quicfuscate::transport::Config::new_with_version(
        quicfuscate::transport::PROTOCOL_VERSION_V2,
    )?;
    config.set_supported_versions(vec![
        quicfuscate::transport::PROTOCOL_VERSION_V2,
        quicfuscate::transport::PROTOCOL_VERSION,
    ])?;
    Ok(config)
}

fn runtime_optimize_config(
    config_path: Option<&PathBuf>,
    opt_cfg: OptimizeConfig,
    pool_capacity: usize,
    pool_block: usize,
    origin: &str,
) -> OptimizeConfig {
    if config_path.is_some() {
        quicfuscate::implementations::server::normalize_runtime_optimize_config(
            OptimizeConfig { pool_capacity: opt_cfg.pool_capacity, block_size: opt_cfg.block_size },
            origin,
        )
    } else {
        OptimizeConfig { pool_capacity, block_size: pool_block }
    }
}

fn derive_client_pool_for_tun(
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let ip = u32::from(server_ip);
    let mask = u32::from(netmask);
    let network = ip & mask;
    let broadcast = network | !mask;
    let first_host = network.checked_add(1)?;
    let last_host = broadcast.checked_sub(1)?;
    if first_host > last_host {
        return None;
    }

    if ip < last_host {
        let start = ip.checked_add(1)?;
        if start <= last_host {
            return Some((Ipv4Addr::from(start), Ipv4Addr::from(last_host)));
        }
    }

    if ip > first_host {
        let end = ip.checked_sub(1)?;
        if first_host <= end {
            return Some((Ipv4Addr::from(first_host), Ipv4Addr::from(end)));
        }
    }

    None
}

fn apply_standalone_tun_server_config(
    server_config: &mut quicfuscate::implementations::server::ServerConfig,
    tun_ip: Option<&str>,
    tun_netmask: Option<&str>,
    tun_ip6: Option<&str>,
    tun_prefix6: Option<u8>,
) -> std::io::Result<()> {
    // A netmask without an address has nothing to apply to. The IPv4 branch below only
    // runs when an address is supplied, so accepting the flag here would silently drop
    // it from the server configuration while the TUN construction still used it, which
    // is the divergence this contract exists to prevent.
    if tun_ip.is_none() && tun_netmask.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--tun-netmask requires --tun-ip",
        ));
    }

    if let Some(tun_ip) = tun_ip {
        let server_ip = tun_ip.parse::<Ipv4Addr>().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid --tun-ip: {e}"))
        })?;
        let netmask = match tun_netmask {
            Some(mask) => mask.parse::<Ipv4Addr>().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid --tun-netmask: {e}"),
                )
            })?,
            None => server_config.server_netmask,
        };
        let Some((pool_start, pool_end)) = derive_client_pool_for_tun(server_ip, netmask) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("no usable client IP pool for TUN address {server_ip}/{netmask}"),
            ));
        };

        server_config.server_ip = server_ip;
        server_config.server_netmask = netmask;
        server_config.ip_pool_start = pool_start;
        server_config.ip_pool_end = pool_end;
    }

    if tun_ip6.is_some() || tun_prefix6.is_some() {
        let server_ip = match tun_ip6 {
            Some(value) => value.parse::<Ipv6Addr>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid --tun-ip6: {error}"),
                )
            })?,
            None => server_config.ipv6_server_ip.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--tun-prefix6 requires an IPv6 server address",
                )
            })?,
        };
        let prefix = tun_prefix6.unwrap_or(server_config.ipv6_prefix_len);
        let Some((pool_start, pool_end)) = derive_ipv6_client_pool_for_tun(server_ip, prefix)
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("no usable client IPv6 pool for TUN address {server_ip}/{prefix}"),
            ));
        };
        server_config.ipv6_server_ip = Some(server_ip);
        server_config.ipv6_prefix_len = prefix;
        server_config.ipv6_pool_start = Some(pool_start);
        server_config.ipv6_pool_end = Some(pool_end);
    }
    Ok(())
}

fn derive_ipv6_client_pool_for_tun(
    server_ip: Ipv6Addr,
    prefix: u8,
) -> Option<(Ipv6Addr, Ipv6Addr)> {
    if prefix == 0 || prefix > 128 {
        return None;
    }
    let server = u128::from(server_ip);
    let mask = u128::MAX << (128 - prefix);
    let network = server & mask;
    let last = network | !mask;
    let first_host = network.checked_add(1)?;
    if first_host > last || server < network || server > last {
        return None;
    }

    if server < last {
        let start = server.checked_add(1)?;
        let end = start.saturating_add(252).min(last);
        return Some((Ipv6Addr::from(start), Ipv6Addr::from(end)));
    }
    if server > first_host {
        let end = server.checked_sub(1)?;
        let start = end.saturating_sub(252).max(first_host);
        return Some((Ipv6Addr::from(start), Ipv6Addr::from(end)));
    }
    None
}

fn client_packet_too_big_response(packet: &[u8], tunnel_mtu: usize) -> Vec<u8> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            quicfuscate::implementations::server::icmp::build_icmpv4_error(
                packet,
                destination,
                quicfuscate::implementations::server::icmp::icmp_type::DESTINATION_UNREACHABLE,
                quicfuscate::implementations::server::icmp::icmp_code::FRAGMENTATION_NEEDED,
                u16::try_from(tunnel_mtu).ok(),
            )
        }
        Some(6) if packet.len() >= 40 => {
            let destination =
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap_or([0; 16]));
            quicfuscate::implementations::server::icmp::build_icmpv6_error(
                packet,
                destination,
                quicfuscate::implementations::server::icmp::icmpv6_type::PACKET_TOO_BIG,
                Some(tunnel_mtu.min(u32::MAX as usize) as u32),
            )
        }
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ClientTunPacketError {
    Backpressure,
    Fault(quicfuscate::engine::DataPlaneFault),
}

fn send_client_tun_packet(
    conn: &mut QuicFuscateConnection,
    tun: &quicfuscate::interface::TunInterface,
    stream_id: u64,
    packet: &[u8],
) -> Result<(), ClientTunPacketError> {
    let tunnel_mtu = conn.effective_tunnel_mtu().min(usize::from(tun.mtu()));
    if packet.len() <= tunnel_mtu {
        return conn.send_tunnel_packet(stream_id, packet).map_err(|error| match error {
            ConnectionError::DgramQueueFull => ClientTunPacketError::Backpressure,
            error => ClientTunPacketError::Fault(
                quicfuscate::engine::DataPlaneFault::TransportSend {
                    component: "standalone client TUN uplink".to_string(),
                    error: error.to_string(),
                },
            ),
        });
    }

    let response = client_packet_too_big_response(packet, tunnel_mtu);
    if response.is_empty() {
        return Err(ClientTunPacketError::Fault(
            quicfuscate::engine::DataPlaneFault::TransportSend {
                component: "standalone client oversized TUN response".to_string(),
                error: ConnectionError::BufferTooShort.to_string(),
            },
        ));
    }
    tun.write(&response).map_err(|error| {
        ClientTunPacketError::Fault(quicfuscate::engine::DataPlaneFault::TunWrite {
            component: "standalone client oversized TUN response".to_string(),
            error: error.to_string(),
        })
    })?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InitialClientPacketEvidence {
    constructed_bytes: usize,
    sent_bytes: usize,
}

fn initial_client_packet_constructed(
    result: Result<usize, ConnectionError>,
) -> std::io::Result<usize> {
    let constructed_bytes = result.map_err(|error| {
        std::io::Error::other(format!("initial client packet construction failed: {error}"))
    })?;
    if constructed_bytes == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "initial client packet construction produced no datagram",
        ));
    }
    Ok(constructed_bytes)
}

fn initial_client_packet_sent(
    constructed_bytes: usize,
    result: std::io::Result<()>,
) -> std::io::Result<InitialClientPacketEvidence> {
    result.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("initial client handshake datagram send failed: {error}"),
        )
    })?;
    Ok(InitialClientPacketEvidence { constructed_bytes, sent_bytes: constructed_bytes })
}

/// Complete the standalone client's authenticated assignment barrier before
/// opening a native TUN device. The control capsule and MASQUE readiness are
/// accepted only for the current reconnect generation.
async fn negotiate_standalone_assignment(
    conn: &mut QuicFuscateConnection,
    socket: &tokio::net::UdpSocket,
    recv_buf: &mut [u8],
    send_buf: &mut [u8],
    generation: u64,
) -> std::io::Result<quicfuscate::control_plane::ClientAssignment> {
    let reception = Arc::new(parking_lot::Mutex::new(
        quicfuscate::control_plane::AssignmentReception::new(generation)
            .map_err(|error| std::io::Error::other(error.to_string()))?,
    ));
    let callback_state = Arc::clone(&reception);
    conn.set_client_connection_generation(generation);
    conn.set_masque_control_cb(Arc::new(std::sync::Mutex::new(Box::new(
        move |capsule_type: u64, payload: &[u8]| {
            callback_state.lock().receive(capsule_type, payload);
        },
    ))));

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut control_started = false;
    while Instant::now() < deadline {
        flush_connected_outgoing(socket, conn, send_buf, None)
            .await
            .map_err(|fault| std::io::Error::other(fault.to_string()))?;

        {
            let state = reception.lock();
            if let Some(error) = state.failure() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("authenticated client assignment rejected: {error}"),
                ));
            }
            if let Some(assignment) = state.assignment() {
                if conn.masque_tunnel_established() {
                    return Ok(assignment.clone());
                }
            }
        }

        if conn.conn.is_closed() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "server closed the connection before assignment readiness",
            ));
        }

        if conn.conn.is_established() && !control_started {
            conn.begin_masque_control_tunnel().map_err(|error| {
                std::io::Error::other(format!("MASQUE assignment tunnel failed: {error}"))
            })?;
            control_started = true;
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = remaining.min(Duration::from_millis(100));
        if wait.is_zero() {
            break;
        }
        match tokio::time::timeout(wait, recv_connected_datagram(socket, recv_buf)).await {
            Ok(Ok(length)) if length > 0 => {
                conn.recv(&recv_buf[..length]).map_err(|error| {
                    std::io::Error::other(format!("assignment QUIC receive failed: {error}"))
                })?;
                if control_started {
                    conn.poll_http3().map_err(|error| {
                        std::io::Error::other(format!("assignment H3 poll failed: {error}"))
                    })?;
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                return Err(std::io::Error::other(format!(
                    "assignment UDP receive failed: {error}"
                )));
            }
            Err(_) => {}
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out waiting for authenticated server assignment",
    ))
}

fn client_startup_error_with_cleanup(
    primary: std::io::Error,
    cleanup_errors: Vec<String>,
) -> std::io::Error {
    if cleanup_errors.is_empty() {
        return primary;
    }
    let kind = primary.kind();
    std::io::Error::new(
        kind,
        format!("{primary}; client startup cleanup failed: {}", cleanup_errors.join("; ")),
    )
}

async fn cleanup_client_startup_failure(
    conn: &mut QuicFuscateConnection,
    stealth_runtime: &Arc<StealthRuntimeOwner>,
    kill_switch: Option<&Arc<quicfuscate::implementations::client::KillSwitch>>,
    primary: std::io::Error,
    close_reason: &[u8],
) -> std::io::Error {
    let mut cleanup_errors = Vec::new();
    if let Err(error) = conn.conn.close(true, 0, close_reason) {
        cleanup_errors.push(format!("QUIC close failed: {error:?}"));
    }
    if let Some(kill_switch) = kill_switch {
        if let Err(error) = kill_switch.on_vpn_disconnected() {
            cleanup_errors.push(format!("kill switch fail-closed cleanup failed: {error}"));
        }
    }
    if let Err(error) = stealth_runtime
        .shutdown(quicfuscate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT)
        .await
    {
        cleanup_errors.push(format!("stealth runtime shutdown failed: {error}"));
    }
    client_startup_error_with_cleanup(primary, cleanup_errors)
}

fn spawn_client_tun_reader(
    spawn: impl FnOnce(
        Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<std::thread::JoinHandle<()>>,
    reader: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn(Box::new(reader))
        .map_err(|error| std::io::Error::other(format!("client TUN reader spawn failed: {error}")))
}

fn client_tun_activation_ready(
    tun_enable: bool,
    has_receiver: bool,
    has_writer: bool,
    has_shutdown: bool,
    has_reader: bool,
) -> bool {
    !tun_enable || (has_receiver && has_writer && has_shutdown && has_reader)
}

fn record_standalone_client_tun_fault(
    fault_slot: &Arc<parking_lot::Mutex<Option<quicfuscate::engine::DataPlaneFault>>>,
    notify: &Arc<tokio::sync::Notify>,
    shutdown: &AtomicBool,
    fault: quicfuscate::engine::DataPlaneFault,
) {
    if shutdown.load(Ordering::Acquire) {
        return;
    }
    let mut stored = fault_slot.lock();
    if stored.is_none() {
        *stored = Some(fault);
        notify.notify_one();
    }
}

/// Drain TUN frames from `rx` and forward them through `conn` without dropping
/// a frame that encounters DATAGRAM queue backpressure. A backpressured frame
/// is held in `backlog` and retried on the next call before new frames.
fn drain_client_tun_uplink(
    conn: &mut QuicFuscateConnection,
    tun: &quicfuscate::interface::TunInterface,
    sid: u64,
    rx: &std::sync::mpsc::Receiver<quicfuscate::interface::TunPacket>,
    backlog: &mut Option<quicfuscate::interface::TunPacket>,
    diagnostics_enabled: bool,
) -> Result<bool, quicfuscate::engine::DataPlaneFault> {
    if let Some(frame) = backlog.take() {
        let frame_len = frame.len();
        match send_client_tun_packet(conn, tun, sid, frame.as_slice()) {
            Ok(()) => {
                if diagnostics_enabled {
                    info!("Client Wintun backlog accepted by MASQUE uplink: bytes={frame_len}");
                }
            }
            Err(ClientTunPacketError::Backpressure) => {
                if diagnostics_enabled {
                    info!("Client MASQUE uplink remains backpressured: bytes={frame_len}");
                }
                *backlog = Some(frame);
                return Ok(true);
            }
            Err(ClientTunPacketError::Fault(fault)) => {
                warn!("TUN packet send failed: {fault}");
                return Err(fault);
            }
        }
    }

    for _ in 0..16 {
        match rx.try_recv() {
            Ok(frame) => {
                let frame_len = frame.len();
                match send_client_tun_packet(conn, tun, sid, frame.as_slice()) {
                    Ok(()) => {
                        if diagnostics_enabled {
                            info!(
                                "Client Wintun packet accepted by MASQUE uplink: bytes={frame_len}"
                            );
                        }
                    }
                    Err(ClientTunPacketError::Backpressure) => {
                        if diagnostics_enabled {
                            info!("Client MASQUE uplink backpressured: bytes={frame_len}");
                        }
                        *backlog = Some(frame);
                        break;
                    }
                    Err(ClientTunPacketError::Fault(fault)) => {
                        warn!("TUN packet send failed: {fault}");
                        return Err(fault);
                    }
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err(quicfuscate::engine::DataPlaneFault::ChannelDisconnected {
                    component: "standalone client TUN reader channel".to_string(),
                });
            }
        }
    }

    if backlog.is_some() {
        return Ok(true);
    }

    // Preserve the wake-up contract when the bounded drain limit was reached.
    // Holding one frame in the existing backlog also keeps the adaptive tick
    // active without probing the channel on every idle tick.
    match rx.try_recv() {
        Ok(frame) => {
            *backlog = Some(frame);
            Ok(true)
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => Ok(false),
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            Err(quicfuscate::engine::DataPlaneFault::ChannelDisconnected {
                component: "standalone client TUN reader channel".to_string(),
            })
        }
    }
}

const CLIENT_HOUSEKEEPING_ACTIVE: Duration = Duration::from_millis(5);
const CLIENT_HOUSEKEEPING_IDLE: Duration = Duration::from_millis(250);

fn client_housekeeping_delay(
    conn: &QuicFuscateConnection,
    tun_enable: bool,
    request_sent: bool,
    tun_backpressure_pending: bool,
    heartbeat_deadline: Option<tokio::time::Instant>,
) -> Duration {
    let active = !conn.conn.is_established()
        || !request_sent
        || (tun_enable && !conn.masque_tunnel_established())
        || conn.conn.has_pending_application_ack()
        || conn.conn.dgram_send_queue_len() > 0
        || tun_backpressure_pending;
    if active {
        return CLIENT_HOUSEKEEPING_ACTIVE;
    }

    // QUIC release and recovery deadlines belong to the connection's injected
    // protocol clock. Only the resulting duration crosses into Tokio.
    let now = conn.protocol_clock().now();
    let mut delay = CLIENT_HOUSEKEEPING_IDLE;
    for deadline in [
        conn.next_outbound_release_deadline(),
        conn.conn.recovery_deadline(),
    ]
    .into_iter()
    .flatten()
    {
        delay = delay.min(deadline.saturating_duration_since(now));
    }
    if let Some(deadline) = heartbeat_deadline {
        delay = delay.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    }
    delay.max(CLIENT_HOUSEKEEPING_ACTIVE)
}

fn synchronize_client_tun_mtu(
    conn: &QuicFuscateConnection,
    tun: &quicfuscate::interface::TunInterface,
    configured_ceiling: u16,
) -> std::io::Result<()> {
    let target =
        configured_ceiling.min(u16::try_from(conn.effective_tunnel_mtu()).unwrap_or(u16::MAX));
    if tun.mtu() != target {
        tun.set_mtu(target)?;
        info!("Client TUN MTU updated to {}", target);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientTargetSource {
    Default,
    Explicit,
}

impl ClientTargetSource {
    const fn label(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Explicit => "explicit",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClientTarget {
    source: ClientTargetSource,
    host: String,
    authority: String,
    port: u16,
    request_path: String,
    transport_destination: std::net::SocketAddr,
    alternate_transport_ip: Option<IpAddr>,
}

fn invalid_client_target(reason: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid client URL: {reason}"),
    )
}

fn resolve_client_target(
    raw_url: Option<&str>,
    remote_addr_str: &str,
) -> std::io::Result<ClientTarget> {
    let (source, raw_url) = match raw_url {
        Some(raw_url) => (ClientTargetSource::Explicit, raw_url),
        None => (ClientTargetSource::Default, DEFAULT_RUNTIME_URL),
    };
    let parsed = url::Url::parse(raw_url).map_err(invalid_client_target)?;

    if parsed.scheme() != "https" {
        return Err(invalid_client_target(format!(
            "unsupported scheme {:?}; expected https",
            parsed.scheme()
        )));
    }
    let (raw_scheme, raw_authority_and_path) = raw_url
        .split_once("://")
        .ok_or_else(|| invalid_client_target("authority is required after https://"))?;
    let authority_is_missing = raw_authority_and_path.is_empty()
        || matches!(raw_authority_and_path.as_bytes().first(), Some(b'/' | b'?' | b'#'));
    if !raw_scheme.eq_ignore_ascii_case("https") || authority_is_missing {
        return Err(invalid_client_target("authority is required after https://"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_client_target("credentials are not supported"));
    }
    if parsed.fragment().is_some() {
        return Err(invalid_client_target("fragments are not supported"));
    }

    let host_kind = parsed.host().ok_or_else(|| invalid_client_target("host is required"))?;
    let host = match host_kind {
        url::Host::Ipv6(address) => address.to_string(),
        _ => parsed
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| invalid_client_target("host is required"))?
            .to_owned(),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| invalid_client_target("URL has no usable port"))?;
    if port == 0 {
        return Err(invalid_client_target("port must be between 1 and 65535"));
    }

    let authority_host = match host_kind {
        url::Host::Ipv6(_) => format!("[{host}]"),
        _ => host.clone(),
    };
    let authority = match parsed.port() {
        Some(port) => format!("{authority_host}:{port}"),
        None => authority_host,
    };
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
    let request_path = match parsed.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };

    let resolved_servers: Vec<_> = remote_addr_str.to_socket_addrs()?.collect();
    let transport_destination = resolved_servers.first().copied().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;
    let alternate_transport_ip = resolved_servers
        .iter()
        .map(|address| address.ip())
        .find(|ip| ip.is_ipv4() != transport_destination.ip().is_ipv4());

    let target = ClientTarget {
        source,
        host,
        authority,
        port,
        request_path,
        transport_destination,
        alternate_transport_ip,
    };
    info!(
        "Accepted client target source={} host={} port={} authority={} transport_destination={}",
        target.source.label(),
        target.host,
        target.port,
        target.authority,
        target.transport_destination
    );
    Ok(target)
}

fn load_client_ca_file(
    config: &mut quicfuscate::transport::Config,
    path: &Path,
) -> std::io::Result<()> {
    let ca_path = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("CA file path is not valid UTF-8: {}", path.display()),
        )
    })?;
    config.load_verify_locations_from_file(ca_path).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("failed to load CA file {}: {error}", path.display()),
        )
    })?;
    info!("Accepted client CA file {}", path.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_client(
    remote_addr_str: &str,
    local_addr_str: &str,
    url: Option<&str>,
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
    ca_file: &Option<PathBuf>,
    no_utls: bool,
    debug_tls: bool,
    list_fingerprints: bool,
    verify_peer: bool,
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
    qkey: Option<&str>,
    kill_switch_enabled: bool,
    cleanup_firewall: bool,
    firewall_backend: quicfuscate::firewall::FirewallBackend,
    vpn_dns: &[IpAddr],
    heartbeat_timeout_ms: u64,
) -> std::io::Result<()> {
    enum ExitReason {
        CleanShutdown,
        RemoteClosed,
        HeartbeatTimeout,
        DataPlane(quicfuscate::engine::DataPlaneFault),
        SocketError(String),
    }

    let config_path = config.as_ref();

    // Handle --cleanup-firewall: remove stale rules from crashed session, then exit
    if cleanup_firewall {
        info!("Cleaning up stale kill switch firewall rules...");
        match quicfuscate::implementations::client::KillSwitch::cleanup_stale_rules() {
            Ok(()) => info!("Stale firewall rules cleaned up successfully"),
            Err(error) => {
                return Err(std::io::Error::other(format!(
                    "stale firewall cleanup failed: {error}"
                )));
            }
        }
        return Ok(());
    }

    if list_fingerprints {
        info!("Available browser fingerprints:");
        for (b, o) in TlsClientHelloProfileCatalog::available_profiles() {
            info!("- {}@{}", format!("{:?}", b).to_lowercase(), format!("{:?}", o).to_lowercase());
        }
        return Ok(());
    }

    if tun_enable
        && (tun_mtu.is_some()
            || tun_ip.is_some()
            || tun_netmask.is_some()
            || tun_ip6.is_some()
            || tun_prefix6.is_some())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "standalone client TUN address and MTU flags are server-assigned; remove --tun-mtu/--tun-ip/--tun-netmask/--tun-ip6/--tun-prefix6",
        ));
    }

    let cli_profile = FingerprintProfile::try_new(profile, os).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid profile/OS selection: {error}"),
        )
    })?;

    let target = resolve_client_target(url, remote_addr_str)?;
    let server_addr = target.transport_destination;
    let alternate_server_ip = target.alternate_transport_ip;

    let local_addr = local_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "Local address invalid")
    })?;

    let std_socket = std::net::UdpSocket::bind(local_addr)?;
    let socket_ref = socket2::SockRef::from(&std_socket);
    if let Err(error) =
        socket_ref.set_recv_buffer_size(quicfuscate::transport::UDP_SOCKET_BUFFER_BYTES)
    {
        log::debug!("UDP receive buffer hint rejected: {}", error);
    }
    if let Err(error) =
        socket_ref.set_send_buffer_size(quicfuscate::transport::UDP_SOCKET_BUFFER_BYTES)
    {
        log::debug!("UDP send buffer hint rejected: {}", error);
    }
    std_socket.connect(server_addr)?;
    std_socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;

    info!("Client connecting to {}", server_addr);

    let tun_name_str = tun_name.clone().unwrap_or_else(|| "tun0".to_string());
    let firewall_policy = quicfuscate::implementations::client::VpnFirewallPolicy::new(
        tun_name_str.clone(),
        server_addr,
        alternate_server_ip,
        vpn_dns.iter().copied(),
    )
    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string()))?;
    let mut prepared_dns = if tun_enable && !disable_doh {
        Some(tokio::task::block_in_place(|| {
            quicfuscate::implementations::client::ClientDnsRuntime::prepare_endpoint(doh_provider)
        })
        .map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
        })?)
    } else {
        None
    };
    let stealth_runtime = Arc::new(
        StealthRuntimeOwner::from_env()
            .map_err(|error| std::io::Error::other(format!("invalid Reality config: {error}")))?,
    );

    let (fec_cfg, mut stealth_config, opt_cfg, _) =
        load_runtime_profiles(config_path, fec_config, fec_mode)?;

    let mut config = match new_runtime_transport_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create transport config: {}", e);
            return Err(std::io::Error::other("transport config init failed"));
        }
    };
    apply_runtime_transport_defaults(&mut config, cc_algorithm);
    if let Some(cfg_path) = config_path {
        quicfuscate::implementations::server::apply_transport_overrides_from_file(
            cfg_path,
            &mut config,
        )
        .map_err(std::io::Error::other)?;
    }
    config.verify_peer(true);
    if verify_peer {
        log::debug!("--verify-peer is retained for compatibility; verification is already enabled");
    }
    if debug_tls {
        warn!(
            "--debug-tls currently relies on QUICFUSCATE_TRACE_TLS tracing paths; transport keylog emission is not wired in this fork"
        );
    }
    if let Some(path) = ca_file {
        load_client_ca_file(&mut config, path)?;
    }

    // Do not publish firewall state until all explicit client configuration, including
    // the CA trust root, has been accepted. Configuration failures must not strand a
    // connecting kill switch without entering the normal cleanup path.
    let kill_switch = if kill_switch_enabled {
        quicfuscate::implementations::client::KillSwitch::cleanup_stale_rules().map_err(
            |error| std::io::Error::other(format!("stale firewall cleanup failed: {error}")),
        )?;
        let ks = std::sync::Arc::new(
            quicfuscate::implementations::client::KillSwitch::new_with_backend(firewall_backend),
        );
        ks.enable().map_err(|error| {
            std::io::Error::other(format!("kill switch enable failed: {error}"))
        })?;
        ks.on_vpn_connecting(&firewall_policy).map_err(|error| {
            std::io::Error::other(format!("kill switch connecting policy failed: {error}"))
        })?;
        info!("Kill switch enabled with VPN-endpoint-only connecting policy");
        Some(ks)
    } else {
        None
    };

    quicfuscate::implementations::server::apply_runtime_stealth_overrides(
        &mut stealth_config,
        profile,
        os,
        disable_doh,
        doh_provider,
        disable_fronting,
        front_domain,
        disable_http3,
    );

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => quicfuscate::implementations::server::resolve_runtime_profiles(
            profile, os, seq, false,
        )
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid profile sequence: {error}"),
            )
        })?,
        None => {
            let configured = stealth_config.rotation_profiles();
            if configured.is_empty() {
                vec![cli_profile.clone()]
            } else {
                configured
            }
        }
    };
    if profile_seq.is_some() && profiles.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--profile-seq must contain at least one profile",
        ));
    }

    if let Some(first) = profiles.first() {
        stealth_config.initial_browser = first.browser;
        stealth_config.initial_os = first.os;
    }
    let rotation_interval = if profile_seq.is_some() {
        profile_interval
    } else {
        stealth_config.fingerprint_rotation_interval
    };
    let should_rotate = profiles.len() > 1 && rotation_interval > 0;
    if profile_seq.is_some() {
        stealth_config.fingerprint_rotation_profiles = profiles
            .iter()
            .map(|profile| (profile.browser, profile.os))
            .collect();
        stealth_config.fingerprint_rotation_mode = quicfuscate::stealth::RotationMode::Slots;
        stealth_config.enable_fingerprint_rotation = should_rotate;
        stealth_config.fingerprint_rotation_interval = rotation_interval;
    }
    let shared_stealth_config = Arc::new(std::sync::Mutex::new(stealth_config.clone()));

    let host = target.host.as_str();
    let opt_params = runtime_optimize_config(
        config_path,
        opt_cfg,
        pool_capacity,
        pool_block,
        "client runtime config",
    );
    // Derive the QKey bearer token (x-qf-auth) from a supplied QKey string.
    // Servers that require a QKey reject clients without a valid token.
    let qkey_auth_token_hex = match qkey {
        Some(raw) if !raw.trim().is_empty() => match quicfuscate::engine::qkey::parse(raw.trim()) {
            Ok(parsed) => match parsed.token.as_deref().map(str::trim) {
                Some(tok) if !tok.is_empty() => {
                    Some(quicfuscate::engine::qkey::QKeyToken::from(tok))
                }
                _ => {
                    error!("supplied --qkey does not contain a token");
                    return Err(std::io::Error::other("qkey missing token"));
                }
            },
            Err(e) => {
                error!("failed to parse --qkey: {}", e);
                return Err(std::io::Error::other("invalid qkey"));
            }
        },
        _ => None,
    };
    // Compute the 12-char QKey ID for the QUIC Initial packet token.
    let qkey_initial_token: Option<Vec<u8>> =
        qkey.map(|raw| quicfuscate::engine::qkey::id(raw.trim()).into_bytes());

    let mut conn = match QuicFuscateConnection::new_client_with_runtime(
        host,
        local_addr,
        server_addr,
        config,
        stealth_config.clone(),
        fec_cfg,
        opt_params,
        qkey_auth_token_hex,
        qkey_initial_token,
        !no_utls,
        Some(stealth_runtime.clone()),
        Some(target.authority.as_str()),
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to create client connection: {}", e);
            return Err(std::io::Error::other("client connection init failed"));
        }
    };

    stealth_runtime
        .start(
            should_rotate.then_some(shared_stealth_config),
            if should_rotate { profiles } else { Vec::new() },
            if should_rotate { rotation_interval } else { 0 },
        )
        .map_err(|error| std::io::Error::other(format!("stealth runtime start failed: {error}")))?;

    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    // Construct and send the first wire datagram before any later request or TUN
    // readiness can be published. A live runtime without this packet is not a
    // valid client startup.
    let constructed_bytes = match initial_client_packet_constructed(conn.send(&mut out)) {
        Ok(bytes) => {
            info!("Constructed initial client packet of size {}", bytes);
            bytes
        }
        Err(error) => {
            error!("Initial client packet construction failed: {}", error);
            return Err(
                cleanup_client_startup_failure(
                    &mut conn,
                    &stealth_runtime,
                    kill_switch.as_ref(),
                    error,
                    b"initial client handshake construction failed",
                )
                .await,
            );
        }
    };
    let initial_packet = match initial_client_packet_sent(
        constructed_bytes,
        send_connected_datagram(&socket, &out[..constructed_bytes]).await,
    ) {
        Ok(evidence) => evidence,
        Err(error) => {
            error!("Initial client handshake send failed: {}", error);
            return Err(
                cleanup_client_startup_failure(
                    &mut conn,
                    &stealth_runtime,
                    kill_switch.as_ref(),
                    error,
                    b"initial client handshake send failed",
                )
                .await,
            );
        }
    };
    telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(initial_packet.sent_bytes as u64));
    info!(
        "Sent initial client packet constructed_bytes={} sent_bytes={}",
        initial_packet.constructed_bytes,
        initial_packet.sent_bytes
    );

    let mut request_sent = false;
    let mut kill_switch_connected = false;
    let client_receive_diagnostics_enabled =
        quicfuscate::env_utils::env_flag(CLIENT_RECV_DIAGNOSTICS_ENV, false);
    if client_receive_diagnostics_enabled {
        info!("Client receive diagnostics enabled for this process");
    }

    let assignment = if tun_enable {
        match negotiate_standalone_assignment(&mut conn, &socket, &mut buf, &mut out, 1).await {
            Ok(assignment) => {
                info!(
                    "Accepted authenticated client assignment: session_id={} generation={} mode={:?} ipv4={:?} ipv6={:?} mtu={} dns_servers={:?}",
                    assignment.session_id,
                    assignment.generation,
                    assignment.mode,
                    assignment.ipv4,
                    assignment.ipv6,
                    assignment.mtu,
                    assignment.dns_servers
                );
                Some(assignment)
            }
            Err(error) => {
                error!("Standalone client assignment negotiation failed: {error}");
                return Err(
                    cleanup_client_startup_failure(
                        &mut conn,
                        &stealth_runtime,
                        kill_switch.as_ref(),
                        error,
                        b"authenticated client assignment negotiation failed",
                    )
                    .await,
                );
            }
        }
    } else {
        None
    };
    let negotiated_tun_mtu = assignment.as_ref().map_or(1500, |value| value.mtu);
    let connected_firewall_policy = if let Some(assignment) = assignment.as_ref() {
        quicfuscate::implementations::client::VpnFirewallPolicy::new(
            tun_name_str.clone(),
            server_addr,
            alternate_server_ip,
            assignment.dns_servers.iter().copied(),
        )
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("server-assigned firewall DNS policy invalid: {error}"),
            )
        })?
    } else {
        firewall_policy.clone()
    };

    // Optional TUN bridging setup
    let tun_notify = Arc::new(tokio::sync::Notify::new());
    #[allow(clippy::type_complexity)]
    let tun_setup: std::io::Result<(
        Option<std::sync::mpsc::Receiver<quicfuscate::interface::TunPacket>>,
        Option<Arc<quicfuscate::interface::TunInterface>>,
        Option<u64>,
        Option<Arc<AtomicBool>>,
        Option<Arc<AtomicBool>>,
        Option<Arc<parking_lot::Mutex<Option<quicfuscate::engine::DataPlaneFault>>>>,
        Option<std::thread::JoinHandle<()>>,
    )> = if tun_enable {
        let effective_tun_mtu =
            negotiated_tun_mtu.min(u16::try_from(conn.effective_tunnel_mtu()).unwrap_or(u16::MAX));
        let assignment = assignment.as_ref().ok_or_else(|| {
            std::io::Error::other("client TUN activation requires a negotiated assignment")
        })?;
        let mut tcfg = quicfuscate::implementations::client::tun_config_from_assignment(
            assignment,
            tun_name,
            true,
        )
        .map_err(|error| std::io::Error::other(format!("invalid server assignment: {error}")))?;
        tcfg.mtu = effective_tun_mtu;
        let optm = OptimizationManager::from_cfg(opt_params);
        let pool = optm.memory_pool();
        match quicfuscate::interface::TunInterface::open(tcfg, pool.clone()) {
            Ok(tun) => {
                // Share the TUN via a plain Arc (no Mutex): read_block() and write()
                // both take &self and the kernel serializes the fd, so the blocking
                // reader thread must NOT hold a lock that would starve the downlink
                // writer (that deadlock left the tunnel one-directional).
                let tun = Arc::new(tun);
                // The reader owns the shutdown flag and is joined after the
                // transport loop exits. The bounded channel still applies
                // backpressure to the TUN source.
                let (tx, rx) = std::sync::mpsc::sync_channel::<quicfuscate::interface::TunPacket>(
                    quicfuscate::interface::TUN_PACKET_QUEUE_CAPACITY,
                );
                let tun_for_reader = tun.clone();
                let tun_reader_diagnostics = client_receive_diagnostics_enabled;
                let reader_shutdown = Arc::new(AtomicBool::new(false));
                let reader_failed = Arc::new(AtomicBool::new(false));
                let reader_fault = Arc::new(parking_lot::Mutex::new(None));
                let shutdown_for_loop = Arc::clone(&reader_shutdown);
                let shutdown_for_callback = Arc::clone(&reader_shutdown);
                let failed_for_error = Arc::clone(&reader_failed);
                let failed_for_callback = Arc::clone(&reader_failed);
                let fault_for_error = Arc::clone(&reader_fault);
                let fault_for_callback = Arc::clone(&reader_fault);
                let tun_notify_for_reader = Arc::clone(&tun_notify);
                let tun_notify_for_callback_failure = Arc::clone(&tun_notify);
                let tun_notify_for_error = Arc::clone(&tun_notify);
                match spawn_client_tun_reader(
                    |reader| {
                        std::thread::Builder::new()
                            .name("client-tun-reader".to_string())
                            .spawn(reader)
                    },
                    move || {
                        let read_result = tun_for_reader.reader_loop_with_shutdown_owned(
                            &shutdown_for_loop,
                            move |packet| {
                                if tun_reader_diagnostics {
                                    info!("Client Wintun packet read: bytes={}", packet.len());
                                }
                                if tx.send(packet).is_err() {
                                    if !shutdown_for_callback.load(Ordering::Acquire) {
                                        record_standalone_client_tun_fault(
                                            &fault_for_callback,
                                            &tun_notify_for_callback_failure,
                                            &shutdown_for_callback,
                                            quicfuscate::engine::DataPlaneFault::ChannelDisconnected {
                                                component: "standalone client TUN reader channel".to_string(),
                                            },
                                        );
                                    }
                                    shutdown_for_callback.store(true, Ordering::Release);
                                    failed_for_callback.store(true, Ordering::Release);
                                    tun_notify_for_callback_failure.notify_one();
                                    return;
                                }
                                tun_notify_for_reader.notify_one();
                            },
                        );
                        if let Err(error) = read_result {
                            warn!("Client TUN reader stopped with error: {error}");
                            if !shutdown_for_loop.load(Ordering::Acquire) {
                                record_standalone_client_tun_fault(
                                    &fault_for_error,
                                    &tun_notify_for_error,
                                    &shutdown_for_loop,
                                    quicfuscate::engine::DataPlaneFault::ReaderStopped {
                                        component: "standalone client TUN reader".to_string(),
                                        error: error.to_string(),
                                    },
                                );
                                failed_for_error.store(true, Ordering::Release);
                            }
                        }
                    },
                ) {
                    Ok(reader_handle) => {
                        // Install the MASQUE→TUN sink so downlink CONNECT-UDP
                        // datagrams are written to the client TUN by the H3 poll.
                        let tun_for_cb = tun.clone();
                        let fault_for_masque = Arc::clone(&reader_fault);
                        let notify_for_masque = Arc::clone(&tun_notify);
                        let shutdown_for_masque = Arc::clone(&reader_shutdown);
                        conn.set_masque_datagram_cb(std::sync::Arc::new(
                            std::sync::Mutex::new(Box::new(move |payload: &[u8]| {
                                // Only write raw IPv4/IPv6 packets. CONNECT-UDP
                                // capsules are not TUN payloads.
                                if !payload.is_empty()
                                    && (payload[0] >> 4 == 4 || payload[0] >> 4 == 6)
                                {
                                    if let Err(error) = tun_for_cb.write(payload) {
                                        warn!(
                                            "Client TUN write (MASQUE downlink) failed: {:?}",
                                            error
                                        );
                                        record_standalone_client_tun_fault(
                                            &fault_for_masque,
                                            &notify_for_masque,
                                            &shutdown_for_masque,
                                            quicfuscate::engine::DataPlaneFault::TunWrite {
                                                component: "standalone client MASQUE downlink".to_string(),
                                                error: error.to_string(),
                                            },
                                        );
                                    }
                                }
                            })),
                        ));
                        Ok((
                            Some(rx),
                            Some(tun),
                            None,
                            Some(reader_shutdown),
                            Some(reader_failed),
                            Some(reader_fault),
                            Some(reader_handle),
                        ))
                    }
                    Err(error) => Err(error),
                }
            }
            Err(e) => {
                Err(std::io::Error::other(format!("client TUN open failed: {e:?}")))
            }
        }
    } else {
        Ok((None, None, None, None, None, None, None))
    };
    let (
        tun_rx,
        tun_writer,
        mut h3_stream_id,
        tun_reader_shutdown,
        _tun_reader_failed,
        tun_reader_fault,
        mut tun_reader_handle,
    ) = match tun_setup {
            Ok(resources) => resources,
            Err(error) => {
                error!("Standalone client TUN activation failed: {error}");
                return Err(
                    cleanup_client_startup_failure(
                        &mut conn,
                        &stealth_runtime,
                        kill_switch.as_ref(),
                        error,
                        b"client TUN setup failed",
                    )
                    .await,
                );
            }
        };
    let tun_activation_ready = client_tun_activation_ready(
        tun_enable,
        tun_rx.is_some(),
        tun_writer.is_some(),
        tun_reader_shutdown.is_some(),
        tun_reader_handle.is_some(),
    );
    // TUN frame held when the QUIC DATAGRAM queue is full so a backpressured
    // packet is not dropped before carrier acceptance.
    let mut tun_backpressure_frame: Option<quicfuscate::interface::TunPacket> = None;
    let mut dns_runtime: Option<quicfuscate::implementations::client::ClientDnsRuntime> = None;
    let mut housekeeping = interval(Duration::from_millis(5));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut next_stats_log = tokio::time::Instant::now();
    let heartbeat_probe_interval = heartbeat_probe_interval(heartbeat_timeout_ms);
    let mut next_heartbeat_probe =
        heartbeat_probe_interval.map(|interval| tokio::time::Instant::now() + interval);
    let mut io_diagnostics =
        client_receive_diagnostics_enabled.then(ClientIoDiagnostics::default);
    let mut last_runtime_progress = std::time::Instant::now();
    let shutdown_signal = wait_shutdown_signal();
    tokio::pin!(shutdown_signal);

    let exit_reason = loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                if let Err(e) = conn.conn.close(true, 0x0, b"shutdown") {
                    warn!("Client close on shutdown failed: {:?}", e);
                }
                if let Err(e) = flush_connected_outgoing(
                    &socket,
                    &mut conn,
                    &mut out,
                    io_diagnostics.as_mut(),
                )
                .await
                {
                    warn!("Client shutdown frame flush failed: {}", e);
                }
                break ExitReason::CleanShutdown;
            }
            recv_res = recv_connected_datagram(&socket, &mut buf) => {
                if let Some(fault) = tun_reader_fault.as_ref().and_then(|slot| slot.lock().clone()) {
                    break ExitReason::DataPlane(fault);
                }
                let branch_started = std::time::Instant::now();
                let scheduling_gap = branch_started.duration_since(last_runtime_progress);
                if client_receive_diagnostics_enabled
                    && scheduling_gap >= Duration::from_millis(250)
                {
                    info!(
                        "Client runtime resumed: branch=udp-recv scheduling_gap_ms={}",
                        scheduling_gap.as_millis()
                    );
                }
                last_runtime_progress = branch_started;
                match recv_res {
                    Ok(len) => {
                        telemetry!(quicfuscate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        let activity_before = io_diagnostics
                            .as_ref()
                            .map(|_| conn.conn.last_activity_marker());
                        if let Some(diagnostics) = io_diagnostics.as_mut() {
                            diagnostics.record_socket_datagram(len);
                        }
                        match conn.recv(&buf[..len]) {
                            Err(error @ (quicfuscate::error::ConnectionError::TlsError(_)
                                | quicfuscate::error::ConnectionError::TlsAlert(_)
                                | quicfuscate::error::ConnectionError::PeerCertificateUnsupported)) => {
                                if let Some(diagnostics) = io_diagnostics.as_mut() {
                                    diagnostics.record_core_recv_error();
                                }
                                error!("TLS handshake failed: {}", error);
                                break ExitReason::SocketError(error.to_string());
                            }
                            Err(error) => {
                                if let Some(diagnostics) = io_diagnostics.as_mut() {
                                    diagnostics.record_core_recv_error();
                                }
                                error!("QUIC recv failed: {:?}", error);
                            }
                            Ok(_) => {
                                if let (Some(diagnostics), Some(before)) =
                                    (io_diagnostics.as_mut(), activity_before)
                                {
                                    diagnostics.record_core_recv_success(
                                        conn.conn.last_activity_marker() != before,
                                    );
                                }
                                if let Err(error) =
                                    flush_connected_outgoing(
                                        &socket,
                                        &mut conn,
                                        &mut out,
                                        io_diagnostics.as_mut(),
                                    )
                                    .await
                                {
                                    break ExitReason::DataPlane(error);
                                }
                            }
                        }
                        // TUN uplink: forward frames from the TUN reader channel
                        // to the MASQUE data plane. This is done here (in the recv
                        // branch) rather than in the housekeeping branch because
                        // tokio::select! is not fair: when the peer constantly sends
                        // packets, the recv branch is always ready first and the
                        // housekeeping tick may never fire, starving the TUN uplink.
                        if tun_enable && conn.masque_tunnel_established() {
                            if let (Some(ref rx), Some(sid), Some(ref tun)) = (&tun_rx, h3_stream_id, &tun_writer) {
                                let more_tun = match drain_client_tun_uplink(
                                    &mut conn,
                                    tun,
                                    sid,
                                    rx,
                                    &mut tun_backpressure_frame,
                                    client_receive_diagnostics_enabled,
                                ) {
                                    Ok(more_tun) => more_tun,
                                    Err(fault) => break ExitReason::DataPlane(fault),
                                };
                                if more_tun {
                                    tun_notify.notify_one();
                                }
                            }
                            // Flush any outgoing packets generated by the body chunk sends.
                            let flush_started = std::time::Instant::now();
                            if let Err(e) = flush_connected_outgoing(
                                &socket,
                                &mut conn,
                                &mut out,
                                io_diagnostics.as_mut(),
                            )
                            .await
                            {
                                break ExitReason::DataPlane(e);
                            }
                            let flush_elapsed = flush_started.elapsed();
                            if client_receive_diagnostics_enabled
                                && flush_elapsed >= Duration::from_millis(100)
                            {
                                info!(
                                    "Client runtime slow phase: branch=udp-recv phase=flush duration_ms={}",
                                    flush_elapsed.as_millis()
                                );
                            }
                        }
                        if conn.conn.is_closed() {
                            info!("Server closed the connection");
                            break ExitReason::RemoteClosed;
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                        break ExitReason::SocketError(e.to_string());
                    }
                }
                housekeeping.reset_after(client_housekeeping_delay(
                    &conn,
                    tun_writer.is_some(),
                    request_sent,
                    tun_backpressure_frame.is_some(),
                    next_heartbeat_probe,
                ));
            }
            _ = tun_notify.notified(), if tun_writer.is_some() => {
                if let Some(fault) = tun_reader_fault.as_ref().and_then(|slot| slot.lock().clone()) {
                    break ExitReason::DataPlane(fault);
                }
                let branch_started = std::time::Instant::now();
                let scheduling_gap = branch_started.duration_since(last_runtime_progress);
                if client_receive_diagnostics_enabled
                    && scheduling_gap >= Duration::from_millis(250)
                {
                    info!(
                        "Client runtime resumed: branch=tun-notify scheduling_gap_ms={}",
                        scheduling_gap.as_millis()
                    );
                }
                last_runtime_progress = branch_started;
                if conn.masque_tunnel_established() {
                    if let (Some(ref rx), Some(sid), Some(ref tun)) =
                        (&tun_rx, h3_stream_id, &tun_writer)
                    {
                        let more_tun = match drain_client_tun_uplink(
                            &mut conn,
                            tun,
                            sid,
                            rx,
                            &mut tun_backpressure_frame,
                            client_receive_diagnostics_enabled,
                        ) {
                            Ok(more_tun) => more_tun,
                            Err(fault) => break ExitReason::DataPlane(fault),
                        };
                        if more_tun {
                            tun_notify.notify_one();
                        }
                        if let Err(error) = flush_connected_outgoing(
                            &socket,
                            &mut conn,
                            &mut out,
                            io_diagnostics.as_mut(),
                        )
                        .await
                        {
                            break ExitReason::DataPlane(error);
                        }
                    }
                }
                housekeeping.reset_after(client_housekeeping_delay(
                    &conn,
                    tun_writer.is_some(),
                    request_sent,
                    tun_backpressure_frame.is_some(),
                    next_heartbeat_probe,
                ));
            }
            _ = housekeeping.tick() => {
                if let Some(fault) = tun_reader_fault.as_ref().and_then(|slot| slot.lock().clone()) {
                    break ExitReason::DataPlane(fault);
                }
                let branch_started = std::time::Instant::now();
                let scheduling_gap = branch_started.duration_since(last_runtime_progress);
                if client_receive_diagnostics_enabled
                    && scheduling_gap >= Duration::from_millis(250)
                {
                    info!(
                        "Client runtime resumed: branch=housekeeping scheduling_gap_ms={}",
                        scheduling_gap.as_millis()
                    );
                }
                last_runtime_progress = branch_started;
                if conn.conn.is_established()
                    && tun_enable
                    && !conn.masque_tunnel_established()
                {
                    if let Err(error) = conn.begin_masque_tunnel() {
                        warn!("MASQUE CONNECT-UDP open failed: {:?}", error);
                    }
                }

                if conn.conn.is_established() && !request_sent {
                    match conn.send_http3_request(target.request_path.as_str()) {
                        Ok(_) => {
                            request_sent = true;
                        }
                        Err(e) => {
                            warn!("HTTP/3 request failed: {:?}", e);
                        }
                    }
                }

                if tun_enable {
                    let poll_started = std::time::Instant::now();
                    if h3_stream_id.is_none() {
                        match conn.open_http3_stream_post("/tun") {
                            Ok(sid) => { h3_stream_id = Some(sid); }
                            Err(e) => { warn!("open_http3_stream_post failed: {:?}", e); }
                        }
                    }
                    // Downlink: H3 stream data from server → TUN interface
                    let tun_writer_ref = tun_writer.clone();
                    let tun_fault_for_h3 = tun_reader_fault.clone();
                    let tun_notify_for_h3 = Arc::clone(&tun_notify);
                    let shutdown_for_h3 = tun_reader_shutdown.clone();
                    if let Err(e) = conn.poll_http3_with(move |data| {
                        if let Some(ref tw) = tun_writer_ref {
                            // Only write to TUN if the data looks like a valid IP packet.
                            if !data.is_empty() && (data[0] >> 4 == 4 || data[0] >> 4 == 6) {
                                if let Err(e) = tw.write(data) {
                                    warn!("Client TUN write (H3 downlink) failed: {:?}", e);
                                    if let (Some(fault_slot), Some(shutdown)) =
                                        (tun_fault_for_h3.as_ref(), shutdown_for_h3.as_ref())
                                    {
                                        record_standalone_client_tun_fault(
                                            fault_slot,
                                            &tun_notify_for_h3,
                                            shutdown,
                                            quicfuscate::engine::DataPlaneFault::TunWrite {
                                                component: "standalone client HTTP/3 downlink".to_string(),
                                                error: e.to_string(),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    }) {
                        warn!("HTTP/3 poll in TUN mode failed: {:?}", e);
                    }
                    // MASQUE CONNECT-UDP downlink datagrams are drained and written
                    // to the TUN by drain_masque_datagrams (inside poll_http3_with
                    // above) via the masque_datagram_cb sink installed at TUN open.
                    // The previous bare dgram_recv loop expected unframed QUIC
                    // datagrams and has been removed in favor of the single
                    // consistent MASQUE transport.

                    // TUN uplink: forward frames from the TUN reader channel to
                    // the MASQUE data plane. Also done in the recv branch above,
                    // but tokio::select! is not fair and the recv branch may not
                    // fire when the server is silent. TUN reader notifications
                    // wake the event loop immediately; the adaptive tick remains
                    // as a bounded retry path for transport progress.
                    if conn.masque_tunnel_established() {
                        if let (Some(ref rx), Some(sid), Some(ref tun)) = (&tun_rx, h3_stream_id, &tun_writer) {
                            let more_tun = match drain_client_tun_uplink(
                                &mut conn,
                                tun,
                                sid,
                                rx,
                                &mut tun_backpressure_frame,
                                client_receive_diagnostics_enabled,
                            ) {
                                Ok(more_tun) => more_tun,
                                Err(fault) => break ExitReason::DataPlane(fault),
                            };
                            if more_tun {
                                tun_notify.notify_one();
                            }
                        }
                    }
                    let poll_elapsed = poll_started.elapsed();
                    if client_receive_diagnostics_enabled
                        && poll_elapsed >= Duration::from_millis(100)
                    {
                        info!(
                            "Client runtime slow phase: branch=housekeeping phase=http3-and-tun duration_ms={}",
                            poll_elapsed.as_millis()
                        );
                    }
                } else if let Err(e) = conn.poll_http3() {
                    warn!("HTTP/3 error: {:?}", e);
                }

                // Connected policy means the authenticated tunnel data plane is
                // ready, not merely that QUIC completed its handshake.
                let reader_failed = tun_reader_fault
                    .as_ref()
                    .is_some_and(|slot| slot.lock().is_some());
                let data_plane_ready = conn.conn.is_established()
                    && tun_activation_ready
                    && !reader_failed
                    && (!tun_enable || conn.masque_tunnel_established());
                if data_plane_ready && !kill_switch_connected {
                    let policy_started = std::time::Instant::now();
                    if let Some(ref ks) = kill_switch {
                        if let Err(error) = ks.on_vpn_connected(&connected_firewall_policy) {
                            break ExitReason::SocketError(format!(
                                "kill switch connected policy failed: {error}"
                            ));
                        }
                        info!("Kill switch: VPN traffic allowed, non-VPN blocked");
                    }
                    kill_switch_connected = true;
                    if tun_enable && !disable_doh {
                        let Some(tun) = tun_writer.as_ref() else {
                            break ExitReason::SocketError(
                                "client DoH requires an active TUN interface".to_string(),
                            );
                        };
                        let Some(proxy_config) = prepared_dns.take() else {
                            break ExitReason::SocketError(
                                "client DoH configuration was not prepared".to_string(),
                            );
                        };
                        let dns_start =
                            quicfuscate::implementations::client::ClientDnsRuntime::start_with_config(
                                &tokio::runtime::Handle::current(),
                                proxy_config,
                                tun.name(),
                            );
                        match dns_start {
                            Ok(proxy) => {
                                dns_runtime = Some(proxy);
                                info!("Client DoH DNS proxy activated for the standalone TUN runtime");
                            }
                            Err(error) => {
                                break ExitReason::SocketError(format!(
                                    "client DoH DNS proxy activation failed: {error}"
                                ));
                            }
                        }
                    }
                    if client_receive_diagnostics_enabled {
                        info!(
                            "Client runtime phase: connected-firewall duration_ms={}",
                            policy_started.elapsed().as_millis()
                        );
                    }
                }

                let now = tokio::time::Instant::now();
                if conn.conn.is_established()
                    && heartbeat_probe_interval.is_some()
                    && next_heartbeat_probe.is_some_and(|deadline| now >= deadline)
                {
                    conn.queue_keepalive_ping();
                    next_heartbeat_probe =
                        heartbeat_probe_interval.map(|interval| now + interval);
                }
                let flush_started = std::time::Instant::now();
                if let Err(e) = flush_connected_outgoing(
                    &socket,
                    &mut conn,
                    &mut out,
                    io_diagnostics.as_mut(),
                )
                .await
                {
                    break ExitReason::DataPlane(e);
                }
                let flush_elapsed = flush_started.elapsed();
                if client_receive_diagnostics_enabled
                    && flush_elapsed >= Duration::from_millis(100)
                {
                    info!(
                        "Client runtime slow phase: branch=housekeeping phase=flush duration_ms={}",
                        flush_elapsed.as_millis()
                    );
                }

                let update_started = std::time::Instant::now();
                if client_receive_diagnostics_enabled {
                    conn.update_state_with_slow_phase_diagnostics();
                } else {
                    conn.update_state();
                }
                let update_elapsed = update_started.elapsed();
                if client_receive_diagnostics_enabled
                    && update_elapsed >= Duration::from_millis(100)
                {
                    info!(
                        "Client runtime slow phase: branch=housekeeping phase=update-state duration_ms={}",
                        update_elapsed.as_millis()
                    );
                }
                if let Some(tun) = tun_writer.as_ref() {
                    if let Err(error) =
                        synchronize_client_tun_mtu(&conn, tun, negotiated_tun_mtu)
                    {
                        break ExitReason::SocketError(format!(
                            "client TUN MTU synchronization failed: {error}"
                        ));
                    }
                }
                if now >= next_stats_log {
                    info!(
                        "client stats: RTT {:.0} ms, Loss {:.2}%",
                        conn.rtt_ms(),
                        conn.loss_rate() * 100.0
                    );
                    next_stats_log = now + Duration::from_secs(1);
                }
                // Only drive the idle timeout when the connection has actually been
                // idle; calling it every tick collapses cwnd and inflates loss.
                if conn.conn.idle_timeout_elapsed() {
                    conn.conn.on_timeout();
                }
                if conn.conn.is_established()
                    && heartbeat_timeout_ms > 0
                    && conn.conn.last_activity_elapsed()
                        >= Duration::from_millis(heartbeat_timeout_ms)
                {
                    if let Some(diagnostics) = io_diagnostics.as_ref() {
                        let diagnostic_now = std::time::Instant::now();
                        let protocol_now = conn.protocol_clock().now();
                        warn!(
                            "Client receive diagnostics at heartbeat: socket_datagrams={}, socket_bytes={}, core_recv_successes={}, core_recv_errors={}, activity_updates={}, send_polls={}, send_datagrams={}, send_bytes={}, send_zero_results={}, send_done_results={}, send_errors={}, last_send_elapsed_ms={:?}, request_sent={}, h3_stream_id={:?}, masque_established={}, kill_switch_connected={}, transport_sent={}, transport_recv={}, transport_lost={}, transport_dgram_queue={}, transport_bytes_in_flight={}, transport_cwnd={}, pending_application_ack={}, outbound_release_remaining_ms={:?}, recovery_remaining_ms={:?}, last_activity_elapsed_ms={}",
                            diagnostics.socket_datagrams,
                            diagnostics.socket_bytes,
                            diagnostics.core_recv_successes,
                            diagnostics.core_recv_errors,
                            diagnostics.activity_updates,
                            diagnostics.send_polls,
                            diagnostics.send_datagrams,
                            diagnostics.send_bytes,
                            diagnostics.send_zero_results,
                            diagnostics.send_done_results,
                            diagnostics.send_errors,
                            diagnostics
                                .last_send_at
                                .map(|sent_at| diagnostic_now.saturating_duration_since(sent_at).as_millis()),
                            request_sent,
                            h3_stream_id,
                            conn.masque_tunnel_established(),
                            kill_switch_connected,
                            conn.conn.stats().sent,
                            conn.conn.stats().recv,
                            conn.conn.stats().lost,
                            conn.conn.dgram_send_queue_len(),
                            conn.conn.bytes_in_flight(),
                            conn.conn.cwnd(),
                            conn.conn.has_pending_application_ack(),
                            conn.next_outbound_release_deadline().map(|deadline| {
                                deadline.saturating_duration_since(protocol_now).as_millis()
                            }),
                            conn.conn.recovery_deadline().map(|deadline| {
                                deadline.saturating_duration_since(protocol_now).as_millis()
                            }),
                            conn.conn.last_activity_elapsed().as_millis(),
                        );
                    }
                    warn!(
                        "Client heartbeat timeout after {}ms; activating fail-closed firewall state",
                        heartbeat_timeout_ms
                    );
                    break ExitReason::HeartbeatTimeout;
                }
                if conn.conn.is_closed() {
                    break ExitReason::RemoteClosed;
                }
                housekeeping.reset_after(client_housekeeping_delay(
                    &conn,
                    tun_writer.is_some(),
                    request_sent,
                    tun_backpressure_frame.is_some(),
                    next_heartbeat_probe,
                ));
            }
        }
    };

    let dns_shutdown_error = if let Some(mut dns_runtime) = dns_runtime.take() {
        dns_runtime
            .stop_async()
            .await
            .err()
            .map(|error| format!("client DNS proxy shutdown failed: {error}"))
    } else {
        None
    };

    // Publish cooperative shutdown before dropping the receiver so the reader
    // can distinguish deliberate teardown from an unexpected channel close.
    let tun_reader_shutdown_error = tun_writer.as_ref().and_then(|tun| {
        tun.request_reader_shutdown()
            .err()
            .map(|error| format!("client TUN reader wake failed: {error}"))
    });
    if let Some(shutdown) = tun_reader_shutdown.as_ref() {
        shutdown.store(true, Ordering::Release);
    }
    // Dropping the receiver unblocks a reader waiting for capacity in the
    // bounded channel. Wake any native backend wait before joining the owned
    // reader handle.
    drop(tun_rx);
    let tun_reader_error = tun_reader_handle.take().and_then(|handle| {
        handle
            .join()
            .err()
            .map(|_| "client TUN reader thread panicked".to_string())
    });
    let stealth_shutdown_error = stealth_runtime
        .shutdown(quicfuscate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT)
        .await
        .err();
    let kill_switch_error = if let Some(ref ks) = kill_switch {
        if dns_shutdown_error.is_some() {
            ks.on_vpn_disconnected().err().map(|error| {
                format!("kill switch fail-closed transition after DNS restore failure failed: {error}")
            })
        } else {
            match &exit_reason {
                ExitReason::CleanShutdown => ks
                    .disable()
                    .err()
                    .map(|error| format!("kill switch cleanup on clean shutdown failed: {error}")),
                _ => ks.on_vpn_disconnected().err().map(|error| {
                    format!("kill switch fail-closed transition failed: {error}")
                }),
            }
        }
    } else {
        None
    };
    let mut cleanup_errors = Vec::new();
    if let Some(error) = stealth_shutdown_error {
        cleanup_errors.push(format!("stealth runtime shutdown failed: {error}"));
    }
    if let Some(error) = kill_switch_error {
        cleanup_errors.push(error);
    }
    if let Some(error) = dns_shutdown_error {
        cleanup_errors.push(error);
    }
    if let Some(error) = tun_reader_error {
        cleanup_errors.push(error);
    }
    if let Some(error) = tun_reader_shutdown_error {
        cleanup_errors.push(error);
    }
    let primary_error = match exit_reason {
        ExitReason::CleanShutdown => None,
        ExitReason::RemoteClosed => Some(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "VPN server closed the connection; firewall remains fail-closed",
        )),
        ExitReason::HeartbeatTimeout => Some(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "VPN heartbeat timed out; firewall remains fail-closed",
        )),
        ExitReason::DataPlane(fault) => Some(std::io::Error::other(format!(
            "VPN data plane failed; firewall remains fail-closed: {fault}"
        ))),
        ExitReason::SocketError(error) => Some(std::io::Error::other(format!(
            "VPN socket failed; firewall remains fail-closed: {error}"
        ))),
    };
    if cleanup_errors.is_empty() {
        return primary_error.map_or(Ok(()), Err);
    }
    let cleanup_error = cleanup_errors.join("; ");
    match primary_error {
        Some(primary) => Err(std::io::Error::new(
            primary.kind(),
            format!("{primary}; client cleanup failed: {cleanup_error}"),
        )),
        None => Err(std::io::Error::other(cleanup_error)),
    }
}

fn heartbeat_probe_interval(heartbeat_timeout_ms: u64) -> Option<Duration> {
    (heartbeat_timeout_ms > 0).then(|| Duration::from_millis((heartbeat_timeout_ms / 3).max(1)))
}
