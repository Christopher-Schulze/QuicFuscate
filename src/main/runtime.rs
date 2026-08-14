use super::*;

#[path = "runtime/client.rs"]
mod client;
use client::run_client;

#[cfg(target_os = "windows")]
const WINDOWS_APPLICATION_STACK_BYTES: usize = 8 * 1024 * 1024;

#[cfg(target_os = "windows")]
pub(super) fn application_entry() -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("quicfuscate-main".to_string())
        .stack_size(WINDOWS_APPLICATION_STACK_BYTES)
        .spawn(application_main)?
        .join()
        .map_err(|_| std::io::Error::other("QuicFuscate application thread panicked"))?
}

#[cfg(not(target_os = "windows"))]
pub(super) fn application_entry() -> std::io::Result<()> {
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
    let mut logging_config =
        startup_engine_config.as_ref().map(|config| config.logging.effective()).unwrap_or_default();
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
    let admin_log_buffer =
        Arc::new(quicfuscate::implementations::server::admin_logs::AdminLogBuffer::new(
            logging_config.ring_buffer_capacity,
        ));
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
                &shared.vpn_dns,
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
                target.error.as_ref().map_or(serde_json::Value::Null, |error| {
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
            target.error.as_ref().map_or(String::new(), |error| format!(" error={error}"))
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

pub(super) fn load_runtime_profiles(
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

pub(super) fn apply_runtime_transport_defaults(
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

pub(super) fn new_runtime_transport_config(
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

pub(super) fn runtime_optimize_config(
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

pub(super) fn derive_client_pool_for_tun(
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

pub(super) fn apply_standalone_tun_server_config(
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

pub(super) fn client_packet_too_big_response(packet: &[u8], tunnel_mtu: usize) -> Vec<u8> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClientTunPacketDisposition {
    Tunnel,
    RespondPacketTooBig { mtu: usize },
}

pub(super) fn classify_client_tun_packet(
    packet_len: usize,
    carrier_mtu: usize,
) -> ClientTunPacketDisposition {
    if packet_len <= carrier_mtu {
        ClientTunPacketDisposition::Tunnel
    } else {
        ClientTunPacketDisposition::RespondPacketTooBig { mtu: carrier_mtu }
    }
}

fn send_client_tun_packet(
    conn: &mut QuicFuscateConnection,
    tun: &quicfuscate::interface::TunInterface,
    stream_id: u64,
    packet: &[u8],
) -> Result<ClientTunPacketDisposition, ClientTunPacketError> {
    let disposition = classify_client_tun_packet(packet.len(), conn.effective_tunnel_mtu());
    match disposition {
        ClientTunPacketDisposition::Tunnel => {
            conn.send_tunnel_packet(stream_id, packet).map_err(|error| match error {
                ConnectionError::DgramQueueFull => ClientTunPacketError::Backpressure,
                error => ClientTunPacketError::Fault(
                    quicfuscate::engine::DataPlaneFault::TransportSend {
                        component: "standalone client TUN uplink".to_string(),
                        error: error.to_string(),
                    },
                ),
            })?;
        }
        ClientTunPacketDisposition::RespondPacketTooBig { mtu } => {
            let response = client_packet_too_big_response(packet, mtu);
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
        }
    }
    Ok(disposition)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InitialClientPacketEvidence {
    pub(super) constructed_bytes: usize,
    pub(super) sent_bytes: usize,
}

pub(super) fn initial_client_packet_constructed(
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

pub(super) fn initial_client_packet_sent(
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

pub(super) fn client_startup_error_with_cleanup(
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
    if let Err(error) =
        stealth_runtime.shutdown(quicfuscate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT).await
    {
        cleanup_errors.push(format!("stealth runtime shutdown failed: {error}"));
    }
    client_startup_error_with_cleanup(primary, cleanup_errors)
}

pub(super) fn spawn_client_tun_reader(
    spawn: impl FnOnce(
        Box<dyn FnOnce() + Send + 'static>,
    ) -> std::io::Result<std::thread::JoinHandle<()>>,
    reader: impl FnOnce() + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    spawn(Box::new(reader))
        .map_err(|error| std::io::Error::other(format!("client TUN reader spawn failed: {error}")))
}

pub(super) fn client_tun_activation_ready(
    tun_enable: bool,
    has_receiver: bool,
    has_writer: bool,
    has_shutdown: bool,
    has_reader: bool,
) -> bool {
    !tun_enable || (has_receiver && has_writer && has_shutdown && has_reader)
}

pub(super) fn record_standalone_client_tun_fault(
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
            Ok(ClientTunPacketDisposition::Tunnel) => {
                if diagnostics_enabled {
                    info!("Client Wintun backlog accepted by MASQUE uplink: bytes={frame_len}");
                }
            }
            Ok(ClientTunPacketDisposition::RespondPacketTooBig { mtu }) => {
                if diagnostics_enabled {
                    info!(
                        "Client Wintun backlog answered locally above tunnel carrier: bytes={frame_len} mtu={mtu}"
                    );
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
                    Ok(ClientTunPacketDisposition::Tunnel) => {
                        if diagnostics_enabled {
                            info!(
                                "Client Wintun packet accepted by MASQUE uplink: bytes={frame_len}"
                            );
                        }
                    }
                    Ok(ClientTunPacketDisposition::RespondPacketTooBig { mtu }) => {
                        if diagnostics_enabled {
                            info!(
                                "Client Wintun packet answered locally above tunnel carrier: bytes={frame_len} mtu={mtu}"
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

    // The canonical connection deadline owns pacing, stealth, recovery, and
    // traffic-analysis scheduling in one protocol clock domain. Only the
    // resulting duration crosses into Tokio.
    let now = conn.protocol_clock().now();
    let mut delay = CLIENT_HOUSEKEEPING_IDLE;
    if let Some(deadline) = conn.next_send_deadline() {
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
pub(super) enum ClientTargetSource {
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
pub(super) struct ClientTarget {
    pub(super) source: ClientTargetSource,
    pub(super) host: String,
    pub(super) authority: String,
    pub(super) port: u16,
    pub(super) request_path: String,
    pub(super) transport_destination: std::net::SocketAddr,
    pub(super) alternate_transport_ip: Option<IpAddr>,
}

fn invalid_client_target(reason: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid client URL: {reason}"))
}

pub(super) fn resolve_client_target(
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

pub(super) fn load_client_ca_file(
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

pub(super) fn heartbeat_probe_interval(heartbeat_timeout_ms: u64) -> Option<Duration> {
    (heartbeat_timeout_ms > 0).then(|| Duration::from_millis((heartbeat_timeout_ms / 3).max(1)))
}
