use super::runtime::{
    apply_runtime_transport_defaults, apply_standalone_tun_server_config, load_runtime_profiles,
    new_runtime_transport_config, runtime_optimize_config,
};
use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_server(
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
    admin_web_max_connections: usize,
    admin_web_operation_timeout_ms: u64,
    admin_web_root: PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    qkey_ttl_secs: Option<u64>,
    qkey_store: Option<PathBuf>,
    allow_client_to_client: bool,
    no_drop_privileges: bool,
    drop_user: &str,
    drop_group: &str,
    audit_log_path: Option<PathBuf>,
    startup_engine_config: Option<quicfuscate::engine::EngineConfig>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    let config_path_ref = config_path.map(PathBuf::as_path);
    quicfuscate::implementations::server::validate_admin_web_max_connections(
        admin_web_max_connections,
    )?;
    quicfuscate::implementations::server::validate_admin_web_operation_timeout_ms(
        admin_web_operation_timeout_ms,
    )?;
    let cli_profile = FingerprintProfile::try_new(profile, os).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid profile/OS selection: {error}"),
        )
    })?;
    #[cfg(not(target_os = "linux"))]
    let _ = (no_drop_privileges, drop_user, drop_group);

    #[cfg(target_os = "linux")]
    let privilege_target = if no_drop_privileges {
        None
    } else {
        Some(quicfuscate::privilege::resolve_identity(drop_user, drop_group).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("privilege target preflight failed: {error}"),
            )
        })?)
    };
    #[cfg(not(target_os = "linux"))]
    let privilege_target: Option<quicfuscate::privilege::ResolvedIdentity> = None;

    #[cfg(target_os = "linux")]
    let privilege_requirements = {
        let listen_port = listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid server listen address: {error}"),
                )
            })?
            .port();
        quicfuscate::privilege::CapabilityRequirements {
            tun: tun_enable,
            privileged_bind: listen_port < 1024,
            privilege_finalize: privilege_target.is_some(),
            audit_owner: privilege_target.is_some() && audit_log_path.is_some(),
        }
    };
    #[cfg(target_os = "linux")]
    {
        let initial = quicfuscate::privilege::try_check_capabilities(
            privilege_target.as_ref(),
            privilege_requirements,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        quicfuscate::privilege::validate_startup_capabilities(&initial, privilege_requirements)
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
            })?;
        if privilege_target.is_some() && !initial.can_drop {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "privilege target does not match the current identity and process is not root",
            ));
        }
    }

    let requested_firewall_backend =
        startup_engine_config.as_ref().and_then(|config| config.security.firewall.backend);
    let firewall_backend = if tun_enable {
        quicfuscate::firewall::resolve_backend(requested_firewall_backend)
            .map_err(|error| std::io::Error::other(error.to_string()))?
    } else {
        requested_firewall_backend.unwrap_or_default()
    };
    let mut server_config = quicfuscate::implementations::server::server_config_from_listen_addr(
        listen_addr,
        firewall_backend,
    )
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

    // Initialize the global audit log (TODO-515).
    let audit_config =
        startup_engine_config.as_ref().map(|config| config.audit.clone()).unwrap_or_default();
    quicfuscate::audit::init_audit_log_with_options(
        audit_log_path.clone(),
        privilege_target.as_ref().map(|identity| (identity.uid(), identity.gid())),
        audit_config.to_audit_options(),
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let _audit_flush_guard = quicfuscate::audit::AuditFlushGuard::new();
    quicfuscate::audit::audit_typed(
        quicfuscate::audit::AuditEventType::ServerStarted,
        quicfuscate::audit::AuditSeverity::Info,
        None,
        None,
        quicfuscate::audit::AuditContext {
            actor: quicfuscate::audit::AuditActor::System,
            target: quicfuscate::audit::AuditTarget::Server,
            outcome: quicfuscate::audit::AuditOutcome::Started,
            reason: None,
        },
        &format!("Server starting on {listen_addr}"),
    );

    let (fec_cfg, mut stealth_cfg, opt_cfg, anti_replay_section) =
        load_runtime_profiles(config_path, fec_config, fec_mode)?;

    // Reuse the configuration validated before global logger and runtime setup.
    let engine_cfg_opt = startup_engine_config;

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
    }

    // Apply the shared memory-lock policy before TLS identity loading. Linux
    // process-wide locking is deferred until after a configured UID/GID drop:
    // carrying MCL_CURRENT mappings through glibc's multi-threaded setxid
    // broadcast is not safe on the production ARM64 runtime.
    let memory_lock_policy = engine_cfg_opt
        .as_ref()
        .map(|cfg| quicfuscate::memory_lock::MemoryLockPolicy::from_security(&cfg.security))
        .unwrap_or_default();
    let defer_process_memory_lock =
        cfg!(target_os = "linux") && privilege_target.is_some() && memory_lock_policy.lock_memory;
    memory_lock_policy.apply_before_tls_identity(defer_process_memory_lock).map_err(|error| {
        std::io::Error::other(format!("server memory-lock startup failed: {error}"))
    })?;

    let mut config = match new_runtime_transport_config() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create server transport config: {}", e);
            return Err(std::io::Error::other("server transport config init failed"));
        }
    };
    apply_runtime_transport_defaults(&mut config, cc_algorithm);
    quicfuscate::implementations::server::load_server_identity(
        &mut config,
        cert_path,
        key_path,
        memory_lock_policy.lock_memory,
    )?;

    if let Some(cfg_path) = config_path.as_ref() {
        quicfuscate::implementations::server::apply_transport_overrides_from_file(
            cfg_path,
            &mut config,
        )
        .map_err(std::io::Error::other)?;
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
                .map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid profile sequence: {error}"),
                    )
                })?
        }
        None => {
            let configured = stealth_cfg.rotation_profiles();
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

    let (effective_profile, effective_os) = if profile_seq.is_some() {
        let first = profiles.first().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--profile-seq must contain at least one profile",
            )
        })?;
        (first.browser, first.os)
    } else {
        (profile, os)
    };
    let rotation_interval = if profile_seq.is_some() {
        profile_interval
    } else {
        stealth_cfg.fingerprint_rotation_interval
    };
    if profile_seq.is_some() {
        stealth_cfg.fingerprint_rotation_profiles =
            profiles.iter().map(|profile| (profile.browser, profile.os)).collect();
        stealth_cfg.fingerprint_rotation_mode = quicfuscate::stealth::RotationMode::Slots;
        stealth_cfg.enable_fingerprint_rotation = profiles.len() > 1 && rotation_interval > 0;
        stealth_cfg.fingerprint_rotation_interval = rotation_interval;
    }

    let standalone_tun_config = if tun_enable {
        Some(quicfuscate::interface::TunConfig {
            name: tun_name,
            // Consume the values `apply_standalone_tun_server_config` already parsed and
            // validated instead of parsing the strings a second time. Reparsing here with
            // `parse().ok()` turned any error into an absent field, and duplicating the
            // boundary let the two paths drift apart. Presence still follows the flag, so
            // an unsupplied address keeps the platform default.
            ip: tun_ip.map(|_| std::net::IpAddr::V4(server_config.server_ip)),
            netmask: tun_netmask.map(|_| std::net::IpAddr::V4(server_config.server_netmask)),
            mtu: tun_mtu.unwrap_or(1500),
            ip6: server_config.ipv6_server_ip,
            prefix6: server_config.ipv6_server_ip.map(|_| server_config.ipv6_prefix_len),
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
    runtime.standalone_metrics().set_memory_lock_status(quicfuscate::memory_lock::current_status());
    let fec_mode_override = fec_mode;
    let mut launch =
        quicfuscate::implementations::server::PreparedStandaloneLaunch::new_with_runtime_stealth(
            metrics_port,
            admin_socket,
            admin_web,
            admin_web_max_connections,
            admin_web_operation_timeout_ms,
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
            rotation_interval,
            quicfuscate::implementations::server::RuntimeStealthPolicy {
                profile: effective_profile,
                os: effective_os,
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
    #[cfg(target_os = "linux")]
    if let Some(identity) = privilege_target.as_ref() {
        info!(
            "Finalizing process privileges as {}:{} (uid={}, gid={})",
            identity.user_name(),
            identity.group_name(),
            identity.uid(),
            identity.gid()
        );
        let drop_identity = identity.clone();
        let finalization = tokio::task::spawn_blocking(move || {
            let report = quicfuscate::privilege::drop_privileges_resolved(&drop_identity)?;
            let verified_threads =
                quicfuscate::privilege::verify_process_privilege_state(&drop_identity)?;
            Ok::<_, quicfuscate::privilege::DropError>((report, verified_threads))
        })
        .await
        .map_err(|error| {
            std::io::Error::other(format!("privilege finalization worker failed: {error}"))
        })?;
        match finalization {
            Ok((report, verified_threads)) => {
                if defer_process_memory_lock {
                    let status = memory_lock_policy.apply_deferred_process_memory_lock().map_err(
                        |error| {
                            std::io::Error::other(format!(
                                "deferred server memory-lock startup failed: {error}"
                            ))
                        },
                    )?;
                    runtime.standalone_metrics().set_memory_lock_status(status);
                }
                info!(
                    "Privileges finalized across {} threads: uid={}/{}/{:?}, gid={}/{}/{:?}, capabilities=0, no_new_privileges=true",
                    verified_threads,
                    report.real_uid,
                    report.effective_uid,
                    report.saved_uid,
                    report.real_gid,
                    report.effective_gid,
                    report.saved_gid
                );
                quicfuscate::audit::audit_typed(
                    quicfuscate::audit::AuditEventType::PrivilegesDropped,
                    quicfuscate::audit::AuditSeverity::Info,
                    None,
                    None,
                    quicfuscate::audit::AuditContext {
                        actor: quicfuscate::audit::AuditActor::System,
                        target: quicfuscate::audit::AuditTarget::System,
                        outcome: quicfuscate::audit::AuditOutcome::Succeeded,
                        reason: Some("configured_identity_applied"),
                    },
                    &format!(
                        "Privileges irreversibly reduced to uid={} gid={}",
                        identity.uid(),
                        identity.gid()
                    ),
                );
                if tun_enable {
                    log::warn!(
                        "Post-drop TUN descriptors remain active; host routing teardown is owned by the service manager or privileged orchestration layer"
                    );
                }
            }
            Err(error) => {
                error!("Privilege finalization failed: {error} - refusing service exposure");
                quicfuscate::audit::audit_typed(
                    quicfuscate::audit::AuditEventType::PrivilegeDropFailed,
                    quicfuscate::audit::AuditSeverity::Critical,
                    None,
                    None,
                    quicfuscate::audit::AuditContext {
                        actor: quicfuscate::audit::AuditActor::System,
                        target: quicfuscate::audit::AuditTarget::System,
                        outcome: quicfuscate::audit::AuditOutcome::Failed,
                        reason: Some("privilege_finalization_failed"),
                    },
                    &format!("Privilege finalization failed: {error}"),
                );
                return Err(std::io::Error::other("privilege finalization failed"));
            }
        }
    }

    let runtime_result = runtime.run_standalone(Box::new(launch)).await;
    let (severity, message) = match &runtime_result {
        Ok(()) => {
            (quicfuscate::audit::AuditSeverity::Info, "Server runtime stopped cleanly".to_string())
        }
        Err(error) => (
            quicfuscate::audit::AuditSeverity::Critical,
            format!("Server runtime stopped with error: {error}"),
        ),
    };
    let stop_context = match &runtime_result {
        Ok(()) => quicfuscate::audit::AuditContext {
            actor: quicfuscate::audit::AuditActor::System,
            target: quicfuscate::audit::AuditTarget::Server,
            outcome: quicfuscate::audit::AuditOutcome::Stopped,
            reason: Some("runtime_completed"),
        },
        Err(_) => quicfuscate::audit::AuditContext {
            actor: quicfuscate::audit::AuditActor::System,
            target: quicfuscate::audit::AuditTarget::Server,
            outcome: quicfuscate::audit::AuditOutcome::Failed,
            reason: Some("runtime_failed"),
        },
    };
    quicfuscate::audit::audit_typed(
        quicfuscate::audit::AuditEventType::ServerStopped,
        severity,
        None,
        None,
        stop_context,
        &message,
    );
    let flush_result =
        quicfuscate::audit::flush().map_err(|error| std::io::Error::other(error.to_string()));
    match (runtime_result, flush_result) {
        (Err(runtime_error), _) => Err(runtime_error),
        (Ok(()), Err(audit_error)) => Err(audit_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}
