use super::*;

async fn run_circuit_client(
    config_path: &Path,
    config: quicfuscate::engine::EngineConfig,
) -> std::io::Result<()> {
    use quicfuscate::engine::{EngineState, QuicFuscateEngine};

    let mut engine = QuicFuscateEngine::new(config).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid circuit configuration {}: {error}", config_path.display()),
        )
    })?;
    engine
        .start()
        .map_err(|error| std::io::Error::other(format!("circuit engine start failed: {error}")))?;
    if let Err(error) = engine.connect() {
        let cleanup = engine.stop().err();
        return Err(std::io::Error::other(match cleanup {
            Some(cleanup) => {
                format!("circuit connection failed: {error}; cleanup failed: {cleanup}")
            }
            None => format!("circuit connection failed: {error}"),
        }));
    }

    info!("Circuit client connected from canonical engine configuration {}", config_path.display());
    let mut health_tick = interval(Duration::from_millis(250));
    health_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let shutdown_signal = wait_shutdown_signal();
    tokio::pin!(shutdown_signal);

    let runtime_error = loop {
        tokio::select! {
            _ = &mut shutdown_signal => break None,
            _ = health_tick.tick() => {
                match engine.service_connection_health() {
                    Ok(false) => {}
                    Ok(true) if engine.state() == EngineState::Connected => {
                        info!("Circuit health owner promoted a ready alternate generation");
                    }
                    Ok(true) => {
                        break Some(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "circuit failed without a ready alternate; traffic remains fail-closed",
                        ));
                    }
                    Err(error) => {
                        break Some(std::io::Error::other(format!(
                            "circuit health service failed: {error}"
                        )));
                    }
                }
            }
        }
    };

    let disconnect_error =
        (engine.state() == EngineState::Connected).then(|| engine.disconnect().err()).flatten();
    let stop_error = engine.stop().err();
    let cleanup_error = disconnect_error.or(stop_error);
    match (runtime_error, cleanup_error) {
        (None, None) => Ok(()),
        (Some(error), None) => Err(error),
        (None, Some(cleanup)) => {
            Err(std::io::Error::other(format!("circuit cleanup failed: {cleanup}")))
        }
        (Some(error), Some(cleanup)) => Err(std::io::Error::new(
            error.kind(),
            format!("{error}; circuit cleanup failed: {cleanup}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_client(
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

    if let Some(config_path) = config_path {
        let engine_config =
            quicfuscate::engine::EngineConfig::from_file(config_path).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid configuration {}: {error}", config_path.display()),
                )
            })?;
        if engine_config.circuit.is_some() {
            return run_circuit_client(config_path, engine_config).await;
        }
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
        Some(
            tokio::task::block_in_place(|| {
                quicfuscate::implementations::client::ClientDnsRuntime::prepare_endpoint(
                    doh_provider,
                )
            })
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
            })?,
        )
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
        stealth_config.fingerprint_rotation_profiles =
            profiles.iter().map(|profile| (profile.browser, profile.os)).collect();
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
            return Err(cleanup_client_startup_failure(
                &mut conn,
                &stealth_runtime,
                kill_switch.as_ref(),
                error,
                b"initial client handshake construction failed",
            )
            .await);
        }
    };
    let initial_packet = match initial_client_packet_sent(
        constructed_bytes,
        send_connected_datagram(&socket, &out[..constructed_bytes]).await,
    ) {
        Ok(evidence) => evidence,
        Err(error) => {
            error!("Initial client handshake send failed: {}", error);
            return Err(cleanup_client_startup_failure(
                &mut conn,
                &stealth_runtime,
                kill_switch.as_ref(),
                error,
                b"initial client handshake send failed",
            )
            .await);
        }
    };
    telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(initial_packet.sent_bytes as u64));
    info!(
        "Sent initial client packet constructed_bytes={} sent_bytes={}",
        initial_packet.constructed_bytes, initial_packet.sent_bytes
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
                return Err(cleanup_client_startup_failure(
                    &mut conn,
                    &stealth_runtime,
                    kill_switch.as_ref(),
                    error,
                    b"authenticated client assignment negotiation failed",
                )
                .await);
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
            assignment, tun_name, true,
        )
        .map_err(|error| std::io::Error::other(format!("invalid server assignment: {error}")))?;
        tcfg.mtu = effective_tun_mtu;
        let optm = OptimizationManager::from_cfg(opt_params);
        let pool = optm.memory_pool();
        match quicfuscate::interface::TunInterface::open(tcfg, pool) {
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
                        conn.set_masque_datagram_cb(std::sync::Arc::new(std::sync::Mutex::new(
                            Box::new(move |payload: &[u8]| {
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
                                                component: "standalone client MASQUE downlink"
                                                    .to_string(),
                                                error: error.to_string(),
                                            },
                                        );
                                    }
                                }
                            }),
                        )));
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
            Err(e) => Err(std::io::Error::other(format!("client TUN open failed: {e:?}"))),
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
            return Err(cleanup_client_startup_failure(
                &mut conn,
                &stealth_runtime,
                kill_switch.as_ref(),
                error,
                b"client TUN setup failed",
            )
            .await);
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
    let mut io_diagnostics = client_receive_diagnostics_enabled.then(ClientIoDiagnostics::default);
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
        handle.join().err().map(|_| "client TUN reader thread panicked".to_string())
    });
    let stealth_shutdown_error = stealth_runtime
        .shutdown(quicfuscate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT)
        .await
        .err();
    let kill_switch_error = if let Some(ref ks) = kill_switch {
        if dns_shutdown_error.is_some() {
            ks.on_vpn_disconnected().err().map(|error| {
                format!(
                    "kill switch fail-closed transition after DNS restore failure failed: {error}"
                )
            })
        } else {
            match &exit_reason {
                ExitReason::CleanShutdown => ks
                    .disable()
                    .err()
                    .map(|error| format!("kill switch cleanup on clean shutdown failed: {error}")),
                _ => ks
                    .on_vpn_disconnected()
                    .err()
                    .map(|error| format!("kill switch fail-closed transition failed: {error}")),
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
