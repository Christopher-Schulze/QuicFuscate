const SERVER_HOUSEKEEPING_ACTIVE: Duration = Duration::from_millis(5);
const SERVER_HOUSEKEEPING_IDLE: Duration = Duration::from_millis(250);

fn standalone_housekeeping_delay(live: &ServerLiveRuntime) -> Duration {
    let fanout_pending = live
        .live_state
        .fanout_queue
        .lock()
        .map(|queue| !queue.is_empty())
        .unwrap_or(true);
    if fanout_pending || live.live_state.pending_tun_downlinks.len() > 0 {
        return SERVER_HOUSEKEEPING_ACTIVE;
    }

    let now = live.live_state.clock.now();
    let mut delay = SERVER_HOUSEKEEPING_IDLE;
    for connection in live.live_state.clients.values() {
        if !connection.conn.is_established()
            || connection.conn.has_pending_application_ack()
            || connection.conn.dgram_send_queue_len() > 0
        {
            return SERVER_HOUSEKEEPING_ACTIVE;
        }
        if let Some(deadline) = connection.next_send_deadline() {
            delay = delay.min(deadline.saturating_duration_since(now));
        }
    }
    delay.max(SERVER_HOUSEKEEPING_ACTIVE)
}

impl ServerRuntime {
    /// Create a new server runtime.
    pub fn new(
        engine_config: EngineConfig,
        server_config: ServerConfig,
    ) -> Result<Self, EngineError> {
        Self::new_with_clock(engine_config, server_config, ProtocolClock::default())
    }

    /// Create a server runtime bound to an explicit protocol clock.
    pub fn new_with_clock(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        clock: ProtocolClock,
    ) -> Result<Self, EngineError> {
        engine_config.validate().map_err(EngineError::from)?;
        server_config
            .validate_engine_interface_alignment(&engine_config.interface)
            .map_err(EngineError::Config)?;
        let assignment_settings = server_config
            .assignment_settings(engine_config.interface.tun_mtu)
            .map_err(EngineError::Config)?;
        server_config.auth_policy.validate().map_err(EngineError::Config)?;
        server_config.dns_admission.validate().map_err(|error| {
            EngineError::Config(format!("server DNS admission configuration: {error}"))
        })?;
        server_config.validate_revocation_retention().map_err(EngineError::Config)?;
        server_config.bandwidth_policy.validate().map_err(EngineError::Config)?;
        server_config.validate_downlink_scheduler().map_err(EngineError::Config)?;
        #[cfg(feature = "rate_limiter")]
        {
            server_config.ddos_policy.validate().map_err(EngineError::Config)?;
            server_config.blacklist.validate().map_err(EngineError::Config)?;
        }
        // Create memory pool
        let optimize_config = engine_config
            .optimization
            .to_runtime_config()
            .map_err(|error| EngineError::Config(error.to_string()))?;
        let pool = Arc::new(MemoryPool::new(
            optimize_config.pool_capacity,
            optimize_config.block_size,
        ));

        let domain =
            SharedServerDomain::try_new_with_clock(&server_config, &clock).map_err(EngineError::Config)?;
        let stealth_runtime = Arc::new(
            StealthRuntimeOwner::from_env()
                .map_err(|error| EngineError::Config(format!("Invalid Reality config: {error}")))?,
        );

        Ok(Self {
            clock: clock.clone(),
            graceful_shutdown: Arc::new(GracefulShutdown::new(engine_config.engine.shutdown_timeout_ms)),
            engine_config,
            server_config,
            assignment_settings,
            pool,
            host_resources: None,
            domain,
            shutdown: Arc::new(AtomicBool::new(false)),
            state: ServerState::Stopped,
            stats: Arc::new(ServerStats::default()),
            live: None,
            dns_intercept_workers: None,
            stealth_runtime,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_standalone(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        accept_config: AcceptConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
    ) -> std::io::Result<Self> {
        Self::new_standalone_with_clock(
            engine_config,
            server_config,
            accept_config,
            tun_config,
            opt_params,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
            ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_standalone_with_clock(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        accept_config: AcceptConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let mut runtime = Self::new_with_clock(
            engine_config,
            server_config.clone(),
            clock.clone(),
        )
        .map_err(std::io::Error::other)?;
        let tun_config = tun_config
            .map(|config| server_config.reconcile_standalone_tun_config(config))
            .transpose()
            .map_err(std::io::Error::other)?;
        let mut live_state = LiveServerState::try_new_with_clock(
            server_config.clone(),
            clock.clone(),
        )
        .map_err(std::io::Error::other)?;
        live_state.enable_uring_worker();

        let std_socket = std::net::UdpSocket::bind(server_config.listen)?;
        let socket_ref = socket2::SockRef::from(&std_socket);
        if let Err(error) =
            socket_ref.set_recv_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES)
        {
            log::debug!("UDP receive buffer hint rejected: {}", error);
        }
        if let Err(error) =
            socket_ref.set_send_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES)
        {
            log::debug!("UDP send buffer hint rejected: {}", error);
        }
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let local_addr = socket.local_addr()?;
        let (admin_actions_tx, admin_actions_rx) = mpsc::unbounded_channel::<AdminAction>();
        let accept_max_clients = server_config.max_clients;
        let server_tun_ip = Some(server_config.server_ip);
        let server_tun_ipv6 = server_config.ipv6_server_ip;
        let tun_notify = Arc::new(tokio::sync::Notify::new());
        let tun_fault = Arc::new(Mutex::new(None));
        let (server_tun, tun_rx, routing, tun_reader_shutdown, tun_reader_handle) = match tun_config {
            Some(tun_config) => {
                let optm = crate::optimize::OptimizationManager::from_cfg(opt_params);
                #[cfg(target_os = "linux")]
                {
                    crate::interface::validate_tun_config(&tun_config)
                        .map_err(|error| std::io::Error::other(format!("{error:?}")))?;
                    cleanup_stale_routing_records(tun_config.name.as_deref(), &server_config)
                        .map_err(std::io::Error::other)?;
                }

                match open_server_tun(tun_config, optm.memory_pool()) {
                    Ok(tun) => {
                        #[cfg(target_os = "linux")]
                        let routing = {
                            let routing =
                                configured_routing_manager(tun.name().to_string(), &server_config)
                                    .map_err(std::io::Error::other)?;
                            if let Err(error) = routing.setup() {
                                let rollback_error = routing.teardown().err();
                                crate::audit::audit_typed(
                                    crate::audit::AuditEventType::FirewallRuleAdded,
                                    crate::audit::AuditSeverity::Critical,
                                    None,
                                    None,
                                    crate::audit::AuditContext {
                                        actor: crate::audit::AuditActor::System,
                                        target: crate::audit::AuditTarget::Route,
                                        outcome: crate::audit::AuditOutcome::Failed,
                                        reason: Some("routing_setup_failed"),
                                    },
                                    &format!("Standalone server routing setup failed: {error}"),
                                );
                                let detail = rollback_error.map_or_else(
                                    || format!("standalone server routing setup failed: {error}"),
                                    |rollback| {
                                        format!(
                                            "standalone server routing setup failed: {error}; owned rollback failed: {rollback}"
                                        )
                                    },
                                );
                                return Err(std::io::Error::other(detail));
                            }
                            Some(routing)
                        };
                        #[cfg(not(target_os = "linux"))]
                        let routing = None;
                        let tun_arc = Arc::new(tun);
                        // Spawn a blocking reader thread that forwards TUN frames into a channel.
                        // These packets are forwarded to the client via QUIC datagrams in the run_loop.
                        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(
                            crate::interface::TUN_PACKET_QUEUE_CAPACITY,
                        );
                        let tun_for_reader = tun_arc.clone();
                        let reader_shutdown = Arc::new(AtomicBool::new(false));
                        let shutdown_for_loop = Arc::clone(&reader_shutdown);
                        let shutdown_for_callback = Arc::clone(&reader_shutdown);
                        let fault_for_loop = Arc::clone(&tun_fault);
                        let fault_for_callback = Arc::clone(&tun_fault);
                        let tun_notify_for_reader = Arc::clone(&tun_notify);
                        let tun_notify_for_callback_failure = Arc::clone(&tun_notify);
                        let tun_notify_for_reader_error = Arc::clone(&tun_notify);
                        let reader_spawn = std::thread::Builder::new()
                            .name("tun-reader".to_string())
                            .spawn(move || {
                                let read_result = tun_for_reader.reader_loop_with_shutdown(
                                    &shutdown_for_loop,
                                    move |packet| {
                                        let v = packet.to_vec();
                                        log::debug!(
                                            "TUN reader: read {}B proto={:#x} dst={}",
                                            v.len(),
                                            v[0] >> 4,
                                            if v[0] >> 4 == 4 && v.len() >= 20 {
                                                format!("{}.{}.{}.{}", v[16], v[17], v[18], v[19])
                                            } else {
                                                String::from("?")
                                            }
                                        );
                                        if tx.send(v).is_err() {
                                            if !shutdown_for_callback.load(Ordering::Acquire) {
                                                let mut fault = fault_for_callback.lock();
                                                if fault.is_none() {
                                                    *fault = Some(DataPlaneFault::ChannelDisconnected {
                                                        component: "server TUN reader channel".to_string(),
                                                    });
                                                }
                                                drop(fault);
                                                tun_notify_for_callback_failure.notify_one();
                                            }
                                            shutdown_for_callback.store(true, Ordering::Release);
                                            return;
                                        }
                                        tun_notify_for_reader.notify_one();
                                    },
                                );
                                if let Err(error) = read_result {
                                    if !shutdown_for_loop.load(Ordering::Acquire) {
                                        log::warn!("TUN reader stopped with error: {error}");
                                        let mut fault = fault_for_loop.lock();
                                        if fault.is_none() {
                                            *fault = Some(DataPlaneFault::ReaderStopped {
                                                component: "server TUN reader".to_string(),
                                                error: error.to_string(),
                                            });
                                        }
                                        drop(fault);
                                        tun_notify_for_reader_error.notify_one();
                                    }
                                }
                            });
                        let reader_handle = match reader_spawn {
                            Ok(handle) => handle,
                            Err(error) => {
                                let routing_error =
                                    routing.and_then(|routing| teardown_routing(routing).err());
                                let detail = routing_error.map_or_else(
                                    || format!("standalone TUN reader spawn failed: {error}"),
                                    |routing_error| {
                                        format!(
                                            "standalone TUN reader spawn failed: {error}; routing rollback failed: {routing_error}"
                                        )
                                    },
                                );
                                return Err(std::io::Error::other(detail));
                            }
                        };
                        log::info!("Server TUN reader thread spawned for bidirectional forwarding");
                        (
                            Some(tun_arc),
                            Some(rx),
                            routing,
                            Some(reader_shutdown),
                            Some(reader_handle),
                        )
                    }
                    Err(error) => {
                        return Err(std::io::Error::other(format!(
                            "standalone server TUN open failed: {error}"
                        )));
                    }
                }
            }
            None => (None, None, None, None, None),
        };

        let metrics = Arc::new(Metrics::new_with_clock(&clock));
        metrics.set_memory_lock_status(qf_memory_lock::current_status());
        #[cfg(feature = "rate_limiter")]
        {
            metrics.set_geoip_status(live_state.geoip_status());
            let blacklist = live_state.domain.blacklist();
            metrics.configure_blacklist_sync(blacklist.has_sync_url(), blacklist.sync_interval());
            let cached_entries = blacklist.len();
            if blacklist.has_sync_url() && cached_entries > 0 {
                metrics.record_blacklist_cache_loaded(cached_entries);
            }
        }
        runtime.live = Some(ServerLiveRuntime {
            live_state,
            accept_loop: AcceptLoop::new(accept_config),
            accept_max_clients,
            admin_actions_tx,
            admin_actions_rx: Some(admin_actions_rx),
            metrics,
            socket,
            local_addr,
            server_tun,
            routing,
            server_tun_ip,
            server_tun_ipv6,
            tun_rx,
            tun_reader_shutdown,
            tun_reader_handle,
            tun_notify,
            tun_fault,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
            standalone_runtime_metadata: None,
            service_signals: StandaloneServiceSignals::default(),
        });

        Ok(runtime)
    }

    pub fn new_standalone_default(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
    ) -> std::io::Result<Self> {
        Self::new_standalone(
            engine_config,
            server_config,
            AcceptConfig::default(),
            tun_config,
            opt_params,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
        )
    }

    pub fn new_standalone_with_bootstrap(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        bootstrap: StandaloneServerBootstrapState,
    ) -> std::io::Result<Self> {
        Self::new_standalone_with_bootstrap_and_clock(
            engine_config,
            server_config,
            tun_config,
            opt_params,
            bootstrap,
            ProtocolClock::default(),
        )
    }

    pub fn new_standalone_with_bootstrap_and_clock(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        bootstrap: StandaloneServerBootstrapState,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let (blocked_ips, qkey_registry, admin_web_bootstrap) = bootstrap.into_runtime_parts();
        Self::new_standalone_with_clock(
            engine_config,
            server_config,
            AcceptConfig::default(),
            tun_config,
            opt_params,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_initialized_standalone_default(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        config_path: Option<&std::path::Path>,
        admin_log_buffer_override: Option<Arc<self::admin_logs::AdminLogBuffer>>,
        qkey_ttl_override: Option<u64>,
        qkey_store_override: Option<std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        Self::new_initialized_standalone_default_with_clock(
            engine_config,
            server_config,
            tun_config,
            opt_params,
            config_path,
            admin_log_buffer_override,
            qkey_ttl_override,
            qkey_store_override,
            ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_initialized_standalone_default_with_clock(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        config_path: Option<&std::path::Path>,
        admin_log_buffer_override: Option<Arc<self::admin_logs::AdminLogBuffer>>,
        qkey_ttl_override: Option<u64>,
        qkey_store_override: Option<std::path::PathBuf>,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let bootstrap = initialize_standalone_server_bootstrap_with_clock(
            config_path,
            admin_log_buffer_override,
            qkey_ttl_override,
            qkey_store_override,
            clock.clone(),
        )?;
        Self::new_standalone_with_bootstrap_and_clock(
            engine_config,
            server_config,
            tun_config,
            opt_params,
            bootstrap,
            clock,
        )
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.state != ServerState::Stopped {
            return Err(EngineError::InvalidState(
                qf_engine_types::EngineState::Running,
                "start (already running)",
            ));
        }

        if self.stealth_runtime.is_shutdown() {
            self.stealth_runtime = Arc::new(
                StealthRuntimeOwner::from_env()
                    .map_err(|error| EngineError::Config(format!("Invalid Reality config: {error}")))?,
            );
        }

        self.set_state(ServerState::Starting);
        self.shutdown.store(false, Ordering::SeqCst);

        if self.live.is_none() {
            match ServerHostResources::start(
                &self.engine_config,
                &self.server_config,
                self.pool.clone(),
            ) {
                Ok(resources) => {
                    self.host_resources = Some(resources);
                }
                Err(error) => {
                    self.set_state(ServerState::Stopped);
                    return Err(error);
                }
            }
            log::info!(
                "Embedded server runtime started on {} with TUN/routing ownership prepared",
                self.server_config.listen
            );
        } else {
            log::info!(
                "Standalone server runtime started on {} with TUN/routing ownership prepared",
                self.server_config.listen
            );
        }

        self.set_state(ServerState::Running);
        self.graceful_shutdown.set_running();

        Ok(())
    }

    fn stop_tun_reader(&mut self) -> Result<(), String> {
        let Some(live) = self.live.as_mut() else {
            return Ok(());
        };

        // Publish deliberate shutdown before releasing the receiver so a
        // callback that observes the closed channel cannot become a runtime
        // fault during normal cleanup. The bounded send is then unblocked by
        // dropping the receiver; the device remains owned until the join.
        if let Some(shutdown) = live.tun_reader_shutdown.as_ref() {
            shutdown.store(true, Ordering::Release);
        }
        live.tun_rx.take();
        let wake_error = live.server_tun.as_ref().and_then(|tun| {
            tun.request_reader_shutdown()
                .err()
                .map(|error| format!("server TUN reader wake failed: {error}"))
        });
        live.tun_reader_shutdown.take();
        let join_error = live.tun_reader_handle.take().and_then(|handle| {
            handle
                .join()
                .err()
                .map(|_| "server TUN reader thread panicked".to_string())
        });
        live.server_tun.take();
        match (wake_error, join_error) {
            (None, None) => Ok(()),
            (Some(error), None) | (None, Some(error)) => Err(error),
            (Some(wake), Some(join)) => Err(format!("{wake}; {join}")),
        }
    }

    /// Stop the server.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        self.stealth_runtime.request_shutdown();
        #[cfg(feature = "rate_limiter")]
        if let Some(live) = self.live.as_ref() {
            live.live_state.abandon_blacklist_sync(&live.metrics);
        }
        if let Some(dns_workers) = self.dns_intercept_workers.take() {
            dns_workers.abandon();
        }
        let tun_reader_error = self.stop_tun_reader().err();
        let uring_worker_error = self
            .live
            .as_mut()
            .and_then(|live| live.live_state.stop_uring_worker());
        if self.state == ServerState::Stopped {
            // Idempotent: signalling again is harmless and keeps a repeated stop from leaving a
            // service that was registered after the first one.
            if let Some(live) = self.live.as_mut() {
                live.service_signals.shutdown_all();
            }
            let mut cleanup_errors = Vec::new();
            if let Some(error) = tun_reader_error {
                cleanup_errors.push(error);
            }
            if let Some(error) = uring_worker_error {
                cleanup_errors.push(format!("server io_uring worker cleanup failed: {error}"));
            }
            if let Some(routing) = self.live.as_mut().and_then(|live| live.routing.take()) {
                if let Err(error) = teardown_routing(routing) {
                    cleanup_errors.push(format!("server routing teardown failed: {error}"));
                }
            }
            if cleanup_errors.is_empty() {
                return Ok(());
            }
            return Err(EngineError::Io(cleanup_errors.join("; ")));
        }

        self.set_state(ServerState::Stopping);
        self.shutdown.store(true, Ordering::SeqCst);

        // Signal every registered auxiliary service. The async drain and live-shutdown paths
        // already did this, but direct stop did not, so admin, web, and metrics listeners could
        // stay alive holding their ports and serving stale state while the runtime published
        // Stopped.
        if let Some(live) = self.live.as_mut() {
            live.service_signals.shutdown_all();
        }

        // Close all sessions
        for id in self.domain.all_session_ids() {
            self.domain.remove(id);
        }

        let mut cleanup_errors = Vec::new();
        if let Some(error) = tun_reader_error {
            cleanup_errors.push(error);
        }
        if let Some(error) = uring_worker_error {
            cleanup_errors.push(format!("server io_uring worker cleanup failed: {error}"));
        }
        if let Some(resources) = self.host_resources.take() {
            if let Err(error) = resources.teardown() {
                cleanup_errors.push(error.to_string());
            }
        }
        if let Some(routing) = self.live.as_mut().and_then(|live| live.routing.take()) {
            if let Err(error) = teardown_routing(routing) {
                cleanup_errors.push(format!("server routing teardown failed: {error}"));
            }
        }

        self.set_state(ServerState::Stopped);
        self.graceful_shutdown.set_stopped();
        if cleanup_errors.is_empty() {
            log::info!("Server stopped");
            Ok(())
        } else {
            let detail = cleanup_errors.join("; ");
            log::error!("Server stopped with incomplete owned cleanup: {}", detail);
            // Distinct from a clean stop: host state was left behind, and a probe that
            // cannot tell the two apart cannot know an operator has to intervene.
            self.publish_lifecycle(
                crate::implementations::server::metrics::LifecyclePhase::StoppedIncomplete,
            );
            Err(EngineError::Io(detail))
        }
    }

    /// Handle new client connection.
    pub fn accept_client(&self, remote_addr: SocketAddr) -> Result<SessionId, AcceptError> {
        let (session_id, _stats, assigned_ips) = {
            match self.domain.accept(remote_addr) {
                Ok(value) => value,
                Err(error) => {
                    self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    let source_ip = remote_addr.ip().to_string();
                    crate::audit::audit_typed(
                        crate::audit::AuditEventType::ConnectionRejected,
                        crate::audit::AuditSeverity::Warning,
                        Some(&source_ip),
                        None,
                        crate::audit::AuditContext {
                            actor: crate::audit::AuditActor::NetworkPeer,
                            target: crate::audit::AuditTarget::Connection,
                            outcome: crate::audit::AuditOutcome::Denied,
                            reason: Some("connection_policy_rejected"),
                        },
                        "Client connection rejected",
                    );
                    return Err(error);
                }
            }
        };
        if let Err(error) = self.domain.sessions.write().activate_bandwidth(session_id, None) {
            self.domain.remove(session_id);
            self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(AcceptError::SessionError(error.to_string()));
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

        log::info!("Client connected: {} -> {}", remote_addr, assigned_ips.ipv4);
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionEstablished,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client connection accepted",
        );

        Ok(session_id)
    }

    /// Remove client session.
    pub fn remove_client(&self, session_id: SessionId) {
        let session = self.domain.remove(session_id);

        if let Some(session) = session {
            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            let source_ip = session.remote_addr().ip().to_string();
            let client_id = session.id().as_u64().to_string();
            crate::audit::audit(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                Some(&source_ip),
                Some(&client_id),
                "Client session removed",
            );

            log::info!(
                "Client disconnected: {} (IP: {})",
                session.remote_addr(),
                session.client_ip()
            );
        }
    }

    pub fn traffic_snapshot(&self) -> ServerTrafficSnapshot {
        let domain_snapshot = self.domain.traffic_snapshot();
        ServerTrafficSnapshot {
            active_connections: domain_snapshot.active_connections,
            total_connections: self.stats.total_connections.load(Ordering::Relaxed),
            connections_rejected: self.stats.connections_rejected.load(Ordering::Relaxed),
            bytes_in: domain_snapshot.bytes_in,
            bytes_out: domain_snapshot.bytes_out,
            packets_in: domain_snapshot.packets_in,
            packets_out: domain_snapshot.packets_out,
        }
    }

    pub fn reap_expired_sessions(&self) -> usize {
        let removed = self.domain.reap_expired();
        let removed_len = removed.len();
        if removed_len == 0 {
            return 0;
        }
        self.stats.active_connections.fetch_sub(removed_len as u64, Ordering::Relaxed);
        removed_len
    }

    /// Publish `state` and mirror it to every health surface.
    ///
    /// The lifecycle must never be assigned without publishing it, because that is how
    /// the surfaces came to report `up=1` and `status=ok` for a stopped runtime.
    pub(crate) fn set_state(&mut self, state: ServerState) {
        self.state = state;
        self.publish_lifecycle(match state {
            ServerState::Stopped => crate::implementations::server::metrics::LifecyclePhase::Stopped,
            ServerState::Starting => {
                crate::implementations::server::metrics::LifecyclePhase::Starting
            }
            ServerState::Running => crate::implementations::server::metrics::LifecyclePhase::Running,
            ServerState::Draining => {
                crate::implementations::server::metrics::LifecyclePhase::Draining
            }
            ServerState::Stopping => {
                crate::implementations::server::metrics::LifecyclePhase::Stopping
            }
        });
    }

    /// Publish a lifecycle phase that has no `ServerState` of its own.
    pub(crate) fn publish_lifecycle(
        &self,
        phase: crate::implementations::server::metrics::LifecyclePhase,
    ) {
        if let Some(live) = self.live.as_ref() {
            live.metrics.set_lifecycle_phase(phase);
        }
    }

    /// Get server state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Get server statistics.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Get session count.
    pub fn session_count(&self) -> usize {
        self.domain.session_count()
    }

    pub fn session_stats(&self, session_id: SessionId) -> Option<Arc<SessionStats>> {
        self.domain.session_stats(session_id)
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    // SAFETY: `live` is always `Some` after standalone-mode construction.
    // Callers are exclusively standalone-mode methods; `None` here is a logic bug.
    #[allow(clippy::expect_used)]
    fn live(&self) -> &ServerLiveRuntime {
        self.live.as_ref().expect("standalone live runtime is only available in standalone mode")
    }

    // SAFETY: `live` is always `Some` after standalone-mode construction.
    // Callers are exclusively standalone-mode methods; `None` here is a logic bug.
    #[allow(clippy::expect_used)]
    fn live_mut(&mut self) -> &mut ServerLiveRuntime {
        self.live.as_mut().expect("standalone live runtime is only available in standalone mode")
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.live().socket.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.live().local_addr
    }

    pub fn standalone_metrics(&self) -> Arc<Metrics> {
        self.live().metrics.clone()
    }

    pub fn admin_actions_sender(&self) -> mpsc::UnboundedSender<AdminAction> {
        self.live().admin_actions_tx.clone()
    }

    pub fn live_client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.live().live_state.client_snapshots()
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<String>>> {
        &self.live().blocked_ips
    }

    pub fn qkey_registry(&self) -> &Arc<std::sync::Mutex<QKeyRegistry>> {
        &self.live().qkey_registry
    }

    fn admin_web_bootstrap(&self) -> &StandaloneAdminWebBootstrap {
        &self.live().admin_web_bootstrap
    }

    fn make_admin_core(&self) -> ServerAdminCore {
        ServerAdminCore::new_with_clock(
            self.standalone_metrics(),
            self.blocked_ips().clone(),
            self.live_client_snapshots().clone(),
            Arc::clone(&self.live().live_state.domain.shared.sessions),
            ServerAdminControlPlane {
                actions: self.admin_actions_sender(),
                listen_addr: self.local_addr().to_string(),
                front_domain: self
                    .live()
                    .standalone_runtime_metadata
                    .as_ref()
                    .map(|metadata| metadata.front_domain.clone())
                    .unwrap_or_default(),
                qkeys: self.qkey_registry().clone(),
                graceful_shutdown: self.graceful_shutdown.clone(),
            },
            #[cfg(feature = "rate_limiter")]
            self.live().live_state.geoip_status(),
            self.clock.clone(),
        )
    }

    #[cfg(unix)]
    fn start_admin_socket_service(&mut self, path: std::path::PathBuf) {
        let admin_core = self.make_admin_core();
        start_standalone_admin_service(self, path, admin_core);
    }

    #[allow(clippy::too_many_arguments)]
    fn start_admin_web_service(
        &mut self,
        addr: std::net::SocketAddr,
        web_root: std::path::PathBuf,
        max_connections: usize,
        operation_timeout_ms: u64,
        admin_web_user: Option<String>,
        admin_web_password: Option<String>,
    ) -> std::io::Result<()> {
        let admin_web_bootstrap = self.admin_web_bootstrap().clone();
        let admin_core = self.make_admin_core();
        let config_path = self
            .live()
            .standalone_runtime_metadata
            .as_ref()
            .and_then(|metadata| metadata.config_path.clone());
        start_configured_standalone_admin_web_service(
            self,
            addr,
            web_root,
            max_connections,
            operation_timeout_ms,
            admin_web_user,
            admin_web_password,
            config_path.as_deref(),
            admin_web_bootstrap.blocked_ips_path,
            admin_web_bootstrap.initial_logging_mode,
            admin_core,
            admin_web_bootstrap.admin_log_buffer,
        )
    }

    fn start_standalone_services(
        &mut self,
        config: StandaloneServiceConfig,
    ) -> std::io::Result<()> {
        if let Some(port) = config.metrics_port {
            start_standalone_metrics_service(self, port);
        }

        #[cfg(unix)]
        if let Some(path) = config.admin_socket {
            self.start_admin_socket_service(path);
        }
        #[cfg(not(unix))]
        let _ = config.admin_socket;

        if let Some(addr) = config.admin_web {
            self.start_admin_web_service(
                addr,
                config.admin_web_root,
                config.admin_web_max_connections,
                config.admin_web_operation_timeout_ms,
                config.admin_web_user,
                config.admin_web_password,
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) fn admit_incoming_datagram(
        &self,
        from: SocketAddr,
        packet: &[u8],
        retry_eligible: bool,
        metrics: &Metrics,
    ) -> crate::implementations::server::ddos::IncomingDatagramAdmission {
        let established = self.live().live_state.is_established_datagram(from, packet);
        self.live().live_state.admit_incoming_datagram(
            from,
            packet,
            established,
            retry_eligible,
            metrics,
        )
    }

    fn live_parts(&mut self) -> ServerRuntimeLiveParts<'_> {
        let shutdown = Arc::clone(&self.shutdown);
        let mut assignment_settings = self.assignment_settings.clone();
        let live = self.live_mut();
        let uring_worker = live.live_state.uring_worker.clone();
        if let Some(tun) = live.server_tun.as_ref() {
            assignment_settings.mtu = tun.mtu();
        }
        ServerRuntimeLiveParts {
            live_state: &mut live.live_state,
            accept_loop: &live.accept_loop,
            accept_max_clients: live.accept_max_clients,
            server_tun: live.server_tun.as_ref(),
            server_ips: ServerTunIps {
                ipv4: live.server_tun_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                ipv6: live.server_tun_ipv6,
            },
            assignment_settings,
            tun_fault: Arc::clone(&live.tun_fault),
            tun_notify: Arc::clone(&live.tun_notify),
            shutdown,
            uring_worker,
        }
    }

    pub fn register_admin_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.admin = Some(signal);
    }

    pub fn register_admin_web_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.admin_web = Some(signal);
    }

    pub fn register_metrics_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.metrics = Some(signal);
    }

    fn sync_standalone_runtime_metadata(&mut self, metadata: &StandaloneRuntimeMetadata) {
        self.live_mut().standalone_runtime_metadata = Some(metadata.clone());
    }

    fn ensure_standalone_runtime_metadata(&mut self, metadata: &StandaloneRuntimeMetadata) {
        if self.live().standalone_runtime_metadata.is_none() {
            self.sync_standalone_runtime_metadata(metadata);
        }
    }

    async fn run_loop(
        &mut self,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) -> std::io::Result<()> {
        let profiles = runtime_config.profiles.clone();
        let profile_interval_secs = runtime_config.profile_interval_secs;
        let standalone_runtime_metadata = runtime_config.standalone_runtime_metadata.clone();
        let tun_enable = runtime_config.tun_enable;
        let fingerprint_profile = runtime_config.transport.fingerprint_profile();
        let dns_upstream_resolvers = Arc::new(self.server_config.dns_servers.clone());
        let dns_intercept_admission = self.live().live_state.dns_admission();
        if self.state != ServerState::Stopped {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "server runtime already started",
            ));
        }

        self.start()
            .map_err(|error| std::io::Error::other(format!("server loop start failed: {error}")))?;

        self.ensure_standalone_runtime_metadata(&standalone_runtime_metadata);
        let runtime_owner = self.stealth_runtime.clone();

        let metrics = self.standalone_metrics();
        let socket = self.socket();
        let local_addr = self.local_addr();
        let blocked_ips = self.blocked_ips().clone();
        let qkey_registry = self.qkey_registry().clone();
        let dns_intercept_workers = Arc::new(DnsInterceptWorkerOwner::new(Arc::clone(&metrics)));
        self.dns_intercept_workers = Some(Arc::clone(&dns_intercept_workers));
        let Some(mut admin_actions_rx) = self.live_mut().admin_actions_rx.take() else {
            if let Err(stop_error) = self.stop() {
                return Err(std::io::Error::other(format!(
                    "server admin action receiver unavailable; cleanup failed: {stop_error}"
                )));
            }
            return Err(std::io::Error::other("server admin action receiver unavailable"));
        };
        // Take the TUN reader channel (if any) for forwarding TUN→client datagrams.
        let mut tun_rx = self.live_mut().tun_rx.take();
        let tun_notify = self.live().tun_notify.clone();
        let tun_fault = self.live().tun_fault.clone();
        if tun_enable {
            metrics.set_tun_data_plane_ready(tun_rx.is_some());
        }
        let mut runtime_fault: Option<DataPlaneFault> = None;
        let mut buf = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
        let mut out = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
        let mut housekeeping = tokio::time::interval(Duration::from_millis(5));
        housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Create shared 0-RTT anti-replay strike register if early data is enabled.
        if runtime_config.transport.is_early_data_enabled()
            && runtime_config.strike_register.is_none()
        {
            use crate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};
            let ar_section = &runtime_config.anti_replay_section;
            if ar_section.enabled {
                let ar_config = AntiReplayConfig {
                    max_ticket_age: std::time::Duration::from_secs(ar_section.max_ticket_age_secs),
                    max_entries: ar_section.max_entries,
                    max_early_data_size: ar_section.max_early_data_size,
                    ..AntiReplayConfig::default()
                };
                // Set configurable max_early_data_size for new TLS server connections.
                crate::qftls::set_max_early_data_size(ar_config.max_early_data_size);
                let register = Arc::new(StrikeRegister::new(ar_config));
                runtime_config.transport.set_strike_register(register.clone());
                runtime_config.strike_register = Some(register);
                log::info!(
                    "[server] 0-RTT anti-replay strike register created \
                     (max_entries={}, max_age={}s, max_early_data={}B)",
                    ar_section.max_entries,
                    ar_section.max_ticket_age_secs,
                    ar_section.max_early_data_size,
                );
            } else {
                log::warn!(
                    "[server] 0-RTT anti-replay protection disabled by config \
                     (anti_replay.enabled=false) - replay attacks are possible"
                );
            }
        }

        let mut server_signals = match ServerSignals::install() {
            Ok(signals) => signals,
            Err(error) => {
                drop(tun_rx);
                let live = self.live_mut();
                live.admin_actions_rx = Some(admin_actions_rx);
                live.service_signals.shutdown_all();
                if let Err(stop_error) = self.stop() {
                    return Err(std::io::Error::other(format!(
                        "{error}; server cleanup after signal handler installation failure failed: {stop_error}"
                    )));
                }
                return Err(error);
            }
        };

        if let Err(error) = start_runtime_profile_rotation_with_generation(
            &runtime_owner,
            runtime_config.stealth_config.clone(),
            profiles,
            profile_interval_secs,
            runtime_config.runtime_policy_generation.clone(),
        ) {
            drop(tun_rx);
            self.live_mut().admin_actions_rx = Some(admin_actions_rx);
            self.live_mut().service_signals.shutdown_all();
            let shutdown_error = self.shutdown_stealth_runtime().await.err();
            let stop_error = self.stop().err();
            let detail = match (shutdown_error, stop_error) {
                (Some(shutdown), Some(stop)) => {
                    format!("{error}; stealth shutdown failed: {shutdown}; server cleanup failed: {stop}")
                }
                (Some(shutdown), None) => format!("{error}; stealth shutdown failed: {shutdown}"),
                (None, Some(stop)) => format!("{error}; server cleanup failed: {stop}"),
                (None, None) => error,
            };
            return Err(std::io::Error::other(detail));
        }

        #[cfg(unix)]
        {
            record_systemd_notification("READY=1", self::systemd::notify::ready());
            record_systemd_notification(
                "STATUS=Accepting connections",
                self::systemd::notify::status("Accepting connections"),
            );
        }
        #[cfg(unix)]
        // systemd owns this watchdog deadline; it must remain live during
        // protocol-clock freezes and runtime teardown.
        let watchdog_interval = self::systemd::notify::watchdog_interval();
        #[cfg(unix)]
        let mut next_watchdog = watchdog_interval.map(|interval| Instant::now() + interval);

        loop {
            tokio::select! {
                Some(action) = admin_actions_rx.recv() => {
                    self.handle_admin_action_with_runtime_reload(
                        action,
                        &metrics,
                        runtime_config,
                    );
                }
                signal = server_signals.recv() => {
                    match signal {
                        ServerSignalEvent::Shutdown(reason) => {
                            self.initiate_drain(reason);
                        }
                        ServerSignalEvent::Reload => {
                            self.reload_standalone_runtime(runtime_config, "SIGHUP");
                            match crate::logging::reopen() {
                                Ok(()) => {
                                    log::info!(
                                        "SIGHUP reopened the operational log sink after configuration reload"
                                    );
                                    crate::audit::audit_typed(
                                        crate::audit::AuditEventType::AdminAction,
                                        crate::audit::AuditSeverity::Info,
                                        None,
                                        None,
                                        crate::audit::AuditContext {
                                            actor: crate::audit::AuditActor::System,
                                            target: crate::audit::AuditTarget::System,
                                            outcome: crate::audit::AuditOutcome::Succeeded,
                                            reason: Some("sighup_log_reopen"),
                                        },
                                        "SIGHUP reopened the operational log sink",
                                    );
                                }
                                Err(error) => {
                                    log::error!("SIGHUP log sink reopen failed: {}", error);
                                    crate::audit::audit_typed(
                                        crate::audit::AuditEventType::AdminAction,
                                        crate::audit::AuditSeverity::Warning,
                                        None,
                                        None,
                                        crate::audit::AuditContext {
                                            actor: crate::audit::AuditActor::System,
                                            target: crate::audit::AuditTarget::System,
                                            outcome: crate::audit::AuditOutcome::Failed,
                                            reason: Some("sighup_log_reopen_failed"),
                                        },
                                        &format!("SIGHUP log sink reopen failed: {error}"),
                                    );
                                }
                            }
                        }
                    }
                }
                recv_res = recv_datagram_from(&socket, &mut buf) => {
                    match recv_res {
                        Ok((len, from)) => {
                            crate::telemetry!(crate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                            metrics.record_ingress_datagram(len);

                            let ip_str = from.ip().to_string();
                            if blocked_ips.read().contains(&ip_str) {
                                metrics.record_connection_rejected();
                                continue;
                            }
                            let version_negotiation = stateless_version_negotiation_response(
                                &buf[..len],
                                runtime_config.transport.supported_versions(),
                            )
                            .ok()
                            .flatten();
                            #[cfg(feature = "rate_limiter")]
                            {
                                use crate::implementations::server::ddos::IncomingDatagramAdmission;
                                match self.admit_incoming_datagram(
                                    from,
                                    &buf[..len],
                                    version_negotiation.is_none(),
                                    &metrics,
                                ) {
                                    IncomingDatagramAdmission::Allow => {}
                                    IncomingDatagramAdmission::RetryValidated => {
                                        metrics.record_ddos_retry_validated();
                                    }
                                    IncomingDatagramAdmission::Drop(reason) => {
                                        metrics.record_ddos_drop(reason);
                                        continue;
                                    }
                                    IncomingDatagramAdmission::Retry(response) => {
                                        metrics.record_ddos_retry_issued();
                                        match socket.send_to(&response, from).await {
                                            Ok(sent) => metrics.record_egress_datagram(sent),
                                            Err(error) => {
                                                log::warn!(
                                                    "failed to send QUIC Retry to {}: {}",
                                                    from,
                                                    error
                                                );
                                            }
                                        }
                                        continue;
                                    }
                                }
                            }
                            if let Some(response) = version_negotiation {
                                match socket.send_to(&response, from).await {
                                    Ok(sent) => metrics.record_egress_datagram(sent),
                                    Err(error) => {
                                        log::warn!(
                                            "failed to send version negotiation to {}: {}",
                                            from,
                                            error
                                        );
                                    }
                                }
                                continue;
                            }

                            #[cfg(feature = "rate_limiter")]
                            let retry_token_manager =
                                self.live().live_state.retry_token_manager.clone();
                            #[cfg(not(feature = "rate_limiter"))]
                            let retry_token_manager = None;
                            let runtime_clock = self.clock.clone();
                            let runtime_parts = self.live_parts();
                            let stealth_runtime = runtime_owner.clone();
                            let client_snapshots = runtime_parts.live_state.client_snapshots().clone();
                            let auth_rate_limiter = runtime_parts.live_state.auth_rate_limiter.clone();
                            let revocation_manager =
                                Arc::clone(&runtime_parts.live_state.revocation_manager);
                            let stealth_config = runtime_config.stealth_config.clone();
                            let fec_cfg_shared = runtime_config.fec_cfg_shared.clone();
                            let opt_params_shared = runtime_config.opt_params_shared.clone();
                            let transport = &runtime_config.transport;
                            let runtime_policy_generation =
                                runtime_config.runtime_policy_generation.clone();
                            let runtime_client = match runtime_parts.live_state.acquire_runtime_client_with(
                                from,
                                &buf[..len],
                                runtime_parts.accept_loop,
                                runtime_parts.accept_max_clients,
                                &metrics,
                                || {
                                    build_live_server_client_init(
                                        LiveClientBuildRequest {
                                            packet: &buf[..len],
                                            local_addr,
                                            remote_addr: from,
                                            qkey_registry: qkey_registry.as_ref(),
                                            revocation_manager: revocation_manager.as_ref(),
                                            metrics: &metrics,
                                            stealth_config: &stealth_config,
                                            fec_cfg_shared: &fec_cfg_shared,
                                            opt_params_shared: &opt_params_shared,
                                            transport_config: transport,
                                            runtime_policy_generation: &runtime_policy_generation,
                                            stealth_runtime: Some(stealth_runtime.clone()),
                                            auth_rate_limiter: auth_rate_limiter.clone(),
                                            retry_token_manager: retry_token_manager.clone(),
                                            clock: runtime_clock.clone(),
                                        },
                                )
                            },
                            ) {
                                LiveClientAcquire::Ready(v) => {
                                    v
                                },
                                LiveClientAcquire::Backpressure => {
                                    tokio::time::sleep(runtime_parts.accept_loop.backpressure_delay()).await;
                                    continue;
                                }
                                LiveClientAcquire::Rejected => {
                                    continue;
                                }
                            };
                            let migration_from = runtime_client.migration_from;

                            let datagram_result = match process_live_server_client_datagram(
                                &socket,
                                from,
                                runtime_client,
                                &buf[..len],
                                &mut out,
                                &metrics,
                                &client_snapshots,
                                runtime_parts.server_tun,
                                runtime_parts.server_ips,
                                runtime_parts.assignment_settings.clone(),
                                tun_enable,
                                Arc::clone(&dns_upstream_resolvers),
                                Arc::clone(&dns_intercept_admission),
                                Arc::clone(&dns_intercept_workers),
                                Arc::clone(&runtime_parts.tun_fault),
                                Arc::clone(&runtime_parts.tun_notify),
                                Arc::clone(&runtime_parts.shutdown),
                                runtime_parts.uring_worker.as_deref(),
                            ).await {
                                Ok(result) => result,
                                Err(fault) => {
                                    runtime_fault = Some(fault);
                                    break;
                                }
                            };
                            if let Some(old_addr) = migration_from {
                                runtime_parts.live_state.reconcile_incoming_path_update(
                                    old_addr,
                                    from,
                                    local_addr,
                                    runtime_parts.accept_loop,
                                );
                            }
                            runtime_parts.live_state.commit_qkey_auth_result(
                                datagram_result.remove_auth_conn_id,
                                datagram_result.auth_result,
                                runtime_parts.accept_loop,
                                &metrics,
                            );
                            runtime_parts.live_state.drain_client_fanout(&metrics);
                        }
                        Err(e) => {
                            log::error!("Failed to read from socket: {}", e);
                        }
                    }
                }
                _ = housekeeping.tick() => {
                    dns_intercept_workers.observe_finished().await;
                    if let Some(fault) = tun_fault.lock().clone() {
                        runtime_fault = Some(fault);
                        break;
                    }
                    let qkey_registry = self.live().qkey_registry.clone();
                    if let Err(error) = qkey_registry
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .prune_replay_window()
                    {
                        log::error!("QKey replay-window pruning unavailable: {error}");
                    }
                    let runtime_parts = self.live_parts();
                    if let Err(fault) = runtime_parts.live_state
                        .run_housekeeping_tick(
                            &socket,
                            &mut out,
                            &metrics,
                            runtime_parts.accept_loop,
                        )
                        .await
                    {
                        runtime_fault = Some(fault);
                        break;
                    }
                    // Retry any downlinks that were deferred because a client's QUIC
                    // DATAGRAM queue was full, before reading new TUN frames.
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }

                    // Forward TUN→client: drain any packets from the TUN reader thread
                    // and route them to the correct client based on the destination IP
                    // in the IP packet header. Each client has a unique TUN IP from the
                    // server's IP pool, and we look up the session by client_ip to find
                    // the corresponding SocketAddr.
                    let more_tun = match drain_server_tun_packets(
                        self.live_mut(),
                        &mut tun_rx,
                        &mut out,
                        &socket,
                        &metrics,
                        fingerprint_profile,
                    ) {
                        Ok(more_tun) => more_tun,
                        Err(fault) => {
                            runtime_fault = Some(fault);
                            break;
                        }
                    };
                    if more_tun {
                        tun_notify.notify_one();
                    }
                    // Retry/final-flush any downlinks that were deferred during the
                    // TUN drain above.
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }

                    // Sweep expired entries from 0-RTT anti-replay strike register.
                    if let Some(ref sr) = runtime_config.strike_register {
                        sr.cleanup(self.clock.now());
                    }
                    #[cfg(unix)]
                    if let (Some(interval), Some(deadline)) =
                        (watchdog_interval, next_watchdog)
                    {
                        if Instant::now() >= deadline {
                            record_systemd_notification(
                                "WATCHDOG=1",
                                self::systemd::notify::watchdog(),
                            );
                            next_watchdog = Some(Instant::now() + interval);
                        }
                    }
                    if self.drain_complete() {
                        log::info!(
                            "Server drain complete (active_clients={}, elapsed_ms={})",
                            self.live().live_state.client_count(),
                            self.graceful_shutdown.elapsed().as_millis()
                        );
                        self.finish_drain(
                            &socket,
                            &mut out,
                            &metrics,
                            b"server_shutdown",
                        )
                        .await;
                        break;
                    }
                    housekeeping.reset_after(standalone_housekeeping_delay(self.live()));
                }
                _ = tun_notify.notified(), if tun_enable && tun_rx.is_some() => {
                    if let Some(fault) = tun_fault.lock().clone() {
                        runtime_fault = Some(fault);
                        break;
                    }
                    let more_tun = match drain_server_tun_packets(
                        self.live_mut(),
                        &mut tun_rx,
                        &mut out,
                        &socket,
                        &metrics,
                        fingerprint_profile,
                    ) {
                        Ok(more_tun) => more_tun,
                        Err(fault) => {
                            runtime_fault = Some(fault);
                            break;
                        }
                    };
                    if more_tun {
                        tun_notify.notify_one();
                    }
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }
                }
            }
        }

        drop(tun_rx);
        self.live_mut().admin_actions_rx = Some(admin_actions_rx);
        let stealth_error = self.shutdown_stealth_runtime().await.err();
        let stop_error = self.stop().err();
        if let Some(fault) = runtime_fault {
            metrics.record_tun_data_plane_fault();
            let primary = std::io::Error::other(fault);
            let cleanup = match (stealth_error, stop_error) {
                (None, None) => None,
                (Some(stealth), None) => Some(format!("stealth shutdown failed: {stealth}")),
                (None, Some(stop)) => Some(format!("server shutdown failed: {stop}")),
                (Some(stealth), Some(stop)) => Some(format!(
                    "stealth shutdown failed: {stealth}; server shutdown failed: {stop}"
                )),
            };
            return match cleanup {
                None => Err(primary),
                Some(cleanup) => Err(std::io::Error::other(format!("{primary}; {cleanup}"))),
            };
        }
        match (stealth_error, stop_error) {
            (None, None) => {}
            (Some(stealth), None) => {
                return Err(std::io::Error::other(format!("stealth shutdown failed: {stealth}")))
            }
            (None, Some(stop)) => {
                return Err(std::io::Error::other(format!("server shutdown failed: {stop}")))
            }
            (Some(stealth), Some(stop)) => {
                return Err(std::io::Error::other(format!(
                    "stealth shutdown failed: {stealth}; server shutdown failed: {stop}"
                )))
            }
        }

        Ok(())
    }

    pub async fn run_standalone(
        &mut self,
        mut launch: Box<PreparedStandaloneLaunch>,
    ) -> std::io::Result<()> {
        let service_config = launch.services.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "standalone launch services already consumed",
            )
        })?;
        self.sync_standalone_runtime_metadata(&launch.runtime.standalone_runtime_metadata);
        self.start_standalone_services(service_config)?;
        self.run_loop(&mut launch.runtime).await
    }

    pub fn handle_admin_action<F>(
        &mut self,
        action: AdminAction,
        metrics: &Arc<Metrics>,
        reload: F,
    ) -> bool
    where
        F: FnOnce() -> Result<(), String>,
    {
        match action {
            AdminAction::Kick(id) => {
                let kicked = if let Some(identity) = ClientIdentity::parse(&id) {
                    let live = self.live_mut();
                    live.live_state.kick_client(&identity, &live.accept_loop, metrics)
                } else {
                    false
                };
                let (outcome, reason, message) = if kicked {
                    (crate::audit::AuditOutcome::Succeeded, "client_kicked", "Admin kicked client")
                } else {
                    (
                        crate::audit::AuditOutcome::Failed,
                        "client_not_found",
                        "Admin client kick did not match an active client",
                    )
                };
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    Some(&id),
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Client,
                        outcome,
                        reason: Some(reason),
                    },
                    message,
                );
                false
            }
            AdminAction::RevokeQKey(id) => {
                let revoke_result = {
                    let live = self.live_mut();
                    live.live_state.revoke_qkey_now(
                        &id,
                        "admin_revoked",
                        &live.accept_loop,
                        metrics,
                    )
                };
                let (outcome, reason, message) = match revoke_result {
                    Ok(()) => (
                        crate::audit::AuditOutcome::Succeeded,
                        "admin_revoked",
                        "Admin revoked QKey",
                    ),
                    Err(error) => {
                        log::error!("Admin QKey revocation rejected: {error}");
                        (
                            crate::audit::AuditOutcome::Failed,
                            "wall_clock_unavailable",
                            "Admin QKey revocation was rejected because wall-clock time was unavailable",
                        )
                    }
                };
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::QkeyRevoked,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    Some(&id),
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Qkey,
                        outcome,
                        reason: Some(reason),
                    },
                    message,
                );
                false
            }
            AdminAction::Reload => {
                match reload() {
                    Ok(()) => {
                        crate::audit::audit_typed(
                            crate::audit::AuditEventType::ConfigReloaded,
                            crate::audit::AuditSeverity::Info,
                            None,
                            None,
                            crate::audit::AuditContext {
                                actor: crate::audit::AuditActor::Administrator,
                                target: crate::audit::AuditTarget::Configuration,
                                outcome: crate::audit::AuditOutcome::Succeeded,
                                reason: Some("admin_reload"),
                            },
                            "Admin triggered config reload",
                        );
                    }
                    Err(error) => {
                        log::warn!("Config reload failed: {}", error);
                        crate::audit::audit_typed(
                            crate::audit::AuditEventType::AdminAction,
                            crate::audit::AuditSeverity::Warning,
                            None,
                            None,
                            crate::audit::AuditContext {
                                actor: crate::audit::AuditActor::Administrator,
                                target: crate::audit::AuditTarget::Configuration,
                                outcome: crate::audit::AuditOutcome::Failed,
                                reason: Some("config_reload_failed"),
                            },
                            &format!("Config reload failed: {error}"),
                        );
                    }
                }
                false
            }
            AdminAction::Drain => {
                log::info!("Admin drain requested");
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Server,
                        outcome: crate::audit::AuditOutcome::Started,
                        reason: Some("drain_requested"),
                    },
                    "Admin requested server drain",
                );
                self.initiate_drain(b"admin_drain");
                false
            }
            AdminAction::Shutdown => {
                log::info!("Admin shutdown requested");
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::ServerStopped,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Server,
                        outcome: crate::audit::AuditOutcome::Started,
                        reason: Some("shutdown_requested"),
                    },
                    "Admin requested server shutdown",
                );
                self.initiate_drain(b"admin_shutdown");
                false
            }
        }
    }

    fn handle_admin_action_with_runtime_reload(
        &mut self,
        action: AdminAction,
        metrics: &Arc<Metrics>,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) {
        if matches!(&action, AdminAction::Reload) {
            self.reload_standalone_runtime(runtime_config, "admin");
            return;
        }
        self.handle_admin_action(action, metrics, || Ok(()));
    }

    fn reload_standalone_runtime(
        &mut self,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
        origin: &str,
    ) {
        if self.graceful_shutdown.lifecycle() != ShutdownLifecycle::Running {
            log::warn!("Config reload ignored during server drain ({})", origin);
            return;
        }
        #[cfg(unix)]
        {
            record_systemd_notification("RELOADING=1", self::systemd::notify::reloading());
            record_systemd_notification(
                "STATUS=Reloading configuration",
                self::systemd::notify::status("Reloading configuration"),
            );
        }

        let runtime_metadata = self.live().standalone_runtime_metadata.clone();
        let result: Result<(), String> = (|| {
            let runtime_metadata = runtime_metadata.as_ref().ok_or_else(|| {
                "Config reload requested but runtime metadata is unavailable".to_string()
            })?;
            let cfg_path = runtime_metadata
                .config_path
                .as_deref()
                .ok_or_else(|| "Config reload requested but no config path is set".to_string())?;
            let engine_config = EngineConfig::from_file(cfg_path)
                .map_err(|error| format!("Engine config parse failed: {error}"))?;
            engine_config
                .validate()
                .map_err(|error| format!("Engine config validation failed: {error}"))?;
            let current_memory_lock_policy = qf_memory_lock::MemoryLockPolicy {
                lock_memory: self.engine_config.security.lock_memory,
                lock_blocks: self.engine_config.security.lock_blocks,
                failure_policy: self.engine_config.security.memory_lock_failure_policy,
            };
            let candidate_memory_lock_policy = qf_memory_lock::MemoryLockPolicy {
                lock_memory: engine_config.security.lock_memory,
                lock_blocks: engine_config.security.lock_blocks,
                failure_policy: engine_config.security.memory_lock_failure_policy,
            };
            current_memory_lock_policy.reject_standalone_reload(candidate_memory_lock_policy)?;
            apply_runtime_config_reload_with_generation(
                cfg_path,
                runtime_metadata.reload_policy.fec_mode_override,
                &runtime_config.runtime_policy_generation,
                &mut runtime_config.transport,
                &runtime_config.fec_cfg_shared,
                &runtime_config.opt_params_shared,
                &runtime_config.stealth_config,
                runtime_metadata.reload_policy.stealth_policy.as_runtime_policy(),
            )?;
            self.engine_config.engine.shutdown_timeout_ms =
                engine_config.engine.shutdown_timeout_ms;
            self.graceful_shutdown.set_grace_ms(engine_config.engine.shutdown_timeout_ms);
            Ok(())
        })();

        match result {
            Ok(()) => {
                let active_sessions = self.live().live_state.clients.len();
                let outcome = StandaloneReloadOutcome {
                    scope: StandaloneReloadScope::NextConnectionOnly,
                    active_sessions_unchanged: active_sessions,
                    runtime_generation: runtime_config.runtime_policy_generation.current(),
                };
                log::info!(
                    "Configuration reloaded successfully ({}): scope={:?}, runtime_generation={}, active_sessions_unchanged={}",
                    origin,
                    outcome.scope,
                    outcome.runtime_generation,
                    outcome.active_sessions_unchanged
                );
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::ConfigReloaded,
                    crate::audit::AuditSeverity::Info,
                    None,
                    None,
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Configuration,
                        outcome: crate::audit::AuditOutcome::Succeeded,
                        reason: Some("next_connection_only_reload"),
                    },
                    &format!(
                        "{origin} triggered next-connection-only config reload at runtime generation {}; {active_sessions} active sessions unchanged",
                        outcome.runtime_generation,
                    ),
                );
            }
            Err(error) => {
                log::warn!("Config reload failed ({}): {}", origin, error);
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Administrator,
                        target: crate::audit::AuditTarget::Configuration,
                        outcome: crate::audit::AuditOutcome::Failed,
                        reason: Some("config_reload_failed"),
                    },
                    &format!("Config reload failed ({origin}): {error}"),
                );
            }
        }
        #[cfg(unix)]
        {
            record_systemd_notification("READY=1", self::systemd::notify::ready());
            record_systemd_notification(
                "STATUS=Accepting connections",
                self::systemd::notify::status("Accepting connections"),
            );
        }
    }

    pub fn initiate_drain(&mut self, reason: &'static [u8]) -> bool {
        if !self.graceful_shutdown.begin_drain() {
            return false;
        }
        self.set_state(ServerState::Draining);
        let grace_ms = self.graceful_shutdown.grace().as_millis();
        if let Some(dns_workers) = self.dns_intercept_workers.as_ref() {
            dns_workers.close_admission();
        }
        #[cfg(feature = "rate_limiter")]
        if let Some(live) = self.live.as_ref() {
            live.live_state.close_blacklist_sync();
        }
        let live = self.live_mut();
        live.accept_loop.shutdown();
        log::info!(
            "Server drain started (reason={}, grace_ms={})",
            String::from_utf8_lossy(reason),
            grace_ms
        );
        #[cfg(unix)]
        {
            record_systemd_notification("STOPPING=1", self::systemd::notify::stopping());
            record_systemd_notification(
                "STATUS=Draining active connections",
                self::systemd::notify::status("Draining active connections"),
            );
        }
        true
    }

    fn drain_complete(&self) -> bool {
        self.graceful_shutdown.lifecycle() == ShutdownLifecycle::Draining
            && (self.live().live_state.client_count() == 0
                || self.graceful_shutdown.deadline_reached())
    }

    async fn finish_drain(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        reason: &'static [u8],
    ) {
        let dns_workers = self.dns_intercept_workers.take();
        let live = self.live_mut();
        if tokio::time::timeout(
            FINAL_CLOSE_FLUSH_TIMEOUT,
            live.live_state.force_close_and_flush(socket, out, metrics, &live.accept_loop, reason),
        )
        .await
        .is_err()
        {
            log::warn!(
                "Final shutdown frame flush exceeded {} ms; continuing teardown",
                FINAL_CLOSE_FLUSH_TIMEOUT.as_millis()
            );
        }
        if let Some(dns_workers) = dns_workers {
            dns_workers.shutdown().await;
        }
        #[cfg(feature = "rate_limiter")]
        live.live_state.shutdown_blacklist_sync(metrics).await;
        live.service_signals.shutdown_all();
    }

    async fn shutdown_stealth_runtime(&self) -> Result<(), String> {
        let report = self
            .stealth_runtime
            .shutdown(crate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT)
            .await?;
        log::debug!(
            "Server stealth runtime generation {} stopped: joined={}, force_stopped={}",
            report.generation,
            report.workers_joined,
            report.workers_force_stopped
        );
        Ok(())
    }

    pub fn shutdown_live(&mut self, reason: &'static [u8]) {
        let _ = self.initiate_drain(reason);
        #[cfg(feature = "rate_limiter")]
        if let Some(live) = self.live.as_ref() {
            live.live_state.abandon_blacklist_sync(&live.metrics);
        }
        let live = self.live_mut();
        live.live_state.shutdown_all(reason, None);
        live.service_signals.shutdown_all();
    }
}

impl Drop for ServerRuntime {
    fn drop(&mut self) {
        let live_needs_cleanup = self.live.as_ref().is_some_and(|live| {
            live.server_tun.is_some()
                || live.tun_reader_handle.is_some()
                || live.tun_reader_shutdown.is_some()
                || live.routing.is_some()
                || {
                    #[cfg(feature = "rate_limiter")]
                    {
                        live.live_state.blacklist_sync_has_task()
                    }
                    #[cfg(not(feature = "rate_limiter"))]
                    {
                        false
                    }
                }
        });
        if self.state != ServerState::Stopped || live_needs_cleanup {
            if let Err(e) = self.stop() {
                log::warn!("ServerRuntime drop cleanup failed: {}", e);
            }
        }
    }
}

/// Errors when accepting a client.
#[derive(Debug, Clone)]
pub enum AcceptError {
    MaxClientsReached,
    TooManyConnectionsPerIp,
    IpPoolExhausted,
    SessionError(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::MaxClientsReached => write!(f, "Maximum clients reached"),
            AcceptError::TooManyConnectionsPerIp => write!(f, "Too many connections from this IP"),
            AcceptError::IpPoolExhausted => write!(f, "IP pool exhausted"),
            AcceptError::SessionError(e) => write!(f, "Session error: {}", e),
        }
    }
}

impl std::error::Error for AcceptError {}

impl From<SessionError> for AcceptError {
    fn from(e: SessionError) -> Self {
        AcceptError::SessionError(e.to_string())
    }
}
