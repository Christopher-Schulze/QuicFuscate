use super::masque_relay::MasqueRelayOwner;
#[cfg(target_os = "linux")]
use super::runtime_admin::{cleanup_stale_routing_records, configured_routing_manager};
use super::sharding::{
    shard_channels, ShardMessage, ShardRouter, COORDINATOR_SHARD_ID, SHARD_MESSAGE_CAPACITY,
};
use super::*;
use crate::time_source::ProtocolClock;
mod runtime_loop;

const SERVER_HOUSEKEEPING_ACTIVE: Duration = Duration::from_millis(5);
const SERVER_HOUSEKEEPING_IDLE: Duration = Duration::from_millis(250);
/// Bounded join window for dataplane shards during runtime teardown; the
/// final CONNECTION_CLOSE flush on each shard shares the same bound.
const SHARD_WORKER_JOIN_TIMEOUT: Duration = FINAL_CLOSE_FLUSH_TIMEOUT;

fn standalone_housekeeping_delay(live: &ServerLiveRuntime) -> Duration {
    let fanout_pending =
        live.live_state.fanout_queue.lock().map(|queue| !queue.is_empty()).unwrap_or(true);
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
        // MASQUE downlink/relay queues are drained by housekeeping and by
        // inbound datagram processing only. A reply queued right after the
        // last drain would otherwise wait a full idle interval, adding up to
        // SERVER_HOUSEKEEPING_IDLE to every tunneled round trip.
        if connection
            .masque_downlink_queue()
            .map(|queue| queue.lock().map(|q| !q.is_empty()).unwrap_or(true))
            .unwrap_or(false)
            || connection
                .masque_relay_response_queue()
                .map(|queue| queue.lock().map(|q| !q.is_empty()).unwrap_or(true))
                .unwrap_or(false)
        {
            return SERVER_HOUSEKEEPING_ACTIVE;
        }
        if let Some(deadline) = connection.next_send_deadline() {
            delay = delay.min(deadline.saturating_duration_since(now));
        }
    }
    delay.max(SERVER_HOUSEKEEPING_ACTIVE)
}

/// Resolve `ServerConfig::rx_shards` into the effective dataplane shard
/// count. `0` selects `min(available_parallelism, 4)`; the result is clamped
/// to `1` off Linux where `SO_REUSEPORT` sharding is unavailable.
fn resolve_rx_shards(configured: usize) -> usize {
    let resolved = match configured {
        0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(4),
        n => n,
    };
    #[cfg(target_os = "linux")]
    {
        resolved.max(1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        if resolved > 1 {
            log::warn!(
                "rx_shards={resolved} requested but RX sharding requires Linux \
                 SO_REUSEPORT; running the single-dataplane loop"
            );
        }
        1
    }
}

/// Apply the socket options every server dataplane socket shares: buffer
/// hints, nonblocking mode, and receive-side coalescing on Linux.
fn tune_server_udp_socket(std_socket: &std::net::UdpSocket) -> std::io::Result<()> {
    let socket_ref = socket2::SockRef::from(std_socket);
    if let Err(error) = socket_ref.set_recv_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES) {
        log::debug!("UDP receive buffer hint rejected: {}", error);
    }
    if let Err(error) = socket_ref.set_send_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES) {
        log::debug!("UDP send buffer hint rejected: {}", error);
    }
    std_socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    {
        // Receive-side coalescing; peers without GSO are unaffected.
        match qf_transport_udp::enable_udp_gro(std_socket) {
            Ok(true) => log::info!("UDP GRO enabled on server socket"),
            Ok(false) => log::debug!("UDP GRO unavailable on server socket"),
            Err(error) => log::debug!("UDP GRO enable failed: {error}"),
        }
    }
    Ok(())
}

/// Bind one dataplane socket; with `reuseport` the bind carries
/// `SO_REUSEADDR` + `SO_REUSEPORT` so sibling sockets share the port.
fn create_udp_socket(listen: SocketAddr, reuseport: bool) -> std::io::Result<std::net::UdpSocket> {
    #[cfg(not(target_os = "linux"))]
    let _ = reuseport;
    #[cfg(target_os = "linux")]
    if reuseport {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(listen),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_reuse_address(true)?;
        {
            use std::os::fd::AsRawFd;
            qf_transport_udp::enable_reuse_port_fd(socket.as_raw_fd())?;
        }
        socket.bind(&socket2::SockAddr::from(listen))?;
        let std_socket: std::net::UdpSocket = socket.into();
        tune_server_udp_socket(&std_socket)?;
        return Ok(std_socket);
    }
    let std_socket = std::net::UdpSocket::bind(listen)?;
    tune_server_udp_socket(&std_socket)?;
    Ok(std_socket)
}

/// Bind `count` dataplane sockets on `listen`. On Linux each carries
/// `SO_REUSEPORT`; if any sibling bind fails the whole set is dropped and a
/// single plain socket is bound instead (graceful N→1 fallback).
fn create_shard_sockets(listen: SocketAddr, count: usize) -> std::io::Result<Vec<Arc<UdpSocket>>> {
    let mut sockets = Vec::with_capacity(count);
    for shard in 0..count.max(1) {
        match create_udp_socket(listen, count > 1) {
            Ok(std_socket) => sockets.push(Arc::new(UdpSocket::from_std(std_socket)?)),
            Err(error) if count > 1 => {
                log::warn!(
                    "SO_REUSEPORT shard socket {shard}/{count} failed ({error}); \
                     falling back to a single dataplane socket"
                );
                drop(sockets);
                let std_socket = create_udp_socket(listen, false)?;
                return Ok(vec![Arc::new(UdpSocket::from_std(std_socket)?)]);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(sockets)
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
        server_config.masque_relay.validate().map_err(EngineError::Config)?;
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
        let pool =
            Arc::new(MemoryPool::new(optimize_config.pool_capacity, optimize_config.block_size));

        let domain = SharedServerDomain::try_new_with_clock(&server_config, &clock)
            .map_err(EngineError::Config)?;
        let stealth_runtime =
            Arc::new(StealthRuntimeOwner::from_env().map_err(|error| {
                EngineError::Config(format!("Invalid Reality config: {error}"))
            })?);

        Ok(Self {
            clock: clock.clone(),
            graceful_shutdown: Arc::new(GracefulShutdown::new(
                engine_config.engine.shutdown_timeout_ms,
            )),
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
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<IpAddr>>>,
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
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<IpAddr>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let mut runtime = Self::new_with_clock(engine_config, server_config.clone(), clock.clone())
            .map_err(std::io::Error::other)?;
        let tun_config = tun_config
            .map(|config| server_config.reconcile_standalone_tun_config(config))
            .transpose()
            .map_err(std::io::Error::other)?;
        let mut live_state =
            LiveServerState::try_new_with_clock(server_config.clone(), clock.clone())
                .map_err(std::io::Error::other)?;

        let shard_count = resolve_rx_shards(server_config.rx_shards);
        let shard_sockets = create_shard_sockets(server_config.listen, shard_count)
            .map_err(std::io::Error::other)?;
        let socket = Arc::clone(&shard_sockets[0]);
        let local_addr = socket.local_addr()?;
        // Sharded dataplane: per-shard channels + the global router are built
        // once here; worker forks are spawned when the run loop starts. The
        // coordinator fork never accepts clients, so its own shard id is the
        // sentinel and its uring worker stays disabled.
        let (shard_router, shard_receivers) = if shard_sockets.len() > 1 {
            let (senders, receivers) = shard_channels(shard_sockets.len(), SHARD_MESSAGE_CAPACITY);
            (Some(ShardRouter::new(senders)), Some(receivers))
        } else {
            (None, None)
        };
        if let Some(router) = &shard_router {
            live_state = live_state.shard_clone(COORDINATOR_SHARD_ID, Arc::clone(router));
            live_state.uring_worker = None;
            log::info!(
                "server RX sharding active: {} dataplane shards on {}",
                shard_sockets.len(),
                local_addr
            );
        } else {
            live_state.enable_uring_worker();
        }
        let (admin_actions_tx, admin_actions_rx) = mpsc::unbounded_channel::<AdminAction>();
        let accept_max_clients = server_config.max_clients;
        let server_tun_ip = Some(server_config.server_ip);
        let server_tun_ipv6 = server_config.ipv6_server_ip;
        let tun_notify = Arc::new(tokio::sync::Notify::new());
        let tun_fault = Arc::new(Mutex::new(None));
        let (server_tun, tun_rx, routing, tun_reader_shutdown, tun_reader_handle) = match tun_config
        {
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
                        // Pooled `TunPacket`s cross the channel directly: zero
                        // alloc, zero copy - the block returns to the TUN pool
                        // when the consumer drops it.
                        let (tx, rx) = std::sync::mpsc::sync_channel::<crate::interface::TunPacket>(
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
                                let read_result = tun_for_reader.reader_loop_with_shutdown_owned(
                                    &shutdown_for_loop,
                                    move |packet| {
                                        let v = packet.as_slice();
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
                                        if tx.send(packet).is_err() {
                                            if !shutdown_for_callback.load(Ordering::Acquire) {
                                                let mut fault = fault_for_callback.lock();
                                                if fault.is_none() {
                                                    *fault =
                                                        Some(DataPlaneFault::ChannelDisconnected {
                                                            component: "server TUN reader channel"
                                                                .to_string(),
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
            accept_loop: Arc::new(AcceptLoop::new(accept_config)),
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
            shard_sockets,
            shard_receivers,
            shard_router,
            shard_fault: Arc::new(Mutex::new(None)),
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
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<IpAddr>>>,
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
            self.stealth_runtime = Arc::new(StealthRuntimeOwner::from_env().map_err(|error| {
                EngineError::Config(format!("Invalid Reality config: {error}"))
            })?);
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
            handle.join().err().map(|_| "server TUN reader thread panicked".to_string())
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
        let uring_worker_error =
            self.live.as_mut().and_then(|live| live.live_state.stop_uring_worker());
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
            ServerState::Stopped => {
                crate::implementations::server::metrics::LifecyclePhase::Stopped
            }
            ServerState::Starting => {
                crate::implementations::server::metrics::LifecyclePhase::Starting
            }
            ServerState::Running => {
                crate::implementations::server::metrics::LifecyclePhase::Running
            }
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
    pub(super) fn live(&self) -> &ServerLiveRuntime {
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

    /// Delegate managed host routing teardown to privileged orchestration.
    ///
    /// Called after an irreversible privilege drop: this process then holds no
    /// capability to mutate host routing or read the root-owned durable
    /// record, so shutdown-time teardown would fail with permission errors and
    /// report a dirty stop. The durable record stays for the next privileged
    /// `cleanup_stale`.
    #[cfg(target_os = "linux")]
    pub fn delegate_host_routing_teardown(&self) {
        if let Some(routing) = self.live.as_ref().and_then(|live| live.routing.as_ref()) {
            routing.delegate_teardown();
        }
    }

    pub fn admin_actions_sender(&self) -> mpsc::UnboundedSender<AdminAction> {
        self.live().admin_actions_tx.clone()
    }

    pub fn live_client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.live().live_state.client_snapshots()
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<IpAddr>>> {
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

    /// Fork `LiveServerState` per shard and spawn one dataplane worker task
    /// per `SO_REUSEPORT` socket. Empty when sharding is inactive (N=1 path).
    #[allow(clippy::too_many_arguments)]
    fn spawn_shard_workers(
        &mut self,
        runtime_config: &PreparedStandaloneRuntimeConfig,
        metrics: &Arc<Metrics>,
        dns_intercept_workers: &Arc<DnsInterceptWorkerOwner>,
        dns_upstream_resolvers: &Arc<Vec<Ipv4Addr>>,
        dns_intercept_admission: &Arc<crate::dns::DnsAdmission>,
        tun_ctx: &ServerTunContext,
        tun_enable: bool,
        masque_relay_owner: Option<Arc<MasqueRelayOwner>>,
    ) -> Vec<tokio::task::JoinHandle<Result<(), DataPlaneFault>>> {
        let Some(router) = self.live().shard_router.clone() else {
            return Vec::new();
        };
        let Some(receivers) = self.live_mut().shard_receivers.take() else {
            return Vec::new();
        };
        let shard_count = self.live().shard_sockets.len();
        // Per-shard admission budget: the global cap stays enforced through
        // the shared `AcceptLoop`; the per-shard slice only bounds local map
        // growth so no single shard hoards the whole budget.
        let accept_budget = (self.live().accept_max_clients / shard_count).max(1);
        let mut assignment_settings = self.assignment_settings.clone();
        if let Some(tun) = self.live().server_tun.as_ref() {
            assignment_settings.mtu = tun.mtu();
        }
        // Clone `self`-derived handles before `live_mut` mutably borrows.
        let shutdown = Arc::clone(&self.shutdown);
        let stealth_runtime = self.stealth_runtime.clone();
        let crypto_config = self.engine_config.crypto.clone();
        let clock = self.clock.clone();
        let live = self.live_mut();
        let mut handles = Vec::with_capacity(shard_count);
        for (shard_id, shard_rx) in receivers.into_iter().enumerate() {
            let state = live.live_state.shard_clone(shard_id, Arc::clone(&router));
            let ctx = super::sharding::ShardWorkerCtx {
                shard_id,
                router: Arc::clone(&router),
                socket: Arc::clone(&live.shard_sockets[shard_id]),
                local_addr: live.local_addr,
                accept_loop: Arc::clone(&live.accept_loop),
                accept_max_clients: accept_budget,
                metrics: Arc::clone(metrics),
                blocked_ips: Arc::clone(&live.blocked_ips),
                qkey_registry: Arc::clone(&live.qkey_registry),
                dns_intercept_admission: Arc::clone(dns_intercept_admission),
                dns_intercept_workers: Arc::clone(dns_intercept_workers),
                dns_upstream_resolvers: Arc::clone(dns_upstream_resolvers),
                tun_ctx: tun_ctx.clone(),
                tun_enable,
                assignment_settings: assignment_settings.clone(),
                tun_notify: Arc::clone(&live.tun_notify),
                shutdown: Arc::clone(&shutdown),
                stealth_runtime: Some(stealth_runtime.clone()),
                stealth_config: runtime_config.stealth_config.clone(),
                fec_cfg_shared: runtime_config.fec_cfg_shared.clone(),
                opt_params_shared: runtime_config.opt_params_shared.clone(),
                transport: runtime_config.transport.clone(),
                runtime_policy_generation: runtime_config.runtime_policy_generation.clone(),
                crypto_config: crypto_config.clone(),
                #[cfg(feature = "rate_limiter")]
                retry_token_manager: live.live_state.retry_token_manager.clone(),
                clock: clock.clone(),
                masque_relay_owner: masque_relay_owner.clone(),
                shard_fault: Arc::clone(&live.shard_fault),
            };
            handles.push(tokio::spawn(super::sharding::run_shard_worker(state, ctx, shard_rx)));
        }
        log::info!("spawned {} dataplane shard workers", handles.len());
        handles
    }

    /// Broadcast `Shutdown` to every shard and join their tasks with a bound.
    /// Runs before `stop()` so worker-held client state closes while the
    /// shared domain is still intact.
    async fn shutdown_shard_workers(
        &self,
        workers: Vec<tokio::task::JoinHandle<Result<(), DataPlaneFault>>>,
        reason: &'static [u8],
    ) {
        if let Some(router) = self.live().shard_router.clone() {
            for shard in 0..router.shard_count() {
                let _ = router.send(shard, ShardMessage::Shutdown { reason });
            }
        }
        let join = async move {
            for handle in workers {
                if let Err(error) = handle.await {
                    log::warn!("shard worker task join failed: {error}");
                }
            }
        };
        if tokio::time::timeout(SHARD_WORKER_JOIN_TIMEOUT, join).await.is_err() {
            log::warn!(
                "shard worker join exceeded {} ms; continuing teardown",
                SHARD_WORKER_JOIN_TIMEOUT.as_millis()
            );
        }
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
            accept_loop: live.accept_loop.as_ref(),
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

    pub(super) fn sync_standalone_runtime_metadata(
        &mut self,
        metadata: &StandaloneRuntimeMetadata,
    ) {
        self.live_mut().standalone_runtime_metadata = Some(metadata.clone());
    }

    fn ensure_standalone_runtime_metadata(&mut self, metadata: &StandaloneRuntimeMetadata) {
        if self.live().standalone_runtime_metadata.is_none() {
            self.sync_standalone_runtime_metadata(metadata);
        }
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
                    live.live_state.kick_client(&identity, live.accept_loop.as_ref(), metrics)
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
                        live.accept_loop.as_ref(),
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

    pub(super) fn reload_standalone_runtime(
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
                // Propagate the reloaded construction transport to every
                // dataplane shard; they build new clients from their own copy.
                if let Some(router) = self.live().shard_router.clone() {
                    let transport = Box::new(runtime_config.transport.clone());
                    for shard in 0..router.shard_count() {
                        if router
                            .send(
                                shard,
                                ShardMessage::ReloadTransport { transport: transport.clone() },
                            )
                            .is_err()
                        {
                            log::warn!(
                                "transport reload propagation to shard {} dropped (queue full)",
                                shard
                            );
                        }
                    }
                }
                let active_sessions = self.active_client_count();
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
            && (self.active_client_count() == 0 || self.graceful_shutdown.deadline_reached())
    }

    /// Global client count: the router's owner keyset under sharding, else
    /// the coordinator's local map.
    fn active_client_count(&self) -> usize {
        let live = self.live();
        live.shard_router
            .as_ref()
            .map_or_else(|| live.live_state.client_count(), |router| router.len())
    }

    pub(super) async fn finish_drain(
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
            live.live_state.force_close_and_flush(
                socket,
                out,
                metrics,
                live.accept_loop.as_ref(),
                reason,
            ),
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
        let report =
            self.stealth_runtime.shutdown(crate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT).await?;
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
