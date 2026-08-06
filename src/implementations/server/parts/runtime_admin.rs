use crate::time_source::ProtocolClock;

/// Server runtime handle.
pub struct ServerRuntime {
    /// Monotonic protocol clock shared by runtime-owned state machines.
    clock: ProtocolClock,
    /// Engine configuration
    engine_config: EngineConfig,
    /// Server-specific configuration
    server_config: ServerConfig,
    /// Validated assignment settings used by every live client session.
    assignment_settings: ServerAssignmentSettings,
    /// Memory pool
    pool: Arc<MemoryPool>,
    /// Embedded host resources
    host_resources: Option<ServerHostResources>,
    /// Shared server domain owner
    domain: SharedServerDomain,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Server state
    state: ServerState,
    /// Shared graceful-shutdown state exposed to control planes.
    graceful_shutdown: Arc<GracefulShutdown>,
    /// Statistics
    stats: Arc<ServerStats>,
    /// Optional standalone live UDP runtime state.
    live: Option<ServerLiveRuntime>,
    /// Owner for accepted standalone DNS interception blocking operations.
    dns_intercept_workers: Option<Arc<DnsInterceptWorkerOwner>>,
    /// Shared owner for all stealth background workers of this generation.
    stealth_runtime: Arc<StealthRuntimeOwner>,
}

/// Server state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerState {
    Stopped,
    Starting,
    Running,
    Draining,
    Stopping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShutdownLifecycle {
    Stopped = 0,
    Running = 1,
    Draining = 2,
}

impl ShutdownLifecycle {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Draining,
            _ => Self::Stopped,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Draining => "draining",
        }
    }
}

struct GracefulShutdown {
    lifecycle: AtomicU8,
    grace_ms: AtomicU64,
    /// Native runtime monotonic time keeps drain progress live while the
    /// protocol clock is manually controlled by tests or an embedding host.
    drain_started: parking_lot::RwLock<Option<Instant>>,
}

impl GracefulShutdown {
    #[allow(dead_code)]
    fn new(grace_ms: u64) -> Self {
        Self {
            lifecycle: AtomicU8::new(ShutdownLifecycle::Stopped as u8),
            grace_ms: AtomicU64::new(grace_ms),
            drain_started: parking_lot::RwLock::new(None),
        }
    }

    fn lifecycle(&self) -> ShutdownLifecycle {
        ShutdownLifecycle::from_u8(self.lifecycle.load(Ordering::Acquire))
    }

    fn set_running(&self) {
        *self.drain_started.write() = None;
        self.lifecycle.store(ShutdownLifecycle::Running as u8, Ordering::Release);
    }

    fn begin_drain(&self) -> bool {
        if self
            .lifecycle
            .compare_exchange(
                ShutdownLifecycle::Running as u8,
                ShutdownLifecycle::Draining as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        *self.drain_started.write() = Some(Instant::now());
        true
    }

    fn set_stopped(&self) {
        *self.drain_started.write() = None;
        self.lifecycle.store(ShutdownLifecycle::Stopped as u8, Ordering::Release);
    }

    fn grace(&self) -> Duration {
        Duration::from_millis(self.grace_ms.load(Ordering::Acquire))
    }

    fn set_grace_ms(&self, grace_ms: u64) {
        self.grace_ms.store(grace_ms, Ordering::Release);
    }

    fn elapsed(&self) -> Duration {
        self.drain_started
            .read()
            .as_ref()
            .map(|started| Instant::now().saturating_duration_since(*started))
            .unwrap_or_default()
    }

    fn deadline_reached(&self) -> bool {
        self.lifecycle() == ShutdownLifecycle::Draining && self.elapsed() >= self.grace()
    }

    fn status_json(&self, active_connections: u64) -> serde_json::Value {
        serde_json::json!({
            "state": self.lifecycle().as_str(),
            "active_connections": active_connections,
            "grace_period_ms": self.grace().as_millis() as u64,
            "drain_elapsed_ms": self.elapsed().as_millis() as u64,
        })
    }
}

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub connections_rejected: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerTrafficSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub connections_rejected: u64,
}

pub enum AdminAction {
    Kick(String),
    RevokeQKey(String),
    Reload,
    Drain,
    Shutdown,
}

#[derive(Clone)]
struct SharedServerDomain {
    clock: ProtocolClock,
    sessions: Arc<RwLock<SessionManager>>,
    forwarding_policy: Arc<ClientIsolationManager>,
    ip_pool: Arc<parking_lot::Mutex<IpPool>>,
    /// IPv6 address pool (None = IPv6 disabled). Allocated lazily from ServerConfig.
    ipv6_pool: Option<Arc<parking_lot::Mutex<Ipv6Pool>>>,
    connection_limiter: Arc<parking_lot::Mutex<ConnectionLimiter>>,
    #[cfg(feature = "rate_limiter")]
    packet_rate_limiter: Arc<parking_lot::Mutex<PacketRateLimiterDomain>>,
    /// Server-wide global rate limiter - caps aggregate PPS across all IPs
    /// to prevent total overload when many sources each stay under the per-IP
    /// limit. Checked before per-IP limiting on the accept hot path.
    #[cfg(feature = "rate_limiter")]
    global_rate_limiter: Arc<GlobalRateLimiter>,
    /// EWMA-based DDoS anomaly detector (TODO-459). When a traffic spike is
    /// detected, per-IP limits are temporarily halved via `limit_multiplier`.
    #[cfg(feature = "rate_limiter")]
    ddos_detector: Arc<crate::implementations::server::limits::EwmaAnomalyDetector>,
    #[cfg(feature = "rate_limiter")]
    retry_token_manager:
        Option<Arc<crate::implementations::server::ddos::RetryTokenManager>>,
    /// GeoIP-based source-IP blocker (TODO-459). Uses `maxminddb` to look up
    /// the country of an incoming IP and reject blocked countries. Configured
    /// activation failures are propagated before the server becomes ready.
    #[cfg(feature = "rate_limiter")]
    geoip_blocker: Arc<crate::implementations::server::limits::GeoIpBlocker>,
    /// External blacklist synchronizer (TODO-459). TTL-based IP blocklist with
    /// optional external feed sync (plain-text IP lists over HTTPS).
    #[cfg(feature = "rate_limiter")]
    blacklist: Arc<crate::implementations::server::limits::BlacklistSync>,
    max_clients: usize,
    client_timeout_secs: u64,
}

#[cfg(feature = "rate_limiter")]
struct PacketRateLimiterDomain {
    limiter: RateLimiter,
    last_prune: Instant,
    last_sample: Instant,
}

struct ServerHostResources {
    tun: TunInterface,
    routing: Option<RoutingManager>,
}

#[cfg(target_os = "linux")]
fn configured_routing_manager(
    tun_name: String,
    server_config: &ServerConfig,
) -> Result<RoutingManager, String> {
    let configured_wan = server_config.wan_interface.trim();
    let configured_wan_exists = !configured_wan.is_empty()
        && std::path::Path::new("/sys/class/net").join(configured_wan).exists();
    let wan_interface = if configured_wan_exists {
        configured_wan.to_string()
    } else {
        detect_wan_interface().ok_or_else(|| {
            format!(
                "configured WAN interface {:?} does not exist and no default-route interface was detected",
                server_config.wan_interface
            )
        })?
    };
    let routing = if let Some(ipv6_server_ip) = server_config.ipv6_server_ip {
        RoutingManager::new_dual_stack(
            tun_name,
            server_config.server_ip,
            server_config.server_netmask,
            wan_interface,
            ipv6_server_ip,
            server_config.ipv6_prefix_len,
        )
    } else {
        RoutingManager::new(
            tun_name,
            server_config.server_ip,
            server_config.server_netmask,
            wan_interface,
        )
    };
    Ok(routing
        .with_client_to_client(server_config.allow_client_to_client)
        .with_firewall_backend(server_config.firewall_backend))
}

#[cfg(target_os = "linux")]
fn cleanup_stale_routing_records(
    requested_tun_name: Option<&str>,
    server_config: &ServerConfig,
) -> Result<(), String> {
    let tun_names = match requested_tun_name {
        Some(name) if !name.is_empty() && name.len() <= 15 && !name.contains('/') && !name.contains('\0') => {
            vec![name.to_string()]
        }
        Some(_) => return Ok(()),
        None => crate::implementations::server::routing::persisted_tun_names()
            .map_err(|error| format!("enumerate stale routing records: {error}"))?,
    };
    for tun_name in tun_names {
        let routing = configured_routing_manager(tun_name, server_config)?;
        routing
            .cleanup_stale()
            .map_err(|error| format!("stale routing cleanup failed: {error}"))?;
    }
    Ok(())
}

fn teardown_routing(routing: RoutingManager) -> Result<(), RoutingError> {
    routing.teardown().map_err(|error| {
        log::error!("Routing teardown failed: {:?}", error);
        crate::audit::audit_typed(
            crate::audit::AuditEventType::FirewallRuleRemoved,
            crate::audit::AuditSeverity::Critical,
            None,
            None,
            crate::audit::AuditContext {
                actor: crate::audit::AuditActor::System,
                target: crate::audit::AuditTarget::Route,
                outcome: crate::audit::AuditOutcome::Failed,
                reason: Some("routing_teardown_failed"),
            },
            &format!("Routing teardown failed: {error}"),
        );
        error
    })
}

impl ServerHostResources {
    fn start(
        engine_config: &EngineConfig,
        server_config: &ServerConfig,
        pool: Arc<MemoryPool>,
    ) -> Result<Self, EngineError> {
        let tun_config = server_config.server_tun_config(
            Some("qfserver0".to_string()),
            engine_config.interface.tun_mtu,
            engine_config.interface.zero_copy,
        );

        #[cfg(target_os = "linux")]
        {
            crate::interface::validate_tun_config(&tun_config)
                .map_err(|error| EngineError::Tun(format!("{error:?}")))?;
            cleanup_stale_routing_records(Some("qfserver0"), server_config)
                .map_err(EngineError::Io)?;
        }

        let tun = open_server_tun(tun_config, pool).map_err(EngineError::Tun)?;
        log::info!("Server TUN interface opened: {}", tun.name());

        #[cfg(target_os = "linux")]
        let routing = {
            let routing = configured_routing_manager("qfserver0".to_string(), server_config)
                .map_err(EngineError::Io)?;

            if let Err(e) = routing.setup() {
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
                    &format!("Server routing setup failed: {e}"),
                );
                let detail = rollback_error.map_or_else(
                    || format!("server routing setup failed: {e}"),
                    |rollback| {
                        format!(
                            "server routing setup failed: {e}; owned rollback failed: {rollback}"
                        )
                    },
                );
                return Err(EngineError::Io(detail));
            }
            Some(routing)
        };

        #[cfg(not(target_os = "linux"))]
        let routing = None;

        Ok(Self { tun, routing })
    }

    fn teardown(self) -> Result<(), EngineError> {
        let routing_result = self.routing.map(teardown_routing).transpose();
        log::info!("Closing server TUN: {}", self.tun.name());
        drop(self.tun);
        routing_result
            .map(|_| ())
            .map_err(|error| EngineError::Io(format!("server routing teardown failed: {error}")))
    }
}

impl SharedServerDomain {
    #[allow(dead_code)]
    fn try_new(server_config: &ServerConfig) -> Result<Self, String> {
        Self::try_new_with_clock(server_config, &ProtocolClock::default())
    }

    fn try_new_with_clock(
        server_config: &ServerConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, String> {
        // Create IPv6 pool only if both start and end are configured
        let ipv6_pool = match (server_config.ipv6_pool_start, server_config.ipv6_pool_end) {
            (Some(start), Some(end)) => {
                Some(Arc::new(parking_lot::Mutex::new(Ipv6Pool::new(start, end))))
            }
            _ => None,
        };
        Ok(Self {
            clock: clock.clone(),
            sessions: Arc::new(RwLock::new(SessionManager::with_bandwidth_manager(
                server_config.max_clients,
                PerClientBandwidthManager::new_with_clock(
                    server_config.bandwidth_policy.clone(),
                    clock,
                )
                    .expect("validated server bandwidth policy"),
            ))),
            forwarding_policy: Arc::new(ClientIsolationManager::with_network(
                server_config.server_ip,
                server_config.server_netmask,
                server_config.allow_client_to_client,
            )),
            ip_pool: Arc::new(parking_lot::Mutex::new(IpPool::new(
                server_config.ip_pool_start,
                server_config.ip_pool_end,
            ))),
            ipv6_pool,
            connection_limiter: Arc::new(parking_lot::Mutex::new(ConnectionLimiter::new(
                DEFAULT_MAX_CONNECTIONS_PER_IP,
            ))),
            #[cfg(feature = "rate_limiter")]
            packet_rate_limiter: Arc::new(parking_lot::Mutex::new(PacketRateLimiterDomain {
                limiter: RateLimiter::new_with_clock(load_rate_limit_config_from_env(), clock),
                last_prune: clock.now(),
                last_sample: clock.now(),
            })),
            #[cfg(feature = "rate_limiter")]
            global_rate_limiter: Arc::new(GlobalRateLimiter::with_default_cap_with_clock(clock)),
            #[cfg(feature = "rate_limiter")]
            ddos_detector: Arc::new(
                crate::implementations::server::limits::EwmaAnomalyDetector::with_config_and_clock(
                    server_config.ddos_policy.clone(),
                    clock,
                )
                .expect("validated server DDoS policy"),
            ),
            #[cfg(feature = "rate_limiter")]
            retry_token_manager: (server_config.ddos_policy.enabled
                && server_config.ddos_policy.retry_enabled)
                .then(|| {
                    Arc::new(
                        crate::implementations::server::ddos::RetryTokenManager::new(
                            server_config.ddos_policy.retry_token_lifetime,
                        )
                        .expect("validated Retry token lifetime"),
                    )
                }),
            #[cfg(feature = "rate_limiter")]
            geoip_blocker: Arc::new(
                crate::implementations::server::limits::GeoIpBlocker::try_new(
                    server_config.geoip.clone(),
                )
                .map_err(|error| {
                    log::error!("GeoIP activation failed: {error}");
                    format!("GeoIP activation failed: {error}")
                })?,
            ),
            #[cfg(feature = "rate_limiter")]
            blacklist: Arc::new(
                crate::implementations::server::limits::BlacklistSync::new_bounded_with_ca_and_clock(
                    Duration::from_secs(server_config.blacklist.default_ttl_secs),
                    server_config.blacklist.sync_url.clone(),
                    Duration::from_secs(server_config.blacklist.sync_interval_secs),
                    Duration::from_secs(server_config.blacklist.request_timeout_secs),
                    server_config.blacklist.max_body_bytes,
                    server_config.blacklist.max_entries,
                    server_config.blacklist.cache_path.clone(),
                    server_config.blacklist.custom_ca_path.clone(),
                    clock,
                )
                .expect("validated server blacklist policy"),
            ),
            max_clients: server_config.max_clients,
            client_timeout_secs: server_config.client_timeout_secs,
        })
    }

    #[cfg(feature = "rate_limiter")]
    fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        self.geoip_blocker.status()
    }

    fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let accepted = accept_session_in_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
            remote_addr,
            self.max_clients,
            self.client_timeout_secs,
            &self.clock,
        );
        if let Ok((session_id, _, addresses)) = accepted.as_ref() {
            self.forwarding_policy.assign_client(&session_id.as_u64().to_string(), *addresses);
        }
        accepted
    }

    fn remove(&self, session_id: SessionId) -> Option<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let removed = remove_session_from_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
            session_id,
        );
        if let Some(session) = removed.as_ref() {
            self.forwarding_policy.release_client(AssignedClientIps {
                ipv4: session.client_ip(),
                ipv6: session.client_ipv6(),
            });
        }
        removed
    }

    fn reap_expired(&self) -> Vec<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let removed = reap_expired_sessions_from_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
        );
        for session in &removed {
            self.forwarding_policy.release_client(AssignedClientIps {
                ipv4: session.client_ip(),
                ipv6: session.client_ipv6(),
            });
        }
        removed
    }

    #[cfg(feature = "rate_limiter")]
    fn admit_incoming_datagram(
        &self,
        from: SocketAddr,
        packet: &[u8],
        established: bool,
        retry_eligible: bool,
        metrics: &Metrics,
    ) -> crate::implementations::server::ddos::IncomingDatagramAdmission {
        use crate::implementations::server::ddos::{DdosDropReason, IncomingDatagramAdmission};

        // 1. Global server-wide cap: drop if aggregate PPS exceeds the cap,
        //    regardless of source IP. This is checked first so a flood from
        //    many IPs cannot overwhelm the host even if each is under its
        //    per-IP limit.
        if !self.global_rate_limiter.check() {
            return IncomingDatagramAdmission::Drop(DdosDropReason::GlobalLimit);
        }
        // 2. GeoIP blocking (TODO-459): a disabled policy is a zero-cost allow
        //    path. An active policy fails closed on lookup/decode errors.
        if self.geoip_blocker.is_enabled() {
            metrics.record_geoip_lookup();
            match self.geoip_blocker.lookup(from.ip()) {
                Ok(true) => {
                    metrics.record_geoip_blocked();
                    return IncomingDatagramAdmission::Drop(DdosDropReason::GeoIp);
                }
                Ok(false) => {}
                Err(error) => {
                    metrics.record_geoip_lookup_error();
                    log::error!(
                        "GeoIP lookup failed for {}; dropping datagram fail-closed: {}",
                        from.ip(),
                        error
                    );
                    return IncomingDatagramAdmission::Drop(DdosDropReason::GeoIp);
                }
            }
        }
        // 3. External blacklist (TODO-459): drop if the source IP is on the
        //    TTL-based blocklist (manual or from an external feed).
        if self.blacklist.is_blocked(from.ip()) {
            return IncomingDatagramAdmission::Drop(DdosDropReason::Blacklist);
        }
        // 4. One per-IP bucket owns both normal and enhanced admission.
        //    Enhanced mode consumes a validated higher token cost instead of
        //    probabilistically discarding arbitrary packets.
        let packet_cost =
            if established { 1 } else { self.ddos_detector.enhanced_packet_cost() };
        let limiter = self.packet_rate_limiter.lock();
        let allowed_packet = limiter.limiter.check_packet_ip_cost(from.ip(), packet_cost);
        let allowed_bytes =
            allowed_packet && limiter.limiter.check_bytes_ip(from.ip(), packet.len() as u64);
        drop(limiter);
        if !allowed_packet || !allowed_bytes {
            return IncomingDatagramAdmission::Drop(DdosDropReason::PerIpLimit);
        }

        let Some(retry_tokens) = self
            .retry_token_manager
            .as_ref()
            .filter(|_| retry_eligible && !established && self.ddos_detector.is_anomaly())
        else {
            return IncomingDatagramAdmission::Allow;
        };
        let Ok((header, _)) = crate::transport::packet::parse_header(packet, 0) else {
            return IncomingDatagramAdmission::Drop(DdosDropReason::MalformedInitial);
        };
        if header.ty != crate::transport::PacketType::Initial {
            return IncomingDatagramAdmission::Drop(DdosDropReason::MalformedInitial);
        }
        if let Some(token) = header.token.as_deref() {
            if crate::implementations::server::ddos::RetryTokenManager::is_retry_token(token) {
                return if retry_tokens.validate(token, from.ip(), &header.dcid).is_ok() {
                    IncomingDatagramAdmission::RetryValidated
                } else {
                    IncomingDatagramAdmission::Drop(DdosDropReason::InvalidRetry)
                };
            }
        }
        match retry_tokens.issue_for_initial(packet, from.ip()) {
            Ok(issue) => IncomingDatagramAdmission::Retry(issue.packet),
            Err(error) => {
                log::debug!("QUIC Retry issuance rejected for {}: {}", from, error);
                IncomingDatagramAdmission::Drop(DdosDropReason::MalformedInitial)
            }
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self, metrics: &Metrics) {
        let should_sample = {
            let mut limiter = self.packet_rate_limiter.lock();
            if self.clock.elapsed_since(limiter.last_prune) >= Duration::from_secs(30) {
                limiter.limiter.prune_idle(Duration::from_secs(120));
                limiter.last_prune = self.clock.now();
                self.blacklist.prune_expired();
            }
            let due = self.clock.elapsed_since(limiter.last_sample)
                >= self.ddos_detector.sample_interval();
            if due {
                limiter.last_sample = self.clock.now();
            }
            due
        };
        if should_sample {
            let pps = self.global_rate_limiter.current_pps();
            let transition = self.ddos_detector.record_pps(pps);
            metrics.record_ddos_sample(pps, transition);
            match transition {
                crate::implementations::server::limits::DdosTransition::Activated => {
                    log::warn!("Enhanced DDoS admission activated at {pps} accepted PPS");
                    crate::audit::audit_typed(
                        crate::audit::AuditEventType::DdosAnomaly,
                        crate::audit::AuditSeverity::Warning,
                        None,
                        None,
                        crate::audit::AuditContext {
                            actor: crate::audit::AuditActor::NetworkPeer,
                            target: crate::audit::AuditTarget::System,
                            outcome: crate::audit::AuditOutcome::Detected,
                            reason: Some("sustained_pps_activation"),
                        },
                        &format!("Enhanced DDoS admission activated at {pps} accepted PPS"),
                    );
                }
                crate::implementations::server::limits::DdosTransition::Cleared => {
                    log::info!("Enhanced DDoS admission cleared at {pps} accepted PPS");
                    crate::audit::audit_typed(
                        crate::audit::AuditEventType::DdosAnomaly,
                        crate::audit::AuditSeverity::Info,
                        None,
                        None,
                        crate::audit::AuditContext {
                            actor: crate::audit::AuditActor::NetworkPeer,
                            target: crate::audit::AuditTarget::System,
                            outcome: crate::audit::AuditOutcome::Stopped,
                            reason: Some("sustained_pps_recovery"),
                        },
                        &format!("Enhanced DDoS admission cleared at {pps} accepted PPS"),
                    );
                }
                crate::implementations::server::limits::DdosTransition::Unchanged => {}
            }
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn remove_rate_limited_ip(&self, ip: IpAddr) {
        self.packet_rate_limiter.lock().limiter.remove_ip(ip);
    }

    fn traffic_snapshot(&self) -> ServerTrafficSnapshot {
        let sessions = self.sessions.read();
        let mut snapshot = ServerTrafficSnapshot {
            active_connections: sessions.len() as u64,
            ..ServerTrafficSnapshot::default()
        };
        for (_, session) in sessions.iter() {
            let stats = session.stats();
            snapshot.bytes_in =
                snapshot.bytes_in.saturating_add(stats.bytes_received.load(Ordering::Relaxed));
            snapshot.bytes_out =
                snapshot.bytes_out.saturating_add(stats.bytes_sent.load(Ordering::Relaxed));
            snapshot.packets_in =
                snapshot.packets_in.saturating_add(stats.packets_received.load(Ordering::Relaxed));
            snapshot.packets_out =
                snapshot.packets_out.saturating_add(stats.packets_sent.load(Ordering::Relaxed));
        }
        snapshot
    }

    fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.read().all_session_ids()
    }

    fn session_stats(&self, session_id: SessionId) -> Option<Arc<SessionStats>> {
        self.sessions.read().get(session_id).map(|session| Arc::clone(session.stats()))
    }
}

#[derive(Clone)]
struct ServerAdminControlPlane {
    actions: mpsc::UnboundedSender<AdminAction>,
    listen_addr: String,
    front_domain: Vec<String>,
    qkeys: Arc<std::sync::Mutex<QKeyRegistry>>,
    graceful_shutdown: Arc<GracefulShutdown>,
}

#[derive(Clone)]
pub struct ServerAdminCore {
    clock: ProtocolClock,
    metrics: Arc<Metrics>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    sessions: Arc<RwLock<SessionManager>>,
    control_plane: ServerAdminControlPlane,
    admin_http_diagnostics:
        Option<Arc<crate::implementations::server::AdminHttpOperationDiagnostics>>,
    #[cfg(feature = "rate_limiter")]
    geoip_status: crate::implementations::server::limits::GeoIpStatus,
}

impl ServerAdminCore {
    #[allow(dead_code)]
    fn new(
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<
            std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>,
        >,
        sessions: Arc<RwLock<SessionManager>>,
        control_plane: ServerAdminControlPlane,
        #[cfg(feature = "rate_limiter")] geoip_status:
            crate::implementations::server::limits::GeoIpStatus,
    ) -> Self {
        Self::new_with_clock(
            metrics,
            blocked_ips,
            client_snapshots,
            sessions,
            control_plane,
            #[cfg(feature = "rate_limiter")]
            geoip_status,
            ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_clock(
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<
            std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>,
        >,
        sessions: Arc<RwLock<SessionManager>>,
        control_plane: ServerAdminControlPlane,
        #[cfg(feature = "rate_limiter")] geoip_status:
            crate::implementations::server::limits::GeoIpStatus,
        clock: ProtocolClock,
    ) -> Self {
        Self {
            clock,
            metrics,
            blocked_ips,
            client_snapshots,
            sessions,
            control_plane,
            admin_http_diagnostics: None,
            #[cfg(feature = "rate_limiter")]
            geoip_status,
        }
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<String>>> {
        &self.blocked_ips
    }

    pub fn listen_addr(&self) -> &str {
        self.control_plane.listen_addr.as_str()
    }

    pub fn qkeys(&self) -> &Arc<std::sync::Mutex<QKeyRegistry>> {
        &self.control_plane.qkeys
    }

    pub fn set_admin_http_operation_diagnostics(
        &mut self,
        diagnostics: Arc<crate::implementations::server::AdminHttpOperationDiagnostics>,
    ) {
        self.admin_http_diagnostics = Some(diagnostics);
    }

    #[cfg(feature = "rate_limiter")]
    pub fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        self.geoip_status
    }

    pub fn base_status_json(&self) -> serde_json::Value {
        let mut data = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.metrics.uptime_secs(),
            "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
            "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
            "connections_accepted": self.metrics.connections_accepted.load(Ordering::Relaxed),
            "connections_rejected": self.metrics.connections_rejected.load(Ordering::Relaxed),
            "auth_attempts": self.metrics.auth_attempts.load(Ordering::Relaxed),
            "auth_succeeded": self.metrics.auth_succeeded.load(Ordering::Relaxed),
            "auth_failed": self.metrics.auth_failed.load(Ordering::Relaxed),
            "auth_backoff_rejected": self.metrics.auth_backoff_rejected.load(Ordering::Relaxed),
            "auth_blocked_rejected": self.metrics.auth_blocked_rejected.load(Ordering::Relaxed),
            "auth_capacity_rejected": self.metrics.auth_capacity_rejected.load(Ordering::Relaxed),
            "auth_state_tracked_ips": self.metrics.auth_state_tracked_ips.load(Ordering::Relaxed),
            "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
        });
        #[cfg(feature = "rate_limiter")]
        {
            data["geoip"] = serde_json::json!({
                "status": self.geoip_status.as_str(),
                "active": self.geoip_status == crate::implementations::server::limits::GeoIpStatus::Active,
            });
            if let Ok(health) = serde_json::from_str::<serde_json::Value>(&self.metrics.export_health()) {
                data["blacklist_sync"] = health["blacklist_sync"].clone();
            }
        }
        if let Some(diagnostics) = self.admin_http_diagnostics.as_ref() {
            data["admin_http"] = serde_json::json!(diagnostics.snapshot());
        }
        data
    }

    pub fn health_json(&self) -> serde_json::Value {
        let mut data = serde_json::json!({ "status": "ok" });
        #[cfg(feature = "rate_limiter")]
        {
            data["geoip_status"] = serde_json::Value::String(self.geoip_status.as_str().to_string());
            if let Ok(health) = serde_json::from_str::<serde_json::Value>(&self.metrics.export_health()) {
                data["blacklist_sync"] = health["blacklist_sync"].clone();
            }
        }
        if let Some(diagnostics) = self.admin_http_diagnostics.as_ref() {
            data["admin_http"] = serde_json::json!(diagnostics.snapshot());
        }
        data
    }

    pub fn drain(&self) -> AdminResponse {
        self.dispatch_action(AdminAction::Drain, "Drain scheduled".to_string())
    }

    pub fn drain_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(
            self.control_plane
                .graceful_shutdown
                .status_json(self.metrics.clients_active.load(Ordering::Relaxed)),
        )
    }

    pub fn list_clients(&self) -> Vec<ClientInfo> {
        let guard = match self.client_snapshots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        snapshots_to_client_info(&guard, self.clock.now())
    }

    fn resolve_session_id(&self, raw: &str) -> Option<SessionId> {
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return self.sessions.read().session_id_by_client_ip(ip);
        }
        let identity = ClientIdentity::parse(raw)?;
        let sessions = self.sessions.read();
        match identity {
            ClientIdentity::Session(id) => sessions.contains(id).then_some(id),
            ClientIdentity::Remote(addr) => sessions.session_id_by_remote_addr(addr),
        }
    }

    fn audit_bandwidth_admin(
        &self,
        client_id: &str,
        action: &str,
        outcome: crate::audit::AuditOutcome,
        reason: Option<&str>,
    ) {
        crate::audit::audit_typed(
            crate::audit::AuditEventType::AdminAction,
            if outcome == crate::audit::AuditOutcome::Succeeded {
                crate::audit::AuditSeverity::Info
            } else {
                crate::audit::AuditSeverity::Warning
            },
            None,
            Some(client_id),
            crate::audit::AuditContext {
                actor: crate::audit::AuditActor::Administrator,
                target: crate::audit::AuditTarget::Client,
                outcome,
                reason,
            },
            action,
        );
    }

    pub fn client_bandwidth(&self, id: &str) -> AdminResponse {
        let Some(session_id) = self.resolve_session_id(id) else {
            return AdminResponse::error("Client not found");
        };
        let sessions = self.sessions.read();
        match sessions.bandwidth_stats(session_id) {
            Some(stats) => AdminResponse::ok_with_data(serde_json::json!({
                "client_id": ClientIdentity::Session(session_id).to_string(),
                "bandwidth": stats,
            })),
            None => AdminResponse::error("Client bandwidth state not found"),
        }
    }

    pub fn set_client_bandwidth(&self, id: &str, policy: BandwidthPolicy) -> AdminResponse {
        if let Err(error) = policy.validate() {
            self.audit_bandwidth_admin(
                id,
                "Client bandwidth policy update rejected",
                crate::audit::AuditOutcome::Denied,
                Some("invalid_bandwidth_policy"),
            );
            return AdminResponse::error(error);
        }
        let Some(session_id) = self.resolve_session_id(id) else {
            self.audit_bandwidth_admin(
                id,
                "Client bandwidth policy update rejected",
                crate::audit::AuditOutcome::Denied,
                Some("client_not_found"),
            );
            return AdminResponse::error("Client not found");
        };
        let canonical_id = ClientIdentity::Session(session_id).to_string();
        match self.sessions.write().update_bandwidth_policy(session_id, policy) {
            Ok(()) => {
                self.audit_bandwidth_admin(
                    &canonical_id,
                    "Client bandwidth policy updated",
                    crate::audit::AuditOutcome::Succeeded,
                    None,
                );
                AdminResponse::ok_with_message("Client bandwidth policy updated")
            }
            Err(error) => {
                self.audit_bandwidth_admin(
                    &canonical_id,
                    "Client bandwidth policy update failed",
                    crate::audit::AuditOutcome::Failed,
                    Some("bandwidth_state_update_failed"),
                );
                AdminResponse::error(error)
            }
        }
    }

    pub fn reset_client_quota(&self, id: &str) -> AdminResponse {
        let Some(session_id) = self.resolve_session_id(id) else {
            self.audit_bandwidth_admin(
                id,
                "Client quota reset rejected",
                crate::audit::AuditOutcome::Denied,
                Some("client_not_found"),
            );
            return AdminResponse::error("Client not found");
        };
        let canonical_id = ClientIdentity::Session(session_id).to_string();
        if self.sessions.write().reset_bandwidth_quota(session_id) {
            self.audit_bandwidth_admin(
                &canonical_id,
                "Client bandwidth quota reset",
                crate::audit::AuditOutcome::Succeeded,
                None,
            );
            AdminResponse::ok_with_message("Client quota reset")
        } else {
            self.audit_bandwidth_admin(
                &canonical_id,
                "Client quota reset failed",
                crate::audit::AuditOutcome::Failed,
                Some("bandwidth_state_not_found"),
            );
            AdminResponse::error("Client bandwidth state not found")
        }
    }

    pub fn dispatch_action(&self, action: AdminAction, ok_message: String) -> AdminResponse {
        match self.control_plane.actions.send(action) {
            Ok(()) => AdminResponse::ok_with_message(ok_message),
            Err(_) => AdminResponse::error("Admin action channel unavailable"),
        }
    }

    pub fn kick_client(&self, id: &str) -> AdminResponse {
        let Some(id) = crate::implementations::server::admin::normalize_admin_client_id(id) else {
            return AdminResponse::error("Invalid client id");
        };
        self.dispatch_action(
            AdminAction::Kick(id.clone()),
            format!("Client {} scheduled for disconnect", id),
        )
    }

    pub fn reload(&self) -> AdminResponse {
        self.dispatch_action(
            AdminAction::Reload,
            "Configuration reload scheduled; FEC, stealth, and transport policy changes apply to next connections only"
                .to_string(),
        )
    }

    pub fn shutdown(&self) -> AdminResponse {
        self.dispatch_action(AdminAction::Shutdown, "Shutdown scheduled".to_string())
    }

    pub fn request_reload_after_write(&self) -> Result<(), &'static str> {
        self.control_plane
            .actions
            .send(AdminAction::Reload)
            .map_err(|_| "admin action channel unavailable")
    }

    pub fn block_ip(&self, ip: &str) -> AdminResponse {
        let Some(ip) = crate::implementations::server::admin::normalize_admin_ip(ip) else {
            return AdminResponse::error("Invalid IP");
        };
        self.blocked_ips.write().insert(ip.clone());
        AdminResponse::ok_with_message(format!("IP {} blocked", ip))
    }

    pub fn unblock_ip(&self, ip: &str) -> AdminResponse {
        let Some(ip) = crate::implementations::server::admin::normalize_admin_ip(ip) else {
            return AdminResponse::error("Invalid IP");
        };
        if self.blocked_ips.write().remove(&ip) {
            AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
        } else {
            AdminResponse::error(format!("IP {} was not blocked", ip))
        }
    }

    pub fn list_blocked_ips(&self) -> AdminResponse {
        let mut ips: Vec<String> = self.blocked_ips.read().iter().cloned().collect();
        ips.sort();
        AdminResponse::ok_with_data(serde_json::json!({ "ips": ips }))
    }

    pub fn issue_unix_qkey(&self) -> String {
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        match issue_unix_admin_qkey(
            &mut registry,
            &self.control_plane.listen_addr,
            &self.control_plane.front_domain,
        ) {
            Ok(qkey) => qkey,
            Err(e) => {
                log::warn!("QKey issuance failed: {}", e);
                String::new()
            }
        }
    }

    pub fn issue_http_qkey(&self, req: &IssueQKeyRequest) -> AdminResponse {
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        let issued = match issue_http_admin_qkey(
            &mut registry,
            &self.control_plane.listen_addr,
            &self.control_plane.front_domain,
            req,
        ) {
            Ok(issued) => issued,
            Err(e) => return AdminResponse::error(e),
        };
        AdminResponse::ok_with_data(serde_json::json!({
            "qkey": issued.qkey,
            "created_at": issued.created_at,
            "expires_at": issued.expires_at,
        }))
    }

    pub fn revoke_http_qkey(&self, id: &str) -> AdminResponse {
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        match registry.revoke(id) {
            Ok(true) => {}
            Ok(false) => return AdminResponse::error("QKey not found"),
            Err(error) => {
                return AdminResponse::error(format!(
                    "QKey revocation persistence failed: {error}"
                ));
            }
        }
        drop(registry);
        match self.control_plane.actions.send(AdminAction::RevokeQKey(id.to_string())) {
            Ok(()) => AdminResponse::ok_with_message("QKey revoked"),
            Err(_) => {
                AdminResponse::error("QKey revoked in registry but runtime channel is unavailable")
            }
        }
    }
}

pub struct ServerAdminHttpRuntimeHandler {
    core: ServerAdminCore,
    blocked_ips_path: Option<std::path::PathBuf>,
    config_path: Option<std::path::PathBuf>,
    logging_mode: Arc<parking_lot::RwLock<String>>,
    log_buffer: Arc<crate::implementations::server::admin_logs::AdminLogBuffer>,
}

impl ServerAdminHttpRuntimeHandler {
    pub fn new(
        core: ServerAdminCore,
        blocked_ips_path: Option<std::path::PathBuf>,
        config_path: Option<std::path::PathBuf>,
        logging_mode: Arc<parking_lot::RwLock<String>>,
        log_buffer: Arc<crate::implementations::server::admin_logs::AdminLogBuffer>,
    ) -> Self {
        Self { core, blocked_ips_path, config_path, logging_mode, log_buffer }
    }
}

#[cfg(unix)]
pub struct ServerAdminRuntimeHandler {
    core: ServerAdminCore,
}

#[cfg(unix)]
impl ServerAdminRuntimeHandler {
    pub fn new(core: ServerAdminCore) -> Self {
        Self { core }
    }
}

#[cfg(unix)]
impl AdminHandler for ServerAdminRuntimeHandler {
    fn handle_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(self.core.base_status_json())
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        self.core.list_clients()
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        self.core.kick_client(id)
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        self.core.block_ip(ip)
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        self.core.unblock_ip(ip)
    }

    fn handle_reload(&self) -> AdminResponse {
        self.core.reload()
    }

    fn handle_qkey(&self) -> String {
        self.core.issue_unix_qkey()
    }

    fn handle_shutdown(&self) -> AdminResponse {
        self.core.shutdown()
    }
}

impl AdminHttpHandler for ServerAdminHttpRuntimeHandler {
    fn handle_status(&self) -> AdminResponse {
        let mut data = self.core.base_status_json();
        data["listen"] = serde_json::Value::String(self.core.listen_addr().to_string());
        data["config_writable"] = serde_json::Value::Bool(self.config_path.is_some());
        AdminResponse::ok_with_data(data)
    }

    fn handle_health(&self) -> AdminResponse {
        AdminResponse::ok_with_data(self.core.health_json())
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        self.core.list_clients()
    }

    fn handle_get_client_bandwidth(&self, id: &str) -> AdminResponse {
        self.core.client_bandwidth(id)
    }

    fn handle_set_client_bandwidth(&self, id: &str, policy: BandwidthPolicy) -> AdminResponse {
        self.core.set_client_bandwidth(id, policy)
    }

    fn handle_reset_client_quota(&self, id: &str) -> AdminResponse {
        self.core.reset_client_quota(id)
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        self.core.kick_client(id)
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        let response = self.core.block_ip(ip);
        if let Some(path) = self.blocked_ips_path.as_ref() {
            if let Err(e) = persist_blocked_ips(path, &self.core.blocked_ips().read()) {
                log::warn!("blocked IPs persist failed: {}", e);
            }
        }
        response
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        let response = self.core.unblock_ip(ip);
        if response.success {
            if let Some(path) = self.blocked_ips_path.as_ref() {
                if let Err(e) = persist_blocked_ips(path, &self.core.blocked_ips().read()) {
                    log::warn!("blocked IPs persist failed: {}", e);
                }
            }
        }
        response
    }

    fn handle_list_blocked_ips(&self) -> AdminResponse {
        self.core.list_blocked_ips()
    }

    fn handle_reload(&self) -> AdminResponse {
        self.core.reload()
    }

    fn handle_drain(&self) -> AdminResponse {
        self.core.drain()
    }

    fn handle_drain_status(&self) -> AdminResponse {
        self.core.drain_status()
    }

    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse {
        self.core.issue_http_qkey(&req)
    }

    fn handle_list_qkeys(&self) -> AdminResponse {
        let mut registry = self.core.qkeys().lock().unwrap_or_else(|e| e.into_inner());
        AdminResponse::ok_with_data(serde_json::json!({ "keys": registry.list() }))
    }

    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse {
        self.core.revoke_http_qkey(id)
    }

    fn handle_shutdown(&self) -> AdminResponse {
        self.core.dispatch_action(AdminAction::Shutdown, "Shutdown scheduled".to_string())
    }

    fn handle_read_config(&self) -> AdminResponse {
        read_runtime_config(self.config_path.as_deref())
    }

    fn handle_write_config(&self, contents: &str) -> AdminResponse {
        write_runtime_config(&self.core, self.config_path.as_deref(), contents)
    }

    fn handle_metrics_text(&self) -> String {
        self.core.metrics().export()
    }

    fn handle_metrics_json(&self) -> AdminResponse {
        use std::sync::atomic::Ordering;
        let mut metrics = serde_json::json!({
                "quicfuscate_up": 1,
                "quicfuscate_uptime_seconds": self.core.metrics().uptime_secs(),
                "quicfuscate_clients_active": self.core.metrics().clients_active.load(Ordering::Relaxed),
                "quicfuscate_clients_total": self.core.metrics().clients_total.load(Ordering::Relaxed),
                "quicfuscate_connections_accepted": self.core.metrics().connections_accepted.load(Ordering::Relaxed),
                "quicfuscate_connections_rejected": self.core.metrics().connections_rejected.load(Ordering::Relaxed),
                "quicfuscate_bytes_in_total": self.core.metrics().bytes_in.load(Ordering::Relaxed),
                "quicfuscate_bytes_out_total": self.core.metrics().bytes_out.load(Ordering::Relaxed),
                "quicfuscate_packets_in_total": self.core.metrics().packets_in.load(Ordering::Relaxed),
                "quicfuscate_packets_out_total": self.core.metrics().packets_out.load(Ordering::Relaxed),
                "quicfuscate_stealth_http3_active": self.core.metrics().stealth_http3_active.load(Ordering::Relaxed),
                "quicfuscate_stealth_tls13_active": self.core.metrics().stealth_tls13_active.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_encoded": self.core.metrics().fec_packets_encoded.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_decoded": self.core.metrics().fec_packets_decoded.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_recovered": self.core.metrics().fec_packets_recovered.load(Ordering::Relaxed),
                "quicfuscate_auth_attempts_total": self.core.metrics().auth_attempts.load(Ordering::Relaxed),
                "quicfuscate_auth_succeeded_total": self.core.metrics().auth_succeeded.load(Ordering::Relaxed),
                "quicfuscate_auth_failed_total": self.core.metrics().auth_failed.load(Ordering::Relaxed),
                "quicfuscate_auth_backoff_rejected_total": self.core.metrics().auth_backoff_rejected.load(Ordering::Relaxed),
                "quicfuscate_auth_blocked_rejected_total": self.core.metrics().auth_blocked_rejected.load(Ordering::Relaxed),
                "quicfuscate_auth_capacity_rejected_total": self.core.metrics().auth_capacity_rejected.load(Ordering::Relaxed),
                "quicfuscate_auth_state_tracked_ips": self.core.metrics().auth_state_tracked_ips.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_uplink_allowed_bytes_total": self.core.metrics().bandwidth_uplink_allowed_bytes.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_downlink_allowed_bytes_total": self.core.metrics().bandwidth_downlink_allowed_bytes.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_uplink_rate_limited_total": self.core.metrics().bandwidth_uplink_rate_limited.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_downlink_rate_limited_total": self.core.metrics().bandwidth_downlink_rate_limited.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_uplink_daily_quota_exceeded_total": self.core.metrics().bandwidth_uplink_daily_quota_exceeded.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_downlink_daily_quota_exceeded_total": self.core.metrics().bandwidth_downlink_daily_quota_exceeded.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_uplink_monthly_quota_exceeded_total": self.core.metrics().bandwidth_uplink_monthly_quota_exceeded.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_downlink_monthly_quota_exceeded_total": self.core.metrics().bandwidth_downlink_monthly_quota_exceeded.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_scheduler_active_clients": self.core.metrics().bandwidth_scheduler_active_clients.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_scheduler_delivered_packets_total": self.core.metrics().bandwidth_scheduler_delivered_packets.load(Ordering::Relaxed),
                "quicfuscate_bandwidth_scheduler_delivered_bytes_total": self.core.metrics().bandwidth_scheduler_delivered_bytes.load(Ordering::Relaxed),
                "quicfuscate_rate_limited_total": self.core.metrics().rate_limited.load(Ordering::Relaxed),
        });
        #[cfg(feature = "rate_limiter")]
        {
            metrics["quicfuscate_geoip_status"] =
                serde_json::json!(self.core.geoip_status().as_str());
            metrics["quicfuscate_geoip_lookups_total"] =
                serde_json::json!(self.core.metrics().geoip_lookups.load(Ordering::Relaxed));
            metrics["quicfuscate_geoip_blocked_total"] =
                serde_json::json!(self.core.metrics().geoip_blocked.load(Ordering::Relaxed));
            metrics["quicfuscate_geoip_lookup_errors_total"] =
                serde_json::json!(self.core.metrics().geoip_lookup_errors.load(Ordering::Relaxed));
        }
        AdminResponse::ok_with_data(serde_json::json!({ "metrics": metrics }))
    }

    fn handle_get_logging_config(&self) -> AdminResponse {
        read_logging_mode(&self.logging_mode)
    }

    fn handle_set_logging_config(&self, mode: &str) -> AdminResponse {
        write_logging_mode(self.config_path.as_deref(), &self.logging_mode, &self.log_buffer, mode)
    }

    fn handle_get_logs(&self, cursor: u64) -> AdminResponse {
        let mode = self.logging_mode.read();
        let mode_str = mode.as_str();
        if mode_str == "no-log" {
            return AdminResponse::ok_with_data(serde_json::json!({
                "lines": [],
                "cursor": 0,
                "mode": "no-log"
            }));
        }
        let (lines, new_cursor) = self.log_buffer.since(cursor, mode_str, 600);
        AdminResponse::ok_with_data(serde_json::json!({
            "lines": lines.iter().map(|l| serde_json::json!({
                "ts": l.ts,
                "level": l.level,
                "msg": l.msg,
            })).collect::<Vec<_>>(),
            "cursor": new_cursor,
            "mode": mode_str
        }))
    }

    fn handle_clear_logs(&self) -> AdminResponse {
        self.log_buffer.clear();
        AdminResponse::ok_with_message("Logs cleared")
    }

    fn handle_rotate_logs(&self) -> AdminResponse {
        let result = crate::logging::rotate();
        let (outcome, severity, response) = match result {
            Ok(()) => (
                crate::audit::AuditOutcome::Succeeded,
                crate::audit::AuditSeverity::Info,
                AdminResponse::ok_with_message("Log rotation completed"),
            ),
            Err(error) => (
                crate::audit::AuditOutcome::Failed,
                crate::audit::AuditSeverity::Warning,
                AdminResponse::error(format!("Log rotation failed: {error}")),
            ),
        };
        crate::audit::audit_typed(
            crate::audit::AuditEventType::AdminAction,
            severity,
            None,
            None,
            crate::audit::AuditContext {
                actor: crate::audit::AuditActor::Administrator,
                target: crate::audit::AuditTarget::System,
                outcome,
                reason: Some("admin_log_rotation"),
            },
            "Authenticated admin requested operational log rotation",
        );
        response
    }
}
