/// Server runtime handle.
pub struct ServerRuntime {
    /// Engine configuration
    engine_config: EngineConfig,
    /// Server-specific configuration
    server_config: ServerConfig,
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
    drain_started: parking_lot::RwLock<Option<Instant>>,
}

impl GracefulShutdown {
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
        self.drain_started.read().as_ref().map(|started| started.elapsed()).unwrap_or_default()
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
    /// GeoIP-based source-IP blocker (TODO-459). Uses `maxminddb` to look up
    /// the country of an incoming IP and reject blocked countries. Gracefully
    /// degrades to allowing all IPs when no database is configured.
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
    Ok(routing.with_client_to_client(server_config.allow_client_to_client))
}

fn teardown_routing_with_retries(routing: RoutingManager) {
    let mut last_error = None;
    for attempt in 1..=3 {
        match routing.teardown() {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(error) => {
                log::warn!("Routing teardown attempt {}/3 failed: {:?}", attempt, error);
                last_error = Some(error);
                if attempt < 3 {
                    std::thread::sleep(Duration::from_millis(100 * attempt as u64));
                }
            }
        }
    }
    if let Some(error) = last_error {
        log::error!("Routing teardown failed after 3 attempts: {:?}", error);
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
            &format!("Routing teardown failed after retries: {error}"),
        );
    }
}

impl ServerHostResources {
    fn start(
        engine_config: &EngineConfig,
        server_config: &ServerConfig,
        pool: Arc<MemoryPool>,
    ) -> Result<Self, EngineError> {
        let tun_config = TunConfig {
            name: Some("qfserver0".to_string()),
            ip: engine_config.interface.tun_ip.or(Some(server_config.server_ip.into())),
            netmask: engine_config
                .interface
                .tun_netmask
                .or(Some(server_config.server_netmask.into())),
            mtu: engine_config.interface.tun_mtu,
            zero_copy: engine_config.interface.zero_copy,
            ip6: server_config.ipv6_server_ip,
            prefix6: Some(server_config.ipv6_prefix_len),
        };

        let tun = open_server_tun(tun_config, pool).map_err(EngineError::Tun)?;
        log::info!("Server TUN interface opened: {}", tun.name());

        #[cfg(target_os = "linux")]
        let routing = {
            let routing = configured_routing_manager("qfserver0".to_string(), server_config)
                .map_err(EngineError::Io)?;

            // Clean up stale rules from a crashed previous session before setup.
            routing.cleanup_stale();

            if let Err(e) = routing.setup() {
                let _ = routing.teardown();
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
                return Err(EngineError::Io(format!("server routing setup failed: {e}")));
            }
            Some(routing)
        };

        #[cfg(not(target_os = "linux"))]
        let routing = None;

        Ok(Self { tun, routing })
    }

    fn teardown(self) {
        if let Some(routing) = self.routing {
            teardown_routing_with_retries(routing);
        }
        log::info!("Closing server TUN: {}", self.tun.name());
        drop(self.tun);
    }
}

impl SharedServerDomain {
    fn new(server_config: &ServerConfig) -> Self {
        // Create IPv6 pool only if both start and end are configured
        let ipv6_pool = match (server_config.ipv6_pool_start, server_config.ipv6_pool_end) {
            (Some(start), Some(end)) => {
                Some(Arc::new(parking_lot::Mutex::new(Ipv6Pool::new(start, end))))
            }
            _ => None,
        };
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new(server_config.max_clients))),
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
                limiter: RateLimiter::new(load_rate_limit_config_from_env()),
                last_prune: Instant::now(),
            })),
            #[cfg(feature = "rate_limiter")]
            global_rate_limiter: Arc::new(GlobalRateLimiter::with_default_cap()),
            #[cfg(feature = "rate_limiter")]
            ddos_detector: Arc::new(
                crate::implementations::server::limits::EwmaAnomalyDetector::with_defaults(),
            ),
            #[cfg(feature = "rate_limiter")]
            geoip_blocker: Arc::new(crate::implementations::server::limits::GeoIpBlocker::new(
                server_config.geoip.clone(),
            )),
            #[cfg(feature = "rate_limiter")]
            blacklist: Arc::new(crate::implementations::server::limits::BlacklistSync::new(
                Duration::from_secs(server_config.blacklist.default_ttl_secs),
                server_config.blacklist.sync_url.clone(),
                Duration::from_secs(server_config.blacklist.sync_interval_secs),
            )),
            max_clients: server_config.max_clients,
            client_timeout_secs: server_config.client_timeout_secs,
        }
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
    fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        // 1. Global server-wide cap: drop if aggregate PPS exceeds the cap,
        //    regardless of source IP. This is checked first so a flood from
        //    many IPs cannot overwhelm the host even if each is under its
        //    per-IP limit.
        if !self.global_rate_limiter.check() {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 2. GeoIP blocking (TODO-459): drop if the source IP maps to a blocked
        //    country. Gracefully allows all IPs when no database is configured.
        if self.geoip_blocker.is_blocked(from.ip()) {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 3. External blacklist (TODO-459): drop if the source IP is on the
        //    TTL-based blocklist (manual or from an external feed).
        if self.blacklist.is_blocked(from.ip()) {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 4. Per-IP token bucket. When the DDoS anomaly detector reports a
        //    spike, per-IP limits are temporarily halved by probabilistically
        //    dropping ~50% of packets before the per-IP bucket is consulted.
        if self.ddos_detector.is_anomaly() {
            // Simple deterministic drop: use the low bit of a counter.
            let count = self.global_rate_limiter.accepted.load(Ordering::Relaxed);
            if count & 1 == 1 {
                crate::instrumentation::global().server.rate_limit_hit();
                return false;
            }
        }
        let limiter = self.packet_rate_limiter.lock();
        let allowed_packet = limiter.limiter.check_packet_ip(from.ip());
        let allowed_bytes = allowed_packet && limiter.limiter.check_bytes_ip(from.ip(), len as u64);
        allowed_packet && allowed_bytes
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self) {
        let mut limiter = self.packet_rate_limiter.lock();
        if limiter.last_prune.elapsed() >= Duration::from_secs(30) {
            limiter.limiter.prune_idle(Duration::from_secs(120));
            limiter.last_prune = Instant::now();
            // DDoS anomaly detection (TODO-459): feed the EWMA detector with
            // the current global PPS count and prune expired blacklist entries.
            let pps = self.global_rate_limiter.current_pps();
            self.ddos_detector.record_pps(pps);
            self.blacklist.prune_expired();
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
    metrics: Arc<Metrics>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    control_plane: ServerAdminControlPlane,
}

impl ServerAdminCore {
    fn new(
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<
            std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>,
        >,
        control_plane: ServerAdminControlPlane,
    ) -> Self {
        Self { metrics, blocked_ips, client_snapshots, control_plane }
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

    pub fn base_status_json(&self) -> serde_json::Value {
        serde_json::json!({
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
        })
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
        snapshots_to_client_info(&guard, Instant::now())
    }

    pub fn dispatch_action(&self, action: AdminAction, ok_message: String) -> AdminResponse {
        match self.control_plane.actions.send(action) {
            Ok(()) => AdminResponse::ok_with_message(ok_message),
            Err(_) => AdminResponse::error("Admin action channel unavailable"),
        }
    }

    pub fn kick_client(&self, id: &str) -> AdminResponse {
        self.dispatch_action(
            AdminAction::Kick(id.to_string()),
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
        self.blocked_ips.write().insert(ip.to_string());
        AdminResponse::ok_with_message(format!("IP {} blocked", ip))
    }

    pub fn unblock_ip(&self, ip: &str) -> AdminResponse {
        if self.blocked_ips.write().remove(ip) {
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

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        self.core.list_clients()
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
        AdminResponse::ok_with_data(serde_json::json!({
            "metrics": {
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
                "quicfuscate_rate_limited_total": self.core.metrics().rate_limited.load(Ordering::Relaxed),
            }
        }))
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
}
