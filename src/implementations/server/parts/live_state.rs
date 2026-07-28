#[derive(Debug)]
struct PendingTunDownlink {
    target: SocketAddr,
    packet: Vec<u8>,
    queued_at: Instant,
}

impl PendingTunDownlink {
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.queued_at) >= MAX_PENDING_TUN_DOWNLINK_AGE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingTunDownlinkReject {
    Queue,
    Bytes,
    PerTarget,
}

impl From<PendingTunDownlinkReject> for TunDownlinkBackpressureDrop {
    fn from(reject: PendingTunDownlinkReject) -> Self {
        match reject {
            PendingTunDownlinkReject::Queue => Self::QueueCapacity,
            PendingTunDownlinkReject::Bytes => Self::ByteCapacity,
            PendingTunDownlinkReject::PerTarget => Self::PerTargetCapacity,
        }
    }
}

#[derive(Debug)]
struct PendingTunDownlinks {
    entries: std::collections::VecDeque<PendingTunDownlink>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    max_per_target: usize,
}

impl PendingTunDownlinks {
    fn new() -> Self {
        Self::with_limits(
            MAX_PENDING_TUN_DOWNLINKS,
            MAX_PENDING_TUN_DOWNLINK_BYTES,
            MAX_PENDING_TUN_DOWNLINKS_PER_TARGET,
        )
    }

    fn with_limits(max_entries: usize, max_bytes: usize, max_per_target: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_entries),
            bytes: 0,
            max_entries,
            max_bytes,
            max_per_target,
        }
    }

    fn enqueue(
        &mut self,
        target: SocketAddr,
        packet: Vec<u8>,
        queued_at: Instant,
    ) -> Result<(), PendingTunDownlinkReject> {
        if self.entries.len() >= self.max_entries {
            return Err(PendingTunDownlinkReject::Queue);
        }
        if self.bytes.saturating_add(packet.len()) > self.max_bytes {
            return Err(PendingTunDownlinkReject::Bytes);
        }
        if self.entries.iter().filter(|entry| entry.target == target).count() >= self.max_per_target
        {
            return Err(PendingTunDownlinkReject::PerTarget);
        }
        self.bytes += packet.len();
        self.entries.push_back(PendingTunDownlink { target, packet, queued_at });
        Ok(())
    }

    fn pop_front(&mut self) -> Option<PendingTunDownlink> {
        let entry = self.entries.pop_front()?;
        self.bytes = self.bytes.saturating_sub(entry.packet.len());
        Some(entry)
    }

    fn requeue(&mut self, entry: PendingTunDownlink) {
        self.bytes += entry.packet.len();
        self.entries.push_back(entry);
    }

    fn rebind_target(&mut self, old_target: SocketAddr, new_target: SocketAddr) {
        for entry in &mut self.entries {
            if entry.target == old_target {
                entry.target = new_target;
            }
        }
    }

    fn discard_target(&mut self, target: SocketAddr) -> (usize, usize) {
        let mut discarded_packets = 0;
        let mut discarded_bytes = 0;
        self.entries.retain(|entry| {
            if entry.target == target {
                discarded_packets += 1;
                discarded_bytes += entry.packet.len();
                false
            } else {
                true
            }
        });
        self.bytes = self.bytes.saturating_sub(discarded_bytes);
        (discarded_packets, discarded_bytes)
    }

    fn discard_all(&mut self) -> (usize, usize) {
        let discarded_packets = self.entries.len();
        let discarded_bytes = self.bytes;
        self.entries.clear();
        self.bytes = 0;
        (discarded_packets, discarded_bytes)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

pub struct LiveServerState {
    clients: std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    /// Bounded downlink packets that could not be enqueued because a client's
    /// QUIC DATAGRAM queue was full. Retried before new TUN packets are read.
    pending_tun_downlinks: PendingTunDownlinks,
    fanout_queue: ClientFanoutQueue,
    qkey_auth: std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    domain: LiveServerDomain,
    auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    revocation_manager: Arc<crate::implementations::server::revocation::RevocationManager>,
    qkey_tracker: Arc<crate::implementations::server::revocation::QKeyConnectionTracker>,
    key_rotation_manager: crate::implementations::server::revocation::KeyRotationManager,
    next_stats_log: Instant,
    /// Last time the external blacklist feed sync was *started*. Used by
    /// `run_housekeeping_tick` to trigger periodic re-syncs at the
    /// configured `sync_interval`. `None` = sync never started yet.
    /// Shared via `Arc<Mutex<>>` so the background sync task spawned via
    /// `tokio::spawn` can update it without holding the `LiveServerState`
    /// borrow. The timestamp is recorded *before* spawning the sync task
    /// so overlapping syncs are prevented even if a prior sync is still
    /// in flight.
    #[cfg(feature = "rate_limiter")]
    last_blacklist_sync: Arc<parking_lot::Mutex<Option<Instant>>>,
}

pub struct LiveClientInit {
    pub connection: QuicFuscateConnection,
    pub pending_qkey_auth: Option<QKeyAuthState>,
}

pub struct LiveClientBuildRequest<'a> {
    pub packet: &'a [u8],
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub qkey_registry: &'a std::sync::Mutex<QKeyRegistry>,
    pub revocation_manager: &'a crate::implementations::server::revocation::RevocationManager,
    pub metrics: &'a Metrics,
    pub stealth_config: &'a Arc<std::sync::Mutex<StealthConfig>>,
    pub fec_cfg_shared: &'a Arc<std::sync::Mutex<FecConfig>>,
    pub opt_params_shared: &'a Arc<std::sync::Mutex<OptimizeConfig>>,
    pub transport_config: &'a mut crate::transport::Config,
    pub profile: BrowserProfile,
    pub os: OsProfile,
    pub disable_doh: bool,
    pub auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    pub doh_provider: &'a str,
    pub disable_fronting: bool,
    pub front_domain: &'a [String],
    pub disable_http3: bool,
}

pub fn build_live_server_client_init(
    request: LiveClientBuildRequest<'_>,
) -> Option<LiveClientInit> {
    // Per-IP auth rate limiting: reject before any QKey lookup if the IP has
    // exceeded the failed auth attempt threshold. This prevents brute-force
    // attacks on QKey tokens.
    {
        let ip = request.remote_addr.ip();
        let limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        if !limiter.is_allowed(ip) {
            log::warn!("QKey auth rate limit exceeded for {}; rejecting connection", ip);
            request.metrics.record_connection_rejected();
            return None;
        }
    }

    let initial_ctx = match parse_live_server_initial_auth(
        request.packet,
        request.qkey_registry,
        request.revocation_manager,
        request.metrics,
    ) {
        Some(ctx) => ctx,
        None => {
            // Record the failed auth attempt for rate limiting
            let ip = request.remote_addr.ip();
            let mut limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            limiter.record_failure(ip);
            return None;
        }
    };

    // Successful initial auth - clear any previous failed attempts for this IP
    {
        let ip = request.remote_addr.ip();
        let mut limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(ip);
    }

    log::info!("New client connected: {}", request.remote_addr);

    let cfg = match request.stealth_config.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            log::warn!("stealth_config mutex poisoned; recovering inner state");
            poisoned.into_inner().clone()
        }
    };
    let mut conn_stealth_cfg = cfg;
    let mut conn_fec_cfg = match request.fec_cfg_shared.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    if let Some(ref record) = initial_ctx.qkey_record {
        apply_qkey_policy_overrides(record, &mut conn_stealth_cfg, &mut conn_fec_cfg);
        apply_runtime_stealth_overrides(
            &mut conn_stealth_cfg,
            request.profile,
            request.os,
            request.disable_doh,
            request.doh_provider,
            request.disable_fronting,
            request.front_domain,
            request.disable_http3,
        );
    }
    let opt_params = match request.opt_params_shared.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    };
    let mut selected_transport = request.transport_config.clone();
    if let Err(error) = selected_transport.select_version(initial_ctx.version) {
        log::warn!("refusing unsupported QUIC version {:#010x}: {}", initial_ctx.version, error);
        request.metrics.record_connection_rejected();
        return None;
    }
    match create_live_server_connection(
        request.local_addr,
        request.remote_addr,
        &mut selected_transport,
        conn_stealth_cfg,
        conn_fec_cfg,
        opt_params,
        &initial_ctx.odcid,
    ) {
        Ok(connection) => {
            Some(LiveClientInit { connection, pending_qkey_auth: initial_ctx.pending_qkey_auth })
        }
        Err(error) => {
            log::error!("failed to create server connection: {}", error);
            None
        }
    }
}

pub struct LiveClientRuntime<'a> {
    pub connection: &'a mut QuicFuscateConnection,
    pub client_count: usize,
    pub conn_id: Vec<u8>,
    pub qkey_auth: Option<QKeyAuthState>,
    pub session_id: Option<SessionId>,
    pub session_stats: Option<Arc<SessionStats>>,
    pub assigned_ips: Option<AssignedClientIps>,
    pub forwarding_policy: Arc<ClientIsolationManager>,
    fanout_queue: ClientFanoutQueue,
}

pub enum LiveClientAcquire<'a> {
    Ready(LiveClientRuntime<'a>),
    Backpressure,
    Rejected,
}

struct LiveServerDomain {
    shared: SharedServerDomain,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
}

impl LiveServerDomain {
    fn new(server_config: &ServerConfig) -> Self {
        Self {
            shared: SharedServerDomain::new(server_config),
            client_snapshots: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
        let (session_id, stats, assigned_ips) = self.shared.accept(remote_addr)?;
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionEstablished,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client connection accepted",
        );
        Ok((session_id, stats, assigned_ips))
    }

    fn remove_remote(&self, remote_addr: SocketAddr) {
        let Some(session_id) = self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
        else {
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(remote_addr.ip());
            self.remove_remote_snapshot(remote_addr);
            return;
        };
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionClosed,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client session removed",
        );
        self.shared.remove(session_id);
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(remote_addr.ip());
        self.remove_remote_snapshot(remote_addr);
    }

    fn rebind_remote(&self, old_addr: SocketAddr, new_addr: SocketAddr) {
        let mut sessions = self.shared.sessions.write();
        if sessions.rebind_remote_addr(old_addr, new_addr).is_some() {
            drop(sessions);
            let mut limiter = self.shared.connection_limiter.lock();
            limiter.remove(old_addr.ip());
            limiter.add(new_addr.ip());
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(old_addr.ip());
            if let Ok(mut guard) = self.client_snapshots.lock() {
                if let Some(snapshot) = guard.remove(&old_addr) {
                    guard.insert(new_addr, snapshot);
                }
            }
        }
    }

    fn session_stats_by_remote(&self, remote_addr: SocketAddr) -> Option<Arc<SessionStats>> {
        self.shared.sessions.read().stats_by_remote_addr(remote_addr)
    }

    fn session_id_by_remote(&self, remote_addr: SocketAddr) -> Option<SessionId> {
        self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
    }

    fn assigned_ips_by_remote(&self, remote_addr: SocketAddr) -> Option<AssignedClientIps> {
        self.shared.sessions.read().get_by_remote_addr(remote_addr).map(|session| {
            AssignedClientIps { ipv4: session.client_ip(), ipv6: session.client_ipv6() }
        })
    }

    fn remote_addr_for_identity(&self, identity: &ClientIdentity) -> Option<SocketAddr> {
        match identity {
            ClientIdentity::Remote(addr) => Some(*addr),
            ClientIdentity::Session(session_id) => {
                self.shared.sessions.read().remote_addr_by_session_id(*session_id)
            }
        }
    }

    fn active_session_count(&self) -> usize {
        self.shared.session_count()
    }

    fn reap_expired_remotes(&self) -> Vec<(SocketAddr, SessionId)> {
        let expired = self.shared.reap_expired();
        for session in &expired {
            let source_ip = session.remote_addr().ip().to_string();
            let client_id = session.id().as_u64().to_string();
            crate::audit::audit(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                Some(&source_ip),
                Some(&client_id),
                "Client session expired",
            );
        }
        expired.into_iter().map(|session| (session.remote_addr(), session.id())).collect()
    }

    fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        &self.client_snapshots
    }

    fn remove_remote_snapshot(&self, remote_addr: SocketAddr) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.remove(&remote_addr);
        }
    }

    fn retain_snapshots_for_clients(
        &self,
        clients: &std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    ) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.retain(|addr, _| clients.contains_key(addr));
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        self.shared.allow_incoming_datagram(from, len)
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self) {
        self.shared.prune_rate_limits_if_due();
    }

    /// Returns a clone of the blacklist synchronizer Arc for async sync.
    #[cfg(feature = "rate_limiter")]
    fn blacklist(&self) -> Arc<crate::implementations::server::limits::BlacklistSync> {
        Arc::clone(&self.shared.blacklist)
    }
}

fn accept_session_in_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    mut ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
    remote_addr: SocketAddr,
    max_clients: usize,
    client_timeout_secs: u64,
) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
    if !connection_limiter.check(remote_addr.ip()) {
        return Err(AcceptError::TooManyConnectionsPerIp);
    }
    if sessions.len() >= max_clients {
        return Err(AcceptError::MaxClientsReached);
    }
    let client_ip = ip_pool.allocate().ok_or(AcceptError::IpPoolExhausted)?;

    // Allocate IPv6 address if dual-stack pool is available
    let client_ipv6 = if let Some(ref mut v6_pool) = ipv6_pool {
        match v6_pool.allocate() {
            Some(v6) => Some(v6),
            None => {
                // IPv6 pool exhausted - release IPv4 and fail
                ip_pool.release(client_ip);
                return Err(AcceptError::IpPoolExhausted);
            }
        }
    } else {
        None
    };

    let session = if let Some(v6) = client_ipv6 {
        Session::new_dual_stack(remote_addr, client_ip, Some(v6), client_timeout_secs)
    } else {
        Session::new(remote_addr, client_ip, client_timeout_secs)
    };
    let session_id = session.id();
    let stats = Arc::clone(session.stats());
    match sessions.add(session) {
        Ok(_) => {
            connection_limiter.add(remote_addr.ip());
            Ok((session_id, stats, AssignedClientIps { ipv4: client_ip, ipv6: client_ipv6 }))
        }
        Err(SessionError::MaxSessionsReached) => {
            ip_pool.release(client_ip);
            if let Some(v6) = client_ipv6 {
                if let Some(ref mut v6_pool) = ipv6_pool {
                    v6_pool.release(v6);
                }
            }
            Err(AcceptError::MaxClientsReached)
        }
        Err(SessionError::NotFound | SessionError::AlreadyExists) => {
            ip_pool.release(client_ip);
            if let Some(v6) = client_ipv6 {
                if let Some(ref mut v6_pool) = ipv6_pool {
                    v6_pool.release(v6);
                }
            }
            Err(AcceptError::SessionError("failed to add live session".to_string()))
        }
    }
}

fn remove_session_from_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
    session_id: SessionId,
) -> Option<Session> {
    let session = sessions.remove(session_id)?;
    ip_pool.release(session.client_ip());
    if let Some(v6) = session.client_ipv6() {
        if let Some(v6_pool) = ipv6_pool {
            v6_pool.release(v6);
        }
    }
    connection_limiter.remove(session.remote_addr().ip());
    Some(session)
}

fn collect_expired_session_ids(sessions: &SessionManager) -> Vec<SessionId> {
    sessions
        .iter()
        .filter_map(|(session_id, session)| session.is_expired().then_some(*session_id))
        .collect()
}

fn reap_expired_sessions_from_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    mut ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
) -> Vec<Session> {
    let expired_ids = collect_expired_session_ids(sessions);
    let mut removed = Vec::with_capacity(expired_ids.len());
    for session_id in expired_ids {
        if let Some(session) = remove_session_from_domain(
            sessions,
            ip_pool,
            ipv6_pool.as_deref_mut(),
            connection_limiter,
            session_id,
        ) {
            removed.push(session);
        }
    }
    removed
}

impl LiveServerState {
    pub fn new(server_config: ServerConfig) -> Self {
        let revocation_manager =
            Arc::new(crate::implementations::server::revocation::RevocationManager::new());
        let qkey_tracker =
            Arc::new(crate::implementations::server::revocation::QKeyConnectionTracker::new());
        let key_rotation_manager =
            crate::implementations::server::revocation::KeyRotationManager::new(
                crate::implementations::server::revocation::DEFAULT_ROTATION_INTERVAL_SECS,
                crate::implementations::server::revocation::DEFAULT_OVERLAP_WINDOW_SECS,
                Arc::clone(&revocation_manager),
            );
        Self {
            clients: std::collections::HashMap::new(),
            pending_tun_downlinks: PendingTunDownlinks::new(),
            fanout_queue: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            qkey_auth: std::collections::HashMap::new(),
            domain: LiveServerDomain::new(&server_config),
            auth_rate_limiter: Arc::new(std::sync::Mutex::new(
                crate::implementations::server::limits::AuthRateLimiter::new(
                    10,
                    std::time::Duration::from_secs(60),
                ),
            )),
            revocation_manager,
            qkey_tracker,
            key_rotation_manager,
            next_stats_log: Instant::now(),
            #[cfg(feature = "rate_limiter")]
            last_blacklist_sync: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.domain.client_snapshots()
    }

    #[cfg(feature = "rate_limiter")]
    pub fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        self.domain.allow_incoming_datagram(from, len)
    }

    #[cfg(feature = "rate_limiter")]
    pub fn prune_rate_limits_if_due(&self) {
        self.domain.prune_rate_limits_if_due();
    }

    /// Periodically sync the external blacklist feed if a sync URL is
    /// configured and the sync interval has elapsed since the last sync.
    ///
    /// The sync is an async HTTPS fetch with a 30s timeout. To avoid
    /// blocking the 5ms housekeeping tick (and thus all UDP packet
    /// processing, TUN forwarding, and client flushing), the actual fetch
    /// is dispatched via `tokio::spawn` as a background task. The
    /// `last_blacklist_sync` timestamp is recorded *before* spawning so
    /// overlapping syncs are prevented - if a sync is still in flight when
    /// the next interval elapses, the new tick sees a recent timestamp and
    /// skips. The background task updates the shared `BlacklistSync` (via
    /// its `Arc`) in place; `replace_list` takes the internal write lock,
    /// so concurrent `is_blocked` reads remain safe. Errors are logged and
    /// non-fatal - the blacklist continues to use the last-known-good set.
    #[cfg(feature = "rate_limiter")]
    fn maybe_sync_blacklist(&self) {
        let blacklist = self.domain.blacklist();
        if !blacklist.has_sync_url() {
            return;
        }
        let interval = blacklist.sync_interval();
        let should_sync = {
            let guard = self.last_blacklist_sync.lock();
            match *guard {
                None => true,
                Some(last) => last.elapsed() >= interval,
            }
        };
        if !should_sync {
            return;
        }
        // Record the sync start time *before* spawning so that subsequent
        // ticks do not spawn overlapping syncs while this one is in flight.
        {
            let mut guard = self.last_blacklist_sync.lock();
            *guard = Some(Instant::now());
        }
        log::debug!("Blacklist: dispatching background sync from external feed");
        // Spawn the sync as a detached background task. The task owns a
        // clone of the `Arc<BlacklistSync>` and performs the HTTPS fetch
        // without holding any borrow on `LiveServerState`. The result is
        // logged; the blacklist is updated in place via `replace_list`.
        tokio::spawn(async move {
            match blacklist.sync().await {
                Ok(count) => {
                    log::info!("Blacklist: synced {count} IPs from external feed");
                }
                Err(e) => {
                    log::warn!("Blacklist: sync failed (using last-known-good set): {e}");
                }
            }
        });
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut QuicFuscateConnection> {
        self.clients.values_mut()
    }

    pub fn accept_or_get_client_with<F>(
        &mut self,
        addr: SocketAddr,
        accept_loop: &AcceptLoop,
        accept_max_clients: usize,
        metrics: &Metrics,
        build: F,
    ) -> LiveClientAcquire<'_>
    where
        F: FnOnce() -> Option<LiveClientInit>,
    {
        use std::collections::hash_map::Entry;

        let count_before = self.clients.len();
        let existing_assigned_ips = self.domain.assigned_ips_by_remote(addr);
        let forwarding_policy = Arc::clone(&self.domain.shared.forwarding_policy);
        let fanout_queue = Arc::clone(&self.fanout_queue);
        match self.clients.entry(addr) {
            Entry::Occupied(entry) => {
                let connection = entry.into_mut();
                let conn_id = connection.conn.source_id().as_ref().to_vec();
                let qkey_auth = self.qkey_auth.get(&conn_id).cloned();
                let session_id = self.domain.session_id_by_remote(addr);
                let session_stats = self.domain.session_stats_by_remote(addr);
                LiveClientAcquire::Ready(LiveClientRuntime {
                    connection,
                    client_count: count_before,
                    conn_id,
                    qkey_auth,
                    session_id,
                    session_stats,
                    assigned_ips: existing_assigned_ips,
                    forwarding_policy,
                    fanout_queue: Arc::clone(&fanout_queue),
                })
            }
            Entry::Vacant(entry) => {
                match accept_loop.should_accept(addr, count_before, accept_max_clients) {
                    AcceptDecision::Accept => {}
                    AcceptDecision::Backpressure => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Backpressure;
                    }
                    AcceptDecision::Reject(_) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Rejected;
                    }
                }

                let mut init = match build() {
                    Some(value) => value,
                    None => {
                        return LiveClientAcquire::Rejected;
                    }
                };
                let (session_id, session_stats, assigned_ips) = match self.domain.accept(addr) {
                    Ok(value) => value,
                    Err(_) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Rejected;
                    }
                };
                if let Some(state) = init.pending_qkey_auth.take() {
                    let conn_id = init.connection.conn.source_id().as_ref().to_vec();
                    self.qkey_auth.insert(conn_id, state);
                }
                let connection = entry.insert(init.connection);
                let conn_id = connection.conn.source_id().as_ref().to_vec();
                let qkey_auth = self.qkey_auth.get(&conn_id).cloned();
                metrics.record_connection_accepted();
                accept_loop.record_accepted(addr);
                LiveClientAcquire::Ready(LiveClientRuntime {
                    connection,
                    client_count: count_before + 1,
                    conn_id,
                    qkey_auth,
                    session_id: Some(session_id),
                    session_stats: Some(session_stats),
                    assigned_ips: Some(assigned_ips),
                    forwarding_policy,
                    fanout_queue,
                })
            }
        }
    }

    pub fn acquire_runtime_client_with<F>(
        &mut self,
        addr: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
        accept_max_clients: usize,
        metrics: &Metrics,
        build: F,
    ) -> LiveClientAcquire<'_>
    where
        F: FnOnce() -> Option<LiveClientInit>,
    {
        if self.handle_incoming_path_update(addr, packet, accept_loop) {
            log::info!("Client path updated to {}", addr);
        }

        let acquired =
            self.accept_or_get_client_with(addr, accept_loop, accept_max_clients, metrics, build);
        if let LiveClientAcquire::Ready(client) = &acquired {
            metrics.clients_active.store(client.client_count as u64, Ordering::Relaxed);
        }
        acquired
    }

    fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut QuicFuscateConnection> {
        self.clients.get_mut(addr)
    }

    fn drain_client_fanout(&mut self, metrics: &Metrics) {
        let pending: Vec<ClientFanoutPacket> = match self.fanout_queue.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        };
        for fanout in pending {
            let targets = {
                let sessions = self.domain.shared.sessions.read();
                self.clients
                    .iter()
                    .filter_map(|(address, connection)| {
                        if *address == fanout.source {
                            return None;
                        }
                        let conn_id = connection.conn.source_id().as_ref();
                        if self.qkey_auth.get(conn_id).is_some_and(|state| !state.authed) {
                            return None;
                        }
                        let session = sessions.get_by_remote_addr(*address)?;
                        if fanout.destination.is_ipv6() && session.client_ipv6().is_none() {
                            return None;
                        }
                        Some(*address)
                    })
                    .collect::<smallvec::SmallVec<[SocketAddr; 4]>>()
            };

            let mut queued = false;
            for target in targets {
                let Some(connection) = self.clients.get_mut(&target) else {
                    continue;
                };
                if fanout.packet.len() > connection.effective_tunnel_mtu() {
                    log::debug!("Client fan-out packet exceeds tunnel MTU for {}", target);
                    continue;
                }
                match connection.send_masque_downlink(&fanout.packet) {
                    Ok(()) => queued = true,
                    Err(error) => {
                        log::debug!("Client fan-out queue for {} failed: {:?}", target, error);
                    }
                }
            }
            if queued {
                metrics.record_routing_outcome(RoutingOutcome::Fanout);
            }
        }
    }

    fn key_addrs(&self) -> Vec<SocketAddr> {
        self.clients.keys().copied().collect()
    }

    pub async fn run_housekeeping_tick(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        accept_loop: &AcceptLoop,
    ) {
        let now = Instant::now();
        let log_client_stats = now >= self.next_stats_log;
        if log_client_stats {
            self.next_stats_log = now + SERVER_STATS_LOG_INTERVAL;
        }
        #[cfg(feature = "rate_limiter")]
        {
            self.prune_rate_limits_if_due();
            // Periodically dispatch a background blacklist sync. The sync
            // is an async HTTPS fetch (30s timeout) but is spawned via
            // `tokio::spawn` so it never blocks the 5ms housekeeping tick.
            // The dispatch only fires when the configured sync_interval has
            // elapsed (default: 3600s), so the per-tick cost is just an
            // `Instant::now()` comparison under a short-lived lock.
            self.maybe_sync_blacklist();
        }
        let _ = self.key_rotation_manager.check_and_rotate();
        for revoked_key_id in self.key_rotation_manager.process_pending_revocations() {
            self.close_sessions_for_revoked_qkey(&revoked_key_id, accept_loop, metrics);
        }
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        let addresses = self.key_addrs();
        for addr in addresses {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            if let Some(conn) = self.get_mut(&addr) {
                drain_masque_downlink_responses(conn, addr, metrics);
                if let Err(error) = flush_live_server_outgoing(
                    socket,
                    addr,
                    conn,
                    out,
                    metrics,
                    &client_snapshots,
                    session_stats,
                    session_id,
                )
                .await
                {
                    log::warn!("Failed to flush packets to {}: {}", addr, error);
                }
                conn.update_state();
                if log_client_stats {
                    log::info!(
                        "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                        addr,
                        conn.rtt_ms(),
                        conn.loss_rate() * 100.0
                    );
                }
                // Only drive the idle timeout when the connection has actually been
                // idle; calling it every tick collapses cwnd and inflates loss.
                if conn.conn.idle_timeout_elapsed() {
                    conn.conn.on_timeout();
                }
            }
        }
        self.enforce_qkey_auth_timeouts(metrics);
        self.reap_expired_sessions(accept_loop, metrics);
        self.reconcile(accept_loop, metrics);
    }

    pub fn sync_active_metrics(&self, metrics: &Metrics) {
        metrics.clients_active.store(self.domain.active_session_count() as u64, Ordering::Relaxed);
    }

    fn qkey_auth_state_mut(&mut self, conn_id: &[u8]) -> Option<&mut QKeyAuthState> {
        self.qkey_auth.get_mut(conn_id)
    }

    fn remove_qkey_auth(&mut self, conn_id: &[u8]) -> Option<QKeyAuthState> {
        self.qkey_auth.remove(conn_id)
    }

    fn session_id_for_conn_id(&self, conn_id: &[u8]) -> Option<SessionId> {
        self.clients.iter().find_map(|(addr, conn)| {
            (conn.conn.source_id().as_ref() == conn_id)
                .then(|| self.domain.session_id_by_remote(*addr))
                .flatten()
        })
    }

    fn dissociate_qkey_for_session(&self, session_id: Option<SessionId>) {
        if let Some(session_id) = session_id {
            self.qkey_tracker.dissociate(session_id.as_u64());
        }
    }

    fn close_sessions_for_revoked_qkey(
        &mut self,
        key_id: &str,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let revoked_session_ids = self.qkey_tracker.drain_connections_for_key(key_id);
        if revoked_session_ids.is_empty() {
            return;
        }
        let revoked_session_ids: std::collections::HashSet<u64> =
            revoked_session_ids.into_iter().collect();
        let addrs: Vec<SocketAddr> = self
            .clients
            .keys()
            .copied()
            .filter(|addr| {
                self.domain
                    .session_id_by_remote(*addr)
                    .map(|session_id| revoked_session_ids.contains(&session_id.as_u64()))
                    .unwrap_or(false)
            })
            .collect();
        for addr in addrs {
            if let Some(mut conn) = self.clients.remove(&addr) {
                let conn_id = conn.conn.source_id().as_ref().to_vec();
                if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                    log::warn!(
                        "Client close after QKey revocation failed for {}: {:?}",
                        addr,
                        error
                    );
                }
                self.qkey_auth.remove(&conn_id);
                accept_loop.record_closed(addr);
                metrics.record_connection_rejected();
            }
            self.domain.remove_remote(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn revoke_qkey_now(
        &mut self,
        key_id: &str,
        reason: &str,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        self.revocation_manager.revoke(key_id, reason);
        self.close_sessions_for_revoked_qkey(key_id, accept_loop, metrics);
    }

    fn try_rebind_by_dcid(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
    ) -> bool {
        let old_addr = try_rebind_live_client_by_dcid(&mut self.clients, from, packet, accept_loop);
        if let Some(old_addr) = old_addr {
            self.pending_tun_downlinks.rebind_target(old_addr, from);
            self.domain.rebind_remote(old_addr, from);
            return true;
        }
        false
    }

    pub fn handle_incoming_path_update(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
    ) -> bool {
        if self.clients.contains_key(&from) {
            return false;
        }
        self.try_rebind_by_dcid(from, packet, accept_loop)
    }

    pub fn kick_client(
        &mut self,
        identity: &ClientIdentity,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let Some(addr) = self.domain.remote_addr_for_identity(identity) else {
            return;
        };
        let session_id = self.domain.session_id_by_remote(addr);
        if let Some(mut conn) = self.clients.remove(&addr) {
            let conn_id = conn.conn.source_id().as_ref().to_vec();
            if let Err(e) = conn.conn.close(true, 0x0, b"admin_kick") {
                log::warn!("Client close on admin kick failed for {}: {:?}", addr, e);
            }
            self.qkey_auth.remove(&conn_id);
            accept_loop.record_closed(addr);
            let (discarded_packets, discarded_bytes) = conn.discard_masque_downlink_packets();
            if discarded_packets > 0 {
                metrics.record_masque_downlink_response_terminal_drop(discarded_packets);
                log::warn!(
                    "dropping {} queued MASQUE responses ({} bytes) for administratively removed client {}",
                    discarded_packets,
                    discarded_bytes,
                    addr
                );
            }
        }
        let (discarded_packets, discarded_bytes) = self.pending_tun_downlinks.discard_target(addr);
        if discarded_packets > 0 {
            for _ in 0..discarded_packets {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
            }
            metrics.set_tun_downlink_backpressure_pending(
                self.pending_tun_downlinks.len(),
                self.pending_tun_downlinks.bytes(),
            );
            log::warn!(
                "dropping {} pending TUN downlinks ({} bytes) for administratively removed client {}",
                discarded_packets,
                discarded_bytes,
                addr
            );
        }
        self.dissociate_qkey_for_session(session_id);
        self.domain.remove_remote(addr);
        self.sync_active_metrics(metrics);
    }

    pub fn shutdown_all(&mut self, reason: &'static [u8], metrics: Option<&Metrics>) {
        for conn in self.clients.values_mut() {
            if let Err(e) = conn.conn.close(true, 0x0, reason) {
                log::warn!("Live client close failed for reason {:?}: {:?}", reason, e);
            }
            let (discarded_packets, discarded_bytes) = conn.discard_masque_downlink_packets();
            if discarded_packets > 0 {
                if let Some(metrics) = metrics {
                    metrics.record_masque_downlink_response_shutdown_drop(discarded_packets);
                }
                log::warn!(
                    "dropping {} queued MASQUE responses ({} bytes) during shutdown",
                    discarded_packets,
                    discarded_bytes
                );
            }
        }
        let (discarded_packets, discarded_bytes) = self.pending_tun_downlinks.discard_all();
        if discarded_packets > 0 {
            if let Some(metrics) = metrics {
                for _ in 0..discarded_packets {
                    metrics.record_tun_downlink_backpressure_drop(
                        TunDownlinkBackpressureDrop::Shutdown,
                    );
                }
                metrics.set_tun_downlink_backpressure_pending(0, 0);
            }
            log::warn!(
                "dropping {} pending TUN downlinks ({} bytes) during shutdown",
                discarded_packets,
                discarded_bytes
            );
        }
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    pub async fn force_close_and_flush(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        accept_loop: &AcceptLoop,
        reason: &'static [u8],
    ) {
        self.shutdown_all(reason, Some(metrics));
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        for addr in self.key_addrs() {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            if let Some(conn) = self.get_mut(&addr) {
                if let Err(error) = flush_live_server_outgoing(
                    socket,
                    addr,
                    conn,
                    out,
                    metrics,
                    &client_snapshots,
                    session_stats,
                    session_id,
                )
                .await
                {
                    log::warn!("Failed to flush shutdown frame to {}: {}", addr, error);
                }
            }
        }
        self.reconcile(accept_loop, metrics);
    }

    pub fn reconcile(&mut self, accept_loop: &AcceptLoop, metrics: &Metrics) {
        let closed_addrs =
            reconcile_live_clients(&mut self.clients, &mut self.qkey_auth, accept_loop, metrics);
        for addr in closed_addrs {
            let session_id = self.domain.session_id_by_remote(addr);
            self.dissociate_qkey_for_session(session_id);
            self.domain.remove_remote(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn reap_expired_sessions(&mut self, accept_loop: &AcceptLoop, metrics: &Metrics) {
        let expired_remotes = self.domain.reap_expired_remotes();
        if expired_remotes.is_empty() {
            return;
        }
        for (addr, session_id) in expired_remotes {
            if let Some(mut conn) = self.clients.remove(&addr) {
                let conn_id = conn.conn.source_id().as_ref().to_vec();
                if let Err(error) = conn.conn.close(true, 0x0, b"session_timeout") {
                    log::warn!(
                        "Client close after session timeout failed for {}: {:?}",
                        addr,
                        error
                    );
                }
                self.qkey_auth.remove(&conn_id);
            }
            self.dissociate_qkey_for_session(Some(session_id));
            accept_loop.record_closed(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn enforce_qkey_auth_timeouts(&mut self, metrics: &Metrics) {
        let timed_out_conn_ids: Vec<Vec<u8>> = self
            .qkey_auth
            .iter()
            .filter_map(|(conn_id, state)| state.is_expired().then_some(conn_id.clone()))
            .collect();
        for conn_id in timed_out_conn_ids {
            let key_id = self.qkey_auth.get(&conn_id).map(|state| state.key_id.clone());
            let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
            });
            for conn in self.values_mut() {
                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                    record_qkey_auth_rejection(metrics);
                    if let Err(error) = conn.conn.close(true, 0x0, b"qkey_auth_timeout") {
                        log::warn!("Client close after QKey auth timeout failed: {:?}", error);
                    }
                    break;
                }
            }
            let source_ip = remote_addr.map(|addr| addr.ip().to_string());
            crate::audit::audit(
                crate::audit::AuditEventType::AuthTimeout,
                crate::audit::AuditSeverity::Warning,
                source_ip.as_deref(),
                key_id.as_deref(),
                "QKey authentication timed out",
            );
            let session_id = self.session_id_for_conn_id(&conn_id);
            self.dissociate_qkey_for_session(session_id);
            self.remove_qkey_auth(&conn_id);
        }
    }

    pub fn commit_qkey_auth_result(
        &mut self,
        remove_auth_conn_id: Option<Vec<u8>>,
        auth_result: Option<(Vec<u8>, bool)>,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        if let Some(conn_id) = remove_auth_conn_id {
            self.remove_qkey_auth(&conn_id);
        } else if let Some((conn_id, authed)) = auth_result {
            let mut authed_key_id: Option<String> = None;
            if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                if authed {
                    authed_key_id = Some(state.key_id.clone());
                } else {
                    state.authed = false;
                    crate::audit::audit(
                        crate::audit::AuditEventType::AuthFailed,
                        crate::audit::AuditSeverity::Warning,
                        None,
                        Some(&state.key_id),
                        "QKey authentication failed",
                    );
                }
            }
            if let Some(key_id) = authed_key_id {
                if self.revocation_manager.is_revoked(&key_id) {
                    let addr = self.clients.iter().find_map(|(addr, conn)| {
                        (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                    });
                    if let Some(addr) = addr {
                        let session_id = self.domain.session_id_by_remote(addr);
                        if let Some(mut conn) = self.clients.remove(&addr) {
                            if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                                log::warn!(
                                    "Client close after pending QKey revocation failed for {}: {:?}",
                                    addr,
                                    error
                                );
                            }
                            accept_loop.record_closed(addr);
                            record_qkey_auth_rejection(metrics);
                        }
                        self.dissociate_qkey_for_session(session_id);
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    self.remove_qkey_auth(&conn_id);
                    return;
                }
                if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                    state.authed = true;
                }
                if let Some(session_id) = self.session_id_for_conn_id(&conn_id) {
                    self.qkey_tracker.associate(session_id.as_u64(), &key_id);
                }
                crate::audit::audit(
                    crate::audit::AuditEventType::ClientAuthenticated,
                    crate::audit::AuditSeverity::Info,
                    None,
                    Some(&key_id),
                    "Client authenticated successfully",
                );
            }
        }
    }
}

