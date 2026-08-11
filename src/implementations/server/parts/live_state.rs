#[derive(Debug)]
struct PendingTunDownlink {
    target: SocketAddr,
    session_id: SessionId,
    packet: Vec<u8>,
    queued_at: Instant,
    bandwidth_accounted: bool,
}

impl PendingTunDownlink {
    fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.queued_at) >= MAX_PENDING_TUN_DOWNLINK_AGE
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
struct PendingTunTargetQueue {
    weight: u16,
    deficit_bytes: usize,
    needs_quantum: bool,
    entries: std::collections::VecDeque<PendingTunDownlink>,
}

#[derive(Debug)]
struct PendingTunDownlinks {
    queues: std::collections::HashMap<SessionId, PendingTunTargetQueue>,
    active: std::collections::VecDeque<SessionId>,
    capacity_limiter: BandwidthLimiter,
    entries: usize,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    max_per_target: usize,
}

impl PendingTunDownlinks {
    const DRR_QUANTUM_BYTES: usize = 1_200;

    #[allow(dead_code)]
    fn new(rate_bytes_per_second: u64, burst_bytes: u64) -> Self {
        Self::new_with_clock(
            rate_bytes_per_second,
            burst_bytes,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    fn new_with_clock(
        rate_bytes_per_second: u64,
        burst_bytes: u64,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
        Self::with_limits_and_capacity_and_clock(
            MAX_PENDING_TUN_DOWNLINKS,
            MAX_PENDING_TUN_DOWNLINK_BYTES,
            MAX_PENDING_TUN_DOWNLINKS_PER_TARGET,
            rate_bytes_per_second,
            burst_bytes,
            clock,
        )
    }

    #[cfg(test)]
    fn with_limits(max_entries: usize, max_bytes: usize, max_per_target: usize) -> Self {
        Self::with_limits_and_capacity(
            max_entries,
            max_bytes,
            max_per_target,
            0,
            0,
        )
    }

    #[allow(dead_code)]
    fn with_limits_and_capacity(
        max_entries: usize,
        max_bytes: usize,
        max_per_target: usize,
        rate_bytes_per_second: u64,
        burst_bytes: u64,
    ) -> Self {
        Self::with_limits_and_capacity_and_clock(
            max_entries,
            max_bytes,
            max_per_target,
            rate_bytes_per_second,
            burst_bytes,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    fn with_limits_and_capacity_and_clock(
        max_entries: usize,
        max_bytes: usize,
        max_per_target: usize,
        rate_bytes_per_second: u64,
        burst_bytes: u64,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
        Self {
            queues: std::collections::HashMap::new(),
            active: std::collections::VecDeque::new(),
            capacity_limiter: BandwidthLimiter::new_with_clock(
                rate_bytes_per_second,
                burst_bytes,
                clock,
            ),
            entries: 0,
            bytes: 0,
            max_entries,
            max_bytes,
            max_per_target,
        }
    }

    fn reserve_capacity(&mut self, bytes: usize) -> bool {
        self.capacity_limiter.check(bytes)
    }

    fn refund_capacity(&mut self, bytes: usize) {
        self.capacity_limiter.refund(bytes);
    }

    fn uses_shared_capacity(&self) -> bool {
        !self.capacity_limiter.is_disabled()
    }

    fn contains_session(&self, session_id: SessionId) -> bool {
        self.queues.contains_key(&session_id)
    }

    #[cfg(test)]
    fn enqueue(
        &mut self,
        target: SocketAddr,
        session_id: SessionId,
        weight: u16,
        packet: Vec<u8>,
        queued_at: Instant,
    ) -> Result<(), PendingTunDownlinkReject> {
        self.enqueue_with_accounting(target, session_id, weight, packet, queued_at, false)
    }

    fn enqueue_with_accounting(
        &mut self,
        target: SocketAddr,
        session_id: SessionId,
        weight: u16,
        packet: Vec<u8>,
        queued_at: Instant,
        bandwidth_accounted: bool,
    ) -> Result<(), PendingTunDownlinkReject> {
        if self.entries >= self.max_entries {
            return Err(PendingTunDownlinkReject::Queue);
        }
        if self.bytes.saturating_add(packet.len()) > self.max_bytes {
            return Err(PendingTunDownlinkReject::Bytes);
        }
        let packet_len = packet.len();
        if self
            .queues
            .get(&session_id)
            .is_some_and(|queue| queue.entries.len() >= self.max_per_target)
        {
            return Err(PendingTunDownlinkReject::PerTarget);
        }
        let is_new = !self.queues.contains_key(&session_id);
        let queue = self.queues.entry(session_id).or_insert_with(|| PendingTunTargetQueue {
            weight,
            deficit_bytes: 0,
            needs_quantum: true,
            entries: std::collections::VecDeque::new(),
        });
        queue.weight = weight;
        queue.entries.push_back(PendingTunDownlink {
            target,
            session_id,
            packet,
            queued_at,
            bandwidth_accounted,
        });
        if is_new {
            self.active.push_back(session_id);
        }
        self.entries += 1;
        self.bytes += packet_len;
        Ok(())
    }

    fn pop_next(
        &mut self,
        excluded_sessions: &std::collections::HashSet<SessionId>,
    ) -> Option<PendingTunDownlink> {
        let max_visits = self.pop_visit_budget(excluded_sessions);
        for _ in 0..max_visits {
            let session_id = self.active.pop_front()?;
            if excluded_sessions.contains(&session_id) {
                self.active.push_back(session_id);
                continue;
            }
            let mut remove_queue = false;
            let mut selected = None;
            if let Some(queue) = self.queues.get_mut(&session_id) {
                if queue.needs_quantum {
                    let quantum =
                        Self::DRR_QUANTUM_BYTES.saturating_mul(usize::from(queue.weight.max(1)));
                    queue.deficit_bytes =
                        queue.deficit_bytes.saturating_add(quantum).min(self.max_bytes);
                    queue.needs_quantum = false;
                }
                if queue
                    .entries
                    .front()
                    .is_some_and(|entry| entry.packet.len() <= queue.deficit_bytes)
                {
                    selected = queue.entries.pop_front();
                    if let Some(entry) = selected.as_ref() {
                        queue.deficit_bytes =
                            queue.deficit_bytes.saturating_sub(entry.packet.len());
                    }
                }
                remove_queue = queue.entries.is_empty();
            }
            if remove_queue {
                self.queues.remove(&session_id);
            } else if selected.is_some()
                && self.queues.get(&session_id).is_some_and(|queue| {
                    queue
                        .entries
                        .front()
                        .is_some_and(|entry| entry.packet.len() <= queue.deficit_bytes)
                })
            {
                self.active.push_front(session_id);
            } else {
                if let Some(queue) = self.queues.get_mut(&session_id) {
                    queue.needs_quantum = true;
                }
                self.active.push_back(session_id);
            }
            if let Some(entry) = selected {
                self.entries = self.entries.saturating_sub(1);
                self.bytes = self.bytes.saturating_sub(entry.packet.len());
                return Some(entry);
            }
        }
        None
    }

    fn pop_visit_budget(&self, excluded_sessions: &std::collections::HashSet<SessionId>) -> usize {
        let Some(max_front_packet_bytes) = self
            .active
            .iter()
            .filter(|session_id| !excluded_sessions.contains(session_id))
            .filter_map(|session_id| {
                self.queues
                    .get(session_id)
                    .and_then(|queue| queue.entries.front())
                    .map(|entry| entry.packet.len())
            })
            .max()
        else {
            return 0;
        };
        let required_rounds = max_front_packet_bytes.saturating_add(Self::DRR_QUANTUM_BYTES - 1)
            / Self::DRR_QUANTUM_BYTES;
        self.active.len().saturating_mul(required_rounds.saturating_add(2))
    }

    fn requeue_front(&mut self, entry: PendingTunDownlink, weight: u16) {
        let session_id = entry.session_id;
        let packet_len = entry.packet.len();
        let is_new = !self.queues.contains_key(&session_id);
        let queue = self.queues.entry(session_id).or_insert_with(|| PendingTunTargetQueue {
            weight,
            deficit_bytes: 0,
            needs_quantum: false,
            entries: std::collections::VecDeque::new(),
        });
        queue.weight = weight;
        queue.deficit_bytes = queue.deficit_bytes.saturating_add(packet_len).min(self.max_bytes);
        queue.needs_quantum = false;
        queue.entries.push_front(entry);
        if is_new {
            self.active.push_back(session_id);
        }
        self.entries += 1;
        self.bytes += packet_len;
    }

    fn rebind_target(&mut self, old_target: SocketAddr, new_target: SocketAddr) {
        for queue in self.queues.values_mut() {
            for entry in &mut queue.entries {
                if entry.target == old_target {
                    entry.target = new_target;
                }
            }
        }
    }

    fn discard_target(&mut self, target: SocketAddr) -> (usize, usize) {
        let mut discarded_packets = 0;
        let mut discarded_bytes = 0;
        self.queues.retain(|_, queue| {
            queue.entries.retain(|entry| {
                if entry.target == target {
                    discarded_packets += 1;
                    discarded_bytes += entry.packet.len();
                    false
                } else {
                    true
                }
            });
            !queue.entries.is_empty()
        });
        self.active.retain(|session_id| self.queues.contains_key(session_id));
        self.entries = self.entries.saturating_sub(discarded_packets);
        self.bytes = self.bytes.saturating_sub(discarded_bytes);
        (discarded_packets, discarded_bytes)
    }

    fn discard_all(&mut self) -> (usize, usize) {
        let discarded_packets = self.entries;
        let discarded_bytes = self.bytes;
        self.queues.clear();
        self.active.clear();
        self.entries = 0;
        self.bytes = 0;
        (discarded_packets, discarded_bytes)
    }

    fn len(&self) -> usize {
        self.entries
    }

    fn bytes(&self) -> usize {
        self.bytes
    }

    fn active_clients(&self) -> usize {
        self.queues.len()
    }
}

#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_REAP_INTERVAL: Duration = Duration::from_millis(2);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_RETRY_BASE: Duration = Duration::from_secs(5);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_RETRY_MAX: Duration = Duration::from_secs(300);

#[cfg(feature = "rate_limiter")]
struct BlacklistSyncTask {
    handle: tokio::task::JoinHandle<Result<usize, crate::implementations::server::limits::BlacklistError>>,
    control: Arc<crate::implementations::server::limits::BlacklistSyncControl>,
}

#[cfg(feature = "rate_limiter")]
struct BlacklistSyncState {
    closed: bool,
    next_due: Option<Instant>,
    retry_attempts: u32,
    interval: Duration,
    task: Option<BlacklistSyncTask>,
}

#[cfg(feature = "rate_limiter")]
struct BlacklistSyncOwner {
    state: Arc<Mutex<BlacklistSyncState>>,
    clock: crate::time_source::ProtocolClock,
}

#[cfg(feature = "rate_limiter")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlacklistSyncClaim {
    Claimed,
    NotDue,
    InFlight,
    Closed,
}

#[cfg(feature = "rate_limiter")]
impl BlacklistSyncOwner {
    #[allow(dead_code)]
    fn new() -> Self {
        Self::new_with_clock(&crate::time_source::ProtocolClock::default())
    }

    fn new_with_clock(clock: &crate::time_source::ProtocolClock) -> Self {
        Self {
            state: Arc::new(Mutex::new(BlacklistSyncState {
                closed: false,
                next_due: None,
                retry_attempts: 0,
                interval: Duration::ZERO,
                task: None,
            })),
            clock: clock.clone(),
        }
    }

    fn claim_and_spawn(
        &self,
        blacklist: Arc<crate::implementations::server::limits::BlacklistSync>,
        interval: Duration,
    ) -> BlacklistSyncClaim {
        let mut state = self.state.lock();
        if state.closed {
            return BlacklistSyncClaim::Closed;
        }
        if state.task.is_some() {
            return BlacklistSyncClaim::InFlight;
        }
        if state.next_due.is_some_and(|next_due| self.clock.now() < next_due) {
            return BlacklistSyncClaim::NotDue;
        }

        let control = Arc::new(crate::implementations::server::limits::BlacklistSyncControl::new());
        let control_for_task = Arc::clone(&control);
        let handle = tokio::spawn(async move {
            let result = blacklist.sync_with_cancel(Arc::clone(&control_for_task)).await;
            control_for_task.finish();
            result
        });
        state.next_due = None;
        state.interval = interval;
        state.task = Some(BlacklistSyncTask { handle, control });
        BlacklistSyncClaim::Claimed
    }

    fn close(&self) {
        self.state.lock().closed = true;
    }

    fn take_finished(&self) -> Option<BlacklistSyncTask> {
        let mut state = self.state.lock();
        if state.task.as_ref().is_some_and(|task| task.handle.is_finished()) {
            state.task.take()
        } else {
            None
        }
    }

    fn take_task(&self) -> Option<BlacklistSyncTask> {
        self.state.lock().task.take()
    }

    fn has_task(&self) -> bool {
        self.state.lock().task.is_some()
    }

    async fn observe_finished(&self, metrics: &Metrics) {
        let Some(task) = self.take_finished() else {
            return;
        };
        let retry = Self::observe_join_result(metrics, task.handle.await);
        let mut state = self.state.lock();
        if state.closed {
            return;
        }
        if retry {
            let attempt = state.retry_attempts;
            state.retry_attempts = state.retry_attempts.saturating_add(1);
            let now = self.clock.now();
            state.next_due = Some(now.checked_add(retry_delay(attempt)).unwrap_or(now));
            metrics.record_blacklist_sync_event(
                crate::implementations::server::metrics::BlacklistSyncEvent::RetryScheduled,
            );
        } else {
            state.retry_attempts = 0;
            let now = self.clock.now();
            state.next_due = Some(now.checked_add(state.interval).unwrap_or(now));
        }
    }

    fn observe_join_result(
        metrics: &Metrics,
        result: Result<Result<usize, crate::implementations::server::limits::BlacklistError>, tokio::task::JoinError>,
    ) -> bool {
        match result {
            Ok(Ok(count)) => {
                metrics.record_blacklist_sync_success(count);
                log::info!("Blacklist: synced {count} IPs from external feed");
                false
            }
            Ok(Err(crate::implementations::server::limits::BlacklistError::Cancelled)) => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::Cancelled,
                );
                log::debug!("Blacklist: synchronization cancelled by runtime owner");
                true
            }
            Ok(Err(error)) => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::Failed,
                );
                log::warn!("Blacklist: sync failed (using last-known-good set): {error}");
                true
            }
            Err(error) if error.is_cancelled() => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::Cancelled,
                );
                log::debug!("Blacklist: synchronization task cancelled by runtime owner");
                true
            }
            Err(error) => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::Failed,
                );
                log::warn!("Blacklist: synchronization task join failed: {error}");
                true
            }
        }
    }

    async fn shutdown(&self, metrics: &Metrics) {
        self.close();
        let Some(task) = self.take_task() else {
            return;
        };
        task.control.request_cancel();
        let mut handle = task.handle;
        match tokio::time::timeout(BLACKLIST_SYNC_SHUTDOWN_TIMEOUT, &mut handle).await {
            Ok(result) => {
                Self::observe_join_result(metrics, result);
            }
            Err(_) => {
                if task.control.cancel_before_publication() {
                    handle.abort();
                    let _ = tokio::time::timeout(BLACKLIST_SYNC_REAP_INTERVAL, handle).await;
                } else {
                    debug_assert!(
                        task.control.publication_in_flight()
                            || task.control.is_cancelled()
                    );
                    let result = handle.await;
                    Self::observe_join_result(metrics, result);
                }
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::ShutdownExpired,
                );
                log::warn!(
                    "Blacklist synchronization exceeded the shutdown deadline; publication ownership was retained through its commit barrier"
                );
            }
        }
    }

    fn abandon(&self, metrics: &Metrics) {
        self.close();
        let Some(task) = self.take_task() else {
            return;
        };
        task.control.request_cancel();
        task.control.synchronize_publication_commit();
        task.handle.abort();
        metrics.record_blacklist_sync_event(
            crate::implementations::server::metrics::BlacklistSyncEvent::Cancelled,
        );
    }

    fn has_task_for_cleanup(&self) -> bool {
        self.has_task()
    }
}

#[cfg(feature = "rate_limiter")]
fn retry_delay(attempt: u32) -> Duration {
    let multiplier = 1_u64 << attempt.min(6);
    Duration::from_secs(BLACKLIST_SYNC_RETRY_BASE.as_secs().saturating_mul(multiplier))
        .min(BLACKLIST_SYNC_RETRY_MAX)
}

#[cfg(feature = "rate_limiter")]
impl Drop for BlacklistSyncOwner {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.closed = true;
        if let Some(task) = state.task.take() {
            task.control.request_cancel();
            task.control.synchronize_publication_commit();
            task.handle.abort();
        }
    }
}

pub struct LiveServerState {
    pub(crate) clock: crate::time_source::ProtocolClock,
    clients: std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    path_candidates: std::collections::HashMap<SocketAddr, SocketAddr>,
    /// Bounded downlink packets that could not be enqueued because a client's
    /// QUIC DATAGRAM queue was full. Retried before new TUN packets are read.
    pending_tun_downlinks: PendingTunDownlinks,
    fanout_queue: ClientFanoutQueue,
    qkey_auth: std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    domain: LiveServerDomain,
    auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    #[cfg(feature = "rate_limiter")]
    retry_token_manager: Option<Arc<crate::implementations::server::ddos::RetryTokenManager>>,
    revocation_manager: Arc<crate::implementations::server::revocation::RevocationManager>,
    qkey_tracker: Arc<crate::implementations::server::revocation::QKeyConnectionTracker>,
    next_stats_log: Instant,
    /// Owned external blacklist synchronizer task and atomic due/in-flight claim.
    #[cfg(feature = "rate_limiter")]
    blacklist_sync: BlacklistSyncOwner,
    /// Optional runtime-owned blocking executor for outbound io_uring sends.
    uring_worker: Option<Arc<LiveUringWorker>>,
}

pub struct LiveClientInit {
    pub connection: QuicFuscateConnection,
    pub pending_qkey_auth: Option<QKeyAuthState>,
    /// Runtime policy generation used for this immutable connection snapshot.
    pub runtime_generation: u64,
}

pub(crate) struct LiveClientBuildRequest<'a> {
    pub packet: &'a [u8],
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub qkey_registry: &'a std::sync::Mutex<QKeyRegistry>,
    pub revocation_manager: &'a crate::implementations::server::revocation::RevocationManager,
    pub metrics: &'a Metrics,
    pub stealth_config: &'a Arc<std::sync::Mutex<StealthConfig>>,
    pub fec_cfg_shared: &'a Arc<std::sync::Mutex<FecConfig>>,
    pub opt_params_shared: &'a Arc<std::sync::Mutex<OptimizeConfig>>,
    pub transport_config: &'a crate::transport::Config,
    pub runtime_policy_generation: &'a RuntimePolicyGeneration,
    pub stealth_runtime: Option<Arc<StealthRuntimeOwner>>,
    pub auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    pub retry_token_manager: Option<Arc<crate::implementations::server::ddos::RetryTokenManager>>,
    pub clock: crate::time_source::ProtocolClock,
}

fn complete_auth_attempt(
    limiter: &Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    metrics: &Metrics,
    attempt: crate::implementations::server::limits::AuthAttempt,
    terminal: crate::implementations::server::limits::AuthTerminal,
) -> crate::implementations::server::limits::AuthCompletion {
    use crate::implementations::server::limits::{AuthCompletion, AuthTerminal};

    let mut limiter = limiter.lock().unwrap_or_else(|error| error.into_inner());
    let completion = limiter.complete(attempt, terminal);
    metrics.set_auth_state_tracked_ips(limiter.tracked_ips());
    drop(limiter);
    if completion == AuthCompletion::Duplicate {
        return completion;
    }
    match terminal {
        AuthTerminal::Succeeded => metrics.record_auth_success(),
        AuthTerminal::Failed => metrics.record_auth_failure(),
        AuthTerminal::Abandoned => metrics.record_auth_abandoned(),
    }
    completion
}

fn complete_qkey_auth_state(
    limiter: &Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    metrics: &Metrics,
    state: &mut QKeyAuthState,
    terminal: crate::implementations::server::limits::AuthTerminal,
) -> crate::implementations::server::limits::AuthCompletion {
    let Some(attempt) = state.auth_attempt.take() else {
        return crate::implementations::server::limits::AuthCompletion::Duplicate;
    };
    complete_auth_attempt(limiter, metrics, attempt, terminal)
}

fn audit_qkey_auth_denial(ip: IpAddr, reason: &'static str, message: &'static str) {
    let source_ip = ip.to_string();
    crate::audit::audit_typed(
        crate::audit::AuditEventType::AuthFailed,
        crate::audit::AuditSeverity::Warning,
        Some(&source_ip),
        None,
        crate::audit::AuditContext {
            actor: crate::audit::AuditActor::Client,
            target: crate::audit::AuditTarget::Qkey,
            outcome: crate::audit::AuditOutcome::Denied,
            reason: Some(reason),
        },
        message,
    );
}

pub(crate) fn build_live_server_client_init(
    request: LiveClientBuildRequest<'_>,
) -> Option<LiveClientInit> {
    use crate::implementations::server::limits::{AuthAdmission, AuthTerminal};

    let ip = request.remote_addr.ip();
    let admission = {
        let mut limiter =
            request.auth_rate_limiter.lock().unwrap_or_else(|error| error.into_inner());
        let admission = limiter.begin(ip);
        request.metrics.set_auth_state_tracked_ips(limiter.tracked_ips());
        admission
    };
    request.metrics.record_auth_attempt();
    let auth_attempt = match admission {
        AuthAdmission::Allowed(attempt) => attempt,
        AuthAdmission::Backoff { retry_after } => {
            log::warn!(
                "QKey authentication temporarily rate limited for {}; retry_after_ms={}",
                ip,
                retry_after.as_millis()
            );
            request.metrics.record_connection_rejected();
            request.metrics.record_auth_backoff_rejection();
            audit_qkey_auth_denial(
                ip,
                "qkey_auth_backoff",
                "QKey authentication attempt rejected by backoff policy",
            );
            return None;
        }
        AuthAdmission::Blocked { retry_after } => {
            log::warn!(
                "QKey authentication blocked for {}; retry_after_ms={}",
                ip,
                retry_after.as_millis()
            );
            request.metrics.record_connection_rejected();
            request.metrics.record_auth_blocked_rejection();
            audit_qkey_auth_denial(
                ip,
                "qkey_auth_blocked",
                "QKey authentication attempt rejected by block policy",
            );
            return None;
        }
        AuthAdmission::StateCapacity | AuthAdmission::PendingCapacity => {
            log::warn!("QKey authentication state capacity reached for {}", ip);
            request.metrics.record_connection_rejected();
            request.metrics.record_auth_capacity_rejection();
            audit_qkey_auth_denial(
                ip,
                "qkey_auth_state_capacity",
                "QKey authentication attempt rejected by bounded state capacity",
            );
            return None;
        }
    };

    let mut initial_ctx = match parse_live_server_initial_auth(
        request.packet,
        ip,
        request.retry_token_manager.as_deref(),
        request.qkey_registry,
        request.revocation_manager,
        auth_attempt,
    ) {
        Ok(ctx) => ctx,
        Err(error) => {
            request.metrics.record_connection_rejected();
            let terminal = if error.is_auth_failure() {
                AuthTerminal::Failed
            } else {
                AuthTerminal::Abandoned
            };
            complete_auth_attempt(
                &request.auth_rate_limiter,
                request.metrics,
                auth_attempt,
                terminal,
            );
            if error.is_auth_failure() {
                audit_qkey_auth_denial(
                    ip,
                    "qkey_initial_auth_denied",
                    "QKey initial authentication denied",
                );
            }
            return None;
        }
    };
    let runtime_policy = RuntimePolicySnapshot::capture(
        request.runtime_policy_generation,
        request.transport_config,
        request.fec_cfg_shared,
        request.opt_params_shared,
        request.stealth_config,
    );
    let runtime_generation = runtime_policy.generation;
    if let Some(state) = initial_ctx.pending_qkey_auth.as_mut() {
        let ceiling = runtime_policy.transport.qkey_traffic_analysis_ceiling();
        state.traffic_analysis_policy = state.traffic_analysis_policy.map(|requested| {
            requested.bounded_by(ceiling)
        });
    }

    log::info!("New client connected: {}", request.remote_addr);

    let mut conn_stealth_cfg = runtime_policy.stealth;
    let mut conn_fec_cfg = runtime_policy.fec;
    if let Some(ref record) = initial_ctx.qkey_record {
        apply_qkey_policy_overrides(record, &mut conn_stealth_cfg, &mut conn_fec_cfg);
    }
    let opt_params = runtime_policy.optimize;
    let mut selected_transport = runtime_policy.transport;
    if let Err(error) = selected_transport.select_version(initial_ctx.version) {
        log::warn!("refusing unsupported QUIC version {:#010x}: {}", initial_ctx.version, error);
        request.metrics.record_connection_rejected();
        complete_auth_attempt(
            &request.auth_rate_limiter,
            request.metrics,
            auth_attempt,
            AuthTerminal::Abandoned,
        );
        return None;
    }
    match create_live_server_connection_with_runtime_and_clock(
        request.local_addr,
        request.remote_addr,
        &mut selected_transport,
        conn_stealth_cfg,
        conn_fec_cfg,
        opt_params,
        &initial_ctx.initial_key_dcid,
        request.stealth_runtime.clone(),
        request.clock,
    ) {
        Ok(connection) => {
            Some(LiveClientInit {
                connection,
                pending_qkey_auth: initial_ctx.pending_qkey_auth,
                runtime_generation,
            })
        }
        Err(error) => {
            log::error!("failed to create server connection: {}", error);
            complete_auth_attempt(
                &request.auth_rate_limiter,
                request.metrics,
                auth_attempt,
                AuthTerminal::Abandoned,
            );
            None
        }
    }
}

pub struct LiveClientRuntime<'a> {
    pub connection: &'a mut QuicFuscateConnection,
    pub client_count: usize,
    pub migration_from: Option<SocketAddr>,
    pub conn_id: Vec<u8>,
    pub qkey_auth: Option<QKeyAuthState>,
    pub session_id: Option<SessionId>,
    pub session_stats: Option<Arc<SessionStats>>,
    pub assigned_ips: Option<AssignedClientIps>,
    pub forwarding_policy: Arc<ClientIsolationManager>,
    pub sessions: Arc<RwLock<SessionManager>>,
    fanout_queue: ClientFanoutQueue,
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing LiveClientRuntime would allocate on every server packet acquisition"
)]
pub enum LiveClientAcquire<'a> {
    Ready(LiveClientRuntime<'a>),
    Backpressure,
    Rejected,
}

struct LiveServerDomain {
    shared: SharedServerDomain,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    dns_admission: Arc<crate::dns::DnsAdmission>,
}

impl LiveServerDomain {
    #[allow(dead_code)]
    fn try_new(server_config: &ServerConfig) -> Result<Self, String> {
        Self::try_new_with_clock(server_config, &crate::time_source::ProtocolClock::default())
    }

    fn try_new_with_clock(
        server_config: &ServerConfig,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        let dns_admission = Arc::new(
            crate::dns::DnsAdmission::try_new_with_clock(server_config.dns_admission, clock)
                .map_err(|error| format!("server DNS admission configuration: {error}"))?,
        );
        Ok(Self {
            shared: SharedServerDomain::try_new_with_clock(server_config, clock)?,
            client_snapshots: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            dns_admission,
        })
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
            self.dns_admission
                .remove_identity(crate::dns::DnsAdmissionIdentity::Source(remote_addr.ip()));
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
        self.dns_admission
            .remove_identity(crate::dns::DnsAdmissionIdentity::Session(session_id.as_u64()));
        self.dns_admission
            .remove_identity(crate::dns::DnsAdmissionIdentity::Source(remote_addr.ip()));
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(remote_addr.ip());
        self.remove_remote_snapshot(remote_addr);
    }

    fn rebind_remote(&self, old_addr: SocketAddr, new_addr: SocketAddr) -> bool {
        let mut sessions = self.shared.sessions.write();
        if sessions.rebind_remote_addr(old_addr, new_addr).is_err() {
            return false;
        }
        drop(sessions);
        let mut limiter = self.shared.connection_limiter.lock();
        limiter.remove(old_addr.ip());
        limiter.add(new_addr.ip());
        self.dns_admission
            .remove_identity(crate::dns::DnsAdmissionIdentity::Source(old_addr.ip()));
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(old_addr.ip());
        if let Ok(mut guard) = self.client_snapshots.lock() {
            if let Some(snapshot) = guard.remove(&old_addr) {
                guard.insert(new_addr, snapshot);
            }
        }
        true
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
            self.dns_admission
                .remove_identity(crate::dns::DnsAdmissionIdentity::Session(session.id().as_u64()));
            self.dns_admission
                .remove_identity(crate::dns::DnsAdmissionIdentity::Source(session.remote_addr().ip()));
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

    fn dns_admission(&self) -> Arc<crate::dns::DnsAdmission> {
        Arc::clone(&self.dns_admission)
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
    fn admit_incoming_datagram(
        &self,
        from: SocketAddr,
        packet: &[u8],
        established: bool,
        retry_eligible: bool,
        metrics: &Metrics,
    ) -> crate::implementations::server::ddos::IncomingDatagramAdmission {
        self.shared
            .admit_incoming_datagram(from, packet, established, retry_eligible, metrics)
    }

    #[cfg(feature = "rate_limiter")]
    fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        self.shared.geoip_status()
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self, metrics: &Metrics) {
        self.shared.prune_rate_limits_if_due(metrics);
    }

    /// Returns a clone of the blacklist synchronizer Arc for async sync.
    #[cfg(feature = "rate_limiter")]
    fn blacklist(&self) -> Arc<crate::implementations::server::limits::BlacklistSync> {
        Arc::clone(&self.shared.blacklist)
    }
}

#[allow(clippy::too_many_arguments)]
fn accept_session_in_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    mut ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
    remote_addr: SocketAddr,
    max_clients: usize,
    client_timeout_secs: u64,
    clock: &crate::time_source::ProtocolClock,
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
        Session::new_dual_stack_with_clock(
            remote_addr,
            client_ip,
            Some(v6),
            client_timeout_secs,
            clock,
        )
    } else {
        Session::new_with_clock(remote_addr, client_ip, client_timeout_secs, clock)
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
        Err(
            SessionError::NotFound
                | SessionError::AlreadyExists
                | SessionError::SessionIdConflict(_)
                | SessionError::ClientIpConflict(_)
                | SessionError::ClientIpv6Conflict(_)
                | SessionError::RemoteAddrConflict(_)
                | SessionError::BandwidthPolicy(_),
        ) => {
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
    pub fn try_new(server_config: ServerConfig) -> Result<Self, String> {
        Self::try_new_with_clock(server_config, crate::time_source::ProtocolClock::default())
    }

    pub fn try_new_with_clock(
        server_config: ServerConfig,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        server_config.validate_revocation_retention()?;
        let revocation_manager =
            Arc::new(crate::implementations::server::revocation::RevocationManager::new_with_retention_secs_and_clock(
                server_config.revocation_retention_secs,
                &clock,
            ));
        let qkey_tracker =
            Arc::new(crate::implementations::server::revocation::QKeyConnectionTracker::new());
        let domain = LiveServerDomain::try_new_with_clock(&server_config, &clock)?;
        #[cfg(feature = "rate_limiter")]
        let retry_token_manager = domain.shared.retry_token_manager.clone();
        Ok(Self {
            clock: clock.clone(),
            clients: std::collections::HashMap::new(),
            path_candidates: std::collections::HashMap::new(),
            pending_tun_downlinks: PendingTunDownlinks::new_with_clock(
                server_config.downlink_scheduler_rate_bytes_per_second,
                server_config.downlink_scheduler_burst_bytes,
                &clock,
            ),
            fanout_queue: new_client_fanout_queue(),
            qkey_auth: std::collections::HashMap::new(),
            domain,
            auth_rate_limiter: Arc::new(std::sync::Mutex::new(
                crate::implementations::server::limits::AuthRateLimiter::new_with_clock(
                    server_config.auth_policy.clone(),
                    &clock,
                ),
            )),
            #[cfg(feature = "rate_limiter")]
            retry_token_manager,
            revocation_manager,
            qkey_tracker,
            next_stats_log: clock.now(),
            #[cfg(feature = "rate_limiter")]
            blacklist_sync: BlacklistSyncOwner::new_with_clock(&clock),
            uring_worker: None,
        })
    }

    fn dns_admission(&self) -> Arc<crate::dns::DnsAdmission> {
        self.domain.dns_admission()
    }

    /// Create the bounded outbound io_uring owner for a standalone runtime.
    pub(crate) fn enable_uring_worker(&mut self) {
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        {
            self.uring_worker = LiveUringWorker::with_defaults().map(Arc::new);
            if self.uring_worker.is_some() {
                log::info!("server io_uring batch worker initialised");
            }
        }
    }

    /// Request and join the outbound io_uring owner during runtime teardown.
    pub(crate) fn stop_uring_worker(&mut self) -> Option<String> {
        self.uring_worker.take().and_then(|worker| {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                worker.request_shutdown();
                worker.join().err()
            }
            #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
            {
                let _ = worker;
                None
            }
        })
    }

    pub fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.domain.client_snapshots()
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) fn admit_incoming_datagram(
        &self,
        from: SocketAddr,
        packet: &[u8],
        established: bool,
        retry_eligible: bool,
        metrics: &Metrics,
    ) -> crate::implementations::server::ddos::IncomingDatagramAdmission {
        self.domain
            .admit_incoming_datagram(from, packet, established, retry_eligible, metrics)
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        self.domain.geoip_status()
    }

    #[cfg(feature = "rate_limiter")]
    pub fn is_established_datagram(&self, from: SocketAddr, packet: &[u8]) -> bool {
        if let Some(connection) = self.clients.get(&from) {
            return connection.conn.is_established();
        }
        find_live_client_by_dcid(&self.clients, from, packet)
            .and_then(|address| self.clients.get(&address))
            .is_some_and(|connection| connection.conn.is_established())
    }

    #[cfg(feature = "rate_limiter")]
    pub fn prune_rate_limits_if_due(&self, metrics: &Metrics) {
        self.domain.prune_rate_limits_if_due(metrics);
    }

    /// Periodically synchronize the external blacklist feed under an owned,
    /// atomic due/in-flight claim. Fetching and cache publication remain
    /// outside the housekeeping future; completion is observed here so the
    /// runtime can publish success, failure, and cancellation telemetry.
    #[cfg(feature = "rate_limiter")]
    async fn maybe_sync_blacklist(&mut self, metrics: &Metrics) {
        self.blacklist_sync.observe_finished(metrics).await;
        let blacklist = self.domain.blacklist();
        if !blacklist.has_sync_url() {
            return;
        }
        let interval = blacklist.sync_interval();
        match self.blacklist_sync.claim_and_spawn(blacklist, interval) {
            BlacklistSyncClaim::Claimed => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::Started,
                );
                log::debug!("Blacklist: dispatching owned background sync from external feed");
            }
            BlacklistSyncClaim::InFlight => {
                metrics.record_blacklist_sync_event(
                    crate::implementations::server::metrics::BlacklistSyncEvent::SkippedInFlight,
                );
            }
            BlacklistSyncClaim::NotDue | BlacklistSyncClaim::Closed => {}
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn close_blacklist_sync(&self) {
        self.blacklist_sync.close();
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) async fn shutdown_blacklist_sync(&self, metrics: &Metrics) {
        self.blacklist_sync.shutdown(metrics).await;
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) fn abandon_blacklist_sync(&self, metrics: &Metrics) {
        self.blacklist_sync.abandon(metrics);
    }

    #[cfg(feature = "rate_limiter")]
    pub(crate) fn blacklist_sync_has_task(&self) -> bool {
        self.blacklist_sync.has_task_for_cleanup()
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
        let sessions = Arc::clone(&self.domain.shared.sessions);
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
                    migration_from: None,
                    conn_id,
                    qkey_auth,
                    session_id,
                    session_stats,
                    assigned_ips: existing_assigned_ips,
                    forwarding_policy,
                    sessions,
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
                        if let Some(state) = init.pending_qkey_auth.take() {
                            if let Some(attempt) = state.auth_attempt {
                                complete_auth_attempt(
                                    &self.auth_rate_limiter,
                                    metrics,
                                    attempt,
                                    crate::implementations::server::limits::AuthTerminal::Abandoned,
                                );
                            }
                        }
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Rejected;
                    }
                };
                if init.pending_qkey_auth.is_none() {
                    let activation =
                        self.domain.shared.sessions.write().activate_bandwidth(session_id, None);
                    if let Err(error) = activation {
                        log::error!(
                            "Default authenticated bandwidth policy failed for {}: {}",
                            session_id,
                            error
                        );
                        self.domain.remove_remote(addr);
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Rejected;
                    }
                }
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
                    migration_from: None,
                    conn_id,
                    qkey_auth,
                    session_id: Some(session_id),
                    session_stats: Some(session_stats),
                    assigned_ips: Some(assigned_ips),
                    forwarding_policy,
                    sessions,
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
        let migration_from = self.handle_incoming_path_update(addr, packet);
        let lookup_addr = migration_from.unwrap_or(addr);
        if let Some(old_addr) = migration_from {
            log::debug!("Client path candidate observed: {} -> {}", old_addr, addr);
        }

        let mut acquired = self.accept_or_get_client_with(
            lookup_addr,
            accept_loop,
            accept_max_clients,
            metrics,
            build,
        );
        if let LiveClientAcquire::Ready(client) = &mut acquired {
            client.migration_from = migration_from;
            metrics.clients_active.store(client.client_count as u64, Ordering::Relaxed);
        }
        acquired
    }

    fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut QuicFuscateConnection> {
        self.clients.get_mut(addr)
    }

    fn drain_client_fanout(&mut self, metrics: &Metrics) {
        for _ in 0..MAX_CLIENT_FANOUT_DRAIN_BATCH {
            let fanout = match self.fanout_queue.lock() {
                Ok(mut queue) => queue.pop_front(),
                Err(poisoned) => poisoned.into_inner().pop_front(),
            };
            let Some(fanout) = fanout else {
                break;
            };
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
                        Some((*address, session.id()))
                    })
                    .collect::<smallvec::SmallVec<[(SocketAddr, SessionId); 4]>>()
            };

            let mut queued = false;
            for (target, session_id) in targets {
                let Some(connection) = self.clients.get_mut(&target) else {
                    continue;
                };
                if fanout.packet.len() > connection.effective_tunnel_mtu() {
                    log::debug!("Client fan-out packet exceeds tunnel MTU for {}", target);
                    continue;
                }
                let Some(weight) = self
                    .domain
                    .shared
                    .sessions
                    .read()
                    .bandwidth_stats(session_id)
                    .map(|stats| stats.policy.weight)
                else {
                    continue;
                };
                if enqueue_scheduled_tun_downlink(
                    &mut self.pending_tun_downlinks,
                    target,
                    session_id,
                    weight,
                    fanout.packet.clone(),
                    self.clock.now(),
                    metrics,
                )
                .is_ok()
                {
                    queued = true;
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
    ) -> Result<(), qf_engine_types::DataPlaneFault> {
        let now = self.clock.now();
        let log_client_stats = now >= self.next_stats_log;
        if log_client_stats {
            self.next_stats_log =
                now.checked_add(SERVER_STATS_LOG_INTERVAL).unwrap_or(now);
        }
        {
            let mut limiter =
                self.auth_rate_limiter.lock().unwrap_or_else(|error| error.into_inner());
            let pruned = limiter.prune_if_due();
            metrics.set_auth_state_tracked_ips(limiter.tracked_ips());
            metrics.record_auth_state_pruned(pruned);
        }
        let pruned_revocations = match self.revocation_manager.prune_expired_if_due() {
            Ok(pruned) => pruned,
            Err(error) => {
                log::error!("QKey revocation pruning skipped: {error}");
                0
            }
        };
        metrics.record_revocation_pruned(pruned_revocations);
        #[cfg(feature = "rate_limiter")]
        {
            self.prune_rate_limits_if_due(metrics);
            // Periodically dispatch and observe the owned blacklist worker.
            self.maybe_sync_blacklist(metrics).await;
        }
        self.drain_client_fanout(metrics);
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        let addresses = self.key_addrs();
        let uring_worker = self.uring_worker.clone();
        for addr in addresses {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            let established_conn_id = if let Some(conn) = self.get_mut(&addr) {
                drain_masque_downlink_responses(conn, addr, metrics);
                flush_live_server_outgoing(
                    socket,
                    addr,
                    conn,
                    out,
                    metrics,
                    &client_snapshots,
                    session_stats,
                    session_id,
                    uring_worker.as_deref(),
                )
                .await?;
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
                conn.conn.is_established().then(|| conn.conn.source_id().as_ref().to_vec())
            } else {
                None
            };
            if let Some(conn_id) = established_conn_id {
                if let Some(state) = self.qkey_auth.get_mut(&conn_id) {
                    state.begin_post_handshake_timeout_at(now);
                }
            }
        }
        self.enforce_qkey_auth_timeouts(metrics);
        self.reap_expired_sessions(accept_loop, metrics);
        self.reconcile(accept_loop, metrics);
        Ok(())
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
            // Keep the closed connection in `clients` until the next runtime
            // flush sends its queued CONNECTION_CLOSE frame. Removing it here
            // would drop that frame and leave the peer unaware of revocation.
            if let Some(conn) = self.clients.get_mut(&addr) {
                let conn_id = conn.conn.source_id().as_ref().to_vec();
                if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                    log::warn!(
                        "Client close after QKey revocation failed for {}: {:?}",
                        addr,
                        error
                    );
                }
                self.qkey_auth.remove(&conn_id);
            }
        }
    }

    pub fn revoke_qkey_now(
        &mut self,
        key_id: &str,
        reason: &str,
        _accept_loop: &AcceptLoop,
        _metrics: &Metrics,
    ) -> Result<(), crate::time_source::WallClockError> {
        self.revocation_manager.revoke(key_id, reason)?;
        self.close_sessions_for_revoked_qkey(key_id);
        Ok(())
    }

    pub fn handle_incoming_path_update(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
    ) -> Option<SocketAddr> {
        if self.clients.contains_key(&from) {
            return None;
        }
        if let Some(old_addr) = self.path_candidates.get(&from).copied() {
            if self.clients.contains_key(&old_addr) {
                return Some(old_addr);
            }
            self.path_candidates.remove(&from);
        }
        let old_addr = find_live_client_by_dcid(&self.clients, from, packet)?;
        self.path_candidates.retain(|_, candidate_old| *candidate_old != old_addr);
        self.path_candidates.insert(from, old_addr);
        Some(old_addr)
    }

    pub fn commit_validated_path_update(
        &mut self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        local_addr: SocketAddr,
        accept_loop: &AcceptLoop,
    ) -> bool {
        if old_addr == new_addr || self.clients.contains_key(&new_addr) {
            return false;
        }
        let validated = self.clients.get(&old_addr).is_some_and(|connection| {
            connection
                .conn
                .path_stats()
                .next()
                .is_some_and(|path| path.local_addr == local_addr && path.peer_addr == new_addr)
        });
        if !validated {
            return false;
        }

        let Some(connection) = self.clients.remove(&old_addr) else {
            return false;
        };
        if !self.domain.rebind_remote(old_addr, new_addr) {
            self.clients.insert(old_addr, connection);
            return false;
        }
        self.clients.insert(new_addr, connection);
        self.path_candidates.remove(&new_addr);
        self.pending_tun_downlinks.rebind_target(old_addr, new_addr);
        accept_loop.record_migration(old_addr, new_addr);
        crate::telemetry::QKEY_PATH_REBIND_TOTAL.inc();
        log::info!("Client path validated and committed: {} -> {}", old_addr, new_addr);
        true
    }

    pub fn reconcile_incoming_path_update(
        &mut self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
        local_addr: SocketAddr,
        accept_loop: &AcceptLoop,
    ) -> bool {
        if self.commit_validated_path_update(old_addr, new_addr, local_addr, accept_loop) {
            return true;
        }
        let validation_pending = self.clients.get(&old_addr).is_some_and(|connection| {
            connection.conn.is_path_validation_pending(local_addr, new_addr)
        });
        if !validation_pending {
            self.path_candidates.remove(&new_addr);
        }
        false
    }

    pub fn kick_client(
        &mut self,
        identity: &ClientIdentity,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) -> bool {
        let Some(addr) = self.domain.remote_addr_for_identity(identity) else {
            return false;
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
            metrics.set_bandwidth_scheduler_active_clients(
                self.pending_tun_downlinks.active_clients(),
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
        true
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
                metrics.set_bandwidth_scheduler_active_clients(0);
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
        let uring_worker = self.uring_worker.clone();
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
                    uring_worker.as_deref(),
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
        self.path_candidates.retain(|new_addr, old_addr| {
            self.clients.get(old_addr).is_some_and(|connection| {
                connection.conn.path_stats().next().is_some_and(|active| {
                    connection.conn.is_path_validation_pending(active.local_addr, *new_addr)
                })
            })
        });
        let closed_pending: Vec<(Vec<u8>, IpAddr, String)> = self
            .clients
            .iter()
            .filter(|(_, connection)| connection.conn.is_closed())
            .filter_map(|(addr, connection)| {
                let conn_id = connection.conn.source_id().as_ref().to_vec();
                self.qkey_auth
                    .get(&conn_id)
                    .filter(|state| !state.authed)
                    .map(|state| (conn_id, addr.ip(), state.key_id.clone()))
            })
            .collect();
        for (conn_id, ip, key_id) in closed_pending {
            if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                complete_qkey_auth_state(
                    &self.auth_rate_limiter,
                    metrics,
                    &mut state,
                    crate::implementations::server::limits::AuthTerminal::Failed,
                );
                let source_ip = ip.to_string();
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::AuthFailed,
                    crate::audit::AuditSeverity::Warning,
                    Some(&source_ip),
                    Some(&key_id),
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Client,
                        target: crate::audit::AuditTarget::Qkey,
                        outcome: crate::audit::AuditOutcome::Denied,
                        reason: Some("qkey_auth_connection_closed"),
                    },
                    "QKey authentication connection closed before completion",
                );
            }
        }
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
                if let Some(mut state) = self.qkey_auth.remove(&conn_id) {
                    if !state.authed {
                        complete_qkey_auth_state(
                            &self.auth_rate_limiter,
                            metrics,
                            &mut state,
                            crate::implementations::server::limits::AuthTerminal::Failed,
                        );
                    }
                }
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
            .filter_map(|(conn_id, state)| {
                state.is_expired_at(self.clock.now()).then_some(conn_id.clone())
            })
            .collect();
        for conn_id in timed_out_conn_ids {
            let key_id = self.qkey_auth.get(&conn_id).map(|state| state.key_id.clone());
            let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
            });
            for conn in self.values_mut() {
                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                    metrics.record_connection_rejected();
                    if let Err(error) = conn.conn.close(true, 0x0, b"qkey_auth_timeout") {
                        log::warn!("Client close after QKey auth timeout failed: {:?}", error);
                    }
                    break;
                }
            }
            let source_ip = remote_addr.map(|addr| addr.ip().to_string());
            crate::audit::audit_typed(
                crate::audit::AuditEventType::AuthTimeout,
                crate::audit::AuditSeverity::Warning,
                source_ip.as_deref(),
                key_id.as_deref(),
                crate::audit::AuditContext {
                    actor: crate::audit::AuditActor::Client,
                    target: crate::audit::AuditTarget::Client,
                    outcome: crate::audit::AuditOutcome::TimedOut,
                    reason: Some("qkey_authentication_timeout"),
                },
                "QKey authentication timed out",
            );
            let session_id = self.session_id_for_conn_id(&conn_id);
            self.dissociate_qkey_for_session(session_id);
            if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                complete_qkey_auth_state(
                    &self.auth_rate_limiter,
                    metrics,
                    &mut state,
                    crate::implementations::server::limits::AuthTerminal::Failed,
                );
            }
        }
    }

    pub fn commit_qkey_auth_result(
        &mut self,
        remove_auth_conn_id: Option<Vec<u8>>,
        auth_result: Option<(Vec<u8>, bool)>,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let mut handled_conn_id: Option<Vec<u8>> = None;
        if let Some((conn_id, authed)) = auth_result {
            handled_conn_id = Some(conn_id.clone());
            if authed && self.qkey_auth.get(&conn_id).is_some_and(|state| state.authed) {
                // Authentication was already committed for this connection.
                // Replayed HTTP/3 headers must not create a second bandwidth owner.
            } else if !authed {
                let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                    (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                });
                if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                    let key_id = state.key_id.clone();
                    complete_qkey_auth_state(
                        &self.auth_rate_limiter,
                        metrics,
                        &mut state,
                        crate::implementations::server::limits::AuthTerminal::Failed,
                    );
                    let source_ip = remote_addr.map(|addr| addr.ip().to_string());
                    crate::audit::audit_typed(
                        crate::audit::AuditEventType::AuthFailed,
                        crate::audit::AuditSeverity::Warning,
                        source_ip.as_deref(),
                        Some(&key_id),
                        crate::audit::AuditContext {
                            actor: crate::audit::AuditActor::Client,
                            target: crate::audit::AuditTarget::Qkey,
                            outcome: crate::audit::AuditOutcome::Denied,
                            reason: Some("qkey_authentication_denied"),
                        },
                        "QKey authentication denied",
                    );
                }
            } else {
                let policy = self.qkey_auth.get(&conn_id).map(|state| {
                    (
                        state.key_id.clone(),
                        state.bandwidth_policy.clone(),
                        state.traffic_analysis_policy,
                    )
                });
                let Some((key_id, bandwidth_policy, traffic_analysis_policy)) = policy else {
                    return;
                };
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
                            metrics.record_connection_rejected();
                        }
                        self.dissociate_qkey_for_session(session_id);
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                        complete_qkey_auth_state(
                            &self.auth_rate_limiter,
                            metrics,
                            &mut state,
                            crate::implementations::server::limits::AuthTerminal::Failed,
                        );
                    }
                    return;
                }
                let remote_addr = self.clients.iter().find_map(|(addr, connection)| {
                    (connection.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                });
                let session_id =
                    remote_addr.and_then(|addr| self.domain.session_id_by_remote(addr));
                let traffic_analysis_error = match remote_addr {
                    Some(addr) => self
                        .clients
                        .get_mut(&addr)
                        .ok_or(crate::error::ConnectionError::InvalidState)
                        .and_then(|connection| {
                            if let Some(policy) = traffic_analysis_policy {
                                connection.conn.apply_traffic_analysis_policy(policy)?;
                            }
                            connection
                                .conn
                                .authorize_intelligent_traffic_analysis(traffic_analysis_policy)
                        })
                        .err()
                        .map(|error| error.to_string()),
                    None => Some("live connection not found".to_string()),
                };
                let bandwidth_error = if traffic_analysis_error.is_none() {
                    match session_id {
                        Some(session_id) => self
                            .domain
                            .shared
                            .sessions
                            .write()
                            .activate_bandwidth(session_id, bandwidth_policy)
                            .err()
                            .map(|error| error.to_string()),
                        None => Some(SessionError::NotFound.to_string()),
                    }
                } else {
                    None
                };
                let activation_error = traffic_analysis_error.or(bandwidth_error);
                if let Some(error) = activation_error {
                    log::error!("Authenticated QKey policy activation failed: {}", error);
                    metrics.record_connection_rejected();
                    if let Some(addr) = remote_addr {
                        if let Some(mut connection) = self.clients.remove(&addr) {
                            if let Err(close_error) =
                                connection.conn.close(true, 0x0, b"qkey_policy_invalid")
                            {
                                log::warn!(
                                    "Client close after QKey policy activation failure failed: {:?}",
                                    close_error
                                );
                            }
                            accept_loop.record_closed(addr);
                        }
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                        complete_qkey_auth_state(
                            &self.auth_rate_limiter,
                            metrics,
                            &mut state,
                            crate::implementations::server::limits::AuthTerminal::Failed,
                        );
                    }
                    return;
                }
                let Some(session_id) = session_id else {
                    return;
                };
                self.qkey_tracker.associate(session_id.as_u64(), &key_id);
                let auth_rate_limiter = Arc::clone(&self.auth_rate_limiter);
                if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                    state.authed = true;
                    complete_qkey_auth_state(
                        &auth_rate_limiter,
                        metrics,
                        state,
                        crate::implementations::server::limits::AuthTerminal::Succeeded,
                    );
                }
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::ClientAuthenticated,
                    crate::audit::AuditSeverity::Info,
                    None,
                    Some(&key_id),
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Client,
                        target: crate::audit::AuditTarget::Connection,
                        outcome: crate::audit::AuditOutcome::Succeeded,
                        reason: None,
                    },
                    "Client authenticated successfully",
                );
            }
        }
        if let Some(conn_id) = remove_auth_conn_id {
            if handled_conn_id.as_deref() == Some(conn_id.as_slice()) {
                return;
            }
            if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                complete_qkey_auth_state(
                    &self.auth_rate_limiter,
                    metrics,
                    &mut state,
                    crate::implementations::server::limits::AuthTerminal::Failed,
                );
            }
        }
    }
}

#[cfg(test)]
mod migration_commit_tests {
    use super::*;

    #[test]
    fn server_rebind_commits_only_after_transport_path_validation() {
        let mut live_state = LiveServerState::try_new(ServerConfig::default())
            .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let old_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let new_addr: SocketAddr = "127.0.0.1:54322".parse().unwrap();
        let (session_id, _, _) = live_state.domain.accept(old_addr).expect("session");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
                .expect("transport config");
        let mut connection = create_live_server_connection(
            local_addr,
            old_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"migration-commit"),
        )
        .expect("server connection");
        connection.conn.migrate(local_addr, new_addr).expect("migration candidate");
        let (_, _, _, challenge) =
            connection.conn.pending_path_validation_for_test().expect("pending validation");
        let source_id = connection.conn.source_id().as_ref().to_vec();
        live_state.clients.insert(old_addr, connection);
        live_state
            .pending_tun_downlinks
            .enqueue(old_addr, session_id, 1, vec![1], Instant::now())
            .expect("pending downlink");
        let mut routed_packet = [0u8; 64];
        let header_len =
            crate::transport::packet::format_short_header(&source_id, false, &mut routed_packet)
                .expect("short header");
        routed_packet[header_len] = 0;

        assert_eq!(
            live_state.handle_incoming_path_update(
                new_addr,
                &routed_packet[..header_len.saturating_add(1)],
            ),
            Some(old_addr)
        );
        assert!(live_state.clients.contains_key(&old_addr));
        assert!(!live_state.clients.contains_key(&new_addr));

        assert!(!live_state.reconcile_incoming_path_update(
            old_addr,
            new_addr,
            local_addr,
            &accept_loop,
        ));
        assert_eq!(live_state.path_candidates.get(&new_addr), Some(&old_addr));
        assert!(live_state.clients.contains_key(&old_addr));
        assert!(!live_state.clients.contains_key(&new_addr));
        assert_eq!(live_state.domain.session_id_by_remote(old_addr), Some(session_id));
        assert_eq!(live_state.domain.session_id_by_remote(new_addr), None);

        live_state
            .clients
            .get_mut(&old_addr)
            .expect("old registry key")
            .conn
            .receive_path_response_for_test(local_addr, new_addr, challenge);

        assert!(live_state.reconcile_incoming_path_update(
            old_addr,
            new_addr,
            local_addr,
            &accept_loop,
        ));
        assert!(!live_state.clients.contains_key(&old_addr));
        assert!(live_state.clients.contains_key(&new_addr));
        assert_eq!(live_state.domain.session_id_by_remote(old_addr), None);
        assert_eq!(live_state.domain.session_id_by_remote(new_addr), Some(session_id));
        let downlink = live_state
            .pending_tun_downlinks
            .pop_next(&std::collections::HashSet::new())
            .expect("rebound downlink");
        assert_eq!(downlink.target, new_addr);
    }

    #[test]
    fn server_rebind_rejects_conflicting_session_remote_without_mutating_domain() {
        let live_state = LiveServerState::try_new(ServerConfig::default())
            .unwrap_or_else(|error| panic!("live server state construction failed: {error}"));
        let first_addr: SocketAddr = "127.0.0.1:54331".parse().unwrap();
        let second_addr: SocketAddr = "127.0.0.1:54332".parse().unwrap();
        let (first_id, _, _) = live_state.domain.accept(first_addr).expect("first session");
        let (second_id, _, _) = live_state.domain.accept(second_addr).expect("second session");

        assert!(!live_state.domain.rebind_remote(first_addr, second_addr));
        assert_eq!(live_state.domain.session_id_by_remote(first_addr), Some(first_id));
        assert_eq!(live_state.domain.session_id_by_remote(second_addr), Some(second_id));
    }
}
