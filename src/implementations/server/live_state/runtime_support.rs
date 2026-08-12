use super::*;

#[derive(Debug)]
pub(in crate::implementations::server) struct PendingTunDownlink {
    pub(in crate::implementations::server) target: SocketAddr,
    pub(in crate::implementations::server) session_id: SessionId,
    pub(in crate::implementations::server) packet: Vec<u8>,
    pub(in crate::implementations::server) queued_at: Instant,
    pub(in crate::implementations::server) bandwidth_accounted: bool,
}

impl PendingTunDownlink {
    pub(in crate::implementations::server) fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.queued_at) >= MAX_PENDING_TUN_DOWNLINK_AGE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::implementations::server) enum PendingTunDownlinkReject {
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
pub(in crate::implementations::server) struct PendingTunDownlinks {
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

    pub(super) fn new_with_clock(
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
    pub(in crate::implementations::server) fn with_limits(
        max_entries: usize,
        max_bytes: usize,
        max_per_target: usize,
    ) -> Self {
        Self::with_limits_and_capacity(max_entries, max_bytes, max_per_target, 0, 0)
    }

    #[allow(dead_code)]
    pub(in crate::implementations::server) fn with_limits_and_capacity(
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

    pub(in crate::implementations::server) fn reserve_capacity(&mut self, bytes: usize) -> bool {
        self.capacity_limiter.check(bytes)
    }

    pub(in crate::implementations::server) fn refund_capacity(&mut self, bytes: usize) {
        self.capacity_limiter.refund(bytes);
    }

    pub(in crate::implementations::server) fn uses_shared_capacity(&self) -> bool {
        !self.capacity_limiter.is_disabled()
    }

    pub(in crate::implementations::server) fn contains_session(
        &self,
        session_id: SessionId,
    ) -> bool {
        self.queues.contains_key(&session_id)
    }

    #[cfg(test)]
    pub(in crate::implementations::server) fn enqueue(
        &mut self,
        target: SocketAddr,
        session_id: SessionId,
        weight: u16,
        packet: Vec<u8>,
        queued_at: Instant,
    ) -> Result<(), PendingTunDownlinkReject> {
        self.enqueue_with_accounting(target, session_id, weight, packet, queued_at, false)
    }

    pub(in crate::implementations::server) fn enqueue_with_accounting(
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

    pub(in crate::implementations::server) fn pop_next(
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

    pub(in crate::implementations::server) fn pop_visit_budget(
        &self,
        excluded_sessions: &std::collections::HashSet<SessionId>,
    ) -> usize {
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

    pub(in crate::implementations::server) fn requeue_front(
        &mut self,
        entry: PendingTunDownlink,
        weight: u16,
    ) {
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

    pub(in crate::implementations::server) fn rebind_target(
        &mut self,
        old_target: SocketAddr,
        new_target: SocketAddr,
    ) {
        for queue in self.queues.values_mut() {
            for entry in &mut queue.entries {
                if entry.target == old_target {
                    entry.target = new_target;
                }
            }
        }
    }

    pub(in crate::implementations::server) fn discard_target(
        &mut self,
        target: SocketAddr,
    ) -> (usize, usize) {
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

    pub(super) fn discard_all(&mut self) -> (usize, usize) {
        let discarded_packets = self.entries;
        let discarded_bytes = self.bytes;
        self.queues.clear();
        self.active.clear();
        self.entries = 0;
        self.bytes = 0;
        (discarded_packets, discarded_bytes)
    }

    pub(in crate::implementations::server) fn len(&self) -> usize {
        self.entries
    }

    pub(in crate::implementations::server) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(in crate::implementations::server) fn active_clients(&self) -> usize {
        self.queues.len()
    }
}

#[cfg(feature = "rate_limiter")]
pub(in crate::implementations::server) const BLACKLIST_SYNC_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_millis(500);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_REAP_INTERVAL: Duration = Duration::from_millis(2);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_RETRY_BASE: Duration = Duration::from_secs(5);
#[cfg(feature = "rate_limiter")]
const BLACKLIST_SYNC_RETRY_MAX: Duration = Duration::from_secs(300);

#[cfg(feature = "rate_limiter")]
pub(in crate::implementations::server) struct BlacklistSyncTask {
    pub(in crate::implementations::server) handle: tokio::task::JoinHandle<
        Result<usize, crate::implementations::server::limits::BlacklistError>,
    >,
    pub(in crate::implementations::server) control:
        Arc<crate::implementations::server::limits::BlacklistSyncControl>,
}

#[cfg(feature = "rate_limiter")]
pub(in crate::implementations::server) struct BlacklistSyncState {
    pub(in crate::implementations::server) closed: bool,
    pub(in crate::implementations::server) next_due: Option<Instant>,
    pub(in crate::implementations::server) retry_attempts: u32,
    pub(in crate::implementations::server) interval: Duration,
    pub(in crate::implementations::server) task: Option<BlacklistSyncTask>,
}

#[cfg(feature = "rate_limiter")]
pub(in crate::implementations::server) struct BlacklistSyncOwner {
    pub(in crate::implementations::server) state: Arc<Mutex<BlacklistSyncState>>,
    clock: crate::time_source::ProtocolClock,
}

#[cfg(feature = "rate_limiter")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::implementations::server) enum BlacklistSyncClaim {
    Claimed,
    NotDue,
    InFlight,
    Closed,
}

#[cfg(feature = "rate_limiter")]
impl BlacklistSyncOwner {
    #[allow(dead_code)]
    pub(in crate::implementations::server) fn new() -> Self {
        Self::new_with_clock(&crate::time_source::ProtocolClock::default())
    }

    pub(super) fn new_with_clock(clock: &crate::time_source::ProtocolClock) -> Self {
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

    pub(in crate::implementations::server) fn claim_and_spawn(
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

    pub(super) fn close(&self) {
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

    pub(in crate::implementations::server) fn has_task(&self) -> bool {
        self.state.lock().task.is_some()
    }

    pub(in crate::implementations::server) async fn observe_finished(&self, metrics: &Metrics) {
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
        result: Result<
            Result<usize, crate::implementations::server::limits::BlacklistError>,
            tokio::task::JoinError,
        >,
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

    pub(in crate::implementations::server) async fn shutdown(&self, metrics: &Metrics) {
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
                        task.control.publication_in_flight() || task.control.is_cancelled()
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

    pub(in crate::implementations::server) fn abandon(&self, metrics: &Metrics) {
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

    pub(super) fn has_task_for_cleanup(&self) -> bool {
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
