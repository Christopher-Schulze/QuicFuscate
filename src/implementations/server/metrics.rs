//! Prometheus metrics for QuicFuscate server.
//!
//! Exports metrics in Prometheus text format at /metrics endpoint.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

use super::isolation::{UplinkDrop, UplinkRoute};
use super::{BandwidthDecision, BandwidthDirection};
use crate::time_source::ProtocolClock;

/// Lifecycle phase published to every health surface.
///
/// Health answers a different question than readiness. A stopped runtime is not
/// merely unready, and reporting `up=1` and `status=ok` while it is stopping or
/// stopped tells a probe the service is fine and masks exactly the failure an
/// operator needs to see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecyclePhase {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Draining = 3,
    Stopping = 4,
    /// The runtime reached `Stopped`, but owned cleanup did not complete. This is
    /// distinct from a clean stop because it leaves host state behind.
    StoppedIncomplete = 5,
}

impl LifecyclePhase {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Draining,
            4 => Self::Stopping,
            5 => Self::StoppedIncomplete,
            _ => Self::Stopped,
        }
    }

    /// Stable identifier used in the JSON health body and the metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::StoppedIncomplete => "stopped_incomplete",
        }
    }

    /// Whether the runtime is serving traffic. Only `Running` is up.
    pub fn is_up(self) -> bool {
        matches!(self, Self::Running)
    }

    /// The health status this phase forces, if any.
    ///
    /// `Running` returns `None` so the existing readiness checks decide; every other
    /// phase answers on its own, because no amount of readiness makes a stopped
    /// runtime healthy.
    fn forced_health(self) -> Option<&'static str> {
        match self {
            Self::Running => None,
            Self::Starting => Some("starting"),
            Self::Draining => Some("draining"),
            Self::Stopping => Some("stopping"),
            Self::Stopped => Some("stopped"),
            Self::StoppedIncomplete => Some("failed"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum FecProcessCounterKind {
    Emitted,
    Decoded,
    Recovered,
}

/// Read-only adapter from server metrics to the real process-wide FEC producers.
#[derive(Debug)]
pub struct FecProcessCounter(FecProcessCounterKind);

impl FecProcessCounter {
    const fn new(kind: FecProcessCounterKind) -> Self {
        Self(kind)
    }

    pub fn load(&self, _ordering: Ordering) -> u64 {
        match self.0 {
            FecProcessCounterKind::Emitted => crate::telemetry::FEC_SOURCE_PACKETS_SENT
                .get()
                .saturating_add(crate::telemetry::FEC_REPAIR_PACKETS_SENT.get()),
            FecProcessCounterKind::Decoded => crate::telemetry::FEC_DECODED_PACKETS.get(),
            FecProcessCounterKind::Recovered => crate::telemetry::FEC_RECOVERED_PACKETS.get(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingOutcome {
    Local,
    Unicast,
    Fanout,
    Unknown,
    PacketTooBig,
    TimeExceeded,
    Icmpv6,
}

/// Observable terminal outcomes for the bounded server TUN downlink retry queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunDownlinkBackpressureDrop {
    QueueCapacity,
    ByteCapacity,
    PerTargetCapacity,
    Expired,
    TerminalTransportError,
    Shutdown,
}

/// Observable lifecycle and terminal outcomes for accepted DNS intercept workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DnsInterceptWorkerEvent {
    ClosedBeforeSpawn,
    ResponseQueued,
    EmptyResponse,
    ResponseBuildFailed,
    LatePublication,
    QueueRejectedPacketCapacity,
    QueueRejectedByteCapacity,
    Panic,
    QueuedCancellation,
    StartedCancellation,
    ShutdownExpired,
    JoinError,
}

impl DnsInterceptWorkerEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClosedBeforeSpawn => "closed_before_spawn",
            Self::ResponseQueued => "response_queued",
            Self::EmptyResponse => "empty_response",
            Self::ResponseBuildFailed => "response_build_failed",
            Self::LatePublication => "late_publication",
            Self::QueueRejectedPacketCapacity => "queue_rejected_packet_capacity",
            Self::QueueRejectedByteCapacity => "queue_rejected_byte_capacity",
            Self::Panic => "panic",
            Self::QueuedCancellation => "queued_cancellation",
            Self::StartedCancellation => "started_cancellation",
            Self::ShutdownExpired => "shutdown_expired",
            Self::JoinError => "join_error",
        }
    }
}

/// Lifecycle outcomes for the owned external blacklist synchronizer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlacklistSyncEvent {
    Started,
    Succeeded,
    CacheLoaded,
    Failed,
    Cancelled,
    SkippedInFlight,
    RetryScheduled,
    ShutdownExpired,
}

impl BlacklistSyncEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::CacheLoaded => "cache_loaded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::SkippedInFlight => "skipped_in_flight",
            Self::RetryScheduled => "retry_scheduled",
            Self::ShutdownExpired => "shutdown_expired",
        }
    }
}

const BLACKLIST_SYNC_STATUS_DISABLED: u8 = 0;
const BLACKLIST_SYNC_STATUS_PENDING: u8 = 1;
const BLACKLIST_SYNC_STATUS_IN_FLIGHT: u8 = 2;
const BLACKLIST_SYNC_STATUS_SUCCEEDED: u8 = 3;
const BLACKLIST_SYNC_STATUS_FAILED: u8 = 4;
const BLACKLIST_SYNC_STATUS_CANCELLED: u8 = 5;
const BLACKLIST_SYNC_STATUS_SHUTDOWN_EXPIRED: u8 = 6;
const BLACKLIST_SYNC_TIME_UNKNOWN: u64 = u64::MAX;

/// Server metrics collector.
#[derive(Debug)]
pub struct Metrics {
    // Connection metrics
    pub clients_active: AtomicU64,
    pub clients_total: AtomicU64,
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,

    // Traffic metrics
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,

    // Routing policy metrics
    pub routing_internet: AtomicU64,
    pub routing_client: AtomicU64,
    pub routing_broadcast: AtomicU64,
    pub routing_multicast: AtomicU64,
    pub routing_drop_missing_session: AtomicU64,
    pub routing_drop_malformed: AtomicU64,
    pub routing_drop_spoofed: AtomicU64,
    pub routing_drop_inter_client: AtomicU64,
    pub routing_local: AtomicU64,
    pub routing_unicast: AtomicU64,
    pub routing_fanout: AtomicU64,
    pub routing_unknown: AtomicU64,
    pub routing_packet_too_big: AtomicU64,
    pub routing_time_exceeded: AtomicU64,
    pub routing_icmpv6: AtomicU64,

    // TUN/MASQUE downlink backpressure metrics
    pub tun_downlink_backpressure_enqueued: AtomicU64,
    /// Transient TUN-write backpressure events (EAGAIN/WouldBlock) that were
    /// absorbed without failing the data plane (TODO-896).
    pub tun_write_backpressure_absorbed: AtomicU64,
    pub tun_downlink_backpressure_retried: AtomicU64,
    pub tun_downlink_backpressure_pending_packets: AtomicU64,
    pub tun_downlink_backpressure_pending_bytes: AtomicU64,
    pub tun_downlink_backpressure_drop_queue_capacity: AtomicU64,
    pub tun_downlink_backpressure_drop_byte_capacity: AtomicU64,
    pub tun_downlink_backpressure_drop_per_target_capacity: AtomicU64,
    pub tun_downlink_backpressure_drop_expired: AtomicU64,
    pub tun_downlink_backpressure_drop_terminal_transport_error: AtomicU64,
    pub tun_downlink_backpressure_drop_shutdown: AtomicU64,
    /// Whether the server's requested TUN data plane is available.
    pub tun_data_plane_ready: AtomicU64,
    /// Current lifecycle phase, published by the runtime on every transition.
    lifecycle_phase: AtomicU8,
    /// Number of terminal server TUN data-plane faults.
    pub tun_data_plane_faults: AtomicU64,
    /// Process-wide memory-lock readiness and failure state.
    memory_lock_status: parking_lot::RwLock<qf_memory_lock::MemoryLockStartupStatus>,

    // Per-session bandwidth and fair-scheduler metrics
    pub bandwidth_uplink_allowed_bytes: AtomicU64,
    pub bandwidth_downlink_allowed_bytes: AtomicU64,
    pub bandwidth_uplink_rate_limited: AtomicU64,
    pub bandwidth_downlink_rate_limited: AtomicU64,
    pub bandwidth_uplink_daily_quota_exceeded: AtomicU64,
    pub bandwidth_downlink_daily_quota_exceeded: AtomicU64,
    pub bandwidth_uplink_monthly_quota_exceeded: AtomicU64,
    pub bandwidth_downlink_monthly_quota_exceeded: AtomicU64,
    pub bandwidth_uplink_clock_unavailable: AtomicU64,
    pub bandwidth_downlink_clock_unavailable: AtomicU64,
    pub bandwidth_scheduler_active_clients: AtomicU64,
    pub bandwidth_scheduler_enqueued_packets: AtomicU64,
    pub bandwidth_scheduler_delivered_packets: AtomicU64,
    pub bandwidth_scheduler_delivered_bytes: AtomicU64,

    // Server-generated MASQUE response queue metrics
    pub masque_downlink_response_retried: AtomicU64,
    pub masque_downlink_response_drop_packet_capacity: AtomicU64,
    pub masque_downlink_response_drop_byte_capacity: AtomicU64,
    pub masque_downlink_response_drop_terminal_transport_error: AtomicU64,
    pub masque_downlink_response_drop_shutdown: AtomicU64,
    pub dns_intercept_dropped: AtomicU64,
    pub dns_intercept_admitted: AtomicU64,
    pub dns_intercept_admission_rejected_in_flight: AtomicU64,
    pub dns_intercept_admission_rejected_global_rate: AtomicU64,
    pub dns_intercept_admission_rejected_identity_rate: AtomicU64,
    pub dns_intercept_admission_rejected_identity_capacity: AtomicU64,
    pub dns_intercept_worker_closed_before_spawn: AtomicU64,
    pub dns_intercept_worker_response_queued: AtomicU64,
    pub dns_intercept_worker_empty_response: AtomicU64,
    pub dns_intercept_worker_response_build_failed: AtomicU64,
    pub dns_intercept_worker_late_publication: AtomicU64,
    pub dns_intercept_worker_queue_rejected_packet_capacity: AtomicU64,
    pub dns_intercept_worker_queue_rejected_byte_capacity: AtomicU64,
    pub dns_intercept_worker_panic: AtomicU64,
    pub dns_intercept_worker_queued_cancellation: AtomicU64,
    pub dns_intercept_worker_started_cancellation: AtomicU64,
    pub dns_intercept_worker_shutdown_expired: AtomicU64,
    pub dns_intercept_worker_join_error: AtomicU64,
    pub blacklist_sync_started: AtomicU64,
    pub blacklist_sync_succeeded: AtomicU64,
    pub blacklist_sync_cache_loaded: AtomicU64,
    pub blacklist_sync_failed: AtomicU64,
    pub blacklist_sync_cancelled: AtomicU64,
    pub blacklist_sync_skipped_in_flight: AtomicU64,
    pub blacklist_sync_retry_scheduled: AtomicU64,
    pub blacklist_sync_shutdown_expired: AtomicU64,
    pub blacklist_sync_active_entries: AtomicU64,
    pub blacklist_sync_in_flight: AtomicU64,
    pub blacklist_sync_enabled: AtomicU64,
    pub blacklist_sync_interval_secs: AtomicU64,
    pub blacklist_sync_status: AtomicU8,
    blacklist_sync_last_success_uptime: AtomicU64,
    blacklist_sync_last_failure_uptime: AtomicU64,
    pub client_fanout_dropped: AtomicU64,

    // Stealth metrics
    pub stealth_http3_active: AtomicU64,
    pub stealth_tls13_active: AtomicU64,

    // FEC metrics
    pub fec_packets_encoded: FecProcessCounter,
    pub fec_packets_decoded: FecProcessCounter,
    pub fec_packets_recovered: FecProcessCounter,

    // Error metrics
    pub auth_attempts: AtomicU64,
    pub auth_succeeded: AtomicU64,
    pub auth_failed: AtomicU64,
    pub auth_backoff_rejected: AtomicU64,
    pub auth_blocked_rejected: AtomicU64,
    pub auth_capacity_rejected: AtomicU64,
    pub auth_abandoned: AtomicU64,
    pub auth_state_tracked_ips: AtomicU64,
    pub auth_state_pruned: AtomicU64,
    pub revocation_pruned: AtomicU64,
    pub rate_limited: AtomicU64,
    pub ddos_active: AtomicU64,
    pub ddos_current_pps: AtomicU64,
    pub ddos_activations: AtomicU64,
    pub ddos_clears: AtomicU64,
    pub ddos_retry_issued: AtomicU64,
    pub ddos_retry_validated: AtomicU64,
    pub ddos_drop_global_limit: AtomicU64,
    pub ddos_drop_geoip: AtomicU64,
    pub ddos_drop_blacklist: AtomicU64,
    pub ddos_drop_per_ip_limit: AtomicU64,
    pub ddos_drop_malformed_initial: AtomicU64,
    pub ddos_drop_invalid_retry: AtomicU64,
    pub geoip_status: AtomicU8,
    pub geoip_lookups: AtomicU64,
    pub geoip_blocked: AtomicU64,
    pub geoip_lookup_errors: AtomicU64,

    // Uptime (set once at start)
    start_time: std::time::Instant,
    clock: ProtocolClock,
}

impl Metrics {
    /// Create new metrics collector.
    pub fn new() -> Self {
        Self::new_with_clock(&ProtocolClock::default())
    }

    /// Create metrics bound to an explicit protocol clock.
    pub fn new_with_clock(clock: &ProtocolClock) -> Self {
        Self {
            clients_active: AtomicU64::new(0),
            clients_total: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            routing_internet: AtomicU64::new(0),
            routing_client: AtomicU64::new(0),
            routing_broadcast: AtomicU64::new(0),
            routing_multicast: AtomicU64::new(0),
            routing_drop_missing_session: AtomicU64::new(0),
            routing_drop_malformed: AtomicU64::new(0),
            routing_drop_spoofed: AtomicU64::new(0),
            routing_drop_inter_client: AtomicU64::new(0),
            routing_local: AtomicU64::new(0),
            routing_unicast: AtomicU64::new(0),
            routing_fanout: AtomicU64::new(0),
            routing_unknown: AtomicU64::new(0),
            routing_packet_too_big: AtomicU64::new(0),
            routing_time_exceeded: AtomicU64::new(0),
            routing_icmpv6: AtomicU64::new(0),
            tun_downlink_backpressure_enqueued: AtomicU64::new(0),
            tun_write_backpressure_absorbed: AtomicU64::new(0),
            tun_downlink_backpressure_retried: AtomicU64::new(0),
            tun_downlink_backpressure_pending_packets: AtomicU64::new(0),
            tun_downlink_backpressure_pending_bytes: AtomicU64::new(0),
            tun_downlink_backpressure_drop_queue_capacity: AtomicU64::new(0),
            tun_downlink_backpressure_drop_byte_capacity: AtomicU64::new(0),
            tun_downlink_backpressure_drop_per_target_capacity: AtomicU64::new(0),
            tun_downlink_backpressure_drop_expired: AtomicU64::new(0),
            tun_downlink_backpressure_drop_terminal_transport_error: AtomicU64::new(0),
            tun_downlink_backpressure_drop_shutdown: AtomicU64::new(0),
            tun_data_plane_ready: AtomicU64::new(1),
            lifecycle_phase: AtomicU8::new(LifecyclePhase::Starting as u8),
            tun_data_plane_faults: AtomicU64::new(0),
            memory_lock_status: parking_lot::RwLock::new(
                qf_memory_lock::MemoryLockStartupStatus::not_configured(),
            ),
            bandwidth_uplink_allowed_bytes: AtomicU64::new(0),
            bandwidth_downlink_allowed_bytes: AtomicU64::new(0),
            bandwidth_uplink_rate_limited: AtomicU64::new(0),
            bandwidth_downlink_rate_limited: AtomicU64::new(0),
            bandwidth_uplink_daily_quota_exceeded: AtomicU64::new(0),
            bandwidth_downlink_daily_quota_exceeded: AtomicU64::new(0),
            bandwidth_uplink_monthly_quota_exceeded: AtomicU64::new(0),
            bandwidth_downlink_monthly_quota_exceeded: AtomicU64::new(0),
            bandwidth_uplink_clock_unavailable: AtomicU64::new(0),
            bandwidth_downlink_clock_unavailable: AtomicU64::new(0),
            bandwidth_scheduler_active_clients: AtomicU64::new(0),
            bandwidth_scheduler_enqueued_packets: AtomicU64::new(0),
            bandwidth_scheduler_delivered_packets: AtomicU64::new(0),
            bandwidth_scheduler_delivered_bytes: AtomicU64::new(0),
            masque_downlink_response_retried: AtomicU64::new(0),
            masque_downlink_response_drop_packet_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_byte_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_terminal_transport_error: AtomicU64::new(0),
            masque_downlink_response_drop_shutdown: AtomicU64::new(0),
            dns_intercept_dropped: AtomicU64::new(0),
            dns_intercept_admitted: AtomicU64::new(0),
            dns_intercept_admission_rejected_in_flight: AtomicU64::new(0),
            dns_intercept_admission_rejected_global_rate: AtomicU64::new(0),
            dns_intercept_admission_rejected_identity_rate: AtomicU64::new(0),
            dns_intercept_admission_rejected_identity_capacity: AtomicU64::new(0),
            dns_intercept_worker_closed_before_spawn: AtomicU64::new(0),
            dns_intercept_worker_response_queued: AtomicU64::new(0),
            dns_intercept_worker_empty_response: AtomicU64::new(0),
            dns_intercept_worker_response_build_failed: AtomicU64::new(0),
            dns_intercept_worker_late_publication: AtomicU64::new(0),
            dns_intercept_worker_queue_rejected_packet_capacity: AtomicU64::new(0),
            dns_intercept_worker_queue_rejected_byte_capacity: AtomicU64::new(0),
            dns_intercept_worker_panic: AtomicU64::new(0),
            dns_intercept_worker_queued_cancellation: AtomicU64::new(0),
            dns_intercept_worker_started_cancellation: AtomicU64::new(0),
            dns_intercept_worker_shutdown_expired: AtomicU64::new(0),
            dns_intercept_worker_join_error: AtomicU64::new(0),
            blacklist_sync_started: AtomicU64::new(0),
            blacklist_sync_succeeded: AtomicU64::new(0),
            blacklist_sync_cache_loaded: AtomicU64::new(0),
            blacklist_sync_failed: AtomicU64::new(0),
            blacklist_sync_cancelled: AtomicU64::new(0),
            blacklist_sync_skipped_in_flight: AtomicU64::new(0),
            blacklist_sync_retry_scheduled: AtomicU64::new(0),
            blacklist_sync_shutdown_expired: AtomicU64::new(0),
            blacklist_sync_active_entries: AtomicU64::new(0),
            blacklist_sync_in_flight: AtomicU64::new(0),
            blacklist_sync_enabled: AtomicU64::new(0),
            blacklist_sync_interval_secs: AtomicU64::new(0),
            blacklist_sync_status: AtomicU8::new(BLACKLIST_SYNC_STATUS_DISABLED),
            blacklist_sync_last_success_uptime: AtomicU64::new(BLACKLIST_SYNC_TIME_UNKNOWN),
            blacklist_sync_last_failure_uptime: AtomicU64::new(BLACKLIST_SYNC_TIME_UNKNOWN),
            client_fanout_dropped: AtomicU64::new(0),
            stealth_http3_active: AtomicU64::new(0),
            stealth_tls13_active: AtomicU64::new(0),
            fec_packets_encoded: FecProcessCounter::new(FecProcessCounterKind::Emitted),
            fec_packets_decoded: FecProcessCounter::new(FecProcessCounterKind::Decoded),
            fec_packets_recovered: FecProcessCounter::new(FecProcessCounterKind::Recovered),
            auth_attempts: AtomicU64::new(0),
            auth_succeeded: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
            auth_backoff_rejected: AtomicU64::new(0),
            auth_blocked_rejected: AtomicU64::new(0),
            auth_capacity_rejected: AtomicU64::new(0),
            auth_abandoned: AtomicU64::new(0),
            auth_state_tracked_ips: AtomicU64::new(0),
            auth_state_pruned: AtomicU64::new(0),
            revocation_pruned: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            ddos_active: AtomicU64::new(0),
            ddos_current_pps: AtomicU64::new(0),
            ddos_activations: AtomicU64::new(0),
            ddos_clears: AtomicU64::new(0),
            ddos_retry_issued: AtomicU64::new(0),
            ddos_retry_validated: AtomicU64::new(0),
            ddos_drop_global_limit: AtomicU64::new(0),
            ddos_drop_geoip: AtomicU64::new(0),
            ddos_drop_blacklist: AtomicU64::new(0),
            ddos_drop_per_ip_limit: AtomicU64::new(0),
            ddos_drop_malformed_initial: AtomicU64::new(0),
            ddos_drop_invalid_retry: AtomicU64::new(0),
            geoip_status: AtomicU8::new(
                crate::implementations::server::limits::GeoIpStatus::Disabled as u8,
            ),
            geoip_lookups: AtomicU64::new(0),
            geoip_blocked: AtomicU64::new(0),
            geoip_lookup_errors: AtomicU64::new(0),
            start_time: clock.now(),
            clock: clock.clone(),
        }
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.clock.elapsed_since(self.start_time).as_secs()
    }

    pub fn record_connection_accepted(&self) {
        self.clients_total.fetch_add(1, Ordering::Relaxed);
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().server.connection_rejected();
    }

    pub fn record_auth_failure(&self) {
        self.auth_failed.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().server.auth_failure();
    }

    pub fn record_auth_attempt(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_success(&self) {
        self.auth_succeeded.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_backoff_rejection(&self) {
        self.auth_backoff_rejected.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn record_auth_blocked_rejection(&self) {
        self.auth_blocked_rejected.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn record_auth_capacity_rejection(&self) {
        self.auth_capacity_rejected.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn record_auth_abandoned(&self) {
        self.auth_abandoned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_auth_state_tracked_ips(&self, tracked_ips: usize) {
        self.auth_state_tracked_ips.store(tracked_ips as u64, Ordering::Relaxed);
    }

    pub fn record_auth_state_pruned(&self, pruned: usize) {
        self.auth_state_pruned.fetch_add(pruned as u64, Ordering::Relaxed);
    }

    pub fn record_revocation_pruned(&self, pruned: usize) {
        self.revocation_pruned.fetch_add(pruned as u64, Ordering::Relaxed);
    }

    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().server.rate_limit_hit();
    }

    pub fn record_dns_intercept_drop(&self) {
        self.dns_intercept_dropped.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn record_dns_intercept_admitted(&self) {
        self.dns_intercept_admitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dns_intercept_admission_reject(&self, reason: crate::dns::DnsAdmissionReject) {
        self.record_dns_intercept_drop();
        let counter = match reason {
            crate::dns::DnsAdmissionReject::InFlight => {
                &self.dns_intercept_admission_rejected_in_flight
            }
            crate::dns::DnsAdmissionReject::GlobalRate => {
                &self.dns_intercept_admission_rejected_global_rate
            }
            crate::dns::DnsAdmissionReject::IdentityRate => {
                &self.dns_intercept_admission_rejected_identity_rate
            }
            crate::dns::DnsAdmissionReject::IdentityCapacity => {
                &self.dns_intercept_admission_rejected_identity_capacity
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dns_intercept_worker_event(&self, event: DnsInterceptWorkerEvent) {
        let counter = match event {
            DnsInterceptWorkerEvent::ClosedBeforeSpawn => {
                &self.dns_intercept_worker_closed_before_spawn
            }
            DnsInterceptWorkerEvent::ResponseQueued => &self.dns_intercept_worker_response_queued,
            DnsInterceptWorkerEvent::EmptyResponse => &self.dns_intercept_worker_empty_response,
            DnsInterceptWorkerEvent::ResponseBuildFailed => {
                &self.dns_intercept_worker_response_build_failed
            }
            DnsInterceptWorkerEvent::LatePublication => &self.dns_intercept_worker_late_publication,
            DnsInterceptWorkerEvent::QueueRejectedPacketCapacity => {
                &self.dns_intercept_worker_queue_rejected_packet_capacity
            }
            DnsInterceptWorkerEvent::QueueRejectedByteCapacity => {
                &self.dns_intercept_worker_queue_rejected_byte_capacity
            }
            DnsInterceptWorkerEvent::Panic => &self.dns_intercept_worker_panic,
            DnsInterceptWorkerEvent::QueuedCancellation => {
                &self.dns_intercept_worker_queued_cancellation
            }
            DnsInterceptWorkerEvent::StartedCancellation => {
                &self.dns_intercept_worker_started_cancellation
            }
            DnsInterceptWorkerEvent::ShutdownExpired => &self.dns_intercept_worker_shutdown_expired,
            DnsInterceptWorkerEvent::JoinError => &self.dns_intercept_worker_join_error,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn configure_blacklist_sync(&self, enabled: bool, interval: Duration) {
        self.blacklist_sync_enabled.store(u64::from(enabled), Ordering::Release);
        self.blacklist_sync_interval_secs.store(interval.as_secs(), Ordering::Release);
        self.blacklist_sync_status.store(
            if enabled { BLACKLIST_SYNC_STATUS_PENDING } else { BLACKLIST_SYNC_STATUS_DISABLED },
            Ordering::Release,
        );
    }

    pub(crate) fn record_blacklist_sync_event(&self, event: BlacklistSyncEvent) {
        let counter = match event {
            BlacklistSyncEvent::Started => &self.blacklist_sync_started,
            BlacklistSyncEvent::Succeeded => &self.blacklist_sync_succeeded,
            BlacklistSyncEvent::CacheLoaded => &self.blacklist_sync_cache_loaded,
            BlacklistSyncEvent::Failed => &self.blacklist_sync_failed,
            BlacklistSyncEvent::Cancelled => &self.blacklist_sync_cancelled,
            BlacklistSyncEvent::SkippedInFlight => &self.blacklist_sync_skipped_in_flight,
            BlacklistSyncEvent::RetryScheduled => &self.blacklist_sync_retry_scheduled,
            BlacklistSyncEvent::ShutdownExpired => &self.blacklist_sync_shutdown_expired,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        let status = match event {
            BlacklistSyncEvent::Started => BLACKLIST_SYNC_STATUS_IN_FLIGHT,
            BlacklistSyncEvent::Succeeded | BlacklistSyncEvent::CacheLoaded => {
                BLACKLIST_SYNC_STATUS_SUCCEEDED
            }
            BlacklistSyncEvent::Failed => BLACKLIST_SYNC_STATUS_FAILED,
            BlacklistSyncEvent::Cancelled => BLACKLIST_SYNC_STATUS_CANCELLED,
            BlacklistSyncEvent::SkippedInFlight => return,
            BlacklistSyncEvent::RetryScheduled => BLACKLIST_SYNC_STATUS_PENDING,
            BlacklistSyncEvent::ShutdownExpired => BLACKLIST_SYNC_STATUS_SHUTDOWN_EXPIRED,
        };
        self.blacklist_sync_status.store(status, Ordering::Release);
        self.blacklist_sync_in_flight
            .store(u64::from(matches!(event, BlacklistSyncEvent::Started)), Ordering::Release);
        match event {
            BlacklistSyncEvent::Succeeded | BlacklistSyncEvent::CacheLoaded => {
                self.blacklist_sync_last_success_uptime
                    .store(self.uptime_secs(), Ordering::Release);
            }
            BlacklistSyncEvent::Failed => {
                self.blacklist_sync_last_failure_uptime
                    .store(self.uptime_secs(), Ordering::Release);
            }
            BlacklistSyncEvent::Cancelled | BlacklistSyncEvent::ShutdownExpired => {
                self.blacklist_sync_last_failure_uptime
                    .store(self.uptime_secs(), Ordering::Release);
            }
            BlacklistSyncEvent::Started
            | BlacklistSyncEvent::SkippedInFlight
            | BlacklistSyncEvent::RetryScheduled => {}
        }
    }

    pub(crate) fn record_blacklist_sync_success(&self, count: usize) {
        self.blacklist_sync_active_entries.store(count as u64, Ordering::Release);
        self.record_blacklist_sync_event(BlacklistSyncEvent::Succeeded);
    }

    pub(crate) fn record_blacklist_cache_loaded(&self, count: usize) {
        self.blacklist_sync_active_entries.store(count as u64, Ordering::Release);
        self.record_blacklist_sync_event(BlacklistSyncEvent::CacheLoaded);
    }

    pub fn record_client_fanout_drop(&self) {
        self.client_fanout_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ddos_sample(
        &self,
        pps: u64,
        transition: crate::implementations::server::limits::DdosTransition,
    ) {
        use crate::implementations::server::limits::DdosTransition;

        self.ddos_current_pps.store(pps, Ordering::Relaxed);
        match transition {
            DdosTransition::Activated => {
                self.ddos_active.store(1, Ordering::Relaxed);
                self.ddos_activations.fetch_add(1, Ordering::Relaxed);
            }
            DdosTransition::Cleared => {
                self.ddos_active.store(0, Ordering::Relaxed);
                self.ddos_clears.fetch_add(1, Ordering::Relaxed);
            }
            DdosTransition::Unchanged => {}
        }
    }

    pub(crate) fn record_ddos_retry_issued(&self) {
        self.ddos_retry_issued.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ddos_retry_validated(&self) {
        self.ddos_retry_validated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_geoip_status(
        &self,
        status: crate::implementations::server::limits::GeoIpStatus,
    ) {
        self.geoip_status.store(status as u8, Ordering::Release);
    }

    pub(crate) fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        match self.geoip_status.load(Ordering::Acquire) {
            value if value == crate::implementations::server::limits::GeoIpStatus::Active as u8 => {
                crate::implementations::server::limits::GeoIpStatus::Active
            }
            value if value == crate::implementations::server::limits::GeoIpStatus::Failed as u8 => {
                crate::implementations::server::limits::GeoIpStatus::Failed
            }
            _ => crate::implementations::server::limits::GeoIpStatus::Disabled,
        }
    }

    pub(crate) fn record_geoip_lookup(&self) {
        self.geoip_lookups.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_geoip_blocked(&self) {
        self.geoip_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_geoip_lookup_error(&self) {
        self.geoip_lookup_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_ddos_drop(
        &self,
        reason: crate::implementations::server::ddos::DdosDropReason,
    ) {
        use crate::implementations::server::ddos::DdosDropReason;

        let counter = match reason {
            DdosDropReason::GlobalLimit => &self.ddos_drop_global_limit,
            DdosDropReason::GeoIp => &self.ddos_drop_geoip,
            DdosDropReason::Blacklist => &self.ddos_drop_blacklist,
            DdosDropReason::PerIpLimit => &self.ddos_drop_per_ip_limit,
            DdosDropReason::MalformedInitial => &self.ddos_drop_malformed_initial,
            DdosDropReason::InvalidRetry => &self.ddos_drop_invalid_retry,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        if reason != DdosDropReason::PerIpLimit {
            crate::instrumentation::global().server.rate_limit_hit();
        }
    }

    pub fn record_ingress_datagram(&self, bytes: usize) {
        self.bytes_in.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_in.fetch_add(1, Ordering::Relaxed);
        let global = crate::instrumentation::global();
        global.transport.record_bytes_in(bytes as u64);
        global.transport.record_packet_in();
    }

    pub fn record_egress_datagram(&self, bytes: usize) {
        self.bytes_out.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_out.fetch_add(1, Ordering::Relaxed);
        let global = crate::instrumentation::global();
        global.transport.record_bytes_out(bytes as u64);
        global.transport.record_packet_out();
    }

    pub fn record_uplink_route(&self, route: UplinkRoute) {
        let counter = match route {
            UplinkRoute::Local { .. } => &self.routing_local,
            UplinkRoute::Internet { .. } => &self.routing_internet,
            UplinkRoute::Client { .. } => &self.routing_client,
            UplinkRoute::Broadcast { .. } => &self.routing_broadcast,
            UplinkRoute::Multicast { .. } => &self.routing_multicast,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_uplink_drop(&self, drop: UplinkDrop) {
        let counter = match drop {
            UplinkDrop::MissingSession => &self.routing_drop_missing_session,
            UplinkDrop::MalformedPacket => &self.routing_drop_malformed,
            UplinkDrop::SourceIpSpoofing { .. } => &self.routing_drop_spoofed,
            UplinkDrop::InterClientTraffic { .. } => &self.routing_drop_inter_client,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_routing_outcome(&self, outcome: RoutingOutcome) {
        let counter = match outcome {
            RoutingOutcome::Local => &self.routing_local,
            RoutingOutcome::Unicast => &self.routing_unicast,
            RoutingOutcome::Fanout => &self.routing_fanout,
            RoutingOutcome::Unknown => &self.routing_unknown,
            RoutingOutcome::PacketTooBig => &self.routing_packet_too_big,
            RoutingOutcome::TimeExceeded => &self.routing_time_exceeded,
            RoutingOutcome::Icmpv6 => &self.routing_icmpv6,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_tun_downlink_backpressure_pending(&self, packets: usize, bytes: usize) {
        self.tun_downlink_backpressure_pending_packets.store(packets as u64, Ordering::Relaxed);
        self.tun_downlink_backpressure_pending_bytes.store(bytes as u64, Ordering::Relaxed);
    }

    /// Publish the current lifecycle phase to every health surface.
    pub fn set_lifecycle_phase(&self, phase: LifecyclePhase) {
        self.lifecycle_phase.store(phase as u8, Ordering::Release);
    }

    /// Read the currently published lifecycle phase.
    pub fn lifecycle_phase(&self) -> LifecyclePhase {
        LifecyclePhase::from_u8(self.lifecycle_phase.load(Ordering::Acquire))
    }

    /// Publish the availability of the requested server TUN data plane.
    pub fn set_tun_data_plane_ready(&self, ready: bool) {
        self.tun_data_plane_ready.store(u64::from(ready), Ordering::Release);
    }

    /// Record one terminal server TUN data-plane fault and make health fail closed.
    pub fn record_tun_data_plane_fault(&self) {
        self.tun_data_plane_faults.fetch_add(1, Ordering::Relaxed);
        self.set_tun_data_plane_ready(false);
    }

    /// Publish the process-wide memory-lock result for runtime health probes.
    pub fn set_memory_lock_status(&self, status: qf_memory_lock::MemoryLockStartupStatus) {
        *self.memory_lock_status.write() = status;
    }

    /// Read the process-wide memory-lock result exposed by this runtime.
    pub fn memory_lock_status(&self) -> qf_memory_lock::MemoryLockStartupStatus {
        *self.memory_lock_status.read()
    }

    pub fn record_tun_downlink_backpressure_enqueued(&self) {
        self.tun_downlink_backpressure_enqueued.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one transient TUN-write backpressure event that was absorbed
    /// without failing the data plane (TODO-896).
    pub fn record_tun_write_backpressure(&self) {
        self.tun_write_backpressure_absorbed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tun_downlink_backpressure_retry(&self) {
        self.tun_downlink_backpressure_retried.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tun_downlink_backpressure_drop(&self, reason: TunDownlinkBackpressureDrop) {
        let counter = match reason {
            TunDownlinkBackpressureDrop::QueueCapacity => {
                &self.tun_downlink_backpressure_drop_queue_capacity
            }
            TunDownlinkBackpressureDrop::ByteCapacity => {
                &self.tun_downlink_backpressure_drop_byte_capacity
            }
            TunDownlinkBackpressureDrop::PerTargetCapacity => {
                &self.tun_downlink_backpressure_drop_per_target_capacity
            }
            TunDownlinkBackpressureDrop::Expired => &self.tun_downlink_backpressure_drop_expired,
            TunDownlinkBackpressureDrop::TerminalTransportError => {
                &self.tun_downlink_backpressure_drop_terminal_transport_error
            }
            TunDownlinkBackpressureDrop::Shutdown => &self.tun_downlink_backpressure_drop_shutdown,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bandwidth_decision(
        &self,
        direction: BandwidthDirection,
        decision: BandwidthDecision,
        bytes: usize,
    ) {
        let counter = match (direction, decision) {
            (BandwidthDirection::Uplink, BandwidthDecision::Allowed) => {
                self.bandwidth_uplink_allowed_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                return;
            }
            (BandwidthDirection::Downlink, BandwidthDecision::Allowed) => {
                self.bandwidth_downlink_allowed_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
                return;
            }
            (BandwidthDirection::Uplink, BandwidthDecision::RateLimited) => {
                &self.bandwidth_uplink_rate_limited
            }
            (BandwidthDirection::Downlink, BandwidthDecision::RateLimited) => {
                &self.bandwidth_downlink_rate_limited
            }
            (BandwidthDirection::Uplink, BandwidthDecision::DailyQuotaExceeded) => {
                &self.bandwidth_uplink_daily_quota_exceeded
            }
            (BandwidthDirection::Downlink, BandwidthDecision::DailyQuotaExceeded) => {
                &self.bandwidth_downlink_daily_quota_exceeded
            }
            (BandwidthDirection::Uplink, BandwidthDecision::MonthlyQuotaExceeded) => {
                &self.bandwidth_uplink_monthly_quota_exceeded
            }
            (BandwidthDirection::Downlink, BandwidthDecision::MonthlyQuotaExceeded) => {
                &self.bandwidth_downlink_monthly_quota_exceeded
            }
            (BandwidthDirection::Uplink, BandwidthDecision::ClockUnavailable) => {
                &self.bandwidth_uplink_clock_unavailable
            }
            (BandwidthDirection::Downlink, BandwidthDecision::ClockUnavailable) => {
                &self.bandwidth_downlink_clock_unavailable
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn set_bandwidth_scheduler_active_clients(&self, clients: usize) {
        self.bandwidth_scheduler_active_clients.store(clients as u64, Ordering::Relaxed);
    }

    pub fn record_bandwidth_scheduler_enqueue(&self) {
        self.bandwidth_scheduler_enqueued_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bandwidth_scheduler_delivery(&self, bytes: usize) {
        self.bandwidth_scheduler_delivered_packets.fetch_add(1, Ordering::Relaxed);
        self.bandwidth_scheduler_delivered_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_masque_downlink_response_retry(&self) {
        self.masque_downlink_response_retried.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_masque_downlink_response_drop(
        &self,
        reason: qf_transport_types::MasqueDownlinkQueueReject,
    ) {
        let counter = match reason {
            qf_transport_types::MasqueDownlinkQueueReject::PacketCapacity => {
                &self.masque_downlink_response_drop_packet_capacity
            }
            qf_transport_types::MasqueDownlinkQueueReject::ByteCapacity => {
                &self.masque_downlink_response_drop_byte_capacity
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_masque_downlink_response_terminal_drop(&self, packets: usize) {
        self.masque_downlink_response_drop_terminal_transport_error
            .fetch_add(packets as u64, Ordering::Relaxed);
    }

    pub fn record_masque_downlink_response_shutdown_drop(&self, packets: usize) {
        self.masque_downlink_response_drop_shutdown.fetch_add(packets as u64, Ordering::Relaxed);
    }

    /// Export as JSON for health endpoint.
    pub fn export_health(&self) -> String {
        let geoip_status = self.geoip_status();
        let uptime = self.uptime_secs();
        let memory_lock = self.memory_lock_status();
        let phase = self.lifecycle_phase();
        let health = if let Some(forced) = phase.forced_health() {
            forced
        } else if geoip_status == crate::implementations::server::limits::GeoIpStatus::Failed
            || self.tun_data_plane_ready.load(Ordering::Acquire) == 0
            || memory_lock.is_not_ready()
        {
            "not_ready"
        } else if memory_lock.is_degraded() {
            "degraded"
        } else {
            "ok"
        };
        let enabled = self.blacklist_sync_enabled.load(Ordering::Acquire) != 0;
        let last_success = self.blacklist_sync_last_success_uptime.load(Ordering::Acquire);
        let last_failure = self.blacklist_sync_last_failure_uptime.load(Ordering::Acquire);
        let interval = self.blacklist_sync_interval_secs.load(Ordering::Acquire);
        let stale = enabled
            && (last_success == BLACKLIST_SYNC_TIME_UNKNOWN
                || uptime.saturating_sub(last_success) > interval);
        let status = match self.blacklist_sync_status.load(Ordering::Acquire) {
            BLACKLIST_SYNC_STATUS_PENDING => "pending",
            BLACKLIST_SYNC_STATUS_IN_FLIGHT => "in_flight",
            BLACKLIST_SYNC_STATUS_SUCCEEDED => "succeeded",
            BLACKLIST_SYNC_STATUS_FAILED => "failed",
            BLACKLIST_SYNC_STATUS_CANCELLED => "cancelled",
            BLACKLIST_SYNC_STATUS_SHUTDOWN_EXPIRED => "shutdown_expired",
            _ => "disabled",
        };
        serde_json::json!({
            "status": health,
            "lifecycle": phase.as_str(),
            "version": env!("CARGO_PKG_VERSION"),
            "uptime": uptime,
            "clients": self.clients_active.load(Ordering::Relaxed),
            "geoip_status": geoip_status.as_str(),
            "tun_data_plane_ready": self.tun_data_plane_ready.load(Ordering::Acquire),
            "memory_lock": memory_lock.health_json(),
            "blacklist_sync": {
                "enabled": enabled,
                "status": status,
                "in_flight": self.blacklist_sync_in_flight.load(Ordering::Acquire),
                "active_entries": self.blacklist_sync_active_entries.load(Ordering::Acquire),
                "stale": stale,
                "last_success_age_secs": (last_success != BLACKLIST_SYNC_TIME_UNKNOWN)
                    .then_some(uptime.saturating_sub(last_success)),
                "last_failure_age_secs": (last_failure != BLACKLIST_SYNC_TIME_UNKNOWN)
                    .then_some(uptime.saturating_sub(last_failure)),
            },
        })
        .to_string()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics HTTP server.
mod export;
mod server;
#[cfg(any(test, feature = "rust-tests"))]
pub use server::GlobalMetricsServer;
pub use server::MetricsServer;

#[cfg(test)]
mod tests;
