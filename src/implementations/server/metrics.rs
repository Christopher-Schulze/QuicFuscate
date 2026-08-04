//! Prometheus metrics for QuicFuscate server.
//!
//! Exports metrics in Prometheus text format at /metrics endpoint.

use super::http::{read_request, RequestReadError, MAX_CONCURRENT_CONNECTIONS};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use super::isolation::{UplinkDrop, UplinkRoute};
use super::{BandwidthDecision, BandwidthDirection};

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
    /// Number of terminal server TUN data-plane faults.
    pub tun_data_plane_faults: AtomicU64,

    // Per-session bandwidth and fair-scheduler metrics
    pub bandwidth_uplink_allowed_bytes: AtomicU64,
    pub bandwidth_downlink_allowed_bytes: AtomicU64,
    pub bandwidth_uplink_rate_limited: AtomicU64,
    pub bandwidth_downlink_rate_limited: AtomicU64,
    pub bandwidth_uplink_daily_quota_exceeded: AtomicU64,
    pub bandwidth_downlink_daily_quota_exceeded: AtomicU64,
    pub bandwidth_uplink_monthly_quota_exceeded: AtomicU64,
    pub bandwidth_downlink_monthly_quota_exceeded: AtomicU64,
    pub bandwidth_scheduler_active_clients: AtomicU64,
    pub bandwidth_scheduler_delivered_packets: AtomicU64,
    pub bandwidth_scheduler_delivered_bytes: AtomicU64,

    // Server-generated MASQUE response queue metrics
    pub masque_downlink_response_retried: AtomicU64,
    pub masque_downlink_response_drop_packet_capacity: AtomicU64,
    pub masque_downlink_response_drop_byte_capacity: AtomicU64,
    pub masque_downlink_response_drop_terminal_transport_error: AtomicU64,
    pub masque_downlink_response_drop_shutdown: AtomicU64,
    pub dns_intercept_dropped: AtomicU64,
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
}

impl Metrics {
    /// Create new metrics collector.
    pub fn new() -> Self {
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
            tun_data_plane_faults: AtomicU64::new(0),
            bandwidth_uplink_allowed_bytes: AtomicU64::new(0),
            bandwidth_downlink_allowed_bytes: AtomicU64::new(0),
            bandwidth_uplink_rate_limited: AtomicU64::new(0),
            bandwidth_downlink_rate_limited: AtomicU64::new(0),
            bandwidth_uplink_daily_quota_exceeded: AtomicU64::new(0),
            bandwidth_downlink_daily_quota_exceeded: AtomicU64::new(0),
            bandwidth_uplink_monthly_quota_exceeded: AtomicU64::new(0),
            bandwidth_downlink_monthly_quota_exceeded: AtomicU64::new(0),
            bandwidth_scheduler_active_clients: AtomicU64::new(0),
            bandwidth_scheduler_delivered_packets: AtomicU64::new(0),
            bandwidth_scheduler_delivered_bytes: AtomicU64::new(0),
            masque_downlink_response_retried: AtomicU64::new(0),
            masque_downlink_response_drop_packet_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_byte_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_terminal_transport_error: AtomicU64::new(0),
            masque_downlink_response_drop_shutdown: AtomicU64::new(0),
            dns_intercept_dropped: AtomicU64::new(0),
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
            start_time: std::time::Instant::now(),
        }
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
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

    /// Publish the availability of the requested server TUN data plane.
    pub fn set_tun_data_plane_ready(&self, ready: bool) {
        self.tun_data_plane_ready.store(u64::from(ready), Ordering::Release);
    }

    /// Record one terminal server TUN data-plane fault and make health fail closed.
    pub fn record_tun_data_plane_fault(&self) {
        self.tun_data_plane_faults.fetch_add(1, Ordering::Relaxed);
        self.set_tun_data_plane_ready(false);
    }

    pub fn record_tun_downlink_backpressure_enqueued(&self) {
        self.tun_downlink_backpressure_enqueued.fetch_add(1, Ordering::Relaxed);
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
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.record_rate_limited();
    }

    pub fn set_bandwidth_scheduler_active_clients(&self, clients: usize) {
        self.bandwidth_scheduler_active_clients.store(clients as u64, Ordering::Relaxed);
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
        reason: crate::core::MasqueDownlinkQueueReject,
    ) {
        let counter = match reason {
            crate::core::MasqueDownlinkQueueReject::PacketCapacity => {
                &self.masque_downlink_response_drop_packet_capacity
            }
            crate::core::MasqueDownlinkQueueReject::ByteCapacity => {
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

    /// Export as Prometheus text format.
    pub fn export(&self) -> String {
        let mut out = String::with_capacity(16 * 1024);
        macro_rules! write_metric {
            ($($arg:tt)*) => {{
                let _ = write!(out, $($arg)*);
            }};
        }

        // Server info
        out.push_str("# HELP quicfuscate_up Server is up\n");
        out.push_str("# TYPE quicfuscate_up gauge\n");
        out.push_str("quicfuscate_up 1\n\n");

        out.push_str("# HELP quicfuscate_uptime_seconds Server uptime\n");
        out.push_str("# TYPE quicfuscate_uptime_seconds counter\n");
        write_metric!("quicfuscate_uptime_seconds {}\n\n", self.uptime_secs());

        // Clients
        out.push_str("# HELP quicfuscate_clients_active Current active clients\n");
        out.push_str("# TYPE quicfuscate_clients_active gauge\n");
        write_metric!(
            "quicfuscate_clients_active {}\n\n",
            self.clients_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_clients_total Total clients connected\n");
        out.push_str("# TYPE quicfuscate_clients_total counter\n");
        write_metric!(
            "quicfuscate_clients_total {}\n\n",
            self.clients_total.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_accepted Accepted connections\n");
        out.push_str("# TYPE quicfuscate_connections_accepted counter\n");
        write_metric!(
            "quicfuscate_connections_accepted {}\n\n",
            self.connections_accepted.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_rejected Rejected connections\n");
        out.push_str("# TYPE quicfuscate_connections_rejected counter\n");
        write_metric!(
            "quicfuscate_connections_rejected {}\n\n",
            self.connections_rejected.load(Ordering::Relaxed)
        );

        // Traffic
        out.push_str("# HELP quicfuscate_bytes_in_total Total bytes received\n");
        out.push_str("# TYPE quicfuscate_bytes_in_total counter\n");
        write_metric!("quicfuscate_bytes_in_total {}\n\n", self.bytes_in.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_bytes_out_total Total bytes sent\n");
        out.push_str("# TYPE quicfuscate_bytes_out_total counter\n");
        write_metric!("quicfuscate_bytes_out_total {}\n\n", self.bytes_out.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_packets_in_total Total packets received\n");
        out.push_str("# TYPE quicfuscate_packets_in_total counter\n");
        write_metric!(
            "quicfuscate_packets_in_total {}\n\n",
            self.packets_in.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_packets_out_total Total packets sent\n");
        out.push_str("# TYPE quicfuscate_packets_out_total counter\n");
        write_metric!(
            "quicfuscate_packets_out_total {}\n\n",
            self.packets_out.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_routing_packets_total Packets by typed routing outcome\n");
        out.push_str("# TYPE quicfuscate_routing_packets_total counter\n");
        for (outcome, value) in [
            ("internet", self.routing_internet.load(Ordering::Relaxed)),
            ("client", self.routing_client.load(Ordering::Relaxed)),
            ("broadcast", self.routing_broadcast.load(Ordering::Relaxed)),
            ("multicast", self.routing_multicast.load(Ordering::Relaxed)),
            ("drop_missing_session", self.routing_drop_missing_session.load(Ordering::Relaxed)),
            ("drop_malformed", self.routing_drop_malformed.load(Ordering::Relaxed)),
            ("drop_spoofed", self.routing_drop_spoofed.load(Ordering::Relaxed)),
            ("drop_inter_client", self.routing_drop_inter_client.load(Ordering::Relaxed)),
            ("local", self.routing_local.load(Ordering::Relaxed)),
            ("unicast", self.routing_unicast.load(Ordering::Relaxed)),
            ("fanout", self.routing_fanout.load(Ordering::Relaxed)),
            ("unknown", self.routing_unknown.load(Ordering::Relaxed)),
            ("packet_too_big", self.routing_packet_too_big.load(Ordering::Relaxed)),
            ("time_exceeded", self.routing_time_exceeded.load(Ordering::Relaxed)),
            ("icmpv6", self.routing_icmpv6.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_routing_packets_total{{outcome=\"{outcome}\"}} {value}\n");
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_packets Current packets retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_packets gauge\n");
        write_metric!(
            "quicfuscate_tun_downlink_backpressure_pending_packets {}\n\n",
            self.tun_downlink_backpressure_pending_packets.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_bytes Current bytes retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_bytes gauge\n");
        write_metric!(
            "quicfuscate_tun_downlink_backpressure_pending_bytes {}\n\n",
            self.tun_downlink_backpressure_pending_bytes.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_events_total Server TUN downlink retry queue events\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_events_total counter\n");
        for (event, value) in [
            ("enqueued", self.tun_downlink_backpressure_enqueued.load(Ordering::Relaxed)),
            ("retried", self.tun_downlink_backpressure_retried.load(Ordering::Relaxed)),
            (
                "drop_queue_capacity",
                self.tun_downlink_backpressure_drop_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_byte_capacity",
                self.tun_downlink_backpressure_drop_byte_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_per_target_capacity",
                self.tun_downlink_backpressure_drop_per_target_capacity.load(Ordering::Relaxed),
            ),
            ("drop_expired", self.tun_downlink_backpressure_drop_expired.load(Ordering::Relaxed)),
            (
                "drop_terminal_transport_error",
                self.tun_downlink_backpressure_drop_terminal_transport_error
                    .load(Ordering::Relaxed),
            ),
            ("drop_shutdown", self.tun_downlink_backpressure_drop_shutdown.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_tun_downlink_backpressure_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_tun_data_plane_ready Whether the requested server TUN data plane is available\n");
        out.push_str("# TYPE quicfuscate_tun_data_plane_ready gauge\n");
        write_metric!(
            "quicfuscate_tun_data_plane_ready {}\n\n",
            self.tun_data_plane_ready.load(Ordering::Acquire)
        );
        out.push_str("# HELP quicfuscate_tun_data_plane_faults_total Terminal server TUN data-plane faults\n");
        out.push_str("# TYPE quicfuscate_tun_data_plane_faults_total counter\n");
        write_metric!(
            "quicfuscate_tun_data_plane_faults_total {}\n\n",
            self.tun_data_plane_faults.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_bandwidth_allowed_bytes_total Bytes admitted by per-session policy\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_allowed_bytes_total counter\n");
        for (direction, value) in [
            ("uplink", self.bandwidth_uplink_allowed_bytes.load(Ordering::Relaxed)),
            ("downlink", self.bandwidth_downlink_allowed_bytes.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_allowed_bytes_total{{direction=\"{direction}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_bandwidth_denials_total Per-session bandwidth denials by typed outcome\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_denials_total counter\n");
        for (direction, outcome, value) in [
            ("uplink", "rate_limited", self.bandwidth_uplink_rate_limited.load(Ordering::Relaxed)),
            (
                "downlink",
                "rate_limited",
                self.bandwidth_downlink_rate_limited.load(Ordering::Relaxed),
            ),
            (
                "uplink",
                "daily_quota_exceeded",
                self.bandwidth_uplink_daily_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "downlink",
                "daily_quota_exceeded",
                self.bandwidth_downlink_daily_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "uplink",
                "monthly_quota_exceeded",
                self.bandwidth_uplink_monthly_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "downlink",
                "monthly_quota_exceeded",
                self.bandwidth_downlink_monthly_quota_exceeded.load(Ordering::Relaxed),
            ),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_denials_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_bandwidth_scheduler_active_clients Current clients in the bounded DRR queue\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_scheduler_active_clients gauge\n");
        write_metric!(
            "quicfuscate_bandwidth_scheduler_active_clients {}\n\n",
            self.bandwidth_scheduler_active_clients.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_bandwidth_scheduler_delivered_total DRR deliveries by unit\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_scheduler_delivered_total counter\n");
        for (unit, value) in [
            ("packets", self.bandwidth_scheduler_delivered_packets.load(Ordering::Relaxed)),
            ("bytes", self.bandwidth_scheduler_delivered_bytes.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_scheduler_delivered_total{{unit=\"{unit}\"}} {value}\n"
            );
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_masque_downlink_response_events_total Server-generated MASQUE response queue events\n");
        out.push_str("# TYPE quicfuscate_masque_downlink_response_events_total counter\n");
        for (event, value) in [
            ("retried", self.masque_downlink_response_retried.load(Ordering::Relaxed)),
            (
                "drop_packet_capacity",
                self.masque_downlink_response_drop_packet_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_byte_capacity",
                self.masque_downlink_response_drop_byte_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_terminal_transport_error",
                self.masque_downlink_response_drop_terminal_transport_error.load(Ordering::Relaxed),
            ),
            ("drop_shutdown", self.masque_downlink_response_drop_shutdown.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_masque_downlink_response_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');

        out.push_str(
            "# HELP quicfuscate_dns_intercept_dropped_total DNS queries dropped before blocking upstream resolution\n",
        );
        out.push_str("# TYPE quicfuscate_dns_intercept_dropped_total counter\n");
        write_metric!(
            "quicfuscate_dns_intercept_dropped_total {}\n\n",
            self.dns_intercept_dropped.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_dns_intercept_worker_events_total DNS intercept worker lifecycle and terminal outcomes\n",
        );
        out.push_str("# TYPE quicfuscate_dns_intercept_worker_events_total counter\n");
        for (event, value) in [
            DnsInterceptWorkerEvent::ClosedBeforeSpawn,
            DnsInterceptWorkerEvent::ResponseQueued,
            DnsInterceptWorkerEvent::EmptyResponse,
            DnsInterceptWorkerEvent::ResponseBuildFailed,
            DnsInterceptWorkerEvent::LatePublication,
            DnsInterceptWorkerEvent::QueueRejectedPacketCapacity,
            DnsInterceptWorkerEvent::QueueRejectedByteCapacity,
            DnsInterceptWorkerEvent::Panic,
            DnsInterceptWorkerEvent::QueuedCancellation,
            DnsInterceptWorkerEvent::StartedCancellation,
            DnsInterceptWorkerEvent::ShutdownExpired,
            DnsInterceptWorkerEvent::JoinError,
        ]
        .into_iter()
        .map(|event| {
            let value = match event {
                DnsInterceptWorkerEvent::ClosedBeforeSpawn => {
                    self.dns_intercept_worker_closed_before_spawn.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ResponseQueued => {
                    self.dns_intercept_worker_response_queued.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::EmptyResponse => {
                    self.dns_intercept_worker_empty_response.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ResponseBuildFailed => {
                    self.dns_intercept_worker_response_build_failed.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::LatePublication => {
                    self.dns_intercept_worker_late_publication.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueueRejectedPacketCapacity => {
                    self.dns_intercept_worker_queue_rejected_packet_capacity.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueueRejectedByteCapacity => {
                    self.dns_intercept_worker_queue_rejected_byte_capacity.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::Panic => {
                    self.dns_intercept_worker_panic.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueuedCancellation => {
                    self.dns_intercept_worker_queued_cancellation.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::StartedCancellation => {
                    self.dns_intercept_worker_started_cancellation.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ShutdownExpired => {
                    self.dns_intercept_worker_shutdown_expired.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::JoinError => {
                    self.dns_intercept_worker_join_error.load(Ordering::Relaxed)
                }
            };
            (event.as_str(), value)
        }) {
            write_metric!(
                "quicfuscate_dns_intercept_worker_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_client_fanout_dropped_total Broadcast/multicast packets dropped before fan-out queue admission\n",
        );
        out.push_str("# TYPE quicfuscate_client_fanout_dropped_total counter\n");
        write_metric!(
            "quicfuscate_client_fanout_dropped_total {}\n\n",
            self.client_fanout_dropped.load(Ordering::Relaxed)
        );

        // Stealth
        out.push_str("# HELP quicfuscate_stealth_http3_active Clients using HTTP/3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_http3_active gauge\n");
        write_metric!(
            "quicfuscate_stealth_http3_active {}\n\n",
            self.stealth_http3_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_stealth_tls13_active Clients using TLS 1.3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_tls13_active gauge\n");
        write_metric!(
            "quicfuscate_stealth_tls13_active {}\n\n",
            self.stealth_tls13_active.load(Ordering::Relaxed)
        );

        // FEC
        out.push_str(
            "# HELP quicfuscate_fec_packets_encoded Process-wide source plus repair datagrams actually written by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_encoded counter\n");
        write_metric!(
            "quicfuscate_fec_packets_encoded {}\n\n",
            self.fec_packets_encoded.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_fec_packets_decoded Process-wide original plus recovered source packets delivered by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_decoded counter\n");
        write_metric!(
            "quicfuscate_fec_packets_decoded {}\n\n",
            self.fec_packets_decoded.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_fec_packets_recovered Process-wide source packets reconstructed from repair data\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_recovered counter\n");
        write_metric!(
            "quicfuscate_fec_packets_recovered {}\n\n",
            self.fec_packets_recovered.load(Ordering::Relaxed)
        );

        // Allocation and pool pressure
        out.push_str(
            "# HELP quicfuscate_mem_pool_allocations_total Process-wide memory-pool allocation outcomes\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_allocations_total counter\n");
        for (source, value) in [
            ("thread_local", crate::telemetry::MEM_POOL_HITS_TLS.get()),
            ("shared_queue", crate::telemetry::MEM_POOL_HITS_QUEUE.get()),
            ("grow", crate::telemetry::MEM_POOL_ALLOC_GROW.get()),
            ("ephemeral", crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.get()),
        ] {
            write_metric!(
                "quicfuscate_mem_pool_allocations_total{{source=\"{source}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_body_pool_allocations_total Process-wide HTTP body-pool allocations\n",
        );
        out.push_str("# TYPE quicfuscate_body_pool_allocations_total counter\n");
        write_metric!(
            "quicfuscate_body_pool_allocations_total {}\n\n",
            crate::telemetry::BODY_POOL_ALLOCS.get()
        );
        out.push_str(
            "# HELP quicfuscate_mem_pool_in_use Current process-wide memory-pool blocks in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_in_use gauge\n");
        write_metric!(
            "quicfuscate_mem_pool_in_use {}\n\n",
            crate::telemetry::MEM_POOL_IN_USE.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_mem_pool_usage_bytes Current process-wide memory-pool bytes in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_usage_bytes gauge\n");
        write_metric!(
            "quicfuscate_mem_pool_usage_bytes {}\n\n",
            crate::telemetry::MEM_POOL_USAGE_BYTES.load(Ordering::Relaxed)
        );

        // Errors
        out.push_str("# HELP quicfuscate_auth_attempts_total QKey authentication attempts\n");
        out.push_str("# TYPE quicfuscate_auth_attempts_total counter\n");
        write_metric!(
            "quicfuscate_auth_attempts_total {}\n\n",
            self.auth_attempts.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_auth_succeeded_total Successful QKey authentications\n");
        out.push_str("# TYPE quicfuscate_auth_succeeded_total counter\n");
        write_metric!(
            "quicfuscate_auth_succeeded_total {}\n\n",
            self.auth_succeeded.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_auth_failed_total Terminal QKey authentication failures\n",
        );
        out.push_str("# TYPE quicfuscate_auth_failed_total counter\n");
        write_metric!(
            "quicfuscate_auth_failed_total {}\n\n",
            self.auth_failed.load(Ordering::Relaxed)
        );
        for (name, help, value) in [
            (
                "backoff_rejected",
                "QKey attempts rejected by exponential backoff",
                self.auth_backoff_rejected.load(Ordering::Relaxed),
            ),
            (
                "blocked_rejected",
                "QKey attempts rejected by the explicit blocked state",
                self.auth_blocked_rejected.load(Ordering::Relaxed),
            ),
            (
                "capacity_rejected",
                "QKey attempts rejected by bounded state capacity",
                self.auth_capacity_rejected.load(Ordering::Relaxed),
            ),
            (
                "abandoned",
                "QKey attempts abandoned before a credential result",
                self.auth_abandoned.load(Ordering::Relaxed),
            ),
        ] {
            write_metric!("# HELP quicfuscate_auth_{name}_total {help}\n");
            write_metric!("# TYPE quicfuscate_auth_{name}_total counter\n");
            write_metric!("quicfuscate_auth_{name}_total {value}\n\n");
        }
        out.push_str("# HELP quicfuscate_auth_state_tracked_ips Current QKey auth IP states\n");
        out.push_str("# TYPE quicfuscate_auth_state_tracked_ips gauge\n");
        write_metric!(
            "quicfuscate_auth_state_tracked_ips {}\n\n",
            self.auth_state_tracked_ips.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_auth_state_pruned_total Idle QKey auth IP states pruned\n",
        );
        out.push_str("# TYPE quicfuscate_auth_state_pruned_total counter\n");
        write_metric!(
            "quicfuscate_auth_state_pruned_total {}\n\n",
            self.auth_state_pruned.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_revocation_pruned_total Expired revoked QKey records pruned\n",
        );
        out.push_str("# TYPE quicfuscate_revocation_pruned_total counter\n");
        write_metric!(
            "quicfuscate_revocation_pruned_total {}\n\n",
            self.revocation_pruned.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_rate_limited_total Rate-limited events\n");
        out.push_str("# TYPE quicfuscate_rate_limited_total counter\n");
        write_metric!(
            "quicfuscate_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        );
        out.push_str("\n# HELP quicfuscate_ddos_active Enhanced DDoS admission state\n");
        out.push_str("# TYPE quicfuscate_ddos_active gauge\n");
        write_metric!("quicfuscate_ddos_active {}\n", self.ddos_active.load(Ordering::Relaxed));
        out.push_str("# HELP quicfuscate_ddos_current_pps Latest interval-correct accepted PPS\n");
        out.push_str("# TYPE quicfuscate_ddos_current_pps gauge\n");
        write_metric!(
            "quicfuscate_ddos_current_pps {}\n",
            self.ddos_current_pps.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_ddos_transitions_total Enhanced admission transitions\n");
        out.push_str("# TYPE quicfuscate_ddos_transitions_total counter\n");
        for (transition, value) in [
            ("activated", self.ddos_activations.load(Ordering::Relaxed)),
            ("cleared", self.ddos_clears.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_ddos_transitions_total{{transition=\"{transition}\"}} {value}\n"
            );
        }
        out.push_str("# HELP quicfuscate_ddos_retry_total QUIC Retry outcomes\n");
        out.push_str("# TYPE quicfuscate_ddos_retry_total counter\n");
        for (outcome, value) in [
            ("issued", self.ddos_retry_issued.load(Ordering::Relaxed)),
            ("validated", self.ddos_retry_validated.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_ddos_retry_total{{outcome=\"{outcome}\"}} {value}\n");
        }
        out.push_str("# HELP quicfuscate_ddos_drops_total DDoS admission drops by cause\n");
        out.push_str("# TYPE quicfuscate_ddos_drops_total counter\n");
        for (reason, value) in [
            ("global_limit", self.ddos_drop_global_limit.load(Ordering::Relaxed)),
            ("geoip", self.ddos_drop_geoip.load(Ordering::Relaxed)),
            ("blacklist", self.ddos_drop_blacklist.load(Ordering::Relaxed)),
            ("per_ip_limit", self.ddos_drop_per_ip_limit.load(Ordering::Relaxed)),
            ("malformed_initial", self.ddos_drop_malformed_initial.load(Ordering::Relaxed)),
            ("invalid_retry", self.ddos_drop_invalid_retry.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_ddos_drops_total{{reason=\"{reason}\"}} {value}\n");
        }
        out.push_str("# HELP quicfuscate_geoip_activation Actual GeoIP policy activation state\n");
        out.push_str("# TYPE quicfuscate_geoip_activation gauge\n");
        let geoip_status = self.geoip_status();
        for status in [
            crate::implementations::server::limits::GeoIpStatus::Disabled,
            crate::implementations::server::limits::GeoIpStatus::Active,
            crate::implementations::server::limits::GeoIpStatus::Failed,
        ] {
            let value = u8::from(status == geoip_status);
            write_metric!(
                "quicfuscate_geoip_activation{{state=\"{}\"}} {value}\n",
                status.as_str()
            );
        }
        out.push_str("# HELP quicfuscate_geoip_lookups_total Active GeoIP source lookups\n");
        out.push_str("# TYPE quicfuscate_geoip_lookups_total counter\n");
        write_metric!(
            "quicfuscate_geoip_lookups_total {}\n",
            self.geoip_lookups.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_geoip_blocked_total Sources blocked by GeoIP country policy\n",
        );
        out.push_str("# TYPE quicfuscate_geoip_blocked_total counter\n");
        write_metric!(
            "quicfuscate_geoip_blocked_total {}\n",
            self.geoip_blocked.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_geoip_lookup_errors_total GeoIP lookup/decode failures dropped fail-closed\n");
        out.push_str("# TYPE quicfuscate_geoip_lookup_errors_total counter\n");
        write_metric!(
            "quicfuscate_geoip_lookup_errors_total {}\n",
            self.geoip_lookup_errors.load(Ordering::Relaxed)
        );
        let audit = crate::audit::stats();
        out.push_str(
            "\n# HELP quicfuscate_audit_dropped_events_total Audit events rejected by the bounded writer queue\n",
        );
        out.push_str("# TYPE quicfuscate_audit_dropped_events_total counter\n");
        write_metric!("quicfuscate_audit_dropped_events_total {}\n\n", audit.dropped_events);
        out.push_str(
            "# HELP quicfuscate_audit_persistence_errors_total Audit writer or durability-checkpoint failures\n",
        );
        out.push_str("# TYPE quicfuscate_audit_persistence_errors_total counter\n");
        write_metric!("quicfuscate_audit_persistence_errors_total {}\n", audit.persistence_errors);

        out
    }

    /// Export as JSON for health endpoint.
    pub fn export_health(&self) -> String {
        let status = self.geoip_status();
        let health = if status == crate::implementations::server::limits::GeoIpStatus::Failed
            || self.tun_data_plane_ready.load(Ordering::Acquire) == 0
        {
            "not_ready"
        } else {
            "ok"
        };
        format!(
            r#"{{"status":"{}","version":"{}","uptime":{},"clients":{},"geoip_status":"{}","tun_data_plane_ready":{}}}"#,
            health,
            env!("CARGO_PKG_VERSION"),
            self.uptime_secs(),
            self.clients_active.load(Ordering::Relaxed),
            status.as_str(),
            self.tun_data_plane_ready.load(Ordering::Acquire)
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_request_line(request: &[u8]) -> Option<(&str, &str)> {
    let line = request.split(|byte| *byte == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.split_whitespace();
    Some((parts.next()?, parts.next()?))
}

fn route_path(path: &str) -> &str {
    path.split('?').next().unwrap_or(path)
}

fn bad_request_response() -> String {
    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn too_large_response() -> String {
    "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn not_found_response() -> String {
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
}

fn metrics_body_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
}

fn health_body_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    )
}

fn metrics_response(request: &[u8], metrics: &Metrics) -> String {
    let Some((method, path)) = parse_request_line(request) else {
        return bad_request_response();
    };

    match (method, route_path(path)) {
        ("GET", "/metrics") => metrics_body_response(&metrics.export()),
        ("GET", "/health") => health_body_response(&metrics.export_health()),
        _ => not_found_response(),
    }
}

fn global_metrics_response(request: &[u8]) -> String {
    let Some((method, path)) = parse_request_line(request) else {
        return bad_request_response();
    };
    let global = crate::instrumentation::global();

    match (method, route_path(path)) {
        ("GET", "/metrics") => metrics_body_response(&global.export_prometheus()),
        ("GET", "/health") => health_body_response(&global.export_health()),
        _ => not_found_response(),
    }
}

async fn handle_metrics_connection(mut socket: TcpStream, metrics: Arc<Metrics>) {
    let response = match read_request(&mut socket).await {
        Ok(Some(request)) => metrics_response(&request, &metrics),
        Ok(None) => return,
        Err(RequestReadError::Incomplete) => bad_request_response(),
        Err(RequestReadError::TooLarge) => too_large_response(),
        Err(RequestReadError::TimedOut) => {
            log::debug!("Metrics server request read timed out");
            return;
        }
        Err(RequestReadError::Io(error)) => {
            log::debug!("Metrics server request read failed: {}", error);
            return;
        }
    };

    if let Err(error) = socket.write_all(response.as_bytes()).await {
        log::debug!("Metrics response write failed: {}", error);
    }
    if let Err(error) = socket.shutdown().await {
        log::debug!("Metrics socket shutdown failed: {}", error);
    }
}

#[cfg(any(test, feature = "rust-tests"))]
async fn handle_global_metrics_connection(mut socket: TcpStream) {
    let response = match read_request(&mut socket).await {
        Ok(Some(request)) => global_metrics_response(&request),
        Ok(None) => return,
        Err(RequestReadError::Incomplete) => bad_request_response(),
        Err(RequestReadError::TooLarge) => too_large_response(),
        Err(RequestReadError::TimedOut) => {
            log::debug!("Global metrics server request read timed out");
            return;
        }
        Err(RequestReadError::Io(error)) => {
            log::debug!("Global metrics server request read failed: {}", error);
            return;
        }
    };

    if let Err(error) = socket.write_all(response.as_bytes()).await {
        log::debug!("Global metrics response write failed: {}", error);
    }
    if let Err(error) = socket.shutdown().await {
        log::debug!("Global metrics socket shutdown failed: {}", error);
    }
}

/// Metrics HTTP server.
pub struct MetricsServer {
    addr: std::net::SocketAddr,
    metrics: Arc<Metrics>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsServer {
    /// Create a new metrics server.
    pub fn new(port: u16, metrics: Arc<Metrics>) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            metrics,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn run_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((socket, _addr))) => {
                    let permit = match connection_slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    let metrics = Arc::clone(&self.metrics);
                    tokio::spawn(async move {
                        handle_metrics_connection(socket, metrics).await;
                        drop(permit);
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        Ok(())
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Metrics server listening on http://{}", self.addr);

        let result = self.run_listener(listener).await;
        log::info!("Metrics server stopped");
        result
    }
}

/// Metrics HTTP server using global instrumentation.
///
/// This server reads from the global metrics registry at `crate::instrumentation::global()`.
#[cfg(any(test, feature = "rust-tests"))]
pub struct GlobalMetricsServer {
    addr: std::net::SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(any(test, feature = "rust-tests"))]
impl GlobalMetricsServer {
    /// Create a new global metrics server.
    pub fn new(port: u16) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn run_listener(&self, listener: TcpListener) -> std::io::Result<()> {
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((socket, _addr))) => {
                    let permit = match connection_slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        handle_global_metrics_connection(socket).await;
                        drop(permit);
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Global metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        Ok(())
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Global metrics server listening on http://{}", self.addr);

        let result = self.run_listener(listener).await;
        log::info!("Global metrics server stopped");
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn metrics_server_serves_next_request_while_first_reader_is_silent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server =
            MetricsServer { addr, metrics: Arc::new(Metrics::new()), shutdown: shutdown.clone() };
        let server_task = tokio::spawn(async move { server.run_listener(listener).await });

        let stalled = TcpStream::connect(addr).await.unwrap();
        let mut valid = TcpStream::connect(addr).await.unwrap();
        valid.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), valid.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        drop(stalled);
        shutdown.store(true, Ordering::SeqCst);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn global_metrics_server_uses_the_same_bounded_connection_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server = GlobalMetricsServer { addr, shutdown: shutdown.clone() };
        let server_task = tokio::spawn(async move { server.run_listener(listener).await });

        let stalled = TcpStream::connect(addr).await.unwrap();
        let mut valid = TcpStream::connect(addr).await.unwrap();
        valid.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), valid.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();

        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        drop(stalled);
        shutdown.store(true, Ordering::SeqCst);
        server_task.await.unwrap().unwrap();
    }

    #[test]
    fn test_metrics_export() {
        let metrics = Metrics::new();
        metrics.record_connection_accepted();
        metrics.record_connection_rejected();
        metrics.record_ingress_datagram(1_000_000);
        metrics.clients_active.store(42, Ordering::Relaxed);
        metrics.record_uplink_route(UplinkRoute::Internet {
            source: "10.8.0.2".parse().unwrap(),
            destination: "1.1.1.1".parse().unwrap(),
        });
        metrics.record_uplink_drop(UplinkDrop::MalformedPacket);

        let output = metrics.export();
        assert!(output.contains("quicfuscate_up 1"));
        assert!(output.contains("quicfuscate_clients_active 42"));
        assert!(output.contains("quicfuscate_connections_accepted 1"));
        assert!(output.contains("quicfuscate_connections_rejected 1"));
        assert!(output.contains("quicfuscate_bytes_in_total 1000000"));
        assert!(output.contains("quicfuscate_routing_packets_total{outcome=\"internet\"} 1"));
        assert!(output.contains("quicfuscate_routing_packets_total{outcome=\"drop_malformed\"} 1"));
        assert!(output.contains("quicfuscate_audit_dropped_events_total"));
        assert!(output.contains("quicfuscate_audit_persistence_errors_total"));
    }

    #[test]
    fn tun_downlink_backpressure_metrics_expose_depth_and_terminal_cause() {
        let metrics = Metrics::new();
        metrics.set_tun_downlink_backpressure_pending(3, 1_024);
        metrics.record_tun_downlink_backpressure_enqueued();
        metrics.record_tun_downlink_backpressure_retry();
        metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::ByteCapacity);
        metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);

        let output = metrics.export();

        assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_packets 3"));
        assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_bytes 1024"));
        assert!(output
            .contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 1"));
        assert!(output
            .contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"retried\"} 1"));
        assert!(output.contains(
            "quicfuscate_tun_downlink_backpressure_events_total{event=\"drop_byte_capacity\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_tun_downlink_backpressure_events_total{event=\"drop_expired\"} 1"
        ));
    }

    #[test]
    fn tun_data_plane_faults_fail_health_and_are_exported() {
        let metrics = Metrics::new();
        metrics.record_tun_data_plane_fault();

        let output = metrics.export();
        assert!(output.contains("quicfuscate_tun_data_plane_ready 0"));
        assert!(output.contains("quicfuscate_tun_data_plane_faults_total 1"));

        let health = metrics.export_health();
        assert!(health.contains("\"status\":\"not_ready\""));
        assert!(health.contains("\"tun_data_plane_ready\":0"));
    }

    #[test]
    fn bandwidth_metrics_expose_direction_outcome_and_scheduler_state() {
        let metrics = Metrics::new();
        metrics.record_bandwidth_decision(
            BandwidthDirection::Uplink,
            BandwidthDecision::Allowed,
            1_250,
        );
        metrics.record_bandwidth_decision(
            BandwidthDirection::Downlink,
            BandwidthDecision::RateLimited,
            500,
        );
        metrics.record_bandwidth_decision(
            BandwidthDirection::Uplink,
            BandwidthDecision::DailyQuotaExceeded,
            500,
        );
        metrics.record_bandwidth_decision(
            BandwidthDirection::Downlink,
            BandwidthDecision::MonthlyQuotaExceeded,
            500,
        );
        metrics.set_bandwidth_scheduler_active_clients(3);
        metrics.record_bandwidth_scheduler_delivery(1_200);

        let output = metrics.export();
        assert!(
            output.contains("quicfuscate_bandwidth_allowed_bytes_total{direction=\"uplink\"} 1250")
        );
        assert!(output.contains(
            "quicfuscate_bandwidth_denials_total{direction=\"downlink\",outcome=\"rate_limited\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_bandwidth_denials_total{direction=\"uplink\",outcome=\"daily_quota_exceeded\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_bandwidth_denials_total{direction=\"downlink\",outcome=\"monthly_quota_exceeded\"} 1"
        ));
        assert!(output.contains("quicfuscate_bandwidth_scheduler_active_clients 3"));
        assert!(
            output.contains("quicfuscate_bandwidth_scheduler_delivered_total{unit=\"packets\"} 1")
        );
        assert!(
            output.contains("quicfuscate_bandwidth_scheduler_delivered_total{unit=\"bytes\"} 1200")
        );
    }

    #[test]
    fn masque_downlink_response_metrics_expose_retry_and_terminal_causes() {
        let metrics = Metrics::new();
        metrics.record_masque_downlink_response_retry();
        metrics.record_masque_downlink_response_drop(
            crate::core::MasqueDownlinkQueueReject::PacketCapacity,
        );
        metrics.record_masque_downlink_response_drop(
            crate::core::MasqueDownlinkQueueReject::ByteCapacity,
        );
        metrics.record_masque_downlink_response_terminal_drop(2);
        metrics.record_masque_downlink_response_shutdown_drop(3);

        let output = metrics.export();

        assert!(output
            .contains("quicfuscate_masque_downlink_response_events_total{event=\"retried\"} 1"));
        assert!(output.contains(
            "quicfuscate_masque_downlink_response_events_total{event=\"drop_packet_capacity\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_masque_downlink_response_events_total{event=\"drop_byte_capacity\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_masque_downlink_response_events_total{event=\"drop_terminal_transport_error\"} 2"
        ));
        assert!(output.contains(
            "quicfuscate_masque_downlink_response_events_total{event=\"drop_shutdown\"} 3"
        ));
    }

    #[test]
    fn dns_intercept_drop_metric_is_exported_and_rate_limited() {
        let metrics = Metrics::new();
        metrics.record_dns_intercept_drop();

        let output = metrics.export();

        assert!(output.contains("quicfuscate_dns_intercept_dropped_total 1"));
        assert_eq!(metrics.dns_intercept_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dns_intercept_worker_events_are_exported_without_rate_limit_side_effects() {
        let metrics = Metrics::new();
        metrics.record_dns_intercept_worker_event(DnsInterceptWorkerEvent::QueuedCancellation);
        metrics.record_dns_intercept_worker_event(DnsInterceptWorkerEvent::ShutdownExpired);
        metrics
            .record_dns_intercept_worker_event(DnsInterceptWorkerEvent::QueueRejectedByteCapacity);

        let output = metrics.export();

        assert!(output.contains(
            "quicfuscate_dns_intercept_worker_events_total{event=\"queued_cancellation\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_dns_intercept_worker_events_total{event=\"shutdown_expired\"} 1"
        ));
        assert!(output.contains(
            "quicfuscate_dns_intercept_worker_events_total{event=\"queue_rejected_byte_capacity\"} 1"
        ));
        assert_eq!(metrics.rate_limited.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn client_fanout_drop_metric_is_exported() {
        let metrics = Metrics::new();
        metrics.record_client_fanout_drop();

        let output = metrics.export();

        assert!(output.contains("quicfuscate_client_fanout_dropped_total 1"));
        assert_eq!(metrics.client_fanout_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn fec_metrics_project_real_process_wire_producers() {
        let metrics = Metrics::new();
        let emitted_before = metrics.fec_packets_encoded.load(Ordering::Relaxed);
        let decoded_before = metrics.fec_packets_decoded.load(Ordering::Relaxed);
        let recovered_before = metrics.fec_packets_recovered.load(Ordering::Relaxed);

        crate::telemetry::fec_observe_wire_send(true, 100, 100);
        crate::telemetry::fec_observe_wire_send(false, 0, 132);
        crate::telemetry::fec_observe_wire_receive(false, 0, 132, 2, 2, 180);

        assert!(metrics.fec_packets_encoded.load(Ordering::Relaxed) >= emitted_before + 2);
        assert!(metrics.fec_packets_decoded.load(Ordering::Relaxed) >= decoded_before + 2);
        assert!(metrics.fec_packets_recovered.load(Ordering::Relaxed) >= recovered_before + 2);
    }

    #[test]
    fn allocation_metrics_project_real_process_producers() {
        let metrics = Metrics::new();
        let tls_before = crate::telemetry::MEM_POOL_HITS_TLS.get();
        let ephemeral_before = crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.get();
        let body_before = crate::telemetry::BODY_POOL_ALLOCS.get();

        crate::telemetry::MEM_POOL_HITS_TLS.inc();
        crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
        crate::telemetry::BODY_POOL_ALLOCS.inc();

        let output = metrics.export();
        let exported_value = |metric: &str| {
            output
                .lines()
                .find_map(|line| line.strip_prefix(metric))
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or_default()
        };
        assert!(
            exported_value("quicfuscate_mem_pool_allocations_total{source=\"thread_local\"}")
                > tls_before
        );
        assert!(
            exported_value("quicfuscate_mem_pool_allocations_total{source=\"ephemeral\"}")
                > ephemeral_before
        );
        assert!(exported_value("quicfuscate_body_pool_allocations_total") > body_before);
        assert!(output.contains("quicfuscate_mem_pool_in_use "));
        assert!(output.contains("quicfuscate_mem_pool_usage_bytes "));
    }

    #[test]
    fn test_health_export() {
        let metrics = Metrics::new();
        metrics.clients_active.store(10, Ordering::Relaxed);

        let output = metrics.export_health();
        assert!(output.contains("\"status\":\"ok\""));
        assert!(output.contains("\"clients\":10"));
        assert!(output.contains("\"geoip_status\":\"disabled\""));
    }

    #[test]
    fn geoip_metrics_expose_activation_state_lookup_counters_and_failed_health() {
        let metrics = Metrics::new();
        use crate::implementations::server::limits::GeoIpStatus;

        metrics.record_geoip_lookup();
        metrics.record_geoip_blocked();
        metrics.record_geoip_lookup_error();
        metrics.set_geoip_status(GeoIpStatus::Active);

        let output = metrics.export();
        for expected in [
            "quicfuscate_geoip_activation{state=\"active\"} 1",
            "quicfuscate_geoip_activation{state=\"disabled\"} 0",
            "quicfuscate_geoip_activation{state=\"failed\"} 0",
            "quicfuscate_geoip_lookups_total 1",
            "quicfuscate_geoip_blocked_total 1",
            "quicfuscate_geoip_lookup_errors_total 1",
        ] {
            assert!(output.contains(expected), "missing GeoIP metric: {expected}");
        }
        assert!(metrics.export_health().contains("\"status\":\"ok\""));
        assert!(metrics.export_health().contains("\"geoip_status\":\"active\""));

        metrics.set_geoip_status(GeoIpStatus::Failed);
        let failed_health = metrics.export_health();
        assert!(failed_health.contains("\"status\":\"not_ready\""));
        assert!(failed_health.contains("\"geoip_status\":\"failed\""));
    }

    #[test]
    fn auth_policy_metrics_export_distinct_terminal_and_admission_families() {
        let metrics = Metrics::new();
        metrics.record_auth_attempt();
        metrics.record_auth_success();
        metrics.record_auth_failure();
        metrics.record_auth_backoff_rejection();
        metrics.record_auth_blocked_rejection();
        metrics.record_auth_capacity_rejection();
        metrics.record_auth_abandoned();
        metrics.set_auth_state_tracked_ips(7);
        metrics.record_auth_state_pruned(3);
        metrics.record_revocation_pruned(4);

        let output = metrics.export();
        for metric in [
            "quicfuscate_auth_attempts_total 1",
            "quicfuscate_auth_succeeded_total 1",
            "quicfuscate_auth_failed_total 1",
            "quicfuscate_auth_backoff_rejected_total 1",
            "quicfuscate_auth_blocked_rejected_total 1",
            "quicfuscate_auth_capacity_rejected_total 1",
            "quicfuscate_auth_abandoned_total 1",
            "quicfuscate_auth_state_tracked_ips 7",
            "quicfuscate_auth_state_pruned_total 3",
            "quicfuscate_revocation_pruned_total 4",
        ] {
            assert!(output.contains(metric), "missing auth policy metric: {metric}");
        }
    }

    #[test]
    fn ddos_metrics_expose_state_retry_and_exact_drop_causes() {
        let metrics = Metrics::new();
        metrics.record_ddos_sample(
            42_000,
            crate::implementations::server::limits::DdosTransition::Activated,
        );
        metrics.record_ddos_retry_issued();
        metrics.record_ddos_retry_validated();
        for reason in [
            crate::implementations::server::ddos::DdosDropReason::GlobalLimit,
            crate::implementations::server::ddos::DdosDropReason::GeoIp,
            crate::implementations::server::ddos::DdosDropReason::Blacklist,
            crate::implementations::server::ddos::DdosDropReason::PerIpLimit,
            crate::implementations::server::ddos::DdosDropReason::MalformedInitial,
            crate::implementations::server::ddos::DdosDropReason::InvalidRetry,
        ] {
            metrics.record_ddos_drop(reason);
        }
        metrics.record_ddos_sample(
            1_000,
            crate::implementations::server::limits::DdosTransition::Cleared,
        );

        let output = metrics.export();
        for expected in [
            "quicfuscate_ddos_active 0",
            "quicfuscate_ddos_current_pps 1000",
            "quicfuscate_ddos_transitions_total{transition=\"activated\"} 1",
            "quicfuscate_ddos_transitions_total{transition=\"cleared\"} 1",
            "quicfuscate_ddos_retry_total{outcome=\"issued\"} 1",
            "quicfuscate_ddos_retry_total{outcome=\"validated\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"global_limit\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"geoip\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"blacklist\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"per_ip_limit\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"malformed_initial\"} 1",
            "quicfuscate_ddos_drops_total{reason=\"invalid_retry\"} 1",
        ] {
            assert!(output.contains(expected), "missing DDoS metric: {expected}");
        }
    }

    #[test]
    fn test_metrics_mirror_global_instrumentation_for_runtime_events() {
        let global = crate::instrumentation::global();
        let rejected_before = global.server.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = global.server.auth_failed.load(Ordering::Relaxed);
        let rate_limited_before = global.server.rate_limited.load(Ordering::Relaxed);
        let bytes_in_before = global.transport.bytes_in.load(Ordering::Relaxed);
        let bytes_out_before = global.transport.bytes_out.load(Ordering::Relaxed);
        let packets_in_before = global.transport.packets_in.load(Ordering::Relaxed);
        let packets_out_before = global.transport.packets_out.load(Ordering::Relaxed);

        let metrics = Metrics::new();
        metrics.record_connection_rejected();
        metrics.record_auth_failure();
        metrics.record_rate_limited();
        metrics.record_ingress_datagram(321);
        metrics.record_egress_datagram(654);

        assert!(global.server.connections_rejected.load(Ordering::Relaxed) > rejected_before);
        assert!(global.server.auth_failed.load(Ordering::Relaxed) > auth_failed_before);
        assert!(global.server.rate_limited.load(Ordering::Relaxed) > rate_limited_before);
        assert!(global.transport.bytes_in.load(Ordering::Relaxed) >= bytes_in_before + 321);
        assert!(global.transport.bytes_out.load(Ordering::Relaxed) >= bytes_out_before + 654);
        assert!(global.transport.packets_in.load(Ordering::Relaxed) > packets_in_before);
        assert!(global.transport.packets_out.load(Ordering::Relaxed) > packets_out_before);
    }
}
