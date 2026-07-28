//! Prometheus metrics for QuicFuscate server.
//!
//! Exports metrics in Prometheus text format at /metrics endpoint.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::isolation::{UplinkDrop, UplinkRoute};

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

    // Server-generated MASQUE response queue metrics
    pub masque_downlink_response_retried: AtomicU64,
    pub masque_downlink_response_drop_packet_capacity: AtomicU64,
    pub masque_downlink_response_drop_byte_capacity: AtomicU64,
    pub masque_downlink_response_drop_terminal_transport_error: AtomicU64,
    pub masque_downlink_response_drop_shutdown: AtomicU64,

    // Stealth metrics
    pub stealth_http3_active: AtomicU64,
    pub stealth_tls13_active: AtomicU64,

    // FEC metrics
    pub fec_packets_encoded: FecProcessCounter,
    pub fec_packets_decoded: FecProcessCounter,
    pub fec_packets_recovered: FecProcessCounter,

    // Error metrics
    pub auth_failed: AtomicU64,
    pub rate_limited: AtomicU64,

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
            masque_downlink_response_retried: AtomicU64::new(0),
            masque_downlink_response_drop_packet_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_byte_capacity: AtomicU64::new(0),
            masque_downlink_response_drop_terminal_transport_error: AtomicU64::new(0),
            masque_downlink_response_drop_shutdown: AtomicU64::new(0),
            stealth_http3_active: AtomicU64::new(0),
            stealth_tls13_active: AtomicU64::new(0),
            fec_packets_encoded: FecProcessCounter::new(FecProcessCounterKind::Emitted),
            fec_packets_decoded: FecProcessCounter::new(FecProcessCounterKind::Decoded),
            fec_packets_recovered: FecProcessCounter::new(FecProcessCounterKind::Recovered),
            auth_failed: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
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

    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        crate::instrumentation::global().server.rate_limit_hit();
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
        let mut out = String::new();

        // Server info
        out.push_str("# HELP quicfuscate_up Server is up\n");
        out.push_str("# TYPE quicfuscate_up gauge\n");
        out.push_str("quicfuscate_up 1\n\n");

        out.push_str("# HELP quicfuscate_uptime_seconds Server uptime\n");
        out.push_str("# TYPE quicfuscate_uptime_seconds counter\n");
        out.push_str(&format!("quicfuscate_uptime_seconds {}\n\n", self.uptime_secs()));

        // Clients
        out.push_str("# HELP quicfuscate_clients_active Current active clients\n");
        out.push_str("# TYPE quicfuscate_clients_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_clients_active {}\n\n",
            self.clients_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_clients_total Total clients connected\n");
        out.push_str("# TYPE quicfuscate_clients_total counter\n");
        out.push_str(&format!(
            "quicfuscate_clients_total {}\n\n",
            self.clients_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_connections_accepted Accepted connections\n");
        out.push_str("# TYPE quicfuscate_connections_accepted counter\n");
        out.push_str(&format!(
            "quicfuscate_connections_accepted {}\n\n",
            self.connections_accepted.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_connections_rejected Rejected connections\n");
        out.push_str("# TYPE quicfuscate_connections_rejected counter\n");
        out.push_str(&format!(
            "quicfuscate_connections_rejected {}\n\n",
            self.connections_rejected.load(Ordering::Relaxed)
        ));

        // Traffic
        out.push_str("# HELP quicfuscate_bytes_in_total Total bytes received\n");
        out.push_str("# TYPE quicfuscate_bytes_in_total counter\n");
        out.push_str(&format!(
            "quicfuscate_bytes_in_total {}\n\n",
            self.bytes_in.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_bytes_out_total Total bytes sent\n");
        out.push_str("# TYPE quicfuscate_bytes_out_total counter\n");
        out.push_str(&format!(
            "quicfuscate_bytes_out_total {}\n\n",
            self.bytes_out.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_packets_in_total Total packets received\n");
        out.push_str("# TYPE quicfuscate_packets_in_total counter\n");
        out.push_str(&format!(
            "quicfuscate_packets_in_total {}\n\n",
            self.packets_in.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_packets_out_total Total packets sent\n");
        out.push_str("# TYPE quicfuscate_packets_out_total counter\n");
        out.push_str(&format!(
            "quicfuscate_packets_out_total {}\n\n",
            self.packets_out.load(Ordering::Relaxed)
        ));

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
            out.push_str(&format!(
                "quicfuscate_routing_packets_total{{outcome=\"{outcome}\"}} {value}\n"
            ));
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_packets Current packets retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_packets gauge\n");
        out.push_str(&format!(
            "quicfuscate_tun_downlink_backpressure_pending_packets {}\n\n",
            self.tun_downlink_backpressure_pending_packets.load(Ordering::Relaxed)
        ));
        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_bytes Current bytes retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_bytes gauge\n");
        out.push_str(&format!(
            "quicfuscate_tun_downlink_backpressure_pending_bytes {}\n\n",
            self.tun_downlink_backpressure_pending_bytes.load(Ordering::Relaxed)
        ));
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
            out.push_str(&format!(
                "quicfuscate_tun_downlink_backpressure_events_total{{event=\"{event}\"}} {value}\n"
            ));
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
            out.push_str(&format!(
                "quicfuscate_masque_downlink_response_events_total{{event=\"{event}\"}} {value}\n"
            ));
        }
        out.push('\n');

        // Stealth
        out.push_str("# HELP quicfuscate_stealth_http3_active Clients using HTTP/3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_http3_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_stealth_http3_active {}\n\n",
            self.stealth_http3_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_stealth_tls13_active Clients using TLS 1.3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_tls13_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_stealth_tls13_active {}\n\n",
            self.stealth_tls13_active.load(Ordering::Relaxed)
        ));

        // FEC
        out.push_str(
            "# HELP quicfuscate_fec_packets_encoded Process-wide source plus repair datagrams actually written by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_encoded counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_encoded {}\n\n",
            self.fec_packets_encoded.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP quicfuscate_fec_packets_decoded Process-wide original plus recovered source packets delivered by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_decoded counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_decoded {}\n\n",
            self.fec_packets_decoded.load(Ordering::Relaxed)
        ));

        out.push_str(
            "# HELP quicfuscate_fec_packets_recovered Process-wide source packets reconstructed from repair data\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_recovered counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_recovered {}\n\n",
            self.fec_packets_recovered.load(Ordering::Relaxed)
        ));

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
            out.push_str(&format!(
                "quicfuscate_mem_pool_allocations_total{{source=\"{source}\"}} {value}\n"
            ));
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_body_pool_allocations_total Process-wide HTTP body-pool allocations\n",
        );
        out.push_str("# TYPE quicfuscate_body_pool_allocations_total counter\n");
        out.push_str(&format!(
            "quicfuscate_body_pool_allocations_total {}\n\n",
            crate::telemetry::BODY_POOL_ALLOCS.get()
        ));
        out.push_str(
            "# HELP quicfuscate_mem_pool_in_use Current process-wide memory-pool blocks in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_in_use gauge\n");
        out.push_str(&format!(
            "quicfuscate_mem_pool_in_use {}\n\n",
            crate::telemetry::MEM_POOL_IN_USE.load(Ordering::Relaxed)
        ));
        out.push_str(
            "# HELP quicfuscate_mem_pool_usage_bytes Current process-wide memory-pool bytes in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_usage_bytes gauge\n");
        out.push_str(&format!(
            "quicfuscate_mem_pool_usage_bytes {}\n\n",
            crate::telemetry::MEM_POOL_USAGE_BYTES.load(Ordering::Relaxed)
        ));

        // Errors
        out.push_str("# HELP quicfuscate_auth_failed_total Authentication failures\n");
        out.push_str("# TYPE quicfuscate_auth_failed_total counter\n");
        out.push_str(&format!(
            "quicfuscate_auth_failed_total {}\n\n",
            self.auth_failed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_rate_limited_total Rate-limited events\n");
        out.push_str("# TYPE quicfuscate_rate_limited_total counter\n");
        out.push_str(&format!(
            "quicfuscate_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        ));

        out
    }

    /// Export as JSON for health endpoint.
    pub fn export_health(&self) -> String {
        format!(
            r#"{{"status":"ok","version":"{}","uptime":{},"clients":{}}}"#,
            env!("CARGO_PKG_VERSION"),
            self.uptime_secs(),
            self.clients_active.load(Ordering::Relaxed)
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
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

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Metrics server listening on http://{}", self.addr);

        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((mut socket, _addr))) => {
                    let mut buf = [0u8; 1024];
                    if let Err(e) = socket.read(&mut buf).await {
                        log::debug!("Metrics request read failed: {}", e);
                        continue;
                    }

                    let request = String::from_utf8_lossy(&buf);

                    // Parse request path
                    let response = if request.contains("GET /metrics") {
                        let body = self.metrics.export();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain; version=0.0.4\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else if request.contains("GET /health") {
                        let body = self.metrics.export_health();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                            .to_string()
                    };

                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        log::debug!("Metrics response write failed: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        log::info!("Metrics server stopped");
        Ok(())
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

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Global metrics server listening on http://{}", self.addr);

        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((mut socket, _addr))) => {
                    let mut buf = [0u8; 1024];
                    if let Err(e) = socket.read(&mut buf).await {
                        log::debug!("Global metrics request read failed: {}", e);
                        continue;
                    }

                    let request = String::from_utf8_lossy(&buf);
                    let global = crate::instrumentation::global();

                    // Parse request path
                    let response = if request.contains("GET /metrics") {
                        let body = global.export_prometheus();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain; version=0.0.4\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else if request.contains("GET /health") {
                        let body = global.export_health();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                            .to_string()
                    };

                    if let Err(e) = socket.write_all(response.as_bytes()).await {
                        log::debug!("Global metrics response write failed: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Global metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        log::info!("Global metrics server stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                >= tls_before + 1
        );
        assert!(
            exported_value("quicfuscate_mem_pool_allocations_total{source=\"ephemeral\"}")
                >= ephemeral_before + 1
        );
        assert!(exported_value("quicfuscate_body_pool_allocations_total") >= body_before + 1);
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
