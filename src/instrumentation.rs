//! Instrumentation for metrics collection throughout QuicFuscate.
//!
//! This module provides a global metrics registry that can be accessed
//! from anywhere in the codebase to record events and statistics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;

/// Global metrics instance.
static GLOBAL_METRICS: LazyLock<Arc<GlobalMetrics>> =
    LazyLock::new(|| Arc::new(GlobalMetrics::new()));

/// Get the global metrics instance.
pub fn global() -> Arc<GlobalMetrics> {
    GLOBAL_METRICS.clone()
}

/// Global metrics collector.
#[derive(Debug)]
pub struct GlobalMetrics {
    /// Server-side connection and session metrics.
    pub server: ServerMetrics,
    /// Client-side connection metrics.
    pub client: ClientMetrics,
    /// Transport layer traffic and congestion metrics.
    pub transport: TransportMetrics,
    /// Stealth mode and fingerprint metrics.
    pub stealth: StealthMetrics,
    /// Forward error correction metrics.
    pub fec: FecMetrics,
}

impl GlobalMetrics {
    /// Create a new `GlobalMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            server: ServerMetrics::new(),
            client: ClientMetrics::new(),
            transport: TransportMetrics::new(),
            stealth: StealthMetrics::new(),
            fec: FecMetrics::new(),
        }
    }

    /// Export all metrics in Prometheus format.
    pub fn export_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // Server metrics
        self.server.export(&mut out);

        // Transport metrics
        self.transport.export(&mut out);

        // Stealth metrics
        self.stealth.export(&mut out);

        // FEC metrics
        self.fec.export(&mut out);

        // Client metrics
        self.client.export(&mut out);

        out
    }

    /// Export health status as JSON.
    pub fn export_health(&self) -> String {
        format!(
            r#"{{"status":"ok","version":"{}","uptime":{},"clients":{}}}"#,
            env!("CARGO_PKG_VERSION"),
            self.server.uptime_secs(),
            self.server.clients_active.load(Ordering::Relaxed)
        )
    }
}

impl Default for GlobalMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Server-specific metrics.
#[derive(Debug)]
pub struct ServerMetrics {
    /// Instant when the server started (for uptime calculation).
    pub start_time: std::time::Instant,

    /// Currently connected clients (gauge).
    pub clients_active: AtomicU64,
    /// Cumulative total clients that have connected.
    pub clients_total: AtomicU64,
    /// Total accepted connections.
    pub connections_accepted: AtomicU64,
    /// Total rejected connections.
    pub connections_rejected: AtomicU64,

    /// Total sessions created.
    pub sessions_created: AtomicU64,
    /// Total sessions expired.
    pub sessions_expired: AtomicU64,

    /// Total authentication failures.
    pub auth_failed: AtomicU64,
    /// Total rate-limited events.
    pub rate_limited: AtomicU64,
}

impl ServerMetrics {
    /// Create a new `ServerMetrics` with start time set to now.
    pub fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            clients_active: AtomicU64::new(0),
            clients_total: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            sessions_created: AtomicU64::new(0),
            sessions_expired: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }

    /// Return seconds elapsed since server start.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Record a new client connection (increments active + total).
    pub fn client_connected(&self) {
        self.clients_active.fetch_add(1, Ordering::Relaxed);
        self.clients_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a client disconnection (decrements active count).
    pub fn client_disconnected(&self) {
        let _ = self
            .clients_active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
    }

    /// Record a rejected connection attempt.
    pub fn connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new session creation.
    pub fn session_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a session expiration.
    pub fn session_expired(&self) {
        self.sessions_expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an authentication failure.
    pub fn auth_failure(&self) {
        self.auth_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rate-limit enforcement event.
    pub fn rate_limit_hit(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    fn export(&self, out: &mut String) {
        out.push_str("# HELP quicfuscate_up Server is up\n");
        out.push_str("# TYPE quicfuscate_up gauge\n");
        out.push_str("quicfuscate_up 1\n\n");

        out.push_str("# HELP quicfuscate_uptime_seconds Server uptime\n");
        out.push_str("# TYPE quicfuscate_uptime_seconds counter\n");
        let _ = write!(out, "quicfuscate_uptime_seconds {}\n\n", self.uptime_secs());

        out.push_str("# HELP quicfuscate_clients_active Active client connections\n");
        out.push_str("# TYPE quicfuscate_clients_active gauge\n");
        let _ = write!(
            out,
            "quicfuscate_clients_active {}\n\n",
            self.clients_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_clients_total Total clients connected\n");
        out.push_str("# TYPE quicfuscate_clients_total counter\n");
        let _ = write!(
            out,
            "quicfuscate_clients_total {}\n\n",
            self.clients_total.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_accepted Accepted connections\n");
        out.push_str("# TYPE quicfuscate_connections_accepted counter\n");
        let _ = write!(
            out,
            "quicfuscate_connections_accepted {}\n\n",
            self.connections_accepted.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_rejected Rejected connections\n");
        out.push_str("# TYPE quicfuscate_connections_rejected counter\n");
        let _ = write!(
            out,
            "quicfuscate_connections_rejected {}\n\n",
            self.connections_rejected.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_sessions_created Sessions created\n");
        out.push_str("# TYPE quicfuscate_sessions_created counter\n");
        let _ = write!(
            out,
            "quicfuscate_sessions_created {}\n\n",
            self.sessions_created.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_sessions_expired Sessions expired\n");
        out.push_str("# TYPE quicfuscate_sessions_expired counter\n");
        let _ = write!(
            out,
            "quicfuscate_sessions_expired {}\n\n",
            self.sessions_expired.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_auth_failed Authentication failures\n");
        out.push_str("# TYPE quicfuscate_auth_failed counter\n");
        let _ =
            write!(out, "quicfuscate_auth_failed {}\n\n", self.auth_failed.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_rate_limited Rate-limited events\n");
        out.push_str("# TYPE quicfuscate_rate_limited counter\n");
        let _ = write!(
            out,
            "quicfuscate_rate_limited {}\n\n",
            self.rate_limited.load(Ordering::Relaxed)
        );
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Client-specific metrics.
#[derive(Debug)]
pub struct ClientMetrics {
    /// Total connection attempts initiated by the client.
    pub connection_attempts: AtomicU64,
    /// Successful connection establishments.
    pub connection_successes: AtomicU64,
    /// Failed connection attempts.
    pub connection_failures: AtomicU64,
    /// Automatic reconnection events.
    pub reconnects: AtomicU64,
    /// Client uptime in seconds (updated periodically).
    pub uptime_secs: AtomicU64,
}

impl ClientMetrics {
    /// Create a new `ClientMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            connection_attempts: AtomicU64::new(0),
            connection_successes: AtomicU64::new(0),
            connection_failures: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            uptime_secs: AtomicU64::new(0),
        }
    }

    /// Record a connection attempt.
    pub fn connection_attempt(&self) {
        self.connection_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful connection.
    pub fn connection_success(&self) {
        self.connection_successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed connection attempt.
    pub fn connection_failure(&self) {
        self.connection_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an automatic reconnection event.
    pub fn reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    fn export(&self, out: &mut String) {
        out.push_str(
            "# HELP quicfuscate_client_connection_attempts Total client connection attempts\n",
        );
        out.push_str("# TYPE quicfuscate_client_connection_attempts counter\n");
        let _ = write!(
            out,
            "quicfuscate_client_connection_attempts {}\n\n",
            self.connection_attempts.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_client_connection_successes Successful client connections\n",
        );
        out.push_str("# TYPE quicfuscate_client_connection_successes counter\n");
        let _ = write!(
            out,
            "quicfuscate_client_connection_successes {}\n\n",
            self.connection_successes.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_client_connection_failures Failed client connections\n");
        out.push_str("# TYPE quicfuscate_client_connection_failures counter\n");
        let _ = write!(
            out,
            "quicfuscate_client_connection_failures {}\n\n",
            self.connection_failures.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_client_reconnects Automatic reconnection events\n");
        out.push_str("# TYPE quicfuscate_client_reconnects counter\n");
        let _ = write!(
            out,
            "quicfuscate_client_reconnects {}\n\n",
            self.reconnects.load(Ordering::Relaxed)
        );
    }
}

impl Default for ClientMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Transport layer metrics.
#[derive(Debug)]
pub struct TransportMetrics {
    /// Total bytes received.
    pub bytes_in: AtomicU64,
    /// Total bytes sent.
    pub bytes_out: AtomicU64,
    /// Total packets received.
    pub packets_in: AtomicU64,
    /// Total packets sent.
    pub packets_out: AtomicU64,

    /// QUIC streams opened.
    pub streams_opened: AtomicU64,
    /// QUIC streams closed.
    pub streams_closed: AtomicU64,
    /// QUIC datagrams sent.
    pub datagrams_sent: AtomicU64,
    /// QUIC datagrams received.
    pub datagrams_received: AtomicU64,

    /// Packets detected as lost.
    pub packets_lost: AtomicU64,
    /// Packets retransmitted.
    pub packets_retransmitted: AtomicU64,
    /// Number of RTT samples collected.
    pub rtt_samples: AtomicU64,
    /// Cumulative RTT sum in microseconds (for averaging).
    pub rtt_sum_us: AtomicU64,
}

impl TransportMetrics {
    /// Create a new `TransportMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            streams_opened: AtomicU64::new(0),
            streams_closed: AtomicU64::new(0),
            datagrams_sent: AtomicU64::new(0),
            datagrams_received: AtomicU64::new(0),
            packets_lost: AtomicU64::new(0),
            packets_retransmitted: AtomicU64::new(0),
            rtt_samples: AtomicU64::new(0),
            rtt_sum_us: AtomicU64::new(0),
        }
    }

    /// Add received bytes to the counter.
    pub fn record_bytes_in(&self, bytes: u64) {
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add sent bytes to the counter.
    pub fn record_bytes_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the received packet counter.
    pub fn record_packet_in(&self) {
        self.packets_in.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the sent packet counter.
    pub fn record_packet_out(&self) {
        self.packets_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet loss event.
    pub fn record_packet_loss(&self) {
        self.packets_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an RTT sample in microseconds.
    pub fn record_rtt(&self, rtt_us: u64) {
        self.rtt_samples.fetch_add(1, Ordering::Relaxed);
        self.rtt_sum_us.fetch_add(rtt_us, Ordering::Relaxed);
    }

    /// Compute the average RTT in milliseconds from collected samples.
    pub fn avg_rtt_ms(&self) -> f64 {
        let samples = self.rtt_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0.0;
        }
        let sum = self.rtt_sum_us.load(Ordering::Relaxed);
        (sum as f64 / samples as f64) / 1000.0
    }

    /// Compute the packet loss rate as a percentage.
    pub fn loss_rate(&self) -> f64 {
        let sent = self.packets_out.load(Ordering::Relaxed);
        if sent == 0 {
            return 0.0;
        }
        let lost = self.packets_lost.load(Ordering::Relaxed);
        lost as f64 / sent as f64 * 100.0
    }

    fn export(&self, out: &mut String) {
        out.push_str("# HELP quicfuscate_bytes_in Total bytes received\n");
        out.push_str("# TYPE quicfuscate_bytes_in counter\n");
        let _ = write!(out, "quicfuscate_bytes_in {}\n\n", self.bytes_in.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_bytes_out Total bytes sent\n");
        out.push_str("# TYPE quicfuscate_bytes_out counter\n");
        let _ = write!(out, "quicfuscate_bytes_out {}\n\n", self.bytes_out.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_packets_in Total packets received\n");
        out.push_str("# TYPE quicfuscate_packets_in counter\n");
        let _ =
            write!(out, "quicfuscate_packets_in {}\n\n", self.packets_in.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_packets_out Total packets sent\n");
        out.push_str("# TYPE quicfuscate_packets_out counter\n");
        let _ =
            write!(out, "quicfuscate_packets_out {}\n\n", self.packets_out.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_packets_lost Packets lost\n");
        out.push_str("# TYPE quicfuscate_packets_lost counter\n");
        let _ = write!(
            out,
            "quicfuscate_packets_lost {}\n\n",
            self.packets_lost.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_rtt_avg_ms Average RTT in milliseconds\n");
        out.push_str("# TYPE quicfuscate_rtt_avg_ms gauge\n");
        let _ = write!(out, "quicfuscate_rtt_avg_ms {:.2}\n\n", self.avg_rtt_ms());

        out.push_str("# HELP quicfuscate_loss_rate Packet loss rate percent\n");
        out.push_str("# TYPE quicfuscate_loss_rate gauge\n");
        let _ = write!(out, "quicfuscate_loss_rate {:.2}\n\n", self.loss_rate());
    }
}

impl Default for TransportMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Stealth mode metrics.
#[derive(Debug)]
pub struct StealthMetrics {
    /// Times stealth mode was set to "off".
    pub mode_off: AtomicU64,
    /// Times stealth mode was set to "auto".
    pub mode_auto: AtomicU64,
    /// Times stealth mode was set to "max".
    pub mode_max: AtomicU64,
    /// Clients currently using HTTP/3 stealth path.
    pub http3_active: AtomicU64,
    /// Clients currently using TLS 1.3 stealth path.
    pub tls13_active: AtomicU64,
    /// Total padding bytes injected for stealth.
    pub padding_bytes: AtomicU64,
    /// Total fingerprint rotation events.
    pub fingerprint_rotations: AtomicU64,
}

impl StealthMetrics {
    /// Create a new `StealthMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            mode_off: AtomicU64::new(0),
            mode_auto: AtomicU64::new(0),
            mode_max: AtomicU64::new(0),
            http3_active: AtomicU64::new(0),
            tls13_active: AtomicU64::new(0),
            padding_bytes: AtomicU64::new(0),
            fingerprint_rotations: AtomicU64::new(0),
        }
    }

    /// Record a stealth mode selection ("off", "auto", or "max").
    pub fn record_mode(&self, mode: &str) {
        match mode {
            "off" => self.mode_off.fetch_add(1, Ordering::Relaxed),
            "auto" => self.mode_auto.fetch_add(1, Ordering::Relaxed),
            "max" => self.mode_max.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    /// Record padding bytes injected for stealth.
    pub fn record_padding(&self, bytes: u64) {
        self.padding_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Set the count of clients using HTTP/3 stealth.
    pub fn set_http3_active(&self, count: u64) {
        self.http3_active.store(count, Ordering::Relaxed);
    }

    /// Set the count of clients using TLS 1.3 stealth.
    pub fn set_tls13_active(&self, count: u64) {
        self.tls13_active.store(count, Ordering::Relaxed);
    }

    fn export(&self, out: &mut String) {
        out.push_str("# HELP quicfuscate_stealth_http3 Clients using HTTP/3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_http3 gauge\n");
        let _ = write!(
            out,
            "quicfuscate_stealth_http3 {}\n\n",
            self.http3_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_stealth_tls13 Clients using TLS 1.3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_tls13 gauge\n");
        let _ = write!(
            out,
            "quicfuscate_stealth_tls13 {}\n\n",
            self.tls13_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_padding_bytes Total padding bytes added\n");
        out.push_str("# TYPE quicfuscate_padding_bytes counter\n");
        let _ = write!(
            out,
            "quicfuscate_padding_bytes {}\n\n",
            self.padding_bytes.load(Ordering::Relaxed)
        );
    }
}

impl Default for StealthMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// FEC (Forward Error Correction) metrics.
#[derive(Debug)]
pub struct FecMetrics {
    /// Total packets processed by FEC encoder.
    pub packets_encoded: AtomicU64,
    /// Total packets processed by FEC decoder.
    pub packets_decoded: AtomicU64,
    /// Total packets successfully recovered via FEC.
    pub packets_recovered: AtomicU64,
    /// Total FEC recovery failures.
    pub recovery_failures: AtomicU64,
    /// Total redundancy bytes added by FEC.
    pub redundancy_bytes: AtomicU64,
}

impl FecMetrics {
    /// Create a new `FecMetrics` with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_encoded: AtomicU64::new(0),
            packets_decoded: AtomicU64::new(0),
            packets_recovered: AtomicU64::new(0),
            recovery_failures: AtomicU64::new(0),
            redundancy_bytes: AtomicU64::new(0),
        }
    }

    /// Record a FEC encode operation.
    pub fn record_encode(&self) {
        self.packets_encoded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a FEC decode operation.
    pub fn record_decode(&self) {
        self.packets_decoded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful FEC packet recovery.
    pub fn record_recovery(&self) {
        self.packets_recovered.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed FEC recovery attempt.
    pub fn record_recovery_failure(&self) {
        self.recovery_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record redundancy bytes added by FEC encoding.
    pub fn record_redundancy(&self, bytes: u64) {
        self.redundancy_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Compute the FEC recovery success rate as a percentage.
    pub fn recovery_rate(&self) -> f64 {
        let total = self.packets_recovered.load(Ordering::Relaxed)
            + self.recovery_failures.load(Ordering::Relaxed);
        if total == 0 {
            return 100.0;
        }
        let recovered = self.packets_recovered.load(Ordering::Relaxed);
        recovered as f64 / total as f64 * 100.0
    }

    fn export(&self, out: &mut String) {
        out.push_str("# HELP quicfuscate_fec_encoded FEC encoded packets\n");
        out.push_str("# TYPE quicfuscate_fec_encoded counter\n");
        let _ = write!(
            out,
            "quicfuscate_fec_encoded {}\n\n",
            self.packets_encoded.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_fec_decoded FEC decoded packets\n");
        out.push_str("# TYPE quicfuscate_fec_decoded counter\n");
        let _ = write!(
            out,
            "quicfuscate_fec_decoded {}\n\n",
            self.packets_decoded.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_fec_recovered FEC recovered packets\n");
        out.push_str("# TYPE quicfuscate_fec_recovered counter\n");
        let _ = write!(
            out,
            "quicfuscate_fec_recovered {}\n\n",
            self.packets_recovered.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_fec_recovery_rate FEC recovery success rate\n");
        out.push_str("# TYPE quicfuscate_fec_recovery_rate gauge\n");
        let _ = write!(out, "quicfuscate_fec_recovery_rate {:.2}\n\n", self.recovery_rate());

        out.push_str("# HELP quicfuscate_fec_redundancy FEC redundancy bytes\n");
        out.push_str("# TYPE quicfuscate_fec_redundancy counter\n");
        let _ = writeln!(
            out,
            "quicfuscate_fec_redundancy {}",
            self.redundancy_bytes.load(Ordering::Relaxed)
        );
    }
}

impl Default for FecMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_metrics() {
        let metrics = GlobalMetrics::new();

        metrics.server.client_connected();
        metrics.server.client_connected();
        metrics.server.client_disconnected();

        assert_eq!(metrics.server.clients_active.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.server.clients_total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_server_client_connected_does_not_imply_connection_accepted() {
        let metrics = GlobalMetrics::new();

        metrics.server.client_connected();

        assert_eq!(metrics.server.clients_active.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.server.clients_total.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.server.connections_accepted.load(Ordering::Relaxed), 0);

        metrics.server.connections_accepted.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.server.connections_accepted.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_transport_metrics() {
        let metrics = TransportMetrics::new();

        metrics.record_bytes_in(1000);
        metrics.record_bytes_out(500);
        metrics.record_packet_in();
        metrics.record_packet_out();
        metrics.record_packet_loss();

        assert_eq!(metrics.bytes_in.load(Ordering::Relaxed), 1000);
        assert_eq!(metrics.loss_rate(), 100.0); // 1 lost / 1 sent
    }

    #[test]
    fn test_fec_metrics() {
        let metrics = FecMetrics::new();

        metrics.record_recovery();
        metrics.record_recovery();
        metrics.record_recovery_failure();

        // ~66.67%
        let rate = metrics.recovery_rate();
        assert!(rate > 66.0 && rate < 67.0);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = GlobalMetrics::new();
        metrics.server.client_connected();

        let output = metrics.export_prometheus();
        assert!(output.contains("quicfuscate_up 1"));
        assert!(output.contains("quicfuscate_clients_active 1"));
    }
}
