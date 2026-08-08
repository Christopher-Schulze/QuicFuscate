//! Compatibility surface for the standalone telemetry metrics server.

/// Spawn the telemetry server using the root telemetry exporter.
pub fn spawn_telemetry_server() {
    qf_metrics::spawn_telemetry_server(crate::telemetry::export_telemetry_text);
}
