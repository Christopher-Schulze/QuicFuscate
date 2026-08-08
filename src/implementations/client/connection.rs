//! Client connection wrapper for QuicFuscateConnection.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::core::QuicFuscateConnection;
use crate::engine::{EngineConfig, EngineError};
use crate::stealth::StealthRuntimeOwner;
use crate::time_source::ProtocolClock;

/// Client connection wrapper.
///
/// Wraps `QuicFuscateConnection` and provides a streamlined interface
/// for the client runtime.
pub struct ClientConnection {
    inner: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl ClientConnection {
    /// Create a new client connection from engine configuration.
    pub fn connect(config: &EngineConfig) -> Result<Self, EngineError> {
        Self::connect_with_clock(config, &ProtocolClock::default())
    }

    /// Create a new client connection bound to an explicit protocol clock.
    pub fn connect_with_clock(
        config: &EngineConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, EngineError> {
        Self::connect_with_runtime_and_clock(config, None, clock)
    }

    /// Create a new client connection attached to a runtime-owned stealth service.
    pub fn connect_with_runtime(
        config: &EngineConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
    ) -> Result<Self, EngineError> {
        Self::connect_with_runtime_and_clock(config, runtime_owner, &ProtocolClock::default())
    }

    /// Create a client connection attached to a runtime owner and explicit clock.
    pub fn connect_with_runtime_and_clock(
        config: &EngineConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: &ProtocolClock,
    ) -> Result<Self, EngineError> {
        config.validate().map_err(|error| {
            EngineError::Config(format!("Invalid engine configuration: {error}"))
        })?;
        // Record connection attempt
        crate::instrumentation::global().client.connection_attempt();

        // Parse addresses
        let remote_addr: SocketAddr = config.connection.remote.parse().map_err(|e| {
            crate::instrumentation::global().client.connection_failure();
            EngineError::Config(format!("Invalid remote address: {}", e))
        })?;

        let local_addr: SocketAddr = if config.connection.local.is_empty() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            config.connection.local.parse().map_err(|e| {
                crate::instrumentation::global().client.connection_failure();
                EngineError::Config(format!("Invalid local address: {}", e))
            })?
        };

        // Build transport config
        let transport_config = Self::build_transport_config(config)?;

        // Build stealth config from EngineConfig
        let stealth_config = Self::build_stealth_config(config)?;

        // Build FEC config
        let fec_config = Self::build_fec_config(config)?;

        // Build optimization config
        let opt_config = Self::build_optimize_config(config)?;

        let sni = derive_sni(&config.connection.sni, remote_addr);

        log::info!("Connecting to {} (SNI: {}) from {}", remote_addr, sni, local_addr);

        // Create QUIC connection using core.rs
        let qkey_token = config.connection.qkey_token.clone().filter(|t| !t.trim().is_empty());
        let qkey_initial_token: Option<Vec<u8>> =
            qkey_token.as_deref().map(|raw| crate::engine::qkey::id(raw.trim()).into_bytes());
        let conn = QuicFuscateConnection::new_client_with_runtime_and_clock(
            &sni,
            local_addr,
            remote_addr,
            transport_config,
            stealth_config,
            fec_config,
            opt_config,
            qkey_token,
            qkey_initial_token,
            Self::should_use_utls(config),
            runtime_owner,
            None,
            clock.clone(),
        )
        .map_err(|e| {
            crate::instrumentation::global().client.connection_failure();
            EngineError::Connection(e)
        })?;

        // Record success
        crate::instrumentation::global().client.connection_success();
        log::info!("QUIC connection established to {}", remote_addr);

        Ok(Self { inner: Arc::new(parking_lot::Mutex::new(conn)), remote_addr, local_addr })
    }

    /// Send data through the QUIC connection.
    ///
    /// Returns the number of bytes written to the buffer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.send(buf).map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }

    /// Receive data from the QUIC connection.
    ///
    /// Returns the number of bytes processed.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.recv(data).map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }

    /// Get the remote peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the stealth manager for dynamic configuration.
    pub fn stealth_manager(&self) -> Arc<crate::stealth::StealthManager> {
        let guard = self.inner.lock();
        guard.stealth_manager()
    }

    /// Get the underlying connection (for advanced usage).
    pub fn shared(&self) -> Arc<parking_lot::Mutex<QuicFuscateConnection>> {
        self.inner.clone()
    }

    /// Check if the connection is established.
    pub fn is_established(&self) -> bool {
        let guard = self.inner.lock();
        guard.conn.is_established()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        let guard = self.inner.lock();
        guard.conn.is_closed()
    }

    /// Returns the duration elapsed since the last inbound packet was received.
    /// Used by the heartbeat watchdog to detect connection loss.
    pub fn last_activity_elapsed(&self) -> std::time::Duration {
        let guard = self.inner.lock();
        guard.conn.last_activity_elapsed()
    }

    /// Get RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        let guard = self.inner.lock();
        guard.rtt_ms()
    }

    /// Get packet loss rate.
    pub fn loss_rate(&self) -> f32 {
        let guard = self.inner.lock();
        guard.loss_rate()
    }

    /// Apply and observe an active FEC policy change under the connection owner.
    pub fn set_fec_control_policy(
        &self,
        policy: crate::fec::FecControlPolicy,
    ) -> crate::core::ActiveFecPolicyChange {
        let mut guard = self.inner.lock();
        guard.set_fec_control_policy(policy)
    }

    /// Return exact active FEC policy, mode, and wire counters.
    pub fn fec_telemetry_snapshot(&self) -> crate::fec::FecTelemetrySnapshot {
        let guard = self.inner.lock();
        guard.fec_telemetry_snapshot()
    }

    /// Get the effective stealth mode currently used by the live connection.
    pub fn stealth_mode(&self) -> crate::stealth::StealthMode {
        let guard = self.inner.lock();
        guard.stealth_mode()
    }

    /// Get the effective TLS SNI currently used by the live connection.
    pub fn server_name(&self) -> Option<String> {
        let guard = self.inner.lock();
        guard.server_name()
    }

    /// Return the terminal error, preferring the first local root cause.
    pub fn error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.conn.error().cloned()
    }

    /// Return the first locally decided terminal or protocol error.
    pub fn local_error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.conn.local_error().cloned()
    }

    /// Return the first close reason received from the peer.
    pub fn remote_error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.conn.remote_error().cloned()
    }

    /// Close the connection with an application error.
    ///
    /// This emits an `APPLICATION_CLOSE` frame. Use `close_transport()` when
    /// the error belongs to the QUIC transport rather than the application.
    pub fn close(&mut self, app_error: u64, reason: &[u8]) {
        self.close_with_kind(true, app_error, reason, "application");
    }

    /// Close the connection with a transport error.
    ///
    /// This emits a `CONNECTION_CLOSE` frame with frame type zero, matching the
    /// transport's local close representation.
    pub fn close_transport(&mut self, transport_error: u64, reason: &[u8]) {
        self.close_with_kind(false, transport_error, reason, "transport");
    }

    fn close_with_kind(&mut self, app: bool, error_code: u64, reason: &[u8], kind: &str) {
        let mut guard = self.inner.lock();
        if let Err(e) = guard.conn.close(app, error_code, reason) {
            log::warn!(
                "{} connection close returned error (error_code={}, reason={:?}): {:?}",
                kind,
                error_code,
                reason,
                e
            );
        }
        log::info!("{} connection closed: error={}, reason={:?}", kind, error_code, reason);
    }

    // ========================================================================
    // Config builders
    // ========================================================================

    fn build_transport_config(
        config: &EngineConfig,
    ) -> Result<crate::transport::Config, EngineError> {
        let mut tc = crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
            .map_err(|e| EngineError::Config(format!("Transport config error: {:?}", e)))?;
        let versions = config
            .transport
            .quic_versions
            .iter()
            .map(|version| version.wire_version())
            .collect::<Vec<_>>();
        tc.set_supported_versions(versions)
            .map_err(|e| EngineError::Config(format!("QUIC version config error: {e}")))?;

        tc.set_max_idle_timeout(config.transport.max_idle_timeout);
        tc.set_max_recv_udp_payload_size(config.transport.max_udp_payload as usize);
        tc.set_max_send_udp_payload_size(config.transport.mtu as usize);
        tc.enable_pacing(config.transport.enable_pacing);
        tc.set_initial_rtt_ms(config.transport.initial_rtt_ms);
        tc.set_initial_max_data(config.transport.initial_max_data);
        tc.set_initial_max_stream_data_bidi_local(
            config.transport.initial_max_stream_data_bidi_local,
        );
        tc.set_initial_max_stream_data_bidi_remote(
            config.transport.initial_max_stream_data_bidi_remote,
        );
        tc.set_initial_max_streams_bidi(config.transport.initial_max_streams_bidi);
        tc.set_initial_max_stream_data_uni(config.transport.initial_max_stream_data_uni);
        tc.set_initial_max_streams_uni(config.transport.initial_max_streams_uni);

        tc.set_pmtu_policy(crate::transport::PmtuPolicy {
            min_mtu: usize::from(config.transport.pmtu_min_mtu),
            max_mtu: usize::from(config.transport.pmtu_max_mtu),
            probe_interval: std::time::Duration::from_millis(
                config.transport.pmtu_probe_interval_ms,
            ),
            black_hole_timeout: std::time::Duration::from_millis(
                config.transport.pmtu_black_hole_timeout_ms,
            ),
        })
        .map_err(|error| EngineError::Config(format!("DPLPMTUD policy invalid: {error}")))?;
        if config.transport.disable_pmtud {
            tc.discover_pmtu(false);
        }

        if config.transport.dgram_recv_queue_len > 0 {
            tc.enable_dgram(
                config.transport.dgram_recv_queue_len,
                config.transport.dgram_send_queue_len,
            );
        }

        // Enable early data if configured
        if config.transport.enable_early_data {
            tc.enable_early_data();
        }

        tc.set_disable_active_migration(!config.connection.enable_migration);
        tc.set_migration_policy(crate::transport::MigrationPolicy {
            port_rebinding_cwnd_factor: config.connection.migration_cwnd_reduction_factor,
            cooldown: std::time::Duration::from_millis(config.connection.migration_cooldown_ms),
            probe_target: config.connection.migration_probe_target,
        })
        .map_err(|e| EngineError::Config(format!("Migration policy invalid: {e}")))?;

        tc.set_nat_traversal(
            config
                .nat_traversal
                .to_transport_config()
                .map_err(|e| EngineError::Config(format!("NAT traversal config invalid: {e}")))?,
        );

        if let Some(id) = config.connection.qkey_id.as_deref() {
            let id = id.trim();
            if !id.is_empty() {
                tc.set_initial_token(Some(id.as_bytes().to_vec()));
            }
        }

        // CC algorithm
        match config.transport.cc_algorithm {
            crate::engine::CcAlgorithm::Reno => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno)
            }
            crate::engine::CcAlgorithm::Cubic => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Cubic)
            }
            crate::engine::CcAlgorithm::Bbr2 => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::BBR2)
            }
            crate::engine::CcAlgorithm::Bbr3 => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::BBR3)
            }
        }

        tc.set_traffic_analysis_policy(config.transport.traffic_analysis).map_err(|error| {
            EngineError::Config(format!("traffic-analysis policy invalid: {error}"))
        })?;
        tc.set_qkey_traffic_analysis_ceiling(config.transport.qkey_traffic_analysis_ceiling)
            .map_err(|error| {
                EngineError::Config(format!("QKey traffic-analysis ceiling invalid: {error}"))
            })?;
        tc.set_intelligent_traffic_analysis_ceiling(
            config.transport.intelligent_traffic_analysis_ceiling,
        )
        .map_err(|error| {
            EngineError::Config(format!("Intelligent traffic-analysis ceiling invalid: {error}"))
        })?;

        Ok(tc)
    }

    fn build_stealth_config(
        config: &EngineConfig,
    ) -> Result<crate::stealth::StealthConfig, EngineError> {
        config
            .stealth
            .to_runtime_config(&config.fingerprint_rotation)
            .map_err(|error| EngineError::Config(format!("Stealth config error: {error}")))
    }

    fn should_use_utls(config: &EngineConfig) -> bool {
        config.stealth.use_utls && !matches!(config.stealth.mode, crate::engine::StealthMode::Off)
    }

    fn build_fec_config(config: &EngineConfig) -> Result<crate::fec::FecConfig, EngineError> {
        config
            .fec
            .to_runtime_config()
            .map_err(|error| EngineError::Config(format!("FEC config error: {error}")))
    }

    fn build_optimize_config(
        config: &EngineConfig,
    ) -> Result<crate::optimize::OptimizeConfig, EngineError> {
        config
            .optimization
            .to_runtime_config()
            .map_err(|error| EngineError::Config(format!("Optimization config error: {error}")))
    }
}

/// Determine the SNI for a connection.
///
/// A configured value stays authoritative; only the fallback is derived, and it comes
/// from the already validated `SocketAddr` rather than from splitting the remote string
/// on ':'. That split is only correct for `host:port`: for the bracketed IPv6 form
/// `[2001:db8::1]:4433` it yields `[`, which then travelled into the stealth headers
/// and the TLS configuration, so a dual-stack deployment failed on one family only.
/// Because `connection.remote` must parse as a `SocketAddr`, the endpoint is always an
/// IP literal here, and the fallback is that literal, matching `qf-e2e-client`.
fn derive_sni(configured: &str, remote: SocketAddr) -> String {
    if configured.is_empty() {
        remote.ip().to_string()
    } else {
        configured.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_falls_back_to_the_endpoint_host_for_every_address_family() {
        // The old `remote.split(':').next()` derived "[" from a bracketed IPv6
        // authority and sent that as the SNI, so the defect was invisible on IPv4 and
        // broke exactly one half of a dual-stack deployment.
        let ipv4: SocketAddr = "203.0.113.10:4433".parse().expect("IPv4 endpoint");
        assert_eq!(derive_sni("", ipv4), "203.0.113.10");

        let ipv6: SocketAddr = "[2001:db8::1]:4433".parse().expect("IPv6 endpoint");
        assert_eq!(derive_sni("", ipv6), "2001:db8::1");
        assert!(!derive_sni("", ipv6).contains('['), "the bracket is socket syntax, not a host");

        let loopback6: SocketAddr = "[::1]:4433".parse().expect("IPv6 loopback endpoint");
        assert_eq!(derive_sni("", loopback6), "::1");
    }

    #[test]
    fn a_configured_sni_stays_authoritative_for_every_address_family() {
        for endpoint in ["203.0.113.10:4433", "[2001:db8::1]:4433"] {
            let remote: SocketAddr = endpoint.parse().expect("endpoint");
            assert_eq!(derive_sni("vpn.example.com", remote), "vpn.example.com");
        }
    }

    fn make_client_connection() -> ClientConnection {
        let config = EngineConfig::default();
        let local_addr = "127.0.0.1:10000".parse().unwrap();
        let remote_addr = "127.0.0.1:10001".parse().unwrap();
        let conn = QuicFuscateConnection::new_client(
            "localhost",
            local_addr,
            remote_addr,
            ClientConnection::build_transport_config(&config).unwrap(),
            ClientConnection::build_stealth_config(&config).unwrap(),
            ClientConnection::build_fec_config(&config).unwrap(),
            ClientConnection::build_optimize_config(&config).unwrap(),
            None,
            None,
            false,
        )
        .unwrap();

        ClientConnection { inner: Arc::new(parking_lot::Mutex::new(conn)), remote_addr, local_addr }
    }

    #[test]
    fn test_build_configs() {
        let config = EngineConfig::default();

        let tc = ClientConnection::build_transport_config(&config);
        assert!(tc.is_ok());
        let tc = tc.unwrap();
        assert_eq!(tc.version(), crate::transport::PROTOCOL_VERSION_V2);
        assert_eq!(
            tc.supported_versions(),
            &[crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION]
        );

        let sc = ClientConnection::build_stealth_config(&config).unwrap();
        assert!(sc.max_padding_size > 0);
        assert_eq!(sc.mode, crate::stealth::StealthMode::Intelligent);
        assert!(!sc.enable_domain_fronting);
        assert!(ClientConnection::should_use_utls(&config));

        let fc = ClientConnection::build_fec_config(&config).unwrap();
        assert!(fc.burst_window > 0);

        let oc = ClientConnection::build_optimize_config(&config).unwrap();
        assert!(oc.pool_capacity > 0);
    }

    #[test]
    fn test_client_transport_config_carries_nat_traversal_policy() {
        let mut config = EngineConfig::default();
        config.nat_traversal.enabled = true;
        config.nat_traversal.mode = crate::transport::NatTraversalMode::ConnectivityFallback;
        config.nat_traversal.ice_enabled = true;
        config.nat_traversal.stun_servers = vec!["203.0.113.10:3478".to_string()];

        let tc = ClientConnection::build_transport_config(&config).unwrap();
        let nat = tc.nat_traversal();
        assert!(nat.enabled);
        assert_eq!(nat.mode, crate::transport::NatTraversalMode::ConnectivityFallback);
        assert!(nat.ice_enabled);
        assert_eq!(nat.stun_servers.len(), 1);
    }

    #[test]
    fn test_client_transport_config_carries_migration_policy() {
        let mut config = EngineConfig::default();
        config.connection.enable_migration = false;
        config.connection.migration_cwnd_reduction_factor = 1.0;
        config.connection.migration_cooldown_ms = 1250;
        config.connection.migration_probe_target =
            crate::transport::MigrationProbeTarget::ReducedWindow;

        let tc = ClientConnection::build_transport_config(&config).unwrap();
        assert!(tc.disable_active_migration);
        let policy = tc.migration_policy();
        assert_eq!(policy.port_rebinding_cwnd_factor, 1.0);
        assert_eq!(policy.cooldown, std::time::Duration::from_millis(1250));
        assert_eq!(policy.probe_target, crate::transport::MigrationProbeTarget::ReducedWindow);
    }

    #[test]
    fn test_client_transport_config_carries_all_traffic_analysis_policies() {
        let active = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 25,
            chaff_size_bytes: 1200,
            constant_rate_pps: 0,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };
        let qkey_ceiling = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 500,
            chaff_size_bytes: 1400,
            constant_rate_pps: 100,
            idle_timeout_ms: 60_000,
            ramp_down_ms: 10_000,
        };
        let intelligent_ceiling = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1000,
            constant_rate_pps: 0,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };
        let mut config = EngineConfig::default();
        config.transport.traffic_analysis = active;
        config.transport.qkey_traffic_analysis_ceiling = qkey_ceiling;
        config.transport.intelligent_traffic_analysis_ceiling = intelligent_ceiling;

        let transport =
            ClientConnection::build_transport_config(&config).expect("transport config");
        assert_eq!(transport.traffic_analysis_policy(), active);
        assert_eq!(transport.qkey_traffic_analysis_ceiling(), qkey_ceiling);
        assert_eq!(transport.intelligent_traffic_analysis_ceiling(), intelligent_ceiling);
    }

    #[test]
    fn test_utls_disabled_for_off_mode_and_explicit_opt_out() {
        let mut config = EngineConfig::default();
        config.stealth.mode = crate::engine::StealthMode::Off;
        assert!(!ClientConnection::should_use_utls(&config));

        config.stealth.mode = crate::engine::StealthMode::Stealth;
        config.stealth.use_utls = false;
        assert!(!ClientConnection::should_use_utls(&config));
    }

    #[test]
    fn test_stealth_builder_applies_persona_and_protocol_bundle() {
        let mut config = EngineConfig::default();
        config.stealth.mode = crate::engine::StealthMode::Manual;
        config.stealth.enable_protocol_mimicry = true;
        config.stealth.enable_http3_masquerading = false;
        config.stealth.use_qpack_headers = false;
        config.stealth.use_tls_cover = false;
        config.stealth.initial_browser = "firefox".to_string();
        config.stealth.initial_os = "linux".to_string();
        config.stealth.enable_network_fingerprint_normalization = false;
        config.stealth.suppress_icmp_unreachable = true;
        config.stealth.padding_strategy = "browser-mimic".to_string();

        let sc = ClientConnection::build_stealth_config(&config).unwrap();
        assert_eq!(sc.mode, crate::stealth::StealthMode::Manual);
        assert_eq!(sc.initial_browser, crate::stealth::BrowserProfile::Firefox);
        assert_eq!(sc.initial_os, crate::stealth::OsProfile::Linux);
        assert!(!sc.enable_network_fingerprint_normalization);
        assert!(sc.suppress_icmp_unreachable);
        assert_eq!(sc.padding_strategy, crate::stealth::PaddingStrategy::BrowserMimic);
        assert!(sc.enable_http3_masquerading);
        assert!(sc.use_qpack_headers);
        assert!(sc.use_tls_cover);
    }

    #[test]
    fn public_close_reports_application_error_and_is_idempotent() {
        let mut client = make_client_connection();

        client.close(7, b"application shutdown");
        client.close_transport(8, b"later transport shutdown");

        assert_eq!(
            client.local_error(),
            Some(crate::error::ConnectionError::LocalApplicationClosed {
                error_code: 7,
                reason: b"application shutdown".to_vec(),
            })
        );
        assert_eq!(client.error(), client.local_error());
        assert!(client.remote_error().is_none());
        assert!(client.is_closed());
    }

    #[test]
    fn public_transport_close_reports_transport_error() {
        let mut client = make_client_connection();

        client.close_transport(9, b"transport shutdown");

        assert_eq!(
            client.local_error(),
            Some(crate::error::ConnectionError::LocalConnectionClosed {
                error_code: 9,
                frame_type: 0,
                reason: b"transport shutdown".to_vec(),
            })
        );
        assert!(client.is_closed());
    }
}
