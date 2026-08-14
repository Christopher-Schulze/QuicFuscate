//! Client connection wrapper for QuicFuscateConnection.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use crate::core::QuicFuscateConnection;
use crate::implementations::client::circuit_runtime::{ClientDataPlane, HopFactory};
use crate::stealth::StealthRuntimeOwner;
use crate::time_source::ProtocolClock;
use qf_engine_types::{EngineConfig, EngineError};

/// Client connection wrapper.
///
/// Wraps `QuicFuscateConnection` and provides a streamlined interface
/// for the client runtime.
pub struct ClientConnection {
    inner: Arc<parking_lot::Mutex<ClientDataPlane>>,
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
        let stealth_config = Self::resolve_stealth_config(config, runtime_owner.as_ref())?;
        Self::connect_with_stealth_config(config, runtime_owner, stealth_config, clock)
    }

    fn connect_with_stealth_config(
        config: &EngineConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        stealth_config: crate::stealth::StealthConfig,
        clock: &ProtocolClock,
    ) -> Result<Self, EngineError> {
        // Record connection attempt
        crate::instrumentation::global().client.connection_attempt();

        let local_addr: SocketAddr = if config.connection.local.is_empty() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            config.connection.local.parse().map_err(|e| {
                crate::instrumentation::global().client.connection_failure();
                EngineError::Config(format!("Invalid local address: {}", e))
            })?
        };

        let migrated_topology = legacy_circuit_config(config);
        let topology = config.circuit.as_ref().or(migrated_topology.as_ref());
        let (data_plane, remote_addr) = if let Some(topology) = topology {
            topology
                .validate(config.transport.mtu.min(config.transport.max_udp_payload))
                .map_err(|error| EngineError::Config(error.to_string()))?;
            let hop_count = topology.hops.len();
            let entry_hop = topology.hops.first().ok_or_else(|| {
                EngineError::Config("validated circuit has no entry hop".to_string())
            })?;
            let entry_addr = configured_hop_endpoint(entry_hop, 0)?;
            let entry = Self::build_configured_circuit_hop(
                config,
                &stealth_config,
                runtime_owner.clone(),
                clock,
                local_addr,
                entry_hop,
                0,
                hop_count,
            )?;
            let pending_hops = topology
                .hops
                .iter()
                .cloned()
                .enumerate()
                .skip(1)
                .map(|(index, hop)| {
                    let config = config.clone();
                    let stealth_config = stealth_config.clone();
                    let runtime_owner = runtime_owner.clone();
                    let clock = clock.clone();
                    Box::new(move || {
                        Self::build_configured_circuit_hop(
                            &config,
                            &stealth_config,
                            runtime_owner,
                            &clock,
                            local_addr,
                            &hop,
                            index,
                            hop_count,
                        )
                    }) as HopFactory
                })
                .collect::<std::collections::VecDeque<_>>();
            (ClientDataPlane::circuit(topology.clone(), entry, pending_hops)?, entry_addr)
        } else {
            let remote_addr = resolve_endpoint(&config.connection.remote)?;
            let sni = derive_sni(&config.connection.sni, remote_addr);
            let qkey_token =
                config.connection.qkey_token.clone().filter(|token| !token.trim().is_empty());
            let qkey_initial_token =
                config.connection.qkey_id.as_ref().map(|id| id.as_bytes().to_vec()).or_else(|| {
                    qkey_token.as_deref().map(|raw| qf_engine_types::id(raw.trim()).into_bytes())
                });
            let connection = Self::build_core_connection(
                config,
                stealth_config,
                Self::build_fec_config(config)?,
                runtime_owner,
                clock,
                local_addr,
                remote_addr,
                &sni,
                config.connection.verify_peer,
                &config.connection.ca_file,
                config.connection.idle_timeout_ms,
                config.transport.mtu.min(config.transport.max_udp_payload),
                qkey_token,
                qkey_initial_token,
            )?;
            (ClientDataPlane::single(connection), remote_addr)
        };

        // Record success
        crate::instrumentation::global().client.connection_success();
        log::info!("QUIC connection established to {}", remote_addr);

        Ok(Self { inner: Arc::new(parking_lot::Mutex::new(data_plane)), remote_addr, local_addr })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_core_connection(
        config: &EngineConfig,
        stealth_config: crate::stealth::StealthConfig,
        fec_config: crate::fec::FecConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: &ProtocolClock,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        sni: &str,
        verify_peer: bool,
        ca_file: &str,
        idle_timeout_ms: u64,
        udp_payload_limit: u16,
        qkey_token: Option<qf_engine_types::QKeyToken>,
        qkey_initial_token: Option<Vec<u8>>,
    ) -> Result<QuicFuscateConnection, EngineError> {
        let mut transport_config = Self::build_transport_config(config, udp_payload_limit)?;
        transport_config.set_max_idle_timeout(idle_timeout_ms);
        transport_config.verify_peer(verify_peer);
        if !ca_file.trim().is_empty() {
            transport_config
                .load_verify_locations_from_file(ca_file)
                .map_err(|error| EngineError::Config(error.to_string()))?;
        }
        log::info!("Connecting circuit hop to {} (SNI: {}) from {}", remote_addr, sni, local_addr);
        let mut connection = QuicFuscateConnection::new_client_with_runtime_and_clock(
            sni,
            local_addr,
            remote_addr,
            transport_config,
            stealth_config,
            fec_config,
            Self::build_optimize_config(config)?,
            qkey_token,
            qkey_initial_token,
            Self::should_use_utls(config),
            runtime_owner,
            None,
            clock.clone(),
        )
        .map_err(EngineError::Connection)?;
        connection.set_private_packet_protection_policy(
            config.crypto.packet_protection_mode,
            config.crypto.private_family(),
        );
        Ok(connection)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_configured_circuit_hop(
        config: &EngineConfig,
        base_stealth_config: &crate::stealth::StealthConfig,
        runtime_owner: Option<Arc<StealthRuntimeOwner>>,
        clock: &ProtocolClock,
        physical_local_addr: SocketAddr,
        hop: &qf_engine_types::HopConfig,
        index: usize,
        hop_count: usize,
    ) -> Result<QuicFuscateConnection, EngineError> {
        let remote_addr = configured_hop_endpoint(hop, index)?;
        let local_addr = if index == 0 {
            physical_local_addr
        } else if remote_addr.is_ipv4() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))
        };
        let token = match hop.qkey_token.clone() {
            Some(token) => Some(token),
            None => resolve_qkey_token_reference(&hop.qkey_token_ref)?,
        };
        let outer_payload = config.transport.mtu.min(config.transport.max_udp_payload);
        let encapsulation = u16::try_from(index)
            .ok()
            .and_then(|depth| qf_engine_types::NESTED_MASQUE_OVERHEAD.checked_mul(depth))
            .ok_or_else(|| EngineError::Config("circuit datagram budget overflow".to_string()))?;
        let hop_payload = outer_payload
            .checked_sub(encapsulation)
            .ok_or_else(|| EngineError::Config("circuit datagram budget underflow".to_string()))?;
        let stealth_config = Self::apply_hop_stealth_policy(base_stealth_config, &hop.policy)?;
        let fec_config = Self::build_hop_fec_config(config, &hop.policy, index, hop_count)?;
        Self::build_core_connection(
            config,
            stealth_config,
            fec_config,
            runtime_owner,
            clock,
            local_addr,
            remote_addr,
            &hop.sni,
            hop.verify_peer,
            &hop.ca_file,
            hop.idle_timeout_ms,
            hop_payload,
            token,
            Some(hop.qkey_id.as_bytes().to_vec()),
        )
    }

    fn resolve_stealth_config(
        config: &EngineConfig,
        runtime_owner: Option<&Arc<StealthRuntimeOwner>>,
    ) -> Result<crate::stealth::StealthConfig, EngineError> {
        if let Some(snapshot) = runtime_owner.and_then(|owner| owner.next_session_stealth_config())
        {
            snapshot.validate().map_err(|error| {
                EngineError::Config(format!("Invalid next-session stealth configuration: {error}"))
            })?;
            return Ok(snapshot);
        }
        Self::build_stealth_config(config)
    }

    /// Send data through the QUIC connection.
    ///
    /// Returns the number of bytes written to the buffer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.send_physical(buf)
    }

    /// Receive data from the QUIC connection.
    ///
    /// Returns the number of bytes processed.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.recv_physical(data)
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
        guard.exit().stealth_manager()
    }

    /// Get the underlying connection (for advanced usage).
    pub(super) fn shared(&self) -> Arc<parking_lot::Mutex<ClientDataPlane>> {
        self.inner.clone()
    }

    /// Return the bounded circuit lifecycle without exposing credentials or endpoints.
    pub fn circuit_lifecycle_state(&self) -> crate::implementations::client::CircuitLifecycleState {
        self.inner.lock().lifecycle_state()
    }

    /// Return bounded per-hop health without endpoint or credential material.
    pub fn circuit_diagnostics(&self) -> crate::implementations::client::CircuitDiagnostics {
        self.inner.lock().diagnostics()
    }

    /// Mark the active generation as draining before its data-plane tasks stop.
    pub fn mark_circuit_draining(&self) {
        self.inner.lock().mark_draining();
    }

    /// Mark an authenticated VPN-contained fallback as usable but privacy-degraded.
    pub fn mark_circuit_degraded(&self) {
        self.inner.lock().mark_degraded();
    }

    /// Check if the connection is established.
    pub fn is_established(&self) -> bool {
        let guard = self.inner.lock();
        guard.circuit_ready()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        let guard = self.inner.lock();
        guard.physical().conn.is_closed() || guard.exit().conn.is_closed()
    }

    /// Returns the duration elapsed since the last inbound packet was received.
    /// Used by the heartbeat watchdog to detect connection loss.
    pub fn last_activity_elapsed(&self) -> std::time::Duration {
        let guard = self.inner.lock();
        guard.last_activity_elapsed()
    }

    /// Get RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        let guard = self.inner.lock();
        guard.exit().rtt_ms()
    }

    /// Get packet loss rate.
    pub fn loss_rate(&self) -> f32 {
        let guard = self.inner.lock();
        guard.exit().loss_rate()
    }

    /// Apply and observe an active FEC policy change under the connection owner.
    pub fn set_fec_control_policy(
        &self,
        policy: crate::fec::FecControlPolicy,
    ) -> crate::fec::ActiveFecPolicyChange {
        let mut guard = self.inner.lock();
        guard.exit_mut().set_fec_control_policy(policy)
    }

    /// Return exact active FEC policy, mode, and wire counters.
    pub fn fec_telemetry_snapshot(&self) -> crate::fec::FecTelemetrySnapshot {
        let guard = self.inner.lock();
        guard.exit().fec_telemetry_snapshot()
    }

    /// Get the effective stealth mode currently used by the live connection.
    pub fn stealth_mode(&self) -> crate::stealth::StealthMode {
        let guard = self.inner.lock();
        guard.exit().stealth_mode()
    }

    /// Get the effective TLS SNI currently used by the live connection.
    pub fn server_name(&self) -> Option<String> {
        let guard = self.inner.lock();
        guard.exit().server_name()
    }

    /// Return the terminal error, preferring the first local root cause.
    pub fn error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.error()
    }

    /// Return the first locally decided terminal or protocol error.
    pub fn local_error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.local_error()
    }

    /// Return the first close reason received from the peer.
    pub fn remote_error(&self) -> Option<crate::error::ConnectionError> {
        let guard = self.inner.lock();
        guard.remote_error()
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
        guard.close_all(app, error_code, reason);
        log::info!("{} connection closed: error={}, reason={:?}", kind, error_code, reason);
    }

    // ========================================================================
    // Config builders
    // ========================================================================

    fn build_transport_config(
        config: &EngineConfig,
        udp_payload_limit: u16,
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
        tc.set_max_recv_udp_payload_size(usize::from(udp_payload_limit));
        tc.set_max_send_udp_payload_size(usize::from(udp_payload_limit));
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
            min_mtu: usize::from(config.transport.pmtu_min_mtu.min(udp_payload_limit)),
            max_mtu: usize::from(config.transport.pmtu_max_mtu.min(udp_payload_limit)),
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
            qf_transport_cc::cc::Algorithm::Reno => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno)
            }
            qf_transport_cc::cc::Algorithm::Cubic => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Cubic)
            }
            qf_transport_cc::cc::Algorithm::Bbr2 => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::BBR2)
            }
            qf_transport_cc::cc::Algorithm::Bbr3 => {
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

    fn apply_hop_stealth_policy(
        base: &crate::stealth::StealthConfig,
        policy: &qf_engine_types::HopPolicyOverrides,
    ) -> Result<crate::stealth::StealthConfig, EngineError> {
        let mut resolved = base.clone();
        if let Some(persona) = policy.persona {
            resolved.initial_browser = persona.browser;
            resolved.initial_os = persona.os;
            resolved.enable_fingerprint_rotation = false;
            resolved.fingerprint_rotation_profiles.clear();
        }
        if let Some(enabled) = policy.enable_traffic_padding {
            resolved.enable_traffic_padding = enabled;
        }
        if let Some(enabled) = policy.enable_timing_obfuscation {
            resolved.enable_timing_obfuscation = enabled;
        }
        if let Some(enabled) = policy.enable_cover_ping {
            resolved.enable_cover_ping = enabled;
        }
        resolved.normalize_protocol_mimicry_bundle();
        resolved.validate().map_err(|error| {
            EngineError::Config(format!("Invalid per-hop stealth policy: {error}"))
        })?;
        Ok(resolved)
    }

    fn should_use_utls(config: &EngineConfig) -> bool {
        config.stealth.use_utls && !matches!(config.stealth.mode, qf_engine_types::StealthMode::Off)
    }

    fn build_fec_config(config: &EngineConfig) -> Result<crate::fec::FecConfig, EngineError> {
        config
            .fec
            .to_runtime_config()
            .map_err(|error| EngineError::Config(format!("FEC config error: {error}")))
    }

    fn build_hop_fec_config(
        config: &EngineConfig,
        policy: &qf_engine_types::HopPolicyOverrides,
        hop_index: usize,
        hop_count: usize,
    ) -> Result<crate::fec::FecConfig, EngineError> {
        let mut section = config.fec.clone();
        let mode = policy.fec_mode.unwrap_or_else(|| {
            if hop_index + 1 == hop_count {
                config.fec.mode
            } else {
                qf_engine_types::FecMode::Off
            }
        });
        if mode != section.mode {
            section.mode = mode;
            section.initial_mode = match mode {
                qf_engine_types::FecMode::Off => "off",
                qf_engine_types::FecMode::Auto => "auto",
            }
            .to_string();
        }
        section
            .to_runtime_config()
            .map_err(|error| EngineError::Config(format!("Per-hop FEC config error: {error}")))
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

fn legacy_circuit_config(config: &EngineConfig) -> Option<qf_engine_types::CircuitConfig> {
    let token = config.connection.qkey_token.clone()?;
    let endpoint = config.connection.remote.trim();
    if endpoint.is_empty() {
        return None;
    }
    let sni = if config.connection.sni.trim().is_empty() {
        endpoint.parse::<SocketAddr>().map(|address| address.ip().to_string()).unwrap_or_else(
            |_| {
                endpoint
                    .rsplit_once(':')
                    .map_or(endpoint, |(host, _)| host)
                    .trim_matches(['[', ']'])
                    .to_string()
            },
        )
    } else {
        config.connection.sni.trim().to_string()
    };
    let qkey_id =
        config.connection.qkey_id.clone().unwrap_or_else(|| qf_engine_types::id(token.as_ref()));
    Some(qf_engine_types::CircuitConfig {
        hops: vec![qf_engine_types::HopConfig {
            label: "Legacy single hop".to_string(),
            endpoint: endpoint.to_string(),
            sni,
            verify_peer: config.connection.verify_peer,
            ca_file: config.connection.ca_file.clone(),
            qkey_id,
            qkey_token_ref: "runtime:legacy-connection".to_string(),
            qkey_token: Some(token),
            role: qf_engine_types::HopRole::Exit,
            idle_timeout_ms: config.connection.idle_timeout_ms,
            ..qf_engine_types::HopConfig::default()
        }],
        max_hops: 1,
        ..qf_engine_types::CircuitConfig::default()
    })
}

fn resolve_endpoint(authority: &str) -> Result<SocketAddr, EngineError> {
    authority
        .to_socket_addrs()
        .map_err(|error| EngineError::Config(format!("endpoint resolution failed: {error}")))?
        .next()
        .ok_or_else(|| EngineError::Config(format!("endpoint resolved to no address: {authority}")))
}

fn configured_hop_endpoint(
    hop: &qf_engine_types::HopConfig,
    index: usize,
) -> Result<SocketAddr, EngineError> {
    if index == 0 {
        return match hop.pinned_endpoint {
            Some(endpoint) => Ok(endpoint),
            None => resolve_endpoint(&hop.endpoint),
        };
    }
    logical_inner_endpoint(hop, index)
}

fn logical_inner_endpoint(
    hop: &qf_engine_types::HopConfig,
    index: usize,
) -> Result<SocketAddr, EngineError> {
    let endpoint = hop.parsed_endpoint().map_err(|error| EngineError::Config(error.to_string()))?;
    if let Ok(address) = hop.endpoint.parse::<SocketAddr>() {
        return Ok(address);
    }
    let host = endpoint.host.parse::<std::net::IpAddr>().ok();
    let ip = match host {
        Some(ip) => ip,
        None => {
            let suffix = u8::try_from(index.saturating_add(1)).map_err(|_| {
                EngineError::Config("circuit logical endpoint index overflow".to_string())
            })?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, suffix))
        }
    };
    Ok(SocketAddr::new(ip, endpoint.port))
}

fn resolve_qkey_token_reference(
    reference: &str,
) -> Result<Option<qf_engine_types::QKeyToken>, EngineError> {
    let reference = reference.trim();
    let value = if let Some(name) = reference.strip_prefix("env:") {
        if name.is_empty() {
            return Err(EngineError::Config("empty QKey environment reference".to_string()));
        }
        std::env::var(name).map_err(|_| {
            EngineError::Config(format!("QKey environment reference is unavailable: {name}"))
        })?
    } else if let Some(path) = reference.strip_prefix("file:") {
        if path.is_empty() {
            return Err(EngineError::Config("empty QKey file reference".to_string()));
        }
        std::fs::read_to_string(path)
            .map_err(|error| EngineError::Config(format!("QKey file reference failed: {error}")))?
    } else if let Some(specifier) = reference.strip_prefix("keychain:") {
        let (service, account) = specifier.split_once('/').ok_or_else(|| {
            EngineError::Config(
                "QKey keychain reference must use keychain:service/account".to_string(),
            )
        })?;
        let output = std::process::Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .map_err(|error| {
                EngineError::Config(format!("QKey keychain lookup failed: {error}"))
            })?;
        if !output.status.success() {
            return Err(EngineError::Config("QKey keychain reference was not found".to_string()));
        }
        String::from_utf8(output.stdout)
            .map_err(|_| EngineError::Config("QKey keychain value is not UTF-8".to_string()))?
    } else {
        return Err(EngineError::Config(
            "QKey token reference must use env:, file:, or keychain:service/account".to_string(),
        ));
    };
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError::Config(
            "resolved QKey token must contain exactly 64 hexadecimal characters".to_string(),
        ));
    }
    Ok(Some(qf_engine_types::QKeyToken::new(value.to_ascii_lowercase())))
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

    #[test]
    fn authenticated_legacy_connection_projects_to_the_canonical_one_hop_circuit() {
        let mut config = EngineConfig::default();
        config.connection.remote = "203.0.113.10:4433".to_string();
        config.connection.sni = "exit.example.com".to_string();
        config.connection.qkey_token = Some(qf_engine_types::QKeyToken::new("a".repeat(64)));

        let circuit = legacy_circuit_config(&config).expect("legacy circuit projection");

        assert_eq!(circuit.hops.len(), 1);
        assert_eq!(circuit.max_hops, 1);
        assert_eq!(circuit.hops[0].role, qf_engine_types::HopRole::Exit);
        assert_eq!(circuit.hops[0].endpoint, "203.0.113.10:4433");
        assert_eq!(circuit.hops[0].sni, "exit.example.com");
        assert!(circuit.hops[0].qkey_token.is_some());
        circuit
            .validate(config.transport.mtu.min(config.transport.max_udp_payload))
            .expect("projected circuit validates");
    }

    #[test]
    fn unauthenticated_legacy_connection_keeps_the_compatibility_path() {
        assert!(legacy_circuit_config(&EngineConfig::default()).is_none());
    }

    fn make_client_connection() -> ClientConnection {
        let config = EngineConfig::default();
        let local_addr = "127.0.0.1:10000".parse().unwrap();
        let remote_addr = "127.0.0.1:10001".parse().unwrap();
        let conn = QuicFuscateConnection::new_client(
            "localhost",
            local_addr,
            remote_addr,
            ClientConnection::build_transport_config(
                &config,
                config.transport.mtu.min(config.transport.max_udp_payload),
            )
            .unwrap(),
            ClientConnection::build_stealth_config(&config).unwrap(),
            ClientConnection::build_fec_config(&config).unwrap(),
            ClientConnection::build_optimize_config(&config).unwrap(),
            None,
            None,
            false,
        )
        .unwrap();

        ClientConnection {
            inner: Arc::new(parking_lot::Mutex::new(ClientDataPlane::single(conn))),
            remote_addr,
            local_addr,
        }
    }

    #[test]
    fn test_build_configs() {
        let config = EngineConfig::default();

        let tc = ClientConnection::build_transport_config(
            &config,
            config.transport.mtu.min(config.transport.max_udp_payload),
        );
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
    fn client_stealth_projection_carries_validated_rotation_slots() {
        let mut config = EngineConfig::default();
        config.fingerprint_rotation.enabled = true;
        config.fingerprint_rotation.interval_secs = 21;
        config.fingerprint_rotation.mode = qf_stealth::RotationMode::Slots;
        config.fingerprint_rotation.profile_slots =
            vec!["firefox@linux".to_string(), "safari@macos".to_string()];
        config.validate().expect("rotation config validates");

        let runtime = ClientConnection::build_stealth_config(&config).expect("runtime config");
        assert!(runtime.enable_fingerprint_rotation);
        assert_eq!(runtime.fingerprint_rotation_interval, 21);
        assert_eq!(runtime.fingerprint_rotation_mode, crate::stealth::RotationMode::Slots);
        assert_eq!(
            runtime.fingerprint_rotation_profiles,
            vec![
                (crate::stealth::BrowserProfile::Firefox, crate::stealth::OsProfile::Linux),
                (crate::stealth::BrowserProfile::Safari, crate::stealth::OsProfile::MacOS),
            ]
        );
    }

    #[test]
    fn client_connection_prefers_runtime_owner_next_session_snapshot() {
        let owner = Arc::new(
            StealthRuntimeOwner::new(crate::reality::RealityConfig::default())
                .expect("runtime owner"),
        );
        let shared = Arc::new(std::sync::Mutex::new(crate::stealth::StealthConfig::default()));
        owner.start(Some(shared.clone()), Vec::new(), 0).expect("publish next-session snapshot");
        {
            let mut config = shared.lock().expect("shared stealth config");
            config.initial_browser = crate::stealth::BrowserProfile::Firefox;
            config.initial_os = crate::stealth::OsProfile::Linux;
        }

        let runtime =
            ClientConnection::resolve_stealth_config(&EngineConfig::default(), Some(&owner))
                .expect("next-session snapshot");
        assert_eq!(runtime.initial_browser, crate::stealth::BrowserProfile::Firefox);
        assert_eq!(runtime.initial_os, crate::stealth::OsProfile::Linux);
        owner.request_shutdown();
    }

    #[test]
    fn test_client_transport_config_carries_nat_traversal_policy() {
        let mut config = EngineConfig::default();
        config.nat_traversal.enabled = true;
        config.nat_traversal.mode = crate::transport::NatTraversalMode::ConnectivityFallback;
        config.nat_traversal.ice_enabled = true;
        config.nat_traversal.stun_servers = vec!["203.0.113.10:3478".to_string()];

        let tc = ClientConnection::build_transport_config(
            &config,
            config.transport.mtu.min(config.transport.max_udp_payload),
        )
        .unwrap();
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

        let tc = ClientConnection::build_transport_config(
            &config,
            config.transport.mtu.min(config.transport.max_udp_payload),
        )
        .unwrap();
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

        let transport = ClientConnection::build_transport_config(
            &config,
            config.transport.mtu.min(config.transport.max_udp_payload),
        )
        .expect("transport config");
        assert_eq!(transport.traffic_analysis_policy(), active);
        assert_eq!(transport.qkey_traffic_analysis_ceiling(), qkey_ceiling);
        assert_eq!(transport.intelligent_traffic_analysis_ceiling(), intelligent_ceiling);
    }

    #[test]
    fn test_utls_disabled_for_off_mode_and_explicit_opt_out() {
        let mut config = EngineConfig::default();
        config.stealth.mode = qf_engine_types::StealthMode::Off;
        assert!(!ClientConnection::should_use_utls(&config));

        config.stealth.mode = qf_engine_types::StealthMode::Stealth;
        config.stealth.use_utls = false;
        assert!(!ClientConnection::should_use_utls(&config));
    }

    #[test]
    fn test_stealth_builder_applies_persona_and_protocol_bundle() {
        let mut config = EngineConfig::default();
        config.stealth.mode = qf_engine_types::StealthMode::Manual;
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
    fn per_hop_policy_freezes_persona_and_overrides_segment_behaviors() {
        let mut base = ClientConnection::build_stealth_config(&EngineConfig::default()).unwrap();
        base.enable_fingerprint_rotation = true;
        base.fingerprint_rotation_profiles =
            vec![(crate::stealth::BrowserProfile::Chrome, crate::stealth::OsProfile::Windows)];
        let policy = qf_engine_types::HopPolicyOverrides {
            persona: Some(qf_engine_types::HopPersonaConfig {
                browser: crate::stealth::BrowserProfile::Firefox,
                os: crate::stealth::OsProfile::Linux,
            }),
            fec_mode: Some(qf_engine_types::FecMode::Off),
            enable_traffic_padding: Some(false),
            enable_timing_obfuscation: Some(true),
            enable_cover_ping: Some(false),
        };

        let resolved = ClientConnection::apply_hop_stealth_policy(&base, &policy)
            .expect("valid per-hop policy");
        assert_eq!(resolved.initial_browser, crate::stealth::BrowserProfile::Firefox);
        assert_eq!(resolved.initial_os, crate::stealth::OsProfile::Linux);
        assert!(!resolved.enable_fingerprint_rotation);
        assert!(resolved.fingerprint_rotation_profiles.is_empty());
        assert!(!resolved.enable_traffic_padding);
        assert!(resolved.enable_timing_obfuscation);
        assert!(!resolved.enable_cover_ping);

        let fec = ClientConnection::build_hop_fec_config(&EngineConfig::default(), &policy, 0, 1)
            .expect("valid per-hop FEC policy");
        assert!(matches!(fec.control_policy, crate::fec::FecControlPolicy::Off));
    }

    #[test]
    fn circuit_fec_defaults_to_one_deepest_layer_and_allows_explicit_segment_override() {
        let config = EngineConfig::default();
        let inherited = qf_engine_types::HopPolicyOverrides::default();
        let entry = ClientConnection::build_hop_fec_config(&config, &inherited, 0, 3)
            .expect("entry FEC projection");
        let middle = ClientConnection::build_hop_fec_config(&config, &inherited, 1, 3)
            .expect("middle FEC projection");
        let exit = ClientConnection::build_hop_fec_config(&config, &inherited, 2, 3)
            .expect("exit FEC projection");
        assert!(matches!(entry.control_policy, crate::fec::FecControlPolicy::Off));
        assert!(matches!(middle.control_policy, crate::fec::FecControlPolicy::Off));
        assert!(!matches!(exit.control_policy, crate::fec::FecControlPolicy::Off));

        let explicit = qf_engine_types::HopPolicyOverrides {
            fec_mode: Some(qf_engine_types::FecMode::Auto),
            ..qf_engine_types::HopPolicyOverrides::default()
        };
        let entry = ClientConnection::build_hop_fec_config(&config, &explicit, 0, 3)
            .expect("explicit segment FEC projection");
        assert!(!matches!(entry.control_policy, crate::fec::FecControlPolicy::Off));
    }

    #[test]
    fn inner_hop_construction_waits_for_authenticated_predecessor_link() {
        let config = EngineConfig {
            circuit: Some(qf_engine_types::CircuitConfig {
                hops: vec![
                    qf_engine_types::HopConfig {
                        label: "Entry".to_string(),
                        endpoint: "127.0.0.1:4433".to_string(),
                        sni: "entry.example.com".to_string(),
                        verify_peer: false,
                        qkey_id: "000000000001".to_string(),
                        qkey_token_ref: "runtime:test-entry".to_string(),
                        qkey_token: Some(qf_engine_types::QKeyToken::new("11".repeat(32))),
                        role: qf_engine_types::HopRole::Relay,
                        ..qf_engine_types::HopConfig::default()
                    },
                    qf_engine_types::HopConfig {
                        label: "Exit".to_string(),
                        endpoint: "127.0.0.2:4433".to_string(),
                        sni: "exit.example.com".to_string(),
                        verify_peer: false,
                        qkey_id: "000000000002".to_string(),
                        qkey_token_ref: "unsupported:must-not-resolve-before-link-readiness"
                            .to_string(),
                        role: qf_engine_types::HopRole::Exit,
                        ..qf_engine_types::HopConfig::default()
                    },
                ],
                ..qf_engine_types::CircuitConfig::default()
            }),
            ..EngineConfig::default()
        };

        let connection = ClientConnection::connect(&config)
            .expect("entry construction must not resolve the pending exit credential");
        let diagnostics = connection.circuit_diagnostics();
        assert_eq!(diagnostics.hops.len(), 2);
        assert!(!diagnostics.hops[1].established);
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
    fn degraded_fallback_state_is_persistent_and_observable() {
        let client = make_client_connection();

        client.mark_circuit_degraded();

        assert_eq!(
            client.circuit_diagnostics().lifecycle,
            crate::implementations::client::CircuitLifecycleState::Degraded
        );
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
