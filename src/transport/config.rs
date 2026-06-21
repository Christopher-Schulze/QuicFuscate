use super::{CongestionControlAlgorithm, PROTOCOL_VERSION};
use rustls::pki_types::pem::PemObject;

// ============================================================================

/// QUIC connection configuration
#[derive(Clone)]
pub struct Config {
    pub(crate) version: u32,
    pub(crate) cc_algorithm: CongestionControlAlgorithm,
    pub(crate) application_protos: Vec<Vec<u8>>,
    pub(crate) max_idle_timeout: u64,
    pub(crate) max_udp_payload_size: u64,
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_stream_data_bidi_local: u64,
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    pub(crate) initial_max_stream_data_uni: u64,
    pub(crate) initial_max_streams_bidi: u64,
    pub(crate) initial_max_streams_uni: u64,
    pub(crate) ack_delay_exponent: u64,
    pub(crate) max_ack_delay: u64,
    pub(crate) disable_active_migration: bool,
    /// Enables 0-RTT early data (TLS 1.3 early data / QUIC 0-RTT).
    ///
    /// WARNING: 0-RTT data is inherently replayable. An attacker who captures
    /// a 0-RTT packet can replay it, causing the enclosed request to be processed
    /// multiple times. Per RFC 9001 Section 9.2 and TLS 1.3 RFC 8446 Section 8,
    /// servers SHOULD implement anti-replay mechanisms such as:
    ///   - A strike register (set of seen 0-RTT client hello hashes/tickets)
    ///   - Single-use session tickets
    ///   - Time-bounded ticket expiration enforcement
    ///
    /// Anti-replay is implemented via `StrikeRegister` in `transport::anti_replay`.
    /// The server runtime creates a shared register and injects it via `set_strike_register()`.
    pub(crate) enable_early_data: bool,

    // TLS configuration
    pub(crate) verify_peer: bool,

    // Certificate paths
    pub(crate) cert_chain_path: Option<String>,
    pub(crate) priv_key_path: Option<String>,
    pub(crate) verify_locations_file: Option<String>,
    pub(crate) verify_locations_directory: Option<String>,
    // Parity fields
    pub(crate) dgram_recv_max_queue_len: usize,
    pub(crate) dgram_send_max_queue_len: usize,
    pub(crate) path_challenge_recv_max_queue_len: usize,
    pub(crate) max_connection_window: u64,
    pub(crate) max_stream_window: u64,
    pub(crate) max_amplification_factor: usize,
    pub(crate) send_capacity_factor: f64,
    pub(crate) pmtu_discovery_enabled: bool,
    pub(crate) disable_dcid_reuse: bool,
    pub(crate) track_unknown_transport_params: Option<usize>,
    // Real-TLS knobs
    pub(crate) chlo_template: Option<Vec<u8>>,
    // Pacing / Hystart / Initial CWND / Initial RTT
    pub(crate) pacing: bool,
    pub(crate) max_pacing_rate: Option<u64>,
    pub(crate) hystart: bool,
    pub(crate) initial_congestion_window_packets: usize,
    /// Initial RTT estimate in milliseconds used before real measurements arrive (default: 100).
    pub(crate) initial_rtt_ms: u64,
    // Optional: TLS/QLog compatibility knobs
    #[cfg(any(test, feature = "rust-tests"))]
    pub(crate) qlog_config: Option<(String, String, String, u32)>,
    #[cfg(any(test, feature = "rust-tests"))]
    pub(crate) ticket_key: Option<Vec<u8>>,
    #[cfg(any(test, feature = "rust-tests"))]
    pub(crate) tls_session: Option<Vec<u8>>,
    pub(crate) simd_enabled: bool,
    pub(crate) custom_bbr_settings: Option<Vec<u8>>,
    pub(crate) active_connection_id_limit: u64,
    pub(crate) stateless_reset_token: Option<[u8; 16]>,
    pub(crate) initial_token: Option<Vec<u8>>,
    // Stealth padding knobs (set by StealthManager)
    pub(crate) stealth_padding_enabled: bool,
    pub(crate) stealth_padding_strategy: u8, // 0=off,1=random,2=fixed,3=adaptive,4=browser-mimic,5=packet-normalize
    pub(crate) stealth_padding_max_size: usize,
    pub(crate) stealth_normalize_target_size: usize,
    /// Padding application rate (0-100%): fraction of packets that receive padding.
    pub(crate) stealth_padding_rate: u8,
    // Stealth timing knobs
    pub(crate) stealth_timing_enabled: bool,
    pub(crate) stealth_timing_max_jitter_us: u32,
    /// Timing obfuscation rate (0-100%): scales jitter magnitude.
    pub(crate) stealth_timing_rate: u8,
    // Adaptive padding granularity (bytes), default 64
    pub(crate) stealth_adaptive_granularity: u16,
    // BrowserMimic bias code: 1=very small (Safari/iOS), 2=small (Firefox/Linux), 3=default (Chromium/Windows), 4=mobile (Android)
    pub(crate) stealth_mimic_bias: u8,
    // ACK policy: number of ack-eliciting packets before sending ACK (Chrome-like tuning)
    pub(crate) ack_eliciting_threshold: u64,
    // When true, pacing/timing is controlled externally (e.g., StealthManager/RateChoker)
    // and the internal stealth timing gate should not schedule sleeps.
    pub(crate) external_pacing: bool,
    // Shared 0-RTT anti-replay strike register (server-side only).
    pub(crate) strike_register: Option<std::sync::Arc<super::anti_replay::StrikeRegister>>,
}

impl Config {
    /// Creates a new config with the given version
    pub fn new_with_version(version: u32) -> Result<Self, crate::error::ConnectionError> {
        if version != PROTOCOL_VERSION {
            return Err(crate::error::ConnectionError::VersionMismatch);
        }

        Ok(Self {
            version,
            cc_algorithm: CongestionControlAlgorithm::BBR3,
            application_protos: Vec::new(),
            max_idle_timeout: 30000,
            max_udp_payload_size: 1200,
            initial_max_data: 10485760,
            initial_max_stream_data_bidi_local: 1048576,
            initial_max_stream_data_bidi_remote: 1048576,
            initial_max_stream_data_uni: 1048576,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            enable_early_data: false,
            verify_peer: true,
            cert_chain_path: None,
            priv_key_path: None,
            verify_locations_file: None,
            verify_locations_directory: None,
            dgram_recv_max_queue_len: 0,
            dgram_send_max_queue_len: 0,
            path_challenge_recv_max_queue_len: 3,
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 6 * 1024 * 1024,
            max_amplification_factor: 3,
            send_capacity_factor: 1.0,
            pmtu_discovery_enabled: false,
            disable_dcid_reuse: false,
            track_unknown_transport_params: None,
            chlo_template: None,
            pacing: true,
            max_pacing_rate: None,
            hystart: true,
            initial_congestion_window_packets: 10,
            initial_rtt_ms: 100,
            #[cfg(any(test, feature = "rust-tests"))]
            qlog_config: None,
            #[cfg(any(test, feature = "rust-tests"))]
            ticket_key: None,
            #[cfg(any(test, feature = "rust-tests"))]
            tls_session: None,
            simd_enabled: true,
            custom_bbr_settings: None,
            active_connection_id_limit: 8,
            stateless_reset_token: None,
            initial_token: None,
            stealth_padding_enabled: false,
            stealth_padding_strategy: 0,
            stealth_padding_max_size: 0,
            stealth_normalize_target_size: 0,
            stealth_padding_rate: 100,
            stealth_timing_enabled: false,
            stealth_timing_max_jitter_us: 0,
            stealth_timing_rate: 100,
            stealth_adaptive_granularity: 64,
            stealth_mimic_bias: 3,
            ack_eliciting_threshold: 2,
            external_pacing: false,
            strike_register: None,
        })
    }

    /// Sets the congestion control algorithm.
    ///
    /// Supported: `Reno`, `BBR2`, `BBR3` (default).
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }
    /// Sets the congestion control algorithm by name (case-insensitive).
    ///
    /// Accepts: `reno`, `bbr2`, `bbr3`. Rejects anything else.
    pub fn set_cc_algorithm_name(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let algo = match name.to_lowercase().as_str() {
            "reno" => CongestionControlAlgorithm::Reno,
            "bbr2" => CongestionControlAlgorithm::BBR2,
            "bbr3" => CongestionControlAlgorithm::BBR3,
            _ => return Err(crate::error::ConnectionError::InvalidState),
        };
        self.set_cc_algorithm(algo);
        Ok(())
    }

    /// Sets the list of supported application protocols
    pub fn set_application_protos(
        &mut self,
        protos: &[&[u8]],
    ) -> Result<(), crate::error::ConnectionError> {
        self.application_protos = protos.iter().map(|p| p.to_vec()).collect();
        Ok(())
    }
    /// Parses and sets application protocols from TLS ALPN wire format.
    pub fn set_application_protos_wire_format(
        &mut self,
        wire: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if wire.is_empty() {
            self.application_protos.clear();
            return Ok(());
        }

        let mut protos = Vec::new();
        let mut off = 0usize;
        while off < wire.len() {
            let len = wire[off] as usize;
            off += 1;
            if len == 0 || off + len > wire.len() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
            protos.push(wire[off..off + len].to_vec());
            off += len;
        }
        self.application_protos = protos;
        Ok(())
    }

    /// Sets the maximum idle timeout
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.max_idle_timeout = v;
    }

    /// Sets the maximum UDP payload size
    pub fn set_max_recv_udp_payload_size(&mut self, v: usize) {
        self.max_udp_payload_size = v as u64;
    }

    /// Sets the maximum UDP payload size for sending
    pub fn set_max_send_udp_payload_size(&mut self, v: usize) {
        self.max_udp_payload_size = v as u64;
    }
    // duplicate removed: set_max_recv_udp_payload_size

    /// Sets the initial maximum data
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.initial_max_data = v;
    }

    /// Sets the initial maximum stream data for bidirectional streams (local)
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.initial_max_stream_data_bidi_local = v;
    }

    /// Sets the initial maximum stream data for bidirectional streams (remote)
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.initial_max_stream_data_bidi_remote = v;
    }

    /// Sets the initial maximum stream data for unidirectional streams
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.initial_max_stream_data_uni = v;
    }

    // Introspection helpers (used by tests and admin tooling).

    /// Returns the configured maximum UDP payload size.
    pub fn max_udp_payload_size(&self) -> u64 {
        self.max_udp_payload_size
    }

    /// Returns the selected congestion control algorithm.
    pub fn cc_algorithm(&self) -> CongestionControlAlgorithm {
        self.cc_algorithm
    }

    /// Returns whether pacing is enabled.
    pub fn pacing_enabled(&self) -> bool {
        self.pacing
    }

    /// Returns the send capacity multiplier factor.
    pub fn send_capacity_factor(&self) -> f64 {
        self.send_capacity_factor
    }

    /// Returns whether PMTU discovery is enabled.
    pub fn pmtu_discovery_enabled(&self) -> bool {
        self.pmtu_discovery_enabled
    }

    /// Returns whether SIMD acceleration is enabled.
    pub fn simd_enabled(&self) -> bool {
        self.simd_enabled
    }

    /// Returns custom BBR settings blob, if configured.
    pub fn custom_bbr_settings(&self) -> Option<&[u8]> {
        self.custom_bbr_settings.as_deref()
    }

    /// Sets the initial maximum number of bidirectional streams
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.initial_max_streams_bidi = v;
    }

    /// Sets the initial maximum number of unidirectional streams
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.initial_max_streams_uni = v;
    }

    /// Sets the ACK delay exponent
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.ack_delay_exponent = v;
    }

    /// Sets the maximum ACK delay
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.max_ack_delay = v;
    }

    /// Sets whether to disable active migration
    pub fn set_disable_active_migration(&mut self, v: bool) {
        self.disable_active_migration = v;
    }
    /// Sets the anti-amplification factor for unvalidated paths (default: 3x).
    pub fn set_max_amplification_factor(&mut self, v: usize) {
        self.max_amplification_factor = v;
    }
    /// Sets the send capacity multiplier, clamped to [0.1, 16.0].
    pub fn set_send_capacity_factor(&mut self, v: f64) {
        // Keep the range conservative to avoid pathological send bursts.
        self.send_capacity_factor = v.clamp(0.1, 16.0);
    }
    /// Enables or disables Path MTU discovery.
    pub fn discover_pmtu(&mut self, discover: bool) {
        self.pmtu_discovery_enabled = discover;
    }
    /// Sets the maximum number of queued PATH_CHALLENGE frames per path.
    pub fn set_path_challenge_recv_max_queue_len(&mut self, v: usize) {
        self.path_challenge_recv_max_queue_len = v;
    }
    /// Sets the maximum connection-level receive window in bytes.
    pub fn set_max_connection_window(&mut self, v: u64) {
        self.max_connection_window = v;
    }
    /// Sets the maximum per-stream receive window in bytes.
    pub fn set_max_stream_window(&mut self, v: u64) {
        self.max_stream_window = v;
    }
    /// Disables destination Connection ID reuse across paths.
    pub fn set_disable_dcid_reuse(&mut self, v: bool) {
        self.disable_dcid_reuse = v;
    }
    /// Enables tracking of unknown transport parameters up to `size` bytes.
    pub fn enable_track_unknown_transport_parameters(&mut self, size: usize) {
        self.track_unknown_transport_params = Some(size);
    }
    /// Enables QUIC DATAGRAM support with the given queue depths.
    pub fn enable_dgram(&mut self, recv_q: usize, send_q: usize) {
        self.dgram_recv_max_queue_len = recv_q;
        self.dgram_send_max_queue_len = send_q;
    }
    /// Enables or disables packet pacing.
    pub fn enable_pacing(&mut self, v: bool) {
        self.pacing = v;
    }
    /// Sets the maximum pacing rate in bytes/sec.
    pub fn set_max_pacing_rate(&mut self, v: u64) {
        self.max_pacing_rate = Some(v);
    }
    /// Enables or disables HyStart slow-start exit algorithm.
    pub fn enable_hystart(&mut self, v: bool) {
        self.hystart = v;
    }
    /// Sets the initial congestion window in number of packets.
    pub fn set_initial_congestion_window_packets(&mut self, packets: usize) {
        self.initial_congestion_window_packets = packets;
    }
    /// Set the initial RTT estimate (milliseconds). Applied to recovery before the first
    /// real measurement arrives. Values below 1 are clamped to 1.
    pub fn set_initial_rtt_ms(&mut self, ms: u64) {
        self.initial_rtt_ms = ms.max(1);
    }

    /// Enables 0-RTT early data.
    ///
    /// For production use, attach a strike register via `set_strike_register()`
    /// to protect against replay attacks (RFC 8446 Section 8, RFC 9001 Section 9.2).
    pub fn enable_early_data(&mut self) {
        if self.strike_register.is_none() {
            log::warn!(
                "[transport] 0-RTT early data enabled without anti-replay strike register. \
                 Attach one via set_strike_register() for production use."
            );
        } else {
            log::info!("[transport] 0-RTT early data enabled with anti-replay protection.");
        }
        self.enable_early_data = true;
    }

    /// Attach a shared strike register for 0-RTT anti-replay protection (server only).
    pub fn set_strike_register(
        &mut self,
        register: std::sync::Arc<super::anti_replay::StrikeRegister>,
    ) {
        self.strike_register = Some(register);
    }

    /// Returns true if 0-RTT early data is currently enabled.
    pub fn is_early_data_enabled(&self) -> bool {
        self.enable_early_data
    }

    /// Enables or disables TLS peer certificate verification.
    pub fn verify_peer(&mut self, verify: bool) {
        self.verify_peer = verify;
    }

    /// Loads certificate chain from file
    pub fn load_cert_chain_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let cert_data = std::fs::read(path).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Certificate chain read failed ({}): {}",
                path, e
            ))
        })?;
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&cert_data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                crate::error::ConnectionError::TlsError(format!(
                    "Certificate chain parse failed ({}): {}",
                    path, e
                ))
            })?;
        if certs.is_empty() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "Certificate chain parse failed ({}): no certificates found",
                path
            )));
        }
        self.cert_chain_path = Some(path.to_string());
        Ok(())
    }

    /// Loads private key from file
    pub fn load_priv_key_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let key_data = std::fs::read(path).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Private key read failed ({}): {}",
                path, e
            ))
        })?;
        rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_data).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Private key parse failed ({}): {}",
                path, e
            ))
        })?;
        self.priv_key_path = Some(path.to_string());
        Ok(())
    }
    /// Loads CA certificates from a PEM file for peer verification.
    pub fn load_verify_locations_from_file(
        &mut self,
        file: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let ca_data = std::fs::read(file).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA file read failed ({}): {}",
                file, e
            ))
        })?;
        let certs = rustls::pki_types::CertificateDer::pem_slice_iter(&ca_data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                crate::error::ConnectionError::TlsError(format!(
                    "CA file parse failed ({}): {}",
                    file, e
                ))
            })?;
        if certs.is_empty() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "CA file parse failed ({}): no certificates found",
                file
            )));
        }
        self.verify_locations_file = Some(file.to_string());
        Ok(())
    }
    /// Sets a CA certificate directory for peer verification.
    pub fn load_verify_locations_from_directory(
        &mut self,
        dir: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let meta = std::fs::metadata(dir).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA directory stat failed ({}): {}",
                dir, e
            ))
        })?;
        if !meta.is_dir() {
            return Err(crate::error::ConnectionError::TlsError(format!(
                "CA directory is not a directory ({})",
                dir
            )));
        }
        std::fs::read_dir(dir).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "CA directory read failed ({}): {}",
                dir, e
            ))
        })?;
        self.verify_locations_directory = Some(dir.to_string());
        Ok(())
    }
    /// Sets a Real-TLS ClientHello template for deterministic TLS fingerprinting.
    pub fn set_chlo_template(&mut self, tmpl: &[u8]) -> Result<(), crate::error::ConnectionError> {
        self.chlo_template = Some(tmpl.to_vec());
        Ok(())
    }
    /// Applies a deterministic TLS ClientHello template (alias for `set_chlo_template`).
    pub fn apply_deterministic_tls_hello_template(
        &mut self,
        tmpl: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_chlo_template(tmpl)
    }
    /// Installs a TLS session ticket encryption key (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if _key.is_empty() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.ticket_key = Some(_key.to_vec());
        Ok(())
    }
    // duplicate removed: enable_early_data
    /// Sets a raw ClientHello template for TLS cover (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_custom_tls(&mut self, hello: &[u8]) {
        let _ = self.set_chlo_template(hello);
    }
    // qlog / session controls
    /// Configures qlog output at default verbosity (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_qlog(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_qlog_with_level(path, title, desc, 0)
    }
    /// Configures qlog output with a specific verbosity level (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_qlog_with_level(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
        level: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        self.qlog_config = Some((path.to_string(), title.to_string(), desc.to_string(), level));
        Ok(())
    }
    /// Returns `Some(())` if qlog is configured, `None` otherwise.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn qlog_streamer(&self) -> Option<()> {
        self.qlog_config.as_ref().map(|_| ())
    }
    /// Stores a TLS session ticket for 0-RTT resumption (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_session(&mut self, ticket: &[u8]) {
        self.tls_session = Some(ticket.to_vec());
    }
    // Handshake-specific setters delegate to base setters
    /// Sets initial congestion window for the handshake phase (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_congestion_window_packets_in_handshake(&mut self, v: usize) {
        self.set_initial_congestion_window_packets(v);
    }
    /// Enables or disables HyStart++ during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_hystart_in_handshake(&mut self, v: bool) {
        self.enable_hystart(v);
    }
    /// Enables or disables send pacing during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_pacing_in_handshake(&mut self, v: bool) {
        self.enable_pacing(v);
    }
    /// Sets the max pacing rate (bytes/s) for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_pacing_rate_in_handshake(&mut self, v: u64) {
        self.set_max_pacing_rate(v);
    }
    /// Sets max UDP payload size during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_send_udp_payload_size_in_handshake(&mut self, v: usize) {
        self.set_max_send_udp_payload_size(v);
    }
    /// Sets send capacity factor during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_send_capacity_factor_in_handshake(&mut self, v: u64) {
        self.set_send_capacity_factor(v as f64);
    }
    /// Enables or disables PMTU discovery during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_discover_pmtu_in_handshake(&mut self, v: bool) {
        self.discover_pmtu(v);
    }
    /// Sets the max idle timeout during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_max_idle_timeout_in_handshake(&mut self, v: u64) {
        self.set_max_idle_timeout(v);
    }
    /// Sets initial max bidirectional streams during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_max_streams_bidi_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_bidi = v;
    }
    /// Sets initial max unidirectional streams during the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_initial_max_streams_uni_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_uni = v;
    }
    /// Sets congestion control algorithm for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_cc_algorithm_in_handshake(&mut self, algo: CongestionControlAlgorithm) {
        self.set_cc_algorithm(algo);
    }
    /// Sets congestion control algorithm by name for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_cc_algorithm_name_in_handshake(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_cc_algorithm_name(name)
    }
    /// Injects custom BBR tuning bytes for the handshake (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_custom_bbr_settings_in_handshake(&mut self, s: &[u8]) {
        self.custom_bbr_settings = if s.is_empty() { None } else { Some(s.to_vec()) };
    }
    /// Sets the maximum number of active connection IDs the peer may use.
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        self.active_connection_id_limit = v;
    }
    /// Sets the 16-byte stateless reset token for this connection.
    pub fn set_stateless_reset_token(&mut self, token: [u8; 16]) {
        self.stateless_reset_token = Some(token);
    }

    /// Sets the initial address validation token for the first Initial packet.
    pub fn set_initial_token(&mut self, token: Option<Vec<u8>>) {
        self.initial_token = token;
    }
    /// Configures stealth padding (strategy: 0=off, 1=random, 2=fixed, 3=adaptive, 4=browser-mimic, 5=packet-normalize).
    pub fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.stealth_padding_enabled = enabled;
        self.stealth_padding_strategy = strategy;
        self.stealth_padding_max_size = max_size;
    }
    /// Sets the padding application rate (0-100%): fraction of packets that receive padding.
    pub fn set_stealth_padding_rate(&mut self, rate: u8) {
        self.stealth_padding_rate = rate.min(100);
    }
    /// Sets the PacketNormalize target size (strategy 5). 0 = disabled.
    pub fn set_stealth_normalize_target(&mut self, target_size: usize) {
        self.stealth_normalize_target_size = target_size;
    }
    /// Configures stealth timing jitter injection.
    pub fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.stealth_timing_enabled = enabled;
        self.stealth_timing_max_jitter_us = max_jitter_us;
    }
    /// Sets the timing obfuscation rate (0-100%): scales jitter magnitude.
    pub fn set_stealth_timing_rate(&mut self, rate: u8) {
        self.stealth_timing_rate = rate.min(100);
    }
    /// Sets the adaptive padding granularity in bytes (minimum 1).
    pub fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }
    /// Sets the browser mimic bias code (1=Safari, 2=Firefox, 3=Chromium, 4=Android).
    pub fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }
    /// Sets ACK-eliciting threshold (packets) before emitting ACK
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.ack_eliciting_threshold = thr.max(1);
    }
    /// Disables internal stealth timing sleeps when true (external controller active)
    pub fn set_external_pacing(&mut self, v: bool) {
        self.external_pacing = v;
    }

    // duplicate removed: load_verify_locations_from_directory
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> Config {
        Config::new_with_version(PROTOCOL_VERSION).expect("default config should succeed")
    }

    #[test]
    fn test_new_with_valid_version() {
        let cfg = Config::new_with_version(PROTOCOL_VERSION);
        assert!(cfg.is_ok());
    }

    #[test]
    fn test_new_with_invalid_version() {
        let cfg = Config::new_with_version(0xDEADBEEF);
        assert!(cfg.is_err());
    }

    #[test]
    fn test_default_cc_algorithm() {
        let cfg = default_config();
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR3));
    }

    #[test]
    fn test_default_values() {
        let cfg = default_config();
        assert_eq!(cfg.max_idle_timeout, 30000);
        assert_eq!(cfg.max_udp_payload_size(), 1200);
        assert_eq!(cfg.initial_max_data, 10485760);
        assert_eq!(cfg.initial_max_stream_data_bidi_local, 1048576);
        assert_eq!(cfg.initial_max_stream_data_bidi_remote, 1048576);
        assert_eq!(cfg.initial_max_stream_data_uni, 1048576);
        assert_eq!(cfg.initial_max_streams_bidi, 100);
        assert_eq!(cfg.initial_max_streams_uni, 100);
        assert_eq!(cfg.ack_delay_exponent, 3);
        assert_eq!(cfg.max_ack_delay, 25);
        assert!(cfg.pacing_enabled());
        assert!(cfg.hystart);
        assert_eq!(cfg.initial_congestion_window_packets, 10);
        assert_eq!(cfg.initial_rtt_ms, 100);
        assert!(cfg.simd_enabled());
        assert!(!cfg.pmtu_discovery_enabled());
    }

    #[test]
    fn test_set_cc_algorithm_name_valid() {
        let mut cfg = default_config();
        assert!(cfg.set_cc_algorithm_name("reno").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::Reno));
        assert!(cfg.set_cc_algorithm_name("bbr2").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR2));
        assert!(cfg.set_cc_algorithm_name("BBR3").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR3));
    }

    #[test]
    fn test_set_cc_algorithm_name_invalid() {
        let mut cfg = default_config();
        assert!(cfg.set_cc_algorithm_name("cubic").is_err());
        assert!(cfg.set_cc_algorithm_name("").is_err());
        assert!(cfg.set_cc_algorithm_name("LEDBAT").is_err());
    }

    #[test]
    fn test_send_capacity_factor_clamped() {
        let mut cfg = default_config();
        cfg.set_send_capacity_factor(0.0);
        assert!((cfg.send_capacity_factor() - 0.1).abs() < f64::EPSILON);
        cfg.set_send_capacity_factor(100.0);
        assert!((cfg.send_capacity_factor() - 16.0).abs() < f64::EPSILON);
        cfg.set_send_capacity_factor(5.0);
        assert!((cfg.send_capacity_factor() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_initial_rtt_ms_clamped_to_one() {
        let mut cfg = default_config();
        cfg.set_initial_rtt_ms(0);
        assert_eq!(cfg.initial_rtt_ms, 1);
        cfg.set_initial_rtt_ms(500);
        assert_eq!(cfg.initial_rtt_ms, 500);
    }

    #[test]
    fn test_stealth_padding_configuration() {
        let mut cfg = default_config();
        cfg.set_stealth_padding(true, 3, 128);
        assert!(cfg.stealth_padding_enabled);
        assert_eq!(cfg.stealth_padding_strategy, 3);
        assert_eq!(cfg.stealth_padding_max_size, 128);
    }

    #[test]
    fn test_stealth_mimic_bias_valid_range() {
        let mut cfg = default_config();
        for bias in 1..=4u8 {
            cfg.set_stealth_mimic_bias(bias);
            assert_eq!(cfg.stealth_mimic_bias, bias);
        }
        // Out of range falls back to default 3
        cfg.set_stealth_mimic_bias(0);
        assert_eq!(cfg.stealth_mimic_bias, 3);
        cfg.set_stealth_mimic_bias(5);
        assert_eq!(cfg.stealth_mimic_bias, 3);
        cfg.set_stealth_mimic_bias(255);
        assert_eq!(cfg.stealth_mimic_bias, 3);
    }

    #[test]
    fn test_stealth_adaptive_granularity_zero_becomes_one() {
        let mut cfg = default_config();
        cfg.set_stealth_adaptive_granularity(0);
        assert_eq!(cfg.stealth_adaptive_granularity, 1);
        cfg.set_stealth_adaptive_granularity(64);
        assert_eq!(cfg.stealth_adaptive_granularity, 64);
    }

    #[test]
    fn test_ack_eliciting_threshold_minimum_one() {
        let mut cfg = default_config();
        cfg.set_ack_eliciting_threshold(0);
        assert_eq!(cfg.ack_eliciting_threshold, 1);
        cfg.set_ack_eliciting_threshold(10);
        assert_eq!(cfg.ack_eliciting_threshold, 10);
    }

    #[test]
    fn test_application_protos_wire_format_empty() {
        let mut cfg = default_config();
        assert!(cfg.set_application_protos_wire_format(&[]).is_ok());
        assert!(cfg.application_protos.is_empty());
    }

    #[test]
    fn test_application_protos_wire_format_valid() {
        let mut cfg = default_config();
        // Wire format: [len, bytes...] per proto
        let wire = [2u8, b'h', b'3', 2, b'h', b'2'];
        assert!(cfg.set_application_protos_wire_format(&wire).is_ok());
        assert_eq!(cfg.application_protos.len(), 2);
        assert_eq!(cfg.application_protos[0], b"h3");
        assert_eq!(cfg.application_protos[1], b"h2");
    }

    #[test]
    fn test_application_protos_wire_format_invalid_zero_len() {
        let mut cfg = default_config();
        // A zero-length entry is invalid
        let wire = [0u8];
        assert!(cfg.set_application_protos_wire_format(&wire).is_err());
    }

    #[test]
    fn test_application_protos_wire_format_truncated() {
        let mut cfg = default_config();
        // Claims 5 bytes but only 2 available
        let wire = [5u8, b'h', b'3'];
        assert!(cfg.set_application_protos_wire_format(&wire).is_err());
    }

    #[test]
    fn test_early_data_and_strike_register() {
        let mut cfg = default_config();
        assert!(!cfg.is_early_data_enabled());
        cfg.enable_early_data();
        assert!(cfg.is_early_data_enabled());
        // Attach a strike register
        let register = std::sync::Arc::new(super::super::anti_replay::StrikeRegister::new(
            super::super::anti_replay::AntiReplayConfig::default(),
        ));
        cfg.set_strike_register(register);
        assert!(cfg.strike_register.is_some());
    }

    #[test]
    fn test_stealth_timing_configuration() {
        let mut cfg = default_config();
        assert!(!cfg.stealth_timing_enabled);
        assert_eq!(cfg.stealth_timing_max_jitter_us, 0);
        cfg.set_stealth_timing(true, 5000);
        assert!(cfg.stealth_timing_enabled);
        assert_eq!(cfg.stealth_timing_max_jitter_us, 5000);
    }
}
