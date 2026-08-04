use super::{is_supported_version, CongestionControlAlgorithm};
use crate::stealth::OsFingerprintProfile;
use rustls::pki_types::pem::PemObject;
use zeroize::Zeroizing;

// ============================================================================

/// Traffic analysis defense mode (TODO-455).
///
/// Controls how aggressively the transport layer defends against size-, timing-,
/// and volume-based traffic analysis. The modes are ordered by increasing
/// protection (and increasing bandwidth overhead):
///
/// - [`TrafficAnalysisDefense::Off`] - current probabilistic padding behavior
///   (gated by `stealth_padding_rate`). No chaffing. This is the default and
///   preserves backward compatibility.
/// - [`TrafficAnalysisDefense::FullPadding`] - pad **every** outgoing 1-RTT
///   packet to `max_udp_payload_size`, ignoring `stealth_padding_rate`.
///   Eliminates size-based analysis entirely at the cost of bandwidth overhead
///   on small packets.
/// - [`TrafficAnalysisDefense::ConstantRate`] - pad to a consistent size **and**
///   inject chaff (dummy packets) to maintain a fixed target emission rate
///   (`constant_rate_pps`). Defeats both timing- and bandwidth-based analysis.
///   This is the strongest defense and the most expensive - opt-in only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
pub enum TrafficAnalysisDefense {
    /// No traffic analysis defense beyond the existing probabilistic padding.
    /// This is the default and preserves backward compatibility.
    #[serde(alias = "off", alias = "Off", alias = "disabled")]
    #[default]
    Off,
    /// Pad ALL outgoing 1-RTT packets to `max_udp_payload_size`.
    /// Eliminates size-based traffic analysis. No probabilistic skipping.
    #[serde(alias = "full", alias = "Full", alias = "full-padding", alias = "FullPadding")]
    FullPadding,
    /// Pad to a consistent size and inject chaff to maintain a fixed target
    /// rate (`constant_rate_pps`). Defeats timing- and bandwidth-based analysis.
    #[serde(
        alias = "constant",
        alias = "Constant",
        alias = "constant-rate",
        alias = "ConstantRate"
    )]
    ConstantRate,
}

impl TrafficAnalysisDefense {
    /// Parse a mode from a case-insensitive string identifier.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" | "" => Some(Self::Off),
            "full" | "full-padding" | "fullpadding" => Some(Self::FullPadding),
            "constant" | "constant-rate" | "constantrate" => Some(Self::ConstantRate),
            _ => None,
        }
    }

    const fn protection_level(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::FullPadding => 1,
            Self::ConstantRate => 2,
        }
    }
}

/// Complete traffic-analysis policy for one transport connection.
///
/// A server may use its configured policy as a ceiling for an authenticated
/// per-QKey request. Numeric fields are bandwidth-cost ceilings, and defense
/// modes are ordered `Off < FullPadding < ConstantRate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficAnalysisPolicy {
    pub defense: TrafficAnalysisDefense,
    pub chaff_rate_pps: u32,
    pub chaff_size_bytes: u32,
    pub constant_rate_pps: u32,
    pub idle_timeout_ms: u64,
    pub ramp_down_ms: u64,
}

impl Default for TrafficAnalysisPolicy {
    fn default() -> Self {
        Self {
            defense: TrafficAnalysisDefense::Off,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1280,
            constant_rate_pps: 100,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        }
    }
}

impl TrafficAnalysisPolicy {
    pub const MAX_CHAFF_RATE_PPS: u32 = 10_000;
    pub const MAX_CONSTANT_RATE_PPS: u32 = 1_000;
    pub const MIN_CHAFF_SIZE_BYTES: u32 = 64;
    pub const MAX_CHAFF_SIZE_BYTES: u32 = 65_535;
    pub const MAX_IDLE_TIMEOUT_MS: u64 = 3_600_000;
    pub const MAX_RAMP_DOWN_MS: u64 = 60_000;

    /// Hard upper bound used for authenticated per-QKey policy requests.
    pub const fn safety_ceiling() -> Self {
        Self {
            defense: TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: Self::MAX_CHAFF_RATE_PPS,
            chaff_size_bytes: Self::MAX_CHAFF_SIZE_BYTES,
            constant_rate_pps: Self::MAX_CONSTANT_RATE_PPS,
            idle_timeout_ms: Self::MAX_IDLE_TIMEOUT_MS,
            ramp_down_ms: Self::MAX_RAMP_DOWN_MS,
        }
    }

    /// Rejects malformed or intrinsically unsafe policy values.
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.chaff_rate_pps > Self::MAX_CHAFF_RATE_PPS {
            return Err("chaff_rate_pps exceeds 10000");
        }
        if self.constant_rate_pps > Self::MAX_CONSTANT_RATE_PPS {
            return Err("constant_rate_pps exceeds 1000");
        }
        if !(Self::MIN_CHAFF_SIZE_BYTES..=Self::MAX_CHAFF_SIZE_BYTES)
            .contains(&self.chaff_size_bytes)
        {
            return Err("chaff_size_bytes must be between 64 and 65535");
        }
        if self.idle_timeout_ms > Self::MAX_IDLE_TIMEOUT_MS {
            return Err("idle_timeout_ms exceeds 3600000");
        }
        if self.ramp_down_ms > Self::MAX_RAMP_DOWN_MS {
            return Err("ramp_down_ms exceeds 60000");
        }
        if self.defense == TrafficAnalysisDefense::ConstantRate && self.constant_rate_pps == 0 {
            return Err("constant-rate defense requires constant_rate_pps > 0");
        }
        Ok(self)
    }

    /// Intersects a requested policy with an independently configured ceiling.
    pub fn bounded_by(self, ceiling: Self) -> Self {
        let defense = if self.defense.protection_level() <= ceiling.defense.protection_level() {
            self.defense
        } else {
            ceiling.defense
        };
        let rate_pps = self.rate_ceiling_for(defense).min(ceiling.rate_ceiling_for(defense));
        let mut bounded = Self {
            defense,
            chaff_rate_pps: rate_pps,
            chaff_size_bytes: self.chaff_size_bytes.min(ceiling.chaff_size_bytes),
            constant_rate_pps: rate_pps,
            idle_timeout_ms: self.idle_timeout_ms.min(ceiling.idle_timeout_ms),
            ramp_down_ms: self.ramp_down_ms.min(ceiling.ramp_down_ms),
        };
        match bounded.defense {
            TrafficAnalysisDefense::Off => {
                bounded.chaff_rate_pps = 0;
                bounded.constant_rate_pps = 0;
            }
            TrafficAnalysisDefense::FullPadding => {
                bounded.constant_rate_pps = 0;
            }
            TrafficAnalysisDefense::ConstantRate => {
                bounded.chaff_rate_pps = 0;
            }
        }
        bounded
    }

    const fn rate_ceiling_for(self, defense: TrafficAnalysisDefense) -> u32 {
        match (self.defense, defense) {
            (_, TrafficAnalysisDefense::Off) => 0,
            (TrafficAnalysisDefense::Off, _) => 0,
            (TrafficAnalysisDefense::FullPadding, TrafficAnalysisDefense::FullPadding) => {
                self.chaff_rate_pps
            }
            (TrafficAnalysisDefense::ConstantRate, TrafficAnalysisDefense::FullPadding)
            | (TrafficAnalysisDefense::ConstantRate, TrafficAnalysisDefense::ConstantRate) => {
                self.constant_rate_pps
            }
            (TrafficAnalysisDefense::FullPadding, TrafficAnalysisDefense::ConstantRate) => 0,
        }
    }

    /// Maximum configured wire cost before IP/UDP overhead.
    pub fn estimated_max_bits_per_second(self, max_udp_payload_size: u32) -> u64 {
        let (rate, target_size) = match self.defense {
            TrafficAnalysisDefense::Off => (0, 0),
            TrafficAnalysisDefense::FullPadding => (self.chaff_rate_pps, max_udp_payload_size),
            TrafficAnalysisDefense::ConstantRate => {
                (self.constant_rate_pps, self.chaff_size_bytes.min(max_udp_payload_size))
            }
        };
        u64::from(rate).saturating_mul(u64::from(target_size)).saturating_mul(8)
    }
}

// ============================================================================

/// Policy that controls when NAT traversal may emit discovery probes.
///
/// NAT traversal is intentionally disabled by default. STUN/ICE traffic can be
/// useful for connectivity, roaming, and mesh scenarios, but it is also an
/// observable protocol surface. The policy therefore treats NAT traversal as a
/// bounded path-discovery tool, not as a default stealth mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatTraversalMode {
    /// Do not emit NAT traversal probes.
    #[default]
    Off,
    /// Probe only after the direct path fails or becomes unreachable.
    ConnectivityFallback,
    /// Probe after direct failure and during local path changes or roaming.
    Roaming,
    /// Probe for direct failure, roaming, and explicit mesh/peer discovery.
    Mesh,
    /// Probe for any explicit discovery reason. Intended for diagnostics only.
    Always,
}

/// Reason a caller wants to run NAT path discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatDiscoveryReason {
    /// Direct client-to-server connectivity failed.
    ConnectivityFailure,
    /// The local network path changed, for example WiFi to LTE.
    Roaming,
    /// Mesh or peer-to-peer path establishment needs candidates.
    Mesh,
    /// Explicit operator/test request.
    Manual,
}

/// NAT traversal configuration (TODO-454): STUN/TURN/ICE settings.
///
/// Controls whether the transport attempts NAT traversal via STUN binding
/// requests, TURN relaying, and ICE candidate gathering. Disabled by default.
/// Enabling it provides optional path discovery for direct-connect failures,
/// roaming, or mesh scenarios without turning STUN/ICE into permanent
/// background noise.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct NatTraversalConfig {
    /// Master switch for NAT traversal. When false, STUN/TURN/ICE are skipped.
    pub enabled: bool,
    /// Policy that decides which discovery reasons may emit probes.
    pub mode: NatTraversalMode,
    /// STUN server addresses used to discover server-reflexive candidates.
    pub stun_servers: Vec<std::net::SocketAddr>,
    /// TURN server addresses used to obtain relayed candidates when direct
    /// connectivity is impossible.
    pub turn_servers: Vec<std::net::SocketAddr>,
    /// Whether ICE candidate gathering and pair selection is enabled.
    pub ice_enabled: bool,
    /// Minimum interval between discovery probe bursts.
    pub probe_interval_ms: u64,
    /// Maximum number of candidates returned by one discovery run.
    pub max_candidates: usize,
}

impl Default for NatTraversalConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl NatTraversalConfig {
    /// Conservative default probe interval. Large enough to avoid STUN chatter
    /// while still reacting quickly to a real direct-path failure.
    pub const DEFAULT_PROBE_INTERVAL_MS: u64 = 30_000;
    /// Default candidate cap. Keeps discovery bounded even with many local
    /// interfaces and STUN/TURN servers.
    pub const DEFAULT_MAX_CANDIDATES: usize = 8;

    /// Create an explicitly disabled config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            mode: NatTraversalMode::Off,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            ice_enabled: false,
            probe_interval_ms: Self::DEFAULT_PROBE_INTERVAL_MS,
            max_candidates: Self::DEFAULT_MAX_CANDIDATES,
        }
    }

    /// Parse a STUN/TURN server address from a string.
    pub fn parse_server_addr(
        s: &str,
    ) -> Result<std::net::SocketAddr, crate::error::ConnectionError> {
        s.parse().map_err(|e| {
            crate::error::ConnectionError::Transport(format!("Invalid NAT server address: {}", e))
        })
    }

    /// Returns true when the configured policy permits discovery for `reason`.
    pub fn allows_discovery(&self, reason: NatDiscoveryReason) -> bool {
        if !self.enabled || self.mode == NatTraversalMode::Off {
            return false;
        }
        match self.mode {
            NatTraversalMode::Off => false,
            NatTraversalMode::ConnectivityFallback => {
                matches!(
                    reason,
                    NatDiscoveryReason::ConnectivityFailure | NatDiscoveryReason::Manual
                )
            }
            NatTraversalMode::Roaming => {
                matches!(
                    reason,
                    NatDiscoveryReason::ConnectivityFailure
                        | NatDiscoveryReason::Roaming
                        | NatDiscoveryReason::Manual
                )
            }
            NatTraversalMode::Mesh => true,
            NatTraversalMode::Always => true,
        }
    }

    /// Returns a normalized copy with production-safe lower bounds.
    pub fn normalized(&self) -> Self {
        let mut out = self.clone();
        out.probe_interval_ms = out.probe_interval_ms.max(1_000);
        out.max_candidates = out.max_candidates.max(1);
        if !out.enabled {
            out.mode = NatTraversalMode::Off;
        }
        out
    }
}

// ============================================================================

/// Congestion recovery boundary used after a validated port-only rebinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationProbeTarget {
    /// Recover toward the congestion window observed before rebinding.
    #[default]
    PreviousWindow,
    /// Treat the reduced window as the new congestion-avoidance boundary.
    ReducedWindow,
}

/// Validated connection-migration policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MigrationPolicy {
    /// Multiplicative retained cwnd fraction for port-only rebinding.
    ///
    /// `0.0` explicitly resets to the initial window and `1.0` retains the
    /// complete prior window. Genuine IP-address changes always reset.
    pub port_rebinding_cwnd_factor: f64,
    /// Minimum interval between successful migrations.
    pub cooldown: std::time::Duration,
    /// Recovery boundary after a reduced port-only rebinding.
    pub probe_target: MigrationProbeTarget,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self {
            port_rebinding_cwnd_factor: 0.5,
            cooldown: std::time::Duration::from_millis(750),
            probe_target: MigrationProbeTarget::PreviousWindow,
        }
    }
}

impl MigrationPolicy {
    const MAX_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(60);

    fn validate(self) -> Result<Self, crate::error::ConnectionError> {
        if !self.port_rebinding_cwnd_factor.is_finite()
            || !(0.0..=1.0).contains(&self.port_rebinding_cwnd_factor)
            || self.cooldown > Self::MAX_COOLDOWN
        {
            return Err(crate::error::ConnectionError::Transport(
                "migration cwnd factor must be finite in [0,1] and cooldown must not exceed 60s"
                    .to_string(),
            ));
        }
        Ok(self)
    }
}

// ============================================================================

/// QUIC connection configuration
#[derive(Clone)]
pub struct Config {
    pub(crate) version: u32,
    /// Ordered list of QUIC versions this endpoint will advertise and accept.
    /// The first entry is the preferred version. It is initialized to the
    /// version passed to `new_with_version`; Engine runtime defaults to v2,
    /// then v1. When v2 (RFC 9369) is included, Version Negotiation and initial
    /// salt selection honor it.
    pub(crate) supported_versions: Vec<u32>,
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
    pub(crate) migration_policy: MigrationPolicy,
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
    pub(crate) pmtu_policy: PmtuPolicy,
    pub(crate) disable_dcid_reuse: bool,
    pub(crate) track_unknown_transport_params: Option<usize>,
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
    pub(crate) ticket_key: Option<crate::secret::SecretBytes>,
    #[cfg(any(test, feature = "rust-tests"))]
    pub(crate) tls_session: Option<crate::secret::SecretBytes>,
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
    // --- Traffic analysis defense (TODO-455) ---
    /// Traffic analysis defense mode. `Off` preserves the existing probabilistic
    /// padding behavior. `FullPadding` pads every 1-RTT packet to
    /// `max_udp_payload_size`. `ConstantRate` pads to a consistent size and
    /// injects chaff to maintain `constant_rate_pps`.
    pub(crate) traffic_analysis_defense: TrafficAnalysisDefense,
    /// Dummy (chaff) packet injection rate in packets per second. 0 = disabled.
    /// Chaff packets are real QUIC 1-RTT packets containing PING + PADDING frames,
    /// indistinguishable from real traffic to an outside observer.
    pub(crate) chaff_rate_pps: u32,
    /// Target size in bytes for each chaff (dummy) packet. Default 1280 (IPv6
    /// minimum MTU). Chaff is padded to this size so it matches real traffic.
    pub(crate) chaff_size_bytes: u32,
    /// Target emission rate (packets/sec) for `ConstantRate` mode. When real
    /// traffic is sparse, chaff is injected to maintain this rate. Default 100.
    pub(crate) constant_rate_pps: u32,
    /// Full-rate idle window before chaff begins a gradual soft stop.
    pub(crate) chaff_idle_timeout_ms: u64,
    /// Ramp-down duration after the idle window. Zero stops immediately.
    pub(crate) chaff_ramp_down_ms: u64,
    /// Independent ceiling for authenticated per-QKey traffic-analysis requests.
    qkey_traffic_analysis_ceiling: TrafficAnalysisPolicy,
    /// Operator ceiling for post-authentication Intelligent escalation.
    intelligent_traffic_analysis_ceiling: TrafficAnalysisPolicy,
    // --- TCP/ICMP fingerprint obfuscation (TODO-462) ---
    /// Target OS fingerprint profile for packet normalization on the TUN
    /// egress path. Controls TTL, TCP window, MSS, DF bit, IP ID behavior,
    /// and TCP option ordering to prevent passive OS fingerprinting.
    /// Default: Linux.
    pub(crate) fingerprint_profile: OsFingerprintProfile,
    // --- Multipath support (TODO-449) ---
    /// Whether multipath (WiFi+LTE bonding) is enabled for this connection.
    /// When disabled (the default) the connection behaves as single-path,
    /// preserving backward compatibility.
    pub(crate) multipath_enabled: bool,
    /// Maximum number of concurrent paths (primary + secondaries) when
    /// multipath is enabled. Default: 3. Clamped to at least 1.
    pub(crate) max_paths: usize,
    // --- NAT traversal (TODO-454) ---
    /// NAT traversal configuration: STUN/TURN/ICE settings. Disabled by default.
    pub(crate) nat_traversal: NatTraversalConfig,
}

/// Validated DPLPMTUD search and recovery bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PmtuPolicy {
    pub min_mtu: usize,
    pub max_mtu: usize,
    pub probe_interval: std::time::Duration,
    pub black_hole_timeout: std::time::Duration,
}

impl Default for PmtuPolicy {
    fn default() -> Self {
        Self {
            min_mtu: 1280,
            max_mtu: 1500,
            probe_interval: std::time::Duration::from_secs(60),
            black_hole_timeout: std::time::Duration::from_secs(10),
        }
    }
}

impl PmtuPolicy {
    fn validate(self) -> Result<Self, crate::error::ConnectionError> {
        if self.min_mtu < 1200
            || self.max_mtu < self.min_mtu
            || self.max_mtu > u16::MAX as usize
            || self.probe_interval.is_zero()
            || self.black_hole_timeout.is_zero()
        {
            return Err(crate::error::ConnectionError::Transport(
                "invalid DPLPMTUD policy bounds or timers".to_string(),
            ));
        }
        Ok(self)
    }
}

impl Config {
    /// Creates a new config with the given version
    pub fn new_with_version(version: u32) -> Result<Self, crate::error::ConnectionError> {
        if !is_supported_version(version) {
            return Err(crate::error::ConnectionError::VersionMismatch);
        }

        Ok(Self {
            version,
            supported_versions: vec![version],
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
            migration_policy: MigrationPolicy::default(),
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
            pmtu_discovery_enabled: true, // DPLPMTUD enabled by default (RFC 8899)
            pmtu_policy: PmtuPolicy::default(),
            disable_dcid_reuse: false,
            track_unknown_transport_params: None,
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
            traffic_analysis_defense: TrafficAnalysisDefense::Off,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1280,
            constant_rate_pps: 100,
            chaff_idle_timeout_ms: 30_000,
            chaff_ramp_down_ms: 5_000,
            qkey_traffic_analysis_ceiling: TrafficAnalysisPolicy::safety_ceiling(),
            intelligent_traffic_analysis_ceiling: TrafficAnalysisPolicy::default(),
            fingerprint_profile: OsFingerprintProfile::default(),
            multipath_enabled: false,
            max_paths: 3,
            nat_traversal: NatTraversalConfig::default(),
        })
    }

    /// Sets the congestion control algorithm.
    ///
    /// Supported: `Reno`, `Cubic`, `BBR2`, `BBR3` (default).
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }
    /// Sets the congestion control algorithm by name (case-insensitive).
    ///
    /// Accepts: `reno`, `cubic`, `bbr2`, `bbr3`. Rejects anything else.
    pub fn set_cc_algorithm_name(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let algo = match name.to_lowercase().as_str() {
            "reno" => CongestionControlAlgorithm::Reno,
            "cubic" => CongestionControlAlgorithm::Cubic,
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

    /// Sets the ordered list of QUIC versions this endpoint supports.
    ///
    /// The first entry is the preferred version. Every entry must be a
    /// recognized QUIC version (v1 or v2 per RFC 9369); unknown versions are
    /// rejected with [`crate::error::ConnectionError::VersionMismatch`]. An
    /// empty list is rejected with [`crate::error::ConnectionError::InvalidState`].
    /// See TODO-453.
    pub fn set_supported_versions(
        &mut self,
        versions: Vec<u32>,
    ) -> Result<(), crate::error::ConnectionError> {
        if versions.is_empty() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        for v in &versions {
            if !is_supported_version(*v) {
                return Err(crate::error::ConnectionError::VersionMismatch);
            }
        }
        let mut unique = std::collections::HashSet::with_capacity(versions.len());
        if versions.iter().any(|version| !unique.insert(*version)) {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.version = versions[0];
        self.supported_versions = versions;
        Ok(())
    }

    /// Returns the ordered list of supported QUIC versions (preferred first).
    pub fn supported_versions(&self) -> &[u32] {
        &self.supported_versions
    }

    /// Selects one configured version for a concrete connection attempt.
    pub(crate) fn select_version(
        &mut self,
        version: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        if !self.supported_versions.contains(&version) {
            return Err(crate::error::ConnectionError::VersionMismatch);
        }
        self.version = version;
        Ok(())
    }

    /// Returns the version selected for this concrete connection attempt.
    pub fn version(&self) -> u32 {
        self.version
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

    /// Returns the validated DPLPMTUD search and recovery policy.
    pub fn pmtu_policy(&self) -> PmtuPolicy {
        self.pmtu_policy
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
    /// Sets validated port-rebinding reduction and migration timing policy.
    pub fn set_migration_policy(
        &mut self,
        policy: MigrationPolicy,
    ) -> Result<(), crate::error::ConnectionError> {
        self.migration_policy = policy.validate()?;
        Ok(())
    }
    /// Returns the validated connection-migration policy.
    pub fn migration_policy(&self) -> MigrationPolicy {
        self.migration_policy
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

    /// Sets validated DPLPMTUD bounds and timers.
    pub fn set_pmtu_policy(
        &mut self,
        policy: PmtuPolicy,
    ) -> Result<(), crate::error::ConnectionError> {
        self.pmtu_policy = policy.validate()?;
        Ok(())
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

    /// Sets the target OS fingerprint profile for TCP/ICMP packet normalization
    /// on the TUN egress path (TODO-462).
    ///
    /// This controls TTL, TCP window size, MSS, DF bit, IP ID behavior, and TCP
    /// option ordering to prevent passive OS fingerprinting by DPI systems.
    /// Default: [`OsFingerprintProfile::Linux`].
    pub fn set_fingerprint_profile(&mut self, profile: OsFingerprintProfile) {
        self.fingerprint_profile = profile;
    }

    /// Returns the currently configured OS fingerprint profile.
    pub fn fingerprint_profile(&self) -> OsFingerprintProfile {
        self.fingerprint_profile
    }

    // --- Multipath support (TODO-449) ---

    /// Enables or disables multipath (WiFi+LTE bonding) for this connection.
    ///
    /// When disabled (the default) the connection is single-path and the
    /// transport preserves its existing RFC 9000 migration semantics. When
    /// enabled, secondary paths may be added after validation and traffic is
    /// distributed across them by the path scheduler.
    pub fn set_multipath_enabled(&mut self, enabled: bool) {
        self.multipath_enabled = enabled;
    }

    /// Sets the maximum number of concurrent paths (primary + secondaries)
    /// when multipath is enabled. Clamped to at least 1.
    pub fn set_max_paths(&mut self, max_paths: usize) {
        self.max_paths = max_paths.max(1);
    }

    /// Returns whether multipath bonding is enabled.
    pub fn multipath_enabled(&self) -> bool {
        self.multipath_enabled
    }

    /// Returns the maximum number of concurrent paths.
    pub fn max_paths(&self) -> usize {
        self.max_paths
    }

    // --- NAT traversal (TODO-454) ---

    /// Sets the NAT traversal configuration (STUN/TURN/ICE). Replaces any
    /// previously configured NAT traversal settings.
    pub fn set_nat_traversal(&mut self, config: NatTraversalConfig) {
        self.nat_traversal = config.normalized();
    }

    /// Returns a reference to the current NAT traversal configuration.
    pub fn nat_traversal(&self) -> &NatTraversalConfig {
        &self.nat_traversal
    }

    /// Enables or disables NAT traversal as a whole.
    pub fn enable_nat_traversal(&mut self, enabled: bool) {
        self.nat_traversal.enabled = enabled;
        if !enabled {
            self.nat_traversal.mode = NatTraversalMode::Off;
        } else if self.nat_traversal.mode == NatTraversalMode::Off {
            self.nat_traversal.mode = NatTraversalMode::ConnectivityFallback;
        }
    }

    /// Sets the NAT traversal discovery policy.
    pub fn set_nat_traversal_mode(&mut self, mode: NatTraversalMode) {
        self.nat_traversal.mode = mode;
        self.nat_traversal.enabled = mode != NatTraversalMode::Off;
    }

    /// Sets the list of STUN servers used for server-reflexive candidate
    /// discovery.
    pub fn set_stun_servers(&mut self, servers: Vec<std::net::SocketAddr>) {
        self.nat_traversal.stun_servers = servers;
    }

    /// Sets the list of TURN servers used for relayed candidates.
    pub fn set_turn_servers(&mut self, servers: Vec<std::net::SocketAddr>) {
        self.nat_traversal.turn_servers = servers;
    }

    /// Enables or disables ICE candidate gathering and pair selection.
    pub fn enable_ice(&mut self, enabled: bool) {
        self.nat_traversal.ice_enabled = enabled;
    }

    /// Sets the minimum interval between NAT discovery probe bursts.
    pub fn set_nat_probe_interval_ms(&mut self, interval_ms: u64) {
        self.nat_traversal.probe_interval_ms = interval_ms.max(1_000);
    }

    /// Sets the maximum number of candidates returned by one discovery run.
    pub fn set_nat_max_candidates(&mut self, max_candidates: usize) {
        self.nat_traversal.max_candidates = max_candidates.max(1);
    }

    /// Returns true if NAT traversal is enabled.
    pub fn nat_traversal_enabled(&self) -> bool {
        self.nat_traversal.enabled
    }

    /// Returns true if ICE is enabled.
    pub fn ice_enabled(&self) -> bool {
        self.nat_traversal.ice_enabled
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
        let key_data = Zeroizing::new(std::fs::read(path).map_err(|e| {
            crate::error::ConnectionError::TlsError(format!(
                "Private key read failed ({}): {}",
                path, e
            ))
        })?);
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
        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert).map_err(|error| {
                crate::error::ConnectionError::TlsError(format!(
                    "CA certificate validation failed ({}): {}",
                    file, error
                ))
            })?;
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
    /// Installs a TLS session ticket encryption key (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if _key.is_empty() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.ticket_key =
            Some(crate::secret::SecretBytes::new(_key.to_vec(), "tls_ticket_encryption_key"));
        Ok(())
    }
    // duplicate removed: enable_early_data
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
        self.tls_session =
            Some(crate::secret::SecretBytes::new(ticket.to_vec(), "tls_config_session_ticket"));
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

    // --- Traffic analysis defense setters (TODO-455) ---

    /// Sets the traffic analysis defense mode.
    pub fn set_traffic_analysis_defense(&mut self, mode: TrafficAnalysisDefense) {
        self.traffic_analysis_defense = mode;
        if matches!(mode, TrafficAnalysisDefense::ConstantRate)
            && self.constant_rate_pps > 0
            && self.chaff_rate_pps == 0
        {
            // Constant-rate mode needs chaff to fill gaps; default chaff rate
            // to the constant target so idle periods are covered.
            self.chaff_rate_pps = self.constant_rate_pps;
        }
    }

    /// Sets the traffic analysis defense mode from a string identifier.
    /// Returns `Err(InvalidState)` for unrecognized identifiers.
    pub fn set_traffic_analysis_defense_str(
        &mut self,
        s: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        match TrafficAnalysisDefense::parse(s) {
            Some(mode) => {
                self.set_traffic_analysis_defense(mode);
                Ok(())
            }
            None => Err(crate::error::ConnectionError::InvalidState),
        }
    }

    /// Sets the chaff (dummy packet) injection rate in packets per second.
    /// 0 disables chaffing. Values are clamped to a sane maximum (10000 pps).
    pub fn set_chaff_rate_pps(&mut self, pps: u32) {
        self.chaff_rate_pps = pps.min(10_000);
    }

    /// Sets the target chaff packet size in bytes. Clamped to [64, 65535].
    pub fn set_chaff_size_bytes(&mut self, size: u32) {
        self.chaff_size_bytes = size.clamp(64, 65_535);
    }

    /// Sets the constant-rate target emission rate in packets per second.
    /// 0 disables constant-rate shaping. Clamped to a sane maximum (1000 pps).
    /// Enabling this (non-zero) with chaff disabled auto-enables chaff at the
    /// same rate via `set_traffic_analysis_defense`.
    pub fn set_constant_rate_pps(&mut self, pps: u32) {
        self.constant_rate_pps = pps.min(1_000);
    }

    /// Sets the full-rate idle window, bounded to one hour.
    pub fn set_chaff_idle_timeout_ms(&mut self, timeout_ms: u64) {
        self.chaff_idle_timeout_ms = timeout_ms.min(3_600_000);
    }

    /// Sets the soft-stop ramp duration, bounded to one minute.
    pub fn set_chaff_ramp_down_ms(&mut self, ramp_down_ms: u64) {
        self.chaff_ramp_down_ms = ramp_down_ms.min(60_000);
    }

    /// Atomically applies one validated traffic-analysis policy.
    pub fn set_traffic_analysis_policy(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        let policy = policy.validate()?;
        self.traffic_analysis_defense = policy.defense;
        self.chaff_rate_pps = policy.chaff_rate_pps;
        self.chaff_size_bytes = policy.chaff_size_bytes;
        self.constant_rate_pps = policy.constant_rate_pps;
        self.chaff_idle_timeout_ms = policy.idle_timeout_ms;
        self.chaff_ramp_down_ms = policy.ramp_down_ms;
        Ok(())
    }

    /// Sets the independent ceiling for authenticated per-QKey policy requests.
    pub fn set_qkey_traffic_analysis_ceiling(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        self.qkey_traffic_analysis_ceiling = policy.validate()?;
        Ok(())
    }

    /// Sets the operator ceiling for post-authentication Intelligent escalation.
    pub fn set_intelligent_traffic_analysis_ceiling(
        &mut self,
        policy: TrafficAnalysisPolicy,
    ) -> Result<(), &'static str> {
        self.intelligent_traffic_analysis_ceiling = policy.validate()?;
        Ok(())
    }

    /// Returns the active traffic analysis defense mode.
    pub fn traffic_analysis_defense(&self) -> TrafficAnalysisDefense {
        self.traffic_analysis_defense
    }

    /// Returns the configured chaff rate in packets per second.
    pub fn chaff_rate_pps(&self) -> u32 {
        self.chaff_rate_pps
    }

    /// Returns the configured chaff packet size in bytes.
    pub fn chaff_size_bytes(&self) -> u32 {
        self.chaff_size_bytes
    }

    /// Returns the configured constant-rate target in packets per second.
    pub fn constant_rate_pps(&self) -> u32 {
        self.constant_rate_pps
    }

    /// Returns the full-rate idle window in milliseconds.
    pub fn chaff_idle_timeout_ms(&self) -> u64 {
        self.chaff_idle_timeout_ms
    }

    /// Returns the soft-stop ramp duration in milliseconds.
    pub fn chaff_ramp_down_ms(&self) -> u64 {
        self.chaff_ramp_down_ms
    }

    /// Returns the complete effective traffic-analysis policy.
    pub fn traffic_analysis_policy(&self) -> TrafficAnalysisPolicy {
        TrafficAnalysisPolicy {
            defense: self.traffic_analysis_defense,
            chaff_rate_pps: self.chaff_rate_pps,
            chaff_size_bytes: self.chaff_size_bytes,
            constant_rate_pps: self.constant_rate_pps,
            idle_timeout_ms: self.chaff_idle_timeout_ms,
            ramp_down_ms: self.chaff_ramp_down_ms,
        }
    }

    /// Returns the authenticated per-QKey traffic-analysis policy ceiling.
    pub fn qkey_traffic_analysis_ceiling(&self) -> TrafficAnalysisPolicy {
        self.qkey_traffic_analysis_ceiling
    }

    /// Returns the post-authentication Intelligent escalation ceiling.
    pub fn intelligent_traffic_analysis_ceiling(&self) -> TrafficAnalysisPolicy {
        self.intelligent_traffic_analysis_ceiling
    }

    // duplicate removed: load_verify_locations_from_directory
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::PROTOCOL_VERSION;

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
    fn test_ca_file_rejects_invalid_certificate_der_without_storing_path() {
        let path = std::env::temp_dir().join(format!(
            "quicfuscate-invalid-ca-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::write(&path, b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
            .expect("write invalid CA fixture");
        let path_string = path.to_string_lossy().into_owned();
        let mut config = default_config();
        let error = config
            .load_verify_locations_from_file(&path_string)
            .expect_err("invalid certificate DER must fail closed");
        let message = error.to_string();
        assert!(message.contains(&path_string));
        assert!(!message.contains("AA=="));
        assert!(config.verify_locations_file.is_none());
        std::fs::remove_file(path).expect("remove invalid CA fixture");
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
        assert!(cfg.pmtu_discovery_enabled()); // DPLPMTUD now enabled by default
    }

    #[test]
    fn test_nat_traversal_defaults_to_disabled() {
        let cfg = default_config();
        assert!(!cfg.nat_traversal_enabled(), "NAT traversal must be off by default");
        assert!(!cfg.ice_enabled(), "ICE must be off by default");
        assert_eq!(cfg.nat_traversal().mode, NatTraversalMode::Off);
        assert_eq!(
            cfg.nat_traversal().probe_interval_ms,
            NatTraversalConfig::DEFAULT_PROBE_INTERVAL_MS
        );
        assert_eq!(cfg.nat_traversal().max_candidates, NatTraversalConfig::DEFAULT_MAX_CANDIDATES);
        assert!(cfg.nat_traversal().stun_servers.is_empty());
        assert!(cfg.nat_traversal().turn_servers.is_empty());
    }

    #[test]
    fn test_nat_traversal_setters() {
        let mut cfg = default_config();
        let stun: std::net::SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let turn: std::net::SocketAddr = "203.0.113.2:3478".parse().unwrap();
        cfg.set_stun_servers(vec![stun]);
        cfg.set_turn_servers(vec![turn]);
        cfg.enable_nat_traversal(true);
        cfg.enable_ice(true);
        cfg.set_nat_probe_interval_ms(250);
        cfg.set_nat_max_candidates(0);
        assert!(cfg.nat_traversal_enabled());
        assert!(cfg.ice_enabled());
        assert_eq!(cfg.nat_traversal().mode, NatTraversalMode::ConnectivityFallback);
        assert_eq!(cfg.nat_traversal().probe_interval_ms, 1000);
        assert_eq!(cfg.nat_traversal().max_candidates, 1);
        assert_eq!(cfg.nat_traversal().stun_servers, vec![stun]);
        assert_eq!(cfg.nat_traversal().turn_servers, vec![turn]);
    }

    #[test]
    fn test_nat_traversal_config_serde_roundtrip() {
        let nat = NatTraversalConfig {
            enabled: true,
            mode: NatTraversalMode::Roaming,
            stun_servers: vec!["203.0.113.1:3478".parse().unwrap()],
            turn_servers: vec!["203.0.113.2:3478".parse().unwrap()],
            ice_enabled: true,
            probe_interval_ms: 45_000,
            max_candidates: 4,
        };
        let json = serde_json::to_string(&nat).unwrap();
        let decoded: NatTraversalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(nat, decoded);
    }

    #[test]
    fn test_nat_traversal_policy_reasons() {
        let mut nat = NatTraversalConfig {
            enabled: true,
            mode: NatTraversalMode::ConnectivityFallback,
            ..NatTraversalConfig::default()
        };
        assert!(nat.allows_discovery(NatDiscoveryReason::ConnectivityFailure));
        assert!(nat.allows_discovery(NatDiscoveryReason::Manual));
        assert!(!nat.allows_discovery(NatDiscoveryReason::Roaming));
        assert!(!nat.allows_discovery(NatDiscoveryReason::Mesh));

        nat.mode = NatTraversalMode::Roaming;
        assert!(nat.allows_discovery(NatDiscoveryReason::Roaming));
        assert!(!nat.allows_discovery(NatDiscoveryReason::Mesh));

        nat.mode = NatTraversalMode::Mesh;
        assert!(nat.allows_discovery(NatDiscoveryReason::Mesh));
    }

    #[test]
    fn test_parse_server_addr_valid() {
        let addr = NatTraversalConfig::parse_server_addr("127.0.0.1:3478").unwrap();
        assert_eq!(addr.port(), 3478);
    }

    #[test]
    fn test_parse_server_addr_invalid() {
        assert!(NatTraversalConfig::parse_server_addr("not-an-address").is_err());
    }

    #[test]
    fn test_set_cc_algorithm_name_valid() {
        let mut cfg = default_config();
        assert!(cfg.set_cc_algorithm_name("reno").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::Reno));
        assert!(cfg.set_cc_algorithm_name("cubic").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::Cubic));
        assert!(cfg.set_cc_algorithm_name("bbr2").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR2));
        assert!(cfg.set_cc_algorithm_name("BBR3").is_ok());
        assert!(matches!(cfg.cc_algorithm(), CongestionControlAlgorithm::BBR3));
    }

    #[test]
    fn test_set_cc_algorithm_name_invalid() {
        let mut cfg = default_config();
        assert!(cfg.set_cc_algorithm_name("vegas").is_err());
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
    fn migration_policy_validates_factor_cooldown_and_probe_target() {
        let mut cfg = default_config();
        let policy = MigrationPolicy {
            port_rebinding_cwnd_factor: 0.25,
            cooldown: std::time::Duration::ZERO,
            probe_target: MigrationProbeTarget::ReducedWindow,
        };
        cfg.set_migration_policy(policy).unwrap();
        assert_eq!(cfg.migration_policy(), policy);

        for factor in [f64::NAN, f64::INFINITY, -0.01, 1.01] {
            let invalid = MigrationPolicy { port_rebinding_cwnd_factor: factor, ..policy };
            assert!(cfg.set_migration_policy(invalid).is_err());
        }
        let excessive =
            MigrationPolicy { cooldown: std::time::Duration::from_millis(60_001), ..policy };
        assert!(cfg.set_migration_policy(excessive).is_err());
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
    fn tls_test_key_and_session_replacement_and_drop_erase_owned_bytes() {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<(&'static str, Vec<u8>)>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            observed.lock().expect("erasure event lock").push((label, bytes.to_vec()));
        }));

        let mut cfg = default_config();
        cfg.set_ticket_key(&[0x31; 32]).expect("set first ticket key");
        cfg.set_ticket_key(&[0x42; 32]).expect("replace ticket key");
        cfg.set_session(&[0x53; 48]);
        cfg.set_session(&[0x64; 48]);
        drop(cfg);

        let events = events.lock().expect("erasure events");
        for (label, expected_len) in
            [("tls_ticket_encryption_key", 32), ("tls_config_session_ticket", 48)]
        {
            let matching =
                events.iter().filter(|(event_label, _)| *event_label == label).collect::<Vec<_>>();
            assert_eq!(matching.len(), 2, "replacement and drop must erase {label}");
            for (_, bytes) in matching {
                assert_eq!(bytes.len(), expected_len);
                assert!(bytes.iter().all(|byte| *byte == 0));
            }
        }
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

    // --- Traffic analysis defense tests (TODO-455) ---

    #[test]
    fn test_traffic_analysis_defense_default_is_off() {
        let cfg = default_config();
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::Off);
        assert_eq!(cfg.chaff_rate_pps(), 0);
        assert_eq!(cfg.chaff_size_bytes(), 1280);
        assert_eq!(cfg.constant_rate_pps(), 100);
        assert_eq!(cfg.chaff_idle_timeout_ms(), 30_000);
        assert_eq!(cfg.chaff_ramp_down_ms(), 5_000);
        assert_eq!(cfg.qkey_traffic_analysis_ceiling(), TrafficAnalysisPolicy::safety_ceiling());
        assert_eq!(cfg.intelligent_traffic_analysis_ceiling(), TrafficAnalysisPolicy::default());
    }

    #[test]
    fn test_traffic_analysis_defense_parse_all_modes() {
        // Off variants
        assert_eq!(TrafficAnalysisDefense::parse("off"), Some(TrafficAnalysisDefense::Off));
        assert_eq!(TrafficAnalysisDefense::parse("Off"), Some(TrafficAnalysisDefense::Off));
        assert_eq!(TrafficAnalysisDefense::parse("disabled"), Some(TrafficAnalysisDefense::Off));
        assert_eq!(TrafficAnalysisDefense::parse("none"), Some(TrafficAnalysisDefense::Off));
        assert_eq!(TrafficAnalysisDefense::parse(""), Some(TrafficAnalysisDefense::Off));
        // FullPadding variants
        assert_eq!(
            TrafficAnalysisDefense::parse("full"),
            Some(TrafficAnalysisDefense::FullPadding)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("Full"),
            Some(TrafficAnalysisDefense::FullPadding)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("full-padding"),
            Some(TrafficAnalysisDefense::FullPadding)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("fullpadding"),
            Some(TrafficAnalysisDefense::FullPadding)
        );
        // ConstantRate variants
        assert_eq!(
            TrafficAnalysisDefense::parse("constant"),
            Some(TrafficAnalysisDefense::ConstantRate)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("Constant"),
            Some(TrafficAnalysisDefense::ConstantRate)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("constant-rate"),
            Some(TrafficAnalysisDefense::ConstantRate)
        );
        assert_eq!(
            TrafficAnalysisDefense::parse("constantrate"),
            Some(TrafficAnalysisDefense::ConstantRate)
        );
        // Unknown
        assert_eq!(TrafficAnalysisDefense::parse("garbage"), None);
    }

    #[test]
    fn test_traffic_analysis_defense_setter_modes() {
        let mut cfg = default_config();
        cfg.set_traffic_analysis_defense(TrafficAnalysisDefense::FullPadding);
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::FullPadding);
        cfg.set_traffic_analysis_defense(TrafficAnalysisDefense::ConstantRate);
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::ConstantRate);
        // ConstantRate auto-enables chaff at the constant target rate when chaff is disabled
        assert_eq!(cfg.chaff_rate_pps(), 100);
        cfg.set_traffic_analysis_defense(TrafficAnalysisDefense::Off);
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::Off);
    }

    #[test]
    fn test_traffic_analysis_defense_str_setter() {
        let mut cfg = default_config();
        assert!(cfg.set_traffic_analysis_defense_str("full").is_ok());
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::FullPadding);
        assert!(cfg.set_traffic_analysis_defense_str("constant-rate").is_ok());
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::ConstantRate);
        assert!(cfg.set_traffic_analysis_defense_str("off").is_ok());
        assert_eq!(cfg.traffic_analysis_defense(), TrafficAnalysisDefense::Off);
        assert!(cfg.set_traffic_analysis_defense_str("nonsense").is_err());
    }

    #[test]
    fn test_chaff_rate_clamped() {
        let mut cfg = default_config();
        cfg.set_chaff_rate_pps(0);
        assert_eq!(cfg.chaff_rate_pps(), 0);
        cfg.set_chaff_rate_pps(50);
        assert_eq!(cfg.chaff_rate_pps(), 50);
        // Clamped to 10000
        cfg.set_chaff_rate_pps(99_999);
        assert_eq!(cfg.chaff_rate_pps(), 10_000);
    }

    #[test]
    fn test_chaff_size_clamped() {
        let mut cfg = default_config();
        cfg.set_chaff_size_bytes(0);
        assert_eq!(cfg.chaff_size_bytes(), 64);
        cfg.set_chaff_size_bytes(1400);
        assert_eq!(cfg.chaff_size_bytes(), 1400);
        cfg.set_chaff_size_bytes(100_000);
        assert_eq!(cfg.chaff_size_bytes(), 65_535);
    }

    #[test]
    fn test_constant_rate_clamped() {
        let mut cfg = default_config();
        cfg.set_constant_rate_pps(0);
        assert_eq!(cfg.constant_rate_pps(), 0);
        cfg.set_constant_rate_pps(250);
        assert_eq!(cfg.constant_rate_pps(), 250);
        cfg.set_constant_rate_pps(99_999);
        assert_eq!(cfg.constant_rate_pps(), 1_000);
    }

    #[test]
    fn test_chaff_lifecycle_bounds() {
        let mut cfg = default_config();
        cfg.set_chaff_idle_timeout_ms(u64::MAX);
        cfg.set_chaff_ramp_down_ms(u64::MAX);
        assert_eq!(cfg.chaff_idle_timeout_ms(), 3_600_000);
        assert_eq!(cfg.chaff_ramp_down_ms(), 60_000);
    }

    #[test]
    fn test_traffic_analysis_policy_is_bounded_by_global_ceiling() {
        let requested = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1400,
            constant_rate_pps: 100,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };
        let ceiling = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 8,
            chaff_size_bytes: 1280,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };

        assert_eq!(
            requested.bounded_by(ceiling),
            TrafficAnalysisPolicy {
                defense: TrafficAnalysisDefense::FullPadding,
                chaff_rate_pps: 8,
                chaff_size_bytes: 1280,
                constant_rate_pps: 0,
                idle_timeout_ms: 20_000,
                ramp_down_ms: 2_000,
            }
        );
    }

    #[test]
    fn test_traffic_analysis_policy_rejects_unbounded_constant_rate() {
        let policy = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            constant_rate_pps: TrafficAnalysisPolicy::MAX_CONSTANT_RATE_PPS + 1,
            ..TrafficAnalysisPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_traffic_analysis_cost_uses_mode_specific_wire_target() {
        let full_padding = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1280,
            ..TrafficAnalysisPolicy::default()
        };
        let constant_rate = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            constant_rate_pps: 100,
            chaff_size_bytes: 1280,
            ..TrafficAnalysisPolicy::default()
        };

        assert_eq!(full_padding.estimated_max_bits_per_second(1500), 120_000);
        assert_eq!(constant_rate.estimated_max_bits_per_second(1500), 1_024_000);
        assert_eq!(constant_rate.estimated_max_bits_per_second(1200), 960_000);
    }

    #[test]
    fn test_qkey_traffic_analysis_ceiling_is_independent_from_active_policy() {
        let mut config = default_config();
        let ceiling = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1200,
            constant_rate_pps: 0,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };

        config.set_qkey_traffic_analysis_ceiling(ceiling).expect("valid ceiling");

        assert_eq!(config.traffic_analysis_policy().defense, TrafficAnalysisDefense::Off);
        assert_eq!(config.qkey_traffic_analysis_ceiling(), ceiling);
    }

    #[test]
    fn test_stronger_constant_rate_caps_a_full_padding_escalation_rate() {
        let requested = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 100,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };
        let ceiling = TrafficAnalysisPolicy {
            defense: TrafficAnalysisDefense::FullPadding,
            chaff_rate_pps: 10,
            chaff_size_bytes: 1200,
            constant_rate_pps: 0,
            idle_timeout_ms: 30_000,
            ramp_down_ms: 5_000,
        };

        let bounded = requested.bounded_by(ceiling);

        assert_eq!(bounded.defense, TrafficAnalysisDefense::FullPadding);
        assert_eq!(bounded.chaff_rate_pps, 10);
        assert_eq!(bounded.constant_rate_pps, 0);
    }

    #[test]
    fn test_traffic_analysis_defense_serde_roundtrip() {
        let off: TrafficAnalysisDefense = serde_json::from_str("\"off\"").expect("off parses");
        assert_eq!(off, TrafficAnalysisDefense::Off);
        let full: TrafficAnalysisDefense =
            serde_json::from_str("\"full-padding\"").expect("full parses");
        assert_eq!(full, TrafficAnalysisDefense::FullPadding);
        let constant: TrafficAnalysisDefense =
            serde_json::from_str("\"constant-rate\"").expect("constant parses");
        assert_eq!(constant, TrafficAnalysisDefense::ConstantRate);
        // Roundtrip serialization
        assert_eq!(
            serde_json::to_string(&TrafficAnalysisDefense::FullPadding).unwrap(),
            "\"FullPadding\""
        );
    }

    // --- QUIC version negotiation (TODO-453) ---

    #[test]
    fn test_default_supported_versions_is_v1_only() {
        let cfg = default_config();
        assert_eq!(cfg.supported_versions(), &[PROTOCOL_VERSION]);
    }

    #[test]
    fn test_set_supported_versions_v1_and_v2() {
        let mut cfg = default_config();
        cfg.set_supported_versions(vec![crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION])
            .expect("v1+v2 accepted");
        assert_eq!(
            cfg.supported_versions(),
            &[crate::transport::PROTOCOL_VERSION_V2, PROTOCOL_VERSION]
        );
    }

    #[test]
    fn test_set_supported_versions_rejects_empty() {
        let mut cfg = default_config();
        assert!(cfg.set_supported_versions(Vec::new()).is_err());
    }

    #[test]
    fn test_set_supported_versions_rejects_unknown() {
        let mut cfg = default_config();
        assert!(cfg.set_supported_versions(vec![PROTOCOL_VERSION, 0xdeadbeef]).is_err());
        // 0x00000002 is not a recognized QUIC version (v2 is 0x6b3343cf per RFC 9369)
        assert!(cfg.set_supported_versions(vec![0x00000002]).is_err());
    }

    // --- Multipath support (TODO-449) ---

    #[test]
    fn test_multipath_defaults_to_disabled_with_three_paths() {
        let cfg = default_config();
        assert!(!cfg.multipath_enabled());
        assert_eq!(cfg.max_paths(), 3);
    }

    #[test]
    fn test_set_multipath_enabled_toggles_flag() {
        let mut cfg = default_config();
        cfg.set_multipath_enabled(true);
        assert!(cfg.multipath_enabled());
        cfg.set_multipath_enabled(false);
        assert!(!cfg.multipath_enabled());
    }

    #[test]
    fn test_set_max_paths_clamped_to_at_least_one() {
        let mut cfg = default_config();
        cfg.set_max_paths(0);
        assert_eq!(cfg.max_paths(), 1);
        cfg.set_max_paths(8);
        assert_eq!(cfg.max_paths(), 8);
    }

    #[test]
    fn pmtu_policy_defaults_cover_ipv6_floor_and_1500_ceiling() {
        let cfg = default_config();
        let policy = cfg.pmtu_policy();

        assert_eq!(policy.min_mtu, 1280);
        assert_eq!(policy.max_mtu, 1500);
        assert_eq!(policy.probe_interval, std::time::Duration::from_secs(60));
        assert_eq!(policy.black_hole_timeout, std::time::Duration::from_secs(10));
    }

    #[test]
    fn pmtu_policy_rejects_unsafe_or_inverted_bounds() {
        let mut cfg = default_config();
        let invalid = PmtuPolicy { min_mtu: 1199, ..PmtuPolicy::default() };
        assert!(cfg.set_pmtu_policy(invalid).is_err());

        let inverted = PmtuPolicy { min_mtu: 1500, max_mtu: 1400, ..PmtuPolicy::default() };
        assert!(cfg.set_pmtu_policy(inverted).is_err());
    }
}
