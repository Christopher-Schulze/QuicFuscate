//! QuicFuscate Engine Configuration
//!
//! This module provides comprehensive configuration structures for the QuicFuscate engine.
//! All settings can be loaded from a TOML configuration file.
//!
//! # Example
//!
//! ```ignore
//! use quicfuscate::engine::EngineConfig;
//!
//! let config = EngineConfig::from_file("config/quicfuscate.toml")?;
//! config.validate()?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use crate::audit::{
    AuditOptions, DEFAULT_AUDIT_FLUSH_TIMEOUT_MS, DEFAULT_AUDIT_MAX_SEGMENTS,
    DEFAULT_AUDIT_MAX_SEGMENT_BYTES, DEFAULT_AUDIT_QUEUE_CAPACITY,
};

// Re-export existing configs for aggregation
pub use crate::fec::FecConfig;
pub use crate::optimize::OptimizeConfig;
pub use crate::stealth::StealthConfig;

/// Complete engine configuration aggregating all subsystems.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    /// Engine mode and lifecycle settings
    pub engine: EngineSection,
    /// Connection parameters (remote, TLS, streams)
    pub connection: ConnectionConfig,
    /// Transport layer settings (CC, MTU, pacing)
    pub transport: TransportConfig,
    /// Optional NAT path discovery settings (STUN/TURN/ICE).
    pub nat_traversal: NatTraversalSection,
    /// Cryptographic settings (AEAD, PQ)
    pub crypto: CryptoConfig,
    /// TUN interface settings
    pub interface: InterfaceConfig,
    /// Telemetry and metrics settings
    pub telemetry: TelemetryConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Security audit persistence configuration
    pub audit: AuditConfig,
    /// Forward Error Correction settings
    #[serde(rename = "fec")]
    pub fec: FecSection,
    /// Stealth and obfuscation settings
    pub stealth: StealthSection,
    /// Fingerprint rotation settings
    pub fingerprint_rotation: FingerprintRotationConfig,
    /// Performance optimization settings
    pub optimization: OptimizationConfig,
    /// 0-RTT anti-replay protection settings
    pub anti_replay: AntiReplaySection,
    /// Security settings (kill switch, leak prevention)
    #[serde(default)]
    pub security: SecurityConfig,
}

impl EngineConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents =
            std::fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Validate all configuration sections.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.engine.validate()?;
        self.connection.validate()?;
        self.transport.validate()?;
        self.nat_traversal.validate()?;
        self.crypto.validate()?;
        self.interface.validate()?;
        self.telemetry.validate()?;
        self.logging.validate()?;
        self.audit.validate()?;
        self.fec.validate()?;
        self.fingerprint_rotation.validate()?;
        self.optimization.validate()?;
        self.anti_replay.validate()?;
        self.security.validate()?;
        self.stealth
            .to_runtime_config(&self.fingerprint_rotation)
            .map_err(|error| ConfigError::Validation(format!("stealth: {error}")))?;
        if self.connection.enable_0rtt && !self.anti_replay.enabled {
            log::warn!(
                "[config] 0-RTT enabled without anti-replay protection. \
                 Set [anti_replay] enabled = true for production use."
            );
        }
        Ok(())
    }

    /// Create a builder for programmatic configuration.
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }
}

/// Configuration errors returned during file loading, TOML parsing, or validation.
///
/// Each variant carries a human-readable description of the failure.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Filesystem I/O error (file not found, permission denied, etc.)
    Io(String),
    /// TOML deserialization error (syntax, missing fields, type mismatches)
    Parse(String),
    /// Semantic validation error (invalid ranges, conflicting settings)
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::Validation(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// ENGINE SECTION
// ============================================================================

/// Engine lifecycle and mode settings.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EngineSection {
    /// Engine operation mode: "client" or "server"
    pub mode: EngineMode,
    /// Log level override (trace, debug, info, warn, error)
    pub log_level: String,
    /// Auto-start on engine creation
    pub auto_start: bool,
    /// Graceful shutdown timeout in milliseconds
    pub shutdown_timeout_ms: u64,
}

impl Default for EngineSection {
    fn default() -> Self {
        Self {
            mode: EngineMode::Client,
            log_level: "info".to_string(),
            auto_start: false,
            shutdown_timeout_ms: 5000,
        }
    }
}

impl EngineSection {
    fn validate(&self) -> Result<(), ConfigError> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.log_level.to_lowercase().as_str()) {
            return Err(ConfigError::Validation(format!(
                "Invalid log_level: {}. Must be one of: {:?}",
                self.log_level, valid_levels
            )));
        }
        if self.shutdown_timeout_ms == 0 {
            return Err(ConfigError::Validation("engine.shutdown_timeout_ms must be > 0".into()));
        }
        Ok(())
    }
}

/// Engine operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    /// Run as a VPN client connecting to a remote server.
    #[default]
    Client,
    /// Run as a VPN server accepting incoming connections.
    Server,
}

// ============================================================================
// CONNECTION SECTION
// ============================================================================

/// Connection parameters for QUIC connections.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectionConfig {
    /// Remote endpoint (server: listen addr, client: server addr)
    pub remote: String,
    /// Local bind address (optional)
    pub local: String,
    /// Verify peer certificate
    pub verify_peer: bool,
    /// Custom CA file path (empty = system CAs)
    pub ca_file: String,
    /// TLS certificate file (server mode)
    pub cert_file: String,
    /// TLS private key file (server mode)
    pub key_file: String,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Server Name Indication (client mode)
    pub sni: String,
    /// QKey token (hex, client mode only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_token: Option<crate::engine::qkey::QKeyToken>,
    /// QKey id (public identifier, client mode only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_id: Option<String>,
    /// Connection idle timeout in milliseconds
    pub idle_timeout_ms: u64,
    /// Enable 0-RTT early data
    pub enable_0rtt: bool,
    /// Maximum bidirectional streams
    pub max_streams_bidi: u64,
    /// Maximum unidirectional streams
    pub max_streams_uni: u64,
    /// Enable validated connection migration
    pub enable_migration: bool,
    /// Retained congestion-window fraction for port-only rebinding.
    pub migration_cwnd_reduction_factor: f64,
    /// Minimum interval between successful migrations.
    pub migration_cooldown_ms: u64,
    /// Congestion recovery boundary after port-only rebinding.
    pub migration_probe_target: crate::transport::MigrationProbeTarget,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            remote: "0.0.0.0:4433".to_string(),
            local: String::new(),
            verify_peer: true,
            ca_file: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            alpn: vec!["h3".to_string(), "quicfuscate".to_string()],
            sni: String::new(),
            qkey_token: None,
            qkey_id: None,
            idle_timeout_ms: 30000,
            enable_0rtt: true,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            enable_migration: true,
            migration_cwnd_reduction_factor: 0.5,
            migration_cooldown_ms: 750,
            migration_probe_target: crate::transport::MigrationProbeTarget::PreviousWindow,
        }
    }
}

impl ConnectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let remote = self.remote.trim();
        if remote.is_empty() {
            return Err(ConfigError::Validation("remote address cannot be empty".into()));
        }
        remote.parse::<SocketAddr>().map_err(|error| {
            ConfigError::Validation(format!("connection.remote must be a socket address: {error}"))
        })?;
        if !self.local.trim().is_empty() {
            self.local.trim().parse::<SocketAddr>().map_err(|error| {
                ConfigError::Validation(format!(
                    "connection.local must be a socket address: {error}"
                ))
            })?;
        }
        if self.idle_timeout_ms == 0 {
            return Err(ConfigError::Validation("idle_timeout_ms must be > 0".into()));
        }
        if self.max_streams_bidi == 0 || self.max_streams_uni == 0 {
            return Err(ConfigError::Validation(
                "connection.max_streams_bidi and max_streams_uni must be > 0".into(),
            ));
        }
        if self.cert_file.trim().is_empty() != self.key_file.trim().is_empty() {
            return Err(ConfigError::Validation(
                "connection.cert_file and connection.key_file must be configured together".into(),
            ));
        }
        if !self.migration_cwnd_reduction_factor.is_finite()
            || !(0.0..=1.0).contains(&self.migration_cwnd_reduction_factor)
        {
            return Err(ConfigError::Validation(
                "migration_cwnd_reduction_factor must be finite and within [0, 1]".into(),
            ));
        }
        if self.migration_cooldown_ms > 60_000 {
            return Err(ConfigError::Validation(
                "migration_cooldown_ms must not exceed 60000".into(),
            ));
        }
        if let Some(id) = self.qkey_id.as_deref() {
            let id = id.trim();
            if !id.is_empty() && (id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(ConfigError::Validation("qkey_id must be 12 hex chars".into()));
            }
        }
        Ok(())
    }
}

// ============================================================================
// TRANSPORT SECTION
// ============================================================================

/// Standards-based QUIC wire version.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum QuicVersion {
    /// QUIC version 2 (RFC 9369).
    V2,
    /// QUIC version 1 (RFC 9000).
    V1,
}

impl QuicVersion {
    pub(crate) fn wire_version(self) -> u32 {
        match self {
            Self::V2 => crate::transport::PROTOCOL_VERSION_V2,
            Self::V1 => crate::transport::PROTOCOL_VERSION,
        }
    }
}

/// Transport layer configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Ordered usable QUIC versions, preferred first.
    pub quic_versions: Vec<QuicVersion>,
    /// Congestion control algorithm
    pub cc_algorithm: CcAlgorithm,
    /// Maximum Transmission Unit
    pub mtu: u16,
    /// Maximum UDP payload size
    pub max_udp_payload: u16,
    /// Maximum idle timeout in milliseconds
    pub max_idle_timeout: u64,
    /// Initial RTT estimate in milliseconds
    pub initial_rtt_ms: u64,
    /// Enable pacing
    pub enable_pacing: bool,
    /// Initial maximum data
    pub initial_max_data: u64,
    /// Initial maximum stream data (bidi local)
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial maximum stream data (bidi remote)
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial maximum stream data (uni)
    pub initial_max_stream_data_uni: u64,
    /// Initial maximum streams (bidi)
    pub initial_max_streams_bidi: u64,
    /// Initial maximum streams (uni)
    pub initial_max_streams_uni: u64,
    /// Enable 0-RTT early data
    pub enable_early_data: bool,
    /// QUIC DATAGRAM receive queue length (0 = disabled)
    pub dgram_recv_queue_len: usize,
    /// QUIC DATAGRAM send queue length (0 = disabled)
    pub dgram_send_queue_len: usize,
    /// Disable path MTU discovery
    pub disable_pmtud: bool,
    /// Safe DPLPMTUD floor.
    pub pmtu_min_mtu: u16,
    /// Maximum DPLPMTUD probe size.
    pub pmtu_max_mtu: u16,
    /// Delay between probe attempts.
    pub pmtu_probe_interval_ms: u64,
    /// Large-packet ACK silence before black-hole recovery.
    pub pmtu_black_hole_timeout_ms: u64,
    /// Active traffic-analysis defense policy.
    pub traffic_analysis: crate::transport::config::TrafficAnalysisPolicy,
    /// Hard ceiling for authenticated per-QKey traffic-analysis requests.
    pub qkey_traffic_analysis_ceiling: crate::transport::config::TrafficAnalysisPolicy,
    /// Ceiling for post-authentication Intelligent traffic-analysis escalation.
    pub intelligent_traffic_analysis_ceiling: crate::transport::config::TrafficAnalysisPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            quic_versions: vec![QuicVersion::V2, QuicVersion::V1],
            cc_algorithm: CcAlgorithm::Bbr3,
            mtu: 1500,
            max_udp_payload: 1500,
            max_idle_timeout: 30000,
            initial_rtt_ms: 100,
            enable_pacing: true,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            enable_early_data: false,
            dgram_recv_queue_len: 1024,
            dgram_send_queue_len: 1024,
            disable_pmtud: false,
            pmtu_min_mtu: 1280,
            pmtu_max_mtu: 1500,
            pmtu_probe_interval_ms: 60_000,
            pmtu_black_hole_timeout_ms: 10_000,
            traffic_analysis: crate::transport::config::TrafficAnalysisPolicy::default(),
            qkey_traffic_analysis_ceiling:
                crate::transport::config::TrafficAnalysisPolicy::safety_ceiling(),
            intelligent_traffic_analysis_ceiling:
                crate::transport::config::TrafficAnalysisPolicy::default(),
        }
    }
}

impl TransportConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.quic_versions.is_empty() {
            return Err(ConfigError::Validation("quic_versions must not be empty".into()));
        }
        let mut unique_versions = std::collections::HashSet::new();
        if self.quic_versions.iter().any(|version| !unique_versions.insert(*version)) {
            return Err(ConfigError::Validation(
                "quic_versions must not contain duplicates".into(),
            ));
        }
        if self.mtu < 1200 {
            return Err(ConfigError::Validation(format!(
                "MTU must be at least 1200, got {}",
                self.mtu
            )));
        }
        if self.max_udp_payload < 1200 {
            return Err(ConfigError::Validation(format!(
                "max_udp_payload must be at least 1200, got {}",
                self.max_udp_payload
            )));
        }
        if self.initial_rtt_ms == 0 {
            return Err(ConfigError::Validation("initial_rtt_ms must be > 0".into()));
        }
        if self.initial_max_data == 0
            || self.initial_max_stream_data_bidi_local == 0
            || self.initial_max_stream_data_bidi_remote == 0
            || self.initial_max_stream_data_uni == 0
            || self.initial_max_streams_bidi == 0
            || self.initial_max_streams_uni == 0
        {
            return Err(ConfigError::Validation(
                "initial transport data and stream limits must be > 0".into(),
            ));
        }
        if self.pmtu_min_mtu < 1200 || self.pmtu_max_mtu < self.pmtu_min_mtu {
            return Err(ConfigError::Validation(
                "pmtu_min_mtu must be >= 1200 and <= pmtu_max_mtu".into(),
            ));
        }
        if self.pmtu_max_mtu > self.mtu {
            return Err(ConfigError::Validation(
                "pmtu_max_mtu must not exceed transport.mtu".into(),
            ));
        }
        if self.pmtu_max_mtu > self.max_udp_payload {
            return Err(ConfigError::Validation(
                "pmtu_max_mtu must not exceed transport.max_udp_payload".into(),
            ));
        }
        if self.pmtu_probe_interval_ms == 0 || self.pmtu_black_hole_timeout_ms == 0 {
            return Err(ConfigError::Validation(
                "DPLPMTUD probe and black-hole timers must be > 0".into(),
            ));
        }
        if (self.dgram_recv_queue_len == 0) != (self.dgram_send_queue_len == 0) {
            return Err(ConfigError::Validation(
                "dgram_recv_queue_len and dgram_send_queue_len must both be 0 or both be > 0"
                    .into(),
            ));
        }
        for (name, policy) in [
            ("traffic_analysis", self.traffic_analysis),
            ("qkey_traffic_analysis_ceiling", self.qkey_traffic_analysis_ceiling),
            ("intelligent_traffic_analysis_ceiling", self.intelligent_traffic_analysis_ceiling),
        ] {
            policy
                .validate()
                .map_err(|error| ConfigError::Validation(format!("transport.{name}: {error}")))?;
        }
        Ok(())
    }
}

// ============================================================================
// NAT TRAVERSAL SECTION
// ============================================================================

/// Optional NAT path discovery configuration.
///
/// NAT traversal is a bounded connectivity tool, not a default stealth layer.
/// It remains off unless explicitly enabled and policy-approved for a concrete
/// discovery reason such as direct-path failure, roaming, or mesh mode.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatTraversalSection {
    /// Master switch. When false, no STUN/TURN/ICE probes are emitted.
    pub enabled: bool,
    /// Discovery policy: off, connectivity-fallback, roaming, mesh, always.
    pub mode: crate::transport::NatTraversalMode,
    /// STUN servers used for server-reflexive candidate discovery.
    pub stun_servers: Vec<String>,
    /// TURN servers reserved for relayed-candidate support.
    pub turn_servers: Vec<String>,
    /// Enable ICE candidate gathering.
    pub ice_enabled: bool,
    /// Minimum interval between discovery probe bursts.
    pub probe_interval_ms: u64,
    /// Maximum candidates returned by one discovery run.
    pub max_candidates: usize,
}

impl Default for NatTraversalSection {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: crate::transport::NatTraversalMode::Off,
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            ice_enabled: false,
            probe_interval_ms: crate::transport::NatTraversalConfig::DEFAULT_PROBE_INTERVAL_MS,
            max_candidates: crate::transport::NatTraversalConfig::DEFAULT_MAX_CANDIDATES,
        }
    }
}

impl NatTraversalSection {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.probe_interval_ms < 1_000 {
            return Err(ConfigError::Validation(
                "nat_traversal.probe_interval_ms must be at least 1000".into(),
            ));
        }
        if self.max_candidates == 0 {
            return Err(ConfigError::Validation(
                "nat_traversal.max_candidates must be at least 1".into(),
            ));
        }
        for value in self.stun_servers.iter().chain(self.turn_servers.iter()) {
            crate::transport::NatTraversalConfig::parse_server_addr(value)
                .map_err(|e| ConfigError::Validation(e.to_string()))?;
        }
        if !self.enabled && self.mode != crate::transport::NatTraversalMode::Off {
            return Err(ConfigError::Validation(
                "nat_traversal.mode must be off when nat_traversal.enabled is false".into(),
            ));
        }
        Ok(())
    }

    /// Convert engine TOML config into the transport-level config.
    pub fn to_transport_config(&self) -> Result<crate::transport::NatTraversalConfig, ConfigError> {
        let parse_servers = |values: &[String]| -> Result<Vec<SocketAddr>, ConfigError> {
            values
                .iter()
                .map(|value| {
                    crate::transport::NatTraversalConfig::parse_server_addr(value)
                        .map_err(|e| ConfigError::Validation(e.to_string()))
                })
                .collect()
        };

        Ok(crate::transport::NatTraversalConfig {
            enabled: self.enabled,
            mode: self.mode,
            stun_servers: parse_servers(&self.stun_servers)?,
            turn_servers: parse_servers(&self.turn_servers)?,
            ice_enabled: self.ice_enabled,
            probe_interval_ms: self.probe_interval_ms,
            max_candidates: self.max_candidates,
        }
        .normalized())
    }
}

/// Congestion control algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CcAlgorithm {
    /// TCP New Reno (RFC 6582) - conservative AIMD baseline.
    Reno,
    /// Paced CUBIC (RFC 9438) with HyStart++ (RFC 9406).
    Cubic,
    /// BBR v2 (IETF draft-ietf-ccwg-bbr) - loss-aware model-based CC.
    Bbr2,
    /// BBR v3 with stealth browser-profile shaping (default, recommended).
    #[default]
    Bbr3,
}

// ============================================================================
// CRYPTO SECTION
// ============================================================================

/// Cryptographic configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CryptoConfig {
    /// AEAD cipher preference
    pub aead_preference: AeadPreference,
    /// Force specific AEAD (for testing or deployment constraints)
    pub force_aead: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self { aead_preference: AeadPreference::Auto, force_aead: String::new() }
    }
}

impl CryptoConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let force = self.force_aead.trim();
        if !force.is_empty() {
            let v = force.to_ascii_lowercase();
            let ok = matches!(
                v.as_str(),
                "auto"
                    | "aegis-128l"
                    | "aegis128l"
                    | "aegis"
                    | "morus"
                    | "morus-1280-128"
                    | "morus1280-128"
            );
            if !ok {
                return Err(ConfigError::Validation(format!(
                    "crypto.force_aead has unsupported value: {force}"
                )));
            }
        }

        Ok(())
    }
}

/// AEAD cipher preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AeadPreference {
    /// Automatically select the best AEAD for the detected CPU features.
    #[default]
    Auto,
    /// Prefer the AEGIS-128L product family on capable hardware.
    #[serde(rename = "aegis-128l")]
    Aegis128L,
    /// Prefer MORUS-1280-128 AEAD.
    Morus,
}

// ============================================================================
// INTERFACE SECTION
// ============================================================================

/// Canonical IPv4 address assigned to a client TUN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTunnelIpv4 {
    /// Client-side IPv4 address.
    pub address: Ipv4Addr,
    /// Contiguous IPv4 prefix length.
    pub prefix: u8,
}

/// Canonical IPv6 address assigned to a client TUN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientTunnelIpv6 {
    /// Client-side IPv6 address.
    pub address: Ipv6Addr,
    /// IPv6 prefix length.
    pub prefix: u8,
}

/// Canonical client tunnel address model.
///
/// Each family is optional, so the model represents IPv4-only, IPv6-only, and
/// dual-stack client interfaces without overloading the IPv4 fields in
/// [`crate::interface::TunConfig`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientTunnelAddresses {
    /// Optional IPv4 client address and prefix.
    pub ipv4: Option<ClientTunnelIpv4>,
    /// Optional IPv6 client address and prefix.
    pub ipv6: Option<ClientTunnelIpv6>,
}

impl ClientTunnelAddresses {
    /// Project the canonical address model into the native TUN configuration.
    pub(crate) fn to_tun_config(
        self,
        name: Option<String>,
        mtu: u16,
        zero_copy: bool,
    ) -> crate::interface::TunConfig {
        crate::interface::TunConfig {
            name,
            ip: self.ipv4.map(|address| IpAddr::V4(address.address)),
            netmask: self.ipv4.map(|address| IpAddr::V4(ipv4_prefix_to_netmask(address.prefix))),
            mtu,
            zero_copy,
            ip6: self.ipv6.map(|address| address.address),
            prefix6: self.ipv6.map(|address| address.prefix),
        }
    }
}

fn ipv4_prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let raw = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ipv4Addr::from(raw)
}

fn ipv4_netmask_prefix(mask: Ipv4Addr) -> Result<u8, ConfigError> {
    let raw = u32::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    if raw != canonical {
        return Err(ConfigError::Validation(format!(
            "interface.tun_netmask is not a contiguous IPv4 netmask: {mask}"
        )));
    }
    Ok(prefix)
}

fn ipv6_netmask_prefix(mask: Ipv6Addr) -> Result<u8, ConfigError> {
    let raw = u128::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    if raw != canonical {
        return Err(ConfigError::Validation(format!(
            "interface.tun_netmask is not a contiguous IPv6 netmask: {mask}"
        )));
    }
    Ok(prefix)
}

/// TUN interface configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceConfig {
    /// Interface type
    #[serde(rename = "type")]
    pub interface_type: InterfaceType,
    /// TUN device name
    pub tun_name: String,
    /// TUN MTU
    pub tun_mtu: u16,
    /// Optional static TUN IP address
    pub tun_ip: Option<IpAddr>,
    /// Optional static TUN netmask
    pub tun_netmask: Option<IpAddr>,
    /// Optional static IPv6 TUN address for the canonical generic client path
    pub tun_ip6: Option<Ipv6Addr>,
    /// Optional IPv6 TUN prefix for the canonical generic client path
    pub tun_prefix6: Option<u8>,
    /// Enable zero-copy preference on TUN runtime path
    pub zero_copy: bool,
    /// Enable GSO
    pub enable_gso: bool,
    /// Enable GRO
    pub enable_gro: bool,
    /// TUN gateway address (default: 10.8.0.1)
    pub tun_gateway: Option<IpAddr>,
    /// TUN subnet prefix length (default: 24)
    pub tun_subnet_prefix: Option<u8>,
    /// DNS servers to use when VPN is active (default: [1.1.1.1, 8.8.8.8])
    pub dns_servers: Vec<IpAddr>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            interface_type: InterfaceType::Tun,
            tun_name: "quicfuse0".to_string(),
            tun_mtu: 1500,
            tun_ip: None,
            tun_netmask: None,
            tun_ip6: None,
            tun_prefix6: None,
            zero_copy: true,
            enable_gso: true,
            enable_gro: true,
            tun_gateway: None,
            tun_subnet_prefix: None,
            dns_servers: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ],
        }
    }
}

impl InterfaceConfig {
    /// Resolve legacy and canonical fields into one typed client address model.
    pub fn client_tunnel_addresses(&self) -> Result<ClientTunnelAddresses, ConfigError> {
        let legacy_ipv4_or_ipv6 = match (self.tun_ip, self.tun_netmask) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "interface.tun_ip and interface.tun_netmask must be configured together"
                        .to_string(),
                ));
            }
            (Some(ip), Some(mask)) if ip.is_ipv4() != mask.is_ipv4() => {
                return Err(ConfigError::Validation(
                    "interface.tun_ip and interface.tun_netmask must use the same address family"
                        .to_string(),
                ));
            }
            pair => pair,
        };

        let mut ipv4 = None;
        let mut legacy_ipv6 = None;
        match legacy_ipv4_or_ipv6 {
            (Some(IpAddr::V4(address)), Some(IpAddr::V4(mask))) => {
                ipv4 = Some(ClientTunnelIpv4 { address, prefix: ipv4_netmask_prefix(mask)? });
            }
            (Some(IpAddr::V6(address)), Some(IpAddr::V6(mask))) => {
                legacy_ipv6 =
                    Some(ClientTunnelIpv6 { address, prefix: ipv6_netmask_prefix(mask)? });
            }
            (None, None) => {}
            _ => {
                return Err(ConfigError::Validation(
                    "interface.tun_ip and interface.tun_netmask must use the same address family"
                        .to_string(),
                ));
            }
        }

        let canonical_ipv6 = match (self.tun_ip6, self.tun_prefix6) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "interface.tun_ip6 and interface.tun_prefix6 must be configured together"
                        .to_string(),
                ));
            }
            (Some(_address), Some(prefix)) if prefix > 128 => {
                return Err(ConfigError::Validation(format!(
                    "interface.tun_prefix6 must be at most 128, got {prefix}"
                )));
            }
            (Some(address), Some(prefix)) => Some(ClientTunnelIpv6 { address, prefix }),
            (None, None) => None,
        };

        if legacy_ipv6.is_some() && canonical_ipv6.is_some() {
            return Err(ConfigError::Validation(
                "legacy IPv6 interface.tun_ip/tun_netmask cannot be combined with canonical interface.tun_ip6/tun_prefix6"
                    .to_string(),
            ));
        }

        let ipv6 = canonical_ipv6.or(legacy_ipv6);
        if ipv6.is_some() && self.tun_mtu < 1280 {
            return Err(ConfigError::Validation(format!(
                "interface.tun_mtu must be at least 1280 when IPv6 TUN addressing is configured, got {}",
                self.tun_mtu
            )));
        }

        Ok(ClientTunnelAddresses { ipv4, ipv6 })
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self.interface_type {
            InterfaceType::Tun => {}
            InterfaceType::Xdp => {
                return Err(ConfigError::Validation(
                    "interface.type = \"xdp\" is unsupported because AF_XDP was removed; use \"tun\""
                        .to_string(),
                ));
            }
            InterfaceType::Tap | InterfaceType::RawSocket => {
                return Err(ConfigError::Validation(
                    "interface.type is unsupported by the current runtime; only \"tun\" is supported"
                        .to_string(),
                ));
            }
        }
        if self.tun_mtu < 576 {
            return Err(ConfigError::Validation(format!(
                "tun_mtu must be at least 576, got {}",
                self.tun_mtu
            )));
        }
        self.client_tunnel_addresses()?;
        Ok(())
    }
}

/// Interface type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    /// Layer 3 TUN device (IP packets).
    #[default]
    Tun,
    /// Legacy Layer 2 TAP value. Validation rejects it because the current
    /// runtime supports only the TUN interface.
    Tap,
    /// Legacy Linux XDP fast-path value. Validation rejects it because AF_XDP
    /// is not implemented by the current runtime.
    Xdp,
    /// Legacy raw socket value. Validation rejects it because the current
    /// runtime supports only the TUN interface.
    #[serde(rename = "raw_socket")]
    RawSocket,
}

// ============================================================================
// TELEMETRY SECTION
// ============================================================================

/// Telemetry and metrics configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Enable telemetry collection
    pub enabled: bool,
    /// Export interval in seconds
    pub export_interval: u64,
    /// Collect packet stats
    pub collect_packet_stats: bool,
    /// Collect stream stats
    pub collect_stream_stats: bool,
    /// Collect congestion stats
    pub collect_congestion_stats: bool,
    /// Collect FEC stats
    pub collect_fec_stats: bool,
    /// Collect stealth stats
    pub collect_stealth_stats: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval: 60,
            collect_packet_stats: true,
            collect_stream_stats: true,
            collect_congestion_stats: true,
            collect_fec_stats: true,
            collect_stealth_stats: true,
        }
    }
}

impl TelemetryConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.export_interval == 0 {
            return Err(ConfigError::Validation(
                "telemetry.export_interval must be > 0 when telemetry is enabled".into(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// LOGGING SECTION
// ============================================================================

/// Logging mode - controls the privacy/verbosity trade-off.
///
/// - `verbose`: Full debug logging, all metadata, disk + stdout.
/// - `normal`: Info-level, optional file output, standard operation.
/// - `minimal`: Warn-level only, no client metadata in log lines.
/// - `no-log`: **Strict privacy mode.** Enforces:
///   - In-memory ring buffer only (capped, overwritten on rotation).
///   - Zero disk writes for log data - `log_to_file` forced off.
///   - Stdout suppressed (`log_to_stdout` forced off).
///   - Systemd journal forwarding disabled (stderr closed).
///   - Client IPs, connection metadata, and session identifiers stripped.
///   - No timestamps in retained buffer entries (monotonic index only).
///   - Syslog facility explicitly not registered.
///   - On shutdown: ring buffer zeroed before deallocation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoggingMode {
    /// Full debug logging with all metadata to disk and stdout.
    Verbose,
    /// Info-level default operation.
    #[default]
    Normal,
    /// Warn-level only with client metadata stripped.
    Minimal,
    /// Strict privacy mode - in-memory ring buffer only, zero disk writes.
    NoLog,
}

/// Logging output format for the production logger.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// Structured NDJSON: one JSON object per line with timestamp, level, target, message, fields.
    Json,
    /// RFC 5424 syslog (forwarded via UDP to `syslog_addr`).
    Syslog,
}

/// Logging configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// Logging mode (verbose | normal | minimal | no-log)
    pub mode: LoggingMode,
    /// Log level (overridden by mode in verbose/minimal/no-log)
    pub level: String,
    /// Log to file (forced off in no-log mode)
    pub log_to_file: bool,
    /// Log file path (legacy field; prefer `file_path`)
    pub log_file_path: String,
    /// Log to stdout (forced off in no-log mode)
    pub log_to_stdout: bool,
    /// In-memory ring buffer capacity (entries). Used in no-log mode.
    pub ring_buffer_capacity: usize,
    /// Strip client metadata (IPs, session IDs) from log entries
    pub strip_metadata: bool,
    /// Output format: text, json, or syslog.
    pub format: LogFormat,
    /// Explicit path for the rotating file appender. When set, takes precedence
    /// over `log_to_file` / `log_file_path`.
    pub file_path: Option<PathBuf>,
    /// Maximum size in bytes of the active log file before rotation (default: 100 MiB).
    pub max_file_size_bytes: u64,
    /// Number of rotated files to retain (default: 5).
    pub max_files: usize,
    /// Optional syslog forwarding target (UDP). When set, RFC 5424 messages are
    /// sent to this address in addition to file/stderr output.
    pub syslog_addr: Option<SocketAddr>,
    /// Per-module level overrides, e.g. `{"quicfuscate::net": "debug"}`.
    pub module_levels: HashMap<String, String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: LoggingMode::Normal,
            level: "info".to_string(),
            log_to_file: false,
            log_file_path: "/var/log/quicfuscate.log".to_string(),
            log_to_stdout: true,
            ring_buffer_capacity: 512,
            strip_metadata: false,
            format: LogFormat::Text,
            file_path: None,
            max_file_size_bytes: 100 * 1024 * 1024,
            max_files: 5,
            syslog_addr: None,
            module_levels: HashMap::new(),
        }
    }
}

impl LoggingConfig {
    /// Returns the effective configuration after applying mode overrides.
    pub fn effective(&self) -> Self {
        let mut cfg = self.clone();
        match cfg.mode {
            LoggingMode::Verbose => {
                cfg.level = "debug".to_string();
            }
            LoggingMode::Normal => {
                // user settings respected as-is
            }
            LoggingMode::Minimal => {
                cfg.level = "warn".to_string();
                cfg.strip_metadata = true;
            }
            LoggingMode::NoLog => {
                cfg.level = "off".to_string();
                cfg.log_to_file = false;
                cfg.log_to_stdout = false;
                cfg.strip_metadata = true;
                // Strict privacy: no disk or syslog forwarding.
                cfg.file_path = None;
                cfg.syslog_addr = None;
            }
        }
        cfg
    }

    fn validate(&self) -> Result<(), ConfigError> {
        const VALID_LEVELS: &[&str] = &["off", "error", "warn", "info", "debug", "trace"];
        if !VALID_LEVELS.contains(&self.level.trim().to_ascii_lowercase().as_str()) {
            return Err(ConfigError::Validation(format!(
                "Invalid logging.level: {}. Must be one of: {:?}",
                self.level, VALID_LEVELS
            )));
        }
        if self.ring_buffer_capacity == 0 {
            return Err(ConfigError::Validation(
                "logging.ring_buffer_capacity must be greater than zero".to_string(),
            ));
        }
        if self.log_to_file && self.file_path.is_none() && self.log_file_path.trim().is_empty() {
            return Err(ConfigError::Validation(
                "logging.log_file_path must not be empty when log_to_file is enabled".to_string(),
            ));
        }
        if self.file_path.as_ref().is_some_and(|path| path.as_os_str().is_empty()) {
            return Err(ConfigError::Validation("logging.file_path must not be empty".to_string()));
        }
        if (self.log_to_file || self.file_path.is_some()) && self.max_file_size_bytes == 0 {
            return Err(ConfigError::Validation(
                "logging.max_file_size_bytes must be greater than zero when file logging is enabled"
                    .to_string(),
            ));
        }
        if self.max_files > 1024 {
            return Err(ConfigError::Validation(
                "logging.max_files must not exceed 1024".to_string(),
            ));
        }
        if self.syslog_addr.is_some_and(|address| address.port() == 0) {
            return Err(ConfigError::Validation(
                "logging.syslog_addr port must be greater than zero".to_string(),
            ));
        }
        for (module, level) in &self.module_levels {
            if module.trim().is_empty() {
                return Err(ConfigError::Validation(
                    "logging.module_levels keys must not be empty".to_string(),
                ));
            }
            if !VALID_LEVELS.contains(&level.trim().to_ascii_lowercase().as_str()) {
                return Err(ConfigError::Validation(format!(
                    "Invalid logging.module_levels value for {module}: {level}"
                )));
            }
        }
        Ok(())
    }
}

/// Bounded security audit persistence configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    /// Maximum accepted events waiting for the single audit writer.
    pub queue_capacity: usize,
    /// Maximum active audit segment size before rotation.
    pub max_segment_bytes: u64,
    /// Maximum retained segments, including the active segment.
    pub max_segments: usize,
    /// Maximum enqueue and acknowledgement wait for a flush barrier.
    pub flush_timeout_ms: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_AUDIT_QUEUE_CAPACITY,
            max_segment_bytes: DEFAULT_AUDIT_MAX_SEGMENT_BYTES,
            max_segments: DEFAULT_AUDIT_MAX_SEGMENTS,
            flush_timeout_ms: DEFAULT_AUDIT_FLUSH_TIMEOUT_MS,
        }
    }
}

impl AuditConfig {
    /// Convert the validated configuration shape to the audit-owner options.
    pub fn to_audit_options(&self) -> AuditOptions {
        AuditOptions {
            queue_capacity: self.queue_capacity,
            max_segment_bytes: self.max_segment_bytes,
            max_segments: self.max_segments,
            flush_timeout: Duration::from_millis(self.flush_timeout_ms),
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.to_audit_options()
            .validate()
            .map_err(|error| ConfigError::Validation(error.to_string()))
    }
}

// ============================================================================
// FEC SECTION
// ============================================================================

/// FEC configuration section (wraps detailed FEC settings).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FecSection {
    /// FEC mode: auto, off
    pub mode: FecMode,
    /// Initial adaptive FEC bootstrap hint. Canonical product value: auto.
    pub initial_mode: String,
    /// FEC window size for excellent link quality (0 = disabled).
    pub window_excellent: usize,
    /// FEC window size for good link quality.
    pub window_good: usize,
    /// FEC window size for fair link quality.
    pub window_fair: usize,
    /// FEC window size for poor link quality.
    pub window_poor: usize,
    /// Enable partial recovery
    pub enable_partial: bool,
    /// Enable PID controller
    pub enable_pid: bool,
    /// Enable hysteresis
    pub enable_hysteresis: bool,
    /// Enable Kalman filter
    pub enable_kalman: bool,
    /// Streaming emission period
    pub stream_every: usize,
}

impl Default for FecSection {
    fn default() -> Self {
        Self {
            mode: FecMode::Auto,
            initial_mode: "auto".to_string(),
            window_excellent: 0,
            window_good: 10,
            window_fair: 30,
            window_poor: 50,
            enable_partial: true,
            enable_pid: true,
            enable_hysteresis: true,
            enable_kalman: true,
            stream_every: 5,
        }
    }
}

impl FecSection {
    /// Convert the engine-level FEC section into the validated runtime policy.
    ///
    /// The product engine schema intentionally keeps bootstrap mode at `auto` or
    /// `off`; the standalone `[adaptive_fec]` file owns the complete codec-mode
    /// surface. Partial recovery remains environment-controlled, so the engine
    /// compatibility flags must retain their enabled defaults instead of being
    /// silently ignored by an adapter.
    pub fn to_runtime_config(&self) -> Result<crate::fec::FecConfig, ConfigError> {
        match self.initial_mode.trim().to_ascii_lowercase().as_str() {
            "auto" | "off" => {}
            value => {
                return Err(ConfigError::Validation(format!(
                    "fec.initial_mode has unsupported value '{value}'; use 'auto' or 'off'"
                )))
            }
        }
        if !self.enable_partial {
            return Err(ConfigError::Validation(
                "fec.enable_partial=false is not supported by the engine adapter; use QUICFUSCATE_FEC_PARTIAL=false for the runtime override".into(),
            ));
        }
        if !self.enable_pid {
            return Err(ConfigError::Validation(
                "fec.enable_pid=false is not supported by the engine adapter; the adaptive controller owns PID behavior".into(),
            ));
        }
        if self.stream_every == 0 {
            return Err(ConfigError::Validation("fec.stream_every must be > 0".into()));
        }
        let config = crate::fec::FecConfig::from_engine_section(self);
        config
            .validate()
            .map_err(|error| ConfigError::Validation(format!("fec runtime projection: {error}")))?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.window_good == 0 || self.window_fair == 0 || self.window_poor == 0 {
            return Err(ConfigError::Validation(
                "fec.window_good, window_fair, and window_poor must be > 0".into(),
            ));
        }
        self.to_runtime_config().map(|_| ())
    }
}

/// FEC operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    /// FEC disabled entirely.
    Off,
    /// Adaptive FEC - automatically adjusts redundancy based on measured loss.
    #[default]
    Auto,
}

// ============================================================================
// STEALTH SECTION
// ============================================================================

/// Stealth configuration section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StealthSection {
    /// Stealth mode
    pub mode: StealthMode,
    /// Enable uTLS/ClientHello persona spoofing. Effective only when mode is not Off.
    pub use_utls: bool,
    /// Enable domain fronting. Keep disabled unless fronting domains are explicitly configured.
    pub enable_domain_fronting: bool,
    /// Enable HTTP/3 masquerading
    pub enable_http3_masquerading: bool,
    /// Use TLS Cover
    pub use_tls_cover: bool,
    /// Use QPACK headers
    pub use_qpack_headers: bool,
    /// Enable traffic padding
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry
    pub enable_protocol_mimicry: bool,
    /// Enable DNS-over-HTTPS
    pub enable_doh: bool,
    /// DoH provider URL
    pub doh_provider: String,
    /// Padding strategy
    pub padding_strategy: String,
    /// Maximum padding size
    pub max_padding_size: usize,
    /// Custom fronting domains
    pub fronting_domains: Vec<String>,
    /// Initial browser profile
    pub initial_browser: String,
    /// Initial OS profile
    pub initial_os: String,
    /// Normalize decoded server-side tunnel ingress to the selected OS profile.
    pub enable_network_fingerprint_normalization: bool,
    /// Suppress ICMP destination-unreachable traffic except PMTUD signals.
    pub suppress_icmp_unreachable: bool,
}

impl Default for StealthSection {
    fn default() -> Self {
        Self {
            mode: StealthMode::Auto,
            use_utls: true,
            enable_domain_fronting: false,
            enable_http3_masquerading: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: true,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            padding_strategy: "adaptive".to_string(),
            max_padding_size: 256,
            fronting_domains: Vec::new(),
            initial_browser: "chrome".to_string(),
            initial_os: "windows".to_string(),
            enable_network_fingerprint_normalization: true,
            suppress_icmp_unreachable: false,
        }
    }
}

impl StealthSection {
    fn parse_padding_strategy(value: &str) -> Option<crate::stealth::PaddingStrategy> {
        match value.trim().to_ascii_lowercase().as_str() {
            "random" | "1" => Some(crate::stealth::PaddingStrategy::Random),
            "fixed" | "constant" | "2" => Some(crate::stealth::PaddingStrategy::Fixed),
            "adaptive" | "3" => Some(crate::stealth::PaddingStrategy::Adaptive),
            "browser" | "browser_mimic" | "browser-mimic" | "browsermimic" | "mimic" | "4" => {
                Some(crate::stealth::PaddingStrategy::BrowserMimic)
            }
            "normalize" | "packet_normalize" | "packet-normalize" | "packetnormalize" | "5" => {
                Some(crate::stealth::PaddingStrategy::PacketNormalize)
            }
            _ => None,
        }
    }

    /// Convert the engine stealth section and rotation policy into one runtime
    /// configuration. Invalid string enums fail here instead of falling back to
    /// a mode preset inside an adapter.
    pub fn to_runtime_config(
        &self,
        rotation: &FingerprintRotationConfig,
    ) -> Result<crate::stealth::StealthConfig, ConfigError> {
        rotation.validate()?;
        let runtime_mode = match self.mode {
            StealthMode::Off => crate::stealth::StealthMode::Off,
            StealthMode::Performance => crate::stealth::StealthMode::Performance,
            StealthMode::Stealth => crate::stealth::StealthMode::Stealth,
            StealthMode::AntiDpi => crate::stealth::StealthMode::AntiDpi,
            StealthMode::Manual => crate::stealth::StealthMode::Manual,
            StealthMode::Auto => crate::stealth::StealthMode::Intelligent,
        };
        let mut runtime = crate::stealth::StealthConfig::from_mode(runtime_mode);
        runtime.enable_domain_fronting = self.enable_domain_fronting;
        runtime.enable_http3_masquerading = self.enable_http3_masquerading;
        runtime.use_tls_cover = self.use_tls_cover;
        runtime.use_qpack_headers = self.use_qpack_headers;
        runtime.enable_traffic_padding = self.enable_traffic_padding;
        runtime.enable_timing_obfuscation = self.enable_timing_obfuscation;
        runtime.enable_protocol_mimicry = self.enable_protocol_mimicry;
        runtime.enable_network_fingerprint_normalization =
            self.enable_network_fingerprint_normalization;
        runtime.suppress_icmp_unreachable = self.suppress_icmp_unreachable;
        runtime.enable_doh = self.enable_doh;
        runtime.doh_provider = self.doh_provider.clone();
        runtime.max_padding_size = self.max_padding_size;
        runtime.fronting_domains = self.fronting_domains.clone();
        runtime.initial_browser = self.initial_browser.parse().map_err(|_| {
            ConfigError::Validation(format!(
                "stealth.initial_browser has unsupported value '{}'",
                self.initial_browser
            ))
        })?;
        runtime.initial_os = self.initial_os.parse().map_err(|_| {
            ConfigError::Validation(format!(
                "stealth.initial_os has unsupported value '{}'",
                self.initial_os
            ))
        })?;
        runtime.padding_strategy = Self::parse_padding_strategy(&self.padding_strategy)
            .ok_or_else(|| {
                ConfigError::Validation(format!(
                    "stealth.padding_strategy has unsupported value '{}'",
                    self.padding_strategy
                ))
            })?;
        if runtime.padding_strategy == crate::stealth::PaddingStrategy::PacketNormalize
            && runtime.normalize_target_size == 0
        {
            return Err(ConfigError::Validation(
                "stealth.padding_strategy=normalize requires a runtime normalize target, which is not part of the engine schema".into(),
            ));
        }
        if runtime.enable_traffic_padding && runtime.max_padding_size == 0 {
            return Err(ConfigError::Validation(
                "stealth.max_padding_size must be > 0 when traffic padding is enabled".into(),
            ));
        }
        runtime.enable_fingerprint_rotation = rotation.enabled;
        runtime.fingerprint_rotation_interval = rotation.interval_secs;
        runtime.fingerprint_rotation_mode = match rotation.mode {
            RotationMode::Fixed => crate::stealth::RotationMode::Fixed,
            RotationMode::Slots => crate::stealth::RotationMode::Slots,
            RotationMode::All => crate::stealth::RotationMode::All,
        };
        runtime.normalize_protocol_mimicry_bundle();
        runtime.validate().map_err(|error| {
            ConfigError::Validation(format!("stealth runtime projection: {error}"))
        })?;
        Ok(runtime)
    }
}

/// Stealth operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StealthMode {
    /// Stealth disabled - no obfuscation applied.
    Off,
    /// Zero-overhead stealth: uTLS persona, HTTP/3 masquerading, TLS cover, QPACK and DoH.
    /// No domain fronting, padding, jitter or rotation. Fastest coherent browser-like path.
    Performance,
    /// Balanced stealth: adds adaptive padding, timing jitter, protocol mimicry and light
    /// server push cover traffic. Good DPI resistance without heavy performance cost.
    Stealth,
    /// Maximum anti-DPI: all features at aggressive settings. Browser-mimic padding (256B),
    /// 3ms timing jitter, fingerprint rotation every 2 minutes, server push cover traffic.
    /// Accepts performance cost for maximum censorship resistance.
    #[serde(rename = "anti-dpi", alias = "antidpi", alias = "max")]
    AntiDpi,
    /// Manual control - each stealth feature toggled individually via sub-fields.
    Manual,
    /// Adaptive mode: starts like Performance, escalates features on detected censorship
    /// pressure (packet loss, ECN marks, RTT spikes, active probes). Alias: "auto".
    #[default]
    #[serde(alias = "intelligent")]
    Auto,
}

// ============================================================================
// FINGERPRINT ROTATION SECTION
// ============================================================================

/// Fingerprint rotation configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FingerprintRotationConfig {
    /// Enable rotation
    pub enabled: bool,
    /// Rotation interval in seconds
    pub interval_secs: u64,
    /// Rotation mode
    pub mode: RotationMode,
    /// Profile slots
    pub profile_slots: Vec<String>,
}

impl Default for FingerprintRotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 300,
            mode: RotationMode::Fixed,
            profile_slots: vec![
                "chrome:windows".to_string(),
                "firefox:windows".to_string(),
                "safari:macos".to_string(),
            ],
        }
    }
}

impl FingerprintRotationConfig {
    fn validate_profile_slot(slot: &str) -> Result<(), ConfigError> {
        let mut parts = slot.split(['@', ':']);
        let browser = parts.next().unwrap_or_default().trim();
        if browser.is_empty() || browser.parse::<crate::stealth::BrowserProfile>().is_err() {
            return Err(ConfigError::Validation(format!(
                "fingerprint_rotation.profile_slots contains an invalid browser profile: '{slot}'"
            )));
        }
        if let Some(os) = parts.next() {
            if os.trim().parse::<crate::stealth::OsProfile>().is_err() {
                return Err(ConfigError::Validation(format!(
                    "fingerprint_rotation.profile_slots contains an invalid OS profile: '{slot}'"
                )));
            }
        }
        if parts.next().is_some() {
            return Err(ConfigError::Validation(format!(
                "fingerprint_rotation.profile_slots entry has more than one separator: '{slot}'"
            )));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.interval_secs == 0 {
            return Err(ConfigError::Validation(
                "fingerprint_rotation.interval_secs must be > 0 when rotation is enabled".into(),
            ));
        }
        if self.profile_slots.len() > 64 {
            return Err(ConfigError::Validation(
                "fingerprint_rotation.profile_slots must contain at most 64 entries".into(),
            ));
        }
        if self.enabled && self.mode == RotationMode::Slots && self.profile_slots.is_empty() {
            return Err(ConfigError::Validation(
                "fingerprint_rotation.profile_slots must not be empty in slots mode".into(),
            ));
        }
        for slot in &self.profile_slots {
            Self::validate_profile_slot(slot)?;
        }
        Ok(())
    }
}

/// Rotation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationMode {
    /// Use a single fixed fingerprint profile.
    #[default]
    Fixed,
    /// Rotate through configured profile slots.
    Slots,
    /// Rotate through all available browser/OS combinations.
    All,
}

// ============================================================================
// OPTIMIZATION SECTION
// ============================================================================

/// Performance optimization configuration.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OptimizationConfig {
    /// Memory pool size (bytes). 0 = auto-detect based on available RAM.
    pub memory_pool_size: usize,
    /// Memory pool alignment (bytes, should be cache line size = 64).
    pub memory_pool_alignment: usize,
    /// Number of Tokio worker threads (0 = use default of 8).
    pub num_worker_threads: usize,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            memory_pool_size: auto_memory_pool_size(),
            memory_pool_alignment: 64,
            num_worker_threads: 0,
        }
    }
}

const MIN_POOL_BYTES: usize = 16 * 1024 * 1024; // 16 MB floor
const MAX_POOL_BYTES: usize = 64 * 1024 * 1024; // 64 MB cap
const FALLBACK_POOL_BYTES: usize = 64 * 1024 * 1024; // 64 MB fallback default

fn scaled_memory_pool_size(total_ram: usize) -> usize {
    (total_ram / 20).clamp(MIN_POOL_BYTES, MAX_POOL_BYTES)
}

/// Determine the memory pool size with the following priority:
/// 1. Environment variable `QUICFUSCATE_MEMORY_POOL_MB` (explicit override, in megabytes)
/// 2. Auto-scale: 5% of total system RAM (clamped to 16 MB..64 MB)
/// 3. Fallback: 64 MB (if sysinfo detection fails)
fn auto_memory_pool_size() -> usize {
    let environment = crate::env_utils::EnvSnapshot::capture();
    auto_memory_pool_size_with_snapshot(&environment)
}

fn auto_memory_pool_size_with_snapshot(environment: &crate::env_utils::EnvSnapshot) -> usize {
    // Priority 1: environment variable override
    if let Some(mb) = environment.parse_positive_usize("QUICFUSCATE_MEMORY_POOL_MB") {
        let bytes = mb.saturating_mul(1024 * 1024);
        log::info!("Memory pool size from QUICFUSCATE_MEMORY_POOL_MB: {} MB", mb);
        return bytes;
    }

    // Priority 2: auto-scale based on system RAM
    let sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let total_ram = sys.total_memory() as usize; // bytes

    if total_ram > 0 {
        let five_percent = total_ram / 20;
        let clamped = scaled_memory_pool_size(total_ram);
        log::info!(
            "Memory pool auto-scaled: {} MB (system RAM: {} MB, 5% = {} MB)",
            clamped / (1024 * 1024),
            total_ram / (1024 * 1024),
            five_percent / (1024 * 1024),
        );
        return clamped;
    }

    // Priority 3: fallback
    log::info!("Memory pool using fallback default: {} MB", FALLBACK_POOL_BYTES / (1024 * 1024));
    FALLBACK_POOL_BYTES
}

impl OptimizationConfig {
    /// Convert memory-pool settings into the block-based runtime contract.
    /// `memory_pool_size = 0` is resolved here so every adapter uses the same
    /// auto-sized pool instead of silently creating a one-block pool.
    pub fn to_runtime_config(&self) -> Result<crate::optimize::OptimizeConfig, ConfigError> {
        if self.memory_pool_alignment == 0 {
            return Err(ConfigError::Validation(
                "optimization.memory_pool_alignment must be > 0".into(),
            ));
        }
        if self.num_worker_threads > 256 {
            return Err(ConfigError::Validation(
                "optimization.num_worker_threads must be 0 or <= 256".into(),
            ));
        }
        let pool_bytes = if self.memory_pool_size == 0 {
            auto_memory_pool_size()
        } else {
            self.memory_pool_size
        };
        let block_size = self.memory_pool_alignment.max(65_536);
        let pool_capacity = (pool_bytes / block_size).max(1);
        let config = crate::optimize::OptimizeConfig { pool_capacity, block_size };
        config.validate().map_err(|error| {
            ConfigError::Validation(format!("optimization runtime projection: {error}"))
        })?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.to_runtime_config().map(|_| ())
    }
}

// ============================================================================
// ANTI-REPLAY SECTION (0-RTT)
// ============================================================================

/// 0-RTT anti-replay protection settings.
///
/// When enabled, a strike register rejects replayed 0-RTT packets per
/// RFC 8446 Section 8 and RFC 9001 Section 9.2.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AntiReplaySection {
    /// Enable 0-RTT anti-replay protection (server mode only).
    pub enabled: bool,
    /// Maximum ticket age in seconds before 0-RTT is rejected (default: 10).
    pub max_ticket_age_secs: u64,
    /// Maximum entries in the strike register (default: 100000).
    pub max_entries: usize,
    /// Maximum early data size in bytes per connection (default: 16384).
    pub max_early_data_size: u32,
}

impl Default for AntiReplaySection {
    fn default() -> Self {
        Self {
            enabled: true,
            max_ticket_age_secs: 10,
            max_entries: 100_000,
            max_early_data_size: 16384,
        }
    }
}

impl AntiReplaySection {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_ticket_age_secs == 0 {
            return Err(ConfigError::Validation(
                "anti_replay.max_ticket_age_secs must be > 0 when anti-replay is enabled".into(),
            ));
        }
        if self.max_entries == 0 {
            return Err(ConfigError::Validation(
                "anti_replay.max_entries must be > 0 when anti-replay is enabled".into(),
            ));
        }
        if self.max_early_data_size == 0 {
            return Err(ConfigError::Validation(
                "anti_replay.max_early_data_size must be > 0 when anti-replay is enabled".into(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// SECURITY SECTION
// ============================================================================

/// Process-wide memory-lock failure behavior.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryLockFailurePolicy {
    /// Keep the service available and expose a degraded memory-lock state.
    #[default]
    BestEffort,
    /// Abort startup before TLS identity publication or service readiness.
    FailClosed,
}

impl MemoryLockFailurePolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BestEffort => "best-effort",
            Self::FailClosed => "fail-closed",
        }
    }
}

/// Security settings: kill switch, leak prevention, connection-loss detection.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Enable kill switch (blocks all non-VPN traffic when disconnected).
    pub kill_switch: bool,
    /// Heartbeat timeout in milliseconds - if no data received from server for
    /// this duration, trigger connection-loss detection and activate kill switch.
    /// Default: 30000 (30s). Set to 0 to disable heartbeat watchdog.
    pub heartbeat_timeout_ms: u64,
    /// Legacy compatibility key. Kill-switch startup cleanup is mandatory and
    /// fail-closed regardless of this value.
    pub cleanup_firewall_on_start: bool,
    /// Firewall backend selection (Linux only). When `None`, one backend is
    /// resolved and retained at startup via [`crate::firewall::resolve_backend`].
    pub firewall: FirewallConfig,
    /// Lock process memory against swap with `mlockall` on server startup
    /// (TODO-516). Unlimited `RLIMIT_MEMLOCK` permits current-and-future
    /// locking; finite budgets use current-only locking. Prevents key
    /// material, AEAD state, and QKey tokens from being written to disk where
    /// they persist across reboots. Requires `LimitMEMLOCK=infinity` in
    /// systemd or `ulimit -l unlimited` for current-and-future coverage.
    pub lock_memory: bool,
    /// Process-wide memory-lock failure behavior. The best-effort default
    /// preserves cross-platform embedding; the Linux server template selects
    /// fail-closed explicitly for production service startup.
    pub memory_lock_failure_policy: MemoryLockFailurePolicy,
    /// Lock `MemoryPool` blocks against swap with `mlock` on allocation
    /// (TODO-516). Crypto buffers used for packet encryption/decryption are
    /// kept in RAM. Default: true on server, false on client.
    pub lock_blocks: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            kill_switch: false,
            heartbeat_timeout_ms: 30_000,
            cleanup_firewall_on_start: false,
            firewall: FirewallConfig::default(),
            lock_memory: true,
            memory_lock_failure_policy: MemoryLockFailurePolicy::default(),
            lock_blocks: true,
        }
    }
}

impl SecurityConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Zero explicitly disables the heartbeat watchdog and is documented as
        // a valid compatibility setting. All other security fields are typed
        // enums or booleans and therefore need no additional normalization.
        Ok(())
    }
}

/// Firewall backend configuration.
///
/// Controls whether QuicFuscate uses `iptables` or `nftables` for kill switch
/// and NAT/routing rules on Linux. On macOS and Windows this setting has no
/// effect (pf / Windows Firewall are used unconditionally).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    /// Explicit backend selection. `None` (default) auto-detects at runtime,
    /// preferring nftables when available and falling back to iptables.
    pub backend: Option<crate::firewall::FirewallBackend>,
}

// ============================================================================
// BUILDER
// ============================================================================

/// Builder for programmatic configuration.
#[derive(Default)]
pub struct EngineConfigBuilder {
    config: EngineConfig,
}

impl EngineConfigBuilder {
    /// Set engine mode.
    pub fn mode(mut self, mode: EngineMode) -> Self {
        self.config.engine.mode = mode;
        self
    }

    /// Set remote address.
    pub fn remote(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.remote = addr.into();
        self
    }

    /// Set local bind address.
    pub fn local(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.local = addr.into();
        self
    }

    /// Enable/disable peer verification.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.connection.verify_peer = verify;
        self
    }

    /// Set stealth mode.
    pub fn stealth_mode(mut self, mode: StealthMode) -> Self {
        self.config.stealth.mode = mode;
        self
    }

    /// Set AEAD preference.
    pub fn aead_preference(mut self, pref: AeadPreference) -> Self {
        self.config.crypto.aead_preference = pref;
        self
    }

    /// Set congestion control algorithm.
    pub fn cc_algorithm(mut self, cc: CcAlgorithm) -> Self {
        self.config.transport.cc_algorithm = cc;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<EngineConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.transport.quic_versions, [QuicVersion::V2, QuicVersion::V1]);
        assert_eq!(config.transport.cc_algorithm, CcAlgorithm::Bbr3);
        assert_eq!(config.crypto.aead_preference, AeadPreference::Auto);
        assert!(config.stealth.enable_network_fingerprint_normalization);
        assert!(!config.stealth.suppress_icmp_unreachable);
    }

    #[test]
    fn interface_validation_rejects_legacy_non_tun_types() {
        for (interface_type, expected_fragment) in [
            (InterfaceType::Xdp, "AF_XDP was removed"),
            (InterfaceType::Tap, "only \"tun\" is supported"),
            (InterfaceType::RawSocket, "only \"tun\" is supported"),
        ] {
            let interface = InterfaceConfig { interface_type, ..InterfaceConfig::default() };
            let error =
                interface.validate().expect_err("legacy non-TUN interface types must fail closed");
            assert!(
                error.to_string().contains(expected_fragment),
                "unexpected validation error for {interface_type:?}: {error}"
            );
        }
    }

    #[test]
    fn interface_schema_removes_xdp_fields_and_rejects_legacy_input() {
        let encoded = toml::to_string(&EngineConfig::default()).expect("serialize default config");
        assert!(!encoded.contains("xdp_mode"));
        assert!(!encoded.contains("xdp_flags"));

        let error = EngineConfig::from_toml(
            "[interface]\nxdp_mode = \"skb\"\nxdp_flags = [\"update_if_noexist\"]\n",
        )
        .expect_err("removed XDP fields must not remain accepted by the schema");
        assert!(error.to_string().contains("xdp_mode"));

        let config = EngineConfig::from_toml("[interface]\ntype = \"xdp\"\n")
            .expect("legacy XDP type remains parseable for an explicit validation error");
        let error =
            config.validate().expect_err("legacy XDP type must fail closed during validation");
        assert!(error.to_string().contains("AF_XDP was removed"));
    }

    #[test]
    fn network_fingerprint_policy_roundtrips_through_engine_toml() {
        let config = EngineConfig::from_toml(
            r#"
[stealth]
enable_network_fingerprint_normalization = false
suppress_icmp_unreachable = true
"#,
        )
        .unwrap();
        assert!(!config.stealth.enable_network_fingerprint_normalization);
        assert!(config.stealth.suppress_icmp_unreachable);

        let encoded = toml::to_string(&config).unwrap();
        let decoded = EngineConfig::from_toml(&encoded).unwrap();
        assert!(!decoded.stealth.enable_network_fingerprint_normalization);
        assert!(decoded.stealth.suppress_icmp_unreachable);
    }

    #[test]
    fn automatic_memory_pool_stays_within_runtime_bounds() {
        assert_eq!(scaled_memory_pool_size(128 * 1024 * 1024), MIN_POOL_BYTES);
        assert_eq!(scaled_memory_pool_size(2 * 1024 * 1024 * 1024), MAX_POOL_BYTES);
        assert_eq!(scaled_memory_pool_size(usize::MAX), MAX_POOL_BYTES);
    }

    #[test]
    fn transport_rejects_empty_or_duplicate_quic_versions() {
        let mut transport = TransportConfig::default();
        transport.quic_versions.clear();
        assert!(transport.validate().is_err());
        transport.quic_versions = vec![QuicVersion::V2, QuicVersion::V2];
        assert!(transport.validate().is_err());
    }

    #[test]
    fn test_cubic_transport_config_roundtrip() {
        let mut config = EngineConfig::default();
        config.transport.cc_algorithm = CcAlgorithm::Cubic;
        let encoded = toml::to_string(&config).expect("serialize cubic config");
        let decoded: EngineConfig = toml::from_str(&encoded).expect("deserialize cubic config");
        assert_eq!(decoded.transport.cc_algorithm, CcAlgorithm::Cubic);
    }

    #[test]
    fn test_builder() {
        let config = EngineConfig::builder()
            .mode(EngineMode::Server)
            .remote("0.0.0.0:4433")
            .stealth_mode(StealthMode::AntiDpi)
            .build()
            .unwrap();

        assert_eq!(config.engine.mode, EngineMode::Server);
        assert_eq!(config.stealth.mode, StealthMode::AntiDpi);
    }

    #[test]
    fn test_nat_traversal_defaults_to_disabled_path_discovery() {
        let config = EngineConfig::default();
        assert!(!config.nat_traversal.enabled);
        assert_eq!(config.nat_traversal.mode, crate::transport::NatTraversalMode::Off);
        assert!(config.nat_traversal.stun_servers.is_empty());
        assert!(config.nat_traversal.turn_servers.is_empty());
    }

    #[test]
    fn test_nat_traversal_toml_maps_to_transport_config() {
        let toml = r#"
[connection]
remote = "127.0.0.1:4433"

[nat_traversal]
enabled = true
mode = "connectivity-fallback"
stun_servers = ["203.0.113.1:3478"]
turn_servers = ["203.0.113.2:3478"]
ice_enabled = true
probe_interval_ms = 30000
max_candidates = 4
"#;
        let config = EngineConfig::from_toml(toml).unwrap();
        config.validate().unwrap();
        let transport_nat = config.nat_traversal.to_transport_config().unwrap();
        assert!(transport_nat.enabled);
        assert_eq!(transport_nat.mode, crate::transport::NatTraversalMode::ConnectivityFallback);
        assert!(transport_nat.ice_enabled);
        assert_eq!(transport_nat.max_candidates, 4);
        assert_eq!(transport_nat.stun_servers.len(), 1);
        assert_eq!(transport_nat.turn_servers.len(), 1);
    }

    #[test]
    fn test_nat_traversal_rejects_enabled_mode_when_disabled() {
        let toml = r#"
[connection]
remote = "127.0.0.1:4433"

[nat_traversal]
enabled = false
mode = "roaming"
"#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_empty_remote() {
        let mut config = EngineConfig::default();
        config.connection.remote = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn migration_policy_toml_roundtrip_and_bounds() {
        let mut config = EngineConfig::default();
        config.connection.migration_cwnd_reduction_factor = 0.25;
        config.connection.migration_cooldown_ms = 0;
        config.connection.migration_probe_target =
            crate::transport::MigrationProbeTarget::ReducedWindow;
        config.validate().unwrap();

        let encoded = toml::to_string(&config).unwrap();
        let decoded = EngineConfig::from_toml(&encoded).unwrap();
        assert_eq!(decoded.connection.migration_cwnd_reduction_factor, 0.25);
        assert_eq!(decoded.connection.migration_cooldown_ms, 0);
        assert_eq!(
            decoded.connection.migration_probe_target,
            crate::transport::MigrationProbeTarget::ReducedWindow
        );

        config.connection.migration_cwnd_reduction_factor = 1.01;
        assert!(config.validate().is_err());
        config.connection.migration_cwnd_reduction_factor = 0.5;
        config.connection.migration_cooldown_ms = 60_001;
        assert!(config.validate().is_err());
    }

    #[test]
    fn logging_configuration_rejects_invalid_levels_and_file_bounds() {
        let mut config = EngineConfig::default();
        config.logging.level = "loud".to_string();
        assert!(config.validate().is_err());

        config.logging.level = "info".to_string();
        config.logging.log_to_file = true;
        config.logging.log_file_path.clear();
        assert!(config.validate().is_err());

        config.logging.log_file_path = "runtime.log".to_string();
        config.logging.max_file_size_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_configuration_enforces_shared_audit_option_bounds() {
        use crate::audit::{
            MAX_AUDIT_FLUSH_TIMEOUT_MS, MAX_AUDIT_QUEUE_CAPACITY, MAX_AUDIT_SEGMENTS,
            MAX_AUDIT_SEGMENT_BYTES,
        };

        let mut config = EngineConfig::default();
        config.audit.queue_capacity = 0;
        assert!(config.validate().is_err());

        config.audit.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY;
        assert!(config.validate().is_ok());
        config.audit.queue_capacity = MAX_AUDIT_QUEUE_CAPACITY + 1;
        assert!(config.validate().is_err());

        config.audit.queue_capacity = 1;
        config.audit.max_segment_bytes = 0;
        assert!(config.validate().is_err());

        config.audit.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES;
        assert!(config.validate().is_ok());
        config.audit.max_segment_bytes = MAX_AUDIT_SEGMENT_BYTES + 1;
        assert!(config.validate().is_err());

        config.audit.max_segment_bytes = 1;
        config.audit.max_segments = 0;
        assert!(config.validate().is_err());

        config.audit.max_segments = MAX_AUDIT_SEGMENTS;
        assert!(config.validate().is_ok());
        config.audit.max_segments = MAX_AUDIT_SEGMENTS + 1;
        assert!(config.validate().is_err());

        config.audit.max_segments = 1;
        config.audit.flush_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.audit.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS;
        assert!(config.validate().is_ok());
        config.audit.flush_timeout_ms = MAX_AUDIT_FLUSH_TIMEOUT_MS + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn no_log_mode_removes_every_external_sink_and_filter() {
        let config = LoggingConfig {
            mode: LoggingMode::NoLog,
            log_to_file: true,
            file_path: Some(PathBuf::from("runtime.log")),
            log_to_stdout: true,
            syslog_addr: Some("127.0.0.1:514".parse().unwrap()),
            ..Default::default()
        };
        let effective = config.effective();
        assert_eq!(effective.level, "off");
        assert!(!effective.log_to_file);
        assert!(effective.file_path.is_none());
        assert!(!effective.log_to_stdout);
        assert!(effective.syslog_addr.is_none());
    }

    #[test]
    fn test_crypto_force_aead_rejects_internal_width_backends() {
        for force in ["aegis-128x4", "aegis128x4", "aegis-128x8", "aegis128x8"] {
            let mut config = EngineConfig::default();
            config.crypto.force_aead = force.to_string();
            assert!(config.validate().is_err(), "{force} must stay internal-only");
        }
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
            [engine]
            mode = "client"
            
            [connection]
            remote = "127.0.0.1:4433"
        "#;

        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.connection.remote, "127.0.0.1:4433");
    }

    #[test]
    fn canonical_engine_document_validates_and_roundtrips_all_sections() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/quicfuscate.toml");
        let config = EngineConfig::from_file(path).expect("canonical engine config parses");
        config.validate().expect("canonical engine config validates");
        assert_eq!(config.transport.traffic_analysis.chaff_size_bytes, 1280);
        assert_eq!(config.fec.window_poor, 50);
        assert_eq!(config.optimization.memory_pool_size, 67_108_864);
        assert!(config.telemetry.enabled);
        assert_eq!(config.audit.max_segments, 8);
        assert_eq!(config.security.memory_lock_failure_policy, MemoryLockFailurePolicy::BestEffort);

        let encoded = toml::to_string(&config).expect("canonical engine config serializes");
        let decoded = EngineConfig::from_toml(&encoded).expect("serialized engine config parses");
        decoded.validate().expect("serialized engine config validates");
        assert_eq!(decoded.transport.quic_versions, config.transport.quic_versions);
        assert_eq!(decoded.transport.cc_algorithm, config.transport.cc_algorithm);
        assert_eq!(decoded.transport.traffic_analysis, config.transport.traffic_analysis);
        assert_eq!(
            decoded.transport.qkey_traffic_analysis_ceiling,
            config.transport.qkey_traffic_analysis_ceiling
        );
        assert_eq!(
            decoded.transport.intelligent_traffic_analysis_ceiling,
            config.transport.intelligent_traffic_analysis_ceiling
        );
        assert_eq!(decoded.fec.window_poor, config.fec.window_poor);
        assert_eq!(decoded.security.kill_switch, config.security.kill_switch);
        assert_eq!(
            decoded.security.memory_lock_failure_policy,
            config.security.memory_lock_failure_policy
        );
        assert_eq!(decoded.security.firewall.backend, config.security.firewall.backend);
    }

    #[test]
    fn strict_engine_schema_rejects_unknown_keys_in_every_section() {
        let sections = [
            "engine",
            "connection",
            "transport",
            "transport.traffic_analysis",
            "transport.qkey_traffic_analysis_ceiling",
            "transport.intelligent_traffic_analysis_ceiling",
            "nat_traversal",
            "crypto",
            "interface",
            "telemetry",
            "logging",
            "audit",
            "fec",
            "stealth",
            "fingerprint_rotation",
            "optimization",
            "anti_replay",
            "security",
            "security.firewall",
        ];
        for section in sections {
            let source = format!("[{section}]\nunknown_audit_fixture = true\n");
            let error = EngineConfig::from_toml(&source)
                .expect_err("unknown section keys must not be silently dropped");
            assert!(
                error.to_string().contains("unknown_audit_fixture"),
                "unknown key was not reported for [{section}]: {error}"
            );
        }

        let error = EngineConfig::from_toml("top_level_unknown_audit_fixture = true\n")
            .expect_err("unknown top-level keys must not be silently dropped");
        assert!(error.to_string().contains("top_level_unknown_audit_fixture"));
    }

    #[test]
    fn validation_rejects_invalid_typed_strings_ranges_and_compatibility_values() {
        for source in [
            "[engine]\nmode = \"invalid\"\n",
            "[transport]\ncc_algorithm = \"invalid\"\n",
            "[fingerprint_rotation]\nmode = \"invalid\"\n",
        ] {
            assert!(EngineConfig::from_toml(source).is_err(), "invalid enum accepted: {source}");
        }

        let mut config = EngineConfig::default();
        config.stealth.padding_strategy = "invalid".to_string();
        assert!(config.validate().is_err());
        config.stealth.padding_strategy = "adaptive".to_string();
        config.stealth.initial_browser = "invalid".to_string();
        assert!(config.validate().is_err());
        config.stealth.initial_browser = "chrome".to_string();
        config.fingerprint_rotation.profile_slots = vec!["chrome:invalid".to_string()];
        assert!(config.validate().is_err());

        config.fingerprint_rotation.profile_slots =
            FingerprintRotationConfig::default().profile_slots;
        config.transport.max_udp_payload = 1199;
        assert!(config.validate().is_err());
        config.transport.max_udp_payload = 1500;
        config.fec.stream_every = 0;
        assert!(config.validate().is_err());
        config.fec.stream_every = 5;
        config.optimization.memory_pool_alignment = 0;
        assert!(config.validate().is_err());
        config.optimization.memory_pool_alignment = 64;
        config.anti_replay.max_entries = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_partial_tun_addressing() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_mixed_tun_address_family() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = Some("ffff:ffff:ffff:ffff::".parse().unwrap());
        assert!(config.validate().is_err());
    }

    #[test]
    fn client_tunnel_addresses_project_ipv4_ipv6_and_roundtrip() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("IPv4 address"));
        config.interface.tun_netmask = Some("255.255.255.0".parse().expect("IPv4 netmask"));
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        config.interface.tun_prefix6 = Some(64);

        let addresses =
            config.interface.client_tunnel_addresses().expect("dual-stack address model");
        assert_eq!(
            addresses.ipv4,
            Some(ClientTunnelIpv4 {
                address: "10.20.30.40".parse().expect("IPv4 address"),
                prefix: 24,
            })
        );
        assert_eq!(
            addresses.ipv6,
            Some(ClientTunnelIpv6 {
                address: "fd00::42".parse().expect("IPv6 address"),
                prefix: 64,
            })
        );

        let encoded = toml::to_string(&config).expect("serialize dual-stack config");
        let decoded = EngineConfig::from_toml(&encoded).expect("parse dual-stack config");
        assert_eq!(decoded.interface.tun_ip6, config.interface.tun_ip6);
        assert_eq!(decoded.interface.tun_prefix6, config.interface.tun_prefix6);
        decoded.validate().expect("round-tripped dual-stack config validates");
    }

    #[test]
    fn client_tunnel_addresses_accept_legacy_ipv6_single_family() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("IPv6 address"));
        config.interface.tun_netmask = Some("ffff:ffff:ffff:ffff::".parse().expect("IPv6 netmask"));

        let addresses =
            config.interface.client_tunnel_addresses().expect("legacy IPv6 address model");
        assert_eq!(addresses.ipv4, None);
        assert_eq!(
            addresses.ipv6,
            Some(ClientTunnelIpv6 {
                address: "2001:db8:42::2".parse().expect("IPv6 address"),
                prefix: 64,
            })
        );
    }

    #[test]
    fn client_tunnel_addresses_reject_non_contiguous_legacy_netmasks() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("IPv4 address"));
        config.interface.tun_netmask = Some("255.0.255.0".parse().expect("IPv4 netmask"));
        assert!(config
            .interface
            .client_tunnel_addresses()
            .expect_err("non-contiguous IPv4 netmask must fail")
            .to_string()
            .contains("contiguous IPv4"));

        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("IPv6 address"));
        config.interface.tun_netmask = Some("ffff:ffff:ffff:fffd::".parse().expect("IPv6 netmask"));
        assert!(config
            .interface
            .client_tunnel_addresses()
            .expect_err("non-contiguous IPv6 netmask must fail")
            .to_string()
            .contains("contiguous IPv6"));
    }

    #[test]
    fn validation_rejects_partial_canonical_ipv6_addressing() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        assert!(config.validate().is_err());

        config.interface.tun_ip6 = None;
        config.interface.tun_prefix6 = Some(64);
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_invalid_canonical_ipv6_prefix_and_mtu() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("IPv6 address"));
        config.interface.tun_prefix6 = Some(129);
        assert!(config.validate().is_err());

        config.interface.tun_prefix6 = Some(64);
        config.interface.tun_mtu = 1279;
        assert!(config.validate().is_err());
    }

    #[test]
    fn validation_rejects_two_ipv6_address_sources() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("legacy IPv6 address"));
        config.interface.tun_netmask =
            Some("ffff:ffff:ffff:ffff::".parse().expect("legacy IPv6 netmask"));
        config.interface.tun_ip6 = Some("fd00::42".parse().expect("canonical IPv6 address"));
        config.interface.tun_prefix6 = Some(64);

        let error = config.validate().expect_err("duplicate IPv6 source must fail closed");
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[test]
    fn test_firewall_config_default_is_auto_detect() {
        let config = EngineConfig::default();
        assert!(config.security.firewall.backend.is_none());
    }

    #[test]
    fn test_firewall_config_explicit_nftables() {
        let toml = r#"
            [security.firewall]
            backend = "nftables"
        "#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.security.firewall.backend,
            Some(crate::firewall::FirewallBackend::Nftables)
        );
    }

    #[test]
    fn test_firewall_config_explicit_iptables() {
        let toml = r#"
            [security.firewall]
            backend = "iptables"
        "#;
        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(
            config.security.firewall.backend,
            Some(crate::firewall::FirewallBackend::Iptables)
        );
    }
}
