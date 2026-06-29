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
use std::net::IpAddr;
use std::path::Path;

// Re-export existing configs for aggregation
pub use crate::fec::FecConfig;
pub use crate::optimize::OptimizeConfig;
pub use crate::stealth::StealthConfig;

/// Complete engine configuration aggregating all subsystems.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EngineConfig {
    /// Engine mode and lifecycle settings
    pub engine: EngineSection,
    /// Connection parameters (remote, TLS, streams)
    pub connection: ConnectionConfig,
    /// Transport layer settings (CC, MTU, pacing)
    pub transport: TransportConfig,
    /// Cryptographic settings (AEAD, PQ)
    pub crypto: CryptoConfig,
    /// TUN/TAP interface settings
    pub interface: InterfaceConfig,
    /// Telemetry and metrics settings
    pub telemetry: TelemetryConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
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
        self.crypto.validate()?;
        self.interface.validate()?;
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
#[serde(default)]
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
    pub qkey_token: Option<String>,
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
        }
    }
}

impl ConnectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.remote.is_empty() {
            return Err(ConfigError::Validation("remote address cannot be empty".into()));
        }
        if self.idle_timeout_ms == 0 {
            return Err(ConfigError::Validation("idle_timeout_ms must be > 0".into()));
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

/// Transport layer configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct TransportConfig {
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
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            cc_algorithm: CcAlgorithm::Bbr3,
            mtu: 1400,
            max_udp_payload: 1350,
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
        }
    }
}

impl TransportConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.mtu < 1200 {
            return Err(ConfigError::Validation(format!(
                "MTU must be at least 1200, got {}",
                self.mtu
            )));
        }
        if self.initial_rtt_ms == 0 {
            return Err(ConfigError::Validation("initial_rtt_ms must be > 0".into()));
        }
        if self.dgram_recv_queue_len == 0 && self.dgram_send_queue_len == 0 {
            return Ok(());
        }
        if self.dgram_recv_queue_len == 0 || self.dgram_send_queue_len == 0 {
            return Err(ConfigError::Validation(
                "dgram_recv_queue_len and dgram_send_queue_len must both be 0 or both be > 0"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Congestion control algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CcAlgorithm {
    /// TCP New Reno (RFC 6582) - conservative AIMD baseline.
    Reno,
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
                    | "aegis-128x4"
                    | "aegis128x4"
                    | "aegis-128x8"
                    | "aegis128x8"
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
    /// Prefer AEGIS-128L (or AEGIS-128x4/x8 on capable hardware).
    #[serde(rename = "aegis-128l", alias = "aegis-128x4", alias = "aegis-128x8")]
    Aegis128L,
    /// Prefer MORUS-1280-128 AEAD.
    Morus,
}

// ============================================================================
// INTERFACE SECTION
// ============================================================================

/// TUN/TAP interface configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
    /// XDP mode (Linux only)
    pub xdp_mode: XdpMode,
    /// XDP flags
    pub xdp_flags: Vec<String>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            interface_type: InterfaceType::Tun,
            tun_name: "quicfuse0".to_string(),
            tun_mtu: 1500,
            tun_ip: None,
            tun_netmask: None,
            zero_copy: true,
            enable_gso: true,
            enable_gro: true,
            tun_gateway: None,
            tun_subnet_prefix: None,
            dns_servers: vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ],
            xdp_mode: XdpMode::Skb,
            xdp_flags: vec!["update_if_noexist".to_string()],
        }
    }
}

impl InterfaceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.tun_mtu < 576 {
            return Err(ConfigError::Validation(format!(
                "tun_mtu must be at least 576, got {}",
                self.tun_mtu
            )));
        }
        match (self.tun_ip, self.tun_netmask) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "tun_ip and tun_netmask must be configured together".to_string(),
                ));
            }
            (Some(ip), Some(mask)) if ip.is_ipv4() != mask.is_ipv4() => {
                return Err(ConfigError::Validation(
                    "tun_ip and tun_netmask must use the same address family".to_string(),
                ));
            }
            _ => {}
        }
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
    /// Layer 2 TAP device (Ethernet frames).
    Tap,
    /// Linux XDP fast-path (AF_XDP socket).
    Xdp,
    /// Raw socket interface.
    #[serde(rename = "raw_socket")]
    RawSocket,
}

/// XDP operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// Generic SKB mode (software fallback, any NIC).
    #[default]
    Skb,
    /// Native driver mode (requires NIC driver support).
    Driver,
    /// Hardware offload mode (requires NIC hardware support).
    Hardware,
}

// ============================================================================
// TELEMETRY SECTION
// ============================================================================

/// Telemetry and metrics configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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

/// Logging configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Logging mode (verbose | normal | minimal | no-log)
    pub mode: LoggingMode,
    /// Log level (overridden by mode in verbose/minimal/no-log)
    pub level: String,
    /// Log to file (forced off in no-log mode)
    pub log_to_file: bool,
    /// Log file path
    pub log_file_path: String,
    /// Log to stdout (forced off in no-log mode)
    pub log_to_stdout: bool,
    /// In-memory ring buffer capacity (entries). Used in no-log mode.
    pub ring_buffer_capacity: usize,
    /// Strip client metadata (IPs, session IDs) from log entries
    pub strip_metadata: bool,
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
                cfg.level = "error".to_string();
                cfg.log_to_file = false;
                cfg.log_to_stdout = false;
                cfg.strip_metadata = true;
            }
        }
        cfg
    }
}

// ============================================================================
// FEC SECTION
// ============================================================================

/// FEC configuration section (wraps detailed FEC settings).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
#[serde(default)]
pub struct StealthSection {
    /// Stealth mode
    pub mode: StealthMode,
    /// Enable domain fronting
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
}

impl Default for StealthSection {
    fn default() -> Self {
        Self {
            mode: StealthMode::Auto,
            enable_domain_fronting: true,
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
        }
    }
}

/// Stealth operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StealthMode {
    /// Stealth disabled - no obfuscation applied.
    Off,
    /// Zero-overhead stealth: domain fronting, HTTP/3 masquerading, TLS cover, DoH only.
    /// No padding, no jitter, no rotation. Fastest possible with solid base cover.
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
#[serde(default)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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
const MAX_POOL_BYTES: usize = 256 * 1024 * 1024; // 256 MB cap
const FALLBACK_POOL_BYTES: usize = 64 * 1024 * 1024; // 64 MB fallback default

/// Determine the memory pool size with the following priority:
/// 1. Environment variable `QUICFUSCATE_MEMORY_POOL_MB` (explicit override, in megabytes)
/// 2. Auto-scale: 5% of total system RAM (clamped to 16 MB..256 MB)
/// 3. Fallback: 64 MB (if sysinfo detection fails)
fn auto_memory_pool_size() -> usize {
    // Priority 1: environment variable override
    if let Ok(val) = std::env::var("QUICFUSCATE_MEMORY_POOL_MB") {
        if let Ok(mb) = val.trim().parse::<usize>() {
            if mb > 0 {
                let bytes = mb.saturating_mul(1024 * 1024);
                log::info!("Memory pool size from QUICFUSCATE_MEMORY_POOL_MB: {} MB", mb);
                return bytes;
            }
        }
    }

    // Priority 2: auto-scale based on system RAM
    let sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let total_ram = sys.total_memory() as usize; // bytes

    if total_ram > 0 {
        let five_percent = total_ram / 20;
        let clamped = five_percent.clamp(MIN_POOL_BYTES, MAX_POOL_BYTES);
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

// ============================================================================
// ANTI-REPLAY SECTION (0-RTT)
// ============================================================================

/// 0-RTT anti-replay protection settings.
///
/// When enabled, a strike register rejects replayed 0-RTT packets per
/// RFC 8446 Section 8 and RFC 9001 Section 9.2.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
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

// ============================================================================
// SECURITY SECTION
// ============================================================================

/// Security settings: kill switch, leak prevention, connection-loss detection.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Enable kill switch (blocks all non-VPN traffic when disconnected).
    pub kill_switch: bool,
    /// Heartbeat timeout in milliseconds — if no data received from server for
    /// this duration, trigger connection-loss detection and activate kill switch.
    /// Default: 30000 (30s). Set to 0 to disable heartbeat watchdog.
    pub heartbeat_timeout_ms: u64,
    /// Cleanup stale firewall rules from a crashed previous session on startup.
    pub cleanup_firewall_on_start: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            kill_switch: false,
            heartbeat_timeout_ms: 30_000,
            cleanup_firewall_on_start: false,
        }
    }
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
        assert_eq!(config.transport.cc_algorithm, CcAlgorithm::Bbr3);
        assert_eq!(config.crypto.aead_preference, AeadPreference::Auto);
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
    fn test_validation_fails_empty_remote() {
        let mut config = EngineConfig::default();
        config.connection.remote = String::new();
        assert!(config.validate().is_err());
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
}
