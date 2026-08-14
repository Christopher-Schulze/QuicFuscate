//! Root-independent engine configuration, lifecycle, error, event, and statistics contracts.
//!
//! The runtime engine remains in the root crate because it owns concrete client, server, TUN, and
//! transport implementations. The aggregate configuration and these contracts contain no such
//! runtime dependencies, so control-plane consumers can share them without importing the product
//! runtime.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

mod circuit;
mod config;
mod qkey;
#[cfg(test)]
mod tests;

pub use circuit::{
    CircuitConfig, CircuitConfigError, CircuitDiversityPolicy, HopConfig, HopEndpoint,
    HopPersonaConfig, HopPolicyOverrides, HopRole, DEFAULT_PRODUCT_HOPS, MAX_CIRCUIT_HOPS,
    MAX_CIRCUIT_HOP_LABEL_CHARS, MIN_INNER_QUIC_DATAGRAM, NESTED_FEC_OVERHEAD,
    NESTED_HTTP_DATAGRAM_OVERHEAD, NESTED_MASQUE_OVERHEAD, NESTED_QUIC_OVERHEAD,
};
pub use config::{
    EngineConfig, EngineConfigBuilder, StealthSection, MAX_NORMALIZE_TARGET_SIZE,
    MIN_NORMALIZE_TARGET_SIZE,
};
pub use qf_audit::AuditConfig;
pub use qf_crypto::{
    CryptoConfig, DataAeadPreference as AeadPreference, PacketProtectionMode, PrivateAeadFamily,
};
pub use qf_firewall::FirewallConfig;
pub use qf_logging::{LogFormat, LoggingConfig, LoggingMode};
pub use qf_memory_lock::MemoryLockFailurePolicy;
pub use qf_stealth::{FingerprintRotationConfig, RotationMode};
pub use qf_telemetry::TelemetryConfig;
pub use qf_transport_anti_replay::AntiReplaySection;
pub use qf_transport_cc::cc::Algorithm as CcAlgorithm;
pub use qf_transport_nat::NatTraversalSection;
pub use qf_transport_version::QuicVersion;
pub use qkey::{
    authenticated_transcript_hash_from_token_hex,
    authenticated_transcript_hash_from_verifier_hash_hex, generate, id, parse, QKeyConfig,
    QKeyError, QKeyToken, QKEY_PREFIX,
};

/// Failure returned while loading, parsing, or validating the aggregate engine configuration.
///
/// The error carries only stable text so callers can handle configuration failures without
/// importing implementation-specific error types or the runtime engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Filesystem I/O error while loading a configuration file.
    Io(String),
    /// TOML deserialization error.
    Parse(String),
    /// Semantic validation or runtime-projection error.
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IO error: {error}"),
            Self::Parse(error) => write!(formatter, "Parse error: {error}"),
            Self::Validation(error) => write!(formatter, "Validation error: {error}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Shared publication gate for one coherent runtime policy generation.
///
/// Readers and writers hold the returned guards while accessing the transport,
/// FEC, optimization, and stealth values governed by the generation.
#[derive(Clone)]
pub struct RuntimePolicyGeneration {
    value: std::sync::Arc<std::sync::RwLock<u64>>,
}

impl RuntimePolicyGeneration {
    /// Create a publication gate at the initial generation.
    pub fn new() -> Self {
        Self { value: std::sync::Arc::new(std::sync::RwLock::new(1)) }
    }

    /// Read the currently published generation.
    pub fn current(&self) -> u64 {
        *self.read_guard()
    }

    /// Hold the shared publication gate for a coherent read.
    pub fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, u64> {
        self.value.read().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Hold the exclusive publication gate while updating governed values.
    pub fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, u64> {
        self.value.write().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Publish the next generation without wrapping at the integer boundary.
    pub fn advance(guard: &mut std::sync::RwLockWriteGuard<'_, u64>) {
        **guard = (**guard).saturating_add(1);
    }
}

impl Default for RuntimePolicyGeneration {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    /// Run as a VPN client connecting to a remote server.
    #[default]
    Client,
    /// Run as a VPN server accepting incoming connections.
    Server,
}

/// Stealth operation mode exposed by the engine configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StealthMode {
    /// Stealth disabled, with no obfuscation applied.
    Off,
    /// Zero-overhead browser-like stealth path.
    Performance,
    /// Balanced stealth with adaptive padding and timing defenses.
    Stealth,
    /// Maximum anti-DPI mode with aggressive defenses.
    #[serde(rename = "anti-dpi", alias = "antidpi", alias = "max")]
    AntiDpi,
    /// Manual control through the individual stealth feature fields.
    Manual,
    /// Adaptive mode that escalates defenses under censorship pressure.
    #[default]
    #[serde(alias = "intelligent")]
    Auto,
}

/// FEC mode exposed by the engine configuration contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    /// FEC disabled entirely.
    Off,
    /// Adaptive FEC that selects a bounded runtime policy from measured loss.
    #[default]
    Auto,
}

impl qf_fec::EngineFecMode for FecMode {
    fn adaptive_requested(self) -> bool {
        matches!(self, Self::Auto)
    }
}

/// FEC configuration section embedded in the engine configuration.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FecSection {
    /// FEC mode: auto or off.
    pub mode: FecMode,
    /// Initial adaptive FEC bootstrap hint. The canonical product value is auto.
    pub initial_mode: String,
    /// FEC window size for excellent link quality (0 disables this tier).
    pub window_excellent: usize,
    /// FEC window size for good link quality.
    pub window_good: usize,
    /// FEC window size for fair link quality.
    pub window_fair: usize,
    /// FEC window size for poor link quality.
    pub window_poor: usize,
    /// Enable partial recovery.
    pub enable_partial: bool,
    /// Enable PID control.
    pub enable_pid: bool,
    /// Enable hysteresis.
    pub enable_hysteresis: bool,
    /// Enable Kalman filtering.
    pub enable_kalman: bool,
    /// Streaming emission period.
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

/// Validation or runtime-projection failure for the engine FEC section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FecSectionError(String);

impl FecSectionError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for FecSectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for FecSectionError {}

impl qf_fec::EngineFecSection for FecSection {
    fn mode_is_auto(&self) -> bool {
        matches!(self.mode, FecMode::Auto)
    }

    fn window_excellent(&self) -> usize {
        self.window_excellent
    }

    fn window_good(&self) -> usize {
        self.window_good
    }

    fn window_fair(&self) -> usize {
        self.window_fair
    }

    fn window_poor(&self) -> usize {
        self.window_poor
    }

    fn enable_hysteresis(&self) -> bool {
        self.enable_hysteresis
    }

    fn enable_kalman(&self) -> bool {
        self.enable_kalman
    }

    fn stream_every(&self) -> usize {
        self.stream_every
    }
}

impl FecSection {
    /// Convert the engine-level FEC section into the validated runtime policy.
    pub fn to_runtime_config(&self) -> Result<qf_fec::FecConfig, FecSectionError> {
        match self.initial_mode.trim().to_ascii_lowercase().as_str() {
            "auto" | "off" => {}
            value => {
                return Err(FecSectionError::new(format!(
                    "fec.initial_mode has unsupported value '{value}'; use 'auto' or 'off'"
                )))
            }
        }
        if !self.enable_partial {
            return Err(FecSectionError::new(
                "fec.enable_partial=false is not supported by the engine adapter; use QUICFUSCATE_FEC_PARTIAL=false for the runtime override",
            ));
        }
        if !self.enable_pid {
            return Err(FecSectionError::new(
                "fec.enable_pid=false is not supported by the engine adapter; the adaptive controller owns PID behavior",
            ));
        }
        if self.stream_every == 0 {
            return Err(FecSectionError::new("fec.stream_every must be > 0"));
        }
        let config = qf_fec::FecConfig::from_engine_section(self);
        config
            .validate()
            .map_err(|error| FecSectionError::new(format!("fec runtime projection: {error}")))?;
        Ok(config)
    }

    /// Validate the serialized FEC section and its runtime projection.
    pub fn validate(&self) -> Result<(), FecSectionError> {
        if self.window_good == 0 || self.window_fair == 0 || self.window_poor == 0 {
            return Err(FecSectionError::new(
                "fec.window_good, fec.window_fair, and fec.window_poor must be > 0",
            ));
        }
        self.to_runtime_config().map(|_| ())
    }
}

/// Security settings for kill-switch, firewall, and memory-lock startup policy.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    /// Enable kill switch (blocks all non-VPN traffic when disconnected).
    pub kill_switch: bool,
    /// Heartbeat timeout in milliseconds; zero disables the watchdog.
    pub heartbeat_timeout_ms: u64,
    /// Legacy compatibility key; startup cleanup remains mandatory and fail-closed.
    pub cleanup_firewall_on_start: bool,
    /// Explicit firewall backend selection, or automatic selection when absent.
    pub firewall: FirewallConfig,
    /// Lock process memory against swap with `mlockall` on server startup.
    pub lock_memory: bool,
    /// Process-wide memory-lock failure behavior.
    pub memory_lock_failure_policy: MemoryLockFailurePolicy,
    /// Lock memory-pool blocks against swap on allocation.
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

/// Performance optimization settings embedded in the engine configuration.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OptimizationConfig {
    /// Memory pool size in bytes; zero selects the host-sized default.
    pub memory_pool_size: usize,
    /// Memory pool alignment in bytes.
    pub memory_pool_alignment: usize,
    /// Tokio worker thread count; zero selects the runtime default.
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

const MIN_POOL_BYTES: usize = 16 * 1024 * 1024;
const MAX_POOL_BYTES: usize = 64 * 1024 * 1024;
const FALLBACK_POOL_BYTES: usize = 64 * 1024 * 1024;

fn scaled_memory_pool_size(total_ram: usize) -> usize {
    (total_ram / 20).clamp(MIN_POOL_BYTES, MAX_POOL_BYTES)
}

fn auto_memory_pool_size() -> usize {
    auto_memory_pool_size_with_snapshot(&qf_common::env_utils::EnvSnapshot::capture())
}

fn auto_memory_pool_size_with_snapshot(environment: &qf_common::env_utils::EnvSnapshot) -> usize {
    if let Some(mb) = environment.parse_positive_usize("QUICFUSCATE_MEMORY_POOL_MB") {
        let bytes = mb.saturating_mul(1024 * 1024);
        log::info!("Memory pool size from QUICFUSCATE_MEMORY_POOL_MB: {} MB", mb);
        return bytes;
    }

    let system = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    let total_ram = system.total_memory() as usize;
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

    log::info!("Memory pool using fallback default: {} MB", FALLBACK_POOL_BYTES / (1024 * 1024));
    FALLBACK_POOL_BYTES
}

/// Validation or runtime-projection failure for optimization settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptimizationConfigError(String);

impl std::fmt::Display for OptimizationConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for OptimizationConfigError {}

impl OptimizationConfig {
    /// Convert engine optimization settings into the block-based runtime contract.
    pub fn to_runtime_config(&self) -> Result<qf_cpu::OptimizeConfig, OptimizationConfigError> {
        if self.memory_pool_alignment == 0 {
            return Err(OptimizationConfigError(
                "optimization.memory_pool_alignment must be > 0".to_string(),
            ));
        }
        if self.num_worker_threads > 256 {
            return Err(OptimizationConfigError(
                "optimization.num_worker_threads must be 0 or <= 256".to_string(),
            ));
        }
        let pool_bytes = if self.memory_pool_size == 0 {
            auto_memory_pool_size()
        } else {
            self.memory_pool_size
        };
        let block_size = self.memory_pool_alignment.max(65_536);
        let config =
            qf_cpu::OptimizeConfig { pool_capacity: (pool_bytes / block_size).max(1), block_size };
        config.validate().map_err(|error| {
            OptimizationConfigError(format!("optimization runtime projection: {error}"))
        })?;
        Ok(config)
    }

    /// Validate optimization settings and their runtime projection.
    pub fn validate(&self) -> Result<(), OptimizationConfigError> {
        self.to_runtime_config().map(|_| ())
    }
}

/// Transport-layer settings embedded in the engine configuration.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransportConfig {
    /// Ordered usable QUIC versions, preferred first.
    pub quic_versions: Vec<qf_transport_version::QuicVersion>,
    /// Congestion control algorithm.
    pub cc_algorithm: qf_transport_cc::cc::Algorithm,
    /// Maximum Transmission Unit.
    pub mtu: u16,
    /// Maximum UDP payload size.
    pub max_udp_payload: u16,
    /// Maximum idle timeout in milliseconds.
    pub max_idle_timeout: u64,
    /// Initial RTT estimate in milliseconds.
    pub initial_rtt_ms: u64,
    /// Enable pacing.
    pub enable_pacing: bool,
    /// Initial maximum data.
    pub initial_max_data: u64,
    /// Initial maximum stream data (bidi local).
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial maximum stream data (bidi remote).
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial maximum stream data (uni).
    pub initial_max_stream_data_uni: u64,
    /// Initial maximum streams (bidi).
    pub initial_max_streams_bidi: u64,
    /// Initial maximum streams (uni).
    pub initial_max_streams_uni: u64,
    /// Enable 0-RTT early data.
    pub enable_early_data: bool,
    /// QUIC DATAGRAM receive queue length (0 = disabled).
    pub dgram_recv_queue_len: usize,
    /// QUIC DATAGRAM send queue length (0 = disabled).
    pub dgram_send_queue_len: usize,
    /// Disable path MTU discovery.
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
    pub traffic_analysis: qf_transport_types::TrafficAnalysisPolicy,
    /// Hard ceiling for authenticated per-QKey traffic-analysis requests.
    pub qkey_traffic_analysis_ceiling: qf_transport_types::TrafficAnalysisPolicy,
    /// Ceiling for post-authentication Intelligent traffic-analysis escalation.
    pub intelligent_traffic_analysis_ceiling: qf_transport_types::TrafficAnalysisPolicy,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            quic_versions: vec![
                qf_transport_version::QuicVersion::V2,
                qf_transport_version::QuicVersion::V1,
            ],
            cc_algorithm: qf_transport_cc::cc::Algorithm::Bbr3,
            mtu: 1500,
            max_udp_payload: 1500,
            max_idle_timeout: 30_000,
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
            traffic_analysis: qf_transport_types::TrafficAnalysisPolicy::default(),
            qkey_traffic_analysis_ceiling:
                qf_transport_types::TrafficAnalysisPolicy::safety_ceiling(),
            intelligent_traffic_analysis_ceiling:
                qf_transport_types::TrafficAnalysisPolicy::default(),
        }
    }
}

/// Validation failure for the serialized engine transport section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfigError(String);

impl std::fmt::Display for TransportConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TransportConfigError {}

impl TransportConfig {
    /// Validate transport settings before projecting them into the runtime transport.
    pub fn validate(&self) -> Result<(), TransportConfigError> {
        if self.quic_versions.is_empty() {
            return Err(TransportConfigError("quic_versions must not be empty".to_string()));
        }
        let mut unique_versions = std::collections::HashSet::new();
        if self.quic_versions.iter().any(|version| !unique_versions.insert(*version)) {
            return Err(TransportConfigError(
                "quic_versions must not contain duplicates".to_string(),
            ));
        }
        if self.mtu < 1200 {
            return Err(TransportConfigError(format!(
                "transport.mtu must be at least 1200, got {}",
                self.mtu
            )));
        }
        if self.max_udp_payload < 1200 {
            return Err(TransportConfigError(format!(
                "max_udp_payload must be at least 1200, got {}",
                self.max_udp_payload
            )));
        }
        if self.initial_rtt_ms == 0 {
            return Err(TransportConfigError("initial_rtt_ms must be > 0".to_string()));
        }
        if self.initial_max_data == 0
            || self.initial_max_stream_data_bidi_local == 0
            || self.initial_max_stream_data_bidi_remote == 0
            || self.initial_max_stream_data_uni == 0
            || self.initial_max_streams_bidi == 0
            || self.initial_max_streams_uni == 0
        {
            return Err(TransportConfigError(
                "initial transport data and stream limits must be > 0".to_string(),
            ));
        }
        if self.pmtu_min_mtu < 1200 || self.pmtu_max_mtu < self.pmtu_min_mtu {
            return Err(TransportConfigError(
                "pmtu_min_mtu must be >= 1200 and <= pmtu_max_mtu".to_string(),
            ));
        }
        if self.pmtu_max_mtu > self.mtu {
            return Err(TransportConfigError(format!(
                "pmtu_max_mtu ({}) must not exceed transport.mtu ({})",
                self.pmtu_max_mtu, self.mtu
            )));
        }
        if self.pmtu_max_mtu > self.max_udp_payload {
            return Err(TransportConfigError(
                "pmtu_max_mtu must not exceed transport.max_udp_payload".to_string(),
            ));
        }
        if self.pmtu_probe_interval_ms == 0 || self.pmtu_black_hole_timeout_ms == 0 {
            return Err(TransportConfigError(
                "DPLPMTUD probe and black-hole timers must be > 0".to_string(),
            ));
        }
        if (self.dgram_recv_queue_len == 0) != (self.dgram_send_queue_len == 0) {
            return Err(TransportConfigError(
                "dgram_recv_queue_len and dgram_send_queue_len must both be 0 or both be > 0"
                    .to_string(),
            ));
        }
        for (name, policy) in [
            ("traffic_analysis", self.traffic_analysis),
            ("qkey_traffic_analysis_ceiling", self.qkey_traffic_analysis_ceiling),
            ("intelligent_traffic_analysis_ceiling", self.intelligent_traffic_analysis_ceiling),
        ] {
            policy
                .validate()
                .map_err(|error| TransportConfigError(format!("transport.{name}: {error}")))?;
        }
        Ok(())
    }
}

/// Connection parameters for the engine's QUIC endpoints.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConnectionConfig {
    /// Remote endpoint (server: listen address, client: server address).
    pub remote: String,
    /// Local bind address (optional).
    pub local: String,
    /// Verify peer certificate.
    pub verify_peer: bool,
    /// Custom CA file path (empty = system CAs).
    pub ca_file: String,
    /// TLS certificate file (server mode).
    pub cert_file: String,
    /// TLS private key file (server mode).
    pub key_file: String,
    /// ALPN protocols.
    pub alpn: Vec<String>,
    /// Server Name Indication (client mode).
    pub sni: String,
    /// QKey token (hex, client mode only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_token: Option<QKeyToken>,
    /// QKey id (public identifier, client mode only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_id: Option<String>,
    /// Connection idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Enable 0-RTT early data.
    pub enable_0rtt: bool,
    /// Maximum bidirectional streams.
    pub max_streams_bidi: u64,
    /// Maximum unidirectional streams.
    pub max_streams_uni: u64,
    /// Enable validated connection migration.
    pub enable_migration: bool,
    /// Retained congestion-window fraction for port-only rebinding.
    pub migration_cwnd_reduction_factor: f64,
    /// Minimum interval between successful migrations.
    pub migration_cooldown_ms: u64,
    /// Congestion recovery boundary after port-only rebinding.
    pub migration_probe_target: qf_transport_recovery::MigrationProbeTarget,
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
            idle_timeout_ms: 30_000,
            enable_0rtt: false,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            enable_migration: true,
            migration_cwnd_reduction_factor: 0.5,
            migration_cooldown_ms: 750,
            migration_probe_target: qf_transport_recovery::MigrationProbeTarget::PreviousWindow,
        }
    }
}

/// Validation failure for the serialized engine connection section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionConfigError(String);

impl std::fmt::Display for ConnectionConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConnectionConfigError {}

impl ConnectionConfig {
    /// Validate connection settings before endpoint construction.
    pub fn validate(&self) -> Result<(), ConnectionConfigError> {
        let remote = self.remote.trim();
        if remote.is_empty() {
            return Err(ConnectionConfigError("remote address cannot be empty".to_string()));
        }
        circuit::parse_endpoint_authority(remote).map_err(|error| {
            ConnectionConfigError(format!(
                "connection.remote must be a host:port or [ipv6]:port authority: {error}"
            ))
        })?;
        if !self.local.trim().is_empty() {
            self.local.trim().parse::<SocketAddr>().map_err(|error| {
                ConnectionConfigError(format!("connection.local must be a socket address: {error}"))
            })?;
        }
        if self.idle_timeout_ms == 0 {
            return Err(ConnectionConfigError("idle_timeout_ms must be > 0".to_string()));
        }
        if self.max_streams_bidi == 0 || self.max_streams_uni == 0 {
            return Err(ConnectionConfigError(
                "connection.max_streams_bidi and max_streams_uni must be > 0".to_string(),
            ));
        }
        if self.cert_file.trim().is_empty() != self.key_file.trim().is_empty() {
            return Err(ConnectionConfigError(
                "connection.cert_file and connection.key_file must be configured together"
                    .to_string(),
            ));
        }
        if !self.migration_cwnd_reduction_factor.is_finite()
            || !(0.0..=1.0).contains(&self.migration_cwnd_reduction_factor)
        {
            return Err(ConnectionConfigError(
                "migration_cwnd_reduction_factor must be finite and within [0, 1]".to_string(),
            ));
        }
        if self.migration_cooldown_ms > 60_000 {
            return Err(ConnectionConfigError(
                "migration_cooldown_ms must not exceed 60000".to_string(),
            ));
        }
        if let Some(id) = self.qkey_id.as_deref() {
            let id = id.trim();
            if !id.is_empty()
                && (id.len() != 12 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(ConnectionConfigError("qkey_id must be 12 hex chars".to_string()));
            }
        }
        Ok(())
    }
}

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientTunnelAddresses {
    /// Optional IPv4 client address and prefix.
    pub ipv4: Option<ClientTunnelIpv4>,
    /// Optional IPv6 client address and prefix.
    pub ipv6: Option<ClientTunnelIpv6>,
}

impl ClientTunnelAddresses {
    /// Project the canonical address model into the native TUN configuration.
    pub fn to_tun_config(
        self,
        name: Option<String>,
        mtu: u16,
        zero_copy: bool,
    ) -> qf_transport_types::TunConfig {
        qf_transport_types::TunConfig {
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

fn ipv4_netmask_prefix(mask: Ipv4Addr) -> Result<u8, InterfaceConfigError> {
    let raw = u32::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    if raw != canonical {
        return Err(InterfaceConfigError(format!(
            "interface.tun_netmask is not a contiguous IPv4 netmask: {mask}"
        )));
    }
    Ok(prefix)
}

fn ipv6_netmask_prefix(mask: Ipv6Addr) -> Result<u8, InterfaceConfigError> {
    let raw = u128::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    if raw != canonical {
        return Err(InterfaceConfigError(format!(
            "interface.tun_netmask is not a contiguous IPv6 netmask: {mask}"
        )));
    }
    Ok(prefix)
}

/// TUN interface configuration stored in the engine configuration.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceConfig {
    /// Interface type.
    #[serde(rename = "type")]
    pub interface_type: InterfaceType,
    /// TUN device name.
    pub tun_name: String,
    /// TUN MTU.
    pub tun_mtu: u16,
    /// Optional static TUN IP address.
    pub tun_ip: Option<IpAddr>,
    /// Optional static TUN netmask.
    pub tun_netmask: Option<IpAddr>,
    /// Optional static IPv6 TUN address for the canonical generic client path.
    pub tun_ip6: Option<Ipv6Addr>,
    /// Optional IPv6 TUN prefix for the canonical generic client path.
    pub tun_prefix6: Option<u8>,
    /// Enable zero-copy preference on TUN runtime path.
    pub zero_copy: bool,
    /// Enable GSO.
    pub enable_gso: bool,
    /// Enable GRO.
    pub enable_gro: bool,
    /// TUN gateway address (default: 10.8.0.1).
    pub tun_gateway: Option<IpAddr>,
    /// TUN subnet prefix length (default: 24).
    pub tun_subnet_prefix: Option<u8>,
    /// DNS servers to use when VPN is active.
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
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ],
        }
    }
}

/// Validation failure for the serialized engine interface section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceConfigError(String);

impl std::fmt::Display for InterfaceConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InterfaceConfigError {}

impl InterfaceConfig {
    /// Resolve legacy and canonical fields into one typed client address model.
    pub fn client_tunnel_addresses(&self) -> Result<ClientTunnelAddresses, InterfaceConfigError> {
        let legacy_ipv4_or_ipv6 = match (self.tun_ip, self.tun_netmask) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(InterfaceConfigError(
                    "interface.tun_ip and interface.tun_netmask must be configured together"
                        .to_string(),
                ));
            }
            (Some(ip), Some(mask)) if ip.is_ipv4() != mask.is_ipv4() => {
                return Err(InterfaceConfigError(
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
                return Err(InterfaceConfigError(
                    "interface.tun_ip and interface.tun_netmask must use the same address family"
                        .to_string(),
                ));
            }
        }

        let canonical_ipv6 = match (self.tun_ip6, self.tun_prefix6) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(InterfaceConfigError(
                    "interface.tun_ip6 and interface.tun_prefix6 must be configured together"
                        .to_string(),
                ));
            }
            (Some(_address), Some(prefix)) if prefix > 128 => {
                return Err(InterfaceConfigError(format!(
                    "interface.tun_prefix6 must be at most 128, got {prefix}"
                )));
            }
            (Some(address), Some(prefix)) => Some(ClientTunnelIpv6 { address, prefix }),
            (None, None) => None,
        };

        if legacy_ipv6.is_some() && canonical_ipv6.is_some() {
            return Err(InterfaceConfigError(
                "legacy IPv6 interface.tun_ip/tun_netmask cannot be combined with canonical interface.tun_ip6/tun_prefix6"
                    .to_string(),
            ));
        }

        let ipv6 = canonical_ipv6.or(legacy_ipv6);
        if ipv6.is_some() && self.tun_mtu < 1280 {
            return Err(InterfaceConfigError(format!(
                "interface.tun_mtu must be at least 1280 when IPv6 TUN addressing is configured, got {}",
                self.tun_mtu
            )));
        }

        Ok(ClientTunnelAddresses { ipv4, ipv6 })
    }

    /// Validate the interface schema and canonical address projection.
    pub fn validate(&self) -> Result<(), InterfaceConfigError> {
        match self.interface_type {
            InterfaceType::Tun => {}
            InterfaceType::Xdp => {
                return Err(InterfaceConfigError(
                    "interface.type = \"xdp\" is unsupported because AF_XDP was removed; use \"tun\""
                        .to_string(),
                ));
            }
            InterfaceType::Tap | InterfaceType::RawSocket => {
                return Err(InterfaceConfigError(
                    "interface.type is unsupported by the current runtime; only \"tun\" is supported"
                        .to_string(),
                ));
            }
        }
        if self.tun_mtu < 576 {
            return Err(InterfaceConfigError(format!(
                "tun_mtu must be at least 576, got {}",
                self.tun_mtu
            )));
        }
        self.client_tunnel_addresses().map(|_| ())
    }
}

/// Interface types retained for schema compatibility.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    /// Layer 3 TUN device (IP packets).
    #[default]
    Tun,
    /// Legacy Layer 2 TAP value; validation rejects it.
    Tap,
    /// Legacy Linux XDP value; validation rejects it.
    Xdp,
    /// Legacy raw socket value; validation rejects it.
    #[serde(rename = "raw_socket")]
    RawSocket,
}

/// Engine lifecycle and mode settings from the serialized engine configuration.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineSection {
    /// Engine operation mode: `client` or `server`.
    pub mode: EngineMode,
    /// Log level override (`trace`, `debug`, `info`, `warn`, or `error`).
    pub log_level: String,
    /// Auto-start on engine creation.
    pub auto_start: bool,
    /// Graceful shutdown timeout in milliseconds.
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
    /// Validate the serialized engine section without depending on the root configuration error.
    pub fn validate(&self) -> Result<(), String> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.log_level.to_lowercase().as_str()) {
            return Err(format!(
                "Invalid log_level: {}. Must be one of: {:?}",
                self.log_level, valid_levels
            ));
        }
        if self.shutdown_timeout_ms == 0 {
            return Err("engine.shutdown_timeout_ms must be > 0".to_string());
        }
        Ok(())
    }
}

/// Structured control-plane events emitted by the engine runtime.
#[derive(Clone, Debug)]
pub enum EngineEvent {
    /// Engine lifecycle state transition.
    StateChanged { old: EngineState, new: EngineState },
    /// Successfully connected to a remote peer.
    Connected { remote: SocketAddr },
    /// Connection was closed or lost.
    Disconnected { reason: DisconnectReason },
    /// An error occurred during engine operation.
    Error { error: EngineError },
    /// Periodic statistics snapshot update.
    StatsUpdated { stats: StatsSnapshot },
    /// Stealth level was automatically escalated by the brain.
    StealthEscalated { from: u8, to: u8 },
}

/// Engine lifecycle state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EngineState {
    /// Engine created but not started.
    #[default]
    Created,
    /// Engine is starting up.
    Starting,
    /// Engine is running and ready for connections.
    Running,
    /// Engine is establishing a client connection.
    Connecting,
    /// Engine is connected in client mode.
    Connected,
    /// Engine is stopping.
    Stopping,
    /// Engine has stopped.
    Stopped,
    /// Engine encountered an error.
    Error,
}

impl std::fmt::Display for EngineState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Created => "Created",
            Self::Starting => "Starting",
            Self::Running => "Running",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Error => "Error",
        };
        formatter.write_str(name)
    }
}

/// Typed terminal failures of the requested TUN/QUIC data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPlaneFault {
    /// The native TUN reader stopped unexpectedly.
    ReaderStopped { component: String, error: String },
    /// The bounded reader channel disconnected unexpectedly.
    ChannelDisconnected { component: String },
    /// A packet could not be delivered to the local TUN device.
    TunWrite { component: String, error: String },
    /// A non-retryable packet or UDP send failed.
    TransportSend { component: String, error: String },
    /// A non-retryable receive or datagram decode path failed.
    TransportReceive { component: String, error: String },
}

impl std::fmt::Display for DataPlaneFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReaderStopped { component, error } => {
                write!(formatter, "reader stopped ({component}): {error}")
            }
            Self::ChannelDisconnected { component } => {
                write!(formatter, "channel disconnected ({component})")
            }
            Self::TunWrite { component, error } => {
                write!(formatter, "TUN write failed ({component}): {error}")
            }
            Self::TransportSend { component, error } => {
                write!(formatter, "transport send failed ({component}): {error}")
            }
            Self::TransportReceive { component, error } => {
                write!(formatter, "transport receive failed ({component}): {error}")
            }
        }
    }
}

impl std::error::Error for DataPlaneFault {}

/// Engine errors.
#[derive(Debug, Clone)]
pub enum EngineError {
    /// Configuration error.
    Config(String),
    /// Invalid state for operation.
    InvalidState(EngineState, &'static str),
    /// TUN interface error.
    Tun(String),
    /// Connection error.
    Connection(String),
    /// Transport error.
    Transport(String),
    /// Terminal TUN/QUIC data-plane error.
    DataPlane(DataPlaneFault),
    /// Crypto error.
    Crypto(String),
    /// I/O error.
    Io(String),
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "Config error: {error}"),
            Self::InvalidState(state, operation) => {
                write!(formatter, "Invalid state {state} for operation: {operation}")
            }
            Self::Tun(error) => write!(formatter, "TUN error: {error}"),
            Self::Connection(error) => write!(formatter, "Connection error: {error}"),
            Self::Transport(error) => write!(formatter, "Transport error: {error}"),
            Self::DataPlane(error) => write!(formatter, "Data-plane error: {error}"),
            Self::Crypto(error) => write!(formatter, "Crypto error: {error}"),
            Self::Io(error) => write!(formatter, "IO error: {error}"),
            Self::Internal(error) => write!(formatter, "Internal error: {error}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ConfigError> for EngineError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error.to_string())
    }
}

impl From<std::io::Error> for EngineError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Runtime statistics for the engine.
#[derive(Debug, Default)]
pub struct EngineStats {
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total packets sent.
    pub packets_sent: AtomicU64,
    /// Total packets received.
    pub packets_received: AtomicU64,
    /// Active streams.
    pub active_streams: AtomicU64,
    /// Connection uptime in seconds.
    pub uptime_secs: AtomicU64,
    /// Current RTT in milliseconds.
    pub rtt_ms: AtomicU64,
    /// Packet loss percentage (0-100).
    pub loss_percent: AtomicU64,
    /// Current stealth mode (as u8).
    pub stealth_mode: AtomicU64,
    /// Current FEC mode (as u8).
    pub fec_mode: AtomicU64,
    /// Whether the requested packet data plane is currently available.
    pub data_plane_ready: AtomicU64,
    /// Number of terminal data-plane faults observed by the active runtime.
    pub data_plane_faults: AtomicU64,
}

impl EngineStats {
    /// Create a snapshot of current stats.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            uptime_secs: self.uptime_secs.load(Ordering::Relaxed),
            rtt_ms: self.rtt_ms.load(Ordering::Relaxed),
            loss_percent: self.loss_percent.load(Ordering::Relaxed),
            data_plane_ready: self.data_plane_ready.load(Ordering::Relaxed),
            data_plane_faults: self.data_plane_faults.load(Ordering::Relaxed),
        }
    }
}

/// Immutable snapshot of engine statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Total bytes transmitted.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Total packets transmitted.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Currently active streams or connections.
    pub active_streams: u64,
    /// Engine uptime in seconds since start.
    pub uptime_secs: u64,
    /// Current smoothed RTT in milliseconds.
    pub rtt_ms: u64,
    /// Current packet loss percentage (0-100).
    pub loss_percent: u64,
    /// Whether the requested packet data plane is currently available.
    pub data_plane_ready: u64,
    /// Number of terminal data-plane faults observed by the active runtime.
    pub data_plane_faults: u64,
}

/// Structured control-plane command set for engine integrations.
#[derive(Debug)]
pub enum EngineCommand {
    /// Start the engine runtime.
    Start,
    /// Stop the engine and release resources.
    Stop,
    /// Establish a connection to the remote server (client mode).
    Connect,
    /// Close the active connection.
    Disconnect,
    /// Disconnect and reconnect with current configuration.
    Reconnect,
    /// Authenticate and service one bounded alternate circuit without TUN ownership.
    PrebuildAlternateCircuit(EngineConfig),
    /// Promote the already-ready alternate circuit.
    PromotePrebuiltAlternate,
    /// Build, verify, and promote a replacement circuit synchronously.
    RotateCircuit(EngineConfig),
    /// Change the stealth mode at runtime.
    SetStealthMode(StealthMode),
    /// Change the FEC mode at runtime.
    SetFecMode(FecMode),
    /// Change the congestion control algorithm at runtime.
    SetCongestionControl(qf_transport_cc::cc::Algorithm),
    /// Enable or disable traffic padding.
    SetTrafficPadding(bool),
    /// Enable or disable timing obfuscation.
    SetTimingObfuscation(bool),
    /// Enable or disable 0-RTT early data.
    SetZeroRtt(bool),
    /// Query TUN interface capabilities for the current platform.
    GetTunCapabilities,
    /// Query the current engine state.
    GetState,
    /// Query the current statistics snapshot.
    GetStats,
}

/// Structured result for control-plane command execution.
#[derive(Debug, Clone)]
pub enum EngineCommandResult {
    /// Command accepted, no return data.
    Ack,
    /// Returns the current engine state.
    State(EngineState),
    /// Returns a statistics snapshot.
    Stats(StatsSnapshot),
    /// Returns TUN capability information.
    TunCapabilities(qf_transport_types::TunCapabilities),
    /// Returns the exact scope and effective state of an FEC policy command.
    FecPolicy(FecPolicyCommandResult),
}

/// Scope of an accepted engine FEC policy command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecPolicyCommandScope {
    /// The active client connection was changed before acknowledgement.
    ActiveConnection,
    /// No connection was active; the policy is configured for the next connection.
    NextConnection,
}

/// Truthful acknowledgement for a synchronous engine FEC policy command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecPolicyCommandResult {
    /// Policy requested by the caller.
    pub requested: FecMode,
    /// Policy retained in engine configuration after acceptance.
    pub configured: FecMode,
    /// Policy observed on the active connection, when one exists.
    pub effective: Option<FecMode>,
    /// Whether acknowledgement covers the active or next connection.
    pub scope: FecPolicyCommandScope,
    /// Source datagrams preserved across an active transition.
    pub queued_sources_preserved: usize,
    /// Repair-only datagrams discarded before active acknowledgement.
    pub queued_repairs_discarded: usize,
}

/// Callback trait for engine events.
pub trait EngineCallback: Send + Sync {
    /// Called when engine state changes.
    fn on_state_change(&self, _old: EngineState, _new: EngineState) {}

    /// Called when connected to a remote peer in client mode.
    fn on_connected(&self, _remote: SocketAddr) {}

    /// Called when disconnected.
    fn on_disconnected(&self, _reason: DisconnectReason) {}

    /// Called on error.
    fn on_error(&self, _error: &EngineError) {}

    /// Called periodically with a statistics update.
    fn on_stats_update(&self, _stats: &StatsSnapshot) {}

    /// Called when stealth mode is escalated in auto mode.
    fn on_stealth_escalation(&self, _from: u8, _to: u8) {}
}

/// Reason for disconnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Clean shutdown requested by the application.
    Requested,
    /// Remote closed the connection.
    RemoteClosed,
    /// Connection timed out.
    Timeout,
    /// Transport error.
    Error(String),
    /// Idle timeout reached.
    IdleTimeout,
    /// The requested packet data plane failed while the process was alive.
    DataPlane(DataPlaneFault),
}
