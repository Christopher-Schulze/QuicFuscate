//! QuicFuscate Engine - Main Control Interface
//!
//! This module provides the `QuicFuscateEngine` struct, which is the primary
//! interface for embedding QuicFuscate in applications.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::config::{ConfigError, EngineConfig, EngineMode};
use crate::implementations::client::{
    ClientDnsRuntime, ClientRuntime, KillSwitch, VpnFirewallPolicy,
};
use crate::implementations::server::{
    metrics::Metrics, normalize_runtime_optimize_config, AdminAction, PreparedStandaloneLaunch,
    ServerRuntime,
};
use crate::interface::app_config::AppConfig;
use crate::memory_lock::MemoryLockPolicy;
use crate::transport::Config;
use crate::transport::{self, CongestionControlAlgorithm};
use tokio::runtime::Builder as TokioRuntimeBuilder;

fn build_server_optimize_config(
    config: &EngineConfig,
) -> Result<crate::optimize::OptimizeConfig, EngineError> {
    config.optimization.to_runtime_config().map_err(EngineError::from)
}

fn build_runtime_transport_config(config: &EngineConfig) -> Result<Config, EngineError> {
    let mut transport =
        transport::Config::new_with_version(transport::PROTOCOL_VERSION).map_err(|error| {
            EngineError::Transport(format!("transport config init failed: {error}"))
        })?;
    let versions = config
        .transport
        .quic_versions
        .iter()
        .map(|version| version.wire_version())
        .collect::<Vec<_>>();
    transport.set_supported_versions(versions).map_err(|error| {
        EngineError::Transport(format!("QUIC version configuration failed: {error}"))
    })?;

    transport.set_cc_algorithm(map_server_cc_algorithm(config.transport.cc_algorithm));

    let protos = if config.connection.alpn.is_empty() {
        vec![
            b"hq-interop".to_vec(),
            b"h3-29".to_vec(),
            b"h3-28".to_vec(),
            b"h3-27".to_vec(),
            b"http/0.9".to_vec(),
        ]
    } else {
        config
            .connection
            .alpn
            .iter()
            .filter_map(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.as_bytes().to_vec())
                }
            })
            .collect()
    };

    let proto_refs: Vec<&[u8]> = protos.iter().map(std::vec::Vec::as_slice).collect();
    transport.set_application_protos(&proto_refs).map_err(|error| {
        EngineError::Transport(format!("application protocol setup failed: {error}"))
    })?;

    transport.set_max_idle_timeout(config.connection.idle_timeout_ms);
    transport.set_max_recv_udp_payload_size(config.transport.max_udp_payload as usize);
    transport.set_max_send_udp_payload_size(config.transport.mtu as usize);
    transport.set_initial_max_data(config.transport.initial_max_data.max(1024));
    transport.set_initial_max_stream_data_bidi_local(
        config.transport.initial_max_stream_data_bidi_local,
    );
    transport.set_initial_max_stream_data_bidi_remote(
        config.transport.initial_max_stream_data_bidi_remote,
    );
    // [connection].max_streams_bidi/uni override [transport] values when explicitly set to
    // a different non-zero value (the two sections are historical duplicates).
    let bidi = if config.connection.max_streams_bidi != config.transport.initial_max_streams_bidi
        && config.connection.max_streams_bidi > 0
    {
        config.connection.max_streams_bidi
    } else {
        config.transport.initial_max_streams_bidi
    };
    let uni = if config.connection.max_streams_uni != config.transport.initial_max_streams_uni
        && config.connection.max_streams_uni > 0
    {
        config.connection.max_streams_uni
    } else {
        config.transport.initial_max_streams_uni
    };
    transport.set_initial_max_streams_bidi(bidi);
    transport.set_initial_max_streams_uni(uni);
    transport.enable_pacing(config.transport.enable_pacing);
    transport.set_initial_rtt_ms(config.transport.initial_rtt_ms);
    transport
        .set_pmtu_policy(crate::transport::PmtuPolicy {
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

    if config.connection.enable_0rtt {
        transport.enable_early_data();
    }
    transport.set_disable_active_migration(!config.connection.enable_migration);
    transport
        .set_migration_policy(crate::transport::MigrationPolicy {
            port_rebinding_cwnd_factor: config.connection.migration_cwnd_reduction_factor,
            cooldown: Duration::from_millis(config.connection.migration_cooldown_ms),
            probe_target: config.connection.migration_probe_target,
        })
        .map_err(|error| EngineError::Config(format!("migration policy invalid: {error}")))?;
    transport.set_nat_traversal(
        config.nat_traversal.to_transport_config().map_err(|error| {
            EngineError::Config(format!("NAT traversal config invalid: {error}"))
        })?,
    );
    if config.transport.disable_pmtud {
        transport.discover_pmtu(false);
    }

    transport.set_traffic_analysis_policy(config.transport.traffic_analysis).map_err(|error| {
        EngineError::Config(format!("traffic-analysis policy invalid: {error}"))
    })?;
    transport
        .set_qkey_traffic_analysis_ceiling(config.transport.qkey_traffic_analysis_ceiling)
        .map_err(|error| {
            EngineError::Config(format!("QKey traffic-analysis ceiling invalid: {error}"))
        })?;
    transport
        .set_intelligent_traffic_analysis_ceiling(
            config.transport.intelligent_traffic_analysis_ceiling,
        )
        .map_err(|error| {
            EngineError::Config(format!("Intelligent traffic-analysis ceiling invalid: {error}"))
        })?;

    if config.transport.dgram_recv_queue_len > 0 && config.transport.dgram_send_queue_len > 0 {
        transport.enable_dgram(
            config.transport.dgram_recv_queue_len,
            config.transport.dgram_send_queue_len,
        );
    }

    transport.verify_peer(config.connection.verify_peer);

    transport.set_initial_max_stream_data_uni(config.transport.initial_max_stream_data_uni);

    if !config.connection.ca_file.trim().is_empty() {
        let ca_file = Path::new(&config.connection.ca_file);
        let ca_path = ca_file.to_str().ok_or_else(|| {
            EngineError::Config(format!(
                "CA file path is not valid UTF-8: {}",
                ca_file.to_string_lossy()
            ))
        })?;
        transport.load_verify_locations_from_file(ca_path).map_err(|error| {
            EngineError::Config(format!("failed to load CA file '{}': {error}", ca_path))
        })?;
    }

    if !config.connection.cert_file.trim().is_empty()
        || !config.connection.key_file.trim().is_empty()
    {
        if config.connection.cert_file.trim().is_empty()
            || config.connection.key_file.trim().is_empty()
        {
            return Err(EngineError::Config(
                "server mode requires both connection.cert_file and connection.key_file"
                    .to_string(),
            ));
        }

        crate::implementations::server::load_server_identity(
            &mut transport,
            Path::new(&config.connection.cert_file),
            Path::new(&config.connection.key_file),
            config.security.lock_memory,
        )
        .map_err(|error| {
            EngineError::Transport(format!("server identity setup failed: {error}"))
        })?;
    }

    Ok(transport)
}

fn map_server_cc_algorithm(cc: super::config::CcAlgorithm) -> CongestionControlAlgorithm {
    match cc {
        super::config::CcAlgorithm::Reno => CongestionControlAlgorithm::Reno,
        super::config::CcAlgorithm::Cubic => CongestionControlAlgorithm::Cubic,
        super::config::CcAlgorithm::Bbr2 => CongestionControlAlgorithm::BBR2,
        super::config::CcAlgorithm::Bbr3 => CongestionControlAlgorithm::BBR3,
    }
}

fn load_runtime_profile_values(
    config: &EngineConfig,
) -> Result<
    (
        crate::stealth::BrowserProfile,
        crate::stealth::OsProfile,
        Vec<crate::stealth::FingerprintProfile>,
    ),
    EngineError,
> {
    let browser =
        config.stealth.initial_browser.parse::<crate::stealth::BrowserProfile>().map_err(|_| {
            EngineError::Config(format!(
                "invalid initial_browser profile: {}",
                config.stealth.initial_browser
            ))
        })?;
    let os = config.stealth.initial_os.parse::<crate::stealth::OsProfile>().map_err(|_| {
        EngineError::Config(format!("invalid initial_os profile: {}", config.stealth.initial_os))
    })?;
    let profiles = crate::implementations::server::resolve_runtime_profiles(
        browser,
        os,
        &config.fingerprint_rotation.profile_slots,
        true,
    );

    Ok((browser, os, profiles))
}

fn build_server_runtime_profiles(
    config: &EngineConfig,
) -> Result<(crate::fec::FecConfig, crate::stealth::StealthConfig), EngineError> {
    let config_text = toml::to_string(config).map_err(|error| {
        EngineError::Config(format!("failed to serialize server config: {error}"))
    })?;

    let runtime_cfg = AppConfig::from_toml(&config_text)
        .map_err(|error| EngineError::Config(format!("failed to build runtime config: {error}")))?;

    runtime_cfg.validate().map_err(|error| {
        EngineError::Config(format!("runtime config validation failed: {error}"))
    })?;

    let (fec_cfg, stealth_cfg, _, _) =
        crate::implementations::server::runtime_components_from_app_config(
            runtime_cfg,
            Some(config.fec.mode),
        );

    Ok((fec_cfg, stealth_cfg))
}

fn reject_started_client_config_changes(
    current: &EngineConfig,
    candidate: &EngineConfig,
    state: EngineState,
) -> Result<(), EngineError> {
    if current.engine != candidate.engine
        || current.interface != candidate.interface
        || current.telemetry != candidate.telemetry
        || current.logging != candidate.logging
        || current.audit != candidate.audit
        || current.crypto != candidate.crypto
        || current.optimization != candidate.optimization
        || current.security != candidate.security
    {
        return Err(EngineError::InvalidState(
            state,
            "configuration update (engine startup-owned sections require a stopped client)",
        ));
    }
    Ok(())
}

/// The main QuicFuscate engine providing full lifecycle control.
///
/// # Example
///
/// ```ignore
/// use quicfuscate::engine::{QuicFuscateEngine, EngineConfig};
///
/// let config = EngineConfig::from_file("config/quicfuscate.toml")?;
/// let mut engine = QuicFuscateEngine::new(config)?;
///
/// engine.start()?;
/// engine.connect()?;
///
/// // ... use the VPN connection ...
///
/// engine.disconnect()?;
/// engine.stop()?;
/// ```
pub struct QuicFuscateEngine {
    /// Engine configuration
    config: EngineConfig,
    /// Monotonic clock owned by engine lifecycle and statistics state.
    clock: crate::time_source::ProtocolClock,
    /// Current engine state
    state: EngineState,
    /// Statistics
    stats: Arc<EngineStats>,
    /// Process-wide instrumentation registry reused by statistics refreshes.
    instrumentation: Arc<crate::instrumentation::GlobalMetrics>,
    /// Registered callbacks
    callbacks: Arc<Mutex<Vec<Arc<dyn EngineCallback>>>>,
    /// Central event sinks for control-plane integrations.
    event_sinks: Arc<Mutex<Vec<mpsc::Sender<EngineEvent>>>>,
    /// Client runtime (client mode)
    client_runtime: Option<ClientRuntime>,
    /// Active server loop thread handle.
    server_loop_handle: Option<thread::JoinHandle<()>>,
    /// Sender for server loop shutdown.
    server_loop_shutdown_tx: Option<tokio::sync::mpsc::UnboundedSender<AdminAction>>,
    /// Shared server metrics for loop mode.
    server_metrics: Option<Arc<Metrics>>,
    /// Engine start time
    start_time: Option<Instant>,
    /// Kill switch (client mode, optional)
    kill_switch: Option<Arc<KillSwitch>>,
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

/// Structured control-plane command set for app integrations.
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
    /// Change the stealth mode at runtime.
    SetStealthMode(super::config::StealthMode),
    /// Change the FEC mode at runtime.
    SetFecMode(super::config::FecMode),
    /// Change the congestion control algorithm at runtime.
    SetCongestionControl(super::config::CcAlgorithm),
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
    TunCapabilities(crate::interface::TunCapabilities),
    /// Returns the exact scope and effective state of an FEC policy command.
    FecPolicy(FecPolicyCommandResult),
}

/// Scope of an accepted Engine FEC policy command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecPolicyCommandScope {
    /// The active client connection was changed before acknowledgement.
    ActiveConnection,
    /// No connection was active; the policy is configured for the next connection.
    NextConnection,
}

/// Truthful acknowledgement for a synchronous Engine FEC policy command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecPolicyCommandResult {
    /// Policy requested by the caller.
    pub requested: super::config::FecMode,
    /// Policy retained in Engine configuration after acceptance.
    pub configured: super::config::FecMode,
    /// Policy observed on the active connection, when one exists.
    pub effective: Option<super::config::FecMode>,
    /// Whether acknowledgement covers the active or next connection.
    pub scope: FecPolicyCommandScope,
    /// Source datagrams preserved across an active transition.
    pub queued_sources_preserved: usize,
    /// Repair-only datagrams discarded before active acknowledgement.
    pub queued_repairs_discarded: usize,
}

/// Engine lifecycle state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EngineState {
    /// Engine created but not started
    #[default]
    Created,
    /// Engine is starting up
    Starting,
    /// Engine is running and ready for connections
    Running,
    /// Engine is establishing a client connection
    Connecting,
    /// Engine is connected (client mode)
    Connected,
    /// Engine is stopping
    Stopping,
    /// Engine has stopped
    Stopped,
    /// Engine encountered an error
    Error,
}

impl std::fmt::Display for EngineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineState::Created => write!(f, "Created"),
            EngineState::Starting => write!(f, "Starting"),
            EngineState::Running => write!(f, "Running"),
            EngineState::Connecting => write!(f, "Connecting"),
            EngineState::Connected => write!(f, "Connected"),
            EngineState::Stopping => write!(f, "Stopping"),
            EngineState::Stopped => write!(f, "Stopped"),
            EngineState::Error => write!(f, "Error"),
        }
    }
}

/// Typed terminal failures of the requested TUN/QUIC data plane.
///
/// The process and the QUIC control connection can remain alive while the
/// packet path is unusable. Keeping these outcomes typed prevents runtime
/// owners from reducing a reader failure, channel disconnect, device write,
/// or transport send failure to an ordinary idle poll.
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReaderStopped { component, error } => {
                write!(f, "reader stopped ({component}): {error}")
            }
            Self::ChannelDisconnected { component } => {
                write!(f, "channel disconnected ({component})")
            }
            Self::TunWrite { component, error } => {
                write!(f, "TUN write failed ({component}): {error}")
            }
            Self::TransportSend { component, error } => {
                write!(f, "transport send failed ({component}): {error}")
            }
            Self::TransportReceive { component, error } => {
                write!(f, "transport receive failed ({component}): {error}")
            }
        }
    }
}

impl std::error::Error for DataPlaneFault {}

/// Engine errors.
#[derive(Debug, Clone)]
pub enum EngineError {
    /// Configuration error
    Config(String),
    /// Invalid state for operation
    InvalidState(EngineState, &'static str),
    /// TUN interface error
    Tun(String),
    /// Connection error
    Connection(String),
    /// Transport error
    Transport(String),
    /// Terminal TUN/QUIC data-plane error
    DataPlane(DataPlaneFault),
    /// Crypto error
    Crypto(String),
    /// IO error
    Io(String),
    /// Internal error
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Config(e) => write!(f, "Config error: {}", e),
            EngineError::InvalidState(state, op) => {
                write!(f, "Invalid state {} for operation: {}", state, op)
            }
            EngineError::Tun(e) => write!(f, "TUN error: {}", e),
            EngineError::Connection(e) => write!(f, "Connection error: {}", e),
            EngineError::Transport(e) => write!(f, "Transport error: {}", e),
            EngineError::DataPlane(e) => write!(f, "Data-plane error: {}", e),
            EngineError::Crypto(e) => write!(f, "Crypto error: {}", e),
            EngineError::Io(e) => write!(f, "IO error: {}", e),
            EngineError::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ConfigError> for EngineError {
    fn from(e: ConfigError) -> Self {
        EngineError::Config(e.to_string())
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> Self {
        EngineError::Io(e.to_string())
    }
}

/// Runtime statistics for the engine.
#[derive(Debug, Default)]
pub struct EngineStats {
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total packets sent
    pub packets_sent: AtomicU64,
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Active streams
    pub active_streams: AtomicU64,
    /// Connection uptime in seconds
    pub uptime_secs: AtomicU64,
    /// Current RTT in milliseconds
    pub rtt_ms: AtomicU64,
    /// Packet loss percentage (0-100)
    pub loss_percent: AtomicU64,
    /// Current stealth mode (as u8)
    pub stealth_mode: AtomicU64,
    /// Current FEC mode (as u8)
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
#[derive(Debug, Clone, Default)]
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

/// Callback trait for engine events.
///
/// Implement this trait to receive notifications about engine state changes,
/// connection events, and errors.
///
/// # Example
///
/// ```ignore
/// struct MyCallback;
///
/// impl EngineCallback for MyCallback {
///     fn on_state_change(&self, old: EngineState, new: EngineState) {
///         println!("State changed: {:?} -> {:?}", old, new);
///     }
///     
///     fn on_connected(&self, remote: SocketAddr) {
///         println!("Connected to {}", remote);
///     }
/// }
/// ```
pub trait EngineCallback: Send + Sync {
    /// Called when engine state changes.
    fn on_state_change(&self, _old: EngineState, _new: EngineState) {}

    /// Called when connected to remote (client mode).
    fn on_connected(&self, _remote: SocketAddr) {}

    /// Called when disconnected.
    fn on_disconnected(&self, _reason: DisconnectReason) {}

    /// Called on error.
    fn on_error(&self, _error: &EngineError) {}

    /// Called periodically with stats update.
    fn on_stats_update(&self, _stats: &StatsSnapshot) {}

    /// Called when stealth mode is escalated (auto mode).
    fn on_stealth_escalation(&self, _from: u8, _to: u8) {}
}

/// Reason for disconnection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Clean shutdown requested by application
    Requested,
    /// Remote closed connection
    RemoteClosed,
    /// Connection timed out
    Timeout,
    /// Transport error
    Error(String),
    /// Idle timeout reached
    IdleTimeout,
    /// The requested packet data plane failed while the process was alive.
    DataPlane(DataPlaneFault),
}

impl QuicFuscateEngine {
    const CONNECT_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

    /// Create a new engine from a configuration file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    ///
    /// A new `QuicFuscateEngine` instance or an error if config parsing fails.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, EngineError> {
        let config = EngineConfig::from_file(path)?;
        Self::new(config)
    }

    /// Reload and validate a complete engine configuration from a TOML file.
    ///
    /// A created or stopped engine replaces its complete configuration. A
    /// running client accepts only changes that can be projected to the next
    /// connection; its active connection remains immutable except for the
    /// existing FEC control contract. A running generic server rejects this
    /// API because standalone server reload owns that runtime boundary.
    pub fn reload_config_from_file(&mut self, path: impl AsRef<Path>) -> Result<(), EngineError> {
        let candidate = EngineConfig::from_file(path)?;
        self.apply_config_candidate(candidate)
    }

    /// Create a new engine from a configuration struct.
    ///
    /// # Arguments
    ///
    /// * `config` - The engine configuration
    ///
    /// # Returns
    ///
    /// A new `QuicFuscateEngine` instance or an error if validation fails.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.validate()?;
        crate::crypto::install_data_aead_config(&config.crypto);
        let instrumentation = crate::instrumentation::global();

        let engine = Self {
            config,
            clock: crate::time_source::ProtocolClock::default(),
            state: EngineState::Created,
            stats: Arc::new(EngineStats::default()),
            instrumentation,
            callbacks: Arc::new(Mutex::new(Vec::new())),
            event_sinks: Arc::new(Mutex::new(Vec::new())),
            client_runtime: None,
            server_loop_handle: None,
            server_loop_shutdown_tx: None,
            server_metrics: None,
            start_time: None,
            kill_switch: None,
        };

        Ok(engine)
    }

    /// Get the current engine state.
    pub fn state(&self) -> EngineState {
        if self.state == EngineState::Connected
            && self.client_runtime.as_ref().is_some_and(|runtime| {
                runtime.connection_loss_reason().is_some() || runtime.data_plane_fault().is_some()
            })
        {
            EngineState::Running
        } else {
            self.state
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Get current statistics snapshot.
    pub fn stats(&self) -> StatsSnapshot {
        self.refresh_stats();
        let snapshot = self.stats.snapshot();
        self.notify_stats_update(&snapshot);
        snapshot
    }

    /// Add an event callback.
    pub fn add_callback(&mut self, callback: impl EngineCallback + 'static) {
        self.callbacks.lock().push(Arc::new(callback));
    }

    /// Remove all callbacks.
    pub fn clear_callbacks(&mut self) {
        self.callbacks.lock().clear();
    }

    /// Subscribe to structured engine events for control-plane integration.
    pub fn subscribe_events(&self) -> mpsc::Receiver<EngineEvent> {
        let (tx, rx) = mpsc::channel();
        self.event_sinks.lock().push(tx);
        rx
    }

    /// Apply a structured control-plane command against the engine.
    pub fn apply_command(
        &mut self,
        command: EngineCommand,
    ) -> Result<EngineCommandResult, EngineError> {
        let result = match command {
            EngineCommand::Start => self.start().map(|_| EngineCommandResult::State(self.state())),
            EngineCommand::Stop => self.stop().map(|_| EngineCommandResult::State(self.state())),
            EngineCommand::Connect => {
                self.connect().map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::Disconnect => {
                self.disconnect().map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::Reconnect => {
                self.reconnect().map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::SetStealthMode(mode) => {
                self.set_stealth_mode(mode).map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::SetFecMode(mode) => {
                self.set_fec_mode(mode).map(EngineCommandResult::FecPolicy)
            }
            EngineCommand::SetCongestionControl(cc) => {
                self.set_cc_algorithm(cc).map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::SetTrafficPadding(enable) => {
                self.set_traffic_padding(enable).map(|_| EngineCommandResult::Ack)
            }
            EngineCommand::SetTimingObfuscation(enable) => {
                self.set_timing_obfuscation(enable).map(|_| EngineCommandResult::Ack)
            }
            EngineCommand::SetZeroRtt(enable) => {
                self.set_0rtt(enable).map(|_| EngineCommandResult::Ack)
            }
            EngineCommand::GetTunCapabilities => {
                Ok(EngineCommandResult::TunCapabilities(crate::interface::tun_capabilities()))
            }
            EngineCommand::GetState => Ok(EngineCommandResult::State(self.state())),
            EngineCommand::GetStats => Ok(EngineCommandResult::Stats(self.stats())),
        };

        if let Err(ref error) = result {
            self.notify_error(error);
        }
        result
    }

    /// Start the engine.
    ///
    /// This initializes the runtime and prepares it for use.
    /// In server mode, this starts the real headless standalone server runtime.
    /// The embedded path launches the same `ServerRuntime::run_standalone(...)`
    /// loop used by the CLI server, but without the standalone admin services.
    ///
    /// # Returns
    ///
    /// `Ok(())` if started successfully, or an error.
    pub fn start(&mut self) -> Result<(), EngineError> {
        // Validate state
        let state = self.state();
        match state {
            EngineState::Created | EngineState::Stopped => {}
            _ => {
                return Err(EngineError::InvalidState(state, "start"));
            }
        }

        let old_state = state;
        self.set_state(EngineState::Starting);
        self.start_time = Some(self.clock.now());

        if self.config.engine.mode == EngineMode::Server {
            if let Err(error) = MemoryLockPolicy::from_security(&self.config.security)
                .apply_before_tls_identity(false)
            {
                return Err(self.fail_start(
                    old_state,
                    EngineError::Config(format!("server memory-lock startup failed: {error}")),
                ));
            }
        }

        // Initialize memory pool for optimized memory management
        let _pool = crate::optimize::global_pool();

        // Stealth and FEC modes are stored in config and applied during connection establishment
        let stealth_enabled = self.config.stealth.mode != super::config::StealthMode::Off;
        let fec_enabled = self.config.fec.mode != super::config::FecMode::Off;
        let firewall_required = match self.config.engine.mode {
            EngineMode::Client => self.config.security.kill_switch,
            EngineMode::Server => {
                self.config.interface.interface_type == super::config::InterfaceType::Tun
            }
        };
        let firewall_backend = if firewall_required {
            match crate::firewall::resolve_backend(self.config.security.firewall.backend) {
                Ok(backend) => backend,
                Err(error) => {
                    return Err(self.fail_start(old_state, EngineError::Config(error.to_string())))
                }
            }
        } else {
            self.config.security.firewall.backend.unwrap_or_default()
        };
        if self.config.engine.mode == EngineMode::Client && self.config.security.kill_switch {
            if let Err(error) = KillSwitch::cleanup_stale_rules() {
                return Err(self.fail_start(
                    old_state,
                    EngineError::Internal(format!("Kill switch stale cleanup failed: {error}")),
                ));
            }
        }

        let start_result = (|| -> Result<(), EngineError> {
            match self.config.engine.mode {
                EngineMode::Client => {
                    let mut runtime =
                        ClientRuntime::new_with_clock(self.config.clone(), self.clock.clone())?;
                    runtime.start()?;
                    self.client_runtime = Some(runtime);
                    Ok(())
                }
                EngineMode::Server => {
                    let server_config =
                        crate::implementations::server::server_config_from_listen_addr(
                            &self.config.connection.remote,
                            firewall_backend,
                        )
                        .map_err(EngineError::Config)?;
                    let (fec_cfg, stealth_cfg) = build_server_runtime_profiles(&self.config)?;
                    let transport = build_runtime_transport_config(&self.config)?;
                    let (profile, os, mut profiles) = load_runtime_profile_values(&self.config)?;
                    if !self.config.fingerprint_rotation.enabled {
                        profiles = vec![crate::stealth::FingerprintProfile::new(profile, os)];
                    }
                    let fec_mode_override = Some(self.config.fec.mode);
                    let opt_params = normalize_runtime_optimize_config(
                        build_server_optimize_config(&self.config)?,
                        "engine server runtime",
                    );
                    let doh_provider = self.config.stealth.doh_provider.clone();
                    let front_domain = self.config.stealth.fronting_domains.clone();
                    let tun_enable =
                        self.config.interface.interface_type == super::config::InterfaceType::Tun;
                    let profile_interval = self.config.fingerprint_rotation.interval_secs;
                    let doh_disable = !self.config.stealth.enable_doh;
                    let fronting_disable = !self.config.stealth.enable_domain_fronting;
                    let http3_disable = !self.config.stealth.enable_http3_masquerading;
                    let launch = PreparedStandaloneLaunch::new_headless_with_runtime_stealth(
                        transport,
                        fec_cfg,
                        opt_params,
                        stealth_cfg,
                        fec_mode_override,
                        profiles,
                        profile_interval,
                        crate::implementations::server::RuntimeStealthPolicy {
                            profile,
                            os,
                            disable_doh: doh_disable,
                            doh_provider: doh_provider.as_str(),
                            disable_fronting: fronting_disable,
                            front_domain: &front_domain,
                            disable_http3: http3_disable,
                        },
                        tun_enable,
                    );
                    let engine_config = self.config.clone();
                    let server_opt_params = build_server_optimize_config(&self.config)?;
                    let runtime_clock = self.clock.clone();
                    let startup_timeout = std::time::Duration::from_millis(
                        self.config.engine.shutdown_timeout_ms.max(30_000),
                    );
                    let (startup_tx, startup_rx) = crossbeam_channel::bounded(1);
                    // The admin sender only exists once ServerRuntime is constructed inside the
                    // thread, so it cannot be captured before the acknowledgement. Publishing it
                    // through a shared slot lets a startup timeout still reach a runtime that came
                    // up just after the deadline, instead of retaining a handle it can never
                    // signal.
                    let shutdown_slot: std::sync::Arc<
                        std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<AdminAction>>>,
                    > = std::sync::Arc::new(std::sync::Mutex::new(None));
                    let thread_shutdown_slot = std::sync::Arc::clone(&shutdown_slot);

                    let handle = thread::Builder::new()
                        .name("quicfuscate-server-runtime".to_string())
                        .spawn(move || {
                            let Ok(runtime) =
                                TokioRuntimeBuilder::new_multi_thread().enable_all().build()
                            else {
                                let _ = startup_tx.send(Err(EngineError::Internal(
                                    "failed to create tokio runtime for server loop".to_string(),
                                )));
                                return;
                            };

                            runtime.block_on(async move {
                                let mut server_runtime =
                                    match ServerRuntime::new_initialized_standalone_default_with_clock(
                                        engine_config,
                                        server_config,
                                        None,
                                        server_opt_params,
                                        None,
                                        None,
                                        None,
                                        None,
                                        runtime_clock,
                                    ) {
                                        Ok(server_runtime) => server_runtime,
                                        Err(error) => {
                                            let _ = startup_tx.send(Err(EngineError::from(error)));
                                            return;
                                        }
                                    };
                                let server_metrics = server_runtime.standalone_metrics();
                                let admin_actions_tx = server_runtime.admin_actions_sender();
                                // Publish before acknowledging, so the sender is reachable even if
                                // the engine has already given up waiting.
                                if let Ok(mut slot) = thread_shutdown_slot.lock() {
                                    *slot = Some(admin_actions_tx.clone());
                                }
                                if startup_tx.send(Ok((admin_actions_tx, server_metrics))).is_err()
                                {
                                    return;
                                }
                                if let Err(error) =
                                    server_runtime.run_standalone(Box::new(launch)).await
                                {
                                    log::error!("server loop exited with error: {error}");
                                }
                            });
                        })
                        .map_err(EngineError::from)?;
                    match startup_rx.recv_timeout(startup_timeout) {
                        Ok(Ok((admin_actions_tx, server_metrics))) => {
                            self.server_loop_handle = Some(handle);
                            self.server_loop_shutdown_tx = Some(admin_actions_tx);
                            self.server_metrics = Some(server_metrics);
                            Ok(())
                        }
                        Ok(Err(error)) => {
                            let _ = handle.join();
                            Err(error)
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                            let _ = handle.join();
                            Err(EngineError::Internal(
                                "server runtime exited before startup acknowledgement".to_string(),
                            ))
                        }
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                            self.server_loop_handle = Some(handle);
                            // Retain the ability to signal the loop. Without this the engine kept
                            // a handle it could only ever join, so a runtime that finished coming
                            // up after the deadline could keep accepting connections while the
                            // public state said Error.
                            self.server_loop_shutdown_tx =
                                shutdown_slot.lock().ok().and_then(|mut slot| slot.take());
                            Err(EngineError::Internal(format!(
                                "server runtime did not acknowledge startup within {}ms",
                                startup_timeout.as_millis()
                            )))
                        }
                    }
                }
            }
        })();

        if let Err(e) = start_result {
            return Err(self.fail_start(old_state, e));
        }

        // Initialize kill switch for client mode if enabled
        if self.config.engine.mode == EngineMode::Client && self.config.security.kill_switch {
            let ks = Arc::new(KillSwitch::new_with_backend(firewall_backend));
            if let Err(error) = ks.enable() {
                return Err(self.fail_start(
                    old_state,
                    EngineError::Internal(format!("Kill switch enable failed: {error}")),
                ));
            }
            self.kill_switch = Some(ks);
            log::info!("Kill switch enabled (firewall blocking until VPN connects)");
        }

        log::info!(
            "Engine started in {} mode (stealth: {}, fec: {})",
            if self.config.engine.mode == EngineMode::Client { "client" } else { "server" },
            if stealth_enabled { "enabled" } else { "disabled" },
            if fec_enabled { "enabled" } else { "disabled" }
        );

        self.set_state(EngineState::Running);
        self.notify_state_change(old_state, EngineState::Running);

        Ok(())
    }

    /// Stop the engine.
    ///
    /// This gracefully shuts down all connections and releases resources.
    ///
    /// # Returns
    ///
    /// `Ok(())` if stopped successfully, or an error.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        // Validate state
        let state = self.state();
        match state {
            EngineState::Running
            | EngineState::Connecting
            | EngineState::Connected
            | EngineState::Error => {}
            EngineState::Stopped => return Ok(()), // Already stopped
            _ => {
                return Err(EngineError::InvalidState(state, "stop"));
            }
        }

        if state == EngineState::Connected {
            if let Err(e) = self.disconnect() {
                log::warn!("Engine disconnect during stop failed: {}", e);
            }
        }

        let old_state = state;
        self.set_state(EngineState::Stopping);

        let mut client_runtime_stop_error = None;
        if let Some(mut runtime) = self.client_runtime.take() {
            if let Err(error) = runtime.stop() {
                log::error!("Client runtime stop failed; preserving runtime for retry: {}", error);
                client_runtime_stop_error = Some(error);
                self.client_runtime = Some(runtime);
            }
        }
        let mut server_loop_stop_error: Option<EngineError> = None;
        if let Some(sender) = self.server_loop_shutdown_tx.take() {
            if let Err(error) = sender.send(AdminAction::Shutdown) {
                log::warn!("Server loop shutdown signal failed: {}", error);
            }
        }
        if let Some(handle) = self.server_loop_handle.take() {
            let timeout = std::time::Duration::from_millis(self.config.engine.shutdown_timeout_ms);
            let (done_tx, done_rx) = crossbeam_channel::bounded::<()>(1);
            std::thread::spawn(move || {
                if handle.join().is_err() {
                    log::warn!("Server loop thread exited with error");
                }
                let _ = done_tx.send(());
            });
            if done_rx.recv_timeout(timeout).is_err() {
                log::warn!(
                    "[engine] Server loop did not stop within {}ms; continuing shutdown.",
                    timeout.as_millis()
                );
                // Reporting Stopped here would be untruthful: the loop may still hold listeners,
                // sessions, and descriptors. Record the unresolved state so the caller sees an
                // error instead of a clean shutdown.
                server_loop_stop_error = Some(EngineError::Internal(format!(
                    "server loop did not stop within {}ms and may still be running",
                    timeout.as_millis()
                )));
            }
        }
        self.server_metrics = None;
        self.start_time = None;

        // Disable kill switch on stop (removes all firewall rules)
        let kill_switch_cleanup_error = if client_runtime_stop_error.is_none() {
            self.kill_switch.take().and_then(|kill_switch| {
                kill_switch.disable().err().map(|error| {
                    self.kill_switch = Some(kill_switch);
                    EngineError::Internal(format!("Kill switch disable on stop failed: {error}"))
                })
            })
        } else {
            None
        };

        let shutdown_error =
            client_runtime_stop_error.or(server_loop_stop_error).or(kill_switch_cleanup_error);
        match shutdown_error {
            Some(error) => {
                self.set_state(EngineState::Error);
                self.notify_state_change(old_state, EngineState::Error);
                log::error!("Engine stop incomplete: {error}");
                Err(error)
            }
            None => {
                self.set_state(EngineState::Stopped);
                self.notify_state_change(old_state, EngineState::Stopped);
                log::info!("Engine stopped gracefully");
                Ok(())
            }
        }
    }

    /// Connect to remote server (client mode only).
    ///
    /// # Returns
    ///
    /// `Ok(())` if connected successfully, or an error.
    pub fn connect(&mut self) -> Result<(), EngineError> {
        // Validate mode
        if self.config.engine.mode != EngineMode::Client {
            return Err(EngineError::InvalidState(self.state, "connect (not in client mode)"));
        }

        // Validate state
        let state = self.state();
        if state != EngineState::Running {
            return Err(EngineError::InvalidState(state, "connect"));
        }

        let old_state = state;

        // Resolve remote address for validation
        let remote: SocketAddr = self.config.connection.remote.parse().map_err(|e| {
            EngineError::Connection(format!(
                "Invalid remote address {}: {}",
                self.config.connection.remote, e
            ))
        })?;
        let firewall_policy = VpnFirewallPolicy::new(
            if self.config.interface.tun_name.is_empty() {
                "tun0"
            } else {
                &self.config.interface.tun_name
            },
            remote,
            None,
            self.config.interface.dns_servers.iter().copied(),
        )
        .map_err(|error| EngineError::Config(error.to_string()))?;

        let prepared_dns = if self.config.stealth.enable_doh {
            Some(ClientDnsRuntime::prepare(&self.config)?)
        } else {
            None
        };

        if let Some(ref kill_switch) = self.kill_switch {
            kill_switch
                .on_vpn_connecting(&firewall_policy)
                .map_err(|error| EngineError::Internal(error.to_string()))?;
        }

        self.set_state(EngineState::Connecting);
        self.notify_state_change(old_state, EngineState::Connecting);

        let runtime = self
            .client_runtime
            .as_mut()
            .ok_or_else(|| EngineError::Internal("Client runtime not initialized".to_string()))?;

        if runtime.is_connected()
            && (runtime.connection_loss_reason().is_some() || runtime.data_plane_fault().is_some())
        {
            runtime.disconnect()?;
        }

        match runtime.connect() {
            Ok(_) => {}
            Err(err) => {
                self.set_state(EngineState::Running);
                self.notify_state_change(EngineState::Connecting, EngineState::Running);
                return Err(err);
            }
        }

        // The Condvar wait is an OS-runtime boundary. Its deadline must remain
        // in the native Instant domain used by ClientRuntime::wait_handshake;
        // TODO-822 owns injecting that runtime clock without mixing domains.
        let deadline = Instant::now() + Self::CONNECT_HANDSHAKE_DEADLINE;
        let handshake_ok = runtime.wait_handshake(deadline);

        if !handshake_ok {
            crate::telemetry::ENGINE_HANDSHAKE_TIMEOUT_TOTAL.inc();
            if let Err(error) = runtime.disconnect() {
                log::warn!("Client runtime cleanup after handshake timeout failed: {:?}", error);
            }
            self.set_state(EngineState::Running);
            self.notify_state_change(EngineState::Connecting, EngineState::Running);
            return Err(EngineError::Connection(
                "Client runtime did not complete handshake in time".to_string(),
            ));
        }

        log::info!("Connecting to {} in client mode", remote);

        let connected_firewall_policy = VpnFirewallPolicy::new(
            if self.config.interface.tun_name.is_empty() {
                "tun0"
            } else {
                &self.config.interface.tun_name
            },
            remote,
            None,
            runtime.assigned_dns_servers().unwrap_or_default(),
        )
        .map_err(|error| EngineError::Config(error.to_string()))?;

        // Notify kill switch that VPN is connected
        if let Some(ref ks) = self.kill_switch {
            if let Err(error) = ks.on_vpn_connected(&connected_firewall_policy) {
                if let Err(disconnect_error) = runtime.disconnect() {
                    log::warn!(
                        "Client runtime cleanup after kill-switch policy failure failed: {}",
                        disconnect_error
                    );
                }
                self.set_state(EngineState::Running);
                self.notify_state_change(EngineState::Connecting, EngineState::Running);
                return Err(EngineError::Internal(format!(
                    "Kill switch VPN-connected failed: {}",
                    error
                )));
            }
            log::info!("Kill switch: VPN traffic allowed, non-VPN traffic blocked");
        }

        if let Some(proxy_config) = prepared_dns {
            if let Err(error) = runtime.activate_dns_with_config(proxy_config) {
                if let Err(disconnect_error) = runtime.disconnect() {
                    log::warn!(
                        "Client runtime cleanup after DNS activation failure failed: {}",
                        disconnect_error
                    );
                }
                if let Some(ref ks) = self.kill_switch {
                    if let Err(disconnect_error) = ks.on_vpn_disconnected() {
                        log::error!(
                            "Kill switch restore after DNS activation failure failed: {}",
                            disconnect_error
                        );
                    }
                }
                self.set_state(EngineState::Running);
                self.notify_state_change(EngineState::Connecting, EngineState::Running);
                return Err(error);
            }
        }

        self.set_state(EngineState::Connected);
        self.notify_state_change(EngineState::Connecting, EngineState::Connected);
        self.notify_connected(remote);

        let kill_switch = self.kill_switch.clone();
        let callbacks = self.callbacks.clone();
        let event_sinks = self.event_sinks.clone();
        let on_loss = Arc::new(move |reason: DisconnectReason| {
            if let Some(ref kill_switch) = kill_switch {
                if let Err(error) = kill_switch.on_vpn_disconnected() {
                    log::error!("Kill switch activation on connection loss failed: {}", error);
                }
            }
            {
                let mut sinks = event_sinks.lock();
                sinks.retain(|sink| {
                    sink.send(EngineEvent::StateChanged {
                        old: EngineState::Connected,
                        new: EngineState::Running,
                    })
                    .is_ok()
                        && sink.send(EngineEvent::Disconnected { reason: reason.clone() }).is_ok()
                });
            }
            let callback_snapshot = callbacks.lock().clone();
            for callback in callback_snapshot {
                callback.on_state_change(EngineState::Connected, EngineState::Running);
                callback.on_disconnected(reason.clone());
            }
        });
        let watchdog_result = self
            .client_runtime
            .as_mut()
            .ok_or_else(|| EngineError::Internal("Client runtime not initialized".to_string()))?
            .start_loss_watchdog(
                Duration::from_millis(self.config.security.heartbeat_timeout_ms),
                on_loss,
            );
        if let Err(error) = watchdog_result {
            self.handle_connection_loss(DisconnectReason::Error(error.to_string()));
            return Err(error);
        }

        Ok(())
    }

    /// Disconnect from remote server (client mode only).
    ///
    /// # Returns
    ///
    /// `Ok(())` if disconnected successfully, or an error.
    pub fn disconnect(&mut self) -> Result<(), EngineError> {
        // Validate state
        let state = self.state();
        if state != EngineState::Connected {
            return Err(EngineError::InvalidState(state, "disconnect"));
        }

        let old_state = state;

        if let Some(runtime) = self.client_runtime.as_mut() {
            runtime.disconnect()?;
        }

        // Notify kill switch that VPN is disconnected
        if let Some(ref ks) = self.kill_switch {
            if let Err(e) = ks.on_vpn_disconnected() {
                log::error!("Kill switch on_vpn_disconnected failed: {}", e);
            }
            log::warn!("Kill switch: all traffic blocked (VPN disconnected)");
        }

        log::info!("Disconnecting from remote server");

        self.set_state(EngineState::Running);
        self.notify_state_change(old_state, EngineState::Running);
        self.notify_disconnected(DisconnectReason::Requested);

        Ok(())
    }

    /// Reconnect to remote server with current configuration.
    ///
    /// This is equivalent to calling `disconnect()` followed by `connect()`.
    pub fn reconnect(&mut self) -> Result<(), EngineError> {
        if self.state() == EngineState::Connected {
            self.disconnect()?;
        }
        self.connect()
    }

    /// Handle unexpected connection loss (heartbeat timeout, remote close, etc.).
    ///
    /// Activates the kill switch immediately if enabled, transitions to Running state,
    /// and emits a disconnected event with the given reason.
    pub fn handle_connection_loss(&mut self, reason: DisconnectReason) {
        if self.state() != EngineState::Connected {
            return;
        }
        log::warn!("Connection loss detected: {:?}, activating kill switch", reason);

        if let Some(ref ks) = self.kill_switch {
            if let Err(e) = ks.on_vpn_disconnected() {
                log::error!("Kill switch activation on connection loss failed: {}", e);
            }
        }

        if let Some(runtime) = self.client_runtime.as_mut() {
            if let Err(e) = runtime.disconnect() {
                log::warn!("Client runtime disconnect on connection loss failed: {}", e);
            }
        }

        let old_state = self.state();
        self.set_state(EngineState::Running);
        self.notify_state_change(old_state, EngineState::Running);
        self.notify_disconnected(reason);
    }

    /// Check if the kill switch is currently enabled.
    pub fn is_kill_switch_enabled(&self) -> bool {
        self.kill_switch.as_ref().map(|ks| ks.is_enabled()).unwrap_or(false)
    }

    /// Compatibility probe for the runtime-owned automatic loss watchdog.
    ///
    /// Loss detection and firewall activation are automatic. This method no
    /// longer drives a second polling loop; it only reports whether the runtime
    /// watchdog has already handled a loss.
    pub fn check_heartbeat(&mut self) -> bool {
        self.client_runtime.as_ref().is_some_and(|runtime| {
            runtime.connection_loss_reason().is_some() || runtime.data_plane_fault().is_some()
        })
    }

    // ========================================================================
    // Runtime Control Methods
    // ========================================================================

    /// Set the stealth mode at runtime.
    ///
    /// For a client, the validated mode is retained for the next connection or
    /// reconnect. An established connection keeps its construction snapshot.
    /// A running generic server rejects this mutation because standalone reload
    /// owns its next-connection policy.
    ///
    /// # Arguments
    ///
    /// * `mode` - The new stealth mode (Auto, Off, Max, Manual)
    pub fn set_stealth_mode(
        &mut self,
        mode: super::config::StealthMode,
    ) -> Result<(), EngineError> {
        let old_mode = self.config.stealth.mode as u8;
        let mut candidate = self.config.clone();
        candidate.stealth.mode = mode;
        self.apply_config_candidate(candidate)?;
        self.stats.stealth_mode.store(mode as u64, Ordering::Relaxed);

        // Notify callbacks of stealth escalation
        let new_mode = mode as u8;
        if old_mode != new_mode {
            self.notify_stealth_escalation(old_mode, new_mode);
        }

        // Log the stealth mode change
        log::info!("Stealth mode changed from {} to {:?}", old_mode, mode);

        Ok(())
    }

    /// Get the current stealth mode.
    pub fn stealth_mode(&self) -> super::config::StealthMode {
        self.config.stealth.mode
    }

    /// Get the effective runtime stealth mode from the active client connection.
    pub fn active_stealth_mode(&self) -> Option<crate::stealth::StealthMode> {
        self.client_runtime
            .as_ref()
            .and_then(|runtime| runtime.connection())
            .map(|conn| conn.stealth_mode())
    }

    /// Get the effective runtime TLS SNI from the active client connection.
    pub fn active_server_name(&self) -> Option<String> {
        self.client_runtime
            .as_ref()
            .and_then(|runtime| runtime.connection())
            .and_then(|conn| conn.server_name())
    }

    /// Set the FEC mode at runtime.
    ///
    /// This allows changing the FEC level without restarting the engine.
    ///
    /// # Arguments
    ///
    /// * `mode` - The new FEC mode (Auto, Off)
    pub fn set_fec_mode(
        &mut self,
        mode: super::config::FecMode,
    ) -> Result<FecPolicyCommandResult, EngineError> {
        if self.config.engine.mode == EngineMode::Server && self.is_running() {
            return Err(EngineError::InvalidState(
                self.state(),
                "set_fec_mode (running server policy is reload-owned and next-connection-only)",
            ));
        }

        let active =
            self.client_runtime.as_ref().and_then(ClientRuntime::connection).map(|connection| {
                let policy = match mode {
                    super::config::FecMode::Off => crate::fec::FecControlPolicy::Off,
                    super::config::FecMode::Auto => crate::fec::FecControlPolicy::Auto,
                };
                connection.set_fec_control_policy(policy)
            });

        if self.state() == EngineState::Connected && active.is_none() {
            return Err(EngineError::Internal(
                "engine reports Connected without an owned client connection".to_string(),
            ));
        }

        if let Some(runtime) = self.client_runtime.as_mut() {
            runtime.set_next_fec_mode(mode);
        }
        self.config.fec.mode = mode;
        self.stats.fec_mode.store(mode as u64, Ordering::Relaxed);

        let result = if let Some(change) = active {
            let effective = match change.controller.effective_policy {
                crate::fec::FecControlPolicy::Off => super::config::FecMode::Off,
                crate::fec::FecControlPolicy::Auto => super::config::FecMode::Auto,
            };
            FecPolicyCommandResult {
                requested: mode,
                configured: mode,
                effective: Some(effective),
                scope: FecPolicyCommandScope::ActiveConnection,
                queued_sources_preserved: change.queued_sources_preserved,
                queued_repairs_discarded: change.queued_repairs_discarded,
            }
        } else {
            FecPolicyCommandResult {
                requested: mode,
                configured: mode,
                effective: None,
                scope: FecPolicyCommandScope::NextConnection,
                queued_sources_preserved: 0,
                queued_repairs_discarded: 0,
            }
        };
        log::info!("FEC policy command accepted: {:?}", result);
        Ok(result)
    }

    /// Get the current FEC mode.
    pub fn fec_mode(&self) -> super::config::FecMode {
        self.config.fec.mode
    }

    /// Observe the operator-owned FEC policy on the active client connection.
    pub fn active_fec_mode(&self) -> Option<super::config::FecMode> {
        self.client_runtime.as_ref().and_then(ClientRuntime::connection).map(|connection| {
            match connection.fec_telemetry_snapshot().control_policy {
                crate::fec::FecControlPolicy::Off => super::config::FecMode::Off,
                crate::fec::FecControlPolicy::Auto => super::config::FecMode::Auto,
            }
        })
    }

    /// Update the congestion control algorithm at runtime.
    ///
    /// The change applies to the next client connection or reconnect. Existing
    /// connections keep their transport controller. A running generic server
    /// rejects the mutation.
    ///
    /// # Arguments
    ///
    /// * `cc` - The new congestion control algorithm
    pub fn set_cc_algorithm(&mut self, cc: super::config::CcAlgorithm) -> Result<(), EngineError> {
        let mut candidate = self.config.clone();
        candidate.transport.cc_algorithm = cc;
        self.apply_config_candidate(candidate)?;

        // Log the congestion control change
        log::info!("Congestion control algorithm changed to {:?}", cc);

        Ok(())
    }

    /// Get the current congestion control algorithm.
    pub fn cc_algorithm(&self) -> super::config::CcAlgorithm {
        self.config.transport.cc_algorithm
    }

    /// Update multiple configuration values at once.
    ///
    /// This method applies a closure to modify the configuration.
    /// Use this for batch updates to avoid multiple change notifications. A
    /// running client accepts only next-connection fields plus the existing
    /// active/next FEC policy; startup-owned sections require a stopped engine.
    /// A running generic server rejects the update.
    ///
    /// # Example
    ///
    /// ```ignore
    /// engine.update_config(|config| {
    ///     config.stealth.mode = StealthMode::Max;
    ///     config.fec.mode = FecMode::Auto;
    /// })?;
    /// ```
    pub fn update_config<F>(&mut self, updater: F) -> Result<(), EngineError>
    where
        F: FnOnce(&mut EngineConfig),
    {
        let mut candidate = self.config.clone();
        updater(&mut candidate);
        self.apply_config_candidate(candidate)
    }

    fn apply_config_candidate(&mut self, mut candidate: EngineConfig) -> Result<(), EngineError> {
        // `from_toml` normalizes before validating, so the same document was accepted
        // from a file and rejected programmatically: lowering `transport.mtu` without
        // also lowering `pmtu_max_mtu` failed here but was clamped there. Both paths
        // must mean the same thing.
        candidate.normalize();
        candidate.validate()?;
        let state = self.state();
        let started = matches!(
            state,
            EngineState::Starting
                | EngineState::Running
                | EngineState::Connecting
                | EngineState::Connected
        );

        if started && self.config.engine.mode == EngineMode::Server {
            return Err(EngineError::InvalidState(
                state,
                "configuration update (running generic server is standalone-reload-owned)",
            ));
        }
        if started {
            reject_started_client_config_changes(&self.config, &candidate, state)?;
        }

        if candidate.fec.mode != self.config.fec.mode {
            self.set_fec_mode(candidate.fec.mode)?;
        }
        if let Some(runtime) = self.client_runtime.as_mut() {
            runtime.update_next_config(&candidate)?;
        }
        self.config = candidate;

        // Update stats to reflect new config
        self.stats.stealth_mode.store(self.config.stealth.mode as u64, Ordering::Relaxed);
        let effective_fec = self.active_fec_mode().unwrap_or(self.config.fec.mode);
        self.stats.fec_mode.store(effective_fec as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Enable or disable traffic padding for the next client connection or
    /// reconnect. Existing connections keep their immutable construction
    /// snapshot. Returns an error for a running generic server.
    pub fn set_traffic_padding(&mut self, enable: bool) -> Result<(), EngineError> {
        let mut candidate = self.config.clone();
        candidate.stealth.enable_traffic_padding = enable;
        self.apply_config_candidate(candidate)
    }

    /// Enable or disable timing obfuscation for the next client connection or
    /// reconnect. Existing connections keep their immutable construction
    /// snapshot. Returns an error for a running generic server.
    pub fn set_timing_obfuscation(&mut self, enable: bool) -> Result<(), EngineError> {
        let mut candidate = self.config.clone();
        candidate.stealth.enable_timing_obfuscation = enable;
        self.apply_config_candidate(candidate)
    }

    /// Enable or disable 0-RTT early data for the next client connection or
    /// reconnect. Existing connections keep their immutable transport
    /// snapshot. Returns an error for a running generic server.
    pub fn set_0rtt(&mut self, enable: bool) -> Result<(), EngineError> {
        let mut candidate = self.config.clone();
        candidate.connection.enable_0rtt = enable;
        self.apply_config_candidate(candidate)
    }

    /// Get whether the engine is in client mode.
    pub fn is_client(&self) -> bool {
        self.config.engine.mode == EngineMode::Client
    }

    /// Get whether the engine is in server mode.
    pub fn is_server(&self) -> bool {
        self.config.engine.mode == EngineMode::Server
    }

    /// Check if the engine is currently connected (client mode only).
    pub fn is_connected(&self) -> bool {
        self.state() == EngineState::Connected
    }

    /// Check if the engine is running (ready for connections).
    pub fn is_running(&self) -> bool {
        matches!(
            self.state(),
            EngineState::Running | EngineState::Connecting | EngineState::Connected
        )
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn refresh_stats(&self) {
        let metrics = &self.instrumentation;
        if let Some(metrics) = self.server_metrics.as_ref() {
            self.stats
                .bytes_sent
                .store(metrics.bytes_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .bytes_received
                .store(metrics.bytes_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_sent
                .store(metrics.packets_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_received
                .store(metrics.packets_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .active_streams
                .store(metrics.clients_active.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats.rtt_ms.store(0, Ordering::Relaxed);
            self.stats.loss_percent.store(0, Ordering::Relaxed);
            self.stats
                .data_plane_ready
                .store(metrics.tun_data_plane_ready.load(Ordering::Acquire), Ordering::Relaxed);
            self.stats
                .data_plane_faults
                .store(metrics.tun_data_plane_faults.load(Ordering::Relaxed), Ordering::Relaxed);
        } else {
            self.stats
                .bytes_sent
                .store(metrics.transport.bytes_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .bytes_received
                .store(metrics.transport.bytes_in.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_sent
                .store(metrics.transport.packets_out.load(Ordering::Relaxed), Ordering::Relaxed);
            self.stats
                .packets_received
                .store(metrics.transport.packets_in.load(Ordering::Relaxed), Ordering::Relaxed);
            let active_streams = self
                .client_runtime
                .as_ref()
                .and_then(|runtime| runtime.connection())
                .map(|conn| u64::from(conn.is_established()))
                .unwrap_or(0);
            self.stats.active_streams.store(active_streams, Ordering::Relaxed);
            self.stats
                .rtt_ms
                .store(metrics.transport.avg_rtt_ms().round() as u64, Ordering::Relaxed);
            self.stats
                .loss_percent
                .store(metrics.transport.loss_rate().round() as u64, Ordering::Relaxed);
            if let Some(runtime) = self.client_runtime.as_ref() {
                self.stats
                    .data_plane_ready
                    .store(u64::from(runtime.data_plane_available()), Ordering::Relaxed);
                self.stats.data_plane_faults.store(
                    runtime.io_driver_stats().map(|stats| stats.data_plane_faults).unwrap_or(0),
                    Ordering::Relaxed,
                );
            } else {
                self.stats.data_plane_ready.store(0, Ordering::Relaxed);
                self.stats.data_plane_faults.store(0, Ordering::Relaxed);
            }
        }
        if let Some(start) = self.start_time {
            self.stats
                .uptime_secs
                .store(self.clock.elapsed_since(start).as_secs(), Ordering::Relaxed);
        }
        self.stats.stealth_mode.store(self.config.stealth.mode as u64, Ordering::Relaxed);
        let effective_fec = self.active_fec_mode().unwrap_or(self.config.fec.mode);
        self.stats.fec_mode.store(effective_fec as u64, Ordering::Relaxed);
    }

    fn set_state(&mut self, state: EngineState) {
        self.state = state;
    }

    fn fail_start(&mut self, old_state: EngineState, error: EngineError) -> EngineError {
        self.set_state(EngineState::Error);
        self.notify_state_change(old_state, EngineState::Error);
        error
    }

    fn notify_state_change(&self, old: EngineState, new: EngineState) {
        self.emit_event(EngineEvent::StateChanged { old, new });
        for cb in self.callbacks.lock().clone() {
            cb.on_state_change(old, new);
        }
    }

    fn notify_connected(&self, remote: SocketAddr) {
        self.emit_event(EngineEvent::Connected { remote });
        for cb in self.callbacks.lock().clone() {
            cb.on_connected(remote);
        }
    }

    fn notify_disconnected(&self, reason: DisconnectReason) {
        self.emit_event(EngineEvent::Disconnected { reason: reason.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_disconnected(reason.clone());
        }
    }

    fn notify_stats_update(&self, stats: &StatsSnapshot) {
        self.emit_event(EngineEvent::StatsUpdated { stats: stats.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_stats_update(stats);
        }
    }

    fn notify_stealth_escalation(&self, from: u8, to: u8) {
        self.emit_event(EngineEvent::StealthEscalated { from, to });
        for cb in self.callbacks.lock().clone() {
            cb.on_stealth_escalation(from, to);
        }
    }

    fn notify_error(&self, error: &EngineError) {
        self.emit_event(EngineEvent::Error { error: error.clone() });
        for cb in self.callbacks.lock().clone() {
            cb.on_error(error);
        }
    }

    fn emit_event(&self, event: EngineEvent) {
        let mut sinks = self.event_sinks.lock();
        sinks.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::FecMode;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

    static ENGINE_TUN_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn engine_tun_test_guard() -> StdMutexGuard<'static, ()> {
        ENGINE_TUN_TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn engine_tun_test_config() -> EngineConfig {
        let mut config = EngineConfig::default();
        config.interface.tun_name.clear();
        config
    }

    fn tun_available() -> bool {
        let pool = crate::optimize::global_pool();
        let cfg = crate::interface::TunConfig {
            name: None,
            ip: None,
            netmask: None,
            mtu: 1500,
            zero_copy: true,
            ip6: None,
            prefix6: None,
        };
        crate::interface::TunInterface::open(cfg, pool).is_ok()
    }

    #[test]
    fn test_engine_lifecycle() {
        let _tun_guard = engine_tun_test_guard();
        if !tun_available() {
            return;
        }
        let config = engine_tun_test_config();
        let mut engine = QuicFuscateEngine::new(config).unwrap();

        assert_eq!(engine.state(), EngineState::Created);

        engine.start().unwrap();
        assert_eq!(engine.state(), EngineState::Running);

        engine.stop().unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
    }

    #[test]
    fn fec_policy_command_without_connection_reports_next_connection_scope() {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");

        let result = engine.set_fec_mode(FecMode::Off).expect("policy command");

        assert_eq!(result.requested, FecMode::Off);
        assert_eq!(result.configured, FecMode::Off);
        assert_eq!(result.effective, None);
        assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
        assert_eq!(engine.fec_mode(), FecMode::Off);
        assert_eq!(engine.active_fec_mode(), None);
    }

    #[test]
    fn structured_fec_command_returns_policy_acknowledgement() {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");

        let result =
            engine.apply_command(EngineCommand::SetFecMode(FecMode::Off)).expect("policy command");

        let EngineCommandResult::FecPolicy(result) = result else {
            panic!("FEC command must return a typed policy acknowledgement");
        };
        assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
        assert_eq!(result.effective, None);
    }

    #[test]
    fn next_connection_fec_command_updates_started_client_runtime_config() {
        let config = EngineConfig::default();
        let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        engine.client_runtime = Some(runtime);
        engine.state = EngineState::Running;

        let result = engine.set_fec_mode(FecMode::Off).expect("policy command");

        assert_eq!(result.scope, FecPolicyCommandScope::NextConnection);
        assert_eq!(engine.client_runtime.as_ref().expect("runtime").next_fec_mode(), FecMode::Off);
    }

    #[test]
    fn started_client_setters_update_the_next_connection_projection() {
        let config = EngineConfig::default();
        let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        engine.client_runtime = Some(runtime);
        engine.state = EngineState::Running;

        engine.set_stealth_mode(crate::engine::StealthMode::AntiDpi).expect("stealth update");
        engine
            .set_cc_algorithm(crate::engine::CcAlgorithm::Cubic)
            .expect("congestion-control update");
        engine.set_traffic_padding(true).expect("padding update");
        engine.set_timing_obfuscation(true).expect("timing update");
        engine.set_0rtt(false).expect("0-RTT update");

        let next = engine.client_runtime.as_ref().expect("client runtime").next_config();
        assert_eq!(next.stealth.mode, crate::engine::StealthMode::AntiDpi);
        assert_eq!(next.transport.cc_algorithm, crate::engine::CcAlgorithm::Cubic);
        assert!(next.stealth.enable_traffic_padding);
        assert!(next.stealth.enable_timing_obfuscation);
        assert!(!next.connection.enable_0rtt);
    }

    #[test]
    fn started_client_rejects_startup_owned_config_changes() {
        let config = EngineConfig::default();
        let runtime = ClientRuntime::new(config.clone()).expect("client runtime");
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        engine.client_runtime = Some(runtime);
        engine.state = EngineState::Running;
        let before = toml::to_string(engine.config()).expect("serialize config");

        let error = engine
            .update_config(|candidate| candidate.interface.tun_mtu = 1400)
            .expect_err("started client must reject TUN replacement");

        assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
        assert_eq!(toml::to_string(engine.config()).expect("serialize config"), before);
        assert_eq!(
            toml::to_string(engine.client_runtime.as_ref().expect("client runtime").next_config())
                .expect("serialize next config"),
            before
        );
    }

    #[test]
    fn running_generic_server_rejects_control_plane_config_mutation() {
        let mut config = EngineConfig::default();
        config.engine.mode = EngineMode::Server;
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        engine.state = EngineState::Running;

        let error = engine
            .set_traffic_padding(true)
            .expect_err("running generic server must reject client-style mutation");

        assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
        assert!(!engine.config().stealth.enable_traffic_padding);
    }

    #[test]
    fn file_reload_replaces_created_config_and_rejects_invalid_candidate() {
        let root = std::env::temp_dir().join(format!(
            "quicfuscate-engine-reload-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let valid_path = root.with_extension("valid.toml");
        let invalid_path = root.with_extension("invalid.toml");

        let mut replacement = EngineConfig::default();
        replacement.connection.remote = "127.0.0.1:9443".to_string();
        replacement.stealth.enable_traffic_padding = true;
        std::fs::write(&valid_path, toml::to_string(&replacement).expect("serialize valid config"))
            .expect("write valid config");

        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
        engine.reload_config_from_file(&valid_path).expect("valid reload");
        assert_eq!(engine.config().connection.remote, "127.0.0.1:9443");
        assert!(engine.config().stealth.enable_traffic_padding);

        let before_invalid = toml::to_string(engine.config()).expect("serialize current config");
        std::fs::write(&invalid_path, "[transport]\nmtu = 100\n").expect("write invalid config");
        assert!(engine.reload_config_from_file(&invalid_path).is_err());
        assert_eq!(
            toml::to_string(engine.config()).expect("serialize current config"),
            before_invalid
        );

        let missing_path = root.with_extension("missing.toml");
        assert!(engine.reload_config_from_file(&missing_path).is_err());
        assert_eq!(
            toml::to_string(engine.config()).expect("serialize current config"),
            before_invalid
        );

        let _ = std::fs::remove_file(valid_path);
        let _ = std::fs::remove_file(invalid_path);
    }

    #[test]
    fn running_server_rejects_engine_fec_mutation_without_changing_configured_state() {
        let mut config = EngineConfig::default();
        config.engine.mode = EngineMode::Server;
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        engine.state = EngineState::Running;

        let error = engine
            .set_fec_mode(FecMode::Off)
            .expect_err("running server mutation must be rejected");

        assert!(matches!(error, EngineError::InvalidState(EngineState::Running, _)));
        assert_eq!(engine.fec_mode(), FecMode::Auto);
    }

    #[test]
    fn test_engine_connect_disconnect() {
        let _tun_guard = engine_tun_test_guard();
        if !tun_available() {
            return;
        }
        let mut config = engine_tun_test_config();
        config.connection.remote = "127.0.0.1:4433".to_string();

        let mut engine = QuicFuscateEngine::new(config).unwrap();

        engine.start().unwrap();
        match engine.connect() {
            Ok(()) => {
                assert_eq!(engine.state(), EngineState::Connected);
                engine.disconnect().unwrap();
                assert_eq!(engine.state(), EngineState::Running);
            }
            Err(_) => {
                // On hosts without a reachable test server, connect must fail closed and
                // never leave the engine in a connected state.
                assert_eq!(engine.state(), EngineState::Running);
            }
        }

        engine.stop().unwrap();
    }

    #[test]
    fn test_runtime_transport_config_respects_enable_migration() {
        let mut enabled = EngineConfig::default();
        enabled.connection.enable_migration = true;
        let enabled_transport = build_runtime_transport_config(&enabled).expect("transport config");
        assert!(!enabled_transport.disable_active_migration);

        let mut disabled = EngineConfig::default();
        disabled.connection.enable_migration = false;
        let disabled_transport =
            build_runtime_transport_config(&disabled).expect("transport config");
        assert!(disabled_transport.disable_active_migration);
    }

    #[test]
    fn test_runtime_transport_config_carries_migration_policy() {
        let mut config = EngineConfig::default();
        config.connection.migration_cwnd_reduction_factor = 0.25;
        config.connection.migration_cooldown_ms = 0;
        config.connection.migration_probe_target =
            crate::transport::MigrationProbeTarget::ReducedWindow;

        let transport = build_runtime_transport_config(&config).expect("transport config");
        let policy = transport.migration_policy();
        assert_eq!(policy.port_rebinding_cwnd_factor, 0.25);
        assert_eq!(policy.cooldown, Duration::ZERO);
        assert_eq!(policy.probe_target, crate::transport::MigrationProbeTarget::ReducedWindow);
    }

    #[test]
    fn test_runtime_transport_config_rejects_missing_ca_file() {
        let mut config = EngineConfig::default();
        config.connection.ca_file = std::env::temp_dir()
            .join(format!("quicfuscate-missing-engine-ca-{}.pem", std::process::id()))
            .to_string_lossy()
            .into_owned();

        let error = match build_runtime_transport_config(&config) {
            Err(error) => error,
            Ok(_) => panic!("a configured CA path must fail closed when it cannot be loaded"),
        };
        assert!(matches!(error, EngineError::Config(_)));
    }

    #[test]
    fn test_runtime_transport_config_carries_nat_traversal_policy() {
        let mut config = EngineConfig::default();
        config.nat_traversal.enabled = true;
        config.nat_traversal.mode = crate::transport::NatTraversalMode::Roaming;
        config.nat_traversal.ice_enabled = true;
        config.nat_traversal.stun_servers = vec!["203.0.113.1:3478".to_string()];
        config.nat_traversal.max_candidates = 4;

        let transport = build_runtime_transport_config(&config).expect("transport config");
        let nat = transport.nat_traversal();
        assert!(nat.enabled);
        assert_eq!(nat.mode, crate::transport::NatTraversalMode::Roaming);
        assert!(nat.ice_enabled);
        assert_eq!(nat.max_candidates, 4);
        assert_eq!(nat.stun_servers.len(), 1);
    }

    #[test]
    fn test_runtime_transport_config_carries_all_traffic_analysis_policies() {
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

        let transport = build_runtime_transport_config(&config).expect("transport config");
        assert_eq!(transport.traffic_analysis_policy(), active);
        assert_eq!(transport.qkey_traffic_analysis_ceiling(), qkey_ceiling);
        assert_eq!(transport.intelligent_traffic_analysis_ceiling(), intelligent_ceiling);
    }

    /// A stop that cannot reap the server loop must not report a clean shutdown.
    ///
    /// The join previously timed out with a warning and the engine still published `Stopped`,
    /// while the loop could still hold listeners, sessions, and descriptors.
    #[test]
    fn stop_reports_an_error_when_the_server_loop_cannot_be_reaped() {
        let mut engine = QuicFuscateEngine::new(engine_tun_test_config()).expect("engine");
        engine.set_state(EngineState::Running);
        // A loop that never exits, standing in for a runtime that outlived its shutdown budget.
        let (block_tx, block_rx) = crossbeam_channel::bounded::<()>(1);
        engine.server_loop_handle = Some(
            std::thread::Builder::new()
                .name("test-unreapable-server-loop".to_string())
                .spawn(move || {
                    let _ = block_rx.recv();
                })
                .expect("spawn test loop"),
        );
        engine.config.engine.shutdown_timeout_ms = 50;

        let outcome = engine.stop();

        assert!(
            outcome.is_err(),
            "an unreaped server loop must surface as an error, not a clean Stopped"
        );
        assert_eq!(
            engine.state(),
            EngineState::Error,
            "the published state must not claim the engine stopped"
        );

        // Release the loop so the test leaves no live thread behind.
        let _ = block_tx.send(());
    }

    #[test]
    fn test_engine_server_start_stop_runs_standalone_runtime() {
        let _tun_guard = engine_tun_test_guard();
        let cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("config/local/dev-certs/admin-local-20260208_213140.crt");
        let key_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("config/local/dev-certs/admin-local-20260208_213140.key");
        if !cert_path.exists() || !key_path.exists() {
            return;
        }
        if !tun_available() {
            return;
        }

        let mut config = engine_tun_test_config();
        config.engine.mode = EngineMode::Server;
        config.connection.remote = "127.0.0.1:0".to_string();
        config.connection.cert_file = cert_path.to_string_lossy().into_owned();
        config.connection.key_file = key_path.to_string_lossy().into_owned();
        let mut engine = QuicFuscateEngine::new(config).unwrap();
        engine.start().unwrap();
        assert_eq!(engine.state(), EngineState::Running);
        assert!(engine.server_loop_handle.is_some());
        assert!(engine.server_loop_shutdown_tx.is_some());
        assert!(engine.server_metrics.is_some());
        std::thread::sleep(std::time::Duration::from_millis(25));
        assert!(engine.is_running());

        engine.stop().unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
        assert!(!engine.is_running());
    }

    #[test]
    fn test_engine_start_failure_enters_error_state() {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).unwrap();
        engine.config.engine.mode = EngineMode::Server;
        engine.config.connection.remote = "not-a-socket-address".to_string();

        assert!(matches!(engine.start(), Err(EngineError::Config(_))));
        assert_eq!(engine.state(), EngineState::Error);
        engine.stop().unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
    }

    #[test]
    fn test_invalid_state_transitions() {
        let _tun_guard = engine_tun_test_guard();
        if !tun_available() {
            return;
        }
        let config = engine_tun_test_config();
        let mut engine = QuicFuscateEngine::new(config).unwrap();

        // Can't connect before start
        assert!(engine.connect().is_err());

        // Can't disconnect before connect
        engine.start().unwrap();
        assert!(engine.disconnect().is_err());
    }

    struct TestCallback {
        state_changed: Arc<AtomicBool>,
    }

    impl EngineCallback for TestCallback {
        fn on_state_change(&self, _old: EngineState, _new: EngineState) {
            self.state_changed.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_callbacks() {
        let _tun_guard = engine_tun_test_guard();
        if !tun_available() {
            return;
        }
        let config = engine_tun_test_config();
        let mut engine = QuicFuscateEngine::new(config).unwrap();

        let state_changed = Arc::new(AtomicBool::new(false));
        let callback = TestCallback { state_changed: state_changed.clone() };

        engine.add_callback(callback);
        engine.start().unwrap();

        assert!(state_changed.load(Ordering::SeqCst));
    }

    #[test]
    fn test_server_refresh_stats_projects_runtime_owned_server_metrics() {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
        let server_metrics = Arc::new(Metrics::new());
        server_metrics.record_egress_datagram(100);
        server_metrics.record_egress_datagram(10);
        server_metrics.record_egress_datagram(1);
        server_metrics.record_ingress_datagram(200);
        server_metrics.record_ingress_datagram(20);
        server_metrics.record_ingress_datagram(1);
        server_metrics.record_ingress_datagram(1);
        server_metrics.clients_active.store(5, Ordering::Relaxed);
        engine.server_metrics = Some(server_metrics.clone());

        let global = crate::instrumentation::global();
        global.transport.record_rtt(123_000);
        global.transport.record_packet_out();
        global.transport.record_packet_loss();

        engine.refresh_stats();

        assert_eq!(engine.stats.bytes_sent.load(Ordering::Relaxed), 111);
        assert_eq!(engine.stats.bytes_received.load(Ordering::Relaxed), 222);
        assert_eq!(engine.stats.packets_sent.load(Ordering::Relaxed), 3);
        assert_eq!(engine.stats.packets_received.load(Ordering::Relaxed), 4);
        assert_eq!(engine.stats.active_streams.load(Ordering::Relaxed), 5);
        assert_eq!(engine.stats.rtt_ms.load(Ordering::Relaxed), 0);
        assert_eq!(engine.stats.loss_percent.load(Ordering::Relaxed), 0);
        assert_eq!(engine.stats.data_plane_ready.load(Ordering::Relaxed), 1);
        assert_eq!(engine.stats.data_plane_faults.load(Ordering::Relaxed), 0);

        server_metrics.record_tun_data_plane_fault();
        engine.refresh_stats();
        assert_eq!(engine.stats.data_plane_ready.load(Ordering::Relaxed), 0);
        assert_eq!(engine.stats.data_plane_faults.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn data_plane_faults_are_typed_and_displayable() {
        let fault = DataPlaneFault::TunWrite {
            component: "server MASQUE downlink".to_string(),
            error: "device closed".to_string(),
        };

        assert_eq!(fault.to_string(), "TUN write failed (server MASQUE downlink): device closed");
        assert_eq!(
            EngineError::DataPlane(fault.clone()).to_string(),
            "Data-plane error: TUN write failed (server MASQUE downlink): device closed"
        );
        assert_eq!(DisconnectReason::DataPlane(fault.clone()), DisconnectReason::DataPlane(fault));
    }

    #[test]
    fn test_check_heartbeat_returns_false_when_not_connected() {
        let mut config = EngineConfig::default();
        config.security.heartbeat_timeout_ms = 1000;
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        // Engine is in Created state, not Connected
        assert!(!engine.check_heartbeat());
    }

    #[test]
    fn test_check_heartbeat_disabled_when_timeout_zero() {
        let mut config = EngineConfig::default();
        config.security.heartbeat_timeout_ms = 0;
        let mut engine = QuicFuscateEngine::new(config).expect("engine");
        // Even if we forced state to Connected, heartbeat=0 means disabled
        engine.state = EngineState::Connected;
        assert!(!engine.check_heartbeat());
    }

    #[test]
    fn test_security_config_defaults() {
        let config = EngineConfig::default();
        // Kill switch disabled by default (safe default)
        assert!(!config.security.kill_switch);
        // Heartbeat timeout default is 30s
        assert_eq!(config.security.heartbeat_timeout_ms, 30_000);
        // Cleanup on start disabled by default
        assert!(!config.security.cleanup_firewall_on_start);
    }

    #[test]
    fn test_handle_connection_loss_no_op_when_not_connected() {
        let mut engine = QuicFuscateEngine::new(EngineConfig::default()).expect("engine");
        // Engine is in Created state - handle_connection_loss should be a no-op
        engine.handle_connection_loss(DisconnectReason::Timeout);
        // State should remain Created
        assert_eq!(engine.state(), EngineState::Created);
    }
}
