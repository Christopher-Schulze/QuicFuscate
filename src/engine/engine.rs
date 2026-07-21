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
use crate::implementations::client::{ClientRuntime, KillSwitch};
use crate::implementations::server::{
    metrics::Metrics, normalize_runtime_optimize_config, AdminAction, PreparedStandaloneLaunch,
    ServerRuntime,
};
use crate::interface::app_config::AppConfig;
use crate::transport::Config;
use crate::transport::{self, CongestionControlAlgorithm};
use tokio::runtime::Builder as TokioRuntimeBuilder;

fn build_server_optimize_config(config: &EngineConfig) -> crate::optimize::OptimizeConfig {
    crate::optimize::OptimizeConfig {
        pool_capacity: config.optimization.memory_pool_size
            / config.optimization.memory_pool_alignment.max(1),
        block_size: config.optimization.memory_pool_alignment.max(65_536),
    }
}

fn build_runtime_transport_config(config: &EngineConfig) -> Result<Config, EngineError> {
    let mut transport =
        transport::Config::new_with_version(transport::PROTOCOL_VERSION).map_err(|error| {
            EngineError::Transport(format!("transport config init failed: {error}"))
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
    transport.set_initial_max_data(config.transport.initial_max_data);
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

    if config.connection.enable_0rtt {
        transport.enable_early_data();
    }
    transport.set_disable_active_migration(!config.connection.enable_migration);
    transport.set_nat_traversal(
        config.nat_traversal.to_transport_config().map_err(|error| {
            EngineError::Config(format!("NAT traversal config invalid: {error}"))
        })?,
    );
    if config.transport.disable_pmtud {
        transport.discover_pmtu(false);
    }

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
        crate::qftls::set_tls_ca_path(ca_path);
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
        super::config::CcAlgorithm::Bbr2 => CongestionControlAlgorithm::BBR2,
        super::config::CcAlgorithm::Bbr3 => CongestionControlAlgorithm::BBR3,
    }
}

fn load_runtime_profile_values(
    config: &EngineConfig,
) -> (
    crate::stealth::BrowserProfile,
    crate::stealth::OsProfile,
    Vec<crate::stealth::FingerprintProfile>,
) {
    let browser = config
        .stealth
        .initial_browser
        .parse::<crate::stealth::BrowserProfile>()
        .unwrap_or(crate::stealth::BrowserProfile::Chrome);
    let os = config
        .stealth
        .initial_os
        .parse::<crate::stealth::OsProfile>()
        .unwrap_or(crate::stealth::OsProfile::Windows);
    let profiles = crate::implementations::server::resolve_runtime_profiles(
        browser,
        os,
        &config.fingerprint_rotation.profile_slots,
        true,
    );

    (browser, os, profiles)
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
    /// Current engine state
    state: EngineState,
    /// Statistics
    stats: Arc<EngineStats>,
    /// Registered callbacks
    callbacks: Vec<Box<dyn EngineCallback>>,
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
#[derive(Debug, Clone)]
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

        let engine = Self {
            config,
            state: EngineState::Created,
            stats: Arc::new(EngineStats::default()),
            callbacks: Vec::new(),
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
        self.state
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
        self.callbacks.push(Box::new(callback));
    }

    /// Remove all callbacks.
    pub fn clear_callbacks(&mut self) {
        self.callbacks.clear();
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
                self.set_fec_mode(mode).map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::SetCongestionControl(cc) => {
                self.set_cc_algorithm(cc).map(|_| EngineCommandResult::State(self.state()))
            }
            EngineCommand::SetTrafficPadding(enable) => {
                self.set_traffic_padding(enable);
                Ok(EngineCommandResult::Ack)
            }
            EngineCommand::SetTimingObfuscation(enable) => {
                self.set_timing_obfuscation(enable);
                Ok(EngineCommandResult::Ack)
            }
            EngineCommand::SetZeroRtt(enable) => {
                self.set_0rtt(enable);
                Ok(EngineCommandResult::Ack)
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
        match self.state {
            EngineState::Created | EngineState::Stopped => {}
            _ => {
                return Err(EngineError::InvalidState(self.state, "start"));
            }
        }

        let old_state = self.state;
        self.set_state(EngineState::Starting);
        self.start_time = Some(Instant::now());

        // Initialize memory pool for optimized memory management
        let _pool = crate::optimize::global_pool();

        // Stealth and FEC modes are stored in config and applied during connection establishment
        let stealth_enabled = self.config.stealth.mode != super::config::StealthMode::Off;
        let fec_enabled = self.config.fec.mode != super::config::FecMode::Off;

        let start_result = match self.config.engine.mode {
            EngineMode::Client => {
                let mut runtime = ClientRuntime::new(self.config.clone())?;
                runtime.start()?;
                self.client_runtime = Some(runtime);
                Ok(())
            }
            EngineMode::Server => {
                let server_config = crate::implementations::server::server_config_from_listen_addr(
                    &self.config.connection.remote,
                )
                .map_err(EngineError::Config)?;
                let mut server_runtime = ServerRuntime::new_initialized_standalone_default(
                    self.config.clone(),
                    server_config,
                    None,
                    build_server_optimize_config(&self.config),
                    None,
                    None,
                    None,
                    None,
                )?;

                let (fec_cfg, stealth_cfg) = build_server_runtime_profiles(&self.config)?;
                let transport = build_runtime_transport_config(&self.config)?;
                let (profile, os, mut profiles) = load_runtime_profile_values(&self.config);
                if !self.config.fingerprint_rotation.enabled {
                    profiles = vec![crate::stealth::FingerprintProfile::new(profile, os)];
                }
                let server_metrics = server_runtime.standalone_metrics();
                let admin_actions_tx = server_runtime.admin_actions_sender();
                let fec_mode_override = Some(self.config.fec.mode);
                let opt_params = normalize_runtime_optimize_config(
                    build_server_optimize_config(&self.config),
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

                let handle = thread::spawn(move || {
                    let Ok(runtime) = TokioRuntimeBuilder::new_multi_thread().enable_all().build()
                    else {
                        log::error!("failed to create tokio runtime for server loop");
                        return;
                    };

                    runtime.block_on(async move {
                        if let Err(error) = server_runtime.run_standalone(launch).await {
                            log::error!("server loop exited with error: {error}");
                        }
                    });
                });
                self.server_loop_handle = Some(handle);
                self.server_loop_shutdown_tx = Some(admin_actions_tx);
                self.server_metrics = Some(server_metrics);
                Ok(())
            }
        };

        if let Err(e) = start_result {
            self.set_state(EngineState::Error);
            self.notify_state_change(old_state, EngineState::Error);
            return Err(e);
        }

        // Initialize kill switch for client mode if enabled
        if self.config.engine.mode == EngineMode::Client && self.config.security.kill_switch {
            // Optionally cleanup stale rules from a crashed previous session
            if self.config.security.cleanup_firewall_on_start {
                if let Err(e) = KillSwitch::cleanup_stale_rules() {
                    log::warn!("Kill switch stale rule cleanup failed: {}", e);
                }
            }
            let ks = Arc::new(KillSwitch::new());
            ks.enable()
                .map_err(|e| EngineError::Internal(format!("Kill switch enable failed: {}", e)))?;
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
        match self.state {
            EngineState::Running
            | EngineState::Connecting
            | EngineState::Connected
            | EngineState::Error => {}
            EngineState::Stopped => return Ok(()), // Already stopped
            _ => {
                return Err(EngineError::InvalidState(self.state, "stop"));
            }
        }

        if self.state == EngineState::Connected {
            if let Err(e) = self.disconnect() {
                log::warn!("Engine disconnect during stop failed: {}", e);
            }
        }

        let old_state = self.state;
        self.set_state(EngineState::Stopping);

        if let Some(mut runtime) = self.client_runtime.take() {
            if let Err(e) = runtime.stop() {
                log::warn!("Client runtime stop failed: {}", e);
            }
        }
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
            }
        }
        self.server_metrics = None;
        self.start_time = None;

        // Disable kill switch on stop (removes all firewall rules)
        if let Some(ks) = self.kill_switch.take() {
            if let Err(e) = ks.disable() {
                log::warn!("Kill switch disable on stop failed: {}", e);
            }
        }

        log::info!("Engine stopped gracefully");

        self.set_state(EngineState::Stopped);
        self.notify_state_change(old_state, EngineState::Stopped);

        Ok(())
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
        if self.state != EngineState::Running {
            return Err(EngineError::InvalidState(self.state, "connect"));
        }

        let old_state = self.state;

        // Resolve remote address for validation
        let remote: SocketAddr = self.config.connection.remote.parse().map_err(|e| {
            EngineError::Connection(format!(
                "Invalid remote address {}: {}",
                self.config.connection.remote, e
            ))
        })?;

        self.set_state(EngineState::Connecting);
        self.notify_state_change(old_state, EngineState::Connecting);

        let runtime = self
            .client_runtime
            .as_mut()
            .ok_or_else(|| EngineError::Internal("Client runtime not initialized".to_string()))?;

        match runtime.connect() {
            Ok(_) => {}
            Err(err) => {
                self.set_state(EngineState::Running);
                self.notify_state_change(EngineState::Connecting, EngineState::Running);
                return Err(err);
            }
        }

        // Wait for handshake completion via Condvar notification from IO driver.
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

        // Notify kill switch that VPN is connected
        if let Some(ref ks) = self.kill_switch {
            let tun_name = if self.config.interface.tun_name.is_empty() {
                "tun0"
            } else {
                &self.config.interface.tun_name
            };
            ks.on_vpn_connected(tun_name, &remote.ip().to_string()).map_err(|e| {
                EngineError::Internal(format!("Kill switch VPN-connected failed: {}", e))
            })?;
            log::info!("Kill switch: VPN traffic allowed, non-VPN traffic blocked");
        }

        self.set_state(EngineState::Connected);
        self.notify_state_change(EngineState::Connecting, EngineState::Connected);
        self.notify_connected(remote);

        Ok(())
    }

    /// Disconnect from remote server (client mode only).
    ///
    /// # Returns
    ///
    /// `Ok(())` if disconnected successfully, or an error.
    pub fn disconnect(&mut self) -> Result<(), EngineError> {
        // Validate state
        if self.state != EngineState::Connected {
            return Err(EngineError::InvalidState(self.state, "disconnect"));
        }

        let old_state = self.state;

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
        if self.state == EngineState::Connected {
            self.disconnect()?;
        }
        self.connect()
    }

    /// Handle unexpected connection loss (heartbeat timeout, remote close, etc.).
    ///
    /// Activates the kill switch immediately if enabled, transitions to Running state,
    /// and emits a disconnected event with the given reason.
    pub fn handle_connection_loss(&mut self, reason: DisconnectReason) {
        if self.state != EngineState::Connected {
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

        let old_state = self.state;
        self.set_state(EngineState::Running);
        self.notify_state_change(old_state, EngineState::Running);
        self.notify_disconnected(reason);
    }

    /// Check if the kill switch is currently enabled.
    pub fn is_kill_switch_enabled(&self) -> bool {
        self.kill_switch.as_ref().map(|ks| ks.is_enabled()).unwrap_or(false)
    }

    /// Check the heartbeat watchdog and trigger connection-loss handling if the
    /// heartbeat timeout has been exceeded.
    ///
    /// This method should be called periodically (e.g., every 1–5 seconds) by
    /// the engine's run loop or an external monitor. When the time since the
    /// last received packet exceeds `security.heartbeat_timeout_ms`, it calls
    /// `handle_connection_loss(Timeout)`, which activates the kill switch and
    /// transitions the engine back to `Running` state.
    ///
    /// Returns `true` if connection loss was detected and handled, `false` otherwise.
    pub fn check_heartbeat(&mut self) -> bool {
        // Only check when connected and heartbeat is enabled
        if self.state != EngineState::Connected {
            return false;
        }
        let timeout_ms = self.config.security.heartbeat_timeout_ms;
        if timeout_ms == 0 {
            return false; // Heartbeat watchdog disabled
        }

        // Get elapsed time since last inbound packet
        let elapsed = self
            .client_runtime
            .as_ref()
            .and_then(|rt| rt.connection())
            .map(|conn| conn.last_activity_elapsed())
            .unwrap_or(Duration::ZERO);

        if elapsed >= Duration::from_millis(timeout_ms) {
            log::warn!(
                "Heartbeat timeout: {}ms elapsed (threshold: {}ms) - triggering connection loss",
                elapsed.as_millis(),
                timeout_ms
            );
            self.handle_connection_loss(DisconnectReason::Timeout);
            return true;
        }
        false
    }

    // ========================================================================
    // Runtime Control Methods
    // ========================================================================

    /// Set the stealth mode at runtime.
    ///
    /// This allows changing the stealth level without restarting the engine.
    /// Changes take effect for new packets immediately.
    ///
    /// # Arguments
    ///
    /// * `mode` - The new stealth mode (Auto, Off, Max, Manual)
    pub fn set_stealth_mode(
        &mut self,
        mode: super::config::StealthMode,
    ) -> Result<(), EngineError> {
        let old_mode = self.config.stealth.mode as u8;
        self.config.stealth.mode = mode;
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
    pub fn set_fec_mode(&mut self, mode: super::config::FecMode) -> Result<(), EngineError> {
        self.config.fec.mode = mode;
        self.stats.fec_mode.store(mode as u64, Ordering::Relaxed);

        // Log the FEC mode change
        log::info!("FEC mode changed to {:?}", mode);

        Ok(())
    }

    /// Get the current FEC mode.
    pub fn fec_mode(&self) -> super::config::FecMode {
        self.config.fec.mode
    }

    /// Update the congestion control algorithm at runtime.
    ///
    /// # Arguments
    ///
    /// * `cc` - The new congestion control algorithm
    pub fn set_cc_algorithm(&mut self, cc: super::config::CcAlgorithm) -> Result<(), EngineError> {
        self.config.transport.cc_algorithm = cc;

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
    /// Use this for batch updates to avoid multiple change notifications.
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
        updater(&mut self.config);
        self.config.validate()?;

        // Update stats to reflect new config
        self.stats.stealth_mode.store(self.config.stealth.mode as u64, Ordering::Relaxed);
        self.stats.fec_mode.store(self.config.fec.mode as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Get a mutable reference to the configuration for direct modification.
    ///
    /// **Warning**: Changes made directly are not validated until the next
    /// operation. Use `update_config()` for validated changes.
    pub fn config_mut(&mut self) -> &mut EngineConfig {
        &mut self.config
    }

    /// Enable or disable traffic padding.
    pub fn set_traffic_padding(&mut self, enable: bool) {
        self.config.stealth.enable_traffic_padding = enable;
    }

    /// Enable or disable timing obfuscation.
    pub fn set_timing_obfuscation(&mut self, enable: bool) {
        self.config.stealth.enable_timing_obfuscation = enable;
    }

    /// Enable or disable 0-RTT early data.
    pub fn set_0rtt(&mut self, enable: bool) {
        self.config.connection.enable_0rtt = enable;
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
        self.state == EngineState::Connected
    }

    /// Check if the engine is running (ready for connections).
    pub fn is_running(&self) -> bool {
        matches!(
            self.state,
            EngineState::Running | EngineState::Connecting | EngineState::Connected
        )
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    fn refresh_stats(&self) {
        let metrics = crate::instrumentation::global();
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
        }
        if let Some(start) = self.start_time {
            self.stats.uptime_secs.store(start.elapsed().as_secs(), Ordering::Relaxed);
        }
        self.stats.stealth_mode.store(self.config.stealth.mode as u64, Ordering::Relaxed);
        self.stats.fec_mode.store(self.config.fec.mode as u64, Ordering::Relaxed);
    }

    fn set_state(&mut self, state: EngineState) {
        self.state = state;
    }

    fn notify_state_change(&self, old: EngineState, new: EngineState) {
        self.emit_event(EngineEvent::StateChanged { old, new });
        for cb in &self.callbacks {
            cb.on_state_change(old, new);
        }
    }

    fn notify_connected(&self, remote: SocketAddr) {
        self.emit_event(EngineEvent::Connected { remote });
        for cb in &self.callbacks {
            cb.on_connected(remote);
        }
    }

    fn notify_disconnected(&self, reason: DisconnectReason) {
        self.emit_event(EngineEvent::Disconnected { reason: reason.clone() });
        for cb in &self.callbacks {
            cb.on_disconnected(reason.clone());
        }
    }

    fn notify_stats_update(&self, stats: &StatsSnapshot) {
        self.emit_event(EngineEvent::StatsUpdated { stats: stats.clone() });
        for cb in &self.callbacks {
            cb.on_stats_update(stats);
        }
    }

    fn notify_stealth_escalation(&self, from: u8, to: u8) {
        self.emit_event(EngineEvent::StealthEscalated { from, to });
        for cb in &self.callbacks {
            cb.on_stealth_escalation(from, to);
        }
    }

    fn notify_error(&self, error: &EngineError) {
        self.emit_event(EngineEvent::Error { error: error.clone() });
        for cb in &self.callbacks {
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
        engine.server_metrics = Some(server_metrics);

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
