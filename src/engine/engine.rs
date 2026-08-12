//! QuicFuscate Engine - Main Control Interface
//!
//! This module provides the `QuicFuscateEngine` struct, which is the primary
//! interface for embedding QuicFuscate in applications.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::app_config::AppConfig;
use super::config::{EngineConfig, EngineMode};
use crate::implementations::client::{
    ClientDnsRuntime, ClientRuntime, KillSwitch, VpnFirewallPolicy,
};
use crate::implementations::server::{
    metrics::Metrics, normalize_runtime_optimize_config, AdminAction, PreparedStandaloneLaunch,
    ServerRuntime,
};
use crate::transport::Config;
use crate::transport::{self, CongestionControlAlgorithm};
use qf_memory_lock::MemoryLockPolicy;
use tokio::runtime::Builder as TokioRuntimeBuilder;

#[cfg(test)]
use qf_engine_types::DataPlaneFault;

pub use qf_engine_types::{
    DisconnectReason, EngineCallback, EngineCommand, EngineCommandResult, EngineError, EngineEvent,
    EngineState, EngineStats, FecPolicyCommandResult, FecPolicyCommandScope, StatsSnapshot,
};

fn build_server_optimize_config(
    config: &EngineConfig,
) -> Result<crate::optimize::OptimizeConfig, EngineError> {
    config.optimization.to_runtime_config().map_err(|error| EngineError::Config(error.to_string()))
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
    (qf_stealth::BrowserProfile, qf_stealth::OsProfile, Vec<qf_stealth::FingerprintProfile>),
    EngineError,
> {
    let browser =
        config.stealth.initial_browser.parse::<qf_stealth::BrowserProfile>().map_err(|_| {
            EngineError::Config(format!(
                "invalid initial_browser profile: {}",
                config.stealth.initial_browser
            ))
        })?;
    let os = config.stealth.initial_os.parse::<qf_stealth::OsProfile>().map_err(|_| {
        EngineError::Config(format!("invalid initial_os profile: {}", config.stealth.initial_os))
    })?;
    qf_stealth::FingerprintProfile::try_new(browser, os)
        .map_err(|error| EngineError::Config(format!("invalid initial profile: {error}")))?;
    let runtime =
        config.stealth.to_runtime_config(&config.fingerprint_rotation).map_err(|error| {
            EngineError::Config(format!("invalid stealth rotation projection: {error}"))
        })?;
    let profiles = runtime.rotation_profiles();

    Ok((browser, os, profiles))
}

fn build_server_runtime_profiles(
    config: &EngineConfig,
) -> Result<(qf_fec::FecConfig, qf_stealth::StealthConfig), EngineError> {
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
    let current_rotation = &current.fingerprint_rotation;
    let candidate_rotation = &candidate.fingerprint_rotation;
    if current_rotation.enabled != candidate_rotation.enabled
        || current_rotation.interval_secs != candidate_rotation.interval_secs
        || current_rotation.mode != candidate_rotation.mode
        || current_rotation.profile_slots != candidate_rotation.profile_slots
    {
        return Err(EngineError::InvalidState(
            state,
            "configuration update (fingerprint rotation policy requires a stopped client runtime)",
        ));
    }
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
            EngineCommand::GetTunCapabilities => Ok(EngineCommandResult::TunCapabilities(
                qf_transport_types::tun_capabilities(cfg!(feature = "tun-windows")),
            )),
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
            if let Err(error) = (MemoryLockPolicy {
                lock_memory: self.config.security.lock_memory,
                lock_blocks: self.config.security.lock_blocks,
                failure_policy: self.config.security.memory_lock_failure_policy,
            })
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
                    if profiles.is_empty() {
                        profiles = vec![qf_stealth::FingerprintProfile::try_new(profile, os)
                            .map_err(EngineError::Config)?];
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
    pub fn active_stealth_mode(&self) -> Option<qf_stealth::StealthMode> {
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
                    super::config::FecMode::Off => qf_fec::FecControlPolicy::Off,
                    super::config::FecMode::Auto => qf_fec::FecControlPolicy::Auto,
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
                qf_fec::FecControlPolicy::Off => super::config::FecMode::Off,
                qf_fec::FecControlPolicy::Auto => super::config::FecMode::Auto,
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
                qf_fec::FecControlPolicy::Off => super::config::FecMode::Off,
                qf_fec::FecControlPolicy::Auto => super::config::FecMode::Auto,
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
mod tests;
