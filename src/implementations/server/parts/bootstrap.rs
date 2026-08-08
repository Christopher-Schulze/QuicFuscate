pub struct StandaloneServerBootstrapState {
    pub admin_log_buffer: Arc<self::admin_logs::AdminLogBuffer>,
    pub initial_logging_mode: String,
    pub blocked_ips_path: Option<std::path::PathBuf>,
    pub blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    pub qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
}

#[derive(Clone)]
pub struct StandaloneAdminWebBootstrap {
    pub admin_log_buffer: Arc<self::admin_logs::AdminLogBuffer>,
    pub initial_logging_mode: String,
    pub blocked_ips_path: Option<std::path::PathBuf>,
}

pub(crate) struct StandaloneServiceConfig {
    metrics_port: Option<u16>,
    admin_socket: Option<std::path::PathBuf>,
    admin_web: Option<std::net::SocketAddr>,
    admin_web_max_connections: usize,
    admin_web_operation_timeout_ms: u64,
    admin_web_root: std::path::PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
}

#[derive(Clone, Copy)]
pub struct RuntimeStealthPolicy<'a> {
    pub profile: BrowserProfile,
    pub os: OsProfile,
    pub disable_doh: bool,
    pub doh_provider: &'a str,
    pub disable_fronting: bool,
    pub front_domain: &'a [String],
    pub disable_http3: bool,
}

#[derive(Clone)]
pub(crate) struct OwnedRuntimeStealthPolicy {
    profile: BrowserProfile,
    os: OsProfile,
    disable_doh: bool,
    doh_provider: String,
    disable_fronting: bool,
    front_domain: Vec<String>,
    disable_http3: bool,
}

impl OwnedRuntimeStealthPolicy {
    fn from_runtime_policy(policy: RuntimeStealthPolicy<'_>) -> Self {
        Self {
            profile: policy.profile,
            os: policy.os,
            disable_doh: policy.disable_doh,
            doh_provider: policy.doh_provider.to_string(),
            disable_fronting: policy.disable_fronting,
            front_domain: policy.front_domain.to_vec(),
            disable_http3: policy.disable_http3,
        }
    }

    pub fn as_runtime_policy(&self) -> RuntimeStealthPolicy<'_> {
        RuntimeStealthPolicy {
            profile: self.profile,
            os: self.os,
            disable_doh: self.disable_doh,
            doh_provider: self.doh_provider.as_str(),
            disable_fronting: self.disable_fronting,
            front_domain: &self.front_domain,
            disable_http3: self.disable_http3,
        }
    }

    pub fn apply_to(&self, stealth_cfg: &mut StealthConfig) {
        apply_runtime_stealth_overrides(
            stealth_cfg,
            self.profile,
            self.os,
            self.disable_doh,
            self.doh_provider.as_str(),
            self.disable_fronting,
            &self.front_domain,
            self.disable_http3,
        );
    }
}

/// Immutable, generation-tagged view of the policy domains used to construct
/// a new server connection.
pub(crate) struct RuntimePolicySnapshot {
    pub(crate) generation: u64,
    pub(crate) transport: crate::transport::Config,
    pub(crate) fec: FecConfig,
    pub(crate) optimize: OptimizeConfig,
    pub(crate) stealth: StealthConfig,
}

impl RuntimePolicySnapshot {
    pub(crate) fn capture(
        generation: &RuntimePolicyGeneration,
        transport: &crate::transport::Config,
        fec: &Arc<std::sync::Mutex<FecConfig>>,
        optimize: &Arc<std::sync::Mutex<OptimizeConfig>>,
        stealth: &Arc<std::sync::Mutex<StealthConfig>>,
    ) -> Self {
        let generation_guard = generation.read_guard();
        let transport = transport.clone();
        let fec = fec.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let optimize = *optimize.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let stealth = stealth.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        Self {
            generation: *generation_guard,
            transport,
            fec,
            optimize,
            stealth,
        }
    }
}

pub(crate) struct PreparedStandaloneRuntimeConfig {
    transport: crate::transport::Config,
    fec_cfg_shared: Arc<std::sync::Mutex<FecConfig>>,
    opt_params_shared: Arc<std::sync::Mutex<OptimizeConfig>>,
    stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    runtime_policy_generation: RuntimePolicyGeneration,
    profiles: Vec<FingerprintProfile>,
    profile_interval_secs: u64,
    standalone_runtime_metadata: StandaloneRuntimeMetadata,
    tun_enable: bool,
    /// Shared 0-RTT anti-replay strike register (server only).
    strike_register: Option<Arc<crate::transport::anti_replay::StrikeRegister>>,
    /// Anti-replay configuration loaded from [anti_replay] TOML section.
    anti_replay_section: crate::engine::AntiReplaySection,
}

pub struct PreparedStandaloneLaunch {
    services: Option<StandaloneServiceConfig>,
    runtime: PreparedStandaloneRuntimeConfig,
}

impl PreparedStandaloneLaunch {
    fn new(services: StandaloneServiceConfig, runtime: PreparedStandaloneRuntimeConfig) -> Self {
        Self { services: Some(services), runtime }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_runtime_stealth(
        metrics_port: Option<u16>,
        admin_socket: Option<std::path::PathBuf>,
        admin_web: Option<std::net::SocketAddr>,
        admin_web_max_connections: usize,
        admin_web_operation_timeout_ms: u64,
        admin_web_root: std::path::PathBuf,
        admin_web_user: Option<String>,
        admin_web_password: Option<String>,
        config_path: Option<std::path::PathBuf>,
        transport: crate::transport::Config,
        fec_cfg: FecConfig,
        opt_params: OptimizeConfig,
        stealth_cfg: StealthConfig,
        fec_mode_override: Option<crate::engine::FecMode>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        stealth_policy: RuntimeStealthPolicy<'_>,
        tun_enable: bool,
    ) -> Self {
        Self::new(
            StandaloneServiceConfig::new(
                metrics_port,
                admin_socket,
                admin_web,
                admin_web_max_connections,
                admin_web_operation_timeout_ms,
                admin_web_root,
                admin_web_user,
                admin_web_password,
            ),
            PreparedStandaloneRuntimeConfig::new_with_runtime_stealth(
                config_path,
                transport,
                fec_cfg,
                opt_params,
                stealth_cfg,
                fec_mode_override,
                profiles,
                profile_interval_secs,
                OwnedRuntimeStealthPolicy::from_runtime_policy(stealth_policy),
                tun_enable,
            ),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_headless_with_runtime_stealth(
        transport: crate::transport::Config,
        fec_cfg: FecConfig,
        opt_params: OptimizeConfig,
        stealth_cfg: StealthConfig,
        fec_mode_override: Option<crate::engine::FecMode>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        stealth_policy: RuntimeStealthPolicy<'_>,
        tun_enable: bool,
    ) -> Self {
        Self::new_with_runtime_stealth(
            None,
            None,
            None,
            crate::implementations::server::DEFAULT_ADMIN_WEB_MAX_CONNECTIONS,
            crate::implementations::server::DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS,
            std::path::PathBuf::new(),
            None,
            None,
            None,
            transport,
            fec_cfg,
            opt_params,
            stealth_cfg,
            fec_mode_override,
            profiles,
            profile_interval_secs,
            stealth_policy,
            tun_enable,
        )
    }
}

impl PreparedStandaloneRuntimeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_runtime_stealth(
        config_path: Option<std::path::PathBuf>,
        transport: crate::transport::Config,
        fec_cfg: FecConfig,
        opt_params: OptimizeConfig,
        mut stealth_cfg: StealthConfig,
        fec_mode_override: Option<crate::engine::FecMode>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        stealth_policy: OwnedRuntimeStealthPolicy,
        tun_enable: bool,
    ) -> Self {
        stealth_policy.apply_to(&mut stealth_cfg);
        Self::new(
            config_path,
            transport,
            fec_cfg,
            opt_params,
            stealth_cfg,
            fec_mode_override,
            profiles,
            profile_interval_secs,
            stealth_policy,
            tun_enable,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config_path: Option<std::path::PathBuf>,
        transport: crate::transport::Config,
        fec_cfg: FecConfig,
        opt_params: OptimizeConfig,
        stealth_cfg: StealthConfig,
        fec_mode_override: Option<crate::engine::FecMode>,
        profiles: Vec<FingerprintProfile>,
        profile_interval_secs: u64,
        stealth_policy: OwnedRuntimeStealthPolicy,
        tun_enable: bool,
    ) -> Self {
        Self {
            transport,
            fec_cfg_shared: Arc::new(std::sync::Mutex::new(fec_cfg)),
            opt_params_shared: Arc::new(std::sync::Mutex::new(opt_params)),
            stealth_config: Arc::new(std::sync::Mutex::new(stealth_cfg)),
            runtime_policy_generation: RuntimePolicyGeneration::new(),
            profiles,
            profile_interval_secs,
            standalone_runtime_metadata: StandaloneRuntimeMetadata {
                front_domain: stealth_policy.front_domain.clone(),
                config_path,
                reload_policy: StandaloneReloadPolicy {
                    fec_mode_override,
                    stealth_policy: stealth_policy.clone(),
                },
            },
            tun_enable,
            strike_register: None,
            anti_replay_section: crate::engine::AntiReplaySection::default(),
        }
    }
}

impl PreparedStandaloneLaunch {
    /// Override the anti-replay section (called after construction when config is available).
    pub fn set_anti_replay_section(&mut self, section: crate::engine::AntiReplaySection) {
        self.runtime.anti_replay_section = section;
    }
}

impl StandaloneServiceConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        metrics_port: Option<u16>,
        admin_socket: Option<std::path::PathBuf>,
        admin_web: Option<std::net::SocketAddr>,
        admin_web_max_connections: usize,
        admin_web_operation_timeout_ms: u64,
        admin_web_root: std::path::PathBuf,
        admin_web_user: Option<String>,
        admin_web_password: Option<String>,
    ) -> Self {
        Self {
            metrics_port,
            admin_socket,
            admin_web,
            admin_web_max_connections,
            admin_web_operation_timeout_ms,
            admin_web_root,
            admin_web_user,
            admin_web_password,
        }
    }
}

pub fn parse_runtime_profile_entry(
    entry: &str,
    default_os: OsProfile,
) -> Option<FingerprintProfile> {
    match parse_runtime_profile_entry_checked(entry, default_os) {
        Ok(profile) => Some(profile),
        Err(error) => {
            log::warn!("Invalid fingerprint profile slot '{}': {}", entry, error);
            None
        }
    }
}

fn parse_runtime_profile_entry_checked(
    entry: &str,
    default_os: OsProfile,
) -> Result<FingerprintProfile, String> {
    crate::stealth::parse_fingerprint_profile_slot(entry, default_os)
}

pub fn resolve_runtime_profiles(
    initial_browser: BrowserProfile,
    initial_os: OsProfile,
    profile_slots: &[String],
    fallback_to_default: bool,
) -> Result<Vec<FingerprintProfile>, String> {
    let default_profile = FingerprintProfile::try_new(initial_browser, initial_os)?;
    let mut profiles = Vec::with_capacity(profile_slots.len().max(1));
    for slot in profile_slots {
        profiles.push(
            parse_runtime_profile_entry_checked(slot, initial_os)
                .map_err(|error| format!("invalid fingerprint profile slot '{slot}': {error}"))?,
        );
    }

    if profiles.is_empty() && fallback_to_default {
        profiles.push(default_profile);
    }

    Ok(profiles)
}

pub fn runtime_components_from_app_config(
    app_cfg: crate::interface::app_config::AppConfig,
    fec_mode_override: Option<crate::engine::FecMode>,
) -> (FecConfig, StealthConfig, OptimizeConfig, crate::engine::AntiReplaySection) {
    let mut fec = app_cfg.fec;
    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }

    (fec, app_cfg.stealth, app_cfg.optimize, app_cfg.anti_replay)
}

impl Default for StandaloneAdminWebBootstrap {
    fn default() -> Self {
        Self {
            admin_log_buffer: Arc::new(self::admin_logs::AdminLogBuffer::new(4096)),
            initial_logging_mode: "normal".to_string(),
            blocked_ips_path: None,
        }
    }
}

type StandaloneRuntimeBootstrapParts = (
    Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    Arc<std::sync::Mutex<QKeyRegistry>>,
    StandaloneAdminWebBootstrap,
);

impl StandaloneServerBootstrapState {
    fn into_runtime_parts(self) -> StandaloneRuntimeBootstrapParts {
        (
            self.blocked_ips,
            self.qkey_registry,
            StandaloneAdminWebBootstrap {
                admin_log_buffer: self.admin_log_buffer,
                initial_logging_mode: self.initial_logging_mode,
                blocked_ips_path: self.blocked_ips_path,
            },
        )
    }
}

pub fn initialize_standalone_server_bootstrap(
    config_path: Option<&std::path::Path>,
    admin_log_buffer_override: Option<Arc<self::admin_logs::AdminLogBuffer>>,
    qkey_ttl_override: Option<u64>,
    qkey_store_override: Option<std::path::PathBuf>,
) -> std::io::Result<StandaloneServerBootstrapState> {
    initialize_standalone_server_bootstrap_with_clock(
        config_path,
        admin_log_buffer_override,
        qkey_ttl_override,
        qkey_store_override,
        crate::time_source::ProtocolClock::default(),
    )
}

pub fn initialize_standalone_server_bootstrap_with_clock(
    config_path: Option<&std::path::Path>,
    admin_log_buffer_override: Option<Arc<self::admin_logs::AdminLogBuffer>>,
    qkey_ttl_override: Option<u64>,
    qkey_store_override: Option<std::path::PathBuf>,
    clock: crate::time_source::ProtocolClock,
) -> std::io::Result<StandaloneServerBootstrapState> {
    let admin_log_buffer = admin_log_buffer_override
        .unwrap_or_else(|| Arc::new(self::admin_logs::AdminLogBuffer::new_with_clock(4096, &clock)));
    let initial_mode = match load_persisted_logging_mode(config_path)? {
        PersistedLoggingModeState::Absent => crate::engine::LoggingMode::Normal,
        PersistedLoggingModeState::Valid(mode) => mode,
    };
    apply_logging_mode(&initial_mode, &admin_log_buffer);
    let initial_logging_mode = logging_mode_name(&initial_mode).to_string();

    let blocked_ips_path = resolve_blocked_ips_store_path(config_path);
    let initial_blocked = match load_persisted_blocked_ips(config_path)? {
        PersistedBlockedIpsState::Absent => {
            log::info!("No persisted blocked-IP policy; starting with an empty set");
            std::collections::HashSet::new()
        }
        PersistedBlockedIpsState::Valid(blocked) => {
            // Log the empty case too. An empty policy and a missing one look identical
            // in memory, and only the log distinguishes them for an operator.
            log::info!("Loaded {} blocked IPs from disk", blocked.len());
            blocked
        }
    };
    let blocked_ips = Arc::new(parking_lot::RwLock::new(initial_blocked));

    let qkey_ttl_secs = resolve_qkey_ttl_secs(qkey_ttl_override);
    let qkey_store_path = resolve_qkey_store_path(config_path, qkey_store_override);
    let qkey_registry = Arc::new(std::sync::Mutex::new(
        QKeyRegistry::open_with_clock(200, qkey_store_path, qkey_ttl_secs, clock)
            .map_err(std::io::Error::other)?,
    ));

    Ok(StandaloneServerBootstrapState {
        admin_log_buffer,
        initial_logging_mode,
        blocked_ips_path,
        blocked_ips,
        qkey_registry,
    })
}

pub(crate) fn read_runtime_config(config_path: Option<&std::path::Path>) -> AdminResponse {
    let Some(path) = config_path else {
        return AdminResponse::error("Config path not set");
    };
    match std::fs::read_to_string(path) {
        Ok(contents) => AdminResponse::ok_with_data(serde_json::json!({ "config": contents })),
        Err(e) => AdminResponse::error(format!("Config read failed: {}", e)),
    }
}

pub(crate) fn write_runtime_config(
    core: &ServerAdminCore,
    config_path: Option<&std::path::Path>,
    contents: &str,
) -> AdminResponse {
    let Some(path) = config_path else {
        return AdminResponse::error("Config path not set");
    };
    match crate::interface::app_config::AppConfig::from_toml(contents) {
        Ok(cfg) => {
            if let Err(e) = cfg.validate() {
                return AdminResponse::error(format!("Config validation failed: {}", e));
            }
        }
        Err(e) => {
            return AdminResponse::error(format!("Config parse failed: {}", e));
        }
    };
    if let Err(e) = validate_transport_overrides_from_toml(contents) {
        return AdminResponse::error(format!("Config validation failed: {}", e));
    }
    match fsutil::atomic_write_file(
        path,
        contents.as_bytes(),
        Some(0o600),
        "server::write_config_tmp_nonce",
    ) {
        Ok(()) => match core.request_reload_after_write() {
            Ok(()) => AdminResponse::ok_with_message("Config saved and reload scheduled"),
            Err(e) => AdminResponse::error(format!("Config saved, but {}", e)),
        },
        Err(e) => AdminResponse::error(format!("Config write failed: {}", e)),
    }
}

pub(crate) fn read_logging_mode(logging_mode: &parking_lot::RwLock<String>) -> AdminResponse {
    let mode = logging_mode.read();
    AdminResponse::ok_with_data(serde_json::json!({ "mode": mode.as_str() }))
}

pub(crate) fn write_logging_mode(
    config_path: Option<&std::path::Path>,
    logging_mode: &parking_lot::RwLock<String>,
    log_buffer: &crate::implementations::server::admin_logs::AdminLogBuffer,
    mode: &str,
) -> AdminResponse {
    let parsed_mode = match parse_logging_mode(mode) {
        Ok(parsed_mode) => parsed_mode,
        Err(error) => return AdminResponse::error(error),
    };
    let mode_name = logging_mode_name(&parsed_mode);
    let mut current_mode = logging_mode.write();
    if let Some(path) = resolve_logging_store_path(config_path) {
        if let Err(error) = persist_logging_mode(config_path, &parsed_mode) {
            return AdminResponse::error(format!(
                "Logging mode persistence failed for {}: {error}; live mode remains '{}'",
                path.display(),
                current_mode.as_str()
            ));
        }
        *current_mode = mode_name.to_string();
        apply_logging_mode(&parsed_mode, log_buffer);
        return AdminResponse::ok_with_message(format!(
            "Logging mode set to '{}' and persisted",
            mode_name
        ));
    }
    *current_mode = mode_name.to_string();
    apply_logging_mode(&parsed_mode, log_buffer);
    AdminResponse::ok_with_message(format!(
        "Logging mode set to '{}' live-only: no config path is configured; restart will not restore it",
        mode_name
    ))
}
