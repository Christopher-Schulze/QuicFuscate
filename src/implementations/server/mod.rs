//! QuicFuscate Server Implementation
//!
//! This module provides the canonical server runtime and retained server-side
//! support surfaces for this fork.
//! - Standalone UDP accept loop and shared server runtime ownership
//! - Session management, IP pool allocation, and limit enforcement
//! - Admin/control-plane wiring and metrics surfaces
//! - Optional host routing integration where platform support exists
//!
//! # Architecture
//!
//! ```text
//! Canonical server runtime flow:
//! - Track sessions and assign IPs
//! - Route traffic via TUN and optionally host routing helpers
//! - Provide the shared ownership model used by the standalone live UDP server path
//! ```

mod accept;
pub mod admin;
pub mod admin_http;
pub mod admin_logs;
#[doc(hidden)]
pub mod fsutil;
mod ip_pool;
mod limits;
pub mod metrics;
pub mod qkey_registry;
mod routing;
mod session;
pub mod systemd;

pub use accept::{
    AcceptConfig, AcceptDecision, AcceptLoop, AcceptStats, AcceptStatsSnapshot,
    IpConnectionTracker, RejectReason, DEFAULT_MAX_CONNECTIONS_PER_IP,
};
#[cfg(any(test, feature = "rust-tests"))]
pub use admin::DefaultAdminHandler;
pub use admin::{
    snapshots_to_client_info, AdminCommand, AdminHandler, AdminResponse, AdminServer,
    ClientIdentity, ClientInfo, ClientSnapshot,
};
pub use admin_http::{AdminHttpHandler, AdminHttpServer};
pub use ip_pool::IpPool;
#[cfg(feature = "rate_limiter")]
pub use limits::load_rate_limit_config_from_env;
pub use limits::{ConnectionLimiter, RateLimitConfig, RateLimiter};
#[cfg(any(test, feature = "rust-tests"))]
pub use metrics::GlobalMetricsServer;
pub use metrics::Metrics;
pub use routing::{detect_wan_interface, RoutingError, RoutingManager};
pub use session::{Session, SessionError, SessionId, SessionManager, SessionStats};

use self::admin_http::{AdminAuth, IssueQKeyRequest};
use self::qkey_registry::{QKeyEntry, QKeyRecord, QKeyRegistry};
use parking_lot::RwLock;
#[cfg(feature = "rate_limiter")]
use std::net::IpAddr;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::QuicFuscateConnection;
use crate::engine::{EngineConfig, EngineError};
use crate::error::ConnectionError;
use crate::fec::FecConfig;
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::optimize::OptimizeConfig;
#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::stealth::{BrowserProfile, FingerprintProfile, OsProfile, StealthConfig};

fn env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).map(|v| v.trim() == "1" || v.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Server configuration (extends EngineConfig).
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Maximum concurrent clients
    pub max_clients: usize,
    /// Client session timeout (seconds)
    pub client_timeout_secs: u64,
    /// IP pool start
    pub ip_pool_start: Ipv4Addr,
    /// IP pool end
    pub ip_pool_end: Ipv4Addr,
    /// Server TUN IP
    pub server_ip: Ipv4Addr,
    /// Server netmask
    pub server_netmask: Ipv4Addr,
    /// DNS servers to push
    pub dns_servers: Vec<Ipv4Addr>,
    /// WAN interface for NAT
    pub wan_interface: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 4433)),
            max_clients: 100,
            client_timeout_secs: 3600,
            ip_pool_start: Ipv4Addr::new(10, 8, 0, 2),
            ip_pool_end: Ipv4Addr::new(10, 8, 0, 254),
            server_ip: Ipv4Addr::new(10, 8, 0, 1),
            server_netmask: Ipv4Addr::new(255, 255, 255, 0),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            wan_interface: "eth0".to_string(),
        }
    }
}

pub fn server_config_from_listen_addr(listen_addr: &str) -> Result<ServerConfig, String> {
    let listen = listen_addr
        .to_socket_addrs()
        .map_err(|e| format!("listen address resolve failed for '{}': {}", listen_addr, e))?
        .next()
        .ok_or_else(|| {
            format!("listen address '{}' resolved to no socket addresses", listen_addr)
        })?;
    Ok(ServerConfig { listen, ..ServerConfig::default() })
}

pub(crate) fn resolve_qkey_ttl_secs(ttl_override: Option<u64>) -> Option<u64> {
    match ttl_override {
        Some(0) => None,
        Some(v) => Some(v),
        None => match std::env::var("QUICFUSCATE_QKEY_TTL_SECS") {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(0) => None,
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!("Invalid QUICFUSCATE_QKEY_TTL_SECS '{}': {}", raw, e);
                    None
                }
            },
            Err(_) => None,
        },
    }
}

pub(crate) fn resolve_admin_web_auth(
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
) -> std::io::Result<admin_http::AdminAuth> {
    let admin_user =
        admin_web_user.or_else(|| env_string("QUICFUSCATE_ADMIN_USER")).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--admin-web requires --admin-web-user or QUICFUSCATE_ADMIN_USER",
            )
        })?;
    let admin_password = admin_web_password
        .or_else(|| env_string("QUICFUSCATE_ADMIN_PASSWORD"))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--admin-web requires --admin-web-password or QUICFUSCATE_ADMIN_PASSWORD",
            )
        })?;

    let requires_password_change = admin_user == "admin" && admin_password == "123";
    if requires_password_change {
        let allow_weak_defaults = env_flag_enabled("QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS");
        if !allow_weak_defaults {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Refusing weak default admin credentials [admin/123]. Set QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS=1 only for controlled test environments.",
            ));
        }
        log::warn!(
            "Admin web weak defaults [admin/123] explicitly allowed by QUICFUSCATE_ALLOW_WEAK_ADMIN_DEFAULTS."
        );
    }

    Ok(admin_http::AdminAuth::new(admin_user, admin_password, requires_password_change))
}

pub(crate) fn resolve_admin_auth_store_path(
    config_path: Option<&std::path::Path>,
) -> std::path::PathBuf {
    config_path
        .and_then(|p| p.parent().map(|dir| dir.join("admin-auth.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("config/local/admin-auth.json"))
}

pub(crate) fn resolve_blocked_ips_store_path(
    config_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    config_path.map(|p| p.with_extension("blocked.json"))
}

pub(crate) fn load_persisted_blocked_ips(
    config_path: Option<&std::path::Path>,
) -> std::collections::HashSet<String> {
    resolve_blocked_ips_store_path(config_path)
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

pub(crate) fn resolve_qkey_store_path(
    config_path: Option<&std::path::Path>,
    qkey_store_override: Option<std::path::PathBuf>,
) -> std::path::PathBuf {
    qkey_store_override
        .or_else(|| config_path.map(|path| path.with_extension("qkeys.json")))
        .unwrap_or_else(|| std::path::PathBuf::from("config/local/qkeys.json"))
}

pub(crate) fn resolve_logging_store_path(
    config_path: Option<&std::path::Path>,
) -> Option<std::path::PathBuf> {
    config_path.map(|p| p.with_extension("logging.json"))
}

pub(crate) fn load_persisted_logging_mode(config_path: Option<&std::path::Path>) -> String {
    resolve_logging_store_path(config_path)
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("mode").and_then(|m| m.as_str().map(String::from)))
        .unwrap_or_else(|| "normal".to_string())
}

pub(crate) fn apply_logging_mode(
    mode: &str,
    log_buffer: &crate::implementations::server::admin_logs::AdminLogBuffer,
) {
    let level = match mode {
        "no-log" => log::LevelFilter::Off,
        "minimal" => log::LevelFilter::Warn,
        "verbose" => log::LevelFilter::Trace,
        _ => log::LevelFilter::Info,
    };
    log::set_max_level(level);
    if mode == "no-log" {
        log_buffer.clear();
    }
}

pub(crate) fn persist_logging_mode(
    config_path: Option<&std::path::Path>,
    mode: &str,
) -> std::io::Result<()> {
    let Some(path) = resolve_logging_store_path(config_path) else {
        return Ok(());
    };
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({ "mode": mode }))?;
    fsutil::atomic_write_file(&path, &bytes, Some(0o600), "server::write_logging_config_tmp_nonce")
}

pub(crate) fn persist_blocked_ips(
    path: &std::path::Path,
    ips: &std::collections::HashSet<String>,
) -> std::io::Result<()> {
    let mut sorted: Vec<&String> = ips.iter().collect();
    sorted.sort();
    let bytes = serde_json::to_vec_pretty(&sorted)?;
    fsutil::atomic_write_file(path, &bytes, Some(0o600), "server::persist_blocked_ips_tmp_nonce")
}

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

pub(crate) struct PreparedStandaloneRuntimeConfig {
    transport: crate::transport::Config,
    fec_cfg_shared: Arc<std::sync::Mutex<FecConfig>>,
    opt_params_shared: Arc<std::sync::Mutex<OptimizeConfig>>,
    stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    profiles: Vec<FingerprintProfile>,
    profile_interval_secs: u64,
    stealth_policy: OwnedRuntimeStealthPolicy,
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
            stealth_policy,
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
        admin_web_root: std::path::PathBuf,
        admin_web_user: Option<String>,
        admin_web_password: Option<String>,
    ) -> Self {
        Self {
            metrics_port,
            admin_socket,
            admin_web,
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
    let mut parts = entry.split('@');
    let browser_part = parts.next()?.trim();
    let browser = match browser_part.parse::<BrowserProfile>() {
        Ok(browser) => browser,
        Err(_) => {
            log::warn!("Invalid browser profile: {}", browser_part);
            return None;
        }
    };

    let os = match parts.next() {
        Some(part) => match part.trim().parse::<OsProfile>() {
            Ok(os) => os,
            Err(_) => {
                log::warn!("Invalid OS profile: {}", part.trim());
                return None;
            }
        },
        None => default_os,
    };

    let profile = FingerprintProfile::new(browser, os);
    if profile.client_hello.is_none() {
        log::warn!(
            "No ClientHello found for {}@{}",
            browser_part,
            format!("{:?}", os).to_lowercase()
        );
        return None;
    }

    Some(profile)
}

pub fn resolve_runtime_profiles(
    initial_browser: BrowserProfile,
    initial_os: OsProfile,
    profile_slots: &[String],
    fallback_to_default: bool,
) -> Vec<FingerprintProfile> {
    let default_profile = FingerprintProfile::new(initial_browser, initial_os);
    let mut profiles = profile_slots
        .iter()
        .filter_map(|slot| parse_runtime_profile_entry(slot, initial_os))
        .collect::<Vec<_>>();

    if profiles.is_empty() && fallback_to_default {
        profiles.push(default_profile);
    }

    profiles
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
) -> StandaloneServerBootstrapState {
    let admin_log_buffer = admin_log_buffer_override
        .unwrap_or_else(|| Arc::new(self::admin_logs::AdminLogBuffer::new(4096)));
    let initial_logging_mode = load_persisted_logging_mode(config_path);
    apply_logging_mode(initial_logging_mode.as_str(), &admin_log_buffer);

    let blocked_ips_path = resolve_blocked_ips_store_path(config_path);
    let initial_blocked = load_persisted_blocked_ips(config_path);
    if !initial_blocked.is_empty() {
        log::info!("Loaded {} blocked IPs from disk", initial_blocked.len());
    }
    let blocked_ips = Arc::new(parking_lot::RwLock::new(initial_blocked));

    let qkey_ttl_secs = resolve_qkey_ttl_secs(qkey_ttl_override);
    let qkey_store_path = resolve_qkey_store_path(config_path, qkey_store_override);
    let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(
        200,
        Some(qkey_store_path),
        qkey_ttl_secs,
    )));

    StandaloneServerBootstrapState {
        admin_log_buffer,
        initial_logging_mode,
        blocked_ips_path,
        blocked_ips,
        qkey_registry,
    }
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
    let valid = ["verbose", "normal", "minimal", "no-log"];
    if !valid.contains(&mode) {
        return AdminResponse::error(format!(
            "Invalid logging mode '{}'. Valid: {:?}",
            mode, valid
        ));
    }
    *logging_mode.write() = mode.to_string();
    apply_logging_mode(mode, log_buffer);
    if let Err(e) = persist_logging_mode(config_path, mode) {
        if mode != "no-log" {
            log::warn!("logging config write failed: {}", e);
        }
    }
    AdminResponse::ok_with_message(format!("Logging mode set to '{}'", mode))
}

/// Server runtime handle.
pub struct ServerRuntime {
    /// Engine configuration
    engine_config: EngineConfig,
    /// Server-specific configuration
    server_config: ServerConfig,
    /// Memory pool
    pool: Arc<MemoryPool>,
    /// Embedded host resources
    host_resources: Option<ServerHostResources>,
    /// Shared server domain owner
    domain: SharedServerDomain,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Server state
    state: ServerState,
    /// Statistics
    stats: Arc<ServerStats>,
    /// Optional standalone live UDP runtime state.
    live: Option<ServerLiveRuntime>,
}

/// Server state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub connections_rejected: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerTrafficSnapshot {
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub connections_rejected: u64,
}

pub enum AdminAction {
    Kick(String),
    Reload,
    Shutdown,
}

#[derive(Clone)]
struct SharedServerDomain {
    sessions: Arc<RwLock<SessionManager>>,
    ip_pool: Arc<parking_lot::Mutex<IpPool>>,
    connection_limiter: Arc<parking_lot::Mutex<ConnectionLimiter>>,
    #[cfg(feature = "rate_limiter")]
    packet_rate_limiter: Arc<parking_lot::Mutex<PacketRateLimiterDomain>>,
    max_clients: usize,
    client_timeout_secs: u64,
}

#[cfg(feature = "rate_limiter")]
struct PacketRateLimiterDomain {
    limiter: RateLimiter,
    last_prune: Instant,
}

struct ServerHostResources {
    tun: TunInterface,
    routing: Option<RoutingManager>,
}

impl ServerHostResources {
    fn start(
        engine_config: &EngineConfig,
        server_config: &ServerConfig,
        pool: Arc<MemoryPool>,
    ) -> Result<Self, EngineError> {
        let tun_config = TunConfig {
            name: Some("qfserver0".to_string()),
            ip: engine_config.interface.tun_ip.or(Some(server_config.server_ip.into())),
            netmask: engine_config
                .interface
                .tun_netmask
                .or(Some(server_config.server_netmask.into())),
            mtu: engine_config.interface.tun_mtu,
            zero_copy: engine_config.interface.zero_copy,
        };

        let tun = open_server_tun(tun_config, pool).map_err(EngineError::Tun)?;
        log::info!("Server TUN interface opened: {}", tun.name());

        #[cfg(target_os = "linux")]
        let routing = {
            let routing = RoutingManager::new(
                "qfserver0".to_string(),
                server_config.server_ip,
                server_config.server_netmask,
                server_config.wan_interface.clone(),
            );

            if let Err(e) = routing.setup() {
                log::warn!("Failed to setup routing: {:?}", e);
                None
            } else {
                Some(routing)
            }
        };

        #[cfg(not(target_os = "linux"))]
        let routing = None;

        Ok(Self { tun, routing })
    }

    fn teardown(self) {
        if let Some(routing) = self.routing {
            if let Err(e) = routing.teardown() {
                log::warn!("Failed to teardown routing: {:?}", e);
            }
        }
        log::info!("Closing server TUN: {}", self.tun.name());
        drop(self.tun);
    }
}

impl SharedServerDomain {
    fn new(server_config: &ServerConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new(server_config.max_clients))),
            ip_pool: Arc::new(parking_lot::Mutex::new(IpPool::new(
                server_config.ip_pool_start,
                server_config.ip_pool_end,
            ))),
            connection_limiter: Arc::new(parking_lot::Mutex::new(ConnectionLimiter::new(
                DEFAULT_MAX_CONNECTIONS_PER_IP,
            ))),
            #[cfg(feature = "rate_limiter")]
            packet_rate_limiter: Arc::new(parking_lot::Mutex::new(PacketRateLimiterDomain {
                limiter: RateLimiter::new(load_rate_limit_config_from_env()),
                last_prune: Instant::now(),
            })),
            max_clients: server_config.max_clients,
            client_timeout_secs: server_config.client_timeout_secs,
        }
    }

    fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>, Ipv4Addr), AcceptError> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut limiter = self.connection_limiter.lock();
        accept_session_in_domain(
            &mut sessions,
            &mut pool,
            &mut limiter,
            remote_addr,
            self.max_clients,
            self.client_timeout_secs,
        )
    }

    fn remove(&self, session_id: SessionId) -> Option<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut limiter = self.connection_limiter.lock();
        remove_session_from_domain(&mut sessions, &mut pool, &mut limiter, session_id)
    }

    fn reap_expired(&self) -> Vec<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut limiter = self.connection_limiter.lock();
        reap_expired_sessions_from_domain(&mut sessions, &mut pool, &mut limiter)
    }

    #[cfg(feature = "rate_limiter")]
    fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        let limiter = self.packet_rate_limiter.lock();
        let allowed_packet = limiter.limiter.check_packet_ip(from.ip());
        let allowed_bytes = allowed_packet && limiter.limiter.check_bytes_ip(from.ip(), len as u64);
        allowed_packet && allowed_bytes
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self) {
        let mut limiter = self.packet_rate_limiter.lock();
        if limiter.last_prune.elapsed() >= Duration::from_secs(30) {
            limiter.limiter.prune_idle(Duration::from_secs(120));
            limiter.last_prune = Instant::now();
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn remove_rate_limited_ip(&self, ip: IpAddr) {
        self.packet_rate_limiter.lock().limiter.remove_ip(ip);
    }

    fn traffic_snapshot(&self) -> ServerTrafficSnapshot {
        let sessions = self.sessions.read();
        let mut snapshot = ServerTrafficSnapshot {
            active_connections: sessions.len() as u64,
            ..ServerTrafficSnapshot::default()
        };
        for (_, session) in sessions.iter() {
            let stats = session.stats();
            snapshot.bytes_in =
                snapshot.bytes_in.saturating_add(stats.bytes_received.load(Ordering::Relaxed));
            snapshot.bytes_out =
                snapshot.bytes_out.saturating_add(stats.bytes_sent.load(Ordering::Relaxed));
            snapshot.packets_in =
                snapshot.packets_in.saturating_add(stats.packets_received.load(Ordering::Relaxed));
            snapshot.packets_out =
                snapshot.packets_out.saturating_add(stats.packets_sent.load(Ordering::Relaxed));
        }
        snapshot
    }

    fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.read().all_session_ids()
    }

    fn session_stats(&self, session_id: SessionId) -> Option<Arc<SessionStats>> {
        self.sessions.read().get(session_id).map(|session| Arc::clone(session.stats()))
    }
}

#[derive(Clone)]
pub struct ServerAdminCore {
    metrics: Arc<Metrics>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    actions: mpsc::UnboundedSender<AdminAction>,
    listen_addr: String,
    front_domain: Vec<String>,
    qkeys: Arc<std::sync::Mutex<QKeyRegistry>>,
}

impl ServerAdminCore {
    pub fn new(
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<
            std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>,
        >,
        actions: mpsc::UnboundedSender<AdminAction>,
        listen_addr: String,
        front_domain: Vec<String>,
        qkeys: Arc<std::sync::Mutex<QKeyRegistry>>,
    ) -> Self {
        Self { metrics, blocked_ips, client_snapshots, actions, listen_addr, front_domain, qkeys }
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<String>>> {
        &self.blocked_ips
    }

    pub fn listen_addr(&self) -> &str {
        self.listen_addr.as_str()
    }

    pub fn qkeys(&self) -> &Arc<std::sync::Mutex<QKeyRegistry>> {
        &self.qkeys
    }

    pub fn base_status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.metrics.uptime_secs(),
            "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
            "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
            "connections_accepted": self.metrics.connections_accepted.load(Ordering::Relaxed),
            "connections_rejected": self.metrics.connections_rejected.load(Ordering::Relaxed),
            "auth_failed": self.metrics.auth_failed.load(Ordering::Relaxed),
            "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
        })
    }

    pub fn list_clients(&self) -> Vec<ClientInfo> {
        let guard = match self.client_snapshots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        snapshots_to_client_info(&guard, Instant::now())
    }

    pub fn dispatch_action(&self, action: AdminAction, ok_message: String) -> AdminResponse {
        match self.actions.send(action) {
            Ok(()) => AdminResponse::ok_with_message(ok_message),
            Err(_) => AdminResponse::error("Admin action channel unavailable"),
        }
    }

    pub fn kick_client(&self, id: &str) -> AdminResponse {
        self.dispatch_action(
            AdminAction::Kick(id.to_string()),
            format!("Client {} scheduled for disconnect", id),
        )
    }

    pub fn reload(&self) -> AdminResponse {
        self.dispatch_action(AdminAction::Reload, "Configuration reload scheduled".to_string())
    }

    pub fn shutdown(&self) -> AdminResponse {
        self.dispatch_action(AdminAction::Shutdown, "Shutdown scheduled".to_string())
    }

    pub fn request_reload_after_write(&self) -> Result<(), &'static str> {
        self.actions.send(AdminAction::Reload).map_err(|_| "admin action channel unavailable")
    }

    pub fn block_ip(&self, ip: &str) -> AdminResponse {
        self.blocked_ips.write().insert(ip.to_string());
        AdminResponse::ok_with_message(format!("IP {} blocked", ip))
    }

    pub fn unblock_ip(&self, ip: &str) -> AdminResponse {
        if self.blocked_ips.write().remove(ip) {
            AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
        } else {
            AdminResponse::error(format!("IP {} was not blocked", ip))
        }
    }

    pub fn list_blocked_ips(&self) -> AdminResponse {
        let mut ips: Vec<String> = self.blocked_ips.read().iter().cloned().collect();
        ips.sort();
        AdminResponse::ok_with_data(serde_json::json!({ "ips": ips }))
    }

    pub fn issue_unix_qkey(&self) -> String {
        let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        match issue_unix_admin_qkey(&mut registry, &self.listen_addr, &self.front_domain) {
            Ok(qkey) => qkey,
            Err(e) => {
                log::warn!("QKey issuance failed: {}", e);
                String::new()
            }
        }
    }

    pub fn issue_http_qkey(&self, req: &IssueQKeyRequest) -> AdminResponse {
        let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        let issued = match issue_http_admin_qkey(
            &mut registry,
            &self.listen_addr,
            &self.front_domain,
            req,
        ) {
            Ok(issued) => issued,
            Err(e) => return AdminResponse::error(e),
        };
        AdminResponse::ok_with_data(serde_json::json!({
            "qkey": issued.qkey,
            "created_at": issued.created_at,
            "expires_at": issued.expires_at,
        }))
    }
}

pub struct ServerAdminHttpRuntimeHandler {
    core: ServerAdminCore,
    blocked_ips_path: Option<std::path::PathBuf>,
    config_path: Option<std::path::PathBuf>,
    logging_mode: Arc<parking_lot::RwLock<String>>,
    log_buffer: Arc<crate::implementations::server::admin_logs::AdminLogBuffer>,
}

impl ServerAdminHttpRuntimeHandler {
    pub fn new(
        core: ServerAdminCore,
        blocked_ips_path: Option<std::path::PathBuf>,
        config_path: Option<std::path::PathBuf>,
        logging_mode: Arc<parking_lot::RwLock<String>>,
        log_buffer: Arc<crate::implementations::server::admin_logs::AdminLogBuffer>,
    ) -> Self {
        Self { core, blocked_ips_path, config_path, logging_mode, log_buffer }
    }
}

#[cfg(unix)]
pub struct ServerAdminRuntimeHandler {
    core: ServerAdminCore,
}

#[cfg(unix)]
impl ServerAdminRuntimeHandler {
    pub fn new(core: ServerAdminCore) -> Self {
        Self { core }
    }
}

#[cfg(unix)]
impl AdminHandler for ServerAdminRuntimeHandler {
    fn handle_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(self.core.base_status_json())
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        self.core.list_clients()
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        self.core.kick_client(id)
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        self.core.block_ip(ip)
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        self.core.unblock_ip(ip)
    }

    fn handle_reload(&self) -> AdminResponse {
        self.core.reload()
    }

    fn handle_qkey(&self) -> String {
        self.core.issue_unix_qkey()
    }

    fn handle_shutdown(&self) -> AdminResponse {
        self.core.shutdown()
    }
}

impl AdminHttpHandler for ServerAdminHttpRuntimeHandler {
    fn handle_status(&self) -> AdminResponse {
        let mut data = self.core.base_status_json();
        data["listen"] = serde_json::Value::String(self.core.listen_addr().to_string());
        data["config_writable"] = serde_json::Value::Bool(self.config_path.is_some());
        AdminResponse::ok_with_data(data)
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        self.core.list_clients()
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        self.core.kick_client(id)
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        let response = self.core.block_ip(ip);
        if let Some(path) = self.blocked_ips_path.as_ref() {
            if let Err(e) = persist_blocked_ips(path, &self.core.blocked_ips().read()) {
                log::warn!("blocked IPs persist failed: {}", e);
            }
        }
        response
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        let response = self.core.unblock_ip(ip);
        if response.success {
            if let Some(path) = self.blocked_ips_path.as_ref() {
                if let Err(e) = persist_blocked_ips(path, &self.core.blocked_ips().read()) {
                    log::warn!("blocked IPs persist failed: {}", e);
                }
            }
        }
        response
    }

    fn handle_list_blocked_ips(&self) -> AdminResponse {
        self.core.list_blocked_ips()
    }

    fn handle_reload(&self) -> AdminResponse {
        self.core.reload()
    }

    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse {
        self.core.issue_http_qkey(&req)
    }

    fn handle_list_qkeys(&self) -> AdminResponse {
        let mut registry = self.core.qkeys().lock().unwrap_or_else(|e| e.into_inner());
        AdminResponse::ok_with_data(serde_json::json!({ "keys": registry.list() }))
    }

    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse {
        let mut registry = self.core.qkeys().lock().unwrap_or_else(|e| e.into_inner());
        if registry.revoke(id) {
            AdminResponse::ok_with_message("QKey revoked")
        } else {
            AdminResponse::error("QKey not found")
        }
    }

    fn handle_shutdown(&self) -> AdminResponse {
        self.core.dispatch_action(AdminAction::Shutdown, "Shutdown scheduled".to_string())
    }

    fn handle_read_config(&self) -> AdminResponse {
        read_runtime_config(self.config_path.as_deref())
    }

    fn handle_write_config(&self, contents: &str) -> AdminResponse {
        write_runtime_config(&self.core, self.config_path.as_deref(), contents)
    }

    fn handle_metrics_text(&self) -> String {
        self.core.metrics().export()
    }

    fn handle_metrics_json(&self) -> AdminResponse {
        use std::sync::atomic::Ordering;
        AdminResponse::ok_with_data(serde_json::json!({
            "metrics": {
                "quicfuscate_up": 1,
                "quicfuscate_uptime_seconds": self.core.metrics().uptime_secs(),
                "quicfuscate_clients_active": self.core.metrics().clients_active.load(Ordering::Relaxed),
                "quicfuscate_clients_total": self.core.metrics().clients_total.load(Ordering::Relaxed),
                "quicfuscate_connections_accepted": self.core.metrics().connections_accepted.load(Ordering::Relaxed),
                "quicfuscate_connections_rejected": self.core.metrics().connections_rejected.load(Ordering::Relaxed),
                "quicfuscate_bytes_in_total": self.core.metrics().bytes_in.load(Ordering::Relaxed),
                "quicfuscate_bytes_out_total": self.core.metrics().bytes_out.load(Ordering::Relaxed),
                "quicfuscate_packets_in_total": self.core.metrics().packets_in.load(Ordering::Relaxed),
                "quicfuscate_packets_out_total": self.core.metrics().packets_out.load(Ordering::Relaxed),
                "quicfuscate_stealth_http3_active": self.core.metrics().stealth_http3_active.load(Ordering::Relaxed),
                "quicfuscate_stealth_tls13_active": self.core.metrics().stealth_tls13_active.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_encoded": self.core.metrics().fec_packets_encoded.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_decoded": self.core.metrics().fec_packets_decoded.load(Ordering::Relaxed),
                "quicfuscate_fec_packets_recovered": self.core.metrics().fec_packets_recovered.load(Ordering::Relaxed),
                "quicfuscate_auth_failed_total": self.core.metrics().auth_failed.load(Ordering::Relaxed),
                "quicfuscate_rate_limited_total": self.core.metrics().rate_limited.load(Ordering::Relaxed),
            }
        }))
    }

    fn handle_get_logging_config(&self) -> AdminResponse {
        read_logging_mode(&self.logging_mode)
    }

    fn handle_set_logging_config(&self, mode: &str) -> AdminResponse {
        write_logging_mode(self.config_path.as_deref(), &self.logging_mode, &self.log_buffer, mode)
    }

    fn handle_get_logs(&self, cursor: u64) -> AdminResponse {
        let mode = self.logging_mode.read();
        let mode_str = mode.as_str();
        if mode_str == "no-log" {
            return AdminResponse::ok_with_data(serde_json::json!({
                "lines": [],
                "cursor": 0,
                "mode": "no-log"
            }));
        }
        let (lines, new_cursor) = self.log_buffer.since(cursor, mode_str, 600);
        AdminResponse::ok_with_data(serde_json::json!({
            "lines": lines.iter().map(|l| serde_json::json!({
                "ts": l.ts,
                "level": l.level,
                "msg": l.msg,
            })).collect::<Vec<_>>(),
            "cursor": new_cursor,
            "mode": mode_str
        }))
    }

    fn handle_clear_logs(&self) -> AdminResponse {
        self.log_buffer.clear();
        AdminResponse::ok_with_message("Logs cleared")
    }
}

pub fn load_server_identity(
    config: &mut crate::transport::Config,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> std::io::Result<()> {
    let cert_str = cert_path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid certificate path")
    })?;
    if let Err(e) = config.load_cert_chain_from_pem_file(cert_str) {
        log::error!("Failed to load server cert {}: {}", cert_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid certificate path",
        ));
    }

    let key_str = key_path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid private key path")
    })?;
    if let Err(e) = config.load_priv_key_from_pem_file(key_str) {
        log::error!("Failed to load server key {}: {}", key_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid private key path",
        ));
    }

    crate::qftls::set_tls_cert_key_paths(cert_str, key_str);
    Ok(())
}

pub fn start_runtime_profile_rotation(
    stealth_config: Arc<std::sync::Mutex<StealthConfig>>,
    profiles: Vec<FingerprintProfile>,
    profile_interval_secs: u64,
) {
    if profile_interval_secs == 0 || profiles.len() <= 1 {
        return;
    }

    tokio::task::spawn(async move {
        let mut idx = 0usize;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(profile_interval_secs)).await;
            idx = (idx + 1) % profiles.len();
            let mut guard = match stealth_config.lock() {
                Ok(g) => g,
                Err(p) => {
                    log::warn!("stealth_config mutex poisoned; recovering inner state");
                    p.into_inner()
                }
            };
            apply_runtime_profile_identity(&mut guard, profiles[idx].browser, profiles[idx].os);
        }
    });
}

pub fn start_standalone_metrics_service(runtime: &mut ServerRuntime, port: u16) {
    let server = self::metrics::MetricsServer::new(port, runtime.standalone_metrics());
    runtime.register_metrics_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown is handled via the
    // registered shutdown signal above. Errors are logged inside the task.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("metrics server failed: {}", e);
        }
    });
}

#[cfg(unix)]
pub fn start_standalone_admin_service(
    runtime: &mut ServerRuntime,
    path: std::path::PathBuf,
    core: ServerAdminCore,
) {
    let handler = ServerAdminRuntimeHandler::new(core);
    let server = AdminServer::new(path, Arc::new(handler));
    runtime.register_admin_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown via registered signal.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("admin server failed: {}", e);
        }
    });
}

pub(crate) fn start_standalone_admin_web_service(
    runtime: &mut ServerRuntime,
    addr: std::net::SocketAddr,
    web_root: std::path::PathBuf,
    auth: AdminAuth,
    auth_path: std::path::PathBuf,
    handler: ServerAdminHttpRuntimeHandler,
) {
    let server =
        AdminHttpServer::new(addr, web_root, Some(auth), Some(auth_path), Arc::new(handler));
    runtime.register_admin_web_shutdown(server.shutdown_signal());
    // JoinHandle intentionally not stored: graceful shutdown via registered signal.
    tokio::spawn(async move {
        if let Err(e) = server.run().await {
            log::warn!("admin web server failed: {}", e);
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn start_configured_standalone_admin_web_service(
    runtime: &mut ServerRuntime,
    addr: std::net::SocketAddr,
    web_root: std::path::PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    config_path: Option<&std::path::Path>,
    blocked_ips_path: Option<std::path::PathBuf>,
    initial_logging_mode: String,
    admin_core: ServerAdminCore,
    admin_log_buffer: Arc<self::admin_logs::AdminLogBuffer>,
) -> std::io::Result<()> {
    let auth = resolve_admin_web_auth(admin_web_user, admin_web_password)?;
    let logging_mode = Arc::new(parking_lot::RwLock::new(initial_logging_mode));
    let handler = ServerAdminHttpRuntimeHandler::new(
        admin_core,
        blocked_ips_path,
        config_path.map(std::path::Path::to_path_buf),
        logging_mode,
        admin_log_buffer,
    );
    let auth_path = resolve_admin_auth_store_path(config_path);
    start_standalone_admin_web_service(runtime, addr, web_root, auth, auth_path, handler);
    Ok(())
}

pub fn try_rebind_live_client_by_dcid(
    clients: &mut std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    from: SocketAddr,
    packet: &[u8],
    accept_loop: &AcceptLoop,
) -> Option<SocketAddr> {
    let migrated_from =
        crate::transport::packet::parse_header(packet, 0).ok().and_then(|(hdr, _)| {
            clients.iter().find_map(|(addr, conn)| {
                if conn.conn.source_id().as_ref() == hdr.dcid.as_slice() {
                    Some(*addr)
                } else {
                    None
                }
            })
        });

    let old_addr = migrated_from?;
    if old_addr == from {
        return None;
    }

    if let Some(conn) = clients.remove(&old_addr) {
        clients.insert(from, conn);
    }
    accept_loop.record_migration(old_addr, from);
    crate::telemetry::QKEY_PATH_REBIND_TOTAL.inc();
    Some(old_addr)
}

pub fn reconcile_live_clients(
    clients: &mut std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    qkey_auth: &mut std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    accept_loop: &AcceptLoop,
    metrics: &Metrics,
) -> Vec<SocketAddr> {
    let closed_addrs: Vec<_> =
        clients.iter().filter_map(|(addr, conn)| conn.conn.is_closed().then_some(*addr)).collect();
    for addr in &closed_addrs {
        accept_loop.record_closed(*addr);
    }
    clients.retain(|_, conn| !conn.conn.is_closed());
    qkey_auth.retain(|conn_id, _| {
        clients.values().any(|conn| conn.conn.source_id().as_ref() == conn_id.as_slice())
    });
    metrics.clients_active.store(clients.len() as u64, Ordering::Relaxed);
    closed_addrs
}

pub fn record_qkey_auth_failure(metrics: &Metrics) {
    metrics.record_auth_failure();
}

pub fn record_qkey_auth_rejection(metrics: &Metrics) {
    metrics.record_connection_rejected();
    record_qkey_auth_failure(metrics);
}

pub struct LiveInitialAuthContext {
    pub odcid: crate::transport::ConnectionId,
    pub qkey_record: Option<QKeyRecord>,
    pub pending_qkey_auth: Option<QKeyAuthState>,
}

pub fn parse_live_server_initial_auth(
    packet: &[u8],
    qkey_registry: &std::sync::Mutex<QKeyRegistry>,
    metrics: &Metrics,
) -> Option<LiveInitialAuthContext> {
    let (mut initial_hdr, _) = match crate::transport::packet::parse_header(packet, 0) {
        Ok(value) => {
            eprintln!("[DEBUG] parse_header OK: ty={:?} dcid_len={}", value.0.ty, value.0.dcid.len());
            value
        }
        Err(e) => {
            eprintln!("[DEBUG] parse_header FAILED: {:?}", e);
            metrics.record_connection_rejected();
            return None;
        }
    };
    if initial_hdr.ty != crate::transport::PacketType::Initial {
        eprintln!("[DEBUG] packet type {:?} != Initial", initial_hdr.ty);
        metrics.record_connection_rejected();
        return None;
    }

    let odcid = crate::transport::ConnectionId::from_vec(std::mem::take(&mut initial_hdr.dcid));
    let initial_token = initial_hdr.token.take();
    let require_qkey = require_qkey_for_new_clients();
    eprintln!("[DEBUG] require_qkey={} token_len={}", require_qkey, initial_token.as_ref().map(|t| t.len()).unwrap_or(0));
    let mut qkey_record = None;
    let mut pending_qkey_auth = None;

    if require_qkey {
        let token = match initial_token {
            Some(token) if !token.is_empty() => token,
            _ => {
                record_qkey_auth_rejection(metrics);
                return None;
            }
        };
        let record = {
            let mut registry = qkey_registry.lock().unwrap_or_else(|error| error.into_inner());
            registry.lookup_initial_id_token(&token)
        };
        let Some(record) = record else {
            record_qkey_auth_rejection(metrics);
            return None;
        };
        pending_qkey_auth = Some(QKeyAuthState {
            expected_token_sha256: record.token_sha256.clone(),
            authed: false,
            connected_at: Instant::now(),
        });
        qkey_record = Some(record);
    }

    Some(LiveInitialAuthContext { odcid, qkey_record, pending_qkey_auth })
}

pub fn apply_qkey_policy_overrides(
    record: &QKeyRecord,
    stealth_config: &mut crate::stealth::StealthConfig,
    fec_config: &mut crate::fec::FecConfig,
) {
    if let Some(mode_raw) = record.stealth.as_deref() {
        let mode = mode_raw.trim().to_ascii_lowercase();
        let mapped = match mode.as_str() {
            "off" => Some(crate::stealth::StealthMode::Off),
            "performance" => Some(crate::stealth::StealthMode::Performance),
            "stealth" => Some(crate::stealth::StealthMode::Stealth),
            "anti-dpi" | "antidpi" | "max" => Some(crate::stealth::StealthMode::AntiDpi),
            "manual" => Some(crate::stealth::StealthMode::Manual),
            "auto" | "intelligent" => Some(crate::stealth::StealthMode::Intelligent),
            _ => None,
        };
        if let Some(mapped) = mapped {
            stealth_config.mode = mapped;
        }
    }
    if let Some(fec_raw) = record.fec.as_deref() {
        match normalize_qkey_fec(Some(fec_raw)) {
            Ok("off") => {
                fec_config.apply_engine_mode(crate::engine::FecMode::Off);
            }
            Ok("auto") => {
                fec_config.apply_engine_mode(crate::engine::FecMode::Auto);
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

pub fn create_live_server_connection(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    transport_config: &mut crate::transport::Config,
    stealth_config: crate::stealth::StealthConfig,
    fec_config: crate::fec::FecConfig,
    opt_params: crate::optimize::OptimizeConfig,
    odcid: &crate::transport::ConnectionId,
) -> Result<QuicFuscateConnection, String> {
    let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut scid_bytes);
    let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);
    QuicFuscateConnection::new_server(
        &scid,
        Some(odcid),
        local_addr,
        remote_addr,
        transport_config,
        stealth_config,
        fec_config,
        opt_params,
    )
}

pub enum QKeyHeaderAuthOutcome {
    Unchanged,
    Authenticated,
    Reject(&'static [u8]),
}

pub fn evaluate_qkey_http3_headers(
    headers: &[crate::transport::h3::Header],
    expected_token_sha256: Option<&str>,
    already_authed: bool,
) -> QKeyHeaderAuthOutcome {
    let Some(expected) = expected_token_sha256 else {
        return QKeyHeaderAuthOutcome::Unchanged;
    };
    if already_authed {
        return QKeyHeaderAuthOutcome::Authenticated;
    }

    let mut provided: Option<&[u8]> = None;
    for header in headers {
        if header.name().eq_ignore_ascii_case(b"x-qf-auth") {
            provided = Some(header.value());
            break;
        }
    }

    let Some(provided) = provided else {
        return QKeyHeaderAuthOutcome::Reject(b"missing_qkey_auth");
    };
    let provided = match std::str::from_utf8(provided) {
        Ok(value) => value.trim(),
        Err(_) => return QKeyHeaderAuthOutcome::Reject(b"invalid_qkey_auth"),
    };
    if crate::implementations::server::qkey_registry::token_matches_hash(provided, expected.trim())
    {
        QKeyHeaderAuthOutcome::Authenticated
    } else {
        QKeyHeaderAuthOutcome::Reject(b"invalid_qkey_auth")
    }
}

pub fn close_live_client_for_qkey_auth_failure(
    conn: &mut QuicFuscateConnection,
    metrics: &Metrics,
    remote_addr: SocketAddr,
    reason: &'static [u8],
) {
    record_qkey_auth_rejection(metrics);
    if let Err(error) = conn.conn.close(true, 0x0, reason) {
        log::warn!("Client close after QKey auth failure failed for {}: {:?}", remote_addr, error);
    }
}

fn record_live_snapshot_bytes_out(
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    addr: SocketAddr,
    bytes_out: u64,
    session_id: Option<SessionId>,
) {
    if bytes_out == 0 {
        return;
    }
    if let Ok(mut guard) = client_snapshots.lock() {
        if let Some(snapshot) = guard.get_mut(&addr) {
            if let Some(session_id) = session_id {
                snapshot.set_session_id(session_id);
            }
            snapshot.record_bytes_out(bytes_out);
        }
    }
}

fn record_live_snapshot_bytes_in(
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    addr: SocketAddr,
    bytes_in: u64,
    stealth_mode: String,
    session_id: Option<SessionId>,
) {
    if bytes_in == 0 {
        return;
    }
    let mut snapshots_guard = match client_snapshots.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    let snap =
        snapshots_guard.entry(addr).or_insert_with(|| ClientSnapshot::new(stealth_mode.clone()));
    if let Some(session_id) = session_id {
        snap.set_session_id(session_id);
    }
    snap.record_bytes_in(bytes_in, stealth_mode);
}

pub struct LiveClientDatagramResult {
    pub auth_result: Option<(Vec<u8>, bool)>,
    pub remove_auth_conn_id: Option<Vec<u8>>,
}

#[cfg(unix)]
pub async fn send_live_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use tokio::io::Interest;

    // Use `async_io` to avoid edge-triggered busy-loop (same fix as recv).
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::WRITABLE, || {
            let zc = ZeroCopyBuffer::new(&[data]);
            let rc = zc.send_to(fd, *addr);
            if rc >= 0 {
                if rc as usize == data.len() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "partial datagram send_to",
                    ))
                }
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
        .await
}

#[cfg(not(unix))]
pub async fn send_live_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    use tokio::io::Interest;

    loop {
        socket.ready(Interest::WRITABLE).await?;
        match socket.try_send_to(data, addr) {
            Ok(len) if len == data.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send_to",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn flush_live_server_outgoing(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    conn: &mut QuicFuscateConnection,
    out: &mut [u8],
    metrics: &Metrics,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    session_stats: Option<Arc<SessionStats>>,
    session_id: Option<SessionId>,
) -> std::io::Result<(u64, u64)> {
    let mut bytes_sent = 0u64;
    let mut packets_sent = 0u64;

    // Collect all outgoing packets from this connection before sending.
    // This lets us submit them as a single io_uring batch (one io_uring_enter
    // syscall instead of one sendmsg per packet).
    let mut staging: Vec<Vec<u8>> = Vec::new();
    loop {
        match conn.send(out) {
            Ok(len) if len > 0 => {
                crate::telemetry::BYTES_SENT.inc_by(len as u64);
                metrics.record_egress_datagram(len);
                if let Some(stats) = session_stats.as_ref() {
                    stats.record_sent(len as u64);
                }
                bytes_sent = bytes_sent.saturating_add(len as u64);
                packets_sent = packets_sent.saturating_add(1);
                staging.push(out[..len].to_vec());
            }
            Ok(_) | Err(ConnectionError::Done) => break,
            Err(e) => {
                log::error!("Send failed to {}: {:?}", addr, e);
                break;
            }
        }
    }

    if !staging.is_empty() {
        // Try io_uring batch on Linux when the feature is compiled in.
        // Full success returns early; partial success falls through for the unsent tail.
        let already_sent = {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                use std::os::unix::io::AsRawFd;
                let fd = socket.as_raw_fd();
                let packets: Vec<(SocketAddr, &[u8])> =
                    staging.iter().map(|p| (addr, p.as_slice())).collect();
                crate::optimize::uring_batch::server_send_batch_to(fd, &packets)
                    .unwrap_or(0)
                    .min(staging.len())
            }

            #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
            {
                0usize
            }
        };
        if already_sent == staging.len() {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
                return Ok((bytes_sent, packets_sent));
            }
        }
        // io_uring unavailable, failed, or partially sent: finish via individual async calls.
        for p in staging.iter().skip(already_sent) {
            send_live_datagram_to(socket, &addr, p).await?;
        }
    }

    record_live_snapshot_bytes_out(client_snapshots, addr, bytes_sent, session_id);
    Ok((bytes_sent, packets_sent))
}

#[allow(clippy::too_many_arguments)]
pub async fn process_live_server_client_datagram(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    runtime_client: LiveClientRuntime<'_>,
    packet: &[u8],
    out: &mut [u8],
    metrics: &Metrics,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    server_tun: Option<&Arc<TunInterface>>,
    tun_enable: bool,
) -> std::io::Result<LiveClientDatagramResult> {
    use std::cell::Cell;

    let LiveClientRuntime {
        connection: conn, conn_id, qkey_auth, session_stats, session_id, ..
    } = runtime_client;
    record_live_snapshot_bytes_in(
        client_snapshots,
        addr,
        packet.len() as u64,
        format!("{:?}", conn.stealth_mode()),
        session_id,
    );
    if let Some(stats) = session_stats.as_ref() {
        stats.record_received(packet.len() as u64);
    }

    if let Err(error) = conn.recv(packet) {
        log::error!("QUIC recv failed for {}: {:?}", addr, error);
    } else {
        eprintln!("[DEBUG] server recv OK from {} len={}", addr, packet.len());
    }

    let require_auth = qkey_auth.is_some();
    let expected_token_sha256 = qkey_auth.as_ref().map(|state| state.expected_token_sha256.clone());
    let authed = Cell::new(qkey_auth.as_ref().map(|state| state.authed).unwrap_or(true));
    let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

    if let Err(error) = conn.poll_http3_with_headers(
        |_sid, headers| match evaluate_qkey_http3_headers(
            headers,
            expected_token_sha256.as_deref(),
            authed.get(),
        ) {
            QKeyHeaderAuthOutcome::Unchanged => {}
            QKeyHeaderAuthOutcome::Authenticated => {
                authed.set(true);
            }
            QKeyHeaderAuthOutcome::Reject(reason) => {
                should_close.set(Some(reason));
            }
        },
        |_sid, data| {
            if require_auth && !authed.get() {
                return;
            }
            if tun_enable {
                if let Some(tun) = server_tun {
                    if let Err(error) = tun.write(data) {
                        log::warn!("Server TUN write failed: {:?}", error);
                    }
                }
            }
        },
    ) {
        log::warn!("HTTP/3 header/body poll failed for {}: {:?}", addr, error);
    }

    // Also drain QUIC datagrams from the client and forward to TUN.
    // This handles the IoDriver client path (dgram_send → server dgram_recv → TUN write).
    if tun_enable {
        if let Some(tun) = server_tun {
            let mut dgram_buf = [0u8; 65535];
            loop {
                match conn.conn.dgram_recv(&mut dgram_buf) {
                    Ok(n) if n > 0 => {
                        if let Err(error) = tun.write(&dgram_buf[..n]) {
                            log::warn!("Server TUN write (dgram) failed: {:?}", error);
                        }
                    }
                    Ok(_) => break,
                    Err(crate::error::ConnectionError::Done) => break,
                    Err(_) => break,
                }
            }
        }
    }

    let auth_result = require_auth.then(|| (conn_id.clone(), authed.get()));
    let mut remove_auth_conn_id = None;
    if let Some(reason) = should_close.get() {
        close_live_client_for_qkey_auth_failure(conn, metrics, addr, reason);
        remove_auth_conn_id = Some(conn_id.clone());
    }

    let flush_result = flush_live_server_outgoing(
        socket,
        addr,
        conn,
        out,
        metrics,
        client_snapshots,
        session_stats,
        session_id,
    )
    .await?;
    eprintln!("[DEBUG] flush_live_server_outgoing: bytes_sent={} packets_sent={}", flush_result.0, flush_result.1);

    Ok(LiveClientDatagramResult { auth_result, remove_auth_conn_id })
}

pub struct LiveServerState {
    clients: std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    qkey_auth: std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    domain: LiveServerDomain,
}

pub struct LiveClientInit {
    pub connection: QuicFuscateConnection,
    pub pending_qkey_auth: Option<QKeyAuthState>,
}

pub struct LiveClientBuildRequest<'a> {
    pub packet: &'a [u8],
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub qkey_registry: &'a std::sync::Mutex<QKeyRegistry>,
    pub metrics: &'a Metrics,
    pub stealth_config: &'a Arc<std::sync::Mutex<StealthConfig>>,
    pub fec_cfg_shared: &'a Arc<std::sync::Mutex<FecConfig>>,
    pub opt_params_shared: &'a Arc<std::sync::Mutex<OptimizeConfig>>,
    pub transport_config: &'a mut crate::transport::Config,
    pub profile: BrowserProfile,
    pub os: OsProfile,
    pub disable_doh: bool,
    pub doh_provider: &'a str,
    pub disable_fronting: bool,
    pub front_domain: &'a [String],
    pub disable_http3: bool,
}

pub fn build_live_server_client_init(
    request: LiveClientBuildRequest<'_>,
) -> Option<LiveClientInit> {
    let initial_ctx =
        match parse_live_server_initial_auth(request.packet, request.qkey_registry, request.metrics) {
            Some(ctx) => ctx,
            None => {
                eprintln!("[DEBUG] parse_live_server_initial_auth returned None for {}", request.remote_addr);
                return None;
            }
        };
    log::info!("New client connected: {}", request.remote_addr);

    let cfg = match request.stealth_config.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => {
            log::warn!("stealth_config mutex poisoned; recovering inner state");
            poisoned.into_inner().clone()
        }
    };
    let mut conn_stealth_cfg = cfg;
    let mut conn_fec_cfg = match request.fec_cfg_shared.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    if let Some(ref record) = initial_ctx.qkey_record {
        apply_qkey_policy_overrides(record, &mut conn_stealth_cfg, &mut conn_fec_cfg);
        apply_runtime_stealth_overrides(
            &mut conn_stealth_cfg,
            request.profile,
            request.os,
            request.disable_doh,
            request.doh_provider,
            request.disable_fronting,
            request.front_domain,
            request.disable_http3,
        );
    }
    let opt_params = match request.opt_params_shared.lock() {
        Ok(guard) => *guard,
        Err(poisoned) => *poisoned.into_inner(),
    };
    match create_live_server_connection(
        request.local_addr,
        request.remote_addr,
        request.transport_config,
        conn_stealth_cfg,
        conn_fec_cfg,
        opt_params,
        &initial_ctx.odcid,
    ) {
        Ok(connection) => {
            Some(LiveClientInit { connection, pending_qkey_auth: initial_ctx.pending_qkey_auth })
        }
        Err(error) => {
            log::error!("failed to create server connection: {}", error);
            None
        }
    }
}

pub struct LiveClientRuntime<'a> {
    pub connection: &'a mut QuicFuscateConnection,
    pub client_count: usize,
    pub conn_id: Vec<u8>,
    pub qkey_auth: Option<QKeyAuthState>,
    pub session_id: Option<SessionId>,
    pub session_stats: Option<Arc<SessionStats>>,
}

pub enum LiveClientAcquire<'a> {
    Ready(LiveClientRuntime<'a>),
    Backpressure,
    Rejected,
}

struct LiveServerDomain {
    shared: SharedServerDomain,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
}

impl LiveServerDomain {
    fn new(server_config: &ServerConfig) -> Self {
        Self {
            shared: SharedServerDomain::new(server_config),
            client_snapshots: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>), AcceptError> {
        let (session_id, stats, _) = self.shared.accept(remote_addr)?;
        Ok((session_id, stats))
    }

    fn remove_remote(&self, remote_addr: SocketAddr) {
        let Some(session_id) = self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
        else {
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(remote_addr.ip());
            self.remove_remote_snapshot(remote_addr);
            return;
        };
        self.shared.remove(session_id);
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(remote_addr.ip());
        self.remove_remote_snapshot(remote_addr);
    }

    fn rebind_remote(&self, old_addr: SocketAddr, new_addr: SocketAddr) {
        let mut sessions = self.shared.sessions.write();
        if sessions.rebind_remote_addr(old_addr, new_addr).is_some() {
            drop(sessions);
            let mut limiter = self.shared.connection_limiter.lock();
            limiter.remove(old_addr.ip());
            limiter.add(new_addr.ip());
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(old_addr.ip());
            if let Ok(mut guard) = self.client_snapshots.lock() {
                if let Some(snapshot) = guard.remove(&old_addr) {
                    guard.insert(new_addr, snapshot);
                }
            }
        }
    }

    fn session_stats_by_remote(&self, remote_addr: SocketAddr) -> Option<Arc<SessionStats>> {
        self.shared.sessions.read().stats_by_remote_addr(remote_addr)
    }

    fn session_id_by_remote(&self, remote_addr: SocketAddr) -> Option<SessionId> {
        self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
    }

    fn remote_addr_for_identity(&self, identity: &ClientIdentity) -> Option<SocketAddr> {
        match identity {
            ClientIdentity::Remote(addr) => Some(*addr),
            ClientIdentity::Session(session_id) => {
                self.shared.sessions.read().remote_addr_by_session_id(*session_id)
            }
        }
    }

    fn active_session_count(&self) -> usize {
        self.shared.session_count()
    }

    fn reap_expired_remotes(&self) -> Vec<SocketAddr> {
        self.shared.reap_expired().into_iter().map(|session| session.remote_addr()).collect()
    }

    fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        &self.client_snapshots
    }

    fn remove_remote_snapshot(&self, remote_addr: SocketAddr) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.remove(&remote_addr);
        }
    }

    fn retain_snapshots_for_clients(
        &self,
        clients: &std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    ) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.retain(|addr, _| clients.contains_key(addr));
        }
    }

    #[cfg(feature = "rate_limiter")]
    fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        self.shared.allow_incoming_datagram(from, len)
    }

    #[cfg(feature = "rate_limiter")]
    fn prune_rate_limits_if_due(&self) {
        self.shared.prune_rate_limits_if_due();
    }
}

fn accept_session_in_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    connection_limiter: &mut ConnectionLimiter,
    remote_addr: SocketAddr,
    max_clients: usize,
    client_timeout_secs: u64,
) -> Result<(SessionId, Arc<SessionStats>, Ipv4Addr), AcceptError> {
    if !connection_limiter.check(remote_addr.ip()) {
        return Err(AcceptError::TooManyConnectionsPerIp);
    }
    if sessions.len() >= max_clients {
        return Err(AcceptError::MaxClientsReached);
    }
    let client_ip = ip_pool.allocate().ok_or(AcceptError::IpPoolExhausted)?;
    let session = Session::new(remote_addr, client_ip, client_timeout_secs);
    let session_id = session.id();
    let stats = Arc::clone(session.stats());
    match sessions.add(session) {
        Ok(_) => {
            connection_limiter.add(remote_addr.ip());
            Ok((session_id, stats, client_ip))
        }
        Err(SessionError::MaxSessionsReached) => {
            ip_pool.release(client_ip);
            Err(AcceptError::MaxClientsReached)
        }
        Err(SessionError::NotFound | SessionError::AlreadyExists) => {
            ip_pool.release(client_ip);
            Err(AcceptError::SessionError("failed to add live session".to_string()))
        }
    }
}

fn remove_session_from_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    connection_limiter: &mut ConnectionLimiter,
    session_id: SessionId,
) -> Option<Session> {
    let session = sessions.remove(session_id)?;
    ip_pool.release(session.client_ip());
    connection_limiter.remove(session.remote_addr().ip());
    Some(session)
}

fn collect_expired_session_ids(sessions: &SessionManager) -> Vec<SessionId> {
    sessions
        .iter()
        .filter_map(|(session_id, session)| session.is_expired().then_some(*session_id))
        .collect()
}

fn reap_expired_sessions_from_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    connection_limiter: &mut ConnectionLimiter,
) -> Vec<Session> {
    let expired_ids = collect_expired_session_ids(sessions);
    let mut removed = Vec::with_capacity(expired_ids.len());
    for session_id in expired_ids {
        if let Some(session) =
            remove_session_from_domain(sessions, ip_pool, connection_limiter, session_id)
        {
            removed.push(session);
        }
    }
    removed
}

impl LiveServerState {
    pub fn new(server_config: ServerConfig) -> Self {
        Self {
            clients: std::collections::HashMap::new(),
            qkey_auth: std::collections::HashMap::new(),
            domain: LiveServerDomain::new(&server_config),
        }
    }

    pub fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.domain.client_snapshots()
    }

    #[cfg(feature = "rate_limiter")]
    pub fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        self.domain.allow_incoming_datagram(from, len)
    }

    #[cfg(feature = "rate_limiter")]
    pub fn prune_rate_limits_if_due(&self) {
        self.domain.prune_rate_limits_if_due();
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut QuicFuscateConnection> {
        self.clients.values_mut()
    }

    pub fn accept_or_get_client_with<F>(
        &mut self,
        addr: SocketAddr,
        accept_loop: &AcceptLoop,
        accept_max_clients: usize,
        metrics: &Metrics,
        build: F,
    ) -> LiveClientAcquire<'_>
    where
        F: FnOnce() -> Option<LiveClientInit>,
    {
        use std::collections::hash_map::Entry;

        let count_before = self.clients.len();
        match self.clients.entry(addr) {
            Entry::Occupied(entry) => {
                let connection = entry.into_mut();
                let conn_id = connection.conn.source_id().as_ref().to_vec();
                let qkey_auth = self.qkey_auth.get(&conn_id).cloned();
                let session_id = self.domain.session_id_by_remote(addr);
                let session_stats = self.domain.session_stats_by_remote(addr);
                LiveClientAcquire::Ready(LiveClientRuntime {
                    connection,
                    client_count: count_before,
                    conn_id,
                    qkey_auth,
                    session_id,
                    session_stats,
                })
            }
            Entry::Vacant(entry) => {
                match accept_loop.should_accept(addr, count_before, accept_max_clients) {
                    AcceptDecision::Accept => {}
                    AcceptDecision::Backpressure => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[DEBUG] Rejected by Backpressure (should_accept) for {}", addr);
                        return LiveClientAcquire::Backpressure;
                    }
                    AcceptDecision::Reject(reason) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[DEBUG] Rejected by should_accept for {}: {:?}", addr, reason);
                        return LiveClientAcquire::Rejected;
                    }
                }

                let mut init = match build() {
                    Some(value) => value,
                    None => {
                        eprintln!("[DEBUG] build() returned None for {}", addr);
                        return LiveClientAcquire::Rejected;
                    }
                };
                let (session_id, session_stats) = match self.domain.accept(addr) {
                    Ok(value) => value,
                    Err(e) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        eprintln!("[DEBUG] domain.accept failed for {}: {:?}", addr, e);
                        return LiveClientAcquire::Rejected;
                    }
                };
                if let Some(state) = init.pending_qkey_auth.take() {
                    let conn_id = init.connection.conn.source_id().as_ref().to_vec();
                    self.qkey_auth.insert(conn_id, state);
                }
                let connection = entry.insert(init.connection);
                let conn_id = connection.conn.source_id().as_ref().to_vec();
                let qkey_auth = self.qkey_auth.get(&conn_id).cloned();
                metrics.record_connection_accepted();
                accept_loop.record_accepted(addr);
                LiveClientAcquire::Ready(LiveClientRuntime {
                    connection,
                    client_count: count_before + 1,
                    conn_id,
                    qkey_auth,
                    session_id: Some(session_id),
                    session_stats: Some(session_stats),
                })
            }
        }
    }

    pub fn acquire_runtime_client_with<F>(
        &mut self,
        addr: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
        accept_max_clients: usize,
        metrics: &Metrics,
        build: F,
    ) -> LiveClientAcquire<'_>
    where
        F: FnOnce() -> Option<LiveClientInit>,
    {
        if self.handle_incoming_path_update(addr, packet, accept_loop) {
            log::info!("Client path updated to {}", addr);
        }

        let acquired =
            self.accept_or_get_client_with(addr, accept_loop, accept_max_clients, metrics, build);
        if let LiveClientAcquire::Ready(client) = &acquired {
            metrics.clients_active.store(client.client_count as u64, Ordering::Relaxed);
        }
        acquired
    }

    fn get_mut(&mut self, addr: &SocketAddr) -> Option<&mut QuicFuscateConnection> {
        self.clients.get_mut(addr)
    }

    fn key_addrs(&self) -> Vec<SocketAddr> {
        self.clients.keys().copied().collect()
    }

    pub async fn run_housekeeping_tick(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        accept_loop: &AcceptLoop,
    ) {
        #[cfg(feature = "rate_limiter")]
        self.prune_rate_limits_if_due();
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        let addresses = self.key_addrs();
        for addr in addresses {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            if let Some(conn) = self.get_mut(&addr) {
                if let Err(error) = flush_live_server_outgoing(
                    socket,
                    addr,
                    conn,
                    out,
                    metrics,
                    &client_snapshots,
                    session_stats,
                    session_id,
                )
                .await
                {
                    log::warn!("Failed to flush packets to {}: {}", addr, error);
                }
                conn.update_state();
                log::info!(
                    "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                    addr,
                    conn.rtt_ms(),
                    conn.loss_rate() * 100.0
                );
                conn.conn.on_timeout();
            }
        }
        self.enforce_qkey_auth_timeouts(metrics);
        self.reap_expired_sessions(accept_loop, metrics);
        self.reconcile(accept_loop, metrics);
    }

    pub fn sync_active_metrics(&self, metrics: &Metrics) {
        metrics.clients_active.store(self.domain.active_session_count() as u64, Ordering::Relaxed);
    }

    fn qkey_auth_state_mut(&mut self, conn_id: &[u8]) -> Option<&mut QKeyAuthState> {
        self.qkey_auth.get_mut(conn_id)
    }

    fn remove_qkey_auth(&mut self, conn_id: &[u8]) -> Option<QKeyAuthState> {
        self.qkey_auth.remove(conn_id)
    }

    fn try_rebind_by_dcid(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
    ) -> bool {
        let old_addr = try_rebind_live_client_by_dcid(&mut self.clients, from, packet, accept_loop);
        if let Some(old_addr) = old_addr {
            self.domain.rebind_remote(old_addr, from);
            return true;
        }
        false
    }

    pub fn handle_incoming_path_update(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
    ) -> bool {
        if self.clients.contains_key(&from) {
            return false;
        }
        self.try_rebind_by_dcid(from, packet, accept_loop)
    }

    pub fn kick_client(
        &mut self,
        identity: &ClientIdentity,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let Some(addr) = self.domain.remote_addr_for_identity(identity) else {
            return;
        };
        if let Some(mut conn) = self.clients.remove(&addr) {
            let conn_id = conn.conn.source_id().as_ref().to_vec();
            if let Err(e) = conn.conn.close(true, 0x0, b"admin_kick") {
                log::warn!("Client close on admin kick failed for {}: {:?}", addr, e);
            }
            self.qkey_auth.remove(&conn_id);
            accept_loop.record_closed(addr);
        }
        self.domain.remove_remote(addr);
        self.sync_active_metrics(metrics);
    }

    pub fn shutdown_all(&mut self, reason: &'static [u8]) {
        for conn in self.clients.values_mut() {
            if let Err(e) = conn.conn.close(true, 0x0, reason) {
                log::warn!("Live client close failed for reason {:?}: {:?}", reason, e);
            }
        }
    }

    pub fn reconcile(&mut self, accept_loop: &AcceptLoop, metrics: &Metrics) {
        let closed_addrs =
            reconcile_live_clients(&mut self.clients, &mut self.qkey_auth, accept_loop, metrics);
        for addr in closed_addrs {
            self.domain.remove_remote(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn reap_expired_sessions(&mut self, accept_loop: &AcceptLoop, metrics: &Metrics) {
        let expired_remotes = self.domain.reap_expired_remotes();
        if expired_remotes.is_empty() {
            return;
        }
        for addr in expired_remotes {
            if let Some(mut conn) = self.clients.remove(&addr) {
                let conn_id = conn.conn.source_id().as_ref().to_vec();
                if let Err(error) = conn.conn.close(true, 0x0, b"session_timeout") {
                    log::warn!(
                        "Client close after session timeout failed for {}: {:?}",
                        addr,
                        error
                    );
                }
                self.qkey_auth.remove(&conn_id);
            }
            accept_loop.record_closed(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn enforce_qkey_auth_timeouts(&mut self, metrics: &Metrics) {
        let timed_out_conn_ids: Vec<Vec<u8>> = self
            .qkey_auth
            .iter()
            .filter_map(|(conn_id, state)| state.is_expired().then_some(conn_id.clone()))
            .collect();
        for conn_id in timed_out_conn_ids {
            for conn in self.values_mut() {
                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                    record_qkey_auth_rejection(metrics);
                    if let Err(error) = conn.conn.close(true, 0x0, b"qkey_auth_timeout") {
                        log::warn!("Client close after QKey auth timeout failed: {:?}", error);
                    }
                    break;
                }
            }
            self.remove_qkey_auth(&conn_id);
        }
    }

    pub fn commit_qkey_auth_result(
        &mut self,
        remove_auth_conn_id: Option<Vec<u8>>,
        auth_result: Option<(Vec<u8>, bool)>,
    ) {
        if let Some(conn_id) = remove_auth_conn_id {
            self.remove_qkey_auth(&conn_id);
        } else if let Some((conn_id, authed)) = auth_result {
            if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                state.authed = authed;
            }
        }
    }
}

impl Default for LiveServerState {
    fn default() -> Self {
        Self::new(ServerConfig::default())
    }
}

struct ServerRuntimeLiveParts<'a> {
    live_state: &'a mut LiveServerState,
    accept_loop: &'a AcceptLoop,
    accept_max_clients: usize,
    server_tun: Option<&'a Arc<TunInterface>>,
}

struct ServerLiveRuntime {
    live_state: LiveServerState,
    accept_loop: AcceptLoop,
    accept_max_clients: usize,
    admin_actions_tx: mpsc::UnboundedSender<AdminAction>,
    admin_actions_rx: Option<mpsc::UnboundedReceiver<AdminAction>>,
    metrics: Arc<Metrics>,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    server_tun: Option<Arc<TunInterface>>,
    /// Channel receiving packets read from the server TUN interface (spawned reader thread).
    /// Forwarded to the appropriate client via QUIC datagrams in the run_loop.
    tun_rx: Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
    admin_web_bootstrap: StandaloneAdminWebBootstrap,
    standalone_runtime_metadata: Option<StandaloneRuntimeMetadata>,
    service_signals: StandaloneServiceSignals,
}

#[derive(Clone)]
struct StandaloneReloadPolicy {
    fec_mode_override: Option<crate::engine::FecMode>,
    stealth_policy: OwnedRuntimeStealthPolicy,
}

#[derive(Clone)]
struct StandaloneRuntimeMetadata {
    front_domain: Vec<String>,
    config_path: Option<std::path::PathBuf>,
    reload_policy: StandaloneReloadPolicy,
}

#[derive(Default)]
struct StandaloneServiceSignals {
    admin: Option<Arc<AtomicBool>>,
    admin_web: Option<Arc<AtomicBool>>,
    metrics: Option<Arc<AtomicBool>>,
}

impl StandaloneServiceSignals {
    fn shutdown_all(&mut self) {
        if let Some(sig) = self.admin.take() {
            sig.store(true, Ordering::SeqCst);
        }
        if let Some(sig) = self.admin_web.take() {
            sig.store(true, Ordering::SeqCst);
        }
        if let Some(sig) = self.metrics.take() {
            sig.store(true, Ordering::SeqCst);
        }
    }
}

pub const QKEY_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
pub const DF_SNI_MODE_FIXED: &str = "fixed";
pub const DF_SNI_MODE_AUTO_ROTATING: &str = "auto_rotating";

const BUILTIN_FRONTING_SNI_ALLOWLIST: &[&str] = &[
    "cdn.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "warp.plus",
    "workers.dev",
    "cdn.fastly.net",
    "fastly.com",
    "fastlylb.net",
    "fsly.net",
    "akamaized.net",
    "akamai.net",
    "akamaihd.net",
    "akamaitechnologies.com",
    "edgesuite.net",
    "cloudfront.net",
    "amazonaws.com",
    "aws.amazon.com",
    "awsstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "google.com",
    "azureedge.net",
    "azure.microsoft.com",
    "windows.net",
    "msecnd.net",
    "stackpathdns.com",
    "stackpathcdn.com",
    "bootstrapcdn.com",
    "kxcdn.com",
    "keycdn.com",
    "b-cdn.net",
    "bunnycdn.com",
    "incapdns.net",
    "imperva.com",
];

pub fn require_qkey_for_new_clients() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct QKeyDomainFrontingPolicy {
    pub qkey_sni: String,
    pub extra_json: String,
}

pub struct IssuedQKey {
    pub qkey: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

#[derive(Clone)]
pub struct QKeyAuthState {
    pub expected_token_sha256: String,
    pub authed: bool,
    pub connected_at: Instant,
}

impl QKeyAuthState {
    #[inline]
    pub fn is_expired(&self) -> bool {
        !self.authed && self.connected_at.elapsed() > QKEY_AUTH_TIMEOUT
    }
}

pub fn default_qkey_domain_fronting_policy(nonce_hex: &str) -> QKeyDomainFrontingPolicy {
    QKeyDomainFrontingPolicy {
        qkey_sni: BUILTIN_FRONTING_SNI_ALLOWLIST[0].to_string(),
        extra_json: serde_json::json!({
            "nonce": nonce_hex,
            "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
            "df_sni_pool": [BUILTIN_FRONTING_SNI_ALLOWLIST[0]],
        })
        .to_string(),
    }
}

pub fn resolve_qkey_domain_fronting_policy(
    front_domain: &[String],
    listen_addr: &str,
    requested_strategy: Option<&str>,
    requested_domain: Option<&str>,
    nonce_hex: &str,
) -> Result<QKeyDomainFrontingPolicy, String> {
    let allowlist: Vec<String> =
        BUILTIN_FRONTING_SNI_ALLOWLIST.iter().map(|d| (*d).to_string()).collect();
    let default_domain =
        allowlist.first().cloned().ok_or_else(|| "Missing SNI allowlist defaults".to_string())?;
    let mode_raw = requested_strategy.unwrap_or("").trim().to_ascii_lowercase();
    let mode = if mode_raw.is_empty()
        || mode_raw == "auto"
        || mode_raw == "rotating"
        || mode_raw == DF_SNI_MODE_AUTO_ROTATING
    {
        DF_SNI_MODE_AUTO_ROTATING
    } else if mode_raw == DF_SNI_MODE_FIXED {
        DF_SNI_MODE_FIXED
    } else {
        return Err(
            "Invalid Domain Fronting [SNI] strategy. Valid: fixed, auto_rotating".to_string()
        );
    };
    let server_host = extract_host_from_endpoint(listen_addr);

    if mode == DF_SNI_MODE_FIXED {
        let requested = requested_domain
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "Domain Fronting [SNI] fixed mode requires a domain".to_string())?;
        let domain = normalize_sni_host(requested)
            .ok_or_else(|| "Invalid Domain Fronting [SNI] domain".to_string())?;
        if !allowlist.iter().any(|v| v == &domain) {
            return Err("Domain Fronting [SNI] domain is not allowlisted".to_string());
        }
        let domain_for_json = domain.clone();
        return Ok(QKeyDomainFrontingPolicy {
            qkey_sni: domain,
            extra_json: serde_json::json!({
                "nonce": nonce_hex,
                "df_sni_mode": DF_SNI_MODE_FIXED,
                "df_sni_domain": domain_for_json,
                "server_host": server_host,
            })
            .to_string(),
        });
    }

    let mut pool: Vec<String> = front_domain
        .iter()
        .filter_map(|raw| normalize_sni_host(raw))
        .filter(|raw| allowlist.iter().any(|v| v == raw))
        .collect();
    if pool.is_empty() {
        pool = allowlist;
    }
    let qkey_sni = pool.first().cloned().unwrap_or(default_domain);
    Ok(QKeyDomainFrontingPolicy {
        qkey_sni,
        extra_json: serde_json::json!({
            "nonce": nonce_hex,
            "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
            "df_sni_pool": pool,
            "server_host": server_host,
        })
        .to_string(),
    })
}

fn is_valid_sni_host(value: &str) -> bool {
    let s = value.trim();
    if s.is_empty() {
        return false;
    }
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    if s.contains(':') {
        return false;
    }
    if s.contains('/') || s.contains('?') || s.contains('#') || s.contains('@') {
        return false;
    }
    true
}

fn normalize_sni_host(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if is_valid_sni_host(&lower) {
        Some(lower)
    } else {
        None
    }
}

fn extract_host_from_endpoint(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return normalize_sni_host(host);
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.is_empty() {
            return normalize_sni_host(host);
        }
    }
    normalize_sni_host(trimmed)
}

pub fn issue_unix_admin_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
) -> Result<String, String> {
    let entry = issue_qkey(
        registry,
        listen_addr,
        front_domain,
        IssueQKeyParams {
            name: None,
            port: None,
            ttl_seconds: None,
            stealth: Some("auto"),
            fec: None,
            sni_strategy: Some(DF_SNI_MODE_AUTO_ROTATING),
            sni_domain: None,
        },
        "server::issue_unix_admin_qkey",
    )?;
    Ok(entry.qkey)
}

pub fn issue_http_admin_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
    req: &IssueQKeyRequest,
) -> Result<IssuedQKey, String> {
    issue_qkey(
        registry,
        listen_addr,
        front_domain,
        IssueQKeyParams {
            name: req.name.as_deref(),
            port: req.port,
            ttl_seconds: req.ttl_seconds,
            stealth: req.stealth.as_deref(),
            fec: req.fec.as_deref(),
            sni_strategy: req.sni_strategy.as_deref(),
            sni_domain: req.sni_domain.as_deref(),
        },
        "server::issue_http_admin_qkey",
    )
}

struct IssueQKeyParams<'a> {
    name: Option<&'a str>,
    port: Option<u16>,
    ttl_seconds: Option<u64>,
    stealth: Option<&'a str>,
    fec: Option<&'a str>,
    sni_strategy: Option<&'a str>,
    sni_domain: Option<&'a str>,
}

fn issue_qkey(
    registry: &mut QKeyRegistry,
    listen_addr: &str,
    front_domain: &[String],
    params: IssueQKeyParams<'_>,
    rng_context: &str,
) -> Result<IssuedQKey, String> {
    use crate::engine::qkey;

    let name = normalize_qkey_name(params.name)?;
    let nonce_hex = random_hex_8(&format!("{rng_context}::nonce"));
    let sni_policy = resolve_qkey_domain_fronting_policy(
        front_domain,
        listen_addr,
        params.sni_strategy,
        params.sni_domain,
        &nonce_hex,
    )?;
    let token_hex = random_hex_32(&format!("{rng_context}::token"));
    let stealth = normalize_qkey_stealth(params.stealth)?;
    let fec = normalize_qkey_fec(params.fec)?;
    let remote = resolve_qkey_remote(listen_addr, params.port)?;
    let config = qkey::QKeyConfig::new(&remote, &sni_policy.qkey_sni)
        .with_stealth(stealth)
        .with_fec(fec)
        .with_extra(&sni_policy.extra_json)
        .with_token(&token_hex);
    let qkey_value = qkey::generate(&config);
    let QKeyEntry { created_at, expires_at, .. } =
        registry.insert_with_ttl(qkey_value.clone(), token_hex, params.ttl_seconds, name)?;
    Ok(IssuedQKey { qkey: qkey_value, created_at, expires_at })
}

fn normalize_qkey_name(name: Option<&str>) -> Result<Option<String>, String> {
    let Some(name) = name.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if name.chars().count() > 64 {
        return Err("QKey name too long (max 64 chars)".to_string());
    }
    if name.chars().any(char::is_control) {
        return Err("QKey name contains invalid characters".to_string());
    }
    Ok(Some(name.to_string()))
}

fn normalize_qkey_stealth(stealth: Option<&str>) -> Result<&'static str, String> {
    let stealth_raw = stealth.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    match stealth_raw.to_ascii_lowercase().as_str() {
        "auto" => Ok("auto"),
        "max" => Ok("max"),
        "manual" => Ok("manual"),
        "off" => Ok("off"),
        _ => Err("Invalid stealth preset. Valid: auto, max, manual, off".to_string()),
    }
}

fn normalize_qkey_fec(fec: Option<&str>) -> Result<&'static str, String> {
    let fec_raw = fec.map(str::trim).filter(|s| !s.is_empty()).unwrap_or("auto");
    match fec_raw.to_ascii_lowercase().as_str() {
        "auto" => Ok("auto"),
        "off" | "zero" => Ok("off"),
        _ => Err("Invalid fec preset. Canonical values: auto, off.".to_string()),
    }
}

fn resolve_qkey_remote(listen_addr: &str, port: Option<u16>) -> Result<String, String> {
    let Some(port) = port else {
        return Ok(listen_addr.to_string());
    };
    let endpoint = listen_addr.trim();
    if endpoint.is_empty() {
        return Err("Server listen address is empty".to_string());
    }
    if let Ok(sock) = endpoint.parse::<std::net::SocketAddr>() {
        return Ok(match sock {
            std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), port),
            std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), port),
        });
    }
    if endpoint.starts_with('[') {
        let Some(end) = endpoint.find(']') else {
            return Err("Invalid server listen address".to_string());
        };
        return Ok(format!("{}:{}", &endpoint[..=end], port));
    }
    if let Some((host, _)) = endpoint.rsplit_once(':') {
        if host.is_empty() {
            return Err("Invalid server listen address".to_string());
        }
        return Ok(format!("{}:{}", host, port));
    }
    Ok(format!("{}:{}", endpoint, port))
}

fn random_hex_8(context: &str) -> String {
    let mut bytes = [0u8; 8];
    crate::rng::fill_secure_or_abort(&mut bytes, context);
    hex_from_bytes(&bytes)
}

fn random_hex_32(context: &str) -> String {
    let mut bytes = [0u8; 32];
    crate::rng::fill_secure_or_abort(&mut bytes, context);
    hex_from_bytes(&bytes)
}

fn hex_from_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Default)]
struct TransportOverrides {
    cc_algorithm: Option<crate::transport::CongestionControlAlgorithm>,
    mtu: Option<usize>,
    max_udp_payload: Option<usize>,
    enable_pacing: Option<bool>,
    max_idle_timeout: Option<u64>,
    initial_max_data: Option<u64>,
    initial_max_stream_data_bidi_local: Option<u64>,
    initial_max_stream_data_bidi_remote: Option<u64>,
    initial_max_stream_data_uni: Option<u64>,
    initial_max_streams_bidi: Option<u64>,
    initial_max_streams_uni: Option<u64>,
    dgram_recv_queue_len: Option<usize>,
    dgram_send_queue_len: Option<usize>,
    disable_pmtud: Option<bool>,
    initial_rtt_ms: Option<u64>,
}

pub fn normalize_runtime_optimize_config(cfg: OptimizeConfig, _origin: &str) -> OptimizeConfig {
    cfg
}

#[allow(clippy::too_many_arguments)]
pub fn apply_runtime_stealth_overrides(
    sc: &mut StealthConfig,
    profile: BrowserProfile,
    os: OsProfile,
    disable_doh: bool,
    doh_provider: &str,
    disable_fronting: bool,
    front_domain: &[String],
    disable_http3: bool,
) {
    apply_runtime_profile_identity(sc, profile, os);
    sc.enable_doh = !disable_doh;
    sc.doh_provider.clear();
    sc.doh_provider.push_str(doh_provider);
    sc.enable_domain_fronting = !disable_fronting;
    sc.fronting_domains = front_domain.to_vec();
    sc.enable_http3_masquerading = !disable_http3;
}

pub(crate) fn apply_runtime_profile_identity(
    sc: &mut StealthConfig,
    profile: BrowserProfile,
    os: OsProfile,
) {
    sc.initial_browser = profile;
    sc.initial_os = os;
    crate::telemetry!(crate::telemetry::STEALTH_BROWSER_PROFILE.set(sc.initial_browser as i64));
    crate::telemetry!(crate::telemetry::STEALTH_OS_PROFILE.set(sc.initial_os as i64));
}

fn parse_transport_overrides_from_toml(contents: &str) -> Result<TransportOverrides, String> {
    let doc: toml::Value =
        toml::from_str(contents).map_err(|e| format!("TOML parse failed: {}", e))?;
    let Some(tbl) = doc.get("transport").and_then(|v| v.as_table()) else {
        return Ok(TransportOverrides::default());
    };

    let mut out = TransportOverrides::default();

    if let Some(v) = tbl.get("cc_algorithm") {
        let raw =
            v.as_str().ok_or_else(|| "transport.cc_algorithm must be a string".to_string())?;
        let name = raw.trim().to_lowercase();
        let algo = match name.as_str() {
            "reno" => Some(crate::transport::CongestionControlAlgorithm::Reno),
            "bbr2" => Some(crate::transport::CongestionControlAlgorithm::BBR2),
            "bbr3" => Some(crate::transport::CongestionControlAlgorithm::BBR3),
            _ => None,
        };
        let Some(algo) = algo else {
            return Err(format!("transport.cc_algorithm '{}' is not supported", raw));
        };
        out.cc_algorithm = Some(algo);
    }

    if let Some(v) = tbl.get("mtu") {
        let mtu = v.as_integer().ok_or_else(|| "transport.mtu must be an integer".to_string())?;
        if mtu <= 0 {
            return Err("transport.mtu must be > 0".to_string());
        }
        if !(1200..=9000).contains(&mtu) {
            return Err("transport.mtu must be between 1200 and 9000".to_string());
        }
        out.mtu = Some(mtu as usize);
    }

    if let Some(v) = tbl.get("enable_pacing") {
        let pacing =
            v.as_bool().ok_or_else(|| "transport.enable_pacing must be a boolean".to_string())?;
        out.enable_pacing = Some(pacing);
    }

    if let Some(v) = tbl.get("max_udp_payload") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.max_udp_payload must be an integer".to_string())?;
        if val <= 0 {
            return Err("transport.max_udp_payload must be > 0".to_string());
        }
        out.max_udp_payload = Some(val as usize);
    }
    if let Some(v) = tbl.get("max_idle_timeout") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.max_idle_timeout must be an integer".to_string())?;
        out.max_idle_timeout = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_data") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_data must be an integer".to_string())?;
        out.initial_max_data = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_bidi_local") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_bidi_local must be an integer".to_string()
        })?;
        out.initial_max_stream_data_bidi_local = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_bidi_remote") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_bidi_remote must be an integer".to_string()
        })?;
        out.initial_max_stream_data_bidi_remote = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_stream_data_uni") {
        let val = v.as_integer().ok_or_else(|| {
            "transport.initial_max_stream_data_uni must be an integer".to_string()
        })?;
        out.initial_max_stream_data_uni = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_streams_bidi") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_streams_bidi must be an integer".to_string())?;
        out.initial_max_streams_bidi = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("initial_max_streams_uni") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_max_streams_uni must be an integer".to_string())?;
        out.initial_max_streams_uni = Some(val.max(0) as u64);
    }
    if let Some(v) = tbl.get("dgram_recv_queue_len") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.dgram_recv_queue_len must be an integer".to_string())?;
        out.dgram_recv_queue_len = Some(val.max(0) as usize);
    }
    if let Some(v) = tbl.get("dgram_send_queue_len") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.dgram_send_queue_len must be an integer".to_string())?;
        out.dgram_send_queue_len = Some(val.max(0) as usize);
    }
    if let Some(v) = tbl.get("disable_pmtud") {
        let val =
            v.as_bool().ok_or_else(|| "transport.disable_pmtud must be a boolean".to_string())?;
        out.disable_pmtud = Some(val);
    }
    if let Some(v) = tbl.get("initial_rtt_ms") {
        let val = v
            .as_integer()
            .ok_or_else(|| "transport.initial_rtt_ms must be an integer".to_string())?;
        if val <= 0 {
            return Err("transport.initial_rtt_ms must be > 0".to_string());
        }
        out.initial_rtt_ms = Some(val as u64);
    }

    Ok(out)
}

pub(crate) fn validate_transport_overrides_from_toml(contents: &str) -> Result<(), String> {
    parse_transport_overrides_from_toml(contents).map(|_| ())
}

pub(crate) fn apply_transport_overrides_from_toml(
    cfg_path: &std::path::Path,
    contents: &str,
    transport: &mut crate::transport::Config,
) {
    let overrides = match parse_transport_overrides_from_toml(contents) {
        Ok(o) => o,
        Err(e) => {
            log::warn!(
                "transport overrides ignored (invalid values, {}): {}",
                cfg_path.display(),
                e
            );
            return;
        }
    };

    if let Some(algo) = overrides.cc_algorithm {
        transport.set_cc_algorithm(algo);
    }
    if let Some(mtu) = overrides.mtu {
        transport.set_max_send_udp_payload_size(mtu);
    }
    if let Some(payload) = overrides.max_udp_payload {
        transport.set_max_recv_udp_payload_size(payload);
    }
    if let Some(pacing) = overrides.enable_pacing {
        transport.enable_pacing(pacing);
    }
    if let Some(timeout) = overrides.max_idle_timeout {
        transport.set_max_idle_timeout(timeout);
    }
    if let Some(data) = overrides.initial_max_data {
        transport.set_initial_max_data(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_bidi_local {
        transport.set_initial_max_stream_data_bidi_local(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_bidi_remote {
        transport.set_initial_max_stream_data_bidi_remote(data);
    }
    if let Some(data) = overrides.initial_max_stream_data_uni {
        transport.set_initial_max_stream_data_uni(data);
    }
    if let Some(streams) = overrides.initial_max_streams_bidi {
        transport.set_initial_max_streams_bidi(streams);
    }
    if let Some(streams) = overrides.initial_max_streams_uni {
        transport.set_initial_max_streams_uni(streams);
    }
    if let (Some(recv), Some(send)) =
        (overrides.dgram_recv_queue_len, overrides.dgram_send_queue_len)
    {
        if recv > 0 && send > 0 {
            transport.enable_dgram(recv, send);
        }
        // If either is 0, datagrams stay at their current state (disable requires both to be 0)
    }
    if let Some(disable) = overrides.disable_pmtud {
        transport.discover_pmtu(!disable);
    }
    if let Some(rtt_ms) = overrides.initial_rtt_ms {
        transport.set_initial_rtt_ms(rtt_ms);
    }
}

pub fn apply_transport_overrides_from_file(
    cfg_path: &std::path::Path,
    transport: &mut crate::transport::Config,
) {
    match std::fs::read_to_string(cfg_path) {
        Ok(contents) => apply_transport_overrides_from_toml(cfg_path, &contents, transport),
        Err(e) => {
            log::warn!("transport overrides ignored (read failed, {}): {}", cfg_path.display(), e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn apply_runtime_config_reload(
    cfg_path: &std::path::Path,
    fec_mode_override: Option<crate::engine::FecMode>,
    transport: &mut crate::transport::Config,
    fec_cfg_shared: &Arc<std::sync::Mutex<FecConfig>>,
    opt_params_shared: &Arc<std::sync::Mutex<OptimizeConfig>>,
    stealth_config: &Arc<std::sync::Mutex<StealthConfig>>,
    stealth_policy: RuntimeStealthPolicy<'_>,
) -> Result<(), String> {
    let RuntimeStealthPolicy {
        profile,
        os,
        disable_doh,
        doh_provider,
        disable_fronting,
        front_domain,
        disable_http3,
    } = stealth_policy;
    let contents =
        std::fs::read_to_string(cfg_path).map_err(|e| format!("Config read failed: {}", e))?;
    let cfg = crate::interface::app_config::AppConfig::from_toml(&contents)
        .map_err(|e| format!("Config parse failed: {}", e))?;

    cfg.validate().map_err(|e| format!("Config validation failed: {}", e))?;
    validate_transport_overrides_from_toml(&contents)?;

    let mut fec = cfg.fec;
    if let Some(mode) = fec_mode_override {
        fec.apply_engine_mode(mode);
    }

    {
        let mut guard = fec_cfg_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = fec;
    }
    {
        let mut guard = opt_params_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = normalize_runtime_optimize_config(
            OptimizeConfig {
                pool_capacity: cfg.optimize.pool_capacity,
                block_size: cfg.optimize.block_size,
            },
            "runtime config reload",
        );
    }
    {
        let mut guard = stealth_config.lock().unwrap_or_else(|e| e.into_inner());
        *guard = cfg.stealth;
        apply_runtime_stealth_overrides(
            &mut guard,
            profile,
            os,
            disable_doh,
            doh_provider,
            disable_fronting,
            front_domain,
            disable_http3,
        );
    }

    apply_transport_overrides_from_toml(cfg_path, &contents, transport);
    Ok(())
}

pub(crate) fn open_server_tun(
    tun_config: TunConfig,
    pool: Arc<MemoryPool>,
) -> Result<TunInterface, String> {
    crate::interface::validate_tun_runtime_requirements().map_err(|e| format!("{:?}", e))?;
    TunInterface::open(tun_config, pool).map_err(|e| format!("{:?}", e))
}

#[cfg(unix)]
pub(crate) async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    use std::io::ErrorKind;

    // Use `async_io` so tokio properly clears the edge-triggered readiness
    // when `recvmsg` returns `WouldBlock`.  Calling `ready()` + raw `recvmsg`
    // in a loop causes a busy-spin because tokio never observes the EAGAIN.
    let fd = socket.as_raw_fd();
    socket
        .async_io(Interest::READABLE, || {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            match zc.recv_from(fd) {
                Ok((rc, addr)) if rc >= 0 => Ok((rc as usize, addr)),
                Ok(_) => Err(std::io::Error::new(ErrorKind::UnexpectedEof, "negative recv_from result")),
                Err(e) => Err(e),
            }
        })
        .await
}

#[cfg(not(unix))]
pub(crate) async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match socket.try_recv_from(buf) {
            Ok(result) => Ok(result),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => Err(e),
        }
    }
}

impl ServerRuntime {
    /// Create a new server runtime.
    pub fn new(
        engine_config: EngineConfig,
        server_config: ServerConfig,
    ) -> Result<Self, EngineError> {
        // Create memory pool
        let pool_bytes = engine_config.optimization.memory_pool_size;
        let block_size = engine_config.optimization.memory_pool_alignment.max(2048);
        let mut capacity = pool_bytes / block_size;
        if capacity == 0 {
            capacity = 1;
        }
        let pool = Arc::new(MemoryPool::new(capacity, block_size));

        let domain = SharedServerDomain::new(&server_config);

        Ok(Self {
            engine_config,
            server_config,
            pool,
            host_resources: None,
            domain,
            shutdown: Arc::new(AtomicBool::new(false)),
            state: ServerState::Stopped,
            stats: Arc::new(ServerStats::default()),
            live: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_standalone(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        accept_config: AcceptConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
    ) -> std::io::Result<Self> {
        let mut runtime =
            Self::new(engine_config, server_config.clone()).map_err(std::io::Error::other)?;

        let std_socket = std::net::UdpSocket::bind(server_config.listen)?;
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let local_addr = socket.local_addr()?;
        let (admin_actions_tx, admin_actions_rx) = mpsc::unbounded_channel::<AdminAction>();
        let accept_max_clients = server_config.max_clients;
        let (server_tun, tun_rx) = match tun_config {
            Some(tun_config) => {
                let optm = crate::optimize::OptimizationManager::from_cfg(opt_params);
                match open_server_tun(tun_config, optm.memory_pool()) {
                    Ok(tun) => {
                        let tun_arc = Arc::new(tun);
                        // Spawn a blocking reader thread that forwards TUN frames into a channel.
                        // These packets are forwarded to the client via QUIC datagrams in the run_loop.
                        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                        let tun_for_reader = tun_arc.clone();
                        std::thread::spawn(move || {
                            loop {
                                match tun_for_reader.read_block() {
                                    Ok((block, len)) if len > 0 => {
                                        let mut v = vec![0u8; len];
                                        v.copy_from_slice(&block[..len]);
                                        if tx.send(v).is_err() {
                                            break;
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(_) => break,
                                }
                            }
                        });
                        log::info!("Server TUN reader thread spawned for bidirectional forwarding");
                        (Some(tun_arc), Some(rx))
                    }
                    Err(error) => {
                        log::warn!("server TUN open failed: {}", error);
                        (None, None)
                    }
                }
            }
            None => (None, None),
        };

        runtime.live = Some(ServerLiveRuntime {
            live_state: LiveServerState::new(server_config),
            accept_loop: AcceptLoop::new(accept_config),
            accept_max_clients,
            admin_actions_tx,
            admin_actions_rx: Some(admin_actions_rx),
            metrics: Arc::new(Metrics::new()),
            socket,
            local_addr,
            server_tun,
            tun_rx,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
            standalone_runtime_metadata: None,
            service_signals: StandaloneServiceSignals::default(),
        });

        Ok(runtime)
    }

    pub fn new_standalone_default(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        qkey_registry: Arc<std::sync::Mutex<QKeyRegistry>>,
        admin_web_bootstrap: StandaloneAdminWebBootstrap,
    ) -> std::io::Result<Self> {
        Self::new_standalone(
            engine_config,
            server_config,
            AcceptConfig::default(),
            tun_config,
            opt_params,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
        )
    }

    pub fn new_standalone_with_bootstrap(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        bootstrap: StandaloneServerBootstrapState,
    ) -> std::io::Result<Self> {
        let (blocked_ips, qkey_registry, admin_web_bootstrap) = bootstrap.into_runtime_parts();
        Self::new_standalone_default(
            engine_config,
            server_config,
            tun_config,
            opt_params,
            blocked_ips,
            qkey_registry,
            admin_web_bootstrap,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_initialized_standalone_default(
        engine_config: EngineConfig,
        server_config: ServerConfig,
        tun_config: Option<TunConfig>,
        opt_params: crate::optimize::OptimizeConfig,
        config_path: Option<&std::path::Path>,
        admin_log_buffer_override: Option<Arc<self::admin_logs::AdminLogBuffer>>,
        qkey_ttl_override: Option<u64>,
        qkey_store_override: Option<std::path::PathBuf>,
    ) -> std::io::Result<Self> {
        let bootstrap = initialize_standalone_server_bootstrap(
            config_path,
            admin_log_buffer_override,
            qkey_ttl_override,
            qkey_store_override,
        );
        Self::new_standalone_with_bootstrap(
            engine_config,
            server_config,
            tun_config,
            opt_params,
            bootstrap,
        )
    }

    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.state != ServerState::Stopped {
            return Err(EngineError::InvalidState(
                crate::engine::EngineState::Running,
                "start (already running)",
            ));
        }

        self.state = ServerState::Starting;
        self.shutdown.store(false, Ordering::SeqCst);

        if self.live.is_none() {
            match ServerHostResources::start(
                &self.engine_config,
                &self.server_config,
                self.pool.clone(),
            ) {
                Ok(resources) => {
                    self.host_resources = Some(resources);
                }
                Err(error) => {
                    self.state = ServerState::Stopped;
                    return Err(error);
                }
            }
            log::info!(
                "Embedded server runtime started on {} with TUN/routing ownership prepared",
                self.server_config.listen
            );
        } else {
            log::info!(
                "Standalone server runtime started on {} with TUN/routing ownership prepared",
                self.server_config.listen
            );
        }

        self.state = ServerState::Running;

        Ok(())
    }

    /// Stop the server.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        if self.state == ServerState::Stopped {
            return Ok(());
        }

        self.state = ServerState::Stopping;
        self.shutdown.store(true, Ordering::SeqCst);

        // Close all sessions
        for id in self.domain.all_session_ids() {
            self.domain.remove(id);
        }

        if let Some(resources) = self.host_resources.take() {
            resources.teardown();
        }

        self.state = ServerState::Stopped;
        log::info!("Server stopped");

        Ok(())
    }

    /// Handle new client connection.
    pub fn accept_client(&self, remote_addr: SocketAddr) -> Result<SessionId, AcceptError> {
        let (session_id, _stats, client_ip) = {
            match self.domain.accept(remote_addr) {
                Ok(value) => value,
                Err(error) => {
                    self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
                    return Err(error);
                }
            }
        };

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

        log::info!("Client connected: {} -> {}", remote_addr, client_ip);

        Ok(session_id)
    }

    /// Remove client session.
    pub fn remove_client(&self, session_id: SessionId) {
        let session = self.domain.remove(session_id);

        if let Some(session) = session {
            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            log::info!(
                "Client disconnected: {} (IP: {})",
                session.remote_addr(),
                session.client_ip()
            );
        }
    }

    pub fn traffic_snapshot(&self) -> ServerTrafficSnapshot {
        let domain_snapshot = self.domain.traffic_snapshot();
        ServerTrafficSnapshot {
            active_connections: domain_snapshot.active_connections,
            total_connections: self.stats.total_connections.load(Ordering::Relaxed),
            connections_rejected: self.stats.connections_rejected.load(Ordering::Relaxed),
            bytes_in: domain_snapshot.bytes_in,
            bytes_out: domain_snapshot.bytes_out,
            packets_in: domain_snapshot.packets_in,
            packets_out: domain_snapshot.packets_out,
        }
    }

    pub fn reap_expired_sessions(&self) -> usize {
        let removed = self.domain.reap_expired();
        let removed_len = removed.len();
        if removed_len == 0 {
            return 0;
        }
        self.stats.active_connections.fetch_sub(removed_len as u64, Ordering::Relaxed);
        removed_len
    }

    /// Get server state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Get server statistics.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Get session count.
    pub fn session_count(&self) -> usize {
        self.domain.session_count()
    }

    pub fn session_stats(&self, session_id: SessionId) -> Option<Arc<SessionStats>> {
        self.domain.session_stats(session_id)
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    // SAFETY: `live` is always `Some` after standalone-mode construction.
    // Callers are exclusively standalone-mode methods; `None` here is a logic bug.
    fn live(&self) -> &ServerLiveRuntime {
        self.live.as_ref().expect("standalone live runtime is only available in standalone mode")
    }

    // SAFETY: `live` is always `Some` after standalone-mode construction.
    // Callers are exclusively standalone-mode methods; `None` here is a logic bug.
    fn live_mut(&mut self) -> &mut ServerLiveRuntime {
        self.live.as_mut().expect("standalone live runtime is only available in standalone mode")
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.live().socket.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.live().local_addr
    }

    pub fn standalone_metrics(&self) -> Arc<Metrics> {
        self.live().metrics.clone()
    }

    pub fn admin_actions_sender(&self) -> mpsc::UnboundedSender<AdminAction> {
        self.live().admin_actions_tx.clone()
    }

    pub fn live_client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        self.live().live_state.client_snapshots()
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<String>>> {
        &self.live().blocked_ips
    }

    pub fn qkey_registry(&self) -> &Arc<std::sync::Mutex<QKeyRegistry>> {
        &self.live().qkey_registry
    }

    fn admin_web_bootstrap(&self) -> &StandaloneAdminWebBootstrap {
        &self.live().admin_web_bootstrap
    }

    fn make_admin_core(&self) -> ServerAdminCore {
        ServerAdminCore::new(
            self.standalone_metrics(),
            self.blocked_ips().clone(),
            self.live_client_snapshots().clone(),
            self.admin_actions_sender(),
            self.local_addr().to_string(),
            self.live()
                .standalone_runtime_metadata
                .as_ref()
                .map(|metadata| metadata.front_domain.clone())
                .unwrap_or_default(),
            self.qkey_registry().clone(),
        )
    }

    #[cfg(unix)]
    fn start_admin_socket_service(&mut self, path: std::path::PathBuf) {
        let admin_core = self.make_admin_core();
        start_standalone_admin_service(self, path, admin_core);
    }

    #[allow(clippy::too_many_arguments)]
    fn start_admin_web_service(
        &mut self,
        addr: std::net::SocketAddr,
        web_root: std::path::PathBuf,
        admin_web_user: Option<String>,
        admin_web_password: Option<String>,
    ) -> std::io::Result<()> {
        let admin_web_bootstrap = self.admin_web_bootstrap().clone();
        let admin_core = self.make_admin_core();
        let config_path = self
            .live()
            .standalone_runtime_metadata
            .as_ref()
            .and_then(|metadata| metadata.config_path.clone());
        start_configured_standalone_admin_web_service(
            self,
            addr,
            web_root,
            admin_web_user,
            admin_web_password,
            config_path.as_deref(),
            admin_web_bootstrap.blocked_ips_path,
            admin_web_bootstrap.initial_logging_mode,
            admin_core,
            admin_web_bootstrap.admin_log_buffer,
        )
    }

    fn start_standalone_services(
        &mut self,
        config: StandaloneServiceConfig,
    ) -> std::io::Result<()> {
        if let Some(port) = config.metrics_port {
            start_standalone_metrics_service(self, port);
        }

        #[cfg(unix)]
        if let Some(path) = config.admin_socket {
            self.start_admin_socket_service(path);
        }
        #[cfg(not(unix))]
        let _ = config.admin_socket;

        if let Some(addr) = config.admin_web {
            self.start_admin_web_service(
                addr,
                config.admin_web_root,
                config.admin_web_user,
                config.admin_web_password,
            )?;
        }

        Ok(())
    }

    #[cfg(feature = "rate_limiter")]
    pub fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        self.live().live_state.allow_incoming_datagram(from, len)
    }

    fn live_parts(&mut self) -> ServerRuntimeLiveParts<'_> {
        let live = self.live_mut();
        ServerRuntimeLiveParts {
            live_state: &mut live.live_state,
            accept_loop: &live.accept_loop,
            accept_max_clients: live.accept_max_clients,
            server_tun: live.server_tun.as_ref(),
        }
    }

    pub fn register_admin_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.admin = Some(signal);
    }

    pub fn register_admin_web_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.admin_web = Some(signal);
    }

    pub fn register_metrics_shutdown(&mut self, signal: Arc<AtomicBool>) {
        self.live_mut().service_signals.metrics = Some(signal);
    }

    fn sync_standalone_runtime_metadata(&mut self, metadata: &StandaloneRuntimeMetadata) {
        self.live_mut().standalone_runtime_metadata = Some(metadata.clone());
    }

    fn ensure_standalone_runtime_metadata(&mut self, metadata: &StandaloneRuntimeMetadata) {
        if self.live().standalone_runtime_metadata.is_none() {
            self.sync_standalone_runtime_metadata(metadata);
        }
    }

    async fn run_loop(
        &mut self,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) -> std::io::Result<()> {
        let profiles = runtime_config.profiles.clone();
        let profile_interval_secs = runtime_config.profile_interval_secs;
        let stealth_policy = runtime_config.stealth_policy.as_runtime_policy();
        let standalone_runtime_metadata = runtime_config.standalone_runtime_metadata.clone();
        let tun_enable = runtime_config.tun_enable;
        let profile = stealth_policy.profile;
        let os = stealth_policy.os;
        let disable_doh = stealth_policy.disable_doh;
        let doh_provider = stealth_policy.doh_provider.to_string();
        let disable_fronting = stealth_policy.disable_fronting;
        let front_domain = stealth_policy.front_domain.to_vec();
        let disable_http3 = stealth_policy.disable_http3;
        if self.state != ServerState::Stopped {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "server runtime already started",
            ));
        }

        self.start()
            .map_err(|error| std::io::Error::other(format!("server loop start failed: {error}")))?;

        self.ensure_standalone_runtime_metadata(&standalone_runtime_metadata);
        if !profiles.is_empty() {
            start_runtime_profile_rotation(
                runtime_config.stealth_config.clone(),
                profiles,
                profile_interval_secs,
            );
        }

        let metrics = self.standalone_metrics();
        let socket = self.socket();
        let local_addr = self.local_addr();
        let blocked_ips = self.blocked_ips().clone();
        let qkey_registry = self.qkey_registry().clone();
        let mut admin_actions_rx = self
            .live_mut()
            .admin_actions_rx
            .take()
            .ok_or_else(|| std::io::Error::other("server admin action receiver unavailable"))?;
        // Take the TUN reader channel (if any) for forwarding TUN→client datagrams.
        let mut tun_rx = self.live_mut().tun_rx.take();
        let mut buf = [0; 65535];
        let mut out = [0; 1460];
        let mut housekeeping = tokio::time::interval(Duration::from_millis(5));
        housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Create shared 0-RTT anti-replay strike register if early data is enabled.
        if runtime_config.transport.is_early_data_enabled()
            && runtime_config.strike_register.is_none()
        {
            use crate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};
            let ar_section = &runtime_config.anti_replay_section;
            if ar_section.enabled {
                let ar_config = AntiReplayConfig {
                    max_ticket_age: std::time::Duration::from_secs(ar_section.max_ticket_age_secs),
                    max_entries: ar_section.max_entries,
                    max_early_data_size: ar_section.max_early_data_size,
                    ..AntiReplayConfig::default()
                };
                // Set configurable max_early_data_size for new TLS server connections.
                crate::qftls::set_max_early_data_size(ar_config.max_early_data_size);
                let register = Arc::new(StrikeRegister::new(ar_config));
                runtime_config.transport.set_strike_register(register.clone());
                runtime_config.strike_register = Some(register);
                log::info!(
                    "[server] 0-RTT anti-replay strike register created \
                     (max_entries={}, max_age={}s, max_early_data={}B)",
                    ar_section.max_entries,
                    ar_section.max_ticket_age_secs,
                    ar_section.max_early_data_size,
                );
            } else {
                log::warn!(
                    "[server] 0-RTT anti-replay protection disabled by config \
                     (anti_replay.enabled=false) - replay attacks are possible"
                );
            }
        }

        loop {
            tokio::select! {
                    Some(action) = admin_actions_rx.recv() => {
                        let should_shutdown = self.handle_admin_action_with_runtime_reload(
                            action,
                            &metrics,
                            runtime_config,
                        );
                        if should_shutdown {
                            break;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        log::info!("Shutdown signal received");
                        self.shutdown_live(b"ctrl_c");
                        break;
                    }
                    recv_res = recv_datagram_from(&socket, &mut buf) => {
                        match recv_res {
                            Ok((len, from)) => {
                                eprintln!("[DEBUG] run_loop recv {} bytes from {}", len, from);
                                crate::telemetry!(crate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                                metrics.record_ingress_datagram(len);

                                let ip_str = from.ip().to_string();
                                if blocked_ips.read().contains(&ip_str) {
                                    metrics.record_connection_rejected();
                                    continue;
                                }
                                #[cfg(feature = "rate_limiter")]
                                {
                                    if !self.allow_incoming_datagram(from, len) {
                                        metrics.record_rate_limited();
                                        continue;
                                    }
                                }

                                let runtime_parts = self.live_parts();
                                let client_snapshots = runtime_parts.live_state.client_snapshots().clone();
                                let stealth_config = runtime_config.stealth_config.clone();
                                let fec_cfg_shared = runtime_config.fec_cfg_shared.clone();
                                let opt_params_shared = runtime_config.opt_params_shared.clone();
                                let transport = &mut runtime_config.transport;
                                let runtime_client = match runtime_parts.live_state.acquire_runtime_client_with(
                                    from,
                                    &buf[..len],
                                    runtime_parts.accept_loop,
                                    runtime_parts.accept_max_clients,
                                    &metrics,
                                    || {
                                        build_live_server_client_init(
                                            LiveClientBuildRequest {
                                                packet: &buf[..len],
                                                local_addr,
                                                remote_addr: from,
                                                qkey_registry: qkey_registry.as_ref(),
                                                metrics: &metrics,
                                                stealth_config: &stealth_config,
                                                fec_cfg_shared: &fec_cfg_shared,
                                                opt_params_shared: &opt_params_shared,
                                            transport_config: transport,
                                            profile,
                                            os,
                                            disable_doh,
                                            doh_provider: doh_provider.as_str(),
                                            disable_fronting,
                                            front_domain: &front_domain,
                                            disable_http3,
                                        },
                                    )
                                },
                                ) {
                                    LiveClientAcquire::Ready(v) => {
                                        eprintln!("[DEBUG] acquired Ready client for {}", from);
                                        v
                                    },
                                    LiveClientAcquire::Backpressure => {
                                        eprintln!("[DEBUG] Backpressure for {}", from);
                                        tokio::time::sleep(runtime_parts.accept_loop.backpressure_delay()).await;
                                        continue;
                                    }
                                    LiveClientAcquire::Rejected => {
                                        eprintln!("[DEBUG] Rejected client {}", from);
                                        continue;
                                    }
                                };

                                let datagram_result = match process_live_server_client_datagram(
                                    &socket,
                                    from,
                                    runtime_client,
                                    &buf[..len],
                                    &mut out,
                                    &metrics,
                                    &client_snapshots,
                                    runtime_parts.server_tun,
                                    tun_enable,
                                ).await {
                                    Ok(result) => result,
                                    Err(e) => {
                                        log::warn!("Failed to process live packet for {}: {}", from, e);
                                        LiveClientDatagramResult {
                                            auth_result: None,
                                            remove_auth_conn_id: None,
                                        }
                                    }
                                };
                                runtime_parts.live_state.commit_qkey_auth_result(
                                    datagram_result.remove_auth_conn_id,
                                    datagram_result.auth_result,
                                );
                            }
                            Err(e) => {
                                log::error!("Failed to read from socket: {}", e);
                            }
                        }
                    }
                    _ = housekeeping.tick() => {
                                let runtime_parts = self.live_parts();
                        runtime_parts.live_state
                            .run_housekeeping_tick(
                                &socket,
                                &mut out,
                                &metrics,
                                runtime_parts.accept_loop,
                            )
                            .await;
                        // Forward TUN→client: drain any packets from the TUN reader thread
                        // and send them to the first connected client via QUIC datagrams.
                        if let Some(ref rx) = tun_rx {
                            for _ in 0..32 {
                                match rx.try_recv() {
                                    Ok(pkt) => {
                                        let live = self.live_mut();
                                        // Send to the first active client (simple VPN model: 1 TUN ↔ 1 client).
                                        if let Some((addr, conn)) = live.live_state.clients.iter_mut().next() {
                                            let addr = *addr;
                                            if let Err(e) = conn.conn.dgram_send(&pkt) {
                                                log::debug!("TUN→dgram_send to {}: {:?}", addr, e);
                                            }
                                        }
                                        // Flush outgoing for all clients after queuing dgrams
                                        let live = self.live_mut();
                                        let live_state = &mut live.live_state;
                                        for (addr, conn) in live_state.clients.iter_mut() {
                                            let addr = *addr;
                                            loop {
                                                let written = match conn.send(&mut out) {
                                                    Ok(0) => break,
                                                    Ok(n) => n,
                                                    Err(_) => break,
                                                };
                                                if let Err(e) = socket.try_send_to(&out[..written], addr) {
                                                    log::debug!("TUN→socket send to {}: {:?}", addr, e);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                        tun_rx = None;
                                        break;
                                    }
                                }
                            }
                        }
                        // Sweep expired entries from 0-RTT anti-replay strike register.
                        if let Some(ref sr) = runtime_config.strike_register {
                            sr.cleanup(std::time::Instant::now());
                        }
            tokio::task::yield_now().await;
                    }
                }
        }

        self.live_mut().admin_actions_rx = Some(admin_actions_rx);
        if let Err(error) = self.stop() {
            log::warn!("ServerRuntime shutdown during loop exit failed: {}", error);
        }

        Ok(())
    }

    pub async fn run_standalone(
        &mut self,
        launch: PreparedStandaloneLaunch,
    ) -> std::io::Result<()> {
        let PreparedStandaloneLaunch { services, mut runtime } = launch;
        let service_config = services.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "standalone launch services already consumed",
            )
        })?;
        self.sync_standalone_runtime_metadata(&runtime.standalone_runtime_metadata);
        self.start_standalone_services(service_config)?;
        self.run_loop(&mut runtime).await
    }

    pub fn handle_admin_action<F>(
        &mut self,
        action: AdminAction,
        metrics: &Arc<Metrics>,
        reload: F,
    ) -> bool
    where
        F: FnOnce() -> Result<(), String>,
    {
        match action {
            AdminAction::Kick(id) => {
                if let Some(identity) = ClientIdentity::parse(&id) {
                    let live = self.live_mut();
                    live.live_state.kick_client(&identity, &live.accept_loop, metrics);
                }
                false
            }
            AdminAction::Reload => {
                if let Err(error) = reload() {
                    log::warn!("Config reload failed: {}", error);
                }
                false
            }
            AdminAction::Shutdown => {
                log::info!("Admin shutdown requested");
                self.shutdown_live(b"admin_shutdown");
                true
            }
        }
    }

    fn handle_admin_action_with_runtime_reload(
        &mut self,
        action: AdminAction,
        metrics: &Arc<Metrics>,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) -> bool {
        let runtime_metadata = self.live().standalone_runtime_metadata.clone();
        self.handle_admin_action(action, metrics, || {
            let Some(runtime_metadata) = runtime_metadata.as_ref() else {
                return Err(
                    "Config reload requested but runtime metadata is unavailable".to_string()
                );
            };
            let Some(cfg_path) = runtime_metadata.config_path.as_deref() else {
                return Err("Config reload requested but no config path is set".to_string());
            };
            apply_runtime_config_reload(
                cfg_path,
                runtime_metadata.reload_policy.fec_mode_override,
                &mut runtime_config.transport,
                &runtime_config.fec_cfg_shared,
                &runtime_config.opt_params_shared,
                &runtime_config.stealth_config,
                runtime_metadata.reload_policy.stealth_policy.as_runtime_policy(),
            )
        })
    }

    pub fn shutdown_live(&mut self, reason: &'static [u8]) {
        let live = self.live_mut();
        live.service_signals.shutdown_all();
        live.accept_loop.shutdown();
        live.live_state.shutdown_all(reason);
    }
}

impl Drop for ServerRuntime {
    fn drop(&mut self) {
        if self.state != ServerState::Stopped {
            if let Err(e) = self.stop() {
                log::warn!("ServerRuntime drop cleanup failed: {}", e);
            }
        }
    }
}

/// Errors when accepting a client.
#[derive(Debug, Clone)]
pub enum AcceptError {
    MaxClientsReached,
    TooManyConnectionsPerIp,
    IpPoolExhausted,
    SessionError(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::MaxClientsReached => write!(f, "Maximum clients reached"),
            AcceptError::TooManyConnectionsPerIp => write!(f, "Too many connections from this IP"),
            AcceptError::IpPoolExhausted => write!(f, "IP pool exhausted"),
            AcceptError::SessionError(e) => write!(f, "Session error: {}", e),
        }
    }
}

impl std::error::Error for AcceptError {}

impl From<SessionError> for AcceptError {
    fn from(e: SessionError) -> Self {
        AcceptError::SessionError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.max_clients, 100);
        assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
    }

    #[test]
    fn test_server_runtime_new() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_server_runtime_traffic_snapshot_aggregates_session_stats() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let session_id = runtime.accept_client("127.0.0.1:54321".parse().unwrap()).unwrap();
        let stats = runtime.session_stats(session_id).unwrap();
        stats.record_received(120);
        stats.record_sent(64);
        stats.record_sent(32);

        let snapshot = runtime.traffic_snapshot();
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.bytes_in, 120);
        assert_eq!(snapshot.bytes_out, 96);
        assert_eq!(snapshot.packets_in, 1);
        assert_eq!(snapshot.packets_out, 2);
    }

    #[test]
    fn test_server_runtime_reaps_expired_sessions() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        runtime.accept_client("127.0.0.1:54322".parse().unwrap()).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(runtime.session_count(), 1);
        assert_eq!(runtime.reap_expired_sessions(), 1);
        assert_eq!(runtime.session_count(), 0);
    }

    #[test]
    fn test_live_server_domain_resolves_session_identity_to_remote_addr() {
        let remote_addr = "127.0.0.1:54322".parse().unwrap();
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let (session_id, _) = domain.accept(remote_addr).unwrap();

        assert_eq!(
            domain.remote_addr_for_identity(&ClientIdentity::Session(session_id)),
            Some(remote_addr)
        );
        assert_eq!(domain.session_id_by_remote(remote_addr), Some(session_id));
    }

    #[test]
    fn test_live_state_kick_client_accepts_canonical_session_identity() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
        let (session_id, _) = live_state.domain.accept(remote_addr).unwrap();
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"admin-kick-sess-id"),
        )
        .expect("live server connection must be creatable");

        live_state.clients.insert(remote_addr, connection);
        live_state.kick_client(&ClientIdentity::Session(session_id), &accept_loop, &metrics);

        assert!(!live_state.clients.contains_key(&remote_addr));
        assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
        assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "rate_limiter")]
    #[test]
    fn test_live_server_domain_remove_remote_clears_packet_rate_limit_ip_state() {
        let remote_addr = "127.0.0.1:54323".parse().unwrap();
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let _ = domain.accept(remote_addr).unwrap();
        *domain.shared.packet_rate_limiter.lock() = PacketRateLimiterDomain {
            limiter: RateLimiter::new(crate::implementations::server::limits::RateLimitConfig {
                max_pps: 1,
                max_bps: 0,
                refill_interval: Duration::from_secs(60),
            }),
            last_prune: Instant::now(),
        };

        assert!(domain.allow_incoming_datagram(remote_addr, 64));
        assert!(!domain.allow_incoming_datagram(remote_addr, 64));

        domain.remove_remote(remote_addr);

        assert!(domain.allow_incoming_datagram(remote_addr, 64));
    }

    #[tokio::test]
    async fn test_housekeeping_tick_reaps_expired_sessions_from_runtime_lifecycle() {
        let server_config = ServerConfig { client_timeout_secs: 1, ..ServerConfig::default() };
        let mut live_state = LiveServerState::new(server_config);
        let remote_addr = "127.0.0.1:54324".parse().unwrap();
        let (session_id, _) = live_state.domain.accept(remote_addr).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let mut out = [0; 1460];

        assert_eq!(live_state.domain.session_id_by_remote(remote_addr), Some(session_id));
        tokio::time::sleep(Duration::from_secs(2)).await;

        live_state.run_housekeeping_tick(&socket, &mut out, &metrics, &accept_loop).await;

        assert_eq!(live_state.domain.session_id_by_remote(remote_addr), None);
        assert_eq!(live_state.domain.active_session_count(), 0);
        assert_eq!(metrics.clients_active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_standalone_runtime_shutdown_trips_registered_service_signals() {
        let server_config =
            ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(16, None, None)));
        let mut runtime = ServerRuntime::new_standalone_default(
            EngineConfig::default(),
            server_config,
            None,
            crate::optimize::OptimizeConfig::default(),
            blocked_ips,
            qkey_registry,
            StandaloneAdminWebBootstrap::default(),
        )
        .unwrap();
        let admin = Arc::new(AtomicBool::new(false));
        let admin_web = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(AtomicBool::new(false));

        runtime.register_admin_shutdown(admin.clone());
        runtime.register_admin_web_shutdown(admin_web.clone());
        runtime.register_metrics_shutdown(metrics.clone());
        runtime.shutdown_live(b"test_shutdown");

        assert!(admin.load(Ordering::SeqCst));
        assert!(admin_web.load(Ordering::SeqCst));
        assert!(metrics.load(Ordering::SeqCst));
    }

    #[test]
    fn test_server_config_from_listen_addr_resolves_socket() {
        let config = server_config_from_listen_addr("127.0.0.1:4433").unwrap();
        assert_eq!(config.listen, "127.0.0.1:4433".parse().unwrap());
    }

    #[test]
    fn test_apply_runtime_profile_identity_updates_browser_and_os() {
        let mut stealth = StealthConfig::default();
        apply_runtime_profile_identity(&mut stealth, BrowserProfile::Firefox, OsProfile::Linux);
        assert_eq!(stealth.initial_browser, BrowserProfile::Firefox);
        assert_eq!(stealth.initial_os, OsProfile::Linux);
    }

    #[test]
    fn test_resolve_qkey_ttl_secs_zero_disables_registry_expiry() {
        assert_eq!(resolve_qkey_ttl_secs(Some(0)), None);
        assert_eq!(resolve_qkey_ttl_secs(Some(120)), Some(120));
    }

    #[test]
    fn test_normalize_qkey_fec_rejects_unknown_mode() {
        assert!(normalize_qkey_fec(Some("turbo")).is_err());
        assert!(normalize_qkey_fec(Some("manual")).is_err());
        assert!(normalize_qkey_fec(Some("on")).is_err());
    }

    #[test]
    fn test_resolve_admin_web_auth_rejects_weak_defaults_without_override() {
        let err = resolve_admin_web_auth(Some("admin".to_string()), Some("123".to_string()))
            .expect_err("weak defaults must be rejected unless explicitly enabled");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("Refusing weak default admin credentials [admin/123]"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_resolve_admin_auth_store_path_defaults_under_config_local() {
        let path = resolve_admin_auth_store_path(None);
        assert_eq!(path, std::path::PathBuf::from("config/local/admin-auth.json"));
    }

    #[test]
    fn test_resolve_qkey_store_path_defaults_under_config_local() {
        let path = resolve_qkey_store_path(None, None);
        assert_eq!(path, std::path::PathBuf::from("config/local/qkeys.json"));
    }

    #[test]
    fn test_load_persisted_blocked_ips_defaults_empty_without_config() {
        assert!(load_persisted_blocked_ips(None).is_empty());
    }

    #[test]
    fn test_load_persisted_logging_mode_defaults_to_normal_without_config() {
        assert_eq!(load_persisted_logging_mode(None), "normal");
    }

    #[test]
    fn test_record_qkey_auth_rejection_updates_exported_metrics() {
        let metrics = Metrics::new();
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = metrics.auth_failed.load(Ordering::Relaxed);

        record_qkey_auth_rejection(&metrics);

        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before + 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), auth_failed_before + 1);
    }

    #[test]
    fn test_enforce_qkey_auth_timeouts_updates_exported_auth_failed_metrics() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54325".parse().unwrap();
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"auth-metric-timeout"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = metrics.auth_failed.load(Ordering::Relaxed);

        live_state.clients.insert(remote_addr, connection);
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                expected_token_sha256: "deadbeef".to_string(),
                authed: false,
                connected_at: Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(1)),
            },
        );

        live_state.enforce_qkey_auth_timeouts(&metrics);

        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before + 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), auth_failed_before + 1);
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
    }

    #[test]
    fn test_read_logging_mode_reports_current_mode() {
        let logging_mode = parking_lot::RwLock::new("minimal".to_string());
        let response = read_logging_mode(&logging_mode);
        assert!(response.success);
        assert_eq!(
            response.data.as_ref().and_then(|v| v.get("mode")),
            Some(&serde_json::json!("minimal"))
        );
    }

    #[tokio::test]
    async fn test_run_loop_stops_from_admin_shutdown_without_start() {
        let server_config =
            ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
        let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(16, None, None)));
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let mut runtime = ServerRuntime::new_standalone_default(
            EngineConfig::default(),
            server_config,
            None,
            crate::optimize::OptimizeConfig::default(),
            blocked_ips,
            qkey_registry,
            StandaloneAdminWebBootstrap::default(),
        )
        .unwrap();

        let transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let mut runtime_config = PreparedStandaloneRuntimeConfig::new(
            None,
            transport,
            FecConfig::default(),
            OptimizeConfig::default(),
            StealthConfig::default(),
            None,
            vec![FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Linux)],
            0,
            OwnedRuntimeStealthPolicy::from_runtime_policy(RuntimeStealthPolicy {
                profile: BrowserProfile::Chrome,
                os: OsProfile::Linux,
                disable_doh: true,
                doh_provider: "",
                disable_fronting: true,
                front_domain: &[],
                disable_http3: true,
            }),
            false,
        );
        let shutdown_sender = runtime.admin_actions_sender();

        let trigger = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            shutdown_sender.send(AdminAction::Shutdown).expect("admin sender closed");
        });

        let run_loop_result =
            tokio::time::timeout(Duration::from_secs(1), runtime.run_loop(&mut runtime_config))
                .await;

        assert!(trigger.await.is_ok());
        let result = run_loop_result.expect("run loop should finish within timeout");
        assert!(result.is_ok());
        assert_eq!(runtime.state, ServerState::Stopped);
    }

    // --- Session lifecycle tests ---

    #[test]
    fn test_accept_client_assigns_unique_session_ids() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:10001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:10002".parse().unwrap()).unwrap();
        let id3 = runtime.accept_client("127.0.0.1:10003".parse().unwrap()).unwrap();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
        assert_eq!(runtime.session_count(), 3);
    }

    #[test]
    fn test_remove_client_decrements_session_count() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:20001".parse().unwrap()).unwrap();
        let _id2 = runtime.accept_client("127.0.0.1:20002".parse().unwrap()).unwrap();
        assert_eq!(runtime.session_count(), 2);

        runtime.remove_client(id1);
        assert_eq!(runtime.session_count(), 1);
    }

    #[test]
    fn test_session_stats_returns_none_for_unknown_id() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        assert!(runtime.session_stats(SessionId::from_u64(99999)).is_none());
    }

    #[test]
    fn test_session_stats_tracks_bytes_after_accept() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let session_id = runtime.accept_client("127.0.0.1:30001".parse().unwrap()).unwrap();
        let stats = runtime.session_stats(session_id).unwrap();
        stats.record_received(256);
        stats.record_sent(128);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 256);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 128);
    }

    // --- Connection limits tests ---

    #[test]
    fn test_accept_rejects_when_max_clients_reached() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 2, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        runtime.accept_client("127.0.0.1:40001".parse().unwrap()).unwrap();
        runtime.accept_client("127.0.0.1:40002".parse().unwrap()).unwrap();

        let result = runtime.accept_client("127.0.0.1:40003".parse().unwrap());
        assert!(result.is_err(), "third client should be rejected");
        if let Err(AcceptError::MaxClientsReached) = result {
            // expected
        } else {
            panic!("expected MaxClientsReached, got {:?}", result.err());
        }
    }

    #[test]
    fn test_accept_rejects_per_ip_limit() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 100, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        // Accept connections from the same IP with different ports up to the per-IP limit.
        // DEFAULT_MAX_CONNECTIONS_PER_IP is typically small (e.g. 5).
        let limit = DEFAULT_MAX_CONNECTIONS_PER_IP;
        for port in 0..limit {
            let addr_str = format!("10.0.0.1:{}", 50000 + port);
            runtime.accept_client(addr_str.parse().unwrap()).unwrap();
        }

        let over_limit = format!("10.0.0.1:{}", 50000 + limit);
        let result = runtime.accept_client(over_limit.parse().unwrap());
        assert!(result.is_err(), "should reject after per-IP limit exceeded");
        if let Err(AcceptError::TooManyConnectionsPerIp) = result {
            // expected
        } else {
            panic!("expected TooManyConnectionsPerIp, got {:?}", result.err());
        }
    }

    // --- Graceful shutdown tests ---

    #[test]
    fn test_server_runtime_start_stop_lifecycle() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        assert_eq!(runtime.state(), ServerState::Stopped);
        assert!(!runtime.is_shutdown());
    }

    #[test]
    fn test_remove_all_clients_clears_session_count_to_zero() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:14001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:14002".parse().unwrap()).unwrap();
        assert_eq!(runtime.session_count(), 2);

        runtime.remove_client(id1);
        runtime.remove_client(id2);
        assert_eq!(runtime.session_count(), 0);
    }

    // --- Metrics / ServerStats tests ---

    #[test]
    fn test_server_stats_rejected_counter_increments_on_limit() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig { max_clients: 1, ..ServerConfig::default() };
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        runtime.accept_client("127.0.0.1:15001".parse().unwrap()).unwrap();
        let _ = runtime.accept_client("127.0.0.1:15002".parse().unwrap());

        assert!(runtime.stats().connections_rejected.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn test_traffic_snapshot_multiple_sessions() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config).unwrap();
        let id1 = runtime.accept_client("127.0.0.1:16001".parse().unwrap()).unwrap();
        let id2 = runtime.accept_client("127.0.0.1:16002".parse().unwrap()).unwrap();
        let stats1 = runtime.session_stats(id1).unwrap();
        let stats2 = runtime.session_stats(id2).unwrap();
        stats1.record_received(100);
        stats1.record_sent(50);
        stats2.record_received(200);
        stats2.record_sent(75);

        let snapshot = runtime.traffic_snapshot();
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.bytes_in, 300);
        assert_eq!(snapshot.bytes_out, 125);
        assert_eq!(snapshot.packets_in, 2);
        assert_eq!(snapshot.packets_out, 2);
    }

    // --- Admin core tests ---

    #[test]
    fn test_server_admin_core_block_unblock_ip() {
        let metrics = Arc::new(Metrics::new());
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let client_snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
        let qkeys = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(16, None, None)));
        let core = ServerAdminCore::new(
            metrics,
            blocked_ips.clone(),
            client_snapshots,
            tx,
            "127.0.0.1:4433".to_string(),
            vec![],
            qkeys,
        );

        let resp = core.block_ip("10.0.0.1");
        assert!(resp.success);
        assert!(blocked_ips.read().contains("10.0.0.1"));

        let resp = core.unblock_ip("10.0.0.1");
        assert!(resp.success);
        assert!(!blocked_ips.read().contains("10.0.0.1"));

        // Unblock non-existent IP should fail
        let resp = core.unblock_ip("10.0.0.99");
        assert!(!resp.success);
    }

    #[test]
    fn test_server_admin_core_list_blocked_ips() {
        let metrics = Arc::new(Metrics::new());
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let client_snapshots = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (tx, _rx) = mpsc::unbounded_channel::<AdminAction>();
        let qkeys = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(16, None, None)));
        let core = ServerAdminCore::new(
            metrics,
            blocked_ips,
            client_snapshots,
            tx,
            "127.0.0.1:4433".to_string(),
            vec![],
            qkeys,
        );

        core.block_ip("10.0.0.3");
        core.block_ip("10.0.0.1");
        core.block_ip("10.0.0.2");

        let resp = core.list_blocked_ips();
        assert!(resp.success);
        let ips = resp.data.as_ref().unwrap()["ips"].as_array().unwrap();
        // Should be sorted
        let ips_vec: Vec<&str> = ips.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(ips_vec, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    }

    // --- Config / path resolution helpers ---

    #[test]
    fn test_resolve_admin_auth_store_path_with_config_path() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_admin_auth_store_path(Some(cfg));
        assert_eq!(path, std::path::PathBuf::from("/etc/quicfuscate/admin-auth.json"));
    }

    #[test]
    fn test_resolve_qkey_store_path_with_override() {
        let override_path = std::path::PathBuf::from("/custom/path/keys.json");
        let path = resolve_qkey_store_path(
            Some(std::path::Path::new("/etc/conf.toml")),
            Some(override_path.clone()),
        );
        assert_eq!(path, override_path);
    }

    #[test]
    fn test_resolve_qkey_store_path_from_config_path() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_qkey_store_path(Some(cfg), None);
        assert_eq!(path, std::path::PathBuf::from("/etc/quicfuscate/server.qkeys.json"));
    }

    #[test]
    fn test_resolve_blocked_ips_store_path_none_without_config() {
        assert!(resolve_blocked_ips_store_path(None).is_none());
    }

    #[test]
    fn test_resolve_blocked_ips_store_path_with_config() {
        let cfg = std::path::Path::new("/etc/quicfuscate/server.toml");
        let path = resolve_blocked_ips_store_path(Some(cfg));
        assert_eq!(path, Some(std::path::PathBuf::from("/etc/quicfuscate/server.blocked.json")));
    }

    // --- QKey helper tests ---

    #[test]
    fn test_normalize_qkey_fec_accepts_valid_presets() {
        assert_eq!(normalize_qkey_fec(Some("auto")).unwrap(), "auto");
        assert_eq!(normalize_qkey_fec(Some("off")).unwrap(), "off");
        assert_eq!(normalize_qkey_fec(Some("zero")).unwrap(), "off");
        assert_eq!(normalize_qkey_fec(None).unwrap(), "auto");
        assert_eq!(normalize_qkey_fec(Some("  ")).unwrap(), "auto");
    }

    #[test]
    fn test_normalize_qkey_stealth_accepts_valid_presets() {
        assert_eq!(normalize_qkey_stealth(Some("auto")).unwrap(), "auto");
        assert_eq!(normalize_qkey_stealth(Some("max")).unwrap(), "max");
        assert_eq!(normalize_qkey_stealth(Some("manual")).unwrap(), "manual");
        assert_eq!(normalize_qkey_stealth(Some("off")).unwrap(), "off");
        assert_eq!(normalize_qkey_stealth(None).unwrap(), "auto");
    }

    #[test]
    fn test_normalize_qkey_stealth_rejects_unknown() {
        assert!(normalize_qkey_stealth(Some("turbo")).is_err());
    }

    #[test]
    fn test_normalize_qkey_name_validates_length_and_chars() {
        assert_eq!(normalize_qkey_name(None).unwrap(), None);
        assert_eq!(normalize_qkey_name(Some("  ")).unwrap(), None);
        assert_eq!(normalize_qkey_name(Some("my-key")).unwrap(), Some("my-key".to_string()));

        // Too long
        let long_name = "a".repeat(65);
        assert!(normalize_qkey_name(Some(&long_name)).is_err());

        // Control chars
        assert!(normalize_qkey_name(Some("bad\x00name")).is_err());
    }

    // --- SNI / domain fronting helpers ---

    #[test]
    fn test_is_valid_sni_host_rejects_bad_values() {
        assert!(!is_valid_sni_host(""));
        assert!(!is_valid_sni_host("  "));
        assert!(!is_valid_sni_host("host:443"));
        assert!(!is_valid_sni_host("https://host.com"));
        assert!(!is_valid_sni_host("host.com/path"));
        assert!(!is_valid_sni_host("host?q=1"));
        assert!(!is_valid_sni_host("user@host"));
        assert!(is_valid_sni_host("cdn.cloudflare.com"));
    }

    #[test]
    fn test_extract_host_from_endpoint_various_formats() {
        assert_eq!(extract_host_from_endpoint("example.com:4433"), Some("example.com".to_string()));
        assert_eq!(
            extract_host_from_endpoint("[::1]:4433"),
            None // IPv6 addresses are not valid SNI hostnames
        );
        assert_eq!(extract_host_from_endpoint(""), None);
        assert_eq!(
            extract_host_from_endpoint("cdn.cloudflare.com"),
            Some("cdn.cloudflare.com".to_string())
        );
    }

    // --- QKeyAuthState tests ---

    #[test]
    fn test_qkey_auth_state_is_expired_when_not_authed_past_timeout() {
        let state = QKeyAuthState {
            expected_token_sha256: "abc".to_string(),
            authed: false,
            connected_at: Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(1)),
        };
        assert!(state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_authed() {
        let state = QKeyAuthState {
            expected_token_sha256: "abc".to_string(),
            authed: true,
            connected_at: Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(10)),
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_recent() {
        let state = QKeyAuthState {
            expected_token_sha256: "abc".to_string(),
            authed: false,
            connected_at: Instant::now(),
        };
        assert!(!state.is_expired());
    }

    // --- Logging mode tests ---

    #[test]
    fn test_write_logging_mode_rejects_invalid_mode() {
        let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
        let logging_mode = parking_lot::RwLock::new("normal".to_string());
        let response = write_logging_mode(None, &logging_mode, &log_buffer, "debug");
        assert!(!response.success);
        assert!(response.message.as_deref().unwrap_or("").contains("Invalid logging mode"));
    }

    #[test]
    fn test_write_logging_mode_accepts_valid_modes() {
        let log_buffer = crate::implementations::server::admin_logs::AdminLogBuffer::new(64);
        let logging_mode = parking_lot::RwLock::new("normal".to_string());
        for mode in &["verbose", "normal", "minimal", "no-log"] {
            let response = write_logging_mode(None, &logging_mode, &log_buffer, mode);
            assert!(response.success, "mode '{}' should be valid", mode);
            assert_eq!(*logging_mode.read(), *mode);
        }
    }

    // --- resolve_qkey_remote tests ---

    #[test]
    fn test_resolve_qkey_remote_without_port_override() {
        let result = resolve_qkey_remote("1.2.3.4:4433", None).unwrap();
        assert_eq!(result, "1.2.3.4:4433");
    }

    #[test]
    fn test_resolve_qkey_remote_with_port_override() {
        let result = resolve_qkey_remote("1.2.3.4:4433", Some(8443)).unwrap();
        assert_eq!(result, "1.2.3.4:8443");
    }

    #[test]
    fn test_resolve_qkey_remote_ipv6_with_port_override() {
        let result = resolve_qkey_remote("[::1]:4433", Some(9999)).unwrap();
        assert_eq!(result, "[::1]:9999");
    }

    #[test]
    fn test_resolve_qkey_remote_empty_address_error() {
        let result = resolve_qkey_remote("", Some(4433));
        assert!(result.is_err());
    }

    // --- apply_runtime_stealth_overrides test ---

    #[test]
    fn test_apply_runtime_stealth_overrides_sets_all_fields() {
        let mut sc = StealthConfig::default();
        let front_domains = vec!["cdn.cloudflare.com".to_string()];
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Firefox,
            OsProfile::Windows,
            true, // disable_doh
            "custom-doh",
            false, // disable_fronting
            &front_domains,
            true, // disable_http3
        );
        assert_eq!(sc.initial_browser, BrowserProfile::Firefox);
        assert_eq!(sc.initial_os, OsProfile::Windows);
        assert!(!sc.enable_doh);
        assert_eq!(sc.doh_provider, "custom-doh");
        assert!(sc.enable_domain_fronting);
        assert_eq!(sc.fronting_domains, front_domains);
        assert!(!sc.enable_http3_masquerading);
    }

    // --- LiveServerDomain session tracking ---

    #[test]
    fn test_live_server_domain_accept_tracks_multiple_remotes() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr1: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:5002".parse().unwrap();
        let (id1, _) = domain.accept(addr1).unwrap();
        let (id2, _) = domain.accept(addr2).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(domain.active_session_count(), 2);
        assert_eq!(domain.session_id_by_remote(addr1), Some(id1));
        assert_eq!(domain.session_id_by_remote(addr2), Some(id2));
    }

    #[test]
    fn test_live_server_domain_remove_remote_clears_session() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr: SocketAddr = "10.0.0.1:5003".parse().unwrap();
        let (id, _) = domain.accept(addr).unwrap();
        assert_eq!(domain.session_id_by_remote(addr), Some(id));

        domain.remove_remote(addr);
        assert_eq!(domain.session_id_by_remote(addr), None);
        assert_eq!(domain.active_session_count(), 0);
    }

    // --- ServerConfig defaults ---

    #[test]
    fn test_server_config_default_dns_servers() {
        let config = ServerConfig::default();
        assert_eq!(config.dns_servers.len(), 2);
        assert_eq!(config.dns_servers[0], Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(config.dns_servers[1], Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn test_server_config_from_listen_addr_rejects_invalid() {
        let result = server_config_from_listen_addr("not_a_valid_address");
        assert!(result.is_err());
    }

    // --- AcceptError Display ---

    #[test]
    fn test_accept_error_display_variants() {
        assert_eq!(AcceptError::MaxClientsReached.to_string(), "Maximum clients reached");
        assert_eq!(
            AcceptError::TooManyConnectionsPerIp.to_string(),
            "Too many connections from this IP"
        );
        assert_eq!(AcceptError::IpPoolExhausted.to_string(), "IP pool exhausted");
        assert_eq!(
            AcceptError::SessionError("test".to_string()).to_string(),
            "Session error: test"
        );
    }

    // --- validate_transport_overrides_from_toml ---

    #[test]
    fn test_validate_transport_overrides_empty_toml_ok() {
        assert!(validate_transport_overrides_from_toml("").is_ok());
    }

    #[test]
    fn test_validate_transport_overrides_valid_cc_algorithm() {
        let toml_str = r#"
[transport]
cc_algorithm = "bbr3"
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_ok());
    }

    #[test]
    fn test_validate_transport_overrides_invalid_cc_algorithm() {
        let toml_str = r#"
[transport]
cc_algorithm = "cubic"
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }

    #[test]
    fn test_validate_transport_overrides_mtu_out_of_range() {
        let toml_str = r#"
[transport]
mtu = 500
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }
}
