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
pub mod auth_frame;
pub mod bandwidth;
#[doc(hidden)]
pub mod fsutil;
pub mod icmp;
mod ip_pool;
pub mod isolation;
mod limits;
pub mod metrics;
pub mod qkey_registry;
pub mod replay_window;
pub mod revocation;
mod routing;
mod session;
pub mod systemd;

pub use accept::{
    AcceptConfig, AcceptDecision, AcceptLoop, AcceptStats, AcceptStatsSnapshot,
    IpConnectionTracker, RejectReason, DEFAULT_MAX_CONNECTIONS_PER_IP,
};
#[cfg(unix)]
pub use admin::AdminServer;
#[cfg(any(test, feature = "rust-tests"))]
pub use admin::DefaultAdminHandler;
pub use admin::{
    snapshots_to_client_info, AdminCommand, AdminHandler, AdminResponse, ClientIdentity,
    ClientInfo, ClientSnapshot,
};
pub use admin_http::{AdminHttpHandler, AdminHttpServer};
pub use bandwidth::{BandwidthLimiter, BandwidthStats, PerClientBandwidthManager, QuotaTracker};
pub use ip_pool::{IpPool, Ipv6Pool};
pub use isolation::{
    AssignedClientIps, ClientIsolationManager, DownlinkRoute, IsolationStats, UplinkDrop,
    UplinkRoute,
};
#[cfg(feature = "rate_limiter")]
pub use limits::load_rate_limit_config_from_env;
#[cfg(feature = "rate_limiter")]
pub use limits::{BlacklistSync, GeoIpBlocker, GeoIpConfig};
pub use limits::{ConnectionLimiter, GlobalRateLimiter, RateLimitConfig, RateLimiter};
#[cfg(any(test, feature = "rust-tests"))]
pub use metrics::GlobalMetricsServer;
pub use metrics::{Metrics, RoutingOutcome, TunDownlinkBackpressureDrop};
pub use routing::{detect_wan_interface, RoutingError, RoutingManager};
pub use session::{Session, SessionError, SessionId, SessionManager, SessionStats};

use self::admin_http::{AdminAuth, IssueQKeyRequest};
use self::qkey_registry::{QKeyEntry, QKeyRecord, QKeyRegistry};
use parking_lot::RwLock;
#[cfg(feature = "rate_limiter")]
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::QuicFuscateConnection;
use crate::engine::{EngineConfig, EngineError};
use crate::fec::FecConfig;
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::optimize::OptimizeConfig;
#[cfg(unix)]
use crate::optimize::ZeroCopyBuffer;
use crate::stealth::{
    BrowserProfile, FingerprintProfile, OsFingerprintProfile, OsProfile, PacketNormalizer,
    StealthConfig, StealthMode,
};

const SERVER_STATS_LOG_INTERVAL: Duration = Duration::from_secs(1);
const LIVE_UDP_DATAGRAM_BUFFER_SIZE: usize = 65_535;
const _: () = assert!(LIVE_UDP_DATAGRAM_BUFFER_SIZE >= 1500);
const MAX_PENDING_TUN_DOWNLINKS: usize = 256;
const MAX_PENDING_TUN_DOWNLINK_BYTES: usize = 384 * 1024;
const MAX_PENDING_TUN_DOWNLINKS_PER_TARGET: usize = 32;
const MAX_PENDING_TUN_DOWNLINK_AGE: Duration = Duration::from_secs(5);
const MAX_MASQUE_DOWNLINK_RESPONSES: usize = 128;
const MAX_MASQUE_DOWNLINK_RESPONSE_BYTES: usize = 192 * 1024;

async fn wait_for_send_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,
        None => std::future::pending::<()>().await,
    }
}

#[derive(Clone, Copy, Debug)]
struct ServerTunIps {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

#[cfg(unix)]
fn record_systemd_notification(state: &str, result: std::io::Result<()>) {
    if let Err(error) = result {
        log::debug!("systemd notification {} failed: {}", state, error);
    }
}

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
    /// IPv6 IP pool start (None = IPv6 disabled)
    pub ipv6_pool_start: Option<Ipv6Addr>,
    /// IPv6 IP pool end
    pub ipv6_pool_end: Option<Ipv6Addr>,
    /// Server IPv6 TUN address
    pub ipv6_server_ip: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64)
    pub ipv6_prefix_len: u8,
    /// IPv6 DNS servers to push
    pub ipv6_dns_servers: Vec<Ipv6Addr>,
    /// Explicit opt-in for direct VPN client-to-client unicast.
    pub allow_client_to_client: bool,
    /// GeoIP-based source-IP blocking config (TODO-459). When a MaxMindDB
    /// database path and blocked countries are configured, incoming
    /// datagrams from those countries are dropped. Gracefully degrades to
    /// allowing all IPs when no database is configured.
    #[cfg(feature = "rate_limiter")]
    pub geoip: limits::GeoIpConfig,
    /// External blacklist synchronizer config (TODO-459). When a sync URL
    /// is configured, the server periodically fetches a plain-text IP list
    /// from that URL and blocks those IPs with TTL-based expiry.
    #[cfg(feature = "rate_limiter")]
    pub blacklist: BlacklistConfig,
}

/// Configuration for the external blacklist synchronizer.
#[cfg(feature = "rate_limiter")]
#[derive(Clone, Debug)]
pub struct BlacklistConfig {
    /// Default TTL for blocked IPs (seconds).
    pub default_ttl_secs: u64,
    /// HTTPS URL to fetch a plain-text IP list from (one IP per line,
    /// `#` comments allowed). `None` = manual blocking only.
    pub sync_url: Option<String>,
    /// Interval between automatic sync fetches (seconds).
    pub sync_interval_secs: u64,
}

#[cfg(feature = "rate_limiter")]
impl Default for BlacklistConfig {
    fn default() -> Self {
        Self { default_ttl_secs: 3600, sync_url: None, sync_interval_secs: 3600 }
    }
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
            ipv6_pool_start: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)),
            ipv6_pool_end: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x00fe)),
            ipv6_server_ip: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001)),
            ipv6_prefix_len: 64,
            ipv6_dns_servers: vec![
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), // Cloudflare
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), // Google
            ],
            allow_client_to_client: false,
            #[cfg(feature = "rate_limiter")]
            geoip: limits::GeoIpConfig::default(),
            #[cfg(feature = "rate_limiter")]
            blacklist: BlacklistConfig::default(),
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
    let mut config = ServerConfig { listen, ..ServerConfig::default() };
    #[cfg(feature = "rate_limiter")]
    {
        config.geoip = load_geoip_config_from_env();
        config.blacklist = load_blacklist_config_from_env();
    }
    Ok(config)
}

fn stateless_version_negotiation_response(
    packet: &[u8],
    supported_versions: &[u32],
) -> Result<Option<Vec<u8>>, crate::error::ConnectionError> {
    if crate::fec::wire::is_framed(packet) {
        return Ok(None);
    }
    crate::transport::packet::server_version_negotiation_response(packet, supported_versions)
}

/// Load GeoIP blocking config from environment variables.
///
/// - `QUICFUSCATE_GEOIP_DB_PATH`: path to a MaxMindDB GeoLite2-Country database.
/// - `QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES`: comma-separated ISO country codes
///   (e.g. "CN,RU,KP").
#[cfg(feature = "rate_limiter")]
fn load_geoip_config_from_env() -> limits::GeoIpConfig {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let db_path = env_string("QUICFUSCATE_GEOIP_DB_PATH").map(PathBuf::from);
    let blocked_countries: HashSet<String> = env_string("QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES")
        .map(|s| s.split(',').map(|c| c.trim().to_uppercase()).filter(|c| !c.is_empty()).collect())
        .unwrap_or_default();

    let config = limits::GeoIpConfig { db_path, blocked_countries };
    if config.is_enabled() {
        log::info!(
            "GeoIP blocking enabled: {} blocked countries, db={}",
            config.blocked_countries.len(),
            config.db_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
        );
    }
    config
}

/// Load external blacklist sync config from environment variables.
///
/// - `QUICFUSCATE_BLACKLIST_SYNC_URL`: HTTPS URL to fetch a plain-text IP list.
/// - `QUICFUSCATE_BLACKLIST_TTL_SECS`: TTL for blocked IPs (default: 3600).
/// - `QUICFUSCATE_BLACKLIST_SYNC_INTERVAL_SECS`: sync interval (default: 3600).
#[cfg(feature = "rate_limiter")]
fn load_blacklist_config_from_env() -> BlacklistConfig {
    let sync_url = env_string("QUICFUSCATE_BLACKLIST_SYNC_URL");
    let default_ttl_secs = std::env::var("QUICFUSCATE_BLACKLIST_TTL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(3600);
    let sync_interval_secs = std::env::var("QUICFUSCATE_BLACKLIST_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(3600);

    let config = BlacklistConfig { default_ttl_secs, sync_url, sync_interval_secs };
    if config.sync_url.is_some() {
        log::info!(
            "Blacklist sync enabled: ttl={}s, interval={}s",
            config.default_ttl_secs,
            config.sync_interval_secs
        );
    }
    config
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
    /// Shared graceful-shutdown state exposed to control planes.
    graceful_shutdown: Arc<GracefulShutdown>,
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
    Draining,
    Stopping,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ShutdownLifecycle {
    Stopped = 0,
    Running = 1,
    Draining = 2,
}

impl ShutdownLifecycle {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Draining,
            _ => Self::Stopped,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Draining => "draining",
        }
    }
}

struct GracefulShutdown {
    lifecycle: AtomicU8,
    grace_ms: AtomicU64,
    drain_started: parking_lot::RwLock<Option<Instant>>,
}

impl GracefulShutdown {
    fn new(grace_ms: u64) -> Self {
        Self {
            lifecycle: AtomicU8::new(ShutdownLifecycle::Stopped as u8),
            grace_ms: AtomicU64::new(grace_ms),
            drain_started: parking_lot::RwLock::new(None),
        }
    }

    fn lifecycle(&self) -> ShutdownLifecycle {
        ShutdownLifecycle::from_u8(self.lifecycle.load(Ordering::Acquire))
    }

    fn set_running(&self) {
        *self.drain_started.write() = None;
        self.lifecycle.store(ShutdownLifecycle::Running as u8, Ordering::Release);
    }

    fn begin_drain(&self) -> bool {
        if self
            .lifecycle
            .compare_exchange(
                ShutdownLifecycle::Running as u8,
                ShutdownLifecycle::Draining as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        *self.drain_started.write() = Some(Instant::now());
        true
    }

    fn set_stopped(&self) {
        *self.drain_started.write() = None;
        self.lifecycle.store(ShutdownLifecycle::Stopped as u8, Ordering::Release);
    }

    fn grace(&self) -> Duration {
        Duration::from_millis(self.grace_ms.load(Ordering::Acquire))
    }

    fn set_grace_ms(&self, grace_ms: u64) {
        self.grace_ms.store(grace_ms, Ordering::Release);
    }

    fn elapsed(&self) -> Duration {
        self.drain_started.read().as_ref().map(|started| started.elapsed()).unwrap_or_default()
    }

    fn deadline_reached(&self) -> bool {
        self.lifecycle() == ShutdownLifecycle::Draining && self.elapsed() >= self.grace()
    }

    fn status_json(&self, active_connections: u64) -> serde_json::Value {
        serde_json::json!({
            "state": self.lifecycle().as_str(),
            "active_connections": active_connections,
            "grace_period_ms": self.grace().as_millis() as u64,
            "drain_elapsed_ms": self.elapsed().as_millis() as u64,
        })
    }
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
    RevokeQKey(String),
    Reload,
    Drain,
    Shutdown,
}

#[derive(Clone)]
struct SharedServerDomain {
    sessions: Arc<RwLock<SessionManager>>,
    forwarding_policy: Arc<ClientIsolationManager>,
    ip_pool: Arc<parking_lot::Mutex<IpPool>>,
    /// IPv6 address pool (None = IPv6 disabled). Allocated lazily from ServerConfig.
    ipv6_pool: Option<Arc<parking_lot::Mutex<Ipv6Pool>>>,
    connection_limiter: Arc<parking_lot::Mutex<ConnectionLimiter>>,
    #[cfg(feature = "rate_limiter")]
    packet_rate_limiter: Arc<parking_lot::Mutex<PacketRateLimiterDomain>>,
    /// Server-wide global rate limiter - caps aggregate PPS across all IPs
    /// to prevent total overload when many sources each stay under the per-IP
    /// limit. Checked before per-IP limiting on the accept hot path.
    #[cfg(feature = "rate_limiter")]
    global_rate_limiter: Arc<GlobalRateLimiter>,
    /// EWMA-based DDoS anomaly detector (TODO-459). When a traffic spike is
    /// detected, per-IP limits are temporarily halved via `limit_multiplier`.
    #[cfg(feature = "rate_limiter")]
    ddos_detector: Arc<crate::implementations::server::limits::EwmaAnomalyDetector>,
    /// GeoIP-based source-IP blocker (TODO-459). Uses `maxminddb` to look up
    /// the country of an incoming IP and reject blocked countries. Gracefully
    /// degrades to allowing all IPs when no database is configured.
    #[cfg(feature = "rate_limiter")]
    geoip_blocker: Arc<crate::implementations::server::limits::GeoIpBlocker>,
    /// External blacklist synchronizer (TODO-459). TTL-based IP blocklist with
    /// optional external feed sync (plain-text IP lists over HTTPS).
    #[cfg(feature = "rate_limiter")]
    blacklist: Arc<crate::implementations::server::limits::BlacklistSync>,
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

#[cfg(target_os = "linux")]
fn configured_routing_manager(
    tun_name: String,
    server_config: &ServerConfig,
) -> Result<RoutingManager, String> {
    let configured_wan = server_config.wan_interface.trim();
    let configured_wan_exists = !configured_wan.is_empty()
        && std::path::Path::new("/sys/class/net").join(configured_wan).exists();
    let wan_interface = if configured_wan_exists {
        configured_wan.to_string()
    } else {
        detect_wan_interface().ok_or_else(|| {
            format!(
                "configured WAN interface {:?} does not exist and no default-route interface was detected",
                server_config.wan_interface
            )
        })?
    };
    let routing = if let Some(ipv6_server_ip) = server_config.ipv6_server_ip {
        RoutingManager::new_dual_stack(
            tun_name,
            server_config.server_ip,
            server_config.server_netmask,
            wan_interface,
            ipv6_server_ip,
            server_config.ipv6_prefix_len,
        )
    } else {
        RoutingManager::new(
            tun_name,
            server_config.server_ip,
            server_config.server_netmask,
            wan_interface,
        )
    };
    Ok(routing.with_client_to_client(server_config.allow_client_to_client))
}

fn teardown_routing_with_retries(routing: RoutingManager) {
    let mut last_error = None;
    for attempt in 1..=3 {
        match routing.teardown() {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(error) => {
                log::warn!("Routing teardown attempt {}/3 failed: {:?}", attempt, error);
                last_error = Some(error);
                if attempt < 3 {
                    std::thread::sleep(Duration::from_millis(100 * attempt as u64));
                }
            }
        }
    }
    if let Some(error) = last_error {
        log::error!("Routing teardown failed after 3 attempts: {:?}", error);
    }
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
            ip6: server_config.ipv6_server_ip,
            prefix6: Some(server_config.ipv6_prefix_len),
        };

        let tun = open_server_tun(tun_config, pool).map_err(EngineError::Tun)?;
        log::info!("Server TUN interface opened: {}", tun.name());

        #[cfg(target_os = "linux")]
        let routing = {
            let routing = configured_routing_manager("qfserver0".to_string(), server_config)
                .map_err(EngineError::Io)?;

            // Clean up stale rules from a crashed previous session before setup.
            routing.cleanup_stale();

            if let Err(e) = routing.setup() {
                let _ = routing.teardown();
                return Err(EngineError::Io(format!("server routing setup failed: {e}")));
            }
            Some(routing)
        };

        #[cfg(not(target_os = "linux"))]
        let routing = None;

        Ok(Self { tun, routing })
    }

    fn teardown(self) {
        if let Some(routing) = self.routing {
            teardown_routing_with_retries(routing);
        }
        log::info!("Closing server TUN: {}", self.tun.name());
        drop(self.tun);
    }
}

impl SharedServerDomain {
    fn new(server_config: &ServerConfig) -> Self {
        // Create IPv6 pool only if both start and end are configured
        let ipv6_pool = match (server_config.ipv6_pool_start, server_config.ipv6_pool_end) {
            (Some(start), Some(end)) => {
                Some(Arc::new(parking_lot::Mutex::new(Ipv6Pool::new(start, end))))
            }
            _ => None,
        };
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new(server_config.max_clients))),
            forwarding_policy: Arc::new(ClientIsolationManager::with_network(
                server_config.server_ip,
                server_config.server_netmask,
                server_config.allow_client_to_client,
            )),
            ip_pool: Arc::new(parking_lot::Mutex::new(IpPool::new(
                server_config.ip_pool_start,
                server_config.ip_pool_end,
            ))),
            ipv6_pool,
            connection_limiter: Arc::new(parking_lot::Mutex::new(ConnectionLimiter::new(
                DEFAULT_MAX_CONNECTIONS_PER_IP,
            ))),
            #[cfg(feature = "rate_limiter")]
            packet_rate_limiter: Arc::new(parking_lot::Mutex::new(PacketRateLimiterDomain {
                limiter: RateLimiter::new(load_rate_limit_config_from_env()),
                last_prune: Instant::now(),
            })),
            #[cfg(feature = "rate_limiter")]
            global_rate_limiter: Arc::new(GlobalRateLimiter::with_default_cap()),
            #[cfg(feature = "rate_limiter")]
            ddos_detector: Arc::new(
                crate::implementations::server::limits::EwmaAnomalyDetector::with_defaults(),
            ),
            #[cfg(feature = "rate_limiter")]
            geoip_blocker: Arc::new(crate::implementations::server::limits::GeoIpBlocker::new(
                server_config.geoip.clone(),
            )),
            #[cfg(feature = "rate_limiter")]
            blacklist: Arc::new(crate::implementations::server::limits::BlacklistSync::new(
                Duration::from_secs(server_config.blacklist.default_ttl_secs),
                server_config.blacklist.sync_url.clone(),
                Duration::from_secs(server_config.blacklist.sync_interval_secs),
            )),
            max_clients: server_config.max_clients,
            client_timeout_secs: server_config.client_timeout_secs,
        }
    }

    fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let accepted = accept_session_in_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
            remote_addr,
            self.max_clients,
            self.client_timeout_secs,
        );
        if let Ok((session_id, _, addresses)) = accepted.as_ref() {
            self.forwarding_policy.assign_client(&session_id.as_u64().to_string(), *addresses);
        }
        accepted
    }

    fn remove(&self, session_id: SessionId) -> Option<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let removed = remove_session_from_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
            session_id,
        );
        if let Some(session) = removed.as_ref() {
            self.forwarding_policy.release_client(AssignedClientIps {
                ipv4: session.client_ip(),
                ipv6: session.client_ipv6(),
            });
        }
        removed
    }

    fn reap_expired(&self) -> Vec<Session> {
        let mut sessions = self.sessions.write();
        let mut pool = self.ip_pool.lock();
        let mut v6_pool = self.ipv6_pool.as_ref().map(|p| p.lock());
        let mut limiter = self.connection_limiter.lock();
        let removed = reap_expired_sessions_from_domain(
            &mut sessions,
            &mut pool,
            v6_pool.as_deref_mut(),
            &mut limiter,
        );
        for session in &removed {
            self.forwarding_policy.release_client(AssignedClientIps {
                ipv4: session.client_ip(),
                ipv6: session.client_ipv6(),
            });
        }
        removed
    }

    #[cfg(feature = "rate_limiter")]
    fn allow_incoming_datagram(&self, from: SocketAddr, len: usize) -> bool {
        // 1. Global server-wide cap: drop if aggregate PPS exceeds the cap,
        //    regardless of source IP. This is checked first so a flood from
        //    many IPs cannot overwhelm the host even if each is under its
        //    per-IP limit.
        if !self.global_rate_limiter.check() {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 2. GeoIP blocking (TODO-459): drop if the source IP maps to a blocked
        //    country. Gracefully allows all IPs when no database is configured.
        if self.geoip_blocker.is_blocked(from.ip()) {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 3. External blacklist (TODO-459): drop if the source IP is on the
        //    TTL-based blocklist (manual or from an external feed).
        if self.blacklist.is_blocked(from.ip()) {
            crate::instrumentation::global().server.rate_limit_hit();
            return false;
        }
        // 4. Per-IP token bucket. When the DDoS anomaly detector reports a
        //    spike, per-IP limits are temporarily halved by probabilistically
        //    dropping ~50% of packets before the per-IP bucket is consulted.
        if self.ddos_detector.is_anomaly() {
            // Simple deterministic drop: use the low bit of a counter.
            let count = self.global_rate_limiter.accepted.load(Ordering::Relaxed);
            if count & 1 == 1 {
                crate::instrumentation::global().server.rate_limit_hit();
                return false;
            }
        }
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
            // DDoS anomaly detection (TODO-459): feed the EWMA detector with
            // the current global PPS count and prune expired blacklist entries.
            let pps = self.global_rate_limiter.current_pps();
            self.ddos_detector.record_pps(pps);
            self.blacklist.prune_expired();
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
struct ServerAdminControlPlane {
    actions: mpsc::UnboundedSender<AdminAction>,
    listen_addr: String,
    front_domain: Vec<String>,
    qkeys: Arc<std::sync::Mutex<QKeyRegistry>>,
    graceful_shutdown: Arc<GracefulShutdown>,
}

#[derive(Clone)]
pub struct ServerAdminCore {
    metrics: Arc<Metrics>,
    blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
    client_snapshots: Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    control_plane: ServerAdminControlPlane,
}

impl ServerAdminCore {
    fn new(
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<
            std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>,
        >,
        control_plane: ServerAdminControlPlane,
    ) -> Self {
        Self { metrics, blocked_ips, client_snapshots, control_plane }
    }

    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    pub fn blocked_ips(&self) -> &Arc<parking_lot::RwLock<std::collections::HashSet<String>>> {
        &self.blocked_ips
    }

    pub fn listen_addr(&self) -> &str {
        self.control_plane.listen_addr.as_str()
    }

    pub fn qkeys(&self) -> &Arc<std::sync::Mutex<QKeyRegistry>> {
        &self.control_plane.qkeys
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

    pub fn drain(&self) -> AdminResponse {
        self.dispatch_action(AdminAction::Drain, "Drain scheduled".to_string())
    }

    pub fn drain_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(
            self.control_plane
                .graceful_shutdown
                .status_json(self.metrics.clients_active.load(Ordering::Relaxed)),
        )
    }

    pub fn list_clients(&self) -> Vec<ClientInfo> {
        let guard = match self.client_snapshots.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        snapshots_to_client_info(&guard, Instant::now())
    }

    pub fn dispatch_action(&self, action: AdminAction, ok_message: String) -> AdminResponse {
        match self.control_plane.actions.send(action) {
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
        self.control_plane
            .actions
            .send(AdminAction::Reload)
            .map_err(|_| "admin action channel unavailable")
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
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        match issue_unix_admin_qkey(
            &mut registry,
            &self.control_plane.listen_addr,
            &self.control_plane.front_domain,
        ) {
            Ok(qkey) => qkey,
            Err(e) => {
                log::warn!("QKey issuance failed: {}", e);
                String::new()
            }
        }
    }

    pub fn issue_http_qkey(&self, req: &IssueQKeyRequest) -> AdminResponse {
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        let issued = match issue_http_admin_qkey(
            &mut registry,
            &self.control_plane.listen_addr,
            &self.control_plane.front_domain,
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

    pub fn revoke_http_qkey(&self, id: &str) -> AdminResponse {
        let mut registry = self.control_plane.qkeys.lock().unwrap_or_else(|e| e.into_inner());
        if !registry.revoke(id) {
            return AdminResponse::error("QKey not found");
        }
        drop(registry);
        match self.control_plane.actions.send(AdminAction::RevokeQKey(id.to_string())) {
            Ok(()) => AdminResponse::ok_with_message("QKey revoked"),
            Err(_) => {
                AdminResponse::error("QKey revoked in registry but runtime channel is unavailable")
            }
        }
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

    fn handle_drain(&self) -> AdminResponse {
        self.core.drain()
    }

    fn handle_drain_status(&self) -> AdminResponse {
        self.core.drain_status()
    }

    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse {
        self.core.issue_http_qkey(&req)
    }

    fn handle_list_qkeys(&self) -> AdminResponse {
        let mut registry = self.core.qkeys().lock().unwrap_or_else(|e| e.into_inner());
        AdminResponse::ok_with_data(serde_json::json!({ "keys": registry.list() }))
    }

    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse {
        self.core.revoke_http_qkey(id)
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
    pub version: u32,
    pub qkey_record: Option<QKeyRecord>,
    pub pending_qkey_auth: Option<QKeyAuthState>,
}

pub fn parse_live_server_initial_auth(
    packet: &[u8],
    qkey_registry: &std::sync::Mutex<QKeyRegistry>,
    revocation_manager: &crate::implementations::server::revocation::RevocationManager,
    metrics: &Metrics,
) -> Option<LiveInitialAuthContext> {
    let (mut initial_hdr, _) = match crate::transport::packet::parse_header(packet, 0) {
        Ok(value) => value,
        Err(_) => {
            metrics.record_connection_rejected();
            return None;
        }
    };
    if initial_hdr.ty != crate::transport::PacketType::Initial {
        metrics.record_connection_rejected();
        return None;
    }

    let version = initial_hdr.version;
    let odcid = crate::transport::ConnectionId::from_vec(std::mem::take(&mut initial_hdr.dcid));
    let initial_token = initial_hdr.token.take();
    let require_qkey = require_qkey_for_new_clients();
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
        if revocation_manager.is_revoked(&record.id) {
            record_qkey_auth_rejection(metrics);
            return None;
        }
        pending_qkey_auth = Some(QKeyAuthState {
            key_id: record.id.clone(),
            expected_token_sha256: record.token_sha256.clone(),
            authed: false,
            connected_at: Instant::now(),
        });
        qkey_record = Some(record);
    }

    Some(LiveInitialAuthContext { odcid, version, qkey_record, pending_qkey_auth })
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

#[inline]
fn qkey_payload_allowed(require_auth: bool, authenticated: bool) -> bool {
    !require_auth || authenticated
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QKeyDatagramAuthProgress {
    Pending,
    Authenticated,
    Rejected,
}

fn qkey_datagram_auth_result(
    conn_id: &[u8],
    progress: QKeyDatagramAuthProgress,
) -> Option<(Vec<u8>, bool)> {
    match progress {
        QKeyDatagramAuthProgress::Pending => None,
        QKeyDatagramAuthProgress::Authenticated => Some((conn_id.to_vec(), true)),
        QKeyDatagramAuthProgress::Rejected => Some((conn_id.to_vec(), false)),
    }
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
        match socket.try_send_to(data, *addr) {
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
    while staging.len() < crate::transport::UDP_DATAGRAM_BURST_LIMIT {
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
            Ok(_) => break,
            Err(e) => {
                log::error!("Send failed to {}: {:?}", addr, e);
                break;
            }
        }
    }
    if staging.len() == crate::transport::UDP_DATAGRAM_BURST_LIMIT {
        log::debug!(
            "Outgoing flush for {} reached the {} datagram burst limit",
            addr,
            crate::transport::UDP_DATAGRAM_BURST_LIMIT
        );
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

#[derive(Debug)]
struct ClientFanoutPacket {
    source: SocketAddr,
    destination: IpAddr,
    packet: Vec<u8>,
}

type ClientFanoutQueue = Arc<std::sync::Mutex<std::collections::VecDeque<ClientFanoutPacket>>>;

fn enqueue_client_fanout(
    queue: &ClientFanoutQueue,
    source: SocketAddr,
    route: UplinkRoute,
    packet: &[u8],
) {
    let destination = match route {
        UplinkRoute::Broadcast { destination, .. } => IpAddr::V4(destination),
        UplinkRoute::Multicast { destination, .. } => destination,
        UplinkRoute::Local { .. } | UplinkRoute::Internet { .. } | UplinkRoute::Client { .. } => {
            return;
        }
    };
    let pending = ClientFanoutPacket { source, destination, packet: packet.to_vec() };
    match queue.lock() {
        Ok(mut queue) => queue.push_back(pending),
        Err(poisoned) => poisoned.into_inner().push_back(pending),
    }
}

#[inline]
fn allow_client_uplink(
    forwarding_policy: &ClientIsolationManager,
    metrics: &Metrics,
    assigned_ips: Option<AssignedClientIps>,
    packet: &[u8],
    server_ips: ServerTunIps,
    tun_mtu: u16,
    response_queue: &Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
) -> Option<UplinkRoute> {
    let route = match forwarding_policy.evaluate_uplink(packet, assigned_ips) {
        Ok(route) => route,
        Err(reason) => {
            metrics.record_uplink_drop(reason);
            log::debug!("Client uplink dropped by forwarding policy: {:?}", reason);
            return None;
        }
    };
    let route = match route {
        UplinkRoute::Internet { source, destination }
            if destination == IpAddr::V4(server_ips.ipv4)
                || server_ips.ipv6.is_some_and(|ipv6| destination == IpAddr::V6(ipv6)) =>
        {
            UplinkRoute::Local { source, destination }
        }
        route => route,
    };
    metrics.record_uplink_route(route);

    let is_forwarded_unicast =
        matches!(route, UplinkRoute::Internet { .. } | UplinkRoute::Client { .. });
    if is_forwarded_unicast && packet.first().is_some_and(|byte| byte >> 4 == 4) && packet[8] <= 1 {
        let response = icmp::build_icmpv4_error(
            packet,
            server_ips.ipv4,
            icmp::icmp_type::TIME_EXCEEDED,
            0,
            None,
        );
        enqueue_routing_response(response_queue, metrics, response);
        metrics.record_routing_outcome(RoutingOutcome::TimeExceeded);
        return None;
    }
    if is_forwarded_unicast && packet.first().is_some_and(|byte| byte >> 4 == 6) && packet[7] <= 1 {
        if let Some(server_ipv6) = server_ips.ipv6 {
            let response = icmp::build_icmpv6_error(
                packet,
                server_ipv6,
                icmp::icmpv6_type::TIME_EXCEEDED,
                None,
            );
            enqueue_routing_response(response_queue, metrics, response);
            metrics.record_routing_outcome(RoutingOutcome::TimeExceeded);
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
        }
        return None;
    }

    if packet.len() > usize::from(tun_mtu) && packet.first().is_some_and(|byte| byte >> 4 == 4) {
        let dont_fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x4000 != 0;
        if dont_fragment {
            let response = icmp::build_icmpv4_error(
                packet,
                server_ips.ipv4,
                icmp::icmp_type::DESTINATION_UNREACHABLE,
                icmp::icmp_code::FRAGMENTATION_NEEDED,
                Some(tun_mtu),
            );
            enqueue_routing_response(response_queue, metrics, response);
            metrics.record_routing_outcome(RoutingOutcome::PacketTooBig);
            return None;
        }
    }
    if packet.len() > usize::from(tun_mtu) && packet.first().is_some_and(|byte| byte >> 4 == 6) {
        if let Some(server_ipv6) = server_ips.ipv6 {
            let response = icmp::build_icmpv6_error(
                packet,
                server_ipv6,
                icmp::icmpv6_type::PACKET_TOO_BIG,
                Some(u32::from(tun_mtu)),
            );
            enqueue_routing_response(response_queue, metrics, response);
            metrics.record_routing_outcome(RoutingOutcome::PacketTooBig);
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
        }
        return None;
    }

    Some(route)
}

fn enqueue_routing_response(
    queue: &Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
    metrics: &Metrics,
    response: Vec<u8>,
) {
    if response.is_empty() {
        return;
    }
    let admission = match queue.lock() {
        Ok(mut pending) => pending.enqueue(response),
        Err(poisoned) => poisoned.into_inner().enqueue(response),
    };
    if let Err(reason) = admission {
        metrics.record_masque_downlink_response_drop(reason);
    }
}

fn drain_masque_downlink_responses(
    conn: &mut QuicFuscateConnection,
    addr: SocketAddr,
    metrics: &Metrics,
) {
    let mut terminal_drops = 0usize;
    while let Some(packet) = conn.pop_masque_downlink_packet() {
        match conn.send_masque_downlink(&packet) {
            Ok(()) => {}
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                conn.retry_masque_downlink_packet(packet);
                metrics.record_masque_downlink_response_retry();
                break;
            }
            Err(error) => {
                metrics.record_masque_downlink_response_terminal_drop(1);
                terminal_drops = terminal_drops.saturating_add(1);
                log::trace!(
                    "MASQUE queued downlink to {} reached terminal send outcome: {:?}",
                    addr,
                    error
                );
            }
        }
    }
    if terminal_drops > 0 {
        log::debug!(
            "dropped {} MASQUE queued downlinks to {} after terminal send outcomes",
            terminal_drops,
            addr
        );
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_live_server_client_datagram(
    socket: &tokio::net::UdpSocket,
    addr: SocketAddr,
    runtime_client: LiveClientRuntime<'_>,
    packet: &[u8],
    out: &mut [u8],
    metrics: &Arc<Metrics>,
    client_snapshots: &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>>,
    server_tun: Option<&Arc<TunInterface>>,
    server_ips: ServerTunIps,
    tun_enable: bool,
    fingerprint_profile: OsFingerprintProfile,
    dns_upstream_resolvers: Arc<Vec<Ipv4Addr>>,
) -> std::io::Result<LiveClientDatagramResult> {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

    // Packet normalizer for OS fingerprint obfuscation (TODO-462).
    // Applied to all IPv4 packets before they are written to the TUN interface
    // so that passive OS fingerprinting (p0f, Nmap) classifies the host as the
    // target OS rather than the real underlying platform. Wrapped in Arc so the
    // MASQUE datagram callback (set once per connection) can retain its own
    // clone across calls.
    let normalizer = std::sync::Arc::new(PacketNormalizer::new(fingerprint_profile));

    let LiveClientRuntime {
        connection: conn,
        conn_id,
        qkey_auth,
        session_stats,
        session_id,
        assigned_ips,
        forwarding_policy,
        fanout_queue,
        ..
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

    match conn.recv(packet) {
        Ok(_) => {}
        Err(error) => {
            log::error!("QUIC recv failed for {}: {:?}", addr, error);
        }
    }

    let require_auth = qkey_auth.is_some();
    let expected_token_sha256 = qkey_auth.as_ref().map(|state| state.expected_token_sha256.clone());
    let auth_gate =
        Arc::new(AtomicBool::new(qkey_auth.as_ref().map(|state| state.authed).unwrap_or(true)));
    let auth_progress = Cell::new(QKeyDatagramAuthProgress::Pending);
    let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

    // Install the MASQUE→TUN sink when TUN bridging is active. Decoded MASQUE
    // CONNECT-UDP datagram payloads (raw IP packets) are written to the server
    // TUN interface by this callback, invoked from drain_masque_datagrams
    // inside poll_http3_event_loop. The callback is rebound on each packet
    // processing pass so it always captures the current QKey auth gate; keeping
    // the first unauthenticated gate forever would silently drop later valid
    // MASQUE datagrams.
    if tun_enable {
        if let Some(tun) = server_tun {
            if !conn.has_masque_downlink_queue() {
                conn.set_masque_downlink_queue(Arc::new(std::sync::Mutex::new(
                    crate::core::MasqueDownlinkQueue::new(
                        MAX_MASQUE_DOWNLINK_RESPONSES,
                        MAX_MASQUE_DOWNLINK_RESPONSE_BYTES,
                    ),
                )));
            }
            let tun_sink = Arc::clone(tun);
            let masque_normalizer = std::sync::Arc::clone(&normalizer);
            let masque_forwarding_policy = Arc::clone(&forwarding_policy);
            let masque_fanout_queue = Arc::clone(&fanout_queue);
            let masque_metrics = Arc::clone(metrics);
            let dns_resolvers = Arc::clone(&dns_upstream_resolvers);
            let dns_downlink_queue = conn
                .masque_downlink_queue()
                .expect("MASQUE downlink queue installed before callback");
            let masque_response_queue = Arc::clone(&dns_downlink_queue);
            let tun_mtu = tun.mtu();
            let datagram_auth_gate = Arc::clone(&auth_gate);
            conn.set_masque_datagram_cb(Arc::new(std::sync::Mutex::new(Box::new(
                move |payload: &[u8]| {
                    if !qkey_payload_allowed(
                        require_auth,
                        datagram_auth_gate.load(AtomicOrdering::Relaxed),
                    ) {
                        return;
                    }
                    let Some(route) = allow_client_uplink(
                        &masque_forwarding_policy,
                        &masque_metrics,
                        assigned_ips,
                        payload,
                        server_ips,
                        tun_mtu,
                        &masque_response_queue,
                    ) else {
                        return;
                    };
                    if spawn_dns_intercept(
                        payload,
                        Arc::clone(&dns_resolvers),
                        Arc::clone(&dns_downlink_queue),
                        Arc::clone(&masque_metrics),
                        fingerprint_profile,
                    ) {
                        return;
                    }
                    // Apply OS fingerprint normalization for IPv4 packets
                    // before writing to TUN (TODO-462).
                    if !payload.is_empty() && payload[0] >> 4 == 4 {
                        let mut buf = payload.to_vec();
                        masque_normalizer.normalize_ipv4(&mut buf);
                        enqueue_client_fanout(&masque_fanout_queue, addr, route, &buf);
                        if let Err(error) = tun_sink.write(&buf) {
                            log::warn!("Server TUN write (MASQUE) failed: {:?}", error);
                        }
                    } else {
                        enqueue_client_fanout(&masque_fanout_queue, addr, route, payload);
                        if let Err(error) = tun_sink.write(payload) {
                            log::warn!("Server TUN write (MASQUE) failed: {:?}", error);
                        }
                    }
                },
            ))));
        }
    }

    let stream_response_queue = conn.masque_downlink_queue();

    if let Err(error) = conn.poll_http3_with_headers(
        |_sid, headers| match evaluate_qkey_http3_headers(
            headers,
            expected_token_sha256.as_deref(),
            auth_gate.load(AtomicOrdering::Relaxed),
        ) {
            QKeyHeaderAuthOutcome::Unchanged => {}
            QKeyHeaderAuthOutcome::Authenticated => {
                auth_gate.store(true, AtomicOrdering::Relaxed);
                auth_progress.set(QKeyDatagramAuthProgress::Authenticated);
            }
            QKeyHeaderAuthOutcome::Reject(reason) => {
                auth_progress.set(QKeyDatagramAuthProgress::Rejected);
                should_close.set(Some(reason));
            }
        },
        |_sid, data| {
            if !qkey_payload_allowed(require_auth, auth_gate.load(AtomicOrdering::Relaxed)) {
                return;
            }
            if tun_enable {
                if let Some(tun) = server_tun {
                    // Only write to TUN if the data looks like a valid IP packet
                    // (version 4 or 6 in the high nibble of the first byte).
                    // This filters out CONNECT-UDP capsule protocol data on the
                    // MASQUE stream, which is not a raw IP packet and would cause
                    // EINVAL on TUN write.
                    if !data.is_empty() && (data[0] >> 4 == 4 || data[0] >> 4 == 6) {
                        let Some(response_queue) = stream_response_queue.as_ref() else {
                            return;
                        };
                        let Some(route) = allow_client_uplink(
                            &forwarding_policy,
                            metrics,
                            assigned_ips,
                            data,
                            server_ips,
                            tun.mtu(),
                            response_queue,
                        ) else {
                            return;
                        };
                        // Apply OS fingerprint normalization for IPv4 packets
                        // before writing to TUN (TODO-462).
                        if data[0] >> 4 == 4 {
                            let mut buf = data.to_vec();
                            normalizer.normalize_ipv4(&mut buf);
                            enqueue_client_fanout(&fanout_queue, addr, route, &buf);
                            if let Err(error) = tun.write(&buf) {
                                log::warn!("Server TUN write failed: {:?}", error);
                            }
                        } else {
                            enqueue_client_fanout(&fanout_queue, addr, route, data);
                            if let Err(error) = tun.write(data) {
                                log::warn!("Server TUN write failed: {:?}", error);
                            }
                        }
                    }
                }
            }
        },
    ) {
        log::warn!("HTTP/3 header/body poll failed for {}: {:?}", addr, error);
    }

    // MASQUE CONNECT-UDP uplink datagrams are drained and written to the TUN by
    // drain_masque_datagrams (inside poll_http3_with_headers above) via the
    // masque_datagram_cb sink installed earlier. The previous bare dgram_recv
    // loop was either redundant (datagrams already drained) or wrote corrupted
    // bytes (MASQUE flow-id varint prefix not stripped) and has been removed.

    let auth_result = qkey_datagram_auth_result(&conn_id, auth_progress.get());
    let mut remove_auth_conn_id = None;
    if let Some(reason) = should_close.get() {
        close_live_client_for_qkey_auth_failure(conn, metrics, addr, reason);
        remove_auth_conn_id = Some(conn_id.clone());
    }

    drain_masque_downlink_responses(conn, addr, metrics);

    flush_live_server_outgoing(
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

    Ok(LiveClientDatagramResult { auth_result, remove_auth_conn_id })
}

#[derive(Debug)]
struct PendingTunDownlink {
    target: SocketAddr,
    packet: Vec<u8>,
    queued_at: Instant,
}

impl PendingTunDownlink {
    fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.queued_at) >= MAX_PENDING_TUN_DOWNLINK_AGE
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingTunDownlinkReject {
    Queue,
    Bytes,
    PerTarget,
}

impl From<PendingTunDownlinkReject> for TunDownlinkBackpressureDrop {
    fn from(reject: PendingTunDownlinkReject) -> Self {
        match reject {
            PendingTunDownlinkReject::Queue => Self::QueueCapacity,
            PendingTunDownlinkReject::Bytes => Self::ByteCapacity,
            PendingTunDownlinkReject::PerTarget => Self::PerTargetCapacity,
        }
    }
}

#[derive(Debug)]
struct PendingTunDownlinks {
    entries: std::collections::VecDeque<PendingTunDownlink>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    max_per_target: usize,
}

impl PendingTunDownlinks {
    fn new() -> Self {
        Self::with_limits(
            MAX_PENDING_TUN_DOWNLINKS,
            MAX_PENDING_TUN_DOWNLINK_BYTES,
            MAX_PENDING_TUN_DOWNLINKS_PER_TARGET,
        )
    }

    fn with_limits(max_entries: usize, max_bytes: usize, max_per_target: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(max_entries),
            bytes: 0,
            max_entries,
            max_bytes,
            max_per_target,
        }
    }

    fn enqueue(
        &mut self,
        target: SocketAddr,
        packet: Vec<u8>,
        queued_at: Instant,
    ) -> Result<(), PendingTunDownlinkReject> {
        if self.entries.len() >= self.max_entries {
            return Err(PendingTunDownlinkReject::Queue);
        }
        if self.bytes.saturating_add(packet.len()) > self.max_bytes {
            return Err(PendingTunDownlinkReject::Bytes);
        }
        if self.entries.iter().filter(|entry| entry.target == target).count() >= self.max_per_target
        {
            return Err(PendingTunDownlinkReject::PerTarget);
        }
        self.bytes += packet.len();
        self.entries.push_back(PendingTunDownlink { target, packet, queued_at });
        Ok(())
    }

    fn pop_front(&mut self) -> Option<PendingTunDownlink> {
        let entry = self.entries.pop_front()?;
        self.bytes = self.bytes.saturating_sub(entry.packet.len());
        Some(entry)
    }

    fn requeue(&mut self, entry: PendingTunDownlink) {
        self.bytes += entry.packet.len();
        self.entries.push_back(entry);
    }

    fn rebind_target(&mut self, old_target: SocketAddr, new_target: SocketAddr) {
        for entry in &mut self.entries {
            if entry.target == old_target {
                entry.target = new_target;
            }
        }
    }

    fn discard_target(&mut self, target: SocketAddr) -> (usize, usize) {
        let mut discarded_packets = 0;
        let mut discarded_bytes = 0;
        self.entries.retain(|entry| {
            if entry.target == target {
                discarded_packets += 1;
                discarded_bytes += entry.packet.len();
                false
            } else {
                true
            }
        });
        self.bytes = self.bytes.saturating_sub(discarded_bytes);
        (discarded_packets, discarded_bytes)
    }

    fn discard_all(&mut self) -> (usize, usize) {
        let discarded_packets = self.entries.len();
        let discarded_bytes = self.bytes;
        self.entries.clear();
        self.bytes = 0;
        (discarded_packets, discarded_bytes)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn bytes(&self) -> usize {
        self.bytes
    }
}

pub struct LiveServerState {
    clients: std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    /// Bounded downlink packets that could not be enqueued because a client's
    /// QUIC DATAGRAM queue was full. Retried before new TUN packets are read.
    pending_tun_downlinks: PendingTunDownlinks,
    fanout_queue: ClientFanoutQueue,
    qkey_auth: std::collections::HashMap<Vec<u8>, QKeyAuthState>,
    domain: LiveServerDomain,
    auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    revocation_manager: Arc<crate::implementations::server::revocation::RevocationManager>,
    qkey_tracker: Arc<crate::implementations::server::revocation::QKeyConnectionTracker>,
    key_rotation_manager: crate::implementations::server::revocation::KeyRotationManager,
    next_stats_log: Instant,
    /// Last time the external blacklist feed sync was *started*. Used by
    /// `run_housekeeping_tick` to trigger periodic re-syncs at the
    /// configured `sync_interval`. `None` = sync never started yet.
    /// Shared via `Arc<Mutex<>>` so the background sync task spawned via
    /// `tokio::spawn` can update it without holding the `LiveServerState`
    /// borrow. The timestamp is recorded *before* spawning the sync task
    /// so overlapping syncs are prevented even if a prior sync is still
    /// in flight.
    #[cfg(feature = "rate_limiter")]
    last_blacklist_sync: Arc<parking_lot::Mutex<Option<Instant>>>,
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
    pub revocation_manager: &'a crate::implementations::server::revocation::RevocationManager,
    pub metrics: &'a Metrics,
    pub stealth_config: &'a Arc<std::sync::Mutex<StealthConfig>>,
    pub fec_cfg_shared: &'a Arc<std::sync::Mutex<FecConfig>>,
    pub opt_params_shared: &'a Arc<std::sync::Mutex<OptimizeConfig>>,
    pub transport_config: &'a mut crate::transport::Config,
    pub profile: BrowserProfile,
    pub os: OsProfile,
    pub disable_doh: bool,
    pub auth_rate_limiter:
        Arc<std::sync::Mutex<crate::implementations::server::limits::AuthRateLimiter>>,
    pub doh_provider: &'a str,
    pub disable_fronting: bool,
    pub front_domain: &'a [String],
    pub disable_http3: bool,
}

pub fn build_live_server_client_init(
    request: LiveClientBuildRequest<'_>,
) -> Option<LiveClientInit> {
    // Per-IP auth rate limiting: reject before any QKey lookup if the IP has
    // exceeded the failed auth attempt threshold. This prevents brute-force
    // attacks on QKey tokens.
    {
        let ip = request.remote_addr.ip();
        let limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        if !limiter.is_allowed(ip) {
            log::warn!("QKey auth rate limit exceeded for {}; rejecting connection", ip);
            request.metrics.record_connection_rejected();
            return None;
        }
    }

    let initial_ctx = match parse_live_server_initial_auth(
        request.packet,
        request.qkey_registry,
        request.revocation_manager,
        request.metrics,
    ) {
        Some(ctx) => ctx,
        None => {
            // Record the failed auth attempt for rate limiting
            let ip = request.remote_addr.ip();
            let mut limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            limiter.record_failure(ip);
            return None;
        }
    };

    // Successful initial auth - clear any previous failed attempts for this IP
    {
        let ip = request.remote_addr.ip();
        let mut limiter = request.auth_rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(ip);
    }

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
    let mut selected_transport = request.transport_config.clone();
    if let Err(error) = selected_transport.select_version(initial_ctx.version) {
        log::warn!("refusing unsupported QUIC version {:#010x}: {}", initial_ctx.version, error);
        request.metrics.record_connection_rejected();
        return None;
    }
    match create_live_server_connection(
        request.local_addr,
        request.remote_addr,
        &mut selected_transport,
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
    pub assigned_ips: Option<AssignedClientIps>,
    pub forwarding_policy: Arc<ClientIsolationManager>,
    fanout_queue: ClientFanoutQueue,
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
    ) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
        let (session_id, stats, assigned_ips) = self.shared.accept(remote_addr)?;
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionEstablished,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client connection accepted",
        );
        Ok((session_id, stats, assigned_ips))
    }

    fn remove_remote(&self, remote_addr: SocketAddr) {
        let Some(session_id) = self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
        else {
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(remote_addr.ip());
            self.remove_remote_snapshot(remote_addr);
            return;
        };
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionClosed,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client session removed",
        );
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

    fn assigned_ips_by_remote(&self, remote_addr: SocketAddr) -> Option<AssignedClientIps> {
        self.shared.sessions.read().get_by_remote_addr(remote_addr).map(|session| {
            AssignedClientIps { ipv4: session.client_ip(), ipv6: session.client_ipv6() }
        })
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

    fn reap_expired_remotes(&self) -> Vec<(SocketAddr, SessionId)> {
        let expired = self.shared.reap_expired();
        for session in &expired {
            let source_ip = session.remote_addr().ip().to_string();
            let client_id = session.id().as_u64().to_string();
            crate::audit::audit(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                Some(&source_ip),
                Some(&client_id),
                "Client session expired",
            );
        }
        expired.into_iter().map(|session| (session.remote_addr(), session.id())).collect()
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

    /// Returns a clone of the blacklist synchronizer Arc for async sync.
    #[cfg(feature = "rate_limiter")]
    fn blacklist(&self) -> Arc<crate::implementations::server::limits::BlacklistSync> {
        Arc::clone(&self.shared.blacklist)
    }
}

fn accept_session_in_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    mut ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
    remote_addr: SocketAddr,
    max_clients: usize,
    client_timeout_secs: u64,
) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
    if !connection_limiter.check(remote_addr.ip()) {
        return Err(AcceptError::TooManyConnectionsPerIp);
    }
    if sessions.len() >= max_clients {
        return Err(AcceptError::MaxClientsReached);
    }
    let client_ip = ip_pool.allocate().ok_or(AcceptError::IpPoolExhausted)?;

    // Allocate IPv6 address if dual-stack pool is available
    let client_ipv6 = if let Some(ref mut v6_pool) = ipv6_pool {
        match v6_pool.allocate() {
            Some(v6) => Some(v6),
            None => {
                // IPv6 pool exhausted - release IPv4 and fail
                ip_pool.release(client_ip);
                return Err(AcceptError::IpPoolExhausted);
            }
        }
    } else {
        None
    };

    let session = if let Some(v6) = client_ipv6 {
        Session::new_dual_stack(remote_addr, client_ip, Some(v6), client_timeout_secs)
    } else {
        Session::new(remote_addr, client_ip, client_timeout_secs)
    };
    let session_id = session.id();
    let stats = Arc::clone(session.stats());
    match sessions.add(session) {
        Ok(_) => {
            connection_limiter.add(remote_addr.ip());
            Ok((session_id, stats, AssignedClientIps { ipv4: client_ip, ipv6: client_ipv6 }))
        }
        Err(SessionError::MaxSessionsReached) => {
            ip_pool.release(client_ip);
            if let Some(v6) = client_ipv6 {
                if let Some(ref mut v6_pool) = ipv6_pool {
                    v6_pool.release(v6);
                }
            }
            Err(AcceptError::MaxClientsReached)
        }
        Err(SessionError::NotFound | SessionError::AlreadyExists) => {
            ip_pool.release(client_ip);
            if let Some(v6) = client_ipv6 {
                if let Some(ref mut v6_pool) = ipv6_pool {
                    v6_pool.release(v6);
                }
            }
            Err(AcceptError::SessionError("failed to add live session".to_string()))
        }
    }
}

fn remove_session_from_domain(
    sessions: &mut SessionManager,
    ip_pool: &mut IpPool,
    ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
    session_id: SessionId,
) -> Option<Session> {
    let session = sessions.remove(session_id)?;
    ip_pool.release(session.client_ip());
    if let Some(v6) = session.client_ipv6() {
        if let Some(v6_pool) = ipv6_pool {
            v6_pool.release(v6);
        }
    }
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
    mut ipv6_pool: Option<&mut Ipv6Pool>,
    connection_limiter: &mut ConnectionLimiter,
) -> Vec<Session> {
    let expired_ids = collect_expired_session_ids(sessions);
    let mut removed = Vec::with_capacity(expired_ids.len());
    for session_id in expired_ids {
        if let Some(session) = remove_session_from_domain(
            sessions,
            ip_pool,
            ipv6_pool.as_deref_mut(),
            connection_limiter,
            session_id,
        ) {
            removed.push(session);
        }
    }
    removed
}

impl LiveServerState {
    pub fn new(server_config: ServerConfig) -> Self {
        let revocation_manager =
            Arc::new(crate::implementations::server::revocation::RevocationManager::new());
        let qkey_tracker =
            Arc::new(crate::implementations::server::revocation::QKeyConnectionTracker::new());
        let key_rotation_manager =
            crate::implementations::server::revocation::KeyRotationManager::new(
                crate::implementations::server::revocation::DEFAULT_ROTATION_INTERVAL_SECS,
                crate::implementations::server::revocation::DEFAULT_OVERLAP_WINDOW_SECS,
                Arc::clone(&revocation_manager),
            );
        Self {
            clients: std::collections::HashMap::new(),
            pending_tun_downlinks: PendingTunDownlinks::new(),
            fanout_queue: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            qkey_auth: std::collections::HashMap::new(),
            domain: LiveServerDomain::new(&server_config),
            auth_rate_limiter: Arc::new(std::sync::Mutex::new(
                crate::implementations::server::limits::AuthRateLimiter::new(
                    10,
                    std::time::Duration::from_secs(60),
                ),
            )),
            revocation_manager,
            qkey_tracker,
            key_rotation_manager,
            next_stats_log: Instant::now(),
            #[cfg(feature = "rate_limiter")]
            last_blacklist_sync: Arc::new(parking_lot::Mutex::new(None)),
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

    /// Periodically sync the external blacklist feed if a sync URL is
    /// configured and the sync interval has elapsed since the last sync.
    ///
    /// The sync is an async HTTPS fetch with a 30s timeout. To avoid
    /// blocking the 5ms housekeeping tick (and thus all UDP packet
    /// processing, TUN forwarding, and client flushing), the actual fetch
    /// is dispatched via `tokio::spawn` as a background task. The
    /// `last_blacklist_sync` timestamp is recorded *before* spawning so
    /// overlapping syncs are prevented - if a sync is still in flight when
    /// the next interval elapses, the new tick sees a recent timestamp and
    /// skips. The background task updates the shared `BlacklistSync` (via
    /// its `Arc`) in place; `replace_list` takes the internal write lock,
    /// so concurrent `is_blocked` reads remain safe. Errors are logged and
    /// non-fatal - the blacklist continues to use the last-known-good set.
    #[cfg(feature = "rate_limiter")]
    fn maybe_sync_blacklist(&self) {
        let blacklist = self.domain.blacklist();
        if !blacklist.has_sync_url() {
            return;
        }
        let interval = blacklist.sync_interval();
        let should_sync = {
            let guard = self.last_blacklist_sync.lock();
            match *guard {
                None => true,
                Some(last) => last.elapsed() >= interval,
            }
        };
        if !should_sync {
            return;
        }
        // Record the sync start time *before* spawning so that subsequent
        // ticks do not spawn overlapping syncs while this one is in flight.
        {
            let mut guard = self.last_blacklist_sync.lock();
            *guard = Some(Instant::now());
        }
        log::debug!("Blacklist: dispatching background sync from external feed");
        // Spawn the sync as a detached background task. The task owns a
        // clone of the `Arc<BlacklistSync>` and performs the HTTPS fetch
        // without holding any borrow on `LiveServerState`. The result is
        // logged; the blacklist is updated in place via `replace_list`.
        tokio::spawn(async move {
            match blacklist.sync().await {
                Ok(count) => {
                    log::info!("Blacklist: synced {count} IPs from external feed");
                }
                Err(e) => {
                    log::warn!("Blacklist: sync failed (using last-known-good set): {e}");
                }
            }
        });
    }

    fn values_mut(&mut self) -> impl Iterator<Item = &mut QuicFuscateConnection> {
        self.clients.values_mut()
    }

    fn next_outbound_release_deadline(&self) -> Option<Instant> {
        self.clients
            .values()
            .filter_map(QuicFuscateConnection::next_outbound_release_deadline)
            .min()
    }

    async fn flush_due_outgoing(&mut self, socket: &UdpSocket, out: &mut [u8], metrics: &Metrics) {
        let now = Instant::now();
        let addresses = self
            .clients
            .iter()
            .filter_map(|(addr, conn)| {
                conn.next_outbound_release_deadline()
                    .is_some_and(|deadline| deadline <= now)
                    .then_some(*addr)
            })
            .collect::<Vec<_>>();
        let client_snapshots = Arc::clone(self.domain.client_snapshots());

        for addr in addresses {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            let Some(conn) = self.get_mut(&addr) else {
                continue;
            };
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
                log::warn!("Failed to flush paced packets to {}: {}", addr, error);
            }
        }
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
        let existing_assigned_ips = self.domain.assigned_ips_by_remote(addr);
        let forwarding_policy = Arc::clone(&self.domain.shared.forwarding_policy);
        let fanout_queue = Arc::clone(&self.fanout_queue);
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
                    assigned_ips: existing_assigned_ips,
                    forwarding_policy,
                    fanout_queue: Arc::clone(&fanout_queue),
                })
            }
            Entry::Vacant(entry) => {
                match accept_loop.should_accept(addr, count_before, accept_max_clients) {
                    AcceptDecision::Accept => {}
                    AcceptDecision::Backpressure => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Backpressure;
                    }
                    AcceptDecision::Reject(_) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                        return LiveClientAcquire::Rejected;
                    }
                }

                let mut init = match build() {
                    Some(value) => value,
                    None => {
                        return LiveClientAcquire::Rejected;
                    }
                };
                let (session_id, session_stats, assigned_ips) = match self.domain.accept(addr) {
                    Ok(value) => value,
                    Err(_) => {
                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
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
                    assigned_ips: Some(assigned_ips),
                    forwarding_policy,
                    fanout_queue,
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

    fn drain_client_fanout(&mut self, metrics: &Metrics) {
        let pending: Vec<ClientFanoutPacket> = match self.fanout_queue.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(poisoned) => poisoned.into_inner().drain(..).collect(),
        };
        for fanout in pending {
            let targets = {
                let sessions = self.domain.shared.sessions.read();
                self.clients
                    .iter()
                    .filter_map(|(address, connection)| {
                        if *address == fanout.source {
                            return None;
                        }
                        let conn_id = connection.conn.source_id().as_ref();
                        if self.qkey_auth.get(conn_id).is_some_and(|state| !state.authed) {
                            return None;
                        }
                        let session = sessions.get_by_remote_addr(*address)?;
                        if fanout.destination.is_ipv6() && session.client_ipv6().is_none() {
                            return None;
                        }
                        Some(*address)
                    })
                    .collect::<smallvec::SmallVec<[SocketAddr; 4]>>()
            };

            let mut queued = false;
            for target in targets {
                let Some(connection) = self.clients.get_mut(&target) else {
                    continue;
                };
                if fanout.packet.len() > connection.effective_tunnel_mtu() {
                    log::debug!("Client fan-out packet exceeds tunnel MTU for {}", target);
                    continue;
                }
                match connection.send_masque_downlink(&fanout.packet) {
                    Ok(()) => queued = true,
                    Err(error) => {
                        log::debug!("Client fan-out queue for {} failed: {:?}", target, error);
                    }
                }
            }
            if queued {
                metrics.record_routing_outcome(RoutingOutcome::Fanout);
            }
        }
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
        let now = Instant::now();
        let log_client_stats = now >= self.next_stats_log;
        if log_client_stats {
            self.next_stats_log = now + SERVER_STATS_LOG_INTERVAL;
        }
        #[cfg(feature = "rate_limiter")]
        {
            self.prune_rate_limits_if_due();
            // Periodically dispatch a background blacklist sync. The sync
            // is an async HTTPS fetch (30s timeout) but is spawned via
            // `tokio::spawn` so it never blocks the 5ms housekeeping tick.
            // The dispatch only fires when the configured sync_interval has
            // elapsed (default: 3600s), so the per-tick cost is just an
            // `Instant::now()` comparison under a short-lived lock.
            self.maybe_sync_blacklist();
        }
        let _ = self.key_rotation_manager.check_and_rotate();
        for revoked_key_id in self.key_rotation_manager.process_pending_revocations() {
            self.close_sessions_for_revoked_qkey(&revoked_key_id, accept_loop, metrics);
        }
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        let addresses = self.key_addrs();
        for addr in addresses {
            let session_stats = self.domain.session_stats_by_remote(addr);
            let session_id = self.domain.session_id_by_remote(addr);
            if let Some(conn) = self.get_mut(&addr) {
                drain_masque_downlink_responses(conn, addr, metrics);
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
                if log_client_stats {
                    log::info!(
                        "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                        addr,
                        conn.rtt_ms(),
                        conn.loss_rate() * 100.0
                    );
                }
                // Only drive the idle timeout when the connection has actually been
                // idle; calling it every tick collapses cwnd and inflates loss.
                if conn.conn.idle_timeout_elapsed() {
                    conn.conn.on_timeout();
                }
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

    fn session_id_for_conn_id(&self, conn_id: &[u8]) -> Option<SessionId> {
        self.clients.iter().find_map(|(addr, conn)| {
            (conn.conn.source_id().as_ref() == conn_id)
                .then(|| self.domain.session_id_by_remote(*addr))
                .flatten()
        })
    }

    fn dissociate_qkey_for_session(&self, session_id: Option<SessionId>) {
        if let Some(session_id) = session_id {
            self.qkey_tracker.dissociate(session_id.as_u64());
        }
    }

    fn close_sessions_for_revoked_qkey(
        &mut self,
        key_id: &str,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let revoked_session_ids = self.qkey_tracker.drain_connections_for_key(key_id);
        if revoked_session_ids.is_empty() {
            return;
        }
        let revoked_session_ids: std::collections::HashSet<u64> =
            revoked_session_ids.into_iter().collect();
        let addrs: Vec<SocketAddr> = self
            .clients
            .keys()
            .copied()
            .filter(|addr| {
                self.domain
                    .session_id_by_remote(*addr)
                    .map(|session_id| revoked_session_ids.contains(&session_id.as_u64()))
                    .unwrap_or(false)
            })
            .collect();
        for addr in addrs {
            if let Some(mut conn) = self.clients.remove(&addr) {
                let conn_id = conn.conn.source_id().as_ref().to_vec();
                if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                    log::warn!(
                        "Client close after QKey revocation failed for {}: {:?}",
                        addr,
                        error
                    );
                }
                self.qkey_auth.remove(&conn_id);
                accept_loop.record_closed(addr);
                metrics.record_connection_rejected();
            }
            self.domain.remove_remote(addr);
        }
        self.domain.retain_snapshots_for_clients(&self.clients);
        self.sync_active_metrics(metrics);
    }

    pub fn revoke_qkey_now(
        &mut self,
        key_id: &str,
        reason: &str,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        self.revocation_manager.revoke(key_id, reason);
        self.close_sessions_for_revoked_qkey(key_id, accept_loop, metrics);
    }

    fn try_rebind_by_dcid(
        &mut self,
        from: SocketAddr,
        packet: &[u8],
        accept_loop: &AcceptLoop,
    ) -> bool {
        let old_addr = try_rebind_live_client_by_dcid(&mut self.clients, from, packet, accept_loop);
        if let Some(old_addr) = old_addr {
            self.pending_tun_downlinks.rebind_target(old_addr, from);
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
        let session_id = self.domain.session_id_by_remote(addr);
        if let Some(mut conn) = self.clients.remove(&addr) {
            let conn_id = conn.conn.source_id().as_ref().to_vec();
            if let Err(e) = conn.conn.close(true, 0x0, b"admin_kick") {
                log::warn!("Client close on admin kick failed for {}: {:?}", addr, e);
            }
            self.qkey_auth.remove(&conn_id);
            accept_loop.record_closed(addr);
            let (discarded_packets, discarded_bytes) = conn.discard_masque_downlink_packets();
            if discarded_packets > 0 {
                metrics.record_masque_downlink_response_terminal_drop(discarded_packets);
                log::warn!(
                    "dropping {} queued MASQUE responses ({} bytes) for administratively removed client {}",
                    discarded_packets,
                    discarded_bytes,
                    addr
                );
            }
        }
        let (discarded_packets, discarded_bytes) = self.pending_tun_downlinks.discard_target(addr);
        if discarded_packets > 0 {
            for _ in 0..discarded_packets {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
            }
            metrics.set_tun_downlink_backpressure_pending(
                self.pending_tun_downlinks.len(),
                self.pending_tun_downlinks.bytes(),
            );
            log::warn!(
                "dropping {} pending TUN downlinks ({} bytes) for administratively removed client {}",
                discarded_packets,
                discarded_bytes,
                addr
            );
        }
        self.dissociate_qkey_for_session(session_id);
        self.domain.remove_remote(addr);
        self.sync_active_metrics(metrics);
    }

    pub fn shutdown_all(&mut self, reason: &'static [u8], metrics: Option<&Metrics>) {
        for conn in self.clients.values_mut() {
            if let Err(e) = conn.conn.close(true, 0x0, reason) {
                log::warn!("Live client close failed for reason {:?}: {:?}", reason, e);
            }
            let (discarded_packets, discarded_bytes) = conn.discard_masque_downlink_packets();
            if discarded_packets > 0 {
                if let Some(metrics) = metrics {
                    metrics.record_masque_downlink_response_shutdown_drop(discarded_packets);
                }
                log::warn!(
                    "dropping {} queued MASQUE responses ({} bytes) during shutdown",
                    discarded_packets,
                    discarded_bytes
                );
            }
        }
        let (discarded_packets, discarded_bytes) = self.pending_tun_downlinks.discard_all();
        if discarded_packets > 0 {
            if let Some(metrics) = metrics {
                for _ in 0..discarded_packets {
                    metrics.record_tun_downlink_backpressure_drop(
                        TunDownlinkBackpressureDrop::Shutdown,
                    );
                }
                metrics.set_tun_downlink_backpressure_pending(0, 0);
            }
            log::warn!(
                "dropping {} pending TUN downlinks ({} bytes) during shutdown",
                discarded_packets,
                discarded_bytes
            );
        }
    }

    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    pub async fn force_close_and_flush(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        accept_loop: &AcceptLoop,
        reason: &'static [u8],
    ) {
        self.shutdown_all(reason, Some(metrics));
        let client_snapshots = Arc::clone(self.domain.client_snapshots());
        for addr in self.key_addrs() {
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
                    log::warn!("Failed to flush shutdown frame to {}: {}", addr, error);
                }
            }
        }
        self.reconcile(accept_loop, metrics);
    }

    pub fn reconcile(&mut self, accept_loop: &AcceptLoop, metrics: &Metrics) {
        let closed_addrs =
            reconcile_live_clients(&mut self.clients, &mut self.qkey_auth, accept_loop, metrics);
        for addr in closed_addrs {
            let session_id = self.domain.session_id_by_remote(addr);
            self.dissociate_qkey_for_session(session_id);
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
        for (addr, session_id) in expired_remotes {
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
            self.dissociate_qkey_for_session(Some(session_id));
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
            let key_id = self.qkey_auth.get(&conn_id).map(|state| state.key_id.clone());
            let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
            });
            for conn in self.values_mut() {
                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                    record_qkey_auth_rejection(metrics);
                    if let Err(error) = conn.conn.close(true, 0x0, b"qkey_auth_timeout") {
                        log::warn!("Client close after QKey auth timeout failed: {:?}", error);
                    }
                    break;
                }
            }
            let source_ip = remote_addr.map(|addr| addr.ip().to_string());
            crate::audit::audit(
                crate::audit::AuditEventType::AuthTimeout,
                crate::audit::AuditSeverity::Warning,
                source_ip.as_deref(),
                key_id.as_deref(),
                "QKey authentication timed out",
            );
            let session_id = self.session_id_for_conn_id(&conn_id);
            self.dissociate_qkey_for_session(session_id);
            self.remove_qkey_auth(&conn_id);
        }
    }

    pub fn commit_qkey_auth_result(
        &mut self,
        remove_auth_conn_id: Option<Vec<u8>>,
        auth_result: Option<(Vec<u8>, bool)>,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        if let Some(conn_id) = remove_auth_conn_id {
            self.remove_qkey_auth(&conn_id);
        } else if let Some((conn_id, authed)) = auth_result {
            let mut authed_key_id: Option<String> = None;
            if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                if authed {
                    authed_key_id = Some(state.key_id.clone());
                } else {
                    state.authed = false;
                    crate::audit::audit(
                        crate::audit::AuditEventType::AuthFailed,
                        crate::audit::AuditSeverity::Warning,
                        None,
                        Some(&state.key_id),
                        "QKey authentication failed",
                    );
                }
            }
            if let Some(key_id) = authed_key_id {
                if self.revocation_manager.is_revoked(&key_id) {
                    let addr = self.clients.iter().find_map(|(addr, conn)| {
                        (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                    });
                    if let Some(addr) = addr {
                        let session_id = self.domain.session_id_by_remote(addr);
                        if let Some(mut conn) = self.clients.remove(&addr) {
                            if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                                log::warn!(
                                    "Client close after pending QKey revocation failed for {}: {:?}",
                                    addr,
                                    error
                                );
                            }
                            accept_loop.record_closed(addr);
                            record_qkey_auth_rejection(metrics);
                        }
                        self.dissociate_qkey_for_session(session_id);
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    self.remove_qkey_auth(&conn_id);
                    return;
                }
                if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                    state.authed = true;
                }
                if let Some(session_id) = self.session_id_for_conn_id(&conn_id) {
                    self.qkey_tracker.associate(session_id.as_u64(), &key_id);
                }
                crate::audit::audit(
                    crate::audit::AuditEventType::ClientAuthenticated,
                    crate::audit::AuditSeverity::Info,
                    None,
                    Some(&key_id),
                    "Client authenticated successfully",
                );
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
    server_ips: ServerTunIps,
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
    routing: Option<RoutingManager>,
    /// Server TUN IP for ICMP echo reply handling.
    server_tun_ip: Option<Ipv4Addr>,
    server_tun_ipv6: Option<Ipv6Addr>,
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

fn write_tun_control_packet(tun: &TunInterface, packet: &[u8], context: &str) {
    if packet.is_empty() {
        return;
    }
    if let Err(error) = tun.write(packet) {
        log::warn!("{} write to server TUN failed: {:?}", context, error);
    }
}

fn handle_local_tun_packet(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    fingerprint_profile: OsFingerprintProfile,
    metrics: &Metrics,
) -> bool {
    if packet.len() >= 20 && packet[0] >> 4 == 4 {
        let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        if destination != server_ips.ipv4 {
            return false;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        if let Some(header) = icmp::parse_icmpv4(header_len, packet) {
            if header.icmp_type == icmp::icmp_type::ECHO_REQUEST {
                let reply = icmp::build_echo_reply_with_ttl(packet, fingerprint_profile.ttl());
                write_tun_control_packet(tun, &reply, "ICMPv4 echo reply");
            }
        }
        metrics.record_routing_outcome(RoutingOutcome::Local);
        return true;
    }

    let Some(server_ipv6) = server_ips.ipv6 else {
        return false;
    };
    let Some(header) = icmp::parse_icmpv6(packet) else {
        return false;
    };
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap_or([0; 16]));
    let response = if header.icmp_type == icmp::icmpv6_type::NEIGHBOR_SOLICITATION {
        icmp::build_neighbor_advertisement(packet, server_ipv6)
    } else if destination == server_ipv6 && header.icmp_type == icmp::icmpv6_type::ECHO_REQUEST {
        icmp::build_icmpv6_echo_reply(packet, fingerprint_profile.ttl())
    } else if destination == server_ipv6 {
        Vec::new()
    } else {
        return false;
    };
    write_tun_control_packet(tun, &response, "ICMPv6 local response");
    metrics.record_routing_outcome(RoutingOutcome::Local);
    metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
    true
}

fn write_downlink_error(
    packet: &[u8],
    tun: &TunInterface,
    server_ips: ServerTunIps,
    outcome: RoutingOutcome,
    mtu: Option<usize>,
    metrics: &Metrics,
) {
    let response = match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            let (icmp_type, code) = match outcome {
                RoutingOutcome::PacketTooBig => (
                    icmp::icmp_type::DESTINATION_UNREACHABLE,
                    icmp::icmp_code::FRAGMENTATION_NEEDED,
                ),
                RoutingOutcome::TimeExceeded => (icmp::icmp_type::TIME_EXCEEDED, 0),
                _ => (icmp::icmp_type::DESTINATION_UNREACHABLE, icmp::icmp_code::HOST_UNREACHABLE),
            };
            let next_hop_mtu = mtu.map(|value| value.min(usize::from(u16::MAX)) as u16);
            icmp::build_icmpv4_error(packet, server_ips.ipv4, icmp_type, code, next_hop_mtu)
        }
        Some(6) => {
            let Some(server_ipv6) = server_ips.ipv6 else {
                return;
            };
            let icmp_type = match outcome {
                RoutingOutcome::PacketTooBig => icmp::icmpv6_type::PACKET_TOO_BIG,
                RoutingOutcome::TimeExceeded => icmp::icmpv6_type::TIME_EXCEEDED,
                _ => icmp::icmpv6_type::DESTINATION_UNREACHABLE,
            };
            metrics.record_routing_outcome(RoutingOutcome::Icmpv6);
            icmp::build_icmpv6_error(
                packet,
                server_ipv6,
                icmp_type,
                mtu.map(|value| value.min(u32::MAX as usize) as u32),
            )
        }
        _ => return,
    };
    write_tun_control_packet(tun, &response, "routing ICMP response");
    metrics.record_routing_outcome(outcome);
}

/// Retry downlink packets that were deferred because a client's QUIC DATAGRAM
/// queue was full. Successfully enqueued packets are flushed to the socket;
/// entries that are still backpressured remain in the pending queue.
fn drain_pending_tun_downlinks(
    live: &mut ServerLiveRuntime,
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
) {
    let mut still_pending = std::collections::VecDeque::new();
    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    let now = Instant::now();
    while let Some(entry) = live.live_state.pending_tun_downlinks.pop_front() {
        if entry.is_expired(now) {
            metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);
            log::warn!(
                "dropping expired pending TUN downlink for {} after {} ms",
                entry.target,
                now.duration_since(entry.queued_at).as_millis()
            );
            continue;
        }
        let target = entry.target;
        let send_result = {
            let Some(connection) = live.live_state.clients.get_mut(&target) else {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!(
                    "dropping pending TUN downlink for {} because its connection no longer exists",
                    target
                );
                continue;
            };
            connection.send_masque_downlink(&entry.packet)
        };
        match send_result {
            Ok(()) => queued.push(target),
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                log::debug!("pending TUN downlink for {} still backpressured", target);
                metrics.record_tun_downlink_backpressure_retry();
                still_pending.push_back(entry);
            }
            Err(error) => {
                metrics.record_tun_downlink_backpressure_drop(
                    TunDownlinkBackpressureDrop::TerminalTransportError,
                );
                log::warn!("pending TUN downlink for {} failed: {:?}", target, error);
            }
        }
    }

    // Return still-pending entries to the queue in their original order.
    for entry in still_pending {
        live.live_state.pending_tun_downlinks.requeue(entry);
    }
    metrics.set_tun_downlink_backpressure_pending(
        live.live_state.pending_tun_downlinks.len(),
        live.live_state.pending_tun_downlinks.bytes(),
    );

    flush_tun_downlink_queue(live, &queued, out, socket, metrics);
}

/// Flush a list of client connections whose downlink datagrams have been
/// enqueued. Callers are responsible for collecting `queued` addresses.
fn flush_tun_downlink_queue(
    live: &mut ServerLiveRuntime,
    queued: &[SocketAddr],
    out: &mut [u8],
    socket: &UdpSocket,
    _metrics: &Metrics,
) {
    for target in queued {
        let Some(connection) = live.live_state.clients.get_mut(target) else {
            continue;
        };
        loop {
            let written = match connection.send(out) {
                Ok(0) => {
                    log::debug!("TUN to socket send to {}: connection.send returned 0", target);
                    break;
                }
                Ok(written) => written,
                Err(error) => {
                    log::warn!(
                        "TUN to socket send to {}: connection.send failed: {:?}",
                        target,
                        error
                    );
                    break;
                }
            };
            if let Err(error) = socket.try_send_to(&out[..written], *target) {
                log::warn!("TUN to socket send to {} failed: {:?}", target, error);
                break;
            }
            log::debug!("TUN to socket send to {}: sent {}B", target, written);
        }
    }
}

fn process_server_tun_packet(
    live: &mut ServerLiveRuntime,
    packet: &[u8],
    out: &mut [u8],
    socket: &UdpSocket,
    metrics: &Metrics,
    fingerprint_profile: OsFingerprintProfile,
) {
    let Some(tun) = live.server_tun.clone() else {
        return;
    };
    let server_ips = ServerTunIps {
        ipv4: live.server_tun_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
        ipv6: live.server_tun_ipv6,
    };
    if handle_local_tun_packet(packet, &tun, server_ips, fingerprint_profile, metrics) {
        return;
    }

    let policy = Arc::clone(&live.live_state.domain.shared.forwarding_policy);
    let route = policy.classify_downlink(packet, server_ips.ipv4, server_ips.ipv6);
    log::debug!(
        "process_server_tun_packet: {}B route={:?} assigned_count={}",
        packet.len(),
        route,
        policy.assigned_address_count()
    );
    let expired = matches!(route, DownlinkRoute::Unicast { .. })
        && match packet.first().map(|byte| byte >> 4) {
            Some(4) => packet.get(8).is_some_and(|ttl| *ttl == 0),
            Some(6) => packet.get(7).is_some_and(|hop_limit| *hop_limit == 0),
            _ => false,
        };
    if expired {
        write_downlink_error(packet, &tun, server_ips, RoutingOutcome::TimeExceeded, None, metrics);
        return;
    }
    let mut targets = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    {
        let sessions = live.live_state.domain.shared.sessions.read();
        match route {
            DownlinkRoute::Unicast { destination, .. } => {
                let target = match destination {
                    std::net::IpAddr::V4(ipv4) => sessions.get_by_client_ip(ipv4),
                    std::net::IpAddr::V6(ipv6) => sessions.get_by_client_ipv6(ipv6),
                };
                if let Some(session) = target {
                    targets.push(session.remote_addr());
                }
                metrics.record_routing_outcome(RoutingOutcome::Unicast);
            }
            DownlinkRoute::Fanout { source, destination } => {
                for (_, session) in sessions.iter() {
                    let owns_source = match source {
                        std::net::IpAddr::V4(ipv4) => session.client_ip() == ipv4,
                        std::net::IpAddr::V6(ipv6) => session.client_ipv6() == Some(ipv6),
                    };
                    let supports_family = destination.is_ipv4() || session.client_ipv6().is_some();
                    if !owns_source && supports_family {
                        targets.push(session.remote_addr());
                    }
                }
                metrics.record_routing_outcome(RoutingOutcome::Fanout);
            }
            DownlinkRoute::Unknown { .. } => {
                drop(sessions);
                write_downlink_error(
                    packet,
                    &tun,
                    server_ips,
                    RoutingOutcome::Unknown,
                    None,
                    metrics,
                );
                return;
            }
            DownlinkRoute::Malformed => {
                metrics.routing_drop_malformed.fetch_add(1, Ordering::Relaxed);
                return;
            }
            DownlinkRoute::Local { .. } => return,
        }
    }

    let mut queued = smallvec::SmallVec::<[SocketAddr; 4]>::new();
    log::debug!(
        "process_server_tun_packet: targets={} clients_count={}",
        targets.len(),
        live.live_state.clients.len()
    );
    for target in targets {
        let send_result = {
            let Some(connection) = live.live_state.clients.get_mut(&target) else {
                log::debug!("process_server_tun_packet: no connection for target {}", target);
                continue;
            };
            let effective_mtu = connection.effective_tunnel_mtu().min(usize::from(tun.mtu()));
            if packet.len() > effective_mtu {
                if matches!(route, DownlinkRoute::Unicast { .. }) {
                    write_downlink_error(
                        packet,
                        &tun,
                        server_ips,
                        RoutingOutcome::PacketTooBig,
                        Some(effective_mtu),
                        metrics,
                    );
                }
                continue;
            }
            connection.send_masque_downlink(packet)
        };
        match send_result {
            Ok(()) => queued.push(target),
            Err(crate::error::ConnectionError::DgramQueueFull) => {
                match live.live_state.pending_tun_downlinks.enqueue(
                    target,
                    packet.to_vec(),
                    Instant::now(),
                ) {
                    Ok(()) => {
                        metrics.record_tun_downlink_backpressure_enqueued();
                        metrics.set_tun_downlink_backpressure_pending(
                            live.live_state.pending_tun_downlinks.len(),
                            live.live_state.pending_tun_downlinks.bytes(),
                        );
                    }
                    Err(reject) => {
                        metrics.record_tun_downlink_backpressure_drop(reject.into());
                        log::warn!(
                            "dropping TUN downlink for {} after bounded backpressure rejection: {:?}",
                            target,
                            reject
                        );
                    }
                }
            }
            Err(error) => {
                log::warn!("TUN to MASQUE queue for {} failed: {:?}", target, error);
            }
        }
    }

    flush_tun_downlink_queue(live, &queued, out, socket, metrics);
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
const FINAL_CLOSE_FLUSH_TIMEOUT: Duration = Duration::from_millis(500);
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
    pub key_id: String,
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
    quic_versions: Option<Vec<u32>>,
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
    pmtu_min_mtu: Option<usize>,
    pmtu_max_mtu: Option<usize>,
    pmtu_probe_interval_ms: Option<u64>,
    pmtu_black_hole_timeout_ms: Option<u64>,
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
    sc.fronting_domains = front_domain.to_vec();
    sc.enable_domain_fronting = !disable_fronting
        && (!sc.fronting_domains.is_empty() || matches!(sc.mode, StealthMode::AntiDpi));
    sc.enable_http3_masquerading = !disable_http3;
    if disable_http3 {
        sc.use_qpack_headers = false;
        sc.enable_protocol_mimicry = false;
    } else {
        sc.normalize_protocol_mimicry_bundle();
    }
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

    if let Some(value) = tbl.get("quic_versions") {
        let versions = value
            .as_array()
            .ok_or_else(|| "transport.quic_versions must be an array".to_string())?;
        if versions.is_empty() {
            return Err("transport.quic_versions must not be empty".to_string());
        }
        let mut parsed = Vec::with_capacity(versions.len());
        for value in versions {
            let name = value
                .as_str()
                .ok_or_else(|| "transport.quic_versions entries must be strings".to_string())?;
            let version = match name.trim().to_ascii_lowercase().as_str() {
                "v2" => crate::transport::PROTOCOL_VERSION_V2,
                "v1" => crate::transport::PROTOCOL_VERSION,
                _ => {
                    return Err(format!(
                        "transport.quic_versions entry '{}' is not supported",
                        name
                    ));
                }
            };
            if parsed.contains(&version) {
                return Err("transport.quic_versions must not contain duplicates".to_string());
            }
            parsed.push(version);
        }
        out.quic_versions = Some(parsed);
    }

    if let Some(v) = tbl.get("cc_algorithm") {
        let raw =
            v.as_str().ok_or_else(|| "transport.cc_algorithm must be a string".to_string())?;
        let name = raw.trim().to_lowercase();
        let algo = match name.as_str() {
            "reno" => Some(crate::transport::CongestionControlAlgorithm::Reno),
            "cubic" => Some(crate::transport::CongestionControlAlgorithm::Cubic),
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
    for (key, destination) in
        [("pmtu_min_mtu", &mut out.pmtu_min_mtu), ("pmtu_max_mtu", &mut out.pmtu_max_mtu)]
    {
        if let Some(value) = tbl.get(key) {
            let value =
                value.as_integer().ok_or_else(|| format!("transport.{key} must be an integer"))?;
            if !(1200..=u16::MAX as i64).contains(&value) {
                return Err(format!("transport.{key} must be between 1200 and 65535"));
            }
            *destination = Some(value as usize);
        }
    }
    for (key, destination) in [
        ("pmtu_probe_interval_ms", &mut out.pmtu_probe_interval_ms),
        ("pmtu_black_hole_timeout_ms", &mut out.pmtu_black_hole_timeout_ms),
    ] {
        if let Some(value) = tbl.get(key) {
            let value =
                value.as_integer().ok_or_else(|| format!("transport.{key} must be an integer"))?;
            if value <= 0 {
                return Err(format!("transport.{key} must be > 0"));
            }
            *destination = Some(value as u64);
        }
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

    if let Some(versions) = overrides.quic_versions {
        if let Err(error) = transport.set_supported_versions(versions) {
            log::warn!("transport QUIC version override ignored: {error}");
        }
    }
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
    if overrides.pmtu_min_mtu.is_some()
        || overrides.pmtu_max_mtu.is_some()
        || overrides.pmtu_probe_interval_ms.is_some()
        || overrides.pmtu_black_hole_timeout_ms.is_some()
    {
        let current = transport.pmtu_policy();
        let policy = crate::transport::PmtuPolicy {
            min_mtu: overrides.pmtu_min_mtu.unwrap_or(current.min_mtu),
            max_mtu: overrides.pmtu_max_mtu.unwrap_or(current.max_mtu),
            probe_interval: Duration::from_millis(
                overrides
                    .pmtu_probe_interval_ms
                    .unwrap_or(current.probe_interval.as_millis().min(u128::from(u64::MAX)) as u64),
            ),
            black_hole_timeout: Duration::from_millis(
                overrides.pmtu_black_hole_timeout_ms.unwrap_or(
                    current.black_hole_timeout.as_millis().min(u128::from(u64::MAX)) as u64,
                ),
            ),
        };
        if let Err(error) = transport.set_pmtu_policy(policy) {
            log::warn!("transport DPLPMTUD policy ignored: {error}");
        }
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

/// Extract the destination IPv4 address from a raw IP packet.
///
/// Returns `None` if the packet is too short, is not IPv4, or has options
/// that make the header length invalid.
#[cfg(test)]
fn parse_ipv4_dest(pkt: &[u8]) -> Option<std::net::Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    // Destination IP is at bytes 16-19
    let dest = std::net::Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some(dest)
}

/// Extract the destination IPv6 address from a raw IP packet.
/// Returns None if the packet is too short or is not IPv6.
#[cfg(test)]
fn parse_ipv6_dest(pkt: &[u8]) -> Option<Ipv6Addr> {
    if pkt.len() < 40 {
        return None;
    }
    let version = pkt[0] >> 4;
    if version != 6 {
        return None;
    }
    // IPv6 destination address is at offset 24-39
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&pkt[24..40]);
    Some(Ipv6Addr::from(addr))
}

/// Extract the destination IP address (IPv4 or IPv6) from a raw IP packet.
#[cfg(test)]
fn parse_ip_dest(pkt: &[u8]) -> Option<std::net::IpAddr> {
    if pkt.is_empty() {
        return None;
    }
    let version = pkt[0] >> 4;
    match version {
        4 => parse_ipv4_dest(pkt).map(std::net::IpAddr::V4),
        6 => parse_ipv6_dest(pkt).map(std::net::IpAddr::V6),
        _ => None,
    }
}

struct InterceptedIpv4DnsQuery<'a> {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: &'a [u8],
}

struct InterceptedIpv6DnsQuery<'a> {
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    hop_limit: u8,
    payload: &'a [u8],
}

fn parse_ipv4_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv4DnsQuery<'_>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl + 8 || total_len > pkt.len() {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_fragment & 0x1fff != 0 {
        return None;
    }
    if pkt[9] != 17 {
        return None;
    }

    let udp = &pkt[ihl..total_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }

    Some(InterceptedIpv4DnsQuery {
        src_ip: Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        dst_ip: Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
        src_port,
        dst_port,
        ttl: pkt[8],
        payload,
    })
}

fn parse_ipv6_udp_dns_query(pkt: &[u8]) -> Option<InterceptedIpv6DnsQuery<'_>> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if payload_len < 8 || 40usize.checked_add(payload_len)? > pkt.len() {
        return None;
    }
    if pkt[6] != 17 {
        return None;
    }

    let udp = &pkt[40..40 + payload_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return None;
    }
    let payload = &udp[8..udp_len];
    if !crate::dns::is_dns_query(payload) {
        return None;
    }

    let mut src = [0u8; 16];
    src.copy_from_slice(&pkt[8..24]);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(&pkt[24..40]);
    Some(InterceptedIpv6DnsQuery {
        src_ip: Ipv6Addr::from(src),
        dst_ip: Ipv6Addr::from(dst),
        src_port,
        dst_port,
        hop_limit: pkt[7],
        payload,
    })
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add((byte as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp_packet);
    let checksum = ones_complement_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn ipv6_udp_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp_packet.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(udp_packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0]);
    pseudo.push(17);
    pseudo.extend_from_slice(udp_packet);
    let checksum = ones_complement_checksum(&pseudo);
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn build_ipv4_udp_dns_response_packet(
    query: &InterceptedIpv4DnsQuery<'_>,
    dns_response: &[u8],
    fingerprint_profile: OsFingerprintProfile,
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(dns_response.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    if udp_len > u16::MAX as usize || total_len > u16::MAX as usize {
        return None;
    }

    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes());
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    pkt[8] = fingerprint_profile.ttl().max(query.ttl);
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&query.dst_ip.octets());
    pkt[16..20].copy_from_slice(&query.src_ip.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_start = 20;
    pkt[udp_start..udp_start + 2].copy_from_slice(&query.dst_port.to_be_bytes());
    pkt[udp_start + 2..udp_start + 4].copy_from_slice(&query.src_port.to_be_bytes());
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[udp_start + 8..].copy_from_slice(dns_response);
    let udp_checksum = ipv4_udp_checksum(query.dst_ip, query.src_ip, &pkt[udp_start..]);
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(pkt)
}

fn build_ipv6_udp_dns_response_packet(
    query: &InterceptedIpv6DnsQuery<'_>,
    dns_response: &[u8],
    fingerprint_profile: OsFingerprintProfile,
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(dns_response.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }
    let total_len = 40usize.checked_add(udp_len)?;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[6] = 17;
    pkt[7] = fingerprint_profile.ttl().max(query.hop_limit);
    pkt[8..24].copy_from_slice(&query.dst_ip.octets());
    pkt[24..40].copy_from_slice(&query.src_ip.octets());

    let udp_start = 40;
    pkt[udp_start..udp_start + 2].copy_from_slice(&query.dst_port.to_be_bytes());
    pkt[udp_start + 2..udp_start + 4].copy_from_slice(&query.src_port.to_be_bytes());
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[udp_start + 8..].copy_from_slice(dns_response);
    let udp_checksum = ipv6_udp_checksum(query.dst_ip, query.src_ip, &pkt[udp_start..]);
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    Some(pkt)
}

fn resolve_dns_query_via_upstream(query: &[u8], upstream_resolvers: &[Ipv4Addr]) -> Vec<u8> {
    for upstream in upstream_resolvers {
        match crate::dns::forward_dns_query(query, *upstream) {
            Ok(response) => return response,
            Err(error) => log::debug!("DNS upstream {} failed: {}", upstream, error),
        }
    }
    match crate::dns::parse_dns_query(query) {
        Some(parsed) => crate::dns::build_dns_nxdomain(&parsed),
        None => Vec::new(),
    }
}

fn spawn_dns_intercept(
    pkt: &[u8],
    upstream_resolvers: Arc<Vec<Ipv4Addr>>,
    downlink_queue: Arc<std::sync::Mutex<crate::core::MasqueDownlinkQueue>>,
    metrics: Arc<Metrics>,
    fingerprint_profile: OsFingerprintProfile,
) -> bool {
    let parsed = parse_ipv4_udp_dns_query(pkt)
        .map(|query| {
            let src_ip = query.src_ip;
            let dst_ip = query.dst_ip;
            let src_port = query.src_port;
            let dst_port = query.dst_port;
            let ttl = query.ttl;
            let payload = query.payload.to_vec();
            Box::new(move |response: &[u8]| {
                let query = InterceptedIpv4DnsQuery {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ttl,
                    payload: &payload,
                };
                build_ipv4_udp_dns_response_packet(&query, response, fingerprint_profile)
            }) as Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send>
        })
        .or_else(|| {
            parse_ipv6_udp_dns_query(pkt).map(|query| {
                let src_ip = query.src_ip;
                let dst_ip = query.dst_ip;
                let src_port = query.src_port;
                let dst_port = query.dst_port;
                let hop_limit = query.hop_limit;
                let payload = query.payload.to_vec();
                Box::new(move |response: &[u8]| {
                    let query = InterceptedIpv6DnsQuery {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        hop_limit,
                        payload: &payload,
                    };
                    build_ipv6_udp_dns_response_packet(&query, response, fingerprint_profile)
                }) as Box<dyn FnOnce(&[u8]) -> Option<Vec<u8>> + Send>
            })
        });
    let Some(build_response_packet) = parsed else {
        return false;
    };
    let payload = if let Some(query) = parse_ipv4_udp_dns_query(pkt) {
        query.payload.to_vec()
    } else if let Some(query) = parse_ipv6_udp_dns_query(pkt) {
        query.payload.to_vec()
    } else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        let response = resolve_dns_query_via_upstream(&payload, upstream_resolvers.as_slice());
        if response.is_empty() {
            return;
        }
        if let Some(packet) = build_response_packet(&response) {
            let admission = match downlink_queue.lock() {
                Ok(mut guard) => guard.enqueue(packet),
                Err(poisoned) => poisoned.into_inner().enqueue(packet),
            };
            if let Err(reason) = admission {
                metrics.record_masque_downlink_response_drop(reason);
            }
        }
    });
    true
}

pub(crate) fn open_server_tun(
    tun_config: TunConfig,
    pool: Arc<MemoryPool>,
) -> Result<TunInterface, String> {
    crate::interface::validate_tun_runtime_requirements().map_err(|e| format!("{:?}", e))?;
    TunInterface::open(tun_config, pool).map_err(|e| format!("{:?}", e))
}

enum ServerSignalEvent {
    Shutdown(&'static [u8]),
    Reload,
}

#[cfg(unix)]
struct ServerSignals {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ServerSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self {
            sigint: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            sigterm: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            sighup: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?,
        })
    }

    async fn recv(&mut self) -> ServerSignalEvent {
        tokio::select! {
            _ = self.sigint.recv() => {
                log::info!("SIGINT received");
                ServerSignalEvent::Shutdown(b"sigint")
            }
            _ = self.sigterm.recv() => {
                log::info!("SIGTERM received");
                ServerSignalEvent::Shutdown(b"sigterm")
            }
            _ = self.sighup.recv() => {
                log::info!("SIGHUP received");
                ServerSignalEvent::Reload
            }
        }
    }
}

#[cfg(not(unix))]
struct ServerSignals;

#[cfg(not(unix))]
impl ServerSignals {
    fn install() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> ServerSignalEvent {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Shutdown signal received");
        ServerSignalEvent::Shutdown(b"shutdown")
    }
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
                Ok(_) => {
                    Err(std::io::Error::new(ErrorKind::UnexpectedEof, "negative recv_from result"))
                }
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
            Ok(result) => return Ok(result),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
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
            graceful_shutdown: Arc::new(GracefulShutdown::new(
                engine_config.engine.shutdown_timeout_ms,
            )),
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
        let socket_ref = socket2::SockRef::from(&std_socket);
        if let Err(error) =
            socket_ref.set_recv_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES)
        {
            log::debug!("UDP receive buffer hint rejected: {}", error);
        }
        if let Err(error) =
            socket_ref.set_send_buffer_size(crate::transport::UDP_SOCKET_BUFFER_BYTES)
        {
            log::debug!("UDP send buffer hint rejected: {}", error);
        }
        std_socket.set_nonblocking(true)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let local_addr = socket.local_addr()?;
        let (admin_actions_tx, admin_actions_rx) = mpsc::unbounded_channel::<AdminAction>();
        let accept_max_clients = server_config.max_clients;
        let server_tun_ip = Some(server_config.server_ip);
        let server_tun_ipv6 = server_config.ipv6_server_ip;
        let (server_tun, tun_rx, routing) = match tun_config {
            Some(tun_config) => {
                let optm = crate::optimize::OptimizationManager::from_cfg(opt_params);
                match open_server_tun(tun_config, optm.memory_pool()) {
                    Ok(tun) => {
                        #[cfg(target_os = "linux")]
                        let routing = {
                            let routing =
                                configured_routing_manager(tun.name().to_string(), &server_config)
                                    .map_err(std::io::Error::other)?;
                            routing.cleanup_stale();
                            if let Err(error) = routing.setup() {
                                let _ = routing.teardown();
                                return Err(std::io::Error::other(format!(
                                    "standalone server routing setup failed: {error}"
                                )));
                            }
                            Some(routing)
                        };
                        #[cfg(not(target_os = "linux"))]
                        let routing = None;
                        let tun_arc = Arc::new(tun);
                        // Spawn a blocking reader thread that forwards TUN frames into a channel.
                        // These packets are forwarded to the client via QUIC datagrams in the run_loop.
                        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(
                            crate::interface::TUN_PACKET_QUEUE_CAPACITY,
                        );
                        let tun_for_reader = tun_arc.clone();
                        let _handle = std::thread::Builder::new()
                            .name("tun-reader".to_string())
                            .spawn(move || loop {
                                match tun_for_reader.read_block() {
                                    Ok((block, len)) if len > 0 => {
                                        let mut v = vec![0u8; len];
                                        v.copy_from_slice(&block[..len]);
                                        log::debug!(
                                            "TUN reader: read {}B proto={:#x} dst={}",
                                            len,
                                            v[0] >> 4,
                                            if v[0] >> 4 == 4 && v.len() >= 20 {
                                                format!("{}.{}.{}.{}", v[16], v[17], v[18], v[19])
                                            } else {
                                                String::from("?")
                                            }
                                        );
                                        if tx.send(v).is_err() {
                                            log::warn!(
                                                "TUN reader: channel closed, exiting thread"
                                            );
                                            break;
                                        }
                                    }
                                    Ok(_) => {}
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        std::thread::sleep(Duration::from_millis(1));
                                    }
                                    Err(e) => {
                                        log::warn!(
                                            "TUN reader: fatal error {:?}, exiting thread",
                                            e
                                        );
                                        break;
                                    }
                                }
                            });
                        log::info!("Server TUN reader thread spawned for bidirectional forwarding");
                        (Some(tun_arc), Some(rx), routing)
                    }
                    Err(error) => {
                        return Err(std::io::Error::other(format!(
                            "standalone server TUN open failed: {error}"
                        )));
                    }
                }
            }
            None => (None, None, None),
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
            routing,
            server_tun_ip,
            server_tun_ipv6,
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
        self.graceful_shutdown.set_running();

        Ok(())
    }

    /// Stop the server.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        if self.state == ServerState::Stopped {
            if let Some(routing) = self.live.as_mut().and_then(|live| live.routing.take()) {
                teardown_routing_with_retries(routing);
            }
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
        if let Some(routing) = self.live.as_mut().and_then(|live| live.routing.take()) {
            teardown_routing_with_retries(routing);
        }

        self.state = ServerState::Stopped;
        self.graceful_shutdown.set_stopped();
        log::info!("Server stopped");

        Ok(())
    }

    /// Handle new client connection.
    pub fn accept_client(&self, remote_addr: SocketAddr) -> Result<SessionId, AcceptError> {
        let (session_id, _stats, assigned_ips) = {
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

        log::info!("Client connected: {} -> {}", remote_addr, assigned_ips.ipv4);
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionEstablished,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client connection accepted",
        );

        Ok(session_id)
    }

    /// Remove client session.
    pub fn remove_client(&self, session_id: SessionId) {
        let session = self.domain.remove(session_id);

        if let Some(session) = session {
            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            let source_ip = session.remote_addr().ip().to_string();
            let client_id = session.id().as_u64().to_string();
            crate::audit::audit(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                Some(&source_ip),
                Some(&client_id),
                "Client session removed",
            );

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
            ServerAdminControlPlane {
                actions: self.admin_actions_sender(),
                listen_addr: self.local_addr().to_string(),
                front_domain: self
                    .live()
                    .standalone_runtime_metadata
                    .as_ref()
                    .map(|metadata| metadata.front_domain.clone())
                    .unwrap_or_default(),
                qkeys: self.qkey_registry().clone(),
                graceful_shutdown: self.graceful_shutdown.clone(),
            },
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
            server_ips: ServerTunIps {
                ipv4: live.server_tun_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                ipv6: live.server_tun_ipv6,
            },
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
        let fingerprint_profile = runtime_config.transport.fingerprint_profile();
        let dns_upstream_resolvers = Arc::new(self.server_config.dns_servers.clone());
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
        let mut buf = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
        let mut out = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
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

        let mut server_signals = match ServerSignals::install() {
            Ok(signals) => signals,
            Err(error) => {
                let live = self.live_mut();
                live.admin_actions_rx = Some(admin_actions_rx);
                live.service_signals.shutdown_all();
                if let Err(stop_error) = self.stop() {
                    log::warn!(
                        "Server cleanup after signal handler installation failure failed: {}",
                        stop_error
                    );
                }
                return Err(error);
            }
        };

        #[cfg(unix)]
        {
            record_systemd_notification("READY=1", self::systemd::notify::ready());
            record_systemd_notification(
                "STATUS=Accepting connections",
                self::systemd::notify::status("Accepting connections"),
            );
        }
        #[cfg(unix)]
        let watchdog_interval = self::systemd::notify::watchdog_interval();
        #[cfg(unix)]
        let mut next_watchdog = watchdog_interval.map(|interval| Instant::now() + interval);

        loop {
            let send_deadline = self.live().live_state.next_outbound_release_deadline();
            tokio::select! {
                Some(action) = admin_actions_rx.recv() => {
                    self.handle_admin_action_with_runtime_reload(
                        action,
                        &metrics,
                        runtime_config,
                    );
                }
                signal = server_signals.recv() => {
                    match signal {
                        ServerSignalEvent::Shutdown(reason) => {
                            self.initiate_drain(reason);
                        }
                        ServerSignalEvent::Reload => {
                            self.reload_standalone_runtime(runtime_config, "SIGHUP");
                        }
                    }
                }
                recv_res = recv_datagram_from(&socket, &mut buf) => {
                    match recv_res {
                        Ok((len, from)) => {
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
                            if let Ok(Some(response)) = stateless_version_negotiation_response(
                                &buf[..len],
                                runtime_config.transport.supported_versions(),
                            )
                            {
                                match socket.send_to(&response, from).await {
                                    Ok(sent) => metrics.record_egress_datagram(sent),
                                    Err(error) => {
                                        log::warn!(
                                            "failed to send version negotiation to {}: {}",
                                            from,
                                            error
                                        );
                                    }
                                }
                                continue;
                            }

                            let runtime_parts = self.live_parts();
                            let client_snapshots = runtime_parts.live_state.client_snapshots().clone();
                            let auth_rate_limiter = runtime_parts.live_state.auth_rate_limiter.clone();
                            let revocation_manager =
                                Arc::clone(&runtime_parts.live_state.revocation_manager);
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
                                            revocation_manager: revocation_manager.as_ref(),
                                            metrics: &metrics,
                                            stealth_config: &stealth_config,
                                            fec_cfg_shared: &fec_cfg_shared,
                                            opt_params_shared: &opt_params_shared,
                                        transport_config: transport,
                                        profile,
                                        os,
                                        disable_doh,
                                        auth_rate_limiter: auth_rate_limiter.clone(),
                                        doh_provider: doh_provider.as_str(),
                                        disable_fronting,
                                        front_domain: &front_domain,
                                        disable_http3,
                                    },
                                )
                            },
                            ) {
                                LiveClientAcquire::Ready(v) => {
                                    v
                                },
                                LiveClientAcquire::Backpressure => {
                                    tokio::time::sleep(runtime_parts.accept_loop.backpressure_delay()).await;
                                    continue;
                                }
                                LiveClientAcquire::Rejected => {
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
                                runtime_parts.server_ips,
                                tun_enable,
                                transport.fingerprint_profile(),
                                Arc::clone(&dns_upstream_resolvers),
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
                                runtime_parts.accept_loop,
                                &metrics,
                            );
                            runtime_parts.live_state.drain_client_fanout(&metrics);
                        }
                        Err(e) => {
                            log::error!("Failed to read from socket: {}", e);
                        }
                    }
                }
                _ = wait_for_send_deadline(send_deadline) => {
                    self.live_mut().live_state.flush_due_outgoing(&socket, &mut out, &metrics).await;
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
                    // Retry any downlinks that were deferred because a client's QUIC
                    // DATAGRAM queue was full, before reading new TUN frames.
                    drain_pending_tun_downlinks(self.live_mut(), &mut out, &socket, &metrics);

                    // Forward TUN→client: drain any packets from the TUN reader thread
                    // and route them to the correct client based on the destination IP
                    // in the IP packet header. Each client has a unique TUN IP from the
                    // server's IP pool, and we look up the session by client_ip to find
                    // the corresponding SocketAddr.
                    if let Some(ref rx) = tun_rx {
                        for _ in 0..32 {
                            match rx.try_recv() {
                                Ok(pkt) => {
                                    let live = self.live_mut();
                                    process_server_tun_packet(
                                        live,
                                        &pkt,
                                        &mut out,
                                        &socket,
                                        &metrics,
                                        fingerprint_profile,
                                    );
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                    tun_rx = None;
                                    break;
                                }
                            }
                        }
                    }
                    // Retry/final-flush any downlinks that were deferred during the
                    // TUN drain above.
                    drain_pending_tun_downlinks(self.live_mut(), &mut out, &socket, &metrics);

                    // Sweep expired entries from 0-RTT anti-replay strike register.
                    if let Some(ref sr) = runtime_config.strike_register {
                        sr.cleanup(std::time::Instant::now());
                    }
                    #[cfg(unix)]
                    if let (Some(interval), Some(deadline)) =
                        (watchdog_interval, next_watchdog)
                    {
                        if Instant::now() >= deadline {
                            record_systemd_notification(
                                "WATCHDOG=1",
                                self::systemd::notify::watchdog(),
                            );
                            next_watchdog = Some(Instant::now() + interval);
                        }
                    }
                    if self.drain_complete() {
                        log::info!(
                            "Server drain complete (active_clients={}, elapsed_ms={})",
                            self.live().live_state.client_count(),
                            self.graceful_shutdown.elapsed().as_millis()
                        );
                        self.finish_drain(
                            &socket,
                            &mut out,
                            &metrics,
                            b"server_shutdown",
                        )
                        .await;
                        break;
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
                crate::audit::audit(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    Some(&id),
                    "Admin kicked client",
                );
                false
            }
            AdminAction::RevokeQKey(id) => {
                let live = self.live_mut();
                live.live_state.revoke_qkey_now(&id, "admin_revoked", &live.accept_loop, metrics);
                crate::audit::audit(
                    crate::audit::AuditEventType::QkeyRevoked,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    Some(&id),
                    "Admin revoked QKey",
                );
                false
            }
            AdminAction::Reload => {
                match reload() {
                    Ok(()) => {
                        crate::audit::audit(
                            crate::audit::AuditEventType::ConfigReloaded,
                            crate::audit::AuditSeverity::Info,
                            None,
                            None,
                            "Admin triggered config reload",
                        );
                    }
                    Err(error) => {
                        log::warn!("Config reload failed: {}", error);
                        crate::audit::audit(
                            crate::audit::AuditEventType::AdminAction,
                            crate::audit::AuditSeverity::Warning,
                            None,
                            None,
                            &format!("Config reload failed: {error}"),
                        );
                    }
                }
                false
            }
            AdminAction::Drain => {
                log::info!("Admin drain requested");
                crate::audit::audit(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    "Admin requested server drain",
                );
                self.initiate_drain(b"admin_drain");
                false
            }
            AdminAction::Shutdown => {
                log::info!("Admin shutdown requested");
                crate::audit::audit(
                    crate::audit::AuditEventType::ServerStopped,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    "Admin requested server shutdown",
                );
                self.initiate_drain(b"admin_shutdown");
                false
            }
        }
    }

    fn handle_admin_action_with_runtime_reload(
        &mut self,
        action: AdminAction,
        metrics: &Arc<Metrics>,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) {
        if matches!(&action, AdminAction::Reload) {
            self.reload_standalone_runtime(runtime_config, "admin");
            return;
        }
        self.handle_admin_action(action, metrics, || Ok(()));
    }

    fn reload_standalone_runtime(
        &mut self,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
        origin: &str,
    ) {
        if self.graceful_shutdown.lifecycle() != ShutdownLifecycle::Running {
            log::warn!("Config reload ignored during server drain ({})", origin);
            return;
        }
        #[cfg(unix)]
        {
            record_systemd_notification("RELOADING=1", self::systemd::notify::reloading());
            record_systemd_notification(
                "STATUS=Reloading configuration",
                self::systemd::notify::status("Reloading configuration"),
            );
        }

        let runtime_metadata = self.live().standalone_runtime_metadata.clone();
        let result: Result<(), String> = (|| {
            let runtime_metadata = runtime_metadata.as_ref().ok_or_else(|| {
                "Config reload requested but runtime metadata is unavailable".to_string()
            })?;
            let cfg_path = runtime_metadata
                .config_path
                .as_deref()
                .ok_or_else(|| "Config reload requested but no config path is set".to_string())?;
            let engine_config = EngineConfig::from_file(cfg_path)
                .map_err(|error| format!("Engine config parse failed: {error}"))?;
            engine_config
                .validate()
                .map_err(|error| format!("Engine config validation failed: {error}"))?;
            apply_runtime_config_reload(
                cfg_path,
                runtime_metadata.reload_policy.fec_mode_override,
                &mut runtime_config.transport,
                &runtime_config.fec_cfg_shared,
                &runtime_config.opt_params_shared,
                &runtime_config.stealth_config,
                runtime_metadata.reload_policy.stealth_policy.as_runtime_policy(),
            )?;
            self.engine_config.engine.shutdown_timeout_ms =
                engine_config.engine.shutdown_timeout_ms;
            self.graceful_shutdown.set_grace_ms(engine_config.engine.shutdown_timeout_ms);
            Ok(())
        })();

        match result {
            Ok(()) => {
                log::info!("Configuration reloaded successfully ({})", origin);
                crate::audit::audit(
                    crate::audit::AuditEventType::ConfigReloaded,
                    crate::audit::AuditSeverity::Info,
                    None,
                    None,
                    &format!("{origin} triggered config reload"),
                );
            }
            Err(error) => {
                log::warn!("Config reload failed ({}): {}", origin, error);
                crate::audit::audit(
                    crate::audit::AuditEventType::AdminAction,
                    crate::audit::AuditSeverity::Warning,
                    None,
                    None,
                    &format!("Config reload failed ({origin}): {error}"),
                );
            }
        }
        #[cfg(unix)]
        {
            record_systemd_notification("READY=1", self::systemd::notify::ready());
            record_systemd_notification(
                "STATUS=Accepting connections",
                self::systemd::notify::status("Accepting connections"),
            );
        }
    }

    pub fn initiate_drain(&mut self, reason: &'static [u8]) -> bool {
        if !self.graceful_shutdown.begin_drain() {
            return false;
        }
        self.state = ServerState::Draining;
        let grace_ms = self.graceful_shutdown.grace().as_millis();
        let live = self.live_mut();
        live.accept_loop.shutdown();
        log::info!(
            "Server drain started (reason={}, grace_ms={})",
            String::from_utf8_lossy(reason),
            grace_ms
        );
        #[cfg(unix)]
        {
            record_systemd_notification("STOPPING=1", self::systemd::notify::stopping());
            record_systemd_notification(
                "STATUS=Draining active connections",
                self::systemd::notify::status("Draining active connections"),
            );
        }
        true
    }

    fn drain_complete(&self) -> bool {
        self.graceful_shutdown.lifecycle() == ShutdownLifecycle::Draining
            && (self.live().live_state.client_count() == 0
                || self.graceful_shutdown.deadline_reached())
    }

    async fn finish_drain(
        &mut self,
        socket: &tokio::net::UdpSocket,
        out: &mut [u8],
        metrics: &Metrics,
        reason: &'static [u8],
    ) {
        let live = self.live_mut();
        if tokio::time::timeout(
            FINAL_CLOSE_FLUSH_TIMEOUT,
            live.live_state.force_close_and_flush(socket, out, metrics, &live.accept_loop, reason),
        )
        .await
        .is_err()
        {
            log::warn!(
                "Final shutdown frame flush exceeded {} ms; continuing teardown",
                FINAL_CLOSE_FLUSH_TIMEOUT.as_millis()
            );
        }
        live.service_signals.shutdown_all();
    }

    pub fn shutdown_live(&mut self, reason: &'static [u8]) {
        let _ = self.initiate_drain(reason);
        let live = self.live_mut();
        live.live_state.shutdown_all(reason, None);
        live.service_signals.shutdown_all();
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
    use std::io::Write as _;

    #[test]
    fn stateless_version_negotiation_skips_fec_envelopes() {
        let meta = crate::fec::wire::WirePacketMeta {
            profile: crate::fec::wire::WireProfile {
                epoch: 1,
                codec: crate::fec::wire::WireCodec::Gf8,
                source_count: 4,
                total_count: 5,
                interleave_depth: 1,
            },
            window: 0,
            sequence: 3,
            repair_index: 0,
            block_index: 0,
            systematic: false,
        };
        let payload =
            vec![0; crate::transport::MIN_CLIENT_INITIAL_LEN - crate::fec::wire::HEADER_LEN];
        let mut datagram = vec![0; crate::transport::MIN_CLIENT_INITIAL_LEN];
        let written = crate::fec::wire::write_packet(meta, &payload, &mut datagram)
            .expect("FEC envelope must serialize");
        let datagram = &datagram[..written];
        let supported_versions = [crate::transport::PROTOCOL_VERSION];

        assert!(crate::fec::wire::is_framed(datagram));
        assert!(crate::transport::packet::server_version_negotiation_response(
            datagram,
            &supported_versions,
        )
        .expect("FEC bytes can resemble an unsupported long header")
        .is_some());
        assert!(stateless_version_negotiation_response(datagram, &supported_versions)
            .expect("FEC envelope must bypass stateless version negotiation")
            .is_none());
    }

    #[test]
    fn pending_tun_downlinks_bound_admission_and_preserve_ownership() {
        let first_target: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let second_target: SocketAddr = "127.0.0.1:41002".parse().unwrap();
        let migrated_target: SocketAddr = "127.0.0.1:41003".parse().unwrap();
        let now = Instant::now();

        let mut per_target = PendingTunDownlinks::with_limits(4, 64, 1);
        per_target.enqueue(first_target, vec![1], now).unwrap();
        assert_eq!(
            per_target.enqueue(first_target, vec![2], now),
            Err(PendingTunDownlinkReject::PerTarget)
        );

        let mut by_count = PendingTunDownlinks::with_limits(2, 64, 2);
        by_count.enqueue(first_target, vec![1], now).unwrap();
        by_count.enqueue(second_target, vec![2], now).unwrap();
        assert_eq!(
            by_count.enqueue(migrated_target, vec![3], now),
            Err(PendingTunDownlinkReject::Queue)
        );

        let mut by_bytes = PendingTunDownlinks::with_limits(4, 3, 4);
        by_bytes.enqueue(first_target, vec![1, 2, 3], now).unwrap();
        assert_eq!(
            by_bytes.enqueue(second_target, vec![4], now),
            Err(PendingTunDownlinkReject::Bytes)
        );

        let mut queue = PendingTunDownlinks::with_limits(4, 64, 4);
        queue.enqueue(first_target, vec![10], now).unwrap();
        queue.enqueue(second_target, vec![20], now).unwrap();
        queue.rebind_target(first_target, migrated_target);

        let first = queue.pop_front().unwrap();
        assert_eq!(first.target, migrated_target);
        assert_eq!(first.packet, vec![10]);
        assert!(!first.is_expired(now));
        queue.requeue(first);

        let (discarded_packets, discarded_bytes) = queue.discard_target(second_target);
        assert_eq!((discarded_packets, discarded_bytes), (1, 1));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.bytes(), 1);

        let expired = PendingTunDownlink {
            target: migrated_target,
            packet: vec![30],
            queued_at: now - MAX_PENDING_TUN_DOWNLINK_AGE,
        };
        assert!(expired.is_expired(now));
    }

    #[test]
    fn client_fanout_queue_accepts_only_broadcast_and_multicast() {
        let queue = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new()));
        let source = "127.0.0.1:4433".parse().unwrap();
        let packet = [0x45, 0, 0, 20];
        enqueue_client_fanout(
            &queue,
            source,
            UplinkRoute::Broadcast {
                source: Ipv4Addr::new(10, 0, 1, 2),
                destination: Ipv4Addr::new(10, 0, 1, 255),
            },
            &packet,
        );
        enqueue_client_fanout(
            &queue,
            source,
            UplinkRoute::Internet {
                source: Ipv4Addr::new(10, 0, 1, 2).into(),
                destination: Ipv4Addr::new(1, 1, 1, 1).into(),
            },
            &packet,
        );

        let mut queue = queue.lock().unwrap();
        assert_eq!(queue.len(), 1);
        let fanout = queue.pop_front().unwrap();
        assert_eq!(fanout.source, source);
        assert_eq!(fanout.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 1, 255)));
        assert_eq!(fanout.packet, packet);
    }

    #[test]
    fn authenticated_server_uplink_is_typed_as_local() {
        let server_ip = Ipv4Addr::new(10, 0, 1, 1);
        let client_ip = Ipv4Addr::new(10, 0, 1, 2);
        let forwarding_policy =
            ClientIsolationManager::with_network(server_ip, Ipv4Addr::new(255, 255, 255, 0), false);
        let assigned = AssignedClientIps { ipv4: client_ip, ipv6: None };
        forwarding_policy.assign_client("client", assigned);
        let metrics = Metrics::new();
        let responses =
            Arc::new(std::sync::Mutex::new(crate::core::MasqueDownlinkQueue::new(8, 4096)));
        let packet = test_ipv4_udp_packet(client_ip, server_ip, 40_000, 53, &[1]);

        let route = allow_client_uplink(
            &forwarding_policy,
            &metrics,
            Some(assigned),
            &packet,
            ServerTunIps { ipv4: server_ip, ipv6: None },
            1280,
            &responses,
        );

        assert!(matches!(route, Some(UplinkRoute::Local { .. })));
        assert_eq!(metrics.routing_local.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.routing_internet.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.max_clients, 100);
        assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
        // IPv6 defaults
        assert!(config.ipv6_server_ip.is_some());
        assert_eq!(config.ipv6_server_ip.unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
        assert_eq!(config.ipv6_prefix_len, 64);
    }

    #[test]
    fn test_parse_ipv6_dest_valid() {
        // Construct a minimal IPv6 packet header (40 bytes)
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60; // version 6
                       // Destination at offset 24-39: fd00::1
        pkt[24] = 0xfd;
        pkt[39] = 0x01;
        let dest = parse_ipv6_dest(&pkt).unwrap();
        assert_eq!(dest, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001));
    }

    #[test]
    fn test_parse_ipv6_dest_too_short() {
        let pkt = vec![0u8; 30];
        assert!(parse_ipv6_dest(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv6_dest_wrong_version() {
        let mut pkt = [0u8; 40];
        pkt[0] = 0x45; // IPv4
        assert!(parse_ipv6_dest(&pkt).is_none());
    }

    #[test]
    fn test_parse_ip_dest_dispatches_v4_and_v6() {
        // IPv4 packet
        let mut pkt4 = [0u8; 20];
        pkt4[0] = 0x45;
        pkt4[16] = 10;
        pkt4[17] = 8;
        pkt4[18] = 0;
        pkt4[19] = 2;
        match parse_ip_dest(&pkt4) {
            Some(std::net::IpAddr::V4(v4)) => assert_eq!(v4, Ipv4Addr::new(10, 8, 0, 2)),
            other => panic!("expected V4, got {:?}", other),
        }

        // IPv6 packet
        let mut pkt6 = [0u8; 40];
        pkt6[0] = 0x60;
        pkt6[24] = 0xfd;
        pkt6[39] = 0x01;
        match parse_ip_dest(&pkt6) {
            Some(std::net::IpAddr::V6(v6)) => {
                assert_eq!(v6, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001))
            }
            other => panic!("expected V6, got {:?}", other),
        }
    }

    fn test_dns_query_payload() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&[0x01, 0x00]);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        for label in ["example", "com"] {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt
    }

    fn test_ipv4_udp_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src_ip.octets());
        pkt[16..20].copy_from_slice(&dst_ip.octets());
        let ip_checksum = ones_complement_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[28..].copy_from_slice(payload);
        let udp_checksum = ipv4_udp_checksum(src_ip, dst_ip, &pkt[20..]);
        pkt[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
        pkt
    }

    fn test_ipv6_udp_packet(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut pkt = vec![0u8; 40 + udp_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[6] = 17;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&src_ip.octets());
        pkt[24..40].copy_from_slice(&dst_ip.octets());
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[48..].copy_from_slice(payload);
        let udp_checksum = ipv6_udp_checksum(src_ip, dst_ip, &pkt[40..]);
        pkt[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
        pkt
    }

    #[test]
    fn test_parse_ipv4_udp_dns_query_detects_port_53_payload() {
        let payload = test_dns_query_payload();
        let pkt = test_ipv4_udp_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            53000,
            53,
            &payload,
        );
        let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
        assert_eq!(query.src_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(query.dst_ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(query.src_port, 53000);
        assert_eq!(query.dst_port, 53);
        assert_eq!(query.payload, payload.as_slice());
    }

    #[test]
    fn test_parse_ipv6_udp_dns_query_detects_port_53_payload() {
        let payload = test_dns_query_payload();
        let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
        let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
        assert_eq!(query.src_ip, src_ip);
        assert_eq!(query.dst_ip, dst_ip);
        assert_eq!(query.src_port, 53000);
        assert_eq!(query.dst_port, 53);
        assert_eq!(query.payload, payload.as_slice());
    }

    #[test]
    fn test_build_ipv4_udp_dns_response_packet_swaps_tuple() {
        let payload = test_dns_query_payload();
        let pkt = test_ipv4_udp_packet(
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv4Addr::new(1, 1, 1, 1),
            53000,
            53,
            &payload,
        );
        let query = parse_ipv4_udp_dns_query(&pkt).expect("DNS query must parse");
        let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
        let dns_response = crate::dns::build_dns_nxdomain(&parsed);
        let response =
            build_ipv4_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
                .expect("DNS response packet must build");
        assert_eq!(parse_ipv4_dest(&response), Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(
            Ipv4Addr::new(response[12], response[13], response[14], response[15]),
            Ipv4Addr::new(1, 1, 1, 1)
        );
        assert_eq!(u16::from_be_bytes([response[20], response[21]]), 53);
        assert_eq!(u16::from_be_bytes([response[22], response[23]]), 53000);
        assert_eq!(&response[28..], dns_response.as_slice());
    }

    #[test]
    fn test_build_ipv6_udp_dns_response_packet_swaps_tuple() {
        let payload = test_dns_query_payload();
        let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst_ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let pkt = test_ipv6_udp_packet(src_ip, dst_ip, 53000, 53, &payload);
        let query = parse_ipv6_udp_dns_query(&pkt).expect("IPv6 DNS query must parse");
        let parsed = crate::dns::parse_dns_query(query.payload).expect("DNS payload must parse");
        let dns_response = crate::dns::build_dns_nxdomain(&parsed);
        let response =
            build_ipv6_udp_dns_response_packet(&query, &dns_response, OsFingerprintProfile::Linux)
                .expect("IPv6 DNS response packet must build");
        assert_eq!(parse_ipv6_dest(&response), Some(src_ip));
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&response[8..24]).unwrap()), dst_ip);
        assert_eq!(u16::from_be_bytes([response[40], response[41]]), 53);
        assert_eq!(u16::from_be_bytes([response[42], response[43]]), 53000);
        assert_eq!(&response[48..], dns_response.as_slice());
    }

    #[test]
    fn test_parse_ipv4_dest_valid() {
        // Construct a minimal IPv4 packet with dest 10.8.0.2
        let mut pkt = [0u8; 20];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[16] = 10;
        pkt[17] = 8;
        pkt[18] = 0;
        pkt[19] = 2;
        let dest = parse_ipv4_dest(&pkt).unwrap();
        assert_eq!(dest, Ipv4Addr::new(10, 8, 0, 2));
    }

    #[test]
    fn test_parse_ipv4_dest_too_short() {
        let pkt = [0u8; 10];
        assert!(parse_ipv4_dest(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_dest_not_ipv4() {
        // IPv6 packet (version 6)
        let mut pkt = [0u8; 40];
        pkt[0] = 0x60; // version 6
        assert!(parse_ipv4_dest(&pkt).is_none());
    }

    #[test]
    fn test_parse_ipv4_dest_with_options() {
        // IPv4 packet with IHL=6 (24 bytes header)
        let mut pkt = [0u8; 24];
        pkt[0] = 0x46; // version 4, IHL 6
        pkt[16] = 192;
        pkt[17] = 168;
        pkt[18] = 1;
        pkt[19] = 100;
        let dest = parse_ipv4_dest(&pkt).unwrap();
        assert_eq!(dest, Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_parse_ipv4_dest_invalid_ihl() {
        let mut pkt = [0u8; 20];
        pkt[0] = 0x40; // IHL=0, invalid
        assert!(parse_ipv4_dest(&pkt).is_none());
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
        let (session_id, _, _) = domain.accept(remote_addr).unwrap();

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
        let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
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
                burst_size: 1,
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
        let (session_id, _, _) = live_state.domain.accept(remote_addr).unwrap();
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

    #[test]
    fn test_live_udp_datagram_buffer_serializes_full_1500_byte_fec_envelope() {
        let profile = crate::fec::wire::WireProfile {
            epoch: 1,
            codec: crate::fec::wire::WireCodec::Gf8,
            source_count: 4,
            total_count: 6,
            interleave_depth: 1,
        };
        let metadata = crate::fec::wire::WirePacketMeta {
            profile,
            window: 0,
            sequence: 0,
            repair_index: crate::fec::wire::SYSTEMATIC_REPAIR_INDEX,
            block_index: 0,
            systematic: true,
        };
        let payload = vec![0u8; 1500 - crate::fec::wire::HEADER_LEN];
        let mut output = vec![0u8; LIVE_UDP_DATAGRAM_BUFFER_SIZE];

        let written = crate::fec::wire::write_packet(metadata, &payload, &mut output)
            .expect("1500-byte FEC envelope must fit the live server UDP buffer");

        assert_eq!(written, 1500);
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

    #[tokio::test]
    async fn test_standalone_runtime_drain_rejects_new_clients_and_reports_lifecycle() {
        let engine_config = EngineConfig {
            engine: crate::engine::EngineSection {
                shutdown_timeout_ms: 250,
                ..crate::engine::EngineSection::default()
            },
            ..EngineConfig::default()
        };
        let server_config =
            ServerConfig { listen: "127.0.0.1:0".parse().unwrap(), ..ServerConfig::default() };
        let blocked_ips = Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new()));
        let qkey_registry = Arc::new(std::sync::Mutex::new(QKeyRegistry::new(16, None, None)));
        let mut runtime = ServerRuntime::new_standalone_default(
            engine_config,
            server_config,
            None,
            crate::optimize::OptimizeConfig::default(),
            blocked_ips,
            qkey_registry,
            StandaloneAdminWebBootstrap::default(),
        )
        .unwrap();

        runtime.start().unwrap();
        assert!(runtime.initiate_drain(b"test_drain"));
        assert!(!runtime.initiate_drain(b"duplicate_drain"));
        assert_eq!(runtime.state(), ServerState::Draining);
        assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Draining);
        assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(250));
        assert!(runtime.live().accept_loop.is_shutdown());
        assert_eq!(
            runtime.live().accept_loop.should_accept(
                "127.0.0.1:54321".parse().unwrap(),
                0,
                runtime.live().accept_max_clients,
            ),
            AcceptDecision::Reject(RejectReason::Shutdown)
        );
        let status = runtime.graceful_shutdown.status_json(3);
        assert_eq!(status["state"], "draining");
        assert_eq!(status["active_connections"], 3);
        assert_eq!(status["grace_period_ms"], 250);

        runtime.stop().unwrap();
        assert_eq!(runtime.graceful_shutdown.lifecycle(), ShutdownLifecycle::Stopped);
    }

    #[tokio::test]
    async fn test_runtime_reload_updates_shutdown_grace_without_stopping_server() {
        static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
        let config_path = std::env::temp_dir().join(format!(
            "quicfuscate-reload-grace-{}-{}.toml",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut config_file =
            std::fs::OpenOptions::new().write(true).create_new(true).open(&config_path).unwrap();
        config_file.write_all(b"[engine]\nshutdown_timeout_ms = 175\n").unwrap();
        drop(config_file);

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
        let transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let mut runtime_config = PreparedStandaloneRuntimeConfig::new(
            Some(config_path.clone()),
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
        runtime.sync_standalone_runtime_metadata(&runtime_config.standalone_runtime_metadata);
        runtime.start().unwrap();

        runtime.reload_standalone_runtime(&mut runtime_config, "test");

        assert_eq!(runtime.state(), ServerState::Running);
        assert_eq!(runtime.graceful_shutdown.grace(), Duration::from_millis(175));
        runtime.stop().unwrap();
        std::fs::remove_file(config_path).unwrap();
    }

    #[test]
    fn test_server_config_from_listen_addr_resolves_socket() {
        let config = server_config_from_listen_addr("127.0.0.1:4433").unwrap();
        assert_eq!(config.listen, "127.0.0.1:4433".parse().unwrap());
    }

    #[cfg(feature = "rate_limiter")]
    #[test]
    fn test_server_config_carries_geoip_and_blacklist_defaults() {
        // Default config should have GeoIP disabled and no blacklist sync URL.
        let config = ServerConfig::default();
        assert!(!config.geoip.is_enabled(), "default geoip should be disabled");
        assert!(config.blacklist.sync_url.is_none(), "default blacklist should have no sync URL");
    }

    #[cfg(feature = "rate_limiter")]
    #[test]
    fn test_shared_server_domain_uses_configured_blacklist() {
        // When ServerConfig has a blacklist sync URL, SharedServerDomain
        // should construct a BlacklistSync with that URL (has_sync_url=true).
        let config = ServerConfig {
            #[cfg(feature = "rate_limiter")]
            blacklist: BlacklistConfig {
                default_ttl_secs: 60,
                sync_url: Some("https://example.com/blocklist".to_string()),
                sync_interval_secs: 300,
            },
            ..ServerConfig::default()
        };
        let domain = SharedServerDomain::new(&config);
        assert!(domain.blacklist.has_sync_url());
        assert_eq!(domain.blacklist.sync_interval(), Duration::from_secs(300));
    }

    #[cfg(feature = "rate_limiter")]
    #[test]
    fn test_shared_server_domain_uses_configured_geoip() {
        use crate::implementations::server::limits::GeoIpConfig;
        use std::collections::HashSet;
        use std::path::PathBuf;

        let mut countries = HashSet::new();
        countries.insert("XX".to_string());
        let config = ServerConfig {
            #[cfg(feature = "rate_limiter")]
            geoip: GeoIpConfig {
                db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
                blocked_countries: countries,
            },
            ..ServerConfig::default()
        };
        let domain = SharedServerDomain::new(&config);
        // The blocker should be enabled (config has db_path + countries),
        // but gracefully degrade (missing db → is_blocked returns false).
        assert!(domain.geoip_blocker.is_enabled());
        assert!(!domain.geoip_blocker.is_blocked("1.2.3.4".parse().unwrap()));
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
                key_id: "test-key".to_string(),
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
    fn test_qkey_auth_success_associates_session_and_revocation_closes_client() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54326".parse().unwrap();
        let (session_id, _, _) = live_state.domain.accept(remote_addr).expect("session accepted");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"auth-revoke-close"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();

        live_state.clients.insert(remote_addr, connection);
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "test-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                authed: false,
                connected_at: Instant::now(),
            },
        );

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), true)),
            &accept_loop,
            &metrics,
        );

        assert_eq!(
            live_state.qkey_tracker.key_for_connection(session_id.as_u64()).as_deref(),
            Some("test-key")
        );

        live_state.revoke_qkey_now("test-key", "test", &accept_loop, &metrics);

        assert!(live_state.revocation_manager.is_revoked("test-key"));
        assert!(!live_state.clients.contains_key(&remote_addr));
        assert!(live_state.domain.session_id_by_remote(remote_addr).is_none());
        assert!(live_state.qkey_tracker.connections_for_key("test-key").is_empty());
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
    }

    #[test]
    fn test_pending_qkey_auth_cannot_complete_after_revocation() {
        let mut live_state = LiveServerState::new(ServerConfig::default());
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let metrics = Metrics::new();
        let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let remote_addr: SocketAddr = "127.0.0.1:54327".parse().unwrap();
        live_state.domain.accept(remote_addr).expect("session accepted");
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let connection = create_live_server_connection(
            local_addr,
            remote_addr,
            &mut transport,
            StealthConfig::default(),
            FecConfig::default(),
            OptimizeConfig::default(),
            &crate::transport::ConnectionId::from_ref(b"pending-revoked"),
        )
        .expect("live server connection must be creatable");
        let conn_id = connection.conn.source_id().as_ref().to_vec();
        let rejected_before = metrics.connections_rejected.load(Ordering::Relaxed);
        let auth_failed_before = metrics.auth_failed.load(Ordering::Relaxed);

        live_state.clients.insert(remote_addr, connection);
        live_state.qkey_auth.insert(
            conn_id.clone(),
            QKeyAuthState {
                key_id: "pending-key".to_string(),
                expected_token_sha256: "deadbeef".to_string(),
                authed: false,
                connected_at: Instant::now(),
            },
        );
        live_state.revocation_manager.revoke("pending-key", "test");

        live_state.commit_qkey_auth_result(
            None,
            Some((conn_id.clone(), true)),
            &accept_loop,
            &metrics,
        );

        assert!(!live_state.clients.contains_key(&remote_addr));
        assert!(live_state.domain.session_id_by_remote(remote_addr).is_none());
        assert!(live_state.qkey_tracker.connections_for_key("pending-key").is_empty());
        assert!(!live_state.qkey_auth.contains_key(&conn_id));
        assert_eq!(metrics.connections_rejected.load(Ordering::Relaxed), rejected_before + 1);
        assert_eq!(metrics.auth_failed.load(Ordering::Relaxed), auth_failed_before + 1);
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
            ServerAdminControlPlane {
                actions: tx,
                listen_addr: "127.0.0.1:4433".to_string(),
                front_domain: vec![],
                qkeys,
                graceful_shutdown: Arc::new(GracefulShutdown::new(5_000)),
            },
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
            ServerAdminControlPlane {
                actions: tx,
                listen_addr: "127.0.0.1:4433".to_string(),
                front_domain: vec![],
                qkeys,
                graceful_shutdown: Arc::new(GracefulShutdown::new(5_000)),
            },
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
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            authed: false,
            connected_at: Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(1)),
        };
        assert!(state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_authed() {
        let state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            authed: true,
            connected_at: Instant::now() - (QKEY_AUTH_TIMEOUT + Duration::from_secs(10)),
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn test_qkey_auth_state_not_expired_when_recent() {
        let state = QKeyAuthState {
            key_id: "test-key".to_string(),
            expected_token_sha256: "abc".to_string(),
            authed: false,
            connected_at: Instant::now(),
        };
        assert!(!state.is_expired());
    }

    #[test]
    fn qkey_datagram_auth_result_preserves_pending_state() {
        let conn_id = b"pending-auth";

        assert_eq!(qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Pending), None);
        assert_eq!(
            qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Authenticated),
            Some((conn_id.to_vec(), true))
        );
        assert_eq!(
            qkey_datagram_auth_result(conn_id, QKeyDatagramAuthProgress::Rejected),
            Some((conn_id.to_vec(), false))
        );
    }

    #[test]
    fn qkey_http3_authentication_is_fail_closed() {
        let valid_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let expected = qkey_registry::token_sha256_hex_from_token_hex(valid_token)
            .expect("valid QKey token must hash");
        let cases = [
            ("auth disabled", Vec::new(), None, false, QKeyHeaderAuthOutcome::Unchanged),
            (
                "already authenticated",
                Vec::new(),
                Some(expected.as_str()),
                true,
                QKeyHeaderAuthOutcome::Authenticated,
            ),
            (
                "missing header",
                Vec::new(),
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"missing_qkey_auth"),
            ),
            (
                "invalid UTF-8",
                vec![crate::transport::h3::Header::new(b"x-qf-auth", &[0xff])],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"invalid_qkey_auth"),
            ),
            (
                "wrong bearer",
                vec![crate::transport::h3::Header::new(
                    b"x-qf-auth",
                    b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Reject(b"invalid_qkey_auth"),
            ),
            (
                "valid bearer",
                vec![crate::transport::h3::Header::new(
                    b"X-QF-AUTH",
                    format!("  {}  ", valid_token).as_bytes(),
                )],
                Some(expected.as_str()),
                false,
                QKeyHeaderAuthOutcome::Authenticated,
            ),
        ];

        for (name, headers, expected_hash, already_authed, expected_outcome) in cases {
            let outcome = evaluate_qkey_http3_headers(&headers, expected_hash, already_authed);
            match (outcome, expected_outcome) {
                (QKeyHeaderAuthOutcome::Unchanged, QKeyHeaderAuthOutcome::Unchanged)
                | (QKeyHeaderAuthOutcome::Authenticated, QKeyHeaderAuthOutcome::Authenticated) => {}
                (
                    QKeyHeaderAuthOutcome::Reject(actual),
                    QKeyHeaderAuthOutcome::Reject(expected),
                ) => {
                    assert_eq!(actual, expected, "{name}");
                }
                _ => panic!("unexpected QKey auth outcome for {name}"),
            }
        }
    }

    #[test]
    fn qkey_payload_gate_blocks_every_protected_path_until_authentication() {
        let cases = [
            ("auth disabled", false, false, true),
            ("auth disabled and authenticated", false, true, true),
            ("auth required but pending", true, false, false),
            ("auth required and complete", true, true, true),
        ];

        for (name, require_auth, authenticated, expected) in cases {
            assert_eq!(qkey_payload_allowed(require_auth, authenticated), expected, "{name}");
        }
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

    #[test]
    fn test_apply_runtime_stealth_overrides_keeps_fronting_explicit_only() {
        let mut sc = StealthConfig::default();
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Chrome,
            OsProfile::Windows,
            false,
            "https://cloudflare-dns.com/dns-query",
            false,
            &[],
            false,
        );
        assert!(!sc.enable_domain_fronting);

        sc.mode = StealthMode::AntiDpi;
        apply_runtime_stealth_overrides(
            &mut sc,
            BrowserProfile::Chrome,
            OsProfile::Windows,
            false,
            "https://cloudflare-dns.com/dns-query",
            false,
            &[],
            false,
        );
        assert!(sc.enable_domain_fronting);
    }

    // --- LiveServerDomain session tracking ---

    #[test]
    fn test_live_server_domain_accept_tracks_multiple_remotes() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr1: SocketAddr = "10.0.0.1:5001".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:5002".parse().unwrap();
        let (id1, _, _) = domain.accept(addr1).unwrap();
        let (id2, _, _) = domain.accept(addr2).unwrap();

        assert_ne!(id1, id2);
        assert_eq!(domain.active_session_count(), 2);
        assert_eq!(domain.session_id_by_remote(addr1), Some(id1));
        assert_eq!(domain.session_id_by_remote(addr2), Some(id2));
    }

    #[test]
    fn test_live_server_domain_remove_remote_clears_session() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let addr: SocketAddr = "10.0.0.1:5003".parse().unwrap();
        let (id, _, _) = domain.accept(addr).unwrap();
        assert_eq!(domain.session_id_by_remote(addr), Some(id));

        domain.remove_remote(addr);
        assert_eq!(domain.session_id_by_remote(addr), None);
        assert_eq!(domain.active_session_count(), 0);
    }

    #[test]
    fn test_live_server_domain_synchronizes_forwarding_policy_lifecycle() {
        let domain = LiveServerDomain::new(&ServerConfig::default());
        let remote: SocketAddr = "10.0.0.1:5004".parse().unwrap();
        let (_, _, assigned_ips) = domain.accept(remote).unwrap();

        assert_eq!(domain.shared.forwarding_policy.assigned_address_count(), 2);
        assert_eq!(
            domain.shared.forwarding_policy.client_for_ip(assigned_ips.ipv4.into()),
            domain.session_id_by_remote(remote).map(|id| id.as_u64().to_string())
        );

        domain.remove_remote(remote);
        assert_eq!(domain.shared.forwarding_policy.assigned_address_count(), 0);
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
        for algorithm in ["reno", "cubic", "bbr2", "bbr3"] {
            let toml_str = format!(
                r#"
[transport]
cc_algorithm = "{algorithm}"
"#
            );
            assert!(validate_transport_overrides_from_toml(&toml_str).is_ok());
        }
    }

    #[test]
    fn test_validate_transport_overrides_invalid_cc_algorithm() {
        let toml_str = r#"
[transport]
cc_algorithm = "not-a-controller"
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }

    #[test]
    fn test_transport_overrides_apply_ordered_quic_versions() {
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let contents = r#"
[transport]
quic_versions = ["v2", "v1"]
"#;

        apply_transport_overrides_from_toml(
            std::path::Path::new("test.toml"),
            contents,
            &mut transport,
        );

        assert_eq!(transport.version(), crate::transport::PROTOCOL_VERSION_V2);
        assert_eq!(
            transport.supported_versions(),
            &[crate::transport::PROTOCOL_VERSION_V2, crate::transport::PROTOCOL_VERSION]
        );
        assert!(validate_transport_overrides_from_toml(
            "[transport]\nquic_versions = [\"v2\", \"v2\"]"
        )
        .is_err());
    }

    #[test]
    fn test_validate_transport_overrides_mtu_out_of_range() {
        let toml_str = r#"
[transport]
mtu = 500
"#;
        assert!(validate_transport_overrides_from_toml(toml_str).is_err());
    }

    #[test]
    fn test_transport_overrides_apply_dplpmtud_policy() {
        let mut transport =
            crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION).unwrap();
        let contents = r#"
[transport]
pmtu_min_mtu = 1260
pmtu_max_mtu = 1460
pmtu_probe_interval_ms = 2500
pmtu_black_hole_timeout_ms = 7500
"#;

        apply_transport_overrides_from_toml(
            std::path::Path::new("test.toml"),
            contents,
            &mut transport,
        );

        let policy = transport.pmtu_policy();
        assert_eq!(policy.min_mtu, 1260);
        assert_eq!(policy.max_mtu, 1460);
        assert_eq!(policy.probe_interval, Duration::from_millis(2500));
        assert_eq!(policy.black_hole_timeout, Duration::from_millis(7500));
    }

    #[test]
    fn test_validate_transport_overrides_rejects_zero_pmtud_timer() {
        let contents = r#"
[transport]
pmtu_probe_interval_ms = 0
"#;

        assert!(validate_transport_overrides_from_toml(contents).is_err());
    }

    #[test]
    fn test_accept_session_dual_stack_allocates_ipv6() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut v6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0005),
        );
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        let result = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            remote,
            10,
            30,
        );
        assert!(result.is_ok());
        let (session_id, _, assigned_ips) = result.unwrap();
        assert_eq!(assigned_ips.ipv4, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(assigned_ips.ipv6, Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)));

        // Verify the session has an IPv6 address
        let session = sessions.get(session_id).unwrap();
        assert!(session.client_ipv6().is_some());
        assert_eq!(session.client_ipv6().unwrap(), Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002));
    }

    #[test]
    fn test_accept_session_no_ipv6_pool_when_none() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        let result = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            None,
            &mut limiter,
            remote,
            10,
            30,
        );
        assert!(result.is_ok());
        let (session_id, _, _) = result.unwrap();

        // Session should NOT have an IPv6 address
        let session = sessions.get(session_id).unwrap();
        assert!(session.client_ipv6().is_none());
    }

    #[test]
    fn test_remove_session_releases_ipv6() {
        use std::net::SocketAddr;
        let mut sessions = SessionManager::new(10);
        let mut ip_pool = IpPool::new(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 10));
        let mut v6_pool = Ipv6Pool::new(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0003),
        );
        let mut limiter = ConnectionLimiter::new(10);
        let remote: SocketAddr = "1.2.3.4:1234".parse().unwrap();

        // Accept a session
        let (session_id, _, _) = accept_session_in_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            remote,
            10,
            30,
        )
        .unwrap();

        // IPv6 pool should have 1 allocated
        assert_eq!(v6_pool.allocated_count(), 1);
        assert_eq!(v6_pool.available(), 1);

        // Remove the session
        let removed = remove_session_from_domain(
            &mut sessions,
            &mut ip_pool,
            Some(&mut v6_pool),
            &mut limiter,
            session_id,
        );
        assert!(removed.is_some());

        // IPv6 pool should be fully available again
        assert_eq!(v6_pool.allocated_count(), 0);
        assert_eq!(v6_pool.available(), 2);
    }

    #[test]
    fn test_shared_server_domain_creates_ipv6_pool() {
        let config = ServerConfig::default();
        let domain = SharedServerDomain::new(&config);
        // Default config has IPv6 pool start/end configured
        assert!(domain.ipv6_pool.is_some());
    }

    #[test]
    fn test_shared_server_domain_no_ipv6_pool_when_disabled() {
        let config = ServerConfig {
            ipv6_pool_start: None,
            ipv6_pool_end: None,
            ipv6_server_ip: None,
            ..Default::default()
        };
        let domain = SharedServerDomain::new(&config);
        // IPv6 pool should not be created
        assert!(domain.ipv6_pool.is_none());
    }

    #[test]
    fn test_routing_manager_new_dual_stack() {
        let mgr = RoutingManager::new_dual_stack(
            "tun0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001),
            64,
        );
        assert!(mgr.is_ipv6_enabled());
    }

    #[test]
    fn test_routing_manager_new_no_ipv6() {
        let mgr = RoutingManager::new(
            "tun0".to_string(),
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            "eth0".to_string(),
        );
        assert!(!mgr.is_ipv6_enabled());
    }
}
