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
    read_persisted_logging_mode(config_path).unwrap_or_else(|| "normal".to_string())
}

pub(crate) fn read_persisted_logging_mode(
    config_path: Option<&std::path::Path>,
) -> Option<String> {
    resolve_logging_store_path(config_path)
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("mode").and_then(|m| m.as_str().map(String::from)))
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
