#[derive(Clone, Copy, Debug)]
struct ServerTunIps {
    ipv4: Ipv4Addr,
    ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Debug)]
struct ServerAssignmentSettings {
    ipv4_prefix: u8,
    ipv6_prefix: u8,
    mtu: u16,
    dns_servers: Vec<IpAddr>,
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
    /// Concrete firewall backend resolved once before server startup.
    pub firewall_backend: crate::firewall::FirewallBackend,
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
    /// Bounded QKey authentication backoff and block lifecycle.
    pub auth_policy: AuthPolicyConfig,
    /// Retention for revoked QKey records in seconds.
    pub revocation_retention_secs: u64,
    /// Default per-session bandwidth, quota, and scheduling policy.
    pub bandwidth_policy: BandwidthPolicy,
    /// Shared downlink service rate for weighted scheduling. Zero disables the shaper.
    pub downlink_scheduler_rate_bytes_per_second: u64,
    /// Shared downlink token-bucket burst. Zero disables the shaper.
    pub downlink_scheduler_burst_bytes: u64,
    /// Validated sustained DDoS detection and enhanced-admission policy.
    #[cfg(feature = "rate_limiter")]
    pub ddos_policy: limits::DdosPolicyConfig,
    /// GeoIP-based source-IP blocking config (TODO-459). When a MaxMindDB
    /// country database path and blocked countries are configured, incoming
    /// datagrams from those countries are dropped. Activation is fail-closed.
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
    /// End-to-end HTTPS request timeout (seconds).
    pub request_timeout_secs: u64,
    /// Maximum feed and serialized-cache size.
    pub max_body_bytes: usize,
    /// Maximum number of unique blocked addresses.
    pub max_entries: usize,
    /// Atomic last-known-good cache path. `None` disables persistence.
    pub cache_path: Option<std::path::PathBuf>,
    /// Optional PEM CA bundle for private HTTPS feed endpoints.
    pub custom_ca_path: Option<std::path::PathBuf>,
}

#[cfg(feature = "rate_limiter")]
impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 3600,
            sync_url: None,
            sync_interval_secs: 3600,
            request_timeout_secs: 30,
            max_body_bytes: limits::MAX_BLACKLIST_BODY_BYTES,
            max_entries: limits::MAX_BLACKLIST_ENTRIES,
            cache_path: Some(std::path::PathBuf::from(
                "config/local/blacklist-cache.json",
            )),
            custom_ca_path: None,
        }
    }
}

#[cfg(feature = "rate_limiter")]
impl BlacklistConfig {
    fn validate(&self) -> Result<(), String> {
        if self.default_ttl_secs == 0
            || self.sync_interval_secs == 0
            || self.request_timeout_secs == 0
            || self.max_body_bytes == 0
            || self.max_entries == 0
        {
            return Err(
                "blacklist TTL, interval, timeout, body cap, and entry cap must be nonzero"
                    .to_string(),
            );
        }
        if self.default_ttl_secs > limits::MAX_BLACKLIST_TTL_SECS {
            return Err(format!(
                "blacklist TTL exceeds {} seconds",
                limits::MAX_BLACKLIST_TTL_SECS
            ));
        }
        if self.sync_interval_secs > limits::MAX_BLACKLIST_SYNC_INTERVAL_SECS {
            return Err(format!(
                "blacklist sync interval exceeds {} seconds",
                limits::MAX_BLACKLIST_SYNC_INTERVAL_SECS
            ));
        }
        if self.request_timeout_secs > limits::MAX_BLACKLIST_REQUEST_TIMEOUT_SECS {
            return Err(format!(
                "blacklist request timeout exceeds {} seconds",
                limits::MAX_BLACKLIST_REQUEST_TIMEOUT_SECS
            ));
        }
        if self.max_body_bytes > limits::MAX_BLACKLIST_BODY_BYTES {
            return Err(format!(
                "blacklist body cap exceeds {} bytes",
                limits::MAX_BLACKLIST_BODY_BYTES
            ));
        }
        if self.max_entries > limits::MAX_BLACKLIST_ENTRIES {
            return Err(format!(
                "blacklist entry cap exceeds {} entries",
                limits::MAX_BLACKLIST_ENTRIES
            ));
        }
        if self.sync_url.as_ref().is_some_and(|url| !url.starts_with("https://")) {
            return Err("blacklist sync URL must use HTTPS".to_string());
        }
        if self.custom_ca_path.is_some() && self.sync_url.is_none() {
            return Err("blacklist CA path requires a sync URL".to_string());
        }
        Ok(())
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
            firewall_backend: crate::firewall::FirewallBackend::Iptables,
            ipv6_pool_start: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)),
            ipv6_pool_end: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x00fe)),
            ipv6_server_ip: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0001)),
            ipv6_prefix_len: 64,
            ipv6_dns_servers: vec![
                Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), // Cloudflare
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), // Google
            ],
            allow_client_to_client: false,
            auth_policy: AuthPolicyConfig::default(),
            revocation_retention_secs:
                crate::implementations::server::revocation::DEFAULT_REVOCATION_RETENTION_SECS,
            bandwidth_policy: BandwidthPolicy::default(),
            downlink_scheduler_rate_bytes_per_second: 0,
            downlink_scheduler_burst_bytes: 0,
            #[cfg(feature = "rate_limiter")]
            ddos_policy: limits::DdosPolicyConfig::default(),
            #[cfg(feature = "rate_limiter")]
            geoip: limits::GeoIpConfig::default(),
            #[cfg(feature = "rate_limiter")]
            blacklist: BlacklistConfig::default(),
        }
    }
}

impl ServerConfig {
    fn assignment_settings(&self, mtu: u16) -> Result<ServerAssignmentSettings, String> {
        let raw_mask = u32::from(self.server_netmask);
        let ipv4_prefix = raw_mask.leading_ones() as u8;
        let canonical_mask = if ipv4_prefix == 0 {
            0
        } else {
            u32::MAX << (32 - ipv4_prefix)
        };
        if raw_mask != canonical_mask {
            return Err(format!(
                "server_netmask is not a contiguous IPv4 netmask: {}",
                self.server_netmask
            ));
        }
        if self.ipv6_prefix_len > 128 {
            return Err(format!(
                "ipv6_prefix_len must be at most 128, got {}",
                self.ipv6_prefix_len
            ));
        }
        self.validate_address_pools(ipv4_prefix)?;
        if mtu < 576 {
            return Err(format!("server TUN MTU must be at least 576, got {mtu}"));
        }
        if self.ipv6_server_ip.is_some() && mtu < 1280 {
            return Err(format!(
                "server TUN MTU must be at least 1280 for IPv6, got {mtu}"
            ));
        }
        let mut dns_servers = Vec::with_capacity(
            self.dns_servers.len().saturating_add(self.ipv6_dns_servers.len()),
        );
        dns_servers.extend(self.dns_servers.iter().copied().map(IpAddr::V4));
        dns_servers.extend(self.ipv6_dns_servers.iter().copied().map(IpAddr::V6));
        if dns_servers.len() > crate::control_plane::MAX_CLIENT_ASSIGNMENT_DNS_SERVERS {
            return Err(format!(
                "server assignment supports at most {} DNS servers",
                crate::control_plane::MAX_CLIENT_ASSIGNMENT_DNS_SERVERS
            ));
        }
        Ok(ServerAssignmentSettings { ipv4_prefix, ipv6_prefix: self.ipv6_prefix_len, mtu, dns_servers })
    }

    fn validate_address_pools(&self, ipv4_prefix: u8) -> Result<(), String> {
        let ipv4_network = u32::from(self.server_ip) & u32::from(self.server_netmask);
        let ipv4_broadcast = ipv4_network | !u32::from(self.server_netmask);
        let ipv4_first_client = ipv4_network.checked_add(1).ok_or_else(|| {
            "server IPv4 network has no usable client address range".to_string()
        })?;
        let ipv4_last_client = ipv4_broadcast.checked_sub(1).ok_or_else(|| {
            "server IPv4 network has no usable client address range".to_string()
        })?;
        let pool_start = u32::from(self.ip_pool_start);
        let pool_end = u32::from(self.ip_pool_end);
        if pool_start > pool_end {
            return Err(format!(
                "IPv4 client pool is reversed: {} > {}",
                self.ip_pool_start, self.ip_pool_end
            ));
        }
        if pool_start < ipv4_first_client || pool_end > ipv4_last_client {
            return Err(format!(
                "IPv4 client pool {}-{} is outside server network {}/{}",
                self.ip_pool_start, self.ip_pool_end, self.server_ip, ipv4_prefix
            ));
        }
        let server_ip = u32::from(self.server_ip);
        if (pool_start..=pool_end).contains(&server_ip) {
            return Err(format!(
                "IPv4 client pool {}-{} contains the server TUN address {}",
                self.ip_pool_start, self.ip_pool_end, self.server_ip
            ));
        }

        match (self.ipv6_server_ip, self.ipv6_pool_start, self.ipv6_pool_end) {
            (None, None, None) => {}
            (None, _, _) => {
                return Err(
                    "IPv6 server address and IPv6 client pool must be enabled together"
                        .to_string(),
                );
            }
            (Some(server_ip), Some(pool_start), Some(pool_end)) => {
                if self.ipv6_prefix_len == 0 {
                    return Err("ipv6_prefix_len must be at least 1 when IPv6 is enabled".to_string());
                }
                let mask = u128::MAX << (128 - self.ipv6_prefix_len);
                let network = u128::from(server_ip) & mask;
                let last = network | !mask;
                let first_client = network.checked_add(1).ok_or_else(|| {
                    "server IPv6 network has no usable client address range".to_string()
                })?;
                let pool_start = u128::from(pool_start);
                let pool_end = u128::from(pool_end);
                if pool_start > pool_end {
                    return Err(format!(
                        "IPv6 client pool is reversed: {} > {}",
                        Ipv6Addr::from(pool_start),
                        Ipv6Addr::from(pool_end)
                    ));
                }
                if pool_start < first_client || pool_end > last {
                    return Err(format!(
                        "IPv6 client pool {}-{} is outside server network {}/{}",
                        Ipv6Addr::from(pool_start),
                        Ipv6Addr::from(pool_end),
                        server_ip,
                        self.ipv6_prefix_len
                    ));
                }
                let server_ip = u128::from(server_ip);
                if (pool_start..=pool_end).contains(&server_ip) {
                    return Err(format!(
                        "IPv6 client pool {}-{} contains the server TUN address {}",
                        Ipv6Addr::from(pool_start),
                        Ipv6Addr::from(pool_end),
                        Ipv6Addr::from(server_ip)
                    ));
                }
            }
            (Some(_), None, None)
            | (Some(_), None, Some(_))
            | (Some(_), Some(_), None) => {
                return Err(
                    "IPv6 server address and IPv6 client pool start/end must be configured together"
                        .to_string(),
                );
            }
        }
        Ok(())
    }

    fn server_tun_config(&self, name: Option<String>, mtu: u16, zero_copy: bool) -> TunConfig {
        TunConfig {
            name,
            ip: Some(IpAddr::V4(self.server_ip)),
            netmask: Some(IpAddr::V4(self.server_netmask)),
            mtu,
            zero_copy,
            ip6: self.ipv6_server_ip,
            prefix6: self.ipv6_server_ip.map(|_| self.ipv6_prefix_len),
        }
    }

    fn validate_engine_interface_alignment(
        &self,
        interface: &crate::engine::InterfaceConfig,
    ) -> Result<(), String> {
        let addresses = interface
            .client_tunnel_addresses()
            .map_err(|error| format!("invalid engine interface address contract: {error}"))?;
        let expected_ipv4_prefix = u32::from(self.server_netmask).leading_ones() as u8;
        if let Some(ipv4) = addresses.ipv4 {
            if ipv4.address != self.server_ip || ipv4.prefix != expected_ipv4_prefix {
                return Err(format!(
                    "server TUN IPv4 conflict: EngineConfig.interface requests {}/{} but ServerConfig is authoritative at {}/{}",
                    ipv4.address,
                    ipv4.prefix,
                    self.server_ip,
                    expected_ipv4_prefix
                ));
            }
        }
        if let Some(ipv6) = addresses.ipv6 {
            match self.ipv6_server_ip {
                Some(server_ip)
                    if ipv6.address == server_ip && ipv6.prefix == self.ipv6_prefix_len => {}
                Some(server_ip) => {
                    return Err(format!(
                        "server TUN IPv6 conflict: EngineConfig.interface requests {}/{} but ServerConfig is authoritative at {}/{}",
                        ipv6.address, ipv6.prefix, server_ip, self.ipv6_prefix_len
                    ));
                }
                None => {
                    return Err(format!(
                        "server TUN IPv6 conflict: EngineConfig.interface requests {}/{} but ServerConfig disables IPv6",
                        ipv6.address, ipv6.prefix
                    ));
                }
            }
        }
        Ok(())
    }

    fn reconcile_standalone_tun_config(
        &self,
        mut tun_config: TunConfig,
    ) -> Result<TunConfig, String> {
        match (tun_config.ip, tun_config.netmask) {
            (None, None) => {}
            (Some(IpAddr::V4(ip)), Some(IpAddr::V4(netmask)))
                if ip == self.server_ip && netmask == self.server_netmask => {}
            (Some(IpAddr::V4(ip)), Some(IpAddr::V4(netmask))) => {
                return Err(format!(
                    "standalone server TUN IPv4 conflict: TunConfig requests {ip}/{netmask} but ServerConfig is authoritative at {}/{}",
                    self.server_ip, self.server_netmask
                ));
            }
            _ => {
                return Err(
                    "standalone server TUN IPv4 address and netmask must be an IPv4 pair matching ServerConfig"
                        .to_string(),
                );
            }
        }

        match (tun_config.ip6, tun_config.prefix6) {
            (None, None) => {}
            (Some(ip), Some(prefix)) => match self.ipv6_server_ip {
                Some(server_ip) if ip == server_ip && prefix == self.ipv6_prefix_len => {}
                Some(server_ip) => {
                    return Err(format!(
                        "standalone server TUN IPv6 conflict: TunConfig requests {ip}/{prefix} but ServerConfig is authoritative at {server_ip}/{}",
                        self.ipv6_prefix_len
                    ));
                }
                None => {
                    return Err(format!(
                        "standalone server TUN IPv6 conflict: TunConfig requests {ip}/{prefix} but ServerConfig disables IPv6"
                    ));
                }
            },
            _ => {
                return Err(
                    "standalone server TUN IPv6 address and prefix must be configured together"
                        .to_string(),
                );
            }
        }

        tun_config.ip = Some(IpAddr::V4(self.server_ip));
        tun_config.netmask = Some(IpAddr::V4(self.server_netmask));
        tun_config.ip6 = self.ipv6_server_ip;
        tun_config.prefix6 = self.ipv6_server_ip.map(|_| self.ipv6_prefix_len);
        Ok(tun_config)
    }
}

pub fn server_config_from_listen_addr(
    listen_addr: &str,
    firewall_backend: crate::firewall::FirewallBackend,
) -> Result<ServerConfig, String> {
    let listen = listen_addr
        .to_socket_addrs()
        .map_err(|e| format!("listen address resolve failed for '{}': {}", listen_addr, e))?
        .next()
        .ok_or_else(|| {
            format!("listen address '{}' resolved to no socket addresses", listen_addr)
        })?;
    let mut config = ServerConfig { listen, firewall_backend, ..ServerConfig::default() };
    config.revocation_retention_secs = parse_auth_policy_env_u64(
        "QUICFUSCATE_REVOCATION_RETENTION_SECS",
        config.revocation_retention_secs,
    )?;
    config.validate_revocation_retention()?;
    config.auth_policy = load_auth_policy_config_from_env()?;
    config.bandwidth_policy = load_bandwidth_policy_from_env()?;
    (
        config.downlink_scheduler_rate_bytes_per_second,
        config.downlink_scheduler_burst_bytes,
    ) = load_downlink_scheduler_from_env()?;
    #[cfg(feature = "rate_limiter")]
    {
        config.ddos_policy = load_ddos_policy_config_from_env()?;
        config.geoip = load_geoip_config_from_env()?;
        config.blacklist = load_blacklist_config_from_env()?;
    }
    Ok(config)
}

impl ServerConfig {
    fn validate_revocation_retention(&self) -> Result<(), String> {
        if self.revocation_retention_secs == 0 {
            return Err("server revocation retention must be nonzero".to_string());
        }
        Ok(())
    }

    fn validate_downlink_scheduler(&self) -> Result<(), String> {
        validate_downlink_scheduler_pair(
            self.downlink_scheduler_rate_bytes_per_second,
            self.downlink_scheduler_burst_bytes,
        )
    }
}

fn validate_downlink_scheduler_pair(rate: u64, burst: u64) -> Result<(), String> {
    if (rate == 0) != (burst == 0) {
        return Err(
            "server downlink scheduler rate and burst must both be zero or nonzero".to_string(),
        );
    }
    Ok(())
}

fn load_downlink_scheduler_from_env() -> Result<(u64, u64), String> {
    let rate = parse_auth_policy_env_u64(
        "QUICFUSCATE_SERVER_DOWNLINK_RATE_BYTES_PER_SECOND",
        0,
    )?;
    let burst =
        parse_auth_policy_env_u64("QUICFUSCATE_SERVER_DOWNLINK_BURST_BYTES", 0)?;
    validate_downlink_scheduler_pair(rate, burst)?;
    Ok((rate, burst))
}

fn load_bandwidth_policy_from_env() -> Result<BandwidthPolicy, String> {
    let defaults = BandwidthPolicy::default();
    let parse = |name: &str, default: u64| parse_auth_policy_env_u64(name, default);
    let weight = parse(
        "QUICFUSCATE_CLIENT_BANDWIDTH_WEIGHT",
        u64::from(defaults.weight),
    )?;
    let policy = BandwidthPolicy {
        rate_bytes_per_second: parse(
            "QUICFUSCATE_CLIENT_RATE_BYTES_PER_SECOND",
            defaults.rate_bytes_per_second,
        )?,
        burst_bytes: parse(
            "QUICFUSCATE_CLIENT_BURST_BYTES",
            defaults.burst_bytes,
        )?,
        daily_quota_bytes: parse(
            "QUICFUSCATE_CLIENT_DAILY_QUOTA_BYTES",
            defaults.daily_quota_bytes,
        )?,
        monthly_quota_bytes: parse(
            "QUICFUSCATE_CLIENT_MONTHLY_QUOTA_BYTES",
            defaults.monthly_quota_bytes,
        )?,
        weight: u16::try_from(weight)
            .map_err(|_| "QUICFUSCATE_CLIENT_BANDWIDTH_WEIGHT exceeds u16".to_string())?,
    };
    policy.validate()?;
    Ok(policy)
}

fn parse_auth_policy_env_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .map_err(|error| format!("invalid {name}='{raw}': {error}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("could not read {name}: {error}")),
    }
}

fn parse_policy_env_bool(name: &str, default: bool) -> Result<bool, String> {
    match std::env::var(name) {
        Ok(raw) if raw.trim() == "1" || raw.trim().eq_ignore_ascii_case("true") => Ok(true),
        Ok(raw) if raw.trim() == "0" || raw.trim().eq_ignore_ascii_case("false") => Ok(false),
        Ok(raw) => Err(format!("invalid {name}='{raw}': expected true, false, 1, or 0")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("could not read {name}: {error}")),
    }
}

#[cfg(feature = "rate_limiter")]
fn parse_policy_env_f64(name: &str, default: f64) -> Result<f64, String> {
    match std::env::var(name) {
        Ok(raw) => raw.trim().parse::<f64>().map_err(|error| format!("invalid {name}='{raw}': {error}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("could not read {name}: {error}")),
    }
}

#[cfg(feature = "rate_limiter")]
fn load_ddos_policy_config_from_env() -> Result<limits::DdosPolicyConfig, String> {
    let defaults = limits::DdosPolicyConfig::default();
    let milliseconds = |name: &str, default: Duration| -> Result<Duration, String> {
        Ok(Duration::from_millis(parse_auth_policy_env_u64(
            name,
            u64::try_from(default.as_millis()).unwrap_or(u64::MAX),
        )?))
    };
    let seconds = |name: &str, default: Duration| -> Result<Duration, String> {
        Ok(Duration::from_secs(parse_auth_policy_env_u64(name, default.as_secs())?))
    };
    let config = limits::DdosPolicyConfig {
        enabled: parse_policy_env_bool("QUICFUSCATE_DDOS_ENABLED", defaults.enabled)?,
        sample_interval: milliseconds(
            "QUICFUSCATE_DDOS_SAMPLE_INTERVAL_MS",
            defaults.sample_interval,
        )?,
        activation_window: milliseconds(
            "QUICFUSCATE_DDOS_ACTIVATION_WINDOW_MS",
            defaults.activation_window,
        )?,
        clear_window: milliseconds(
            "QUICFUSCATE_DDOS_CLEAR_WINDOW_MS",
            defaults.clear_window,
        )?,
        ewma_alpha: parse_policy_env_f64(
            "QUICFUSCATE_DDOS_EWMA_ALPHA",
            defaults.ewma_alpha,
        )?,
        spike_multiplier: parse_policy_env_f64(
            "QUICFUSCATE_DDOS_SPIKE_MULTIPLIER",
            defaults.spike_multiplier,
        )?,
        clear_factor: parse_policy_env_f64(
            "QUICFUSCATE_DDOS_CLEAR_FACTOR",
            defaults.clear_factor,
        )?,
        enhanced_packet_cost: parse_auth_policy_env_u64(
            "QUICFUSCATE_DDOS_ENHANCED_PACKET_COST",
            defaults.enhanced_packet_cost,
        )?,
        retry_enabled: parse_policy_env_bool(
            "QUICFUSCATE_DDOS_RETRY_ENABLED",
            defaults.retry_enabled,
        )?,
        retry_token_lifetime: seconds(
            "QUICFUSCATE_DDOS_RETRY_TOKEN_LIFETIME_SECS",
            defaults.retry_token_lifetime,
        )?,
    };
    config.validate()?;
    Ok(config)
}

fn load_auth_policy_config_from_env() -> Result<AuthPolicyConfig, String> {
    let defaults = AuthPolicyConfig::default();
    let enabled = match std::env::var("QUICFUSCATE_AUTH_POLICY_ENABLED") {
        Ok(raw) if raw.trim() == "1" || raw.trim().eq_ignore_ascii_case("true") => true,
        Ok(raw) if raw.trim() == "0" || raw.trim().eq_ignore_ascii_case("false") => false,
        Ok(raw) => {
            return Err(format!(
                "invalid QUICFUSCATE_AUTH_POLICY_ENABLED='{raw}': expected true, false, 1, or 0"
            ))
        }
        Err(std::env::VarError::NotPresent) => defaults.enabled,
        Err(error) => {
            return Err(format!("could not read QUICFUSCATE_AUTH_POLICY_ENABLED: {error}"))
        }
    };
    let milliseconds = |name: &str, default: Duration| -> Result<Duration, String> {
        Ok(Duration::from_millis(parse_auth_policy_env_u64(
            name,
            u64::try_from(default.as_millis()).unwrap_or(u64::MAX),
        )?))
    };
    let seconds = |name: &str, default: Duration| -> Result<Duration, String> {
        Ok(Duration::from_secs(parse_auth_policy_env_u64(name, default.as_secs())?))
    };
    let as_u32 = |name: &str, default: u32| -> Result<u32, String> {
        let value = parse_auth_policy_env_u64(name, u64::from(default))?;
        u32::try_from(value).map_err(|_| format!("{name} exceeds u32"))
    };
    let as_usize = |name: &str, default: usize| -> Result<usize, String> {
        let value = parse_auth_policy_env_u64(name, default as u64)?;
        usize::try_from(value).map_err(|_| format!("{name} exceeds usize"))
    };

    let config = AuthPolicyConfig {
        enabled,
        backoff_after_failures: as_u32(
            "QUICFUSCATE_AUTH_BACKOFF_AFTER_FAILURES",
            defaults.backoff_after_failures,
        )?,
        backoff_base: milliseconds(
            "QUICFUSCATE_AUTH_BACKOFF_BASE_MS",
            defaults.backoff_base,
        )?,
        backoff_max: milliseconds(
            "QUICFUSCATE_AUTH_BACKOFF_MAX_MS",
            defaults.backoff_max,
        )?,
        block_after_failures: as_u32(
            "QUICFUSCATE_AUTH_BLOCK_AFTER_FAILURES",
            defaults.block_after_failures,
        )?,
        block_duration: seconds(
            "QUICFUSCATE_AUTH_BLOCK_DURATION_SECS",
            defaults.block_duration,
        )?,
        idle_timeout: seconds(
            "QUICFUSCATE_AUTH_IDLE_TIMEOUT_SECS",
            defaults.idle_timeout,
        )?,
        prune_interval: seconds(
            "QUICFUSCATE_AUTH_PRUNE_INTERVAL_SECS",
            defaults.prune_interval,
        )?,
        max_tracked_ips: as_usize(
            "QUICFUSCATE_AUTH_MAX_TRACKED_IPS",
            defaults.max_tracked_ips,
        )?,
        max_pending_attempts_per_ip: as_usize(
            "QUICFUSCATE_AUTH_MAX_PENDING_PER_IP",
            defaults.max_pending_attempts_per_ip,
        )?,
    };
    config.validate()?;
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
fn load_geoip_config_from_env() -> Result<limits::GeoIpConfig, String> {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let db_path = env_string("QUICFUSCATE_GEOIP_DB_PATH").map(PathBuf::from);
    let blocked_countries: HashSet<String> = env_string("QUICFUSCATE_GEOIP_BLOCKED_COUNTRIES")
        .map(|s| s.split(',').map(|c| c.trim().to_uppercase()).collect())
        .unwrap_or_default();

    let config = limits::GeoIpConfig { db_path, blocked_countries };
    config.validate().map_err(|error| format!("Invalid GeoIP configuration: {error}"))?;
    if config.is_enabled() {
        log::info!(
            "GeoIP blocking configured: {} blocked countries, db={}",
            config.blocked_countries.len(),
            config.db_path.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
        );
    }
    Ok(config)
}

/// Load external blacklist sync config from environment variables.
///
/// - `QUICFUSCATE_BLACKLIST_SYNC_URL`: HTTPS URL to fetch a plain-text IP list.
/// - `QUICFUSCATE_BLACKLIST_TTL_SECS`: TTL for blocked IPs (default: 3600).
/// - `QUICFUSCATE_BLACKLIST_SYNC_INTERVAL_SECS`: sync interval (default: 3600).
/// - `QUICFUSCATE_BLACKLIST_CA_PATH`: optional PEM CA bundle for a private feed.
#[cfg(feature = "rate_limiter")]
fn load_blacklist_config_from_env() -> Result<BlacklistConfig, String> {
    let defaults = BlacklistConfig::default();
    let sync_url = env_string("QUICFUSCATE_BLACKLIST_SYNC_URL");
    let custom_ca_path =
        env_string("QUICFUSCATE_BLACKLIST_CA_PATH").map(std::path::PathBuf::from);
    let max_body_bytes = parse_auth_policy_env_u64(
        "QUICFUSCATE_BLACKLIST_MAX_BODY_BYTES",
        defaults.max_body_bytes as u64,
    )?;
    let max_entries = parse_auth_policy_env_u64(
        "QUICFUSCATE_BLACKLIST_MAX_ENTRIES",
        defaults.max_entries as u64,
    )?;
    let cache_path = match std::env::var("QUICFUSCATE_BLACKLIST_CACHE_PATH") {
        Ok(raw) if raw.trim().eq_ignore_ascii_case("disabled") => None,
        Ok(raw) if raw.trim().is_empty() => {
            return Err(
                "QUICFUSCATE_BLACKLIST_CACHE_PATH must be a path or 'disabled'".to_string(),
            )
        }
        Ok(raw) => Some(std::path::PathBuf::from(raw.trim())),
        Err(std::env::VarError::NotPresent) => defaults.cache_path,
        Err(error) => {
            return Err(format!("could not read QUICFUSCATE_BLACKLIST_CACHE_PATH: {error}"))
        }
    };
    let config = BlacklistConfig {
        default_ttl_secs: parse_auth_policy_env_u64(
            "QUICFUSCATE_BLACKLIST_TTL_SECS",
            defaults.default_ttl_secs,
        )?,
        sync_url,
        sync_interval_secs: parse_auth_policy_env_u64(
            "QUICFUSCATE_BLACKLIST_SYNC_INTERVAL_SECS",
            defaults.sync_interval_secs,
        )?,
        request_timeout_secs: parse_auth_policy_env_u64(
            "QUICFUSCATE_BLACKLIST_REQUEST_TIMEOUT_SECS",
            defaults.request_timeout_secs,
        )?,
        max_body_bytes: usize::try_from(max_body_bytes)
            .map_err(|_| "QUICFUSCATE_BLACKLIST_MAX_BODY_BYTES exceeds usize".to_string())?,
        max_entries: usize::try_from(max_entries)
            .map_err(|_| "QUICFUSCATE_BLACKLIST_MAX_ENTRIES exceeds usize".to_string())?,
        cache_path,
        custom_ca_path,
    };
    config.validate()?;
    if config.sync_url.is_some() {
        log::info!(
            "Blacklist sync enabled: ttl={}s, interval={}s",
            config.default_ttl_secs,
            config.sync_interval_secs
        );
    }
    Ok(config)
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

    admin_http::AdminAuth::new(admin_user, admin_password, requires_password_change).map_err(
        |error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admin authentication initialization failed: {error}"),
            )
        },
    )
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

const SUPPORTED_LOGGING_MODES: [&str; 4] = ["verbose", "normal", "minimal", "no-log"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PersistedLoggingModeState {
    Absent,
    Valid(crate::engine::LoggingMode),
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedLoggingModeFile {
    mode: crate::engine::LoggingMode,
}

pub(crate) fn logging_mode_name(mode: &crate::engine::LoggingMode) -> &'static str {
    match mode {
        crate::engine::LoggingMode::Verbose => "verbose",
        crate::engine::LoggingMode::Normal => "normal",
        crate::engine::LoggingMode::Minimal => "minimal",
        crate::engine::LoggingMode::NoLog => "no-log",
    }
}

pub(crate) fn parse_logging_mode(
    mode: &str,
) -> Result<crate::engine::LoggingMode, String> {
    match mode {
        "verbose" => Ok(crate::engine::LoggingMode::Verbose),
        "normal" => Ok(crate::engine::LoggingMode::Normal),
        "minimal" => Ok(crate::engine::LoggingMode::Minimal),
        "no-log" => Ok(crate::engine::LoggingMode::NoLog),
        _ => Err(format!(
            "Invalid logging mode '{}'. Valid: {:?}",
            mode, SUPPORTED_LOGGING_MODES
        )),
    }
}

pub(crate) fn load_persisted_logging_mode(
    config_path: Option<&std::path::Path>,
) -> std::io::Result<PersistedLoggingModeState> {
    let Some(path) = resolve_logging_store_path(config_path) else {
        return Ok(PersistedLoggingModeState::Absent);
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistedLoggingModeState::Absent)
        }
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!("logging state read failed for {}: {error}", path.display()),
            ))
        }
    };
    let state = serde_json::from_str::<PersistedLoggingModeFile>(&contents).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("logging state invalid for {}: {error}", path.display()),
        )
    })?;
    Ok(PersistedLoggingModeState::Valid(state.mode))
}

pub(crate) fn apply_logging_mode(
    mode: &crate::engine::LoggingMode,
    log_buffer: &crate::implementations::server::admin_logs::AdminLogBuffer,
) {
    let level = match mode {
        crate::engine::LoggingMode::NoLog => log::LevelFilter::Off,
        crate::engine::LoggingMode::Minimal => log::LevelFilter::Warn,
        crate::engine::LoggingMode::Verbose => log::LevelFilter::Trace,
        crate::engine::LoggingMode::Normal => log::LevelFilter::Info,
    };
    log::set_max_level(level);
    if matches!(mode, crate::engine::LoggingMode::NoLog) {
        log_buffer.clear();
    }
}

pub(crate) fn persist_logging_mode(
    config_path: Option<&std::path::Path>,
    mode: &crate::engine::LoggingMode,
) -> std::io::Result<()> {
    let Some(path) = resolve_logging_store_path(config_path) else {
        return Ok(());
    };
    let bytes = serde_json::to_vec_pretty(&PersistedLoggingModeFile { mode: mode.clone() })?;
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
