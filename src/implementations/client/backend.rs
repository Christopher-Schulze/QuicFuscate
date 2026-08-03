//! Unified cross-platform client backend.
//!
//! Provides a single API for connecting to QuicFuscate VPN servers
//! from Windows, macOS, and Linux.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

use super::connection::ClientConnection;
use super::platform::{
    self, DnsConfig, PlatformBackend, PlatformError, RouteConfig, TunDeviceConfig, TunHandle,
};
use crate::engine::{qkey, EngineConfig, EngineError};

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Connecting to server
    Connecting,
    /// Connected and routing traffic
    Connected,
    /// Reconnecting after failure
    Reconnecting,
    /// Disconnecting gracefully
    Disconnecting,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected => write!(f, "Connected"),
            Self::Reconnecting => write!(f, "Reconnecting"),
            Self::Disconnecting => write!(f, "Disconnecting"),
        }
    }
}

/// Client statistics.
#[derive(Debug, Clone)]
pub struct ClientStats {
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Current RTT in milliseconds
    pub rtt_ms: f32,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f32,
    /// Connection uptime in seconds
    pub uptime_secs: u64,
}

/// Backend error.
#[derive(Debug)]
pub enum BackendError {
    /// Platform-specific error
    Platform(PlatformError),
    /// Engine/connection error
    Engine(EngineError),
    /// QKey parsing error
    QKey(String),
    /// Invalid state for operation
    InvalidState(String),
    /// Configuration error
    Config(String),
    /// One or more owned resources could not be released.
    Cleanup(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform(e) => write!(f, "Platform error: {}", e),
            Self::Engine(e) => write!(f, "Engine error: {}", e),
            Self::QKey(s) => write!(f, "QKey error: {}", s),
            Self::InvalidState(s) => write!(f, "Invalid state: {}", s),
            Self::Config(s) => write!(f, "Config error: {}", s),
            Self::Cleanup(s) => write!(f, "Cleanup error: {}", s),
        }
    }
}

impl std::error::Error for BackendError {}

impl From<PlatformError> for BackendError {
    fn from(e: PlatformError) -> Self {
        Self::Platform(e)
    }
}

impl From<EngineError> for BackendError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

/// Unified cross-platform client backend.
pub struct ClientBackend {
    /// Platform-specific backend
    platform: Box<dyn PlatformBackend>,
    /// Current connection state
    state: ConnectionState,
    /// Active connection
    connection: Option<ClientConnection>,
    /// TUN device handle
    tun_handle: Option<TunHandle>,
    /// Routes successfully installed by this instance and still owned by it.
    active_routes: Vec<RouteConfig>,
    /// Whether this instance attempted to replace system DNS state.
    dns_configured: bool,
    /// Statistics
    stats: ClientStatsInternal,
}

struct ClientStatsInternal {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    connect_time: Option<std::time::Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EffectiveTunNetwork {
    address: IpAddr,
    prefix: u8,
    gateway: IpAddr,
}

fn ipv4_netmask_prefix(mask: Ipv4Addr) -> Result<u8, BackendError> {
    let raw = u32::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    if raw != canonical {
        return Err(BackendError::Config(format!("TUN IPv4 netmask is not contiguous: {mask}")));
    }
    Ok(prefix)
}

fn ipv6_netmask_prefix(mask: Ipv6Addr) -> Result<u8, BackendError> {
    let raw = u128::from(mask);
    let prefix = raw.leading_ones() as u8;
    let canonical = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    if raw != canonical {
        return Err(BackendError::Config(format!("TUN IPv6 netmask is not contiguous: {mask}")));
    }
    Ok(prefix)
}

fn netmask_prefix(address: IpAddr, netmask: IpAddr) -> Result<u8, BackendError> {
    match (address, netmask) {
        (IpAddr::V4(_), IpAddr::V4(mask)) => ipv4_netmask_prefix(mask),
        (IpAddr::V6(_), IpAddr::V6(mask)) => ipv6_netmask_prefix(mask),
        _ => Err(BackendError::Config(
            "TUN address and netmask must use the same address family".to_string(),
        )),
    }
}

fn default_tun_gateway(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let network = u32::from(address) & mask;
            IpAddr::V4(Ipv4Addr::from(network.saturating_add(1)))
        }
        IpAddr::V6(address) => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            let network = u128::from(address) & mask;
            IpAddr::V6(Ipv6Addr::from(network.saturating_add(1)))
        }
    }
}

fn effective_tun_network(config: &EngineConfig) -> Result<EffectiveTunNetwork, BackendError> {
    match (config.interface.tun_ip, config.interface.tun_netmask) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(BackendError::Config(
                "tun_ip and tun_netmask must be configured together".to_string(),
            ));
        }
        (Some(ip), Some(mask)) if ip.is_ipv4() != mask.is_ipv4() => {
            return Err(BackendError::Config(
                "tun_ip and tun_netmask must use the same address family".to_string(),
            ));
        }
        _ => {}
    }

    let address = config.interface.tun_ip.unwrap_or(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
    let mask_prefix =
        config.interface.tun_netmask.map(|mask| netmask_prefix(address, mask)).transpose()?;
    let prefix = match (mask_prefix, config.interface.tun_subnet_prefix) {
        (Some(mask_prefix), Some(configured_prefix)) if mask_prefix != configured_prefix => {
            return Err(BackendError::Config(format!(
                "tun_netmask prefix {mask_prefix} conflicts with tun_subnet_prefix {configured_prefix}"
            )));
        }
        (Some(mask_prefix), _) => mask_prefix,
        (None, Some(configured_prefix)) => configured_prefix,
        (None, None) => 24,
    };
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(BackendError::Config(format!(
            "TUN subnet prefix {prefix} exceeds the {}-bit address family",
            max_prefix
        )));
    }

    let gateway = match config.interface.tun_gateway {
        Some(gateway) if gateway.is_ipv4() != address.is_ipv4() => {
            return Err(BackendError::Config(
                "tun_gateway must use the same address family as tun_ip".to_string(),
            ));
        }
        Some(gateway) => gateway,
        None => default_tun_gateway(address, prefix),
    };

    Ok(EffectiveTunNetwork { address, prefix, gateway })
}

fn default_routes(gateway: IpAddr) -> [RouteConfig; 2] {
    match gateway {
        IpAddr::V4(gateway) => [
            RouteConfig {
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_len: 1,
                gateway: IpAddr::V4(gateway),
                metric: 10,
            },
            RouteConfig {
                destination: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
                prefix_len: 1,
                gateway: IpAddr::V4(gateway),
                metric: 10,
            },
        ],
        IpAddr::V6(gateway) => [
            RouteConfig {
                destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_len: 1,
                gateway: IpAddr::V6(gateway),
                metric: 10,
            },
            RouteConfig {
                destination: IpAddr::V6(Ipv6Addr::from(1u128 << 127)),
                prefix_len: 1,
                gateway: IpAddr::V6(gateway),
                metric: 10,
            },
        ],
    }
}

impl Default for ClientStatsInternal {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            connect_time: None,
        }
    }
}

impl ClientBackend {
    /// Create a new client backend using the native platform.
    pub fn new() -> Self {
        Self {
            platform: Box::new(platform::native()),
            state: ConnectionState::Disconnected,
            connection: None,
            tun_handle: None,
            active_routes: Vec::new(),
            dns_configured: false,
            stats: ClientStatsInternal::default(),
        }
    }

    /// Create with custom platform backend.
    pub fn with_platform(platform: Box<dyn PlatformBackend>) -> Self {
        Self {
            platform,
            state: ConnectionState::Disconnected,
            connection: None,
            tun_handle: None,
            active_routes: Vec::new(),
            dns_configured: false,
            stats: ClientStatsInternal::default(),
        }
    }

    /// Get current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Get current statistics.
    pub fn stats(&self) -> ClientStats {
        let uptime = self.stats.connect_time.map(|t| t.elapsed().as_secs()).unwrap_or(0);

        let (rtt_ms, loss_rate) = if let Some(ref conn) = self.connection {
            (conn.rtt_ms(), conn.loss_rate())
        } else {
            (0.0, 0.0)
        };

        ClientStats {
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            rtt_ms,
            loss_rate,
            uptime_secs: uptime,
        }
    }

    /// Connect using a QKey connection string.
    pub fn connect_qkey(&mut self, qkey_str: &str) -> Result<(), BackendError> {
        // Parse QKey
        let qkey_config = qkey::parse(qkey_str).map_err(|e| BackendError::QKey(e.to_string()))?;
        let qkey_id = qkey::id(qkey_str);

        // Build EngineConfig from QKey
        let mut config = EngineConfig::default();
        config.connection.remote = qkey_config.remote;
        config.connection.sni = qkey_config.sni;
        let token_hex = qkey_config
            .token
            .as_deref()
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .ok_or_else(|| BackendError::QKey("QKey missing token".to_string()))?;
        let token_hex = qkey::QKeyToken::new(token_hex.to_lowercase());
        if token_hex.len() != 64
            || !token_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(BackendError::QKey(
                "Invalid QKey token hex (expected 64 hex chars)".to_string(),
            ));
        }
        config.connection.qkey_token = Some(token_hex);
        config.connection.qkey_id = Some(qkey_id);

        if let Some(stealth) = qkey_config.stealth {
            let s = stealth.trim().to_ascii_lowercase();
            config.stealth.mode = match s.as_str() {
                "off" => crate::engine::StealthMode::Off,
                "performance" => crate::engine::StealthMode::Performance,
                "stealth" => crate::engine::StealthMode::Stealth,
                "anti-dpi" | "antidpi" | "anti_dpi" | "max" => crate::engine::StealthMode::AntiDpi,
                "manual" => crate::engine::StealthMode::Manual,
                _ => crate::engine::StealthMode::Auto,
            };
        }

        if let Some(fec) = qkey_config.fec {
            let f = fec.trim().to_ascii_lowercase();
            config.fec.mode = match f.as_str() {
                "off" | "zero" => crate::engine::FecMode::Off,
                "auto" | "dynamic" | "on" | "manual" | "normal" => crate::engine::FecMode::Auto,
                _ => crate::engine::FecMode::Auto,
            };
        }

        self.connect(&config)
    }

    /// Connect using an EngineConfig.
    pub fn connect(&mut self, config: &EngineConfig) -> Result<(), BackendError> {
        // Check state
        if self.state != ConnectionState::Disconnected {
            return Err(BackendError::InvalidState(format!(
                "Cannot connect from state: {}",
                self.state
            )));
        }

        self.state = ConnectionState::Connecting;
        log::info!("Connecting to {}", config.connection.remote);

        match self.connect_inner(config) {
            Ok(()) => {
                self.stats.connect_time = Some(std::time::Instant::now());
                self.state = ConnectionState::Connected;
                log::info!("Connected successfully");
                Ok(())
            }
            Err(connect_error) => {
                let rollback_error = self.cleanup_owned_resources().err();
                self.state = if rollback_error.is_some() {
                    ConnectionState::Disconnecting
                } else {
                    ConnectionState::Disconnected
                };
                match rollback_error {
                    Some(rollback) => Err(BackendError::Cleanup(format!(
                        "connect failed: {connect_error}; owned rollback failed: {rollback}"
                    ))),
                    None => Err(connect_error),
                }
            }
        }
    }

    fn connect_inner(&mut self, config: &EngineConfig) -> Result<(), BackendError> {
        // Check privileges
        if !self.platform.is_elevated() {
            self.platform.request_elevation()?;
        }

        let effective_network = effective_tun_network(config)?;

        // Create TUN device
        let tun_config = TunDeviceConfig {
            name: Some(config.interface.tun_name.clone()),
            address: effective_network.address,
            netmask: effective_network.prefix,
            mtu: config.interface.tun_mtu,
        };

        let tun_handle = self.platform.create_tun(&tun_config)?;
        self.tun_handle = Some(tun_handle);

        // Establish QUIC connection
        let connection = ClientConnection::connect(config)?;
        self.connection = Some(connection);

        // Add routes (route all traffic through VPN)
        for route in default_routes(effective_network.gateway) {
            self.platform.add_route(&route)?;
            self.active_routes.push(route);
        }

        // Configure DNS (from config or defaults)
        let dns_servers = if config.interface.dns_servers.is_empty() {
            vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ]
        } else {
            config.interface.dns_servers.clone()
        };
        self.dns_configured = true;
        self.platform.set_dns(&DnsConfig { servers: dns_servers, search_domains: vec![] })?;
        Ok(())
    }

    /// Disconnect from VPN.
    pub fn disconnect(&mut self) -> Result<(), BackendError> {
        if self.state == ConnectionState::Disconnected {
            return Ok(());
        }

        self.state = ConnectionState::Disconnecting;
        log::info!("Disconnecting");

        self.cleanup_owned_resources()?;

        self.stats = ClientStatsInternal::default();
        self.state = ConnectionState::Disconnected;

        log::info!("Disconnected");
        Ok(())
    }

    fn cleanup_owned_resources(&mut self) -> Result<(), BackendError> {
        if let Some(mut connection) = self.connection.take() {
            connection.close(0, b"owned resource cleanup");
        }

        let mut failures = Vec::new();
        if self.dns_configured {
            match Self::retry_cleanup("restore DNS", || self.platform.restore_dns()) {
                Ok(()) => self.dns_configured = false,
                Err(error) => failures.push(error),
            }
        }

        let routes = std::mem::take(&mut self.active_routes);
        let mut retained_routes = Vec::new();
        for route in routes.into_iter().rev() {
            let label = format!("remove route {}/{}", route.destination, route.prefix_len);
            if let Err(error) = Self::retry_cleanup(&label, || self.platform.remove_route(&route)) {
                failures.push(error);
                retained_routes.push(route);
            }
        }
        retained_routes.reverse();
        self.active_routes = retained_routes;

        if let Some(mut handle) = self.tun_handle.take() {
            let label = format!("destroy descriptor-owned TUN {}", handle.name);
            if let Err(error) =
                Self::retry_cleanup(&label, || self.platform.destroy_tun(&mut handle))
            {
                failures.push(error);
                self.tun_handle = Some(handle);
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(BackendError::Cleanup(failures.join("; ")))
        }
    }

    fn retry_cleanup<Cleanup>(label: &str, mut cleanup: Cleanup) -> Result<(), String>
    where
        Cleanup: FnMut() -> Result<(), PlatformError>,
    {
        let mut last_error = None;
        for attempt in 1..=3 {
            match cleanup() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_error = Some(error);
                    if attempt < 3 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
        }
        let detail = last_error
            .map_or_else(|| "cleanup returned no result".to_string(), |error| error.to_string());
        Err(format!("{label} failed after 3 attempts: {detail}"))
    }

    /// Get the platform name.
    pub fn platform_name(&self) -> &'static str {
        self.platform.name()
    }
}

impl Default for ClientBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ClientBackend {
    fn drop(&mut self) {
        // Ensure cleanup on drop
        if let Err(e) = self.disconnect() {
            log::warn!("ClientBackend drop cleanup failed: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::{Arc, Mutex as StdMutex};

    struct CleanupTestPlatform {
        destroy_attempts: Arc<AtomicUsize>,
        fail_through_attempt: Arc<AtomicUsize>,
    }

    struct ConfigCapturePlatform {
        tun_config: Arc<StdMutex<Option<TunDeviceConfig>>>,
        routes: Arc<StdMutex<Vec<RouteConfig>>>,
    }

    impl PlatformBackend for ConfigCapturePlatform {
        fn name(&self) -> &'static str {
            "config-capture"
        }

        fn is_elevated(&self) -> bool {
            true
        }

        fn request_elevation(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
            *self.tun_config.lock().unwrap() = Some(config.clone());
            Ok(TunHandle {
                name: config.name.clone().unwrap_or_else(|| "capture-tun".to_string()),
                id: 1,
                #[cfg(unix)]
                fd: -1,
                #[cfg(windows)]
                handle: 0,
            })
        }

        fn destroy_tun(&self, _handle: &mut TunHandle) -> Result<(), PlatformError> {
            Ok(())
        }

        fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError> {
            self.routes.lock().unwrap().push(route.clone());
            Ok(())
        }

        fn remove_route(&self, _route: &RouteConfig) -> Result<(), PlatformError> {
            Ok(())
        }

        fn set_dns(&self, _config: &DnsConfig) -> Result<(), PlatformError> {
            Ok(())
        }

        fn restore_dns(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
            Ok(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)))
        }
    }

    impl PlatformBackend for CleanupTestPlatform {
        fn name(&self) -> &'static str {
            "cleanup-test"
        }

        fn is_elevated(&self) -> bool {
            true
        }

        fn request_elevation(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        fn create_tun(&self, _config: &TunDeviceConfig) -> Result<TunHandle, PlatformError> {
            Err(PlatformError::Unsupported(
                "cleanup test does not create platform devices".to_string(),
            ))
        }

        fn destroy_tun(&self, _handle: &mut TunHandle) -> Result<(), PlatformError> {
            let attempt = self.destroy_attempts.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            if attempt <= self.fail_through_attempt.load(AtomicOrdering::SeqCst) {
                Err(PlatformError::DeviceError(format!("injected destroy failure {attempt}")))
            } else {
                Ok(())
            }
        }

        fn add_route(&self, _route: &RouteConfig) -> Result<(), PlatformError> {
            Ok(())
        }

        fn remove_route(&self, _route: &RouteConfig) -> Result<(), PlatformError> {
            Ok(())
        }

        fn set_dns(&self, _config: &DnsConfig) -> Result<(), PlatformError> {
            Ok(())
        }

        fn restore_dns(&self) -> Result<(), PlatformError> {
            Ok(())
        }

        fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
            Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        }
    }

    fn cleanup_test_tun_handle() -> TunHandle {
        TunHandle {
            name: "owned-test-tun".to_string(),
            id: 7,
            #[cfg(unix)]
            fd: -1,
            #[cfg(windows)]
            handle: 0,
        }
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Disconnected.to_string(), "Disconnected");
    }

    #[test]
    fn test_client_backend_new() {
        let backend = ClientBackend::new();
        assert_eq!(backend.state(), ConnectionState::Disconnected);
        assert!(!backend.is_connected());
    }

    #[test]
    fn test_client_stats_default() {
        let backend = ClientBackend::new();
        let stats = backend.stats();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.uptime_secs, 0);
    }

    fn config_capture_backend(
    ) -> (ClientBackend, Arc<StdMutex<Option<TunDeviceConfig>>>, Arc<StdMutex<Vec<RouteConfig>>>)
    {
        let tun_config = Arc::new(StdMutex::new(None));
        let routes = Arc::new(StdMutex::new(Vec::new()));
        let platform = ConfigCapturePlatform {
            tun_config: Arc::clone(&tun_config),
            routes: Arc::clone(&routes),
        };
        (ClientBackend::with_platform(Box::new(platform)), tun_config, routes)
    }

    fn test_backend_config() -> EngineConfig {
        let mut config = EngineConfig::default();
        config.connection.remote = "127.0.0.1:4433".to_string();
        config
    }

    #[test]
    fn client_backend_preserves_default_tun_network() {
        let (mut backend, tun_config, routes) = config_capture_backend();
        backend.connect(&test_backend_config()).expect("default backend connect");

        let tun_config = tun_config.lock().unwrap().clone().expect("captured TUN config");
        assert_eq!(tun_config.address, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(tun_config.netmask, 24);

        let routes = routes.lock().unwrap().clone();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| {
            route.gateway == IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)) && route.destination.is_ipv4()
        }));

        backend.disconnect().expect("default backend disconnect");
    }

    #[test]
    fn client_backend_propagates_configured_tun_network_and_gateway() {
        let (mut backend, tun_config, routes) = config_capture_backend();
        let mut config = test_backend_config();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("TUN address"));
        config.interface.tun_netmask = Some("255.255.0.0".parse().expect("TUN netmask"));

        backend.connect(&config).expect("configured backend connect");

        let tun_config = tun_config.lock().unwrap().clone().expect("captured TUN config");
        assert_eq!(tun_config.address, IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
        assert_eq!(tun_config.netmask, 16);

        let routes = routes.lock().unwrap().clone();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| {
            route.gateway == IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1)) && route.destination.is_ipv4()
        }));

        backend.disconnect().expect("configured backend disconnect");
    }

    #[test]
    fn client_backend_uses_subnet_prefix_when_netmask_is_absent() {
        let (mut backend, tun_config, routes) = config_capture_backend();
        let mut config = test_backend_config();
        config.interface.tun_subnet_prefix = Some(16);

        backend.connect(&config).expect("prefix-configured backend connect");

        let tun_config = tun_config.lock().unwrap().clone().expect("captured TUN config");
        assert_eq!(tun_config.address, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(tun_config.netmask, 16);
        assert!(routes
            .lock()
            .unwrap()
            .iter()
            .all(|route| { route.gateway == IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)) }));

        backend.disconnect().expect("prefix-configured backend disconnect");
    }

    #[test]
    fn client_backend_propagates_ipv6_tun_network_and_routes() {
        let (mut backend, tun_config, routes) = config_capture_backend();
        let mut config = test_backend_config();
        config.interface.tun_ip = Some("2001:db8:42::2".parse().expect("TUN IPv6 address"));
        config.interface.tun_netmask =
            Some("ffff:ffff:ffff:ffff::".parse().expect("TUN IPv6 netmask"));

        backend.connect(&config).expect("IPv6 backend connect");

        let tun_config = tun_config.lock().unwrap().clone().expect("captured TUN config");
        assert_eq!(tun_config.address, "2001:db8:42::2".parse::<IpAddr>().unwrap());
        assert_eq!(tun_config.netmask, 64);

        let routes = routes.lock().unwrap().clone();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| {
            route.gateway == "2001:db8:42::1".parse::<IpAddr>().unwrap()
                && route.destination.is_ipv6()
        }));

        backend.disconnect().expect("IPv6 backend disconnect");
    }

    #[test]
    fn effective_tun_network_rejects_non_contiguous_netmask() {
        let mut config = test_backend_config();
        config.interface.tun_ip = Some("10.20.30.40".parse().expect("TUN address"));
        config.interface.tun_netmask = Some("255.0.255.0".parse().expect("TUN netmask"));

        let error = effective_tun_network(&config).expect_err("invalid netmask must fail closed");
        assert!(error.to_string().contains("not contiguous"));
    }

    #[test]
    fn cleanup_retry_recovers_first_transient_failure() {
        let mut attempts = 0;
        ClientBackend::retry_cleanup("test cleanup", || {
            attempts += 1;
            if attempts == 1 {
                Err(PlatformError::CommandFailed("busy".to_string()))
            } else {
                Ok(())
            }
        })
        .unwrap();

        assert_eq!(attempts, 2);
    }

    #[test]
    fn cleanup_retry_reports_persistent_failure_exactly() {
        let mut attempts = 0;
        let error = ClientBackend::retry_cleanup("test cleanup", || {
            attempts += 1;
            Err(PlatformError::CommandFailed("permanent".to_string()))
        })
        .unwrap_err();

        assert_eq!(attempts, 3);
        assert!(error.contains("test cleanup failed after 3 attempts"));
        assert!(error.contains("permanent"));
    }

    #[test]
    fn failed_tun_cleanup_retains_owned_handle_for_later_retry() {
        let destroy_attempts = Arc::new(AtomicUsize::new(0));
        let fail_through_attempt = Arc::new(AtomicUsize::new(usize::MAX));
        let platform = CleanupTestPlatform {
            destroy_attempts: Arc::clone(&destroy_attempts),
            fail_through_attempt: Arc::clone(&fail_through_attempt),
        };
        let mut backend = ClientBackend::with_platform(Box::new(platform));
        backend.state = ConnectionState::Disconnecting;
        backend.tun_handle = Some(cleanup_test_tun_handle());

        let error = backend.cleanup_owned_resources().unwrap_err();
        assert!(error.to_string().contains("injected destroy failure 3"));
        assert_eq!(destroy_attempts.load(AtomicOrdering::SeqCst), 3);
        assert!(backend.tun_handle.is_some());

        fail_through_attempt.store(3, AtomicOrdering::SeqCst);
        backend.cleanup_owned_resources().unwrap();
        assert_eq!(destroy_attempts.load(AtomicOrdering::SeqCst), 4);
        assert!(backend.tun_handle.is_none());
    }
}
