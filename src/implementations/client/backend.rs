//! Unified cross-platform client backend.
//!
//! Provides a single API for connecting to QuicFuscate VPN servers
//! from Windows, macOS, and Linux.

use std::net::IpAddr;
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
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform(e) => write!(f, "Platform error: {}", e),
            Self::Engine(e) => write!(f, "Engine error: {}", e),
            Self::QKey(s) => write!(f, "QKey error: {}", s),
            Self::InvalidState(s) => write!(f, "Invalid state: {}", s),
            Self::Config(s) => write!(f, "Config error: {}", s),
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
    /// Active gateway used for routing (stored for disconnect cleanup)
    active_gateway: Option<IpAddr>,
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
            active_gateway: None,
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
            active_gateway: None,
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

        // Check privileges
        if !self.platform.is_elevated() {
            self.platform.request_elevation()?;
        }

        // Create TUN device
        let tun_config = TunDeviceConfig {
            name: Some(config.interface.tun_name.clone()),
            address: IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
            netmask: 24,
            mtu: config.interface.tun_mtu,
        };

        let tun_handle = self.platform.create_tun(&tun_config)?;
        self.tun_handle = Some(tun_handle);

        // Establish QUIC connection
        let connection = ClientConnection::connect(config)?;
        self.connection = Some(connection);

        // Add routes (route all traffic through VPN)
        let default_gateway = IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 1));
        let gateway: IpAddr = config.interface.tun_gateway.unwrap_or(default_gateway);
        self.platform.add_route(&RouteConfig {
            destination: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 1,
            gateway,
            metric: 10,
        })?;
        self.platform.add_route(&RouteConfig {
            destination: IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)),
            prefix_len: 1,
            gateway,
            metric: 10,
        })?;

        // Configure DNS (from config or defaults)
        let dns_servers = if config.interface.dns_servers.is_empty() {
            vec![
                IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            ]
        } else {
            config.interface.dns_servers.clone()
        };
        self.platform.set_dns(&DnsConfig { servers: dns_servers, search_domains: vec![] })?;

        // Store active gateway for disconnect cleanup
        self.active_gateway = Some(gateway);

        // Update state
        self.stats.connect_time = Some(std::time::Instant::now());
        self.state = ConnectionState::Connected;

        log::info!("Connected successfully");
        Ok(())
    }

    /// Disconnect from VPN.
    pub fn disconnect(&mut self) -> Result<(), BackendError> {
        if self.state == ConnectionState::Disconnected {
            return Ok(());
        }

        self.state = ConnectionState::Disconnecting;
        log::info!("Disconnecting");

        // Close QUIC connection
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"user disconnect");
        }

        // Restore DNS - retry once on failure, then propagate error
        if let Err(e) = self.platform.restore_dns() {
            log::warn!("DNS restore failed, retrying: {}", e);
            if let Err(e2) = self.platform.restore_dns() {
                return Err(BackendError::Platform(e2));
            }
        }

        // Remove routes
        let default_gateway = IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 1));
        let gateway: IpAddr = self.active_gateway.take().unwrap_or(default_gateway);
        if let Err(e) = self.platform.remove_route(&RouteConfig {
            destination: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: 1,
            gateway,
            metric: 10,
        }) {
            log::warn!("Failed to remove default route half 0.0.0.0/1: {}", e);
        }
        if let Err(e) = self.platform.remove_route(&RouteConfig {
            destination: IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)),
            prefix_len: 1,
            gateway,
            metric: 10,
        }) {
            log::warn!("Failed to remove default route half 128.0.0.0/1: {}", e);
        }

        // Destroy TUN device
        if let Some(handle) = self.tun_handle.take() {
            if let Err(e) = self.platform.destroy_tun(handle) {
                log::warn!("Failed to destroy TUN device during disconnect: {}", e);
            }
        }

        // Reset state
        self.stats = ClientStatsInternal::default();
        self.state = ConnectionState::Disconnected;

        log::info!("Disconnected");
        Ok(())
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
}
