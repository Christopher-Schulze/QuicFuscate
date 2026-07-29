//! Platform backend traits.

use std::net::IpAddr;

/// TUN device configuration.
#[derive(Clone, Debug)]
pub struct TunDeviceConfig {
    /// Device name (e.g., "tun0", "utun5")
    pub name: Option<String>,
    /// Device IP address
    pub address: IpAddr,
    /// Netmask (as CIDR prefix length)
    pub netmask: u8,
    /// MTU
    pub mtu: u16,
}

impl Default for TunDeviceConfig {
    fn default() -> Self {
        Self {
            name: None,
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 8, 0, 2)),
            netmask: 24,
            mtu: 1400,
        }
    }
}

/// Route configuration.
#[derive(Clone, Debug)]
pub struct RouteConfig {
    /// Destination network
    pub destination: IpAddr,
    /// Prefix length (CIDR)
    pub prefix_len: u8,
    /// Gateway address
    pub gateway: IpAddr,
    /// Metric (lower = preferred)
    pub metric: u32,
}

/// DNS configuration.
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// DNS servers
    pub servers: Vec<IpAddr>,
    /// Search domains
    pub search_domains: Vec<String>,
}

/// Platform-specific error.
#[derive(Debug)]
pub enum PlatformError {
    /// Permission denied (need elevated privileges)
    PermissionDenied(String),
    /// Device creation failed
    DeviceError(String),
    /// Routing error
    RoutingError(String),
    /// DNS configuration error
    DnsError(String),
    /// Command execution failed
    CommandFailed(String),
    /// Feature not supported on this platform
    Unsupported(String),
    /// General I/O error
    Io(std::io::Error),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionDenied(s) => write!(f, "Permission denied: {}", s),
            Self::DeviceError(s) => write!(f, "Device error: {}", s),
            Self::RoutingError(s) => write!(f, "Routing error: {}", s),
            Self::DnsError(s) => write!(f, "DNS error: {}", s),
            Self::CommandFailed(s) => write!(f, "Command failed: {}", s),
            Self::Unsupported(s) => write!(f, "Unsupported: {}", s),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for PlatformError {}

impl From<std::io::Error> for PlatformError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Platform backend trait.
///
/// Implementors provide platform-specific functionality for:
/// - TUN device management
/// - Route management
/// - DNS configuration
pub trait PlatformBackend: Send + Sync {
    /// Get platform name.
    fn name(&self) -> &'static str;

    /// Check if running with elevated privileges.
    fn is_elevated(&self) -> bool;

    /// Request privilege elevation.
    fn request_elevation(&self) -> Result<(), PlatformError>;

    /// Create and configure TUN device.
    fn create_tun(&self, config: &TunDeviceConfig) -> Result<TunHandle, PlatformError>;

    /// Destroy a descriptor-owned TUN device.
    ///
    /// The mutable handle remains with the caller until the platform verifies
    /// the interface is absent, allowing bounded retries without losing the
    /// ownership proof after a partial failure.
    fn destroy_tun(&self, handle: &mut TunHandle) -> Result<(), PlatformError>;

    /// Add a route.
    fn add_route(&self, route: &RouteConfig) -> Result<(), PlatformError>;

    /// Remove a route.
    fn remove_route(&self, route: &RouteConfig) -> Result<(), PlatformError>;

    /// Configure DNS servers.
    fn set_dns(&self, config: &DnsConfig) -> Result<(), PlatformError>;

    /// Restore original DNS configuration.
    fn restore_dns(&self) -> Result<(), PlatformError>;

    /// Get default gateway.
    fn default_gateway(&self) -> Result<IpAddr, PlatformError>;
}

/// Handle to an open TUN device.
#[derive(Debug)]
pub struct TunHandle {
    /// Device name
    pub name: String,
    /// Platform-specific identifier
    pub id: u32,
    /// File descriptor (Unix) or handle (Windows)
    #[cfg(unix)]
    pub fd: std::os::unix::io::RawFd,
    #[cfg(windows)]
    pub handle: usize,
}

#[cfg(unix)]
impl Drop for TunHandle {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: `fd` remains owned by this handle until platform cleanup
            // closes it and sets it to -1. Drop is the final leak-prevention
            // fallback when all explicit cleanup attempts fail.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_config_default() {
        let config = TunDeviceConfig::default();
        assert_eq!(config.netmask, 24);
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_platform_error_display() {
        let err = PlatformError::PermissionDenied("test".to_string());
        assert!(err.to_string().contains("Permission denied"));
    }
}
