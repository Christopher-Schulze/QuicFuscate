//! Root-independent TUN interface contracts.

use std::io;
use std::net::{IpAddr, Ipv6Addr};

/// Maximum number of owned packets buffered between a blocking TUN reader and
/// the async transport loop.
pub const TUN_PACKET_QUEUE_CAPACITY: usize = 1024;
/// Minimum valid IPv4 TUN MTU.
pub const TUN_MIN_MTU: u16 = 576;
/// Minimum valid MTU while IPv6 is enabled.
pub const TUN_IPV6_MIN_MTU: u16 = 1280;

/// Errors produced by the TUN contract layer.
#[derive(Debug)]
#[doc(hidden)]
pub enum TunError {
    /// TUN is not supported on the current platform.
    Unsupported,
    /// Operating system I/O error.
    Io(io::Error),
    /// Configuration or prerequisite error.
    Config(&'static str),
}

impl From<io::Error> for TunError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Configuration shared by native and externally supplied TUN backends.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct TunConfig {
    /// Requested TUN device name (None for OS-assigned).
    pub name: Option<String>,
    /// Static IPv4 address to assign to the TUN interface.
    pub ip: Option<IpAddr>,
    /// IPv4 netmask for the TUN interface address.
    pub netmask: Option<IpAddr>,
    /// Maximum transmission unit for the TUN device.
    pub mtu: u16,
    /// If true, consumers should prefer memory-pool backed I/O.
    pub zero_copy: bool,
    /// IPv6 address for dual-stack TUN (None = IPv4-only).
    pub ip6: Option<Ipv6Addr>,
    /// IPv6 prefix length (e.g., 64).
    pub prefix6: Option<u8>,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            ip: None,
            netmask: None,
            mtu: 1500,
            zero_copy: true,
            ip6: None,
            prefix6: None,
        }
    }
}

/// Validate the shared address and MTU contract before a backend is opened.
#[doc(hidden)]
pub fn validate_tun_config(config: &TunConfig) -> Result<(), TunError> {
    if config.mtu < TUN_MIN_MTU {
        return Err(TunError::Config("TUN MTU must be >= 576"));
    }
    if let Some(name) = config.name.as_deref() {
        if name.is_empty() || name.contains('\0') {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN interface name must be non-empty and must not contain NUL",
            )));
        }
    }

    match (config.ip, config.netmask) {
        (None, None) => {}
        (Some(IpAddr::V4(_)), Some(IpAddr::V4(mask))) => {
            let raw = u32::from(mask);
            let prefix = raw.leading_ones();
            let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            if raw != canonical {
                return Err(TunError::Config("TUN IPv4 netmask must be contiguous"));
            }
        }
        (Some(IpAddr::V6(_)), Some(IpAddr::V6(_))) => {
            return Err(TunError::Config(
                "TUN IPv6 address must use ip6 and prefix6, not ip and netmask",
            ));
        }
        (Some(_), Some(_)) => {
            return Err(TunError::Config("TUN IPv4 address and netmask must use IPv4"));
        }
        _ => {
            return Err(TunError::Config(
                "TUN IPv4 address and netmask must be configured together",
            ));
        }
    }

    match (config.ip6, config.prefix6) {
        (None, None) => {}
        (Some(_), Some(prefix)) if prefix <= 128 => {
            if config.mtu < TUN_IPV6_MIN_MTU {
                return Err(TunError::Config("IPv6 TUN MTU must be >= 1280"));
            }
        }
        (Some(_), Some(_)) => {
            return Err(TunError::Config("IPv6 TUN prefix must be <= 128"));
        }
        _ => {
            return Err(TunError::Config(
                "IPv6 TUN address and prefix must be configured together",
            ));
        }
    }
    Ok(())
}

/// Runtime capability view for TUN integration.
#[derive(Clone, Copy, Debug)]
#[doc(hidden)]
pub struct TunCapabilities {
    /// Built-in native implementation exists for the current target.
    pub built_in: bool,
    /// External factory has been registered for platform-managed backends.
    pub external_factory_registered: bool,
    /// Zero-copy can be used on the current platform/runtime path.
    pub supports_zero_copy: bool,
    /// Raw file descriptor exposure is available.
    pub supports_raw_fd: bool,
}

/// Execution contract for a backend's single-packet read operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum TunReadContract {
    /// `read()` returns promptly with data, `WouldBlock`, or another result.
    NonBlocking,
    /// `read()` may wait for device input and must have a dedicated reader owner.
    Blocking,
}

/// Basic TUN device contract implemented by native and externally supplied backends.
#[doc(hidden)]
pub trait TunDevice: Send + Sync {
    /// Returns the OS-level device name.
    fn name(&self) -> &str;
    /// Returns the configured MTU for this device.
    fn mtu(&self) -> u16;
    /// Declares whether `read()` is safe to call from an async-owned loop.
    fn read_contract(&self) -> TunReadContract {
        TunReadContract::Blocking
    }
    /// Applies a new MTU to the live device.
    fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        if mtu == self.mtu() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dynamic TUN MTU updates are unsupported by this backend",
            ))
        }
    }
    /// Reads one IP packet into `buf`.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes one complete IP packet from `buf`.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Wakes a potentially blocking reader so its owner can observe shutdown.
    fn request_read_shutdown(&self) -> io::Result<()> {
        Ok(())
    }
    /// Returns the raw file descriptor for Unix readiness integration.
    #[cfg(unix)]
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// Global factory contract for platform-managed TUN implementations.
#[doc(hidden)]
pub type TunFactory =
    Box<dyn Fn(&TunConfig) -> io::Result<Box<dyn TunDevice>> + Send + Sync + 'static>;

#[cfg(test)]
mod tests {
    use super::{validate_tun_config, TunConfig, TunError, TUN_IPV6_MIN_MTU, TUN_MIN_MTU};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn default_config_is_valid_and_keeps_mtu_bounds() {
        let config = TunConfig::default();
        assert_eq!(config.mtu, 1500);
        assert!(config.zero_copy);
        assert!(validate_tun_config(&config).is_ok());
    }

    #[test]
    fn validation_rejects_incomplete_or_malformed_address_configuration() {
        let missing_netmask =
            TunConfig { ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), ..TunConfig::default() };
        assert!(matches!(validate_tun_config(&missing_netmask), Err(TunError::Config(_))));

        let non_contiguous = TunConfig {
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 0, 255, 0))),
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&non_contiguous), Err(TunError::Config(_))));

        let ipv6_in_ipv4_fields = TunConfig {
            ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            netmask: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&ipv6_in_ipv4_fields), Err(TunError::Config(_))));
    }

    #[test]
    fn validation_enforces_ipv6_prefix_and_mtu_contract() {
        let missing_prefix = TunConfig { ip6: Some(Ipv6Addr::LOCALHOST), ..TunConfig::default() };
        assert!(matches!(validate_tun_config(&missing_prefix), Err(TunError::Config(_))));

        let invalid_prefix = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(129),
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&invalid_prefix), Err(TunError::Config(_))));

        let low_mtu = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(64),
            mtu: TUN_IPV6_MIN_MTU - 1,
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&low_mtu), Err(TunError::Config(_))));

        let valid = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(64),
            mtu: TUN_IPV6_MIN_MTU,
            ..TunConfig::default()
        };
        assert!(validate_tun_config(&valid).is_ok());
    }

    #[test]
    fn validation_rejects_invalid_names_and_mtu() {
        let bad_name = TunConfig { name: Some("tun\0hidden".to_string()), ..TunConfig::default() };
        assert!(matches!(validate_tun_config(&bad_name), Err(TunError::Io(_))));

        let low_mtu = TunConfig { mtu: TUN_MIN_MTU - 1, ..TunConfig::default() };
        assert!(matches!(validate_tun_config(&low_mtu), Err(TunError::Config(_))));
    }
}
