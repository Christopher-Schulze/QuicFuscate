//! Cross-platform abstraction layer for VPN client.
//!
//! This module provides platform-agnostic interfaces for:
//! - TUN device management
//! - DNS configuration
//! - Route management
//! - Privilege elevation

mod traits;

#[cfg(any(test, target_os = "linux"))]
mod dns_restore;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

pub use traits::*;

#[cfg(target_os = "linux")]
pub use linux::{LinuxPlatform, LinuxPlatform as NativePlatform, LinuxResolverPaths};
#[cfg(target_os = "macos")]
pub use macos::MacOSPlatform as NativePlatform;
#[cfg(target_os = "windows")]
pub use windows::WindowsPlatform as NativePlatform;

/// Get the native platform backend.
pub fn native() -> NativePlatform {
    NativePlatform::new()
}

/// Detect current platform.
pub fn current_platform() -> Platform {
    #[cfg(target_os = "linux")]
    return Platform::Linux;
    #[cfg(target_os = "macos")]
    return Platform::MacOS;
    #[cfg(target_os = "windows")]
    return Platform::Windows;
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    return Platform::Unsupported;
}

/// Supported platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOS,
    Windows,
    Unsupported,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Linux => write!(f, "Linux"),
            Platform::MacOS => write!(f, "macOS"),
            Platform::Windows => write!(f, "Windows"),
            Platform::Unsupported => write!(f, "Unsupported"),
        }
    }
}
