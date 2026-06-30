//! Cross-platform TUN interface (library)
//!
//! This module provides a minimal, high-performance TUN abstraction that
//! integrates with QuicFuscate's optimization primitives (aligned memory pool)
//! and telemetry. It focuses on efficient, low-overhead I/O while keeping a
//! small, portable surface area. CLI wiring is intentionally out-of-scope so
//! this module can be used by clients/servers or higher-level runners.
//!
//! Platforms:
//! - Linux & Android: `/dev/net/tun` (fallback to `/dev/tun`) via `TUNSETIFF` (IFF_TUN | IFF_NO_PI)
//! - macOS: `utun` via PF_SYSTEM/SYSPROTO_CONTROL with 4-byte AF header
//! - Windows: provide via `register_tun_factory` (Wintun recommended; optional feature `tun-windows`)
//! - iOS: provide via `register_tun_factory` (NetworkExtension/NEPacketTunnelProvider)
//! - Other Unix: currently unsupported; external factory can be registered
//!
//! Design choices:
//! - Zero-copy friendly: expose a `TunInterface` that reads directly into
//!   memory-pool blocks and emits slices without extra allocations.
//! - No background runtime dependency: synchronous API with helper loop; users
//!   may drive it from threads or async runtimes as needed.

use crate::optimize::MemoryPool;
use crate::telemetry::TELEMETRY_ENABLED;
use aligned_box::AlignedBox;
use std::io::{self};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

/// Application configuration module
pub mod app_config {
    use crate::engine::{EngineConfig, StealthMode as EngineStealthMode};
    use crate::fec::FecConfig;
    use crate::optimize::OptimizeConfig;
    use crate::stealth::{BrowserProfile, OsProfile, PaddingStrategy, StealthConfig};

    /// Unified configuration structure parsed from a TOML file.
    #[derive(Clone)]
    pub struct AppConfig {
        /// Forward error correction settings.
        pub fec: FecConfig,
        /// Stealth and obfuscation settings.
        pub stealth: StealthConfig,
        /// Memory pool and optimization settings.
        pub optimize: OptimizeConfig,
        /// 0-RTT anti-replay protection settings.
        pub anti_replay: crate::engine::AntiReplaySection,
    }

    impl AppConfig {
        fn parse_padding_strategy(raw: &str) -> Option<PaddingStrategy> {
            match raw.trim().to_ascii_lowercase().as_str() {
                "random" | "1" => Some(PaddingStrategy::Random),
                "fixed" | "constant" | "2" => Some(PaddingStrategy::Fixed),
                "adaptive" | "3" => Some(PaddingStrategy::Adaptive),
                "browser" | "browser_mimic" | "browser-mimic" | "browsermimic" | "mimic" | "4" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                _ => None,
            }
        }

        fn from_engine_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let parsed = EngineConfig::from_toml(s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

            let fec = FecConfig::from_engine_section(&parsed.fec);

            let mut stealth = match parsed.stealth.mode {
                EngineStealthMode::Off => StealthConfig::off(),
                EngineStealthMode::Performance => StealthConfig::performance(),
                EngineStealthMode::Stealth => StealthConfig::stealth(),
                EngineStealthMode::AntiDpi => StealthConfig::anti_dpi(),
                EngineStealthMode::Manual => StealthConfig::manual(),
                EngineStealthMode::Auto => StealthConfig::intelligent(),
            };
            stealth.enable_domain_fronting = parsed.stealth.enable_domain_fronting;
            stealth.enable_http3_masquerading = parsed.stealth.enable_http3_masquerading;
            stealth.use_tls_cover = parsed.stealth.use_tls_cover;
            stealth.use_qpack_headers = parsed.stealth.use_qpack_headers;
            stealth.enable_traffic_padding = parsed.stealth.enable_traffic_padding;
            stealth.enable_timing_obfuscation = parsed.stealth.enable_timing_obfuscation;
            stealth.enable_protocol_mimicry = parsed.stealth.enable_protocol_mimicry;
            stealth.enable_doh = parsed.stealth.enable_doh;
            stealth.doh_provider = parsed.stealth.doh_provider.clone();
            stealth.max_padding_size = parsed.stealth.max_padding_size;
            if let Some(p) = Self::parse_padding_strategy(&parsed.stealth.padding_strategy) {
                stealth.padding_strategy = p;
            }
            stealth.fronting_domains = parsed.stealth.fronting_domains.clone();
            if let Ok(p) = parsed.stealth.initial_browser.parse::<BrowserProfile>() {
                stealth.initial_browser = p;
            }
            if let Ok(p) = parsed.stealth.initial_os.parse::<OsProfile>() {
                stealth.initial_os = p;
            }
            stealth.enable_fingerprint_rotation = parsed.fingerprint_rotation.enabled;
            stealth.fingerprint_rotation_interval = parsed.fingerprint_rotation.interval_secs;
            stealth.fingerprint_rotation_mode = match parsed.fingerprint_rotation.mode {
                crate::engine::RotationMode::Fixed => crate::stealth::RotationMode::Fixed,
                crate::engine::RotationMode::Slots => crate::stealth::RotationMode::Slots,
                crate::engine::RotationMode::All => crate::stealth::RotationMode::All,
            };

            let default_block_size = 65_536usize;
            let pool_capacity = (parsed.optimization.memory_pool_size / default_block_size).max(1);
            let optimize = OptimizeConfig { pool_capacity, block_size: default_block_size };

            Ok(Self { fec, stealth, optimize, anti_replay: parsed.anti_replay })
        }

        /// Load configuration from a TOML string.
        pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
            Self::from_engine_toml(s)
        }

        /// Load configuration from a file path.
        pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
            let contents = std::fs::read_to_string(path)?;
            Self::from_toml(&contents)
        }

        /// Validate all sub-configurations.
        pub fn validate(&self) -> Result<(), String> {
            self.fec.validate()?;
            self.stealth.validate()?;
            self.optimize.validate()?;
            Ok(())
        }
    }
}

/// Errors produced by the TUN layer.
#[derive(Debug)]
pub enum TunError {
    /// TUN is not supported on the current platform.
    Unsupported,
    /// Operating system I/O error.
    Io(io::Error),
    /// Configuration or prerequisite error (e.g., missing factory, MTU too low).
    Config(&'static str),
}

impl From<io::Error> for TunError {
    fn from(e: io::Error) -> Self {
        TunError::Io(e)
    }
}

/// Configuration for creating a TUN device.
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Requested TUN device name (None for OS-assigned).
    pub name: Option<String>,
    /// Static IP address to assign to the TUN interface.
    pub ip: Option<IpAddr>,
    /// Netmask for the TUN interface IP.
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

/// Runtime capability view for TUN integration.
#[derive(Clone, Copy, Debug)]
pub struct TunCapabilities {
    /// Built-in native implementation exists for current target.
    pub built_in: bool,
    /// External factory has been registered for platform-managed TUN backends.
    pub external_factory_registered: bool,
    /// Zero-copy can be used on the current platform/runtime path.
    pub supports_zero_copy: bool,
    /// Raw file descriptor exposure is available.
    pub supports_raw_fd: bool,
}

/// Shared runtime fastpath selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastpathMode {
    /// Disable fastpath optimization, use direct syscalls.
    Off,
    /// Automatically use best available fastpath (sendmmsg on Linux).
    Auto,
}

impl FastpathMode {
    /// Parse a fastpath mode from a string ("off" or "auto").
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            _ => Self::Auto,
        }
    }

    /// Read fastpath mode from the QUICFUSCATE_FASTPATH environment variable.
    pub fn from_env() -> Self {
        let raw = std::env::var("QUICFUSCATE_FASTPATH").unwrap_or_else(|_| "auto".to_string());
        let mode = Self::parse(&raw);
        if mode == Self::Auto && !raw.trim().eq_ignore_ascii_case("auto") {
            log::warn!(
                "Unsupported QUICFUSCATE_FASTPATH='{}'; using canonical fastpath policy 'auto'",
                raw
            );
        }
        mode
    }
}

/// Return current TUN capability profile for control-plane and diagnostics.
pub fn tun_capabilities() -> TunCapabilities {
    TunCapabilities {
        built_in: cfg!(target_os = "linux")
            || cfg!(target_os = "android")
            || cfg!(target_os = "macos")
            || (cfg!(target_os = "windows") && cfg!(feature = "tun-windows")),
        external_factory_registered: TUN_FACTORY.get().is_some(),
        supports_zero_copy: cfg!(target_os = "linux")
            || cfg!(target_os = "android")
            || cfg!(target_os = "macos"),
        supports_raw_fd: cfg!(unix),
    }
}

/// Validate whether TUN runtime requirements are currently satisfied.
pub fn validate_tun_runtime_requirements() -> Result<(), TunError> {
    let caps = tun_capabilities();
    if !caps.built_in && !caps.external_factory_registered {
        crate::optimize::telemetry::TUN_REQUIREMENT_REJECTS.fetch_add(1, Ordering::Relaxed);
        return Err(TunError::Config(
            "No built-in TUN backend and no external factory registered (built_in=false,factory=false)",
        ));
    }
    Ok(())
}

/// Basic TUN device contract.
pub trait TunDevice: Send + Sync {
    /// Returns the OS-level device name (e.g., "utun3", "quicfuse0").
    fn name(&self) -> &str;
    /// Returns the configured MTU for this device.
    fn mtu(&self) -> u16;
    /// Reads one IP packet into `buf`, returning the number of bytes read.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes one IP packet from `buf`, returning the number of bytes written.
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Returns the raw file descriptor for io_uring or epoll integration (Unix only).
    #[cfg(unix)]
    fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }
}

/// A high-performance wrapper integrating a TUN device with QuicFuscate's
/// aligned memory pool for minimal-copy I/O.
pub struct TunInterface {
    dev: Box<dyn TunDevice>,
    pool: Arc<MemoryPool>,
    #[cfg(target_os = "linux")]
    zero_copy: bool,
}

impl std::fmt::Debug for TunInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("TunInterface");
        dbg.field("name", &self.dev.name()).field("mtu", &self.dev.mtu());
        #[cfg(target_os = "linux")]
        {
            dbg.field("zero_copy", &self.zero_copy);
        }
        dbg.finish()
    }
}

impl TunInterface {
    /// Open a TUN interface using the given config and memory pool.
    pub fn open(config: TunConfig, pool: Arc<MemoryPool>) -> Result<Self, TunError> {
        if config.mtu < 576 {
            crate::optimize::telemetry::TUN_CONFIG_REJECTS.fetch_add(1, Ordering::Relaxed);
            return Err(TunError::Config("TUN MTU must be >= 576"));
        }

        // Deterministic behavior on factory-required targets.
        // Windows has a built-in Wintun backend when `tun-windows` is enabled;
        // iOS always requires an external NetworkExtension factory.
        let needs_factory = cfg!(target_os = "ios")
            || (cfg!(target_os = "windows") && !cfg!(feature = "tun-windows"));
        if needs_factory && TUN_FACTORY.get().is_none() {
            crate::optimize::telemetry::TUN_REQUIREMENT_REJECTS.fetch_add(1, Ordering::Relaxed);
            return Err(TunError::Config(
                "TUN factory required on this platform; call register_tun_factory first",
            ));
        }

        // Allow external factory override (e.g., iOS NetworkExtension, Windows Wintun)
        if let Some(f) = TUN_FACTORY.get() {
            let dev = match f(&config) {
                Ok(dev) => dev,
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    crate::optimize::telemetry::TUN_PERMISSION_REJECTS
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(TunError::Config(
                        "Insufficient privileges for external TUN factory",
                    ));
                }
                Err(e) => return Err(TunError::Io(e)),
            };
            return Ok(Self {
                dev,
                pool,
                #[cfg(target_os = "linux")]
                zero_copy: config.zero_copy,
            });
        }
        let dev = match open_platform_tun(&config) {
            Ok(dev) => dev,
            Err(TunError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied => {
                crate::optimize::telemetry::TUN_PERMISSION_REJECTS.fetch_add(1, Ordering::Relaxed);
                return Err(TunError::Config("Insufficient privileges to open TUN interface"));
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            dev,
            pool,
            #[cfg(target_os = "linux")]
            zero_copy: config.zero_copy,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_device_for_test(
        dev: Box<dyn TunDevice>,
        pool: Arc<MemoryPool>,
        zero_copy: bool,
    ) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = zero_copy;
        Self {
            dev,
            pool,
            #[cfg(target_os = "linux")]
            zero_copy,
        }
    }

    /// Returns the interface name.
    pub fn name(&self) -> &str {
        self.dev.name()
    }

    /// Reads one packet into a pooled block and returns (block, len).
    /// The block remains zero-initialized outside the valid frame region.
    pub fn read_block(&self) -> io::Result<(AlignedBox<[u8]>, usize)> {
        let mut block = self.pool.alloc();
        let len = self.dev.read(&mut block[..])?;
        if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
            crate::telemetry::BYTES_RECEIVED.inc_by(len as u64);
        }
        Ok((block, len))
    }

    /// Write a packet to the TUN device with hardware acceleration
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Parse IP header with BMI2 on supported x86 profiles, otherwise scalar.
        #[cfg(target_arch = "x86_64")]
        {
            let profile = crate::optimize::FeatureDetector::instance().profile();
            match profile {
                crate::optimize::CpuProfile::X86_P2b
                | crate::optimize::CpuProfile::X86_P3a
                | crate::optimize::CpuProfile::X86_P3b
                | crate::optimize::CpuProfile::X86_P3c
                | crate::optimize::CpuProfile::X86_P3d
                | crate::optimize::CpuProfile::X86_P3e
                | crate::optimize::CpuProfile::X86_P4a
                | crate::optimize::CpuProfile::X86_P4b => unsafe {
                    self.parse_ip_header_bmi2(buf);
                },
                _ => self.parse_ip_header_scalar(buf),
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        self.parse_ip_header_scalar(buf);

        self.dev.write(buf)
    }

    /// Parse IP header with BMI2 PEXT/PDEP - 2x faster
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    unsafe fn parse_ip_header_bmi2(&self, packet: &[u8]) {
        use std::arch::x86_64::*;

        if packet.len() < 20 {
            return;
        }

        // Extract fields with BMI2
        let header = *(packet.as_ptr() as *const u32);

        // Extract version and header length with PEXT
        let ver_ihl = _pext_u32(header, 0xFF);
        let version = (ver_ihl >> 4) & 0xF;
        let ihl = ver_ihl & 0xF;

        // Extract other fields efficiently
        let tos = _pext_u32(header >> 8, 0xFF);
        let total_len = _pext_u32(header >> 16, 0xFFFF);

        // Process extracted fields
        self.process_ip_info(version as u8, ihl as u8, tos as u8, total_len as u16);
    }

    #[inline(always)]
    fn parse_ip_header_scalar(&self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }

        let ver_ihl = buf[0];
        let version = ver_ihl >> 4;
        if version == 4 {
            let ihl = ver_ihl & 0x0F;
            let tos = if buf.len() > 1 { buf[1] } else { 0 };
            let total_len = if buf.len() > 4 { u16::from_be_bytes([buf[2], buf[3]]) } else { 0 };
            self.process_ip_info(version, ihl, tos, total_len);
        } else if version == 6 && buf.len() >= 2 {
            // tc = (b0 low 4 bits << 4) | (b1 high 4 bits)
            let tc = ((buf[0] & 0x0F) << 4) | ((buf[1] & 0xF0) >> 4);
            use std::sync::atomic::Ordering;
            crate::optimize::telemetry::IP_V6_PACKETS.fetch_add(1, Ordering::Relaxed);
            if (tc & 0b11) == 0b11 {
                crate::optimize::telemetry::STEALTH_SIGNAL_ECN_CE.fetch_add(1, Ordering::Relaxed);
            }
            let dscp = tc >> 2;
            if dscp >= 0x30 {
                crate::optimize::telemetry::STEALTH_SIGNAL_TOS_ANOM.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn process_ip_info(&self, version: u8, ihl: u8, tos: u8, total_len: u16) {
        let _ = ihl;
        let _ = total_len;
        use std::sync::atomic::Ordering;
        // Telemetry: count IPv4/IPv6 packets and sample TOS
        if version == 4 {
            crate::optimize::telemetry::IP_V4_PACKETS.fetch_add(1, Ordering::Relaxed);
            crate::optimize::telemetry::IP_TOS_SUM.fetch_add(tos as u64, Ordering::Relaxed);
            crate::optimize::telemetry::IP_TOS_SAMPLES.fetch_add(1, Ordering::Relaxed);
            // If ECN bits indicate Congestion Experienced (CE=0b11), record a stealth signal
            if (tos & 0b11) == 0b11 {
                crate::optimize::telemetry::STEALTH_SIGNAL_ECN_CE.fetch_add(1, Ordering::Relaxed);
            }
        } else if version == 6 {
            crate::optimize::telemetry::IP_V6_PACKETS.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Writes a single packet from a provided slice.
    pub fn write(&self, packet: &[u8]) -> io::Result<usize> {
        let n = self.dev.write(packet)?;
        if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
            crate::telemetry::BYTES_SENT.inc_by(n as u64);
        }
        Ok(n)
    }

    /// Convenience loop: repeatedly reads from TUN and invokes callback with a
    /// borrowed slice into a pooled block. The callback may copy or process in
    /// place; the block is returned to the pool once the callback returns.
    pub fn reader_loop<F>(&self, mut on_packet: F) -> io::Result<()>
    where
        F: FnMut(&[u8]),
    {
        loop {
            let (block, len) = self.read_block()?;
            if len > 0 {
                on_packet(&block[..len]);
            }
            // Return the block to the pool by dropping it.
            self.pool.free(block);
        }
    }
}

// Platform-specific implementations

// Optional global factory to inject platform TUN devices (iOS/Windows or custom).
/// Factory type alias to simplify signatures and avoid clippy::type_complexity.
pub type TunFactory =
    Box<dyn Fn(&TunConfig) -> io::Result<Box<dyn TunDevice>> + Send + Sync + 'static>;

static TUN_FACTORY: OnceLock<TunFactory> = OnceLock::new();

/// Registers a global TUN factory. Useful on platforms that require
/// OS-specific frameworks (e.g., iOS NetworkExtension, Windows Wintun).
/// Returns false if a factory was already set.
///
/// Example (Windows/iOS):
/// ```ignore
/// use quicfuscate::interface::{register_tun_factory, TunConfig, TunDevice};
/// use std::io;
/// struct MyTun;
/// impl TunDevice for MyTun {
///     fn name(&self) -> &str { "wintun0" }
///     fn mtu(&self) -> u16 { 1500 }
///     fn read(&self, _buf: &mut [u8]) -> io::Result<usize> { Ok(0) }
///     fn write(&self, _buf: &[u8]) -> io::Result<usize> { Ok(0) }
/// }
/// let _ = register_tun_factory(Box::new(|_cfg: &TunConfig| -> io::Result<Box<dyn TunDevice>> {
///     Ok(Box::new(MyTun))
/// }));
/// ```
pub fn register_tun_factory(factory: TunFactory) -> bool {
    TUN_FACTORY.set(factory).is_ok()
}

#[cfg(target_os = "linux")]
mod linux_tun {
    use super::*;
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::mem;
    use std::os::fd::{AsRawFd, IntoRawFd, RawFd};

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; 16],
        ifr_flags: libc::c_short,
    }

    /// Linux TUN device using /dev/net/tun (IFF_TUN | IFF_NO_PI).
    pub struct LinuxTun {
        name: Arc<str>,
        fd: RawFd,
        mtu: u16,
    }

    impl LinuxTun {
        /// Open a Linux TUN device with the given configuration.
        pub fn open(cfg: &TunConfig) -> io::Result<Self> {
            // Try canonical path first, fallback to /dev/tun (Android)
            let file = match OpenOptions::new().read(true).write(true).open("/dev/net/tun") {
                Ok(f) => f,
                Err(_) => OpenOptions::new().read(true).write(true).open("/dev/tun")?,
            };

            let mut ifr: IfReq = unsafe { mem::zeroed() };
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            if let Some(ref n) = cfg.name {
                let c = CString::new(n.as_str())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let bytes = c.as_bytes_with_nul();
                let len = bytes.len().min(ifr.ifr_name.len());
                for i in 0..len {
                    ifr.ifr_name[i] = bytes[i] as libc::c_char;
                }
            }
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            // Determine actual device name
            let mut name = String::new();
            for &c in &ifr.ifr_name {
                if c == 0 {
                    break;
                }
                name.push(c as u8 as char);
            }

            // Take ownership of the fd to avoid per-call File reconstruction
            let fd = file.into_raw_fd();
            let name: Arc<str> = Arc::from(name);
            Ok(Self { name, fd, mtu: cfg.mtu })
        }
    }

    impl TunDevice for LinuxTun {
        fn name(&self) -> &str {
            self.name.as_ref()
        }
        fn mtu(&self) -> u16 {
            self.mtu
        }
        #[cfg(unix)]
        fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
            Some(self.fd)
        }
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // Blocking read into the user-provided buffer using libc::read with EINTR retry
            loop {
                let n = unsafe {
                    libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                return Ok(n as usize);
            }
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            // Write the full packet using libc::write with EINTR retry
            let mut off = 0usize;
            while off < buf.len() {
                let n = unsafe {
                    libc::write(
                        self.fd,
                        buf[off..].as_ptr() as *const libc::c_void,
                        buf.len() - off,
                    )
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                off += n as usize;
            }
            Ok(off)
        }
    }

    impl Drop for LinuxTun {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Open the platform-native Linux TUN device.
    pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(LinuxTun::open(cfg)?))
    }
}

#[cfg(target_os = "macos")]
mod macos_tun {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;

    // PF_SYSTEM/SYSPROTO_CONTROL utun open
    const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
    const AF_SYS_CONTROL: u16 = 2; // AF_SYSTEM subtype
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [u8; 96],
    }
    #[repr(C)]
    struct SockAddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    /// macOS utun device via PF_SYSTEM/SYSPROTO_CONTROL.
    pub struct MacTun {
        fd: RawFd,
        name: Arc<str>,
        mtu: u16,
    }

    impl MacTun {
        /// Open a macOS utun device with the given configuration.
        pub fn open(cfg: &TunConfig) -> io::Result<Self> {
            let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut info: CtlInfo = unsafe { mem::zeroed() };
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
            let rc = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            let mut addr: SockAddrCtl = unsafe { mem::zeroed() };
            addr.sc_len = mem::size_of::<SockAddrCtl>() as u8;
            addr.sc_family = libc::AF_SYSTEM as u8;
            addr.ss_sysaddr = AF_SYS_CONTROL;
            addr.sc_id = info.ctl_id;
            addr.sc_unit = 0; // next available utunX
            let rc = unsafe {
                libc::connect(
                    fd,
                    (&addr as *const SockAddrCtl) as *const libc::sockaddr,
                    mem::size_of::<SockAddrCtl>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            // Query interface name
            let mut ifname = [0u8; 64];
            let mut len = ifname.len() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    ifname.as_mut_ptr() as *mut libc::c_void,
                    &mut len,
                )
            };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }
            if len == 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::other("ifname empty"));
            }
            let name_s = String::from_utf8_lossy(&ifname[..(len as usize - 1)]).to_string();
            let name: Arc<str> = Arc::from(name_s);
            Ok(Self { fd, name, mtu: cfg.mtu })
        }
    }

    impl TunDevice for MacTun {
        fn name(&self) -> &str {
            self.name.as_ref()
        }
        fn mtu(&self) -> u16 {
            self.mtu
        }
        #[cfg(unix)]
        fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
            Some(self.fd)
        }
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // utun prepends 4-byte AF header; use readv to avoid extra allocation/copy
            let mut hdr = [0u8; 4];
            let mut iov = [
                libc::iovec { iov_base: hdr.as_mut_ptr() as *mut libc::c_void, iov_len: hdr.len() },
                libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() },
            ];
            loop {
                let n = unsafe { libc::readv(self.fd, iov.as_mut_ptr(), iov.len() as i32) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                if n <= 4 {
                    return Ok(0);
                }
                return Ok((n as usize) - 4);
            }
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            // Prepend AF header based on version (IPv6 0x60 high nibble == 6) using writev
            let af: u32 = if !buf.is_empty() && (buf[0] >> 4) == 6 {
                libc::AF_INET6 as u32
            } else {
                libc::AF_INET as u32
            };
            let mut hdr = af.to_be_bytes();
            let mut iov = [
                libc::iovec { iov_base: hdr.as_mut_ptr() as *mut libc::c_void, iov_len: hdr.len() },
                libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() },
            ];
            let total = 4 + buf.len();
            let mut written = 0isize;
            while (written as usize) < total {
                let n = unsafe { libc::writev(self.fd, iov.as_ptr(), iov.len() as i32) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                written += n;
                // After first successful writev, if partial, adjust iovecs
                if (written as usize) < total {
                    // Compute how much consumed from hdr/payload
                    let mut remain = written as usize;
                    // Consume hdr first
                    if remain >= 4 {
                        iov[0].iov_len = 0;
                        remain -= 4;
                        iov[1].iov_base =
                            unsafe { (buf.as_ptr().add(remain)) as *mut libc::c_void };
                        iov[1].iov_len = buf.len() - remain;
                    } else {
                        // Still within header
                        iov[0].iov_base =
                            unsafe { hdr.as_mut_ptr().add(remain) as *mut libc::c_void };
                        iov[0].iov_len = 4 - remain;
                    }
                }
            }
            Ok(buf.len())
        }
    }

    impl Drop for MacTun {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Open the platform-native macOS utun device.
    pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(MacTun::open(cfg)?))
    }
}

#[cfg(target_os = "ios")]
mod ios_tun {
    use super::*;
    /// iOS stub - requires external factory via NetworkExtension.
    pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        // iOS requires NetworkExtension. Applications must register a factory
        // that returns a TunDevice backed by NEPacketTunnel flow.
        Err(TunError::Config(
            "iOS requires NetworkExtension; use register_tun_factory to supply TunDevice",
        ))
    }
}

/// Wintun-backed Windows TUN device (dynamic `wintun.dll` loading).
/// On non-Windows targets this compiles to a stub returning
/// `TunError::Unsupported`. See [`wintun::WintunDevice`] for details.
pub mod wintun;

#[cfg(target_os = "windows")]
mod windows_tun {
    use super::wintun::WintunDevice;
    use super::*;

    /// Windows TUN via Wintun. Requires the `tun-windows` feature and a
    /// `wintun.dll` present beside the executable (or on the system search
    /// path). Falls back to a clear Config error if Wintun is unavailable, so
    /// callers can still register an external factory via
    /// [`register_tun_factory`].
    #[cfg(feature = "tun-windows")]
    pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        match WintunDevice::new(cfg) {
            Ok(dev) => Ok(Box::new(dev)),
            // DLL missing / incompatible: keep the existing fallback path so a
            // caller-registered factory can still take over.
            Err(TunError::Config(msg)) if msg.contains("wintun.dll") => {
                Err(TunError::Config(
                    "Windows TUN requires Wintun; wintun.dll not found - use register_tun_factory or install wintun.dll",
                ))
            }
            Err(e) => Err(e),
        }
    }

    /// Windows stub - tun-windows feature not enabled.
    #[cfg(not(feature = "tun-windows"))]
    pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Err(TunError::Config(
            "Windows TUN not built-in; enable 'tun-windows' or use register_tun_factory",
        ))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "ios"
)))]
mod other_tun {
    use super::*;
    struct UnsupportedTun;
    impl TunDevice for UnsupportedTun {
        fn name(&self) -> &str {
            "unsupported"
        }
        fn mtu(&self) -> u16 {
            0
        }
        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "TUN unsupported on this platform"))
        }
        fn write(&self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Other, "TUN unsupported on this platform"))
        }
    }
    /// Unsupported platform stub - always returns `TunError::Unsupported`.
    pub fn open_platform_tun(_cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Err(TunError::Unsupported)
    }
}

#[cfg(target_os = "ios")]
use ios_tun::open_platform_tun;
#[cfg(target_os = "linux")]
use linux_tun::open_platform_tun;
#[cfg(target_os = "macos")]
use macos_tun::open_platform_tun;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "ios"
)))]
use other_tun::open_platform_tun;
#[cfg(target_os = "windows")]
use windows_tun::open_platform_tun;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct DummyTun {
        reads: Mutex<Vec<Vec<u8>>>,
        writes: AtomicUsize,
        last_write_len: AtomicUsize,
    }

    impl DummyTun {
        fn with_reads(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: Mutex::new(reads),
                writes: AtomicUsize::new(0),
                last_write_len: AtomicUsize::new(0),
            }
        }
    }

    impl TunDevice for DummyTun {
        fn name(&self) -> &str {
            "dummy"
        }

        fn mtu(&self) -> u16 {
            1500
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut reads = self.reads.lock().expect("dummy read lock poisoned");
            if reads.is_empty() {
                return Ok(0);
            }
            let data = reads.remove(0);
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.last_write_len.store(buf.len(), Ordering::Relaxed);
            Ok(buf.len())
        }
    }

    #[test]
    fn read_block_returns_packet_payload() {
        let pool = crate::optimize::global_pool();
        let packet = vec![0x45, 0x00, 0x00, 0x20, 0xaa, 0xbb];
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(vec![packet.clone()])),
            pool,
            false,
        );

        let (block, len) = tun.read_block().expect("read_block must succeed");
        assert_eq!(len, packet.len());
        assert_eq!(&block[..len], packet.as_slice());
    }

    #[test]
    fn write_packet_direct_fallback_returns_device_length() {
        let pool = crate::optimize::global_pool();
        let tun_dev = DummyTun::with_reads(Vec::new());
        let expected_len = 64usize;
        let mut tun = TunInterface::from_device_for_test(Box::new(tun_dev), pool, false);
        let payload = vec![0u8; expected_len];
        let written = tun.write_packet(&payload).expect("write_packet must succeed");
        assert_eq!(written, expected_len);
    }

    #[test]
    fn fastpath_mode_space_is_off_auto_only() {
        assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
        assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
        assert_eq!(FastpathMode::parse("legacy-token"), FastpathMode::Auto);
    }
}
