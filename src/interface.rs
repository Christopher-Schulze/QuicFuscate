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

use crate::optimize::{MemoryPool, PooledBlock};
#[cfg(target_arch = "x86_64")]
use crate::simd::{CpuFeatures, CpuProfile};
use crate::telemetry::TELEMETRY_ENABLED;
pub(crate) use qf_transport_types::validate_tun_config;
pub use qf_transport_types::{
    FastpathMode, TunCapabilities, TunConfig, TunDevice, TunError, TunFactory, TunReadContract,
    TUN_IPV6_MIN_MTU, TUN_MIN_MTU, TUN_PACKET_QUEUE_CAPACITY,
};
use std::io::{self};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};

#[cfg(unix)]
fn close_owned_fd_with<F>(fd: &mut std::os::fd::RawFd, close: F) -> io::Result<()>
where
    F: FnOnce(std::os::fd::RawFd) -> io::Result<()>,
{
    if *fd == -1 {
        return Ok(());
    }
    if *fd < -1 {
        *fd = -1;
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    let owned_fd = *fd;
    // POSIX leaves the descriptor state unspecified after a close error such
    // as EINTR. Never retry the number because it may already be reused.
    *fd = -1;
    close(owned_fd)
}

/// Close a descriptor while making the terminal ownership transition explicit.
/// A close error is returned, but the descriptor number is not retained for a
/// retry because POSIX may have released it before reporting the error.
#[cfg(unix)]
pub(crate) fn close_owned_fd(fd: &mut std::os::fd::RawFd) -> io::Result<()> {
    close_owned_fd_with(fd, |owned_fd| {
        let result = unsafe { libc::close(owned_fd) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })
}

#[cfg(unix)]
pub(crate) fn validate_raw_read_result(
    result: libc::ssize_t,
    capacity: usize,
    operation: &str,
) -> io::Result<usize> {
    if result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{operation} returned a negative result after errno handling"),
        ));
    }
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("{operation} returned zero bytes"),
        ));
    }
    let result = usize::try_from(result).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{operation} result overflowed usize"))
    })?;
    if result > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{operation} returned {result} bytes for a {capacity}-byte destination"),
        ));
    }
    Ok(result)
}

#[cfg(unix)]
pub(crate) fn validate_raw_write_progress(
    result: libc::ssize_t,
    remaining: usize,
    operation: &str,
) -> io::Result<usize> {
    if result < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{operation} returned a negative result after errno handling"),
        ));
    }
    if result == 0 {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("{operation} made no progress while {remaining} bytes remained"),
        ));
    }
    let result = usize::try_from(result).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("{operation} result overflowed usize"))
    })?;
    if result > remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{operation} reported {result} bytes for {remaining} remaining bytes"),
        ));
    }
    Ok(result)
}

#[cfg(unix)]
pub(crate) fn parse_bounded_interface_name(
    bytes: &[u8],
    reported_len: usize,
) -> io::Result<String> {
    if reported_len == 0 || reported_len > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "kernel interface name length {reported_len} exceeds {}-byte buffer",
                bytes.len()
            ),
        ));
    }
    let bounded = &bytes[..reported_len];
    if bounded.last() != Some(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel interface name is not NUL-terminated within the reported length",
        ));
    }
    let name_bytes = &bounded[..reported_len - 1];
    if name_bytes.is_empty() || name_bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel interface name is empty or contains an interior NUL",
        ));
    }
    String::from_utf8(name_bytes.to_vec()).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("kernel interface name is not valid UTF-8: {error}"),
        )
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn kernel_interface_name_bytes(ifr_name: &[libc::c_char]) -> Vec<u8> {
    let raw: Vec<u8> = ifr_name.iter().map(|byte| byte.to_ne_bytes()[0]).collect();
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    raw[..end].to_vec()
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_kernel_interface_name(ifr_name: &[libc::c_char]) -> io::Result<String> {
    let raw: Vec<u8> = ifr_name.iter().map(|byte| byte.to_ne_bytes()[0]).collect();
    let terminator = raw.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel interface name has no NUL terminator in the fixed buffer",
        )
    })?;
    parse_bounded_interface_name(&raw, terminator + 1)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_linux_interface_name(name: &str) -> io::Result<()> {
    if name.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux TUN interface name must not be empty",
        ));
    }
    if name.len() > 15 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Linux TUN interface name is {} bytes; maximum is 15", name.len()),
        ));
    }
    if name.contains('/') || name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Linux TUN interface name contains a forbidden character",
        ));
    }
    Ok(())
}

/// Permit the BMI2 parser only when both the automatic/override profile is an
/// x86 profile and the exact runtime BMI2 feature is present. Higher x86
/// profiles do not imply BMI2, so the feature bit remains a separate gate.
#[cfg(target_arch = "x86_64")]
#[inline]
fn bmi2_parser_is_allowed(profile: CpuProfile, features: &CpuFeatures) -> bool {
    matches!(
        profile,
        CpuProfile::X86_P0a
            | CpuProfile::X86_P0b
            | CpuProfile::X86_P1a
            | CpuProfile::X86_P1b
            | CpuProfile::X86_P1f
            | CpuProfile::X86_P2a
            | CpuProfile::X86_P2b
            | CpuProfile::X86_P3a
            | CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b
    ) && features.bmi2
}

/// An owned TUN frame backed by a pooled memory block.
///
/// The frame can cross the blocking-reader to async-runtime boundary without
/// copying into a newly allocated `Vec`. Dropping it returns the block to the
/// originating pool.
pub struct TunPacket {
    block: PooledBlock,
    len: usize,
}

fn validate_tun_read_len(len: usize, capacity: usize) -> io::Result<usize> {
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "TUN backend returned zero bytes for a packet read",
        ));
    }
    if len > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TUN backend returned {len} bytes for a {capacity}-byte read buffer"),
        ));
    }
    Ok(len)
}

fn validate_tun_write_len(written: usize, expected: usize) -> io::Result<usize> {
    if written > expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("TUN backend reported {written} written bytes for a {expected}-byte packet"),
        ));
    }
    if written != expected {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "TUN backend completed {written} of {expected} bytes; complete packet writes are required"
            ),
        ));
    }
    Ok(written)
}

impl TunPacket {
    fn new(block: PooledBlock, len: usize) -> io::Result<Self> {
        let len = validate_tun_read_len(len, block.len())?;
        Ok(Self { block, len })
    }

    /// Return the valid layer-3 frame bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.block[..self.len]
    }

    /// Return the valid frame length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether the frame contains no valid bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Application configuration module
pub mod app_config {
    use crate::engine::EngineConfig;
    use crate::fec::FecConfig;
    use crate::optimize::OptimizeConfig;
    use crate::stealth::StealthConfig;

    /// Runtime projection for FEC, stealth, optimization, and anti-replay.
    ///
    /// `EngineConfig::validate` must succeed before this reduced projection is
    /// constructed. Transport policies and startup-owned engine sections remain
    /// in the source `EngineConfig` and are consumed by their dedicated adapters.
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
        fn from_engine_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let parsed = EngineConfig::from_toml(s)?;
            parsed.validate()?;
            let fec = parsed.fec.to_runtime_config()?;
            let stealth = parsed.stealth.to_runtime_config(&parsed.fingerprint_rotation)?;
            let optimize = parsed.optimization.to_runtime_config()?;

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
            self.anti_replay.validate().map_err(|error| error.to_string())?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn app_config_rejects_unknown_engine_keys_before_projection() {
            let error = match AppConfig::from_toml(
                r#"
[connection]
remote = "127.0.0.1:4433"

[stealth]
unknown_setting = true
"#,
            ) {
                Ok(_) => panic!("unknown engine settings must not be silently dropped"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("unknown_setting"));
        }

        #[test]
        fn app_config_preserves_typed_engine_projection() {
            let config = AppConfig::from_toml(
                r#"
[connection]
remote = "127.0.0.1:4433"

[stealth]
initial_browser = "firefox"
initial_os = "linux"
padding_strategy = "browser-mimic"

[optimization]
memory_pool_size = 1048576
memory_pool_alignment = 4096
"#,
            )
            .expect("valid engine projection");
            assert_eq!(config.stealth.initial_browser, crate::stealth::BrowserProfile::Firefox);
            assert_eq!(config.stealth.initial_os, crate::stealth::OsProfile::Linux);
            assert_eq!(
                config.stealth.padding_strategy,
                crate::stealth::PaddingStrategy::BrowserMimic
            );
            assert_eq!(config.optimize.block_size, 65_536);
            assert_eq!(config.optimize.pool_capacity, 16);
        }
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

/// A high-performance wrapper integrating a TUN device with QuicFuscate's
/// aligned memory pool for minimal-copy I/O.
pub struct TunInterface {
    dev: Box<dyn TunDevice>,
    pool: Arc<MemoryPool>,
    configured_mtu: AtomicU16,
    ipv6_enabled: bool,
    #[cfg(target_os = "linux")]
    zero_copy: bool,
}

impl std::fmt::Debug for TunInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("TunInterface");
        dbg.field("name", &self.dev.name())
            .field("mtu", &self.mtu())
            .field("ipv6_enabled", &self.ipv6_enabled);
        #[cfg(target_os = "linux")]
        {
            dbg.field("zero_copy", &self.zero_copy);
        }
        dbg.finish()
    }
}

impl TunInterface {
    fn reconcile_device_mtu(
        dev: &dyn TunDevice,
        requested_mtu: u16,
        ipv6_enabled: bool,
    ) -> Result<u16, TunError> {
        let reported_mtu = dev.mtu();
        if reported_mtu != requested_mtu {
            dev.set_mtu(requested_mtu).map_err(TunError::Io)?;
        }
        let verified_mtu = dev.mtu();
        if verified_mtu != requested_mtu {
            return Err(TunError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "TUN backend reported MTU {} after requesting {}",
                    verified_mtu, requested_mtu
                ),
            )));
        }
        if verified_mtu < TUN_MIN_MTU {
            return Err(TunError::Config("TUN backend reported an MTU below 576"));
        }
        if ipv6_enabled && verified_mtu < TUN_IPV6_MIN_MTU {
            return Err(TunError::Config("IPv6 TUN backend reported an MTU below 1280"));
        }
        Ok(verified_mtu)
    }

    /// Open a TUN interface using the given config and memory pool.
    pub fn open(config: TunConfig, pool: Arc<MemoryPool>) -> Result<Self, TunError> {
        if let Err(error) = validate_tun_config(&config) {
            crate::optimize::telemetry::TUN_CONFIG_REJECTS.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        let ipv6_enabled = config.ip6.is_some();

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
            let verified_mtu = Self::reconcile_device_mtu(&*dev, config.mtu, ipv6_enabled)?;
            return Ok(Self {
                dev,
                pool,
                configured_mtu: AtomicU16::new(verified_mtu),
                ipv6_enabled,
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
        let verified_mtu = Self::reconcile_device_mtu(&*dev, config.mtu, ipv6_enabled)?;
        Ok(Self {
            dev,
            pool,
            configured_mtu: AtomicU16::new(verified_mtu),
            ipv6_enabled,
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
            configured_mtu: AtomicU16::new(dev.mtu()),
            ipv6_enabled: false,
            dev,
            pool,
            #[cfg(target_os = "linux")]
            zero_copy,
        }
    }

    #[cfg(test)]
    pub(crate) fn from_device_for_test_with_ipv6(
        dev: Box<dyn TunDevice>,
        pool: Arc<MemoryPool>,
        zero_copy: bool,
    ) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = zero_copy;
        let mtu = dev.mtu();
        Self {
            configured_mtu: AtomicU16::new(mtu),
            ipv6_enabled: true,
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

    /// Returns the configured layer-3 MTU.
    pub fn mtu(&self) -> u16 {
        self.configured_mtu.load(Ordering::Acquire)
    }

    /// Returns the backend read contract used by generic client loops.
    pub fn read_contract(&self) -> TunReadContract {
        self.dev.read_contract()
    }

    /// Atomically applies and publishes a new live layer-3 MTU.
    pub fn set_mtu(&self, mtu: u16) -> io::Result<()> {
        if mtu < TUN_MIN_MTU {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "TUN MTU must be >= 576"));
        }
        if self.ipv6_enabled && mtu < TUN_IPV6_MIN_MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 TUN MTU must be >= 1280",
            ));
        }
        if self.mtu() == mtu {
            return Ok(());
        }
        self.dev.set_mtu(mtu)?;
        if self.dev.mtu() != mtu {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("TUN backend did not report requested MTU {mtu}"),
            ));
        }
        self.configured_mtu.store(mtu, Ordering::Release);
        Ok(())
    }

    /// Reads one packet into a pooled block and returns `(block, len)`.
    /// The block remains zero-initialized outside the valid frame region and
    /// returns to its pool automatically when the returned `PooledBlock` is
    /// dropped. The result count has already been checked against the block.
    pub fn read_block(&self) -> io::Result<(PooledBlock, usize)> {
        let mut block = PooledBlock::new(Arc::clone(&self.pool));
        let len = validate_tun_read_len(self.dev.read(&mut block[..])?, block.len())?;
        if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
            crate::telemetry::BYTES_RECEIVED.inc_by(len as u64);
        }
        Ok((block, len))
    }

    /// Write a packet to the TUN device with hardware acceleration
    pub fn write_packet(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.write(buf)?;
        // Parse IP headers with BMI2 only when the exact runtime feature is present.
        #[cfg(target_arch = "x86_64")]
        {
            let detector = crate::optimize::FeatureDetector::instance();
            let features = detector.features_full();
            if bmi2_parser_is_allowed(detector.profile(), features) {
                // SAFETY: the exact runtime BMI2 feature is proven above.
                unsafe { self.parse_ip_header_bmi2(buf) };
            } else {
                self.parse_ip_header_scalar(buf);
            }
        }

        #[cfg(not(target_arch = "x86_64"))]
        self.parse_ip_header_scalar(buf);

        Ok(written)
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
        let header = std::ptr::read_unaligned(packet.as_ptr().cast::<u32>());

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

    /// Writes a single packet from a provided slice and accepts it only after
    /// the backend reports the complete packet length.
    pub fn write(&self, packet: &[u8]) -> io::Result<usize> {
        let n = validate_tun_write_len(self.dev.write(packet)?, packet.len())?;
        if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
            crate::telemetry::BYTES_SENT.inc_by(n as u64);
        }
        Ok(n)
    }

    /// Wake the backend reader before its owning thread is joined.
    pub fn request_reader_shutdown(&self) -> io::Result<()> {
        self.dev.request_read_shutdown()
    }

    /// Waits until the device is readable or shutdown is requested.
    #[cfg(unix)]
    fn wait_for_readable(&self, shutdown: &AtomicBool) -> io::Result<bool> {
        let Some(fd) = self.dev.raw_fd() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN backend returned WouldBlock without a raw file descriptor",
            ));
        };
        let mut pollfd =
            libc::pollfd { fd, events: libc::POLLIN | libc::POLLERR | libc::POLLHUP, revents: 0 };
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Ok(false);
            }
            // SAFETY: `pollfd` points to one initialized descriptor owned by the
            // TUN backend and remains valid for the duration of this call.
            let result = unsafe { libc::poll(&mut pollfd, 1, 100) };
            if result > 0 {
                if pollfd.revents & libc::POLLNVAL != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "TUN descriptor became invalid while waiting for input",
                    ));
                }
                return Ok(true);
            }
            if result == 0 {
                continue;
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }

    #[cfg(not(unix))]
    fn wait_for_readable(&self, _shutdown: &AtomicBool) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN backend returned WouldBlock without event-driven wait support",
        ))
    }

    /// Convenience loop with cooperative shutdown: repeatedly reads from TUN
    /// and invokes callback with a borrowed slice into a pooled block. The
    /// callback may copy or process in place; the block is returned to the pool
    /// once the callback returns.
    pub fn reader_loop_with_shutdown<F>(
        &self,
        shutdown: &AtomicBool,
        mut on_packet: F,
    ) -> io::Result<()>
    where
        F: FnMut(&[u8]),
    {
        loop {
            if shutdown.load(Ordering::Acquire) {
                self.request_reader_shutdown()?;
                return Ok(());
            }
            match self.read_block() {
                Ok((block, len)) => {
                    on_packet(&block[..len]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !self.wait_for_readable(shutdown)? {
                        return Ok(());
                    }
                }
                Err(_) if shutdown.load(Ordering::Acquire) => {
                    self.request_reader_shutdown()?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Convenience loop with cooperative shutdown that transfers pooled TUN
    /// blocks to the callback without copying packet bytes.
    pub fn reader_loop_with_shutdown_owned<F>(
        &self,
        shutdown: &AtomicBool,
        mut on_packet: F,
    ) -> io::Result<()>
    where
        F: FnMut(TunPacket),
    {
        loop {
            if shutdown.load(Ordering::Acquire) {
                self.request_reader_shutdown()?;
                return Ok(());
            }
            match self.read_block() {
                Ok((block, len)) => on_packet(TunPacket::new(block, len)?),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if !self.wait_for_readable(shutdown)? {
                        return Ok(());
                    }
                }
                Err(_) if shutdown.load(Ordering::Acquire) => {
                    self.request_reader_shutdown()?;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Convenience loop: repeatedly reads from TUN and invokes callback with a
    /// borrowed slice into a pooled block. The callback may copy or process in
    /// place; the block is returned to the pool once the callback returns.
    ///
    /// This compatibility wrapper runs until the device returns an error. New
    /// callers should use [`Self::reader_loop_with_shutdown`] so the reader can
    /// be joined deterministically.
    pub fn reader_loop<F>(&self, mut on_packet: F) -> io::Result<()>
    where
        F: FnMut(&[u8]),
    {
        let shutdown = AtomicBool::new(false);
        self.reader_loop_with_shutdown(&shutdown, |packet| on_packet(packet))
    }
}

// Platform-specific implementations

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
///     fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
///         Err(io::Error::from(io::ErrorKind::WouldBlock))
///     }
///     fn write(&self, buf: &[u8]) -> io::Result<usize> { Ok(buf.len()) }
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
    use std::ffi::{CString, OsString};
    use std::fs::OpenOptions;
    use std::mem;
    use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;
    use std::sync::atomic::{AtomicU16, Ordering};

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
        mtu: AtomicU16,
    }

    impl LinuxTun {
        fn netmask_prefix(netmask: IpAddr) -> io::Result<u8> {
            match netmask {
                IpAddr::V4(mask) => {
                    let raw = u32::from(mask);
                    let prefix = raw.leading_ones();
                    let canonical = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                    if raw != canonical {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("non-contiguous IPv4 TUN netmask: {mask}"),
                        ));
                    }
                    Ok(prefix as u8)
                }
                IpAddr::V6(mask) => {
                    let raw = u128::from(mask);
                    let prefix = raw.leading_ones();
                    let canonical = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                    if raw != canonical {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("non-contiguous IPv6 TUN netmask: {mask}"),
                        ));
                    }
                    Ok(prefix as u8)
                }
            }
        }

        fn validate_interface_name(name: &str) -> io::Result<()> {
            validate_linux_interface_name(name)
        }

        fn interface_exists_bytes(name: &[u8]) -> io::Result<bool> {
            if name.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot inspect an unnamed Linux TUN interface",
                ));
            }
            let name = OsString::from_vec(name.to_vec());
            let output = Command::new("ip")
                .args(["link", "show", "dev"])
                .arg(name)
                .output()
                .map_err(|error| io::Error::other(format!("ip link inspect spawn: {error}")))?;
            if output.status.success() {
                return Ok(true);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if stderr.contains("cannot find device")
                || stderr.contains("does not exist")
                || stderr.contains("no such device")
            {
                return Ok(false);
            }
            Err(io::Error::other(format!(
                "ip link inspect returned status {}: {}",
                output.status,
                stderr.trim()
            )))
        }

        fn interface_exists(name: &str) -> io::Result<bool> {
            Self::interface_exists_bytes(name.as_bytes())
        }

        fn remove_owned_interface_bytes(name: &[u8]) -> io::Result<()> {
            if name.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot roll back a Linux TUN without an exact interface name",
                ));
            }
            let name_bytes = name.to_vec();
            let display_name = String::from_utf8_lossy(&name_bytes);
            if !Self::interface_exists_bytes(&name_bytes)? {
                return Ok(());
            }
            let name = OsString::from_vec(name_bytes.clone());
            let output = Command::new("ip")
                .args(["link", "delete", "dev"])
                .arg(name)
                .output()
                .map_err(|error| io::Error::other(format!("ip link delete spawn: {error}")))?;
            if !output.status.success() && Self::interface_exists_bytes(&name_bytes)? {
                return Err(io::Error::other(format!(
                    "ip link delete returned status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            if Self::interface_exists_bytes(&name_bytes)? {
                return Err(io::Error::other(format!(
                    "owned Linux TUN interface {display_name} remains after rollback"
                )));
            }
            Ok(())
        }

        fn rollback_open_failure(fd: &mut RawFd, name: &[u8], primary: io::Error) -> io::Error {
            let close_error = close_owned_fd(fd).err();
            let cleanup_error = Self::remove_owned_interface_bytes(name).err();
            if close_error.is_none() && cleanup_error.is_none() {
                return primary;
            }
            let mut message = format!("Linux TUN setup failed: {primary}");
            if let Some(error) = close_error {
                message.push_str(&format!("; descriptor close failed: {error}"));
            }
            if let Some(error) = cleanup_error {
                message.push_str(&format!("; interface rollback failed: {error}"));
            }
            io::Error::other(message)
        }

        fn json_ip(args: &[&str]) -> io::Result<serde_json::Value> {
            let output = Command::new("ip")
                .args(args)
                .output()
                .map_err(|error| io::Error::other(format!("ip inspection spawn: {error}")))?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "ip {} returned status {}: {}",
                    args.join(" "),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            serde_json::from_slice(&output.stdout).map_err(|error| {
                io::Error::other(format!("ip {} returned invalid JSON: {error}", args.join(" ")))
            })
        }

        fn read_mtu(name: &str) -> io::Result<u16> {
            let value = Self::json_ip(&["-j", "link", "show", "dev", name])?;
            let mtu = value
                .as_array()
                .and_then(|items| items.first())
                .and_then(|item| item.get("mtu"))
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| io::Error::other("ip link inspection omitted MTU"))?;
            u16::try_from(mtu).map_err(|_| io::Error::other("Linux TUN MTU exceeds u16"))
        }

        fn verify_configured(name: &str, cfg: &TunConfig) -> io::Result<u16> {
            let link = Self::json_ip(&["-j", "link", "show", "dev", name])?;
            let item = link
                .as_array()
                .and_then(|items| items.first())
                .ok_or_else(|| io::Error::other("ip link inspection returned no device"))?;
            let is_up = item
                .get("flags")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")));
            if !is_up {
                return Err(io::Error::other("Linux TUN link is not administratively up"));
            }
            let mtu = item
                .get("mtu")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| io::Error::other("ip link inspection omitted MTU"))?;
            let mtu =
                u16::try_from(mtu).map_err(|_| io::Error::other("Linux TUN MTU exceeds u16"))?;

            let addresses = Self::json_ip(&["-j", "address", "show", "dev", name])?;
            let address_items = addresses
                .as_array()
                .and_then(|items| items.first())
                .and_then(|item| item.get("addr_info"))
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| io::Error::other("ip address inspection omitted addr_info"))?;
            if let Some(IpAddr::V4(expected)) = cfg.ip {
                let Some(netmask) = cfg.netmask else {
                    return Err(io::Error::other("validated TUN configuration lost IPv4 netmask"));
                };
                let prefix = Self::netmask_prefix(netmask)?;
                let expected_text = expected.to_string();
                let found = address_items.iter().any(|entry| {
                    entry.get("family").and_then(serde_json::Value::as_str) == Some("inet")
                        && entry.get("local").and_then(serde_json::Value::as_str)
                            == Some(expected_text.as_str())
                        && entry.get("prefixlen").and_then(serde_json::Value::as_u64)
                            == Some(u64::from(prefix))
                });
                if !found {
                    return Err(io::Error::other(format!(
                        "Linux TUN is missing IPv4 address {expected}/{prefix}"
                    )));
                }
            }
            if let (Some(expected), Some(prefix)) = (cfg.ip6, cfg.prefix6) {
                let expected_text = expected.to_string();
                let found = address_items.iter().any(|entry| {
                    entry.get("family").and_then(serde_json::Value::as_str) == Some("inet6")
                        && entry.get("local").and_then(serde_json::Value::as_str)
                            == Some(expected_text.as_str())
                        && entry.get("prefixlen").and_then(serde_json::Value::as_u64)
                            == Some(u64::from(prefix))
                });
                if !found {
                    return Err(io::Error::other(format!(
                        "Linux TUN is missing IPv6 address {expected}/{prefix}"
                    )));
                }
            }
            Ok(mtu)
        }

        fn run_ip(args: &[&str]) -> io::Result<()> {
            let output = Command::new("ip").args(args).output().map_err(|error| {
                io::Error::other(format!("ip {} spawn: {error}", args.join(" ")))
            })?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::other(format!(
                "ip {} returned status {}: {}",
                args.join(" "),
                output.status,
                stderr.trim()
            )))
        }

        fn configure(name: &str, cfg: &TunConfig) -> io::Result<()> {
            let mtu = cfg.mtu.to_string();
            Self::run_ip(&["link", "set", "dev", name, "mtu", &mtu, "up"])?;

            match (cfg.ip, cfg.netmask) {
                (None, None) => {}
                (Some(address), Some(netmask)) if address.is_ipv4() == netmask.is_ipv4() => {
                    let cidr = format!("{address}/{}", Self::netmask_prefix(netmask)?);
                    let family = if address.is_ipv4() { "-4" } else { "-6" };
                    Self::run_ip(&[family, "address", "replace", &cidr, "dev", name])?;
                }
                (Some(_), Some(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TUN address and netmask families differ",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TUN address and netmask must be configured together",
                    ));
                }
            }

            match (cfg.ip6, cfg.prefix6) {
                (None, None) => Ok(()),
                (Some(address), Some(prefix)) if prefix <= 128 => {
                    let cidr = format!("{address}/{prefix}");
                    Self::run_ip(&["-6", "address", "replace", &cidr, "dev", name])
                }
                (Some(_), Some(_)) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 TUN prefix must be <= 128",
                )),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 TUN address and prefix must be configured together",
                )),
            }?;

            Self::verify_configured(name, cfg).map(|_| ())
        }

        /// Open a Linux TUN device with the given configuration.
        pub fn open(cfg: &TunConfig) -> io::Result<Self> {
            if let Some(name) = cfg.name.as_deref() {
                Self::validate_interface_name(name)?;
                if Self::interface_exists(name)? {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("Linux TUN interface {name} already exists"),
                    ));
                }
            }

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
                if bytes.len() > ifr.ifr_name.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Linux TUN interface name exceeds IFNAMSIZ - 1",
                    ));
                }
                for (i, byte) in bytes.iter().enumerate() {
                    ifr.ifr_name[i] = *byte as libc::c_char;
                }
            }
            let ioctl_fd = file.as_raw_fd();
            let ret = unsafe { libc::ioctl(ioctl_fd, TUNSETIFF, &ifr) };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            // The ioctl created the interface, so descriptor and interface
            // cleanup are explicit from this point onward.
            let mut fd = file.into_raw_fd();
            let raw_name = kernel_interface_name_bytes(&ifr.ifr_name);
            let rollback_name = if raw_name.is_empty() {
                cfg.name.as_deref().map(str::as_bytes).unwrap_or(&[])
            } else {
                &raw_name
            };
            let name = match parse_kernel_interface_name(&ifr.ifr_name) {
                Ok(name) => name,
                Err(error) => {
                    return Err(Self::rollback_open_failure(&mut fd, rollback_name, error));
                }
            };
            if let Err(error) = Self::validate_interface_name(&name) {
                return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
            }
            if let Some(requested) = cfg.name.as_deref() {
                if requested != name {
                    let error = io::Error::other(format!(
                        "kernel returned TUN name {name}, requested {requested}"
                    ));
                    return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
                }
            }

            if let Err(error) = Self::configure(&name, cfg) {
                return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
            }

            // Keep the descriptor nonblocking so async runtimes and shutdown
            // paths can poll TUN without getting stuck in an uninterruptible
            // blocking read.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
            }
            let name: Arc<str> = Arc::from(name);
            let mtu = match Self::read_mtu(&name) {
                Ok(mtu) => mtu,
                Err(error) => {
                    return Err(Self::rollback_open_failure(&mut fd, name.as_bytes(), error));
                }
            };
            Ok(Self { name, fd, mtu: AtomicU16::new(mtu) })
        }
    }

    impl TunDevice for LinuxTun {
        fn name(&self) -> &str {
            self.name.as_ref()
        }
        fn mtu(&self) -> u16 {
            self.mtu.load(Ordering::Acquire)
        }
        fn read_contract(&self) -> TunReadContract {
            TunReadContract::NonBlocking
        }
        fn set_mtu(&self, mtu: u16) -> io::Result<()> {
            let mtu_text = mtu.to_string();
            Self::run_ip(&["link", "set", "dev", self.name(), "mtu", &mtu_text])?;
            let verified = Self::read_mtu(self.name())?;
            if verified != mtu {
                return Err(io::Error::other(format!(
                    "Linux TUN reported MTU {verified} after requesting {mtu}"
                )));
            }
            self.mtu.store(verified, Ordering::Release);
            Ok(())
        }
        #[cfg(unix)]
        fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
            Some(self.fd)
        }
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // Read into the user-provided buffer using libc::read with EINTR retry.
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
                return validate_raw_read_result(n, buf.len(), "Linux TUN read");
            }
        }
        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            // Write the full packet using libc::write with EINTR retry.
            let mut off = 0usize;
            while off < buf.len() {
                let remaining = buf.len() - off;
                let n = unsafe {
                    libc::write(self.fd, buf[off..].as_ptr() as *const libc::c_void, remaining)
                };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                off += validate_raw_write_progress(n, remaining, "Linux TUN write")?;
            }
            Ok(off)
        }
    }

    impl Drop for LinuxTun {
        fn drop(&mut self) {
            if let Err(error) = close_owned_fd(&mut self.fd) {
                log::error!("close Linux TUN descriptor failed: {error}");
            }
        }
    }

    /// Open the platform-native Linux TUN device.
    pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(LinuxTun::open(cfg)?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, Ipv6Addr};

        #[test]
        fn linux_backend_declares_nonblocking_read_contract() {
            let tun = LinuxTun { name: Arc::from("test-tun"), fd: -1, mtu: AtomicU16::new(1500) };
            assert_eq!(tun.read_contract(), TunReadContract::NonBlocking);
        }

        #[test]
        fn netmask_prefix_accepts_contiguous_masks() {
            assert_eq!(
                LinuxTun::netmask_prefix(Ipv4Addr::new(255, 255, 255, 0).into()).unwrap(),
                24
            );
            assert_eq!(
                LinuxTun::netmask_prefix(
                    "ffff:ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap().into()
                )
                .unwrap(),
                64
            );
        }

        #[test]
        fn netmask_prefix_rejects_non_contiguous_masks() {
            let error = LinuxTun::netmask_prefix(Ipv4Addr::new(255, 0, 255, 0).into()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }

        #[test]
        fn interface_name_validation_rejects_truncation() {
            assert!(LinuxTun::validate_interface_name("123456789012345").is_ok());
            assert!(LinuxTun::validate_interface_name("1234567890123456").is_err());
            assert!(LinuxTun::validate_interface_name("tun/name").is_err());
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_tun {
    use super::*;
    use std::mem;
    use std::os::fd::RawFd;
    use std::process::Command;
    use std::sync::atomic::{AtomicU16, Ordering};

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
        mtu: AtomicU16,
    }

    impl MacTun {
        fn run_ifconfig(args: &[&str]) -> io::Result<()> {
            let output = Command::new("/sbin/ifconfig")
                .args(args)
                .output()
                .map_err(|error| io::Error::other(format!("ifconfig spawn: {error}")))?;
            if output.status.success() {
                return Ok(());
            }
            Err(io::Error::other(format!(
                "ifconfig {} returned status {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }

        fn read_mtu(name: &str) -> io::Result<u16> {
            let output = Command::new("/sbin/ifconfig")
                .arg(name)
                .output()
                .map_err(|error| io::Error::other(format!("ifconfig inspect spawn: {error}")))?;
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "ifconfig {name} inspect returned status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tokens: Vec<&str> = stdout.split_whitespace().collect();
            let mtu = tokens
                .windows(2)
                .find(|pair| pair[0] == "mtu")
                .and_then(|pair| pair[1].parse::<u16>().ok())
                .ok_or_else(|| io::Error::other("ifconfig inspection omitted MTU"))?;
            Ok(mtu)
        }

        fn configure(name: &str, cfg: &TunConfig) -> io::Result<u16> {
            if let (Some(IpAddr::V4(address)), Some(IpAddr::V4(netmask))) = (cfg.ip, cfg.netmask) {
                let address = address.to_string();
                let netmask = netmask.to_string();
                Self::run_ifconfig(&[name, "inet", &address, "netmask", &netmask, "up"])?;
            }
            if let (Some(address), Some(prefix)) = (cfg.ip6, cfg.prefix6) {
                let address = address.to_string();
                let prefix = prefix.to_string();
                Self::run_ifconfig(&[name, "inet6", &address, "prefixlen", &prefix, "up"])?;
            }
            let mtu = cfg.mtu.to_string();
            Self::run_ifconfig(&[name, "mtu", &mtu, "up"])?;
            let verified = Self::read_mtu(name)?;
            if verified != cfg.mtu {
                return Err(io::Error::other(format!(
                    "macOS utun reported MTU {verified} after requesting {}",
                    cfg.mtu
                )));
            }
            Ok(verified)
        }

        fn set_device_mtu(name: &str, mtu: u16) -> io::Result<()> {
            let mtu_text = mtu.to_string();
            Self::run_ifconfig(&[name, "mtu", &mtu_text])?;
            let verified = Self::read_mtu(name)?;
            if verified != mtu {
                return Err(io::Error::other(format!(
                    "macOS utun reported MTU {verified} after requesting {mtu}"
                )));
            }
            Ok(())
        }

        fn interface_exists(name: &str) -> io::Result<bool> {
            let output = Command::new("/sbin/ifconfig")
                .arg(name)
                .output()
                .map_err(|error| io::Error::other(format!("ifconfig inspect spawn: {error}")))?;
            if output.status.success() {
                return Ok(true);
            }
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            if stderr.contains("does not exist") || stderr.contains("no such") {
                return Ok(false);
            }
            Err(io::Error::other(format!(
                "ifconfig {name} inspect returned status {}: {}",
                output.status,
                stderr.trim()
            )))
        }

        fn rollback_open_error(
            fd: &mut RawFd,
            connected: bool,
            name: Option<&str>,
            primary: io::Error,
        ) -> io::Error {
            let close_error = close_owned_fd(fd).err();
            let cleanup_error = if close_error.is_none() && connected {
                match name {
                    Some(name) => match Self::interface_exists(name) {
                        Ok(false) => None,
                        Ok(true) => Some(io::Error::other(format!(
                            "utun interface {name} remains after descriptor close"
                        ))),
                        Err(error) => Some(error),
                    },
                    None => Some(io::Error::other(
                        "utun interface identity is unavailable; absence cannot be proven",
                    )),
                }
            } else {
                None
            };
            if close_error.is_none() && cleanup_error.is_none() {
                return primary;
            }
            let mut message = format!("macOS utun setup failed: {primary}");
            if let Some(error) = close_error {
                message.push_str(&format!("; descriptor close failed: {error}"));
            }
            if let Some(error) = cleanup_error {
                message.push_str(&format!("; interface rollback failed: {error}"));
            }
            io::Error::other(message)
        }

        fn writev_iovecs(
            hdr: &mut [u8; 4],
            buf: &[u8],
            written: usize,
        ) -> io::Result<[libc::iovec; 2]> {
            let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "utun packet length overflow")
            })?;
            if written >= total {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun writev progress is outside the packet",
                ));
            }
            if written < 4 {
                // SAFETY: written < 4 proves the header pointer offset is in bounds.
                let header_ptr = unsafe { hdr.as_mut_ptr().add(written) };
                return Ok([
                    libc::iovec { iov_base: header_ptr as *mut libc::c_void, iov_len: 4 - written },
                    libc::iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() },
                ]);
            }
            let payload_offset = written - 4;
            // written < total proves payload_offset < buf.len() here.
            // SAFETY: The checked offset is strictly inside the payload.
            let payload_ptr = unsafe { buf.as_ptr().add(payload_offset) };
            Ok([
                libc::iovec { iov_base: hdr.as_mut_ptr() as *mut libc::c_void, iov_len: 0 },
                libc::iovec {
                    iov_base: payload_ptr as *mut libc::c_void,
                    iov_len: buf.len() - payload_offset,
                },
            ])
        }

        /// Open a macOS utun device with the given configuration.
        pub fn open(cfg: &TunConfig) -> io::Result<Self> {
            let mut fd =
                unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let mut info: CtlInfo = unsafe { mem::zeroed() };
            info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
            let rc = unsafe { libc::ioctl(fd, CTLIOCGINFO, &mut info) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_error(&mut fd, false, None, error));
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
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_error(&mut fd, false, None, error));
            }

            // Keep the descriptor interruptible by the cooperative reader
            // loop. `poll(2)` supplies the blocking wait and the shutdown
            // flag is checked between bounded waits.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_error(&mut fd, true, None, error));
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_error(&mut fd, true, None, error));
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
                let error = io::Error::last_os_error();
                return Err(Self::rollback_open_error(&mut fd, true, None, error));
            }
            let reported_len = match usize::try_from(len) {
                Ok(length) => length,
                Err(_) => {
                    let error = io::Error::new(
                        io::ErrorKind::InvalidData,
                        "utun interface name length overflow",
                    );
                    return Err(Self::rollback_open_error(&mut fd, true, None, error));
                }
            };
            let name_s = match parse_bounded_interface_name(&ifname, reported_len) {
                Ok(name) => name,
                Err(error) => return Err(Self::rollback_open_error(&mut fd, true, None, error)),
            };
            let mtu = match Self::configure(&name_s, cfg) {
                Ok(mtu) => mtu,
                Err(error) => {
                    return Err(Self::rollback_open_error(&mut fd, true, Some(&name_s), error));
                }
            };
            let name: Arc<str> = Arc::from(name_s);
            Ok(Self { fd, name, mtu: AtomicU16::new(mtu) })
        }
    }

    impl TunDevice for MacTun {
        fn name(&self) -> &str {
            self.name.as_ref()
        }
        fn mtu(&self) -> u16 {
            self.mtu.load(Ordering::Acquire)
        }
        fn read_contract(&self) -> TunReadContract {
            TunReadContract::NonBlocking
        }
        fn set_mtu(&self, mtu: u16) -> io::Result<()> {
            Self::set_device_mtu(self.name(), mtu)?;
            self.mtu.store(mtu, Ordering::Release);
            Ok(())
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
                let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "utun read buffer length overflow")
                })?;
                let total_read = validate_raw_read_result(n, total, "macOS utun readv")?;
                if total_read <= 4 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "macOS utun readv returned an incomplete AF header or empty packet",
                    ));
                }
                return Ok(total_read - 4);
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
            let total = 4usize.checked_add(buf.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "utun packet length overflow")
            })?;
            let mut written = 0usize;
            while written < total {
                let iov = Self::writev_iovecs(&mut hdr, buf, written)?;
                let n = unsafe { libc::writev(self.fd, iov.as_ptr(), iov.len() as i32) };
                if n < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                let progress =
                    validate_raw_write_progress(n, total - written, "macOS utun writev")?;
                written = written.checked_add(progress).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "utun writev progress overflow")
                })?;
            }
            Ok(buf.len())
        }
    }

    impl Drop for MacTun {
        fn drop(&mut self) {
            if let Err(error) = close_owned_fd(&mut self.fd) {
                log::error!("close macOS utun descriptor failed: {error}");
            }
        }
    }

    /// Open the platform-native macOS utun device.
    pub fn open_platform_tun(cfg: &TunConfig) -> Result<Box<dyn TunDevice>, TunError> {
        Ok(Box::new(MacTun::open(cfg)?))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn utun_writev_iovecs_follow_bounded_progress() {
            let mut hdr = [0u8; 4];
            let payload = [1u8, 2, 3];

            let initial = MacTun::writev_iovecs(&mut hdr, &payload, 0).unwrap();
            assert_eq!(initial[0].iov_len, 4);
            assert_eq!(initial[1].iov_len, payload.len());

            let header_partial = MacTun::writev_iovecs(&mut hdr, &payload, 2).unwrap();
            assert_eq!(header_partial[0].iov_len, 2);
            assert_eq!(header_partial[1].iov_len, payload.len());

            let payload_partial = MacTun::writev_iovecs(&mut hdr, &payload, 5).unwrap();
            assert_eq!(payload_partial[0].iov_len, 0);
            assert_eq!(payload_partial[1].iov_len, 2);
            assert_eq!(payload_partial[1].iov_base as usize, payload.as_ptr() as usize + 1);

            assert!(MacTun::writev_iovecs(&mut hdr, &payload, 7).is_err());
        }
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
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[cfg(unix)]
    #[test]
    fn unix_raw_result_contract_rejects_zero_and_oversized_counts() {
        assert_eq!(validate_raw_read_result(8, 8, "read").unwrap(), 8);
        assert_eq!(validate_raw_write_progress(8, 8, "write").unwrap(), 8);

        let zero_read = validate_raw_read_result(0, 8, "read").expect_err("zero read must fail");
        assert_eq!(zero_read.kind(), io::ErrorKind::UnexpectedEof);
        let oversized_read =
            validate_raw_read_result(9, 8, "read").expect_err("oversized read must fail");
        assert_eq!(oversized_read.kind(), io::ErrorKind::InvalidData);
        let zero_write =
            validate_raw_write_progress(0, 8, "write").expect_err("zero write must fail");
        assert_eq!(zero_write.kind(), io::ErrorKind::WriteZero);
        let oversized_write =
            validate_raw_write_progress(9, 8, "write").expect_err("oversized write must fail");
        assert_eq!(oversized_write.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn unix_interface_name_parser_requires_bounded_terminated_utf8() {
        assert_eq!(parse_bounded_interface_name(b"utun4\0", 6).unwrap(), "utun4");
        for (bytes, reported_len) in
            [(&b"utun4\0"[..], 0), (&b"utun4\0"[..], 7), (&b"utun4x"[..], 6), (&[0xff, 0][..], 2)]
        {
            assert!(
                parse_bounded_interface_name(bytes, reported_len).is_err(),
                "malformed interface name must fail: bytes={bytes:?} len={reported_len}"
            );
        }

        #[cfg(target_os = "linux")]
        {
            let mut ifr_name = [0 as libc::c_char; 16];
            for (slot, byte) in ifr_name.iter_mut().zip(b"tun0\0") {
                *slot = *byte as libc::c_char;
            }
            assert_eq!(parse_kernel_interface_name(&ifr_name).unwrap(), "tun0");
            ifr_name.fill(b'x' as libc::c_char);
            assert!(parse_kernel_interface_name(&ifr_name).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_close_failure_is_reported_and_descriptor_number_is_terminalized() {
        let mut fd = 42;
        let error =
            close_owned_fd_with(&mut fd, |_fd| Err(io::Error::from_raw_os_error(libc::EIO)))
                .expect_err("injected close failure must be observable");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(fd, -1);
        assert!(close_owned_fd_with(&mut fd, |_fd| {
            Err(io::Error::other("close must not be retried"))
        })
        .is_ok());
    }

    struct DummyTun {
        reads: Mutex<Vec<Vec<u8>>>,
        writes: AtomicUsize,
        last_write_len: AtomicUsize,
        mtu: AtomicU16,
        refuse_mtu_updates: bool,
        fail_reads: bool,
    }

    impl DummyTun {
        fn with_reads(reads: Vec<Vec<u8>>) -> Self {
            Self {
                reads: Mutex::new(reads),
                writes: AtomicUsize::new(0),
                last_write_len: AtomicUsize::new(0),
                mtu: AtomicU16::new(1500),
                refuse_mtu_updates: false,
                fail_reads: false,
            }
        }

        fn refusing_mtu_updates() -> Self {
            Self { refuse_mtu_updates: true, ..Self::with_reads(Vec::new()) }
        }

        fn failing_reads() -> Self {
            Self { fail_reads: true, ..Self::with_reads(Vec::new()) }
        }
    }

    impl TunDevice for DummyTun {
        fn name(&self) -> &str {
            "dummy"
        }

        fn mtu(&self) -> u16 {
            self.mtu.load(Ordering::Relaxed)
        }

        fn set_mtu(&self, mtu: u16) -> io::Result<()> {
            if self.refuse_mtu_updates {
                return Err(io::Error::other("dummy backend refused MTU update"));
            }
            self.mtu.store(mtu, Ordering::Relaxed);
            Ok(())
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            if self.fail_reads {
                return Err(io::Error::other("dummy read failure"));
            }
            let mut reads = self.reads.lock().expect("dummy read lock poisoned");
            if reads.is_empty() {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
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

    #[derive(Clone, Copy)]
    enum FaultReadResult {
        Zero,
        Oversized,
    }

    #[derive(Clone, Copy)]
    enum FaultWriteResult {
        Zero,
        Short(usize),
        Oversized,
    }

    /// Fault-injection backend representing a device returned by an external
    /// factory. The wrapper, rather than the backend, owns result validation.
    struct FaultTun {
        read_result: FaultReadResult,
        write_result: FaultWriteResult,
    }

    impl FaultTun {
        fn new(read_result: FaultReadResult, write_result: FaultWriteResult) -> Self {
            Self { read_result, write_result }
        }
    }

    impl TunDevice for FaultTun {
        fn name(&self) -> &str {
            "fault-injection"
        }

        fn mtu(&self) -> u16 {
            1500
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            match self.read_result {
                FaultReadResult::Zero => Ok(0),
                FaultReadResult::Oversized => Ok(buf.len().saturating_add(1)),
            }
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            match self.write_result {
                FaultWriteResult::Zero => Ok(0),
                FaultWriteResult::Short(len) => Ok(len.min(buf.len())),
                FaultWriteResult::Oversized => Ok(buf.len().saturating_add(1)),
            }
        }
    }

    #[test]
    fn external_factory_read_result_contract_rejects_zero_and_oversized_lengths() {
        for (read_result, expected_kind) in [
            (FaultReadResult::Zero, io::ErrorKind::UnexpectedEof),
            (FaultReadResult::Oversized, io::ErrorKind::InvalidData),
        ] {
            let tun = TunInterface::from_device_for_test(
                Box::new(FaultTun::new(read_result, FaultWriteResult::Zero)),
                crate::optimize::global_pool(),
                false,
            );
            let error = match tun.read_block() {
                Err(error) => error,
                Ok((_block, _len)) => panic!("invalid external read result must fail"),
            };
            assert_eq!(error.kind(), expected_kind);
        }
    }

    #[test]
    fn external_factory_write_result_contract_rejects_zero_short_and_oversized_results() {
        let packet = [0x45u8; 32];
        for (write_result, expected_kind) in [
            (FaultWriteResult::Zero, io::ErrorKind::WriteZero),
            (FaultWriteResult::Short(1), io::ErrorKind::WriteZero),
            (FaultWriteResult::Oversized, io::ErrorKind::InvalidData),
        ] {
            let tun = TunInterface::from_device_for_test(
                Box::new(FaultTun::new(FaultReadResult::Zero, write_result)),
                crate::optimize::global_pool(),
                false,
            );
            let error = tun.write(&packet).expect_err("invalid external write result must fail");
            assert_eq!(error.kind(), expected_kind);
        }
    }

    #[test]
    fn write_packet_rejects_short_external_factory_result() {
        let mut tun = TunInterface::from_device_for_test(
            Box::new(FaultTun::new(FaultReadResult::Zero, FaultWriteResult::Short(1))),
            crate::optimize::global_pool(),
            false,
        );
        let error = tun
            .write_packet(&[0x45u8; 32])
            .expect_err("client write_packet must reject a short backend write");
        assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn owned_packet_constructor_rejects_oversized_length() {
        let block = PooledBlock::new(crate::optimize::global_pool());
        let capacity = block.len();
        let error = match TunPacket::new(block, capacity.saturating_add(1)) {
            Ok(_) => panic!("owned packet constructor must reject an oversized length"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn shared_config_rejects_incomplete_address_pairs_and_ipv6_floor() {
        let missing_netmask = TunConfig {
            ip: Some("10.8.0.1".parse().expect("valid test IPv4 address")),
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&missing_netmask), Err(TunError::Config(_))));

        let missing_prefix =
            TunConfig { ip6: Some(Ipv6Addr::LOCALHOST), mtu: 1500, ..TunConfig::default() };
        assert!(matches!(validate_tun_config(&missing_prefix), Err(TunError::Config(_))));

        let low_ipv6_mtu = TunConfig {
            ip6: Some(Ipv6Addr::LOCALHOST),
            prefix6: Some(128),
            mtu: 1279,
            ..TunConfig::default()
        };
        assert!(matches!(validate_tun_config(&low_ipv6_mtu), Err(TunError::Config(_))));
    }

    #[cfg(any(
        target_os = "ios",
        all(target_os = "windows", not(feature = "tun-windows")),
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "ios"
        ))
    ))]
    #[test]
    fn platform_without_native_tun_backend_fails_closed() {
        let result = open_platform_tun(&TunConfig::default());

        assert!(matches!(result, Err(TunError::Config(_)) | Err(TunError::Unsupported)));
    }

    #[test]
    fn external_factory_mtu_is_reconciled_and_misreport_fails() {
        let device = DummyTun::with_reads(Vec::new());
        let verified = TunInterface::reconcile_device_mtu(&device, 1400, false)
            .expect("factory MTU update must be verified");
        assert_eq!(verified, 1400);
        assert_eq!(device.mtu(), 1400);

        let refusing = DummyTun::refusing_mtu_updates();
        assert!(matches!(
            TunInterface::reconcile_device_mtu(&refusing, 1400, false),
            Err(TunError::Io(_))
        ));
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
    fn read_block_failure_returns_the_pool_block() {
        let pool = Arc::new(crate::optimize::MemoryPool::new(1, 2_048));
        let before = pool.accounting_snapshot();
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::failing_reads()),
            Arc::clone(&pool),
            false,
        );

        assert!(tun.read_block().is_err());
        assert_eq!(pool.accounting_snapshot(), before);
    }

    #[test]
    fn custom_backend_defaults_to_owned_blocking_reader_contract() {
        let device = DummyTun::with_reads(Vec::new());
        assert_eq!(device.read_contract(), TunReadContract::Blocking);

        let tun = TunInterface::from_device_for_test(
            Box::new(device),
            crate::optimize::global_pool(),
            false,
        );
        assert_eq!(tun.read_contract(), TunReadContract::Blocking);
    }

    #[test]
    fn reader_loop_with_shutdown_exits_after_callback_requests_stop() {
        let pool = crate::optimize::global_pool();
        let shutdown = AtomicBool::new(false);
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(vec![vec![0x45, 0, 0, 20]])),
            pool,
            false,
        );
        let mut packets = 0;

        tun.reader_loop_with_shutdown(&shutdown, |packet| {
            assert_eq!(packet, [0x45, 0, 0, 20]);
            packets += 1;
            shutdown.store(true, Ordering::Release);
        })
        .expect("reader must exit cleanly after shutdown");

        assert_eq!(packets, 1);
        assert!(shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn owned_reader_loop_transfers_pooled_packet_without_copying() {
        let pool = crate::optimize::global_pool();
        let shutdown = AtomicBool::new(false);
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(vec![vec![0x45, 0, 0, 20]])),
            pool,
            false,
        );
        let mut packets = 0;

        tun.reader_loop_with_shutdown_owned(&shutdown, |packet| {
            assert_eq!(packet.as_slice(), [0x45, 0, 0, 20]);
            assert_eq!(packet.len(), 4);
            packets += 1;
            shutdown.store(true, Ordering::Release);
        })
        .expect("owned reader must exit cleanly after shutdown");

        assert_eq!(packets, 1);
        assert!(shutdown.load(Ordering::Acquire));
    }

    #[cfg(unix)]
    struct PollWaitTun {
        read_fd: std::os::fd::RawFd,
        write_fd: std::os::fd::RawFd,
        ready: Arc<AtomicBool>,
    }

    #[cfg(unix)]
    impl TunDevice for PollWaitTun {
        fn name(&self) -> &str {
            "poll-wait"
        }

        fn mtu(&self) -> u16 {
            1500
        }

        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            self.ready.store(true, Ordering::Release);
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        }

        fn write(&self, _buf: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
            Some(self.read_fd)
        }
    }

    #[cfg(unix)]
    impl Drop for PollWaitTun {
        fn drop(&mut self) {
            // SAFETY: both descriptors were returned by one successful pipe
            // call and are owned exclusively by this test device.
            unsafe {
                libc::close(self.read_fd);
                libc::close(self.write_fd);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn reader_loop_with_shutdown_interrupts_poll_wait() {
        let mut fds = [-1; 2];
        // SAFETY: `fds` points to storage for the two descriptors requested by
        // libc::pipe and remains valid for the duration of the call.
        let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(result, 0, "pipe must be created for poll shutdown test");

        let ready = Arc::new(AtomicBool::new(false));
        let shutdown = Arc::new(AtomicBool::new(false));
        let reader_shutdown = Arc::clone(&shutdown);
        let tun = TunInterface::from_device_for_test(
            Box::new(PollWaitTun { read_fd: fds[0], write_fd: fds[1], ready: Arc::clone(&ready) }),
            crate::optimize::global_pool(),
            false,
        );
        let reader =
            std::thread::spawn(move || tun.reader_loop_with_shutdown(&reader_shutdown, |_| {}));

        for _ in 0..1_000 {
            if ready.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(ready.load(Ordering::Acquire), "reader must reach the poll wait");
        shutdown.store(true, Ordering::Release);
        assert!(reader.join().expect("reader thread must join").is_ok());
    }

    #[test]
    fn set_mtu_publishes_only_after_backend_success() {
        let pool = crate::optimize::global_pool();
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(Vec::new())),
            pool,
            false,
        );

        tun.set_mtu(1280).expect("dummy MTU update must succeed");

        assert_eq!(tun.mtu(), 1280);
    }

    #[test]
    fn ipv6_rejects_subminimum_mtu_before_backend_mutation() {
        let pool = crate::optimize::global_pool();
        let tun = TunInterface::from_device_for_test_with_ipv6(
            Box::new(DummyTun::with_reads(Vec::new())),
            pool,
            false,
        );

        let error = tun.set_mtu(1279).expect_err("IPv6 MTU below 1280 must be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(tun.mtu(), 1500);
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
    fn write_packet_accepts_intentionally_unaligned_ipv4_slice() {
        let pool = crate::optimize::global_pool();
        let mut tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(Vec::new())),
            pool,
            false,
        );
        let mut backing = [0u8; 64];
        let base = backing.as_ptr() as usize;
        let offset = (1..4)
            .find(|candidate| !(base + *candidate).is_multiple_of(std::mem::align_of::<u32>()))
            .expect("an offset must produce an unaligned u32 address");
        let packet = &mut backing[offset..];
        packet[..20].copy_from_slice(&[
            0x45, 0x03, 0x00, 0x3c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
        ]);
        let before =
            crate::optimize::telemetry::IP_V4_PACKETS.load(std::sync::atomic::Ordering::Relaxed);

        let written = tun.write_packet(packet).expect("unaligned packet must be writable");

        assert_eq!(written, packet.len());
        assert!(
            crate::optimize::telemetry::IP_V4_PACKETS.load(std::sync::atomic::Ordering::Relaxed)
                > before,
            "unaligned IPv4 packet must reach header telemetry"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported() {
        if !is_x86_feature_detected!("bmi2") {
            eprintln!(
                "SIMD_SKIP test=bmi2_parser_accepts_intentionally_unaligned_ipv4_slice_when_supported required=bmi2"
            );
            return;
        }

        let pool = crate::optimize::global_pool();
        let tun = TunInterface::from_device_for_test(
            Box::new(DummyTun::with_reads(Vec::new())),
            pool,
            false,
        );
        let mut backing = [0u8; 64];
        let base = backing.as_ptr() as usize;
        let offset = (1..4)
            .find(|candidate| !(base + *candidate).is_multiple_of(std::mem::align_of::<u32>()))
            .expect("an offset must produce an unaligned u32 address");
        let packet = &mut backing[offset..];
        packet[..20].copy_from_slice(&[
            0x45, 0x03, 0x00, 0x3c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 1,
        ]);

        // SAFETY: The runtime check above proves BMI2 support for this call,
        // and the parser uses an alignment-safe four-byte load.
        unsafe { tun.parse_ip_header_bmi2(packet) };
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn bmi2_dispatch_requires_profile_and_runtime_feature_intersection() {
        let selecting_profiles = [
            CpuProfile::X86_P0a,
            CpuProfile::X86_P0b,
            CpuProfile::X86_P1a,
            CpuProfile::X86_P1b,
            CpuProfile::X86_P1f,
            CpuProfile::X86_P2a,
            CpuProfile::X86_P2b,
            CpuProfile::X86_P3a,
            CpuProfile::X86_P3b,
            CpuProfile::X86_P3c,
            CpuProfile::X86_P3d,
            CpuProfile::X86_P3e,
            CpuProfile::X86_P4a,
            CpuProfile::X86_P4b,
        ];
        let without_bmi2 = CpuFeatures::default();
        let with_bmi2 = CpuFeatures { bmi2: true, ..CpuFeatures::default() };

        for profile in selecting_profiles {
            assert!(!bmi2_parser_is_allowed(profile, &without_bmi2));
            assert!(bmi2_parser_is_allowed(profile, &with_bmi2));
        }

        for profile in [
            CpuProfile::ARM_A0,
            CpuProfile::ARM_A1a,
            CpuProfile::ARM_A1b,
            CpuProfile::ARM_A1c,
            CpuProfile::ARM_A1d,
            CpuProfile::ARM_A2,
            CpuProfile::Apple_M,
            CpuProfile::RVV,
            CpuProfile::Scalar,
        ] {
            assert!(!bmi2_parser_is_allowed(profile, &with_bmi2));
        }
    }

    #[test]
    fn fastpath_mode_space_is_off_auto_only() {
        assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
        assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
        assert_eq!(FastpathMode::parse("legacy-token"), FastpathMode::Auto);
    }
}
