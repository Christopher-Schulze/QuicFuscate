//! Core networking primitives for QuicFuscate.
//!
//! This crate provides a minimal QUIC connection wrapper, MTU discovery
//! utilities and a placeholder congestion controller used in the tests.

#[cfg(feature = "quiche")]
use quiche;
use thiserror::Error;
use once_cell::sync::Lazy;
#[cfg(not(feature = "quiche"))]
use std::collections::{HashMap, VecDeque};
#[cfg(not(feature = "quiche"))]
use std::sync::Mutex;

#[cfg(not(feature = "quiche"))]
static NETWORK: Lazy<Mutex<HashMap<String, VecDeque<Vec<u8>>>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

mod quic_packet;
pub use quic_packet::{PacketType, QuicPacket, QuicPacketHeader};

/// Errors that can occur within the QUIC core crate.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Generic I/O error propagated from std
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// Error returned from the underlying QUIC implementation
    #[error("QUIC error: {0}")]
    Quic(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

/// Default minimum MTU recommended by RFC 8899.
pub const RFC_8899_MIN_MTU: u16 = 1200;
/// Default minimum MTU recommended by RFC 8899.
pub const DEFAULT_MIN_MTU: u16 = RFC_8899_MIN_MTU;
/// Typical Ethernet MTU used as an upper bound for probing.
pub const DEFAULT_MAX_MTU: u16 = 1500;
/// Common starting MTU before the path has been validated.
pub const DEFAULT_INITIAL_MTU: u16 = 1350;
/// Increment used when probing for a larger MTU.
pub const DEFAULT_MTU_STEP_SIZE: u16 = 10;

/// Interval for adaptive MTU checks based on network feedback (ms).
pub const DEFAULT_ADAPTIVE_CHECK_INTERVAL_MS: u32 = 10_000;
/// Periodic probe interval after MTU was validated (ms).
pub const DEFAULT_PERIODIC_PROBE_INTERVAL_MS: u32 = 60_000;
/// Expiry for outstanding probes when no response is seen (ms).
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 2_000;
/// Number of consecutive probe failures before assuming a black hole.
pub const DEFAULT_PATH_BLACKHOLE_THRESHOLD: u8 = 3;

/// Limits controlling MTU discovery and related timeouts.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct QuicLimits {
    pub min_mtu: u16,
    pub max_mtu: u16,
    pub initial_mtu: u16,
    pub mtu_step: u16,
    pub probe_timeout_ms: u32,
    pub periodic_probe_interval_ms: u32,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            min_mtu: DEFAULT_MIN_MTU,
            max_mtu: DEFAULT_MAX_MTU,
            initial_mtu: DEFAULT_INITIAL_MTU,
            mtu_step: DEFAULT_MTU_STEP_SIZE,
            probe_timeout_ms: DEFAULT_PROBE_TIMEOUT_MS,
            periodic_probe_interval_ms: DEFAULT_PERIODIC_PROBE_INTERVAL_MS,
        }
    }
}

/// Basic configuration for a QUIC connection.
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub server_name: String,
    pub port: u16,
}

/// Simple QUIC connection wrapper used for testing the Rust port.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    New,
    Connected,
    Error,
}

pub struct QuicConnection {
    #[allow(dead_code)]
    config: QuicConfig,
    mtu_discovery: bool,
    migration: bool,
    bbr: bool,
    current_path: Option<String>,
    bbr_controller: Option<BbrCongestionController>,
    zero_copy: bool,
    state: ConnectionState,
    #[cfg(feature = "quiche")]
    conn: Option<quiche::Connection>,
}

/// Configuration for zero-copy behaviour.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ZeroCopyConfig {
    pub enable_send: bool,
    pub enable_recv: bool,
}

impl QuicConnection {
    pub fn new(config: QuicConfig) -> Result<Self> {
        Ok(Self {
            config,
            mtu_discovery: false,
            migration: false,
            bbr: false,
            current_path: None,
            bbr_controller: None,
            zero_copy: false,
            state: ConnectionState::New,
            #[cfg(feature = "quiche")]
            conn: None,
        })
    }

    pub fn connect(&mut self, addr: &str) -> Result<()> {
        if self.state != ConnectionState::New {
            return Err(CoreError::Quic("already connected".into()));
        }

        let _sock_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| CoreError::Quic("invalid address".into()))?;

        #[cfg(not(feature = "quiche"))]
        {
            NETWORK
                .lock()
                .map_err(|_| CoreError::Quic("network lock poisoned".into()))?
                .entry(addr.to_string())
                .or_insert_with(VecDeque::new);
        }

        #[cfg(feature = "quiche")]
        {
            self.conn = Some(quiche::Connection::connect(addr));
        }

        if self.bbr && self.bbr_controller.is_none() {
            self.bbr_controller = Some(BbrCongestionController::new());
        }

        self.current_path = Some(addr.to_string());
        self.state = ConnectionState::Connected;
        Ok(())
    }

    pub fn enable_mtu_discovery(&mut self, enable: bool) {
        self.mtu_discovery = enable;
    }
    pub fn is_mtu_discovery_enabled(&self) -> bool {
        self.mtu_discovery
    }
    pub fn enable_migration(&mut self, enable: bool) {
        self.migration = enable;
    }
    pub fn is_migration_enabled(&self) -> bool {
        self.migration
    }

    pub fn migrate(&mut self, new_addr: &str) -> Result<()> {
        if !self.migration {
            return Err(CoreError::Quic("migration disabled".into()));
        }
        let _sock_addr: std::net::SocketAddr = new_addr
            .parse()
            .map_err(|_| CoreError::Quic("invalid address".into()))?;

        #[cfg(not(feature = "quiche"))]
        {
            NETWORK
                .lock()
                .map_err(|_| CoreError::Quic("network lock poisoned".into()))?
                .entry(new_addr.to_string())
                .or_insert_with(VecDeque::new);
        }

        #[cfg(feature = "quiche")]
        {
            self.conn = Some(quiche::Connection::connect(new_addr));
        }

        self.current_path = Some(new_addr.to_string());
        Ok(())
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Connected {
            return Err(CoreError::Quic("not connected".into()));
        }
        #[cfg(not(feature = "quiche"))]
        {
            let addr = self.current_path.clone().ok_or_else(|| CoreError::Quic("no path".into()))?;
            let mut net = NETWORK.lock().map_err(|_| CoreError::Quic("network lock poisoned".into()))?;
            let queue = net.entry(addr).or_insert_with(VecDeque::new);
            queue.push_back(data.to_vec());
        }
        #[cfg(feature = "quiche")]
        {
            if let Some(conn) = &mut self.conn {
                conn.send(data);
            }
        }
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.state != ConnectionState::Connected {
            return Err(CoreError::Quic("not connected".into()));
        }
        #[cfg(not(feature = "quiche"))]
        {
            if let Some(addr) = &self.current_path {
                let mut net = NETWORK.lock().map_err(|_| CoreError::Quic("network lock poisoned".into()))?;
                if let Some(queue) = net.get_mut(addr) {
                    return Ok(queue.pop_front());
                }
            }
            return Ok(None);
        }
        #[cfg(feature = "quiche")]
        {
            if let Some(conn) = &mut self.conn {
                return Ok(conn.recv());
            }
            Ok(None)
        }
    }

    pub fn enable_bbr_congestion_control(&mut self, enable: bool) {
        self.bbr = enable;
        if enable {
            if self.bbr_controller.is_none() {
                self.bbr_controller = Some(BbrCongestionController::new());
            }
        } else {
            self.bbr_controller = None;
        }
    }
    pub fn enable_zero_copy(&mut self, enable: bool) {
        self.zero_copy = enable;
    }
    pub fn configure_zero_copy(&mut self, cfg: ZeroCopyConfig) {
        self.zero_copy = cfg.enable_send || cfg.enable_recv;
    }
    pub fn zero_copy_config(&self) -> ZeroCopyConfig {
        if self.zero_copy {
            ZeroCopyConfig {
                enable_send: true,
                enable_recv: true,
            }
        } else {
            ZeroCopyConfig::default()
        }
    }
    pub fn is_zero_copy_enabled(&self) -> bool {
        self.zero_copy
    }
    pub fn is_bbr_enabled(&self) -> bool {
        self.bbr
    }
    pub fn current_path(&self) -> Option<&str> {
        self.current_path.as_deref()
    }
}

