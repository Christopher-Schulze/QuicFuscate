//! Core networking primitives for QuicFuscate.
//!
//! This crate provides a minimal QUIC connection wrapper, MTU discovery
//! utilities and a placeholder congestion controller used in the tests.

#[cfg(feature = "quiche")]
use quiche;
use thiserror::Error;
use once_cell::sync::Lazy;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

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
/// Reference minimum MTU defined by RFC 8899.
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
    /// Minimum allowed MTU for path discovery.
    pub min_mtu: u16,
    /// Maximum allowed MTU for path discovery.
    pub max_mtu: u16,
    /// Initial MTU value used before validation.
    pub initial_mtu: u16,
    /// Increment used when probing for a larger MTU.
    pub mtu_step: u16,
    /// Duration until an unanswered probe is considered lost (ms).
    pub probe_timeout_ms: u32,
    /// Interval for periodic probe attempts (ms).
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
    /// Enable zero-copy for sending operations.
    pub enable_send: bool,
    /// Enable zero-copy for receiving operations.
    pub enable_recv: bool,
}

impl QuicConnection {
    /// Create a new connection instance from the given config.
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

    /// Connect to the provided address. For the stub this always succeeds.
    pub fn connect(&mut self, addr: &str) -> Result<()> {
        if self.state != ConnectionState::New {
            return Err(CoreError::Quic("already connected".into()));
        }

        let _sock_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| CoreError::Quic("invalid address".into()))?;

        self.current_path = Some(addr.to_string());
        NETWORK
            .lock()
            .unwrap()
            .entry(addr.to_string())
            .or_insert_with(VecDeque::new);

        #[cfg(feature = "quiche")]
        {
            self.conn = Some(quiche::Connection);
        }

        if self.bbr && self.bbr_controller.is_none() {
            self.bbr_controller = Some(BbrCongestionController::new());
        }

        self.state = ConnectionState::Connected;
        Ok(())
    }

    /// Enable or disable MTU discovery.
    pub fn enable_mtu_discovery(&mut self, enable: bool) {
        self.mtu_discovery = enable;
    }

    /// Check whether MTU discovery is enabled.
    pub fn is_mtu_discovery_enabled(&self) -> bool {
        self.mtu_discovery
    }

    /// Enable or disable connection migration handling.
    pub fn enable_migration(&mut self, enable: bool) {
        self.migration = enable;
    }

    /// Check whether connection migration is enabled.
    pub fn is_migration_enabled(&self) -> bool {
        self.migration
    }

    /// Migrate the connection to a new network path.
    pub fn migrate(&mut self, new_addr: &str) -> Result<()> {
        if !self.migration {
            return Err(CoreError::Quic("migration disabled".into()));
        }
        let _sock_addr: std::net::SocketAddr = new_addr
            .parse()
            .map_err(|_| CoreError::Quic("invalid address".into()))?;
        NETWORK
            .lock()
            .unwrap()
            .entry(new_addr.to_string())
            .or_insert_with(VecDeque::new);
        self.current_path = Some(new_addr.to_string());
        Ok(())
    }

    /// Send data on the current connection path.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if self.state != ConnectionState::Connected {
            return Err(CoreError::Quic("not connected".into()));
        }
        let addr = self.current_path.clone().ok_or_else(|| CoreError::Quic("no path".into()))?;
        let mut net = NETWORK.lock().unwrap();
        let queue = net.entry(addr).or_insert_with(VecDeque::new);
        queue.push_back(data.to_vec());
        Ok(())
    }

    /// Receive pending data if available.
    pub fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        if self.state != ConnectionState::Connected {
            return Err(CoreError::Quic("not connected".into()));
        }
        if let Some(addr) = &self.current_path {
            let mut net = NETWORK.lock().unwrap();
            if let Some(queue) = net.get_mut(addr) {
                return Ok(queue.pop_front());
            }
        }
        Ok(None)
    }

    /// Enable or disable the BBRv2 congestion control algorithm.
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

    /// Enable or disable zero-copy transmission.
    pub fn enable_zero_copy(&mut self, enable: bool) {
        self.zero_copy = enable;
    }

    /// Configure zero-copy behaviour using [`ZeroCopyConfig`].
    pub fn configure_zero_copy(&mut self, cfg: ZeroCopyConfig) {
        self.zero_copy = cfg.enable_send || cfg.enable_recv;
    }

    /// Retrieve the current zero-copy configuration.
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

    /// Check whether zero-copy is enabled.
    pub fn is_zero_copy_enabled(&self) -> bool {
        self.zero_copy
    }

    /// Check if BBRv2 congestion control is enabled.
    pub fn is_bbr_enabled(&self) -> bool {
        self.bbr
    }

    /// Retrieve the currently connected path, if any.
    pub fn current_path(&self) -> Option<&str> {
        self.current_path.as_deref()
    }
}

/// Manager for sending and validating MTU probes.
use std::time::Instant;

/// Status of MTU discovery on a path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtuStatus {
    Disabled,
    Searching,
    Validating,
    Blackhole,
    Complete,
}

/// Information about an MTU change event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MtuChange {
    pub old_mtu: u16,
    pub new_mtu: u16,
    pub success: bool,
    pub reason: String,
}

/// Manager for sending and validating MTU probes.
pub struct PathMtuManager {
    outgoing_mtu: u16,
    incoming_mtu: u16,
    limits: QuicLimits,
    bidirectional: bool,
    next_probe_id: u32,
    probes: HashMap<u32, (bool, u16, Instant)>,
    outgoing_status: MtuStatus,
    incoming_status: MtuStatus,
    last_outgoing_probe: Option<Instant>,
    last_incoming_probe: Option<Instant>,
    outgoing_failures: u8,
    incoming_failures: u8,
    blackhole_threshold: u8,
    callback: Option<Box<dyn Fn(MtuChange) + Send + Sync>>,
}

impl Default for PathMtuManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PathMtuManager {
    pub fn new() -> Self {
        Self::with_limits(QuicLimits::default())
    }

    /// Create a manager with custom limits.
    pub fn with_limits(limits: QuicLimits) -> Self {
        Self {
            outgoing_mtu: limits.initial_mtu,
            incoming_mtu: limits.initial_mtu,
            limits,
            bidirectional: false,
            next_probe_id: 0,
            probes: HashMap::new(),
            outgoing_status: MtuStatus::Disabled,
            incoming_status: MtuStatus::Disabled,
            last_outgoing_probe: None,
            last_incoming_probe: None,
            outgoing_failures: 0,
            incoming_failures: 0,
            blackhole_threshold: DEFAULT_PATH_BLACKHOLE_THRESHOLD,
            callback: None,
        }
    }

    /// Enable or disable bidirectional MTU discovery.
    pub fn enable_bidirectional_discovery(&mut self, enable: bool) {
        self.bidirectional = enable;
    }

    /// Check if bidirectional MTU discovery is enabled.
    pub fn is_bidirectional_discovery_enabled(&self) -> bool {
        self.bidirectional
    }

    /// Manually set the MTU size used for probes.
    pub fn set_mtu_size(&mut self, mtu: u16, apply_both: bool) {
        self.outgoing_mtu = mtu;
        if apply_both {
            self.incoming_mtu = mtu;
        }
    }

    /// Get the current outgoing MTU.
    pub fn get_outgoing_mtu(&self) -> u16 {
        self.outgoing_mtu
    }

    /// Get the current incoming MTU.
    pub fn get_incoming_mtu(&self) -> u16 {
        self.incoming_mtu
    }

    /// Update discovery parameters.
    pub fn set_discovery_params(
        &mut self,
        min_mtu: u16,
        max_mtu: u16,
        step: u16,
        apply_both: bool,
    ) {
        self.limits.min_mtu = min_mtu;
        self.limits.max_mtu = max_mtu;
        self.limits.mtu_step = step;
        if apply_both {
            self.incoming_mtu = min_mtu;
            self.outgoing_mtu = min_mtu;
        }
    }

    /// Send a probe of the given size. Returns a probe identifier.
    pub fn send_probe(&mut self, size: u16, incoming: bool) -> u32 {
        self.next_probe_id += 1;
        self.probes
            .insert(self.next_probe_id, (incoming, size, Instant::now()));
        self.next_probe_id
    }

    /// Handle the result of a previously sent probe.
    pub fn handle_probe_response(&mut self, id: u32, success: bool, incoming: bool) {
        if let Some((probe_incoming, size, _sent)) = self.probes.remove(&id) {
            if probe_incoming == incoming {
                let (old, status, failures, last_probe) = if incoming {
                    (
                        self.incoming_mtu,
                        &mut self.incoming_status,
                        &mut self.incoming_failures,
                        &mut self.last_incoming_probe,
                    )
                } else {
                    (
                        self.outgoing_mtu,
                        &mut self.outgoing_status,
                        &mut self.outgoing_failures,
                        &mut self.last_outgoing_probe,
                    )
                };
                *last_probe = Some(Instant::now());
                if success {
                    let new_mtu = size.min(self.limits.max_mtu);
                    if incoming {
                        self.incoming_mtu = new_mtu;
                    } else {
                        self.outgoing_mtu = new_mtu;
                    }
                    *status = MtuStatus::Complete;
                    *failures = 0;
                    if let Some(cb) = &self.callback {
                        cb(MtuChange {
                            old_mtu: old,
                            new_mtu,
                            success: true,
                            reason: "probe-success".into(),
                        });
                    }
                } else {
                    *failures = failures.saturating_add(1);
                    if *failures >= self.blackhole_threshold {
                        *status = MtuStatus::Blackhole;
                    }
                    if let Some(cb) = &self.callback {
                        cb(MtuChange {
                            old_mtu: old,
                            new_mtu: size,
                            success: false,
                            reason: "probe-fail".into(),
                        });
                    }
                }
            }
        }
    }

    /// Simple dynamic adjustment based on observed loss and RTT.
    pub fn adapt_mtu_dynamically(&mut self, packet_loss_rate: f32, rtt_ms: u32) {
        if packet_loss_rate > 0.1 {
            let new_mtu = self.outgoing_mtu.saturating_sub(self.limits.mtu_step);
            self.outgoing_mtu = new_mtu.max(self.limits.min_mtu);
        } else if packet_loss_rate == 0.0 && rtt_ms < 100 {
            let new_mtu = self.outgoing_mtu.saturating_add(self.limits.mtu_step);
            self.outgoing_mtu = new_mtu.min(self.limits.max_mtu);
        }

        if self.bidirectional {
            self.incoming_mtu = self.outgoing_mtu;
        }
    }

    fn maybe_send_probe(&mut self, now: Instant, incoming: bool) {
        let (last_probe, mtu) = if incoming {
            (self.last_incoming_probe, self.incoming_mtu)
        } else {
            (self.last_outgoing_probe, self.outgoing_mtu)
        };

        if mtu >= self.limits.max_mtu {
            return;
        }

        let needs_probe = last_probe
            .map(|t| {
                now.duration_since(t).as_millis() as u32 >= self.limits.periodic_probe_interval_ms
            })
            .unwrap_or(true);
        if needs_probe {
            let probe_size = (mtu + self.limits.mtu_step).min(self.limits.max_mtu);
            self.send_probe(probe_size, incoming);
            if incoming {
                self.last_incoming_probe = Some(now);
                self.incoming_status = MtuStatus::Validating;
            } else {
                self.last_outgoing_probe = Some(now);
                self.outgoing_status = MtuStatus::Validating;
            }
        }
    }

    fn check_probe_timeouts(&mut self, now: Instant) {
        let timeout = self.limits.probe_timeout_ms;
        let expired: Vec<u32> = self
            .probes
            .iter()
            .filter(|(_, &(_, _, sent))| now.duration_since(sent).as_millis() as u32 >= timeout)
            .map(|(&id, _)| id)
            .collect();
        for id in expired {
            if let Some((incoming, _, _)) = self.probes.get(&id).cloned() {
                self.handle_probe_response(id, false, incoming);
            }
        }
    }

    /// Handle an incoming probe request and update state.
    pub fn handle_incoming_probe(&mut self, probe_id: u32, size: u16) {
        let success = size <= self.limits.max_mtu;
        let old = self.incoming_mtu;
        if success {
            self.incoming_mtu = size.min(self.limits.max_mtu);
            self.incoming_status = MtuStatus::Complete;
            self.incoming_failures = 0;
        } else {
            self.incoming_failures = self.incoming_failures.saturating_add(1);
            if self.incoming_failures >= self.blackhole_threshold {
                self.incoming_status = MtuStatus::Blackhole;
            }
        }
        self.last_incoming_probe = Some(Instant::now());
        if let Some(cb) = &self.callback {
            cb(MtuChange {
                old_mtu: old,
                new_mtu: size,
                success,
                reason: "incoming-probe".into(),
            });
        }
        // acknowledge by storing probe id removal for completeness
        self.probes.remove(&probe_id);
    }

    /// Periodic update entry point used to integrate feedback.
    pub fn update(&mut self, packet_loss_rate: f32, rtt_ms: u32) {
        if self.outgoing_status == MtuStatus::Disabled {
            self.outgoing_status = MtuStatus::Searching;
        }
        if self.bidirectional && self.incoming_status == MtuStatus::Disabled {
            self.incoming_status = MtuStatus::Searching;
        }

        self.adapt_mtu_dynamically(packet_loss_rate, rtt_ms);

        let now = Instant::now();
        self.maybe_send_probe(now, false);
        if self.bidirectional {
            self.maybe_send_probe(now, true);
        }
        self.check_probe_timeouts(now);
    }

    /// Retrieve the current status for the specified direction.
    pub fn get_mtu_status(&self, incoming: bool) -> MtuStatus {
        if incoming {
            self.incoming_status
        } else {
            self.outgoing_status
        }
    }

    /// Check if MTU discovery has not yet converged.
    pub fn is_mtu_unstable(&self) -> bool {
        self.get_mtu_status(false) != MtuStatus::Complete
            || (self.bidirectional && self.get_mtu_status(true) != MtuStatus::Complete)
    }

    /// Install a callback that is invoked whenever the MTU changes.
    pub fn set_mtu_change_callback<F>(&mut self, cb: F)
    where
        F: Fn(MtuChange) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(cb));
    }
}

pub struct StreamOptimizationConfig;

#[derive(Default)]
struct StreamInfo {
    priority: u8,
    window: u32,
}

pub struct QuicStreamOptimizer {
    streams: std::collections::HashMap<u64, StreamInfo>,
    base_chunk: u32,
}

impl Default for QuicStreamOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicStreamOptimizer {
    pub fn new() -> Self {
        Self {
            streams: std::collections::HashMap::new(),
            base_chunk: 1024,
        }
    }

    pub fn initialize(&mut self, _cfg: StreamOptimizationConfig) -> bool {
        true
    }

    pub fn set_stream_priority(&mut self, stream_id: u64, priority: u8) -> bool {
        let entry = self
            .streams
            .entry(stream_id)
            .or_default();
        entry.priority = priority;
        true
    }

    pub fn update_flow_control_window(&mut self, stream_id: u64, size: u32) -> bool {
        let entry = self
            .streams
            .entry(stream_id)
            .or_default();
        entry.window = size;
        true
    }

    pub fn can_send_data(&self, stream_id: u64, size: u32) -> bool {
        self.streams
            .get(&stream_id)
            .map(|info| size <= info.window)
            .unwrap_or(false)
    }

    pub fn get_optimal_chunk_size(&self, stream_id: u64) -> u32 {
        self.streams
            .get(&stream_id)
            .map(|info| {
                let chunk = self.base_chunk + info.priority as u32 * 100;
                info.window.min(chunk).max(1)
            })
            .unwrap_or(0)
    }
}

/// Very small BBRv2 inspired congestion controller used for tests.
#[derive(Default)]
pub struct BbrCongestionController {
    cwnd: u64,
    min_cwnd: u64,
    max_cwnd: u64,
}

impl BbrCongestionController {
    /// Create a controller with sane default limits.
    pub fn new() -> Self {
        Self {
            cwnd: 10_000,
            min_cwnd: 4_000,
            max_cwnd: 200_000,
        }
    }

    /// Congestion window in bytes.
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Update internal state when packets are acknowledged.
    pub fn on_packet_acknowledged(&mut self, bytes: u64) {
        let inc = bytes.min(self.cwnd / 2);
        self.cwnd = (self.cwnd + inc).min(self.max_cwnd);
    }

    /// React to packet loss events.
    pub fn on_packet_lost(&mut self) {
        self.cwnd = (self.cwnd / 2).max(self.min_cwnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructible() {
        let cfg = QuicConfig {
            server_name: "localhost".into(),
            port: 443,
        };
        let conn = QuicConnection::new(cfg);
        assert!(conn.is_ok());
    }

    #[test]
    fn has_probe_methods() {
        let mut mgr = PathMtuManager::new();
        let id = mgr.send_probe(1200, false);
        mgr.handle_probe_response(id, true, false);
    }
}
