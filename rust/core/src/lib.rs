use thiserror::Error;

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

/// Default minimum MTU recommended by RFC 8899.
pub const DEFAULT_MIN_MTU: u16 = 1200;
/// Typical Ethernet MTU used as an upper bound for probing.
pub const DEFAULT_MAX_MTU: u16 = 1500;
/// Common starting MTU before the path has been validated.
pub const DEFAULT_INITIAL_MTU: u16 = 1350;
/// Increment used when probing for a larger MTU.
pub const DEFAULT_MTU_STEP_SIZE: u16 = 10;

/// Basic configuration for a QUIC connection.
#[derive(Clone, Debug)]
pub struct QuicConfig {
    pub server_name: String,
    pub port: u16,
}

/// Simple QUIC connection wrapper used for testing the Rust port.
pub struct QuicConnection {
    config: QuicConfig,
    mtu_discovery: bool,
    migration: bool,
    bbr: bool,
    zero_copy: bool,
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
    pub fn new(config: QuicConfig) -> Result<Self, CoreError> {
        Ok(Self {
            config,
            mtu_discovery: false,
            migration: false,
            bbr: false,
            zero_copy: false,
        })
    }

    /// Connect to the provided address. For the stub this always succeeds.
    pub fn connect(&self, _addr: &str) -> Result<(), CoreError> {
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

    /// Enable or disable the BBRv2 congestion control algorithm.
    pub fn enable_bbr_congestion_control(&mut self, enable: bool) {
        self.bbr = enable;
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
}

/// Manager for sending and validating MTU probes.
use std::collections::HashMap;

/// Status of MTU discovery on a path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtuStatus {
    Disabled,
    Searching,
    Validating,
    Blackhole,
    Complete,
}

/// Manager for sending and validating MTU probes.
pub struct PathMtuManager {
    outgoing_mtu: u16,
    incoming_mtu: u16,
    min_mtu: u16,
    max_mtu: u16,
    step: u16,
    bidirectional: bool,
    next_probe_id: u32,
    probes: HashMap<u32, (bool, u16)>,
    outgoing_status: MtuStatus,
    incoming_status: MtuStatus,
}

impl PathMtuManager {
    pub fn new() -> Self {
        Self {
            outgoing_mtu: DEFAULT_INITIAL_MTU,
            incoming_mtu: DEFAULT_INITIAL_MTU,
            min_mtu: DEFAULT_MIN_MTU,
            max_mtu: DEFAULT_MAX_MTU,
            step: DEFAULT_MTU_STEP_SIZE,
            bidirectional: false,
            next_probe_id: 0,
            probes: HashMap::new(),
            outgoing_status: MtuStatus::Disabled,
            incoming_status: MtuStatus::Disabled,
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
        self.min_mtu = min_mtu;
        self.max_mtu = max_mtu;
        self.step = step;
        if apply_both {
            self.incoming_mtu = min_mtu;
            self.outgoing_mtu = min_mtu;
        }
    }

    /// Send a probe of the given size. Returns a probe identifier.
    pub fn send_probe(&mut self, size: u16, incoming: bool) -> u32 {
        self.next_probe_id += 1;
        self.probes.insert(self.next_probe_id, (incoming, size));
        self.next_probe_id
    }

    /// Handle the result of a previously sent probe.
    pub fn handle_probe_response(&mut self, id: u32, success: bool, incoming: bool) {
        if let Some((probe_incoming, size)) = self.probes.remove(&id) {
            if probe_incoming == incoming && success {
                if incoming {
                    self.incoming_mtu = size.min(self.max_mtu);
                    self.incoming_status = MtuStatus::Complete;
                } else {
                    self.outgoing_mtu = size.min(self.max_mtu);
                    self.outgoing_status = MtuStatus::Complete;
                }
            }
        }
    }

    /// Simple dynamic adjustment based on observed loss and RTT.
    pub fn adapt_mtu_dynamically(&mut self, packet_loss_rate: f32, rtt_ms: u32) {
        if packet_loss_rate > 0.1 {
            let new_mtu = self.outgoing_mtu.saturating_sub(self.step);
            self.outgoing_mtu = new_mtu.max(self.min_mtu);
        } else if packet_loss_rate == 0.0 && rtt_ms < 100 {
            let new_mtu = self.outgoing_mtu.saturating_add(self.step);
            self.outgoing_mtu = new_mtu.min(self.max_mtu);
        }

        if self.bidirectional {
            self.incoming_mtu = self.outgoing_mtu;
        }
    }
}

pub struct StreamOptimizationConfig;

pub struct QuicStreamOptimizer;

impl QuicStreamOptimizer {
    pub fn new() -> Self {
        Self
    }

    pub fn initialize(&mut self, _cfg: StreamOptimizationConfig) -> bool {
        true
    }

    pub fn set_stream_priority(&mut self, _stream_id: u64, _priority: u8) -> bool {
        true
    }

    pub fn update_flow_control_window(&mut self, _stream_id: u64, _size: u32) -> bool {
        true
    }

    pub fn can_send_data(&self, _stream_id: u64, _size: u32) -> bool {
        true
    }

    pub fn get_optimal_chunk_size(&self, _stream_id: u64) -> u32 {
        1
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
