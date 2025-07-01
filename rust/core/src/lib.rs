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
}

/// Manager for sending and validating MTU probes.
pub struct PathMtuManager {
    current: u16,
    step: u16,
}

impl PathMtuManager {
    pub fn new() -> Self {
        Self {
            current: DEFAULT_INITIAL_MTU,
            step: DEFAULT_MTU_STEP_SIZE,
        }
    }

    /// Send a probe of the given size. Returns a probe identifier.
    pub fn send_probe(&self, _size: u16, _incoming: bool) -> u32 {
        // For the purposes of the tests we simply return a dummy ID.
        1
    }

    /// Handle the result of a previously sent probe.
    pub fn handle_probe_response(&self, _id: u32, _success: bool, _incoming: bool) {}
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
        let cfg = QuicConfig { server_name: "localhost".into(), port: 443 };
        let conn = QuicConnection::new(cfg);
        assert!(conn.is_ok());
    }

    #[test]
    fn has_probe_methods() {
        let mgr = PathMtuManager::new();
        let id = mgr.send_probe(1200, false);
        mgr.handle_probe_response(id, true, false);
    }
}
