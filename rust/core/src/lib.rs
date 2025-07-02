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

/// Interval for adaptive MTU checks based on network feedback (ms).
pub const DEFAULT_ADAPTIVE_CHECK_INTERVAL_MS: u32 = 10_000;
/// Periodic probe interval after MTU was validated (ms).
pub const DEFAULT_PERIODIC_PROBE_INTERVAL_MS: u32 = 60_000;
/// Expiry for outstanding probes when no response is seen (ms).
pub const DEFAULT_PROBE_TIMEOUT_MS: u32 = 2_000;
/// Number of consecutive probe failures before assuming a black hole.
pub const DEFAULT_PATH_BLACKHOLE_THRESHOLD: u8 = 3;

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
    min_mtu: u16,
    max_mtu: u16,
    step: u16,
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
    probe_timeout_ms: u32,
    periodic_probe_interval_ms: u32,
    callback: Option<Box<dyn Fn(MtuChange) + Send + Sync>>,
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
            last_outgoing_probe: None,
            last_incoming_probe: None,
            outgoing_failures: 0,
            incoming_failures: 0,
            blackhole_threshold: DEFAULT_PATH_BLACKHOLE_THRESHOLD,
            probe_timeout_ms: DEFAULT_PROBE_TIMEOUT_MS,
            periodic_probe_interval_ms: DEFAULT_PERIODIC_PROBE_INTERVAL_MS,
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
                    let new_mtu = size.min(self.max_mtu);
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

    fn maybe_send_probe(&mut self, now: Instant, incoming: bool) {
        let (last_probe, mtu) = if incoming {
            (self.last_incoming_probe, self.incoming_mtu)
        } else {
            (self.last_outgoing_probe, self.outgoing_mtu)
        };

        if mtu >= self.max_mtu {
            return;
        }

        let needs_probe = last_probe
            .map(|t| now.duration_since(t).as_millis() as u32 >= self.periodic_probe_interval_ms)
            .unwrap_or(true);
        if needs_probe {
            let probe_size = (mtu + self.step).min(self.max_mtu);
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
        let timeout = self.probe_timeout_ms;
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
        let success = size <= self.max_mtu;
        let old = self.incoming_mtu;
        if success {
            self.incoming_mtu = size.min(self.max_mtu);
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
