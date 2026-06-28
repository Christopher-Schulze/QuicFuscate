//! Client connection wrapper for QuicFuscateConnection.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::core::QuicFuscateConnection;
use crate::engine::{EngineConfig, EngineError};

/// Client connection wrapper.
///
/// Wraps `QuicFuscateConnection` and provides a streamlined interface
/// for the client runtime.
pub struct ClientConnection {
    inner: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl ClientConnection {
    /// Create a new client connection from engine configuration.
    pub fn connect(config: &EngineConfig) -> Result<Self, EngineError> {
        // Record connection attempt
        crate::instrumentation::global().client.connection_attempt();

        // Parse addresses
        let remote_addr: SocketAddr = config.connection.remote.parse().map_err(|e| {
            crate::instrumentation::global().client.connection_failure();
            EngineError::Config(format!("Invalid remote address: {}", e))
        })?;

        let local_addr: SocketAddr = if config.connection.local.is_empty() {
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0))
        } else {
            config.connection.local.parse().map_err(|e| {
                crate::instrumentation::global().client.connection_failure();
                EngineError::Config(format!("Invalid local address: {}", e))
            })?
        };

        // Build transport config
        let transport_config = Self::build_transport_config(config)?;

        // Build stealth config from EngineConfig
        let stealth_config = Self::build_stealth_config(config);

        // Build FEC config
        let fec_config = Self::build_fec_config(config);

        // Build optimization config
        let opt_config = Self::build_optimize_config(config);

        // Determine SNI
        let sni = if config.connection.sni.is_empty() {
            // Extract hostname from remote
            config.connection.remote.split(':').next().unwrap_or("localhost").to_string()
        } else {
            config.connection.sni.clone()
        };

        log::info!("Connecting to {} (SNI: {}) from {}", remote_addr, sni, local_addr);

        // Create QUIC connection using core.rs
        let qkey_token = config.connection.qkey_token.clone().filter(|t| !t.trim().is_empty());
        let qkey_initial_token: Option<Vec<u8>> =
            qkey_token.as_deref().map(|raw| crate::engine::qkey::id(raw.trim()).into_bytes());
        let conn = QuicFuscateConnection::new_client(
            &sni,
            local_addr,
            remote_addr,
            transport_config,
            stealth_config,
            fec_config,
            opt_config,
            qkey_token,
            qkey_initial_token,
            false, // use_utls
        )
        .map_err(|e| {
            crate::instrumentation::global().client.connection_failure();
            EngineError::Connection(e)
        })?;

        // Record success
        crate::instrumentation::global().client.connection_success();
        log::info!("QUIC connection established to {}", remote_addr);

        Ok(Self { inner: Arc::new(parking_lot::Mutex::new(conn)), remote_addr, local_addr })
    }

    /// Send data through the QUIC connection.
    ///
    /// Returns the number of bytes written to the buffer.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.send(buf).map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }

    /// Receive data from the QUIC connection.
    ///
    /// Returns the number of bytes processed.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, EngineError> {
        let mut guard = self.inner.lock();
        guard.recv(data).map_err(|e| EngineError::Connection(format!("{:?}", e)))
    }

    /// Get the remote peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the stealth manager for dynamic configuration.
    pub fn stealth_manager(&self) -> Arc<crate::stealth::StealthManager> {
        let guard = self.inner.lock();
        guard.stealth_manager()
    }

    /// Get the underlying connection (for advanced usage).
    pub fn shared(&self) -> Arc<parking_lot::Mutex<QuicFuscateConnection>> {
        self.inner.clone()
    }

    /// Check if the connection is established.
    pub fn is_established(&self) -> bool {
        let guard = self.inner.lock();
        guard.conn.is_established()
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        let guard = self.inner.lock();
        guard.conn.is_closed()
    }

    /// Get RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        let guard = self.inner.lock();
        guard.rtt_ms()
    }

    /// Get packet loss rate.
    pub fn loss_rate(&self) -> f32 {
        let guard = self.inner.lock();
        guard.loss_rate()
    }

    /// Get the effective stealth mode currently used by the live connection.
    pub fn stealth_mode(&self) -> crate::stealth::StealthMode {
        let guard = self.inner.lock();
        guard.stealth_mode()
    }

    /// Get the effective TLS SNI currently used by the live connection.
    pub fn server_name(&self) -> Option<String> {
        let guard = self.inner.lock();
        guard.server_name()
    }

    /// Close the connection gracefully.
    pub fn close(&mut self, app_error: u64, reason: &[u8]) {
        let mut guard = self.inner.lock();
        if let Err(e) = guard.conn.close(false, app_error, reason) {
            log::warn!(
                "Connection close returned error (app_error={}, reason={:?}): {:?}",
                app_error,
                reason,
                e
            );
        }
        log::info!("Connection closed: error={}, reason={:?}", app_error, reason);
    }

    // ========================================================================
    // Config builders
    // ========================================================================

    fn build_transport_config(
        config: &EngineConfig,
    ) -> Result<crate::transport::Config, EngineError> {
        let mut tc = crate::transport::Config::new_with_version(crate::transport::PROTOCOL_VERSION)
            .map_err(|e| EngineError::Config(format!("Transport config error: {:?}", e)))?;

        tc.set_max_idle_timeout(config.transport.max_idle_timeout);
        tc.set_initial_max_data(config.transport.initial_max_data);
        tc.set_initial_max_stream_data_bidi_local(
            config.transport.initial_max_stream_data_bidi_local,
        );
        tc.set_initial_max_stream_data_bidi_remote(
            config.transport.initial_max_stream_data_bidi_remote,
        );
        tc.set_initial_max_streams_bidi(config.transport.initial_max_streams_bidi);
        tc.set_initial_max_stream_data_uni(config.transport.initial_max_stream_data_uni);
        tc.set_initial_max_streams_uni(config.transport.initial_max_streams_uni);

        if config.transport.dgram_recv_queue_len > 0 {
            tc.enable_dgram(
                config.transport.dgram_recv_queue_len,
                config.transport.dgram_send_queue_len,
            );
        }

        // Enable early data if configured
        if config.transport.enable_early_data {
            tc.enable_early_data();
        }

        if let Some(id) = config.connection.qkey_id.as_deref() {
            let id = id.trim();
            if !id.is_empty() {
                tc.set_initial_token(Some(id.as_bytes().to_vec()));
            }
        }

        // CC algorithm
        match config.transport.cc_algorithm {
            crate::engine::CcAlgorithm::Reno => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::Reno)
            }
            crate::engine::CcAlgorithm::Bbr2 => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::BBR2)
            }
            crate::engine::CcAlgorithm::Bbr3 => {
                tc.set_cc_algorithm(crate::transport::CongestionControlAlgorithm::BBR3)
            }
        }

        Ok(tc)
    }

    fn build_stealth_config(config: &EngineConfig) -> crate::stealth::StealthConfig {
        crate::stealth::StealthConfig {
            enable_domain_fronting: config.stealth.enable_domain_fronting,
            enable_http3_masquerading: config.stealth.enable_http3_masquerading,
            use_tls_cover: config.stealth.use_tls_cover,
            use_qpack_headers: config.stealth.use_qpack_headers,
            enable_traffic_padding: config.stealth.enable_traffic_padding,
            enable_timing_obfuscation: config.stealth.enable_timing_obfuscation,
            enable_protocol_mimicry: config.stealth.enable_protocol_mimicry,
            enable_doh: config.stealth.enable_doh,
            doh_provider: config.stealth.doh_provider.clone(),
            max_padding_size: config.stealth.max_padding_size,
            fronting_domains: config.stealth.fronting_domains.clone(),
            ..Default::default()
        }
    }

    fn build_fec_config(config: &EngineConfig) -> crate::fec::FecConfig {
        crate::fec::FecConfig::from_engine_section(&config.fec)
    }

    fn build_optimize_config(config: &EngineConfig) -> crate::optimize::OptimizeConfig {
        crate::optimize::OptimizeConfig {
            pool_capacity: config.optimization.memory_pool_size
                / config.optimization.memory_pool_alignment.max(1),
            block_size: config.optimization.memory_pool_alignment.max(65536),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_configs() {
        let config = EngineConfig::default();

        let tc = ClientConnection::build_transport_config(&config);
        assert!(tc.is_ok());

        let sc = ClientConnection::build_stealth_config(&config);
        assert!(sc.max_padding_size > 0);

        let fc = ClientConnection::build_fec_config(&config);
        assert!(fc.burst_window > 0);

        let oc = ClientConnection::build_optimize_config(&config);
        assert!(oc.pool_capacity > 0);
    }
}
