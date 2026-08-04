//! QuicFuscate Client Implementation
//!
//! This module provides the production-ready client implementation with:
//! - TUN device integration
//! - QUIC connection management
//! - Packet I/O driver
//! - Stealth and FEC processing
//!
//! # Architecture
//!
//! ```text
//! Client packet flow:
//! - Outbound: TUN -> Stealth -> FEC -> QUIC
//! - Inbound:  QUIC -> FEC -> Stealth -> TUN
//! ```

mod backend;
mod connection;
mod dns_runtime;
#[cfg(test)]
mod integration;
mod io_driver;
pub mod killswitch;
pub mod platform;
pub mod profile;
pub mod quality;
mod runtime;
mod subsystems;

pub use backend::*;
pub use connection::*;
pub use dns_runtime::ClientDnsRuntime;
pub use io_driver::*;
pub use killswitch::{KillSwitch, VpnFirewallPolicy};
pub use profile::{Profile, ProfileError, ProfileManager};
pub use quality::{BandwidthTracker, Quality, QualityTracker};
pub use runtime::*;

use socket2::SockRef;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::engine::{DataPlaneFault, DisconnectReason, EngineConfig, EngineError, EngineState};
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::stealth::StealthRuntimeOwner;

/// Client runtime handle for the VPN client.
///
/// This struct manages all client subsystems and provides
/// a clean interface for the Engine layer.
pub struct ClientRuntime {
    /// Configuration
    config: EngineConfig,
    /// Memory pool for zero-copy I/O
    pool: Arc<MemoryPool>,
    /// TUN interface handle
    tun: Option<Arc<parking_lot::Mutex<TunInterface>>>,
    /// QUIC connection handle
    connection: Option<ClientConnection>,
    /// UDP socket
    socket: Option<Arc<UdpSocket>>,
    /// Subsystem handles
    subsystems: Option<ClientSubsystems>,
    /// Tokio runtime handle
    runtime: Option<runtime::SharedRuntime>,
    /// Client-owned DoH proxy and system DNS lifecycle.
    dns_runtime: Option<dns_runtime::ClientDnsRuntime>,
    /// Shared owner for all stealth background workers of this generation.
    stealth_runtime: Option<Arc<StealthRuntimeOwner>>,
    /// I/O driver
    io_driver: Option<Arc<IoDriver>>,
    /// I/O task handles
    io_handles: Vec<JoinHandle<()>>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Current state
    state: ClientState,
    /// Event-driven handshake completion notification (replaces polling loop).
    handshake_event: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    /// First automatically detected connection-loss reason for the active session.
    loss_reason: Arc<parking_lot::Mutex<Option<DisconnectReason>>>,
    /// First terminal packet-data-plane fault for the active session.
    data_plane_fault: Arc<parking_lot::Mutex<Option<DataPlaneFault>>>,
}

/// Client subsystem handles (initialized during start).
pub struct ClientSubsystems {
    /// Stealth manager for obfuscation
    pub stealth: Arc<crate::stealth::StealthManager>,
}

/// Internal client state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Stopped,
    Starting,
    Running,
    Connected,
    Stopping,
    Error,
}

impl From<ClientState> for EngineState {
    fn from(state: ClientState) -> Self {
        match state {
            ClientState::Stopped => EngineState::Stopped,
            ClientState::Starting => EngineState::Starting,
            ClientState::Running => EngineState::Running,
            ClientState::Connected => EngineState::Connected,
            ClientState::Stopping => EngineState::Stopping,
            ClientState::Error => EngineState::Error,
        }
    }
}

impl ClientRuntime {
    /// Create a new client runtime from configuration.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.validate().map_err(|error| {
            EngineError::Config(format!("Invalid engine configuration: {error}"))
        })?;
        let optimize_config = config
            .optimization
            .to_runtime_config()
            .map_err(|error| EngineError::Config(format!("Optimization config error: {error}")))?;
        // Create memory pool
        let pool =
            Arc::new(MemoryPool::new(optimize_config.pool_capacity, optimize_config.block_size));
        let stealth_runtime =
            Arc::new(StealthRuntimeOwner::from_env().map_err(|error| {
                EngineError::Config(format!("Invalid Reality config: {error}"))
            })?);

        Ok(Self {
            config,
            pool,
            tun: None,
            connection: None,
            socket: None,
            subsystems: None,
            runtime: None,
            dns_runtime: None,
            stealth_runtime: Some(stealth_runtime),
            io_driver: None,
            io_handles: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            state: ClientState::Stopped,
            handshake_event: Arc::new((
                parking_lot::Mutex::new(false),
                parking_lot::Condvar::new(),
            )),
            loss_reason: Arc::new(parking_lot::Mutex::new(None)),
            data_plane_fault: Arc::new(parking_lot::Mutex::new(None)),
        })
    }

    /// Start the client runtime (opens TUN, initializes subsystems).
    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Stopped {
            return Err(EngineError::InvalidState(self.state.into(), "start (not stopped)"));
        }

        self.state = ClientState::Starting;
        self.shutdown.store(false, Ordering::SeqCst);

        if let Err(e) = crate::interface::validate_tun_runtime_requirements() {
            self.state = ClientState::Error;
            return Err(EngineError::Tun(format!("{:?}", e)));
        }

        // Open TUN interface
        let tun_config = TunConfig {
            name: if self.config.interface.tun_name.is_empty() {
                None
            } else {
                Some(self.config.interface.tun_name.clone())
            },
            ip: self.config.interface.tun_ip,
            netmask: self.config.interface.tun_netmask,
            mtu: self.config.interface.tun_mtu,
            zero_copy: self.config.interface.zero_copy,
            ip6: None,
            prefix6: None,
        };

        let tun = match TunInterface::open(tun_config, self.pool.clone()) {
            Ok(tun) => tun,
            Err(e) => {
                self.state = ClientState::Error;
                return Err(EngineError::Tun(format!("{:?}", e)));
            }
        };

        log::info!("TUN interface opened: {}", tun.name());
        self.tun = Some(Arc::new(parking_lot::Mutex::new(tun)));

        if self.runtime.is_none() {
            let runtime = match runtime::create_shared_runtime(&runtime::RuntimeConfig::default()) {
                Ok(rt) => rt,
                Err(e) => {
                    self.subsystems = None;
                    self.tun = None;
                    self.state = ClientState::Error;
                    return Err(EngineError::Internal(format!("Runtime init failed: {}", e)));
                }
            };
            self.runtime = Some(runtime);
        }

        let runtime_owner = match self.stealth_runtime.as_ref() {
            Some(owner) if !owner.is_shutdown() => owner.clone(),
            _ => match StealthRuntimeOwner::from_env() {
                Ok(owner) => {
                    let owner = Arc::new(owner);
                    self.stealth_runtime = Some(owner.clone());
                    owner
                }
                Err(error) => {
                    self.tun = None;
                    self.state = ClientState::Error;
                    return Err(EngineError::Config(format!("Invalid Reality config: {error}")));
                }
            },
        };

        // Initialize subsystems against the runtime owner before any worker starts.
        self.subsystems = match subsystems::init_subsystems_with_runtime(
            &self.config,
            Some(runtime_owner.clone()),
        ) {
            Ok(subsystems) => Some(subsystems),
            Err(e) => {
                self.tun = None;
                self.state = ClientState::Error;
                return Err(e);
            }
        };

        let Some(runtime) = self.runtime.as_ref().cloned() else {
            runtime_owner.request_shutdown();
            self.subsystems = None;
            self.tun = None;
            self.state = ClientState::Error;
            return Err(EngineError::Internal(
                "Runtime disappeared before stealth worker start".to_string(),
            ));
        };
        let start_result = {
            let _runtime_guard = runtime.enter();
            runtime_owner.start(None, Vec::new(), 0)
        };
        if let Err(error) = start_result {
            runtime_owner.request_shutdown();
            self.subsystems = None;
            self.tun = None;
            self.state = ClientState::Error;
            return Err(EngineError::Internal(format!("Stealth runtime start failed: {error}")));
        }

        self.state = ClientState::Running;
        log::info!("Client runtime started");

        Ok(())
    }

    /// Activate the client-owned DoH proxy after the VPN connection is ready.
    pub fn activate_dns(&mut self) -> Result<(), EngineError> {
        if !self.config.stealth.enable_doh || self.dns_runtime.is_some() {
            return Ok(());
        }
        let proxy_config = dns_runtime::ClientDnsRuntime::prepare(&self.config)?;
        self.activate_dns_with_config(proxy_config)
    }

    /// Activate the client-owned DoH proxy from a pre-resolved configuration.
    pub fn activate_dns_with_config(
        &mut self,
        proxy_config: crate::dns::DnsProxyConfig,
    ) -> Result<(), EngineError> {
        if !self.config.stealth.enable_doh || self.dns_runtime.is_some() {
            return Ok(());
        }
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "activate DNS (must be connected)",
            ));
        }

        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        let tun_name =
            self.tun_name().ok_or_else(|| EngineError::Tun("TUN not initialized".to_string()))?;
        let dns_runtime = dns_runtime::ClientDnsRuntime::start_with_config(
            runtime.handle(),
            proxy_config,
            &tun_name,
        )?;
        self.dns_runtime = Some(dns_runtime);
        Ok(())
    }

    /// Restore the prior system DNS configuration and stop the client proxy.
    pub fn deactivate_dns(&mut self) -> Result<(), EngineError> {
        let Some(mut dns_runtime) = self.dns_runtime.take() else {
            return Ok(());
        };
        let runtime = match self.runtime.as_ref().cloned() {
            Some(runtime) => runtime,
            None => {
                self.dns_runtime = Some(dns_runtime);
                return Err(EngineError::Internal(
                    "Runtime not initialized while stopping client DNS proxy".to_string(),
                ));
            }
        };

        match dns_runtime.stop(&runtime) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.dns_runtime = Some(dns_runtime);
                Err(error)
            }
        }
    }

    /// Stop the client runtime.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        if self.state == ClientState::Stopped {
            return Ok(());
        }
        if self.state == ClientState::Connected {
            if let Err(error) = self.disconnect() {
                self.state = ClientState::Error;
                return Err(error);
            }
        }
        if self.dns_runtime.is_some() {
            if let Err(error) = self.deactivate_dns() {
                self.state = ClientState::Error;
                return Err(error);
            }
        }

        self.state = ClientState::Stopping;
        self.shutdown.store(true, Ordering::SeqCst);

        if let Some(io_driver) = self.io_driver.as_ref() {
            io_driver.shutdown();
        }
        let worker_join_error: Option<String> = {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                self.io_driver.as_ref().and_then(|io_driver| io_driver.join_io_uring_worker().err())
            }
            #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
            {
                None
            }
        };

        // Close connection first
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"Client shutdown");
            log::info!("QUIC connection closed");
        }
        self.socket = None;
        self.io_handles.clear();
        self.io_driver = None;

        // Close subsystems
        self.subsystems = None;

        if let Some(owner) = self.stealth_runtime.as_ref() {
            if let Some(runtime) = self.runtime.as_ref() {
                match runtime
                    .block_on(owner.shutdown(crate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT))
                {
                    Ok(report) => log::debug!(
                        "Client stealth runtime generation {} stopped: joined={}, force_stopped={}",
                        report.generation,
                        report.workers_joined,
                        report.workers_force_stopped
                    ),
                    Err(error) => log::warn!("Client stealth runtime shutdown failed: {}", error),
                }
            } else {
                owner.request_shutdown();
            }
        }

        // Close TUN
        if let Some(tun) = self.tun.take() {
            let name = tun.lock().name().to_string();
            log::info!("Closing TUN interface: {}", name);
        }

        if let Some(error) = worker_join_error {
            self.state = ClientState::Error;
            return Err(EngineError::Internal(format!(
                "Client io_uring worker join failed: {error}"
            )));
        }

        self.state = ClientState::Stopped;
        log::info!("Client runtime stopped");
        Ok(())
    }

    fn rollback_failed_connect(&mut self) {
        if let Some(io_driver) = &self.io_driver {
            io_driver.shutdown();
        }
        let handles = std::mem::take(&mut self.io_handles);
        for handle in &handles {
            handle.abort();
        }
        if let Some(runtime) = self.runtime.as_ref() {
            runtime.block_on(async {
                for handle in handles {
                    if let Err(error) = handle.await {
                        if !error.is_cancelled() {
                            log::warn!(
                                "Client I/O task join failed during connect rollback: {}",
                                error
                            );
                        }
                    }
                }
            });
        }
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        if let Some(io_driver) = self.io_driver.as_ref() {
            if let Err(error) = io_driver.join_io_uring_worker() {
                log::warn!("Client io_uring worker join failed during connect rollback: {error}");
            }
        }
        if let Some(mut connection) = self.connection.take() {
            connection.close(0, b"Connect setup failed");
            log::info!("QUIC connection closed after failed connect");
        }
        self.socket = None;
        self.io_driver = None;
        self.state = ClientState::Running;
    }

    /// Connect to the remote server.
    pub fn connect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Running {
            return Err(EngineError::InvalidState(self.state.into(), "connect (must be running)"));
        }

        *self.loss_reason.lock() = None;
        *self.data_plane_fault.lock() = None;

        // Create QUIC connection
        let conn =
            ClientConnection::connect_with_runtime(&self.config, self.stealth_runtime.clone())?;
        let local_addr = conn.local_addr();
        let remote_addr = conn.peer_addr();
        self.connection = Some(conn);

        let runtime = match self.runtime.as_ref().cloned() {
            Some(runtime) => runtime,
            None => {
                self.rollback_failed_connect();
                return Err(EngineError::Internal("Runtime not initialized".to_string()));
            }
        };
        // `tokio::net::UdpSocket::from_std` requires an active runtime context.
        // The engine API is sync, so we must enter our runtime explicitly.
        let setup_result = {
            let _rt_guard = runtime.enter();
            (|| -> Result<(), EngineError> {
                let io_config = IoDriverConfig::default();
                let std_socket = std::net::UdpSocket::bind(local_addr)
                    .map_err(|e| EngineError::Io(format!("UDP bind failed: {}", e)))?;
                std_socket
                    .set_nonblocking(true)
                    .map_err(|e| EngineError::Io(format!("UDP nonblocking failed: {}", e)))?;
                let sock_ref = SockRef::from(&std_socket);
                if let Err(e) = sock_ref.set_recv_buffer_size(io_config.socket_buffer_size) {
                    log::debug!("UDP recv buffer size hint rejected: {}", e);
                }
                if let Err(e) = sock_ref.set_send_buffer_size(io_config.socket_buffer_size) {
                    log::debug!("UDP send buffer size hint rejected: {}", e);
                }
                std_socket
                    .connect(remote_addr)
                    .map_err(|e| EngineError::Io(format!("UDP connect failed: {}", e)))?;
                let socket = UdpSocket::from_std(std_socket)
                    .map_err(|e| EngineError::Io(format!("UDP setup failed: {}", e)))?;
                let socket = Arc::new(socket);
                self.socket = Some(socket.clone());

                let io_driver = Arc::new(IoDriver::new(io_config));
                self.io_driver = Some(io_driver.clone());
                let tun = self
                    .tun
                    .as_ref()
                    .ok_or_else(|| EngineError::Tun("TUN not initialized".to_string()))?
                    .clone();
                let shared_conn = self
                    .connection
                    .as_ref()
                    .ok_or_else(|| {
                        EngineError::Connection("Connection not initialized".to_string())
                    })?
                    .shared();

                let outbound = runtime.spawn({
                    let io_driver = io_driver.clone();
                    let tun = tun.clone();
                    let conn = shared_conn.clone();
                    let socket = socket.clone();
                    let data_plane_fault = self.data_plane_fault.clone();
                    async move {
                        if let Err(e) = io_driver.run_outbound(tun, conn, socket).await {
                            log::warn!("Client outbound I/O task exited with error: {:?}", e);
                            publish_data_plane_fault(&data_plane_fault, &io_driver, e);
                        }
                    }
                });
                // Reset handshake event for new connection attempt.
                {
                    let (lock, _) = &*self.handshake_event;
                    *lock.lock() = false;
                }
                let inbound = runtime.spawn({
                    let io_driver = io_driver.clone();
                    let tun = tun.clone();
                    let conn = shared_conn.clone();
                    let socket = socket.clone();
                    let hs_event = self.handshake_event.clone();
                    let data_plane_fault = self.data_plane_fault.clone();
                    async move {
                        if let Err(e) = io_driver.run_inbound(tun, conn, socket, hs_event).await {
                            log::warn!("Client inbound I/O task exited with error: {:?}", e);
                            publish_data_plane_fault(&data_plane_fault, &io_driver, e);
                        }
                    }
                });
                self.io_handles = vec![outbound, inbound];
                Ok(())
            })()
        };
        if let Err(error) = setup_result {
            self.rollback_failed_connect();
            return Err(error);
        }

        self.state = ClientState::Connected;
        log::info!("Connected to server");

        Ok(())
    }

    /// Start the single owner for remote-close and heartbeat-loss detection.
    ///
    /// The watchdog samples every 50 ms, so a timeout transition reaches the
    /// firewall no later than 50 ms after the configured deadline under a
    /// normally scheduled runtime.
    pub fn start_loss_watchdog(
        &mut self,
        timeout: std::time::Duration,
        on_loss: Arc<dyn Fn(DisconnectReason) + Send + Sync>,
    ) -> Result<(), EngineError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        let connection = self
            .connection
            .as_ref()
            .ok_or_else(|| EngineError::Connection("Connection not initialized".to_string()))?
            .shared();
        let io_driver = self
            .io_driver
            .as_ref()
            .ok_or_else(|| EngineError::Internal("I/O driver not initialized".to_string()))?
            .clone();
        let loss_reason = self.loss_reason.clone();
        let data_plane_fault = self.data_plane_fault.clone();

        let watchdog = runtime.spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(50));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Some(fault) = data_plane_fault.lock().clone() {
                    let reason = DisconnectReason::DataPlane(fault);
                    {
                        let mut stored = loss_reason.lock();
                        if stored.is_some() {
                            break;
                        }
                        *stored = Some(reason.clone());
                    }
                    io_driver.shutdown();
                    on_loss(reason);
                    break;
                }
                let detected = {
                    let guard = connection.lock();
                    classify_connection_loss(
                        guard.conn.is_closed(),
                        guard.conn.last_activity_elapsed(),
                        timeout,
                    )
                };
                let Some(reason) = detected else {
                    continue;
                };
                {
                    let mut stored = loss_reason.lock();
                    if stored.is_some() {
                        break;
                    }
                    *stored = Some(reason.clone());
                }
                io_driver.shutdown();
                on_loss(reason);
                break;
            }
        });
        self.io_handles.push(watchdog);
        Ok(())
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "disconnect (must be connected)",
            ));
        }

        self.deactivate_dns()?;

        if let Some(io) = &self.io_driver {
            io.shutdown();
        }
        if let Some(rt) = self.runtime.as_ref() {
            let handles = std::mem::take(&mut self.io_handles);
            for handle in &handles {
                handle.abort();
            }
            rt.block_on(async move {
                for handle in handles {
                    if let Err(e) = handle.await {
                        if e.is_cancelled() {
                            log::debug!("Client I/O task cancelled during disconnect");
                        } else {
                            log::warn!("Client I/O task join failed: {}", e);
                        }
                    }
                }
            });
        }
        let worker_join_error: Option<String> = {
            #[cfg(all(target_os = "linux", feature = "io_uring"))]
            {
                self.io_driver.as_ref().and_then(|io_driver| io_driver.join_io_uring_worker().err())
            }
            #[cfg(not(all(target_os = "linux", feature = "io_uring")))]
            {
                None
            }
        };
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"Disconnect requested");
            log::info!("Disconnected from server");
        }
        self.socket = None;
        self.io_driver = None;

        self.state = ClientState::Running;
        worker_join_error.map_or(Ok(()), |error| {
            self.state = ClientState::Error;
            Err(EngineError::Internal(format!("Client io_uring worker join failed: {error}")))
        })
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected && self.connection.is_some()
    }

    /// Check whether the transport handshake is fully established.
    pub fn is_handshake_established(&self) -> bool {
        if self.state != ClientState::Connected {
            return false;
        }
        self.connection.as_ref().map(|conn| conn.is_established()).unwrap_or(false)
    }

    /// Block until the handshake completes or the deadline expires.
    /// Returns `true` if handshake completed, `false` on timeout.
    pub fn wait_handshake(&self, deadline: std::time::Instant) -> bool {
        let (lock, cvar) = &*self.handshake_event;
        let mut established = lock.lock();
        while !*established {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let result = cvar.wait_for(&mut established, remaining);
            if result.timed_out() {
                return *established;
            }
        }
        true
    }

    /// Get connection reference (if connected).
    pub fn connection(&self) -> Option<&ClientConnection> {
        self.connection.as_ref()
    }

    /// Return the automatic connection-loss reason, if the watchdog fired.
    pub fn connection_loss_reason(&self) -> Option<DisconnectReason> {
        self.loss_reason.lock().clone()
    }

    /// Return the first terminal data-plane fault for the active session.
    pub fn data_plane_fault(&self) -> Option<DataPlaneFault> {
        self.data_plane_fault.lock().clone()
    }

    /// Return whether the client packet data plane is currently available.
    pub fn data_plane_available(&self) -> bool {
        self.is_connected() && self.data_plane_fault().is_none()
    }

    /// Snapshot I/O-driver data-plane counters for engine telemetry.
    pub fn io_driver_stats(&self) -> Option<IoDriverStatsSnapshot> {
        self.io_driver.as_ref().map(|driver| driver.stats().snapshot())
    }

    /// Get mutable connection reference.
    pub fn connection_mut(&mut self) -> Option<&mut ClientConnection> {
        self.connection.as_mut()
    }

    /// Retain an accepted FEC policy for the next connection or reconnect.
    pub fn set_next_fec_mode(&mut self, mode: crate::engine::FecMode) {
        self.config.fec.mode = mode;
    }

    /// Replace the validated configuration projection used by the next
    /// connection or reconnect. The active connection keeps its immutable
    /// transport and stealth construction snapshot, except for explicit
    /// active FEC control handled by the engine.
    pub(crate) fn update_next_config(&mut self, config: &EngineConfig) -> Result<(), EngineError> {
        config.validate().map_err(|error| {
            EngineError::Config(format!("Invalid engine configuration: {error}"))
        })?;
        self.config = config.clone();
        Ok(())
    }

    /// Expose the next-connection projection to crate-level control-plane
    /// tests without exposing mutable runtime configuration.
    #[cfg(test)]
    pub(crate) fn next_config(&self) -> &EngineConfig {
        &self.config
    }

    /// Return the policy that will construct the next connection.
    pub fn next_fec_mode(&self) -> crate::engine::FecMode {
        self.config.fec.mode
    }

    /// Get current state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Get TUN interface name (if open).
    pub fn tun_name(&self) -> Option<String> {
        self.tun.as_ref().map(|t| t.lock().name().to_string())
    }

    /// Get memory pool reference.
    pub fn pool(&self) -> &Arc<MemoryPool> {
        &self.pool
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get subsystems reference (if initialized).
    pub fn subsystems(&self) -> Option<&ClientSubsystems> {
        self.subsystems.as_ref()
    }

    /// Get TUN handle (if open).
    pub fn tun(&self) -> Option<Arc<parking_lot::Mutex<TunInterface>>> {
        self.tun.clone()
    }
}

fn publish_data_plane_fault(
    slot: &Arc<parking_lot::Mutex<Option<DataPlaneFault>>>,
    io_driver: &IoDriver,
    error: EngineError,
) {
    let fault = match error {
        EngineError::DataPlane(fault) => fault,
        other => DataPlaneFault::TransportReceive {
            component: "client I/O task".to_string(),
            error: other.to_string(),
        },
    };
    io_driver.record_data_plane_fault();
    let mut stored = slot.lock();
    if stored.is_none() {
        *stored = Some(fault);
    }
    drop(stored);
    io_driver.shutdown();
}

fn classify_connection_loss(
    remote_closed: bool,
    idle: std::time::Duration,
    timeout: std::time::Duration,
) -> Option<DisconnectReason> {
    if remote_closed {
        Some(DisconnectReason::RemoteClosed)
    } else if !timeout.is_zero() && idle >= timeout {
        Some(DisconnectReason::Timeout)
    } else {
        None
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        if self.state != ClientState::Stopped {
            if let Err(e) = self.stop() {
                log::warn!("ClientRuntime drop-stop failed: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_runtime_new() {
        let config = EngineConfig::default();
        let runtime = ClientRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_client_runtime_rejects_invalid_engine_projection() {
        let mut config = EngineConfig::default();
        config.stealth.padding_strategy = "invalid".to_string();
        let error = match ClientRuntime::new(config) {
            Ok(_) => panic!("invalid stealth must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(error, EngineError::Config(_)));
    }

    #[test]
    fn connect_udp_bind_failure_rolls_back_connection_and_transport_state() {
        let blocker = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind UDP blocker");
        let blocked_addr = blocker.local_addr().expect("read UDP blocker address");
        let mut config = EngineConfig::default();
        config.connection.local = blocked_addr.to_string();

        let mut runtime = ClientRuntime::new(config).expect("client runtime");
        runtime.runtime = Some(
            runtime::create_shared_runtime(&runtime::RuntimeConfig::default())
                .expect("client runtime executor"),
        );
        runtime.state = ClientState::Running;

        let error = runtime.connect().expect_err("occupied UDP address must fail connect");
        assert!(matches!(error, EngineError::Io(message) if message.contains("UDP bind failed")));
        assert_eq!(runtime.state(), ClientState::Running);
        assert!(runtime.connection().is_none());
        assert!(runtime.socket.is_none());
        assert!(runtime.io_driver.is_none());
        assert!(runtime.io_handles.is_empty());

        let second_error = runtime.connect().expect_err("second bind must remain blocked");
        assert!(
            matches!(second_error, EngineError::Io(message) if message.contains("UDP bind failed"))
        );
        assert!(runtime.connection().is_none());
        assert!(runtime.io_handles.is_empty());

        runtime.stop().expect("failed connect must remain stoppable");
        assert_eq!(runtime.state(), ClientState::Stopped);
    }

    #[test]
    fn updated_next_config_is_consumed_by_the_following_connect_attempt() {
        let blocker = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind UDP blocker");
        let blocked_addr = blocker.local_addr().expect("read UDP blocker address");
        let mut config = EngineConfig::default();
        config.connection.local = blocked_addr.to_string();

        let mut runtime = ClientRuntime::new(EngineConfig::default()).expect("client runtime");
        runtime.update_next_config(&config).expect("update next connection config");
        runtime.runtime = Some(
            runtime::create_shared_runtime(&runtime::RuntimeConfig::default())
                .expect("client runtime executor"),
        );
        runtime.state = ClientState::Running;

        let error = runtime
            .connect()
            .expect_err("the following connect must use the updated local address");
        assert!(matches!(error, EngineError::Io(message) if message.contains("UDP bind failed")));
        assert_eq!(runtime.state(), ClientState::Running);
        assert!(runtime.connection().is_none());
    }

    #[test]
    fn connect_without_runtime_rolls_back_connection() {
        let mut runtime = ClientRuntime::new(EngineConfig::default()).expect("client runtime");
        runtime.state = ClientState::Running;

        let error = runtime.connect().expect_err("missing runtime must fail connect");
        assert!(
            matches!(error, EngineError::Internal(message) if message == "Runtime not initialized")
        );
        assert_eq!(runtime.state(), ClientState::Running);
        assert!(runtime.connection().is_none());
        assert!(runtime.socket.is_none());
        assert!(runtime.io_driver.is_none());
        assert!(runtime.io_handles.is_empty());
    }

    #[test]
    fn loss_detector_prioritizes_remote_close_and_honors_timeout_boundary() {
        assert!(matches!(
            classify_connection_loss(
                true,
                std::time::Duration::ZERO,
                std::time::Duration::from_secs(30)
            ),
            Some(DisconnectReason::RemoteClosed)
        ));
        assert!(classify_connection_loss(
            false,
            std::time::Duration::from_millis(999),
            std::time::Duration::from_secs(1)
        )
        .is_none());
        assert!(classify_connection_loss(
            false,
            std::time::Duration::from_secs(86_400),
            std::time::Duration::ZERO
        )
        .is_none());
        assert!(matches!(
            classify_connection_loss(
                false,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1)
            ),
            Some(DisconnectReason::Timeout)
        ));
    }

    // Note: TUN tests require root/admin privileges
    // They are tested in integration tests
}
