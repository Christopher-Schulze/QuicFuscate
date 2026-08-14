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
mod circuit_runtime;
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
#[cfg(test)]
mod tests;

pub use backend::*;
pub use circuit_runtime::{CircuitDiagnostics, CircuitHopDiagnostics, CircuitLifecycleState};
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

use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;
use crate::stealth::StealthRuntimeOwner;
use crate::time_source::ProtocolClock;
use qf_engine_types::{DataPlaneFault, DisconnectReason, EngineConfig, EngineError, EngineState};

const TRANSPORT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Client runtime handle for the VPN client.
///
/// This struct manages all client subsystems and provides
/// a clean interface for the Engine layer.
pub struct ClientRuntime {
    /// Configuration
    config: EngineConfig,
    /// Clock shared by client policy and connection state.
    clock: ProtocolClock,
    /// Memory pool for zero-copy I/O
    pool: Arc<MemoryPool>,
    /// TUN interface handle
    tun: Option<Arc<parking_lot::Mutex<TunInterface>>>,
    /// Assignment accepted for the active authenticated connection.
    assignment: Option<crate::control_plane::ClientAssignment>,
    /// Monotonic client-side reconnect generation.
    connection_generation: u64,
    /// H3 stream that owns framed tunnel fallback packets.
    tunnel_stream_id: Option<u64>,
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
    /// Watchdog contract retained across make-before-break generations.
    loss_watchdog: Option<LossWatchdogRegistration>,
    /// Fully authenticated replacement kept live without TUN ownership.
    standby_transport: Option<StandbyClientTransport>,
}

/// Client subsystem handles (initialized during start).
pub struct ClientSubsystems {
    /// Stealth manager for obfuscation
    pub stealth: Arc<crate::stealth::StealthManager>,
}

struct PreparedClientTransport {
    generation: u64,
    connection: ClientConnection,
    socket: Arc<UdpSocket>,
    assignment: crate::control_plane::ClientAssignment,
    tunnel_stream_id: u64,
    ingress: ClientTunnelIngress,
    io_driver: Arc<IoDriver>,
}

struct StandbyClientTransport {
    config: EngineConfig,
    prepared: PreparedClientTransport,
    handle: JoinHandle<()>,
    fault: Arc<parking_lot::Mutex<Option<DataPlaneFault>>>,
}

#[derive(Clone)]
struct LossWatchdogRegistration {
    timeout: std::time::Duration,
    on_loss: Arc<dyn Fn(DisconnectReason) + Send + Sync>,
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

pub fn tun_config_from_assignment(
    assignment: &crate::control_plane::ClientAssignment,
    name: Option<String>,
    zero_copy: bool,
) -> Result<TunConfig, EngineError> {
    if assignment.mode != crate::control_plane::AssignmentMode::Enabled {
        return Err(EngineError::Tun(
            "server explicitly disabled client TUN activation".to_string(),
        ));
    }
    let addresses = qf_engine_types::ClientTunnelAddresses {
        ipv4: assignment.ipv4.map(|address| qf_engine_types::ClientTunnelIpv4 {
            address: address.address,
            prefix: address.prefix,
        }),
        ipv6: assignment.ipv6.map(|address| qf_engine_types::ClientTunnelIpv6 {
            address: address.address,
            prefix: address.prefix,
        }),
    };
    Ok(addresses.to_tun_config(name, assignment.mtu, zero_copy))
}

#[cfg(test)]
fn client_tun_config(config: &EngineConfig) -> Result<TunConfig, EngineError> {
    let addresses = config.interface.client_tunnel_addresses().map_err(|error| {
        EngineError::Config(format!("Invalid client tunnel address configuration: {error}"))
    })?;
    let name = if config.interface.tun_name.is_empty() {
        None
    } else {
        Some(config.interface.tun_name.clone())
    };
    Ok(addresses.to_tun_config(name, config.interface.tun_mtu, config.interface.zero_copy))
}

fn client_tun_config_from_assignment(
    config: &EngineConfig,
    assignment: &crate::control_plane::ClientAssignment,
) -> Result<TunConfig, EngineError> {
    let name = if config.interface.tun_name.is_empty() {
        None
    } else {
        Some(config.interface.tun_name.clone())
    };
    tun_config_from_assignment(assignment, name, config.interface.zero_copy)
}

impl ClientRuntime {
    /// Create a new client runtime from configuration.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        Self::new_with_clock(config, ProtocolClock::default())
    }

    /// Create a client runtime bound to an explicit protocol clock.
    pub fn new_with_clock(config: EngineConfig, clock: ProtocolClock) -> Result<Self, EngineError> {
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
            clock,
            pool,
            tun: None,
            assignment: None,
            connection_generation: 0,
            tunnel_stream_id: None,
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
            loss_watchdog: None,
            standby_transport: None,
        })
    }

    /// Start the client runtime and initialize subsystems without opening TUN.
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

        if self.runtime.is_none() {
            let runtime = match runtime::create_shared_runtime(&runtime::RuntimeConfig::default()) {
                Ok(rt) => rt,
                Err(e) => {
                    self.subsystems = None;
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
                    self.state = ClientState::Error;
                    return Err(EngineError::Config(format!("Invalid Reality config: {error}")));
                }
            },
        };

        let stealth_config =
            match self.config.stealth.to_runtime_config(&self.config.fingerprint_rotation) {
                Ok(config) => config,
                Err(error) => {
                    runtime_owner.request_shutdown();
                    self.state = ClientState::Error;
                    return Err(EngineError::Config(format!("Stealth config error: {error}")));
                }
            };
        let profiles = stealth_config.rotation_profiles();
        let profile_interval_secs = stealth_config.fingerprint_rotation_interval;
        let should_rotate = profiles.len() > 1 && profile_interval_secs > 0;
        let shared_stealth_config = Arc::new(std::sync::Mutex::new(stealth_config));

        // Initialize subsystems against the runtime owner before any worker starts.
        self.subsystems = match subsystems::init_subsystems_with_runtime_and_clock(
            &self.config,
            Some(runtime_owner.clone()),
            &self.clock,
        ) {
            Ok(subsystems) => Some(subsystems),
            Err(e) => {
                self.state = ClientState::Error;
                return Err(e);
            }
        };

        let Some(runtime) = self.runtime.as_ref().cloned() else {
            runtime_owner.request_shutdown();
            self.subsystems = None;
            self.state = ClientState::Error;
            return Err(EngineError::Internal(
                "Runtime disappeared before stealth worker start".to_string(),
            ));
        };
        let start_result = {
            let _runtime_guard = runtime.enter();
            runtime_owner.start(
                Some(shared_stealth_config),
                if should_rotate { profiles } else { Vec::new() },
                if should_rotate { profile_interval_secs } else { 0 },
            )
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
        let dns_runtime = dns_runtime::ClientDnsRuntime::start_with_config_and_clock(
            runtime.handle(),
            proxy_config,
            &tun_name,
            &self.clock,
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
                match runtime::block_on(
                    runtime,
                    owner.shutdown(crate::stealth::STEALTH_RUNTIME_SHUTDOWN_TIMEOUT),
                ) {
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

    fn next_connection_generation(&mut self) -> Result<u64, EngineError> {
        let generation = self
            .connection_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or_else(|| {
                EngineError::Internal("client connection generation exhausted".to_string())
            })?;
        self.connection_generation = generation;
        Ok(generation)
    }

    fn assignment_timeout(config: &EngineConfig) -> std::time::Duration {
        config.circuit.as_ref().map_or(std::time::Duration::from_secs(10), |circuit| {
            std::time::Duration::from_millis(
                circuit
                    .hops
                    .iter()
                    .map(|hop| hop.connect_timeout_ms)
                    .fold(5_000u64, u64::saturating_add),
            )
        })
    }

    fn prepare_transport(
        &self,
        config: &EngineConfig,
        generation: u64,
    ) -> Result<PreparedClientTransport, EngineError> {
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        let connection = ClientConnection::connect_with_runtime_and_clock(
            config,
            self.stealth_runtime.clone(),
            &self.clock,
        )?;
        let local_addr = connection.local_addr();
        let remote_addr = connection.peer_addr();
        let shared_connection = connection.shared();
        let mut connection = Some(connection);

        let setup = (|| -> Result<PreparedClientTransport, EngineError> {
            let io_config = IoDriverConfig::default();
            let std_socket = std::net::UdpSocket::bind(local_addr)
                .map_err(|error| EngineError::Io(format!("UDP bind failed: {error}")))?;
            std_socket
                .set_nonblocking(true)
                .map_err(|error| EngineError::Io(format!("UDP nonblocking failed: {error}")))?;
            let socket_ref = SockRef::from(&std_socket);
            if let Err(error) = socket_ref.set_recv_buffer_size(io_config.socket_buffer_size) {
                log::debug!("UDP recv buffer size hint rejected: {error}");
            }
            if let Err(error) = socket_ref.set_send_buffer_size(io_config.socket_buffer_size) {
                log::debug!("UDP send buffer size hint rejected: {error}");
            }
            std_socket
                .connect(remote_addr)
                .map_err(|error| EngineError::Io(format!("UDP connect failed: {error}")))?;
            let socket = {
                let _runtime_guard = runtime.enter();
                Arc::new(
                    UdpSocket::from_std(std_socket)
                        .map_err(|error| EngineError::Io(format!("UDP setup failed: {error}")))?,
                )
            };
            let io_driver = Arc::new(IoDriver::new_with_clock(io_config, &self.clock));
            let deadline =
                self.clock.checked_deadline_after(Self::assignment_timeout(config)).ok_or_else(
                    || EngineError::Connection("client assignment deadline overflow".to_string()),
                )?;
            let assignment = runtime::block_on(
                &runtime,
                io_driver.negotiate_assignment(&shared_connection, &socket, generation, deadline),
            )?;
            let ingress = ClientTunnelIngress::new();
            let tunnel_stream_id = {
                let mut connection_guard = shared_connection.lock();
                if !connection_guard.masque_tunnel_established() {
                    return Err(EngineError::Connection(
                        "server assignment arrived before MASQUE readiness".to_string(),
                    ));
                }
                let stream_id =
                    connection_guard.open_http3_stream_post("/tun").map_err(|error| {
                        EngineError::Connection(format!("client /tun stream open failed: {error}"))
                    })?;
                let callback_ingress = ingress.clone();
                connection_guard.set_masque_datagram_cb(Arc::new(std::sync::Mutex::new(Box::new(
                    move |payload: &[u8]| {
                        if !callback_ingress.push(payload) {
                            log::debug!(
                                "client MASQUE ingress queue rejected {} bytes",
                                payload.len()
                            );
                        }
                    },
                ))));
                stream_id
            };
            Ok(PreparedClientTransport {
                generation,
                connection: connection.take().ok_or_else(|| {
                    EngineError::Internal(
                        "prepared client connection ownership disappeared".to_string(),
                    )
                })?,
                socket,
                assignment,
                tunnel_stream_id,
                ingress,
                io_driver,
            })
        })();
        if setup.is_err() {
            if let Some(connection) = connection.as_mut() {
                connection.close(0, b"Transport preparation failed");
            }
        }
        setup
    }

    fn spawn_transport_tasks(
        &self,
        prepared: &PreparedClientTransport,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        runtime: &runtime::SharedRuntime,
    ) -> Vec<JoinHandle<()>> {
        let shared_connection = prepared.connection.shared();
        let outbound = runtime.spawn({
            let io_driver = prepared.io_driver.clone();
            let tun = tun.clone();
            let connection = shared_connection.clone();
            let socket = prepared.socket.clone();
            let tunnel_stream_id = prepared.tunnel_stream_id;
            let data_plane_fault = self.data_plane_fault.clone();
            async move {
                if let Err(error) =
                    io_driver.run_outbound(tun, connection, socket, tunnel_stream_id).await
                {
                    log::warn!("Client outbound I/O task exited with error: {error:?}");
                    publish_data_plane_fault(&data_plane_fault, &io_driver, error);
                }
            }
        });
        let inbound = runtime.spawn({
            let io_driver = prepared.io_driver.clone();
            let tun = tun.clone();
            let connection = shared_connection;
            let socket = prepared.socket.clone();
            let ingress = prepared.ingress.clone();
            let handshake_event = self.handshake_event.clone();
            let data_plane_fault = self.data_plane_fault.clone();
            async move {
                if let Err(error) =
                    io_driver.run_inbound(tun, connection, socket, ingress, handshake_event).await
                {
                    log::warn!("Client inbound I/O task exited with error: {error:?}");
                    publish_data_plane_fault(&data_plane_fault, &io_driver, error);
                }
            }
        });
        vec![outbound, inbound]
    }

    fn install_transport(
        &mut self,
        prepared: PreparedClientTransport,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        runtime: &runtime::SharedRuntime,
    ) {
        let handles = self.spawn_transport_tasks(&prepared, tun, runtime);
        self.connection_generation = prepared.generation;
        self.tunnel_stream_id = Some(prepared.tunnel_stream_id);
        self.assignment = Some(prepared.assignment);
        self.socket = Some(prepared.socket);
        self.io_driver = Some(prepared.io_driver);
        self.connection = Some(prepared.connection);
        self.io_handles = handles;
    }

    /// Connect to the remote server.
    pub fn connect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Running {
            return Err(EngineError::InvalidState(self.state.into(), "connect (must be running)"));
        }

        *self.loss_reason.lock() = None;
        *self.data_plane_fault.lock() = None;
        let generation = self.next_connection_generation()?;
        let config = self.config.clone();
        let mut prepared = self.prepare_transport(&config, generation)?;
        let mut tun_config = client_tun_config_from_assignment(&config, &prepared.assignment)?;
        let effective_transport_mtu =
            u16::try_from(prepared.connection.shared().lock().effective_tunnel_mtu())
                .unwrap_or(u16::MAX);
        tun_config.mtu = tun_config.mtu.min(effective_transport_mtu);
        let tun = match TunInterface::open(tun_config, self.pool.clone()) {
            Ok(tun) => Arc::new(parking_lot::Mutex::new(tun)),
            Err(error) => {
                prepared.connection.close(0, b"TUN open failed");
                return Err(EngineError::Tun(format!(
                    "server-assigned TUN open failed: {error:?}"
                )));
            }
        };
        log::info!("TUN interface opened from server assignment: {}", tun.lock().name());
        {
            let (lock, _) = &*self.handshake_event;
            *lock.lock() = false;
        }
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        self.install_transport(prepared, tun.clone(), &runtime);
        self.tun = Some(tun);

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
        let registration = LossWatchdogRegistration { timeout, on_loss };
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
        let watchdog = self.spawn_loss_watchdog(&registration, &runtime, connection, io_driver);
        self.loss_watchdog = Some(registration);
        self.io_handles.push(watchdog);
        Ok(())
    }

    fn spawn_loss_watchdog(
        &self,
        registration: &LossWatchdogRegistration,
        runtime: &runtime::SharedRuntime,
        connection: Arc<parking_lot::Mutex<circuit_runtime::ClientDataPlane>>,
        io_driver: Arc<IoDriver>,
    ) -> JoinHandle<()> {
        let loss_reason = self.loss_reason.clone();
        let data_plane_fault = self.data_plane_fault.clone();
        let timeout = registration.timeout;
        let on_loss = registration.on_loss.clone();

        runtime.spawn(async move {
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
                        guard.is_closed(),
                        guard.last_activity_elapsed(),
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
        })
    }

    fn stop_transport_tasks(&mut self, context: &str) -> Result<(), EngineError> {
        if let Some(io_driver) = self.io_driver.as_ref() {
            io_driver.shutdown();
        }
        let handles = std::mem::take(&mut self.io_handles);
        if let Some(runtime) = self.runtime.as_ref() {
            runtime::block_on(runtime, async move {
                let deadline = tokio::time::Instant::now() + TRANSPORT_DRAIN_TIMEOUT;
                for mut handle in handles {
                    match tokio::time::timeout_at(deadline, &mut handle).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) if error.is_cancelled() => {}
                        Ok(Err(error)) => {
                            log::warn!("Client I/O task join failed during {context}: {error}");
                        }
                        Err(_) => {
                            handle.abort();
                            if let Err(error) = handle.await {
                                if !error.is_cancelled() {
                                    log::warn!(
                                        "Client I/O task force-stop failed during {context}: {error}"
                                    );
                                }
                            }
                        }
                    }
                }
            });
        }
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        if let Some(io_driver) = self.io_driver.as_ref() {
            io_driver.join_io_uring_worker().map_err(|error| {
                EngineError::Internal(format!(
                    "Client io_uring worker join failed during {context}: {error}"
                ))
            })?;
        }
        Ok(())
    }

    fn validate_replacement_transport(
        &self,
        prepared: &mut PreparedClientTransport,
    ) -> Result<Arc<parking_lot::Mutex<TunInterface>>, EngineError> {
        let current_assignment = self.assignment.as_ref().ok_or_else(|| {
            EngineError::Connection("active circuit has no authenticated assignment".into())
        })?;
        if !assignments_share_tun_identity(current_assignment, &prepared.assignment) {
            prepared.connection.close(0, b"Rotation assignment mismatch");
            return Err(EngineError::Connection(
                "rotation target assignment changes TUN addresses, family order, or DNS".into(),
            ));
        }
        let tun = self
            .tun
            .as_ref()
            .ok_or_else(|| EngineError::Tun("active circuit has no TUN owner".into()))?
            .clone();
        Ok(tun)
    }

    fn reconcile_replacement_tun_mtu(
        prepared: &mut PreparedClientTransport,
        tun: &Arc<parking_lot::Mutex<TunInterface>>,
    ) -> Result<(), EngineError> {
        let current_mtu = tun.lock().mtu();
        let replacement_mtu = conservative_replacement_tun_mtu(
            current_mtu,
            prepared.connection.shared().lock().effective_tunnel_mtu(),
            prepared.assignment.mtu,
        );
        if replacement_mtu >= current_mtu {
            return Ok(());
        }
        if let Err(error) = tun.lock().set_mtu(replacement_mtu) {
            prepared.connection.close(0, b"Rotation MTU update failed");
            return Err(EngineError::Tun(format!(
                "rotation target requires TUN MTU {replacement_mtu}, but the active TUN could not apply it: {error}"
            )));
        }
        Ok(())
    }

    /// Build and continuously service one bounded alternate circuit without TUN ownership.
    pub fn prebuild_alternate_circuit(
        &mut self,
        next_config: EngineConfig,
    ) -> Result<(), EngineError> {
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "prebuild alternate circuit (must be connected)",
            ));
        }
        if self.standby_transport.is_some() {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "prebuild alternate circuit (standby already exists)",
            ));
        }
        next_config.validate().map_err(|error| {
            EngineError::Config(format!("Invalid standby configuration: {error}"))
        })?;
        for (label, circuit) in
            [("active", self.config.circuit.as_ref()), ("standby", next_config.circuit.as_ref())]
        {
            let circuit = circuit.ok_or_else(|| {
                EngineError::Config(format!(
                    "{label} configuration requires a canonical circuit for prebuild"
                ))
            })?;
            if circuit.max_parallel_circuits < 2 {
                return Err(EngineError::Config(format!(
                    "{label} circuit requires max_parallel_circuits = 2"
                )));
            }
        }

        let generation = self.next_connection_generation()?;
        let mut prepared = self.prepare_transport(&next_config, generation)?;
        self.validate_replacement_transport(&mut prepared)?;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?;
        let fault = Arc::new(parking_lot::Mutex::new(None));
        let handle = runtime.spawn({
            let io_driver = prepared.io_driver.clone();
            let connection = prepared.connection.shared();
            let socket = prepared.socket.clone();
            let ingress = prepared.ingress.clone();
            let fault = fault.clone();
            async move {
                if let Err(error) = io_driver.run_standby(connection, socket, ingress).await {
                    let failure = match error {
                        EngineError::DataPlane(failure) => failure,
                        other => DataPlaneFault::TransportReceive {
                            component: "client standby circuit".to_string(),
                            error: other.to_string(),
                        },
                    };
                    *fault.lock() = Some(failure);
                    io_driver.shutdown();
                }
            }
        });
        self.standby_transport =
            Some(StandbyClientTransport { config: next_config, prepared, handle, fault });
        log::info!("Prebuilt alternate circuit generation {generation} is ready");
        Ok(())
    }

    fn stop_standby_task(
        &self,
        standby: &mut StandbyClientTransport,
        context: &str,
    ) -> Result<(), EngineError> {
        standby.prepared.io_driver.shutdown();
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?;
        runtime::block_on(runtime, async {
            match tokio::time::timeout(TRANSPORT_DRAIN_TIMEOUT, &mut standby.handle).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) if error.is_cancelled() => {}
                Ok(Err(error)) => {
                    log::warn!("Standby task join failed during {context}: {error}");
                }
                Err(_) => {
                    standby.handle.abort();
                    if let Err(error) = (&mut standby.handle).await {
                        if !error.is_cancelled() {
                            log::warn!("Standby task force-stop failed during {context}: {error}");
                        }
                    }
                }
            }
        });
        #[cfg(all(target_os = "linux", feature = "io_uring"))]
        standby.prepared.io_driver.join_io_uring_worker().map_err(|error| {
            EngineError::Internal(format!(
                "Client standby io_uring worker join failed during {context}: {error}"
            ))
        })?;
        Ok(())
    }

    /// Atomically attach a healthy prebuilt alternate to the existing TUN.
    pub fn promote_prebuilt_alternate(&mut self) -> Result<EngineConfig, EngineError> {
        let mut standby = self.standby_transport.take().ok_or_else(|| {
            EngineError::InvalidState(self.state.into(), "promote alternate (none prebuilt)")
        })?;
        let standby_fault = standby.fault.lock().clone();
        if let Some(fault) = standby_fault {
            self.stop_standby_task(&mut standby, "failed alternate promotion")?;
            standby.prepared.connection.close(0, b"Standby circuit failed");
            return Err(EngineError::DataPlane(fault));
        }
        if standby.handle.is_finished() || !standby.prepared.connection.is_established() {
            self.stop_standby_task(&mut standby, "unavailable alternate promotion")?;
            standby.prepared.connection.close(0, b"Standby circuit unavailable");
            return Err(EngineError::Connection(
                "prebuilt alternate is no longer ready".to_string(),
            ));
        }
        self.stop_standby_task(&mut standby, "alternate promotion")?;
        standby.prepared.io_driver =
            Arc::new(IoDriver::new_with_clock(IoDriverConfig::default(), &self.clock));
        let tun = self.validate_replacement_transport(&mut standby.prepared)?;
        Self::reconcile_replacement_tun_mtu(&mut standby.prepared, &tun)?;
        let generation = standby.prepared.generation;
        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        let promoted_connection = standby.prepared.connection.shared();
        let promoted_io_driver = standby.prepared.io_driver.clone();

        if let Some(connection) = self.connection.as_ref() {
            connection.mark_circuit_draining();
        }
        if let Err(error) = self.stop_transport_tasks("alternate promotion") {
            standby.prepared.connection.close(0, b"Active circuit drain failed");
            if let Some(connection) = self.connection.as_mut() {
                connection.close(0, b"Active circuit drain failed");
            }
            self.state = ClientState::Error;
            return Err(error);
        }
        let mut old_connection = self.connection.take();
        *self.loss_reason.lock() = None;
        *self.data_plane_fault.lock() = None;
        {
            let (lock, _) = &*self.handshake_event;
            *lock.lock() = false;
        }
        self.install_transport(standby.prepared, tun, &runtime);
        if let Some(registration) = self.loss_watchdog.clone() {
            let watchdog = self.spawn_loss_watchdog(
                &registration,
                &runtime,
                promoted_connection,
                promoted_io_driver,
            );
            self.io_handles.push(watchdog);
        }
        self.config = standby.config;
        if let Some(connection) = old_connection.as_mut() {
            connection.close(0, b"Circuit generation rotated");
        }
        log::info!("Prebuilt alternate promoted at generation {generation}");
        Ok(self.config.clone())
    }

    /// Return the validated configuration retained by the live standby owner.
    pub fn prebuilt_alternate_config(&self) -> Option<&EngineConfig> {
        self.standby_transport.as_ref().map(|standby| &standby.config)
    }

    /// Return whether the retained standby is the same public circuit requested by the caller.
    pub fn prebuilt_alternate_matches(&self, expected: &EngineConfig) -> bool {
        let Some(actual) =
            self.prebuilt_alternate_config().and_then(|config| config.circuit.as_ref())
        else {
            return false;
        };
        let Some(expected) = expected.circuit.as_ref() else {
            return false;
        };
        actual.has_same_operator_configuration(expected)
    }

    /// Return bounded standby health without endpoint or credential material.
    pub fn prebuilt_alternate_diagnostics(&self) -> Option<CircuitDiagnostics> {
        self.standby_transport.as_ref().map(|standby| {
            let mut diagnostics = standby.prepared.connection.circuit_diagnostics();
            if standby.fault.lock().is_some() || standby.handle.is_finished() {
                diagnostics.lifecycle = CircuitLifecycleState::Degraded;
            }
            diagnostics
        })
    }

    fn discard_prebuilt_alternate(&mut self, context: &str) -> Result<(), EngineError> {
        let Some(mut standby) = self.standby_transport.take() else {
            return Ok(());
        };
        let stop_result = self.stop_standby_task(&mut standby, context);
        standby.prepared.connection.close(0, b"Standby circuit discarded");
        stop_result
    }

    /// Prepare a complete replacement circuit before switching the live TUN data plane.
    pub fn rotate_circuit(&mut self, next_config: EngineConfig) -> Result<(), EngineError> {
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "rotate circuit (must be connected)",
            ));
        }
        self.prebuild_alternate_circuit(next_config)?;
        self.promote_prebuilt_alternate().map(|_| ())
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "disconnect (must be connected)",
            ));
        }

        self.discard_prebuilt_alternate("disconnect")?;
        self.deactivate_dns()?;

        self.stop_transport_tasks("disconnect")?;
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"Disconnect requested");
            log::info!("Disconnected from server");
        }
        self.socket = None;
        self.io_driver = None;
        self.tunnel_stream_id = None;
        self.assignment = None;
        self.loss_watchdog = None;
        if let Some(tun) = self.tun.take() {
            log::info!("Closing TUN interface: {}", tun.lock().name());
        }

        self.state = ClientState::Running;
        Ok(())
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

    /// Return the physical entry address actually owned by the active UDP socket.
    pub fn active_entry_addr(&self) -> Option<std::net::SocketAddr> {
        self.connection.as_ref().map(ClientConnection::peer_addr)
    }

    /// Return a copy of the authenticated assignment for the active connection.
    pub fn assignment(&self) -> Option<crate::control_plane::ClientAssignment> {
        self.assignment.clone()
    }

    /// Return server-provided DNS servers for the active assignment.
    pub fn assigned_dns_servers(&self) -> Option<Vec<std::net::IpAddr>> {
        self.assignment.as_ref().map(|assignment| assignment.dns_servers.clone())
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
    pub fn set_next_fec_mode(&mut self, mode: qf_engine_types::FecMode) {
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
        let stealth_config = config
            .stealth
            .to_runtime_config(&config.fingerprint_rotation)
            .map_err(|error| EngineError::Config(format!("Stealth config error: {error}")))?;
        if let Some(owner) = self.stealth_runtime.as_ref() {
            owner.update_next_session_stealth_config(stealth_config);
        }
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
    pub fn next_fec_mode(&self) -> qf_engine_types::FecMode {
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

fn assignments_share_tun_identity(
    current: &crate::control_plane::ClientAssignment,
    replacement: &crate::control_plane::ClientAssignment,
) -> bool {
    current.mode == replacement.mode
        && current.family_order == replacement.family_order
        && current.ipv4 == replacement.ipv4
        && current.ipv6 == replacement.ipv6
        && current.dns_servers == replacement.dns_servers
}

fn conservative_replacement_tun_mtu(
    current_mtu: u16,
    replacement_path_mtu: usize,
    replacement_assignment_mtu: u16,
) -> u16 {
    current_mtu.min(
        u16::try_from(replacement_path_mtu).unwrap_or(u16::MAX).min(replacement_assignment_mtu),
    )
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
