//! Iterative N-hop QUIC-over-MASQUE circuit owner.

use crate::core::QuicFuscateConnection;
use qf_engine_types::{CircuitConfig, EngineError, HopRole};
use std::collections::VecDeque;
use std::sync::Arc;

const MAX_QUEUED_INNER_DATAGRAMS: usize = 256;
const MAX_QUEUED_INNER_BYTES: usize = 384 * 1024;
const MAX_INNER_DATAGRAMS_PER_DRIVE: usize = 64;
const MAX_INNER_BYTES_PER_DRIVE: usize = 256 * 1024;

pub(super) type HopFactory = Box<dyn FnOnce() -> Result<QuicFuscateConnection, EngineError> + Send>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitLifecycleState {
    Idle,
    Resolving,
    EstablishingHop(usize),
    AuthenticatingHop(usize),
    EstablishingExit,
    Ready,
    Degraded,
    Draining,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CircuitHopDiagnostics {
    pub index: usize,
    pub role: HopRole,
    pub established: bool,
    pub rtt_ms: f32,
    pub datagram_budget: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CircuitDiagnostics {
    pub generation: u64,
    pub lifecycle: CircuitLifecycleState,
    pub effective_tunnel_mtu: u16,
    pub hops: Vec<CircuitHopDiagnostics>,
}

#[derive(Default)]
struct InnerIngressState {
    datagrams: VecDeque<Vec<u8>>,
    bytes: usize,
}

#[derive(Clone, Default)]
struct InnerIngress {
    state: Arc<parking_lot::Mutex<InnerIngressState>>,
}

impl InnerIngress {
    fn push(&self, payload: &[u8]) -> bool {
        if payload.is_empty() || payload.len() > u16::MAX as usize {
            return false;
        }
        let mut state = self.state.lock();
        if state.datagrams.len() >= MAX_QUEUED_INNER_DATAGRAMS
            || state.bytes.saturating_add(payload.len()) > MAX_QUEUED_INNER_BYTES
        {
            return false;
        }
        state.bytes = state.bytes.saturating_add(payload.len());
        state.datagrams.push_back(payload.to_vec());
        true
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let mut state = self.state.lock();
        let payload = state.datagrams.pop_front()?;
        state.bytes = state.bytes.saturating_sub(payload.len());
        Some(payload)
    }
}

/// Complete client data plane. Hop zero owns the only physical UDP socket;
/// deeper connections exchange their QUIC wire packets through the preceding
/// hop's purpose-bound CONNECT-UDP flow.
pub struct ClientDataPlane {
    hops: Vec<QuicFuscateConnection>,
    pending_hops: VecDeque<HopFactory>,
    topology: Option<CircuitConfig>,
    link_streams: Vec<Option<u64>>,
    inner_ingress: Vec<InnerIngress>,
    pending_inner_egress: Vec<Option<Vec<u8>>>,
    hop_started_at: Vec<Option<std::time::Instant>>,
    link_started_at: Vec<Option<std::time::Instant>>,
    packet_scratch: Vec<u8>,
    state: CircuitLifecycleState,
    generation: u64,
    circuit_id: Option<[u8; 16]>,
}

impl ClientDataPlane {
    pub(super) fn single(connection: QuicFuscateConnection) -> Self {
        let started_at = connection.protocol_clock().now();
        Self {
            hops: vec![connection],
            pending_hops: VecDeque::new(),
            topology: None,
            link_streams: Vec::new(),
            inner_ingress: Vec::new(),
            pending_inner_egress: Vec::new(),
            hop_started_at: vec![Some(started_at)],
            link_started_at: Vec::new(),
            packet_scratch: vec![0; 65_535],
            state: CircuitLifecycleState::EstablishingHop(0),
            generation: 0,
            circuit_id: None,
        }
    }

    pub(super) fn circuit(
        topology: CircuitConfig,
        mut entry: QuicFuscateConnection,
        pending_hops: VecDeque<HopFactory>,
    ) -> Result<Self, EngineError> {
        if pending_hops.len().saturating_add(1) != topology.hops.len() {
            return Err(EngineError::Config(
                "circuit runtime hop count does not match validated topology".to_string(),
            ));
        }
        let mut hop_started_at = vec![None; topology.hops.len()];
        hop_started_at[0] = Some(entry.protocol_clock().now());
        let mut circuit_id = [0u8; 16];
        crate::rng::fill_secure(&mut circuit_id).map_err(|error| {
            EngineError::Internal(format!("circuit identity entropy failed: {error}"))
        })?;
        if topology.hops.len() > 1 {
            let remaining = u8::try_from(topology.hops.len() - 1)
                .map_err(|_| EngineError::Config("circuit hop budget overflow".to_string()))?;
            entry.set_circuit_context(circuit_id, remaining);
        }
        let link_count = topology.hops.len().saturating_sub(1);
        Ok(Self {
            link_streams: vec![None; link_count],
            inner_ingress: vec![InnerIngress::default(); link_count],
            pending_inner_egress: vec![None; link_count],
            hop_started_at,
            link_started_at: vec![None; link_count],
            topology: Some(topology),
            hops: vec![entry],
            pending_hops,
            packet_scratch: vec![0; 65_535],
            state: CircuitLifecycleState::EstablishingHop(0),
            generation: 0,
            circuit_id: Some(circuit_id),
        })
    }

    pub fn physical(&self) -> &QuicFuscateConnection {
        &self.hops[0]
    }

    pub fn physical_mut(&mut self) -> &mut QuicFuscateConnection {
        &mut self.hops[0]
    }

    pub fn exit(&self) -> &QuicFuscateConnection {
        &self.hops[self.hops.len() - 1]
    }

    pub fn exit_mut(&mut self) -> &mut QuicFuscateConnection {
        let index = self.hops.len() - 1;
        &mut self.hops[index]
    }

    pub fn is_circuit(&self) -> bool {
        self.topology.is_some()
    }

    pub fn circuit_ready(&self) -> bool {
        self.pending_hops.is_empty()
            && self.exit().conn.is_established()
            && self.link_streams.iter().all(Option::is_some)
            && self.links_established()
    }

    fn links_established(&self) -> bool {
        self.link_streams.iter().enumerate().all(|(index, stream)| {
            stream.is_some_and(|stream_id| self.hops[index].masque_stream_established(stream_id))
        })
    }

    /// Progress H3 flow establishment, inner receive delivery, and nested QUIC output.
    pub fn drive(&mut self) -> Result<(), EngineError> {
        let result = self
            .enforce_connect_deadlines()
            .and_then(|()| self.poll_established_h3())
            .and_then(|()| self.deliver_inner_ingress())
            .and_then(|()| self.open_ready_links())
            .and_then(|()| self.activate_ready_hops())
            .and_then(|()| self.mark_ready_hops_authenticated())
            .and_then(|()| self.flush_inner_outbound());
        if result.is_err() {
            self.state = CircuitLifecycleState::Failed;
        } else {
            self.refresh_lifecycle_state();
        }
        result
    }

    fn mark_ready_hops_authenticated(&mut self) -> Result<(), EngineError> {
        let exit_index = self.topology_exit_index_if_active();
        for (index, hop) in self.hops.iter_mut().enumerate() {
            if exit_index == Some(index) {
                continue;
            }
            if hop.has_local_private_packet_protection_flow()
                && !hop.mark_qkey_authenticated_from_token()
            {
                return Err(EngineError::Connection(
                    "authenticated MASQUE flow has no usable QKey transcript".to_string(),
                ));
            }
            hop.private_packet_protection_control_tick()
                .map_err(|error| EngineError::Connection(error.to_string()))?;
        }
        Ok(())
    }

    fn refresh_lifecycle_state(&mut self) {
        if matches!(
            self.state,
            CircuitLifecycleState::Ready
                | CircuitLifecycleState::Degraded
                | CircuitLifecycleState::Draining
                | CircuitLifecycleState::Closed
                | CircuitLifecycleState::Failed
        ) {
            return;
        }
        if let Some(index) = self.hops.iter().position(|hop| !hop.conn.is_established()) {
            self.state = CircuitLifecycleState::EstablishingHop(index);
            return;
        }
        if !self.pending_hops.is_empty() {
            self.state = CircuitLifecycleState::AuthenticatingHop(self.hops.len() - 1);
            return;
        }
        if let Some(index) = self.link_streams.iter().enumerate().find_map(|(index, stream)| {
            (!stream.is_some_and(|stream_id| self.hops[index].masque_stream_established(stream_id)))
                .then_some(index)
        }) {
            self.state = CircuitLifecycleState::AuthenticatingHop(index);
            return;
        }
        self.state = CircuitLifecycleState::EstablishingExit;
    }

    fn enforce_connect_deadlines(&self) -> Result<(), EngineError> {
        let Some(topology) = self.topology.as_ref() else {
            return Ok(());
        };
        for (index, started_at) in self.hop_started_at.iter().enumerate() {
            let Some(started_at) = started_at else {
                continue;
            };
            if !self.hops[index].conn.is_established()
                && self.hops[index].protocol_clock().elapsed_since(*started_at)
                    >= std::time::Duration::from_millis(topology.hops[index].connect_timeout_ms)
            {
                return Err(EngineError::Connection(format!(
                    "circuit hop {index} establishment timed out"
                )));
            }
        }
        for (link_index, started_at) in self.link_started_at.iter().enumerate() {
            let Some(started_at) = started_at else {
                continue;
            };
            let established = self.link_streams[link_index].is_some_and(|stream_id| {
                self.hops[link_index].masque_stream_established(stream_id)
            });
            if !established
                && self.hops[link_index].protocol_clock().elapsed_since(*started_at)
                    >= std::time::Duration::from_millis(
                        topology.hops[link_index + 1].connect_timeout_ms,
                    )
            {
                return Err(EngineError::Connection(format!(
                    "circuit relay link {link_index} authentication timed out"
                )));
            }
        }
        Ok(())
    }

    fn poll_established_h3(&mut self) -> Result<(), EngineError> {
        // The exit is polled by the public `poll_http3`/`poll_http3_with` owner
        // so its stream-body callback is selected exactly once. Polling it here
        // with the discard callback would consume oversized H3 tunnel frames
        // before the TUN writer can receive them. Intermediate hops have no
        // application sink; their only job here is to advance relay flows and
        // deliver opaque datagrams into the next-hop ingress queues.
        let exit_index = self.topology_exit_index_if_active();
        for (index, hop) in self.hops.iter_mut().enumerate() {
            if exit_index == Some(index) {
                continue;
            }
            if hop.conn.is_established() {
                hop.poll_http3().map_err(|error| EngineError::Connection(error.to_string()))?;
            }
        }
        Ok(())
    }

    fn topology_exit_index_if_active(&self) -> Option<usize> {
        let topology = self.topology.as_ref()?;
        let index = topology.hops.len().saturating_sub(1);
        (index < self.hops.len()).then_some(index)
    }

    fn deliver_inner_ingress(&mut self) -> Result<(), EngineError> {
        for inner_index in 0..self.hops.len().saturating_sub(1) {
            let mut delivered_datagrams = 0usize;
            let mut delivered_bytes = 0usize;
            while delivered_datagrams < MAX_INNER_DATAGRAMS_PER_DRIVE
                && delivered_bytes < MAX_INNER_BYTES_PER_DRIVE
            {
                let Some(payload) = self.inner_ingress[inner_index].pop() else {
                    break;
                };
                delivered_datagrams = delivered_datagrams.saturating_add(1);
                delivered_bytes = delivered_bytes.saturating_add(payload.len());
                let hop = &mut self.hops[inner_index + 1];
                hop.recv(&payload).map_err(|error| EngineError::Connection(error.to_string()))?;
                if hop.conn.is_established() {
                    hop.poll_http3().map_err(|error| EngineError::Connection(error.to_string()))?;
                }
            }
        }
        Ok(())
    }

    fn open_ready_links(&mut self) -> Result<(), EngineError> {
        let Some(topology) = self.topology.as_ref() else {
            return Ok(());
        };
        for link_index in 0..self.link_streams.len() {
            if self.link_streams[link_index].is_some()
                || link_index >= self.hops.len()
                || !self.hops[link_index].conn.is_established()
                || (link_index > 0
                    && !self.link_streams[link_index - 1].is_some_and(|stream_id| {
                        self.hops[link_index - 1].masque_stream_established(stream_id)
                    }))
            {
                continue;
            }
            let proxy = topology.hops[link_index].endpoint.clone();
            let target = topology.hops[link_index + 1].endpoint.clone();
            let ingress = self.inner_ingress[link_index].clone();
            self.hops[link_index].set_masque_relay_cb(Arc::new(std::sync::Mutex::new(Box::new(
                move |flow_id, _target, payload| {
                    log::debug!(
                        "received nested QUIC datagram flow={} bytes={}",
                        flow_id,
                        payload.len()
                    );
                    if !ingress.push(payload) {
                        log::warn!(
                            "dropping nested QUIC datagram after bounded ingress saturation"
                        );
                    }
                },
            ))));
            let stream_id = self.hops[link_index]
                .begin_next_hop_masque_tunnel(&proxy, &target)
                .map_err(|error| EngineError::Connection(error.to_string()))?;
            self.link_streams[link_index] = Some(stream_id);
            self.link_started_at[link_index] = Some(self.hops[link_index].protocol_clock().now());
        }
        Ok(())
    }

    fn activate_ready_hops(&mut self) -> Result<(), EngineError> {
        while self.hops.len() <= self.link_streams.len() {
            let link_index = self.hops.len() - 1;
            let Some(stream_id) = self.link_streams[link_index] else {
                break;
            };
            if !self.hops[link_index].masque_stream_established(stream_id) {
                break;
            }
            let factory = self.pending_hops.pop_front().ok_or_else(|| {
                EngineError::Internal("circuit pending-hop ownership disappeared".to_string())
            })?;
            let mut hop = factory()?;
            let hop_index = self.hops.len();
            hop.set_client_connection_generation(self.generation);
            if hop_index + 1 < self.hop_started_at.len() {
                let circuit_id = self.circuit_id.ok_or_else(|| {
                    EngineError::Internal("circuit identity ownership disappeared".to_string())
                })?;
                let remaining = u8::try_from(self.hop_started_at.len() - hop_index - 1)
                    .map_err(|_| EngineError::Config("circuit hop budget overflow".to_string()))?;
                hop.set_circuit_context(circuit_id, remaining);
            }
            self.hop_started_at[hop_index] = Some(hop.protocol_clock().now());
            self.hops.push(hop);
        }
        Ok(())
    }

    fn flush_inner_outbound(&mut self) -> Result<(), EngineError> {
        for hop_index in (1..self.hops.len()).rev() {
            let link_index = hop_index - 1;
            let Some(stream_id) = self.link_streams[link_index] else {
                continue;
            };
            if !self.hops[link_index].masque_stream_established(stream_id) {
                continue;
            }
            let mut sent_datagrams = 0usize;
            let mut sent_bytes = 0usize;
            if let Some(payload) = self.pending_inner_egress[link_index].take() {
                match self.hops[link_index].send_next_hop_masque_datagram(stream_id, &payload) {
                    Ok(()) => {
                        sent_datagrams = 1;
                        sent_bytes = payload.len();
                    }
                    Err(crate::error::ConnectionError::DgramQueueFull) => {
                        self.pending_inner_egress[link_index] = Some(payload);
                        continue;
                    }
                    Err(error) => return Err(EngineError::Connection(error.to_string())),
                }
            }
            while sent_datagrams < MAX_INNER_DATAGRAMS_PER_DRIVE
                && sent_bytes < MAX_INNER_BYTES_PER_DRIVE
            {
                let written = match self.hops[hop_index].send(&mut self.packet_scratch) {
                    Ok(0) | Err(crate::error::ConnectionError::Done) => break,
                    Ok(written) => written,
                    Err(error) => return Err(EngineError::Connection(error.to_string())),
                };
                let payload = &self.packet_scratch[..written];
                match self.hops[link_index].send_next_hop_masque_datagram(stream_id, payload) {
                    Ok(()) => {
                        sent_datagrams = sent_datagrams.saturating_add(1);
                        sent_bytes = sent_bytes.saturating_add(written);
                    }
                    Err(crate::error::ConnectionError::DgramQueueFull) => {
                        self.pending_inner_egress[link_index] = Some(payload.to_vec());
                        break;
                    }
                    Err(error) => return Err(EngineError::Connection(error.to_string())),
                }
            }
        }
        Ok(())
    }

    pub fn recv_physical(&mut self, payload: &[u8]) -> Result<usize, EngineError> {
        let received = self.hops[0]
            .recv(payload)
            .map_err(|error| EngineError::Connection(error.to_string()))?;
        self.drive()?;
        Ok(received)
    }

    pub fn send_physical(&mut self, output: &mut [u8]) -> Result<usize, EngineError> {
        self.drive()?;
        match self.hops[0].send(output) {
            Ok(written) => Ok(written),
            Err(crate::error::ConnectionError::Done) => Ok(0),
            Err(error) => Err(EngineError::Connection(error.to_string())),
        }
    }

    pub fn recv(&mut self, payload: &[u8]) -> Result<usize, EngineError> {
        self.recv_physical(payload)
    }

    pub fn recv_pooled_block(
        &mut self,
        block: crate::optimize::AlignedBox<[u8]>,
        length: usize,
    ) -> Result<usize, EngineError> {
        let received = self
            .physical_mut()
            .recv_pooled_block(block, length)
            .map_err(|error| EngineError::Connection(error.to_string()))?;
        self.drive()?;
        Ok(received)
    }

    pub fn send(&mut self, output: &mut [u8]) -> Result<usize, EngineError> {
        self.send_physical(output)
    }

    pub fn next_send_deadline(&self) -> Option<std::time::Instant> {
        self.hops.iter().filter_map(QuicFuscateConnection::next_send_deadline).min()
    }

    pub fn is_established(&self) -> bool {
        self.circuit_ready()
    }

    pub fn is_closed(&self) -> bool {
        self.hops.iter().any(|hop| hop.conn.is_closed())
    }

    pub fn last_activity_elapsed(&self) -> std::time::Duration {
        self.hops.iter().map(|hop| hop.conn.last_activity_elapsed()).max().unwrap_or_default()
    }

    pub fn error(&self) -> Option<crate::error::ConnectionError> {
        self.hops.iter().find_map(|hop| hop.conn.error().cloned())
    }

    pub fn local_error(&self) -> Option<crate::error::ConnectionError> {
        self.hops.iter().find_map(|hop| hop.conn.local_error().cloned())
    }

    pub fn remote_error(&self) -> Option<crate::error::ConnectionError> {
        self.hops.iter().find_map(|hop| hop.conn.remote_error().cloned())
    }

    pub fn close_all(&mut self, app: bool, error_code: u64, reason: &[u8]) {
        self.state = CircuitLifecycleState::Draining;
        for hop in self.hops.iter_mut().rev() {
            if let Err(error) = hop.conn.close(app, error_code, reason) {
                log::debug!("circuit hop close returned: {error}");
            }
        }
        self.state = CircuitLifecycleState::Closed;
    }

    pub fn mark_draining(&mut self) {
        if !matches!(self.state, CircuitLifecycleState::Closed | CircuitLifecycleState::Failed) {
            self.state = CircuitLifecycleState::Draining;
        }
    }

    pub fn mark_ready(&mut self) {
        self.state = CircuitLifecycleState::Ready;
    }

    pub fn mark_degraded(&mut self) {
        if !matches!(self.state, CircuitLifecycleState::Closed | CircuitLifecycleState::Failed) {
            self.state = CircuitLifecycleState::Degraded;
        }
    }

    pub fn mark_failed(&mut self) {
        self.state = CircuitLifecycleState::Failed;
    }

    pub fn lifecycle_state(&self) -> CircuitLifecycleState {
        self.state
    }

    pub fn set_client_connection_generation(&mut self, generation: u64) {
        self.generation = generation;
        for hop in &mut self.hops {
            hop.set_client_connection_generation(generation);
        }
    }

    pub fn diagnostics(&self) -> CircuitDiagnostics {
        let last_index = self.hops.len().saturating_sub(1);
        let hops = match self.topology.as_ref() {
            None => self
                .hops
                .iter()
                .enumerate()
                .map(|(index, hop)| CircuitHopDiagnostics {
                    index,
                    role: HopRole::Exit,
                    established: hop.conn.is_established(),
                    rtt_ms: hop.rtt_ms(),
                    datagram_budget: u16::try_from(
                        hop.conn.max_send_udp_payload_size().min(hop.conn.effective_path_mtu()),
                    )
                    .unwrap_or(u16::MAX),
                })
                .collect(),
            Some(topology) => topology
                .hops
                .iter()
                .enumerate()
                .map(|(index, configured)| {
                    let active = self.hops.get(index);
                    let datagram_budget = active.map_or_else(
                        || {
                            let depth = u16::try_from(index).unwrap_or(u16::MAX);
                            self.physical()
                                .conn
                                .max_send_udp_payload_size()
                                .saturating_sub(
                                    usize::from(qf_engine_types::NESTED_MASQUE_OVERHEAD)
                                        .saturating_mul(usize::from(depth)),
                                )
                                .try_into()
                                .unwrap_or(qf_engine_types::MIN_INNER_QUIC_DATAGRAM)
                        },
                        |hop| {
                            u16::try_from(
                                hop.conn
                                    .max_send_udp_payload_size()
                                    .min(hop.conn.effective_path_mtu()),
                            )
                            .unwrap_or(u16::MAX)
                        },
                    );
                    CircuitHopDiagnostics {
                        index,
                        role: configured.role,
                        established: active.is_some_and(|hop| hop.conn.is_established()),
                        rtt_ms: active.map_or(0.0, QuicFuscateConnection::rtt_ms),
                        datagram_budget,
                    }
                })
                .collect(),
        };
        debug_assert!(self.topology.is_some() || last_index == 0);
        CircuitDiagnostics {
            generation: self.generation,
            lifecycle: self.state,
            effective_tunnel_mtu: u16::try_from(self.effective_tunnel_mtu()).unwrap_or(u16::MAX),
            hops,
        }
    }

    pub fn set_masque_control_cb(&mut self, callback: crate::core::CapsuleHandler) {
        self.exit_mut().set_masque_control_cb(callback);
    }

    /// Install the private packet-protection control sink on every active hop. Private
    /// negotiation is per authenticated QUIC connection, not an exit-only circuit property.
    pub fn set_private_packet_protection_cb(
        &mut self,
        callback: crate::core::PrivatePacketProtectionHandler,
    ) {
        for hop in &mut self.hops {
            hop.set_private_packet_protection_cb(Arc::clone(&callback));
        }
    }

    /// Commit every active hop's secret-free QKey transcript binding after authenticated
    /// assignment. Private packet protection is connection-local, so an exit-only update would
    /// leave intermediate QUIC sessions on an unauthenticated standard-only path.
    pub fn mark_qkey_authenticated_from_token(&mut self) -> bool {
        self.hops.iter_mut().all(|hop| {
            !hop.has_local_private_packet_protection_flow()
                || hop.mark_qkey_authenticated_from_token()
        })
    }

    /// Prime every active hop's private control owner after authenticated assignment.
    pub fn private_packet_protection_control_tick(&mut self) -> Result<(), EngineError> {
        for hop in &mut self.hops {
            hop.private_packet_protection_control_tick()
                .map_err(|error| EngineError::Connection(error.to_string()))?;
        }
        Ok(())
    }

    /// Send one private packet-protection capsule on the selected exit connection.
    pub fn send_private_packet_protection_capsule(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.exit_mut().send_private_packet_protection_capsule(payload)
    }

    pub fn begin_masque_control_tunnel(&mut self) -> Result<u64, crate::error::ConnectionError> {
        self.exit_mut().begin_masque_control_tunnel()
    }

    pub fn masque_tunnel_established(&self) -> bool {
        self.exit().masque_tunnel_established()
    }

    pub fn poll_http3(&mut self) -> Result<(), EngineError> {
        self.drive()?;
        self.exit_mut().poll_http3().map_err(|error| EngineError::Connection(error.to_string()))
    }

    pub fn poll_http3_with<F>(&mut self, callback: F) -> Result<(), EngineError>
    where
        F: FnMut(&[u8]),
    {
        self.drive()?;
        self.exit_mut()
            .poll_http3_with(callback)
            .map_err(|error| EngineError::Connection(error.to_string()))
    }

    pub fn send_tunnel_packet(&mut self, stream_id: u64, packet: &[u8]) -> Result<(), EngineError> {
        self.exit_mut().send_tunnel_packet(stream_id, packet).map_err(|error| match error {
            crate::error::ConnectionError::DgramQueueFull => EngineError::Backpressure,
            error => EngineError::Connection(error.to_string()),
        })?;
        self.flush_inner_outbound()
    }

    pub fn open_http3_stream_post(&mut self, path: &str) -> Result<u64, EngineError> {
        self.exit_mut()
            .open_http3_stream_post(path)
            .map_err(|error| EngineError::Connection(error.to_string()))
    }

    pub fn set_masque_datagram_cb(&mut self, callback: crate::core::DatagramHandler) {
        self.exit_mut().set_masque_datagram_cb(callback);
    }

    pub fn effective_tunnel_mtu(&self) -> usize {
        let exit_mtu = self.exit().effective_tunnel_mtu();
        self.topology
            .as_ref()
            .and_then(|topology| {
                u16::try_from(self.physical().conn.max_send_udp_payload_size())
                    .ok()
                    .map(|configured| {
                        configured.min(
                            u16::try_from(self.physical().conn.effective_path_mtu())
                                .unwrap_or(u16::MAX),
                        )
                    })
                    .and_then(|mtu| topology.effective_inner_datagram_budget(mtu).ok())
            })
            .map_or(exit_mtu, |budget| exit_mtu.min(usize::from(budget)))
    }

    pub fn recv_memory_pool(&self) -> Arc<crate::optimize::MemoryPool> {
        self.physical().recv_memory_pool()
    }

    pub fn validate_topology_runtime(&self) -> Result<(), EngineError> {
        let Some(topology) = self.topology.as_ref() else {
            return Ok(());
        };
        for (index, hop) in topology.hops.iter().enumerate() {
            let expected =
                if index + 1 == topology.hops.len() { HopRole::Exit } else { HopRole::Relay };
            if hop.role != expected {
                return Err(EngineError::Config(format!(
                    "circuit hop {index} runtime role mismatch"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inner_ingress_enforces_datagram_and_byte_bounds_without_losing_order() {
        let ingress = InnerIngress::default();
        for value in 0..MAX_QUEUED_INNER_DATAGRAMS {
            assert!(ingress.push(&[u8::try_from(value % 251).unwrap_or_default()]));
        }
        assert!(!ingress.push(&[0xFF]));
        for value in 0..MAX_QUEUED_INNER_DATAGRAMS {
            assert_eq!(ingress.pop(), Some(vec![u8::try_from(value % 251).unwrap_or_default()]));
        }
        assert_eq!(ingress.pop(), None);

        let large = vec![0xA5; u16::MAX as usize];
        for _ in 0..6 {
            assert!(ingress.push(&large));
        }
        assert!(!ingress.push(&large));
    }
}
