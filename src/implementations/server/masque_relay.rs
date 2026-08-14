//! Authenticated, bounded RFC 9298 UDP relay ownership for intermediate circuit hops.

use crate::core::{MasqueRelayHandler, MasqueRelayResponseQueue, MasqueUdpTarget};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

const RELAY_CHANNEL_CAPACITY: usize = 512;
const MAX_RELAY_DATAGRAM_BYTES: usize = 65_535;

fn audit_relay_event(
    event_type: crate::audit::AuditEventType,
    severity: crate::audit::AuditSeverity,
    session_id: u64,
    outcome: crate::audit::AuditOutcome,
    reason: &'static str,
    message: &'static str,
) {
    let principal = session_id.to_string();
    crate::audit::audit_typed(
        event_type,
        severity,
        None,
        Some(&principal),
        crate::audit::AuditContext {
            actor: crate::audit::AuditActor::Client,
            target: crate::audit::AuditTarget::Connection,
            outcome,
            reason: Some(reason),
        },
        message,
    );
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayCidr {
    network: IpAddr,
    prefix: u8,
}

impl RelayCidr {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| format!("relay CIDR must contain a prefix: {value}"))?;
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid relay CIDR address: {address}"))?;
        let prefix =
            prefix.parse::<u8>().map_err(|_| format!("invalid relay CIDR prefix: {prefix}"))?;
        let width = if network.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return Err(format!("relay CIDR prefix {prefix} exceeds {width}"));
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MasqueRelayPolicy {
    pub enabled: bool,
    pub allow_non_global_targets: bool,
    pub allowed_hosts: HashSet<String>,
    pub allowed_cidrs: Vec<RelayCidr>,
    pub allowed_ports: HashSet<u16>,
    pub max_associations: usize,
    pub max_associations_per_session: usize,
    pub max_datagram_bytes: usize,
    pub max_dns_resolutions_per_minute: u64,
    pub max_packets_per_second: u64,
    pub max_bytes_per_second: u64,
    pub idle_timeout: Duration,
}

impl Default for MasqueRelayPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_non_global_targets: false,
            allowed_hosts: HashSet::new(),
            allowed_cidrs: Vec::new(),
            allowed_ports: HashSet::new(),
            max_associations: 256,
            max_associations_per_session: usize::from(qf_engine_types::MAX_CIRCUIT_HOPS - 1),
            max_datagram_bytes: MAX_RELAY_DATAGRAM_BYTES,
            max_dns_resolutions_per_minute: 60,
            max_packets_per_second: 10_000,
            max_bytes_per_second: 64 * 1024 * 1024,
            idle_timeout: Duration::from_secs(120),
        }
    }
}

impl MasqueRelayPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled
            && (self.allowed_hosts.is_empty()
                || self.allowed_cidrs.is_empty()
                || self.allowed_ports.is_empty())
        {
            return Err(
                "enabled MASQUE relay requires explicit hostname, CIDR, and port allowlists".into(),
            );
        }
        if self.max_associations == 0
            || self.max_associations_per_session == 0
            || self.max_associations_per_session
                > usize::from(qf_engine_types::MAX_CIRCUIT_HOPS - 1)
            || self.max_datagram_bytes == 0
            || self.max_datagram_bytes > MAX_RELAY_DATAGRAM_BYTES
            || self.max_dns_resolutions_per_minute == 0
            || self.max_packets_per_second == 0
            || self.max_bytes_per_second == 0
            || self.idle_timeout.is_zero()
        {
            return Err("invalid MASQUE relay capacity or timeout".into());
        }
        Ok(())
    }

    fn permits(&self, address: SocketAddr) -> bool {
        self.enabled
            && self.allowed_ports.contains(&address.port())
            && (self.allow_non_global_targets || is_global_relay_address(address.ip()))
            && self.allowed_cidrs.iter().any(|cidr| cidr.contains(address.ip()))
    }
}

fn is_global_relay_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let value = u32::from(address);
            ![
                (Ipv4Addr::new(0, 0, 0, 0), 8),
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(100, 64, 0, 0), 10),
                (Ipv4Addr::new(127, 0, 0, 0), 8),
                (Ipv4Addr::new(169, 254, 0, 0), 16),
                (Ipv4Addr::new(172, 16, 0, 0), 12),
                (Ipv4Addr::new(192, 0, 0, 0), 24),
                (Ipv4Addr::new(192, 0, 2, 0), 24),
                (Ipv4Addr::new(192, 88, 99, 0), 24),
                (Ipv4Addr::new(192, 168, 0, 0), 16),
                (Ipv4Addr::new(198, 18, 0, 0), 15),
                (Ipv4Addr::new(198, 51, 100, 0), 24),
                (Ipv4Addr::new(203, 0, 113, 0), 24),
                (Ipv4Addr::new(224, 0, 0, 0), 3),
            ]
            .into_iter()
            .any(|(network, prefix)| {
                let mask = u32::MAX << (32 - prefix);
                value & mask == u32::from(network) & mask
            })
        }
        IpAddr::V6(address) => {
            !(address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || is_ipv6_unique_local(address)
                || is_ipv6_link_local(address)
                || is_ipv6_documentation(address)
                || is_ipv6_discard_only(address)
                || is_ipv6_translation(address)
                || is_ipv6_protocol_assignment(address)
                || is_ipv6_6to4(address)
                || address.to_ipv4().is_some())
        }
    }
}

fn is_ipv6_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

fn is_ipv6_link_local(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
}

fn is_ipv6_documentation(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

fn is_ipv6_discard_only(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
}

fn is_ipv6_translation(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    (segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
}

fn is_ipv6_protocol_assignment(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] <= 0x01ff
}

fn is_ipv6_6to4(address: Ipv6Addr) -> bool {
    address.segments()[0] == 0x2002
}

#[derive(Debug)]
struct RelayDatagram {
    session_id: u64,
    flow_id: u64,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct RelayAdmission {
    session_id: u64,
    flow_id: u64,
    target: MasqueUdpTarget,
    circuit_id: [u8; 16],
    hop_budget: u8,
    responses: Arc<Mutex<MasqueRelayResponseQueue>>,
    result: oneshot::Sender<Result<(), String>>,
}

#[derive(Debug)]
enum RelayCommand {
    Admit(RelayAdmission),
    Datagram(RelayDatagram),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayExitReason {
    Idle,
    RateQuota,
    Transport,
    IngressClosed,
}

#[derive(Clone, Copy, Debug)]
struct RelayExit {
    key: AssociationKey,
    circuit_id: [u8; 16],
    reason: RelayExitReason,
}

struct RelaySessionLease {
    session_id: u64,
    close_sender: mpsc::UnboundedSender<u64>,
}

impl Drop for RelaySessionLease {
    fn drop(&mut self) {
        let _ = self.close_sender.send(self.session_id);
    }
}

pub struct MasqueRelayOwner {
    sender: mpsc::Sender<RelayCommand>,
    close_sender: mpsc::UnboundedSender<u64>,
    session_leases: Arc<Mutex<HashMap<u64, Weak<RelaySessionLease>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl MasqueRelayOwner {
    pub fn start(policy: MasqueRelayPolicy) -> Result<Self, String> {
        policy.validate()?;
        let (sender, receiver) = mpsc::channel(RELAY_CHANNEL_CAPACITY);
        let (close_sender, close_receiver) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_relay_manager(policy, receiver, close_receiver));
        Ok(Self {
            sender,
            close_sender,
            session_leases: Arc::new(Mutex::new(HashMap::new())),
            task,
        })
    }

    /// Resolve, authorize, pin, and allocate a relay association before the HTTP success response.
    pub async fn authorize_flow(
        &self,
        session_id: u64,
        flow_id: u64,
        target: MasqueUdpTarget,
        circuit_id: [u8; 16],
        hop_budget: u8,
        responses: Arc<Mutex<MasqueRelayResponseQueue>>,
    ) -> Result<(), String> {
        let (result, result_receiver) = oneshot::channel();
        self.sender
            .send(RelayCommand::Admit(RelayAdmission {
                session_id,
                flow_id,
                target,
                circuit_id,
                hop_budget,
                responses,
                result,
            }))
            .await
            .map_err(|_| "MASQUE relay manager stopped".to_string())?;
        result_receiver.await.map_err(|_| "MASQUE relay admission was cancelled".to_string())?
    }

    pub fn handler(&self, session_id: u64) -> MasqueRelayHandler {
        let sender = self.sender.clone();
        let lease = {
            let mut leases = self.session_leases.lock().unwrap_or_else(|error| error.into_inner());
            leases.retain(|_, lease| lease.strong_count() > 0);
            leases.get(&session_id).and_then(Weak::upgrade).unwrap_or_else(|| {
                let lease = Arc::new(RelaySessionLease {
                    session_id,
                    close_sender: self.close_sender.clone(),
                });
                leases.insert(session_id, Arc::downgrade(&lease));
                lease
            })
        };
        Arc::new(Mutex::new(Box::new(move |flow_id, _target, payload| {
            let _lease = &lease;
            let command = RelayCommand::Datagram(RelayDatagram {
                session_id,
                flow_id,
                payload: payload.to_vec(),
            });
            if sender.try_send(command).is_err() {
                log::warn!("dropping MASQUE relay datagram after bounded ingress saturation");
            }
        })))
    }

    pub async fn shutdown(self) -> Result<(), String> {
        drop(self.sender);
        drop(self.close_sender);
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .map_err(|_| "MASQUE relay shutdown timed out".to_string())?
            .map_err(|error| format!("MASQUE relay manager task failed: {error}"))
    }
}

type AssociationKey = (u64, u64);

struct RelayAssociation {
    target: MasqueUdpTarget,
    sender: mpsc::Sender<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

struct DnsResolutionWindow {
    started: tokio::time::Instant,
    resolutions: u64,
}

type RelayAssociationChannel = (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>);

struct RelayAssociationTask {
    key: AssociationKey,
    circuit_id: [u8; 16],
    flow_id: u64,
    socket: UdpSocket,
    outbound: mpsc::Receiver<Vec<u8>>,
    responses: Arc<Mutex<MasqueRelayResponseQueue>>,
    idle_timeout: Duration,
    max_packets_per_second: u64,
    max_bytes_per_second: u64,
    exit_sender: mpsc::UnboundedSender<RelayExit>,
}

async fn run_relay_manager(
    policy: MasqueRelayPolicy,
    mut receiver: mpsc::Receiver<RelayCommand>,
    mut close_receiver: mpsc::UnboundedReceiver<u64>,
) {
    let mut associations: HashMap<AssociationKey, RelayAssociation> = HashMap::new();
    let mut circuits: HashMap<[u8; 16], (u64, u8)> = HashMap::new();
    let mut dns_resolution_windows: HashMap<u64, DnsResolutionWindow> = HashMap::new();
    let (exit_sender, mut exit_receiver) = mpsc::unbounded_channel();
    loop {
        let command = tokio::select! {
            biased;
            Some(exit) = exit_receiver.recv() => {
                close_completed_association(&mut associations, &mut circuits, exit).await;
                continue;
            }
            Some(session_id) = close_receiver.recv() => {
                close_relay_session(&mut associations, &mut circuits, session_id).await;
                dns_resolution_windows.remove(&session_id);
                continue;
            }
            command = receiver.recv() => command,
        };
        let Some(command) = command else { break };
        match command {
            RelayCommand::Admit(admission) => {
                let key = (admission.session_id, admission.flow_id);
                let outcome = admit_relay_association(
                    &policy,
                    &mut associations,
                    &mut circuits,
                    &mut dns_resolution_windows,
                    &exit_sender,
                    key,
                    &admission,
                )
                .await;
                if outcome.is_err() {
                    audit_relay_event(
                        crate::audit::AuditEventType::ConnectionRejected,
                        crate::audit::AuditSeverity::Warning,
                        admission.session_id,
                        crate::audit::AuditOutcome::Denied,
                        "masque_relay_admission_rejected",
                        "Authenticated MASQUE relay association rejected",
                    );
                }
                let _ = admission.result.send(outcome);
            }
            RelayCommand::Datagram(command) => {
                if command.payload.is_empty() || command.payload.len() > policy.max_datagram_bytes {
                    log::warn!("rejecting MASQUE relay datagram outside configured size bounds");
                    continue;
                }
                let key = (command.session_id, command.flow_id);
                let Some(association) = associations.get(&key) else {
                    log::warn!("rejecting MASQUE relay datagram without admitted association");
                    continue;
                };
                if association.sender.try_send(command.payload).is_err() {
                    audit_relay_event(
                        crate::audit::AuditEventType::DdosAnomaly,
                        crate::audit::AuditSeverity::Warning,
                        command.session_id,
                        crate::audit::AuditOutcome::Denied,
                        "masque_relay_ingress_queue_saturated",
                        "Authenticated MASQUE relay ingress quota exceeded",
                    );
                }
            }
        }
    }
    let tasks = associations
        .drain()
        .map(|(_, association)| {
            drop(association.sender);
            association.task
        })
        .collect::<Vec<_>>();
    for task in tasks {
        if let Err(error) = task.await {
            log::warn!("MASQUE relay association task failed during shutdown: {error}");
        }
    }
}

async fn close_completed_association(
    associations: &mut HashMap<AssociationKey, RelayAssociation>,
    circuits: &mut HashMap<[u8; 16], (u64, u8)>,
    exit: RelayExit,
) {
    let Some(association) = associations.remove(&exit.key) else {
        return;
    };
    drop(association.sender);
    if let Err(error) = association.task.await {
        log::warn!("MASQUE relay association exit task failed: {error}");
    }
    circuits.remove(&exit.circuit_id);
    let (event_type, severity, outcome, reason, message) = match exit.reason {
        RelayExitReason::RateQuota => (
            crate::audit::AuditEventType::DdosAnomaly,
            crate::audit::AuditSeverity::Warning,
            crate::audit::AuditOutcome::Denied,
            "masque_relay_rate_quota_exceeded",
            "Authenticated MASQUE relay association exceeded its rate quota",
        ),
        RelayExitReason::Idle => (
            crate::audit::AuditEventType::ConnectionClosed,
            crate::audit::AuditSeverity::Info,
            crate::audit::AuditOutcome::Stopped,
            "masque_relay_idle_timeout",
            "Authenticated MASQUE relay association reached its idle timeout",
        ),
        RelayExitReason::Transport | RelayExitReason::IngressClosed => (
            crate::audit::AuditEventType::ConnectionClosed,
            crate::audit::AuditSeverity::Info,
            crate::audit::AuditOutcome::Stopped,
            "masque_relay_association_closed",
            "Authenticated MASQUE relay association closed",
        ),
    };
    audit_relay_event(event_type, severity, exit.key.0, outcome, reason, message);
}

async fn close_relay_session(
    associations: &mut HashMap<AssociationKey, RelayAssociation>,
    circuits: &mut HashMap<[u8; 16], (u64, u8)>,
    session_id: u64,
) {
    let keys = associations
        .keys()
        .filter_map(|key| (key.0 == session_id).then_some(*key))
        .collect::<Vec<_>>();
    for key in keys {
        if let Some(association) = associations.remove(&key) {
            drop(association.sender);
            if let Err(error) = association.task.await {
                log::warn!(
                    "MASQUE relay association task failed while closing session={}: {}",
                    session_id,
                    error
                );
            }
            log::info!(
                "closed authenticated MASQUE relay association session={} flow={}",
                session_id,
                key.1
            );
            audit_relay_event(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                session_id,
                crate::audit::AuditOutcome::Stopped,
                "masque_relay_session_closed",
                "Authenticated MASQUE relay association closed",
            );
        }
    }
    circuits.retain(|_, (owner_session, _)| *owner_session != session_id);
}

async fn admit_relay_association(
    policy: &MasqueRelayPolicy,
    associations: &mut HashMap<AssociationKey, RelayAssociation>,
    circuits: &mut HashMap<[u8; 16], (u64, u8)>,
    dns_resolution_windows: &mut HashMap<u64, DnsResolutionWindow>,
    exit_sender: &mpsc::UnboundedSender<RelayExit>,
    key: AssociationKey,
    admission: &RelayAdmission,
) -> Result<(), String> {
    if let Some(existing) = associations.get(&key) {
        return if existing.target == admission.target {
            Ok(())
        } else {
            Err("MASQUE flow is already bound to a different target".to_string())
        };
    }
    if admission.hop_budget == 0 || admission.hop_budget > qf_engine_types::MAX_CIRCUIT_HOPS {
        return Err("MASQUE circuit hop budget is invalid".to_string());
    }
    if circuits.contains_key(&admission.circuit_id) {
        return Err("MASQUE circuit loop detected at this relay".to_string());
    }
    let session_count = associations.keys().filter(|(session, _)| *session == key.0).count();
    if associations.len() >= policy.max_associations
        || session_count >= policy.max_associations_per_session
    {
        return Err("MASQUE relay association quota exceeded".to_string());
    }
    consume_dns_resolution_quota(
        policy,
        dns_resolution_windows,
        admission.session_id,
        &admission.target,
    )?;
    let address = resolve_and_pin_target(policy, &admission.target).await?;
    let socket = open_pinned_relay_socket(address).await?;
    let (sender, receiver) = association_channel()?;
    let task = tokio::spawn(run_relay_association(RelayAssociationTask {
        key,
        circuit_id: admission.circuit_id,
        flow_id: key.1,
        socket,
        outbound: receiver,
        responses: Arc::clone(&admission.responses),
        idle_timeout: policy.idle_timeout,
        max_packets_per_second: policy.max_packets_per_second,
        max_bytes_per_second: policy.max_bytes_per_second,
        exit_sender: exit_sender.clone(),
    }));
    associations.insert(key, RelayAssociation { target: admission.target.clone(), sender, task });
    circuits.insert(admission.circuit_id, (admission.session_id, admission.hop_budget));
    log::info!(
        "created authenticated MASQUE relay association session={} flow={} target={}",
        key.0,
        key.1,
        address
    );
    audit_relay_event(
        crate::audit::AuditEventType::ConnectionEstablished,
        crate::audit::AuditSeverity::Info,
        key.0,
        crate::audit::AuditOutcome::Succeeded,
        "masque_relay_association_created",
        "Authenticated MASQUE relay association created",
    );
    Ok(())
}

fn consume_dns_resolution_quota(
    policy: &MasqueRelayPolicy,
    windows: &mut HashMap<u64, DnsResolutionWindow>,
    session_id: u64,
    target: &MasqueUdpTarget,
) -> Result<(), String> {
    if target.host().parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !windows.contains_key(&session_id) && windows.len() >= policy.max_associations {
        return Err("MASQUE relay DNS principal capacity exceeded".to_string());
    }
    let now = tokio::time::Instant::now();
    let window =
        windows.entry(session_id).or_insert(DnsResolutionWindow { started: now, resolutions: 0 });
    if now.duration_since(window.started) >= Duration::from_secs(60) {
        window.started = now;
        window.resolutions = 0;
    }
    window.resolutions = window.resolutions.saturating_add(1);
    if window.resolutions > policy.max_dns_resolutions_per_minute {
        return Err("MASQUE relay DNS resolution quota exceeded".to_string());
    }
    Ok(())
}

fn association_channel() -> Result<RelayAssociationChannel, String> {
    if RELAY_CHANNEL_CAPACITY == 0 {
        return Err("relay association channel capacity is zero".into());
    }
    Ok(mpsc::channel(RELAY_CHANNEL_CAPACITY))
}

async fn resolve_and_pin_target(
    policy: &MasqueRelayPolicy,
    target: &MasqueUdpTarget,
) -> Result<SocketAddr, String> {
    let host = target.host().trim_end_matches('.').to_ascii_lowercase();
    if !policy.allowed_hosts.contains(&host) {
        return Err("relay target hostname or IP identity is not allowlisted".to_string());
    }
    let addresses = tokio::net::lookup_host((target.host(), target.port()))
        .await
        .map_err(|error| format!("relay DNS resolution failed: {error}"))?;
    addresses
        .filter(|address| policy.permits(*address))
        .min_by_key(|address| match address.ip() {
            IpAddr::V6(_) => 0,
            IpAddr::V4(_) => 1,
        })
        .ok_or_else(|| "relay target has no allowlisted public address".to_string())
}

async fn run_relay_association(mut task: RelayAssociationTask) {
    let mut receive_buffer = vec![0u8; MAX_RELAY_DATAGRAM_BYTES];
    let mut rate_window = tokio::time::Instant::now();
    let mut window_packets = 0u64;
    let mut window_bytes = 0u64;
    let reason = loop {
        let idle = tokio::time::sleep(task.idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            payload = task.outbound.recv() => {
                let Some(payload) = payload else { break RelayExitReason::IngressClosed; };
                if rate_window.elapsed() >= Duration::from_secs(1) {
                    rate_window = tokio::time::Instant::now();
                    window_packets = 0;
                    window_bytes = 0;
                }
                window_packets = window_packets.saturating_add(1);
                window_bytes = window_bytes.saturating_add(payload.len() as u64);
                if window_packets > task.max_packets_per_second || window_bytes > task.max_bytes_per_second {
                    log::warn!("closing MASQUE relay association after rate quota breach");
                    break RelayExitReason::RateQuota;
                }
                if task.socket.send(&payload).await.is_err() { break RelayExitReason::Transport; }
            }
            received = task.socket.recv(&mut receive_buffer) => {
                let Ok(received) = received else { break RelayExitReason::Transport; };
                if rate_window.elapsed() >= Duration::from_secs(1) {
                    rate_window = tokio::time::Instant::now();
                    window_packets = 0;
                    window_bytes = 0;
                }
                window_packets = window_packets.saturating_add(1);
                window_bytes = window_bytes.saturating_add(received as u64);
                if window_packets > task.max_packets_per_second || window_bytes > task.max_bytes_per_second {
                    log::warn!("closing MASQUE relay association after response rate quota breach");
                    break RelayExitReason::RateQuota;
                }
                let payload = receive_buffer[..received].to_vec();
                let result = match task.responses.lock() {
                    Ok(mut queue) => queue.enqueue(task.flow_id, payload),
                    Err(poisoned) => poisoned.into_inner().enqueue(task.flow_id, payload),
                };
                if result.is_err() {
                    log::warn!("dropping MASQUE relay response after bounded egress saturation");
                }
            }
            () = &mut idle => break RelayExitReason::Idle,
        }
    };
    let _ = task.exit_sender.send(RelayExit { key: task.key, circuit_id: task.circuit_id, reason });
}

async fn open_pinned_relay_socket(target: SocketAddr) -> Result<UdpSocket, String> {
    let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket =
        UdpSocket::bind(bind).await.map_err(|error| format!("relay UDP bind failed: {error}"))?;
    socket.connect(target).await.map_err(|error| format!("relay UDP connect failed: {error}"))?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_policy_is_fail_closed_and_rejects_private_targets() {
        assert!(MasqueRelayPolicy::default().validate().is_ok());
        let mut policy = MasqueRelayPolicy { enabled: true, ..MasqueRelayPolicy::default() };
        assert!(policy.validate().is_err());
        policy.allowed_hosts.insert("1.1.1.1".to_string());
        policy.allowed_cidrs.push(RelayCidr::parse("0.0.0.0/0").expect("CIDR"));
        policy.allowed_ports.insert(443);
        assert!(policy.validate().is_ok());
        assert!(!policy.permits("127.0.0.1:443".parse().expect("address")));
        assert!(!policy.permits("10.0.0.1:443".parse().expect("address")));
        assert!(!policy.permits("203.0.113.1:443".parse().expect("address")));
        assert!(policy.permits("1.1.1.1:443".parse().expect("address")));
        policy.allow_non_global_targets = true;
        assert!(policy.permits("10.0.0.1:443".parse().expect("address")));
    }

    #[test]
    fn relay_policy_rejects_ipv6_special_purpose_and_embedded_ipv4_targets() {
        let mut policy = MasqueRelayPolicy { enabled: true, ..MasqueRelayPolicy::default() };
        policy.allowed_hosts.insert("ipv6-relay.example".to_string());
        policy.allowed_cidrs.push(RelayCidr::parse("::/0").expect("CIDR"));
        policy.allowed_ports.insert(443);

        for address in [
            "[::]:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "[64:ff9b::7f00:1]:443",
            "[64:ff9b:1::7f00:1]:443",
            "[100::1]:443",
            "[2001::1]:443",
            "[2001:db8::1]:443",
            "[2002:7f00:1::1]:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[ff02::1]:443",
        ] {
            assert!(!policy.permits(address.parse().expect("special-purpose IPv6 address")));
        }
        assert!(policy.permits("[2606:4700:4700::1111]:443".parse().expect("public IPv6")));
    }

    #[test]
    fn cidr_matching_is_family_safe() {
        let ipv4 = RelayCidr::parse("203.0.113.0/24").expect("CIDR");
        assert!(ipv4.contains("203.0.113.9".parse().expect("IP")));
        assert!(!ipv4.contains("203.0.114.9".parse().expect("IP")));
        let ipv6 = RelayCidr::parse("2001:db8::/32").expect("CIDR");
        assert!(ipv6.contains("2001:db8::1".parse().expect("IP")));
        assert!(!ipv6.contains("2001:db9::1".parse().expect("IP")));
    }

    #[test]
    fn dns_resolution_quota_is_per_principal_and_skips_ip_literals() {
        let policy =
            MasqueRelayPolicy { max_dns_resolutions_per_minute: 1, ..MasqueRelayPolicy::default() };
        let hostname = MasqueUdpTarget::parse_authority("relay.example:443").expect("hostname");
        let literal = MasqueUdpTarget::parse_authority("1.1.1.1:443").expect("IP literal");
        let mut windows = HashMap::new();

        consume_dns_resolution_quota(&policy, &mut windows, 7, &hostname)
            .expect("first principal resolution");
        assert_eq!(
            consume_dns_resolution_quota(&policy, &mut windows, 7, &hostname)
                .expect_err("second principal resolution must exceed quota"),
            "MASQUE relay DNS resolution quota exceeded"
        );
        consume_dns_resolution_quota(&policy, &mut windows, 8, &hostname)
            .expect("independent principal quota");
        consume_dns_resolution_quota(&policy, &mut windows, 7, &literal)
            .expect("IP literals do not perform DNS resolution");
    }

    #[tokio::test]
    async fn admitted_association_preserves_real_udp_datagram_boundaries() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.expect("bind echo socket");
        let echo_address = echo.local_addr().expect("echo address");
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let (length, peer) = echo.recv_from(&mut buffer).await.expect("receive relay payload");
            assert_eq!(&buffer[..length], b"opaque-inner-quic");
            echo.send_to(&buffer[..length], peer).await.expect("send relay response");
        });

        let mut policy = MasqueRelayPolicy {
            enabled: true,
            allow_non_global_targets: true,
            ..MasqueRelayPolicy::default()
        };
        policy.allowed_hosts.insert("127.0.0.1".to_string());
        policy.allowed_cidrs.push(RelayCidr::parse("127.0.0.0/8").expect("CIDR"));
        policy.allowed_ports.insert(echo_address.port());
        let owner = MasqueRelayOwner::start(policy).expect("start relay owner");
        let target = MasqueUdpTarget::parse_authority(&echo_address.to_string()).expect("target");
        let responses = Arc::new(Mutex::new(MasqueRelayResponseQueue::new(4, 256)));
        owner
            .authorize_flow(11, 7, target.clone(), [3; 16], 1, Arc::clone(&responses))
            .await
            .expect("authenticated admission");
        let different_port = if echo_address.port() == u16::MAX {
            echo_address.port() - 1
        } else {
            echo_address.port() + 1
        };
        let different_target =
            MasqueUdpTarget::parse_authority(&format!("127.0.0.1:{different_port}"))
                .expect("different target");
        let rebind_error = owner
            .authorize_flow(11, 7, different_target, [4; 16], 1, Arc::clone(&responses))
            .await
            .expect_err("one flow cannot be rebound to another target");
        assert_eq!(rebind_error, "MASQUE flow is already bound to a different target");
        let loop_error = owner
            .authorize_flow(11, 8, target.clone(), [3; 16], 1, Arc::clone(&responses))
            .await
            .expect_err("same circuit cannot revisit one relay");
        assert_eq!(loop_error, "MASQUE circuit loop detected at this relay");
        let handler = owner.handler(11);
        let replacement_handler = owner.handler(11);
        {
            let mut handler = handler.lock().expect("handler lock");
            (handler)(7, &target, b"opaque-inner-quic");
        }

        let response = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(response) = responses.lock().expect("response lock").pop_front() {
                    break response;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay response deadline");
        assert_eq!(response.flow_id, 7);
        assert_eq!(response.payload, b"opaque-inner-quic");
        echo_task.await.expect("echo task");

        drop(handler);
        let still_owned = owner
            .authorize_flow(11, 8, target.clone(), [3; 16], 1, Arc::clone(&responses))
            .await
            .expect_err("replacing one relay callback must retain the session lease");
        assert_eq!(still_owned, "MASQUE circuit loop detected at this relay");
        drop(replacement_handler);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match owner
                    .authorize_flow(12, 9, target.clone(), [3; 16], 1, Arc::clone(&responses))
                    .await
                {
                    Ok(()) => break,
                    Err(error) if error == "MASQUE circuit loop detected at this relay" => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected admission error: {error}"),
                }
            }
        })
        .await
        .expect("session teardown deadline");
        owner.shutdown().await.expect("relay shutdown");
    }

    #[tokio::test]
    async fn rate_quota_closes_and_releases_circuit_ownership() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.expect("bind relay sink");
        let sink_address = sink.local_addr().expect("sink address");
        let mut policy = MasqueRelayPolicy {
            enabled: true,
            allow_non_global_targets: true,
            ..MasqueRelayPolicy::default()
        };
        policy.allowed_hosts.insert("127.0.0.1".to_string());
        policy.allowed_cidrs.push(RelayCidr::parse("127.0.0.0/8").expect("CIDR"));
        policy.allowed_ports.insert(sink_address.port());
        policy.max_packets_per_second = 1;
        let owner = MasqueRelayOwner::start(policy).expect("start relay owner");
        let target = MasqueUdpTarget::parse_authority(&sink_address.to_string()).expect("target");
        let responses = Arc::new(Mutex::new(MasqueRelayResponseQueue::new(4, 256)));
        let circuit_id = [9; 16];
        owner
            .authorize_flow(21, 3, target.clone(), circuit_id, 1, Arc::clone(&responses))
            .await
            .expect("initial admission");
        let handler = owner.handler(21);
        {
            let mut handler = handler.lock().expect("handler lock");
            (handler)(3, &target, b"first");
            (handler)(3, &target, b"quota-breach");
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match owner
                    .authorize_flow(21, 4, target.clone(), circuit_id, 1, Arc::clone(&responses))
                    .await
                {
                    Ok(()) => break,
                    Err(error) if error == "MASQUE circuit loop detected at this relay" => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected re-admission error: {error}"),
                }
            }
        })
        .await
        .expect("quota teardown must release circuit ownership");
        drop(handler);
        owner.shutdown().await.expect("relay shutdown");
    }
}
