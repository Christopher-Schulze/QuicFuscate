//! Traffic isolation between clients (TODO-438).
//!
//! Prevents client-to-client traffic leakage by validating that packets
//! routed through the TUN interface are only destined for the internet
//! (not for other VPN clients). Implements:
//! - `ClientIsolationManager`: maintains the set of assigned client IPs and
//!   validates every authenticated uplink before it reaches the TUN device.
//! - Typed uplink and downlink decisions for source ownership, client unicast,
//!   broadcast, multicast, local delivery, and unknown destinations.

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// VPN addresses assigned to one authenticated session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignedClientIps {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

impl AssignedClientIps {
    #[inline]
    fn owns(self, source: IpAddr) -> bool {
        match source {
            IpAddr::V4(source) => source == self.ipv4,
            IpAddr::V6(source) => self.ipv6 == Some(source),
        }
    }
}

/// Typed route selected for an authenticated client uplink packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UplinkRoute {
    Local { source: IpAddr, destination: IpAddr },
    Internet { source: IpAddr, destination: IpAddr },
    Client { source: IpAddr, destination: IpAddr },
    Broadcast { source: Ipv4Addr, destination: Ipv4Addr },
    Multicast { source: IpAddr, destination: IpAddr },
}

/// Fail-closed reason for rejecting a client uplink packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UplinkDrop {
    MissingSession,
    MalformedPacket,
    SourceIpSpoofing { expected: AssignedClientIps, actual: IpAddr },
    InterClientTraffic { source: IpAddr, destination: IpAddr },
}

/// Typed route for a packet read from the server TUN device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownlinkRoute {
    Local { source: IpAddr, destination: IpAddr },
    Unicast { source: IpAddr, destination: IpAddr },
    Fanout { source: IpAddr, destination: IpAddr },
    Unknown { source: IpAddr, destination: IpAddr },
    Malformed,
}

/// Manages client isolation: tracks assigned VPN IPs and blocks inter-client traffic.
pub struct ClientIsolationManager {
    /// Set of all assigned client VPN IPs.
    assigned_ips: ArcSwap<HashSet<IpAddr>>,
    assigned_ips_write: Mutex<()>,
    /// Maps client VPN IP → client ID (for audit logging).
    ip_to_client: RwLock<HashMap<IpAddr, String>>,
    /// Explicit opt-in for direct client-to-client unicast.
    client_to_client_enabled: AtomicBool,
    /// IPv4 subnet used to identify directed broadcast traffic.
    ipv4_broadcast: Ipv4Addr,
    /// Counters for dropped packets.
    dropped_missing_session: AtomicU64,
    dropped_malformed: AtomicU64,
    dropped_spoofed: AtomicU64,
    dropped_inter_client: AtomicU64,
}

impl ClientIsolationManager {
    pub fn new() -> Self {
        Self::with_network(Ipv4Addr::new(10, 8, 0, 1), Ipv4Addr::new(255, 255, 255, 0), false)
    }

    pub fn with_network(
        server_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        client_to_client_enabled: bool,
    ) -> Self {
        let mask = u32::from(netmask);
        let network = u32::from(server_ip) & mask;
        Self {
            assigned_ips: ArcSwap::from_pointee(HashSet::new()),
            assigned_ips_write: Mutex::new(()),
            ip_to_client: RwLock::new(HashMap::new()),
            client_to_client_enabled: AtomicBool::new(client_to_client_enabled),
            ipv4_broadcast: Ipv4Addr::from(network | !mask),
            dropped_missing_session: AtomicU64::new(0),
            dropped_malformed: AtomicU64::new(0),
            dropped_spoofed: AtomicU64::new(0),
            dropped_inter_client: AtomicU64::new(0),
        }
    }

    /// Register a client's assigned VPN IP.
    pub fn assign_ip(&self, client_id: &str, ip: IpAddr) {
        self.update_assigned_ips(|assigned| {
            assigned.insert(ip);
        });
        self.ip_to_client.write().insert(ip, client_id.to_string());
    }

    /// Register both addresses owned by an authenticated session.
    pub fn assign_client(&self, client_id: &str, addresses: AssignedClientIps) {
        self.update_assigned_ips(|assigned| {
            assigned.insert(IpAddr::V4(addresses.ipv4));
            if let Some(ipv6) = addresses.ipv6 {
                assigned.insert(IpAddr::V6(ipv6));
            }
        });
        let mut clients = self.ip_to_client.write();
        clients.insert(IpAddr::V4(addresses.ipv4), client_id.to_string());
        if let Some(ipv6) = addresses.ipv6 {
            clients.insert(IpAddr::V6(ipv6), client_id.to_string());
        }
    }

    /// Unregister a client's VPN IP (on disconnect).
    pub fn release_ip(&self, ip: IpAddr) {
        self.update_assigned_ips(|assigned| {
            assigned.remove(&ip);
        });
        self.ip_to_client.write().remove(&ip);
    }

    /// Unregister all addresses owned by a session.
    pub fn release_client(&self, addresses: AssignedClientIps) {
        self.update_assigned_ips(|assigned| {
            assigned.remove(&IpAddr::V4(addresses.ipv4));
            if let Some(ipv6) = addresses.ipv6 {
                assigned.remove(&IpAddr::V6(ipv6));
            }
        });
        let mut clients = self.ip_to_client.write();
        clients.remove(&IpAddr::V4(addresses.ipv4));
        if let Some(ipv6) = addresses.ipv6 {
            clients.remove(&IpAddr::V6(ipv6));
        }
    }

    fn update_assigned_ips(&self, update: impl FnOnce(&mut HashSet<IpAddr>)) {
        let _write_guard = self.assigned_ips_write.lock();
        let mut assigned = (*self.assigned_ips.load_full()).clone();
        update(&mut assigned);
        self.assigned_ips.store(Arc::new(assigned));
    }

    /// Enable or disable the explicit client-to-client unicast opt-in.
    pub fn set_client_to_client_enabled(&self, enabled: bool) {
        self.client_to_client_enabled.store(enabled, Ordering::Release);
    }

    /// Parse and validate one authenticated uplink packet before any TUN write.
    pub fn evaluate_uplink(
        &self,
        packet: &[u8],
        expected: Option<AssignedClientIps>,
    ) -> Result<UplinkRoute, UplinkDrop> {
        let Some(expected) = expected else {
            self.dropped_missing_session.fetch_add(1, Ordering::Relaxed);
            return Err(UplinkDrop::MissingSession);
        };
        let Some((source, destination)) = parse_ip_endpoints(packet) else {
            self.dropped_malformed.fetch_add(1, Ordering::Relaxed);
            return Err(UplinkDrop::MalformedPacket);
        };
        if !expected.owns(source) {
            self.dropped_spoofed.fetch_add(1, Ordering::Relaxed);
            return Err(UplinkDrop::SourceIpSpoofing { expected, actual: source });
        }

        if let (IpAddr::V4(source_v4), IpAddr::V4(destination_v4)) = (source, destination) {
            if destination_v4 == Ipv4Addr::BROADCAST || destination_v4 == self.ipv4_broadcast {
                return Ok(UplinkRoute::Broadcast {
                    source: source_v4,
                    destination: destination_v4,
                });
            }
        }
        if destination.is_multicast() {
            return Ok(UplinkRoute::Multicast { source, destination });
        }

        if self.assigned_ips.load().contains(&destination) {
            if !self.client_to_client_enabled.load(Ordering::Acquire) {
                self.dropped_inter_client.fetch_add(1, Ordering::Relaxed);
                return Err(UplinkDrop::InterClientTraffic { source, destination });
            }
            return Ok(UplinkRoute::Client { source, destination });
        }

        Ok(UplinkRoute::Internet { source, destination })
    }

    /// Classify a packet emitted by the host into the server TUN device.
    pub fn classify_downlink(
        &self,
        packet: &[u8],
        server_ipv4: Ipv4Addr,
        server_ipv6: Option<Ipv6Addr>,
    ) -> DownlinkRoute {
        let Some((source, destination)) = parse_ip_endpoints(packet) else {
            return DownlinkRoute::Malformed;
        };
        if destination == IpAddr::V4(server_ipv4)
            || server_ipv6.is_some_and(|ipv6| destination == IpAddr::V6(ipv6))
        {
            return DownlinkRoute::Local { source, destination };
        }
        let fanout = match destination {
            IpAddr::V4(ipv4) => {
                ipv4 == Ipv4Addr::BROADCAST || ipv4 == self.ipv4_broadcast || ipv4.is_multicast()
            }
            IpAddr::V6(ipv6) => ipv6.is_multicast(),
        };
        if fanout {
            return DownlinkRoute::Fanout { source, destination };
        }
        if self.assigned_ips.load().contains(&destination) {
            return DownlinkRoute::Unicast { source, destination };
        }
        DownlinkRoute::Unknown { source, destination }
    }

    /// Get the client ID for a given VPN IP.
    pub fn client_for_ip(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_client.read().get(&ip).cloned()
    }

    /// Number of assigned VPN addresses across all sessions.
    pub fn assigned_address_count(&self) -> usize {
        self.assigned_ips.load().len()
    }

    /// Get isolation statistics.
    pub fn stats(&self) -> IsolationStats {
        IsolationStats {
            dropped_missing_session: self.dropped_missing_session.load(Ordering::Relaxed),
            dropped_malformed: self.dropped_malformed.load(Ordering::Relaxed),
            dropped_spoofed: self.dropped_spoofed.load(Ordering::Relaxed),
            dropped_inter_client: self.dropped_inter_client.load(Ordering::Relaxed),
            assigned_addresses: self.assigned_address_count(),
            client_to_client_enabled: self.client_to_client_enabled.load(Ordering::Acquire),
        }
    }
}

#[inline]
fn parse_ip_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4_endpoints(packet),
        Some(6) => parse_ipv6_endpoints(packet),
        _ => None,
    }
}

#[inline]
fn parse_ipv4_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len || total_len != packet.len() {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((IpAddr::V4(source), IpAddr::V4(destination)))
}

#[inline]
fn parse_ipv6_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if 40usize.checked_add(payload_len)? != packet.len() {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    Some((IpAddr::V6(source), IpAddr::V6(destination)))
}

impl Default for ClientIsolationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Isolation statistics.
#[derive(Debug, Clone)]
pub struct IsolationStats {
    pub dropped_missing_session: u64,
    pub dropped_malformed: u64,
    pub dropped_spoofed: u64,
    pub dropped_inter_client: u64,
    pub assigned_addresses: usize,
    pub client_to_client_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_and_release_ip() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.assign_ip("client-1", ip1);
        assert_eq!(mgr.assigned_address_count(), 1);
        assert_eq!(mgr.client_for_ip(ip1), Some("client-1".to_string()));
        mgr.release_ip(ip1);
        assert_eq!(mgr.assigned_address_count(), 0);
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[8] = 64;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    fn ipv6_packet(source: Ipv6Addr, destination: Ipv6Addr) -> [u8; 40] {
        let mut packet = [0u8; 40];
        packet[0] = 0x60;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn evaluate_uplink_is_fail_closed_without_session_or_valid_packet() {
        let manager = ClientIsolationManager::new();
        let expected = AssignedClientIps { ipv4: Ipv4Addr::new(10, 8, 0, 2), ipv6: None };
        assert_eq!(manager.evaluate_uplink(&[], None), Err(UplinkDrop::MissingSession));
        assert_eq!(
            manager.evaluate_uplink(&[0x45], Some(expected)),
            Err(UplinkDrop::MalformedPacket)
        );
        let mut trailing = ipv4_packet(expected.ipv4, Ipv4Addr::new(1, 1, 1, 1)).to_vec();
        trailing.push(0);
        assert_eq!(
            manager.evaluate_uplink(&trailing, Some(expected)),
            Err(UplinkDrop::MalformedPacket)
        );
    }

    #[test]
    fn evaluate_uplink_validates_dual_stack_source_ownership() {
        let manager = ClientIsolationManager::new();
        let assigned = AssignedClientIps {
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            ipv6: Some("fd00::2".parse().unwrap()),
        };
        let spoofed = ipv4_packet(Ipv4Addr::new(10, 8, 0, 3), Ipv4Addr::new(1, 1, 1, 1));
        assert!(matches!(
            manager.evaluate_uplink(&spoofed, Some(assigned)),
            Err(UplinkDrop::SourceIpSpoofing { .. })
        ));

        let valid_v6 = ipv6_packet(assigned.ipv6.unwrap(), "2606:4700:4700::1111".parse().unwrap());
        assert!(matches!(
            manager.evaluate_uplink(&valid_v6, Some(assigned)),
            Ok(UplinkRoute::Internet { .. })
        ));
    }

    #[test]
    fn evaluate_uplink_types_unicast_and_fanout_routes() {
        let manager = ClientIsolationManager::with_network(
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            false,
        );
        let first = AssignedClientIps {
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            ipv6: Some("fd00::2".parse().unwrap()),
        };
        let second = AssignedClientIps {
            ipv4: Ipv4Addr::new(10, 8, 0, 3),
            ipv6: Some("fd00::3".parse().unwrap()),
        };
        manager.assign_client("second", second);

        let inter_client = ipv4_packet(first.ipv4, second.ipv4);
        assert!(matches!(
            manager.evaluate_uplink(&inter_client, Some(first)),
            Err(UplinkDrop::InterClientTraffic { .. })
        ));
        let stats = manager.stats();
        assert_eq!(stats.dropped_inter_client, 1);
        assert_eq!(stats.assigned_addresses, 2);
        assert!(!stats.client_to_client_enabled);
        manager.set_client_to_client_enabled(true);
        assert!(matches!(
            manager.evaluate_uplink(&inter_client, Some(first)),
            Ok(UplinkRoute::Client { .. })
        ));

        let broadcast = ipv4_packet(first.ipv4, Ipv4Addr::new(10, 8, 0, 255));
        assert!(matches!(
            manager.evaluate_uplink(&broadcast, Some(first)),
            Ok(UplinkRoute::Broadcast { .. })
        ));
        let multicast = ipv6_packet(first.ipv6.unwrap(), "ff02::1".parse().unwrap());
        assert!(matches!(
            manager.evaluate_uplink(&multicast, Some(first)),
            Ok(UplinkRoute::Multicast { .. })
        ));
    }

    #[test]
    fn classify_downlink_types_local_unicast_fanout_and_unknown() {
        let manager = ClientIsolationManager::new();
        let assigned = AssignedClientIps {
            ipv4: Ipv4Addr::new(10, 8, 0, 2),
            ipv6: Some("fd00::2".parse().unwrap()),
        };
        manager.assign_client("client", assigned);

        let local = ipv4_packet(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(10, 8, 0, 1));
        assert!(matches!(
            manager.classify_downlink(
                &local,
                Ipv4Addr::new(10, 8, 0, 1),
                Some("fd00::1".parse().unwrap())
            ),
            DownlinkRoute::Local { .. }
        ));
        let unicast = ipv6_packet("2001:db8::1".parse().unwrap(), assigned.ipv6.unwrap());
        assert!(matches!(
            manager.classify_downlink(
                &unicast,
                Ipv4Addr::new(10, 8, 0, 1),
                Some("fd00::1".parse().unwrap()),
            ),
            DownlinkRoute::Unicast { .. }
        ));
        let fanout = ipv4_packet(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::BROADCAST);
        assert!(matches!(
            manager.classify_downlink(
                &fanout,
                Ipv4Addr::new(10, 8, 0, 1),
                Some("fd00::1".parse().unwrap()),
            ),
            DownlinkRoute::Fanout { .. }
        ));
        let unknown = ipv4_packet(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(10, 8, 0, 99));
        assert!(matches!(
            manager.classify_downlink(
                &unknown,
                Ipv4Addr::new(10, 8, 0, 1),
                Some("fd00::1".parse().unwrap()),
            ),
            DownlinkRoute::Unknown { .. }
        ));
        assert_eq!(
            manager.classify_downlink(
                &[0x60],
                Ipv4Addr::new(10, 8, 0, 1),
                Some("fd00::1".parse().unwrap()),
            ),
            DownlinkRoute::Malformed
        );
    }
}
