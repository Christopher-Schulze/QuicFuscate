//! Traffic isolation between clients (TODO-438).
//!
//! Prevents client-to-client traffic leakage by validating that packets
//! routed through the TUN interface are only destined for the internet
//! (not for other VPN clients). Implements:
//! - `SourceIpValidator`: ensures each client only sends packets from its
//!   assigned VPN IP (prevents IP spoofing).
//! - `ClientIsolationManager`: maintains the set of assigned client IPs and
//!   blocks TUN→TUN routing (packets from one client IP to another client IP
//!   are dropped).
//! - Firewall rule injection: iptables/nftables FORWARD chain DROP rules
//!   for inter-client traffic.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;

/// Manages client isolation: tracks assigned VPN IPs and blocks inter-client traffic.
pub struct ClientIsolationManager {
    /// Set of all assigned client VPN IPs.
    assigned_ips: RwLock<HashSet<IpAddr>>,
    /// Maps client VPN IP → client ID (for audit logging).
    ip_to_client: RwLock<HashMap<IpAddr, String>>,
    /// Whether isolation is enabled.
    enabled: std::sync::atomic::AtomicBool,
    /// Counters for dropped packets.
    dropped_spoofed: std::sync::atomic::AtomicU64,
    dropped_inter_client: std::sync::atomic::AtomicU64,
}

impl ClientIsolationManager {
    pub fn new() -> Self {
        Self {
            assigned_ips: RwLock::new(HashSet::new()),
            ip_to_client: RwLock::new(HashMap::new()),
            enabled: std::sync::atomic::AtomicBool::new(true),
            dropped_spoofed: std::sync::atomic::AtomicU64::new(0),
            dropped_inter_client: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Register a client's assigned VPN IP.
    pub fn assign_ip(&self, client_id: &str, ip: IpAddr) {
        self.assigned_ips.write().unwrap().insert(ip);
        self.ip_to_client.write().unwrap().insert(ip, client_id.to_string());
    }

    /// Unregister a client's VPN IP (on disconnect).
    pub fn release_ip(&self, ip: IpAddr) {
        self.assigned_ips.write().unwrap().remove(&ip);
        self.ip_to_client.write().unwrap().remove(&ip);
    }

    /// Enable or disable isolation.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);
    }

    /// Check if a packet should be allowed through the TUN interface.
    ///
    /// Returns `Ok(())` if the packet is allowed, or `Err(reason)` if it
    /// should be dropped.
    ///
    /// Parameters:
    /// - `src_ip`: Source IP from the packet (must match the client's assigned IP).
    /// - `dst_ip`: Destination IP from the packet.
    /// - `expected_src`: The VPN IP assigned to the sending client.
    pub fn check_packet(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        expected_src: IpAddr,
    ) -> Result<(), IsolationError> {
        if !self.enabled.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        // 1. Source IP validation: prevent spoofing.
        if src_ip != expected_src {
            self.dropped_spoofed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(IsolationError::SourceIpSpoofing {
                expected: expected_src,
                actual: src_ip,
            });
        }

        // 2. Inter-client isolation: block TUN→TUN traffic.
        let assigned = self.assigned_ips.read().unwrap();
        if assigned.contains(&dst_ip) {
            self.dropped_inter_client.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(IsolationError::InterClientTraffic { src: src_ip, dst: dst_ip });
        }

        Ok(())
    }

    /// Get the client ID for a given VPN IP.
    pub fn client_for_ip(&self, ip: IpAddr) -> Option<String> {
        self.ip_to_client.read().unwrap().get(&ip).cloned()
    }

    /// Number of assigned client IPs.
    pub fn assigned_count(&self) -> usize {
        self.assigned_ips.read().unwrap().len()
    }

    /// Get isolation statistics.
    pub fn stats(&self) -> IsolationStats {
        IsolationStats {
            dropped_spoofed: self.dropped_spoofed.load(std::sync::atomic::Ordering::Relaxed),
            dropped_inter_client: self
                .dropped_inter_client
                .load(std::sync::atomic::Ordering::Relaxed),
            assigned_clients: self.assigned_count(),
            enabled: self.enabled.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Generate iptables rules for inter-client isolation.
    ///
    /// Returns a list of iptables rule strings that DROP traffic between
    /// assigned client IPs on the FORWARD chain.
    pub fn generate_iptables_rules(&self, tun_iface: &str) -> Vec<String> {
        let assigned = self.assigned_ips.read().unwrap();
        let mut rules = Vec::new();

        // Rule: DROP packets coming in on TUN and going out on TUN
        // (inter-client traffic).
        rules.push(format!("iptables -A FORWARD -i {} -o {} -j DROP", tun_iface, tun_iface));

        // Per-client rules: only allow traffic from the assigned source IP.
        for ip in assigned.iter() {
            rules.push(format!("iptables -A FORWARD -i {} -s {} -j ACCEPT", tun_iface, ip));
        }

        // Default DROP for anything else on TUN input.
        rules.push(format!("iptables -A FORWARD -i {} -j DROP", tun_iface));

        rules
    }

    /// Generate nftables rules for inter-client isolation.
    pub fn generate_nftables_rules(&self, tun_iface: &str) -> Vec<String> {
        let assigned = self.assigned_ips.read().unwrap();
        let mut rules = Vec::new();

        // DROP inter-client traffic.
        rules.push(format!(
            "add rule inet quicfuscate forward iifname \"{}\" oifname \"{}\" drop",
            tun_iface, tun_iface
        ));

        // Allow traffic from assigned client IPs.
        for ip in assigned.iter() {
            rules.push(format!(
                "add rule inet quicfuscate forward iifname \"{}\" ip saddr {} accept",
                tun_iface, ip
            ));
        }

        // Default DROP.
        rules.push(format!("add rule inet quicfuscate forward iifname \"{}\" drop", tun_iface));

        rules
    }
}

impl Default for ClientIsolationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned when a packet violates isolation rules.
#[derive(Debug)]
pub enum IsolationError {
    /// Source IP doesn't match the client's assigned VPN IP.
    SourceIpSpoofing { expected: IpAddr, actual: IpAddr },
    /// Destination IP is another VPN client (inter-client traffic blocked).
    InterClientTraffic { src: IpAddr, dst: IpAddr },
}

impl std::fmt::Display for IsolationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceIpSpoofing { expected, actual } => {
                write!(f, "source IP spoofing: expected {expected}, got {actual}")
            }
            Self::InterClientTraffic { src, dst } => {
                write!(f, "inter-client traffic blocked: {src} → {dst}")
            }
        }
    }
}

impl std::error::Error for IsolationError {}

/// Isolation statistics.
#[derive(Debug, Clone)]
pub struct IsolationStats {
    pub dropped_spoofed: u64,
    pub dropped_inter_client: u64,
    pub assigned_clients: usize,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign_and_release_ip() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.assign_ip("client-1", ip1);
        assert_eq!(mgr.assigned_count(), 1);
        assert_eq!(mgr.client_for_ip(ip1), Some("client-1".to_string()));
        mgr.release_ip(ip1);
        assert_eq!(mgr.assigned_count(), 0);
    }

    #[test]
    fn test_source_ip_validation() {
        let mgr = ClientIsolationManager::new();
        let assigned: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.assign_ip("client-1", assigned);

        // Correct source IP → OK.
        assert!(mgr.check_packet(assigned, "8.8.8.8".parse().unwrap(), assigned).is_ok());

        // Spoofed source IP → blocked.
        let spoofed: IpAddr = "10.0.0.2".parse().unwrap();
        let result = mgr.check_packet(spoofed, "8.8.8.8".parse().unwrap(), assigned);
        assert!(matches!(result, Err(IsolationError::SourceIpSpoofing { .. })));
    }

    #[test]
    fn test_inter_client_isolation() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        mgr.assign_ip("client-1", ip1);
        mgr.assign_ip("client-2", ip2);

        // Traffic from client-1 to the internet → OK.
        assert!(mgr.check_packet(ip1, "8.8.8.8".parse().unwrap(), ip1).is_ok());

        // Traffic from client-1 to client-2 → blocked.
        let result = mgr.check_packet(ip1, ip2, ip1);
        assert!(matches!(result, Err(IsolationError::InterClientTraffic { .. })));
    }

    #[test]
    fn test_isolation_disabled() {
        let mgr = ClientIsolationManager::new();
        mgr.set_enabled(false);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        mgr.assign_ip("client-1", ip1);
        mgr.assign_ip("client-2", ip2);

        // Even inter-client traffic is allowed when disabled.
        assert!(mgr.check_packet(ip1, ip2, ip1).is_ok());
    }

    #[test]
    fn test_stats() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        mgr.assign_ip("client-1", ip1);
        mgr.assign_ip("client-2", ip2);

        // Trigger some drops.
        let _ = mgr.check_packet(ip2, "8.8.8.8".parse().unwrap(), ip1); // spoof
        let _ = mgr.check_packet(ip1, ip2, ip1); // inter-client

        let stats = mgr.stats();
        assert_eq!(stats.dropped_spoofed, 1);
        assert_eq!(stats.dropped_inter_client, 1);
        assert_eq!(stats.assigned_clients, 2);
        assert!(stats.enabled);
    }

    #[test]
    fn test_iptables_rules() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.assign_ip("client-1", ip1);

        let rules = mgr.generate_iptables_rules("tun0");
        assert!(rules.iter().any(|r| r.contains("DROP")));
        assert!(rules.iter().any(|r| r.contains("10.0.0.1")));
        assert!(rules.iter().any(|r| r.contains("ACCEPT")));
    }

    #[test]
    fn test_nftables_rules() {
        let mgr = ClientIsolationManager::new();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        mgr.assign_ip("client-1", ip1);

        let rules = mgr.generate_nftables_rules("tun0");
        assert!(rules.iter().any(|r| r.contains("drop")));
        assert!(rules.iter().any(|r| r.contains("10.0.0.1")));
        assert!(rules.iter().any(|r| r.contains("accept")));
    }
}
