//! Session management for the server.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::implementations::server::bandwidth::{
    BandwidthDecision, BandwidthDirection, BandwidthPolicy, BandwidthStats,
    PerClientBandwidthManager,
};
use crate::rng;

/// Unique session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    fn new() -> Self {
        let mut buf = [0u8; 8];
        rng::fill_secure_or_abort(&mut buf, "session::SessionId::new");
        Self(u64::from_le_bytes(buf))
    }

    pub fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying numeric session identifier.
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session-{}", self.0)
    }
}

/// Client session.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    remote_addr: SocketAddr,
    client_ip: Ipv4Addr,
    client_ipv6: Option<Ipv6Addr>,
    created_at: Instant,
    timeout: Duration,
    stats: Arc<SessionStats>,
}

/// Session statistics (interior mutable via atomics).
#[derive(Debug, Default)]
pub struct SessionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl SessionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }
}

impl Session {
    /// Create a new session.
    pub fn new(remote_addr: SocketAddr, client_ip: Ipv4Addr, timeout_secs: u64) -> Self {
        Self {
            id: SessionId::new(),
            remote_addr,
            client_ip,
            client_ipv6: None,
            created_at: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
            stats: Arc::new(SessionStats::new()),
        }
    }

    /// Create a new dual-stack session with IPv4 and IPv6 addresses.
    pub fn new_dual_stack(
        remote_addr: SocketAddr,
        client_ip: Ipv4Addr,
        client_ipv6: Option<Ipv6Addr>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            id: SessionId::new(),
            remote_addr,
            client_ip,
            client_ipv6,
            created_at: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
            stats: Arc::new(SessionStats::new()),
        }
    }

    /// Get session ID.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get assigned client IPv4 address.
    pub fn client_ip(&self) -> Ipv4Addr {
        self.client_ip
    }

    /// Get assigned client IPv6 address (if dual-stack).
    pub fn client_ipv6(&self) -> Option<Ipv6Addr> {
        self.client_ipv6
    }

    /// Get session uptime.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if session has expired.
    pub fn is_expired(&self) -> bool {
        !self.timeout.is_zero() && self.created_at.elapsed() > self.timeout
    }

    /// Get session stats.
    pub fn stats(&self) -> &Arc<SessionStats> {
        &self.stats
    }

    pub fn set_remote_addr(&mut self, remote_addr: SocketAddr) {
        self.remote_addr = remote_addr;
    }
}

/// Session manager.
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    by_client_ip: HashMap<Ipv4Addr, SessionId>,
    by_client_ipv6: HashMap<Ipv6Addr, SessionId>,
    by_remote_addr: HashMap<SocketAddr, SessionId>,
    max_sessions: usize,
    bandwidth_manager: PerClientBandwidthManager,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            by_client_ip: HashMap::new(),
            by_client_ipv6: HashMap::new(),
            by_remote_addr: HashMap::new(),
            max_sessions,
            bandwidth_manager: PerClientBandwidthManager::new(BandwidthPolicy::default())
                .expect("default bandwidth policy is valid"),
        }
    }

    /// Create a new session manager with per-client bandwidth limits enabled.
    ///
    /// The `PerClientBandwidthManager` gates outbound data forwarding on a
    /// per-client basis (bytes/sec rate limit + cumulative quota). When the
    /// manager is absent, all sends are allowed.
    pub fn with_bandwidth_manager(
        max_sessions: usize,
        bandwidth_manager: PerClientBandwidthManager,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            by_client_ip: HashMap::new(),
            by_client_ipv6: HashMap::new(),
            by_remote_addr: HashMap::new(),
            max_sessions,
            bandwidth_manager,
        }
    }

    pub fn check_bandwidth(
        &mut self,
        session_id: SessionId,
        direction: BandwidthDirection,
        bytes: usize,
    ) -> BandwidthDecision {
        self.bandwidth_manager.check(&session_id.as_u64().to_string(), direction, bytes)
    }

    pub fn activate_bandwidth(
        &mut self,
        session_id: SessionId,
        policy_override: Option<BandwidthPolicy>,
    ) -> Result<(), SessionError> {
        if !self.sessions.contains_key(&session_id) {
            return Err(SessionError::NotFound);
        }
        if self.bandwidth_stats(session_id).is_some() {
            return Err(SessionError::AlreadyExists);
        }
        self.bandwidth_manager
            .add_client(&session_id.as_u64().to_string(), policy_override)
            .map_err(SessionError::BandwidthPolicy)
    }

    pub fn bandwidth_stats(&self, session_id: SessionId) -> Option<BandwidthStats> {
        self.bandwidth_manager.stats(&session_id.as_u64().to_string())
    }

    pub fn update_bandwidth_policy(
        &mut self,
        session_id: SessionId,
        policy: BandwidthPolicy,
    ) -> Result<(), String> {
        self.bandwidth_manager.update_client_policy(&session_id.as_u64().to_string(), policy)
    }

    pub fn reset_bandwidth_quota(&mut self, session_id: SessionId) -> bool {
        self.bandwidth_manager.reset_client_quota(&session_id.as_u64().to_string())
    }

    /// Add a session.
    pub fn add(&mut self, session: Session) -> Result<SessionId, SessionError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::MaxSessionsReached);
        }

        let id = session.id;
        let client_ip = session.client_ip;
        let client_ipv6 = session.client_ipv6;
        let remote_addr = session.remote_addr;

        if self.sessions.contains_key(&id) {
            return Err(SessionError::SessionIdConflict(id));
        }
        if self.by_client_ip.contains_key(&client_ip) {
            return Err(SessionError::ClientIpConflict(client_ip));
        }
        if let Some(v6) = client_ipv6 {
            if self.by_client_ipv6.contains_key(&v6) {
                return Err(SessionError::ClientIpv6Conflict(v6));
            }
        }
        if self.by_remote_addr.contains_key(&remote_addr) {
            return Err(SessionError::RemoteAddrConflict(remote_addr));
        }

        self.sessions.insert(id, session);
        self.by_client_ip.insert(client_ip, id);
        if let Some(v6) = client_ipv6 {
            self.by_client_ipv6.insert(v6, id);
        }
        self.by_remote_addr.insert(remote_addr, id);

        // Record metrics
        crate::instrumentation::global().server.session_created();
        crate::instrumentation::global().server.client_connected();

        Ok(id)
    }

    /// Remove a session.
    pub fn remove(&mut self, id: SessionId) -> Option<Session> {
        if let Some(session) = self.sessions.remove(&id) {
            self.bandwidth_manager.remove_client(&id.as_u64().to_string());
            if self.by_client_ip.get(&session.client_ip) == Some(&id) {
                self.by_client_ip.remove(&session.client_ip);
            }
            if let Some(v6) = session.client_ipv6 {
                if self.by_client_ipv6.get(&v6) == Some(&id) {
                    self.by_client_ipv6.remove(&v6);
                }
            }
            if self.by_remote_addr.get(&session.remote_addr) == Some(&id) {
                self.by_remote_addr.remove(&session.remote_addr);
            }

            // Record metrics
            crate::instrumentation::global().server.client_disconnected();

            Some(session)
        } else {
            None
        }
    }

    /// Get session by ID.
    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn remote_addr_by_session_id(&self, id: SessionId) -> Option<SocketAddr> {
        self.sessions.get(&id).map(Session::remote_addr)
    }

    pub fn contains(&self, id: SessionId) -> bool {
        self.sessions.contains_key(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SessionId, &Session)> {
        self.sessions.iter()
    }

    /// Get session by client IPv4 address.
    pub fn get_by_client_ip(&self, ip: Ipv4Addr) -> Option<&Session> {
        self.by_client_ip.get(&ip).and_then(|id| self.sessions.get(id))
    }

    /// Get session by client IPv6 address.
    pub fn get_by_client_ipv6(&self, ip: Ipv6Addr) -> Option<&Session> {
        self.by_client_ipv6.get(&ip).and_then(|id| self.sessions.get(id))
    }

    /// Get session by remote address.
    pub fn get_by_remote_addr(&self, addr: SocketAddr) -> Option<&Session> {
        self.by_remote_addr.get(&addr).and_then(|id| self.sessions.get(id))
    }

    pub fn session_id_by_remote_addr(&self, addr: SocketAddr) -> Option<SessionId> {
        self.by_remote_addr.get(&addr).copied()
    }

    pub fn session_id_by_client_ip(&self, ip: IpAddr) -> Option<SessionId> {
        match ip {
            IpAddr::V4(ipv4) => self.by_client_ip.get(&ipv4).copied(),
            IpAddr::V6(ipv6) => self.by_client_ipv6.get(&ipv6).copied(),
        }
    }

    pub fn stats_by_remote_addr(&self, addr: SocketAddr) -> Option<Arc<SessionStats>> {
        self.get_by_remote_addr(addr).map(|session| Arc::clone(session.stats()))
    }

    pub fn rebind_remote_addr(
        &mut self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) -> Result<SessionId, SessionError> {
        let session_id =
            self.by_remote_addr.get(&old_addr).copied().ok_or(SessionError::NotFound)?;
        if let Some(owner) = self.by_remote_addr.get(&new_addr) {
            if *owner != session_id {
                return Err(SessionError::RemoteAddrConflict(new_addr));
            }
        }
        let session = self.sessions.get_mut(&session_id).ok_or(SessionError::NotFound)?;
        if old_addr == new_addr {
            return Ok(session_id);
        }
        session.set_remote_addr(new_addr);
        self.by_remote_addr.remove(&old_addr);
        self.by_remote_addr.insert(new_addr, session_id);
        Ok(session_id)
    }

    /// Get all session IDs.
    pub fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.keys().copied().collect()
    }

    /// Get session count.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove expired sessions, returning their IDs.
    pub fn cleanup_expired(&mut self) -> Vec<SessionId> {
        let expired: Vec<_> =
            self.sessions.iter().filter(|(_, s)| s.is_expired()).map(|(id, _)| *id).collect();

        for id in &expired {
            self.remove(*id);
        }

        expired
    }
}

/// Session errors.
#[derive(Debug, Clone)]
pub enum SessionError {
    MaxSessionsReached,
    NotFound,
    AlreadyExists,
    SessionIdConflict(SessionId),
    ClientIpConflict(Ipv4Addr),
    ClientIpv6Conflict(Ipv6Addr),
    RemoteAddrConflict(SocketAddr),
    BandwidthPolicy(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::MaxSessionsReached => write!(f, "Maximum sessions reached"),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::AlreadyExists => write!(f, "Session already exists"),
            SessionError::SessionIdConflict(id) => write!(f, "Session ID already assigned: {id}"),
            SessionError::ClientIpConflict(ip) => write!(f, "Client IPv4 already assigned: {ip}"),
            SessionError::ClientIpv6Conflict(ip) => {
                write!(f, "Client IPv6 already assigned: {ip}")
            }
            SessionError::RemoteAddrConflict(addr) => {
                write!(f, "Remote address already assigned: {addr}")
            }
            SessionError::BandwidthPolicy(error) => {
                write!(f, "Session bandwidth policy failed: {error}")
            }
        }
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);

        assert_eq!(session.client_ip(), Ipv4Addr::new(10, 8, 0, 2));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_manager() {
        let mut mgr = SessionManager::new(100);

        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let id = session.id();

        mgr.add(session).unwrap();
        assert_eq!(mgr.len(), 1);

        let found = mgr.get_by_client_ip(Ipv4Addr::new(10, 8, 0, 2));
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), id);

        mgr.remove(id);
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn add_rejects_duplicate_client_ipv4_without_mutating_indexes() {
        let mut mgr = SessionManager::new(10);
        let client_ip = Ipv4Addr::new(10, 8, 0, 2);
        let first = Session::new("127.0.0.1:12345".parse().unwrap(), client_ip, 3600);
        let first_id = first.id();
        mgr.add(first).unwrap();

        let duplicate = Session::new("127.0.0.1:12346".parse().unwrap(), client_ip, 3600);
        assert!(matches!(
            mgr.add(duplicate),
            Err(SessionError::ClientIpConflict(ip)) if ip == client_ip
        ));
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.session_id_by_client_ip(IpAddr::V4(client_ip)), Some(first_id));
        assert_eq!(mgr.session_id_by_remote_addr("127.0.0.1:12346".parse().unwrap()), None);
    }

    #[test]
    fn add_rejects_duplicate_ipv6_and_remote_keys_without_mutation() {
        let client_ipv6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let mut ipv6_mgr = SessionManager::new(10);
        let first = Session::new_dual_stack(
            "127.0.0.1:12345".parse().unwrap(),
            Ipv4Addr::new(10, 8, 0, 2),
            Some(client_ipv6),
            3600,
        );
        let first_id = first.id();
        ipv6_mgr.add(first).unwrap();
        let duplicate_ipv6 = Session::new_dual_stack(
            "127.0.0.1:12346".parse().unwrap(),
            Ipv4Addr::new(10, 8, 0, 3),
            Some(client_ipv6),
            3600,
        );
        assert!(matches!(
            ipv6_mgr.add(duplicate_ipv6),
            Err(SessionError::ClientIpv6Conflict(ip)) if ip == client_ipv6
        ));
        assert_eq!(ipv6_mgr.len(), 1);
        assert_eq!(ipv6_mgr.session_id_by_client_ip(IpAddr::V6(client_ipv6)), Some(first_id));

        let remote_addr = "127.0.0.1:12347".parse().unwrap();
        let mut remote_mgr = SessionManager::new(10);
        let first = Session::new(remote_addr, Ipv4Addr::new(10, 8, 0, 4), 3600);
        let first_id = first.id();
        remote_mgr.add(first).unwrap();
        let duplicate_remote = Session::new(remote_addr, Ipv4Addr::new(10, 8, 0, 5), 3600);
        assert!(matches!(
            remote_mgr.add(duplicate_remote),
            Err(SessionError::RemoteAddrConflict(addr)) if addr == remote_addr
        ));
        assert_eq!(remote_mgr.len(), 1);
        assert_eq!(remote_mgr.session_id_by_remote_addr(remote_addr), Some(first_id));
    }

    #[test]
    fn add_rejects_duplicate_session_id_without_replacing_existing_session() {
        let mut mgr = SessionManager::new(10);
        let first =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let first_id = first.id();
        mgr.add(first).unwrap();
        let duplicate = Session {
            id: first_id,
            remote_addr: "127.0.0.1:12346".parse().unwrap(),
            client_ip: Ipv4Addr::new(10, 8, 0, 3),
            client_ipv6: None,
            created_at: Instant::now(),
            timeout: Duration::from_secs(3600),
            stats: Arc::new(SessionStats::new()),
        };

        assert!(
            matches!(mgr.add(duplicate), Err(SessionError::SessionIdConflict(id)) if id == first_id)
        );
        assert_eq!(mgr.len(), 1);
        assert_eq!(mgr.get(first_id).unwrap().remote_addr(), "127.0.0.1:12345".parse().unwrap());
        assert_eq!(mgr.session_id_by_remote_addr("127.0.0.1:12346".parse().unwrap()), None);
    }

    #[test]
    fn rebind_rejects_foreign_remote_address_without_mutating_state() {
        let mut mgr = SessionManager::new(10);
        let old_addr = "127.0.0.1:12345".parse().unwrap();
        let new_addr = "127.0.0.1:12346".parse().unwrap();
        let first_id = mgr.add(Session::new(old_addr, Ipv4Addr::new(10, 8, 0, 2), 3600)).unwrap();
        let second_id = mgr.add(Session::new(new_addr, Ipv4Addr::new(10, 8, 0, 3), 3600)).unwrap();

        assert!(matches!(
            mgr.rebind_remote_addr(old_addr, new_addr),
            Err(SessionError::RemoteAddrConflict(addr)) if addr == new_addr
        ));
        assert_eq!(mgr.session_id_by_remote_addr(old_addr), Some(first_id));
        assert_eq!(mgr.session_id_by_remote_addr(new_addr), Some(second_id));
        assert_eq!(mgr.get(first_id).unwrap().remote_addr(), old_addr);
    }

    #[test]
    fn test_session_manager_bandwidth_check() {
        let mut mgr = SessionManager::new(100);
        let missing = SessionId::from_u64(1);
        assert_eq!(
            mgr.check_bandwidth(missing, BandwidthDirection::Uplink, 10_000),
            BandwidthDecision::RateLimited
        );

        let bw = PerClientBandwidthManager::new(BandwidthPolicy {
            rate_bytes_per_second: 1_000,
            burst_bytes: 1_000,
            daily_quota_bytes: 10_000,
            monthly_quota_bytes: 20_000,
            weight: 1,
        })
        .unwrap();
        let mut mgr = SessionManager::with_bandwidth_manager(100, bw);
        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let id = mgr.add(session).unwrap();
        assert!(mgr.bandwidth_stats(id).is_none());
        assert_eq!(
            mgr.check_bandwidth(id, BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::RateLimited
        );
        mgr.activate_bandwidth(id, None).unwrap();
        assert_eq!(
            mgr.check_bandwidth(id, BandwidthDirection::Uplink, 1_000),
            BandwidthDecision::Allowed
        );
        assert_eq!(
            mgr.check_bandwidth(id, BandwidthDirection::Uplink, 1),
            BandwidthDecision::RateLimited
        );
        assert_eq!(mgr.bandwidth_stats(id).unwrap().daily_used_bytes, 1_000);
        mgr.remove(id);
        assert!(mgr.bandwidth_stats(id).is_none());
    }

    #[test]
    fn bandwidth_policy_precedence_preserves_usage_until_reset() {
        let global_policy = BandwidthPolicy {
            rate_bytes_per_second: 10_000,
            burst_bytes: 10_000,
            daily_quota_bytes: 20_000,
            monthly_quota_bytes: 30_000,
            weight: 1,
        };
        let manager = PerClientBandwidthManager::new(global_policy.clone()).unwrap();
        let mut sessions = SessionManager::with_bandwidth_manager(4, manager);
        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let id = sessions.add(session).unwrap();
        sessions.activate_bandwidth(id, None).unwrap();
        assert_eq!(sessions.bandwidth_stats(id).unwrap().policy, global_policy);

        let qkey_policy = BandwidthPolicy {
            rate_bytes_per_second: 20_000,
            burst_bytes: 20_000,
            daily_quota_bytes: 40_000,
            monthly_quota_bytes: 50_000,
            weight: 2,
        };
        sessions.update_bandwidth_policy(id, qkey_policy.clone()).unwrap();
        assert_eq!(sessions.bandwidth_stats(id).unwrap().policy, qkey_policy);
        assert_eq!(
            sessions.check_bandwidth(id, BandwidthDirection::Uplink, 500),
            BandwidthDecision::Allowed
        );

        let admin_policy = BandwidthPolicy {
            rate_bytes_per_second: 30_000,
            burst_bytes: 30_000,
            daily_quota_bytes: 60_000,
            monthly_quota_bytes: 70_000,
            weight: 3,
        };
        sessions.update_bandwidth_policy(id, admin_policy.clone()).unwrap();
        let stats = sessions.bandwidth_stats(id).unwrap();
        assert_eq!(stats.policy, admin_policy);
        assert_eq!(stats.daily_used_bytes, 500);
        assert!(sessions.reset_bandwidth_quota(id));
        assert_eq!(sessions.bandwidth_stats(id).unwrap().daily_used_bytes, 0);
    }

    #[test]
    fn bandwidth_owner_is_created_once_after_authentication_and_removed_with_session() {
        let mut sessions = SessionManager::new(4);
        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let id = sessions.add(session).unwrap();

        assert!(sessions.bandwidth_stats(id).is_none());
        sessions.activate_bandwidth(id, None).unwrap();
        assert!(sessions.bandwidth_stats(id).is_some());
        assert!(matches!(sessions.activate_bandwidth(id, None), Err(SessionError::AlreadyExists)));

        sessions.remove(id).unwrap();
        assert!(sessions.bandwidth_stats(id).is_none());
        assert!(matches!(sessions.activate_bandwidth(id, None), Err(SessionError::NotFound)));
    }
}
