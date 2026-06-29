//! Session management for the server.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        self.timeout.as_secs() > 0 && self.created_at.elapsed() > self.timeout
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
        }
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
            self.by_client_ip.remove(&session.client_ip);
            if let Some(v6) = session.client_ipv6 {
                self.by_client_ipv6.remove(&v6);
            }
            self.by_remote_addr.remove(&session.remote_addr);

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

    pub fn stats_by_remote_addr(&self, addr: SocketAddr) -> Option<Arc<SessionStats>> {
        self.get_by_remote_addr(addr).map(|session| Arc::clone(session.stats()))
    }

    pub fn rebind_remote_addr(
        &mut self,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) -> Option<SessionId> {
        let session_id = self.by_remote_addr.remove(&old_addr)?;
        let session = self.sessions.get_mut(&session_id)?;
        session.set_remote_addr(new_addr);
        self.by_remote_addr.insert(new_addr, session_id);
        Some(session_id)
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
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::MaxSessionsReached => write!(f, "Maximum sessions reached"),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::AlreadyExists => write!(f, "Session already exists"),
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
}
