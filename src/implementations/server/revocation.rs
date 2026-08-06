//! Immediate QKey revocation and active-session tracking.
//!
//! Provides:
//! - `RevocationManager`: tracks revoked QKeys with O(1) lookup and
//!   immediately terminates active connections using a revoked key.
//! - `QKeyConnectionTracker`: O(1) mapping from QKey ID to active connection IDs,
//!   enabling immediate connection termination on revocation.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

use crate::time_source::{ProtocolClock, WallClockError};

/// Default retention for revoked QKey records.
pub const DEFAULT_REVOCATION_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;
const REVOCATION_PRUNE_INTERVAL_SECS: u64 = 300;

/// A revoked QKey entry.
#[derive(Debug, Clone)]
pub struct RevokedKey {
    /// QKey ID.
    pub key_id: String,
    /// Revocation timestamp (Unix epoch seconds).
    pub revoked_at: u64,
    /// Reason for revocation.
    pub reason: String,
}

/// Manages revoked QKeys with O(1) lookup.
pub struct RevocationManager {
    /// One state owner keeps lookup and display records consistent atomically.
    revoked_records: RwLock<HashMap<String, RevokedKey>>,
    retention_secs: u64,
    last_prune_at: AtomicU64,
    clock: ProtocolClock,
}

impl RevocationManager {
    pub fn new() -> Self {
        Self::new_with_retention_secs(DEFAULT_REVOCATION_RETENTION_SECS)
    }

    /// Create a manager with a bounded retention window for revoked records.
    pub fn new_with_retention_secs(retention_secs: u64) -> Self {
        Self::new_with_retention_secs_and_clock(retention_secs, &ProtocolClock::default())
    }

    /// Create a manager with an explicit wall-clock source for timestamps.
    pub fn new_with_retention_secs_and_clock(retention_secs: u64, clock: &ProtocolClock) -> Self {
        Self {
            revoked_records: RwLock::new(HashMap::new()),
            retention_secs: retention_secs.max(1),
            last_prune_at: AtomicU64::new(0),
            clock: clock.clone(),
        }
    }

    fn current_epoch_secs(&self) -> Result<u64, WallClockError> {
        crate::time_source::unix_epoch_seconds(self.clock.now_system())
    }

    fn revoke_at(&self, key_id: &str, reason: &str, revoked_at: u64) {
        let record =
            RevokedKey { key_id: key_id.to_string(), revoked_at, reason: reason.to_string() };

        self.revoked_records.write().insert(key_id.to_string(), record);
    }

    /// Revoke a QKey by ID. Immediately terminates all active connections
    /// using that key through the owning live server state.
    pub fn revoke(&self, key_id: &str, reason: &str) -> Result<(), WallClockError> {
        let revoked_at = self.current_epoch_secs()?;
        self.revoke_at(key_id, reason, revoked_at);

        log::warn!("QKey revoked: id={} reason={}", key_id, reason);
        Ok(())
    }

    /// Prune expired records at most once per bounded housekeeping interval.
    pub fn prune_expired_if_due(&self) -> Result<usize, WallClockError> {
        let now = self.current_epoch_secs()?;
        Ok(self.prune_expired_if_due_at(now))
    }

    fn prune_expired_if_due_at(&self, now: u64) -> usize {
        let last_prune_at = self.last_prune_at.load(Ordering::Relaxed);
        if last_prune_at != 0 && now.saturating_sub(last_prune_at) < REVOCATION_PRUNE_INTERVAL_SECS
        {
            return 0;
        }
        if self
            .last_prune_at
            .compare_exchange(last_prune_at, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return 0;
        }
        self.prune_expired_at(now)
    }

    fn prune_expired_at(&self, now: u64) -> usize {
        let cutoff = now.saturating_sub(self.retention_secs);
        let mut records = self.revoked_records.write();
        let before = records.len();
        records.retain(|_, record| record.revoked_at > cutoff);
        before.saturating_sub(records.len())
    }

    /// Check if a QKey is revoked. O(1) lookup.
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked_records.read().contains_key(key_id)
    }

    /// List all revoked keys (for admin display).
    pub fn list_revoked(&self) -> Vec<RevokedKey> {
        self.revoked_records.read().values().cloned().collect()
    }

    /// Unrevoke a key (admin manual override).
    pub fn unrevoke(&self, key_id: &str) -> bool {
        if self.revoked_records.write().remove(key_id).is_some() {
            log::info!("QKey unrevoked: id={}", key_id);
            true
        } else {
            false
        }
    }

    /// Clear all revocations (used on restart when revocations are persisted
    /// externally and reloaded).
    pub fn clear(&self) {
        self.revoked_records.write().clear();
    }
}

impl Default for RevocationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks which connections are using which QKey. O(1) lookup in both
/// directions: QKey→connections and connection→QKey.
pub struct QKeyConnectionTracker {
    state: RwLock<QKeyConnectionTrackerState>,
}

struct QKeyConnectionTrackerState {
    /// QKey ID → set of connection IDs.
    by_key: HashMap<String, HashSet<u64>>,
    /// Connection ID → QKey ID.
    by_conn: HashMap<u64, String>,
}

fn remove_connection_from_key(
    by_key: &mut HashMap<String, HashSet<u64>>,
    key_id: &str,
    conn_id: u64,
) {
    if let Some(conns) = by_key.get_mut(key_id) {
        conns.remove(&conn_id);
        if conns.is_empty() {
            by_key.remove(key_id);
        }
    }
}

impl QKeyConnectionTracker {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(QKeyConnectionTrackerState {
                by_key: HashMap::new(),
                by_conn: HashMap::new(),
            }),
        }
    }

    /// Register or reassociate a connection with a QKey atomically.
    pub fn associate(&self, conn_id: u64, key_id: &str) {
        let mut state = self.state.write();
        let key_id = key_id.to_string();
        if let Some(previous_key_id) = state.by_conn.insert(conn_id, key_id.clone()) {
            if previous_key_id != key_id {
                remove_connection_from_key(&mut state.by_key, &previous_key_id, conn_id);
            }
        }
        state.by_key.entry(key_id).or_default().insert(conn_id);
    }

    /// Remove a connection association (on disconnect).
    pub fn dissociate(&self, conn_id: u64) {
        let mut state = self.state.write();
        if let Some(key_id) = state.by_conn.remove(&conn_id) {
            remove_connection_from_key(&mut state.by_key, &key_id, conn_id);
        }
    }

    /// Get all connection IDs using a given QKey. O(1).
    pub fn connections_for_key(&self, key_id: &str) -> Vec<u64> {
        self.state
            .read()
            .by_key
            .get(key_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the QKey ID for a connection. O(1).
    pub fn key_for_connection(&self, conn_id: u64) -> Option<String> {
        self.state.read().by_conn.get(&conn_id).cloned()
    }

    /// Get all connection IDs for a QKey and remove them from the tracker.
    /// Used during revocation to get the list before terminating.
    pub fn drain_connections_for_key(&self, key_id: &str) -> Vec<u64> {
        let mut state = self.state.write();
        let Some(conn_ids) = state.by_key.remove(key_id) else {
            return Vec::new();
        };
        for &conn_id in &conn_ids {
            if state.by_conn.get(&conn_id).is_some_and(|mapped_key| mapped_key == key_id) {
                state.by_conn.remove(&conn_id);
            }
        }
        conn_ids.into_iter().collect()
    }
}

impl Default for QKeyConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_manager_basic() {
        let mgr = RevocationManager::new();
        assert!(!mgr.is_revoked("key1"));
        mgr.revoke("key1", "compromised").expect("revoke");
        assert!(mgr.is_revoked("key1"));
        assert!(!mgr.is_revoked("key2"));
    }

    #[test]
    fn test_revocation_manager_rejects_pre_epoch_wall_clock() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1),
        );
        let clock = ProtocolClock::from_source(source);
        let mgr = RevocationManager::new_with_retention_secs_and_clock(90, &clock);

        assert_eq!(mgr.revoke("key1", "clock-test"), Err(WallClockError::BeforeUnixEpoch));
        assert!(!mgr.is_revoked("key1"));
        assert_eq!(mgr.prune_expired_if_due(), Err(WallClockError::BeforeUnixEpoch));
    }

    #[test]
    fn test_revocation_manager_list() {
        let mgr = RevocationManager::new();
        mgr.revoke("key1", "reason1").expect("revoke");
        mgr.revoke("key2", "reason2").expect("revoke");
        let list = mgr.list_revoked();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_revocation_manager_unrevoke() {
        let mgr = RevocationManager::new();
        mgr.revoke("key1", "test").expect("revoke");
        assert!(mgr.is_revoked("key1"));
        assert!(mgr.unrevoke("key1"));
        assert!(!mgr.is_revoked("key1"));
        assert!(!mgr.unrevoke("nonexistent"));
    }

    #[test]
    fn test_revocation_manager_owns_lookup_and_record_atomically() {
        let mgr = RevocationManager::new();
        mgr.revoke("key1", "compromised").expect("revoke");
        let records = mgr.list_revoked();
        let record = records.iter().find(|record| record.key_id == "key1").expect("record");
        assert_eq!(record.reason, "compromised");
        assert!(mgr.is_revoked("key1"));

        mgr.revoke("key1", "updated").expect("revoke");
        let records = mgr.list_revoked();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, "updated");
        assert!(mgr.unrevoke("key1"));
        assert!(mgr.list_revoked().is_empty());
        assert!(!mgr.is_revoked("key1"));
    }

    #[test]
    fn test_revocation_manager_prunes_expired_records_after_retention() {
        let mgr = RevocationManager::new_with_retention_secs(90);
        mgr.revoke_at("expired", "old", 10);
        mgr.revoke_at("fresh", "current", 11);

        assert_eq!(mgr.prune_expired_at(100), 1);
        assert!(!mgr.is_revoked("expired"));
        assert!(mgr.is_revoked("fresh"));
    }

    #[test]
    fn test_revocation_manager_pruning_is_bounded_by_housekeeping_interval() {
        let mgr = RevocationManager::new_with_retention_secs(90);
        mgr.revoke_at("expired", "old", 1);

        assert_eq!(mgr.prune_expired_if_due_at(100), 1);
        mgr.revoke_at("another-expired", "old", 1);
        assert_eq!(mgr.prune_expired_if_due_at(399), 0);
        assert!(mgr.is_revoked("another-expired"));
        assert_eq!(mgr.prune_expired_if_due_at(400), 1);
        assert!(!mgr.is_revoked("another-expired"));
    }

    #[test]
    fn test_revocation_manager_recovers_after_panicking_owner() {
        let manager = std::sync::Arc::new(RevocationManager::new());
        let owner = std::sync::Arc::clone(&manager);
        let join = std::thread::spawn(move || {
            let _guard = owner.revoked_records.write();
            panic!("test-only revocation owner panic");
        });
        assert!(join.join().is_err());

        manager.revoke("key-after-panic", "still-usable").expect("revoke");
        assert!(manager.is_revoked("key-after-panic"));
    }

    #[test]
    fn test_qkey_connection_tracker() {
        let tracker = QKeyConnectionTracker::new();
        tracker.associate(1, "keyA");
        tracker.associate(2, "keyA");
        tracker.associate(3, "keyB");

        let conns_a = tracker.connections_for_key("keyA");
        assert_eq!(conns_a.len(), 2);
        assert!(conns_a.contains(&1));
        assert!(conns_a.contains(&2));

        let conns_b = tracker.connections_for_key("keyB");
        assert_eq!(conns_b.len(), 1);
        assert!(conns_b.contains(&3));

        assert_eq!(tracker.key_for_connection(1), Some("keyA".to_string()));
        assert_eq!(tracker.key_for_connection(3), Some("keyB".to_string()));
        assert_eq!(tracker.key_for_connection(99), None);
    }

    #[test]
    fn test_qkey_connection_tracker_dissociate() {
        let tracker = QKeyConnectionTracker::new();
        tracker.associate(1, "keyA");
        tracker.associate(2, "keyA");
        tracker.dissociate(1);

        let conns = tracker.connections_for_key("keyA");
        assert_eq!(conns.len(), 1);
        assert!(conns.contains(&2));
        assert_eq!(tracker.key_for_connection(1), None);

        tracker.dissociate(2);
        assert!(tracker.connections_for_key("keyA").is_empty());
        assert_eq!(tracker.key_for_connection(2), None);
    }

    #[test]
    fn test_qkey_connection_tracker_reassociation_preserves_bijection() {
        let tracker = QKeyConnectionTracker::new();
        tracker.associate(1, "keyA");
        tracker.associate(1, "keyB");

        assert!(tracker.connections_for_key("keyA").is_empty());
        assert_eq!(tracker.connections_for_key("keyB"), vec![1]);
        assert_eq!(tracker.key_for_connection(1).as_deref(), Some("keyB"));

        assert_eq!(tracker.drain_connections_for_key("keyB"), vec![1]);
        assert_eq!(tracker.key_for_connection(1), None);
        assert!(tracker.connections_for_key("keyB").is_empty());
    }

    #[test]
    fn test_qkey_connection_tracker_concurrent_reassociation_preserves_bijection() {
        let tracker = std::sync::Arc::new(QKeyConnectionTracker::new());
        let mut workers = Vec::new();
        for worker in 0..4 {
            let tracker = std::sync::Arc::clone(&tracker);
            workers.push(std::thread::spawn(move || {
                for iteration in 0..250 {
                    let key = if (worker + iteration) % 2 == 0 { "keyA" } else { "keyB" };
                    tracker.associate(1, key);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("reassociation worker");
        }

        let final_key = tracker.key_for_connection(1).expect("final association");
        let other_key = if final_key == "keyA" { "keyB" } else { "keyA" };
        assert_eq!(tracker.connections_for_key(&final_key), vec![1]);
        assert!(tracker.connections_for_key(other_key).is_empty());
    }

    #[test]
    fn test_qkey_connection_tracker_drain() {
        let tracker = QKeyConnectionTracker::new();
        tracker.associate(1, "keyA");
        tracker.associate(2, "keyA");
        tracker.associate(3, "keyB");

        let drained = tracker.drain_connections_for_key("keyA");
        assert_eq!(drained.len(), 2);
        assert!(tracker.connections_for_key("keyA").is_empty());
        assert_eq!(tracker.key_for_connection(1), None);
        assert_eq!(tracker.key_for_connection(2), None);
        // keyB connections should be unaffected.
        assert_eq!(tracker.connections_for_key("keyB").len(), 1);
    }
}
