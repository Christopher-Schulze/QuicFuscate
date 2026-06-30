//! Key rotation & immediate revocation (TODO-436).
//!
//! Provides:
//! - `KeyRotationManager`: automatic QKey rotation with an overlap window
//!   (old key stays valid during the overlap to prevent connection drops).
//! - `RevocationManager`: tracks revoked QKeys with O(1) lookup and
//!   immediately terminates active connections using a revoked key.
//! - `QKeyConnectionTracker`: O(1) mapping from QKey ID to active connection IDs,
//!   enabling immediate connection termination on revocation.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default rotation interval (24 hours).
pub const DEFAULT_ROTATION_INTERVAL_SECS: u64 = 86400;
/// Default overlap window: old key remains valid for 5 minutes after rotation.
pub const DEFAULT_OVERLAP_WINDOW_SECS: u64 = 300;

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
    /// Set of revoked key IDs for O(1) `is_revoked()` lookup.
    revoked_ids: RwLock<HashSet<String>>,
    /// Full revocation records (for audit/display).
    revoked_records: RwLock<HashMap<String, RevokedKey>>,
    /// Callback to terminate a connection by QKey ID.
    #[allow(clippy::type_complexity)]
    terminate_callback: Mutex<Option<Box<dyn Fn(&str) + Send + Sync>>>,
}

impl RevocationManager {
    pub fn new() -> Self {
        Self {
            revoked_ids: RwLock::new(HashSet::new()),
            revoked_records: RwLock::new(HashMap::new()),
            terminate_callback: Mutex::new(None),
        }
    }

    /// Register a callback that terminates all active connections using the
    /// given QKey ID. Called immediately when a key is revoked.
    pub fn set_terminate_callback<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        *self.terminate_callback.lock().unwrap() = Some(Box::new(callback));
    }

    /// Revoke a QKey by ID. Immediately terminates all active connections
    /// using that key (if a terminate callback is registered).
    pub fn revoke(&self, key_id: &str, reason: &str) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        let record =
            RevokedKey { key_id: key_id.to_string(), revoked_at: now, reason: reason.to_string() };

        self.revoked_ids.write().unwrap().insert(key_id.to_string());
        self.revoked_records.write().unwrap().insert(key_id.to_string(), record);

        log::warn!("QKey revoked: id={} reason={}", key_id, reason);

        // Immediately terminate active connections using this key.
        if let Some(callback) = self.terminate_callback.lock().unwrap().as_ref() {
            callback(key_id);
        }
    }

    /// Check if a QKey is revoked. O(1) lookup.
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked_ids.read().unwrap().contains(key_id)
    }

    /// List all revoked keys (for admin display).
    pub fn list_revoked(&self) -> Vec<RevokedKey> {
        self.revoked_records.read().unwrap().values().cloned().collect()
    }

    /// Unrevoke a key (admin manual override).
    pub fn unrevoke(&self, key_id: &str) -> bool {
        let removed_ids = self.revoked_ids.write().unwrap().remove(key_id);
        let removed_records = self.revoked_records.write().unwrap().remove(key_id).is_some();
        if removed_ids || removed_records {
            log::info!("QKey unrevoked: id={}", key_id);
            true
        } else {
            false
        }
    }

    /// Clear all revocations (used on restart when revocations are persisted
    /// externally and reloaded).
    pub fn clear(&self) {
        self.revoked_ids.write().unwrap().clear();
        self.revoked_records.write().unwrap().clear();
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
    /// QKey ID → set of connection IDs.
    by_key: RwLock<HashMap<String, HashSet<u64>>>,
    /// Connection ID → QKey ID.
    by_conn: RwLock<HashMap<u64, String>>,
}

impl QKeyConnectionTracker {
    pub fn new() -> Self {
        Self { by_key: RwLock::new(HashMap::new()), by_conn: RwLock::new(HashMap::new()) }
    }

    /// Register that a connection is using a QKey.
    pub fn associate(&self, conn_id: u64, key_id: &str) {
        self.by_conn.write().unwrap().insert(conn_id, key_id.to_string());
        self.by_key.write().unwrap().entry(key_id.to_string()).or_default().insert(conn_id);
    }

    /// Remove a connection association (on disconnect).
    pub fn dissociate(&self, conn_id: u64) {
        if let Some(key_id) = self.by_conn.write().unwrap().remove(&conn_id) {
            if let Some(conns) = self.by_key.write().unwrap().get_mut(&key_id) {
                conns.remove(&conn_id);
                if conns.is_empty() {
                    self.by_key.write().unwrap().remove(&key_id);
                }
            }
        }
    }

    /// Get all connection IDs using a given QKey. O(1).
    pub fn connections_for_key(&self, key_id: &str) -> Vec<u64> {
        self.by_key
            .read()
            .unwrap()
            .get(key_id)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Get the QKey ID for a connection. O(1).
    pub fn key_for_connection(&self, conn_id: u64) -> Option<String> {
        self.by_conn.read().unwrap().get(&conn_id).cloned()
    }

    /// Get all connection IDs for a QKey and remove them from the tracker.
    /// Used during revocation to get the list before terminating.
    pub fn drain_connections_for_key(&self, key_id: &str) -> Vec<u64> {
        let conn_ids = self.by_key.write().unwrap().remove(key_id).unwrap_or_default();
        let mut by_conn = self.by_conn.write().unwrap();
        for &conn_id in &conn_ids {
            by_conn.remove(&conn_id);
        }
        conn_ids.into_iter().collect()
    }
}

impl Default for QKeyConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages automatic QKey rotation with an overlap window.
///
/// During rotation, the new key is generated and distributed. The old key
/// remains valid for `overlap_window` seconds to allow in-flight connections
/// to transition. After the overlap window, the old key is revoked.
pub struct KeyRotationManager {
    /// Rotation interval.
    rotation_interval: Duration,
    /// Overlap window: old key stays valid this long after rotation.
    overlap_window: Duration,
    /// Last rotation time.
    last_rotation: RwLock<Instant>,
    /// Keys that are in the overlap window (old key ID → rotation time).
    pending_revocations: RwLock<Vec<(String, Instant)>>,
    /// Callback to generate a new key.
    generate_callback: Mutex<Option<Box<dyn Fn() -> String + Send + Sync>>>,
    /// Reference to the revocation manager.
    revocation_manager: Arc<RevocationManager>,
}

impl KeyRotationManager {
    pub fn new(
        rotation_interval_secs: u64,
        overlap_window_secs: u64,
        revocation_manager: Arc<RevocationManager>,
    ) -> Self {
        Self {
            rotation_interval: Duration::from_secs(rotation_interval_secs),
            overlap_window: Duration::from_secs(overlap_window_secs),
            last_rotation: RwLock::new(Instant::now()),
            pending_revocations: RwLock::new(Vec::new()),
            generate_callback: Mutex::new(None),
            revocation_manager,
        }
    }

    /// Register a callback that generates a new QKey and returns its ID.
    pub fn set_generate_callback<F>(&self, callback: F)
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        *self.generate_callback.lock().unwrap() = Some(Box::new(callback));
    }

    /// Check if rotation is due. If so, trigger rotation and return the new key ID.
    pub fn check_and_rotate(&self) -> Option<String> {
        let last = *self.last_rotation.read().unwrap();
        if last.elapsed() < self.rotation_interval {
            return None;
        }

        // Generate new key.
        let new_key_id = {
            let cb = self.generate_callback.lock().unwrap();
            if let Some(callback) = cb.as_ref() {
                callback()
            } else {
                return None;
            }
        };

        // Schedule revocation of the old key after the overlap window.
        // (In a real implementation, the old key ID would be passed here.)
        *self.last_rotation.write().unwrap() = Instant::now();

        log::info!("QKey rotated: new key id={}", new_key_id);
        Some(new_key_id)
    }

    /// Schedule revocation of an old key after the overlap window.
    pub fn schedule_revocation(&self, old_key_id: &str) {
        self.pending_revocations.write().unwrap().push((old_key_id.to_string(), Instant::now()));
        log::info!(
            "QKey revocation scheduled: id={} after {}s overlap",
            old_key_id,
            self.overlap_window.as_secs()
        );
    }

    /// Process pending revocations. Called periodically (e.g., every second).
    /// Revokes keys whose overlap window has expired.
    pub fn process_pending_revocations(&self) {
        let now = Instant::now();
        let mut pending = self.pending_revocations.write().unwrap();
        let mut to_revoke = Vec::new();
        pending.retain(|(key_id, scheduled_at)| {
            if now.duration_since(*scheduled_at) >= self.overlap_window {
                to_revoke.push(key_id.clone());
                false
            } else {
                true
            }
        });
        drop(pending);

        for key_id in to_revoke {
            self.revocation_manager.revoke(&key_id, "rotation overlap window expired");
        }
    }

    /// Time until the next rotation (seconds).
    pub fn time_until_rotation(&self) -> u64 {
        let last = *self.last_rotation.read().unwrap();
        let elapsed = last.elapsed();
        if elapsed >= self.rotation_interval {
            0
        } else {
            (self.rotation_interval - elapsed).as_secs()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_manager_basic() {
        let mgr = RevocationManager::new();
        assert!(!mgr.is_revoked("key1"));
        mgr.revoke("key1", "compromised");
        assert!(mgr.is_revoked("key1"));
        assert!(!mgr.is_revoked("key2"));
    }

    #[test]
    fn test_revocation_manager_list() {
        let mgr = RevocationManager::new();
        mgr.revoke("key1", "reason1");
        mgr.revoke("key2", "reason2");
        let list = mgr.list_revoked();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_revocation_manager_unrevoke() {
        let mgr = RevocationManager::new();
        mgr.revoke("key1", "test");
        assert!(mgr.is_revoked("key1"));
        assert!(mgr.unrevoke("key1"));
        assert!(!mgr.is_revoked("key1"));
        assert!(!mgr.unrevoke("nonexistent"));
    }

    #[test]
    fn test_revocation_manager_terminate_callback() {
        let mgr = RevocationManager::new();
        let terminated = Arc::new(Mutex::new(Vec::new()));
        let terminated_clone = terminated.clone();
        mgr.set_terminate_callback(move |key_id| {
            terminated_clone.lock().unwrap().push(key_id.to_string());
        });
        mgr.revoke("key1", "compromised");
        assert_eq!(terminated.lock().unwrap().len(), 1);
        assert_eq!(terminated.lock().unwrap()[0], "key1");
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

    #[test]
    fn test_key_rotation_manager_time_until() {
        let revocation = Arc::new(RevocationManager::new());
        let mgr = KeyRotationManager::new(3600, 300, revocation);
        // Just created, so ~3600 seconds until rotation.
        let t = mgr.time_until_rotation();
        assert!((3599..=3600).contains(&t));
    }

    #[test]
    fn test_key_rotation_manager_pending_revocation() {
        let revocation = Arc::new(RevocationManager::new());
        // Very short overlap window for testing.
        let mgr = KeyRotationManager::new(3600, 0, revocation.clone());
        mgr.schedule_revocation("oldKey");
        // Overlap is 0, so process_pending should revoke immediately.
        mgr.process_pending_revocations();
        assert!(revocation.is_revoked("oldKey"));
    }
}
