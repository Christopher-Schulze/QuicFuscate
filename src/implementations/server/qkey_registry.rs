use std::path::PathBuf;

use crate::secret::{SecretBytes, SecretString};
use qf_engine_types::QKeyToken;

use super::auth_frame::AuthFrame;
use super::qkey_registry_storage::{RegistryStorage, RewriteReason};
use super::replay_window::ReplayWindow;

pub use super::qkey_registry_storage::QKeyRegistryError;

/// Public, stable QKey id used as the QUIC Initial token.
///
/// This is not a secret. Authentication is enforced separately by verifying the per-QKey token
/// post-handshake.
pub fn qkey_id(qkey: &str) -> String {
    qf_engine_types::id(qkey)
}

pub fn qkey_token_hex_from_qkey(qkey: &str) -> Option<QKeyToken> {
    let trimmed = qkey.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(cfg) = qf_engine_types::parse(trimmed) {
        if let Some(token) = cfg.token {
            let token = token.trim();
            if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Some(QKeyToken::new(token.to_ascii_lowercase()));
            }
        }
    }
    None
}

#[derive(Clone, serde::Serialize)]
pub struct QKeyEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth_policy: Option<super::bandwidth::BandwidthPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct QKeyRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// SHA-256 of the 32-byte QKey token. This is the capability verifier (post-handshake).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_sha256: String,
    /// Optional per-key policy overrides. "auto" means no override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    /// Optional per-key policy overrides. "auto" means no override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth_policy: Option<super::bandwidth::BandwidthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

pub struct QKeyRegistry {
    pub entries: Vec<QKeyRecord>,
    max_entries: usize,
    storage: Option<RegistryStorage>,
    default_ttl_secs: Option<u64>,
    /// Sliding-window anti-replay protection for QKey auth frames.
    replay_window: ReplayWindow,
    /// Wall-clock source for epoch metadata and expiry decisions.
    clock: crate::time_source::ProtocolClock,
    #[cfg(any(test, feature = "rust-tests"))]
    initial_lookup_count: u64,
}

/// Default replay-window size in seconds for auth-frame replay protection.
const DEFAULT_AUTH_REPLAY_WINDOW_SECS: u64 = 300;

impl QKeyRegistry {
    pub fn new_in_memory(max_entries: usize, default_ttl_secs: Option<u64>) -> Self {
        Self::new_in_memory_with_clock(
            max_entries,
            default_ttl_secs,
            &crate::time_source::ProtocolClock::default(),
        )
    }

    /// Create an in-memory registry bound to an explicit clock.
    pub fn new_in_memory_with_clock(
        max_entries: usize,
        default_ttl_secs: Option<u64>,
        clock: &crate::time_source::ProtocolClock,
    ) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            storage: None,
            default_ttl_secs,
            replay_window: ReplayWindow::new(DEFAULT_AUTH_REPLAY_WINDOW_SECS),
            clock: clock.clone(),
            #[cfg(any(test, feature = "rust-tests"))]
            initial_lookup_count: 0,
        }
    }

    pub fn open(
        max_entries: usize,
        path: PathBuf,
        default_ttl_secs: Option<u64>,
    ) -> Result<Self, QKeyRegistryError> {
        Self::open_with_clock(
            max_entries,
            path,
            default_ttl_secs,
            crate::time_source::ProtocolClock::default(),
        )
    }

    /// Open a persisted registry bound to an explicit wall-clock source.
    pub fn open_with_clock(
        max_entries: usize,
        path: PathBuf,
        default_ttl_secs: Option<u64>,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, QKeyRegistryError> {
        Self::open_with_storage(
            max_entries,
            default_ttl_secs,
            RegistryStorage::from_environment(path)?,
            clock,
        )
    }

    fn open_with_storage(
        max_entries: usize,
        default_ttl_secs: Option<u64>,
        storage: RegistryStorage,
        clock: crate::time_source::ProtocolClock,
    ) -> Result<Self, QKeyRegistryError> {
        let mut registry = Self {
            entries: Vec::new(),
            max_entries,
            storage: Some(storage),
            default_ttl_secs,
            replay_window: ReplayWindow::new(DEFAULT_AUTH_REPLAY_WINDOW_SECS),
            clock,
            #[cfg(any(test, feature = "rust-tests"))]
            initial_lookup_count: 0,
        };
        registry.load()?;
        Ok(registry)
    }

    #[cfg(test)]
    fn open_with_test_keys(
        max_entries: usize,
        path: PathBuf,
        default_ttl_secs: Option<u64>,
        current: Option<[u8; 32]>,
        previous: Option<[u8; 32]>,
    ) -> Result<Self, QKeyRegistryError> {
        Self::open_with_storage(
            max_entries,
            default_ttl_secs,
            RegistryStorage::for_test(path, current, previous)?,
            crate::time_source::ProtocolClock::default(),
        )
    }

    fn load(&mut self) -> Result<(), QKeyRegistryError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(());
        };
        let Some(loaded) = storage.load()? else {
            return Ok(());
        };
        let mut entries: Vec<QKeyRecord> = serde_json::from_slice(loaded.as_slice())
            .map_err(|error| QKeyRegistryError::InvalidPlaintext(error.to_string()))?;
        let now = current_epoch_secs(&self.clock)?;
        let mut seen = std::collections::HashSet::new();
        let mut filtered = Vec::new();
        let mut updated = false;
        for mut entry in entries.drain(..) {
            if entry.id.trim().is_empty() || entry.token_sha256.trim().is_empty() {
                updated = true;
                continue;
            }
            if entry.created_at == 0 {
                entry.created_at = now;
                updated = true;
            }
            if let Some(policy) = entry.bandwidth_policy.as_ref() {
                policy.validate().map_err(QKeyRegistryError::InvalidRecord)?;
            }
            if let Some(policy) = entry.traffic_analysis_policy {
                policy
                    .validate()
                    .map_err(|error| QKeyRegistryError::InvalidRecord(error.to_string()))?;
            }
            if !seen.insert(entry.id.clone()) {
                updated = true;
                continue;
            }
            filtered.push(entry);
        }
        if filtered.len() > self.max_entries {
            let excess = filtered.len() - self.max_entries;
            filtered.drain(0..excess);
            updated = true;
        }
        let before = filtered.len();
        filtered.retain(|entry| !is_expired(entry.expires_at, now));
        let removed = before != filtered.len();
        let rewrite =
            loaded.rewrite.or_else(|| (removed || updated).then_some(RewriteReason::Normal));
        if let Some(reason) = rewrite {
            let payload = serialize_records(&filtered)?;
            storage.persist(payload.as_slice(), reason)?;
        }
        self.entries = filtered;
        Ok(())
    }

    pub fn insert(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        name: Option<String>,
    ) -> Result<QKeyEntry, QKeyRegistryError> {
        self.insert_with_ttl(qkey, token_hex, None, name)
    }

    pub fn insert_with_ttl(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        ttl_seconds: Option<u64>,
        name: Option<String>,
    ) -> Result<QKeyEntry, QKeyRegistryError> {
        self.insert_with_ttl_and_bandwidth(qkey, token_hex, ttl_seconds, name, None)
    }

    pub fn insert_with_ttl_and_bandwidth(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        ttl_seconds: Option<u64>,
        name: Option<String>,
        bandwidth_policy: Option<super::bandwidth::BandwidthPolicy>,
    ) -> Result<QKeyEntry, QKeyRegistryError> {
        self.insert_with_ttl_and_policies(
            qkey,
            token_hex,
            ttl_seconds,
            name,
            bandwidth_policy,
            None,
        )
    }

    pub fn insert_with_ttl_and_policies(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        ttl_seconds: Option<u64>,
        name: Option<String>,
        bandwidth_policy: Option<super::bandwidth::BandwidthPolicy>,
        traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
    ) -> Result<QKeyEntry, QKeyRegistryError> {
        if let Some(policy) = bandwidth_policy.as_ref() {
            policy.validate().map_err(QKeyRegistryError::InvalidRecord)?;
        }
        if let Some(policy) = traffic_analysis_policy {
            policy
                .validate()
                .map_err(|error| QKeyRegistryError::InvalidRecord(error.to_string()))?;
        }
        let qkey = SecretString::new(qkey, "qkey_registry_input");
        let mut candidate = self.active_entries()?;
        let now = current_epoch_secs(&self.clock)?;
        let id = qkey_id(&qkey);
        if let Some(existing) = candidate.iter().find(|e| e.id == id).cloned() {
            self.commit_entries(candidate)?;
            return Ok(QKeyEntry {
                id: existing.id,
                name: existing.name,
                created_at: existing.created_at,
                expires_at: existing.expires_at,
                stealth: existing.stealth,
                fec: existing.fec,
                bandwidth_policy: existing.bandwidth_policy,
                traffic_analysis_policy: existing.traffic_analysis_policy,
            });
        }
        let parsed = qf_engine_types::parse(qkey.trim()).ok();
        let (stealth, fec) = parsed.as_ref().map(policy_from_parsed_qkey).unwrap_or((None, None));
        let token_sha256 = match token_sha256_hex_from_token_hex(&token_hex) {
            Some(h) => h,
            None => {
                return Err(QKeyRegistryError::InvalidRecord(
                    "QKey token must contain exactly 64 hexadecimal characters".to_string(),
                ));
            }
        };
        let expires_at = compute_expiry(ttl_seconds.or(self.default_ttl_secs), now)?;
        let record = QKeyRecord {
            id,
            name,
            token_sha256,
            stealth,
            fec,
            bandwidth_policy,
            traffic_analysis_policy,
            created_at: now,
            expires_at,
        };
        candidate.push(record.clone());
        if candidate.len() > self.max_entries {
            let excess = candidate.len() - self.max_entries;
            candidate.drain(0..excess);
        }
        self.commit_entries(candidate)?;
        crate::audit::audit(
            crate::audit::AuditEventType::QkeyIssued,
            crate::audit::AuditSeverity::Info,
            None,
            Some(&record.id),
            "QKey issued",
        );
        Ok(QKeyEntry {
            id: record.id,
            name: record.name,
            created_at: record.created_at,
            expires_at: record.expires_at,
            stealth: record.stealth,
            fec: record.fec,
            bandwidth_policy: record.bandwidth_policy,
            traffic_analysis_policy: record.traffic_analysis_policy,
        })
    }

    pub fn list(&mut self) -> Result<Vec<QKeyEntry>, QKeyRegistryError> {
        let now = current_epoch_secs(&self.clock)?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| !is_expired(entry.expires_at, now))
            .cloned()
            .map(|entry| QKeyEntry {
                id: entry.id,
                name: entry.name,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                stealth: entry.stealth,
                fec: entry.fec,
                bandwidth_policy: entry.bandwidth_policy,
                traffic_analysis_policy: entry.traffic_analysis_policy,
            })
            .collect())
    }

    pub fn revoke(&mut self, id: &str) -> Result<bool, QKeyRegistryError> {
        let mut candidate = self.active_entries()?;
        let before = candidate.len();
        candidate.retain(|entry| entry.id != id);
        let changed = before != candidate.len();
        if changed || candidate.len() != self.entries.len() {
            self.commit_entries(candidate)?;
        }
        Ok(changed)
    }

    pub fn record_for_id_token(&mut self, token: &[u8]) -> Option<QKeyRecord> {
        self.lookup_initial_id_token(token)
    }

    /// Verify a QKey auth frame end-to-end: look up the record by the frame's
    /// `client_id`, confirm the HMAC proves possession of the QKey token, then
    /// run the frame through the replay window so a captured frame cannot be
    /// reused.
    ///
    /// Returns `true` only if the record exists, the HMAC is valid, and the
    /// `(timestamp, nonce)` pair is fresh.
    pub fn verify_auth_frame(&mut self, frame: &AuthFrame, qkey_token: &[u8]) -> bool {
        let now = match current_epoch_secs(&self.clock) {
            Ok(now) => now,
            Err(_) => return false,
        };
        let exists = self
            .entries
            .iter()
            .any(|entry| entry.id == frame.client_id && !is_expired(entry.expires_at, now));
        if !exists {
            return false;
        }
        if !frame.verify(&frame.client_id, qkey_token) {
            return false;
        }
        self.replay_window.check_and_mark(frame.timestamp, &frame.nonce)
    }

    /// Prune replay slots against the current Unix-epoch timestamp.
    pub fn prune_replay_window(&mut self) -> Result<(), QKeyRegistryError> {
        let now = current_epoch_secs(&self.clock)?;
        self.replay_window.prune(now);
        Ok(())
    }

    /// Look up a record by Initial packet token value, which must be a 12-char
    /// QKey identifier (case-insensitive hex).
    pub fn lookup_initial_id_token(&mut self, token: &[u8]) -> Option<QKeyRecord> {
        #[cfg(any(test, feature = "rust-tests"))]
        {
            self.initial_lookup_count = self.initial_lookup_count.saturating_add(1);
        }
        let id = normalize_initial_id_token(token)?;
        let now = current_epoch_secs(&self.clock).ok()?;
        self.entries
            .iter()
            .find(|entry| entry.id == id && !is_expired(entry.expires_at, now))
            .cloned()
    }

    #[cfg(any(test, feature = "rust-tests"))]
    pub fn initial_lookup_count(&self) -> u64 {
        self.initial_lookup_count
    }

    pub fn has_entries(&mut self) -> Result<bool, QKeyRegistryError> {
        let now = current_epoch_secs(&self.clock)?;
        Ok(self.entries.iter().any(|entry| !is_expired(entry.expires_at, now)))
    }

    fn active_entries(&self) -> Result<Vec<QKeyRecord>, QKeyRegistryError> {
        let now = current_epoch_secs(&self.clock)?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| !is_expired(entry.expires_at, now))
            .cloned()
            .collect())
    }

    fn commit_entries(&mut self, entries: Vec<QKeyRecord>) -> Result<(), QKeyRegistryError> {
        if let Some(storage) = self.storage.as_ref() {
            let payload = serialize_records(&entries)?;
            storage.persist(payload.as_slice(), RewriteReason::Normal)?;
        }
        self.entries = entries;
        Ok(())
    }
}

fn serialize_records(entries: &[QKeyRecord]) -> Result<SecretBytes, QKeyRegistryError> {
    serde_json::to_vec_pretty(entries)
        .map(|bytes| SecretBytes::new(bytes, "qkey_registry_serialized_records"))
        .map_err(|error| QKeyRegistryError::Serialization(error.to_string()))
}

fn normalize_initial_id_token(token: &[u8]) -> Option<String> {
    let id = std::str::from_utf8(token).ok()?.trim();
    if id.len() != 12 {
        return None;
    }
    if !id.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.to_ascii_lowercase())
}

fn current_epoch_secs(clock: &crate::time_source::ProtocolClock) -> Result<u64, QKeyRegistryError> {
    crate::time_source::unix_epoch_seconds(clock.now_system()).map_err(QKeyRegistryError::Clock)
}

/// Hash a 64-char hex token string by decoding to 32 binary bytes first, then SHA256.
pub fn token_sha256_hex_from_token_hex(token_hex: &str) -> Option<String> {
    let token_hex = token_hex.trim();
    if token_hex.len() != 64 {
        return None;
    }
    let mut binary = SecretBytes::zeroed(32, "qkey_decoded_token");
    hex::decode_to_slice(token_hex, binary.as_mut_slice()).ok()?;
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(binary.as_slice());
    Some(format!("{:x}", hasher.finalize()))
}

/// Check if a token matches a stored hash.
/// Returns `true` if the SHA-256 of the decoded 32-byte token matches the stored hash.
pub fn token_matches_hash(token_hex: &str, stored_hash: &str) -> bool {
    token_sha256_hex_from_token_hex(token_hex)
        .map(|h| h.eq_ignore_ascii_case(stored_hash))
        .unwrap_or(false)
}

fn policy_from_parsed_qkey(cfg: &qf_engine_types::QKeyConfig) -> (Option<String>, Option<String>) {
    let stealth = cfg
        .stealth
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s != "auto");
    let fec = cfg
        .fec
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s != "auto");
    (stealth, fec)
}

fn compute_expiry(ttl_seconds: Option<u64>, now: u64) -> Result<Option<u64>, QKeyRegistryError> {
    let ttl = match ttl_seconds {
        Some(0) | None => return Ok(None),
        Some(v) => v,
    };
    now.checked_add(ttl)
        .map(Some)
        .ok_or(QKeyRegistryError::Clock(crate::time_source::WallClockError::CalendarOverflow))
}

fn is_expired(expires_at: Option<u64>, now: u64) -> bool {
    matches!(expires_at, Some(ts) if ts <= now)
}

#[cfg(test)]
mod tests {
    use super::super::auth_frame::AuthFrame;
    use super::*;
    use qf_engine_types as qkey;
    use std::path::Path;

    fn mk_token_hex(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn mk_qkey_with_token(token_hex: &str) -> String {
        let cfg = qkey::QKeyConfig::new("127.0.0.1:4433", "example.com")
            .with_stealth("auto")
            .with_fec("auto")
            .with_token(token_hex);
        qkey::generate(&cfg)
    }

    fn mk_temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let salt = fastrand::u64(..);
        p.push(format!("quicfuscate-test-{name}-{salt}.json"));
        p
    }

    fn read_records(path: &Path) -> Vec<QKeyRecord> {
        let bytes = std::fs::read(path).expect("read test file");
        serde_json::from_slice::<Vec<QKeyRecord>>(&bytes).expect("parse json")
    }

    #[test]
    fn insert_and_lookup_by_initial_id_token() {
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let token_sha = token_sha256_hex_from_token_hex(&token_hex).expect("sha");

        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value.clone(), token_hex.clone().into(), None).expect("insert");

        let got = reg.lookup_initial_id_token(id.as_bytes()).expect("record must exist");
        assert_eq!(got.id, id);
        assert_eq!(got.token_sha256, token_sha);

        assert!(reg.lookup_initial_id_token(b"").is_none());
        assert!(reg.lookup_initial_id_token(b"unknown").is_none());
    }

    #[test]
    fn registry_rejects_pre_epoch_wall_clock_without_epoch_zero_metadata() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1),
        );
        let clock = crate::time_source::ProtocolClock::from_source(source);
        let mut registry = QKeyRegistry::new_in_memory_with_clock(16, None, &clock);
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);

        assert!(matches!(
            registry.insert(qkey_value, token_hex.into(), None),
            Err(QKeyRegistryError::Clock(crate::time_source::WallClockError::BeforeUnixEpoch))
        ));
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn authenticated_traffic_analysis_policy_roundtrips_through_registry() {
        let token_hex = mk_token_hex('e');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let policy = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            chaff_rate_pps: 0,
            chaff_size_bytes: 1200,
            constant_rate_pps: 80,
            idle_timeout_ms: 20_000,
            ramp_down_ms: 2_000,
        };
        let mut registry = QKeyRegistry::new_in_memory(16, None);

        let entry = registry
            .insert_with_ttl_and_policies(
                qkey_value,
                token_hex.into(),
                None,
                None,
                None,
                Some(policy),
            )
            .expect("valid policy");

        assert_eq!(entry.traffic_analysis_policy, Some(policy));
        assert_eq!(
            registry
                .lookup_initial_id_token(id.as_bytes())
                .expect("stored record")
                .traffic_analysis_policy,
            Some(policy)
        );
    }

    #[test]
    fn registry_rejects_unsafe_traffic_analysis_policy() {
        let token_hex = mk_token_hex('f');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let invalid = crate::transport::config::TrafficAnalysisPolicy {
            defense: crate::transport::config::TrafficAnalysisDefense::ConstantRate,
            constant_rate_pps:
                crate::transport::config::TrafficAnalysisPolicy::MAX_CONSTANT_RATE_PPS + 1,
            ..crate::transport::config::TrafficAnalysisPolicy::default()
        };
        let mut registry = QKeyRegistry::new_in_memory(16, None);

        assert!(registry
            .insert_with_ttl_and_policies(
                qkey_value,
                token_hex.into(),
                None,
                None,
                None,
                Some(invalid),
            )
            .is_err());
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn qkey_id_is_stable_across_prefix_case_and_whitespace() {
        let token_hex = mk_token_hex('f');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let rest = qkey_value
            .trim()
            .strip_prefix(qf_engine_types::QKEY_PREFIX)
            .expect("generated key has prefix");
        let pasted = format!("  {}{}  ", qf_engine_types::QKEY_PREFIX.to_lowercase(), rest);
        assert_eq!(qkey_id(&qkey_value), qkey_id(&pasted));
    }

    #[test]
    fn prunes_expired_records() {
        let token_hex = mk_token_hex('b');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        assert_eq!(reg.entries.len(), 1);

        let now = current_epoch_secs(&reg.clock).unwrap();
        reg.entries[0].expires_at = Some(now.saturating_sub(1));

        assert!(reg.lookup_initial_id_token(id.as_bytes()).is_none());
        assert!(reg.list().unwrap().is_empty());
    }

    #[test]
    fn lookup_initial_id_token_rejects_non_hex_and_too_short_values() {
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        assert!(reg.lookup_initial_id_token(id.to_uppercase().as_bytes()).is_some());
        assert!(reg.lookup_initial_id_token(b"").is_none());
        assert!(reg.lookup_initial_id_token(b"abc").is_none());
        assert!(reg.lookup_initial_id_token(b"a1b2c3d4e5f6g7").is_none());
    }

    #[test]
    fn revoke_persists_to_disk() {
        let path = mk_temp_path("qkeys-revoke");
        let _ = std::fs::remove_file(&path);

        let token_hex = mk_token_hex('c');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        {
            let mut reg = QKeyRegistry::open_with_test_keys(200, path.clone(), None, None, None)
                .expect("open registry");
            reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        }

        let before = read_records(&path);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].id, id);

        {
            let mut reg = QKeyRegistry::open_with_test_keys(200, path.clone(), None, None, None)
                .expect("open registry");
            assert!(reg.revoke(&id).expect("persist revoke"));
        }

        let after = read_records(&path);
        assert_eq!(after.len(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_filters_invalid_entries() {
        let path = mk_temp_path("qkeys-load");
        let _ = std::fs::remove_file(&path);

        let token_hex = mk_token_hex('d');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let sha = token_sha256_hex_from_token_hex(&token_hex).expect("sha");
        let clock = crate::time_source::ProtocolClock::default();
        let now = current_epoch_secs(&clock).unwrap();

        let records = vec![
            // Empty id - dropped
            QKeyRecord {
                id: "".to_string(),
                name: None,
                token_sha256: sha.clone(),
                stealth: None,
                fec: None,
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                created_at: now,
                expires_at: None,
            },
            // Empty token_sha256 - dropped
            QKeyRecord {
                id: "no-sha".to_string(),
                name: None,
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                created_at: now,
                expires_at: None,
            },
            // Expired - dropped
            QKeyRecord {
                id: "expired".to_string(),
                name: None,
                token_sha256: sha.clone(),
                stealth: None,
                fec: None,
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                created_at: now,
                expires_at: Some(now.saturating_sub(1)),
            },
            // Valid - kept
            QKeyRecord {
                id: id.clone(),
                name: None,
                token_sha256: sha.clone(),
                stealth: None,
                fec: None,
                bandwidth_policy: None,
                traffic_analysis_policy: None,
                created_at: now,
                expires_at: None,
            },
        ];

        let bytes = serde_json::to_vec_pretty(&records).expect("serialize");
        std::fs::write(&path, bytes).expect("write test file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set registry permissions");
        }

        let reg = QKeyRegistry::open_with_test_keys(200, path.clone(), None, None, None)
            .expect("open registry");
        assert_eq!(reg.entries.len(), 1);
        assert_eq!(reg.entries[0].id, id);
        assert_eq!(reg.entries[0].token_sha256, sha);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn failed_encrypted_insert_keeps_memory_and_durable_registry_unchanged() {
        use super::super::qkey_registry_storage::test_failpoint;

        let path = mk_temp_path("qkeys-transaction");
        let backup_path = {
            let mut file_name = path.file_name().expect("file name").to_os_string();
            file_name.push(".backup");
            path.with_file_name(file_name)
        };
        let key = [0x81; 32];
        let mut registry =
            QKeyRegistry::open_with_test_keys(200, path.clone(), None, Some(key), None)
                .expect("open encrypted registry");
        let first_token = mk_token_hex('a');
        let first_qkey = mk_qkey_with_token(&first_token);
        let first =
            registry.insert(first_qkey, first_token.into(), None).expect("insert first record");
        let durable_before = std::fs::read(&path).expect("read first durable registry");

        let second_token = mk_token_hex('b');
        let second_qkey = mk_qkey_with_token(&second_token);
        {
            let _failure = test_failpoint::install(2);
            assert!(registry.insert(second_qkey, second_token.into(), None).is_err());
        }
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.entries[0].id, first.id);
        assert_eq!(std::fs::read(&path).expect("read retained primary"), durable_before);
        assert_eq!(std::fs::read(&backup_path).expect("read retained backup"), durable_before);

        let reopened = QKeyRegistry::open_with_test_keys(200, path.clone(), None, Some(key), None)
            .expect("reopen encrypted registry");
        assert_eq!(reopened.entries.len(), 1);
        assert_eq!(reopened.entries[0].id, first.id);

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(backup_path);
    }

    #[test]
    fn qkey_token_hex_extraction_is_stable_and_lowercased() {
        let token_hex = "A".repeat(64);
        let qkey_value = mk_qkey_with_token(&token_hex);
        let lower = qkey_token_hex_from_qkey(&qkey_value).expect("token");
        assert_eq!(lower.as_ref(), "a".repeat(64));

        let mut pasted = qkey_value.clone();
        if let Some(rest) = pasted.strip_prefix(qf_engine_types::QKEY_PREFIX) {
            pasted = format!("{}{}", qf_engine_types::QKEY_PREFIX.to_lowercase(), rest);
        }
        let lower2 = qkey_token_hex_from_qkey(&pasted).expect("token");
        assert_eq!(lower2.as_ref(), "a".repeat(64));
    }

    #[test]
    fn token_sha256_hex_validation_rejects_bad_inputs() {
        assert!(token_sha256_hex_from_token_hex("").is_none());
        assert!(token_sha256_hex_from_token_hex("abc").is_none());
        assert!(token_sha256_hex_from_token_hex(&"g".repeat(64)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"a".repeat(63)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"a".repeat(65)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"A".repeat(64)).is_some());
    }

    #[test]
    fn decoded_token_normal_and_partial_error_paths_erase_before_deallocation() {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let observed = Arc::clone(&events);
        let _observer = crate::secret::test_observation::install(Arc::new(move |label, bytes| {
            if label == "qkey_decoded_token" {
                observed.lock().expect("erasure event lock").push(bytes.to_vec());
            }
        }));

        assert!(token_sha256_hex_from_token_hex(&"a5".repeat(32)).is_some());
        let mut partial = "a5".repeat(32);
        partial.replace_range(46..48, "zz");
        assert!(token_sha256_hex_from_token_hex(&partial).is_none());

        let events = events.lock().expect("erasure events");
        assert_eq!(events.len(), 2, "normal and partial decode owners must both be observed");
        for bytes in events.iter() {
            assert_eq!(bytes.len(), 32);
            assert!(bytes.iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn insert_with_ttl_applies_expiry_and_zero_means_no_expiry() {
        let mut reg = QKeyRegistry::new_in_memory(200, Some(90));

        let t1 = mk_token_hex('1');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert_with_ttl(q1, t1.into(), Some(60), None).expect("insert ttl");
        let now = current_epoch_secs(&reg.clock).unwrap();
        let exp = e1.expires_at.expect("expires");
        assert!(exp >= now + 55 && exp <= now + 65);

        let t2 = mk_token_hex('2');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert_with_ttl(q2, t2.into(), Some(0), None).expect("insert no expiry");
        assert!(e2.expires_at.is_none());
    }

    #[test]
    fn insert_with_default_ttl_is_used_when_request_ttl_missing() {
        let mut reg = QKeyRegistry::new_in_memory(200, Some(120));
        let token_hex = mk_token_hex('3');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let e = reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        let now = current_epoch_secs(&reg.clock).unwrap();
        let exp = e.expires_at.expect("default expiry");
        assert!(exp >= now + 115 && exp <= now + 125);
    }

    #[test]
    fn max_entries_evicts_oldest_records() {
        let mut reg = QKeyRegistry::new_in_memory(2, None);

        let t1 = mk_token_hex('4');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert(q1, t1.into(), None).expect("insert 1");

        let t2 = mk_token_hex('5');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert(q2, t2.into(), None).expect("insert 2");

        let t3 = mk_token_hex('6');
        let q3 = mk_qkey_with_token(&t3);
        let e3 = reg.insert(q3, t3.into(), None).expect("insert 3");

        let ids: Vec<String> = reg.list().unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains(&e1.id));
        assert!(ids.contains(&e2.id));
        assert!(ids.contains(&e3.id));
    }

    #[test]
    fn verify_auth_frame_accepts_fresh_and_rejects_replay() {
        let token_hex = mk_token_hex('7');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value, token_hex.clone().into(), None).expect("insert");

        let token_bytes = hex::decode(token_hex.to_ascii_lowercase()).expect("decode token");
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let frame = AuthFrame::build(&id, &token_bytes, 1_700_000_000, &nonce);

        // Fresh frame: HMAC valid + nonce unseen -> accepted.
        assert!(reg.verify_auth_frame(&frame, &token_bytes));

        // Replay: same (timestamp, nonce) -> rejected.
        assert!(!reg.verify_auth_frame(&frame, &token_bytes));

        // New nonce, same timestamp -> accepted.
        let mut nonce2 = nonce;
        nonce2[0] ^= 0xff;
        let frame2 = AuthFrame::build(&id, &token_bytes, 1_700_000_000, &nonce2);
        assert!(reg.verify_auth_frame(&frame2, &token_bytes));
    }

    #[test]
    fn verify_auth_frame_rejects_unknown_client_id() {
        let token_hex = mk_token_hex('8');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value, token_hex.clone().into(), None).expect("insert");

        let token_bytes = hex::decode(token_hex.to_ascii_lowercase()).expect("decode token");
        let nonce = [0u8; 16];
        // Valid HMAC for a client id that is not registered.
        let frame = AuthFrame::build("deadbeefdead", &token_bytes, 1, &nonce);
        assert!(!reg.verify_auth_frame(&frame, &token_bytes));
    }

    #[test]
    fn verify_auth_frame_rejects_wrong_token() {
        let token_hex = mk_token_hex('9');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let mut reg = QKeyRegistry::new_in_memory(200, None);
        reg.insert(qkey_value, token_hex.clone().into(), None).expect("insert");

        let token_bytes = hex::decode(token_hex.to_ascii_lowercase()).expect("decode token");
        let wrong_token = {
            let mut t = [0u8; 32];
            for (i, b) in t.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(7);
            }
            t.to_vec()
        };
        let nonce = [1u8; 16];
        let frame = AuthFrame::build(&id, &token_bytes, 1, &nonce);
        assert!(!reg.verify_auth_frame(&frame, &wrong_token));
    }
}
