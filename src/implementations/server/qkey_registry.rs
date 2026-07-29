use std::path::PathBuf;

use crate::engine::qkey::QKeyToken;
use crate::secret::{SecretBytes, SecretString};

use super::auth_frame::AuthFrame;
use super::replay_window::ReplayWindow;

/// Magic prefix identifying encrypted QKey registry files.
const ENC_MAGIC: &[u8] = b"QFENC1";

/// Load the encryption key from the `QUICFUSCATE_QKEY_ENC_KEY` environment variable.
/// The key must be a 64-character hex string (32 bytes for AES-256-GCM).
/// Returns `None` if the variable is not set or invalid, in which case
/// the registry is stored in plaintext (backward compatible).
fn load_enc_key() -> Option<[u8; 32]> {
    let hex = std::env::var("QUICFUSCATE_QKEY_ENC_KEY").ok()?;
    let hex = hex.trim();
    if hex.len() != 64 {
        log::warn!(
            "QUICFUSCATE_QKEY_ENC_KEY must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        );
        return None;
    }
    let mut key = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        key[i] = byte;
    }
    Some(key)
}

/// Encrypt plaintext using ChaCha20-Poly1305 with a random nonce.
/// Returns: magic || nonce (12 bytes) || ciphertext (includes 16-byte tag)
fn encrypt_payload(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use crate::crypto::aead::AeadSeal;
    // Generate a random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    crate::rng::fill_secure(&mut nonce_bytes)
        .map_err(|e| format!("nonce generation failed: {}", e))?;

    let cipher = crate::crypto::ChaCha20Poly1305::new(key, &nonce_bytes);

    // Buffer layout: plaintext + 16-byte tag
    let mut buf = vec![0u8; plaintext.len() + 16];
    buf[..plaintext.len()].copy_from_slice(plaintext);

    let written = cipher
        .seal_with_u64_counter(0, &[], &mut buf, plaintext.len(), None)
        .map_err(|e| format!("encryption failed: {:?}", e))?;

    let mut out = Vec::with_capacity(ENC_MAGIC.len() + 12 + written);
    out.extend_from_slice(ENC_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf[..written]);
    Ok(out)
}

/// Decrypt a payload encrypted by `encrypt_payload`.
/// Returns the plaintext if the magic prefix matches and decryption succeeds.
/// Returns `None` if the payload is not encrypted (no magic prefix), allowing
/// backward-compatible reading of plaintext files.
fn decrypt_payload(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() < ENC_MAGIC.len() + 12 + 16 {
        return None; // Too short to be encrypted
    }
    if &data[..ENC_MAGIC.len()] != ENC_MAGIC {
        return None; // Not encrypted - plaintext file
    }

    use crate::crypto::aead::AeadOpen;
    let nonce_bytes = &data[ENC_MAGIC.len()..ENC_MAGIC.len() + 12];
    let cipher = crate::crypto::ChaCha20Poly1305::new(key, nonce_bytes);

    let ct_with_tag = &data[ENC_MAGIC.len() + 12..];
    let mut buf = ct_with_tag.to_vec();

    let plaintext_len = cipher.open_with_u64_counter(0, &[], &mut buf).ok()?;

    Some(buf[..plaintext_len].to_vec())
}

/// Public, stable QKey id used as the QUIC Initial token.
///
/// This is not a secret. Authentication is enforced separately by verifying the per-QKey token
/// post-handshake.
pub fn qkey_id(qkey: &str) -> String {
    crate::engine::qkey::id(qkey)
}

pub fn qkey_token_hex_from_qkey(qkey: &str) -> Option<QKeyToken> {
    let trimmed = qkey.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(cfg) = crate::engine::qkey::parse(trimmed) {
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
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

pub struct QKeyRegistry {
    pub entries: Vec<QKeyRecord>,
    max_entries: usize,
    path: Option<PathBuf>,
    default_ttl_secs: Option<u64>,
    /// Sliding-window anti-replay protection for QKey auth frames.
    replay_window: ReplayWindow,
}

/// Default replay-window size in seconds for auth-frame replay protection.
const DEFAULT_AUTH_REPLAY_WINDOW_SECS: u64 = 300;

impl QKeyRegistry {
    pub fn new(max_entries: usize, path: Option<PathBuf>, default_ttl_secs: Option<u64>) -> Self {
        let mut registry = Self {
            entries: Vec::new(),
            max_entries,
            path,
            default_ttl_secs,
            replay_window: ReplayWindow::new(DEFAULT_AUTH_REPLAY_WINDOW_SECS),
        };
        registry.load();
        registry
    }

    pub fn load(&mut self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let bytes = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::warn!("qkey registry load failed ({}): {}", path.display(), e);
                return;
            }
        };

        // Try to decrypt if an encryption key is configured; fall back to
        // plaintext for backward compatibility.
        let plaintext = match load_enc_key() {
            Some(key) => match decrypt_payload(&bytes, &key) {
                Some(decrypted) => decrypted,
                None => bytes, // Not encrypted or decryption failed - try plaintext
            },
            None => bytes, // No key configured - read as plaintext
        };

        let mut entries: Vec<QKeyRecord> = match serde_json::from_slice(&plaintext) {
            Ok(list) => list,
            Err(e) => {
                log::warn!("qkey registry parse failed ({}): {}", path.display(), e);
                return;
            }
        };
        let mut seen = std::collections::HashSet::new();
        let mut filtered = Vec::new();
        let mut updated = false;
        for mut entry in entries.drain(..) {
            if entry.id.trim().is_empty() || entry.token_sha256.trim().is_empty() {
                continue;
            }
            if entry.created_at == 0 {
                entry.created_at = current_epoch_secs();
                updated = true;
            }
            if !seen.insert(entry.id.clone()) {
                continue;
            }
            filtered.push(entry);
        }
        if filtered.len() > self.max_entries {
            let excess = filtered.len() - self.max_entries;
            filtered.drain(0..excess);
        }
        let before = filtered.len();
        let now = current_epoch_secs();
        filtered.retain(|entry| !is_expired(entry.expires_at, now));
        let removed = before != filtered.len();
        self.entries = filtered;
        if removed || updated {
            self.persist();
        }
    }

    pub fn insert(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        name: Option<String>,
    ) -> Result<QKeyEntry, String> {
        self.insert_with_ttl(qkey, token_hex, None, name)
    }

    pub fn insert_with_ttl(
        &mut self,
        qkey: String,
        token_hex: QKeyToken,
        ttl_seconds: Option<u64>,
        name: Option<String>,
    ) -> Result<QKeyEntry, String> {
        let qkey = SecretString::new(qkey, "qkey_registry_input");
        self.prune_expired();
        let id = qkey_id(&qkey);
        if let Some(existing) = self.entries.iter().find(|e| e.id == id).cloned() {
            return Ok(QKeyEntry {
                id: existing.id,
                name: existing.name,
                created_at: existing.created_at,
                expires_at: existing.expires_at,
                stealth: existing.stealth,
                fec: existing.fec,
            });
        }
        let parsed = crate::engine::qkey::parse(qkey.trim()).ok();
        let (stealth, fec) = parsed.as_ref().map(policy_from_parsed_qkey).unwrap_or((None, None));
        let token_sha256 = match token_sha256_hex_from_token_hex(&token_hex) {
            Some(h) => h,
            None => return Err("Invalid QKey token (expected 64 hex chars)".to_string()),
        };
        let expires_at = compute_expiry(ttl_seconds.or(self.default_ttl_secs));
        let record = QKeyRecord {
            id,
            name,
            token_sha256,
            stealth,
            fec,
            created_at: current_epoch_secs(),
            expires_at,
        };
        self.entries.push(record.clone());
        if self.entries.len() > self.max_entries {
            let excess = self.entries.len() - self.max_entries;
            self.entries.drain(0..excess);
        }
        self.persist();
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
        })
    }

    pub fn list(&mut self) -> Vec<QKeyEntry> {
        self.prune_expired();
        self.entries
            .iter()
            .cloned()
            .map(|entry| QKeyEntry {
                id: entry.id,
                name: entry.name,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                stealth: entry.stealth,
                fec: entry.fec,
            })
            .collect()
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        self.prune_expired();
        let before = self.entries.len();
        self.entries.retain(|entry| entry.id != id);
        let changed = before != self.entries.len();
        if changed {
            self.persist();
        }
        changed
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
        self.prune_expired();
        let exists = self.entries.iter().any(|entry| entry.id == frame.client_id);
        if !exists {
            return false;
        }
        if !frame.verify(&frame.client_id, qkey_token) {
            return false;
        }
        self.replay_window.check_and_mark(frame.timestamp, &frame.nonce)
    }

    /// Look up a record by Initial packet token value, which must be a 12-char
    /// QKey identifier (case-insensitive hex).
    pub fn lookup_initial_id_token(&mut self, token: &[u8]) -> Option<QKeyRecord> {
        let id = normalize_initial_id_token(token)?;
        self.prune_expired();
        self.entries.iter().find(|entry| entry.id == id).cloned()
    }

    pub fn has_entries(&mut self) -> bool {
        self.prune_expired();
        !self.entries.is_empty()
    }

    /// Prune expired QKey entries based on their TTL (expires_at field).
    ///
    /// TTL enforcement (todo-180): QKey entries have an optional `expires_at` epoch timestamp.
    /// When set, the key is considered expired once `current_time >= expires_at`. Expired keys
    /// are removed from the registry and the change is persisted to disk.
    ///
    /// TTL is set during insertion via `insert_with_ttl()` or from `default_ttl_secs` in the
    /// registry config. A TTL of 0 or None means the key never expires.
    ///
    /// This method is called on every registry access (list, lookup, insert, revoke, has_entries)
    /// to ensure expired keys are never returned to callers.
    fn prune_expired(&mut self) {
        let before = self.entries.len();
        let now = current_epoch_secs();
        self.entries.retain(|entry| {
            let expired = is_expired(entry.expires_at, now);
            if expired {
                log::info!(
                    "QKey expired and removed: id={}, expires_at={:?}",
                    entry.id,
                    entry.expires_at
                );
            }
            !expired
        });
        if before != self.entries.len() {
            self.persist();
        }
    }

    fn persist(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::warn!("qkey registry mkdir failed ({}): {}", parent.display(), e);
                return;
            }
        }
        let payload = match serde_json::to_vec_pretty(&self.entries) {
            Ok(data) => data,
            Err(e) => {
                log::warn!("qkey registry serialize failed: {}", e);
                return;
            }
        };

        // Encrypt at rest if an encryption key is configured.
        let final_payload = match load_enc_key() {
            Some(key) => match encrypt_payload(&payload, &key) {
                Ok(encrypted) => encrypted,
                Err(e) => {
                    log::warn!("qkey registry encryption failed, writing plaintext: {}", e);
                    payload
                }
            },
            None => payload, // No key - write plaintext (backward compatible)
        };

        if let Err(e) = super::fsutil::atomic_write_file(
            path,
            &final_payload,
            Some(0o600),
            "qkey_registry::persist_tmp_nonce",
        ) {
            log::warn!("qkey registry write failed ({}): {}", path.display(), e);
        }
    }
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

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

fn policy_from_parsed_qkey(
    cfg: &crate::engine::qkey::QKeyConfig,
) -> (Option<String>, Option<String>) {
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

fn compute_expiry(ttl_seconds: Option<u64>) -> Option<u64> {
    let ttl = match ttl_seconds {
        Some(0) | None => return None,
        Some(v) => v,
    };
    Some(current_epoch_secs().saturating_add(ttl))
}

fn is_expired(expires_at: Option<u64>, now: u64) -> bool {
    matches!(expires_at, Some(ts) if ts <= now)
}

#[cfg(test)]
mod tests {
    use super::super::auth_frame::AuthFrame;
    use super::*;
    use crate::engine::qkey;
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

        let mut reg = QKeyRegistry::new(200, None, None);
        reg.insert(qkey_value.clone(), token_hex.clone().into(), None).expect("insert");

        let got = reg.lookup_initial_id_token(id.as_bytes()).expect("record must exist");
        assert_eq!(got.id, id);
        assert_eq!(got.token_sha256, token_sha);

        assert!(reg.lookup_initial_id_token(b"").is_none());
        assert!(reg.lookup_initial_id_token(b"unknown").is_none());
    }

    #[test]
    fn qkey_id_is_stable_across_prefix_case_and_whitespace() {
        let token_hex = mk_token_hex('f');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let rest = qkey_value
            .trim()
            .strip_prefix(crate::engine::qkey::QKEY_PREFIX)
            .expect("generated key has prefix");
        let pasted = format!("  {}{}  ", crate::engine::qkey::QKEY_PREFIX.to_lowercase(), rest);
        assert_eq!(qkey_id(&qkey_value), qkey_id(&pasted));
    }

    #[test]
    fn prunes_expired_records() {
        let token_hex = mk_token_hex('b');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new(200, None, None);
        reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        assert_eq!(reg.entries.len(), 1);

        let now = current_epoch_secs();
        reg.entries[0].expires_at = Some(now.saturating_sub(1));

        assert!(reg.lookup_initial_id_token(id.as_bytes()).is_none());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn lookup_initial_id_token_rejects_non_hex_and_too_short_values() {
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new(200, None, None);
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
            let mut reg = QKeyRegistry::new(200, Some(path.clone()), None);
            reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        }

        let before = read_records(&path);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].id, id);

        {
            let mut reg = QKeyRegistry::new(200, Some(path.clone()), None);
            assert!(reg.revoke(&id));
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
        let now = current_epoch_secs();

        let records = vec![
            // Empty id - dropped
            QKeyRecord {
                id: "".to_string(),
                name: None,
                token_sha256: sha.clone(),
                stealth: None,
                fec: None,
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
                created_at: now,
                expires_at: None,
            },
        ];

        let bytes = serde_json::to_vec_pretty(&records).expect("serialize");
        std::fs::write(&path, bytes).expect("write test file");

        let reg = QKeyRegistry::new(200, Some(path.clone()), None);
        assert_eq!(reg.entries.len(), 1);
        assert_eq!(reg.entries[0].id, id);
        assert_eq!(reg.entries[0].token_sha256, sha);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn qkey_token_hex_extraction_is_stable_and_lowercased() {
        let token_hex = "A".repeat(64);
        let qkey_value = mk_qkey_with_token(&token_hex);
        let lower = qkey_token_hex_from_qkey(&qkey_value).expect("token");
        assert_eq!(lower.as_ref(), "a".repeat(64));

        let mut pasted = qkey_value.clone();
        if let Some(rest) = pasted.strip_prefix(crate::engine::qkey::QKEY_PREFIX) {
            pasted = format!("{}{}", crate::engine::qkey::QKEY_PREFIX.to_lowercase(), rest);
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
        let mut reg = QKeyRegistry::new(200, None, Some(90));

        let t1 = mk_token_hex('1');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert_with_ttl(q1, t1.into(), Some(60), None).expect("insert ttl");
        let now = current_epoch_secs();
        let exp = e1.expires_at.expect("expires");
        assert!(exp >= now + 55 && exp <= now + 65);

        let t2 = mk_token_hex('2');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert_with_ttl(q2, t2.into(), Some(0), None).expect("insert no expiry");
        assert!(e2.expires_at.is_none());
    }

    #[test]
    fn insert_with_default_ttl_is_used_when_request_ttl_missing() {
        let mut reg = QKeyRegistry::new(200, None, Some(120));
        let token_hex = mk_token_hex('3');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let e = reg.insert(qkey_value, token_hex.into(), None).expect("insert");
        let now = current_epoch_secs();
        let exp = e.expires_at.expect("default expiry");
        assert!(exp >= now + 115 && exp <= now + 125);
    }

    #[test]
    fn max_entries_evicts_oldest_records() {
        let mut reg = QKeyRegistry::new(2, None, None);

        let t1 = mk_token_hex('4');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert(q1, t1.into(), None).expect("insert 1");

        let t2 = mk_token_hex('5');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert(q2, t2.into(), None).expect("insert 2");

        let t3 = mk_token_hex('6');
        let q3 = mk_qkey_with_token(&t3);
        let e3 = reg.insert(q3, t3.into(), None).expect("insert 3");

        let ids: Vec<String> = reg.list().into_iter().map(|e| e.id).collect();
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

        let mut reg = QKeyRegistry::new(200, None, None);
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
        let mut reg = QKeyRegistry::new(200, None, None);
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
        let mut reg = QKeyRegistry::new(200, None, None);
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
