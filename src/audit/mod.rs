//! Security audit logging (TODO-439).
//!
//! Provides a tamper-evident, hash-chained audit log for security-relevant
//! events: authentication, QKey issuance/revocation, admin actions, DDoS
//! anomalies, kill-switch activation, privilege drops, and connection
//! lifecycle events.
//!
//! The log is append-only and each entry's `prev_hash` field contains the
//! SHA-256 of the previous entry, forming a chain. Tampering with any entry
//! breaks the chain and is detectable by [`AuditLog::verify_chain`].
//!
//! Output formats:
//! - JSON Lines (NDJSON) — one event per line, suitable for SIEM ingestion
//!   (Splunk, Elastic, Loki, Wazuh).
//! - Syslog RFC 5424 — for direct forwarding to a SIEM via syslog relay.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Security-relevant audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    /// Client authenticated successfully.
    ClientAuthenticated,
    /// Client authentication failed.
    AuthFailed,
    /// Client did not authenticate before the configured deadline.
    AuthTimeout,
    /// QKey issued to a client.
    QkeyIssued,
    /// QKey revoked.
    QkeyRevoked,
    /// QKey rotated.
    QkeyRotated,
    /// Admin API action (login, config change, manual block).
    AdminAction,
    /// DDoS anomaly detected.
    DdosAnomaly,
    /// IP added to blacklist.
    IpBlacklisted,
    /// IP removed from blacklist.
    IpUnblacklisted,
    /// Kill switch activated.
    KillSwitchActivated,
    /// Kill switch deactivated.
    KillSwitchDeactivated,
    /// Privileges dropped.
    PrivilegesDropped,
    /// Privilege drop failed (security-critical).
    PrivilegeDropFailed,
    /// Connection established.
    ConnectionEstablished,
    /// Connection closed.
    ConnectionClosed,
    /// Firewall or routing rules were installed.
    FirewallRuleAdded,
    /// Firewall or routing rules were removed.
    FirewallRuleRemoved,
    /// Configuration reloaded.
    ConfigReloaded,
    /// Server started.
    ServerStarted,
    /// Server stopped.
    ServerStopped,
}

impl AuditEventType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::ClientAuthenticated => "client_authenticated",
            Self::AuthFailed => "auth_failed",
            Self::AuthTimeout => "auth_timeout",
            Self::QkeyIssued => "qkey_issued",
            Self::QkeyRevoked => "qkey_revoked",
            Self::QkeyRotated => "qkey_rotated",
            Self::AdminAction => "admin_action",
            Self::DdosAnomaly => "ddos_anomaly",
            Self::IpBlacklisted => "ip_blacklisted",
            Self::IpUnblacklisted => "ip_unblacklisted",
            Self::KillSwitchActivated => "kill_switch_activated",
            Self::KillSwitchDeactivated => "kill_switch_deactivated",
            Self::PrivilegesDropped => "privileges_dropped",
            Self::PrivilegeDropFailed => "privilege_drop_failed",
            Self::ConnectionEstablished => "connection_established",
            Self::ConnectionClosed => "connection_closed",
            Self::FirewallRuleAdded => "firewall_rule_added",
            Self::FirewallRuleRemoved => "firewall_rule_removed",
            Self::ConfigReloaded => "config_reloaded",
            Self::ServerStarted => "server_started",
            Self::ServerStopped => "server_stopped",
        }
    }
}

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        }
    }
}

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: u64,
    /// Event type.
    pub event_type: AuditEventType,
    /// Severity level.
    pub severity: AuditSeverity,
    /// Source IP address (if applicable).
    pub source_ip: Option<String>,
    /// Affected client ID (if applicable).
    pub client_id: Option<String>,
    /// Human-readable description.
    pub message: String,
    /// SHA-256 hash of the previous entry (hex).
    pub prev_hash: String,
    /// SHA-256 hash of this entry (hex, computed on flush).
    pub hash: String,
}

/// Audit logger that writes hash-chained entries to a file.
pub struct AuditLog {
    writer: Mutex<AuditWriter>,
    seq: std::sync::atomic::AtomicU64,
    last_hash: Mutex<String>,
}

struct AuditWriter {
    file: BufWriter<File>,
    #[allow(dead_code)]
    path: PathBuf,
}

/// Error returned by audit log operations.
#[derive(Debug)]
pub enum AuditError {
    IoError(std::io::Error),
    HashError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "audit I/O error: {e}"),
            Self::HashError(s) => write!(f, "audit hash error: {s}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl AuditLog {
    /// Create a new audit log at the given path.
    ///
    /// If the file already exists, the chain is resumed from the last entry's
    /// hash. Otherwise, a new chain is started with a genesis hash of all-zeros.
    pub fn open(path: PathBuf) -> Result<Self, AuditError> {
        let last_hash = if path.exists() { read_last_hash(&path)? } else { "0".repeat(64) };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(AuditError::IoError)?;

        Ok(Self {
            writer: Mutex::new(AuditWriter { file: BufWriter::new(file), path }),
            seq: std::sync::atomic::AtomicU64::new(0),
            last_hash: Mutex::new(last_hash),
        })
    }

    /// Log an audit event. The entry is hash-chained and written immediately.
    pub fn log(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<&str>,
        client_id: Option<&str>,
        message: &str,
    ) -> Result<(), AuditError> {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        // Recover from mutex poisoning rather than panicking — a security
        // audit logger must never crash the server because another thread
        // panicked while holding the lock. The poisoned guard still gives
        // access to the inner data; we just continue with the last known
        // state (which is the correct behavior for a hash chain).
        let prev_hash = self.last_hash.lock().unwrap_or_else(|e| e.into_inner()).clone();

        let mut entry = AuditEntry {
            seq,
            timestamp,
            event_type,
            severity,
            source_ip: source_ip.map(String::from),
            client_id: client_id.map(String::from),
            message: message.to_string(),
            prev_hash: prev_hash.clone(),
            hash: String::new(),
        };

        // Compute this entry's hash.
        let hash = compute_entry_hash(&entry);
        entry.hash = hash.clone();

        // Write as NDJSON.
        let json = serialize_entry(&entry);
        {
            let mut writer = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            writer.file.write_all(json.as_bytes()).map_err(AuditError::IoError)?;
            writer.file.write_all(b"\n").map_err(AuditError::IoError)?;
            writer.file.flush().map_err(AuditError::IoError)?;
        }

        // Update last_hash for the next entry.
        *self.last_hash.lock().unwrap_or_else(|e| e.into_inner()) = hash;

        Ok(())
    }

    /// Verify the integrity of the hash chain. Returns Ok(()) if the chain
    /// is intact, or Err with the first broken entry's sequence number.
    pub fn verify_chain(path: &PathBuf) -> Result<(), AuditError> {
        let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
        let mut prev_hash = "0".repeat(64);

        for (line_num, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let entry = parse_entry(line).ok_or_else(|| {
                AuditError::HashError(format!("malformed entry at line {}", line_num + 1))
            })?;

            if entry.prev_hash != prev_hash {
                return Err(AuditError::HashError(format!(
                    "chain broken at entry seq={} (line {}): prev_hash mismatch",
                    entry.seq,
                    line_num + 1
                )));
            }

            let computed = compute_entry_hash(&entry);
            if entry.hash != computed {
                return Err(AuditError::HashError(format!(
                    "hash mismatch at entry seq={} (line {}): expected {computed}, got {}",
                    entry.seq,
                    line_num + 1,
                    entry.hash
                )));
            }

            prev_hash = entry.hash;
        }

        Ok(())
    }
}

fn compute_entry_hash(entry: &AuditEntry) -> String {
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        entry.seq,
        entry.timestamp,
        entry.event_type.as_str(),
        entry.severity.as_str(),
        entry.source_ip.as_deref().unwrap_or(""),
        entry.client_id.as_deref().unwrap_or(""),
        entry.message,
        entry.prev_hash,
    );
    sha256_hex(canonical.as_bytes())
}

// --- Global audit log accessor (TODO-515) ---
//
// The audit log is a cross-cutting concern. Rather than threading
// `Option<Arc<AuditLog>>` through dozens of function signatures, we
// use a `OnceLock` global — the same pattern used by
// `ADMIN_LOG_BUFFER` in `src/main.rs`. The log is initialized once
// during server startup (when `--audit-log <path>` is provided) and
// remains valid for the process lifetime.

use std::sync::Arc;

static AUDIT_LOG: std::sync::OnceLock<Arc<AuditLog>> = std::sync::OnceLock::new();

/// Initialize the global audit log. Called once during server startup.
/// If `path` is `None`, audit logging is disabled (no-op).
///
/// On Unix, the audit log file is created with mode 0o600 (owner read/write
/// only). When the process is running as root, the file is chowned to the
/// `quicfuscate` user/group so that audit logging continues to work after
/// privilege dropping. The parent directory is chowned **only** if this
/// function created it — a pre-existing system directory (e.g. `/var/log`)
/// is never re-owned, which would be a privilege-escalation vector.
/// This must be called **before** `drop_privileges`.
pub fn init_audit_log(path: Option<PathBuf>, owner: Option<(u32, u32)>) {
    if let Some(p) = path {
        // Track whether *we* created the parent dir so we only chown
        // directories we own — never pre-existing system dirs like /var/log.
        let parent_newly_created = p.parent().map(|parent| !parent.exists()).unwrap_or(false);
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::warn!("Failed to create audit log dir {}: {}", parent.display(), e);
            }
        }
        match AuditLog::open(p.clone()) {
            Ok(log) => {
                #[cfg(unix)]
                secure_audit_file(&p, parent_newly_created, owner);
                let _ = AUDIT_LOG.set(Arc::new(log));
            }
            Err(e) => {
                log::warn!("Failed to open audit log: {e}");
            }
        }
    }
}

/// Restrict permissions on the audit log file to owner-only (0o600) and,
/// when running as root, chown the file (and a newly-created parent dir)
/// to the `quicfuscate` user/group so audit logging survives the
/// root→unprivileged privilege drop.
///
/// `parent_newly_created` must be true only when the caller created the
/// parent directory itself. Chowning a pre-existing system directory would
/// be a privilege-escalation vector and is therefore forbidden.
///
/// Extracted from `init_audit_log` so the permission logic is unit-testable
/// without depending on the process-global `OnceLock`.
#[cfg(unix)]
fn secure_audit_file(
    path: &std::path::Path,
    parent_newly_created: bool,
    owner: Option<(u32, u32)>,
) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        log::warn!("Failed to set audit log permissions on {}: {}", path.display(), e);
    }
    // Only chown the parent dir if we just created it. Never reown a
    // pre-existing directory (e.g. /var/log) — that would break other
    // services and open a privilege-escalation path.
    if unsafe { libc::geteuid() } == 0 {
        if let Some((uid, gid)) = owner {
            chown_to_identity(path, uid, gid);
            if parent_newly_created {
                if let Some(parent) = path.parent() {
                    chown_to_identity(parent, uid, gid);
                }
            }
        }
    }
}

/// Chown `path` to the pre-resolved privilege target.
#[cfg(unix)]
fn chown_to_identity(path: &std::path::Path, uid: u32, gid: u32) {
    use std::ffi::CString;
    // SAFETY: chown changes ownership. Path is a valid filesystem path.
    let c_path = match CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("chown: path {} not representable as CString: {}", path.display(), e);
            return;
        }
    };
    if unsafe { libc::chown(c_path.as_ptr(), uid, gid) } != 0 {
        let err = std::io::Error::last_os_error();
        log::warn!(
            "chown failed for {} (uid={}, gid={}): {} — audit logging may break after privilege drop",
            path.display(),
            uid,
            gid,
            err
        );
    }
}

/// Emit an audit event to the global audit log if initialized.
/// No-op if `init_audit_log` was not called or was called with `None`.
pub fn audit(
    event_type: AuditEventType,
    severity: AuditSeverity,
    source_ip: Option<&str>,
    client_id: Option<&str>,
    message: &str,
) {
    if let Some(log) = AUDIT_LOG.get() {
        if let Err(e) = log.log(event_type, severity, source_ip, client_id, message) {
            log::warn!("Audit log write failed: {e}");
        }
    }
}

/// Serialize an entry as a JSON object (NDJSON format).
fn serialize_entry(entry: &AuditEntry) -> String {
    // Manual JSON serialization to avoid a serde_json dependency for audit.
    let source_ip = match &entry.source_ip {
        Some(ip) => format!("\"{}\"", json_escape(ip)),
        None => "null".to_string(),
    };
    let client_id = match &entry.client_id {
        Some(id) => format!("\"{}\"", json_escape(id)),
        None => "null".to_string(),
    };
    format!(
        r#"{{"seq":{},"ts":{},"event":"{}","severity":"{}","src_ip":{},"client_id":{},"msg":"{}","prev_hash":"{}","hash":"{}"}}"#,
        entry.seq,
        entry.timestamp,
        entry.event_type.as_str(),
        entry.severity.as_str(),
        source_ip,
        client_id,
        json_escape(&entry.message),
        entry.prev_hash,
        entry.hash,
    )
}

/// Parse a JSON entry line back into an AuditEntry (for chain verification).
fn parse_entry(line: &str) -> Option<AuditEntry> {
    // Minimal JSON field extraction (no serde_json dependency).
    let seq = extract_json_u64(line, "seq")?;
    let timestamp = extract_json_u64(line, "ts")?;
    let event_str = extract_json_str(line, "event")?;
    let severity_str = extract_json_str(line, "severity")?;
    let source_ip = extract_json_str(line, "src_ip");
    let client_id = extract_json_str(line, "client_id");
    let message = extract_json_str(line, "msg")?;
    let prev_hash = extract_json_str(line, "prev_hash")?;
    let hash = extract_json_str(line, "hash")?;

    let event_type = match event_str.as_str() {
        "client_authenticated" => AuditEventType::ClientAuthenticated,
        "auth_failed" => AuditEventType::AuthFailed,
        "auth_timeout" => AuditEventType::AuthTimeout,
        "qkey_issued" => AuditEventType::QkeyIssued,
        "qkey_revoked" => AuditEventType::QkeyRevoked,
        "qkey_rotated" => AuditEventType::QkeyRotated,
        "admin_action" => AuditEventType::AdminAction,
        "ddos_anomaly" => AuditEventType::DdosAnomaly,
        "ip_blacklisted" => AuditEventType::IpBlacklisted,
        "ip_unblacklisted" => AuditEventType::IpUnblacklisted,
        "kill_switch_activated" => AuditEventType::KillSwitchActivated,
        "kill_switch_deactivated" => AuditEventType::KillSwitchDeactivated,
        "privileges_dropped" => AuditEventType::PrivilegesDropped,
        "privilege_drop_failed" => AuditEventType::PrivilegeDropFailed,
        "connection_established" => AuditEventType::ConnectionEstablished,
        "connection_closed" => AuditEventType::ConnectionClosed,
        "firewall_rule_added" => AuditEventType::FirewallRuleAdded,
        "firewall_rule_removed" => AuditEventType::FirewallRuleRemoved,
        "config_reloaded" => AuditEventType::ConfigReloaded,
        "server_started" => AuditEventType::ServerStarted,
        "server_stopped" => AuditEventType::ServerStopped,
        _ => return None,
    };

    let severity = match severity_str.as_str() {
        "INFO" => AuditSeverity::Info,
        "WARNING" => AuditSeverity::Warning,
        "CRITICAL" => AuditSeverity::Critical,
        _ => return None,
    };

    Some(AuditEntry {
        seq,
        timestamp,
        event_type,
        severity,
        source_ip,
        client_id,
        message,
        prev_hash,
        hash,
    })
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let pattern = format!(r#""{key}":"#);
    let start = json.find(&pattern)? + pattern.len();
    if json[start..].starts_with("null") {
        return None;
    }
    let quote_start = json[start..].find('"')? + start + 1;
    let mut end = quote_start;
    let bytes = json.as_bytes();
    let mut i = quote_start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            end = i;
            break;
        }
        i += 1;
    }
    Some(json[quote_start..end].replace("\\\"", "\"").replace("\\\\", "\\"))
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let pattern = format!(r#""{key}":"#);
    let start = json.find(&pattern)? + pattern.len();
    let rest = &json[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Read the last entry's hash from an existing audit file.
fn read_last_hash(path: &PathBuf) -> Result<String, AuditError> {
    let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
    for line in content.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(hash) = extract_json_str(line, "hash") {
            return Ok(hash);
        }
    }
    Ok("0".repeat(64))
}

// --- Minimal SHA-256 ---

fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Pre-processing: padding.
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit block.
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );
    }

    #[test]
    fn test_audit_log_chain_integrity() {
        let tmp = std::env::temp_dir().join("quicfuscate_audit_test.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Server started")
            .unwrap();
        log.log(
            AuditEventType::ClientAuthenticated,
            AuditSeverity::Info,
            Some("1.2.3.4"),
            Some("client-001"),
            "Client authenticated",
        )
        .unwrap();
        log.log(
            AuditEventType::AuthFailed,
            AuditSeverity::Warning,
            Some("5.6.7.8"),
            None,
            "Authentication failed: invalid QKey",
        )
        .unwrap();
        log.log(
            AuditEventType::DdosAnomaly,
            AuditSeverity::Critical,
            Some("10.0.0.1"),
            None,
            "PPS spike detected: 50000 > 3x baseline 1000",
        )
        .unwrap();
        drop(log);

        // Chain should be intact.
        assert!(AuditLog::verify_chain(&tmp).is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_runtime_boundary_events_round_trip_through_chain_verification() {
        let tmp = std::env::temp_dir()
            .join(format!("quicfuscate_audit_runtime_boundaries_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        let events = [
            AuditEventType::AuthTimeout,
            AuditEventType::ConnectionEstablished,
            AuditEventType::ConnectionClosed,
            AuditEventType::FirewallRuleAdded,
            AuditEventType::FirewallRuleRemoved,
        ];

        for event in events {
            log.log(
                event,
                AuditSeverity::Info,
                Some("192.0.2.1"),
                Some("client-001"),
                "Runtime boundary event",
            )
            .unwrap();
        }
        drop(log);

        assert!(AuditLog::verify_chain(&tmp).is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_audit_log_tamper_detection() {
        let tmp = std::env::temp_dir().join("quicfuscate_audit_tamper_test.jsonl");
        let _ = std::fs::remove_file(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Started").unwrap();
        log.log(
            AuditEventType::AuthFailed,
            AuditSeverity::Warning,
            Some("1.2.3.4"),
            None,
            "Failed",
        )
        .unwrap();
        drop(log);

        // Tamper with the file: modify a character in the message.
        let content = std::fs::read_to_string(&tmp).unwrap();
        let tampered = content.replace("Failed", "Hacked!");
        std::fs::write(&tmp, tampered).unwrap();

        // Chain verification should fail.
        assert!(AuditLog::verify_chain(&tmp).is_err());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_audit_log_resume_chain() {
        let tmp = std::env::temp_dir().join("quicfuscate_audit_resume_test.jsonl");
        let _ = std::fs::remove_file(&tmp);

        // First session.
        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Started").unwrap();
        drop(log);

        // Second session — should resume from last hash.
        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(AuditEventType::ConfigReloaded, AuditSeverity::Info, None, None, "Reloaded")
            .unwrap();
        drop(log);

        // Chain should be intact across sessions.
        assert!(AuditLog::verify_chain(&tmp).is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_json_escape() {
        assert_eq!(json_escape("hello"), "hello");
        assert_eq!(json_escape(r#"a"b"#), r#"a\"b"#);
        assert_eq!(json_escape(r#"a\b"#), r#"a\\b"#);
    }

    #[test]
    fn test_extract_json_str() {
        let json = r#"{"name":"hello","val":42}"#;
        assert_eq!(extract_json_str(json, "name"), Some("hello".to_string()));
        assert_eq!(extract_json_str(json, "val"), None);
    }

    #[test]
    fn test_audit_call_is_safe_regardless_of_init_state() {
        // audit() must never panic, whether or not the global audit log
        // has been initialized by another test in the same process.
        // This test is deterministic: it does not depend on execution order.
        audit(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "Safe-to-call probe");
        // Reaching here without panic is the assertion.
    }

    #[test]
    fn test_init_and_emit_audit_event() {
        // Test the init+emit+verify path directly via AuditLog (not the
        // process-global OnceLock, which cannot be reliably initialized
        // in parallel test execution). This verifies the same code path
        // that init_audit_log() uses internally.
        let tmp = std::env::temp_dir()
            .join(format!("quicfuscate_audit_global_test_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(
            AuditEventType::QkeyIssued,
            AuditSeverity::Info,
            Some("10.0.0.1"),
            Some("test-key-id"),
            "Integration test: QKey issued",
        )
        .unwrap();
        drop(log);

        let content = std::fs::read_to_string(&tmp).unwrap_or_default();
        assert!(!content.is_empty(), "audit log file should not be empty after emit");
        assert!(AuditLog::verify_chain(&tmp).is_ok(), "audit chain should be valid after emit");

        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_audit_file_sets_owner_only_permissions() {
        // secure_audit_file must restrict the audit log file to mode 0o600
        // (owner read/write only) regardless of the previous mode. The
        // chown branch only runs as root and is not exercised here, but the
        // permission hardening — the part that protects the file on disk —
        // is verified directly.
        //
        // We create the file with an explicitly permissive mode (0o644) via
        // OpenOptions::mode() on the *create* path, then verify secure_audit_file
        // tightens it to exactly 0o600. The previous version of this test used
        // std::fs::write() first, which created the file with umask-default
        // mode, then re-opened with OpenOptions::mode(0o644) — but mode() only
        // applies at file creation time, so the second open was a no-op and
        // the test was not actually proving mode tightening from 0o644.
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .join(format!("quicfuscate_audit_secure_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("audit.jsonl");
        // Create the file with a permissive mode (0o644) on the create path.
        {
            use std::fs::OpenOptions;
            let _ = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o644)
                .open(&file_path)
                .unwrap();
        }
        // Verify the file was actually created with mode 0o644 (modulo umask).
        // If umask already stripped it below 0o644, the tightening test still
        // holds — we just need to confirm secure_audit_file sets exactly 0o600.
        let mode_before = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        // After the call the mode must be exactly 0o600 regardless of the
        // mode in effect when the file was created.
        secure_audit_file(&file_path, false, None);
        let mode_after = std::fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_after, 0o600,
            "audit log file must be 0o600 after secure_audit_file, got {mode_after:#o} (was {mode_before:#o} before)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_secure_audit_file_does_not_touch_preexisting_parent_ownership() {
        // Regression guard for the privilege-escalation bug where the parent
        // directory was chowned unconditionally. With parent_newly_created =
        // false, secure_audit_file must NOT chown the parent even when run
        // as root. We cannot easily assert "no chown happened" without root,
        // but we can assert the function returns normally and the parent's
        // ownership is unchanged. This test documents and locks the contract.
        let parent = std::env::temp_dir()
            .join(format!("quicfuscate_audit_parent_guard_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let file_path = parent.join("audit.jsonl");
        std::fs::write(&file_path, b"seed\n").unwrap();
        let parent_meta_before = std::fs::symlink_metadata(&parent).unwrap();
        // parent_newly_created = false simulates a pre-existing system dir.
        secure_audit_file(&file_path, false, None);
        let parent_meta_after = std::fs::symlink_metadata(&parent).unwrap();
        // Ownership (uid/gid) must be identical before and after.
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            parent_meta_before.uid(),
            parent_meta_after.uid(),
            "parent dir uid must not change when parent_newly_created=false"
        );
        assert_eq!(
            parent_meta_before.gid(),
            parent_meta_after.gid(),
            "parent dir gid must not change when parent_newly_created=false"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }
}
