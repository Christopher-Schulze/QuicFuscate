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

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

/// Default number of accepted commands waiting for the single audit writer.
pub const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 16_384;
/// Hard upper bound for the audit command queue.
pub const MAX_AUDIT_QUEUE_CAPACITY: usize = 65_536;
/// Default active audit segment size before rotation.
pub const DEFAULT_AUDIT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
/// Hard upper bound for one configured audit segment.
pub const MAX_AUDIT_SEGMENT_BYTES: u64 = 128 * 1024 * 1024;
/// Default number of retained audit segments, including the active segment.
pub const DEFAULT_AUDIT_MAX_SEGMENTS: usize = 8;
/// Hard upper bound for the retained segment count, including the active segment.
pub const MAX_AUDIT_SEGMENTS: usize = 64;
/// Default flush timeout in milliseconds.
pub const DEFAULT_AUDIT_FLUSH_TIMEOUT_MS: u64 = 5_000;
/// Hard upper bound for a flush or shutdown barrier in milliseconds.
pub const MAX_AUDIT_FLUSH_TIMEOUT_MS: u64 = 60_000;
/// Maximum JSON-encoded UTF-8 size of the optional source IP string.
pub const MAX_AUDIT_SOURCE_IP_ENCODED_BYTES: usize = 128;
/// Maximum JSON-encoded UTF-8 size of the optional client ID string.
pub const MAX_AUDIT_CLIENT_ID_ENCODED_BYTES: usize = 512;
/// Maximum JSON-encoded UTF-8 size of the optional machine-readable reason.
pub const MAX_AUDIT_REASON_ENCODED_BYTES: usize = 512;
/// Maximum JSON-encoded UTF-8 size of the human-readable message.
pub const MAX_AUDIT_MESSAGE_ENCODED_BYTES: usize = 8 * 1024;
/// Maximum combined JSON-encoded UTF-8 size of all dynamic event strings.
pub const MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES: usize = 8 * 1024;
const DEFAULT_AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_millis(DEFAULT_AUDIT_FLUSH_TIMEOUT_MS);
const MAX_AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_millis(MAX_AUDIT_FLUSH_TIMEOUT_MS);
#[cfg(unix)]
const AUDIT_FILE_MODE: u32 = 0o600;
const AUDIT_ADMISSION_STATE_MASK: usize = 0b11;
const AUDIT_ADMISSION_OPEN: usize = 0;
const AUDIT_ADMISSION_CLOSING: usize = 1;
const AUDIT_ADMISSION_CLOSED: usize = 2;
const AUDIT_ADMISSION_COUNT_SHIFT: usize = 2;
const AUDIT_ADMISSION_COUNT_UNIT: usize = 1 << AUDIT_ADMISSION_COUNT_SHIFT;

mod hash;
mod model;

use hash::sha256_hex;
pub use model::{
    AuditActor, AuditConfig, AuditContext, AuditEntry, AuditError, AuditEventType, AuditOptions,
    AuditOutcome, AuditPayloadField, AuditSeverity, AuditStats, AuditTarget,
};

/// Audit logger that writes hash-chained entries to a file.
pub struct AuditLog {
    sender: Sender<AuditCommand>,
    dropped_events: Arc<AtomicU64>,
    queue_full_events: Arc<AtomicU64>,
    worker_closing_events: Arc<AtomicU64>,
    worker_disconnect_events: Arc<AtomicU64>,
    payload_rejections: Arc<AtomicU64>,
    state: Arc<AuditState>,
    admission_state: AtomicUsize,
    worker: Mutex<Option<JoinHandle<()>>>,
    flush_timeout: Duration,
}

struct AuditWriter {
    file: Option<BufWriter<File>>,
    path: PathBuf,
    active_bytes: u64,
    active_start_seq: u64,
    max_segment_bytes: u64,
    max_segments: usize,
    rotated_segments: Vec<AuditSegment>,
    next_seq: u64,
    last_hash: String,
    state: Arc<AuditState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AuditFailure {
    Persistence(String),
    DurabilityTimeout(String),
    FlushTimeout(String),
    ShutdownTimeout(String),
    WorkerDisconnected,
}

impl AuditFailure {
    fn to_error(&self) -> AuditError {
        match self {
            Self::Persistence(error) => AuditError::PersistenceFailed(error.clone()),
            Self::DurabilityTimeout(error) => AuditError::DurabilityTimeout(error.clone()),
            Self::FlushTimeout(error) => AuditError::FlushTimeout(error.clone()),
            Self::ShutdownTimeout(error) => AuditError::ShutdownTimeout(error.clone()),
            Self::WorkerDisconnected => AuditError::WorkerDisconnected,
        }
    }
}

struct AuditState {
    terminal_error: Mutex<Option<AuditFailure>>,
    shutdown_error: Mutex<Option<AuditFailure>>,
    persistence_errors: AtomicU64,
    terminal_dropped_events: AtomicU64,
    slow_flushes: AtomicU64,
    shutdown_failures: AtomicU64,
}

impl Default for AuditState {
    fn default() -> Self {
        Self {
            terminal_error: Mutex::new(None),
            shutdown_error: Mutex::new(None),
            persistence_errors: AtomicU64::new(0),
            terminal_dropped_events: AtomicU64::new(0),
            slow_flushes: AtomicU64::new(0),
            shutdown_failures: AtomicU64::new(0),
        }
    }
}

impl AuditState {
    fn terminal_error(&self) -> Option<AuditFailure> {
        self.terminal_error.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }

    fn record_terminal(&self, failure: AuditFailure) -> AuditFailure {
        let mut terminal = self.terminal_error.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = terminal.as_ref() {
            return existing.clone();
        }
        *terminal = Some(failure.clone());
        failure
    }

    fn record_persistence_failure(&self, failure: AuditFailure) -> AuditFailure {
        self.persistence_errors.fetch_add(1, Ordering::Relaxed);
        self.record_terminal(failure)
    }

    fn sticky_failure(&self) -> Option<AuditFailure> {
        self.shutdown_error().or_else(|| self.terminal_error())
    }

    fn shutdown_error(&self) -> Option<AuditFailure> {
        self.shutdown_error.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }

    fn record_shutdown_failure(&self, failure: AuditFailure) -> AuditFailure {
        let mut shutdown = self.shutdown_error.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = shutdown.as_ref() {
            return existing.clone();
        }
        self.shutdown_failures.fetch_add(1, Ordering::Relaxed);
        *shutdown = Some(failure.clone());
        failure
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditSegment {
    start_seq: u64,
    end_seq: u64,
    path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AuditCheckpoint {
    version: u32,
    anchor_seq: u64,
    anchor_prev_hash: String,
    tail_seq: u64,
    tail_hash: String,
    segments: Vec<AuditCheckpointSegment>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct AuditCheckpointSegment {
    file: String,
    start_seq: u64,
    end_seq: u64,
}

fn json_encoded_string_len(value: &str) -> usize {
    let mut length = 2usize;
    for byte in value.bytes() {
        length = length.saturating_add(match byte {
            b'"' | b'\\' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => 2,
            0x00..=0x1f => 6,
            _ => 1,
        });
    }
    length
}

fn validate_audit_payload(
    source_ip: Option<&str>,
    client_id: Option<&str>,
    context: AuditContext<'_>,
    message: &str,
) -> Result<(), AuditError> {
    let fields = [
        (AuditPayloadField::SourceIp, source_ip, MAX_AUDIT_SOURCE_IP_ENCODED_BYTES),
        (AuditPayloadField::ClientId, client_id, MAX_AUDIT_CLIENT_ID_ENCODED_BYTES),
        (AuditPayloadField::Reason, context.reason, MAX_AUDIT_REASON_ENCODED_BYTES),
        (AuditPayloadField::Message, Some(message), MAX_AUDIT_MESSAGE_ENCODED_BYTES),
    ];
    let mut total = 0usize;
    for (field, value, max_encoded_bytes) in fields {
        if let Some(value) = value {
            let encoded_bytes = json_encoded_string_len(value);
            if encoded_bytes > max_encoded_bytes {
                return Err(AuditError::PayloadTooLarge {
                    field,
                    encoded_bytes,
                    max_encoded_bytes,
                });
            }
            total = total.saturating_add(encoded_bytes);
        }
    }
    if total > MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES {
        return Err(AuditError::PayloadTooLarge {
            field: AuditPayloadField::EventPayload,
            encoded_bytes: total,
            max_encoded_bytes: MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES,
        });
    }
    Ok(())
}

struct PendingAuditEvent {
    event_type: AuditEventType,
    severity: AuditSeverity,
    source_ip: Option<String>,
    client_id: Option<String>,
    message: String,
    actor: AuditActor,
    target: AuditTarget,
    outcome: AuditOutcome,
    reason: Option<String>,
}

/// Guard for one producer admitted before the shutdown linearization point.
struct AuditAdmissionGuard<'a> {
    state: &'a AtomicUsize,
}

impl Drop for AuditAdmissionGuard<'_> {
    fn drop(&mut self) {
        let previous = self.state.fetch_sub(AUDIT_ADMISSION_COUNT_UNIT, Ordering::Release);
        debug_assert!(previous >= AUDIT_ADMISSION_COUNT_UNIT);
    }
}

enum AuditCommand {
    Event(PendingAuditEvent),
    Flush(Sender<Result<(), AuditFailure>>),
    Shutdown,
}

struct DurabilityWatchdog {
    cancel: Sender<()>,
    handle: Option<JoinHandle<()>>,
}

impl DurabilityWatchdog {
    fn start(state: Arc<AuditState>, timeout: Duration) -> Result<Self, std::io::Error> {
        let (cancel, receiver) = crossbeam_channel::bounded(0);
        let handle = std::thread::Builder::new()
            .name("qf-audit-durability-watchdog".to_string())
            .spawn(move || match receiver.recv_timeout(timeout) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => {
                let error =
                    format!("audit durability operation exceeded {} ms", timeout.as_millis());
                log::error!("audit durability watchdog: {error}");
                state.slow_flushes.fetch_add(1, Ordering::Relaxed);
                state.record_persistence_failure(AuditFailure::DurabilityTimeout(error));
            }
        })?;
        Ok(Self { cancel, handle: Some(handle) })
    }

    fn finish(mut self) {
        drop(self.cancel);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

mod audit_log;

impl Drop for AuditLog {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_audit_writer(
    receiver: Receiver<AuditCommand>,
    mut writer: AuditWriter,
    flush_timeout: Duration,
) {
    while let Ok(command) = receiver.recv() {
        match command {
            AuditCommand::Event(event) => writer.write_event(event),
            AuditCommand::Flush(ack) => {
                let result = writer.flush_with_timeout(flush_timeout);
                let _ = ack.send(result);
            }
            AuditCommand::Shutdown => break,
        }
    }
    let _ = writer.flush_with_timeout(flush_timeout);
}

impl AuditWriter {
    fn write_event(&mut self, event: PendingAuditEvent) {
        if self.state.terminal_error().is_some() {
            self.state.terminal_dropped_events.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Err(error) = self.try_write_event(event) {
            self.state.terminal_dropped_events.fetch_add(1, Ordering::Relaxed);
            self.state.record_persistence_failure(AuditFailure::Persistence(error.to_string()));
        }
    }

    fn flush_with_timeout(&mut self, timeout: Duration) -> Result<(), AuditFailure> {
        if let Some(failure) = self.state.terminal_error() {
            return Err(failure);
        }
        let watchdog = DurabilityWatchdog::start(self.state.clone(), timeout).map_err(|error| {
            self.state.record_persistence_failure(AuditFailure::Persistence(format!(
                "failed to start audit durability watchdog: {error}"
            )))
        })?;
        let result = self.flush();
        watchdog.finish();
        match result {
            Ok(()) => self.state.terminal_error().map_or(Ok(()), Err),
            Err(error) => Err(self
                .state
                .record_persistence_failure(AuditFailure::Persistence(error.to_string()))),
        }
    }

    fn try_write_event(&mut self, event: PendingAuditEvent) -> std::io::Result<()> {
        let timestamp = unix_timestamp(qf_common::time_source::now_system())?;
        let mut entry = AuditEntry {
            version: 2,
            seq: self.next_seq,
            timestamp,
            event_type: event.event_type,
            severity: event.severity,
            source_ip: event.source_ip,
            client_id: event.client_id,
            message: event.message,
            actor: event.actor,
            target: event.target,
            outcome: event.outcome,
            reason: event.reason,
            prev_hash: self.last_hash.clone(),
            hash: String::new(),
        };
        entry.hash = compute_entry_hash(&entry);
        let mut json = serialize_entry(&entry).map_err(std::io::Error::other)?.into_bytes();
        json.push(b'\n');
        let rotated = self.active_bytes > 0
            && self.active_bytes.saturating_add(json.len() as u64) > self.max_segment_bytes;
        if rotated {
            self.rotate()?;
        }
        let file =
            self.file.as_mut().ok_or_else(|| std::io::Error::other("audit file unavailable"))?;
        file.write_all(&json)?;
        self.active_bytes = self.active_bytes.saturating_add(json.len() as u64);
        self.next_seq = self.next_seq.saturating_add(1);
        self.last_hash = entry.hash;
        if rotated {
            self.flush_file()?;
            self.persist_checkpoint()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_file()?;
        self.persist_checkpoint()?;
        Ok(())
    }

    fn flush_file(&mut self) -> std::io::Result<()> {
        let file =
            self.file.as_mut().ok_or_else(|| std::io::Error::other("audit file unavailable"))?;
        file.flush()?;
        file.get_ref().sync_data()
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        self.flush_file()?;
        self.persist_checkpoint()?;
        let end_seq = self.next_seq.saturating_sub(1);
        let rotated_path = rotated_segment_path(&self.path, self.active_start_seq, end_seq);
        if rotated_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("audit segment already exists: {}", rotated_path.display()),
            ));
        }
        drop(self.file.take());
        std::fs::rename(&self.path, &rotated_path)?;
        self.rotated_segments.push(AuditSegment {
            start_seq: self.active_start_seq,
            end_seq,
            path: rotated_path,
        });
        let file = open_private_append_file(&self.path, true)?;
        self.file = Some(BufWriter::new(file));
        self.active_bytes = 0;
        self.active_start_seq = self.next_seq;
        Ok(())
    }

    fn persist_checkpoint(&mut self) -> std::io::Result<()> {
        if self.next_seq == 0 {
            return Ok(());
        }
        let keep_rotated_from =
            self.rotated_segments.len().saturating_sub(self.max_segments.saturating_sub(1));
        let retained_rotated = &self.rotated_segments[keep_rotated_from..];
        let mut segments: Vec<AuditCheckpointSegment> = retained_rotated
            .iter()
            .map(|segment| AuditCheckpointSegment {
                file: audit_file_name(&segment.path),
                start_seq: segment.start_seq,
                end_seq: segment.end_seq,
            })
            .collect();
        if self.active_bytes > 0 {
            segments.push(AuditCheckpointSegment {
                file: audit_file_name(&self.path),
                start_seq: self.active_start_seq,
                end_seq: self.next_seq.saturating_sub(1),
            });
        }
        let first = segments
            .first()
            .ok_or_else(|| std::io::Error::other("audit checkpoint has no retained segment"))?;
        let first_path = self.path.with_file_name(&first.file);
        let first_entry = read_first_entry(&first_path)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let checkpoint = AuditCheckpoint {
            version: 1,
            anchor_seq: first_entry.seq,
            anchor_prev_hash: first_entry.prev_hash,
            tail_seq: self.next_seq.saturating_sub(1),
            tail_hash: self.last_hash.clone(),
            segments,
        };
        let bytes = serde_json::to_vec(&checkpoint).map_err(std::io::Error::other)?;
        atomic_write_checkpoint(&checkpoint_path(&self.path), &bytes)?;
        let removed: Vec<AuditSegment> = self.rotated_segments.drain(..keep_rotated_from).collect();
        for segment in removed {
            std::fs::remove_file(segment.path)?;
        }
        sync_parent_directory(&self.path)
    }
}

fn unix_timestamp(now: SystemTime) -> std::io::Result<u64> {
    qf_common::time_source::unix_epoch_seconds(now).map_err(|error| {
        std::io::Error::other(format!("audit wall-clock timestamp unavailable: {error}"))
    })
}

fn default_context(event_type: AuditEventType, _message: &str) -> AuditContext<'static> {
    use AuditEventType::{
        AdminAction, AuthFailed, AuthTimeout, ClientAuthenticated, ConfigReloaded,
        ConnectionClosed, ConnectionEstablished, ConnectionRejected, DdosAnomaly,
        FirewallRuleAdded, FirewallRuleRemoved, IpBlacklisted, IpUnblacklisted,
        KillSwitchActivated, KillSwitchDeactivated, PrivilegeDropFailed, PrivilegesDropped,
        QkeyIssued, QkeyRevoked, QkeyRotated, ServerStarted, ServerStopped,
    };
    let actor = match event_type {
        AdminAction | ConfigReloaded | IpBlacklisted | IpUnblacklisted | QkeyIssued
        | QkeyRevoked | QkeyRotated => AuditActor::Administrator,
        ClientAuthenticated
        | AuthFailed
        | AuthTimeout
        | ConnectionEstablished
        | ConnectionClosed => AuditActor::Client,
        ConnectionRejected => AuditActor::NetworkPeer,
        DdosAnomaly => AuditActor::NetworkPeer,
        _ => AuditActor::System,
    };
    let target = match event_type {
        ClientAuthenticated | AuthFailed | AuthTimeout => AuditTarget::Client,
        QkeyIssued | QkeyRevoked | QkeyRotated => AuditTarget::Qkey,
        ConnectionEstablished | ConnectionClosed | ConnectionRejected => AuditTarget::Connection,
        AdminAction | ServerStarted | ServerStopped => AuditTarget::Server,
        ConfigReloaded => AuditTarget::Configuration,
        FirewallRuleAdded
        | FirewallRuleRemoved
        | IpBlacklisted
        | IpUnblacklisted
        | KillSwitchActivated
        | KillSwitchDeactivated => AuditTarget::Firewall,
        PrivilegesDropped | PrivilegeDropFailed | DdosAnomaly => AuditTarget::System,
    };
    let outcome = match event_type {
        AuthFailed | PrivilegeDropFailed => AuditOutcome::Failed,
        ConnectionRejected => AuditOutcome::Denied,
        AuthTimeout => AuditOutcome::TimedOut,
        DdosAnomaly => AuditOutcome::Detected,
        ServerStarted
        | ConnectionEstablished
        | FirewallRuleAdded
        | IpBlacklisted
        | KillSwitchActivated => AuditOutcome::Started,
        ServerStopped
        | ConnectionClosed
        | FirewallRuleRemoved
        | IpUnblacklisted
        | KillSwitchDeactivated => AuditOutcome::Stopped,
        _ => AuditOutcome::Succeeded,
    };
    AuditContext { actor, target, outcome, reason: None }
}

fn compute_entry_hash(entry: &AuditEntry) -> String {
    let canonical = if entry.version == 1 {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            entry.seq,
            entry.timestamp,
            entry.event_type.as_str(),
            entry.severity.as_str(),
            entry.source_ip.as_deref().unwrap_or(""),
            entry.client_id.as_deref().unwrap_or(""),
            entry.message,
            entry.prev_hash,
        )
    } else {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            entry.version,
            entry.seq,
            entry.timestamp,
            entry.event_type.as_str(),
            entry.severity.as_str(),
            entry.source_ip.as_deref().unwrap_or(""),
            entry.client_id.as_deref().unwrap_or(""),
            entry.actor.as_str(),
            entry.target.as_str(),
            entry.outcome.as_str(),
            entry.reason.as_deref().unwrap_or(""),
            entry.message,
            entry.prev_hash,
        )
    };
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
pub fn init_audit_log(path: Option<PathBuf>, owner: Option<(u32, u32)>) -> Result<(), AuditError> {
    // Returns the status instead of downgrading it to a log line. Audit-file hardening is
    // fail-closed, so a caller that ignored a warning here would run believing the audit log was
    // owner-only and survivable across the privilege drop when it is neither.
    init_audit_log_with_options(path, owner, AuditOptions::default()).inspect_err(|error| {
        log::warn!("Failed to initialize audit log: {error}");
    })
}

/// Initialize the global audit log with validated bounded persistence settings.
pub fn init_audit_log_with_options(
    path: Option<PathBuf>,
    owner: Option<(u32, u32)>,
    options: AuditOptions,
) -> Result<(), AuditError> {
    options.validate()?;
    #[cfg(not(unix))]
    let _ = owner;
    if let Some(p) = path {
        // Track whether *we* created the parent dir so we only chown
        // directories we own — never pre-existing system dirs like /var/log.
        #[cfg(unix)]
        let parent_newly_created = p.parent().map(|parent| !parent.exists()).unwrap_or(false);
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err(AuditError::IoError(e));
            }
        }
        let audit_log = AuditLog::open_with_options(p.clone(), options)?;
        // Hardening must succeed before the owner is published. Publishing after a failed
        // permission or ownership operation would report the documented secure state while the
        // file is readable by others or unreachable after the privilege drop.
        #[cfg(unix)]
        secure_audit_file(&p, parent_newly_created, owner)?;
        if AUDIT_LOG.set(Arc::new(audit_log)).is_err() {
            return Err(AuditError::AlreadyInitialized);
        }
    }
    Ok(())
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
) -> Result<(), AuditError> {
    use std::os::unix::fs::PermissionsExt;
    // Open once with O_NOFOLLOW and do every hardening step through that handle. The
    // pathname versions of chmod and chown resolve the name again on each call, so a
    // replacement between them would tighten permissions on one inode and hand
    // ownership to another. Binding both to one descriptor removes the window instead
    // of narrowing it.
    let file = open_no_follow_for_hardening(path)?;
    // Fail closed. An audit log whose mode could not be tightened to owner-only must not be
    // published as the process audit owner, because every later reader would treat it as the
    // documented secure state.
    file.set_permissions(std::fs::Permissions::from_mode(AUDIT_FILE_MODE))
        .map_err(AuditError::IoError)?;

    // Only chown the parent dir if we just created it. Never reown a
    // pre-existing directory (e.g. /var/log) — that would break other
    // services and open a privilege-escalation path.
    //
    // SAFETY: `geteuid` takes no arguments, dereferences no pointers, and cannot fail. It reads
    // the calling process's effective user id and is always safe to call from any thread.
    let running_as_root = unsafe { libc::geteuid() } == 0;
    if running_as_root {
        if let Some((uid, gid)) = owner {
            fchown_to_identity(&file, path, uid, gid)?;
            if parent_newly_created {
                if let Some(parent) = path.parent() {
                    let dir = open_directory_no_follow(parent)?;
                    fchown_to_identity(&dir, parent, uid, gid)?;
                }
            }
        }
    }
    Ok(())
}

/// Open `path` for hardening without following a symlink at its final component.
#[cfg(unix)]
fn open_no_follow_for_hardening(path: &std::path::Path) -> Result<File, AuditError> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(AuditError::IoError)?;
    if !file.metadata().map_err(AuditError::IoError)?.is_file() {
        return Err(AuditError::HashError(format!(
            "audit path must be a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

/// Open a directory for hardening without following a symlink at its final component.
#[cfg(unix)]
fn open_directory_no_follow(path: &std::path::Path) -> Result<File, AuditError> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(AuditError::IoError)?;
    if !dir.metadata().map_err(AuditError::IoError)?.is_dir() {
        return Err(AuditError::HashError(format!(
            "audit parent must be a directory: {}",
            path.display()
        )));
    }
    Ok(dir)
}

/// Chown an already-opened audit object to the pre-resolved privilege target.
///
/// Fails closed. A failed ownership transfer means audit logging breaks after the privilege
/// drop, so the caller must not publish the audit owner as if hardening had succeeded.
/// `path` is used only for reporting; the operation itself is bound to the descriptor, so
/// no pathname is resolved a second time and no replacement can redirect it.
#[cfg(unix)]
fn fchown_to_identity(
    file: &File,
    path: &std::path::Path,
    uid: u32,
    gid: u32,
) -> Result<(), AuditError> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: `fchown` receives a file descriptor this process owns and keeps alive for
    // the duration of the call, plus two scalar ids. It dereferences no caller pointer
    // and reports failure through its return value, which is checked before `errno` is
    // read.
    let status = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
    if status != 0 {
        let err = std::io::Error::last_os_error();
        log::warn!(
            "fchown failed for {} (uid={}, gid={}): {} - audit logging would break after privilege drop",
            path.display(),
            uid,
            gid,
            err
        );
        return Err(AuditError::IoError(err));
    }
    Ok(())
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

/// Emit one fully typed audit event to the process-global owner.
pub fn audit_typed(
    event_type: AuditEventType,
    severity: AuditSeverity,
    source_ip: Option<&str>,
    client_id: Option<&str>,
    context: AuditContext<'_>,
    message: &str,
) {
    if let Some(log) = AUDIT_LOG.get() {
        if let Err(error) =
            log.log_typed(event_type, severity, source_ip, client_id, context, message)
        {
            log::warn!("Audit log write failed: {error}");
        }
    }
}

/// Flush every event accepted by the process-global audit owner.
pub fn flush() -> Result<(), AuditError> {
    AUDIT_LOG.get().map_or(Ok(()), |audit_log| audit_log.flush())
}

/// Flush and join the process-global audit writer.
pub fn shutdown() -> Result<(), AuditError> {
    AUDIT_LOG.get().map_or(Ok(()), |audit_log| audit_log.shutdown())
}

/// Return process-global bounded audit-worker counters.
pub fn stats() -> AuditStats {
    AUDIT_LOG.get().map_or(AuditStats::default(), |audit_log| audit_log.stats())
}

/// Flushes the process-global audit owner on every server return path.
pub struct AuditFlushGuard;

impl AuditFlushGuard {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuditFlushGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AuditFlushGuard {
    fn drop(&mut self) {
        let _ = shutdown();
    }
}

/// Serialize an entry as a JSON object (NDJSON format).
fn serialize_entry(entry: &AuditEntry) -> Result<String, serde_json::Error> {
    serde_json::to_string(&serde_json::json!({
        "version": entry.version,
        "seq": entry.seq,
        "ts": entry.timestamp,
        "event": entry.event_type.as_str(),
        "severity": entry.severity.as_str(),
        "src_ip": entry.source_ip,
        "client_id": entry.client_id,
        "actor": entry.actor.as_str(),
        "target": entry.target.as_str(),
        "outcome": entry.outcome.as_str(),
        "reason": entry.reason,
        "msg": entry.message,
        "prev_hash": entry.prev_hash,
        "hash": entry.hash,
    }))
}

/// Parse a JSON entry line back into an AuditEntry (for chain verification).
fn parse_entry(line: &str) -> Option<AuditEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let version = value.get("version").and_then(serde_json::Value::as_u64).unwrap_or(1);
    let version = u32::try_from(version).ok()?;
    let seq = value.get("seq")?.as_u64()?;
    let timestamp = value.get("ts")?.as_u64()?;
    let event_str = value.get("event")?.as_str()?;
    let severity_str = value.get("severity")?.as_str()?;
    let source_ip = value.get("src_ip").and_then(serde_json::Value::as_str).map(String::from);
    let client_id = value.get("client_id").and_then(serde_json::Value::as_str).map(String::from);
    let message = value.get("msg")?.as_str()?.to_string();
    let prev_hash = value.get("prev_hash")?.as_str()?.to_string();
    let hash = value.get("hash")?.as_str()?.to_string();

    let event_type = match event_str {
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
        "connection_rejected" => AuditEventType::ConnectionRejected,
        "firewall_rule_added" => AuditEventType::FirewallRuleAdded,
        "firewall_rule_removed" => AuditEventType::FirewallRuleRemoved,
        "config_reloaded" => AuditEventType::ConfigReloaded,
        "server_started" => AuditEventType::ServerStarted,
        "server_stopped" => AuditEventType::ServerStopped,
        _ => return None,
    };

    let severity = match severity_str {
        "INFO" => AuditSeverity::Info,
        "WARNING" => AuditSeverity::Warning,
        "CRITICAL" => AuditSeverity::Critical,
        _ => return None,
    };

    let defaults = default_context(event_type, &message);
    let actor = match value.get("actor").and_then(serde_json::Value::as_str) {
        Some("system") => AuditActor::System,
        Some("administrator") => AuditActor::Administrator,
        Some("client") => AuditActor::Client,
        Some("network_peer") => AuditActor::NetworkPeer,
        None if version == 1 => defaults.actor,
        _ => return None,
    };
    let target = match value.get("target").and_then(serde_json::Value::as_str) {
        Some("server") => AuditTarget::Server,
        Some("client") => AuditTarget::Client,
        Some("connection") => AuditTarget::Connection,
        Some("qkey") => AuditTarget::Qkey,
        Some("configuration") => AuditTarget::Configuration,
        Some("firewall") => AuditTarget::Firewall,
        Some("route") => AuditTarget::Route,
        Some("system") => AuditTarget::System,
        None if version == 1 => defaults.target,
        _ => return None,
    };
    let outcome = match value.get("outcome").and_then(serde_json::Value::as_str) {
        Some("succeeded") => AuditOutcome::Succeeded,
        Some("failed") => AuditOutcome::Failed,
        Some("denied") => AuditOutcome::Denied,
        Some("timed_out") => AuditOutcome::TimedOut,
        Some("started") => AuditOutcome::Started,
        Some("stopped") => AuditOutcome::Stopped,
        Some("detected") => AuditOutcome::Detected,
        None if version == 1 => defaults.outcome,
        _ => return None,
    };
    let reason = value.get("reason").and_then(serde_json::Value::as_str).map(String::from);

    Some(AuditEntry {
        version,
        seq,
        timestamp,
        event_type,
        severity,
        source_ip,
        client_id,
        message,
        actor,
        target,
        outcome,
        reason,
        prev_hash,
        hash,
    })
}

fn checkpoint_path(base: &Path) -> PathBuf {
    let name = base.file_name().and_then(|name| name.to_str()).unwrap_or("audit.ndjson");
    base.with_file_name(format!("{name}.checkpoint"))
}

fn audit_file_name(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Largest single audit entry accepted when reading an existing segment.
///
/// The writer bounds an event's dynamic payload to
/// [`MAX_AUDIT_EVENT_PAYLOAD_ENCODED_BYTES`], and the remaining fields (sequence,
/// timestamp, type, severity, and two 64-character hashes) are fixed-width. This
/// ceiling leaves generous headroom above that and still refuses a single line that
/// no writer of this format could have produced, so a crafted file cannot force one
/// unbounded allocation.
const MAX_AUDIT_ENTRY_BYTES: usize = 64 * 1024;

/// Open an existing audit segment for bounded streaming.
///
/// The size is checked against the retention ceiling before any content is read.
/// A file larger than the largest segment this writer would ever create is outside
/// the configured contract, and reading it to find that out is precisely the
/// resource-exhaustion path being closed.
fn open_bounded_audit_segment(
    path: &Path,
) -> Result<std::io::BufReader<std::fs::File>, AuditError> {
    let file = std::fs::File::open(path).map_err(AuditError::IoError)?;
    let size = file.metadata().map_err(AuditError::IoError)?.len();
    if size > MAX_AUDIT_SEGMENT_BYTES {
        return Err(AuditError::HashError(format!(
            "{} is {size} bytes, above the {MAX_AUDIT_SEGMENT_BYTES}-byte audit segment ceiling",
            path.display()
        )));
    }
    Ok(std::io::BufReader::new(file))
}

/// Read one line into `buf`, refusing an entry larger than a writer could produce.
///
/// Returns `false` at end of file. The newline is stripped, so callers see the entry
/// exactly as `parse_entry` expects.
fn next_audit_line(
    reader: &mut std::io::BufReader<std::fs::File>,
    path: &Path,
    buf: &mut Vec<u8>,
) -> Result<bool, AuditError> {
    use std::io::{BufRead, Read};

    buf.clear();
    let read = reader
        .by_ref()
        .take(MAX_AUDIT_ENTRY_BYTES as u64 + 1)
        .read_until(b'\n', buf)
        .map_err(AuditError::IoError)?;
    if read == 0 {
        return Ok(false);
    }
    while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.len() > MAX_AUDIT_ENTRY_BYTES {
        return Err(AuditError::HashError(format!(
            "{} contains an entry above the {MAX_AUDIT_ENTRY_BYTES}-byte limit",
            path.display()
        )));
    }
    Ok(true)
}

/// Interpret one bounded line as UTF-8 text.
fn audit_line_str<'a>(buf: &'a [u8], path: &Path) -> Result<&'a str, AuditError> {
    std::str::from_utf8(buf).map_err(|error| {
        AuditError::HashError(format!("{} contains non-UTF-8 audit data: {error}", path.display()))
    })
}

fn read_first_entry(path: &Path) -> Result<AuditEntry, AuditError> {
    let mut reader = open_bounded_audit_segment(path)?;
    let mut buf = Vec::new();
    while next_audit_line(&mut reader, path, &mut buf)? {
        let line = audit_line_str(&buf, path)?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(entry) = parse_entry(line) {
            return Ok(entry);
        }
        break;
    }
    Err(AuditError::HashError(format!("no valid entry in {}", path.display())))
}

fn read_checkpoint(base: &Path) -> Result<Option<AuditCheckpoint>, AuditError> {
    let path = checkpoint_path(base);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(AuditError::IoError(error)),
    };
    let checkpoint: AuditCheckpoint = serde_json::from_slice(&bytes)
        .map_err(|error| AuditError::HashError(format!("malformed checkpoint: {error}")))?;
    if checkpoint.version != 1 {
        return Err(AuditError::HashError(format!(
            "unsupported checkpoint version {}",
            checkpoint.version
        )));
    }
    if checkpoint.segments.is_empty() {
        return Err(AuditError::HashError("checkpoint has no retained segments".to_string()));
    }
    for segment in &checkpoint.segments {
        if !is_safe_audit_file_name(&segment.file) {
            return Err(AuditError::HashError(format!(
                "checkpoint contains invalid segment identity {}",
                segment.file
            )));
        }
    }
    Ok(Some(checkpoint))
}

fn is_safe_audit_file_name(file: &str) -> bool {
    !file.is_empty()
        && Path::new(file).file_name().is_some_and(|name| name == file)
        && Path::new(file).components().count() == 1
}

fn recover_interrupted_rotation(base: &Path) -> Result<(), AuditError> {
    let Some(mut checkpoint) = read_checkpoint(base)? else {
        return Ok(());
    };
    let base_name = audit_file_name(base);
    let mut changed = false;
    let last = checkpoint
        .segments
        .last_mut()
        .ok_or_else(|| AuditError::HashError("checkpoint has no retained tail".to_string()))?;
    if last.file == base_name {
        let base_still_matches =
            base.exists() && read_first_entry(base).is_ok_and(|entry| entry.seq == last.start_seq);
        if !base_still_matches {
            let rotated = rotated_segment_path(base, last.start_seq, last.end_seq);
            if rotated.exists() {
                last.file = audit_file_name(&rotated);
                changed = true;
            }
        }
    }

    verify_checkpointed_chain(base, &checkpoint)?;
    let checkpoint_tail_is_active =
        checkpoint.segments.last().is_some_and(|segment| segment.file == base_name);
    if !checkpoint_tail_is_active && base.exists() {
        let active_bytes = std::fs::metadata(base).map_err(AuditError::IoError)?.len();
        if active_bytes > 0 {
            let start_seq = checkpoint.tail_seq.saturating_add(1);
            let (tail_seq, tail_hash) = verify_segment(base, start_seq, &checkpoint.tail_hash)?;
            let tail_seq = tail_seq.ok_or_else(|| {
                AuditError::HashError("recovered active audit segment is empty".to_string())
            })?;
            checkpoint.segments.push(AuditCheckpointSegment {
                file: base_name,
                start_seq,
                end_seq: tail_seq,
            });
            checkpoint.tail_seq = tail_seq;
            checkpoint.tail_hash = tail_hash;
            changed = true;
        }
    }
    if changed {
        let bytes = serde_json::to_vec(&checkpoint)
            .map_err(|error| AuditError::HashError(error.to_string()))?;
        atomic_write_checkpoint(&checkpoint_path(base), &bytes).map_err(AuditError::IoError)?;
    }
    Ok(())
}

fn verify_legacy_chain(base: &Path) -> Result<(), AuditError> {
    if !discover_rotated_segments(base)?.is_empty() {
        return Err(AuditError::HashError(
            "rotated audit segments require a durable checkpoint".to_string(),
        ));
    }
    let (tail_seq, tail_hash) = verify_segment(base, 0, &"0".repeat(64))?;
    if tail_seq.is_none() && tail_hash != "0".repeat(64) {
        return Err(AuditError::HashError("invalid empty audit chain".to_string()));
    }
    Ok(())
}

fn verify_checkpointed_chain(base: &Path, checkpoint: &AuditCheckpoint) -> Result<(), AuditError> {
    let discovered = discover_rotated_segments(base)?;
    for segment in &discovered {
        let retained = checkpoint
            .segments
            .iter()
            .any(|expected| audit_file_name(&segment.path) == expected.file);
        if !retained && segment.end_seq >= checkpoint.anchor_seq {
            return Err(AuditError::HashError(format!(
                "uncheckpointed segment {} overlaps retained chain",
                segment.path.display()
            )));
        }
    }

    let mut expected_seq = checkpoint.anchor_seq;
    let mut previous_hash = checkpoint.anchor_prev_hash.clone();
    let mut final_seq = None;
    for segment in &checkpoint.segments {
        if segment.start_seq != expected_seq {
            return Err(AuditError::HashError(format!(
                "segment {} starts at {}, expected {}",
                segment.file, segment.start_seq, expected_seq
            )));
        }
        if segment.end_seq < segment.start_seq {
            return Err(AuditError::HashError(format!(
                "segment {} has an invalid sequence range",
                segment.file
            )));
        }
        let path = base.with_file_name(&segment.file);
        let (tail_seq, tail_hash) = verify_segment(&path, expected_seq, &previous_hash)?;
        if tail_seq != Some(segment.end_seq) {
            return Err(AuditError::HashError(format!(
                "segment {} ends at {:?}, checkpoint requires {}",
                segment.file, tail_seq, segment.end_seq
            )));
        }
        final_seq = tail_seq;
        previous_hash = tail_hash;
        expected_seq = segment.end_seq.saturating_add(1);
    }
    if final_seq != Some(checkpoint.tail_seq) || previous_hash != checkpoint.tail_hash {
        return Err(AuditError::HashError(
            "checkpoint tail does not match retained audit chain".to_string(),
        ));
    }
    Ok(())
}

fn verify_segment(
    path: &Path,
    mut expected_seq: u64,
    initial_previous_hash: &str,
) -> Result<(Option<u64>, String), AuditError> {
    let mut reader = open_bounded_audit_segment(path)?;
    let mut previous_hash = initial_previous_hash.to_string();
    let mut tail_seq = None;
    let mut buf = Vec::new();
    let mut line_index = 0usize;
    while next_audit_line(&mut reader, path, &mut buf)? {
        let line = audit_line_str(&buf, path)?;
        let line_index = {
            let current = line_index;
            line_index += 1;
            current
        };
        if line.trim().is_empty() {
            continue;
        }
        let entry = parse_entry(line).ok_or_else(|| {
            AuditError::HashError(format!(
                "malformed entry in {} at line {}",
                path.display(),
                line_index + 1
            ))
        })?;
        if entry.seq != expected_seq {
            return Err(AuditError::HashError(format!(
                "sequence mismatch in {} at line {}: expected {}, got {}",
                path.display(),
                line_index + 1,
                expected_seq,
                entry.seq
            )));
        }
        if entry.prev_hash != previous_hash {
            return Err(AuditError::HashError(format!(
                "previous hash mismatch at sequence {}",
                entry.seq
            )));
        }
        let computed = compute_entry_hash(&entry);
        if entry.hash != computed {
            return Err(AuditError::HashError(format!("hash mismatch at sequence {}", entry.seq)));
        }
        tail_seq = Some(entry.seq);
        previous_hash = entry.hash;
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok((tail_seq, previous_hash))
}

fn open_private_append_file(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW makes the refusal atomic with the open. A separate
        // `symlink_metadata` check cannot do this: between the check and the open the
        // name can be replaced, and every later append, chmod, and chown would then
        // target the attacker's inode while the process believes it validated the
        // audit path.
        options.mode(AUDIT_FILE_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    // Bind the type check to the opened object rather than to the name. A directory or
    // device at the audit path must not become the evidence file.
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("audit path is not a regular file: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != AUDIT_FILE_MODE {
            file.set_permissions(std::fs::Permissions::from_mode(AUDIT_FILE_MODE))?;
        }
    }
    Ok(file)
}

fn atomic_write_checkpoint(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let suffix = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path.file_name().and_then(|name| name.to_str()).unwrap_or("audit.checkpoint");
    let temporary = path.with_file_name(format!("{name}.tmp.{}.{suffix}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        replace_file(&temporary, path)?;
        sync_parent_directory(path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

/// Turn UTF-16 path units into the NUL-terminated buffer a wide Win32 call requires.
///
/// An interior NUL would terminate the string early inside the kernel, so the call would act on a
/// prefix of the path the caller named. Reject that instead of encoding it.
///
/// Compiled on Windows, where `replace_file` uses it, and in test builds on every target so the
/// encoding contract stays provable on a non-Windows workspace.
#[cfg(any(windows, test))]
fn encode_wide_nul_terminated(
    units: impl IntoIterator<Item = u16>,
    label: &str,
) -> std::io::Result<Vec<u16>> {
    let mut buffer: Vec<u16> = units.into_iter().collect();
    if buffer.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{label} path contains an interior NUL and cannot be passed to Win32"),
        ));
    }
    buffer.push(0);
    Ok(buffer)
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = encode_wide_nul_terminated(source.as_os_str().encode_wide(), "source")?;
    let destination =
        encode_wide_nul_terminated(destination.as_os_str().encode_wide(), "destination")?;

    // SAFETY: both buffers are owned locals holding NUL-terminated UTF-16 with no interior NUL,
    // rejected above, and they outlive the call. `MoveFileExW` reads through both pointers and
    // writes through neither, so no aliasing or lifetime obligation escapes this scope. A zero
    // return means failure and is the only case in which `errno` is read.
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn read_first_sequence(path: &Path) -> Result<u64, AuditError> {
    read_first_entry(path)
        .map(|entry| entry.seq)
        .map_err(|_| AuditError::HashError("active audit segment has no valid entry".to_string()))
}

fn rotated_segment_path(base: &Path, start_seq: u64, end_seq: u64) -> PathBuf {
    let file_name = base.file_name().and_then(|name| name.to_str()).unwrap_or("audit.ndjson");
    base.with_file_name(format!("{file_name}.{start_seq:020}-{end_seq:020}.segment"))
}

fn discover_rotated_segments(base: &Path) -> Result<Vec<AuditSegment>, AuditError> {
    let Some(parent) = base.parent() else {
        return Ok(Vec::new());
    };
    let file_name = base.file_name().and_then(|name| name.to_str()).unwrap_or("audit.ndjson");
    let prefix = format!("{file_name}.");
    let suffix = ".segment";
    let mut segments = Vec::new();
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(segments),
        Err(error) => return Err(AuditError::IoError(error)),
    };
    for entry in entries {
        let entry = entry.map_err(AuditError::IoError)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(range) = name.strip_prefix(&prefix).and_then(|name| name.strip_suffix(suffix))
        else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start_seq), Ok(end_seq)) = (start.parse::<u64>(), end.parse::<u64>()) else {
            continue;
        };
        segments.push(AuditSegment { start_seq, end_seq, path: entry.path() });
    }
    segments.sort_by_key(|segment| segment.start_seq);
    Ok(segments)
}

/// Read the next sequence and last hash from an existing verified audit file.
fn read_tail_state(path: &Path) -> Result<(u64, String), AuditError> {
    AuditLog::verify_chain(path)?;
    if let Some(checkpoint) = read_checkpoint(path)? {
        return Ok((checkpoint.tail_seq.saturating_add(1), checkpoint.tail_hash));
    }
    // Stream forward and retain only the last entry seen. Reversing over a
    // whole-file string would make startup memory scale with the retained file, which
    // is the exhaustion path this bound closes; keeping one entry costs a constant.
    let mut reader = open_bounded_audit_segment(path)?;
    let mut buf = Vec::new();
    let mut last = None;
    while next_audit_line(&mut reader, path, &mut buf)? {
        let line = audit_line_str(&buf, path)?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(
            parse_entry(line)
                .ok_or_else(|| AuditError::HashError("malformed final audit entry".to_string()))?,
        );
    }
    match last {
        Some(entry) => Ok((entry.seq.saturating_add(1), entry.hash)),
        None => Ok((0, "0".repeat(64))),
    }
}

#[cfg(test)]
mod tests;
