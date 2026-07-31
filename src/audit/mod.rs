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

use crossbeam_channel::{Receiver, Sender, TrySendError};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_AUDIT_QUEUE_CAPACITY: usize = 16_384;
const DEFAULT_AUDIT_MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_AUDIT_MAX_SEGMENTS: usize = 8;
const DEFAULT_AUDIT_FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Connection rejected before session establishment.
    ConnectionRejected,
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
            Self::ConnectionRejected => "connection_rejected",
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

/// Typed principal category responsible for an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditActor {
    System,
    Administrator,
    Client,
    NetworkPeer,
}

impl AuditActor {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Administrator => "administrator",
            Self::Client => "client",
            Self::NetworkPeer => "network_peer",
        }
    }
}

/// Typed resource category affected by an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditTarget {
    Server,
    Client,
    Connection,
    Qkey,
    Configuration,
    Firewall,
    Route,
    System,
}

impl AuditTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
            Self::Connection => "connection",
            Self::Qkey => "qkey",
            Self::Configuration => "configuration",
            Self::Firewall => "firewall",
            Self::Route => "route",
            Self::System => "system",
        }
    }
}

/// Typed terminal result of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Succeeded,
    Failed,
    Denied,
    TimedOut,
    Started,
    Stopped,
    Detected,
}

impl AuditOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::TimedOut => "timed_out",
            Self::Started => "started",
            Self::Stopped => "stopped",
            Self::Detected => "detected",
        }
    }
}

/// Typed security context attached to an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContext<'a> {
    pub actor: AuditActor,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    pub reason: Option<&'a str>,
}

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// Stable schema version. Version 1 entries remain verifier-compatible.
    pub version: u32,
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
    /// Typed principal category.
    pub actor: AuditActor,
    /// Typed affected resource category.
    pub target: AuditTarget,
    /// Typed terminal result.
    pub outcome: AuditOutcome,
    /// Stable machine-oriented reason where applicable.
    pub reason: Option<String>,
    /// SHA-256 hash of the previous entry (hex).
    pub prev_hash: String,
    /// SHA-256 hash of this entry (hex, computed on flush).
    pub hash: String,
}

/// Audit logger that writes hash-chained entries to a file.
pub struct AuditLog {
    sender: Sender<AuditCommand>,
    dropped_events: Arc<AtomicU64>,
    persistence_errors: Arc<AtomicU64>,
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
    terminal_error: Option<String>,
    persistence_errors: Arc<AtomicU64>,
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

/// Bounded audit persistence settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditOptions {
    /// Maximum number of accepted commands waiting for the single writer.
    pub queue_capacity: usize,
    /// Maximum active segment size before deterministic rotation.
    pub max_segment_bytes: u64,
    /// Maximum number of retained segments, including the active segment.
    pub max_segments: usize,
    /// Maximum time a lifecycle barrier may wait for enqueue and acknowledgement.
    pub flush_timeout: Duration,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_AUDIT_QUEUE_CAPACITY,
            max_segment_bytes: DEFAULT_AUDIT_MAX_SEGMENT_BYTES,
            max_segments: DEFAULT_AUDIT_MAX_SEGMENTS,
            flush_timeout: DEFAULT_AUDIT_FLUSH_TIMEOUT,
        }
    }
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

enum AuditCommand {
    Event(PendingAuditEvent),
    Flush(Sender<Result<(), String>>),
    Shutdown,
}

/// Observable bounded audit-persistence outcomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditStats {
    /// Events rejected before persistence because the queue was full or disconnected.
    pub dropped_events: u64,
    /// File write or durability-flush failures observed by the worker.
    pub persistence_errors: u64,
}

/// Error returned by audit log operations.
#[derive(Debug)]
pub enum AuditError {
    IoError(std::io::Error),
    HashError(String),
    QueueFull,
    WorkerDisconnected,
    WorkerSpawnError(std::io::Error),
    FlushTimeout(String),
    AlreadyInitialized,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "audit I/O error: {e}"),
            Self::HashError(s) => write!(f, "audit hash error: {s}"),
            Self::QueueFull => write!(f, "audit queue is full"),
            Self::WorkerDisconnected => write!(f, "audit worker is disconnected"),
            Self::WorkerSpawnError(e) => write!(f, "audit worker spawn error: {e}"),
            Self::FlushTimeout(error) => write!(f, "audit flush failed: {error}"),
            Self::AlreadyInitialized => write!(f, "audit log is already initialized"),
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
        Self::open_with_options(path, AuditOptions::default())
    }

    /// Create a new audit owner with explicit bounded persistence settings.
    pub fn open_with_options(path: PathBuf, options: AuditOptions) -> Result<Self, AuditError> {
        if options.queue_capacity == 0 {
            return Err(AuditError::HashError(
                "audit queue capacity must be greater than zero".into(),
            ));
        }
        if options.max_segment_bytes == 0 {
            return Err(AuditError::HashError(
                "audit maximum segment size must be greater than zero".into(),
            ));
        }
        if options.max_segments == 0 {
            return Err(AuditError::HashError(
                "audit retained segment count must be greater than zero".into(),
            ));
        }
        if path.exists() {
            let metadata = std::fs::symlink_metadata(&path).map_err(AuditError::IoError)?;
            if !metadata.file_type().is_file() {
                return Err(AuditError::HashError(format!(
                    "audit path must be a regular file: {}",
                    path.display()
                )));
            }
        }
        recover_interrupted_rotation(&path)?;
        let has_checkpoint = checkpoint_path(&path).exists();
        let (next_seq, last_hash) = if path.exists() || has_checkpoint {
            read_tail_state(&path)?
        } else {
            (0, "0".repeat(64))
        };

        let file = open_private_append_file(&path, false).map_err(AuditError::IoError)?;
        let active_bytes = file.metadata().map_err(AuditError::IoError)?.len();
        let active_start_seq =
            if active_bytes == 0 { next_seq } else { read_first_sequence(&path)? };
        let rotated_segments = discover_rotated_segments(&path)?;

        let dropped_events = Arc::new(AtomicU64::new(0));
        let persistence_errors = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = crossbeam_channel::bounded(options.queue_capacity);
        let worker_errors = persistence_errors.clone();
        let worker = std::thread::Builder::new()
            .name("qf-audit-writer".to_string())
            .spawn(move || {
                run_audit_writer(
                    receiver,
                    AuditWriter {
                        file: Some(BufWriter::new(file)),
                        path,
                        active_bytes,
                        active_start_seq,
                        max_segment_bytes: options.max_segment_bytes,
                        max_segments: options.max_segments,
                        rotated_segments,
                        next_seq,
                        last_hash,
                        terminal_error: None,
                        persistence_errors: worker_errors,
                    },
                );
            })
            .map_err(AuditError::WorkerSpawnError)?;

        Ok(Self {
            sender,
            dropped_events,
            persistence_errors,
            worker: Mutex::new(Some(worker)),
            flush_timeout: options.flush_timeout,
        })
    }

    /// Enqueue an audit event without performing producer-side hashing or file I/O.
    pub fn log(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<&str>,
        client_id: Option<&str>,
        message: &str,
    ) -> Result<(), AuditError> {
        self.log_typed(
            event_type,
            severity,
            source_ip,
            client_id,
            default_context(event_type, message),
            message,
        )
    }

    /// Enqueue one fully typed audit event.
    pub fn log_typed(
        &self,
        event_type: AuditEventType,
        severity: AuditSeverity,
        source_ip: Option<&str>,
        client_id: Option<&str>,
        context: AuditContext<'_>,
        message: &str,
    ) -> Result<(), AuditError> {
        let event = PendingAuditEvent {
            event_type,
            severity,
            source_ip: source_ip.map(String::from),
            client_id: client_id.map(String::from),
            message: message.to_string(),
            actor: context.actor,
            target: context.target,
            outcome: context.outcome,
            reason: context.reason.map(String::from),
        };
        match self.sender.try_send(AuditCommand::Event(event)) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                Err(AuditError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped_events.fetch_add(1, Ordering::Relaxed);
                Err(AuditError::WorkerDisconnected)
            }
        }
    }

    /// Flush all events accepted before this bounded barrier.
    pub fn flush(&self) -> Result<(), AuditError> {
        let (ack_tx, ack_rx) = crossbeam_channel::bounded(1);
        self.sender
            .send_timeout(AuditCommand::Flush(ack_tx), self.flush_timeout)
            .map_err(|error| AuditError::FlushTimeout(error.to_string()))?;
        ack_rx
            .recv_timeout(self.flush_timeout)
            .map_err(|error| AuditError::FlushTimeout(error.to_string()))?
            .map_err(AuditError::FlushTimeout)
    }

    /// Return bounded-queue and persistence-failure counters.
    pub fn stats(&self) -> AuditStats {
        AuditStats {
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            persistence_errors: self.persistence_errors.load(Ordering::Relaxed),
        }
    }

    /// Flush accepted events and stop the owned writer thread.
    pub fn shutdown(&self) -> Result<(), AuditError> {
        let mut worker = self.worker.lock().unwrap_or_else(|error| error.into_inner());
        if worker.is_none() {
            return Ok(());
        }
        let flush_result = self.flush();
        let _ = self.sender.send_timeout(AuditCommand::Shutdown, self.flush_timeout);
        let mut join_result = Ok(());
        if let Some(handle) = worker.take() {
            if handle.join().is_err() {
                join_result = Err(AuditError::WorkerDisconnected);
            }
        }
        match (flush_result, join_result) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    /// Verify the integrity of the hash chain. Returns Ok(()) if the chain
    /// is intact, or Err with the first broken entry's sequence number.
    pub fn verify_chain(path: &Path) -> Result<(), AuditError> {
        match read_checkpoint(path)? {
            Some(checkpoint) => verify_checkpointed_chain(path, &checkpoint),
            None => verify_legacy_chain(path),
        }
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn run_audit_writer(receiver: Receiver<AuditCommand>, mut writer: AuditWriter) {
    while let Ok(command) = receiver.recv() {
        match command {
            AuditCommand::Event(event) => writer.write_event(event),
            AuditCommand::Flush(ack) => {
                let result = writer.flush().map_err(|error| error.to_string());
                if result.is_err() {
                    writer.persistence_errors.fetch_add(1, Ordering::Relaxed);
                }
                let _ = ack.send(result);
            }
            AuditCommand::Shutdown => break,
        }
    }
    if writer.flush().is_err() {
        writer.persistence_errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl AuditWriter {
    fn write_event(&mut self, event: PendingAuditEvent) {
        if self.terminal_error.is_some() {
            self.persistence_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Err(error) = self.try_write_event(event) {
            self.persistence_errors.fetch_add(1, Ordering::Relaxed);
            self.terminal_error = Some(error.to_string());
        }
    }

    fn try_write_event(&mut self, event: PendingAuditEvent) -> std::io::Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
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
        if let Some(error) = &self.terminal_error {
            return Err(std::io::Error::other(error.clone()));
        }
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
pub fn init_audit_log(path: Option<PathBuf>, owner: Option<(u32, u32)>) {
    if let Err(error) = init_audit_log_with_options(path, owner, AuditOptions::default()) {
        log::warn!("Failed to initialize audit log: {error}");
    }
}

/// Initialize the global audit log with validated bounded persistence settings.
pub fn init_audit_log_with_options(
    path: Option<PathBuf>,
    owner: Option<(u32, u32)>,
    options: AuditOptions,
) -> Result<(), AuditError> {
    if let Some(p) = path {
        // Track whether *we* created the parent dir so we only chown
        // directories we own — never pre-existing system dirs like /var/log.
        let parent_newly_created = p.parent().map(|parent| !parent.exists()).unwrap_or(false);
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return Err(AuditError::IoError(e));
            }
        }
        let audit_log = AuditLog::open_with_options(p.clone(), options)?;
        #[cfg(unix)]
        secure_audit_file(&p, parent_newly_created, owner);
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

fn read_first_entry(path: &Path) -> Result<AuditEntry, AuditError> {
    let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
    content
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(parse_entry)
        .ok_or_else(|| AuditError::HashError(format!("no valid entry in {}", path.display())))
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
    let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
    let mut previous_hash = initial_previous_hash.to_string();
    let mut tail_seq = None;
    for (line_index, line) in content.lines().enumerate() {
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
        options.mode(0o600);
    }
    options.open(path)
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
        options.mode(0o600);
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

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers valid for the duration of the call.
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

fn read_first_sequence(path: &PathBuf) -> Result<u64, AuditError> {
    let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
    content
        .lines()
        .find(|line| !line.trim().is_empty())
        .and_then(parse_entry)
        .map(|entry| entry.seq)
        .ok_or_else(|| AuditError::HashError("active audit segment has no valid entry".to_string()))
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
fn read_tail_state(path: &PathBuf) -> Result<(u64, String), AuditError> {
    AuditLog::verify_chain(path)?;
    if let Some(checkpoint) = read_checkpoint(path)? {
        return Ok((checkpoint.tail_seq.saturating_add(1), checkpoint.tail_hash));
    }
    let content = std::fs::read_to_string(path).map_err(AuditError::IoError)?;
    for line in content.lines().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = parse_entry(line)
            .ok_or_else(|| AuditError::HashError("malformed final audit entry".to_string()))?;
        return Ok((entry.seq.saturating_add(1), entry.hash));
    }
    Ok((0, "0".repeat(64)))
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

    // Tiny segments intentionally force dozens of synchronous checkpoint replacements.
    // Windows write-through durability needs a wider bound under parallel CI load.
    const ROTATION_DURABILITY_TEST_TIMEOUT: Duration = Duration::from_secs(30);

    fn audit_test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "quicfuscate_audit_{name}_{}_{}.jsonl",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ))
    }

    fn remove_audit_set(base: &Path) {
        let _ = std::fs::remove_file(base);
        let _ = std::fs::remove_file(checkpoint_path(base));
        if let Ok(segments) = discover_rotated_segments(base) {
            for segment in segments {
                let _ = std::fs::remove_file(segment.path);
            }
        }
    }

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
        let tmp = audit_test_path("chain");
        remove_audit_set(&tmp);
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
        remove_audit_set(&tmp);
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
        let tmp = audit_test_path("tamper");
        remove_audit_set(&tmp);
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
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_audit_log_resume_chain() {
        let tmp = audit_test_path("resume");
        remove_audit_set(&tmp);

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
        let entries = std::fs::read_to_string(&tmp).unwrap();
        let sequences: Vec<u64> =
            entries.lines().filter_map(|line| parse_entry(line).map(|entry| entry.seq)).collect();
        assert_eq!(sequences, vec![0, 1]);
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_concurrent_producers_preserve_total_order_and_throughput() {
        let tmp = std::env::temp_dir()
            .join(format!("quicfuscate_audit_concurrent_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let log = Arc::new(AuditLog::open(tmp.clone()).unwrap());
        let started = std::time::Instant::now();
        let mut producers = Vec::new();
        for producer in 0..8 {
            let log = log.clone();
            producers.push(std::thread::spawn(move || {
                for event in 0..1_250 {
                    log.log(
                        AuditEventType::AdminAction,
                        AuditSeverity::Info,
                        None,
                        None,
                        &format!("producer={producer} event={event}"),
                    )
                    .unwrap();
                }
            }));
        }
        for producer in producers {
            producer.join().unwrap();
        }
        let producer_elapsed = started.elapsed();
        assert!(
            producer_elapsed < Duration::from_secs(1),
            "10,000 accepted events took {producer_elapsed:?}"
        );
        log.flush().unwrap();
        assert_eq!(log.stats(), AuditStats::default());
        drop(log);

        AuditLog::verify_chain(&tmp).unwrap();
        let contents = std::fs::read_to_string(&tmp).unwrap();
        let entries: Vec<AuditEntry> = contents.lines().filter_map(parse_entry).collect();
        assert_eq!(entries.len(), 10_000);
        assert!(entries.iter().enumerate().all(|(index, entry)| entry.seq == index as u64));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_rotation_retention_restart_and_checkpoint_integrity() {
        let tmp = audit_test_path("rotation");
        remove_audit_set(&tmp);
        let options = AuditOptions {
            queue_capacity: 256,
            max_segment_bytes: 700,
            max_segments: 3,
            flush_timeout: ROTATION_DURABILITY_TEST_TIMEOUT,
        };
        let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
        for index in 0..40 {
            log.log(
                AuditEventType::AdminAction,
                AuditSeverity::Info,
                None,
                None,
                &format!("rotation event {index:04} {}", "x".repeat(80)),
            )
            .unwrap();
        }
        log.flush().unwrap();
        drop(log);

        AuditLog::verify_chain(&tmp).unwrap();
        let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
        assert_eq!(checkpoint.segments.len(), 3);
        assert_eq!(checkpoint.tail_seq, 39);
        assert!(checkpoint.anchor_seq > 0);
        assert_eq!(discover_rotated_segments(&tmp).unwrap().len(), 2);

        let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
        log.log(AuditEventType::ConfigReloaded, AuditSeverity::Info, None, None, "restart event")
            .unwrap();
        log.flush().unwrap();
        drop(log);
        AuditLog::verify_chain(&tmp).unwrap();
        assert_eq!(read_checkpoint(&tmp).unwrap().unwrap().tail_seq, 40);
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_checkpoint_detects_tail_deletion() {
        let tmp = audit_test_path("tail_delete");
        remove_audit_set(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        for index in 0..4 {
            log.log(
                AuditEventType::AdminAction,
                AuditSeverity::Info,
                None,
                None,
                &format!("event {index}"),
            )
            .unwrap();
        }
        log.flush().unwrap();
        drop(log);
        let content = std::fs::read_to_string(&tmp).unwrap();
        let truncated = content.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&tmp, truncated).unwrap();
        assert!(AuditLog::verify_chain(&tmp).is_err());
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_checkpoint_detects_segment_deletion_and_reordering() {
        let tmp = audit_test_path("segments");
        remove_audit_set(&tmp);
        let options = AuditOptions {
            queue_capacity: 128,
            max_segment_bytes: 650,
            max_segments: 5,
            flush_timeout: ROTATION_DURABILITY_TEST_TIMEOUT,
        };
        let log = AuditLog::open_with_options(tmp.clone(), options).unwrap();
        for index in 0..24 {
            log.log(
                AuditEventType::ConnectionEstablished,
                AuditSeverity::Info,
                None,
                Some("client"),
                &format!("segment event {index:04} {}", "y".repeat(80)),
            )
            .unwrap();
        }
        log.flush().unwrap();
        drop(log);
        AuditLog::verify_chain(&tmp).unwrap();

        let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
        assert!(checkpoint.segments.len() >= 3);
        let first_path = tmp.with_file_name(&checkpoint.segments[0].file);
        let saved = std::fs::read(&first_path).unwrap();
        std::fs::remove_file(&first_path).unwrap();
        assert!(AuditLog::verify_chain(&tmp).is_err());
        std::fs::write(&first_path, &saved).unwrap();

        let second_path = tmp.with_file_name(&checkpoint.segments[1].file);
        let first_content = std::fs::read(&first_path).unwrap();
        let second_content = std::fs::read(&second_path).unwrap();
        std::fs::write(&first_path, second_content).unwrap();
        std::fs::write(&second_path, first_content).unwrap();
        assert!(AuditLog::verify_chain(&tmp).is_err());
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_restart_recovers_checkpoint_interrupted_during_rotation() {
        let tmp = audit_test_path("rotation_recovery");
        remove_audit_set(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        for index in 0..3 {
            log.log(
                AuditEventType::AdminAction,
                AuditSeverity::Info,
                None,
                None,
                &format!("event {index}"),
            )
            .unwrap();
        }
        log.flush().unwrap();
        drop(log);

        let checkpoint = read_checkpoint(&tmp).unwrap().unwrap();
        let rotated = rotated_segment_path(&tmp, checkpoint.anchor_seq, checkpoint.tail_seq);
        std::fs::rename(&tmp, &rotated).unwrap();
        open_private_append_file(&tmp, true).unwrap();

        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log(AuditEventType::ServerStarted, AuditSeverity::Info, None, None, "restarted")
            .unwrap();
        log.flush().unwrap();
        drop(log);

        AuditLog::verify_chain(&tmp).unwrap();
        let recovered = read_checkpoint(&tmp).unwrap().unwrap();
        assert_eq!(recovered.tail_seq, 3);
        assert_eq!(recovered.segments.len(), 2);
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_queue_saturation_drops_newest_and_counts_it() {
        let (sender, receiver) = crossbeam_channel::bounded(1);
        let log = AuditLog {
            sender,
            dropped_events: Arc::new(AtomicU64::new(0)),
            persistence_errors: Arc::new(AtomicU64::new(0)),
            worker: Mutex::new(None),
            flush_timeout: Duration::ZERO,
        };
        log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "accepted").unwrap();
        assert!(matches!(
            log.log(AuditEventType::AdminAction, AuditSeverity::Info, None, None, "dropped"),
            Err(AuditError::QueueFull)
        ));
        assert_eq!(log.stats().dropped_events, 1);
        drop(receiver);
        drop(log);
    }

    #[cfg(unix)]
    #[test]
    fn test_checkpoint_permission_failure_is_observable_at_flush() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let tmp = audit_test_path("permission_failure");
        let parent = tmp.parent().unwrap().join(format!(
            "qf-audit-permission-{}",
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("audit.ndjson");
        let log = AuditLog::open(path.clone()).unwrap();
        log.log(
            AuditEventType::AdminAction,
            AuditSeverity::Critical,
            None,
            None,
            "sink failure probe",
        )
        .unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(log.flush().is_err());
        assert!(log.stats().persistence_errors > 0);
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(log);
        remove_audit_set(&path);
        std::fs::remove_dir(&parent).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_special_file_sink_is_rejected_without_reading_it() {
        assert!(matches!(
            AuditLog::open(PathBuf::from("/dev/full")),
            Err(AuditError::HashError(_))
        ));
    }

    #[test]
    fn test_typed_fields_and_control_characters_round_trip() {
        let tmp = audit_test_path("typed");
        remove_audit_set(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        log.log_typed(
            AuditEventType::AuthFailed,
            AuditSeverity::Warning,
            Some("192.0.2.5"),
            Some("client-5"),
            AuditContext {
                actor: AuditActor::Client,
                target: AuditTarget::Qkey,
                outcome: AuditOutcome::Denied,
                reason: Some("invalid_token"),
            },
            "denied\nwith \"quoted\" detail",
        )
        .unwrap();
        log.flush().unwrap();
        drop(log);
        AuditLog::verify_chain(&tmp).unwrap();
        let content = std::fs::read_to_string(&tmp).unwrap();
        assert_eq!(content.lines().count(), 1);
        let entry = parse_entry(content.trim()).unwrap();
        assert_eq!(entry.version, 2);
        assert_eq!(entry.actor, AuditActor::Client);
        assert_eq!(entry.target, AuditTarget::Qkey);
        assert_eq!(entry.outcome, AuditOutcome::Denied);
        assert_eq!(entry.reason.as_deref(), Some("invalid_token"));
        assert_eq!(entry.message, "denied\nwith \"quoted\" detail");
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_checkpoint_detects_interior_deletion_and_truncation() {
        let tmp = audit_test_path("interior");
        remove_audit_set(&tmp);
        let log = AuditLog::open(tmp.clone()).unwrap();
        for index in 0..5 {
            log.log(
                AuditEventType::AdminAction,
                AuditSeverity::Info,
                None,
                None,
                &format!("event {index}"),
            )
            .unwrap();
        }
        log.flush().unwrap();
        drop(log);
        let original = std::fs::read(&tmp).unwrap();
        let text = String::from_utf8(original.clone()).unwrap();
        let without_middle = text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| (index != 2).then_some(line))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&tmp, without_middle).unwrap();
        assert!(AuditLog::verify_chain(&tmp).is_err());

        let truncated_length = original.len().saturating_sub(17);
        std::fs::write(&tmp, &original[..truncated_length]).unwrap();
        assert!(AuditLog::verify_chain(&tmp).is_err());
        remove_audit_set(&tmp);
    }

    #[test]
    fn test_legacy_version_one_entry_remains_verifiable() {
        let tmp = audit_test_path("legacy");
        remove_audit_set(&tmp);
        let mut entry = AuditEntry {
            version: 1,
            seq: 0,
            timestamp: 1_700_000_000,
            event_type: AuditEventType::ServerStarted,
            severity: AuditSeverity::Info,
            source_ip: None,
            client_id: None,
            message: "legacy entry".to_string(),
            actor: AuditActor::System,
            target: AuditTarget::Server,
            outcome: AuditOutcome::Started,
            reason: None,
            prev_hash: "0".repeat(64),
            hash: String::new(),
        };
        entry.hash = compute_entry_hash(&entry);
        let legacy = format!(
            r#"{{"seq":{},"ts":{},"event":"{}","severity":"{}","src_ip":null,"client_id":null,"msg":"{}","prev_hash":"{}","hash":"{}"}}"#,
            entry.seq,
            entry.timestamp,
            entry.event_type.as_str(),
            entry.severity.as_str(),
            entry.message,
            entry.prev_hash,
            entry.hash
        );
        std::fs::write(&tmp, format!("{legacy}\n")).unwrap();
        AuditLog::verify_chain(&tmp).unwrap();
        remove_audit_set(&tmp);
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
