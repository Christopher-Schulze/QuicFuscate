//! Public audit event, configuration, and error contracts.

use std::time::Duration;

use super::{
    DEFAULT_AUDIT_FLUSH_TIMEOUT, DEFAULT_AUDIT_FLUSH_TIMEOUT_MS, DEFAULT_AUDIT_MAX_SEGMENTS,
    DEFAULT_AUDIT_MAX_SEGMENT_BYTES, DEFAULT_AUDIT_QUEUE_CAPACITY, MAX_AUDIT_FLUSH_TIMEOUT,
    MAX_AUDIT_FLUSH_TIMEOUT_MS, MAX_AUDIT_QUEUE_CAPACITY, MAX_AUDIT_SEGMENTS,
    MAX_AUDIT_SEGMENT_BYTES,
};

/// Security-relevant audit event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    ClientAuthenticated,
    AuthFailed,
    AuthTimeout,
    QkeyIssued,
    QkeyRevoked,
    QkeyRotated,
    AdminAction,
    DdosAnomaly,
    IpBlacklisted,
    IpUnblacklisted,
    KillSwitchActivated,
    KillSwitchDeactivated,
    PrivilegesDropped,
    PrivilegeDropFailed,
    ConnectionEstablished,
    ConnectionClosed,
    ConnectionRejected,
    FirewallRuleAdded,
    FirewallRuleRemoved,
    ConfigReloaded,
    ServerStarted,
    ServerStopped,
}

impl AuditEventType {
    pub(super) fn as_str(&self) -> &'static str {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl AuditSeverity {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditActor {
    System,
    Administrator,
    Client,
    NetworkPeer,
}

impl AuditActor {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Administrator => "administrator",
            Self::Client => "client",
            Self::NetworkPeer => "network_peer",
        }
    }
}

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
    pub(super) fn as_str(self) -> &'static str {
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
    pub(super) fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContext<'a> {
    pub actor: AuditActor,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    pub reason: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub version: u32,
    pub seq: u64,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    pub source_ip: Option<String>,
    pub client_id: Option<String>,
    pub message: String,
    pub actor: AuditActor,
    pub target: AuditTarget,
    pub outcome: AuditOutcome,
    pub reason: Option<String>,
    pub prev_hash: String,
    pub hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditOptions {
    pub queue_capacity: usize,
    pub max_segment_bytes: u64,
    pub max_segments: usize,
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

impl AuditOptions {
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.queue_capacity == 0 || self.queue_capacity > MAX_AUDIT_QUEUE_CAPACITY {
            return Err(AuditError::InvalidOptions(format!(
                "audit.queue_capacity must be between 1 and {MAX_AUDIT_QUEUE_CAPACITY}"
            )));
        }
        if self.max_segment_bytes == 0 || self.max_segment_bytes > MAX_AUDIT_SEGMENT_BYTES {
            return Err(AuditError::InvalidOptions(format!(
                "audit.max_segment_bytes must be between 1 and {MAX_AUDIT_SEGMENT_BYTES}"
            )));
        }
        if self.max_segments == 0 || self.max_segments > MAX_AUDIT_SEGMENTS {
            return Err(AuditError::InvalidOptions(format!(
                "audit.max_segments must be between 1 and {MAX_AUDIT_SEGMENTS}"
            )));
        }
        if self.flush_timeout.is_zero() || self.flush_timeout > MAX_AUDIT_FLUSH_TIMEOUT {
            return Err(AuditError::InvalidOptions(format!(
                "audit.flush_timeout must be between 1 and {MAX_AUDIT_FLUSH_TIMEOUT_MS} milliseconds"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct AuditConfig {
    pub queue_capacity: usize,
    pub max_segment_bytes: u64,
    pub max_segments: usize,
    pub flush_timeout_ms: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_AUDIT_QUEUE_CAPACITY,
            max_segment_bytes: DEFAULT_AUDIT_MAX_SEGMENT_BYTES,
            max_segments: DEFAULT_AUDIT_MAX_SEGMENTS,
            flush_timeout_ms: DEFAULT_AUDIT_FLUSH_TIMEOUT_MS,
        }
    }
}

impl AuditConfig {
    pub fn to_audit_options(&self) -> AuditOptions {
        AuditOptions {
            queue_capacity: self.queue_capacity,
            max_segment_bytes: self.max_segment_bytes,
            max_segments: self.max_segments,
            flush_timeout: Duration::from_millis(self.flush_timeout_ms),
        }
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        self.to_audit_options().validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditPayloadField {
    SourceIp,
    ClientId,
    Reason,
    Message,
    EventPayload,
}

impl AuditPayloadField {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::SourceIp => "source_ip",
            Self::ClientId => "client_id",
            Self::Reason => "reason",
            Self::Message => "message",
            Self::EventPayload => "event_payload",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuditStats {
    pub dropped_events: u64,
    pub queue_full_events: u64,
    pub worker_closing_events: u64,
    pub worker_disconnect_events: u64,
    pub payload_rejections: u64,
    pub persistence_errors: u64,
    pub terminal_dropped_events: u64,
    pub slow_flushes: u64,
    pub shutdown_failures: u64,
}

#[derive(Debug)]
pub enum AuditError {
    IoError(std::io::Error),
    HashError(String),
    InvalidOptions(String),
    PayloadTooLarge { field: AuditPayloadField, encoded_bytes: usize, max_encoded_bytes: usize },
    QueueFull,
    WorkerClosing,
    WorkerDisconnected,
    WorkerSpawnError(std::io::Error),
    PersistenceFailed(String),
    DurabilityTimeout(String),
    FlushTimeout(String),
    ShutdownTimeout(String),
    AlreadyInitialized,
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(error) => write!(formatter, "audit I/O error: {error}"),
            Self::HashError(error) => write!(formatter, "audit hash error: {error}"),
            Self::InvalidOptions(error) => write!(formatter, "invalid audit options: {error}"),
            Self::PayloadTooLarge { field, encoded_bytes, max_encoded_bytes } => write!(
                formatter,
                "audit {field} payload is {encoded_bytes} JSON-encoded bytes, maximum is {max_encoded_bytes}",
                field = field.as_str()
            ),
            Self::QueueFull => write!(formatter, "audit queue is full"),
            Self::WorkerClosing => write!(formatter, "audit worker is closing"),
            Self::WorkerDisconnected => write!(formatter, "audit worker is disconnected"),
            Self::WorkerSpawnError(error) => write!(formatter, "audit worker spawn error: {error}"),
            Self::PersistenceFailed(error) => write!(formatter, "audit persistence failed: {error}"),
            Self::DurabilityTimeout(error) => write!(formatter, "audit durability timed out: {error}"),
            Self::FlushTimeout(error) => write!(formatter, "audit flush acknowledgement failed: {error}"),
            Self::ShutdownTimeout(error) => write!(formatter, "audit shutdown timed out: {error}"),
            Self::AlreadyInitialized => write!(formatter, "audit log is already initialized"),
        }
    }
}

impl std::error::Error for AuditError {}
