// HTTP admin server for web dashboard control.
//
// Serves static web assets and exposes a JSON API backed by an AdminHttpHandler.
// Uses hyper 1.x for HTTP/1.1 parsing and response writing.
//
// ## Architecture: admin_http.rs vs admin.rs
//
// This module (`admin_http.rs`) is the **HTTP web dashboard** - a remote-capable,
// authenticated admin interface. It serves the web-admin UI static assets and exposes
// a JSON API with session-based authentication (Argon2 password hashing, CSRF tokens,
// rate limiting, replay protection).
//
// The sibling module `admin.rs` is the **Unix domain socket control plane** - a low-level,
// local-only interface for `quicfuscate-ctl` CLI commands. It uses JSON-over-Unix-socket
// without authentication (socket file permissions provide access control).
//
// Both interfaces serve different use cases and are intentionally parallel:
// - `admin_http.rs`: remote dashboard access, QKey management, multi-user (authenticated)
// - `admin.rs`: local server management, scripting, automation (no auth overhead)
//
// Shared types (`AdminResponse`, `ClientInfo`) are imported from `admin.rs`.
// Handler logic is currently independent in each module. Future direction: extract
// shared handler logic into a common service layer to reduce duplication while
// preserving transport separation.

use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
// Salt via crate::rng::fill_secure (wraps getrandom, consistent with project RNG contract).
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};

use super::super::admin::{
    normalize_admin_client_id, normalize_admin_ip, AdminResponse, ClientInfo,
};
use super::super::BandwidthPolicy;
use crate::time_source::ProtocolClock;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;
const SESSION_COOKIE: &str = "qf_admin_session";
const SESSION_TTL_SECS: u64 = 60 * 60;
const LOGIN_RATE_LIMIT_ATTEMPTS: u32 = 5;
const LOGIN_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const MAX_LOGIN_RATE_LIMIT_KEYS: usize = 10_000;
const CSRF_TOKEN_BYTES: usize = 16;
const CSRF_TOKEN_HEADER: &str = "X-CSRF-Token";
const CSRF_NONCE_HEADER: &str = "X-CSRF-Nonce";
const MAX_REPLAY_FINGERPRINTS: usize = 4096;
const REPLAY_FINGERPRINT_WINDOW_SECS: u64 = 5 * 60;
const REPLAY_FINGERPRINT_WINDOW: Duration = Duration::from_secs(REPLAY_FINGERPRINT_WINDOW_SECS);
const MAX_QKEY_TTL_SECS: u64 = 60 * 60 * 24 * 365 * 10; // 10 years
const ADMIN_CSP: &str = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'";

#[derive(Clone, Debug)]
struct AdminHttpEnvironment {
    trust_proxy: bool,
    trusted_proxy_ips: Vec<std::net::IpAddr>,
    admin_shutdown_enabled: bool,
}

impl AdminHttpEnvironment {
    fn from_snapshot(environment: &crate::env_utils::EnvSnapshot) -> Self {
        let trusted_proxy_ips = environment
            .first(["QUICFUSCATE_TRUSTED_PROXY_IPS"])
            .map(|raw| {
                let mut invalid = false;
                let ips = raw
                    .split(',')
                    .map(str::trim)
                    .map(|value| {
                        if value.is_empty() {
                            invalid = true;
                            None
                        } else {
                            match value.parse::<std::net::IpAddr>() {
                                Ok(ip) => Some(ip),
                                Err(_) => {
                                    invalid = true;
                                    None
                                }
                            }
                        }
                    })
                    .collect::<Option<Vec<_>>>();
                if invalid || ips.is_none() {
                    log::warn!(
                        "QUICFUSCATE_TRUSTED_PROXY_IPS contains an empty or malformed IP; ignoring the complete proxy allowlist"
                    );
                    Vec::new()
                } else {
                    ips.unwrap_or_default()
                }
            })
            .unwrap_or_default();
        Self {
            trust_proxy: environment.flag("QUICFUSCATE_TRUST_PROXY", false),
            trusted_proxy_ips,
            admin_shutdown_enabled: environment.flag("QUICFUSCATE_ENABLE_ADMIN_SHUTDOWN", false),
        }
    }
}

fn shared_session_store(ttl: Duration, clock: &ProtocolClock) -> Arc<Mutex<SessionStore>> {
    Arc::new(Mutex::new(SessionStore::new_with_clock(ttl, clock)))
}

fn shared_login_rate_limiter(
    max_attempts: u32,
    window_secs: u64,
    clock: &ProtocolClock,
) -> Arc<Mutex<LoginRateLimiter>> {
    Arc::new(Mutex::new(LoginRateLimiter::new_with_clock(max_attempts, window_secs, clock)))
}

#[derive(Clone, Debug)]
pub struct AdminAuth {
    user: String,
    password_phc: String,
    requires_password_change: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAuthError {
    EmptyUsername,
    PasswordHash(String),
    InvalidVerifier(String),
}

impl Display for AdminAuthError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyUsername => formatter.write_str("admin username must not be empty"),
            Self::PasswordHash(error) => {
                write!(formatter, "admin password hashing failed: {error}")
            }
            Self::InvalidVerifier(error) => {
                write!(formatter, "admin password verifier is invalid: {error}")
            }
        }
    }
}

impl Error for AdminAuthError {}

impl AdminAuth {
    pub fn new(
        user: String,
        password: String,
        requires_password_change: bool,
    ) -> Result<Self, AdminAuthError> {
        Self::new_with_hasher(user, password, requires_password_change, hash_password)
    }

    fn new_with_hasher(
        user: String,
        password: String,
        requires_password_change: bool,
        hasher: impl FnOnce(&str) -> Result<String, String>,
    ) -> Result<Self, AdminAuthError> {
        let password_phc = hasher(&password).map_err(AdminAuthError::PasswordHash)?;
        Self::from_parts(user, password_phc, requires_password_change)
    }

    fn from_parts(
        user: String,
        password_phc: String,
        requires_password_change: bool,
    ) -> Result<Self, AdminAuthError> {
        if user.trim().is_empty() {
            return Err(AdminAuthError::EmptyUsername);
        }
        PasswordHash::new(&password_phc)
            .map_err(|error| AdminAuthError::InvalidVerifier(error.to_string()))?;
        Ok(Self { user, password_phc, requires_password_change })
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        if self.user != user {
            return false;
        }
        verify_password(&self.password_phc, password)
    }

    fn user(&self) -> &str {
        self.user.as_str()
    }

    fn requires_password_change(&self) -> bool {
        self.requires_password_change
    }

    fn verify_password_only(&self, password: &str) -> bool {
        verify_password(&self.password_phc, password)
    }

    fn candidate_with_credentials(
        &self,
        new_user: String,
        new_password: &str,
    ) -> Result<Self, AdminAuthError> {
        let password_phc = hash_password(new_password).map_err(AdminAuthError::PasswordHash)?;
        Self::from_parts(new_user, password_phc, false)
    }

    fn candidate_with_username(&self, new_user: String) -> Self {
        Self { user: new_user, ..self.clone() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdminAuthFile {
    user: String,
    password_phc: String,
    #[serde(default)]
    requires_password_change: bool,
    #[serde(default)]
    updated_at: u64,
}

fn load_auth_file(path: &Path) -> std::io::Result<Option<AdminAuth>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let file: AdminAuthFile = serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("admin auth file {} is not valid JSON: {error}", path.display()),
        )
    })?;
    AdminAuth::from_parts(file.user, file.password_phc, file.requires_password_change)
        .map(Some)
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("admin auth file {} is invalid: {error}", path.display()),
            )
        })
}

fn persist_auth_file(path: &Path, auth: &AdminAuth) -> std::io::Result<()> {
    persist_auth_file_with_clock(path, auth, &ProtocolClock::default())
}

fn persist_auth_file_with_clock(
    path: &Path,
    auth: &AdminAuth,
    clock: &ProtocolClock,
) -> std::io::Result<()> {
    let updated_at =
        crate::time_source::unix_epoch_seconds(clock.now_system()).map_err(|error| {
            std::io::Error::other(format!("admin auth wall-clock timestamp unavailable: {error}"))
        })?;
    let payload = AdminAuthFile {
        user: auth.user.clone(),
        password_phc: auth.password_phc.clone(),
        requires_password_change: auth.requires_password_change,
        updated_at,
    };
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("admin auth serialization failed: {error}"),
        )
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    super::super::fsutil::atomic_write_file(
        path,
        &bytes,
        Some(0o600),
        "admin_http::auth_write_tmp_nonce",
    )
}

/// Re-export from the canonical shared utility in `crate::rng`.
#[inline(always)]
fn push_hex_byte(out: &mut String, byte: u8) {
    crate::rng::push_hex_byte(out, byte);
}

struct LoginRateLimiter {
    attempts: HashMap<String, (u32, Instant)>,
    lru_keys: VecDeque<String>,
    max_attempts: u32,
    lockout: Duration,
    clock: ProtocolClock,
}

impl LoginRateLimiter {
    #[allow(dead_code)]
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self::new_with_clock(max_attempts, lockout_secs, &ProtocolClock::default())
    }

    fn new_with_clock(max_attempts: u32, lockout_secs: u64, clock: &ProtocolClock) -> Self {
        Self {
            attempts: HashMap::new(),
            lru_keys: VecDeque::new(),
            max_attempts,
            lockout: Duration::from_secs(lockout_secs),
            clock: clock.clone(),
        }
    }

    fn is_locked(&mut self, ip: &str) -> bool {
        self.prune();
        if let Some((count, _)) = self.attempts.get(ip) {
            *count >= self.max_attempts
        } else {
            false
        }
    }

    fn record_attempt(&mut self, ip: &str) {
        let now = self.clock.now();
        if let Some(entry) = self.attempts.get_mut(ip) {
            entry.0 = entry.0.saturating_add(1);
            entry.1 = now;
            self.touch(ip);
        } else {
            self.attempts.insert(ip.to_string(), (1, now));
            self.lru_keys.push_back(ip.to_string());
            self.evict_excess();
        }
    }

    fn clear(&mut self, ip: &str) {
        self.attempts.remove(ip);
        self.remove_from_lru(ip);
    }

    fn prune(&mut self) {
        let cutoff = self.lockout;
        let clock = self.clock.clone();
        self.attempts.retain(|_, (_, ts)| clock.elapsed_since(*ts) < cutoff);
        self.lru_keys.retain(|ip| self.attempts.contains_key(ip));
    }

    fn touch(&mut self, ip: &str) {
        if let Some(index) = self.lru_keys.iter().position(|key| key == ip) {
            if let Some(key) = self.lru_keys.remove(index) {
                self.lru_keys.push_back(key);
            }
        }
    }

    fn remove_from_lru(&mut self, ip: &str) {
        if let Some(index) = self.lru_keys.iter().position(|key| key == ip) {
            self.lru_keys.remove(index);
        }
    }

    fn evict_excess(&mut self) {
        while self.attempts.len() > MAX_LOGIN_RATE_LIMIT_KEYS {
            let Some(oldest) = self.lru_keys.pop_front() else {
                break;
            };
            self.attempts.remove(&oldest);
        }
    }

    fn retry_after_secs(&mut self, ip: &str) -> Option<u64> {
        self.prune();
        let (count, last) = self.attempts.get(ip)?;
        if *count < self.max_attempts {
            return None;
        }
        let elapsed = self.clock.elapsed_since(*last);
        let rem = self.lockout.checked_sub(elapsed).unwrap_or_else(|| Duration::from_secs(0));
        Some(rem.as_secs().max(1))
    }
}

struct SessionStore {
    sessions: HashMap<String, SessionRecord>,
    ttl: Duration,
    max_sessions: usize,
    created_total: u64,
    capacity_rejected_total: u64,
    expired_total: u64,
    clock: ProtocolClock,
}

#[derive(Debug)]
struct SessionRecord {
    expires_at: Instant,
    csrf_token: String,
    replay_fingerprints: VecDeque<ReplayFingerprint>,
    replay_fingerprint_set: HashSet<u64>,
}

#[derive(Clone, Copy, Debug)]
struct ReplayFingerprint {
    fingerprint: u64,
    seen_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionCreateError {
    Capacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AdminHttpSessionSnapshot {
    /// Maximum number of live sessions admitted by the store.
    pub max_sessions: usize,
    /// Current live session count after expiry pruning.
    pub active_sessions: usize,
    /// Successful session creations since store initialization.
    pub created_total: u64,
    /// Login attempts rejected because the live-session cap was full.
    pub capacity_rejected_total: u64,
    /// Sessions removed by expiry pruning.
    pub expired_total: u64,
}

impl SessionRecord {
    fn prune_replay_fingerprints(&mut self, now: Instant) {
        loop {
            let should_expire = self.replay_fingerprints.front().is_some_and(|entry| {
                now.checked_duration_since(entry.seen_at)
                    .is_some_and(|age| age >= REPLAY_FINGERPRINT_WINDOW)
            });
            if !should_expire {
                break;
            }
            let Some(expired) = self.replay_fingerprints.pop_front() else {
                break;
            };
            self.replay_fingerprint_set.remove(&expired.fingerprint);
        }
    }
}

impl SessionStore {
    #[allow(dead_code)]
    fn new(ttl: Duration) -> Self {
        Self::new_with_clock(ttl, &ProtocolClock::default())
    }

    fn new_with_clock(ttl: Duration, clock: &ProtocolClock) -> Self {
        Self::new_with_capacity_and_clock(ttl, DEFAULT_ADMIN_WEB_MAX_SESSIONS, clock)
    }

    #[allow(dead_code)]
    fn new_with_capacity(ttl: Duration, max_sessions: usize) -> Self {
        Self::new_with_capacity_and_clock(ttl, max_sessions, &ProtocolClock::default())
    }

    fn new_with_capacity_and_clock(
        ttl: Duration,
        max_sessions: usize,
        clock: &ProtocolClock,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
            max_sessions,
            created_total: 0,
            capacity_rejected_total: 0,
            expired_total: 0,
            clock: clock.clone(),
        }
    }

    fn create(&mut self) -> Result<(String, String), SessionCreateError> {
        self.prune();
        if self.sessions.len() >= self.max_sessions {
            self.capacity_rejected_total = self.capacity_rejected_total.saturating_add(1);
            return Err(SessionCreateError::Capacity);
        }
        let mut buf = [0u8; 32];
        crate::rng::fill_secure_or_abort(&mut buf, "admin_http::session_id");
        let id = URL_SAFE_NO_PAD.encode(buf);

        let mut token = [0u8; CSRF_TOKEN_BYTES];
        crate::rng::fill_secure_or_abort(&mut token, "admin_http::session_csrf_token");
        let mut csrf_token = String::with_capacity(token.len() * 2);
        for b in token {
            push_hex_byte(&mut csrf_token, b);
        }

        let now = self.clock.now();
        let expires_at = now.checked_add(self.ttl).unwrap_or(now);
        self.sessions.insert(
            id.clone(),
            SessionRecord {
                expires_at,
                csrf_token: csrf_token.clone(),
                replay_fingerprints: VecDeque::new(),
                replay_fingerprint_set: HashSet::new(),
            },
        );
        self.created_total = self.created_total.saturating_add(1);
        Ok((id, csrf_token))
    }

    fn is_valid(&mut self, id: &str) -> bool {
        self.prune();
        let now = self.clock.now();
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at > now {
                record.expires_at = now.checked_add(self.ttl).unwrap_or(now);
                return true;
            }
        }
        false
    }

    fn csrf_token(&mut self, id: &str) -> Option<String> {
        self.prune();
        let now = self.clock.now();
        let record = self.sessions.get_mut(id)?;
        if record.expires_at <= now {
            return None;
        }
        record.expires_at = now.checked_add(self.ttl).unwrap_or(now);
        Some(record.csrf_token.clone())
    }

    fn validate_post_guard(
        &mut self,
        id: &str,
        csrf_token: &str,
        replay_fingerprint: u64,
        enforce_replay_guard: bool,
    ) -> Result<(), &'static str> {
        self.validate_post_guard_at(
            id,
            csrf_token,
            replay_fingerprint,
            enforce_replay_guard,
            self.clock.now(),
        )
    }

    fn validate_post_guard_at(
        &mut self,
        id: &str,
        csrf_token: &str,
        replay_fingerprint: u64,
        enforce_replay_guard: bool,
        now: Instant,
    ) -> Result<(), &'static str> {
        self.prune_at(now);
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at <= now {
                return Err("Invalid CSRF token");
            }
            if !constant_time_token_eq(&record.csrf_token, csrf_token) {
                return Err("Invalid CSRF token");
            }
            if enforce_replay_guard {
                if !record.replay_fingerprint_set.insert(replay_fingerprint) {
                    return Err("Replay request detected");
                }
                record
                    .replay_fingerprints
                    .push_back(ReplayFingerprint { fingerprint: replay_fingerprint, seen_at: now });
                if record.replay_fingerprints.len() > MAX_REPLAY_FINGERPRINTS {
                    if let Some(evicted) = record.replay_fingerprints.pop_front() {
                        record.replay_fingerprint_set.remove(&evicted.fingerprint);
                    }
                }
            }
            record.expires_at = now.checked_add(self.ttl).unwrap_or(now);
            return Ok(());
        }
        Err("Invalid CSRF token")
    }

    fn remove(&mut self, id: &str) {
        self.sessions.remove(id);
    }

    fn clear_all(&mut self) {
        self.sessions.clear();
    }

    fn snapshot(&mut self) -> AdminHttpSessionSnapshot {
        self.prune();
        AdminHttpSessionSnapshot {
            max_sessions: self.max_sessions,
            active_sessions: self.sessions.len(),
            created_total: self.created_total,
            capacity_rejected_total: self.capacity_rejected_total,
            expired_total: self.expired_total,
        }
    }

    fn prune(&mut self) {
        self.prune_at(self.clock.now());
    }

    fn prune_at(&mut self, now: Instant) {
        let mut expired_count = 0_u64;
        self.sessions.retain(|_, record| {
            if record.expires_at <= now {
                expired_count = expired_count.saturating_add(1);
                false
            } else {
                record.prune_replay_fingerprints(now);
                true
            }
        });
        self.expired_total = self.expired_total.saturating_add(expired_count);
    }
}

/// HTTP admin handler interface.
pub trait AdminHttpHandler: Send + Sync {
    fn handle_status(&self) -> AdminResponse;
    fn handle_health(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({ "status": "ok" }))
    }
    fn handle_list_clients(&self) -> Vec<ClientInfo>;
    fn handle_get_client_bandwidth(&self, id: &str) -> AdminResponse;
    fn handle_set_client_bandwidth(&self, id: &str, policy: BandwidthPolicy) -> AdminResponse;
    fn handle_reset_client_quota(&self, id: &str) -> AdminResponse;
    fn handle_kick(&self, id: &str) -> AdminResponse;
    fn handle_block(&self, ip: &str) -> AdminResponse;
    fn handle_unblock(&self, ip: &str) -> AdminResponse;
    fn handle_list_blocked_ips(&self) -> AdminResponse;
    fn handle_reload(&self) -> AdminResponse;
    fn handle_drain(&self) -> AdminResponse;
    fn handle_drain_status(&self) -> AdminResponse;
    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse;
    fn handle_list_qkeys(&self) -> AdminResponse;
    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse;
    fn handle_shutdown(&self) -> AdminResponse;
    fn handle_read_config(&self) -> AdminResponse;
    fn handle_write_config(&self, contents: &str) -> AdminResponse;
    fn handle_metrics_text(&self) -> String;
    fn handle_metrics_json(&self) -> AdminResponse;
    fn handle_get_logging_config(&self) -> AdminResponse;
    fn handle_set_logging_config(&self, mode: &str) -> AdminResponse;
    fn handle_get_logs(&self, cursor: u64) -> AdminResponse;
    fn handle_clear_logs(&self) -> AdminResponse;
    fn handle_rotate_logs(&self) -> AdminResponse {
        AdminResponse::error("Log rotation unavailable")
    }
}

/// Default maximum number of concurrent admin HTTP connections.
/// Limits memory pressure and mitigates connection-exhaustion DoS.
pub const DEFAULT_ADMIN_WEB_MAX_CONNECTIONS: usize = 16;

/// Maximum number of live authenticated admin sessions retained by one server.
pub const DEFAULT_ADMIN_WEB_MAX_SESSIONS: usize = 256;

/// Hard upper bound for the CLI-configured admin HTTP connection capacity.
pub const MAX_ADMIN_WEB_CONNECTIONS: usize = 1024;

/// Default deadline for one admin HTTP request operation.
pub const DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS: u64 = 30_000;

/// Smallest accepted admin HTTP operation deadline.
pub const MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS: u64 = 50;

/// Largest accepted admin HTTP operation deadline.
pub const MAX_ADMIN_WEB_OPERATION_TIMEOUT_MS: u64 = 120_000;

const ADMIN_HTTP_RESPONSE_GRACE: Duration = Duration::from_secs(1);
const ADMIN_HTTP_OPERATION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Validate the standalone admin-web connection capacity before any listener or
/// authentication state is published.
pub fn validate_admin_web_max_connections(max_connections: usize) -> std::io::Result<usize> {
    if max_connections == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "admin web max connections must be at least 1",
        ));
    }
    if max_connections > MAX_ADMIN_WEB_CONNECTIONS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("admin web max connections must not exceed {}", MAX_ADMIN_WEB_CONNECTIONS),
        ));
    }
    Ok(max_connections)
}

/// Validate the bounded deadline applied to body collection and one synchronous
/// admin operation.
pub fn validate_admin_web_operation_timeout_ms(timeout_ms: u64) -> std::io::Result<Duration> {
    if timeout_ms < MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "admin web operation timeout must be at least {} ms",
                MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS
            ),
        ));
    }
    if timeout_ms > MAX_ADMIN_WEB_OPERATION_TIMEOUT_MS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "admin web operation timeout must not exceed {} ms",
                MAX_ADMIN_WEB_OPERATION_TIMEOUT_MS
            ),
        ));
    }
    Ok(Duration::from_millis(timeout_ms))
}

/// Observable operation deadline and worker lifecycle state for one admin-web
/// server lifetime.
#[derive(Clone, Debug, Serialize)]
pub struct AdminHttpOperationSnapshot {
    /// Effective configured operation deadline in milliseconds.
    pub timeout_ms: u64,
    /// Operations whose owner has not reached a terminal state.
    pub active_operations: usize,
    /// Operations admitted to the worker protocol.
    pub started_total: u64,
    /// Operations that produced a worker or direct result before/after the deadline.
    pub completed_total: u64,
    /// Operations whose deadline was observed before terminal completion.
    pub timeout_total: u64,
    /// Operations abandoned before a worker result was delivered.
    pub cancelled_total: u64,
    /// Worker operations that panicked and were converted to HTTP 500.
    pub panic_total: u64,
    /// Worker/direct results that completed after the effective deadline.
    pub completed_after_deadline_total: u64,
    /// Shutdown drains that exceeded the bounded worker wait.
    pub shutdown_expired_total: u64,
}

/// Shared diagnostics for the owned admin HTTP operation protocol.
pub struct AdminHttpOperationDiagnostics {
    timeout_ms: u64,
    active_operations: std::sync::atomic::AtomicUsize,
    started_total: AtomicU64,
    completed_total: AtomicU64,
    timeout_total: AtomicU64,
    cancelled_total: AtomicU64,
    panic_total: AtomicU64,
    completed_after_deadline_total: AtomicU64,
    shutdown_expired_total: AtomicU64,
}

impl AdminHttpOperationDiagnostics {
    pub fn new(timeout_ms: u64) -> std::io::Result<Arc<Self>> {
        validate_admin_web_operation_timeout_ms(timeout_ms)?;
        Ok(Arc::new(Self {
            timeout_ms,
            active_operations: std::sync::atomic::AtomicUsize::new(0),
            started_total: AtomicU64::new(0),
            completed_total: AtomicU64::new(0),
            timeout_total: AtomicU64::new(0),
            cancelled_total: AtomicU64::new(0),
            panic_total: AtomicU64::new(0),
            completed_after_deadline_total: AtomicU64::new(0),
            shutdown_expired_total: AtomicU64::new(0),
        }))
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn snapshot(&self) -> AdminHttpOperationSnapshot {
        AdminHttpOperationSnapshot {
            timeout_ms: self.timeout_ms,
            active_operations: self.active_operations.load(Ordering::Relaxed),
            started_total: self.started_total.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
            timeout_total: self.timeout_total.load(Ordering::Relaxed),
            cancelled_total: self.cancelled_total.load(Ordering::Relaxed),
            panic_total: self.panic_total.load(Ordering::Relaxed),
            completed_after_deadline_total: self
                .completed_after_deadline_total
                .load(Ordering::Relaxed),
            shutdown_expired_total: self.shutdown_expired_total.load(Ordering::Relaxed),
        }
    }

    fn begin(self: &Arc<Self>, deadline: tokio::time::Instant) -> Arc<AdminHttpOperationState> {
        self.active_operations.fetch_add(1, Ordering::Relaxed);
        self.started_total.fetch_add(1, Ordering::Relaxed);
        Arc::new(AdminHttpOperationState {
            deadline,
            diagnostics: Arc::clone(self),
            timed_out: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        })
    }

    fn record_timeout(&self) {
        self.timeout_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_cancelled(&self) {
        self.cancelled_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_completed(&self) {
        self.completed_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_panic(&self) {
        self.panic_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_completed_after_deadline(&self) {
        self.completed_after_deadline_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_shutdown_expired(&self) {
        self.shutdown_expired_total.fetch_add(1, Ordering::Relaxed);
    }
}

struct AdminHttpOperationState {
    deadline: tokio::time::Instant,
    diagnostics: Arc<AdminHttpOperationDiagnostics>,
    timed_out: AtomicBool,
    finished: AtomicBool,
}

impl AdminHttpOperationState {
    fn mark_timeout(&self) {
        if self.finished.load(Ordering::Acquire) {
            return;
        }
        if !self.timed_out.swap(true, Ordering::AcqRel) {
            self.diagnostics.record_timeout();
        }
    }

    fn mark_late_completion(&self) -> bool {
        if tokio::time::Instant::now() >= self.deadline {
            if !self.timed_out.swap(true, Ordering::AcqRel) {
                self.diagnostics.record_timeout();
            }
            return true;
        }
        self.timed_out.load(Ordering::Acquire)
    }

    fn finish_direct(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if self.mark_late_completion() {
            self.diagnostics.record_completed_after_deadline();
        }
        self.diagnostics.record_completed();
        self.diagnostics.active_operations.fetch_sub(1, Ordering::Relaxed);
    }

    fn finish_timeout_without_worker(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.diagnostics.active_operations.fetch_sub(1, Ordering::Relaxed);
    }

    fn finish_cancelled(&self) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        self.diagnostics.record_cancelled();
        self.diagnostics.active_operations.fetch_sub(1, Ordering::Relaxed);
    }

    fn finish_worker(&self, panicked: bool) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        if panicked {
            self.diagnostics.record_panic();
        }
        if self.mark_late_completion() {
            self.diagnostics.record_completed_after_deadline();
        }
        self.diagnostics.record_completed();
        self.diagnostics.active_operations.fetch_sub(1, Ordering::Relaxed);
    }

    fn record_abandoned_result(&self) {
        if !self.timed_out.load(Ordering::Acquire) {
            self.diagnostics.record_cancelled();
        }
    }
}

impl Drop for AdminHttpOperationState {
    fn drop(&mut self) {
        if !self.finished.swap(true, Ordering::AcqRel) {
            if !self.timed_out.load(Ordering::Acquire) {
                self.diagnostics.record_cancelled();
            }
            self.diagnostics.active_operations.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

type AdminHttpOperationWork = Box<dyn FnOnce() -> Response<Full<Bytes>> + Send + 'static>;

struct AdminHttpOperationCommand {
    work: AdminHttpOperationWork,
    response_tx: oneshot::Sender<Response<Full<Bytes>>>,
    state: Arc<AdminHttpOperationState>,
}

fn run_admin_http_operation(command: AdminHttpOperationCommand) {
    let AdminHttpOperationCommand { work, response_tx, state } = command;
    let result = catch_unwind(AssertUnwindSafe(work));
    let panicked = result.is_err();
    let response = result.unwrap_or_else(|_| text_response(500, "Internal Server Error"));
    state.finish_worker(panicked);
    if response_tx.send(response).is_err() {
        state.record_abandoned_result();
    }
}

fn log_operation_task_result(result: Result<(), JoinError>) {
    let Err(error) = result else {
        return;
    };
    if error.is_cancelled() {
        log::debug!("admin web operation worker cancelled during shutdown");
    } else if error.is_panic() {
        log::error!("admin web operation worker panicked: {}", error);
    } else {
        log::warn!("admin web operation worker failed to join: {}", error);
    }
}

/// Observable admission counters for one admin-web server lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminHttpAdmissionSnapshot {
    /// Configured active-connection capacity.
    pub max_connections: usize,
    /// Currently running connection tasks holding an admission permit.
    pub active_connections: usize,
    /// User-space pending connection tasks. This is always zero because excess
    /// sockets are rejected before spawning and no pending queue is retained.
    pub pending_connections: usize,
    /// Total connections admitted before task creation.
    pub admitted_total: u64,
    /// Total accepted sockets rejected before task creation because capacity was full.
    pub rejected_total: u64,
    /// Total admitted connection tasks that completed or were cancelled and joined.
    pub completed_total: u64,
}

struct AdminHttpAdmissionState {
    max_connections: usize,
    active_connections: std::sync::atomic::AtomicUsize,
    admitted_total: std::sync::atomic::AtomicU64,
    rejected_total: std::sync::atomic::AtomicU64,
    completed_total: std::sync::atomic::AtomicU64,
}

impl AdminHttpAdmissionState {
    fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            active_connections: std::sync::atomic::AtomicUsize::new(0),
            admitted_total: std::sync::atomic::AtomicU64::new(0),
            rejected_total: std::sync::atomic::AtomicU64::new(0),
            completed_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn record_admitted(self: &Arc<Self>) -> AdminHttpAdmissionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.admitted_total.fetch_add(1, Ordering::Relaxed);
        AdminHttpAdmissionGuard { state: Arc::clone(self) }
    }

    fn record_rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }

    fn record_completed(&self) {
        self.completed_total.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> AdminHttpAdmissionSnapshot {
        AdminHttpAdmissionSnapshot {
            max_connections: self.max_connections,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            pending_connections: 0,
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            rejected_total: self.rejected_total.load(Ordering::Relaxed),
            completed_total: self.completed_total.load(Ordering::Relaxed),
        }
    }
}

struct AdminHttpAdmissionGuard {
    state: Arc<AdminHttpAdmissionState>,
}

impl Drop for AdminHttpAdmissionGuard {
    fn drop(&mut self) {
        self.state.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn log_connection_task_result(result: Result<(), JoinError>) {
    let Err(error) = result else {
        return;
    };
    if error.is_cancelled() {
        log::debug!("admin web connection task cancelled during shutdown");
    } else if error.is_panic() {
        log::error!("admin web connection task panicked: {}", error);
    } else {
        log::warn!("admin web connection task failed to join: {}", error);
    }
}

/// HTTP admin server.
pub struct AdminHttpServer {
    addr: SocketAddr,
    web_root: PathBuf,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    handler: Arc<dyn AdminHttpHandler>,
    shutdown: Arc<AtomicBool>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    conn_semaphore: Arc<tokio::sync::Semaphore>,
    admission: Arc<AdminHttpAdmissionState>,
    operation_tx: mpsc::Sender<AdminHttpOperationCommand>,
    operation_receiver: std::sync::Mutex<Option<mpsc::Receiver<AdminHttpOperationCommand>>>,
    operation_timeout: Duration,
    operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
    environment: Arc<AdminHttpEnvironment>,
}

impl AdminHttpServer {
    pub fn new(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
    ) -> std::io::Result<Self> {
        Self::new_with_max_connections(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            DEFAULT_ADMIN_WEB_MAX_CONNECTIONS,
        )
    }

    pub fn new_with_max_connections(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
    ) -> std::io::Result<Self> {
        Self::new_with_max_connections_and_operation_timeout(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            max_connections,
            DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS,
        )
    }

    pub fn new_with_max_connections_and_operation_timeout(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
        operation_timeout_ms: u64,
    ) -> std::io::Result<Self> {
        let operation_timeout = validate_admin_web_operation_timeout_ms(operation_timeout_ms)?;
        let operation_diagnostics = AdminHttpOperationDiagnostics::new(operation_timeout_ms)?;
        Self::new_with_operation_timeout_and_diagnostics(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            max_connections,
            operation_timeout,
            operation_diagnostics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(crate) fn new_with_max_connections_and_operation_timeout_and_diagnostics(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
        operation_timeout_ms: u64,
        operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
    ) -> std::io::Result<Self> {
        Self::new_with_max_connections_and_operation_timeout_and_diagnostics_and_clock(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            max_connections,
            operation_timeout_ms,
            operation_diagnostics,
            ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_max_connections_and_operation_timeout_and_diagnostics_and_clock(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
        operation_timeout_ms: u64,
        operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let operation_timeout = validate_admin_web_operation_timeout_ms(operation_timeout_ms)?;
        if operation_diagnostics.timeout_ms() != operation_timeout_ms {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "admin web operation diagnostics timeout does not match server timeout",
            ));
        }
        Self::new_with_operation_timeout_and_diagnostics_and_clock(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            max_connections,
            operation_timeout,
            operation_diagnostics,
            clock,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_operation_timeout_and_diagnostics(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
        operation_timeout: Duration,
        operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
    ) -> std::io::Result<Self> {
        Self::new_with_operation_timeout_and_diagnostics_and_clock(
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            max_connections,
            operation_timeout,
            operation_diagnostics,
            ProtocolClock::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_operation_timeout_and_diagnostics_and_clock(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
        max_connections: usize,
        operation_timeout: Duration,
        operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
        clock: ProtocolClock,
    ) -> std::io::Result<Self> {
        let max_connections = validate_admin_web_max_connections(max_connections)?;
        let mut loaded_from_disk = false;
        let auth_loaded = if let Some(path) = auth_path.as_ref() {
            match load_auth_file(path.as_path())? {
                Some(auth) => {
                    loaded_from_disk = true;
                    Some(auth)
                }
                None => None,
            }
        } else {
            None
        };
        let auth = auth_loaded.or(auth);
        if auth_path.is_some() && auth.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "admin auth path requires an authentication credential",
            ));
        }
        let auth = auth.map(|a| Arc::new(RwLock::new(a)));
        if !loaded_from_disk {
            if let (Some(path), Some(auth_ref)) = (auth_path.as_ref(), auth.as_ref()) {
                let guard = auth_ref.read();
                persist_auth_file(path, &guard)?;
            }
        }
        let (operation_tx, operation_receiver) = mpsc::channel(max_connections);
        let environment = Arc::new(AdminHttpEnvironment::from_snapshot(
            &crate::env_utils::EnvSnapshot::capture(),
        ));
        Ok(Self {
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            shutdown: Arc::new(AtomicBool::new(false)),
            sessions: shared_session_store(Duration::from_secs(SESSION_TTL_SECS), &clock),
            rate_limiter: shared_login_rate_limiter(
                LOGIN_RATE_LIMIT_ATTEMPTS,
                LOGIN_RATE_LIMIT_WINDOW_SECS,
                &clock,
            ),
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(max_connections)),
            admission: Arc::new(AdminHttpAdmissionState::new(max_connections)),
            operation_tx,
            operation_receiver: std::sync::Mutex::new(Some(operation_receiver)),
            operation_timeout,
            operation_diagnostics,
            environment,
        })
    }

    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn admission_snapshot(&self) -> AdminHttpAdmissionSnapshot {
        self.admission.snapshot()
    }

    pub fn session_snapshot(&self) -> AdminHttpSessionSnapshot {
        self.sessions.lock().snapshot()
    }

    pub fn operation_diagnostics(&self) -> Arc<AdminHttpOperationDiagnostics> {
        Arc::clone(&self.operation_diagnostics)
    }

    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("admin web server listening on http://{}", self.addr);
        let mut connection_tasks = JoinSet::new();
        let mut operation_receiver = self
            .operation_receiver
            .lock()
            .map_err(|_| std::io::Error::other("admin web operation receiver lock poisoned"))?
            .take()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "admin web server run called more than once",
                )
            })?;
        let mut operation_tasks = JoinSet::new();

        loop {
            while let Some(result) = connection_tasks.try_join_next() {
                self.admission.record_completed();
                log_connection_task_result(result);
            }
            while let Some(result) = operation_tasks.try_join_next() {
                log_operation_task_result(result);
            }
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                Some(command) = operation_receiver.recv() => {
                    operation_tasks.spawn_blocking(move || run_admin_http_operation(command));
                }
                accepted = tokio::time::timeout(Duration::from_millis(100), listener.accept()) => {
                    let (stream, peer_addr) = match accepted {
                        Ok(Ok(conn)) => conn,
                        Ok(Err(e)) => {
                            log::warn!("admin web accept error: {}", e);
                            continue;
                        }
                        Err(_) => continue,
                    };
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let permit = match self.conn_semaphore.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.admission.record_rejected();
                            log::debug!(
                                "admin web connection rejected at capacity {}",
                                self.admission.max_connections
                            );
                            continue;
                        }
                    };
                    if self.shutdown.load(Ordering::Relaxed) {
                        drop(permit);
                        break;
                    }
                    let handler = self.handler.clone();
                    let web_root = self.web_root.clone();
                    let auth = self.auth.clone();
                    let auth_path = self.auth_path.clone();
                    let shutdown = self.shutdown.clone();
                    let sessions = self.sessions.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let operation_tx = self.operation_tx.clone();
                    let operation_diagnostics = self.operation_diagnostics.clone();
                    let operation_timeout = self.operation_timeout;
                    let environment = self.environment.clone();
                    let admission_guard = self.admission.record_admitted();
                    let peer = Some(peer_addr);
                    connection_tasks.spawn(async move {
                        let _admission_guard = admission_guard;
                        if shutdown.load(Ordering::Relaxed) {
                            return;
                        }
                        let connection_deadline =
                            tokio::time::Instant::now() + operation_timeout;
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let web_root = web_root.clone();
                            let auth = auth.clone();
                            let auth_path = auth_path.clone();
                            let sessions = sessions.clone();
                            let rate_limiter = rate_limiter.clone();
                            let handler = handler.clone();
                            let operation_tx = operation_tx.clone();
                            let operation_diagnostics = operation_diagnostics.clone();
                            let environment = environment.clone();
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    handle_request_with_deadline(
                                        req,
                                        web_root,
                                        auth,
                                        auth_path,
                                        sessions,
                                        rate_limiter,
                                        handler,
                                        peer,
                                        operation_tx,
                                        operation_diagnostics,
                                        environment,
                                        connection_deadline,
                                    )
                                    .await,
                                )
                            }
                        });
                        let conn = http1::Builder::new()
                            .max_buf_size(MAX_HEADER_BYTES)
                            .keep_alive(false)
                            .serve_connection(io, svc);
                        let connection_timeout = operation_timeout + ADMIN_HTTP_RESPONSE_GRACE;
                        match tokio::time::timeout(connection_timeout, conn).await {
                            Ok(Err(e)) => {
                                log::debug!("admin web connection error: {}", e);
                            }
                            Err(_elapsed) => {
                                log::debug!(
                                    "admin web connection exceeded operation deadline plus response grace: {} ms",
                                    operation_timeout.as_millis()
                                );
                            }
                            Ok(Ok(())) => {}
                        }
                        drop(permit);
                    });
                }
            }
        }

        connection_tasks.abort_all();
        while let Some(result) = connection_tasks.join_next().await {
            self.admission.record_completed();
            log_connection_task_result(result);
        }
        operation_tasks.abort_all();
        let drain = tokio::time::timeout(ADMIN_HTTP_OPERATION_SHUTDOWN_TIMEOUT, async {
            while let Some(result) = operation_tasks.join_next().await {
                log_operation_task_result(result);
            }
        })
        .await;
        if drain.is_err() {
            self.operation_diagnostics.record_shutdown_expired();
            log::warn!(
                "admin web operation shutdown drain exceeded {} ms; started blocking workers may still finish",
                ADMIN_HTTP_OPERATION_SHUTDOWN_TIMEOUT.as_millis()
            );
        }
        self.sessions.lock().clear_all();
        Ok(())
    }
}

mod request;
pub use request::IssueQKeyRequest;
pub(super) use request::*;

#[cfg(test)]
mod tests;
