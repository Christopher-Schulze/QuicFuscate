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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use parking_lot::{Mutex, RwLock};
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};

use super::admin::{AdminResponse, ClientInfo};
use super::BandwidthPolicy;

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
const MAX_QKEY_TTL_SECS: u64 = 60 * 60 * 24 * 365 * 10; // 10 years
const ADMIN_CSP: &str = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'";

fn shared_session_store(ttl: Duration) -> Arc<Mutex<SessionStore>> {
    Arc::new(Mutex::new(SessionStore::new(ttl)))
}

fn shared_login_rate_limiter(max_attempts: u32, window_secs: u64) -> Arc<Mutex<LoginRateLimiter>> {
    Arc::new(Mutex::new(LoginRateLimiter::new(max_attempts, window_secs)))
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
            Self::PasswordHash(error) => write!(formatter, "admin password hashing failed: {error}"),
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
    let payload = AdminAuthFile {
        user: auth.user.clone(),
        password_phc: auth.password_phc.clone(),
        requires_password_change: auth.requires_password_change,
        updated_at: current_epoch_secs(),
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
    super::fsutil::atomic_write_file(
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

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

struct LoginRateLimiter {
    attempts: HashMap<String, (u32, Instant)>,
    lru_keys: VecDeque<String>,
    max_attempts: u32,
    lockout: Duration,
}

impl LoginRateLimiter {
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self {
            attempts: HashMap::new(),
            lru_keys: VecDeque::new(),
            max_attempts,
            lockout: Duration::from_secs(lockout_secs),
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
        let now = Instant::now();
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
        self.attempts.retain(|_, (_, ts)| ts.elapsed() < cutoff);
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
        let elapsed = last.elapsed();
        let rem = self.lockout.checked_sub(elapsed).unwrap_or_else(|| Duration::from_secs(0));
        Some(rem.as_secs().max(1))
    }
}

struct SessionStore {
    sessions: HashMap<String, SessionRecord>,
    ttl: Duration,
}

#[derive(Debug)]
struct SessionRecord {
    expires_at: Instant,
    csrf_token: String,
    replay_fingerprints: VecDeque<u64>,
    replay_fingerprint_set: HashSet<u64>,
}

impl SessionStore {
    fn new(ttl: Duration) -> Self {
        Self { sessions: HashMap::new(), ttl }
    }

    fn create(&mut self) -> (String, String) {
        self.prune();
        let mut buf = [0u8; 32];
        crate::rng::fill_secure_or_abort(&mut buf, "admin_http::session_id");
        let id = URL_SAFE_NO_PAD.encode(buf);

        let mut token = [0u8; CSRF_TOKEN_BYTES];
        crate::rng::fill_secure_or_abort(&mut token, "admin_http::session_csrf_token");
        let mut csrf_token = String::with_capacity(token.len() * 2);
        for b in token {
            push_hex_byte(&mut csrf_token, b);
        }

        let expires_at = Instant::now() + self.ttl;
        self.sessions.insert(
            id.clone(),
            SessionRecord {
                expires_at,
                csrf_token: csrf_token.clone(),
                replay_fingerprints: VecDeque::new(),
                replay_fingerprint_set: HashSet::new(),
            },
        );
        (id, csrf_token)
    }

    fn is_valid(&mut self, id: &str) -> bool {
        self.prune();
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at > Instant::now() {
                record.expires_at = Instant::now() + self.ttl;
                return true;
            }
        }
        false
    }

    fn csrf_token(&mut self, id: &str) -> Option<String> {
        self.prune();
        let record = self.sessions.get_mut(id)?;
        if record.expires_at <= Instant::now() {
            return None;
        }
        record.expires_at = Instant::now() + self.ttl;
        Some(record.csrf_token.clone())
    }

    fn validate_post_guard(
        &mut self,
        id: &str,
        csrf_token: &str,
        replay_fingerprint: u64,
        enforce_replay_guard: bool,
    ) -> Result<(), &'static str> {
        self.prune();
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at <= Instant::now() {
                return Err("Invalid CSRF token");
            }
            if !constant_time_token_eq(&record.csrf_token, csrf_token) {
                return Err("Invalid CSRF token");
            }
            if enforce_replay_guard {
                if !record.replay_fingerprint_set.insert(replay_fingerprint) {
                    return Err("Replay request detected");
                }
                record.replay_fingerprints.push_back(replay_fingerprint);
                if record.replay_fingerprints.len() > MAX_REPLAY_FINGERPRINTS {
                    if let Some(evicted) = record.replay_fingerprints.pop_front() {
                        record.replay_fingerprint_set.remove(&evicted);
                    }
                }
            }
            record.expires_at = Instant::now() + self.ttl;
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

    fn prune(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, record| record.expires_at > now);
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
}

/// Default maximum number of concurrent admin HTTP connections.
/// Limits memory pressure and mitigates connection-exhaustion DoS.
pub const DEFAULT_ADMIN_WEB_MAX_CONNECTIONS: usize = 16;

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
            format!(
                "admin web max connections must not exceed {}",
                MAX_ADMIN_WEB_CONNECTIONS
            ),
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
    operation_receiver:
        std::sync::Mutex<Option<mpsc::Receiver<AdminHttpOperationCommand>>>,
    operation_timeout: Duration,
    operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
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
        let operation_diagnostics =
            AdminHttpOperationDiagnostics::new(operation_timeout_ms)?;
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
        let operation_timeout = validate_admin_web_operation_timeout_ms(operation_timeout_ms)?;
        if operation_diagnostics.timeout_ms() != operation_timeout_ms {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "admin web operation diagnostics timeout does not match server timeout",
            ));
        }
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
        Ok(Self {
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            shutdown: Arc::new(AtomicBool::new(false)),
            sessions: shared_session_store(Duration::from_secs(SESSION_TTL_SECS)),
            rate_limiter: shared_login_rate_limiter(
                LOGIN_RATE_LIMIT_ATTEMPTS,
                LOGIN_RATE_LIMIT_WINDOW_SECS,
            ),
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(max_connections)),
            admission: Arc::new(AdminHttpAdmissionState::new(max_connections)),
            operation_tx,
            operation_receiver: std::sync::Mutex::new(Some(operation_receiver)),
            operation_timeout,
            operation_diagnostics,
        })
    }

    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn admission_snapshot(&self) -> AdminHttpAdmissionSnapshot {
        self.admission.snapshot()
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
        Ok(())
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Deserialize)]
struct IdPayload {
    id: String,
}

#[derive(Deserialize)]
struct IpPayload {
    ip: String,
}

#[derive(Deserialize)]
struct ConfigPayload {
    config: String,
}

#[derive(Deserialize)]
struct QKeyRevokePayload {
    id: String,
}

#[derive(Deserialize)]
struct LoggingModePayload {
    mode: String,
}

#[derive(Deserialize)]
struct QKeyCreatePayload {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    stealth: Option<String>,
    #[serde(default)]
    fec: Option<String>,
    #[serde(default)]
    sni_strategy: Option<String>,
    #[serde(default)]
    sni_domain: Option<String>,
    #[serde(default)]
    bandwidth_policy: Option<BandwidthPolicy>,
    #[serde(default)]
    traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
}

#[derive(Clone, Debug)]
pub struct IssueQKeyRequest {
    pub name: Option<String>,
    pub port: Option<u16>,
    pub ttl_seconds: Option<u64>,
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub sni_strategy: Option<String>,
    pub sni_domain: Option<String>,
    pub bandwidth_policy: Option<BandwidthPolicy>,
    pub traffic_analysis_policy: Option<crate::transport::config::TrafficAnalysisPolicy>,
}

fn normalize_ttl(ttl_seconds: Option<u64>) -> Option<u64> {
    match ttl_seconds {
        Some(0) | None => None,
        Some(v) => Some(v),
    }
}

fn normalize_qkey_id(raw: &str) -> Option<String> {
    let id = raw.trim();
    if id.len() != 12 {
        return None;
    }
    if !id.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.to_ascii_lowercase())
}

fn sanitize_asset_path(req_path: &str) -> Option<PathBuf> {
    let mut path = req_path;
    if let Some(idx) = path.find('?') {
        path = &path[..idx];
    }
    if let Some(idx) = path.find('#') {
        path = &path[..idx];
    }
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Convert a hyper Request into our internal HttpRequest representation.
/// This preserves compatibility with all existing helper functions
/// (get_cookie, header_value, authorize, validate_csrf, etc.).
fn hyper_to_http_request(parts: &hyper::http::request::Parts, body: Vec<u8>) -> HttpRequest {
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    HttpRequest { method: parts.method.to_string(), path, headers, body }
}

fn build_response(status: u16, content_type: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    build_response_with_headers(status, content_type, body, &[])
}

fn build_response_with_headers(
    status: u16,
    content_type: &str,
    body: Vec<u8>,
    extra_headers: &[(String, String)],
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header("Content-Type", content_type)
        .header("Connection", "close")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        .header("Cross-Origin-Opener-Policy", "same-origin")
        .header("Cross-Origin-Resource-Policy", "same-origin");
    if content_type.starts_with("text/html") {
        builder = builder.header("Content-Security-Policy", ADMIN_CSP);
    }
    for (key, value) in extra_headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from("Internal Server Error"))))
}

fn text_response(status: u16, body: &str) -> Response<Full<Bytes>> {
    build_response(status, "text/plain; charset=utf-8", body.as_bytes().to_vec())
}

fn json_response<T: Serialize>(status: u16, body: &T) -> Response<Full<Bytes>> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    build_response(status, "application/json", payload)
}

fn admin_json_response(body: &AdminResponse) -> Response<Full<Bytes>> {
    json_response(admin_response_status(body), body)
}

fn json_response_with_headers<T: Serialize>(
    status: u16,
    body: &T,
    headers: Vec<(String, String)>,
) -> Response<Full<Bytes>> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    build_response_with_headers(status, "application/json", payload, &headers)
}

fn file_response(path: &Path, extra_headers: &[(String, String)]) -> Response<Full<Bytes>> {
    let mime = match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "application/octet-stream",
    };
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return text_response(404, "Not Found"),
    };
    build_response_with_headers(200, mime, data, extra_headers)
}

async fn collect_http_request(
    req: Request<Incoming>,
) -> Result<HttpRequest, Response<Full<Bytes>>> {
    // Reject paths containing backslashes (path traversal guard).
    let path = req.uri().path();
    if path.contains('\\') {
        return Err(text_response(400, "Bad Request"));
    }

    // Reject requests with oversized headers (hyper max_buf_size is a soft guard;
    // enforce an explicit limit so the exact 431 status is guaranteed).
    let header_size: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len() + 4)
        .sum();
    if header_size > MAX_HEADER_BYTES {
        return Err(text_response(431, "Request Header Fields Too Large"));
    }

    // Check Content-Length before collecting body.
    let content_length: usize = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(text_response(413, "Payload Too Large"));
    }

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return Err(text_response(400, "Bad Request")),
    };
    if body_bytes.len() > MAX_BODY_BYTES {
        return Err(text_response(413, "Payload Too Large"));
    }

    Ok(hyper_to_http_request(&parts, body_bytes))
}

fn admin_operation_timeout_response() -> Response<Full<Bytes>> {
    text_response(504, "Admin operation timed out")
}

#[allow(clippy::too_many_arguments)]
async fn handle_request_with_deadline(
    req: Request<Incoming>,
    web_root: PathBuf,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    handler: Arc<dyn AdminHttpHandler>,
    peer: Option<SocketAddr>,
    operation_tx: mpsc::Sender<AdminHttpOperationCommand>,
    operation_diagnostics: Arc<AdminHttpOperationDiagnostics>,
    deadline: tokio::time::Instant,
) -> Response<Full<Bytes>> {
    let state = operation_diagnostics.begin(deadline);
    let request = match tokio::time::timeout_at(deadline, collect_http_request(req)).await {
        Ok(Ok(request)) => request,
        Ok(Err(response)) => {
            state.finish_direct();
            return response;
        }
        Err(_) => {
            state.mark_timeout();
            state.finish_timeout_without_worker();
            return text_response(408, "Request body timed out");
        }
    };

    let (response_tx, response_rx) = oneshot::channel();
    let state_for_command = Arc::clone(&state);
    let command = AdminHttpOperationCommand {
        work: Box::new(move || {
            handle_http_request_sync(
                request,
                &web_root,
                auth,
                auth_path,
                sessions,
                rate_limiter,
                handler,
                peer,
            )
        }),
        response_tx,
        state: state_for_command,
    };
    if let Err(error) = operation_tx.try_send(command) {
        match error {
            tokio::sync::mpsc::error::TrySendError::Full(command)
            | tokio::sync::mpsc::error::TrySendError::Closed(command) => {
                command.state.finish_cancelled();
            }
        }
        return text_response(503, "Admin operation queue unavailable");
    }

    match tokio::time::timeout_at(deadline, response_rx).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => {
            state.finish_cancelled();
            text_response(500, "Admin operation worker unavailable")
        }
        Err(_) => {
            state.mark_timeout();
            admin_operation_timeout_response()
        }
    }
}

#[allow(clippy::too_many_arguments, dead_code)]
#[cfg(test)]
async fn handle_request(
    req: Request<Incoming>,
    web_root: &Path,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    handler: Arc<dyn AdminHttpHandler>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {
    let req = match collect_http_request(req).await {
        Ok(req) => req,
        Err(response) => return response,
    };
    handle_http_request_sync(req, web_root, auth, auth_path, sessions, rate_limiter, handler, peer)
}

#[allow(clippy::too_many_arguments)]
fn handle_http_request_sync(
    req: HttpRequest,
    web_root: &Path,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    handler: Arc<dyn AdminHttpHandler>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {

    if req.path.starts_with("/api/") {
        if req.path == "/api/login" {
            return handle_login(req, auth.as_ref(), sessions, rate_limiter, peer);
        }
        if req.path == "/api/logout" {
            return handle_logout(&req, auth.as_ref(), &sessions, peer);
        }
        // Unauthenticated health probe for external liveness/readiness checks.
        // The runtime handler includes actual policy activation state.
        if req.path == "/api/health" {
            if req.method != "GET" {
                return text_response(405, "Method Not Allowed");
            }
            let response = handler.handle_health();
            return json_response(if response.success { 200 } else { 503 }, &response);
        }
        if !authorize(&req, auth.as_ref(), &sessions) {
            return json_response(401, &AdminResponse::error("Unauthorized"));
        }

        if req.path == "/api/csrf" {
            if req.method != "GET" {
                return text_response(405, "Method Not Allowed");
            }
            let Some(csrf_token) = csrf_token_for_request(&req, &sessions) else {
                return json_response(401, &AdminResponse::error("Unauthorized"));
            };
            return json_response_with_headers(
                200,
                &AdminResponse::ok(),
                vec![(CSRF_TOKEN_HEADER.to_string(), csrf_token)],
            );
        }

        if auth.is_some() && req.method == "POST" {
            if let Some(csrf_error) = validate_csrf_request(&req, &sessions) {
                return json_response(403, &AdminResponse::error(csrf_error));
            }
        }
        if let Some(auth_ref) = auth.as_ref() {
            let requires_pw_change = auth_ref.read().requires_password_change();
            if requires_pw_change && req.path != "/api/admin/auth" && req.path != "/api/logout" {
                return json_response(423, &AdminResponse::error("Password change required"));
            }
        }
        if req.path == "/api/admin/auth" {
            return handle_admin_auth(
                req,
                auth,
                auth_path.as_deref(),
                &sessions,
                rate_limiter,
                peer,
            );
        }
        return handle_api(req, handler, peer);
    }

    if req.method != "GET" {
        return text_response(405, "Method Not Allowed");
    }

    let Some(rel_path) = sanitize_asset_path(&req.path) else {
        return text_response(403, "Forbidden");
    };
    let full_path = web_root.join(rel_path);
    if full_path.is_file() {
        let rel = full_path.strip_prefix(web_root).unwrap_or(&full_path);
        let is_index = rel == Path::new("index.html");
        let is_asset =
            rel.components().next().and_then(|c| c.as_os_str().to_str()) == Some("assets");
        let cache = if is_index {
            "no-store"
        } else if is_asset {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        };
        let extra = vec![("Cache-Control".to_string(), cache.to_string())];
        return file_response(&full_path, &extra);
    }
    // SPA fallback: serve index.html for non-file routes (browser refresh on /logs etc.)
    let index = web_root.join("index.html");
    if index.is_file() {
        let extra = vec![("Cache-Control".to_string(), "no-store".to_string())];
        return file_response(&index, &extra);
    }
    text_response(404, "Not Found")
}

fn authorize(
    req: &HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: &Arc<Mutex<SessionStore>>,
) -> bool {
    let Some(_expected) = auth else {
        return true;
    };
    let Some(session_id) = get_cookie(req, SESSION_COOKIE) else {
        return false;
    };
    let mut store = sessions.lock();
    store.is_valid(&session_id)
}

fn csrf_token_for_request(
    req: &HttpRequest,
    sessions: &Arc<Mutex<SessionStore>>,
) -> Option<String> {
    let session_id = get_cookie(req, SESSION_COOKIE)?;
    let mut store = sessions.lock();
    store.csrf_token(&session_id)
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

fn format_peer(peer: Option<SocketAddr>) -> String {
    peer.map(|addr| addr.ip().to_string()).unwrap_or_else(|| "-".to_string())
}

fn trust_proxy_enabled() -> bool {
    std::env::var("QUICFUSCATE_TRUST_PROXY")
        .map(|v| v.trim() == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn trusted_proxy_ips() -> Vec<std::net::IpAddr> {
    std::env::var("QUICFUSCATE_TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            trimmed.parse::<std::net::IpAddr>().ok()
        })
        .collect()
}

fn peer_is_trusted_proxy(peer: Option<SocketAddr>) -> bool {
    let peer_ip = match peer {
        Some(addr) => addr.ip(),
        None => return false,
    };
    let trusted = trusted_proxy_ips();
    if trusted.is_empty() {
        // TRUST_PROXY is set but no trusted proxy IPs configured - unsafe, reject XFF
        log::warn!(
            "QUICFUSCATE_TRUST_PROXY is enabled but QUICFUSCATE_TRUSTED_PROXY_IPS is empty or unset; \
             falling back to peer address for rate limiting"
        );
        return false;
    }
    trusted.contains(&peer_ip)
}

fn header_value<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn first_forwarded_ip(raw: &str) -> Option<String> {
    // "client, proxy1, proxy2"
    let first = raw.split(',').next()?.trim();
    let first = first.trim_matches('"');
    let ip: std::net::IpAddr = first.parse().ok()?;
    Some(ip.to_string())
}

fn client_ip_for_rate_limit(peer: Option<SocketAddr>, req: &HttpRequest) -> String {
    if trust_proxy_enabled() && peer_is_trusted_proxy(peer) {
        if let Some(v) = header_value(req, "x-forwarded-for").and_then(first_forwarded_ip) {
            return v;
        }
        if let Some(v) = header_value(req, "x-real-ip").and_then(first_forwarded_ip) {
            return v;
        }
    }
    format_peer(peer)
}

fn limiter_key(prefix: &str, ip: &str) -> String {
    format!("{}:{}", prefix, ip)
}

fn normalize_ip_for_policy(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Canonicalize so block/unblock semantics match runtime `from.ip().to_string()`.
    trimmed.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

fn normalize_client_id(raw: &str) -> Option<String> {
    super::admin::ClientIdentity::parse(raw).map(|id| id.to_string())
}

fn log_action(peer: Option<SocketAddr>, action: &str, detail: &str, success: bool) {
    let peer = format_peer(peer);
    if success {
        log::info!("admin action={} detail={} peer={} status=ok", action, detail, peer);
    } else {
        log::warn!("admin action={} detail={} peer={} status=err", action, detail, peer);
    }
}

fn handle_login(
    req: HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {
    let Some(auth) = auth else {
        return json_response(500, &AdminResponse::error("Authentication not configured"));
    };
    if req.method != "POST" {
        return text_response(405, "Method Not Allowed");
    }
    let peer_ip = client_ip_for_rate_limit(peer, &req);
    let key = limiter_key("login", &peer_ip);
    let rate_limited = {
        let mut limiter = rate_limiter.lock();
        if limiter.is_locked(&key) {
            let retry_after = limiter.retry_after_secs(&key).unwrap_or(60);
            Some(retry_after)
        } else {
            None
        }
    };
    if let Some(retry_after) = rate_limited {
        log_action(peer, "login", &format!("ip={} RATE_LIMITED", peer_ip), false);
        return json_response_with_headers(
            429,
            &AdminResponse::error("Too many login attempts. Try again later."),
            vec![("Retry-After".to_string(), retry_after.to_string())],
        );
    }
    {
        let mut limiter = rate_limiter.lock();
        limiter.record_attempt(&key);
    }
    let payload: LoginPayload = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
    };
    let username = payload.username.trim();
    if username.chars().count() > MAX_USERNAME_CHARS {
        return json_response(400, &AdminResponse::error("Username too long"));
    }
    if payload.password.len() > MAX_PASSWORD_BYTES {
        return json_response(400, &AdminResponse::error("Password too long"));
    }
    let ok = auth.read().verify(username, payload.password.as_str());
    if !ok {
        log_action(peer, "login", &format!("user={}", username), false);
        return json_response(401, &AdminResponse::error("Invalid credentials"));
    }
    // Success: clear rate limit for this IP
    {
        let mut limiter = rate_limiter.lock();
        limiter.clear(&key);
    }
    let (session_id, csrf_token) = {
        let mut store = sessions.lock();
        store.create()
    };
    let cookie = build_session_cookie(&session_id, &req);
    log_action(peer, "login", &format!("user={}", username), true);
    let requires_password_change = auth.read().requires_password_change();
    json_response_with_headers(
        200,
        &AdminResponse::ok_with_data(serde_json::json!({
            "user": payload.username,
            "requires_password_change": requires_password_change,
        })),
        vec![("Set-Cookie".to_string(), cookie), (CSRF_TOKEN_HEADER.to_string(), csrf_token)],
    )
}

fn handle_logout(
    req: &HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: &Arc<Mutex<SessionStore>>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {
    if auth.is_none() {
        return admin_json_response(&AdminResponse::ok_with_message("Logged out"));
    }
    if let Some(session_id) = get_cookie(req, SESSION_COOKIE) {
        let mut store = sessions.lock();
        store.remove(&session_id);
    }
    let cookie = build_expired_cookie(req);
    log_action(peer, "logout", "-", true);
    json_response_with_headers(
        200,
        &AdminResponse::ok_with_message("Logged out"),
        vec![("Set-Cookie".to_string(), cookie)],
    )
}

#[derive(Deserialize)]
struct AdminAuthUpdatePayload {
    #[serde(default)]
    new_username: Option<String>,
    current_password: String,
    #[serde(default)]
    new_password: Option<String>,
}

fn handle_admin_auth(
    req: HttpRequest,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<&Path>,
    sessions: &Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {
    let Some(auth) = auth else {
        return json_response(500, &AdminResponse::error("Authentication not configured"));
    };

    if req.method == "GET" {
        let guard = auth.read();
        let payload = serde_json::json!({
            "user": guard.user(),
            "requires_password_change": guard.requires_password_change(),
        });
        return admin_json_response(&AdminResponse::ok_with_data(payload));
    }

    if req.method != "POST" {
        return text_response(405, "Method Not Allowed");
    }

    let payload: AdminAuthUpdatePayload = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
    };
    if payload.current_password.len() > MAX_PASSWORD_BYTES {
        return json_response(400, &AdminResponse::error("Password too long (max 256 chars)"));
    }

    if payload.new_username.is_none() && payload.new_password.is_none() {
        return json_response(400, &AdminResponse::error("No update requested"));
    }

    // Rate limit admin-auth attempts (password changes) to slow brute forcing.
    // This uses the same limiter state as login, but with a separate key namespace.
    let peer_ip = client_ip_for_rate_limit(peer, &req);
    let key = limiter_key("admin-auth", &peer_ip);
    let rate_limited = {
        let mut limiter = rate_limiter.lock();
        if limiter.is_locked(&key) {
            let retry_after = limiter.retry_after_secs(&key).unwrap_or(60);
            Some(retry_after)
        } else {
            None
        }
    };
    if let Some(retry_after) = rate_limited {
        log_action(peer, "admin-auth", &format!("ip={} RATE_LIMITED", peer_ip), false);
        return json_response_with_headers(
            429,
            &AdminResponse::error("Too many attempts. Try again later."),
            vec![("Retry-After".to_string(), retry_after.to_string())],
        );
    }
    {
        let mut limiter = rate_limiter.lock();
        limiter.record_attempt(&key);
    }

    let new_password = payload.new_password;
    if let Some(ref pw) = new_password {
        if pw.len() < 6 {
            return json_response(400, &AdminResponse::error("Password too short (min 6 chars)"));
        }
    }

    let (old_user, verified) = {
        let guard = auth.read();
        (
            guard.user().to_string(),
            guard.verify_password_only(payload.current_password.as_str()),
        )
    };
    if !verified {
        log_action(peer, "admin-auth", &format!("user={}", old_user), false);
        return json_response(401, &AdminResponse::error("Invalid credentials"));
    }

    let new_user = payload.new_username.as_deref().unwrap_or(old_user.as_str()).trim().to_string();
    if new_user.is_empty() {
        return json_response(400, &AdminResponse::error("Username cannot be empty"));
    }
    if new_user.chars().count() > MAX_USERNAME_CHARS {
        return json_response(400, &AdminResponse::error("Username too long (max 64 chars)"));
    }
    if new_user.chars().any(|c| c.is_control()) {
        return json_response(400, &AdminResponse::error("Username contains invalid characters"));
    }

    if let Some(ref pw) = new_password {
        if pw.len() > MAX_PASSWORD_BYTES {
            return json_response(400, &AdminResponse::error("Password too long (max 256 chars)"));
        }
    }

    let mut guard = auth.write();
    if !guard.verify_password_only(payload.current_password.as_str()) {
        log_action(peer, "admin-auth", &format!("user={}", guard.user()), false);
        return json_response(401, &AdminResponse::error("Invalid credentials"));
    }
    let candidate = {
        let result = if let Some(ref password) = new_password {
            guard.candidate_with_credentials(new_user.clone(), password)
        } else {
            Ok(guard.candidate_with_username(new_user))
        };
        match result {
            Ok(candidate) => candidate,
            Err(error) => {
                log::error!("admin auth candidate construction failed: {}", error);
                return json_response(500, &AdminResponse::error("Password hashing failed"));
            }
        }
    };
    if let Some(path) = auth_path {
        if let Err(error) = persist_auth_file(path, &candidate) {
            log::error!(
                "admin auth durable update failed ({}): {}",
                path.display(),
                error
            );
            return json_response(
                500,
                &AdminResponse::error("Admin credential persistence failed"),
            );
        }
    }
    *guard = candidate;
    drop(guard);

    // Success: clear rate limiter only after the credential transaction commits.
    {
        let mut limiter = rate_limiter.lock();
        limiter.clear(&key);
    }

    {
        let mut store = sessions.lock();
        store.clear_all();
    }

    let cookie = build_expired_cookie(&req);
    log_action(peer, "admin-auth", &format!("user={}", old_user), true);
    json_response_with_headers(
        200,
        &AdminResponse::ok_with_message("Admin credentials updated"),
        vec![("Set-Cookie".to_string(), cookie)],
    )
}
