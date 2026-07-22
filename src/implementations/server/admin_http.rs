//! HTTP admin server for web dashboard control.
//!
//! Serves static web assets and exposes a JSON API backed by an AdminHttpHandler.
//! Uses hyper 1.x for HTTP/1.1 parsing and response writing.
//!
//! ## Architecture: admin_http.rs vs admin.rs
//!
//! This module (`admin_http.rs`) is the **HTTP web dashboard** - a remote-capable,
//! authenticated admin interface. It serves the web-admin UI static assets and exposes
//! a JSON API with session-based authentication (Argon2 password hashing, CSRF tokens,
//! rate limiting, replay protection).
//!
//! The sibling module `admin.rs` is the **Unix domain socket control plane** - a low-level,
//! local-only interface for `quicfuscate-ctl` CLI commands. It uses JSON-over-Unix-socket
//! without authentication (socket file permissions provide access control).
//!
//! Both interfaces serve different use cases and are intentionally parallel:
//! - `admin_http.rs`: remote dashboard access, QKey management, multi-user (authenticated)
//! - `admin.rs`: local server management, scripting, automation (no auth overhead)
//!
//! Shared types (`AdminResponse`, `ClientInfo`) are imported from `admin.rs`.
//! Handler logic is currently independent in each module. Future direction: extract
//! shared handler logic into a common service layer to reduce duplication while
//! preserving transport separation.

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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

use super::admin::{AdminResponse, ClientInfo};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;
const SESSION_COOKIE: &str = "qf_admin_session";
const SESSION_TTL_SECS: u64 = 60 * 60;
const LOGIN_RATE_LIMIT_ATTEMPTS: u32 = 5;
const LOGIN_RATE_LIMIT_WINDOW_SECS: u64 = 60;
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

impl AdminAuth {
    pub fn new(user: String, password: String, requires_password_change: bool) -> Self {
        let password_phc = hash_password(&password).unwrap_or_else(|e| {
            log::error!("{} - admin account will be unusable until password is reset", e);
            String::new()
        });
        Self { user, password_phc, requires_password_change }
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

    fn set_credentials(&mut self, new_user: String, new_password: String) -> Result<(), String> {
        let phc = hash_password(&new_password)?;
        self.user = new_user;
        self.password_phc = phc;
        self.requires_password_change = false;
        Ok(())
    }

    fn set_username(&mut self, new_user: String) {
        self.user = new_user;
        // Intentionally keep password hash and requires_password_change unchanged.
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

fn load_auth_file(path: &Path) -> Option<AdminAuth> {
    let bytes = std::fs::read(path).ok()?;
    let file: AdminAuthFile = serde_json::from_slice(&bytes).ok()?;
    if file.user.trim().is_empty() || file.password_phc.trim().is_empty() {
        return None;
    }
    Some(AdminAuth {
        user: file.user,
        password_phc: file.password_phc,
        requires_password_change: file.requires_password_change,
    })
}

fn persist_auth_file(path: &Path, auth: &AdminAuth) {
    let payload = AdminAuthFile {
        user: auth.user.clone(),
        password_phc: auth.password_phc.clone(),
        requires_password_change: auth.requires_password_change,
        updated_at: current_epoch_secs(),
    };
    let bytes = match serde_json::to_vec_pretty(&payload) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("admin auth serialize failed: {}", e);
            return;
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::warn!("admin auth mkdir failed ({}): {}", parent.display(), e);
            return;
        }
    }
    if let Err(e) = super::fsutil::atomic_write_file(
        path,
        &bytes,
        Some(0o600),
        "admin_http::auth_write_tmp_nonce",
    ) {
        log::warn!("admin auth write failed ({}): {}", path.display(), e);
    }
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
    max_attempts: u32,
    lockout: Duration,
}

impl LoginRateLimiter {
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self { attempts: HashMap::new(), max_attempts, lockout: Duration::from_secs(lockout_secs) }
    }

    fn is_locked(&mut self, ip: &str) -> bool {
        self.prune();
        if let Some((count, _)) = self.attempts.get(ip) {
            *count >= self.max_attempts
        } else {
            false
        }
    }

    fn record_failure(&mut self, ip: &str) {
        let entry = self.attempts.entry(ip.to_string()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    fn clear(&mut self, ip: &str) {
        self.attempts.remove(ip);
    }

    fn prune(&mut self) {
        let cutoff = self.lockout;
        self.attempts.retain(|_, (_, ts)| ts.elapsed() < cutoff);
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
    replay_fingerprints: Vec<u64>,
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
                replay_fingerprints: Vec::new(),
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
                if record.replay_fingerprints.contains(&replay_fingerprint) {
                    return Err("Replay request detected");
                }
                record.replay_fingerprints.push(replay_fingerprint);
                if record.replay_fingerprints.len() > MAX_REPLAY_FINGERPRINTS {
                    let excess = record.replay_fingerprints.len() - MAX_REPLAY_FINGERPRINTS;
                    record.replay_fingerprints.drain(0..excess);
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
    fn handle_list_clients(&self) -> Vec<ClientInfo>;
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

/// Maximum number of concurrent admin HTTP connections.
/// Limits memory pressure and mitigates connection-exhaustion DoS.
const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// Per-connection timeout. Connections that exceed this duration are dropped,
/// mitigating Slowloris-style attacks without thread-per-connection overhead.
const CONNECTION_TIMEOUT_SECS: u64 = 30;

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
}

impl AdminHttpServer {
    pub fn new(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
    ) -> Self {
        let auth_loaded = auth_path.as_ref().and_then(|p| load_auth_file(p.as_path()));
        let auth = auth_loaded.or(auth);
        let auth = auth.map(|a| Arc::new(RwLock::new(a)));
        if let (Some(path), Some(auth_ref)) = (auth_path.as_ref(), auth.as_ref()) {
            if std::fs::metadata(path).is_err() {
                if let Ok(guard) = auth_ref.read() {
                    persist_auth_file(path, &guard);
                }
            }
        }
        Self {
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
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
        }
    }

    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("admin web server listening on http://{}", self.addr);

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let (stream, peer_addr) =
                match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await {
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
            let handler = self.handler.clone();
            let web_root = self.web_root.clone();
            let auth = self.auth.clone();
            let auth_path = self.auth_path.clone();
            let shutdown = self.shutdown.clone();
            let sessions = self.sessions.clone();
            let rate_limiter = self.rate_limiter.clone();
            let semaphore = self.conn_semaphore.clone();
            let peer = Some(peer_addr);
            tokio::spawn(async move {
                let _permit = match semaphore.acquire().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let web_root = web_root.clone();
                    let auth = auth.clone();
                    let auth_path = auth_path.clone();
                    let sessions = sessions.clone();
                    let rate_limiter = rate_limiter.clone();
                    let handler = handler.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handle_request(
                                req,
                                &web_root,
                                auth,
                                auth_path,
                                sessions,
                                rate_limiter,
                                handler,
                                peer,
                            )
                            .await,
                        )
                    }
                });
                let conn = http1::Builder::new()
                    .max_buf_size(MAX_HEADER_BYTES)
                    .keep_alive(false)
                    .serve_connection(io, svc);
                let timeout = Duration::from_secs(CONNECTION_TIMEOUT_SECS);
                match tokio::time::timeout(timeout, conn).await {
                    Ok(Err(e)) => {
                        log::debug!("admin web connection error: {}", e);
                    }
                    Err(_elapsed) => {
                        log::debug!(
                            "admin web connection timed out after {}s",
                            CONNECTION_TIMEOUT_SECS
                        );
                    }
                    Ok(Ok(())) => {}
                }
            });
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

#[allow(clippy::too_many_arguments)]
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
    // Reject paths containing backslashes (path traversal guard).
    let path = req.uri().path();
    if path.contains('\\') {
        return text_response(400, "Bad Request");
    }

    // Reject requests with oversized headers (hyper max_buf_size is a soft guard;
    // enforce an explicit limit so the exact 431 status is guaranteed).
    {
        let header_size: usize = req
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4) // ": " + "\r\n"
            .sum();
        if header_size > MAX_HEADER_BYTES {
            return text_response(431, "Request Header Fields Too Large");
        }
    }

    // Check Content-Length before collecting body
    let content_length: usize = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return text_response(413, "Payload Too Large");
    }

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return text_response(400, "Bad Request"),
    };
    if body_bytes.len() > MAX_BODY_BYTES {
        return text_response(413, "Payload Too Large");
    }

    let req = hyper_to_http_request(&parts, body_bytes);

    if req.path.starts_with("/api/") {
        if req.path == "/api/login" {
            return handle_login(req, auth.as_ref(), sessions, rate_limiter, peer);
        }
        if req.path == "/api/logout" {
            return handle_logout(&req, auth.as_ref(), &sessions, peer);
        }
        // Unauthenticated health probe for container orchestration
        // (Docker HEALTHCHECK, Kubernetes liveness/readiness).
        // Returns a minimal JSON body with no sensitive information.
        if req.path == "/api/health" {
            if req.method != "GET" {
                return text_response(405, "Method Not Allowed");
            }
            return json_response(200, &serde_json::json!({"status": "ok"}));
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
            let requires_pw_change =
                auth_ref.read().map(|guard| guard.requires_password_change()).unwrap_or(false);
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
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    store.is_valid(&session_id)
}

fn csrf_token_for_request(
    req: &HttpRequest,
    sessions: &Arc<Mutex<SessionStore>>,
) -> Option<String> {
    let session_id = get_cookie(req, SESSION_COOKIE)?;
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
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
    let ok =
        auth.read().map(|guard| guard.verify(username, payload.password.as_str())).unwrap_or(false);
    if !ok {
        {
            let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            limiter.record_failure(&key);
        }
        log_action(peer, "login", &format!("user={}", username), false);
        return json_response(401, &AdminResponse::error("Invalid credentials"));
    }
    // Success: clear rate limit for this IP
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(&key);
    }
    let (session_id, csrf_token) = {
        let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
        store.create()
    };
    let cookie = build_session_cookie(&session_id, &req);
    log_action(peer, "login", &format!("user={}", username), true);
    let requires_password_change =
        auth.read().map(|guard| guard.requires_password_change()).unwrap_or(false);
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
        let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
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
        let payload = auth
            .read()
            .map(|guard| {
                serde_json::json!({
                    "user": guard.user(),
                    "requires_password_change": guard.requires_password_change(),
                })
            })
            .unwrap_or_else(
                |_| serde_json::json!({ "user": "admin", "requires_password_change": false }),
            );
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
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
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

    let new_password = payload.new_password;
    if let Some(ref pw) = new_password {
        if pw.len() < 6 {
            return json_response(400, &AdminResponse::error("Password too short (min 6 chars)"));
        }
    }

    let (old_user, verified) = auth
        .read()
        .map(|guard| {
            (
                guard.user().to_string(),
                guard.verify_password_only(payload.current_password.as_str()),
            )
        })
        .unwrap_or_else(|_| ("-".to_string(), false));
    if !verified {
        {
            let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
            limiter.record_failure(&key);
        }
        log_action(peer, "admin-auth", &format!("user={}", old_user), false);
        return json_response(401, &AdminResponse::error("Invalid credentials"));
    }

    // Success: clear rate limiter for this key.
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(&key);
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

    let hash_failed = {
        let mut guard = auth.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pw) = new_password {
            match guard.set_credentials(new_user.clone(), pw) {
                Ok(()) => false,
                Err(e) => {
                    log::error!("{}", e);
                    true
                }
            }
        } else {
            // Username-only update: keep password hash and requires_password_change.
            guard.set_username(new_user);
            false
        }
    };
    if hash_failed {
        return json_response(500, &AdminResponse::error("Password hashing failed"));
    }
    if let Some(path) = auth_path {
        let guard = auth.read().unwrap_or_else(|e| e.into_inner());
        persist_auth_file(path, &guard);
    }

    {
        let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    #[derive(Clone)]
    struct TestHandler;

    impl AdminHttpHandler for TestHandler {
        fn handle_status(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_clients(&self) -> Vec<ClientInfo> {
            vec![]
        }
        fn handle_kick(&self, _id: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_block(&self, _ip: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_unblock(&self, _ip: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_blocked_ips(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_reload(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_drain(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_drain_status(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "state": "running" }))
        }
        fn handle_qkey(&self, _req: IssueQKeyRequest) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_qkeys(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_revoke_qkey(&self, _id: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_shutdown(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_read_config(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "config": "[x]\n" }))
        }
        fn handle_write_config(&self, _contents: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_metrics_text(&self) -> String {
            String::new()
        }
        fn handle_metrics_json(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "metrics": {} }))
        }
        fn handle_get_logging_config(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "mode": "normal" }))
        }
        fn handle_set_logging_config(&self, _mode: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_get_logs(&self, _cursor: u64) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "lines": [], "cursor": 0 }))
        }
        fn handle_clear_logs(&self) -> AdminResponse {
            AdminResponse::ok_with_message("Logs cleared")
        }
    }

    fn read_all(mut s: StdTcpStream) -> String {
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    }

    fn parse_status(resp: &str) -> u16 {
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0)
    }

    fn parse_set_cookie(resp: &str) -> Option<String> {
        for line in resp.lines() {
            if line.to_lowercase().starts_with("set-cookie:") {
                return Some(line.split_once(':')?.1.trim().to_string());
            }
        }
        None
    }

    fn parse_csrf_token(resp: &str) -> Option<String> {
        parse_header(resp, CSRF_TOKEN_HEADER)
    }

    fn parse_header(resp: &str, name: &str) -> Option<String> {
        let needle = format!("{}:", name.to_ascii_lowercase());
        for line in resp.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with(&needle) {
                return Some(line.split_once(':')?.1.trim().to_string());
            }
        }
        None
    }

    fn cookie_header_from_set_cookie(set_cookie: &str) -> Option<String> {
        // Keep only "name=value"
        let pair = set_cookie.split(';').next()?.trim();
        if pair.is_empty() {
            return None;
        }
        Some(format!("Cookie: {}", pair))
    }

    fn send_req(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut s = StdTcpStream::connect(addr).expect("connect");
        // 10s to accommodate Argon2 password hashing in unoptimized debug builds.
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        s.write_all(raw.as_bytes()).expect("write");
        read_all(s)
    }

    struct AdminLoginSession {
        cookie_header: String,
        csrf_token: String,
    }

    impl AdminLoginSession {
        fn csrf_header(&self) -> String {
            format!("{}: {}", CSRF_TOKEN_HEADER, self.csrf_token)
        }
    }

    fn authenticated_get(login: &AdminLoginSession, path: &str) -> String {
        format!("GET {} HTTP/1.1\r\nHost: localhost\r\n{}\r\n\r\n", path, login.cookie_header)
    }

    fn login_post(username: &str, password: &str) -> String {
        login_post_with_headers(username, password, "")
    }

    fn raw_login_post(extra_headers: &str, body: &str) -> String {
        format!("POST /api/login HTTP/1.1\r\nHost: localhost\r\n{}\r\n{}", extra_headers, body)
    }

    fn login_post_with_headers(username: &str, password: &str, extra_headers: &str) -> String {
        let body = format!(r#"{{"username":"{}","password":"{}"}}"#, username, password);
        let extra_headers =
            if extra_headers.is_empty() { String::new() } else { format!("{extra_headers}\r\n") };
        format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            extra_headers,
            body.len(),
            body
        )
    }

    fn logout_post(login: &AdminLoginSession) -> String {
        format!(
            "POST /api/logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n{}\r\n{}\r\n\r\n",
            login.cookie_header,
            login.csrf_header(),
        )
    }

    fn config_post(body: &str) -> String {
        unauthenticated_json_post("/api/config", body)
    }

    fn unauthenticated_json_post(path: &str, body: &str) -> String {
        format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            path,
            body.len(),
            body
        )
    }

    fn authenticated_config_post_with_headers(
        login: &AdminLoginSession,
        extra_headers: &str,
        body: &str,
    ) -> String {
        let origin_header = if extra_headers.to_ascii_lowercase().contains("origin:") {
            String::new()
        } else {
            "Origin: http://localhost\r\n".to_string()
        };
        let extra_headers =
            if extra_headers.is_empty() { String::new() } else { format!("{extra_headers}\r\n") };
        format!(
            "POST /api/config HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n{}\r\n{}",
            origin_header,
            body.len(),
            login.cookie_header,
            login.csrf_header(),
            extra_headers,
            body
        )
    }

    fn admin_auth_post(login: &AdminLoginSession, body: &str) -> String {
        admin_auth_post_with_headers(login, "", body)
    }

    fn admin_auth_post_without_csrf(login: &AdminLoginSession, body: &str) -> String {
        format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n\r\n{}\r\n",
            body.len(),
            login.cookie_header,
            body
        )
    }

    fn admin_auth_post_with_headers(
        login: &AdminLoginSession,
        extra_headers: &str,
        body: &str,
    ) -> String {
        // If extra_headers contains an Origin, don't add a default one (allows
        // tests to verify cross-origin rejection). Otherwise add same-origin
        // Origin header for CSRF protection.
        let origin_header = if extra_headers.to_ascii_lowercase().contains("origin:") {
            String::new()
        } else {
            "Origin: http://localhost\r\n".to_string()
        };
        let extra_headers =
            if extra_headers.is_empty() { String::new() } else { format!("{extra_headers}\r\n") };
        format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n{}\r\n{}",
            origin_header,
            body.len(),
            login.cookie_header,
            login.csrf_header(),
            extra_headers,
            body
        )
    }

    fn admin_auth_post_with_csrf_and_headers(
        login: &AdminLoginSession,
        csrf_header: &str,
        extra_headers: &str,
        body: &str,
    ) -> String {
        let origin_header = if extra_headers.to_ascii_lowercase().contains("origin:") {
            String::new()
        } else {
            "Origin: http://localhost\r\n".to_string()
        };
        let extra_headers =
            if extra_headers.is_empty() { String::new() } else { format!("{extra_headers}\r\n") };
        format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n{}\r\n{}",
            origin_header,
            body.len(),
            login.cookie_header,
            csrf_header,
            extra_headers,
            body
        )
    }

    fn login_admin(addr: std::net::SocketAddr, password: &str) -> AdminLoginSession {
        let login_req = login_post("admin", password);
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        AdminLoginSession { cookie_header, csrf_token }
    }

    fn test_auth(password: &str, requires_password_change: bool) -> Option<Arc<RwLock<AdminAuth>>> {
        Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            password.to_string(),
            requires_password_change,
        ))))
    }

    fn test_sessions() -> Arc<Mutex<SessionStore>> {
        shared_session_store(Duration::from_secs(3600))
    }

    fn test_short_sessions() -> Arc<Mutex<SessionStore>> {
        shared_session_store(Duration::from_secs(60))
    }

    fn test_rate_limiter(max_attempts: u32) -> Arc<Mutex<LoginRateLimiter>> {
        shared_login_rate_limiter(max_attempts, 60)
    }

    fn test_handler() -> Arc<dyn AdminHttpHandler> {
        Arc::new(TestHandler)
    }

    fn spawn_short_unauth_server(
        listener: StdTcpListener,
        n: usize,
        web_root: std::path::PathBuf,
    ) -> thread::JoinHandle<()> {
        spawn_server(
            listener,
            n,
            web_root,
            None,
            test_short_sessions(),
            test_rate_limiter(5),
            test_handler(),
        )
    }

    fn start_short_unauth_server(
        n: usize,
        web_root: std::path::PathBuf,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let thr = spawn_short_unauth_server(listener, n, web_root);
        (addr, thr)
    }

    fn spawn_auth_server(
        listener: StdTcpListener,
        n: usize,
        web_root: std::path::PathBuf,
        password: &str,
        requires_password_change: bool,
        max_attempts: u32,
    ) -> thread::JoinHandle<()> {
        spawn_server(
            listener,
            n,
            web_root,
            test_auth(password, requires_password_change),
            test_sessions(),
            test_rate_limiter(max_attempts),
            test_handler(),
        )
    }

    fn start_auth_server(
        n: usize,
        web_root: std::path::PathBuf,
        password: &str,
        requires_password_change: bool,
        max_attempts: u32,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let thr = spawn_auth_server(
            listener,
            n,
            web_root,
            password,
            requires_password_change,
            max_attempts,
        );
        (addr, thr)
    }

    fn start_server_with_auth(
        n: usize,
        web_root: std::path::PathBuf,
        auth: Option<Arc<RwLock<AdminAuth>>>,
        max_attempts: u32,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let thr = spawn_server(
            listener,
            n,
            web_root,
            auth,
            test_sessions(),
            test_rate_limiter(max_attempts),
            test_handler(),
        );
        (addr, thr)
    }

    fn start_unauth_server(
        n: usize,
        web_root: std::path::PathBuf,
    ) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let thr = spawn_unauth_server(listener, n, web_root);
        (addr, thr)
    }

    fn spawn_unauth_server(
        listener: StdTcpListener,
        n: usize,
        web_root: std::path::PathBuf,
    ) -> thread::JoinHandle<()> {
        spawn_server(
            listener,
            n,
            web_root,
            None,
            test_sessions(),
            test_rate_limiter(5),
            test_handler(),
        )
    }

    fn spawn_server(
        listener: StdTcpListener,
        n: usize,
        web_root: std::path::PathBuf,
        auth: Option<Arc<RwLock<AdminAuth>>>,
        sessions: Arc<Mutex<SessionStore>>,
        rate_limiter: Arc<Mutex<LoginRateLimiter>>,
        handler: Arc<dyn AdminHttpHandler>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test tokio runtime");
            for _ in 0..n {
                let (stream, peer_addr) = listener.accept().expect("accept");
                stream.set_nonblocking(true).expect("set_nonblocking");
                let peer = Some(peer_addr);
                let _ = rt.block_on(async {
                    let tokio_stream = tokio::net::TcpStream::from_std(stream).expect("from_std");
                    let io = TokioIo::new(tokio_stream);
                    let web_root = web_root.clone();
                    let auth = auth.clone();
                    let sessions = sessions.clone();
                    let rate_limiter = rate_limiter.clone();
                    let handler = handler.clone();
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let web_root = web_root.clone();
                        let auth = auth.clone();
                        let sessions = sessions.clone();
                        let rate_limiter = rate_limiter.clone();
                        let handler = handler.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                handle_request(
                                    req,
                                    &web_root,
                                    auth,
                                    None,
                                    sessions,
                                    rate_limiter,
                                    handler,
                                    peer,
                                )
                                .await,
                            )
                        }
                    });
                    http1::Builder::new()
                        .max_buf_size(MAX_HEADER_BYTES)
                        .keep_alive(false)
                        .serve_connection(io, svc)
                        .await
                });
            }
        })
    }

    fn with_trust_proxy_env<T>(
        enabled: bool,
        trusted_proxy_ips: Option<&str>,
        f: impl FnOnce() -> T,
    ) -> T {
        // Environment variables are process-global. Guard tests that mutate
        // QUICFUSCATE_TRUST_PROXY and QUICFUSCATE_TRUSTED_PROXY_IPS so
        // parallel test execution cannot race.
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard =
            ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());

        let prev_trust_proxy = std::env::var("QUICFUSCATE_TRUST_PROXY").ok();
        let prev_trusted_proxy_ips = std::env::var("QUICFUSCATE_TRUSTED_PROXY_IPS").ok();
        if enabled {
            std::env::set_var("QUICFUSCATE_TRUST_PROXY", "1");
        } else {
            std::env::remove_var("QUICFUSCATE_TRUST_PROXY");
        }
        match trusted_proxy_ips {
            Some(value) => std::env::set_var("QUICFUSCATE_TRUSTED_PROXY_IPS", value),
            None => std::env::remove_var("QUICFUSCATE_TRUSTED_PROXY_IPS"),
        }
        let out = f();
        match prev_trust_proxy {
            Some(v) => std::env::set_var("QUICFUSCATE_TRUST_PROXY", v),
            None => std::env::remove_var("QUICFUSCATE_TRUST_PROXY"),
        }
        match prev_trusted_proxy_ips {
            Some(v) => std::env::set_var("QUICFUSCATE_TRUSTED_PROXY_IPS", v),
            None => std::env::remove_var("QUICFUSCATE_TRUSTED_PROXY_IPS"),
        }
        out
    }

    #[test]
    fn client_ip_for_rate_limit_uses_peer_when_proxy_not_trusted() {
        with_trust_proxy_env(false, None, || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "1.2.3.4".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "127.0.0.1");
        });
    }

    #[test]
    fn client_ip_for_rate_limit_uses_x_forwarded_for_when_trusted() {
        with_trust_proxy_env(true, Some("127.0.0.1"), || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "1.2.3.4, 5.6.7.8".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "1.2.3.4");
        });
    }

    #[test]
    fn client_ip_for_rate_limit_ignores_invalid_forwarded_ip_and_falls_back_to_peer() {
        with_trust_proxy_env(true, Some("127.0.0.1"), || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "not-an-ip".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "127.0.0.1");
        });
    }

    #[test]
    fn session_cookie_is_secure_only_for_https_forwarded_proto() {
        with_trust_proxy_env(true, None, || {
            let base = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![],
                body: Vec::new(),
            };
            let https = HttpRequest {
                headers: vec![("x-forwarded-proto".to_string(), "https".to_string())],
                ..base
            };
            let http = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("x-forwarded-proto".to_string(), "http".to_string())],
                body: Vec::new(),
            };

            let c1 = build_session_cookie("sid", &https);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));

            let c2 = build_session_cookie("sid", &http);
            assert!(!c2.contains("; Secure"));
        });
    }

    #[test]
    fn expired_cookie_is_secure_only_for_https_forwarded_proto() {
        with_trust_proxy_env(true, None, || {
            let base = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![],
                body: Vec::new(),
            };
            let https = HttpRequest {
                headers: vec![("x-forwarded-proto".to_string(), "https".to_string())],
                ..base
            };
            let http = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("x-forwarded-proto".to_string(), "http".to_string())],
                body: Vec::new(),
            };

            let c1 = build_expired_cookie(&https);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));
            assert!(c1.contains("Max-Age=0"));
            assert!(c1.contains("Expires="));

            let c2 = build_expired_cookie(&http);
            assert!(!c2.contains("; Secure"));
        });
    }

    #[test]
    fn get_cookie_parses_from_cookie_header() {
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![("cookie".to_string(), "a=1; qf_admin_session=xyz; b=2".to_string())],
            body: Vec::new(),
        };
        assert_eq!(get_cookie(&req, "qf_admin_session").as_deref(), Some("xyz"));
        assert_eq!(get_cookie(&req, "missing"), None);
    }

    #[test]
    fn get_cookie_parses_from_multiple_cookie_headers() {
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![
                ("cookie".to_string(), "a=1".to_string()),
                ("cookie".to_string(), "qf_admin_session=xyz; b=2".to_string()),
            ],
            body: Vec::new(),
        };
        assert_eq!(get_cookie(&req, "qf_admin_session").as_deref(), Some("xyz"));
    }

    #[test]
    fn login_rate_limit_returns_429_on_6th_failed_attempt() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_auth_server(6, web_root, "123", false, 5);

        let req = || login_post("admin", "wrong");
        for _ in 0..5 {
            let resp = send_req(addr, &req());
            assert_eq!(parse_status(&resp), 401);
        }
        let resp = send_req(addr, &req());
        assert_eq!(parse_status(&resp), 429);
        let ra = parse_header(&resp, "Retry-After").expect("Retry-After");
        assert!(ra.parse::<u64>().unwrap_or(0) > 0);
    }

    #[test]
    fn admin_auth_rate_limit_returns_429_on_6th_failed_attempt() {
        let web_root = std::env::temp_dir();
        // 1 login + 6 admin-auth attempts
        let (addr, _thr) = start_auth_server(7, web_root, "123", false, 5);

        let login_req = login_post("admin", "123");
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let mk = |i: usize| {
            // Each request needs a unique body to avoid the replay guard
            // (which activates when Origin header is present).
            let body = format!(r#"{{"current_password":"wrong","new_password":"abcdef{i}"}}"#);
            format!(
                "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n\r\n{}",
                body.len(),
                cookie_header,
                csrf_header,
                body
            )
        };

        for i in 0..5 {
            let resp = send_req(addr, &mk(i));
            assert_eq!(parse_status(&resp), 401);
        }
        let resp = send_req(addr, &mk(99));
        assert_eq!(parse_status(&resp), 429);
        let ra = parse_header(&resp, "Retry-After").expect("Retry-After");
        assert!(ra.parse::<u64>().unwrap_or(0) > 0);
    }

    #[test]
    fn html_responses_include_csp_but_json_does_not() {
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "qf-admin-http-csp-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis()
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(dir.join("index.html"), "<html><body>ok</body></html>")
                .expect("write index");
            dir
        };
        // 1 request for "/" and 1 request for "/api/status"
        let _thr = spawn_unauth_server(listener, 2, web_root);

        let html = send_req(addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&html), 200);
        assert!(parse_header(&html, "Content-Security-Policy").is_some());

        let json = send_req(addr, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&json), 200);
        assert!(parse_header(&json, "Content-Security-Policy").is_none());
    }

    #[test]
    fn metrics_json_endpoint_returns_json_payload() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let json = send_req(addr, "GET /api/metrics/json HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&json), 200);
        assert!(json.contains("\"metrics\""));
    }

    #[test]
    fn health_endpoint_returns_ok_without_auth() {
        // The health endpoint must be accessible without authentication
        // so it can be used by Docker HEALTHCHECK and Kubernetes probes.
        let web_root = std::env::temp_dir();
        // Use an auth-enabled server to prove the endpoint is unauthenticated.
        let (addr, _thr) = start_auth_server(1, web_root, "secret-pw", false, 5);

        let resp = send_req(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&resp), 200);
        assert!(resp.contains("\"status\""));
        assert!(resp.contains("\"ok\""));
    }

    #[test]
    fn health_endpoint_rejects_non_get() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(2, web_root);

        let post = send_req(
            addr,
            "POST /api/health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(parse_status(&post), 405);

        let get = send_req(addr, "GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&get), 200);
    }

    #[test]
    fn qkey_ttl_too_large_returns_400() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = format!(r#"{{"ttl_seconds":{}}}"#, MAX_QKEY_TTL_SECS + 1);
        let req = unauthenticated_json_post("/api/qkey", &body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("TTL too large"));
    }

    #[test]
    fn qkey_create_rejects_invalid_json() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = "{not_json";
        let req = unauthenticated_json_post("/api/qkey", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn block_rejects_invalid_ip() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"ip":"not-an-ip"}"#;
        let req = unauthenticated_json_post("/api/block", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid IP"));
    }

    #[test]
    fn block_rejects_invalid_json() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = "{not_json";
        let req = unauthenticated_json_post("/api/block", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn unblock_rejects_invalid_json() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = "{not_json";
        let req = unauthenticated_json_post("/api/unblock", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn kick_rejects_invalid_client_id() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"id":"not-a-socket-addr"}"#;
        let req = unauthenticated_json_post("/api/kick", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid client id"));
    }

    #[test]
    fn qkey_revoke_rejects_invalid_id() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"id":"not-a-qkey-id"}"#;
        let req = unauthenticated_json_post("/api/qkeys/revoke", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid QKey id"));
    }

    #[test]
    fn qkey_revoke_rejects_missing_id() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"id":"   "}"#;
        let req = unauthenticated_json_post("/api/qkeys/revoke", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Missing QKey id"));
    }

    #[test]
    fn config_write_rejects_invalid_json() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = "{not_json";
        let req = config_post(body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn config_write_rejects_empty_config() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"config":"   "}"#;
        let req = config_post(body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Empty config"));
    }

    #[test]
    fn logging_config_rejects_invalid_json() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = "{not_json";
        let req = unauthenticated_json_post("/api/config/logging", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn qkey_revoke_accepts_uppercase_hex_id() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_unauth_server(1, web_root);

        let body = r#"{"id":"A1B2C3D4E5F6"}"#;
        let req = unauthenticated_json_post("/api/qkeys/revoke", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 200);
    }

    #[test]
    fn secure_cookie_is_set_only_for_forwarded_https() {
        with_trust_proxy_env(true, None, || {
            let web_root = std::env::temp_dir();
            // 2 login requests
            let (addr, _thr) = start_server_with_auth(2, web_root, test_auth("123", false), 5);

            let mk = |proto: Option<&str>| {
                let extra = proto.map(|p| format!("X-Forwarded-Proto: {p}")).unwrap_or_default();
                login_post_with_headers("admin", "123", &extra)
            };

            let http = send_req(addr, &mk(None));
            assert_eq!(parse_status(&http), 200);
            let set_cookie = parse_set_cookie(&http).expect("set-cookie");
            assert!(!set_cookie.to_ascii_lowercase().contains("secure"));

            let https = send_req(addr, &mk(Some("https")));
            assert_eq!(parse_status(&https), 200);
            let set_cookie = parse_set_cookie(&https).expect("set-cookie");
            assert!(set_cookie.to_ascii_lowercase().contains("secure"));
        });
    }

    #[test]
    fn password_change_lock_returns_423_for_api_except_admin_auth() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", true);
        // 1 login + 2 API calls
        let (addr, _thr) = start_server_with_auth(3, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let cfg_req = authenticated_get(&login, "/api/config");
        let cfg_resp = send_req(addr, &cfg_req);
        assert_eq!(parse_status(&cfg_resp), 423);

        let auth_req = authenticated_get(&login, "/api/admin/auth");
        let auth_resp = send_req(addr, &auth_req);
        assert_eq!(parse_status(&auth_resp), 200);
    }

    #[test]
    fn password_change_lock_allows_logout_and_clears_session() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", true);
        // login + logout + config (old cookie should be invalid)
        let (addr, _thr) = start_server_with_auth(3, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let logout_req = logout_post(&login);
        let logout_resp = send_req(addr, &logout_req);
        assert_eq!(parse_status(&logout_resp), 200);

        // Old cookie must no longer authorize.
        let cfg_req = authenticated_get(&login, "/api/config");
        let cfg_resp = send_req(addr, &cfg_req);
        assert_eq!(parse_status(&cfg_resp), 401);
    }

    #[test]
    fn admin_auth_allows_username_only_update_without_new_password_and_preserves_lock_flag() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", true).expect("auth fixture");
        // login + username update + auth status (GET)
        let (addr, _thr) = start_server_with_auth(3, web_root, Some(auth.clone()), 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_username":"root"}"#;
        let update_req = admin_auth_post(&login, body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 200);

        // Sessions are cleared and lock flag must remain true because no password was changed.
        let auth_req = authenticated_get(&login, "/api/admin/auth");
        let auth_resp = send_req(addr, &auth_req);
        assert_eq!(parse_status(&auth_resp), 401);

        let guard = auth.read().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.user(), "root");
        assert!(guard.requires_password_change());
    }

    #[test]
    fn admin_auth_rejects_username_too_long() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth, 5);

        let login = login_admin(addr, "123");

        let too_long_user = "u".repeat(65);
        let body =
            format!("{{\"current_password\":\"123\",\"new_username\":\"{}\"}}", too_long_user);
        let update_req = admin_auth_post(&login, &body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(
            update_resp.contains("Username too long")
                || update_resp.contains("Invalid JSON")
                || update_resp.contains("Invalid CSRF")
                || update_resp.contains("Missing CSRF token"),
            "unexpected admin/auth response: {update_resp}"
        );
    }

    #[test]
    fn admin_auth_post_rejects_missing_csrf_token() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let req = admin_auth_post_without_csrf(&login, body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Missing CSRF token"));
    }

    #[test]
    fn admin_auth_post_rejects_invalid_csrf_token() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, "g".repeat(CSRF_TOKEN_BYTES * 2));
        let req = admin_auth_post_with_csrf_and_headers(&login, &csrf_header, "", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Invalid CSRF token"));
    }

    #[test]
    fn admin_auth_post_rejects_cross_origin_request() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let req = admin_auth_post_with_headers(&login, "Origin: https://evil.example", body);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Invalid Origin"));
    }

    #[test]
    fn post_replay_is_rejected_for_same_origin_browser_request() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(3, web_root, auth.clone(), 5);

        let login = login_admin(addr, "123");

        let body = r#"{"config":"test = true"}"#;
        let req = authenticated_config_post_with_headers(&login, "Origin: http://localhost", body);
        let first = send_req(addr, &req);
        assert_eq!(parse_status(&first), 200);

        let second = send_req(addr, &req);
        assert_eq!(parse_status(&second), 403);
        assert!(second.contains("Replay request detected"));
    }

    #[test]
    fn admin_auth_rejects_username_with_control_characters() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth, 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_username":"root\nx"}"#;
        let update_req = admin_auth_post(&login, body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Username contains invalid characters"));
    }

    #[test]
    fn admin_auth_rejects_password_too_short() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth, 5);

        let login = login_admin(addr, "123");

        let body = r#"{"current_password":"123","new_password":"abc"}"#;
        let update_req = admin_auth_post(&login, body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Password too short (min 6 chars)"));
    }

    #[test]
    fn admin_auth_rejects_password_too_long() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        let (addr, _thr) = start_server_with_auth(2, web_root, auth, 5);

        let login = login_admin(addr, "123");

        let long_pw = "x".repeat(257);
        let body = format!("{{\"current_password\":\"123\",\"new_password\":\"{}\"}}", long_pw);
        let update_req = admin_auth_post(&login, &body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Password too long"));
    }

    #[test]
    fn password_change_lock_is_removed_after_admin_auth_update_and_relogin() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", true);
        // login + admin/auth update + config(old cookie) + login(new pw) + config(new cookie)
        let (addr, _thr) = start_server_with_auth(5, web_root, auth.clone(), 5);

        let login1 = login_admin(addr, "123");

        let update_body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let update_req = admin_auth_post(&login1, update_body);
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 200);

        // All sessions are cleared as part of the credential update.
        let cfg_old_req = authenticated_get(&login1, "/api/config");
        let cfg_old_resp = send_req(addr, &cfg_old_req);
        assert_eq!(parse_status(&cfg_old_resp), 401);

        let login2 = login_admin(addr, "abcdef");

        // Lock must be gone now: config should be readable.
        let cfg_new_req = authenticated_get(&login2, "/api/config");
        let cfg_new_resp = send_req(addr, &cfg_new_req);
        assert_eq!(parse_status(&cfg_new_resp), 200);
    }

    #[test]
    fn password_change_lock_does_not_leak_to_unauthorized_callers() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", true);
        // Single unauthorized API call.
        let (addr, _thr) = start_server_with_auth(1, web_root, auth.clone(), 5);

        let cfg_req = "GET /api/config HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let cfg_resp = send_req(addr, cfg_req);
        assert_eq!(parse_status(&cfg_resp), 401);
    }

    #[test]
    fn login_rate_limit_is_cleared_on_successful_login() {
        let web_root = std::env::temp_dir();
        let auth = test_auth("123", false);
        // Use a small threshold to make the test short and deterministic.
        // 1st fail, 1 success, then 3 fails (last one should be 429).
        let (addr, _thr) = start_server_with_auth(5, web_root, auth, 2);

        let fail = login_post("admin", "wrong");
        let ok = login_post("admin", "123");

        let r1 = send_req(addr, &fail);
        assert_eq!(parse_status(&r1), 401);

        // Success should clear rate limiter for this IP.
        let r2 = send_req(addr, &ok);
        assert_eq!(parse_status(&r2), 200);

        // After clearing, we should get two more 401s before a 429.
        let r3 = send_req(addr, &fail);
        assert_eq!(parse_status(&r3), 401);
        let r4 = send_req(addr, &fail);
        assert_eq!(parse_status(&r4), 401);
        let r5 = send_req(addr, &fail);
        assert_eq!(parse_status(&r5), 429);
    }

    #[test]
    fn login_response_includes_requires_password_change_flag() {
        let web_root = std::env::temp_dir();
        let (addr, thr) = start_auth_server(1, web_root, "123", true, 5);

        let req = login_post("admin", "123");
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 200);
        assert!(parse_csrf_token(&resp).is_some());
        assert!(resp.contains("\"requires_password_change\":true"));

        thr.join().expect("server thread");
    }

    #[test]
    fn login_and_admin_auth_rate_limits_are_separate_namespaces() {
        let web_root = std::env::temp_dir();
        // login(ok) + login(fail) + login(fail) + login(429) + admin-auth(fail) + admin-auth(fail) + admin-auth(429)
        let (addr, thr) = start_auth_server(7, web_root, "123", false, 2);

        let mk_login = |pw: &str| login_post("admin", pw);

        let login = login_admin(addr, "123");

        let fail = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&fail), 401);
        let fail2 = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&fail2), 401);

        // Third failure should be rate limited (429).
        let limited = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&limited), 429);

        let mk_admin_auth = |i: usize| {
            // Each request needs a unique body to avoid the replay guard
            // (which activates when Origin header is present).
            let body = format!(r#"{{"current_password":"wrong","new_username":"root{i}"}}"#);
            admin_auth_post(&login, &body)
        };

        // Admin auth uses a separate key namespace and should not be 429 yet.
        let a1 = send_req(addr, &mk_admin_auth(1));
        assert_eq!(parse_status(&a1), 401);
        let a2 = send_req(addr, &mk_admin_auth(2));
        assert_eq!(parse_status(&a2), 401);
        let a3 = send_req(addr, &mk_admin_auth(3));
        assert_eq!(parse_status(&a3), 429);

        thr.join().expect("server thread");
    }

    #[test]
    fn static_assets_rejects_path_traversal_with_403() {
        let web_root = {
            let root = std::env::temp_dir()
                .join(format!("qf-admin-webroot-traversal-{}", current_epoch_secs()));
            let _ = std::fs::create_dir_all(&root);
            let index = root.join("index.html");
            let _ = std::fs::write(&index, "<html>ok</html>");
            root
        };

        let (addr, _thr) = start_short_unauth_server(1, web_root);

        // Attempt to escape web_root via parent directory traversal.
        let req = "GET /../Cargo.toml HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 403);
    }

    #[test]
    fn static_assets_serves_index_for_spa_routes() {
        let web_root = {
            let root =
                std::env::temp_dir().join(format!("qf-admin-webroot-spa-{}", current_epoch_secs()));
            let _ = std::fs::create_dir_all(&root);
            let index = root.join("index.html");
            let _ = std::fs::write(&index, "<html>index</html>");
            root
        };

        let (addr, _thr) = start_short_unauth_server(1, web_root);

        // Non-file route should fall back to index.html (SPA refresh support).
        let req = "GET /logs HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 200);
        assert!(resp.contains("<html>index</html>"));
    }

    #[test]
    fn oversized_payload_returns_413() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = format!(
            "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 413);
    }

    #[test]
    fn oversized_headers_return_431() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let large_header_value = "a".repeat(MAX_HEADER_BYTES + 128);
        let req =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Fill: {}\r\n\r\n", large_header_value);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 431);
    }

    #[test]
    fn invalid_content_length_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = raw_login_post("Content-Length: nope", "{}");
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = raw_login_post("Content-Length: 1\r\nContent-Length: 1", "{}");
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn request_body_shorter_than_content_length_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = raw_login_post(
            "Content-Length: 20\r\nContent-Type: application/json",
            "{\"username\":\"ad",
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_http_version_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_http_version_schema_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "GET / FTP/1.0\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_request_line_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "BADLINE\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_method_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "GE T / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_path_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "GET api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_backslash_in_path_is_rejected() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_short_unauth_server(1, web_root);

        let req = "GET /api\\status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn login_rate_limit_prunes_old_attempts_without_sleep() {
        let mut limiter = LoginRateLimiter::new(5, 60);
        let ip = "127.0.0.1";
        for _ in 0..5 {
            limiter.record_failure(ip);
        }
        assert!(limiter.is_locked(ip));

        // Force the timestamp into the past beyond lockout. This avoids sleeping and
        // makes prune behavior deterministic.
        if let Some((_count, ts)) = limiter.attempts.get_mut(ip) {
            *ts = Instant::now() - Duration::from_secs(61);
        } else {
            panic!("missing attempts entry");
        }
        assert!(!limiter.is_locked(ip));
    }

    #[test]
    fn normalize_ttl_maps_zero_and_none_to_none() {
        assert_eq!(normalize_ttl(None), None);
        assert_eq!(normalize_ttl(Some(0)), None);
        assert_eq!(normalize_ttl(Some(1)), Some(1));
        assert_eq!(normalize_ttl(Some(MAX_QKEY_TTL_SECS)), Some(MAX_QKEY_TTL_SECS));
    }

    #[test]
    fn normalize_qkey_id_trims_and_lowercases() {
        assert_eq!(normalize_qkey_id("  A1B2C3D4E5F6  "), Some("a1b2c3d4e5f6".to_string()));
        assert_eq!(normalize_qkey_id("short"), None);
        assert_eq!(normalize_qkey_id("a1b2c3d4e5f6aa"), None);
        assert_eq!(normalize_qkey_id("a1b2c3d4e5g6"), None);
    }

    #[tokio::test]
    async fn idle_admin_server_observes_shutdown_without_new_connection() {
        let server = AdminHttpServer::new(
            "127.0.0.1:0".parse().unwrap(),
            std::env::temp_dir(),
            None,
            None,
            test_handler(),
        );
        let shutdown = server.shutdown_signal();
        let task = tokio::spawn(async move { server.run().await });
        tokio::time::sleep(Duration::from_millis(20)).await;

        shutdown.store(true, Ordering::Relaxed);

        let result = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("idle admin server must observe shutdown promptly")
            .expect("admin server task must not panic");
        assert!(result.is_ok(), "admin server shutdown must be clean: {result:?}");
    }
}

fn handle_api(
    req: HttpRequest,
    handler: Arc<dyn AdminHttpHandler>,
    peer: Option<SocketAddr>,
) -> Response<Full<Bytes>> {
    if req.method == "POST" {
        if let Some(id) =
            req.path.strip_prefix("/api/clients/").and_then(|rest| rest.strip_suffix("/kick"))
        {
            let raw = id.trim();
            if raw.is_empty() {
                return json_response(400, &AdminResponse::error("Missing client id"));
            }
            let Some(id) = normalize_client_id(raw) else {
                return json_response(400, &AdminResponse::error("Invalid client id"));
            };
            let resp = handler.handle_kick(&id);
            log_action(peer, "kick", &format!("id={}", id), resp.success);
            return admin_json_response(&resp);
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => admin_json_response(&handler.handle_status()),
        ("GET", "/api/clients") => {
            let clients = handler.handle_list_clients();
            json_response(
                200,
                &AdminResponse::ok_with_data(
                    serde_json::to_value(clients).unwrap_or_else(|_| serde_json::json!([])),
                ),
            )
        }
        ("GET", "/api/blocked") => admin_json_response(&handler.handle_list_blocked_ips()),
        ("GET", "/api/config") => admin_json_response(&handler.handle_read_config()),
        ("GET", "/api/metrics") => text_response(200, &handler.handle_metrics_text()),
        ("GET", "/api/metrics/json") => admin_json_response(&handler.handle_metrics_json()),
        ("GET", "/api/qkeys") => admin_json_response(&handler.handle_list_qkeys()),
        ("POST", "/api/kick") => {
            let payload: IdPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            let raw = payload.id.trim();
            if raw.is_empty() {
                return json_response(400, &AdminResponse::error("Missing client id"));
            }
            let Some(id) = normalize_client_id(raw) else {
                return json_response(400, &AdminResponse::error("Invalid client id"));
            };
            let resp = handler.handle_kick(&id);
            log_action(peer, "kick", &format!("id={}", id), resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/block") => {
            let payload: IpPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            let Some(ip) = normalize_ip_for_policy(&payload.ip) else {
                return json_response(400, &AdminResponse::error("Invalid IP"));
            };
            let resp = handler.handle_block(&ip);
            log_action(peer, "block", &format!("ip={}", ip), resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/unblock") => {
            let payload: IpPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            let Some(ip) = normalize_ip_for_policy(&payload.ip) else {
                return json_response(400, &AdminResponse::error("Invalid IP"));
            };
            let resp = handler.handle_unblock(&ip);
            log_action(peer, "unblock", &format!("ip={}", ip), resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/reload") => {
            let resp = handler.handle_reload();
            log_action(peer, "reload", "-", resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/drain") => {
            if !admin_shutdown_enabled() {
                return text_response(404, "Not Found");
            }
            let resp = handler.handle_drain();
            log_action(peer, "drain", "-", resp.success);
            admin_json_response(&resp)
        }
        ("GET", "/api/drain/status") => admin_json_response(&handler.handle_drain_status()),
        ("POST", "/api/qkey") => {
            let payload: QKeyCreatePayload = if req.body.is_empty() {
                QKeyCreatePayload {
                    name: None,
                    port: None,
                    ttl_seconds: None,
                    stealth: None,
                    fec: None,
                    sni_strategy: None,
                    sni_domain: None,
                }
            } else {
                match serde_json::from_slice(&req.body) {
                    Ok(p) => p,
                    Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
                }
            };
            if let Some(ttl) = payload.ttl_seconds {
                if ttl > MAX_QKEY_TTL_SECS {
                    return json_response(
                        400,
                        &AdminResponse::error(format!(
                            "TTL too large (max {} seconds)",
                            MAX_QKEY_TTL_SECS
                        )),
                    );
                }
            }
            if let Some(port) = payload.port {
                if port == 0 {
                    return json_response(
                        400,
                        &AdminResponse::error("Port must be between 1 and 65535"),
                    );
                }
            }
            let req = IssueQKeyRequest {
                name: payload.name,
                port: payload.port,
                ttl_seconds: normalize_ttl(payload.ttl_seconds),
                stealth: payload.stealth,
                fec: payload.fec,
                sni_strategy: payload.sni_strategy,
                sni_domain: payload.sni_domain,
            };
            let resp = handler.handle_qkey(req);
            log_action(peer, "qkey", "-", resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/qkeys/revoke") => {
            let payload: QKeyRevokePayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            if payload.id.trim().is_empty() {
                return json_response(400, &AdminResponse::error("Missing QKey id"));
            }
            let Some(id) = normalize_qkey_id(&payload.id) else {
                return json_response(400, &AdminResponse::error("Invalid QKey id"));
            };
            let resp = handler.handle_revoke_qkey(&id);
            log_action(peer, "qkey-revoke", &format!("id={}", id), resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/shutdown") => {
            if !admin_shutdown_enabled() {
                return text_response(404, "Not Found");
            }
            let resp = handler.handle_shutdown();
            log_action(peer, "shutdown", "-", resp.success);
            admin_json_response(&resp)
        }
        ("POST", "/api/config") => {
            let payload: ConfigPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            if payload.config.trim().is_empty() {
                return json_response(400, &AdminResponse::error("Empty config"));
            }
            let resp = handler.handle_write_config(&payload.config);
            log_action(peer, "config", &format!("bytes={}", payload.config.len()), resp.success);
            admin_json_response(&resp)
        }
        ("GET", "/api/config/logging") => admin_json_response(&handler.handle_get_logging_config()),
        ("POST", "/api/config/logging") => {
            let payload: LoggingModePayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return json_response(400, &AdminResponse::error("Invalid JSON")),
            };
            let resp = handler.handle_set_logging_config(&payload.mode);
            log_action(peer, "logging", &format!("mode={}", payload.mode), resp.success);
            admin_json_response(&resp)
        }
        ("GET", "/api/logs") | ("GET", "/api/logs?") => {
            admin_json_response(&handler.handle_get_logs(0))
        }
        ("GET", path) if path.starts_with("/api/logs?") => {
            let cursor = path
                .split('?')
                .nth(1)
                .and_then(|qs| {
                    qs.split('&')
                        .find(|p| p.starts_with("cursor="))
                        .and_then(|p| p.strip_prefix("cursor="))
                        .and_then(|v| v.parse::<u64>().ok())
                })
                .unwrap_or(0);
            admin_json_response(&handler.handle_get_logs(cursor))
        }
        ("POST", "/api/logs/clear") => {
            let resp = handler.handle_clear_logs();
            if !resp.success {
                log_action(peer, "logs-clear", "-", false);
            }
            admin_json_response(&resp)
        }
        _ => text_response(404, "Not Found"),
    }
}

fn get_cookie(req: &HttpRequest, name: &str) -> Option<String> {
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("cookie") {
            for part in v.split(';') {
                let trimmed = part.trim();
                if let Some(value) = trimmed.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn build_session_cookie(session_id: &str, req: &HttpRequest) -> String {
    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_COOKIE, session_id, SESSION_TTL_SECS
    );
    if is_secure_request(req) {
        cookie.push_str("; Secure");
    }
    cookie
}

fn build_expired_cookie(req: &HttpRequest) -> String {
    let mut cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        SESSION_COOKIE
    );
    if is_secure_request(req) {
        cookie.push_str("; Secure");
    }
    cookie
}

fn is_secure_request(req: &HttpRequest) -> bool {
    if !trust_proxy_enabled() {
        return false;
    }
    req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("x-forwarded-proto") && v.eq_ignore_ascii_case("https")
    })
}

fn admin_shutdown_enabled() -> bool {
    std::env::var("QUICFUSCATE_ENABLE_ADMIN_SHUTDOWN")
        .map(|v| v.trim() == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn admin_response_status(resp: &AdminResponse) -> u16 {
    if resp.success {
        return 200;
    }
    let msg = resp.message.as_deref().unwrap_or("").to_ascii_lowercase();
    if msg.contains("not found") {
        404
    } else if msg.contains("invalid") || msg.contains("missing") {
        400
    } else if msg.contains("conflict") || msg.contains("already") || msg.contains("exists") {
        409
    } else {
        400
    }
}

fn normalize_csrf_token(raw: &str) -> Option<String> {
    let token = raw.trim();
    if token.len() != CSRF_TOKEN_BYTES * 2 {
        return None;
    }
    if !token.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(token.to_ascii_lowercase())
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff: u8 = 0;
    let mut i = 0usize;
    let len = left.len().max(right.len());
    while i < len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= a ^ b;
        i += 1;
    }
    if left.len() != right.len() {
        diff |= 1;
    }
    diff == 0
}

fn request_replay_fingerprint(req: &HttpRequest, csrf_token: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(req.method.as_bytes());
    h.update(b"|");
    h.update(req.path.as_bytes());
    h.update(b"|");
    h.update(&req.body);
    h.update(b"|");
    h.update(csrf_token.as_bytes());
    if let Some(nonce) = header_value(req, CSRF_NONCE_HEADER) {
        h.update(b"|");
        h.update(nonce.as_bytes());
    }
    let digest = h.finalize();
    u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
}

fn validate_csrf_request(
    req: &HttpRequest,
    sessions: &Arc<Mutex<SessionStore>>,
) -> Option<&'static str> {
    if req.method != "POST" {
        return None;
    }
    if !is_same_origin_request(req) {
        crate::telemetry::ADMIN_ORIGIN_REJECT_TOTAL.inc();
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Invalid Origin");
    }

    let Some(session_id) = get_cookie(req, SESSION_COOKIE) else {
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Missing session");
    };

    let raw_token = match header_value(req, CSRF_TOKEN_HEADER) {
        Some(v) => v,
        None => {
            crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
            return Some("Missing CSRF token");
        }
    };

    let Some(token) = normalize_csrf_token(raw_token) else {
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Invalid CSRF token");
    };

    let has_origin_header = header_value(req, "origin").is_some();
    let replay_fingerprint = request_replay_fingerprint(req, &token);
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    match store.validate_post_guard(&session_id, &token, replay_fingerprint, has_origin_header) {
        Ok(()) => None,
        Err(msg) => {
            crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
            Some(msg)
        }
    }
}

fn is_same_origin_request(req: &HttpRequest) -> bool {
    let Some(origin_raw) = header_value(req, "origin") else {
        // POST requests MUST include an Origin header for CSRF protection.
        // Allowing missing Origin would let attackers bypass CSRF by simply
        // omitting the header (e.g. via curl or a crafted form submission).
        // Legitimate browsers always send Origin on cross-origin POSTs, and
        // same-origin POSTs from fetch/XHR also include it.
        return false;
    };
    let origin = origin_raw.trim();
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some((_, rest)) = origin.split_once("://") else {
        return false;
    };
    let origin_host = rest.split('/').next().unwrap_or("").trim();
    if origin_host.is_empty() {
        return false;
    }
    let host = match header_value(req, "host") {
        Some(v) => v.trim(),
        None => return false,
    };
    origin_host.eq_ignore_ascii_case(host)
}

fn hash_password(password: &str) -> Result<String, String> {
    let mut salt_bytes = [0u8; 16];
    crate::rng::fill_secure(&mut salt_bytes).map_err(|e| format!("salt RNG failed: {}", e))?;
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|e| format!("salt encoding failed: {}", e))?;
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("admin password hash failed: {}", e))
}

fn verify_password(password_phc: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(password_phc) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}
