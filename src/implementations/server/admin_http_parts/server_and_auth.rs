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
use super::BandwidthPolicy;

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
        // Unauthenticated health probe for external liveness/readiness checks.
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
