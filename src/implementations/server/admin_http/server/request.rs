use super::*;

mod api_handlers;
pub(super) use api_handlers::*;
#[derive(Debug)]
pub(super) struct HttpRequest {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
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

pub(super) fn normalize_ttl(ttl_seconds: Option<u64>) -> Option<u64> {
    match ttl_seconds {
        Some(0) | None => None,
        Some(v) => Some(v),
    }
}

pub(super) fn normalize_qkey_id(raw: &str) -> Option<String> {
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

pub(super) fn text_response(status: u16, body: &str) -> Response<Full<Bytes>> {
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
    let header_size: usize =
        req.headers().iter().map(|(k, v)| k.as_str().len() + v.len() + 4).sum();
    if header_size > MAX_HEADER_BYTES {
        return Err(text_response(431, "Request Header Fields Too Large"));
    }

    // Content-Length is an early rejection, not the boundary. A duplicate or unparsable value is
    // refused outright: disagreeing lengths are a request-smuggling shape, and treating an
    // unparsable one as zero would silently hand an unbounded body to the reader below.
    let declared_length = match parse_content_length(req.headers()) {
        Ok(length) => length,
        Err(()) => return Err(text_response(400, "Bad Request")),
    };
    if declared_length.is_some_and(|length| length > MAX_BODY_BYTES) {
        return Err(text_response(413, "Payload Too Large"));
    }

    let (parts, body) = req.into_parts();
    let body_bytes = match read_body_bounded(body, MAX_BODY_BYTES, declared_length).await {
        Ok(bytes) => bytes,
        Err(BodyReadError::TooLarge) => return Err(text_response(413, "Payload Too Large")),
        Err(BodyReadError::Transport) => return Err(text_response(400, "Bad Request")),
    };

    Ok(hyper_to_http_request(&parts, body_bytes))
}

/// Why a bounded body read stopped.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BodyReadError {
    /// The body exceeded the configured cap while streaming.
    TooLarge,
    /// The peer or transport failed before the body was complete.
    Transport,
}

/// Resolve the declared body length.
///
/// Returns `Ok(None)` when the header is absent, which is legitimate for chunked and lengthless
/// requests. Returns `Err(())` for a value that cannot be parsed and for multiple headers that do
/// not agree, since a disagreeing pair is a request-smuggling shape rather than a length.
pub(super) fn parse_content_length(headers: &hyper::HeaderMap) -> Result<Option<usize>, ()> {
    let mut resolved: Option<usize> = None;
    for value in headers.get_all("content-length") {
        let parsed: usize = value.to_str().map_err(|_| ())?.trim().parse().map_err(|_| ())?;
        match resolved {
            Some(existing) if existing != parsed => return Err(()),
            _ => resolved = Some(parsed),
        }
    }
    Ok(resolved)
}

/// Append one body chunk, refusing to grow the accumulator past `limit`.
///
/// Split out from the async reader so the bound itself is directly testable: the defect this
/// closes is not the status code, which the previous post-collection check also produced, but that
/// the whole body was allocated before any check ran. The check must happen before the append.
pub(super) fn append_bounded(
    collected: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), BodyReadError> {
    if collected.len().saturating_add(chunk.len()) > limit {
        return Err(BodyReadError::TooLarge);
    }
    collected.extend_from_slice(chunk);
    Ok(())
}

/// Read a request body, refusing to accumulate more than `limit` bytes.
///
/// `Incoming::collect()` buffers the whole body before any size check can run, so `Content-Length`
/// was the only guard and a chunked or lengthless request could hold memory until the operation
/// timeout regardless of the configured cap. Frames are consumed one at a time and the accumulator
/// is checked before each append, so peak allocation is bounded by `limit` plus one frame.
///
/// `declared_length` only sizes the initial reservation; it is never trusted as the actual length.
async fn read_body_bounded(
    mut body: Incoming,
    limit: usize,
    declared_length: Option<usize>,
) -> Result<Vec<u8>, BodyReadError> {
    let reserve = declared_length.unwrap_or(0).min(limit);
    let mut collected: Vec<u8> = Vec::with_capacity(reserve);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Transport)?;
        let Some(chunk) = frame.data_ref() else {
            // Trailers carry no body bytes.
            continue;
        };
        append_bounded(&mut collected, chunk, limit)?;
    }
    Ok(collected)
}

fn admin_operation_timeout_response() -> Response<Full<Bytes>> {
    text_response(504, "Admin operation timed out")
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_request_with_deadline(
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
    environment: Arc<AdminHttpEnvironment>,
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
                environment.as_ref(),
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
pub(super) async fn handle_request(
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
    let environment =
        AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture());
    handle_http_request_sync(
        req,
        web_root,
        auth,
        auth_path,
        sessions,
        rate_limiter,
        handler,
        peer,
        &environment,
    )
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
    environment: &AdminHttpEnvironment,
) -> Response<Full<Bytes>> {
    if req.path.starts_with("/api/") {
        if req.path == "/api/login" {
            return handle_login(req, auth.as_ref(), sessions, rate_limiter, peer, environment);
        }
        if req.path == "/api/logout" {
            return handle_logout(&req, auth.as_ref(), &sessions, peer, environment);
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
                environment,
            );
        }
        return handle_api(req, handler, peer, environment);
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

pub(super) fn peer_is_trusted_proxy(
    peer: Option<SocketAddr>,
    environment: &AdminHttpEnvironment,
) -> bool {
    let peer_ip = match peer {
        Some(addr) => addr.ip(),
        None => return false,
    };
    let trusted = &environment.trusted_proxy_ips;
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

pub(super) fn client_ip_for_rate_limit(
    peer: Option<SocketAddr>,
    req: &HttpRequest,
    environment: &AdminHttpEnvironment,
) -> String {
    if environment.trust_proxy && peer_is_trusted_proxy(peer, environment) {
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
    normalize_admin_ip(raw)
}

fn normalize_client_id(raw: &str) -> Option<String> {
    normalize_admin_client_id(raw)
}

fn log_action(peer: Option<SocketAddr>, action: &str, detail: &str, success: bool) {
    let peer = format_peer(peer);
    if success {
        log::info!("admin action={} detail={} peer={} status=ok", action, detail, peer);
    } else {
        log::warn!("admin action={} detail={} peer={} status=err", action, detail, peer);
    }
}

pub(super) fn handle_login(
    req: HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
    environment: &AdminHttpEnvironment,
) -> Response<Full<Bytes>> {
    let Some(auth) = auth else {
        return json_response(500, &AdminResponse::error("Authentication not configured"));
    };
    if req.method != "POST" {
        return text_response(405, "Method Not Allowed");
    }
    let peer_ip = client_ip_for_rate_limit(peer, &req, environment);
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
        match store.create() {
            Ok(session) => session,
            Err(SessionCreateError::Capacity) => {
                log_action(peer, "login", "SESSION_CAPACITY", false);
                return json_response(
                    429,
                    &AdminResponse::error(
                        "Maximum active admin sessions reached. Log out or wait for expiry.",
                    ),
                );
            }
        }
    };
    let cookie = build_session_cookie(&session_id, &req, environment);
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
    environment: &AdminHttpEnvironment,
) -> Response<Full<Bytes>> {
    if auth.is_none() {
        return admin_json_response(&AdminResponse::ok_with_message("Logged out"));
    }
    if let Some(session_id) = get_cookie(req, SESSION_COOKIE) {
        let mut store = sessions.lock();
        store.remove(&session_id);
    }
    let cookie = build_expired_cookie(req, environment);
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

pub(super) fn handle_admin_auth(
    req: HttpRequest,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<&Path>,
    sessions: &Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
    environment: &AdminHttpEnvironment,
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
    let peer_ip = client_ip_for_rate_limit(peer, &req, environment);
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
        (guard.user().to_string(), guard.verify_password_only(payload.current_password.as_str()))
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
            log::error!("admin auth durable update failed ({}): {}", path.display(), error);
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

    let cookie = build_expired_cookie(&req, environment);
    log_action(peer, "admin-auth", &format!("user={}", old_user), true);
    json_response_with_headers(
        200,
        &AdminResponse::ok_with_message("Admin credentials updated"),
        vec![("Set-Cookie".to_string(), cookie)],
    )
}
