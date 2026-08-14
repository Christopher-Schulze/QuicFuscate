use super::*;
use std::io::{Read, Write};
use std::net::{TcpListener as StdTcpListener, TcpStream as StdTcpStream};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct TestHandler {
    status_delay: Duration,
    panic_on_status: bool,
    config_delay: Duration,
    config_completed: Option<Arc<AtomicBool>>,
}

impl TestHandler {
    fn new(status_delay: Duration) -> Self {
        Self {
            status_delay,
            panic_on_status: false,
            config_delay: Duration::ZERO,
            config_completed: None,
        }
    }

    fn with_config_delay(delay: Duration) -> (Self, Arc<AtomicBool>) {
        let completed = Arc::new(AtomicBool::new(false));
        (
            Self {
                status_delay: Duration::ZERO,
                panic_on_status: false,
                config_delay: delay,
                config_completed: Some(Arc::clone(&completed)),
            },
            completed,
        )
    }

    fn panicking() -> Self {
        Self {
            status_delay: Duration::ZERO,
            panic_on_status: true,
            config_delay: Duration::ZERO,
            config_completed: None,
        }
    }
}

impl AdminHttpHandler for TestHandler {
    fn handle_status(&self) -> AdminResponse {
        if !self.status_delay.is_zero() {
            thread::sleep(self.status_delay);
        }
        if self.panic_on_status {
            panic!("test admin handler panic");
        }
        AdminResponse::ok()
    }
    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        vec![]
    }
    fn handle_get_client_bandwidth(&self, _id: &str) -> AdminResponse {
        AdminResponse::ok()
    }
    fn handle_set_client_bandwidth(&self, _id: &str, _policy: BandwidthPolicy) -> AdminResponse {
        AdminResponse::ok()
    }
    fn handle_reset_client_quota(&self, _id: &str) -> AdminResponse {
        AdminResponse::ok()
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
        if !self.config_delay.is_zero() {
            thread::sleep(self.config_delay);
        }
        if let Some(completed) = self.config_completed.as_ref() {
            completed.store(true, Ordering::Release);
        }
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
    fn handle_rotate_logs(&self) -> AdminResponse {
        AdminResponse::ok_with_message("Log rotation requested")
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

fn authenticated_post(login: &AdminLoginSession, path: &str) -> String {
    format!(
            "POST {} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\n{}\r\n{}\r\n\r\n",
            path,
            login.cookie_header,
            login.csrf_header(),
        )
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
    Some(Arc::new(RwLock::new(
        AdminAuth::new("admin".to_string(), password.to_string(), requires_password_change)
            .expect("auth fixture"),
    )))
}

fn test_sessions() -> Arc<Mutex<SessionStore>> {
    shared_session_store(Duration::from_secs(3600), &ProtocolClock::default())
}

fn test_short_sessions() -> Arc<Mutex<SessionStore>> {
    shared_session_store(Duration::from_secs(60), &ProtocolClock::default())
}

fn test_rate_limiter(max_attempts: u32) -> Arc<Mutex<LoginRateLimiter>> {
    shared_login_rate_limiter(max_attempts, 60, &ProtocolClock::default())
}

fn test_handler() -> Arc<dyn AdminHttpHandler> {
    Arc::new(TestHandler::new(Duration::ZERO))
}

fn slow_test_handler(delay: Duration) -> Arc<dyn AdminHttpHandler> {
    Arc::new(TestHandler::new(delay))
}

fn slow_persistence_test_handler(delay: Duration) -> (Arc<dyn AdminHttpHandler>, Arc<AtomicBool>) {
    let (handler, completed) = TestHandler::with_config_delay(delay);
    (Arc::new(handler), completed)
}

fn panicking_test_handler() -> Arc<dyn AdminHttpHandler> {
    Arc::new(TestHandler::panicking())
}

fn test_auth_root(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_nanos();
    let root =
        std::env::temp_dir().join(format!("qf-admin-auth-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&root).expect("auth test root");
    root
}

fn admin_auth_request(body: &str) -> HttpRequest {
    HttpRequest {
        method: "POST".to_string(),
        path: "/api/admin/auth".to_string(),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
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
    let thr =
        spawn_auth_server(listener, n, web_root, password, requires_password_change, max_attempts);
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
    spawn_server(listener, n, web_root, None, test_sessions(), test_rate_limiter(5), test_handler())
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
    let _guard = crate::env_utils::test_support::acquire_env_lock();

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

mod auth_and_static;

#[path = "tests/protocol_and_runtime.rs"]
mod protocol_and_runtime;
