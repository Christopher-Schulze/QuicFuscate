#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
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
        fn handle_set_client_bandwidth(
            &self,
            _id: &str,
            _policy: BandwidthPolicy,
        ) -> AdminResponse {
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
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "qf-admin-auth-{label}-{}-{nanos}",
            std::process::id()
        ));
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
            let environment = AdminHttpEnvironment::from_snapshot(
                &crate::env_utils::EnvSnapshot::capture(),
            );
            assert_eq!(
                client_ip_for_rate_limit(Some(peer), &req, &environment),
                "127.0.0.1"
            );
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
            let environment = AdminHttpEnvironment::from_snapshot(
                &crate::env_utils::EnvSnapshot::capture(),
            );
            assert_eq!(
                client_ip_for_rate_limit(Some(peer), &req, &environment),
                "1.2.3.4"
            );
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
            let environment = AdminHttpEnvironment::from_snapshot(
                &crate::env_utils::EnvSnapshot::capture(),
            );
            assert_eq!(
                client_ip_for_rate_limit(Some(peer), &req, &environment),
                "127.0.0.1"
            );
        });
    }

    #[test]
    fn malformed_trusted_proxy_list_fails_closed_as_one_snapshot() {
        let environment = AdminHttpEnvironment::from_snapshot(
            &crate::env_utils::EnvSnapshot::from_pairs([
                ("QUICFUSCATE_TRUST_PROXY", "true"),
                ("QUICFUSCATE_TRUSTED_PROXY_IPS", "127.0.0.1,not-an-ip"),
            ]),
        );
        let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
        assert!(!peer_is_trusted_proxy(Some(peer), &environment));
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

            let environment = AdminHttpEnvironment::from_snapshot(
                &crate::env_utils::EnvSnapshot::capture(),
            );
            let c1 = build_session_cookie("sid", &https, &environment);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));

            let c2 = build_session_cookie("sid", &http, &environment);
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

            let environment = AdminHttpEnvironment::from_snapshot(
                &crate::env_utils::EnvSnapshot::capture(),
            );
            let c1 = build_expired_cookie(&https, &environment);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));
            assert!(c1.contains("Max-Age=0"));
            assert!(c1.contains("Expires="));

            let c2 = build_expired_cookie(&http, &environment);
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
        // so it can be used by external liveness/readiness probes.
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
    fn authenticated_log_rotation_route_reaches_handler() {
        let web_root = std::env::temp_dir();
        let (addr, _thr) = start_server_with_auth(2, web_root, test_auth("123", false), 5);
        let login = login_admin(addr, "123");

        let response = send_req(addr, &authenticated_post(&login, "/api/logs/rotate"));
        assert_eq!(parse_status(&response), 200);
        assert!(response.contains("Log rotation requested"));
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

        let guard = auth.read();
        assert_eq!(guard.user(), "root");
        assert!(guard.requires_password_change());
    }

    #[test]
    fn admin_auth_initialization_rejects_hash_and_invalid_verifier_failures() {
        let hash_error = AdminAuth::new_with_hasher(
            "admin".to_string(),
            "password".to_string(),
            false,
            |_| Err("entropy unavailable".to_string()),
        )
        .expect_err("hash failure must abort auth construction");
        assert_eq!(hash_error, AdminAuthError::PasswordHash("entropy unavailable".to_string()));

        let verifier_error = AdminAuth::new_with_hasher(
            "admin".to_string(),
            "password".to_string(),
            false,
            |_| Ok("not-a-password-hash".to_string()),
        )
        .expect_err("invalid verifier must abort auth construction");
        assert!(matches!(verifier_error, AdminAuthError::InvalidVerifier(_)));
    }

    #[test]
    fn admin_http_server_rejects_auth_persistence_failure_before_listener_start() {
        let root = test_auth_root("startup");
        let parent_file = root.join("parent-file");
        std::fs::write(&parent_file, b"not a directory").expect("parent fixture");
        let auth_path = parent_file.join("admin-auth.json");
        let auth = AdminAuth::new("admin".to_string(), "123456".to_string(), false)
            .expect("auth fixture");

        let result = AdminHttpServer::new(
            "127.0.0.1:0".parse().expect("address"),
            root.clone(),
            Some(auth),
            Some(auth_path),
            test_handler(),
        );
        let error = result.err().expect("startup must fail before listener publication");
        assert!(!error.to_string().is_empty());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn admin_auth_failed_atomic_update_preserves_memory_and_sessions() {
        let root = test_auth_root("failed-update");
        let auth = Arc::new(RwLock::new(
            AdminAuth::new("admin".to_string(), "123456".to_string(), true)
                .expect("auth fixture"),
        ));
        let failed_target = root.join("auth-target-directory");
        std::fs::create_dir(&failed_target).expect("failure target");
        let sessions = test_sessions();
        let (session_id, _) = sessions.lock().create().expect("session capacity");
        let response = handle_admin_auth(
            admin_auth_request(r#"{"current_password":"123456","new_password":"abcdef"}"#),
            Some(auth.clone()),
            Some(&failed_target),
            &sessions,
            test_rate_limiter(5),
            None,
            &AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture()),
        );

        assert_eq!(response.status().as_u16(), 500);
        let guard = auth.read();
        assert_eq!(guard.user(), "admin");
        assert!(guard.requires_password_change());
        assert!(guard.verify("admin", "123456"));
        assert!(!guard.verify("admin", "abcdef"));
        drop(guard);
        assert!(sessions.lock().is_valid(&session_id));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn admin_auth_success_persists_before_session_invalidation() {
        let root = test_auth_root("success");
        let auth_path = root.join("admin-auth.json");
        let initial = AdminAuth::new("admin".to_string(), "123456".to_string(), true)
            .expect("auth fixture");
        persist_auth_file(&auth_path, &initial).expect("initial auth persistence");
        let auth = Arc::new(RwLock::new(initial));
        let sessions = test_sessions();
        let (session_id, _) = sessions.lock().create().expect("session capacity");
        let response = handle_admin_auth(
            admin_auth_request(r#"{"current_password":"123456","new_username":"root"}"#),
            Some(auth.clone()),
            Some(&auth_path),
            &sessions,
            test_rate_limiter(5),
            None,
            &AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture()),
        );

        assert_eq!(response.status().as_u16(), 200);
        assert!(!sessions.lock().is_valid(&session_id));
        let persisted = load_auth_file(&auth_path)
            .expect("load persisted auth")
            .expect("persisted auth");
        assert_eq!(persisted.user(), "root");
        assert!(persisted.requires_password_change());
        assert!(persisted.verify("root", "123456"));
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn admin_auth_persistence_rejects_pre_epoch_wall_clock() {
        let root = test_auth_root("pre-epoch");
        let auth_path = root.join("admin-auth.json");
        let auth = AdminAuth::new("admin".to_string(), "123456".to_string(), false)
            .expect("auth fixture");
        let source = crate::time_source::test_support::ManualTimeSource::new(
            std::time::Instant::now(),
            std::time::SystemTime::UNIX_EPOCH - Duration::from_secs(1),
        );
        let clock = ProtocolClock::from_source(source);

        let error = persist_auth_file_with_clock(&auth_path, &auth, &clock)
            .expect_err("pre-epoch auth timestamp");
        assert!(error.to_string().contains("before the Unix epoch"), "{error}");
        assert!(!auth_path.exists());
        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn admin_auth_failed_update_does_not_change_restart_credential() {
        let root = test_auth_root("restart");
        let auth_path = root.join("admin-auth.json");
        let backup_path = root.join("admin-auth.backup");
        let initial = AdminAuth::new("admin".to_string(), "123456".to_string(), false)
            .expect("auth fixture");
        persist_auth_file(&auth_path, &initial).expect("initial auth persistence");
        let auth = Arc::new(RwLock::new(initial));

        std::fs::rename(&auth_path, &backup_path).expect("move durable credential");
        std::fs::create_dir(&auth_path).expect("interrupted-write destination");
        let response = handle_admin_auth(
            admin_auth_request(r#"{"current_password":"123456","new_password":"abcdef"}"#),
            Some(auth),
            Some(&auth_path),
            &test_sessions(),
            test_rate_limiter(5),
            None,
            &AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture()),
        );
        assert_eq!(response.status().as_u16(), 500);

        std::fs::remove_dir_all(&auth_path).expect("remove failed destination");
        std::fs::rename(&backup_path, &auth_path).expect("restore durable credential");
        let restarted = AdminHttpServer::new(
            "127.0.0.1:0".parse().expect("address"),
            root.clone(),
            Some(
                AdminAuth::new("configured".to_string(), "configured".to_string(), false)
                    .expect("configured auth"),
            ),
            Some(auth_path),
            test_handler(),
        )
        .expect("restart must load the last durable credential");
        let loaded = restarted.auth.as_ref().expect("auth loaded").read();
        assert_eq!(loaded.user(), "admin");
        assert!(loaded.verify("admin", "123456"));
        assert!(!loaded.verify("configured", "configured"));
        std::fs::remove_dir_all(root).expect("cleanup");
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
            let root = std::env::temp_dir().join(format!(
                "qf-admin-webroot-traversal-{}",
                crate::time_source::unix_epoch_seconds(crate::time_source::now_system())
                    .expect("test wall-clock timestamp")
            ));
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
            let root = std::env::temp_dir().join(format!(
                "qf-admin-webroot-spa-{}",
                crate::time_source::unix_epoch_seconds(crate::time_source::now_system())
                    .expect("test wall-clock timestamp")
            ));
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
            limiter.record_attempt(ip);
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
    fn admin_auth_and_session_expiry_use_explicit_clock_without_sleeping() {
        let source = crate::time_source::test_support::ManualTimeSource::new(
            Instant::now(),
            std::time::SystemTime::UNIX_EPOCH,
        );
        let clock = ProtocolClock::from_source(source.clone());
        let mut limiter = LoginRateLimiter::new_with_clock(2, 60, &clock);
        limiter.record_attempt("127.0.0.1");
        limiter.record_attempt("127.0.0.1");
        assert!(limiter.is_locked("127.0.0.1"));

        let mut store = SessionStore::new_with_capacity_and_clock(Duration::from_secs(60), 1, &clock);
        store.create().expect("first admin session");
        source.advance(Duration::from_secs(61));
        assert_eq!(store.snapshot().active_sessions, 0);
        store.create().expect("expired session releases capacity");
        assert_eq!(store.snapshot().active_sessions, 1);
        assert!(!limiter.is_locked("127.0.0.1"));
    }

    #[test]
    fn login_rate_limiter_evicts_least_recently_used_key_at_cap() {
        let mut limiter = LoginRateLimiter::new(5, 60);
        for index in 0..MAX_LOGIN_RATE_LIMIT_KEYS {
            limiter.record_attempt(&format!("ip-{index}"));
        }
        limiter.record_attempt("ip-0");
        limiter.record_attempt("ip-new");

        assert_eq!(limiter.attempts.len(), MAX_LOGIN_RATE_LIMIT_KEYS);
        assert_eq!(limiter.lru_keys.len(), MAX_LOGIN_RATE_LIMIT_KEYS);
        assert!(limiter.attempts.contains_key("ip-0"));
        assert!(!limiter.attempts.contains_key("ip-1"));
        assert!(limiter.attempts.contains_key("ip-new"));
    }

    #[test]
    fn session_replay_fingerprints_prune_one_oldest_entry_per_insert() {
        let mut store = SessionStore::new(Duration::from_secs(60));
        let (session_id, csrf_token) = store.create().expect("session capacity");

        for fingerprint in 0..=MAX_REPLAY_FINGERPRINTS as u64 {
            assert!(store
                .validate_post_guard(&session_id, &csrf_token, fingerprint, true)
                .is_ok());
        }

        let record = store.sessions.get(&session_id).expect("session must exist");
        assert_eq!(record.replay_fingerprints.len(), MAX_REPLAY_FINGERPRINTS);
        assert_eq!(record.replay_fingerprint_set.len(), MAX_REPLAY_FINGERPRINTS);
        assert!(!record.replay_fingerprint_set.contains(&0));
        assert!(record.replay_fingerprint_set.contains(&(MAX_REPLAY_FINGERPRINTS as u64)));
    }

    #[test]
    fn session_replay_fingerprint_is_rejected_within_window_and_accepted_after_expiry() {
        let mut store = SessionStore::new(Duration::from_secs(3600));
        let (session_id, csrf_token) = store.create().expect("session capacity");
        let first_seen = Instant::now();

        assert!(store
            .validate_post_guard_at(&session_id, &csrf_token, 7, true, first_seen)
            .is_ok());
        assert_eq!(
            store.validate_post_guard_at(
                &session_id,
                &csrf_token,
                7,
                true,
                first_seen + REPLAY_FINGERPRINT_WINDOW - Duration::from_millis(1),
            ),
            Err("Replay request detected")
        );
        assert!(store
            .validate_post_guard_at(
                &session_id,
                &csrf_token,
                7,
                true,
                first_seen + REPLAY_FINGERPRINT_WINDOW + Duration::from_millis(1),
            )
            .is_ok());

        let record = store.sessions.get(&session_id).expect("session must exist");
        assert_eq!(record.replay_fingerprints.len(), 1);
        assert!(record.replay_fingerprint_set.contains(&7));
    }

    #[test]
    fn session_replay_fingerprint_history_limit_allows_post_eviction_reuse() {
        let mut store = SessionStore::new(Duration::from_secs(3600));
        let (session_id, csrf_token) = store.create().expect("session capacity");
        let first_seen = Instant::now();

        for fingerprint in 0..=MAX_REPLAY_FINGERPRINTS as u64 {
            assert!(store
                .validate_post_guard_at(&session_id, &csrf_token, fingerprint, true, first_seen)
                .is_ok());
        }

        assert!(store
            .validate_post_guard_at(
                &session_id,
                &csrf_token,
                0,
                true,
                first_seen + Duration::from_secs(1),
            )
            .is_ok());
        let record = store.sessions.get(&session_id).expect("session must exist");
        assert_eq!(record.replay_fingerprints.len(), MAX_REPLAY_FINGERPRINTS);
        assert_eq!(record.replay_fingerprint_set.len(), MAX_REPLAY_FINGERPRINTS);
        assert!(record.replay_fingerprint_set.contains(&0));
        assert!(!record.replay_fingerprint_set.contains(&1));
    }

    #[test]
    fn session_store_rejects_successful_login_at_capacity_without_eviction() {
        let auth = test_auth("123", false).expect("auth fixture");
        let sessions = Arc::new(Mutex::new(SessionStore::new_with_capacity(
            Duration::from_secs(3600),
            1,
        )));
        let rate_limiter = test_rate_limiter(5);
        let login_request = || HttpRequest {
            method: "POST".to_string(),
            path: "/api/login".to_string(),
            headers: Vec::new(),
            body: br#"{"username":"admin","password":"123"}"#.to_vec(),
        };

        let first = handle_login(
            login_request(),
            Some(&auth),
            Arc::clone(&sessions),
            Arc::clone(&rate_limiter),
            None,
            &AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture()),
        );
        assert_eq!(first.status().as_u16(), 200);

        let second = handle_login(
            login_request(),
            Some(&auth),
            Arc::clone(&sessions),
            Arc::clone(&rate_limiter),
            None,
            &AdminHttpEnvironment::from_snapshot(&crate::env_utils::EnvSnapshot::capture()),
        );
        assert_eq!(second.status().as_u16(), 429);

        let snapshot = sessions.lock().snapshot();
        assert_eq!(snapshot.max_sessions, 1);
        assert_eq!(snapshot.active_sessions, 1);
        assert_eq!(snapshot.created_total, 1);
        assert_eq!(snapshot.capacity_rejected_total, 1);
    }

    #[test]
    fn session_store_prunes_expired_records_before_capacity_admission() {
        let mut store = SessionStore::new_with_capacity(Duration::from_secs(60), 1);
        let (session_id, _) = store.create().expect("session capacity");
        store
            .sessions
            .get_mut(&session_id)
            .expect("session must exist")
            .expires_at = Instant::now() - Duration::from_secs(1);

        let expired_snapshot = store.snapshot();
        assert_eq!(expired_snapshot.active_sessions, 0);
        assert_eq!(expired_snapshot.expired_total, 1);

        store.create().expect("expired session must release capacity");
        let admitted_snapshot = store.snapshot();
        assert_eq!(admitted_snapshot.active_sessions, 1);
        assert_eq!(admitted_snapshot.created_total, 2);
        assert_eq!(admitted_snapshot.capacity_rejected_total, 0);
        assert_eq!(admitted_snapshot.expired_total, 1);
    }

    #[test]
    fn admin_http_shutdown_clears_live_sessions() {
        let server = AdminHttpServer::new(
            "127.0.0.1:0".parse().expect("address"),
            std::env::temp_dir(),
            Some(AdminAuth::new("admin".to_string(), "123".to_string(), false).expect("auth")),
            None,
            test_handler(),
        )
        .expect("admin server");
        server.sessions.lock().create().expect("session capacity");
        assert_eq!(server.session_snapshot().active_sessions, 1);
        server.shutdown_signal().store(true, Ordering::Relaxed);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        runtime.block_on(server.run()).expect("shutdown must complete");

        let snapshot = server.session_snapshot();
        assert_eq!(snapshot.active_sessions, 0);
        assert_eq!(snapshot.created_total, 1);
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

    #[test]
    fn admin_web_capacity_validation_is_bounded_and_defaulted() {
        assert_eq!(
            validate_admin_web_max_connections(DEFAULT_ADMIN_WEB_MAX_CONNECTIONS).unwrap(),
            DEFAULT_ADMIN_WEB_MAX_CONNECTIONS
        );
        assert_eq!(
            validate_admin_web_max_connections(MAX_ADMIN_WEB_CONNECTIONS).unwrap(),
            MAX_ADMIN_WEB_CONNECTIONS
        );
        assert_eq!(
            validate_admin_web_max_connections(0).unwrap_err().to_string(),
            "admin web max connections must be at least 1"
        );
        assert_eq!(
            validate_admin_web_max_connections(MAX_ADMIN_WEB_CONNECTIONS + 1)
                .unwrap_err()
                .to_string(),
            "admin web max connections must not exceed 1024"
        );
        assert!(
            AdminHttpServer::new_with_max_connections(
                "127.0.0.1:0".parse().unwrap(),
                std::env::temp_dir(),
                None,
                None,
                test_handler(),
                0,
            )
            .is_err()
        );
        assert_eq!(
            validate_admin_web_operation_timeout_ms(DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS)
                .unwrap(),
            Duration::from_millis(DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS)
        );
        assert_eq!(
            validate_admin_web_operation_timeout_ms(MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS - 1)
                .unwrap_err()
                .to_string(),
            "admin web operation timeout must be at least 50 ms"
        );
        assert_eq!(
            validate_admin_web_operation_timeout_ms(MAX_ADMIN_WEB_OPERATION_TIMEOUT_MS + 1)
                .unwrap_err()
                .to_string(),
            "admin web operation timeout must not exceed 120000 ms"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_web_admission_rejects_before_spawn_and_joins_on_shutdown() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpStream;

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind admin test listener");
        let addr = listener.local_addr().expect("admin test listener address");
        drop(listener);

        let server = Arc::new(
            AdminHttpServer::new_with_max_connections(
                addr,
                std::env::temp_dir(),
                None,
                None,
                test_handler(),
                1,
            )
            .expect("admin server"),
        );
        let shutdown = server.shutdown_signal();
        let runner = Arc::clone(&server);
        let task = tokio::spawn(async move { runner.run().await });

        let mut active = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    active = Some(stream);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
        let mut active = active.expect("admin listener must accept the active connection");

        for _ in 0..100 {
            if server.admission_snapshot().active_connections == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let active_snapshot = server.admission_snapshot();
        assert_eq!(active_snapshot.active_connections, 1);
        assert_eq!(active_snapshot.pending_connections, 0);
        assert_eq!(active_snapshot.admitted_total, 1);

        let _rejected = TcpStream::connect(addr).await.expect("capacity probe connection");
        for _ in 0..100 {
            if server.admission_snapshot().rejected_total == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let saturated_snapshot = server.admission_snapshot();
        assert_eq!(saturated_snapshot.active_connections, 1);
        assert_eq!(saturated_snapshot.pending_connections, 0);
        assert_eq!(saturated_snapshot.admitted_total, 1);
        assert_eq!(saturated_snapshot.rejected_total, 1);

        shutdown.store(true, Ordering::SeqCst);
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("admin server shutdown must join within one second")
            .expect("admin server task must not panic");
        assert!(result.is_ok(), "admin server shutdown must be clean: {result:?}");

        let mut closed_bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), active.read_to_end(&mut closed_bytes))
            .await
            .expect("active connection must close after server join")
            .expect("active connection close must be readable");
        let final_snapshot = server.admission_snapshot();
        assert_eq!(final_snapshot.active_connections, 0);
        assert_eq!(final_snapshot.pending_connections, 0);
        assert_eq!(final_snapshot.completed_total, 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_web_operation_timeout_owns_slow_worker_and_shutdown_drain() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind admin test listener");
        let addr = listener.local_addr().expect("admin test listener address");
        drop(listener);

        let server = Arc::new(
            AdminHttpServer::new_with_max_connections_and_operation_timeout(
                addr,
                std::env::temp_dir(),
                None,
                None,
                slow_test_handler(Duration::from_millis(1_200)),
                1,
                MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS,
            )
            .expect("admin server"),
        );
        let shutdown = server.shutdown_signal();
        let diagnostics = server.operation_diagnostics();
        let runner = Arc::clone(&server);
        let task = tokio::spawn(async move { runner.run().await });

        let mut stream = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
        let mut stream = stream.expect("admin listener must accept the operation connection");
        stream
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request write");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
            .await
            .expect("timed-out operation must return before connection grace expires")
            .expect("timed-out operation response must be readable");
        let response = String::from_utf8_lossy(&response);
        assert_eq!(parse_status(&response), 504);
        assert!(response.contains("Admin operation timed out"));

        for _ in 0..100 {
            if server.admission_snapshot().active_connections == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(server.admission_snapshot().active_connections, 0);

        let mut follow_up = TcpStream::connect(addr)
            .await
            .expect("permit must be released after timeout response");
        follow_up
            .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("follow-up request write");
        let mut follow_up_response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), follow_up.read_to_end(&mut follow_up_response))
            .await
            .expect("follow-up response must be bounded")
            .expect("follow-up response must be readable");
        assert_eq!(
            parse_status(&String::from_utf8_lossy(&follow_up_response)),
            200
        );

        let before_shutdown = diagnostics.snapshot();
        assert_eq!(before_shutdown.timeout_ms, MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS);
        assert_eq!(before_shutdown.started_total, 2);
        assert_eq!(before_shutdown.timeout_total, 1);
        assert_eq!(before_shutdown.active_operations, 1);

        shutdown.store(true, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("admin server shutdown must be bounded")
            .expect("admin server task must not panic")
            .expect("admin server shutdown must be clean");

        let completed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let snapshot = diagnostics.snapshot();
                if snapshot.active_operations == 0 {
                    break snapshot;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("started blocking operation must eventually release its owner");
        assert_eq!(completed.active_operations, 0);
        assert_eq!(completed.completed_total, 2);
        assert_eq!(completed.completed_after_deadline_total, 1);
        assert_eq!(completed.panic_total, 0);
        assert_eq!(completed.shutdown_expired_total, 1);
        assert_eq!(server.admission_snapshot().active_connections, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_web_operation_timeout_covers_slow_persistence_worker() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind admin test listener");
        let addr = listener.local_addr().expect("admin test listener address");
        drop(listener);

        let (handler, persistence_completed) =
            slow_persistence_test_handler(Duration::from_millis(150));
        let server = Arc::new(
            AdminHttpServer::new_with_max_connections_and_operation_timeout(
                addr,
                std::env::temp_dir(),
                None,
                None,
                handler,
                1,
                MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS,
            )
            .expect("admin server"),
        );
        let shutdown = server.shutdown_signal();
        let diagnostics = server.operation_diagnostics();
        let runner = Arc::clone(&server);
        let task = tokio::spawn(async move { runner.run().await });

        let mut stream = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
        let mut stream = stream.expect("admin listener must accept the operation connection");
        let request = config_post(r#"{"config":"[x]\\n"}"#);
        stream.write_all(request.as_bytes()).await.expect("request write");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
            .await
            .expect("timed-out persistence operation must return promptly")
            .expect("timed-out persistence response must be readable");
        let response = String::from_utf8_lossy(&response);
        assert_eq!(parse_status(&response), 504);
        assert!(!persistence_completed.load(Ordering::Acquire));

        let before_completion = diagnostics.snapshot();
        assert_eq!(before_completion.started_total, 1);
        assert_eq!(before_completion.timeout_total, 1);
        assert_eq!(before_completion.active_operations, 1);

        let completed = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if persistence_completed.load(Ordering::Acquire) {
                    let snapshot = diagnostics.snapshot();
                    if snapshot.active_operations == 0 {
                        break snapshot;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("slow persistence worker must eventually finish");
        assert_eq!(completed.completed_total, 1);
        assert_eq!(completed.completed_after_deadline_total, 1);
        assert_eq!(completed.cancelled_total, 0);

        shutdown.store(true, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("admin server shutdown must be bounded")
            .expect("admin server task must not panic")
            .expect("admin server shutdown must be clean");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_web_operation_cancellation_is_counted() {
        let diagnostics = AdminHttpOperationDiagnostics::new(MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS)
            .expect("operation diagnostics");
        let state = diagnostics.begin(tokio::time::Instant::now() + Duration::from_secs(1));
        state.finish_cancelled();

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.active_operations, 0);
        assert_eq!(snapshot.cancelled_total, 1);
        assert_eq!(snapshot.completed_total, 0);
        assert_eq!(snapshot.timeout_total, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn admin_web_operation_worker_panic_is_converted_and_counted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind admin test listener");
        let addr = listener.local_addr().expect("admin test listener address");
        drop(listener);

        let server = Arc::new(
            AdminHttpServer::new_with_max_connections_and_operation_timeout(
                addr,
                std::env::temp_dir(),
                None,
                None,
                panicking_test_handler(),
                1,
                MIN_ADMIN_WEB_OPERATION_TIMEOUT_MS,
            )
            .expect("admin server"),
        );
        let shutdown = server.shutdown_signal();
        let diagnostics = server.operation_diagnostics();
        let runner = Arc::clone(&server);
        let task = tokio::spawn(async move { runner.run().await });

        let mut stream = None;
        for _ in 0..100 {
            match TcpStream::connect(addr).await {
                Ok(candidate) => {
                    stream = Some(candidate);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
        let mut stream = stream.expect("admin listener must accept the panic connection");
        stream
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request write");
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
            .await
            .expect("panic response must close promptly")
            .expect("panic response must be readable");
        assert_eq!(parse_status(&String::from_utf8_lossy(&response)), 500);

        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.active_operations, 0);
        assert_eq!(snapshot.started_total, 1);
        assert_eq!(snapshot.completed_total, 1);
        assert_eq!(snapshot.panic_total, 1);
        assert_eq!(snapshot.timeout_total, 0);

        shutdown.store(true, Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("admin server shutdown must be bounded")
            .expect("admin server task must not panic")
            .expect("admin server shutdown must be clean");
        assert_eq!(server.admission_snapshot().active_connections, 0);
    }

    #[tokio::test]
    async fn idle_admin_server_observes_shutdown_without_new_connection() {
        let server = AdminHttpServer::new(
            "127.0.0.1:0".parse().unwrap(),
            std::env::temp_dir(),
            None,
            None,
            test_handler(),
        )
        .expect("admin server");
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
