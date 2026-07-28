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
