//! Admin HTTP contract tests.

use quicfuscate::engine::qkey;
use quicfuscate::implementations::server::admin::{AdminResponse, ClientInfo};
use quicfuscate::implementations::server::admin_http::{
    AdminAuth, AdminHttpHandler, AdminHttpServer, IssueQKeyRequest,
};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

struct DummyHandler {
    listen: String,
    qkey: String,
    qkey_token: String,
}

impl DummyHandler {
    fn new(listen: String) -> Self {
        let token = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
        let config = qkey::QKeyConfig::new("127.0.0.1:4433", "127.0.0.1:4433")
            .with_stealth("auto")
            .with_extra("nonce=contract")
            .with_token(token);
        let qkey = qkey::generate(&config);
        Self { listen, qkey, qkey_token: token.to_string() }
    }
}

impl AdminHttpHandler for DummyHandler {
    fn handle_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({
            "version": "0.0.0-test",
            "uptime_secs": 1,
            "clients_active": 1,
            "clients_total": 1,
            "bytes_in": 10,
            "bytes_out": 20,
            "listen": self.listen,
        }))
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        vec![ClientInfo {
            // Client identifiers are treated as socket addresses in the admin HTTP API.
            id: "127.0.0.1:1234".to_string(),
            ip: "127.0.0.1".to_string(),
            remote_addr: "127.0.0.1:1234".to_string(),
            connected_secs: 5,
            bytes_in: 100,
            bytes_out: 200,
            stealth_mode: "auto".to_string(),
        }]
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        AdminResponse::ok_with_message(format!("kicked {id}"))
    }

    fn handle_block(&self, _ip: &str) -> AdminResponse {
        AdminResponse::ok_with_message("blocked")
    }

    fn handle_unblock(&self, _ip: &str) -> AdminResponse {
        AdminResponse::ok_with_message("unblocked")
    }

    fn handle_list_blocked_ips(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({ "ips": [] }))
    }

    fn handle_reload(&self) -> AdminResponse {
        AdminResponse::ok_with_message("reloaded")
    }

    fn handle_drain(&self) -> AdminResponse {
        AdminResponse::ok_with_message("drain scheduled")
    }

    fn handle_drain_status(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({
            "state": "draining",
            "active_connections": 1,
            "grace_period_ms": 5000,
            "drain_elapsed_ms": 250,
        }))
    }

    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse {
        let expires_at = req.ttl_seconds.map(|ttl| 1_000_000u64.saturating_add(ttl));
        AdminResponse::ok_with_data(serde_json::json!({
            "qkey": self.qkey,
            "created_at": 1,
            "expires_at": expires_at,
        }))
    }

    fn handle_list_qkeys(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({
            "keys": [
                {
                    // QKey ids are 12 hex chars derived from a stable SHA-256 based id().
                    "id": "a1b2c3d4e5f6",
                    "name": "Contract Key",
                    "stealth": "auto",
                    "fec": "auto",
                    "created_at": 1,
                    "expires_at": 2
                }
            ]
        }))
    }

    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse {
        if id == "a1b2c3d4e5f6" {
            AdminResponse::ok_with_message("revoked")
        } else {
            AdminResponse::error("not found")
        }
    }

    fn handle_shutdown(&self) -> AdminResponse {
        AdminResponse::ok_with_message("shutdown")
    }

    fn handle_read_config(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({ "config": "test = true" }))
    }

    fn handle_write_config(&self, _contents: &str) -> AdminResponse {
        AdminResponse::ok_with_message("config saved")
    }

    fn handle_metrics_text(&self) -> String {
        "metrics\nline2\n".to_string()
    }

    fn handle_metrics_json(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({
            "metrics": {
                "quicfuscate_up": 1,
                "quicfuscate_uptime_seconds": 1,
                "quicfuscate_clients_active": 1,
                "quicfuscate_clients_total": 1,
                "quicfuscate_connections_rejected": 0,
                "quicfuscate_bytes_in_total": 10,
                "quicfuscate_bytes_out_total": 20
            }
        }))
    }

    fn handle_get_logging_config(&self) -> AdminResponse {
        AdminResponse::ok_with_data(serde_json::json!({ "mode": "normal" }))
    }

    fn handle_set_logging_config(&self, mode: &str) -> AdminResponse {
        if mode.trim().is_empty() {
            return AdminResponse::error("missing mode");
        }
        AdminResponse::ok_with_message(format!("logging mode set to {mode}"))
    }

    fn handle_get_logs(&self, cursor: u64) -> AdminResponse {
        // Deterministic small ring buffer for contract tests.
        let lines = if cursor == 0 {
            vec![
                serde_json::json!({ "ts": 1, "level": "INFO", "msg": "contract log line 1" }),
                serde_json::json!({ "ts": 2, "level": "WARN", "msg": "contract log line 2" }),
            ]
        } else {
            vec![]
        };
        AdminResponse::ok_with_data(serde_json::json!({ "lines": lines, "cursor": 2 }))
    }

    fn handle_clear_logs(&self) -> AdminResponse {
        AdminResponse::ok_with_message("logs cleared")
    }
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (u16, String, Option<String>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut headers = String::new();
    headers.push_str(&format!("Host: {}\r\n", addr));
    if let Some(c) = cookie {
        headers.push_str(&format!("Cookie: {}\r\n", c));
    }
    headers.push_str("Connection: close\r\n");
    headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    let req = format!("{method} {path} HTTP/1.1\r\n{headers}\r\n{body}");
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    let mut parts = resp.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let set_cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());
    (status, body, set_cookie)
}

fn http_request_with_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: &str,
) -> (u16, String, Option<String>, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut headers = String::new();
    headers.push_str(&format!("Host: {}\r\n", addr));
    headers.push_str(&format!("Origin: http://{}\r\n", addr));
    if let Some(c) = cookie {
        headers.push_str(&format!("Cookie: {}\r\n", c));
    }
    headers.push_str("Connection: close\r\n");
    headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    let req = format!("{method} {path} HTTP/1.1\r\n{headers}\r\n{body}");
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    let mut parts = resp.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let set_cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());
    (status, body, set_cookie, head.to_string())
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

fn http_request_with_csrf(
    addr: SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    body: &str,
) -> (u16, String, Option<String>) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut headers = String::new();
    headers.push_str(&format!("Host: {}\r\n", addr));
    headers.push_str(&format!("Origin: http://{}\r\n", addr));
    if let Some(c) = cookie {
        headers.push_str(&format!("Cookie: {}\r\n", c));
    }
    if let Some(token) = csrf_token {
        headers.push_str(&format!("X-CSRF-Token: {}\r\n", token));
    }
    headers.push_str("Connection: close\r\n");
    headers.push_str(&format!("Content-Length: {}\r\n", body.len()));
    let req = format!("{method} {path} HTTP/1.1\r\n{headers}\r\n{body}");
    stream.write_all(req.as_bytes()).expect("write");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("read");
    let mut parts = resp.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let set_cookie = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string());
    (status, body, set_cookie)
}

fn http_request_with_length(
    addr: SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    csrf_token: Option<&str>,
    content_len: usize,
    body: Option<&[u8]>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut headers = String::new();
    headers.push_str(&format!("Host: {}\r\n", addr));
    if let Some(c) = cookie {
        headers.push_str(&format!("Cookie: {}\r\n", c));
    }
    if let Some(token) = csrf_token {
        headers.push_str(&format!("X-CSRF-Token: {}\r\n", token));
    }
    headers.push_str("Connection: close\r\n");
    headers.push_str(&format!("Content-Length: {}\r\n", content_len));
    let req = format!("{method} {path} HTTP/1.1\r\n{headers}\r\n");
    stream.write_all(req.as_bytes()).expect("write headers");
    if let Some(bytes) = body {
        let _ = stream.write_all(bytes);
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    let mut parts = resp.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, body)
}

fn wait_for_listen(addr: SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("admin http server did not start listening");
}

fn raw_request_status(addr: SocketAddr, raw: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
    stream.write_all(raw.as_bytes()).expect("write raw request");
    let mut resp = String::new();
    let _ = stream.read_to_string(&mut resp);
    resp.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

#[test]
fn admin_http_contracts() {
    let user = "admin";
    let password = "test";
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).expect("bind");
    let local_addr = listener.local_addr().expect("local addr");
    drop(listener);

    let web_root = std::env::temp_dir().join("qf_admin_web_root");
    let _ = std::fs::create_dir_all(&web_root);
    let _ = std::fs::write(web_root.join("index.html"), "<!doctype html><html>ok</html>");
    if let Some(parent) = web_root.parent() {
        let _ = std::fs::write(parent.join("qf_admin_http_contract_secret.txt"), "secret");
    }
    let handler = DummyHandler::new(local_addr.to_string());
    let expected_qkey = handler.qkey.clone();
    let expected_qkey_token = handler.qkey_token.clone();
    let handler = Arc::new(handler);
    let auth = AdminAuth::new(user.to_string(), password.to_string(), false);
    let server = AdminHttpServer::new(local_addr, web_root, Some(auth), None, handler);
    let shutdown = server.shutdown_signal();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(server.run()).expect("server run");
    });

    wait_for_listen(local_addr);

    let (status, _body, _) =
        http_request(local_addr, "GET", "/../qf_admin_http_contract_secret.txt", None, "");
    assert_eq!(status, 403);

    let (status, _body, _) = http_request(local_addr, "GET", "/api/status", None, "");
    assert_eq!(status, 401);

    let login_payload = serde_json::json!({ "username": user, "password": password }).to_string();
    let (status, _body, set_cookie, headers) =
        http_request_with_headers(local_addr, "POST", "/api/login", None, &login_payload);
    assert_eq!(status, 200);
    let csrf = parse_header(&headers, "X-CSRF-Token").expect("csrf token");
    let cookie = set_cookie
        .and_then(|c| c.split(';').next().map(|s| s.trim().to_string()))
        .expect("set cookie");

    let bad_payload = serde_json::json!({ "username": user, "password": "wrong" }).to_string();
    let (status, _body, _) = http_request(local_addr, "POST", "/api/login", None, &bad_payload);
    assert_eq!(status, 401);

    let (status, body, _) = http_request(local_addr, "GET", "/api/clients", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("clients response");
    assert!(resp.success);
    assert!(resp.data.is_some());

    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/clients/127.0.0.1:1234/kick",
        Some(&cookie),
        Some(&csrf),
        "",
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("kick response");
    assert!(resp.success);

    let kick_payload = serde_json::json!({ "id": "127.0.0.1:1234" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/kick",
        Some(&cookie),
        Some(&csrf),
        &kick_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("kick payload response");
    assert!(resp.success);

    let (status, body, _) = http_request(local_addr, "GET", "/api/status", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("status response");
    assert!(resp.success);
    assert!(resp.data.is_some());

    let (status, body, _) = http_request(local_addr, "GET", "/api/drain/status", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("drain status response");
    assert!(resp.success);
    let data = resp.data.expect("drain status data");
    assert_eq!(data.get("state").and_then(|value| value.as_str()), Some("draining"));
    assert_eq!(data.get("active_connections").and_then(|value| value.as_u64()), Some(1));

    let (status, body, _) = http_request(local_addr, "GET", "/api/config", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("config response");
    assert!(resp.success);
    let data = resp.data.expect("config data");
    assert_eq!(data.get("config").and_then(|v| v.as_str()).unwrap_or(""), "test = true");

    let config_payload = serde_json::json!({ "config": "test = true" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/config",
        Some(&cookie),
        Some(&csrf),
        &config_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("config write response");
    assert!(resp.success);

    let (status, body, _) =
        http_request_with_csrf(local_addr, "POST", "/api/qkey", Some(&cookie), Some(&csrf), "{}");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("qkey response");
    assert!(resp.success);
    let data = resp.data.expect("qkey data");
    let qkey_value = data.get("qkey").and_then(|v| v.as_str()).unwrap_or_default();
    assert_eq!(qkey_value, expected_qkey);

    let ttl_payload = serde_json::json!({ "ttl_seconds": 60 }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/qkey",
        Some(&cookie),
        Some(&csrf),
        &ttl_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("qkey ttl response");
    assert!(resp.success);
    let data = resp.data.expect("qkey ttl data");
    let expires_at = data.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(expires_at, 1_000_000u64.saturating_add(60));
    let qkey_value = data.get("qkey").and_then(|v| v.as_str()).unwrap_or("");
    assert!(!qkey_value.trim().is_empty());
    let parsed = qkey::parse(qkey_value).expect("qkey parse");
    assert_eq!(parsed.token.as_deref(), Some(expected_qkey_token.as_str()));

    let (status, body, _) = http_request(local_addr, "GET", "/api/qkeys", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("qkeys response");
    assert!(resp.success);
    let data = resp.data.expect("qkeys data");
    let keys = data.get("keys").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].get("id").and_then(|v| v.as_str()).unwrap_or(""), "a1b2c3d4e5f6");
    assert_eq!(keys[0].get("name").and_then(|v| v.as_str()).unwrap_or(""), "Contract Key");
    assert_eq!(keys[0].get("stealth").and_then(|v| v.as_str()).unwrap_or(""), "auto");
    assert_eq!(keys[0].get("fec").and_then(|v| v.as_str()).unwrap_or(""), "auto");
    assert!(keys[0].get("qkey").is_none(), "list endpoint must stay metadata-only");

    let revoke_payload = serde_json::json!({ "id": "a1b2c3d4e5f6" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/qkeys/revoke",
        Some(&cookie),
        Some(&csrf),
        &revoke_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("revoke response");
    assert!(resp.success);

    let revoke_unknown_payload = serde_json::json!({ "id": "ffffffffffff" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/qkeys/revoke",
        Some(&cookie),
        Some(&csrf),
        &revoke_unknown_payload,
    );
    assert_eq!(status, 404);
    let resp: AdminResponse = serde_json::from_str(&body).expect("revoke unknown response");
    assert!(!resp.success);

    let (status, body, _) = http_request(local_addr, "GET", "/api/metrics", Some(&cookie), "");
    assert_eq!(status, 200);
    assert!(body.contains("metrics"));

    let (status, body, _) =
        http_request_with_csrf(local_addr, "POST", "/api/reload", Some(&cookie), Some(&csrf), "{}");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("reload response");
    assert!(resp.success);

    let block_payload = serde_json::json!({ "ip": "127.0.0.1" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/block",
        Some(&cookie),
        Some(&csrf),
        &block_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("block response");
    assert!(resp.success);

    let (status, body, _) = http_request(local_addr, "GET", "/api/blocked", Some(&cookie), "");
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("blocked list response");
    assert!(resp.success);
    let data = resp.data.expect("blocked list data");
    assert!(data.get("ips").and_then(|v| v.as_array()).is_some());

    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/unblock",
        Some(&cookie),
        Some(&csrf),
        &block_payload,
    );
    assert_eq!(status, 200);
    let resp: AdminResponse = serde_json::from_str(&body).expect("unblock response");
    assert!(resp.success);

    let empty_mode_payload = serde_json::json!({ "mode": "" }).to_string();
    let (status, body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/config/logging",
        Some(&cookie),
        Some(&csrf),
        &empty_mode_payload,
    );
    assert_eq!(status, 400);
    let resp: AdminResponse = serde_json::from_str(&body).expect("logging mode error response");
    assert!(!resp.success);

    let (status, _body, _) = http_request(local_addr, "GET", "/api/qkey", Some(&cookie), "");
    assert_eq!(status, 404);

    let (status, _body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/kick",
        Some(&cookie),
        Some(&csrf),
        "{not_json",
    );
    assert_eq!(status, 400);

    let (status, _body, _) =
        http_request_with_csrf(local_addr, "POST", "/api/kick", Some(&cookie), Some(&csrf), "{}");
    assert_eq!(status, 400);

    let (status, _body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/qkeys/revoke",
        Some(&cookie),
        Some(&csrf),
        "{}",
    );
    assert_eq!(status, 400);

    let empty_config = serde_json::json!({ "config": "" }).to_string();
    let (status, _body, _) = http_request_with_csrf(
        local_addr,
        "POST",
        "/api/config",
        Some(&cookie),
        Some(&csrf),
        &empty_config,
    );
    assert_eq!(status, 400);

    let (status, _body) = http_request_with_length(
        local_addr,
        "POST",
        "/api/config",
        Some(&cookie),
        Some(&csrf),
        1024 * 1024 + 1,
        None,
    );
    assert_eq!(status, 413);

    let (status, _body) = http_request_with_length(
        local_addr,
        "POST",
        "/api/login",
        None,
        None,
        20,
        Some(b"{\"username\":\"ad"),
    );
    assert_eq!(status, 400);

    let (status, _body, _) =
        http_request_with_csrf(local_addr, "POST", "/api/logout", Some(&cookie), Some(&csrf), "{}");
    assert_eq!(status, 200);

    let (status, _body, _) = http_request(local_addr, "GET", "/api/status", Some(&cookie), "");
    assert_eq!(status, 401);

    shutdown.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(local_addr);
    let _ = handle.join();
}

#[test]
fn admin_http_request_line_fuzz_corpus_rejects_malformed_inputs() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).expect("bind");
    let local_addr = listener.local_addr().expect("local addr");
    drop(listener);

    let web_root = std::env::temp_dir().join("qf_admin_web_root_fuzz_contract");
    let _ = std::fs::create_dir_all(&web_root);
    let _ = std::fs::write(web_root.join("index.html"), "<!doctype html><html>ok</html>");
    let handler = Arc::new(DummyHandler::new(local_addr.to_string()));
    let server = AdminHttpServer::new(local_addr, web_root, None, None, handler);
    let shutdown = server.shutdown_signal();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(server.run()).expect("server run");
    });

    wait_for_listen(local_addr);

    // Requests that are rejected at the HTTP parse or application layer with 400.
    let corpus_400 = [
        "BADLINE\r\nHost: localhost\r\n\r\n",
        "GET / FTP/1.0\r\nHost: localhost\r\n\r\n",
        "GET / HTTP/9.9\r\nHost: localhost\r\n\r\n",
        "GE T / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET api/status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /api\\status HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ];

    for raw in corpus_400 {
        let status = raw_request_status(local_addr, raw);
        assert_eq!(status, 400, "unexpected status for raw request: {raw:?}");
    }

    // Truncated body: hyper waits for the remaining bytes, connection times
    // out. The server never produces a response so status is 0 (no reply).
    let truncated = "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\nContent-Type: application/json\r\n\r\n{\"username\":\"ad";
    let status = raw_request_status(local_addr, truncated);
    assert!(
        status == 400 || status == 0,
        "expected 400 or 0 (timeout) for truncated body, got {status}",
    );

    shutdown.store(true, Ordering::Relaxed);
    let _ = TcpStream::connect(local_addr);
    let _ = handle.join();
}
