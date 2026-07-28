
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
