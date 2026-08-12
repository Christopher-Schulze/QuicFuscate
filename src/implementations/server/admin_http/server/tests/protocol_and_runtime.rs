use super::*;
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

/// The bound must be applied before the append, not after the whole body is in memory.
///
/// This is the actual defect: the previous code produced the same 413 status, but only after
/// `collect()` had already allocated the entire body, so the configured cap bounded nothing.
#[test]
fn body_accumulation_stops_before_exceeding_the_cap() {
    let limit = 1024usize;
    let mut collected = Vec::new();

    // Chunks up to the cap are accepted and accumulate exactly.
    append_bounded(&mut collected, &[b'a'; 512], limit).expect("first chunk fits");
    assert_eq!(collected.len(), 512);
    append_bounded(&mut collected, &[b'b'; 512], limit).expect("second chunk reaches the cap");
    assert_eq!(collected.len(), limit, "the cap itself is allowed");

    // The next byte is refused, and nothing is appended.
    assert_eq!(append_bounded(&mut collected, &[b'c'; 1], limit), Err(BodyReadError::TooLarge));
    assert_eq!(collected.len(), limit, "a refused chunk must not be appended");

    // A single chunk larger than the cap is refused without allocating it.
    let mut fresh = Vec::new();
    assert_eq!(
        append_bounded(&mut fresh, &vec![b'd'; limit + 1], limit),
        Err(BodyReadError::TooLarge)
    );
    assert!(fresh.is_empty(), "an oversized first chunk must not be buffered at all");

    // The length check saturates rather than wrapping.
    let mut near_max = Vec::new();
    assert_eq!(
        append_bounded(&mut near_max, &[b'e'; 8], usize::MAX),
        Ok(()),
        "a huge limit must not overflow the comparison"
    );
}

/// Content-Length parsing: absent, valid, duplicate-but-equal, conflicting, unparsable.
#[test]
fn content_length_parsing_covers_every_header_shape() {
    let mut headers = hyper::HeaderMap::new();
    assert_eq!(parse_content_length(&headers), Ok(None), "absent is legitimate for chunked");

    headers.insert("content-length", "42".parse().unwrap());
    assert_eq!(parse_content_length(&headers), Ok(Some(42)));

    // Duplicate headers that agree are not a smuggling shape.
    headers.append("content-length", "42".parse().unwrap());
    assert_eq!(parse_content_length(&headers), Ok(Some(42)));

    // Disagreeing duplicates are.
    headers.append("content-length", "9".parse().unwrap());
    assert_eq!(parse_content_length(&headers), Err(()));

    let mut bad = hyper::HeaderMap::new();
    bad.insert("content-length", "not-a-number".parse().unwrap());
    assert_eq!(
        parse_content_length(&bad),
        Err(()),
        "an unparsable length must be refused, not treated as zero"
    );

    let mut negative = hyper::HeaderMap::new();
    negative.insert("content-length", "-1".parse().unwrap());
    assert_eq!(parse_content_length(&negative), Err(()));
}

/// A chunked body over the cap must be refused while streaming, not after buffering it.
///
/// Content-Length was the only guard, so a chunked or lengthless request could hold memory
/// until the operation timeout no matter what the configured cap said.
#[test]
fn oversized_chunked_payload_returns_413_without_content_length() {
    let web_root = std::env::temp_dir();
    let (addr, _thr) = start_short_unauth_server(1, web_root);

    // Chunks that together exceed the cap, with no Content-Length to reject early on.
    let chunk = "a".repeat(64 * 1024);
    let mut req = String::from(
        "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\n\r\n",
    );
    for _ in 0..((MAX_BODY_BYTES / chunk.len()) + 2) {
        req.push_str(&format!("{:x}\r\n{}\r\n", chunk.len(), chunk));
    }
    req.push_str("0\r\n\r\n");

    let resp = send_req(addr, &req);
    assert_eq!(
        parse_status(&resp),
        413,
        "a chunked body past the cap must be refused while streaming"
    );
}

/// A chunked body inside the cap must still be accepted, so the bound is not a blanket reject.
#[test]
fn chunked_payload_within_the_cap_is_accepted() {
    let web_root = std::env::temp_dir();
    let (addr, _thr) = start_short_unauth_server(1, web_root);

    let body = "{}";
    let req = format!(
        "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );
    let resp = send_req(addr, &req);
    assert_ne!(parse_status(&resp), 413, "a body inside the cap must not be rejected as too large");
}

/// Disagreeing Content-Length headers are a request-smuggling shape, not a length.
#[test]
fn conflicting_content_length_headers_return_400() {
    let web_root = std::env::temp_dir();
    let (addr, _thr) = start_short_unauth_server(1, web_root);

    let req = "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\n\
                   Content-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\n{}";
    let resp = send_req(addr, req);
    assert!(
        matches!(parse_status(&resp), 400),
        "disagreeing Content-Length headers must be refused, got {}",
        parse_status(&resp)
    );
}

/// An unparsable Content-Length must be refused rather than silently treated as zero.
#[test]
fn unparsable_content_length_returns_400() {
    let web_root = std::env::temp_dir();
    let (addr, _thr) = start_short_unauth_server(1, web_root);

    let req = "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\n\
                   Content-Type: application/json\r\nContent-Length: not-a-number\r\n\r\n";
    let resp = send_req(addr, req);
    assert!(
        matches!(parse_status(&resp), 400),
        "an unparsable Content-Length must be refused, got {}",
        parse_status(&resp)
    );
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
        assert!(store.validate_post_guard(&session_id, &csrf_token, fingerprint, true).is_ok());
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

    assert!(store.validate_post_guard_at(&session_id, &csrf_token, 7, true, first_seen).is_ok());
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
    let sessions =
        Arc::new(Mutex::new(SessionStore::new_with_capacity(Duration::from_secs(3600), 1)));
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
    store.sessions.get_mut(&session_id).expect("session must exist").expires_at =
        Instant::now() - Duration::from_secs(1);

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

    let runtime =
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("test runtime");
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
        validate_admin_web_max_connections(MAX_ADMIN_WEB_CONNECTIONS + 1).unwrap_err().to_string(),
        "admin web max connections must not exceed 1024"
    );
    assert!(AdminHttpServer::new_with_max_connections(
        "127.0.0.1:0".parse().unwrap(),
        std::env::temp_dir(),
        None,
        None,
        test_handler(),
        0,
    )
    .is_err());
    assert_eq!(
        validate_admin_web_operation_timeout_ms(DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS).unwrap(),
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

    const TEST_OPERATION_TIMEOUT_MS: u64 = 500;
    const SLOW_WORKER_DURATION: Duration = Duration::from_millis(2_500);

    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind admin test listener");
    let addr = listener.local_addr().expect("admin test listener address");
    drop(listener);

    let server = Arc::new(
        AdminHttpServer::new_with_max_connections_and_operation_timeout(
            addr,
            std::env::temp_dir(),
            None,
            None,
            slow_test_handler(SLOW_WORKER_DURATION),
            1,
            TEST_OPERATION_TIMEOUT_MS,
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
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
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

    let mut follow_up =
        TcpStream::connect(addr).await.expect("permit must be released after timeout response");
    follow_up
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("follow-up request write");
    let mut follow_up_response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), follow_up.read_to_end(&mut follow_up_response))
        .await
        .expect("follow-up response must be bounded")
        .expect("follow-up response must be readable");
    assert_eq!(parse_status(&String::from_utf8_lossy(&follow_up_response)), 200);

    let before_shutdown = diagnostics.snapshot();
    assert_eq!(before_shutdown.timeout_ms, TEST_OPERATION_TIMEOUT_MS);
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
            // Timeout behavior has dedicated slow-worker coverage. This fixture isolates
            // panic conversion from platform-dependent spawn_blocking scheduling latency.
            DEFAULT_ADMIN_WEB_OPERATION_TIMEOUT_MS,
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
