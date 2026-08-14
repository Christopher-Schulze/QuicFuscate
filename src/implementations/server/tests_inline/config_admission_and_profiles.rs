use super::*;
#[test]
fn test_server_config_from_listen_addr_resolves_socket() {
    let config = server_config_from_listen_addr(
        "127.0.0.1:4433",
        crate::firewall::FirewallBackend::Iptables,
    )
    .unwrap();
    assert_eq!(config.listen, "127.0.0.1:4433".parse().unwrap());
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_server_config_carries_geoip_and_blacklist_defaults() {
    // Default config should have GeoIP disabled and no blacklist sync URL.
    let config = ServerConfig::default();
    assert!(!config.geoip.is_enabled(), "default geoip should be disabled");
    assert!(config.blacklist.sync_url.is_none(), "default blacklist should have no sync URL");
}

#[cfg(feature = "rate_limiter")]
#[test]
fn blacklist_config_rejects_values_above_absolute_resource_caps() {
    use crate::implementations::server::limits;

    let config = BlacklistConfig {
        default_ttl_secs: limits::MAX_BLACKLIST_TTL_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        sync_interval_secs: limits::MAX_BLACKLIST_SYNC_INTERVAL_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        max_body_bytes: limits::MAX_BLACKLIST_BODY_BYTES + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        max_entries: limits::MAX_BLACKLIST_ENTRIES + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());

    let config = BlacklistConfig {
        request_timeout_secs: limits::MAX_BLACKLIST_REQUEST_TIMEOUT_SECS + 1,
        ..BlacklistConfig::default()
    };
    assert!(config.validate().is_err());
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_shared_server_domain_uses_configured_blacklist() {
    // When ServerConfig has a blacklist sync URL, SharedServerDomain
    // should construct a BlacklistSync with that URL (has_sync_url=true).
    let config = ServerConfig {
        #[cfg(feature = "rate_limiter")]
        blacklist: BlacklistConfig {
            default_ttl_secs: 60,
            sync_url: Some("https://example.com/blocklist".to_string()),
            sync_interval_secs: 300,
            cache_path: None,
            ..BlacklistConfig::default()
        },
        ..ServerConfig::default()
    };
    let domain = SharedServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("shared server domain construction failed: {error}"));
    assert!(domain.blacklist.has_sync_url());
    assert_eq!(domain.blacklist.sync_interval(), Duration::from_secs(300));
}

#[cfg(feature = "rate_limiter")]
#[tokio::test]
async fn blacklist_worker_owner_claims_once_and_cancels_on_stop() {
    let metrics = Metrics::new();
    metrics.configure_blacklist_sync(true, Duration::from_secs(60));
    let owner = BlacklistSyncOwner::new();
    let blacklist = Arc::new(BlacklistSync::manual_only(Duration::from_secs(60)));

    assert_eq!(
        owner.claim_and_spawn(Arc::clone(&blacklist), Duration::from_secs(60)),
        BlacklistSyncClaim::Claimed
    );
    assert_eq!(
        owner.claim_and_spawn(blacklist, Duration::from_secs(60)),
        BlacklistSyncClaim::InFlight
    );
    owner.abandon(&metrics);

    assert!(!owner.has_task());
    assert_eq!(metrics.blacklist_sync_cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_in_flight.load(Ordering::Acquire), 0);

    let completing_owner = BlacklistSyncOwner::new();
    let completing_blacklist = Arc::new(BlacklistSync::manual_only(Duration::from_secs(60)));
    assert_eq!(
        completing_owner.claim_and_spawn(completing_blacklist, Duration::from_secs(60)),
        BlacklistSyncClaim::Claimed
    );
    tokio::task::yield_now().await;
    completing_owner.observe_finished(&metrics).await;
    assert_eq!(metrics.blacklist_sync_failed.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_retry_scheduled.load(Ordering::Relaxed), 1);
    assert_eq!(
        completing_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::NotDue
    );
    assert!(!completing_owner.has_task());

    let shutdown_owner = BlacklistSyncOwner::new();
    assert_eq!(
        shutdown_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::Claimed
    );
    shutdown_owner.shutdown(&metrics).await;
    assert!(!shutdown_owner.has_task());
    assert_eq!(
        shutdown_owner.claim_and_spawn(
            Arc::new(BlacklistSync::manual_only(Duration::from_secs(60))),
            Duration::from_secs(60),
        ),
        BlacklistSyncClaim::Closed
    );
}

#[cfg(feature = "rate_limiter")]
#[tokio::test]
async fn blacklist_shutdown_retains_owned_publication_past_deadline() {
    let owner = Arc::new(BlacklistSyncOwner::new());
    let metrics = Arc::new(Metrics::new());
    metrics.configure_blacklist_sync(true, Duration::from_secs(60));
    let control = Arc::new(crate::implementations::server::limits::BlacklistSyncControl::new());
    assert!(control.begin_publication());
    let release = Arc::new(tokio::sync::Notify::new());
    let release_for_task = Arc::clone(&release);
    let control_for_task = Arc::clone(&control);
    let handle = tokio::spawn(async move {
        release_for_task.notified().await;
        control_for_task.finish();
        Err(crate::implementations::server::limits::BlacklistError::Cancelled)
    });
    owner.state.lock().task = Some(BlacklistSyncTask { handle, control });

    let owner_for_shutdown = Arc::clone(&owner);
    let metrics_for_shutdown = Arc::clone(&metrics);
    let shutdown = tokio::spawn(async move {
        owner_for_shutdown.shutdown(&metrics_for_shutdown).await;
    });
    tokio::time::sleep(BLACKLIST_SYNC_SHUTDOWN_TIMEOUT + Duration::from_millis(25)).await;

    assert!(!shutdown.is_finished(), "publication task was detached at the deadline");
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), shutdown)
        .await
        .expect("owned publication shutdown timed out")
        .expect("owned publication shutdown task panicked");
    assert!(!owner.has_task());
    assert_eq!(metrics.blacklist_sync_cancelled.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.blacklist_sync_shutdown_expired.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "rate_limiter")]
#[test]
fn test_shared_server_domain_uses_configured_geoip() {
    use crate::implementations::server::limits::GeoIpConfig;
    use std::collections::HashSet;
    use std::path::PathBuf;

    let mut countries = HashSet::new();
    countries.insert("XX".to_string());
    let config = ServerConfig {
        #[cfg(feature = "rate_limiter")]
        geoip: GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: countries,
        },
        ..ServerConfig::default()
    };
    let error = match SharedServerDomain::try_new(&config) {
        Ok(_) => panic!("missing GeoIP database must fail domain construction"),
        Err(error) => error,
    };
    assert!(error.contains("GeoIP activation failed"));
    assert!(error.contains("missing"));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn server_runtime_rejects_invalid_geoip_before_live_resources() {
    use crate::implementations::server::limits::GeoIpConfig;
    use std::collections::HashSet;
    use std::path::PathBuf;

    let server_config = ServerConfig {
        geoip: GeoIpConfig {
            db_path: Some(PathBuf::from("/nonexistent/GeoLite2-Country.mmdb")),
            blocked_countries: ["GB".to_string()].into_iter().collect::<HashSet<_>>(),
        },
        ..ServerConfig::default()
    };
    let error = match ServerRuntime::new(EngineConfig::default(), server_config) {
        Ok(_) => panic!("configured missing GeoIP database must reject runtime startup"),
        Err(EngineError::Config(error)) => error,
        Err(other) => panic!("unexpected GeoIP startup error: {other:?}"),
    };
    assert!(error.contains("GeoIP activation failed"));
    assert!(error.contains("missing"));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn sustained_admission_retries_new_initials_and_preserves_established_traffic() {
    use crate::implementations::server::ddos::{DdosDropReason, IncomingDatagramAdmission};
    use crate::implementations::server::limits::DdosPolicyConfig;
    use crate::transport::packet::{format_header, parse_header, verify_retry_tag, Header};

    fn initial_packet(dcid: Vec<u8>, scid: Vec<u8>, token: Vec<u8>) -> Vec<u8> {
        let header = Header {
            ty: crate::transport::PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(token),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 256];
        let length = format_header(&header, &mut storage).expect("Initial header");
        storage[..length].to_vec()
    }

    let config = ServerConfig {
        ddos_policy: DdosPolicyConfig {
            activation_window: Duration::from_secs(1),
            clear_window: Duration::from_secs(5),
            ..DdosPolicyConfig::default()
        },
        blacklist: BlacklistConfig { cache_path: None, ..BlacklistConfig::default() },
        ..ServerConfig::default()
    };
    let domain = LiveServerDomain::try_new(&config)
        .unwrap_or_else(|error| panic!("live server domain construction failed: {error}"));
    let metrics = Metrics::new();
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(100, Duration::ZERO),
        crate::implementations::server::limits::DdosTransition::Unchanged
    );
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(1_000, Duration::from_secs(1)),
        crate::implementations::server::limits::DdosTransition::Unchanged
    );
    assert_eq!(
        domain.shared.ddos_detector.record_pps_at(1_000, Duration::from_secs(2)),
        crate::implementations::server::limits::DdosTransition::Activated
    );

    let remote: SocketAddr = "203.0.113.9:44321".parse().expect("remote address");
    let original_dcid = vec![1, 2, 3, 4];
    let client_scid = vec![5, 6, 7, 8];
    let credential = b"a1b2c3d4e5f6".to_vec();
    let initial = initial_packet(original_dcid.clone(), client_scid.clone(), credential.clone());
    let retry_packet = match domain.admit_incoming_datagram(remote, &initial, false, true, &metrics)
    {
        IncomingDatagramAdmission::Retry(packet) => packet,
        _ => panic!("enhanced admission did not issue Retry"),
    };
    let (retry, _) = parse_header(&retry_packet, 0).expect("Retry header");
    verify_retry_tag(&retry_packet, &original_dcid, crate::transport::PROTOCOL_VERSION)
        .expect("Retry integrity");
    let retry_token = retry.token.clone().expect("Retry token");
    let retried_initial = initial_packet(retry.scid.clone(), client_scid, retry_token.clone());

    assert!(matches!(
        domain.admit_incoming_datagram(remote, &retried_initial, false, true, &metrics),
        IncomingDatagramAdmission::RetryValidated
    ));
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &initial, true, true, &metrics),
        IncomingDatagramAdmission::Allow
    ));
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &initial, false, false, &metrics),
        IncomingDatagramAdmission::Allow
    ));

    let mut tampered_token = retry_token;
    let last = tampered_token.len() - 1;
    tampered_token[last] ^= 1;
    let tampered = initial_packet(retry.scid, vec![9, 10], tampered_token);
    assert!(matches!(
        domain.admit_incoming_datagram(remote, &tampered, false, true, &metrics),
        IncomingDatagramAdmission::Drop(DdosDropReason::InvalidRetry)
    ));
}

#[cfg(feature = "rate_limiter")]
#[test]
fn validated_retry_uses_retry_scid_for_initial_keys_and_restores_qkey_identity() {
    use crate::implementations::server::ddos::RetryTokenManager;
    use crate::implementations::server::limits::{
        AuthAdmission, AuthPolicyConfig, AuthRateLimiter,
    };
    use crate::transport::packet::{format_header, parse_header, Header};

    fn initial_packet(dcid: Vec<u8>, scid: Vec<u8>, token: Vec<u8>) -> Vec<u8> {
        let header = Header {
            ty: crate::transport::PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(token),
            versions: None,
            key_phase: false,
        };
        let mut storage = [0u8; 256];
        let length = format_header(&header, &mut storage).expect("Initial header");
        storage[..length].to_vec()
    }

    let token_hex = "a".repeat(64);
    let qkey = qf_engine_types::generate(
        &qf_engine_types::QKeyConfig::new("127.0.0.1:4433", "example.com")
            .with_stealth("auto")
            .with_fec("auto")
            .with_token(&token_hex),
    );
    let qkey_id = qkey_registry::qkey_id(&qkey);
    let mut registry = QKeyRegistry::new_in_memory(4, None);
    registry.insert(qkey, token_hex.into(), Some("retry-proof".to_string())).expect("QKey insert");
    let registry = std::sync::Mutex::new(registry);

    let remote: SocketAddr = "203.0.113.10:44321".parse().expect("remote address");
    let original_dcid = vec![1, 2, 3, 4];
    let client_scid = vec![5, 6, 7, 8];
    let initial =
        initial_packet(original_dcid.clone(), client_scid.clone(), qkey_id.as_bytes().to_vec());
    let manager = RetryTokenManager::new_with_clock(
        Duration::from_secs(10),
        &crate::time_source::ProtocolClock::default(),
    )
    .expect("Retry manager");
    let issue = manager.issue_for_initial(&initial, remote.ip()).expect("Retry issue");
    let (retry, _) = parse_header(&issue.packet, 0).expect("Retry header");
    let retry_scid = retry.scid.clone();
    let retried = initial_packet(retry.scid, client_scid, retry.token.expect("Retry token"));

    let mut limiter = AuthRateLimiter::new(AuthPolicyConfig::default());
    let attempt = match limiter.begin(remote.ip()) {
        AuthAdmission::Allowed(attempt) => attempt,
        _ => panic!("auth attempt was not admitted"),
    };
    let context = parse_live_server_initial_auth(
        &retried,
        remote.ip(),
        Some(&manager),
        &registry,
        &crate::implementations::server::revocation::RevocationManager::new(),
        attempt,
    )
    .expect("retried Initial authentication");

    assert_eq!(context.initial_key_dcid.as_ref(), retry_scid);
    assert_eq!(context.qkey_record.expect("QKey record").id, qkey_id);
    assert!(context.pending_qkey_auth.is_some());
}

#[test]
fn test_apply_runtime_profile_identity_updates_browser_and_os() {
    let mut stealth = StealthConfig::default();
    apply_runtime_profile_identity(&mut stealth, BrowserProfile::Firefox, OsProfile::Linux);
    assert_eq!(stealth.initial_browser, BrowserProfile::Firefox);
    assert_eq!(stealth.initial_os, OsProfile::Linux);
}

#[test]
fn test_runtime_profile_slots_accept_canonical_at_syntax_only() {
    let at = parse_runtime_profile_entry("safari@macos", OsProfile::Windows)
        .expect("canonical profile slot");
    assert_eq!(at.browser, BrowserProfile::Safari);
    assert_eq!(at.os, OsProfile::MacOS);

    let default_os = parse_runtime_profile_entry("firefox", OsProfile::Linux)
        .expect("browser-only profile slot");
    assert_eq!(default_os.browser, BrowserProfile::Firefox);
    assert_eq!(default_os.os, OsProfile::Linux);

    assert!(parse_runtime_profile_entry("firefox:linux", OsProfile::Windows).is_none());
    assert!(parse_runtime_profile_entry("chrome@windows@linux", OsProfile::Windows).is_none());
    assert!(parse_runtime_profile_entry("safari@windows", OsProfile::Windows).is_none());
}

#[test]
fn runtime_profile_resolution_rejects_invalid_slots_instead_of_dropping_them() {
    let invalid = vec!["firefox@linux".to_string(), "chrome:windows".to_string()];
    let error =
        resolve_runtime_profiles(BrowserProfile::Chrome, OsProfile::Windows, &invalid, true)
            .expect_err("an invalid slot must fail the whole sequence");
    assert!(error.contains("chrome:windows"));

    let empty = resolve_runtime_profiles(BrowserProfile::Chrome, OsProfile::Windows, &[], false)
        .expect("an explicitly empty optional sequence is representable");
    assert!(empty.is_empty());

    let fallback = resolve_runtime_profiles(BrowserProfile::Firefox, OsProfile::Linux, &[], true)
        .expect("empty server sequence falls back to the initial profile");
    assert_eq!(fallback.len(), 1);
    assert_eq!(fallback[0].browser, BrowserProfile::Firefox);
    assert_eq!(fallback[0].os, OsProfile::Linux);
}
