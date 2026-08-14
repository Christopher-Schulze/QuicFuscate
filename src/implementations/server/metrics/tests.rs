use super::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn metrics_server_serves_next_request_while_first_reader_is_silent() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server =
        MetricsServer { addr, metrics: Arc::new(Metrics::new()), shutdown: shutdown.clone() };
    let server_task = tokio::spawn(async move { server.run_listener(listener).await });

    let stalled = TcpStream::connect(addr).await.unwrap();
    let mut valid = TcpStream::connect(addr).await.unwrap();
    valid.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), valid.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    drop(stalled);
    shutdown.store(true, Ordering::SeqCst);
    server_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn global_metrics_server_uses_the_same_bounded_connection_contract() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = GlobalMetricsServer { addr, shutdown: shutdown.clone() };
    let server_task = tokio::spawn(async move { server.run_listener(listener).await });

    let stalled = TcpStream::connect(addr).await.unwrap();
    let mut valid = TcpStream::connect(addr).await.unwrap();
    valid.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), valid.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();

    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    drop(stalled);
    shutdown.store(true, Ordering::SeqCst);
    server_task.await.unwrap().unwrap();
}

/// Read the top-level `status` field of a health body.
fn top_level_status(health: &str) -> String {
    serde_json::from_str::<serde_json::Value>(health)
        .expect("health body is JSON")
        .get("status")
        .and_then(|status| status.as_str())
        .expect("health body has a top-level status")
        .to_string()
}

#[test]
fn every_lifecycle_phase_agrees_across_text_and_json_health() {
    // The nested memory-lock object carries its own `status`, so a substring match
    // would silently read the wrong field.
    // Prometheus, JSON health, and the admin metrics JSON all read one published
    // phase. They used to hardcode up=1 and status=ok, so a probe could not tell a
    // stopped runtime from a live one.
    let metrics = Metrics::new();
    for (phase, expected_status, expected_up) in [
        (LifecyclePhase::Starting, "starting", 0u8),
        (LifecyclePhase::Running, "ok", 1),
        (LifecyclePhase::Draining, "draining", 0),
        (LifecyclePhase::Stopping, "stopping", 0),
        (LifecyclePhase::Stopped, "stopped", 0),
        (LifecyclePhase::StoppedIncomplete, "failed", 0),
    ] {
        metrics.set_lifecycle_phase(phase);
        assert_eq!(metrics.lifecycle_phase(), phase);

        let health = metrics.export_health();
        assert_eq!(
            top_level_status(&health),
            expected_status,
            "{} must report status {expected_status}, got {health}",
            phase.as_str()
        );
        assert!(
            health.contains(&format!("\"lifecycle\":\"{}\"", phase.as_str())),
            "{} must name itself in health, got {health}",
            phase.as_str()
        );

        let text = metrics.export();
        assert!(
            text.contains(&format!("quicfuscate_up {expected_up}\n")),
            "{} must export up={expected_up}",
            phase.as_str()
        );
        assert!(
            text.contains(&format!(
                "quicfuscate_lifecycle_phase{{phase=\"{}\"}} 1",
                phase.as_str()
            )),
            "{} must export its phase label",
            phase.as_str()
        );
    }
}

#[test]
fn a_stopped_runtime_is_never_reported_healthy_by_readiness_alone() {
    // Every readiness input is at its healthiest here. That must not make a stopped
    // runtime look serviceable, which is the exact failure this closes.
    let metrics = Metrics::new();
    metrics.set_tun_data_plane_ready(true);
    metrics.set_lifecycle_phase(LifecyclePhase::Running);
    assert_eq!(top_level_status(&metrics.export_health()), "ok");

    for phase in
        [LifecyclePhase::Stopping, LifecyclePhase::Stopped, LifecyclePhase::StoppedIncomplete]
    {
        metrics.set_lifecycle_phase(phase);
        let health = metrics.export_health();
        assert_ne!(
            top_level_status(&health),
            "ok",
            "{} must not claim healthy service, got {health}",
            phase.as_str()
        );
        assert!(metrics.export().contains("quicfuscate_up 0\n"));
    }

    // Incomplete cleanup is distinct from a clean stop, because it leaves host
    // state behind and an operator has to act.
    metrics.set_lifecycle_phase(LifecyclePhase::StoppedIncomplete);
    assert_eq!(top_level_status(&metrics.export_health()), "failed");
    metrics.set_lifecycle_phase(LifecyclePhase::Stopped);
    assert_eq!(top_level_status(&metrics.export_health()), "stopped");
}

#[test]
fn test_metrics_export() {
    let metrics = Metrics::new();
    // Readiness only decides health while the runtime is running; a fresh Metrics
    // starts in `Starting`, which answers on its own.
    metrics.set_lifecycle_phase(LifecyclePhase::Running);
    metrics.record_connection_accepted();
    metrics.record_connection_rejected();
    metrics.record_ingress_datagram(1_000_000);
    metrics.clients_active.store(42, Ordering::Relaxed);
    metrics.record_uplink_route(UplinkRoute::Internet {
        source: "10.8.0.2".parse().unwrap(),
        destination: "1.1.1.1".parse().unwrap(),
    });
    metrics.record_uplink_drop(UplinkDrop::MalformedPacket);

    let output = metrics.export();
    assert!(output.contains("quicfuscate_up 1"));
    assert!(output.contains("quicfuscate_clients_active 42"));
    assert!(output.contains("quicfuscate_connections_accepted 1"));
    assert!(output.contains("quicfuscate_connections_rejected 1"));
    assert!(output.contains("quicfuscate_bytes_in_total 1000000"));
    assert!(output.contains("quicfuscate_routing_packets_total{outcome=\"internet\"} 1"));
    assert!(output.contains("quicfuscate_routing_packets_total{outcome=\"drop_malformed\"} 1"));
    assert!(output.contains("quicfuscate_audit_dropped_events_total"));
    assert!(output.contains("quicfuscate_audit_payload_rejections_total"));
    assert!(output.contains("quicfuscate_audit_persistence_errors_total"));
    assert!(output.contains("quicfuscate_audit_terminal_dropped_events_total"));
    assert!(output.contains("quicfuscate_audit_slow_flushes_total"));
    assert!(output.contains("quicfuscate_audit_shutdown_failures_total"));
}

#[test]
fn tun_downlink_backpressure_metrics_expose_depth_and_terminal_cause() {
    let metrics = Metrics::new();
    metrics.set_tun_downlink_backpressure_pending(3, 1_024);
    metrics.record_tun_downlink_backpressure_enqueued();
    metrics.record_tun_downlink_backpressure_retry();
    metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::ByteCapacity);
    metrics.record_tun_downlink_backpressure_drop(TunDownlinkBackpressureDrop::Expired);

    let output = metrics.export();

    assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_packets 3"));
    assert!(output.contains("quicfuscate_tun_downlink_backpressure_pending_bytes 1024"));
    assert!(
        output.contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"enqueued\"} 1")
    );
    assert!(
        output.contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"retried\"} 1")
    );
    assert!(output.contains(
        "quicfuscate_tun_downlink_backpressure_events_total{event=\"drop_byte_capacity\"} 1"
    ));
    assert!(output
        .contains("quicfuscate_tun_downlink_backpressure_events_total{event=\"drop_expired\"} 1"));
}

#[test]
fn tun_data_plane_faults_fail_health_and_are_exported() {
    let metrics = Metrics::new();
    // Readiness only decides health while the runtime is running; a fresh Metrics
    // starts in `Starting`, which answers on its own.
    metrics.set_lifecycle_phase(LifecyclePhase::Running);
    metrics.record_tun_data_plane_fault();

    let output = metrics.export();
    assert!(output.contains("quicfuscate_tun_data_plane_ready 0"));
    assert!(output.contains("quicfuscate_tun_data_plane_faults_total 1"));

    let health = metrics.export_health();
    assert!(health.contains("\"status\":\"not_ready\""));
    assert!(health.contains("\"tun_data_plane_ready\":0"));
}

#[test]
fn bandwidth_metrics_expose_direction_outcome_and_scheduler_state() {
    let metrics = Metrics::new();
    metrics.record_bandwidth_decision(
        BandwidthDirection::Uplink,
        BandwidthDecision::Allowed,
        1_250,
    );
    metrics.record_bandwidth_decision(
        BandwidthDirection::Downlink,
        BandwidthDecision::RateLimited,
        500,
    );
    metrics.record_bandwidth_decision(
        BandwidthDirection::Uplink,
        BandwidthDecision::DailyQuotaExceeded,
        500,
    );
    metrics.record_bandwidth_decision(
        BandwidthDirection::Downlink,
        BandwidthDecision::MonthlyQuotaExceeded,
        500,
    );
    metrics.set_bandwidth_scheduler_active_clients(3);
    metrics.record_bandwidth_scheduler_enqueue();
    metrics.record_bandwidth_scheduler_delivery(1_200);

    let output = metrics.export();
    assert!(output.contains("quicfuscate_bandwidth_allowed_bytes_total{direction=\"uplink\"} 1250"));
    assert!(output.contains(
        "quicfuscate_bandwidth_denials_total{direction=\"downlink\",outcome=\"rate_limited\"} 1"
    ));
    assert!(output.contains(
        "quicfuscate_bandwidth_denials_total{direction=\"uplink\",outcome=\"daily_quota_exceeded\"} 1"
    ));
    assert!(output.contains(
        "quicfuscate_bandwidth_denials_total{direction=\"downlink\",outcome=\"monthly_quota_exceeded\"} 1"
    ));
    assert!(output.contains("quicfuscate_bandwidth_scheduler_active_clients 3"));
    assert!(output.contains("quicfuscate_bandwidth_scheduler_enqueued_total 1"));
    assert!(output.contains("quicfuscate_bandwidth_scheduler_delivered_total{unit=\"packets\"} 1"));
    assert!(output.contains("quicfuscate_bandwidth_scheduler_delivered_total{unit=\"bytes\"} 1200"));
}

#[test]
fn masque_downlink_response_metrics_expose_retry_and_terminal_causes() {
    let metrics = Metrics::new();
    metrics.record_masque_downlink_response_retry();
    metrics.record_masque_downlink_response_drop(
        qf_transport_types::MasqueDownlinkQueueReject::PacketCapacity,
    );
    metrics.record_masque_downlink_response_drop(
        qf_transport_types::MasqueDownlinkQueueReject::ByteCapacity,
    );
    metrics.record_masque_downlink_response_terminal_drop(2);
    metrics.record_masque_downlink_response_shutdown_drop(3);

    let output = metrics.export();

    assert!(
        output.contains("quicfuscate_masque_downlink_response_events_total{event=\"retried\"} 1")
    );
    assert!(output.contains(
        "quicfuscate_masque_downlink_response_events_total{event=\"drop_packet_capacity\"} 1"
    ));
    assert!(output.contains(
        "quicfuscate_masque_downlink_response_events_total{event=\"drop_byte_capacity\"} 1"
    ));
    assert!(output.contains(
        "quicfuscate_masque_downlink_response_events_total{event=\"drop_terminal_transport_error\"} 2"
    ));
    assert!(output
        .contains("quicfuscate_masque_downlink_response_events_total{event=\"drop_shutdown\"} 3"));
}

#[test]
fn dns_intercept_drop_metric_is_exported_and_rate_limited() {
    let metrics = Metrics::new();
    metrics.record_dns_intercept_drop();

    let output = metrics.export();

    assert!(output.contains("quicfuscate_dns_intercept_dropped_total 1"));
    assert_eq!(metrics.dns_intercept_dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn dns_intercept_admission_outcomes_are_exported_by_reason() {
    let metrics = Metrics::new();
    metrics.record_dns_intercept_admitted();
    metrics.record_dns_intercept_admission_reject(crate::dns::DnsAdmissionReject::InFlight);
    metrics.record_dns_intercept_admission_reject(crate::dns::DnsAdmissionReject::GlobalRate);

    let output = metrics.export();

    assert!(
        output.contains("quicfuscate_dns_intercept_admission_events_total{event=\"admitted\"} 1")
    );
    assert!(output.contains(
        "quicfuscate_dns_intercept_admission_events_total{event=\"rejected_in_flight\"} 1"
    ));
    assert!(output.contains(
        "quicfuscate_dns_intercept_admission_events_total{event=\"rejected_global_rate\"} 1"
    ));
    assert_eq!(metrics.dns_intercept_dropped.load(Ordering::Relaxed), 2);
}

#[test]
fn dns_intercept_worker_events_are_exported_without_rate_limit_side_effects() {
    let metrics = Metrics::new();
    metrics.record_dns_intercept_worker_event(DnsInterceptWorkerEvent::QueuedCancellation);
    metrics.record_dns_intercept_worker_event(DnsInterceptWorkerEvent::ShutdownExpired);
    metrics.record_dns_intercept_worker_event(DnsInterceptWorkerEvent::QueueRejectedByteCapacity);

    let output = metrics.export();

    assert!(output.contains(
        "quicfuscate_dns_intercept_worker_events_total{event=\"queued_cancellation\"} 1"
    ));
    assert!(output
        .contains("quicfuscate_dns_intercept_worker_events_total{event=\"shutdown_expired\"} 1"));
    assert!(output.contains(
        "quicfuscate_dns_intercept_worker_events_total{event=\"queue_rejected_byte_capacity\"} 1"
    ));
    assert_eq!(metrics.rate_limited.load(Ordering::Relaxed), 0);
}

#[test]
fn blacklist_sync_events_and_health_freshness_are_exported() {
    let metrics = Metrics::new();
    metrics.configure_blacklist_sync(true, Duration::from_secs(60));
    metrics.record_blacklist_sync_event(BlacklistSyncEvent::Started);
    metrics.record_blacklist_sync_success(3);

    let output = metrics.export();
    assert!(output.contains("quicfuscate_blacklist_sync_events_total{event=\"started\"} 1"));
    assert!(output.contains("quicfuscate_blacklist_sync_events_total{event=\"succeeded\"} 1"));
    assert!(output.contains("quicfuscate_blacklist_sync_active_entries 3"));
    let health = metrics.export_health();
    assert!(health.contains("\"blacklist_sync\""));
    assert!(health.contains("\"stale\":false"));
    assert!(health.contains("\"active_entries\":3"));
}

#[test]
fn client_fanout_drop_metric_is_exported() {
    let metrics = Metrics::new();
    metrics.record_client_fanout_drop();

    let output = metrics.export();

    assert!(output.contains("quicfuscate_client_fanout_dropped_total 1"));
    assert_eq!(metrics.client_fanout_dropped.load(Ordering::Relaxed), 1);
}

#[test]
fn fec_metrics_project_real_process_wire_producers() {
    let metrics = Metrics::new();
    let emitted_before = metrics.fec_packets_encoded.load(Ordering::Relaxed);
    let decoded_before = metrics.fec_packets_decoded.load(Ordering::Relaxed);
    let recovered_before = metrics.fec_packets_recovered.load(Ordering::Relaxed);

    crate::telemetry::fec_observe_wire_send(true, 100, 100);
    crate::telemetry::fec_observe_wire_send(false, 0, 132);
    crate::telemetry::fec_observe_wire_receive(false, 0, 132, 2, 2, 180);

    assert!(metrics.fec_packets_encoded.load(Ordering::Relaxed) >= emitted_before + 2);
    assert!(metrics.fec_packets_decoded.load(Ordering::Relaxed) >= decoded_before + 2);
    assert!(metrics.fec_packets_recovered.load(Ordering::Relaxed) >= recovered_before + 2);
}

#[test]
fn allocation_metrics_project_real_process_producers() {
    let metrics = Metrics::new();
    let tls_before = crate::telemetry::MEM_POOL_HITS_TLS.get();
    let ephemeral_before = crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.get();
    let body_before = crate::telemetry::BODY_POOL_ALLOCS.get();

    crate::telemetry::MEM_POOL_HITS_TLS.inc();
    crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
    crate::telemetry::BODY_POOL_ALLOCS.inc();

    let output = metrics.export();
    let exported_value = |metric: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(metric))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or_default()
    };
    assert!(
        exported_value("quicfuscate_mem_pool_allocations_total{source=\"thread_local\"}")
            > tls_before
    );
    assert!(
        exported_value("quicfuscate_mem_pool_allocations_total{source=\"ephemeral\"}")
            > ephemeral_before
    );
    assert!(exported_value("quicfuscate_body_pool_allocations_total") > body_before);
    assert!(output.contains("quicfuscate_mem_pool_in_use "));
    assert!(output.contains("quicfuscate_mem_pool_usage_bytes "));
}

#[test]
fn test_health_export() {
    let metrics = Metrics::new();
    metrics.clients_active.store(10, Ordering::Relaxed);

    let output = metrics.export_health();
    assert!(output.contains("\"status\":\"ok\""));
    assert!(output.contains("\"clients\":10"));
    assert!(output.contains("\"geoip_status\":\"disabled\""));
}

#[test]
fn memory_lock_health_exposes_degraded_and_not_ready_states() {
    let metrics = Metrics::new();
    metrics.set_memory_lock_status(qf_memory_lock::MemoryLockStartupStatus {
        policy: qf_memory_lock::MemoryLockFailurePolicy::BestEffort,
        state: qf_memory_lock::MemoryLockState::Degraded,
        process_mode: qf_memory_lock::MemoryLockProcessMode::None,
        limit: qf_memory_lock::MemoryLockLimit::Unknown,
        failure: Some(qf_memory_lock::MemoryLockFailureKind::RlimitQuery),
    });
    let degraded = metrics.export_health();
    assert!(degraded.contains("\"status\":\"degraded\""));
    assert!(degraded.contains("\"memory_lock\""));
    assert!(degraded.contains("\"failure\":\"rlimit-query\""));

    metrics.set_memory_lock_status(qf_memory_lock::MemoryLockStartupStatus {
        policy: qf_memory_lock::MemoryLockFailurePolicy::FailClosed,
        state: qf_memory_lock::MemoryLockState::Failed,
        process_mode: qf_memory_lock::MemoryLockProcessMode::None,
        limit: qf_memory_lock::MemoryLockLimit::Finite(4096),
        failure: Some(qf_memory_lock::MemoryLockFailureKind::Mlockall),
    });
    let failed = metrics.export_health();
    assert!(failed.contains("\"status\":\"not_ready\""));
    assert!(failed.contains("\"policy\":\"fail-closed\""));
    assert!(failed.contains("\"limit_bytes\":4096"));
}

#[test]
fn geoip_metrics_expose_activation_state_lookup_counters_and_failed_health() {
    let metrics = Metrics::new();
    // Readiness only decides health while the runtime is running; a fresh Metrics
    // starts in `Starting`, which answers on its own.
    metrics.set_lifecycle_phase(LifecyclePhase::Running);
    use crate::implementations::server::limits::GeoIpStatus;

    metrics.record_geoip_lookup();
    metrics.record_geoip_blocked();
    metrics.record_geoip_lookup_error();
    metrics.set_geoip_status(GeoIpStatus::Active);

    let output = metrics.export();
    for expected in [
        "quicfuscate_geoip_activation{state=\"active\"} 1",
        "quicfuscate_geoip_activation{state=\"disabled\"} 0",
        "quicfuscate_geoip_activation{state=\"failed\"} 0",
        "quicfuscate_geoip_lookups_total 1",
        "quicfuscate_geoip_blocked_total 1",
        "quicfuscate_geoip_lookup_errors_total 1",
    ] {
        assert!(output.contains(expected), "missing GeoIP metric: {expected}");
    }
    assert!(metrics.export_health().contains("\"status\":\"ok\""));
    assert!(metrics.export_health().contains("\"geoip_status\":\"active\""));

    metrics.set_geoip_status(GeoIpStatus::Failed);
    let failed_health = metrics.export_health();
    assert!(failed_health.contains("\"status\":\"not_ready\""));
    assert!(failed_health.contains("\"geoip_status\":\"failed\""));
}

#[test]
fn auth_policy_metrics_export_distinct_terminal_and_admission_families() {
    let metrics = Metrics::new();
    metrics.record_auth_attempt();
    metrics.record_auth_success();
    metrics.record_auth_failure();
    metrics.record_auth_backoff_rejection();
    metrics.record_auth_blocked_rejection();
    metrics.record_auth_capacity_rejection();
    metrics.record_auth_abandoned();
    metrics.set_auth_state_tracked_ips(7);
    metrics.record_auth_state_pruned(3);
    metrics.record_revocation_pruned(4);

    let output = metrics.export();
    for metric in [
        "quicfuscate_auth_attempts_total 1",
        "quicfuscate_auth_succeeded_total 1",
        "quicfuscate_auth_failed_total 1",
        "quicfuscate_auth_backoff_rejected_total 1",
        "quicfuscate_auth_blocked_rejected_total 1",
        "quicfuscate_auth_capacity_rejected_total 1",
        "quicfuscate_auth_abandoned_total 1",
        "quicfuscate_auth_state_tracked_ips 7",
        "quicfuscate_auth_state_pruned_total 3",
        "quicfuscate_revocation_pruned_total 4",
    ] {
        assert!(output.contains(metric), "missing auth policy metric: {metric}");
    }
}

#[test]
fn ddos_metrics_expose_state_retry_and_exact_drop_causes() {
    let metrics = Metrics::new();
    metrics.record_ddos_sample(
        42_000,
        crate::implementations::server::limits::DdosTransition::Activated,
    );
    metrics.record_ddos_retry_issued();
    metrics.record_ddos_retry_validated();
    for reason in [
        crate::implementations::server::ddos::DdosDropReason::GlobalLimit,
        crate::implementations::server::ddos::DdosDropReason::GeoIp,
        crate::implementations::server::ddos::DdosDropReason::Blacklist,
        crate::implementations::server::ddos::DdosDropReason::PerIpLimit,
        crate::implementations::server::ddos::DdosDropReason::MalformedInitial,
        crate::implementations::server::ddos::DdosDropReason::InvalidRetry,
    ] {
        metrics.record_ddos_drop(reason);
    }
    metrics
        .record_ddos_sample(1_000, crate::implementations::server::limits::DdosTransition::Cleared);

    let output = metrics.export();
    for expected in [
        "quicfuscate_ddos_active 0",
        "quicfuscate_ddos_current_pps 1000",
        "quicfuscate_ddos_transitions_total{transition=\"activated\"} 1",
        "quicfuscate_ddos_transitions_total{transition=\"cleared\"} 1",
        "quicfuscate_ddos_retry_total{outcome=\"issued\"} 1",
        "quicfuscate_ddos_retry_total{outcome=\"validated\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"global_limit\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"geoip\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"blacklist\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"per_ip_limit\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"malformed_initial\"} 1",
        "quicfuscate_ddos_drops_total{reason=\"invalid_retry\"} 1",
    ] {
        assert!(output.contains(expected), "missing DDoS metric: {expected}");
    }
}

#[test]
fn test_metrics_mirror_global_instrumentation_for_runtime_events() {
    let global = crate::instrumentation::global();
    let rejected_before = global.server.connections_rejected.load(Ordering::Relaxed);
    let auth_failed_before = global.server.auth_failed.load(Ordering::Relaxed);
    let rate_limited_before = global.server.rate_limited.load(Ordering::Relaxed);
    let bytes_in_before = global.transport.bytes_in.load(Ordering::Relaxed);
    let bytes_out_before = global.transport.bytes_out.load(Ordering::Relaxed);
    let packets_in_before = global.transport.packets_in.load(Ordering::Relaxed);
    let packets_out_before = global.transport.packets_out.load(Ordering::Relaxed);

    let metrics = Metrics::new();
    metrics.record_connection_rejected();
    metrics.record_auth_failure();
    metrics.record_rate_limited();
    metrics.record_ingress_datagram(321);
    metrics.record_egress_datagram(654);

    assert!(global.server.connections_rejected.load(Ordering::Relaxed) > rejected_before);
    assert!(global.server.auth_failed.load(Ordering::Relaxed) > auth_failed_before);
    assert!(global.server.rate_limited.load(Ordering::Relaxed) > rate_limited_before);
    assert!(global.transport.bytes_in.load(Ordering::Relaxed) >= bytes_in_before + 321);
    assert!(global.transport.bytes_out.load(Ordering::Relaxed) >= bytes_out_before + 654);
    assert!(global.transport.packets_in.load(Ordering::Relaxed) > packets_in_before);
    assert!(global.transport.packets_out.load(Ordering::Relaxed) > packets_out_before);
}
