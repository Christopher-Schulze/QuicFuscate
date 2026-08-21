use super::*;

impl Metrics {
    /// Export as Prometheus text format.
    pub fn export(&self) -> String {
        let mut out = String::with_capacity(16 * 1024);
        macro_rules! write_metric {
            ($($arg:tt)*) => {{
                let _ = write!(out, $($arg)*);
            }};
        }

        // Server info
        let phase = self.lifecycle_phase();
        out.push_str("# HELP quicfuscate_up Server is serving traffic\n");
        out.push_str("# TYPE quicfuscate_up gauge\n");
        write_metric!("quicfuscate_up {}\n\n", u8::from(phase.is_up()));

        out.push_str("# HELP quicfuscate_lifecycle_phase Current server lifecycle phase\n");
        out.push_str("# TYPE quicfuscate_lifecycle_phase gauge\n");
        write_metric!("quicfuscate_lifecycle_phase{{phase=\"{}\"}} 1\n\n", phase.as_str());

        out.push_str("# HELP quicfuscate_uptime_seconds Server uptime\n");
        out.push_str("# TYPE quicfuscate_uptime_seconds counter\n");
        write_metric!("quicfuscate_uptime_seconds {}\n\n", self.uptime_secs());

        // Clients
        out.push_str("# HELP quicfuscate_clients_active Current active clients\n");
        out.push_str("# TYPE quicfuscate_clients_active gauge\n");
        write_metric!(
            "quicfuscate_clients_active {}\n\n",
            self.clients_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_clients_total Total clients connected\n");
        out.push_str("# TYPE quicfuscate_clients_total counter\n");
        write_metric!(
            "quicfuscate_clients_total {}\n\n",
            self.clients_total.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_accepted Accepted connections\n");
        out.push_str("# TYPE quicfuscate_connections_accepted counter\n");
        write_metric!(
            "quicfuscate_connections_accepted {}\n\n",
            self.connections_accepted.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_connections_rejected Rejected connections\n");
        out.push_str("# TYPE quicfuscate_connections_rejected counter\n");
        write_metric!(
            "quicfuscate_connections_rejected {}\n\n",
            self.connections_rejected.load(Ordering::Relaxed)
        );

        // Traffic
        out.push_str("# HELP quicfuscate_bytes_in_total Total bytes received\n");
        out.push_str("# TYPE quicfuscate_bytes_in_total counter\n");
        write_metric!("quicfuscate_bytes_in_total {}\n\n", self.bytes_in.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_bytes_out_total Total bytes sent\n");
        out.push_str("# TYPE quicfuscate_bytes_out_total counter\n");
        write_metric!("quicfuscate_bytes_out_total {}\n\n", self.bytes_out.load(Ordering::Relaxed));

        out.push_str("# HELP quicfuscate_packets_in_total Total packets received\n");
        out.push_str("# TYPE quicfuscate_packets_in_total counter\n");
        write_metric!(
            "quicfuscate_packets_in_total {}\n\n",
            self.packets_in.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_packets_out_total Total packets sent\n");
        out.push_str("# TYPE quicfuscate_packets_out_total counter\n");
        write_metric!(
            "quicfuscate_packets_out_total {}\n\n",
            self.packets_out.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_routing_packets_total Packets by typed routing outcome\n");
        out.push_str("# TYPE quicfuscate_routing_packets_total counter\n");
        for (outcome, value) in [
            ("internet", self.routing_internet.load(Ordering::Relaxed)),
            ("client", self.routing_client.load(Ordering::Relaxed)),
            ("broadcast", self.routing_broadcast.load(Ordering::Relaxed)),
            ("multicast", self.routing_multicast.load(Ordering::Relaxed)),
            ("drop_missing_session", self.routing_drop_missing_session.load(Ordering::Relaxed)),
            ("drop_malformed", self.routing_drop_malformed.load(Ordering::Relaxed)),
            ("drop_spoofed", self.routing_drop_spoofed.load(Ordering::Relaxed)),
            ("drop_inter_client", self.routing_drop_inter_client.load(Ordering::Relaxed)),
            ("local", self.routing_local.load(Ordering::Relaxed)),
            ("unicast", self.routing_unicast.load(Ordering::Relaxed)),
            ("fanout", self.routing_fanout.load(Ordering::Relaxed)),
            ("unknown", self.routing_unknown.load(Ordering::Relaxed)),
            ("packet_too_big", self.routing_packet_too_big.load(Ordering::Relaxed)),
            ("time_exceeded", self.routing_time_exceeded.load(Ordering::Relaxed)),
            ("icmpv6", self.routing_icmpv6.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_routing_packets_total{{outcome=\"{outcome}\"}} {value}\n");
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_packets Current packets retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_packets gauge\n");
        write_metric!(
            "quicfuscate_tun_downlink_backpressure_pending_packets {}\n\n",
            self.tun_downlink_backpressure_pending_packets.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_pending_bytes Current bytes retained for retry after QUIC DATAGRAM queue pressure\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_pending_bytes gauge\n");
        write_metric!(
            "quicfuscate_tun_downlink_backpressure_pending_bytes {}\n\n",
            self.tun_downlink_backpressure_pending_bytes.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_tun_downlink_backpressure_events_total Server TUN downlink retry queue events\n");
        out.push_str("# TYPE quicfuscate_tun_downlink_backpressure_events_total counter\n");
        for (event, value) in [
            ("enqueued", self.tun_downlink_backpressure_enqueued.load(Ordering::Relaxed)),
            ("retried", self.tun_downlink_backpressure_retried.load(Ordering::Relaxed)),
            (
                "drop_queue_capacity",
                self.tun_downlink_backpressure_drop_queue_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_byte_capacity",
                self.tun_downlink_backpressure_drop_byte_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_per_target_capacity",
                self.tun_downlink_backpressure_drop_per_target_capacity.load(Ordering::Relaxed),
            ),
            ("drop_expired", self.tun_downlink_backpressure_drop_expired.load(Ordering::Relaxed)),
            (
                "drop_terminal_transport_error",
                self.tun_downlink_backpressure_drop_terminal_transport_error
                    .load(Ordering::Relaxed),
            ),
            ("drop_shutdown", self.tun_downlink_backpressure_drop_shutdown.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_tun_downlink_backpressure_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push_str("# HELP quicfuscate_tun_write_backpressure_absorbed_total Server TUN write EAGAIN events absorbed without data-plane failure\n");
        out.push_str("# TYPE quicfuscate_tun_write_backpressure_absorbed_total counter\n");
        write_metric!(
            "quicfuscate_tun_write_backpressure_absorbed_total {}\n\n",
            self.tun_write_backpressure_absorbed.load(Ordering::Relaxed)
        );
        out.push('\n');

        out.push_str("# HELP quicfuscate_tun_data_plane_ready Whether the requested server TUN data plane is available\n");
        out.push_str("# TYPE quicfuscate_tun_data_plane_ready gauge\n");
        write_metric!(
            "quicfuscate_tun_data_plane_ready {}\n\n",
            self.tun_data_plane_ready.load(Ordering::Acquire)
        );
        out.push_str("# HELP quicfuscate_tun_data_plane_faults_total Terminal server TUN data-plane faults\n");
        out.push_str("# TYPE quicfuscate_tun_data_plane_faults_total counter\n");
        write_metric!(
            "quicfuscate_tun_data_plane_faults_total {}\n\n",
            self.tun_data_plane_faults.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_bandwidth_allowed_bytes_total Bytes admitted by per-session policy\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_allowed_bytes_total counter\n");
        for (direction, value) in [
            ("uplink", self.bandwidth_uplink_allowed_bytes.load(Ordering::Relaxed)),
            ("downlink", self.bandwidth_downlink_allowed_bytes.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_allowed_bytes_total{{direction=\"{direction}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_bandwidth_denials_total Per-session bandwidth denials by typed outcome\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_denials_total counter\n");
        for (direction, outcome, value) in [
            ("uplink", "rate_limited", self.bandwidth_uplink_rate_limited.load(Ordering::Relaxed)),
            (
                "downlink",
                "rate_limited",
                self.bandwidth_downlink_rate_limited.load(Ordering::Relaxed),
            ),
            (
                "uplink",
                "daily_quota_exceeded",
                self.bandwidth_uplink_daily_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "downlink",
                "daily_quota_exceeded",
                self.bandwidth_downlink_daily_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "uplink",
                "monthly_quota_exceeded",
                self.bandwidth_uplink_monthly_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "downlink",
                "monthly_quota_exceeded",
                self.bandwidth_downlink_monthly_quota_exceeded.load(Ordering::Relaxed),
            ),
            (
                "uplink",
                "clock_unavailable",
                self.bandwidth_uplink_clock_unavailable.load(Ordering::Relaxed),
            ),
            (
                "downlink",
                "clock_unavailable",
                self.bandwidth_downlink_clock_unavailable.load(Ordering::Relaxed),
            ),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_denials_total{{direction=\"{direction}\",outcome=\"{outcome}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_bandwidth_scheduler_active_clients Current clients in the bounded DRR queue\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_scheduler_active_clients gauge\n");
        write_metric!(
            "quicfuscate_bandwidth_scheduler_active_clients {}\n\n",
            self.bandwidth_scheduler_active_clients.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_bandwidth_scheduler_enqueued_total Packets admitted to the bounded DRR queue\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_scheduler_enqueued_total counter\n");
        write_metric!(
            "quicfuscate_bandwidth_scheduler_enqueued_total {}\n\n",
            self.bandwidth_scheduler_enqueued_packets.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_bandwidth_scheduler_delivered_total DRR deliveries by unit\n",
        );
        out.push_str("# TYPE quicfuscate_bandwidth_scheduler_delivered_total counter\n");
        for (unit, value) in [
            ("packets", self.bandwidth_scheduler_delivered_packets.load(Ordering::Relaxed)),
            ("bytes", self.bandwidth_scheduler_delivered_bytes.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_bandwidth_scheduler_delivered_total{{unit=\"{unit}\"}} {value}\n"
            );
        }
        out.push('\n');

        out.push_str("# HELP quicfuscate_masque_downlink_response_events_total Server-generated MASQUE response queue events\n");
        out.push_str("# TYPE quicfuscate_masque_downlink_response_events_total counter\n");
        for (event, value) in [
            ("retried", self.masque_downlink_response_retried.load(Ordering::Relaxed)),
            (
                "drop_packet_capacity",
                self.masque_downlink_response_drop_packet_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_byte_capacity",
                self.masque_downlink_response_drop_byte_capacity.load(Ordering::Relaxed),
            ),
            (
                "drop_terminal_transport_error",
                self.masque_downlink_response_drop_terminal_transport_error.load(Ordering::Relaxed),
            ),
            ("drop_shutdown", self.masque_downlink_response_drop_shutdown.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_masque_downlink_response_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');

        out.push_str(
            "# HELP quicfuscate_dns_intercept_dropped_total DNS queries dropped before blocking upstream resolution\n",
        );
        out.push_str("# TYPE quicfuscate_dns_intercept_dropped_total counter\n");
        write_metric!(
            "quicfuscate_dns_intercept_dropped_total {}\n\n",
            self.dns_intercept_dropped.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_dns_intercept_admission_events_total DNS admission outcomes before upstream work\n",
        );
        out.push_str("# TYPE quicfuscate_dns_intercept_admission_events_total counter\n");
        for (event, value) in [
            ("admitted", self.dns_intercept_admitted.load(Ordering::Relaxed)),
            (
                "rejected_in_flight",
                self.dns_intercept_admission_rejected_in_flight.load(Ordering::Relaxed),
            ),
            (
                "rejected_global_rate",
                self.dns_intercept_admission_rejected_global_rate.load(Ordering::Relaxed),
            ),
            (
                "rejected_identity_rate",
                self.dns_intercept_admission_rejected_identity_rate.load(Ordering::Relaxed),
            ),
            (
                "rejected_identity_capacity",
                self.dns_intercept_admission_rejected_identity_capacity.load(Ordering::Relaxed),
            ),
        ] {
            write_metric!(
                "quicfuscate_dns_intercept_admission_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_dns_intercept_worker_events_total DNS intercept worker lifecycle and terminal outcomes\n",
        );
        out.push_str("# TYPE quicfuscate_dns_intercept_worker_events_total counter\n");
        for (event, value) in [
            DnsInterceptWorkerEvent::ClosedBeforeSpawn,
            DnsInterceptWorkerEvent::ResponseQueued,
            DnsInterceptWorkerEvent::EmptyResponse,
            DnsInterceptWorkerEvent::ResponseBuildFailed,
            DnsInterceptWorkerEvent::LatePublication,
            DnsInterceptWorkerEvent::QueueRejectedPacketCapacity,
            DnsInterceptWorkerEvent::QueueRejectedByteCapacity,
            DnsInterceptWorkerEvent::Panic,
            DnsInterceptWorkerEvent::QueuedCancellation,
            DnsInterceptWorkerEvent::StartedCancellation,
            DnsInterceptWorkerEvent::ShutdownExpired,
            DnsInterceptWorkerEvent::JoinError,
        ]
        .into_iter()
        .map(|event| {
            let value = match event {
                DnsInterceptWorkerEvent::ClosedBeforeSpawn => {
                    self.dns_intercept_worker_closed_before_spawn.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ResponseQueued => {
                    self.dns_intercept_worker_response_queued.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::EmptyResponse => {
                    self.dns_intercept_worker_empty_response.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ResponseBuildFailed => {
                    self.dns_intercept_worker_response_build_failed.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::LatePublication => {
                    self.dns_intercept_worker_late_publication.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueueRejectedPacketCapacity => {
                    self.dns_intercept_worker_queue_rejected_packet_capacity.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueueRejectedByteCapacity => {
                    self.dns_intercept_worker_queue_rejected_byte_capacity.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::Panic => {
                    self.dns_intercept_worker_panic.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::QueuedCancellation => {
                    self.dns_intercept_worker_queued_cancellation.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::StartedCancellation => {
                    self.dns_intercept_worker_started_cancellation.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::ShutdownExpired => {
                    self.dns_intercept_worker_shutdown_expired.load(Ordering::Relaxed)
                }
                DnsInterceptWorkerEvent::JoinError => {
                    self.dns_intercept_worker_join_error.load(Ordering::Relaxed)
                }
            };
            (event.as_str(), value)
        }) {
            write_metric!(
                "quicfuscate_dns_intercept_worker_events_total{{event=\"{event}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_blacklist_sync_events_total External blacklist synchronizer lifecycle outcomes\n",
        );
        out.push_str("# TYPE quicfuscate_blacklist_sync_events_total counter\n");
        for event in [
            BlacklistSyncEvent::Started,
            BlacklistSyncEvent::Succeeded,
            BlacklistSyncEvent::CacheLoaded,
            BlacklistSyncEvent::Failed,
            BlacklistSyncEvent::Cancelled,
            BlacklistSyncEvent::SkippedInFlight,
            BlacklistSyncEvent::RetryScheduled,
            BlacklistSyncEvent::ShutdownExpired,
        ] {
            let value = match event {
                BlacklistSyncEvent::Started => self.blacklist_sync_started.load(Ordering::Relaxed),
                BlacklistSyncEvent::Succeeded => {
                    self.blacklist_sync_succeeded.load(Ordering::Relaxed)
                }
                BlacklistSyncEvent::CacheLoaded => {
                    self.blacklist_sync_cache_loaded.load(Ordering::Relaxed)
                }
                BlacklistSyncEvent::Failed => self.blacklist_sync_failed.load(Ordering::Relaxed),
                BlacklistSyncEvent::Cancelled => {
                    self.blacklist_sync_cancelled.load(Ordering::Relaxed)
                }
                BlacklistSyncEvent::SkippedInFlight => {
                    self.blacklist_sync_skipped_in_flight.load(Ordering::Relaxed)
                }
                BlacklistSyncEvent::RetryScheduled => {
                    self.blacklist_sync_retry_scheduled.load(Ordering::Relaxed)
                }
                BlacklistSyncEvent::ShutdownExpired => {
                    self.blacklist_sync_shutdown_expired.load(Ordering::Relaxed)
                }
            };
            write_metric!(
                "quicfuscate_blacklist_sync_events_total{{event=\"{}\"}} {}\n",
                event.as_str(),
                value
            );
        }
        out.push_str("# HELP quicfuscate_blacklist_sync_in_flight Active feed synchronizer task\n");
        out.push_str("# TYPE quicfuscate_blacklist_sync_in_flight gauge\n");
        write_metric!(
            "quicfuscate_blacklist_sync_in_flight {}\n",
            self.blacklist_sync_in_flight.load(Ordering::Acquire)
        );
        out.push_str(
            "# HELP quicfuscate_blacklist_sync_active_entries Current active feed entries\n",
        );
        out.push_str("# TYPE quicfuscate_blacklist_sync_active_entries gauge\n");
        write_metric!(
            "quicfuscate_blacklist_sync_active_entries {}\n\n",
            self.blacklist_sync_active_entries.load(Ordering::Acquire)
        );
        out.push_str(
            "# HELP quicfuscate_client_fanout_dropped_total Broadcast/multicast packets dropped before fan-out queue admission\n",
        );
        out.push_str("# TYPE quicfuscate_client_fanout_dropped_total counter\n");
        write_metric!(
            "quicfuscate_client_fanout_dropped_total {}\n\n",
            self.client_fanout_dropped.load(Ordering::Relaxed)
        );

        // Stealth
        out.push_str("# HELP quicfuscate_stealth_http3_active Clients using HTTP/3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_http3_active gauge\n");
        write_metric!(
            "quicfuscate_stealth_http3_active {}\n\n",
            self.stealth_http3_active.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_stealth_tls13_active Clients using TLS 1.3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_tls13_active gauge\n");
        write_metric!(
            "quicfuscate_stealth_tls13_active {}\n\n",
            self.stealth_tls13_active.load(Ordering::Relaxed)
        );

        // FEC
        out.push_str(
            "# HELP quicfuscate_fec_packets_encoded Process-wide source plus repair datagrams actually written by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_encoded counter\n");
        write_metric!(
            "quicfuscate_fec_packets_encoded {}\n\n",
            self.fec_packets_encoded.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_fec_packets_decoded Process-wide original plus recovered source packets delivered by the FEC layer\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_decoded counter\n");
        write_metric!(
            "quicfuscate_fec_packets_decoded {}\n\n",
            self.fec_packets_decoded.load(Ordering::Relaxed)
        );

        out.push_str(
            "# HELP quicfuscate_fec_packets_recovered Process-wide source packets reconstructed from repair data\n",
        );
        out.push_str("# TYPE quicfuscate_fec_packets_recovered counter\n");
        write_metric!(
            "quicfuscate_fec_packets_recovered {}\n\n",
            self.fec_packets_recovered.load(Ordering::Relaxed)
        );

        // Allocation and pool pressure
        out.push_str(
            "# HELP quicfuscate_mem_pool_allocations_total Process-wide memory-pool allocation outcomes\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_allocations_total counter\n");
        for (source, value) in [
            ("thread_local", crate::telemetry::MEM_POOL_HITS_TLS.get()),
            ("shared_queue", crate::telemetry::MEM_POOL_HITS_QUEUE.get()),
            ("grow", crate::telemetry::MEM_POOL_ALLOC_GROW.get()),
            ("ephemeral", crate::telemetry::MEM_POOL_ALLOC_EPHEMERAL.get()),
        ] {
            write_metric!(
                "quicfuscate_mem_pool_allocations_total{{source=\"{source}\"}} {value}\n"
            );
        }
        out.push('\n');
        out.push_str(
            "# HELP quicfuscate_body_pool_allocations_total Process-wide HTTP body-pool allocations\n",
        );
        out.push_str("# TYPE quicfuscate_body_pool_allocations_total counter\n");
        write_metric!(
            "quicfuscate_body_pool_allocations_total {}\n\n",
            crate::telemetry::BODY_POOL_ALLOCS.get()
        );
        out.push_str(
            "# HELP quicfuscate_mem_pool_in_use Current process-wide memory-pool blocks in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_in_use gauge\n");
        write_metric!(
            "quicfuscate_mem_pool_in_use {}\n\n",
            crate::telemetry::MEM_POOL_IN_USE.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_mem_pool_usage_bytes Current process-wide memory-pool bytes in use\n",
        );
        out.push_str("# TYPE quicfuscate_mem_pool_usage_bytes gauge\n");
        write_metric!(
            "quicfuscate_mem_pool_usage_bytes {}\n\n",
            crate::telemetry::MEM_POOL_USAGE_BYTES.load(Ordering::Relaxed)
        );

        // Errors
        out.push_str("# HELP quicfuscate_auth_attempts_total QKey authentication attempts\n");
        out.push_str("# TYPE quicfuscate_auth_attempts_total counter\n");
        write_metric!(
            "quicfuscate_auth_attempts_total {}\n\n",
            self.auth_attempts.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_auth_succeeded_total Successful QKey authentications\n");
        out.push_str("# TYPE quicfuscate_auth_succeeded_total counter\n");
        write_metric!(
            "quicfuscate_auth_succeeded_total {}\n\n",
            self.auth_succeeded.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_auth_failed_total Terminal QKey authentication failures\n",
        );
        out.push_str("# TYPE quicfuscate_auth_failed_total counter\n");
        write_metric!(
            "quicfuscate_auth_failed_total {}\n\n",
            self.auth_failed.load(Ordering::Relaxed)
        );
        for (name, help, value) in [
            (
                "backoff_rejected",
                "QKey attempts rejected by exponential backoff",
                self.auth_backoff_rejected.load(Ordering::Relaxed),
            ),
            (
                "blocked_rejected",
                "QKey attempts rejected by the explicit blocked state",
                self.auth_blocked_rejected.load(Ordering::Relaxed),
            ),
            (
                "capacity_rejected",
                "QKey attempts rejected by bounded state capacity",
                self.auth_capacity_rejected.load(Ordering::Relaxed),
            ),
            (
                "abandoned",
                "QKey attempts abandoned before a credential result",
                self.auth_abandoned.load(Ordering::Relaxed),
            ),
        ] {
            write_metric!("# HELP quicfuscate_auth_{name}_total {help}\n");
            write_metric!("# TYPE quicfuscate_auth_{name}_total counter\n");
            write_metric!("quicfuscate_auth_{name}_total {value}\n\n");
        }
        out.push_str("# HELP quicfuscate_auth_state_tracked_ips Current QKey auth IP states\n");
        out.push_str("# TYPE quicfuscate_auth_state_tracked_ips gauge\n");
        write_metric!(
            "quicfuscate_auth_state_tracked_ips {}\n\n",
            self.auth_state_tracked_ips.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_auth_state_pruned_total Idle QKey auth IP states pruned\n",
        );
        out.push_str("# TYPE quicfuscate_auth_state_pruned_total counter\n");
        write_metric!(
            "quicfuscate_auth_state_pruned_total {}\n\n",
            self.auth_state_pruned.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_revocation_pruned_total Expired revoked QKey records pruned\n",
        );
        out.push_str("# TYPE quicfuscate_revocation_pruned_total counter\n");
        write_metric!(
            "quicfuscate_revocation_pruned_total {}\n\n",
            self.revocation_pruned.load(Ordering::Relaxed)
        );

        out.push_str("# HELP quicfuscate_rate_limited_total Rate-limited events\n");
        out.push_str("# TYPE quicfuscate_rate_limited_total counter\n");
        write_metric!(
            "quicfuscate_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        );
        out.push_str("\n# HELP quicfuscate_ddos_active Enhanced DDoS admission state\n");
        out.push_str("# TYPE quicfuscate_ddos_active gauge\n");
        write_metric!("quicfuscate_ddos_active {}\n", self.ddos_active.load(Ordering::Relaxed));
        out.push_str("# HELP quicfuscate_ddos_current_pps Latest interval-correct accepted PPS\n");
        out.push_str("# TYPE quicfuscate_ddos_current_pps gauge\n");
        write_metric!(
            "quicfuscate_ddos_current_pps {}\n",
            self.ddos_current_pps.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_ddos_transitions_total Enhanced admission transitions\n");
        out.push_str("# TYPE quicfuscate_ddos_transitions_total counter\n");
        for (transition, value) in [
            ("activated", self.ddos_activations.load(Ordering::Relaxed)),
            ("cleared", self.ddos_clears.load(Ordering::Relaxed)),
        ] {
            write_metric!(
                "quicfuscate_ddos_transitions_total{{transition=\"{transition}\"}} {value}\n"
            );
        }
        out.push_str("# HELP quicfuscate_ddos_retry_total QUIC Retry outcomes\n");
        out.push_str("# TYPE quicfuscate_ddos_retry_total counter\n");
        for (outcome, value) in [
            ("issued", self.ddos_retry_issued.load(Ordering::Relaxed)),
            ("validated", self.ddos_retry_validated.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_ddos_retry_total{{outcome=\"{outcome}\"}} {value}\n");
        }
        out.push_str("# HELP quicfuscate_ddos_drops_total DDoS admission drops by cause\n");
        out.push_str("# TYPE quicfuscate_ddos_drops_total counter\n");
        for (reason, value) in [
            ("global_limit", self.ddos_drop_global_limit.load(Ordering::Relaxed)),
            ("geoip", self.ddos_drop_geoip.load(Ordering::Relaxed)),
            ("blacklist", self.ddos_drop_blacklist.load(Ordering::Relaxed)),
            ("per_ip_limit", self.ddos_drop_per_ip_limit.load(Ordering::Relaxed)),
            ("malformed_initial", self.ddos_drop_malformed_initial.load(Ordering::Relaxed)),
            ("invalid_retry", self.ddos_drop_invalid_retry.load(Ordering::Relaxed)),
        ] {
            write_metric!("quicfuscate_ddos_drops_total{{reason=\"{reason}\"}} {value}\n");
        }
        out.push_str("# HELP quicfuscate_geoip_activation Actual GeoIP policy activation state\n");
        out.push_str("# TYPE quicfuscate_geoip_activation gauge\n");
        let geoip_status = self.geoip_status();
        for status in [
            crate::implementations::server::limits::GeoIpStatus::Disabled,
            crate::implementations::server::limits::GeoIpStatus::Active,
            crate::implementations::server::limits::GeoIpStatus::Failed,
        ] {
            let value = u8::from(status == geoip_status);
            write_metric!(
                "quicfuscate_geoip_activation{{state=\"{}\"}} {value}\n",
                status.as_str()
            );
        }
        out.push_str("# HELP quicfuscate_geoip_lookups_total Active GeoIP source lookups\n");
        out.push_str("# TYPE quicfuscate_geoip_lookups_total counter\n");
        write_metric!(
            "quicfuscate_geoip_lookups_total {}\n",
            self.geoip_lookups.load(Ordering::Relaxed)
        );
        out.push_str(
            "# HELP quicfuscate_geoip_blocked_total Sources blocked by GeoIP country policy\n",
        );
        out.push_str("# TYPE quicfuscate_geoip_blocked_total counter\n");
        write_metric!(
            "quicfuscate_geoip_blocked_total {}\n",
            self.geoip_blocked.load(Ordering::Relaxed)
        );
        out.push_str("# HELP quicfuscate_geoip_lookup_errors_total GeoIP lookup/decode failures dropped fail-closed\n");
        out.push_str("# TYPE quicfuscate_geoip_lookup_errors_total counter\n");
        write_metric!(
            "quicfuscate_geoip_lookup_errors_total {}\n",
            self.geoip_lookup_errors.load(Ordering::Relaxed)
        );
        let audit = crate::audit::stats();
        out.push_str(
            "\n# HELP quicfuscate_audit_dropped_events_total Audit events rejected by bounded writer admission\n",
        );
        out.push_str("# TYPE quicfuscate_audit_dropped_events_total counter\n");
        write_metric!("quicfuscate_audit_dropped_events_total {}\n\n", audit.dropped_events);
        out.push_str(
            "# HELP quicfuscate_audit_dropped_events_by_cause_total Audit events rejected before persistence, by cause\n",
        );
        out.push_str("# TYPE quicfuscate_audit_dropped_events_by_cause_total counter\n");
        write_metric!(
            "quicfuscate_audit_dropped_events_by_cause_total{{cause=\"queue_full\"}} {}\n",
            audit.queue_full_events
        );
        write_metric!(
            "quicfuscate_audit_dropped_events_by_cause_total{{cause=\"worker_closing\"}} {}\n",
            audit.worker_closing_events
        );
        write_metric!(
            "quicfuscate_audit_dropped_events_by_cause_total{{cause=\"worker_disconnected\"}} {}\n\n",
            audit.worker_disconnect_events
        );
        out.push_str(
            "# HELP quicfuscate_audit_payload_rejections_total Audit events rejected before queue admission because a dynamic payload bound was exceeded\n",
        );
        out.push_str("# TYPE quicfuscate_audit_payload_rejections_total counter\n");
        write_metric!(
            "quicfuscate_audit_payload_rejections_total {}\n\n",
            audit.payload_rejections
        );
        out.push_str(
            "# HELP quicfuscate_audit_persistence_errors_total Audit writer or durability-checkpoint failures\n",
        );
        out.push_str("# TYPE quicfuscate_audit_persistence_errors_total counter\n");
        write_metric!(
            "quicfuscate_audit_persistence_errors_total {}\n\n",
            audit.persistence_errors
        );
        out.push_str(
            "# HELP quicfuscate_audit_terminal_dropped_events_total Events discarded after terminal audit persistence failure\n",
        );
        out.push_str("# TYPE quicfuscate_audit_terminal_dropped_events_total counter\n");
        write_metric!(
            "quicfuscate_audit_terminal_dropped_events_total {}\n\n",
            audit.terminal_dropped_events
        );
        out.push_str(
            "# HELP quicfuscate_audit_slow_flushes_total Audit durability operations exceeding the configured timeout\n",
        );
        out.push_str("# TYPE quicfuscate_audit_slow_flushes_total counter\n");
        write_metric!("quicfuscate_audit_slow_flushes_total {}\n\n", audit.slow_flushes);
        out.push_str(
            "# HELP quicfuscate_audit_shutdown_failures_total Audit shutdown calls that retained a failure\n",
        );
        out.push_str("# TYPE quicfuscate_audit_shutdown_failures_total counter\n");
        write_metric!("quicfuscate_audit_shutdown_failures_total {}\n", audit.shutdown_failures);

        out
    }
}
