use super::*;

impl ServerRuntime {
    pub(in crate::implementations::server) async fn run_loop(
        &mut self,
        runtime_config: &mut PreparedStandaloneRuntimeConfig,
    ) -> std::io::Result<()> {
        let profiles = runtime_config.profiles.clone();
        let profile_interval_secs = runtime_config.profile_interval_secs;
        let standalone_runtime_metadata = runtime_config.standalone_runtime_metadata.clone();
        let tun_enable = runtime_config.tun_enable;
        let fingerprint_profile = runtime_config.transport.fingerprint_profile();
        let dns_upstream_resolvers = Arc::new(self.server_config.dns_servers.clone());
        let dns_intercept_admission = self.live().live_state.dns_admission();
        if self.state != ServerState::Stopped {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "server runtime already started",
            ));
        }

        self.start()
            .map_err(|error| std::io::Error::other(format!("server loop start failed: {error}")))?;

        self.ensure_standalone_runtime_metadata(&standalone_runtime_metadata);
        let runtime_owner = self.stealth_runtime.clone();

        let metrics = self.standalone_metrics();
        let socket = self.socket();
        let local_addr = self.local_addr();
        let blocked_ips = self.blocked_ips().clone();
        let qkey_registry = self.qkey_registry().clone();
        let dns_intercept_workers = Arc::new(DnsInterceptWorkerOwner::new(Arc::clone(&metrics)));
        self.dns_intercept_workers = Some(Arc::clone(&dns_intercept_workers));
        let Some(mut admin_actions_rx) = self.live_mut().admin_actions_rx.take() else {
            if let Err(stop_error) = self.stop() {
                return Err(std::io::Error::other(format!(
                    "server admin action receiver unavailable; cleanup failed: {stop_error}"
                )));
            }
            return Err(std::io::Error::other("server admin action receiver unavailable"));
        };
        // Take the TUN reader channel (if any) for forwarding TUN→client datagrams.
        let mut tun_rx = self.live_mut().tun_rx.take();
        let tun_notify = self.live().tun_notify.clone();
        let tun_fault = self.live().tun_fault.clone();
        if tun_enable {
            metrics.set_tun_data_plane_ready(tun_rx.is_some());
        }
        let mut runtime_fault: Option<DataPlaneFault> = None;
        let mut buf = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
        let mut out = [0; LIVE_UDP_DATAGRAM_BUFFER_SIZE];
        let mut housekeeping = tokio::time::interval(Duration::from_millis(5));
        housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Create shared 0-RTT anti-replay strike register if early data is enabled.
        if runtime_config.transport.is_early_data_enabled()
            && runtime_config.strike_register.is_none()
        {
            use crate::transport::anti_replay::{AntiReplayConfig, StrikeRegister};
            let ar_section = &runtime_config.anti_replay_section;
            if ar_section.enabled {
                let ar_config = AntiReplayConfig {
                    max_ticket_age: std::time::Duration::from_secs(ar_section.max_ticket_age_secs),
                    max_entries: ar_section.max_entries,
                    max_early_data_size: ar_section.max_early_data_size,
                    ..AntiReplayConfig::default()
                };
                // Set configurable max_early_data_size for new TLS server connections.
                crate::qftls::set_max_early_data_size(ar_config.max_early_data_size);
                let register = Arc::new(StrikeRegister::new(ar_config));
                runtime_config.transport.set_strike_register(register.clone());
                runtime_config.strike_register = Some(register);
                log::info!(
                    "[server] 0-RTT anti-replay strike register created \
                     (max_entries={}, max_age={}s, max_early_data={}B)",
                    ar_section.max_entries,
                    ar_section.max_ticket_age_secs,
                    ar_section.max_early_data_size,
                );
            } else {
                log::warn!(
                    "[server] 0-RTT anti-replay protection disabled by config \
                     (anti_replay.enabled=false) - replay attacks are possible"
                );
            }
        }

        let mut server_signals = match ServerSignals::install() {
            Ok(signals) => signals,
            Err(error) => {
                drop(tun_rx);
                let live = self.live_mut();
                live.admin_actions_rx = Some(admin_actions_rx);
                live.service_signals.shutdown_all();
                if let Err(stop_error) = self.stop() {
                    return Err(std::io::Error::other(format!(
                        "{error}; server cleanup after signal handler installation failure failed: {stop_error}"
                    )));
                }
                return Err(error);
            }
        };

        if let Err(error) = start_runtime_profile_rotation_with_generation(
            &runtime_owner,
            runtime_config.stealth_config.clone(),
            profiles,
            profile_interval_secs,
            runtime_config.runtime_policy_generation.clone(),
        ) {
            drop(tun_rx);
            self.live_mut().admin_actions_rx = Some(admin_actions_rx);
            self.live_mut().service_signals.shutdown_all();
            let shutdown_error = self.shutdown_stealth_runtime().await.err();
            let stop_error = self.stop().err();
            let detail = match (shutdown_error, stop_error) {
                (Some(shutdown), Some(stop)) => {
                    format!("{error}; stealth shutdown failed: {shutdown}; server cleanup failed: {stop}")
                }
                (Some(shutdown), None) => format!("{error}; stealth shutdown failed: {shutdown}"),
                (None, Some(stop)) => format!("{error}; server cleanup failed: {stop}"),
                (None, None) => error,
            };
            return Err(std::io::Error::other(detail));
        }

        let masque_relay_owner = self
            .server_config
            .masque_relay
            .enabled
            .then(|| {
                crate::implementations::server::masque_relay::MasqueRelayOwner::start(
                    self.server_config.masque_relay.clone(),
                )
            })
            .transpose()
            .map_err(std::io::Error::other)?;

        #[cfg(unix)]
        {
            record_systemd_notification("READY=1", self::systemd::notify::ready());
            record_systemd_notification(
                "STATUS=Accepting connections",
                self::systemd::notify::status("Accepting connections"),
            );
        }
        #[cfg(unix)]
        // systemd owns this watchdog deadline; it must remain live during
        // protocol-clock freezes and runtime teardown.
        let watchdog_interval = self::systemd::notify::watchdog_interval();
        #[cfg(unix)]
        let mut next_watchdog = watchdog_interval.map(|interval| Instant::now() + interval);

        loop {
            tokio::select! {
                Some(action) = admin_actions_rx.recv() => {
                    self.handle_admin_action_with_runtime_reload(
                        action,
                        &metrics,
                        runtime_config,
                    );
                }
                signal = server_signals.recv() => {
                    match signal {
                        ServerSignalEvent::Shutdown(reason) => {
                            self.initiate_drain(reason);
                        }
                        #[cfg(unix)]
                        ServerSignalEvent::Reload => {
                            self.reload_standalone_runtime(runtime_config, "SIGHUP");
                            match crate::logging::reopen() {
                                Ok(()) => {
                                    log::info!(
                                        "SIGHUP reopened the operational log sink after configuration reload"
                                    );
                                    crate::audit::audit_typed(
                                        crate::audit::AuditEventType::AdminAction,
                                        crate::audit::AuditSeverity::Info,
                                        None,
                                        None,
                                        crate::audit::AuditContext {
                                            actor: crate::audit::AuditActor::System,
                                            target: crate::audit::AuditTarget::System,
                                            outcome: crate::audit::AuditOutcome::Succeeded,
                                            reason: Some("sighup_log_reopen"),
                                        },
                                        "SIGHUP reopened the operational log sink",
                                    );
                                }
                                Err(error) => {
                                    log::error!("SIGHUP log sink reopen failed: {}", error);
                                    crate::audit::audit_typed(
                                        crate::audit::AuditEventType::AdminAction,
                                        crate::audit::AuditSeverity::Warning,
                                        None,
                                        None,
                                        crate::audit::AuditContext {
                                            actor: crate::audit::AuditActor::System,
                                            target: crate::audit::AuditTarget::System,
                                            outcome: crate::audit::AuditOutcome::Failed,
                                            reason: Some("sighup_log_reopen_failed"),
                                        },
                                        &format!("SIGHUP log sink reopen failed: {error}"),
                                    );
                                }
                            }
                        }
                    }
                }
                batch_res = recv_datagram_batch(&socket, 64) => {
                    match batch_res {
                        Ok(batch) => {
                            'batch: for (datagram, from) in batch {
                                // Copy into the reusable scratch so the unchanged
                                // stateful body below keeps operating on `buf`.
                                let len = datagram.len();
                                buf[..len].copy_from_slice(&datagram);
                                // Process each drained datagram through the same
                                // serial stateful path as before (TODO-901 step 1:
                                // one wakeup amortized across the burst; the
                                // syscall layer no longer caps pps).
                            crate::telemetry!(crate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                            metrics.record_ingress_datagram(len);

                            let ip_str = from.ip().to_string();
                            if blocked_ips.read().contains(&ip_str) {
                                metrics.record_connection_rejected();
                                continue;
                            }
                            let version_negotiation = stateless_version_negotiation_response(
                                &buf[..len],
                                runtime_config.transport.supported_versions(),
                            )
                            .ok()
                            .flatten();
                            #[cfg(feature = "rate_limiter")]
                            {
                                use crate::implementations::server::ddos::IncomingDatagramAdmission;
                                match self.admit_incoming_datagram(
                                    from,
                                    &buf[..len],
                                    version_negotiation.is_none(),
                                    &metrics,
                                ) {
                                    IncomingDatagramAdmission::Allow => {}
                                    IncomingDatagramAdmission::RetryValidated => {
                                        metrics.record_ddos_retry_validated();
                                    }
                                    IncomingDatagramAdmission::Drop(reason) => {
                                        metrics.record_ddos_drop(reason);
                                        continue;
                                    }
                                    IncomingDatagramAdmission::Retry(response) => {
                                        metrics.record_ddos_retry_issued();
                                        match socket.send_to(&response, from).await {
                                            Ok(sent) => metrics.record_egress_datagram(sent),
                                            Err(error) => {
                                                log::warn!(
                                                    "failed to send QUIC Retry to {}: {}",
                                                    from,
                                                    error
                                                );
                                            }
                                        }
                                        continue;
                                    }
                                }
                            }
                            if let Some(response) = version_negotiation {
                                match socket.send_to(&response, from).await {
                                    Ok(sent) => metrics.record_egress_datagram(sent),
                                    Err(error) => {
                                        log::warn!(
                                            "failed to send version negotiation to {}: {}",
                                            from,
                                            error
                                        );
                                    }
                                }
                                continue;
                            }

                            #[cfg(feature = "rate_limiter")]
                            let retry_token_manager =
                                self.live().live_state.retry_token_manager.clone();
                            #[cfg(not(feature = "rate_limiter"))]
                            let retry_token_manager = None;
                            let runtime_clock = self.clock.clone();
                            let crypto_config = self.engine_config.crypto.clone();
                            let runtime_parts = self.live_parts();
                            let stealth_runtime = runtime_owner.clone();
                            let client_snapshots = runtime_parts.live_state.client_snapshots().clone();
                            let auth_rate_limiter = runtime_parts.live_state.auth_rate_limiter.clone();
                            let revocation_manager =
                                Arc::clone(&runtime_parts.live_state.revocation_manager);
                            let stealth_config = runtime_config.stealth_config.clone();
                            let fec_cfg_shared = runtime_config.fec_cfg_shared.clone();
                            let opt_params_shared = runtime_config.opt_params_shared.clone();
                            let transport = &runtime_config.transport;
                            let runtime_policy_generation =
                                runtime_config.runtime_policy_generation.clone();
                            let runtime_client = match runtime_parts.live_state.acquire_runtime_client_with(
                                from,
                                &buf[..len],
                                runtime_parts.accept_loop,
                                runtime_parts.accept_max_clients,
                                &metrics,
                                || {
                                    build_live_server_client_init(
                                        LiveClientBuildRequest {
                                            packet: &buf[..len],
                                            local_addr,
                                            remote_addr: from,
                                            qkey_registry: qkey_registry.as_ref(),
                                            revocation_manager: revocation_manager.as_ref(),
                                            metrics: &metrics,
                                            stealth_config: &stealth_config,
                                            fec_cfg_shared: &fec_cfg_shared,
                                            opt_params_shared: &opt_params_shared,
                                            transport_config: transport,
                                            runtime_policy_generation: &runtime_policy_generation,
                                            stealth_runtime: Some(stealth_runtime.clone()),
                                            auth_rate_limiter: auth_rate_limiter.clone(),
                                            retry_token_manager: retry_token_manager.clone(),
                                            clock: runtime_clock.clone(),
                                            crypto_config: &crypto_config,
                                        },
                                )
                            },
                            ) {
                                LiveClientAcquire::Ready(v) => {
                                    v
                                },
                                LiveClientAcquire::Backpressure => {
                                    tokio::time::sleep(runtime_parts.accept_loop.backpressure_delay()).await;
                                    continue;
                                }
                                LiveClientAcquire::Rejected => {
                                    continue;
                                }
                            };
                            let migration_from = runtime_client.migration_from;

                            let datagram_result = match process_live_server_client_datagram(
                                &socket,
                                from,
                                runtime_client,
                                &buf[..len],
                                &mut out,
                                &metrics,
                                &client_snapshots,
                                runtime_parts.server_tun,
                                runtime_parts.server_ips,
                                runtime_parts.assignment_settings.clone(),
                                tun_enable,
                                Arc::clone(&dns_upstream_resolvers),
                                Arc::clone(&dns_intercept_admission),
                                Arc::clone(&dns_intercept_workers),
                                Arc::clone(&runtime_parts.tun_fault),
                                Arc::clone(&runtime_parts.tun_notify),
                                Arc::clone(&runtime_parts.shutdown),
                                masque_relay_owner.as_ref(),
                                runtime_parts.uring_worker.as_deref(),
                            ).await {
                                Ok(result) => result,
                                Err(fault) => {
                                    runtime_fault = Some(fault);
                                    break 'batch;
                                }
                            };
                            if let Some(old_addr) = migration_from {
                                runtime_parts.live_state.reconcile_incoming_path_update(
                                    old_addr,
                                    from,
                                    local_addr,
                                    runtime_parts.accept_loop,
                                );
                            }
                            runtime_parts.live_state.commit_qkey_auth_result(
                                datagram_result.remove_auth_conn_id,
                                datagram_result.auth_result,
                                runtime_parts.accept_loop,
                                &metrics,
                            );
                            runtime_parts.live_state.drain_client_fanout(&metrics);
                            } // 'batch
                        }
                        Err(e) => {
                            log::error!("Failed to read from socket: {}", e);
                        }
                    }
                }
                _ = housekeeping.tick() => {
                    dns_intercept_workers.observe_finished().await;
                    if let Some(fault) = tun_fault.lock().clone() {
                        runtime_fault = Some(fault);
                        break;
                    }
                    let qkey_registry = self.live().qkey_registry.clone();
                    if let Err(error) = qkey_registry
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .prune_replay_window()
                    {
                        log::error!("QKey replay-window pruning unavailable: {error}");
                    }
                    let runtime_parts = self.live_parts();
                    if let Err(fault) = runtime_parts.live_state
                        .run_housekeeping_tick(
                            &socket,
                            &mut out,
                            &metrics,
                            runtime_parts.accept_loop,
                        )
                        .await
                    {
                        runtime_fault = Some(fault);
                        break;
                    }
                    // Retry any downlinks that were deferred because a client's QUIC
                    // DATAGRAM queue was full, before reading new TUN frames.
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }

                    // Forward TUN→client: drain any packets from the TUN reader thread
                    // and route them to the correct client based on the destination IP
                    // in the IP packet header. Each client has a unique TUN IP from the
                    // server's IP pool, and we look up the session by client_ip to find
                    // the corresponding SocketAddr.
                    let more_tun = match drain_server_tun_packets(
                        self.live_mut(),
                        &mut tun_rx,
                        &mut out,
                        &socket,
                        &metrics,
                        fingerprint_profile,
                    ) {
                        Ok(more_tun) => more_tun,
                        Err(fault) => {
                            runtime_fault = Some(fault);
                            break;
                        }
                    };
                    if more_tun {
                        tun_notify.notify_one();
                    }
                    // Retry/final-flush any downlinks that were deferred during the
                    // TUN drain above.
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }

                    // Sweep expired entries from 0-RTT anti-replay strike register.
                    if let Some(ref sr) = runtime_config.strike_register {
                        sr.cleanup(self.clock.now());
                    }
                    #[cfg(unix)]
                    if let (Some(interval), Some(deadline)) =
                        (watchdog_interval, next_watchdog)
                    {
                        if Instant::now() >= deadline {
                            record_systemd_notification(
                                "WATCHDOG=1",
                                self::systemd::notify::watchdog(),
                            );
                            next_watchdog = Some(Instant::now() + interval);
                        }
                    }
                    if self.drain_complete() {
                        log::info!(
                            "Server drain complete (active_clients={}, elapsed_ms={})",
                            self.live().live_state.client_count(),
                            self.graceful_shutdown.elapsed().as_millis()
                        );
                        self.finish_drain(
                            &socket,
                            &mut out,
                            &metrics,
                            b"server_shutdown",
                        )
                        .await;
                        break;
                    }
                    housekeeping.reset_after(standalone_housekeeping_delay(self.live()));
                }
                _ = tun_notify.notified(), if tun_enable && tun_rx.is_some() => {
                    if let Some(fault) = tun_fault.lock().clone() {
                        runtime_fault = Some(fault);
                        break;
                    }
                    let more_tun = match drain_server_tun_packets(
                        self.live_mut(),
                        &mut tun_rx,
                        &mut out,
                        &socket,
                        &metrics,
                        fingerprint_profile,
                    ) {
                        Ok(more_tun) => more_tun,
                        Err(fault) => {
                            runtime_fault = Some(fault);
                            break;
                        }
                    };
                    if more_tun {
                        tun_notify.notify_one();
                    }
                    if let Err(fault) = drain_pending_tun_downlinks(
                        self.live_mut(),
                        &mut out,
                        &socket,
                        &metrics,
                    ) {
                        runtime_fault = Some(fault);
                        break;
                    }
                }
            }
        }

        drop(tun_rx);
        self.live_mut().admin_actions_rx = Some(admin_actions_rx);
        let stealth_error = self.shutdown_stealth_runtime().await.err();
        let stop_error = self.stop().err();
        let relay_error = match masque_relay_owner {
            Some(owner) => owner.shutdown().await.err(),
            None => None,
        };
        let mut cleanup_errors = Vec::new();
        if let Some(error) = stealth_error {
            cleanup_errors.push(format!("stealth shutdown failed: {error}"));
        }
        if let Some(error) = stop_error {
            cleanup_errors.push(format!("server shutdown failed: {error}"));
        }
        if let Some(error) = relay_error {
            cleanup_errors.push(format!("MASQUE relay shutdown failed: {error}"));
        }
        if let Some(fault) = runtime_fault {
            metrics.record_tun_data_plane_fault();
            let primary = std::io::Error::other(fault);
            return if cleanup_errors.is_empty() {
                Err(primary)
            } else {
                Err(std::io::Error::other(format!("{primary}; {}", cleanup_errors.join("; "))))
            };
        }
        if !cleanup_errors.is_empty() {
            return Err(std::io::Error::other(cleanup_errors.join("; ")));
        }

        Ok(())
    }
}
