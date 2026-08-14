use super::*;

impl LiveServerState {
    pub fn enforce_qkey_auth_timeouts(&mut self, metrics: &Metrics) {
        let timed_out_conn_ids: Vec<Vec<u8>> = self
            .qkey_auth
            .iter()
            .filter_map(|(conn_id, state)| {
                state.is_expired_at(self.clock.now()).then_some(conn_id.clone())
            })
            .collect();
        for conn_id in timed_out_conn_ids {
            let key_id = self.qkey_auth.get(&conn_id).map(|state| state.key_id.clone());
            let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
            });
            for conn in self.values_mut() {
                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                    metrics.record_connection_rejected();
                    if let Err(error) = conn.conn.close(true, 0x0, b"qkey_auth_timeout") {
                        log::warn!("Client close after QKey auth timeout failed: {:?}", error);
                    }
                    break;
                }
            }
            let source_ip = remote_addr.map(|addr| addr.ip().to_string());
            crate::audit::audit_typed(
                crate::audit::AuditEventType::AuthTimeout,
                crate::audit::AuditSeverity::Warning,
                source_ip.as_deref(),
                key_id.as_deref(),
                crate::audit::AuditContext {
                    actor: crate::audit::AuditActor::Client,
                    target: crate::audit::AuditTarget::Client,
                    outcome: crate::audit::AuditOutcome::TimedOut,
                    reason: Some("qkey_authentication_timeout"),
                },
                "QKey authentication timed out",
            );
            let session_id = self.session_id_for_conn_id(&conn_id);
            self.dissociate_qkey_for_session(session_id);
            if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                complete_qkey_auth_state(
                    &self.auth_rate_limiter,
                    metrics,
                    &mut state,
                    crate::implementations::server::limits::AuthTerminal::Failed,
                );
            }
        }
    }

    pub fn commit_qkey_auth_result(
        &mut self,
        remove_auth_conn_id: Option<Vec<u8>>,
        auth_result: Option<(Vec<u8>, bool)>,
        accept_loop: &AcceptLoop,
        metrics: &Metrics,
    ) {
        let mut handled_conn_id: Option<Vec<u8>> = None;
        if let Some((conn_id, authed)) = auth_result {
            handled_conn_id = Some(conn_id.clone());
            if authed && self.qkey_auth.get(&conn_id).is_some_and(|state| state.authed) {
                // Authentication was already committed for this connection.
                // Replayed HTTP/3 headers must not create a second bandwidth owner.
            } else if !authed {
                let remote_addr = self.clients.iter().find_map(|(addr, conn)| {
                    (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                });
                if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                    let key_id = state.key_id.clone();
                    complete_qkey_auth_state(
                        &self.auth_rate_limiter,
                        metrics,
                        &mut state,
                        crate::implementations::server::limits::AuthTerminal::Failed,
                    );
                    let source_ip = remote_addr.map(|addr| addr.ip().to_string());
                    crate::audit::audit_typed(
                        crate::audit::AuditEventType::AuthFailed,
                        crate::audit::AuditSeverity::Warning,
                        source_ip.as_deref(),
                        Some(&key_id),
                        crate::audit::AuditContext {
                            actor: crate::audit::AuditActor::Client,
                            target: crate::audit::AuditTarget::Qkey,
                            outcome: crate::audit::AuditOutcome::Denied,
                            reason: Some("qkey_authentication_denied"),
                        },
                        "QKey authentication denied",
                    );
                }
            } else {
                let policy = self.qkey_auth.get(&conn_id).map(|state| {
                    (
                        state.key_id.clone(),
                        state.bandwidth_policy.clone(),
                        state.traffic_analysis_policy,
                    )
                });
                let Some((key_id, bandwidth_policy, traffic_analysis_policy)) = policy else {
                    return;
                };
                if self.revocation_manager.is_revoked(&key_id) {
                    let addr = self.clients.iter().find_map(|(addr, conn)| {
                        (conn.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                    });
                    if let Some(addr) = addr {
                        let session_id = self.domain.session_id_by_remote(addr);
                        if let Some(mut conn) = self.clients.remove(&addr) {
                            if let Err(error) = conn.conn.close(true, 0x0, b"qkey_revoked") {
                                log::warn!(
                                    "Client close after pending QKey revocation failed for {}: {:?}",
                                    addr,
                                    error
                                );
                            }
                            accept_loop.record_closed(addr);
                            metrics.record_connection_rejected();
                        }
                        self.dissociate_qkey_for_session(session_id);
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                        complete_qkey_auth_state(
                            &self.auth_rate_limiter,
                            metrics,
                            &mut state,
                            crate::implementations::server::limits::AuthTerminal::Failed,
                        );
                    }
                    return;
                }
                let remote_addr = self.clients.iter().find_map(|(addr, connection)| {
                    (connection.conn.source_id().as_ref() == conn_id.as_slice()).then_some(*addr)
                });
                let session_id =
                    remote_addr.and_then(|addr| self.domain.session_id_by_remote(addr));
                let traffic_analysis_error = match remote_addr {
                    Some(addr) => self
                        .clients
                        .get_mut(&addr)
                        .ok_or(crate::error::ConnectionError::InvalidState)
                        .and_then(|connection| {
                            if let Some(policy) = traffic_analysis_policy {
                                connection.conn.apply_traffic_analysis_policy(policy)?;
                            }
                            connection
                                .conn
                                .authorize_intelligent_traffic_analysis(traffic_analysis_policy)
                        })
                        .err()
                        .map(|error| error.to_string()),
                    None => Some("live connection not found".to_string()),
                };
                let bandwidth_error = if traffic_analysis_error.is_none() {
                    match session_id {
                        Some(session_id) => self
                            .domain
                            .shared
                            .sessions
                            .write()
                            .activate_bandwidth(session_id, bandwidth_policy)
                            .err()
                            .map(|error| error.to_string()),
                        None => Some(SessionError::NotFound.to_string()),
                    }
                } else {
                    None
                };
                let activation_error = traffic_analysis_error.or(bandwidth_error);
                if let Some(error) = activation_error {
                    log::error!("Authenticated QKey policy activation failed: {}", error);
                    metrics.record_connection_rejected();
                    if let Some(addr) = remote_addr {
                        if let Some(mut connection) = self.clients.remove(&addr) {
                            if let Err(close_error) =
                                connection.conn.close(true, 0x0, b"qkey_policy_invalid")
                            {
                                log::warn!(
                                    "Client close after QKey policy activation failure failed: {:?}",
                                    close_error
                                );
                            }
                            accept_loop.record_closed(addr);
                        }
                        self.domain.remove_remote(addr);
                        self.domain.retain_snapshots_for_clients(&self.clients);
                        self.sync_active_metrics(metrics);
                    }
                    if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                        complete_qkey_auth_state(
                            &self.auth_rate_limiter,
                            metrics,
                            &mut state,
                            crate::implementations::server::limits::AuthTerminal::Failed,
                        );
                    }
                    return;
                }
                let Some(session_id) = session_id else {
                    return;
                };
                self.qkey_tracker.associate(session_id.as_u64(), &key_id);
                let auth_rate_limiter = Arc::clone(&self.auth_rate_limiter);
                if let Some(state) = self.qkey_auth_state_mut(&conn_id) {
                    state.authed = true;
                    complete_qkey_auth_state(
                        &auth_rate_limiter,
                        metrics,
                        state,
                        crate::implementations::server::limits::AuthTerminal::Succeeded,
                    );
                }
                crate::audit::audit_typed(
                    crate::audit::AuditEventType::ClientAuthenticated,
                    crate::audit::AuditSeverity::Info,
                    None,
                    Some(&key_id),
                    crate::audit::AuditContext {
                        actor: crate::audit::AuditActor::Client,
                        target: crate::audit::AuditTarget::Connection,
                        outcome: crate::audit::AuditOutcome::Succeeded,
                        reason: None,
                    },
                    "Client authenticated successfully",
                );
            }
        }
        if let Some(conn_id) = remove_auth_conn_id {
            if handled_conn_id.as_deref() == Some(conn_id.as_slice()) {
                return;
            }
            if let Some(mut state) = self.remove_qkey_auth(&conn_id) {
                complete_qkey_auth_state(
                    &self.auth_rate_limiter,
                    metrics,
                    &mut state,
                    crate::implementations::server::limits::AuthTerminal::Failed,
                );
            }
        }
    }
}
