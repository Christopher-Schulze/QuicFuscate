use super::*;

impl LiveServerDomain {
    #[allow(dead_code)]
    pub(in crate::implementations::server) fn try_new(
        server_config: &ServerConfig,
    ) -> Result<Self, String> {
        Self::try_new_with_clock(server_config, &crate::time_source::ProtocolClock::default())
    }

    pub(super) fn try_new_with_clock(
        server_config: &ServerConfig,
        clock: &crate::time_source::ProtocolClock,
    ) -> Result<Self, String> {
        let dns_admission = Arc::new(
            crate::dns::DnsAdmission::try_new_with_clock(server_config.dns_admission, clock)
                .map_err(|error| format!("server DNS admission configuration: {error}"))?,
        );
        Ok(Self {
            shared: SharedServerDomain::try_new_with_clock(server_config, clock)?,
            client_snapshots: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            dns_admission,
        })
    }

    pub(in crate::implementations::server) fn accept(
        &self,
        remote_addr: SocketAddr,
    ) -> Result<(SessionId, Arc<SessionStats>, AssignedClientIps), AcceptError> {
        let (session_id, stats, assigned_ips) = self.shared.accept(remote_addr)?;
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionEstablished,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client connection accepted",
        );
        Ok((session_id, stats, assigned_ips))
    }

    pub(in crate::implementations::server) fn remove_remote(&self, remote_addr: SocketAddr) {
        let Some(session_id) = self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
        else {
            self.dns_admission
                .remove_identity(crate::dns::DnsAdmissionIdentity::Source(remote_addr.ip()));
            #[cfg(feature = "rate_limiter")]
            self.shared.remove_rate_limited_ip(remote_addr.ip());
            self.remove_remote_snapshot(remote_addr);
            return;
        };
        let source_ip = remote_addr.ip().to_string();
        let client_id = session_id.as_u64().to_string();
        crate::audit::audit(
            crate::audit::AuditEventType::ConnectionClosed,
            crate::audit::AuditSeverity::Info,
            Some(&source_ip),
            Some(&client_id),
            "Client session removed",
        );
        self.shared.remove(session_id);
        self.dns_admission
            .remove_identity(crate::dns::DnsAdmissionIdentity::Session(session_id.as_u64()));
        self.dns_admission
            .remove_identity(crate::dns::DnsAdmissionIdentity::Source(remote_addr.ip()));
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(remote_addr.ip());
        self.remove_remote_snapshot(remote_addr);
    }

    pub(super) fn rebind_remote(&self, old_addr: SocketAddr, new_addr: SocketAddr) -> bool {
        let mut sessions = self.shared.sessions.write();
        if sessions.rebind_remote_addr(old_addr, new_addr).is_err() {
            return false;
        }
        drop(sessions);
        let mut limiter = self.shared.connection_limiter.lock();
        limiter.remove(old_addr.ip());
        limiter.add(new_addr.ip());
        self.dns_admission.remove_identity(crate::dns::DnsAdmissionIdentity::Source(old_addr.ip()));
        #[cfg(feature = "rate_limiter")]
        self.shared.remove_rate_limited_ip(old_addr.ip());
        if let Ok(mut guard) = self.client_snapshots.lock() {
            if let Some(snapshot) = guard.remove(&old_addr) {
                guard.insert(new_addr, snapshot);
            }
        }
        true
    }

    pub(super) fn session_stats_by_remote(
        &self,
        remote_addr: SocketAddr,
    ) -> Option<Arc<SessionStats>> {
        self.shared.sessions.read().stats_by_remote_addr(remote_addr)
    }

    pub(in crate::implementations::server) fn session_id_by_remote(
        &self,
        remote_addr: SocketAddr,
    ) -> Option<SessionId> {
        self.shared.sessions.read().session_id_by_remote_addr(remote_addr)
    }

    pub(super) fn assigned_ips_by_remote(
        &self,
        remote_addr: SocketAddr,
    ) -> Option<AssignedClientIps> {
        self.shared.sessions.read().get_by_remote_addr(remote_addr).map(|session| {
            AssignedClientIps { ipv4: session.client_ip(), ipv6: session.client_ipv6() }
        })
    }

    pub(in crate::implementations::server) fn remote_addr_for_identity(
        &self,
        identity: &ClientIdentity,
    ) -> Option<SocketAddr> {
        match identity {
            ClientIdentity::Remote(addr) => Some(*addr),
            ClientIdentity::Session(session_id) => {
                self.shared.sessions.read().remote_addr_by_session_id(*session_id)
            }
        }
    }

    pub(in crate::implementations::server) fn active_session_count(&self) -> usize {
        self.shared.session_count()
    }

    pub(super) fn reap_expired_remotes(&self) -> Vec<(SocketAddr, SessionId)> {
        let expired = self.shared.reap_expired();
        for session in &expired {
            self.dns_admission
                .remove_identity(crate::dns::DnsAdmissionIdentity::Session(session.id().as_u64()));
            self.dns_admission.remove_identity(crate::dns::DnsAdmissionIdentity::Source(
                session.remote_addr().ip(),
            ));
            let source_ip = session.remote_addr().ip().to_string();
            let client_id = session.id().as_u64().to_string();
            crate::audit::audit(
                crate::audit::AuditEventType::ConnectionClosed,
                crate::audit::AuditSeverity::Info,
                Some(&source_ip),
                Some(&client_id),
                "Client session expired",
            );
        }
        expired.into_iter().map(|session| (session.remote_addr(), session.id())).collect()
    }

    pub(super) fn client_snapshots(
        &self,
    ) -> &Arc<std::sync::Mutex<std::collections::HashMap<SocketAddr, ClientSnapshot>>> {
        &self.client_snapshots
    }

    pub(super) fn dns_admission(&self) -> Arc<crate::dns::DnsAdmission> {
        Arc::clone(&self.dns_admission)
    }

    pub(super) fn remove_remote_snapshot(&self, remote_addr: SocketAddr) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.remove(&remote_addr);
        }
    }

    pub(super) fn retain_snapshots_for_clients(
        &self,
        clients: &std::collections::HashMap<SocketAddr, QuicFuscateConnection>,
    ) {
        if let Ok(mut guard) = self.client_snapshots.lock() {
            guard.retain(|addr, _| clients.contains_key(addr));
        }
    }

    #[cfg(feature = "rate_limiter")]
    pub(in crate::implementations::server) fn admit_incoming_datagram(
        &self,
        from: SocketAddr,
        packet: &[u8],
        established: bool,
        retry_eligible: bool,
        metrics: &Metrics,
    ) -> crate::implementations::server::ddos::IncomingDatagramAdmission {
        self.shared.admit_incoming_datagram(from, packet, established, retry_eligible, metrics)
    }

    #[cfg(feature = "rate_limiter")]
    pub(super) fn geoip_status(&self) -> crate::implementations::server::limits::GeoIpStatus {
        self.shared.geoip_status()
    }

    #[cfg(feature = "rate_limiter")]
    pub(super) fn prune_rate_limits_if_due(&self, metrics: &Metrics) {
        self.shared.prune_rate_limits_if_due(metrics);
    }

    /// Returns a clone of the blacklist synchronizer Arc for async sync.
    #[cfg(feature = "rate_limiter")]
    pub(in crate::implementations::server) fn blacklist(
        &self,
    ) -> Arc<crate::implementations::server::limits::BlacklistSync> {
        Arc::clone(&self.shared.blacklist)
    }
}
