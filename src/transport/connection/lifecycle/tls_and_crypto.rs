use super::*;

impl Connection {
    /// Process incoming CRYPTO frame
    pub(crate) fn process_crypto_frame(
        &mut self,
        level: qf_transport_types::QuicEncryptionLevel,
        offset: u64,
        data: Cow<'_, [u8]>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.tls_provider.is_some() {
            // CRYPTO frames can arrive out-of-order. Buffer and drain contiguous handshake bytes
            // before feeding into the TLS provider.
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            {
                let mut crypto = self.crypto.write();
                let stream = match level {
                    qf_transport_types::QuicEncryptionLevel::Initial => &mut crypto.crypto_initial,
                    qf_transport_types::QuicEncryptionLevel::Handshake => {
                        &mut crypto.crypto_handshake
                    }
                    _ => &mut crypto.crypto_application,
                };
                stream.recv(offset, data.into_owned())?;
                let mut tmp = [0u8; 2048];
                while stream.has_data() {
                    let n = stream.read(&mut tmp);
                    if n == 0 {
                        break;
                    }
                    chunks.push(tmp[..n].to_vec());
                }
            }

            if let Some(provider) = &mut self.tls_provider {
                for chunk in chunks {
                    if let Err(error) = provider.provide_quic_data(level, &chunk) {
                        return Err(self.fail_tls_handshake(error));
                    }
                }
            }
            // Install any newly derived secrets into the shared CryptoContext.
            // Without this, the transport would never transition to 1-RTT and application streams
            // (including HTTP/3 HEADERS carrying x-qf-auth) would stall behind the handshake gate.
            if let Err(error) = self.poll_tls_and_validate_versions() {
                return Err(self.fail_tls_handshake(error));
            }
        } else {
            // Store in crypto stream for later processing
            let mut crypto = self.crypto.write();
            let stream = match level {
                qf_transport_types::QuicEncryptionLevel::Initial => &mut crypto.crypto_initial,
                qf_transport_types::QuicEncryptionLevel::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.recv(offset, data.into_owned())?;
        }

        Ok(())
    }

    pub(in crate::transport::connection) fn poll_tls_and_validate_versions(
        &mut self,
    ) -> Result<(), crate::error::ConnectionError> {
        let peer_parameters = {
            let Some(provider) = &mut self.tls_provider else {
                return Ok(());
            };
            provider.poll_secrets_and_install(&*self.crypto)?;
            provider.peer_quic_transport_params()
        };
        self.refresh_short_header_tag_reserve();
        self.validate_peer_version_information(peer_parameters)
    }

    pub(in crate::transport::connection) fn validate_peer_version_information(
        &mut self,
        peer_parameters: Option<Vec<u8>>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.version_negotiation.peer_information_validated {
            return Ok(());
        }
        let Some(peer_parameters) = peer_parameters else {
            return Ok(());
        };
        let information = match super::super::version::find_version_information(&peer_parameters) {
            Ok(information) => information,
            Err(_) => {
                return Err(self.fail_version_negotiation(
                    super::super::version::TRANSPORT_PARAMETER_ERROR_CODE,
                    "malformed version_information transport parameter",
                ));
            }
        };
        let required = !self.is_server
            && (self.config.version == super::super::PROTOCOL_VERSION_V2
                || self.version_negotiation.reacted_to_vn);
        let information = match information {
            Some(information) => information,
            None if !self.is_server
                && self.version_negotiation.reacted_to_vn
                && self.config.version == super::super::PROTOCOL_VERSION =>
            {
                super::super::version::VersionInformation {
                    chosen: super::super::PROTOCOL_VERSION,
                    available: vec![super::super::PROTOCOL_VERSION],
                }
            }
            None => {
                if required {
                    return Err(self.fail_version_negotiation(
                        super::super::version::VERSION_NEGOTIATION_ERROR_CODE,
                        "required version_information transport parameter missing",
                    ));
                }
                self.version_negotiation.peer_information_validated = true;
                return Ok(());
            }
        };

        if self.is_server && !information.available.contains(&information.chosen) {
            return Err(self.fail_version_negotiation(
                super::super::version::TRANSPORT_PARAMETER_ERROR_CODE,
                "client chosen version missing from available versions",
            ));
        }
        let valid_choice = information.chosen == self.config.version
            && self.config.supported_versions.contains(&information.chosen);
        let negotiated_preference_matches = if self.version_negotiation.reacted_to_vn
            && !self.is_server
        {
            if information.available.is_empty() {
                false
            } else {
                self.config
                    .supported_versions
                    .iter()
                    .find(|version| {
                        **version == self.config.version || information.available.contains(version)
                    })
                    .is_some_and(|version| *version == self.config.version)
            }
        } else {
            true
        };
        if !valid_choice || !negotiated_preference_matches {
            return Err(self.fail_version_negotiation(
                super::super::version::VERSION_NEGOTIATION_ERROR_CODE,
                "authenticated version_information rejected negotiated version",
            ));
        }
        self.version_negotiation.peer_information_validated = true;
        Ok(())
    }

    fn fail_version_negotiation(
        &mut self,
        error_code: u64,
        reason: &'static str,
    ) -> crate::error::ConnectionError {
        let error = crate::error::ConnectionError::Transport(reason.to_string());
        self.record_local_error(error.clone());
        let _ = self.close(false, error_code, reason.as_bytes());
        error
    }

    /// Get next CRYPTO frame to send
    fn encryption_level_for_space(
        space: recovery::PacketSpace,
    ) -> qf_transport_types::QuicEncryptionLevel {
        match space {
            recovery::PacketSpace::Initial => qf_transport_types::QuicEncryptionLevel::Initial,
            recovery::PacketSpace::Handshake => qf_transport_types::QuicEncryptionLevel::Handshake,
            recovery::PacketSpace::Application => {
                qf_transport_types::QuicEncryptionLevel::Application
            }
        }
    }

    pub(super) fn ack_crypto_range(
        &mut self,
        space: recovery::PacketSpace,
        offset: u64,
        length: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            return provider.ack_crypto(Self::encryption_level_for_space(space), offset, length);
        }
        let mut crypto = self.crypto.write();
        let stream = match space {
            recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
            recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
            recovery::PacketSpace::Application => &mut crypto.crypto_application,
        };
        stream.ack_crypto(offset, length)
    }

    pub(super) fn requeue_crypto_range(
        &mut self,
        space: recovery::PacketSpace,
        offset: u64,
        length: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            return provider.requeue_crypto(
                Self::encryption_level_for_space(space),
                offset,
                length,
            );
        }
        let mut crypto = self.crypto.write();
        let stream = match space {
            recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
            recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
            recovery::PacketSpace::Application => &mut crypto.crypto_application,
        };
        stream.requeue_crypto(offset, length)
    }

    pub(super) fn requeue_all_crypto(&mut self, space: recovery::PacketSpace) {
        if let Some(provider) = &mut self.tls_provider {
            provider.requeue_all_crypto(Self::encryption_level_for_space(space));
            return;
        }
        let mut crypto = self.crypto.write();
        let stream = match space {
            recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
            recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
            recovery::PacketSpace::Application => &mut crypto.crypto_application,
        };
        stream.requeue_all_unacked();
    }

    pub(crate) fn next_crypto_frame(
        &mut self,
        level: qf_transport_types::QuicEncryptionLevel,
        max_len: usize,
    ) -> Result<Option<(u64, Vec<u8>)>, crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            provider.next_crypto_frame(level, max_len)
        } else {
            let mut crypto = self.crypto.write();
            let stream = match level {
                qf_transport_types::QuicEncryptionLevel::Initial => &mut crypto.crypto_initial,
                qf_transport_types::QuicEncryptionLevel::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.next_crypto_frame(max_len)
        }
    }

    // ============================================================================
    // Packet Processing Methods
    // ============================================================================

    pub(in crate::transport::connection) fn handle_version_negotiation_packet(
        &mut self,
        header: &packet::Header,
        packet_len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let valid_context = !self.is_server
            && !self.received_non_vn_packet
            && header.dcid.as_slice() == self.scid.as_ref()
            && header.scid.as_slice() == self.initial_dcid.as_ref();
        if !valid_context {
            return Ok(packet_len);
        }
        let peer_versions = header.versions.as_deref().unwrap_or_default();
        let selected = match self
            .version_negotiation
            .select_from_vn(&self.config.supported_versions, peer_versions)
        {
            Ok(version) => version,
            Err(ConnectionError::Done) => return Ok(packet_len),
            Err(ConnectionError::VersionMismatch) => {
                self.is_closed = true;
                self.record_local_error(ConnectionError::VersionMismatch);
                return Err(ConnectionError::VersionMismatch);
            }
            Err(error) => return Err(error),
        };

        self.config.select_version(selected)?;
        self.version_negotiation.peer_information_validated = false;
        let mut scid = [0u8; super::super::MAX_CONN_ID_LEN];
        let mut dcid = [0u8; super::super::MAX_CONN_ID_LEN];
        super::super::rand::rand_bytes(&mut scid);
        super::super::rand::rand_bytes(&mut dcid);
        self.scid = ConnectionId::from_ref(&scid);
        self.initial_dcid = ConnectionId::from_ref(&dcid);
        self.original_dcid = self.initial_dcid;
        self.dcid = self.initial_dcid;
        self.dest_cids = cid::ConnectionIdSet::new();
        self.dest_cids.insert(&self.dcid);
        self.is_established = false;
        self.is_closed = false;
        self.is_draining = false;
        self.local_error = None;
        self.remote_error = None;
        self.pkt_spaces = [
            pnspace::PktNumSpace::new_with_clock(self.clock.clone()),
            pnspace::PktNumSpace::new_with_clock(self.clock.clone()),
            pnspace::PktNumSpace::new_with_clock(self.clock.clone()),
        ];
        self.next_send_pn_by_space = [0, 0, 0];
        self.pending_control.clear();
        self.recovery.discard_space(recovery::PacketSpace::Initial);
        self.recovery.discard_space(recovery::PacketSpace::Handshake);
        self.recovery.discard_space(recovery::PacketSpace::Application);
        self.pending_probe_spaces.clear();
        self.stream_transmission_by_pn.clear();
        self.lost_stream_transmission_by_pn.clear();
        self.stream_retransmit_queue.clear();
        for (transmission_id, transmission) in &mut self.stream_transmissions {
            transmission.queued = true;
            transmission.active_packet = None;
            transmission.lost_packets.clear();
            self.stream_retransmit_queue.push_back(*transmission_id);
        }
        self.bytes_in_flight = 0;
        self.bytes_in_flight_started = None;
        self.cwnd = INITIAL_WINDOW;
        self.rtt = Duration::ZERO;
        self.timeout_count = 0;
        self.last_activity = self.clock.now();
        self.conn_bytes_sent = 0;
        self.conn_bytes_recvd = 0;
        self.peer_max_data = self.config.initial_max_data;
        self.h3 = None;
        self.pmtu_probe_pn = None;
        self.pmtu_above_floor_pns.clear();
        self.recovery = Self::configured_recovery_with_snapshot(
            &self.config,
            self.dgram_send_max_size,
            &self.environment,
            &self.clock,
        );
        if self.config.initial_rtt_ms != 100 {
            self.recovery.set_initial_rtt(Duration::from_millis(self.config.initial_rtt_ms));
        }
        self.install_recovery_fec_callbacks();
        self.crypto = Arc::new(parking_lot::RwLock::new(packet::CryptoContext::default()));
        self.crypto_1rtt.store(None);
        self.short_header_tag_reserve = 0;
        let tls_was_enabled = self.tls_provider.is_some();
        self.tls_provider = None;

        if tls_was_enabled {
            let profile = self.tls_profile.clone();
            self.enable_tls("version-negotiation-restart")?;
            if let Some(profile) = profile {
                let sni = profile.sni.clone().unwrap_or_default();
                self.configure_tls(&profile, &sni)?;
            }
        }

        self.stats.recv = self.stats.recv.saturating_add(1);
        self.stats.recv_bytes = self.stats.recv_bytes.saturating_add(packet_len as u64);
        Ok(packet_len)
    }
}
