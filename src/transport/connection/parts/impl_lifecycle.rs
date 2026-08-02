impl Connection {
    fn configured_recovery(config: &Config, max_datagram_size: usize) -> recovery::Recovery {
        let algorithm = match config.cc_algorithm {
            crate::transport::CongestionControlAlgorithm::Reno => {
                crate::transport::cc::Algorithm::Reno
            }
            crate::transport::CongestionControlAlgorithm::Cubic => {
                crate::transport::cc::Algorithm::Cubic
            }
            crate::transport::CongestionControlAlgorithm::BBR2 => {
                crate::transport::cc::Algorithm::Bbr2
            }
            crate::transport::CongestionControlAlgorithm::BBR3 => {
                crate::transport::cc::Algorithm::Bbr3
            }
        };
        recovery::Recovery::with_algorithm(INITIAL_WINDOW, max_datagram_size, algorithm)
    }

    fn rebuild_traffic_analysis_scheduler(&mut self) {
        let policy = self.config.traffic_analysis_policy();
        let (rate_pps, constant_rate) = match policy.defense {
            crate::transport::config::TrafficAnalysisDefense::Off => (0, false),
            crate::transport::config::TrafficAnalysisDefense::FullPadding => {
                (policy.chaff_rate_pps, false)
            }
            crate::transport::config::TrafficAnalysisDefense::ConstantRate => {
                (policy.constant_rate_pps, true)
            }
        };
        let Some(rate_pps) = std::num::NonZeroU32::new(rate_pps) else {
            self.traffic_analysis = None;
            return;
        };

        let max_udp_payload_size = self.config.max_udp_payload_size as u32;
        let target_size = match policy.defense {
            crate::transport::config::TrafficAnalysisDefense::FullPadding => max_udp_payload_size,
            crate::transport::config::TrafficAnalysisDefense::ConstantRate => {
                policy.chaff_size_bytes.min(max_udp_payload_size)
            }
            crate::transport::config::TrafficAnalysisDefense::Off => 0,
        };
        log::warn!(
            "traffic-analysis defense enabled: mode={:?} rate_pps={} target_bytes={} estimated_max_bps={}",
            policy.defense,
            rate_pps,
            target_size,
            policy.estimated_max_bits_per_second(max_udp_payload_size)
        );
        self.traffic_analysis = Some(crate::stealth::TrafficAnalysisScheduler::with_lifecycle(
            rate_pps.get(),
            target_size,
            true,
            constant_rate,
            Duration::from_millis(policy.idle_timeout_ms),
            Duration::from_millis(policy.ramp_down_ms),
        ));
    }

    /// Set the Destination Connection ID retained for the Initial packet space.
    ///
    /// For clients this also initializes the current destination CID used in the first Initial
    /// packet. For servers the current destination CID is learned from the peer's SCID when the
    /// first packet is received.
    pub(crate) fn set_initial_dcid(&mut self, dcid: ConnectionId) {
        self.initial_dcid = dcid;
        if !self.is_server {
            self.dcid = dcid;
        }
    }

    /// Set the current destination CID (what we put into outgoing DCID fields).
    pub(crate) fn set_destination_cid(&mut self, dcid: ConnectionId) {
        self.dcid = dcid;
        self.dest_cids.insert(&self.dcid);
    }

    pub(crate) fn new_with_role(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
        is_server: bool,
    ) -> Self {
        let dgram_send_max_size = config.max_udp_payload_size as usize;
        let initial_max_data = config.initial_max_data;
        let pmtu_enabled = config.pmtu_discovery_enabled();
        let pmtu_policy = config.pmtu_policy();
        let traffic_analysis_base_policy = config.traffic_analysis_policy();
        let version_negotiation = super::version::VersionNegotiationState::new(config.version);
        let recovery = Self::configured_recovery(&config, dgram_send_max_size);
        let mut conn = Self {
            scid: ConnectionId::from_ref(scid),
            dcid: ConnectionId::default(),
            initial_dcid: ConnectionId::default(),
            is_server,
            is_established: false,
            is_closed: false,
            is_draining: false,
            received_non_vn_packet: false,
            streams: HashMap::new(),
            local_addr: local,
            peer_addr: peer,
            config,
            version_negotiation,
            stats: Stats::default(),
            dgram_recv_queue: VecDeque::new(),
            dgram_send_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_pool: crate::optimize::global_pool(),
            dgram_send_max_size,
            timeout_count: 0,
            rtt: Duration::from_millis(0),
            cwnd: INITIAL_WINDOW,
            bytes_in_flight: 0,
            path_id: 0,
            path_events: VecDeque::new(),
            validated_paths: HashSet::from([(local, peer)]),
            pending_path_validation: None,
            pending_path_frames: VecDeque::new(),
            last_migration_at: None,
            dest_cids: cid::ConnectionIdSet::new(),
            pkt_spaces: [
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
            ],
            next_send_pn_by_space: [0, 0, 0],
            key_phase: false,
            readable_streams: VecDeque::new(),
            readable_stream_ids: HashSet::new(),
            writable_streams: VecDeque::new(),
            writable_stream_ids: HashSet::new(),
            local_error: None,
            #[cfg(any(test, feature = "rust-tests"))]
            retired_scids: VecDeque::new(),
            bytes_in_flight_started: None,
            last_activity: Instant::now(),
            conn_max_data: initial_max_data,
            conn_bytes_recvd: 0,
            peer_max_data: initial_max_data,
            tls_provider: None,
            tls_profile: None,
            conn_bytes_sent: 0,
            pending_control: VecDeque::new(),
            crypto: Arc::new(parking_lot::RwLock::new(packet::CryptoContext::default())),
            crypto_1rtt: arc_swap::ArcSwapOption::new(None),
            short_header_tag_reserve: 0,
            ecn_ect0: 0,
            ecn_ect1: 0,
            ecn_ce: 0,
            recovery,
            fec_escalation_threshold: 0.05,
            fec_ctrl_delta: FecControlDelta::default(),
            fec_cb_sent_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_sent_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_acked_packets: 0,
            pending_probe_spaces: VecDeque::new(),
            stream_transmissions: HashMap::new(),
            stream_retransmit_queue: VecDeque::new(),
            stream_transmission_by_pn: BTreeMap::new(),
            lost_stream_transmission_by_pn: BTreeMap::new(),
            next_stream_transmission_id: 0,
            stream_retransmit_bytes: 0,
            intelligent_stealth_runtime: false,
            brain_runtime_permissions: crate::transport::BrainRuntimePermissions::default(),
            observer: None,
            h3: None,
            strike_register: None,
            pmtu: PmtuState::new(pmtu_enabled, pmtu_policy),
            pmtu_probe_pn: None,
            pmtu_above_floor_pns: HashSet::new(),
            traffic_analysis: None,
            traffic_analysis_base_policy,
            traffic_analysis_escalation_ceiling: None,
        };
        conn.rebuild_traffic_analysis_scheduler();
        // Inherit strike register from config (server-side 0-RTT anti-replay).
        conn.strike_register = conn.config.strike_register.clone();
        // Apply configured initial RTT estimate before the first real measurement.
        if conn.config.initial_rtt_ms != 100 {
            conn.recovery.set_initial_rtt(Duration::from_millis(conn.config.initial_rtt_ms));
        }
        conn.install_recovery_fec_callbacks();
        conn.refresh_path_count();
        conn
    }

    pub(crate) fn new_client(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, false)
    }

    pub(crate) fn new_server(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, true)
    }

    /// Public wrapper to enable QUIC DATAGRAM queues via config
    pub fn enable_datagrams(&mut self, recv_q: usize, send_q: usize) {
        self.config.enable_dgram(recv_q, send_q);
    }
    pub(crate) fn dgram_pool_or_global(&self) -> Arc<crate::optimize::MemoryPool> {
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_pool.clone()
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            crate::optimize::global_pool()
        }
    }
    fn total_send_buffered_bytes(&self) -> usize {
        #[cfg(not(feature = "stream_ring_buffer"))]
        return self.streams.values().map(|s| s.send_buf.len()).sum();
        #[cfg(feature = "stream_ring_buffer")]
        return self.streams.values().map(|s| s.send_ring.len()).sum();
    }

    #[inline]
    fn stream_ledger_has_capacity(&self, payload_len: usize) -> bool {
        self.stream_transmissions.len() < MAX_STREAM_ORIGINAL_TRANSMISSIONS
            && self.stream_retransmit_bytes.saturating_add(payload_len)
                <= MAX_STREAM_RETRANSMIT_BYTES
    }

    fn has_sendable_stream_frame(&self) -> bool {
        if self.stream_retransmit_queue.iter().any(|transmission_id| {
            self.stream_transmissions
                .get(transmission_id)
                .is_some_and(|transmission| transmission.queued)
        }) {
            return true;
        }
        let Some(stream_id) = self.writable_streams.front() else {
            return false;
        };
        let Some(stream) = self.streams.get(stream_id) else {
            return false;
        };
        #[cfg(not(feature = "stream_ring_buffer"))]
        let has_data = !stream.send_buf.is_empty();
        #[cfg(feature = "stream_ring_buffer")]
        let has_data = !stream.send_ring.is_empty();
        if has_data {
            self.stream_ledger_has_capacity(1)
        } else {
            stream.send_fin && self.stream_ledger_has_capacity(0)
        }
    }

    fn stage_stream_transmission(
        &mut self,
        stream_id: u64,
        offset: u64,
        data: Arc<[u8]>,
        fin: bool,
    ) -> Result<u64, crate::error::ConnectionError> {
        if !self.stream_ledger_has_capacity(data.len()) {
            return Err(crate::error::ConnectionError::Done);
        }

        let transmission_id = self.allocate_stream_transmission_id()?;

        self.stream_retransmit_bytes = self.stream_retransmit_bytes.saturating_add(data.len());
        self.stream_transmissions.insert(
            transmission_id,
            StreamTransmission {
                stream_id,
                offset,
                data,
                fin,
                queued: true,
                active_packet: None,
                lost_packets: VecDeque::new(),
            },
        );
        self.stream_retransmit_queue.push_back(transmission_id);
        Ok(transmission_id)
    }

    fn allocate_stream_transmission_id(&mut self) -> Result<u64, crate::error::ConnectionError> {
        let transmission_id = self.next_stream_transmission_id;
        self.next_stream_transmission_id = self.next_stream_transmission_id.wrapping_add(1);
        if self.stream_transmissions.contains_key(&transmission_id) {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        Ok(transmission_id)
    }

    fn split_queued_stream_transmission(
        &mut self,
        transmission_id: u64,
        prefix_len: usize,
    ) -> Result<(), crate::error::ConnectionError> {
        let Some(transmission) = self.stream_transmissions.get(&transmission_id) else {
            return Err(crate::error::ConnectionError::InvalidState);
        };
        if !transmission.queued
            || transmission.active_packet.is_some()
            || prefix_len == 0
            || prefix_len >= transmission.data.len()
        {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        if self.stream_transmissions.len() >= MAX_STREAM_TRANSMISSIONS {
            return Err(crate::error::ConnectionError::Done);
        }

        let stream_id = transmission.stream_id;
        let tail_offset = transmission.offset.saturating_add(prefix_len as u64);
        let prefix = Arc::<[u8]>::from(&transmission.data[..prefix_len]);
        let tail = Arc::<[u8]>::from(&transmission.data[prefix_len..]);
        let tail_fin = transmission.fin;
        let lost_packets = transmission.lost_packets.clone();
        let tail_id = self.allocate_stream_transmission_id()?;

        let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) else {
            return Err(crate::error::ConnectionError::InvalidState);
        };
        transmission.data = prefix;
        transmission.fin = false;
        self.stream_transmissions.insert(
            tail_id,
            StreamTransmission {
                stream_id,
                offset: tail_offset,
                data: tail,
                fin: tail_fin,
                queued: true,
                active_packet: None,
                lost_packets: lost_packets.clone(),
            },
        );
        let tail_position = self
            .stream_retransmit_queue
            .iter()
            .position(|id| *id == transmission_id)
            .map_or(self.stream_retransmit_queue.len(), |position| position + 1);
        self.stream_retransmit_queue.insert(tail_position, tail_id);
        for packet_number in lost_packets {
            let transmission_ids =
                self.lost_stream_transmission_by_pn.entry(packet_number).or_default();
            if !transmission_ids.contains(&tail_id) {
                transmission_ids.push(tail_id);
            }
        }
        Ok(())
    }

    fn remove_stream_retransmit_queue_entry(&mut self, transmission_id: u64) {
        if self.stream_retransmit_queue.front() == Some(&transmission_id) {
            self.stream_retransmit_queue.pop_front();
        } else {
            self.stream_retransmit_queue.retain(|id| *id != transmission_id);
        }
    }

    fn commit_stream_transmission(&mut self, transmission_id: u64, packet_number: u64) {
        let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) else {
            return;
        };
        transmission.queued = false;
        transmission.active_packet = Some(packet_number);
        self.remove_stream_retransmit_queue_entry(transmission_id);
        self.stream_transmission_by_pn.insert(packet_number, transmission_id);
    }

    fn retire_stream_transmission(&mut self, transmission_id: u64) {
        let Some(transmission) = self.stream_transmissions.remove(&transmission_id) else {
            return;
        };
        self.stream_retransmit_bytes =
            self.stream_retransmit_bytes.saturating_sub(transmission.data.len());
        if let Some(packet_number) = transmission.active_packet {
            self.stream_transmission_by_pn.remove(&packet_number);
        }
        for packet_number in transmission.lost_packets {
            let remove_packet = if let Some(transmission_ids) =
                self.lost_stream_transmission_by_pn.get_mut(&packet_number)
            {
                transmission_ids.retain(|id| *id != transmission_id);
                transmission_ids.is_empty()
            } else {
                false
            };
            if remove_packet {
                self.lost_stream_transmission_by_pn.remove(&packet_number);
            }
        }
        if transmission.queued {
            self.remove_stream_retransmit_queue_entry(transmission_id);
        }
    }

    fn acknowledge_stream_transmission_packet(&mut self, packet_number: u64) {
        if let Some(transmission_id) = self.stream_transmission_by_pn.get(&packet_number).copied() {
            self.retire_stream_transmission(transmission_id);
            return;
        }
        let transmission_ids =
            self.lost_stream_transmission_by_pn.get(&packet_number).cloned().unwrap_or_default();
        for transmission_id in transmission_ids {
            self.retire_stream_transmission(transmission_id);
        }
    }

    fn lose_stream_transmission_packet(&mut self, packet_number: u64) {
        let Some(transmission_id) = self.stream_transmission_by_pn.remove(&packet_number) else {
            return;
        };

        let mut evicted_packet = None;
        if let Some(transmission) = self.stream_transmissions.get_mut(&transmission_id) {
            if transmission.active_packet == Some(packet_number) {
                transmission.active_packet = None;
            }
            if transmission.lost_packets.len() == MAX_STREAM_LOST_PACKET_HISTORY {
                evicted_packet = transmission.lost_packets.pop_front();
            }
            transmission.lost_packets.push_back(packet_number);
            if !transmission.queued {
                transmission.queued = true;
                self.stream_retransmit_queue.push_back(transmission_id);
            }
        }
        if let Some(evicted_packet) = evicted_packet {
            let remove_packet = if let Some(transmission_ids) =
                self.lost_stream_transmission_by_pn.get_mut(&evicted_packet)
            {
                transmission_ids.retain(|id| *id != transmission_id);
                transmission_ids.is_empty()
            } else {
                false
            };
            if remove_packet {
                self.lost_stream_transmission_by_pn.remove(&evicted_packet);
            }
        }
        let transmission_ids =
            self.lost_stream_transmission_by_pn.entry(packet_number).or_default();
        if !transmission_ids.contains(&transmission_id) {
            transmission_ids.push(transmission_id);
        }
    }

    fn acknowledge_late_stream_packets(&mut self, ranges: &[(u64, u64)]) {
        let mut transmission_ids = Vec::new();
        for (start, end) in ranges {
            transmission_ids.extend(
                self.lost_stream_transmission_by_pn
                    .range(*start..=*end)
                    .flat_map(|(_, transmission_ids)| transmission_ids.iter().copied()),
            );
        }
        transmission_ids.sort_unstable();
        transmission_ids.dedup();
        for transmission_id in transmission_ids {
            self.retire_stream_transmission(transmission_id);
        }
    }

    /// Whether the peer's address counts as validated for recovery purposes
    /// (RFC 9002 §6.2.2.1). Clients are never amplification-limited; for a
    /// server, handshake completion implies validation happened by then.
    fn client_address_validated(&self) -> bool {
        !self.is_server || self.tls_handshake_complete()
    }

    /// Earliest loss/PTO deadline across all packet number spaces
    /// (RFC 9002 §6.1.2/§6.2.1). `None` disarms the recovery timer.
    pub fn recovery_deadline(&self) -> Option<Instant> {
        self.recovery.loss_detection_timeout(
            self.tls_handshake_complete(),
            self.is_server,
            self.client_address_validated(),
        )
    }

    /// Runs the recovery loss-detection timer: declares time-threshold losses
    /// or queues PTO probes (RFC 9002 A.8). Event loops call this when
    /// [`recovery_deadline`](Self::recovery_deadline) expires.
    pub fn on_recovery_timeout(&mut self, now: Instant) {
        let outcome = self.recovery.on_loss_detection_timeout(
            self.tls_handshake_complete(),
            self.is_server,
            now,
        );
        // Time-threshold losses: retire stream transmissions, PMTU, crypto.
        for (space, pn, sz) in &outcome.lost {
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(*sz as u64);
            if *space == recovery::PacketSpace::Application {
                self.lose_stream_transmission_packet(*pn);
                self.pmtu_above_floor_pns.remove(pn);
                if self.pmtu_probe_pn == Some(*pn) {
                    self.pmtu.on_probe_lost();
                    self.pmtu_probe_pn = None;
                }
            }
        }
        if !outcome.crypto_lost.is_empty() {
            let mut crypto = self.crypto.write();
            for (space, off, len) in &outcome.crypto_lost {
                let stream = match space {
                    recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                    recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                    recovery::PacketSpace::Application => &mut crypto.crypto_application,
                };
                stream.requeue_crypto(*off, *len);
            }
        }
        if !outcome.lost.is_empty() {
            self.cwnd = self.recovery.cwnd;
        }
        // PTO probes: handshake spaces requeue their retained CRYPTO (the
        // flight loop re-emits it or sends a PING-only probe), the app space
        // gets a PING in the 1-RTT assembly.
        for space in outcome.probe_spaces {
            match space {
                recovery::PacketSpace::Application => {}
                recovery::PacketSpace::Initial | recovery::PacketSpace::Handshake => {
                    let mut crypto = self.crypto.write();
                    let stream = match space {
                        recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                        recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                        recovery::PacketSpace::Application => continue,
                    };
                    stream.requeue_all_unacked();
                }
            }
            self.pending_probe_spaces.push_back(space);
        }
    }

    /// Applies the connection-level reactions of an ACK processed by the
    /// canonical recovery owner: stream retirement, PMTU bookkeeping, CRYPTO
    /// range ack/requeue, stats, RTT mirror, and the FEC clean-ACK counter.
    fn apply_ack_outcome(
        &mut self,
        space: recovery::PacketSpace,
        outcome: recovery::AckOutcome,
        now: Instant,
    ) {
        if !outcome.crypto_acked.is_empty() || !outcome.crypto_lost.is_empty() {
            let mut crypto = self.crypto.write();
            let stream = match space {
                recovery::PacketSpace::Initial => &mut crypto.crypto_initial,
                recovery::PacketSpace::Handshake => &mut crypto.crypto_handshake,
                recovery::PacketSpace::Application => &mut crypto.crypto_application,
            };
            for (off, len) in &outcome.crypto_acked {
                stream.ack_crypto(*off, *len);
            }
            for (off, len) in &outcome.crypto_lost {
                stream.requeue_crypto(*off, *len);
            }
        }
        let mut above_floor_acked = false;
        let acked_packet_count = outcome.newly_acked.len() as u64;
        let mut acked_bytes = 0usize;
        for &(pn, sz) in &outcome.newly_acked {
            acked_bytes = acked_bytes.saturating_add(sz);
            if space == recovery::PacketSpace::Application {
                self.acknowledge_stream_transmission_packet(pn);
                above_floor_acked |= self.pmtu_above_floor_pns.remove(&pn);
                if self.pmtu_probe_pn == Some(pn) {
                    let previous_mtu = self.pmtu.effective_mtu();
                    self.pmtu.on_probe_acked(now);
                    if self.pmtu.effective_mtu() != previous_mtu {
                        log::info!(
                            "DPLPMTUD confirmed path MTU: {}B -> {}B",
                            previous_mtu,
                            self.pmtu.effective_mtu()
                        );
                    }
                    self.pmtu_probe_pn = None;
                }
            }
        }
        for &(pn, sz) in &outcome.lost {
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(sz as u64);
            if space == recovery::PacketSpace::Application {
                self.lose_stream_transmission_packet(pn);
                self.pmtu_above_floor_pns.remove(&pn);
                if self.pmtu_probe_pn == Some(pn) {
                    self.pmtu.on_probe_lost();
                    self.pmtu_probe_pn = None;
                }
            }
        }
        if let Some(sample) = outcome.rtt_sample {
            self.rtt = sample;
        }
        self.stats.acked_bytes = self.stats.acked_bytes.saturating_add(acked_bytes as u64);
        if !outcome.newly_acked.is_empty() || !outcome.lost.is_empty() {
            self.cwnd = self.recovery.cwnd;
        }
        // Only a packet above the safe floor proves that the discovered
        // capacity remains usable. Floor-sized ACKs cannot mask a black hole.
        if above_floor_acked {
            self.pmtu.on_packet_acked(self.pmtu.effective_mtu(), now);
        }
        if space == recovery::PacketSpace::Application {
            self.fec_acked_packets = self.fec_acked_packets.saturating_add(acked_packet_count);
        }
        if let Some(evidence) = outcome.persistent_congestion_evidence {
            log::info!(
                "persistent congestion established; cwnd={} space={:?} pmtu_effective={} largest_acked={} ack_delay_us={} largest_acked_age_known={} largest_acked_age_us={} acked_packets={} ack_lost_packets={} ack_packet_threshold_losses={} ack_time_threshold_losses={} run_start_pn={} run_min_packet_size={} run_max_packet_size={} run_control_packets={} run_stream_packets={} run_stream_fresh_packets={} run_stream_retransmission_packets={} run_datagram_packets={} terminal_lost_pn={} terminal_packet_threshold={} terminal_time_threshold={} lost_packets={} smoothed_rtt_us={} rtt_variance_us={} loss_delay_us={} period_us={} run_us={}",
                self.recovery.cwnd,
                space,
                self.pmtu.effective_mtu(),
                evidence.largest_acked,
                evidence.triggering_ack_delay.as_micros(),
                evidence.largest_acked_packet_age.is_some(),
                evidence
                    .largest_acked_packet_age
                    .map(|age| age.as_micros())
                    .unwrap_or(0),
                evidence.triggering_ack_newly_acked_packets,
                evidence.triggering_ack_lost_packets,
                evidence.triggering_ack_packet_threshold_losses,
                evidence.triggering_ack_time_threshold_losses,
                evidence.run_start_pn,
                evidence.run_min_packet_size,
                evidence.run_max_packet_size,
                evidence.run_control_packets,
                evidence.run_stream_packets,
                evidence.run_stream_fresh_packets,
                evidence.run_stream_retransmission_packets,
                evidence.run_datagram_packets,
                evidence.terminal_lost_pn,
                evidence.terminal_loss_by_packet_threshold,
                evidence.terminal_loss_by_time_threshold,
                evidence.lost_packet_count,
                evidence.smoothed_rtt.as_micros(),
                evidence.rtt_variance.as_micros(),
                evidence.loss_delay.as_micros(),
                evidence.period.as_micros(),
                evidence.run_end.saturating_duration_since(evidence.run_start).as_micros(),
            );
        }
    }

    fn refresh_path_count(&mut self) {
        self.stats.paths_count = self
            .validated_paths
            .len()
            .saturating_add(usize::from(self.pending_path_validation.is_some()));
    }

    fn path_validation_budget_allows(
        &self,
        path: &PendingPathValidation,
        frame: &Frame<'_>,
    ) -> bool {
        if path.origin != PathValidationOrigin::PeerPath {
            return true;
        }
        let estimated_packet_len =
            1 + self.dcid.as_ref().len() + 4 + frames::wire_len(frame) + self.tag_reserve_1rtt();
        let max_factor = self.config.max_amplification_factor.max(1);
        path.sent_bytes.saturating_add(estimated_packet_len)
            <= path.received_bytes.saturating_mul(max_factor)
    }

    fn queue_targeted_path_frame(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        frame: Frame<'static>,
    ) {
        self.pending_path_frames.push_back(PendingPathFrame { local_addr, peer_addr, frame });
    }

    fn count_pending_path_responses(&self, local_addr: SocketAddr, peer_addr: SocketAddr) -> usize {
        self.pending_path_frames
            .iter()
            .filter(|item| {
                item.local_addr == local_addr
                    && item.peer_addr == peer_addr
                    && matches!(item.frame, Frame::PathResponse { .. })
            })
            .count()
    }

    fn pop_targeted_path_frame_for_send(&mut self) -> Option<PendingPathFrame> {
        self.poll_path_validation_timeout(Instant::now());

        if let Some(front) = self.pending_path_frames.front() {
            if let Some(path) = self.pending_path_validation.as_ref() {
                if path.matches_path(front.local_addr, front.peer_addr)
                    && !self.path_validation_budget_allows(path, &front.frame)
                {
                    return None;
                }
            }
        }

        self.pending_path_frames.pop_front()
    }

    /// Returns whether a queued PATH_CHALLENGE or PATH_RESPONSE can be emitted now.
    ///
    /// Outer datagram owners use this to prioritize validation traffic ahead of
    /// buffered application/FEC output without bypassing the server amplification
    /// budget enforced by [`Self::pop_targeted_path_frame_for_send`].
    pub fn has_sendable_path_control(&mut self) -> bool {
        self.poll_path_validation_timeout(Instant::now());

        let Some(front) = self.pending_path_frames.front() else {
            return false;
        };
        self.pending_path_validation.as_ref().is_none_or(|path| {
            !path.matches_path(front.local_addr, front.peer_addr)
                || self.path_validation_budget_allows(path, &front.frame)
        })
    }

    fn mark_unvalidated_path_send(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        bytes: usize,
    ) {
        if let Some(path) = self.pending_path_validation.as_mut() {
            if path.matches_path(local_addr, peer_addr) {
                path.sent_bytes = path.sent_bytes.saturating_add(bytes);
            }
        }
    }

    fn enqueue_path_response(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        if self.count_pending_path_responses(local_addr, peer_addr)
            >= self.config.path_challenge_recv_max_queue_len.max(1)
        {
            return;
        }
        self.queue_targeted_path_frame(local_addr, peer_addr, Frame::PathResponse { data });
    }

    fn emit_failed_validation(&mut self, local_addr: SocketAddr, peer_addr: SocketAddr) {
        self.path_events.push_back(PathEvent::FailedValidation(local_addr, peer_addr));
    }

    fn discard_own_path_challenge(&mut self, path: &PendingPathValidation) {
        self.pending_path_frames.retain(|frame| {
            let is_own_challenge = path.matches_path(frame.local_addr, frame.peer_addr)
                && matches!(
                    &frame.frame,
                    Frame::PathChallenge { data } if *data == path.challenge
                );
            !is_own_challenge
        });
    }

    fn poll_path_validation_timeout(&mut self, now: Instant) {
        let should_fail = self.pending_path_validation.as_ref().is_some_and(|path| {
            now.saturating_duration_since(path.issued_at) >= PATH_VALIDATION_TIMEOUT
        });
        if !should_fail {
            return;
        }

        let Some(path) = self.pending_path_validation.take() else {
            return;
        };
        self.discard_own_path_challenge(&path);
        self.emit_failed_validation(path.local_addr, path.peer_addr);
        self.refresh_path_count();
    }

    fn begin_path_validation(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        origin: PathValidationOrigin,
        initial_received_bytes: usize,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.poll_path_validation_timeout(Instant::now());

        if self.validated_paths.contains(&(local_addr, peer_addr)) {
            return Ok(self.path_id);
        }

        if let Some(path) = self.pending_path_validation.as_ref() {
            if path.matches_path(local_addr, peer_addr) {
                return Ok(path.path_id);
            }
            return Err(crate::error::ConnectionError::InvalidState);
        }

        if origin != PathValidationOrigin::PeerPath
            && self
                .last_migration_at
                .is_some_and(|last| last.elapsed() < self.config.migration_policy.cooldown)
        {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        let mut challenge = [0u8; 8];
        crate::transport::rand::rand_bytes(&mut challenge);
        let next_path_id = self.path_id.wrapping_add(1);
        let issued_at = Instant::now();
        let path = PendingPathValidation {
            path_id: next_path_id,
            old_local_addr: self.local_addr,
            old_peer_addr: self.peer_addr,
            local_addr,
            peer_addr,
            challenge,
            issued_at,
            received_bytes: initial_received_bytes,
            sent_bytes: 0,
            origin,
        };
        self.pending_path_validation = Some(path);
        self.queue_targeted_path_frame(
            local_addr,
            peer_addr,
            Frame::PathChallenge { data: challenge },
        );
        self.path_events.push_back(PathEvent::New(local_addr, peer_addr));
        self.refresh_path_count();
        Ok(next_path_id)
    }

    fn observe_incoming_path(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        received_bytes: usize,
    ) {
        if self.local_addr == local_addr && self.peer_addr == peer_addr {
            return;
        }

        if let Some(path) = self.pending_path_validation.as_mut() {
            if path.matches_path(local_addr, peer_addr) {
                path.received_bytes = path.received_bytes.saturating_add(received_bytes);
            }
            return;
        }

        if self.config.disable_active_migration {
            return;
        }

        if self
            .last_migration_at
            .is_some_and(|last| last.elapsed() < self.config.migration_policy.cooldown)
        {
            return;
        }

        let _ = self.begin_path_validation(
            local_addr,
            peer_addr,
            PathValidationOrigin::PeerPath,
            received_bytes,
        );
    }

    fn handle_path_response_frame(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        self.poll_path_validation_timeout(Instant::now());

        let Some(path) = self.pending_path_validation.as_ref() else {
            return;
        };
        if !path.matches_path(local_addr, peer_addr) || path.challenge != data {
            return;
        }

        let Some(path) = self.pending_path_validation.take() else {
            return;
        };
        let now = Instant::now();
        self.discard_own_path_challenge(&path);
        self.local_addr = path.local_addr;
        self.peer_addr = path.peer_addr;
        self.path_id = path.path_id;
        let kind = if path.old_local_addr.ip() == path.local_addr.ip()
            && path.old_peer_addr.ip() == path.peer_addr.ip()
        {
            crate::transport::cc::PathChangeKind::PortRebinding
        } else {
            crate::transport::cc::PathChangeKind::NewAddress
        };
        self.recovery.on_path_change(
            kind,
            now.saturating_duration_since(path.issued_at),
            self.config.migration_policy,
            now,
        );
        self.cwnd = self.recovery.cwnd;
        self.validated_paths.insert((path.local_addr, path.peer_addr));
        self.last_migration_at = Some(now);
        self.path_events.push_back(PathEvent::Validated(path.local_addr, path.peer_addr));
        if path.old_local_addr != path.local_addr || path.old_peer_addr != path.peer_addr {
            self.path_events.push_back(PathEvent::PeerMigrated(path.old_peer_addr, path.peer_addr));
        }
        self.refresh_path_count();
    }

    /// Returns whether validation is active for the exact network path.
    pub fn is_path_validation_pending(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> bool {
        self.pending_path_validation
            .as_ref()
            .is_some_and(|path| path.matches_path(local_addr, peer_addr))
    }

    /// Returns pending path validation state for test assertions.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pending_path_validation_for_test(
        &self,
    ) -> Option<(u64, SocketAddr, SocketAddr, [u8; 8])> {
        self.pending_path_validation
            .as_ref()
            .map(|path| (path.path_id, path.local_addr, path.peer_addr, path.challenge))
    }

    /// Injects a PATH_RESPONSE for test-driven path validation.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn receive_path_response_for_test(
        &mut self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: [u8; 8],
    ) {
        self.handle_path_response_frame(local_addr, peer_addr, data);
    }

    /// Forces the pending path validation to expire for timeout testing.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn expire_pending_path_validation_for_test(&mut self) {
        if let Some(path) = self.pending_path_validation.as_mut() {
            path.issued_at =
                Instant::now() - PATH_VALIDATION_TIMEOUT - Duration::from_millis(1);
        }
        self.poll_path_validation_timeout(Instant::now());
    }

    // ============================================================================
    // Real-TLS Integration Methods
    // ============================================================================

    /// Enable rustls-backed TLS provider with optional TLS Cover layer.
    pub(crate) fn enable_tls(
        &mut self,
        profile_name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        log::info!("Enabling rustls TLS provider with profile: {}", profile_name);

        // TLS provider must operate on the same CryptoContext as the transport,
        // otherwise secrets would never be installed into the packet protection keys.
        let crypto_arc = self.crypto.clone();
        let mut available_versions = self.config.supported_versions.clone();
        available_versions.push(self.version_negotiation.grease);
        let version_information = super::version::VersionInformation {
            chosen: self.config.version,
            available: available_versions,
        }
        .encode_parameter()?;

        // Create the TLS composition stack (rustls + optional TLS Cover).
        let provider = crate::qftls::create_provider_for_version(
            self.is_server,
            crypto_arc.clone(),
            self.config.verify_peer,
            self.config.version,
            &version_information,
        )?;

        // Store provider
        self.tls_provider = Some(provider);

        if let Some(provider_ref) = self.tls_provider.as_ref() {
            log::info!("TLS provider enabled: {}", provider_ref.provider_name());
        } else {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        // Install Initial secrets/HP from DCID for early Long Header encryption.
        // QUIC initial keys are direction-specific:
        // - Client: write=client_secret, read=server_secret
        // - Server: write=server_secret, read=client_secret
        // RFC 9001: Initial secrets derive from the Destination Connection ID
        // in the packet being accepted. After Retry the server receives its
        // Retry SCID in that field, while the client re-derives explicitly in
        // the Retry receive path.
        let initial_dcid = if !self.initial_dcid.is_empty() {
            self.initial_dcid.as_ref()
        } else {
            self.dcid.as_ref()
        };
        let (client_secret, server_secret) =
            packet::derive_initial_secrets(initial_dcid, self.config.version);
        {
            let (read_secret, write_secret) = if self.is_server {
                (client_secret.as_slice(), server_secret.as_slice())
            } else {
                (server_secret.as_slice(), client_secret.as_slice())
            };
            let mut crypto = self.crypto.write();
            crypto.install_aes_gcm_initial(read_secret, write_secret, self.config.version);
            crypto.install_hp_initial(read_secret, write_secret, self.config.version);
        }

        Ok(())
    }

    /// Configure TLS provider with a specific profile and SNI.
    pub(crate) fn configure_tls(
        &mut self,
        profile: &crate::qftls::TlsProfile,
        sni: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        let Some(provider) = &mut self.tls_provider else {
            return Err(crate::error::ConnectionError::InvalidState);
        };

        let mut effective = profile.clone();
        if !sni.is_empty() {
            effective.sni = Some(sni.to_string());
        }
        provider.configure(&effective)?;
        self.tls_profile = Some(effective);
        // Optionally enable 0-RTT when desired.
        if let Err(e) = provider.enable_0rtt() {
            log::debug!("TLS provider 0-RTT enablement failed: {:?}", e);
        }
        Ok(())
    }

    /// Process TLS handshake with optional cover CH override.
    pub(crate) fn do_tls_handshake(
        &mut self,
        override_template: Option<&str>,
    ) -> Result<bool, crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            // Apply cover layer CH override if supported and requested.
            if let Some(template_name) = override_template {
                if provider.supports_ch_override() {
                    // Create simple template bytes; cover layer expands details.
                    let template_bytes = template_name.as_bytes();
                    provider.apply_ch_override(template_bytes)?;
                }
            }

            // Check handshake completion
            let done = provider.handshake_complete();
            if done {
                // If ALPN negotiated HTTP/3, enable H3 binding
                if let Some(alpn) = provider.alpn() {
                    if alpn.starts_with("h3") {
                        if let Err(e) = self.enable_h3() {
                            log::warn!("Failed to enable HTTP/3 after ALPN negotiation: {:?}", e);
                        }
                    }
                }
            }
            Ok(done)
        } else {
            // No TLS provider configured, consider handshake complete
            Ok(true)
        }
    }

    /// Returns true when the TLS provider reports handshake completion.
    /// This is intentionally distinct from transport liveness/establishment.
    pub fn tls_handshake_complete(&self) -> bool {
        self.tls_provider.as_ref().map(|p| p.handshake_complete()).unwrap_or(true)
    }

    /// Enable HTTP/3 connection bound to this transport (idempotent)
    pub(crate) fn enable_h3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_some() {
            return Ok(());
        }
        let cfg = crate::transport::h3::Config::new()
            .map_err(|_| crate::transport::h3::Error::InternalError)?;
        let h3c = crate::transport::h3::Connection::with_transport(self, &cfg)?;
        self.h3 = Some(h3c);
        Ok(())
    }

    /// Establish a MASQUE CONNECT-UDP stream via HTTP/3, returns stream id
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_connect_udp(
        &mut self,
        proxy_authority: &str,
        target_host_port: &str,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        // Temporarily take ownership to avoid aliasing &mut borrows
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.connect_udp(self, proxy_authority, target_host_port);
        self.h3 = Some(h3c);
        res
    }

    /// Enable MASQUE DATAGRAM context on an existing CONNECT-UDP stream
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_enable_datagram(
        &mut self,
        stream_id: u64,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.enable_masque_datagram(self, stream_id);
        self.h3 = Some(h3c);
        res
    }

    /// Send one MASQUE UDP payload as QUIC DATAGRAM (Flow-ID implicit)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_send_datagram(
        &mut self,
        stream_id: u64,
        udp_payload: &[u8],
    ) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.send_masque_datagram(self, stream_id, udp_payload);
        self.h3 = Some(h3c);
        res
    }

    /// Try to receive one MASQUE DATAGRAM; returns (flow_id, payload)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn masque_try_recv_datagram(&mut self) -> Option<(u64, Vec<u8>)> {
        if let Some(mut h3c) = self.h3.take() {
            let out = h3c.try_recv_masque_datagram(self);
            self.h3 = Some(h3c);
            out
        } else {
            None
        }
    }

    /// Process incoming CRYPTO frame
    pub(crate) fn process_crypto_frame(
        &mut self,
        level: crate::qftls::Level,
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
                    crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                    crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
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
                        self.local_error = Some(error.clone());
                        self.is_closed = true;
                        return Err(error);
                    }
                }
            }
            // Install any newly derived secrets into the shared CryptoContext.
            // Without this, the transport would never transition to 1-RTT and application streams
            // (including HTTP/3 HEADERS carrying x-qf-auth) would stall behind the handshake gate.
            if let Err(error) = self.poll_tls_and_validate_versions() {
                self.local_error = Some(error.clone());
                self.is_closed = true;
                return Err(error);
            }
        } else {
            // Store in crypto stream for later processing
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.recv(offset, data.into_owned())?;
        }

        Ok(())
    }

    fn poll_tls_and_validate_versions(&mut self) -> Result<(), crate::error::ConnectionError> {
        let peer_parameters = {
            let Some(provider) = &mut self.tls_provider else {
                return Ok(());
            };
            provider.poll_secrets_and_install(&self.crypto)?;
            provider.peer_quic_transport_params()
        };
        self.refresh_short_header_tag_reserve();
        self.validate_peer_version_information(peer_parameters)
    }

    fn validate_peer_version_information(
        &mut self,
        peer_parameters: Option<Vec<u8>>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.version_negotiation.peer_information_validated {
            return Ok(());
        }
        let Some(peer_parameters) = peer_parameters else {
            return Ok(());
        };
        let information = match super::version::find_version_information(&peer_parameters) {
            Ok(information) => information,
            Err(_) => {
                return Err(self.fail_version_negotiation(
                    super::version::TRANSPORT_PARAMETER_ERROR_CODE,
                    "malformed version_information transport parameter",
                ));
            }
        };
        let required = !self.is_server
            && (self.config.version == super::PROTOCOL_VERSION_V2
                || self.version_negotiation.reacted_to_vn);
        let information = match information {
            Some(information) => information,
            None if !self.is_server
                && self.version_negotiation.reacted_to_vn
                && self.config.version == super::PROTOCOL_VERSION =>
            {
                super::version::VersionInformation {
                    chosen: super::PROTOCOL_VERSION,
                    available: vec![super::PROTOCOL_VERSION],
                }
            }
            None => {
                if required {
                    return Err(self.fail_version_negotiation(
                        super::version::VERSION_NEGOTIATION_ERROR_CODE,
                        "required version_information transport parameter missing",
                    ));
                }
                self.version_negotiation.peer_information_validated = true;
                return Ok(());
            }
        };

        if self.is_server && !information.available.contains(&information.chosen) {
            return Err(self.fail_version_negotiation(
                super::version::TRANSPORT_PARAMETER_ERROR_CODE,
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
                super::version::VERSION_NEGOTIATION_ERROR_CODE,
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
        let _ = self.close(false, error_code, reason.as_bytes());
        self.local_error = Some(error.clone());
        error
    }

    /// Get next CRYPTO frame to send
    pub(crate) fn next_crypto_frame(
        &mut self,
        level: crate::qftls::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        if let Some(provider) = &mut self.tls_provider {
            provider.next_crypto_frame(level, max_len)
        } else {
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::qftls::Level::Initial => &mut crypto.crypto_initial,
                crate::qftls::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.next_crypto_frame(max_len)
        }
    }

    // ============================================================================
    // Packet Processing Methods
    // ============================================================================

    fn handle_version_negotiation_packet(
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
                self.local_error = Some(ConnectionError::VersionMismatch);
                return Err(ConnectionError::VersionMismatch);
            }
            Err(error) => return Err(error),
        };

        self.config.select_version(selected)?;
        self.version_negotiation.peer_information_validated = false;
        let mut scid = [0u8; super::MAX_CONN_ID_LEN];
        let mut dcid = [0u8; super::MAX_CONN_ID_LEN];
        super::rand::rand_bytes(&mut scid);
        super::rand::rand_bytes(&mut dcid);
        self.scid = ConnectionId::from_ref(&scid);
        self.initial_dcid = ConnectionId::from_ref(&dcid);
        self.dcid = self.initial_dcid;
        self.dest_cids = cid::ConnectionIdSet::new();
        self.dest_cids.insert(&self.dcid);
        self.is_established = false;
        self.is_closed = false;
        self.is_draining = false;
        self.local_error = None;
        self.pkt_spaces = [
            pnspace::PktNumSpace::default(),
            pnspace::PktNumSpace::default(),
            pnspace::PktNumSpace::default(),
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
        self.last_activity = Instant::now();
        self.conn_bytes_sent = 0;
        self.conn_bytes_recvd = 0;
        self.peer_max_data = self.config.initial_max_data;
        self.h3 = None;
        self.pmtu_probe_pn = None;
        self.pmtu_above_floor_pns.clear();
        self.recovery = Self::configured_recovery(&self.config, self.dgram_send_max_size);
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

#[cfg(test)]
mod simultaneous_path_validation_tests {
    use super::*;

    fn migrating_connection() -> (Connection, SocketAddr, SocketAddr, [u8; 8]) {
        let mut config = Config::new_with_version(crate::transport::PROTOCOL_VERSION)
            .expect("transport config");
        config
            .set_migration_policy(crate::transport::MigrationPolicy {
                port_rebinding_cwnd_factor: 0.5,
                cooldown: Duration::ZERO,
                probe_target: crate::transport::MigrationProbeTarget::PreviousWindow,
            })
            .expect("migration policy");
        let local: SocketAddr = "127.0.0.1:41000".parse().expect("local address");
        let migrated_local: SocketAddr =
            "127.0.0.1:41001".parse().expect("migrated local address");
        let peer: SocketAddr = "127.0.0.1:4433".parse().expect("peer address");
        let scid = ConnectionId::from_ref(b"path-race");
        let mut connection =
            packet::connect(None, scid.as_ref(), local, peer, &mut config).expect("connection");
        connection.migrate(migrated_local, peer).expect("migration");
        let (_, _, _, challenge) =
            connection.pending_path_validation_for_test().expect("pending validation");
        (connection, migrated_local, peer, challenge)
    }

    #[test]
    fn successful_validation_preserves_peer_path_response() {
        let (mut connection, migrated_local, peer, own_challenge) = migrating_connection();
        let peer_challenge = [0xA5; 8];
        connection.enqueue_path_response(migrated_local, peer, peer_challenge);

        connection.handle_path_response_frame(migrated_local, peer, own_challenge);

        let queued = connection
            .pop_targeted_path_frame_for_send()
            .expect("peer PATH_RESPONSE must remain queued");
        assert_eq!(queued.local_addr, migrated_local);
        assert_eq!(queued.peer_addr, peer);
        assert!(matches!(
            queued.frame,
            Frame::PathResponse { data } if data == peer_challenge
        ));
    }

    #[test]
    fn validation_timeout_preserves_peer_path_response() {
        let (mut connection, migrated_local, peer, _) = migrating_connection();
        let peer_challenge = [0x5A; 8];
        connection.enqueue_path_response(migrated_local, peer, peer_challenge);

        connection.expire_pending_path_validation_for_test();

        let queued = connection
            .pop_targeted_path_frame_for_send()
            .expect("peer PATH_RESPONSE must survive local validation timeout");
        assert_eq!(queued.local_addr, migrated_local);
        assert_eq!(queued.peer_addr, peer);
        assert!(matches!(
            queued.frame,
            Frame::PathResponse { data } if data == peer_challenge
        ));
    }
}
