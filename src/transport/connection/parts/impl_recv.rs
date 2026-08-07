impl Connection {
    /// Processes incoming packet
    #[inline(always)]
    pub fn recv(
        &mut self,
        buf: &mut [u8],
        info: &RecvInfo,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(buf.is_empty()) {
            return Err(ConnectionError::BufferTooShort);
        }

        // Prefetch packet input for the recv hotpath.
        prefetch_recv_packet_buffer(buf);

        // Pre-parse header to determine space and largest PN hint.
        // For short headers, DCID length is the local SCID length (the peer routes to our CID).
        let short_dcid_len = self.scid.as_ref().len();
        let (pre_ty, largest_hint, mut pre_parsed_hdr) =
            match packet::parse_header(buf, short_dcid_len) {
                Ok((hdr_native, pn_off)) => {
                    let t = hdr_native.ty;
                    let idx = match t {
                        PacketType::Initial => 0,
                        PacketType::Handshake => 1,
                        _ => 2,
                    };
                    (t, self.pkt_spaces[idx].largest_recv.unwrap_or(0), Some((hdr_native, pn_off)))
                }
                Err(_) => (PacketType::Short, 0, None),
            };

        if pre_ty == PacketType::VersionNegotiation {
            let Some((header, _)) = pre_parsed_hdr.as_ref() else {
                return Ok(buf.len());
            };
            return self.handle_version_negotiation_packet(header, buf.len());
        }

        // Retry verification (no payload decrypt)
        if let PacketType::Retry = pre_ty {
            let retry_version_matches = pre_parsed_hdr
                .as_ref()
                .is_some_and(|(header, _)| header.version == self.version_negotiation.chosen);
            if self.is_server || !retry_version_matches {
                return Ok(buf.len());
            }
            let odcid = if !self.initial_dcid.is_empty() {
                self.initial_dcid.as_ref()
            } else {
                self.dcid.as_ref()
            };
            if let Err(e) = packet::verify_retry_tag(buf, odcid, self.config.version) {
                self.record_local_error(e);
                if let Some(err) = self.local_error.clone() {
                    return Err(err);
                }
                return Err(ConnectionError::InvalidState);
            }

            // Client-side Retry handling: adopt token/DCID and re-derive Initial keys.
            // Reuse the pre-parsed header instead of re-parsing (TODO-391).
            if !self.is_server {
                let Some((retry_hdr, _)) = pre_parsed_hdr.take() else {
                    return Ok(buf.len());
                };
                if !retry_hdr.scid.is_empty() {
                    self.set_destination_cid(ConnectionId::from_ref(&retry_hdr.scid));
                }
                self.config.initial_token = retry_hdr.token;
                let (client_secret, server_secret) =
                    packet::derive_initial_secrets(self.dcid.as_ref(), self.config.version)?;
                let (read_secret, write_secret) =
                    (server_secret.as_slice(), client_secret.as_slice());
                let mut crypto = self.crypto.write();
                crypto.install_aes_gcm_initial(read_secret, write_secret, self.config.version)?;
                crypto.install_hp_initial(read_secret, write_secret, self.config.version)?;
                drop(crypto);
                self.refresh_short_header_tag_reserve();
                self.next_send_pn_by_space[0] = 0;
                self.pkt_spaces[0] = pnspace::PktNumSpace::new_with_clock(self.clock.clone());
            }
            // For Retry we do not parse further.
            self.received_non_vn_packet = true;
            self.stats.recv += 1;
            self.stats.recv_bytes += buf.len() as u64;
            return Ok(buf.len());
        }

        // Try to unprotect+decrypt using installed secrets.
        // For short-header packets, a bounded read-key catch-up loop tolerates peer key updates
        // across multiple generations before we receive packets in each phase.
        let mut rx_key_advances = 0usize;
        let (hdr_native, aad_len, pt_len) = loop {
            // Hot path: try lock-free 1-RTT ArcSwap first.
            // Consume pre_parsed_hdr by move (no clone) - on the common 1-RTT
            // success path this eliminates a Header clone (Vec dcid/scid alloc)
            // per packet. On the rare failure path we re-parse below.
            if let Some(keys) = self.crypto_1rtt.load().as_ref() {
                match packet::unprotect_and_decrypt_1rtt(
                    keys,
                    buf,
                    short_dcid_len,
                    largest_hint,
                    pre_parsed_hdr.take(),
                ) {
                    Ok(v) => break v,
                    Err(ConnectionError::Done) | Err(ConnectionError::CryptoError(_)) => {
                        // Fall through to RwLock path (key update in progress or non-Short packet).
                        // Re-parse if the 1-RTT attempt consumed pre_parsed_hdr.
                        // Safe: for Short headers the form/fixed bits (0x80/0x40) are not
                        // HP-protected (mask covers 0x1f only), so parse_header still
                        // identifies the packet type correctly after HP removal.
                        if pre_parsed_hdr.is_none() {
                            pre_parsed_hdr = packet::parse_header(buf, short_dcid_len).ok();
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            // Fallback: full RwLock path (handles Initial, Handshake, 0-RTT, previous keys).
            let decrypt = {
                let crypto_ref_for_rx = self.crypto.read();
                packet::unprotect_and_decrypt_parsed(
                    &crypto_ref_for_rx,
                    buf,
                    short_dcid_len,
                    largest_hint,
                    pre_parsed_hdr.take(),
                )
            };
            let should_try_key_update = matches!(
                &decrypt,
                Err(ConnectionError::Done) | Err(ConnectionError::CryptoError(_))
            );
            if should_try_key_update
                && pre_ty == PacketType::Short
                && rx_key_advances < MAX_RX_KEY_UPDATE_ADVANCE
            {
                match self.try_advance_read_keys() {
                    Ok(true) => {
                        rx_key_advances += 1;
                        // Re-parse for the next retry iteration.
                        if pre_parsed_hdr.is_none() {
                            pre_parsed_hdr = packet::parse_header(buf, short_dcid_len).ok();
                        }
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        self.record_local_error(error.clone());
                        if let Some(err) = self.local_error.clone() {
                            return Err(err);
                        }
                        return Err(error);
                    }
                }
            }
            match decrypt {
                Ok(v) => break v,
                Err(ConnectionError::Done) => return Err(ConnectionError::Done),
                Err(e) => {
                    self.record_local_error(e);
                    if let Some(err) = self.local_error.clone() {
                        return Err(err);
                    }
                    return Err(ConnectionError::InvalidState);
                }
            }
        };
        let pkt_ty = hdr_native.ty;
        self.received_non_vn_packet = true;

        // Receiving a valid 1-RTT (Short) packet confirms the peer has the
        // 1-RTT keys and therefore the handshake is done. Discard the
        // Initial/Handshake packet number spaces and keys per RFC 9002 §6.2.2
        // so unacknowledged handshake packets stop triggering PTO probes and
        // inflating bytes_in_flight.
        if pkt_ty == PacketType::Short {
            self.recovery.discard_space(recovery::PacketSpace::Initial);
            self.recovery.discard_space(recovery::PacketSpace::Handshake);
            let mut crypto = self.crypto.write();
            crypto.seal_initial = None;
            crypto.open_initial = None;
            crypto.seal_handshake = None;
            crypto.open_handshake = None;
        }

        // Learn peer CID from the first long-header packets.
        // - Server: outgoing DCID must be the client's SCID.
        // - Client: after receiving a server packet, outgoing DCID becomes the server's SCID.
        if hdr_native.ty != PacketType::Short && !hdr_native.scid.is_empty() {
            if self.is_server {
                if self.dcid.is_empty() {
                    self.set_destination_cid(ConnectionId::from_ref(&hdr_native.scid));
                }
                if self.initial_dcid.is_empty() && !hdr_native.dcid.is_empty() {
                    self.initial_dcid = ConnectionId::from_ref(&hdr_native.dcid);
                }
            } else {
                // Client: only rotate away from the initial placeholder DCID once we have a peer SCID.
                if self.dcid.is_empty() || self.dcid == self.initial_dcid {
                    self.set_destination_cid(ConnectionId::from_ref(&hdr_native.scid));
                }
            }
        }
        // Observer hook: notify after header processed and payload length known
        if let Some(obs) = &self.observer {
            obs.on_packet_recv(hdr_native.pkt_num, pt_len);
        }
        let space_idx = match pkt_ty {
            PacketType::Initial => 0,
            PacketType::Handshake => 1,
            _ => 2,
        };
        // Duplicate PN detection: if already observed, count and return.
        if hdr_native.pkt_num_len > 0 {
            if self.pkt_spaces[space_idx].contains(hdr_native.pkt_num) {
                let len = aad_len.saturating_add(pt_len).min(buf.len());
                self.stats.recv += 1;
                self.stats.recv_bytes += len as u64;
                return Ok(len);
            }
            if !self.pkt_spaces[space_idx].on_packet_recv(hdr_native.pkt_num) {
                // Duplicate or overflow PN - silently discard per RFC 9000 Section 12.3
                let len = aad_len.saturating_add(pt_len).min(buf.len());
                self.stats.recv += 1;
                self.stats.recv_bytes += len as u64;
                return Ok(len);
            }
        }

        // 0-RTT anti-replay gate (RFC 8446 Section 8, RFC 9001 Section 9.2).
        // After AEAD decryption and PN dedup, but before frame parsing.
        // Silently discard replayed 0-RTT packets - matches duplicate-PN pattern.
        if pkt_ty == PacketType::ZeroRTT {
            if let Some(ref strike_register) = self.strike_register {
                let end_replay = aad_len.saturating_add(pt_len).min(buf.len());
                let payload = &buf[aad_len..end_replay];
                let fingerprint = super::anti_replay::StrikeRegister::compute_fingerprint(
                    &hdr_native.dcid,
                    &hdr_native.scid,
                    payload,
                );
                if !strike_register.check_and_insert(&fingerprint, self.clock.now()) {
                    crate::telemetry!(
                        crate::optimize::telemetry::ZERO_RTT_REPLAY_REJECT_TOTAL.inc()
                    );
                    log::warn!("0-RTT replay detected and rejected");
                    let len = end_replay;
                    self.stats.recv += 1;
                    self.stats.recv_bytes += len as u64;
                    return Ok(len);
                }
                crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_ACCEPT_TOTAL.inc());
            }
        }

        // Parse frames from decrypted payload region
        let mut off = aad_len;
        let end = aad_len.saturating_add(pt_len).min(buf.len());
        self.observe_incoming_path(info.to, info.from, end);
        let mut ack_eliciting = false;
        while off < end {
            // Prefetch the next frame parse window for the recv hotpath.
            prefetch_frame_parse_window(buf.as_ptr(), end, off);
            match frames::from_bytes(&buf[off..end], pkt_ty) {
                Ok((frame, used)) => {
                    if used == 0 {
                        break;
                    }
                    off += used;
                    // Minimal: handle accounting for Stream/Crypto sizes
                    // 0-RTT must not carry CRYPTO frames.
                    if pkt_ty == PacketType::ZeroRTT && matches!(frame, Frame::Crypto { .. }) {
                        continue;
                    }
                    match frame {
                        Frame::Stream { stream_id, offset, data, fin } => {
                            ack_eliciting = true;
                            self.stats.stream_recv_bytes += data.len() as u64;
                            if self.readable_stream_ids.insert(stream_id) {
                                self.readable_streams.push_back(stream_id);
                            }
                            // Flow-control tracking
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                #[cfg(any(test, feature = "rust-tests"))]
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            let end = offset.saturating_add(data.len() as u64);
                            // Track highest received offset for flow control accounting.
                            s.recv_off = s.recv_off.max(end);
                            self.conn_bytes_recvd =
                                self.conn_bytes_recvd.saturating_add(data.len() as u64);

                            // Store fragment for ordered delivery.
                            if !data.is_empty() {
                                let mut start = offset;
                                if start < s.recv_next {
                                    let drop_n = (s.recv_next - start) as usize;
                                    if drop_n < data.len() {
                                        start = s.recv_next;
                                        s.recv_frags.insert(start, data[drop_n..].to_vec());
                                    }
                                } else if start == s.recv_next && s.recv_frags.is_empty() {
                                    // In-order fast path: copy directly to recv buffer, skip recv_frags.
                                    #[cfg(not(feature = "stream_ring_buffer"))]
                                    {
                                        s.recv_buf.extend_from_slice(&data);
                                    }
                                    #[cfg(feature = "stream_ring_buffer")]
                                    {
                                        s.recv_ring.write(&data);
                                    }
                                    s.recv_next += data.len() as u64;
                                } else {
                                    s.recv_frags.insert(start, data.into_owned());
                                }
                            }

                            // FIN denotes the final size of the stream (offset + data_len).
                            if fin {
                                match s.recv_final_size {
                                    None => s.recv_final_size = Some(end),
                                    Some(prev) if prev == end => {}
                                    Some(_) => {
                                        Self::retain_first_error(
                                            &mut self.local_error,
                                            crate::error::ConnectionError::FinalSize,
                                        );
                                    }
                                }
                            }

                            // Drain contiguous fragments into the receive buffer/ring.
                            loop {
                                let next = s.recv_next;
                                // Normalize any fragment that overlaps `next` by re-keying.
                                if let Some((&start, _)) = s.recv_frags.range(..=next).next_back() {
                                    if start < next {
                                        if let Some(mut frag) = s.recv_frags.remove(&start) {
                                            let start_end = start.saturating_add(frag.len() as u64);
                                            if start_end <= next {
                                                continue;
                                            }
                                            let skip = (next - start) as usize;
                                            frag.drain(..skip);
                                            s.recv_frags.insert(next, frag);
                                            continue;
                                        }
                                    }
                                }

                                let Some(frag) = s.recv_frags.remove(&next) else {
                                    break;
                                };

                                #[cfg(not(feature = "stream_ring_buffer"))]
                                {
                                    s.recv_buf.extend_from_slice(&frag);
                                    s.recv_next = s.recv_next.saturating_add(frag.len() as u64);
                                }
                                #[cfg(feature = "stream_ring_buffer")]
                                {
                                    let written = s.recv_ring.write(&frag);
                                    s.recv_next = s.recv_next.saturating_add(written as u64);
                                    if written < frag.len() {
                                        // Keep remainder for later to avoid truncation.
                                        s.recv_frags.insert(s.recv_next, frag[written..].to_vec());
                                        break;
                                    }
                                }
                            }

                            if let Some(final_size) = s.recv_final_size {
                                if s.recv_next >= final_size {
                                    s.recv_fin = true;
                                }
                            }
                            // If exceeding current stream window, flag flow control (minimal handling)
                            if s.recv_off > s.max_stream_data_rx {
                                Self::retain_first_error(
                                    &mut self.local_error,
                                    crate::error::ConnectionError::FlowControl,
                                );
                            } else if s.recv_off * 4 >= s.max_stream_data_rx * 3 {
                                // Grow stream window and queue MAX_STREAM_DATA
                                let new_max =
                                    (s.max_stream_data_rx.saturating_mul(2)).min(MAX_STREAM_SIZE);
                                s.max_stream_data_rx = new_max;
                                Self::queue_control_frame(
                                    &mut self.pending_control,
                                    Frame::MaxStreamData { stream_id, max: new_max },
                                );
                            }
                            if self.conn_bytes_recvd * 4 >= self.conn_max_data * 3 {
                                // Grow connection window and queue MAX_DATA
                                let new_max =
                                    self.conn_max_data.saturating_mul(2).min(MAX_STREAM_SIZE);
                                self.conn_max_data = new_max;
                                Self::queue_control_frame(
                                    &mut self.pending_control,
                                    Frame::MaxData { max: new_max },
                                );
                            }
                        }
                        Frame::MaxData { max } => {
                            // Peer increased our send window - validate and clamp
                            let clamped = if max > MAX_PEER_MAX_DATA {
                                log::warn!(
                                    "[transport] peer MAX_DATA {} exceeds cap {}, clamping",
                                    max,
                                    MAX_PEER_MAX_DATA
                                );
                                MAX_PEER_MAX_DATA
                            } else {
                                max
                            };
                            // RFC 9000: MAX_DATA must be monotonically increasing
                            if clamped > self.peer_max_data {
                                self.peer_max_data = clamped;
                            }
                        }
                        Frame::MaxStreamData { stream_id, max } => {
                            // Peer increased per-stream send window
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                #[cfg(any(test, feature = "rust-tests"))]
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            s.max_stream_data_tx = max;
                        }
                        Frame::ConnectionClose { error_code, frame_type, reason } => {
                            self.record_remote_error(
                                crate::error::ConnectionError::PeerConnectionClosed {
                                    error_code,
                                    frame_type,
                                    reason: reason.into_owned(),
                                },
                            );
                            self.is_closed = true;
                            self.is_draining = true;
                        }
                        Frame::ApplicationClose { error_code, reason } => {
                            self.record_remote_error(
                                crate::error::ConnectionError::PeerApplicationClosed {
                                    error_code,
                                    reason: reason.into_owned(),
                                },
                            );
                            self.is_closed = true;
                            self.is_draining = true;
                        }
                        Frame::PathChallenge { data } => {
                            ack_eliciting = true;
                            self.stats.path_challenge_rx_count =
                                self.stats.path_challenge_rx_count.saturating_add(1);
                            self.enqueue_path_response(info.to, info.from, data);
                        }
                        Frame::Datagram { data } => {
                            ack_eliciting = true;
                            self.stats.dgram_recv += 1;
                            self.enqueue_received_datagram(data);
                        }
                        Frame::Ack { ranges, ack_delay, .. } => {
                            // Decode ack_delay using the configured ack_delay_exponent
                            // (RFC 9000 §19.3: ack_delay is in microseconds = value << exponent)
                            let exp = self.config.ack_delay_exponent.min(20);
                            let ack_delay_us = ack_delay << exp;
                            let ack_delay = Duration::from_micros(ack_delay_us);
                            // Late ACKs retire stream transmissions whose packet was
                            // previously declared lost (spurious-loss accounting).
                            self.acknowledge_late_stream_packets(&ranges);
                            let space = recovery::PacketSpace::from_index(space_idx);
                            let now = self.clock.now();
                            let outcome = self.recovery.on_ack_received(
                                space,
                                &ranges,
                                ack_delay,
                                self.tls_handshake_complete(),
                                self.is_server,
                                now,
                            );
                            self.apply_ack_outcome(space, outcome, now);
                        }
                        Frame::Crypto { offset, data } => {
                            let lvl = match pkt_ty {
                                PacketType::Initial => crate::qftls::Level::Initial,
                                PacketType::Handshake => crate::qftls::Level::Handshake,
                                _ => crate::qftls::Level::Application,
                            };
                            self.process_crypto_frame(lvl, offset, data)?;
                            ack_eliciting = true;
                        }
                        Frame::Ping { .. } => {
                            ack_eliciting = true;
                        }
                        Frame::ResetStream { .. } => {
                            // Transport-level RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::StopSending { .. } => {
                            // Transport-level stop-sending treated as soft RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::PathResponse { data } => {
                            ack_eliciting = true;
                            self.handle_path_response_frame(info.to, info.from, data);
                        }
                        Frame::NewToken { .. }
                        | Frame::MaxStreamsBidi { .. }
                        | Frame::MaxStreamsUni { .. }
                        | Frame::DataBlocked { .. }
                        | Frame::StreamDataBlocked { .. }
                        | Frame::StreamsBlockedBidi { .. }
                        | Frame::StreamsBlockedUni { .. }
                        | Frame::NewConnectionId { .. }
                        | Frame::RetireConnectionId { .. } => {
                            ack_eliciting = true;
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        if ack_eliciting {
            let now = self.clock.now();
            self.pkt_spaces[space_idx]
                .note_ack_eliciting_at(
                    self.config.max_ack_delay,
                    self.config.ack_eliciting_threshold,
                    now,
                );
        }

        // Update ECN counters for ACK ECN section (per-datagram)
        if let Some(mark) = info.ecn {
            match mark {
                EcnMark::Ect0 => self.ecn_ect0 = self.ecn_ect0.saturating_add(1),
                EcnMark::Ect1 => self.ecn_ect1 = self.ecn_ect1.saturating_add(1),
                EcnMark::Ce => self.ecn_ce = self.ecn_ce.saturating_add(1),
            }
            if let Some(obs) = &self.observer {
                obs.on_ecn_update(self.ecn_ect0, self.ecn_ect1, self.ecn_ce);
            }
        }
        // Update connection state
        let len = end;
        self.stats.recv += 1;
        self.stats.recv_bytes += len as u64;
        self.last_activity = self.clock.now();
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        Ok(len)
    }

    #[inline(always)]
    fn refresh_short_header_tag_reserve(&mut self) {
        let has_seal = self.crypto.read().seal_1rtt.is_some();
        self.short_header_tag_reserve = if has_seal { 16 } else { 0 };
        // Sync the lock-free 1-RTT ArcSwap whenever we refresh the tag reserve.
        // This is called after all TLS key installations and key updates, ensuring
        // the ArcSwap mirrors the RwLock-protected CryptoContext.
        self.sync_1rtt();
    }

    /// Sync the lock-free `crypto_1rtt` ArcSwap from the RwLock-protected CryptoContext.
    ///
    /// Must be called after any `crypto.write()` that installs, rotates, or clears 1-RTT keys.
    /// In steady state (no key updates), the ArcSwap is never touched - the hot path loads
    /// it lock-free via `arc_swap::ArcSwapOption::load()`.
    fn sync_1rtt(&self) {
        let crypto = self.crypto.read();
        if let (Some(seal), Some(open), Some(hp_seal), Some(hp_open)) = (
            crypto.seal_1rtt.clone(),
            crypto.open_1rtt.clone(),
            crypto.hp_1rtt.clone(),
            crypto.hp_1rtt_open.clone(),
        ) {
            self.crypto_1rtt.store(Some(std::sync::Arc::new(packet::OneRttCrypto {
                seal,
                open,
                hp_seal,
                hp_open,
            })));
        } else {
            self.crypto_1rtt.store(None);
        }
    }

    #[inline(always)]
    fn tag_reserve_1rtt(&self) -> usize {
        self.short_header_tag_reserve as usize
    }

    /// Returns true if `frame` is ack-eliciting per RFC 9000 §19 / RFC 9002 §7.2.
    /// Ack-eliciting frames require the peer to send an ACK and are congestion-
    /// controlled. Non-ack-eliciting frames: PADDING, ACK, CONNECTION_CLOSE,
    /// APPLICATION_CLOSE. All other frame types are ack-eliciting.
    #[inline(always)]
    fn frame_is_ack_eliciting(frame: &Frame<'_>) -> bool {
        !matches!(
            frame,
            Frame::Padding { .. }
                | Frame::Ack { .. }
                | Frame::ConnectionClose { .. }
                | Frame::ApplicationClose { .. }
        )
    }

    /// Flushes pending control frames. Returns `(new_off, wrote_ack_eliciting)`
    /// where `wrote_ack_eliciting` is true if any ack-eliciting frame was
    /// emitted (e.g. PING, MAX_DATA, NEW_CONNECTION_ID). This is used by the
    /// caller to decide whether the packet is congestion-controlled.
    ///
    /// When `congestion_bypass` is true, the caller is emitting an ACK-only
    /// packet to bypass the congestion gate (RFC 9002 §7.2). In that mode only
    /// non-ack-eliciting control frames (CONNECTION_CLOSE / APPLICATION_CLOSE)
    /// may be emitted - emitting ack-eliciting frames would inflate
    /// bytes_in_flight beyond cwnd, violating RFC 9002 §7.2 ("A sender MUST
    /// NOT send a packet if it would cause bytes_in_flight to exceed the
    /// congestion window"). Ack-eliciting control frames are left in the queue
    /// and flushed on a later non-bypassed send.
    #[inline(always)]
    fn flush_pending_control_frames(
        &mut self,
        out: &mut [u8],
        mut off: usize,
        congestion_bypass: bool,
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        let mut wrote_ack_eliciting = false;
        while let Some(ctrl) = self.pending_control.front() {
            // When bypassing the congestion gate, skip ack-eliciting control
            // frames (PING, MAX_DATA, NEW_CONNECTION_ID, HANDSHAKE_DONE,
            // RESET_STREAM, STOP_SENDING, PATH_CHALLENGE, PATH_RESPONSE,
            // DATA_BLOCKED, STREAM_DATA_BLOCKED, …). They are left in the
            // queue and emitted on a later send that respects the cwnd.
            if congestion_bypass && Self::frame_is_ack_eliciting(ctrl) {
                break;
            }
            let need = frames::wire_len(ctrl)?;
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len().saturating_sub(off) >= need.saturating_add(tag_reserve) {
                let tail = out.get_mut(off..).ok_or(crate::error::ConnectionError::BufferTooShort)?;
                off += frames::to_bytes(ctrl, tail)?;
                if Self::frame_is_ack_eliciting(ctrl) {
                    wrote_ack_eliciting = true;
                }
                self.pending_control.pop_front();
            } else {
                break;
            }
        }
        Ok((off, wrote_ack_eliciting))
    }

    #[inline(always)]
    fn maybe_emit_application_ack_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if let Some((ack_delay, ack_ranges)) =
            self.pkt_spaces[2].take_ack_at(self.config.ack_delay_exponent, self.clock.now())
        {
            let ecn = if self.ecn_ect0 | self.ecn_ect1 | self.ecn_ce > 0 {
                Some(EcnCounts { ect0: self.ecn_ect0, ect1: self.ecn_ect1, ce: self.ecn_ce })
            } else {
                None
            };
            let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: ecn };
            let need = frames::wire_len(&ack)?;
            let tag_reserve = self.tag_reserve_1rtt();
            let mut ack_written = false;
            if out.len().saturating_sub(off) >= need.saturating_add(tag_reserve) {
                let tail = out.get_mut(off..).ok_or(crate::error::ConnectionError::BufferTooShort)?;
                off += frames::to_bytes(&ack, tail)?;
                ack_written = true;
            }
            if ack_written {
                if let Some(obs) = &self.observer {
                    if let Frame::Ack { ranges, .. } = &ack {
                        obs.on_ack(ack_delay, ranges);
                    }
                }

                let exp = self.config.ack_delay_exponent.min(20);
                let ack_delay_us = ack_delay << exp;
                crate::telemetry::ACK_DELAY_LAST_US
                    .store(ack_delay_us, std::sync::atomic::Ordering::Relaxed);
                if let Some(obs) = self.observer.as_ref().cloned() {
                    obs.apply_policy(self);
                }
            }
        }
        Ok(off)
    }

    /// Flushes one retransmitted or new STREAM range. Returns `(new_off,
    /// wrote_ack_eliciting, transmission emission)` - STREAM frames are always
    /// ack-eliciting when emitted (RFC 9000 §19.8).
    fn maximum_stream_payload(
        packet_len: usize,
        packet_offset: usize,
        tag_reserve: usize,
        stream_id: u64,
        stream_offset: u64,
        available: usize,
    ) -> usize {
        let mut lower = 0usize;
        let mut upper = available;
        while lower < upper {
            let candidate = lower + (upper - lower).div_ceil(2);
            let wire_len = frames::stream_frame_wire_len(stream_id, stream_offset, candidate);
            if packet_offset.saturating_add(wire_len).saturating_add(tag_reserve) <= packet_len {
                lower = candidate;
            } else {
                upper = candidate - 1;
            }
        }
        lower
    }

    #[inline(always)]
    fn maybe_flush_one_writable_stream(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<(usize, bool, Option<StreamTransmissionEmission>), crate::error::ConnectionError>
    {
        use crate::error::ConnectionError;

        while let Some(transmission_id) = self.stream_retransmit_queue.front().copied() {
            let Some(transmission) = self.stream_transmissions.get(&transmission_id) else {
                self.stream_retransmit_queue.pop_front();
                continue;
            };
            if !transmission.queued {
                self.stream_retransmit_queue.pop_front();
                continue;
            }

            let stream_id = transmission.stream_id;
            let stream_offset = transmission.offset;
            let data = Arc::clone(&transmission.data);
            let fin = transmission.fin;
            let need = frames::stream_frame_wire_len(stream_id, stream_offset, data.len());
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len() < off + need + tag_reserve {
                let prefix_len = Self::maximum_stream_payload(
                    out.len(),
                    off,
                    tag_reserve,
                    stream_id,
                    stream_offset,
                    data.len(),
                );
                if prefix_len == 0 || data.is_empty() {
                    return Ok((off, false, None));
                }
                self.split_queued_stream_transmission(transmission_id, prefix_len)?;
                continue;
            }
            off += frames::write_stream_frame(
                stream_id,
                stream_offset,
                data.as_ref(),
                fin,
                &mut out[off..],
            )?;
            return Ok((
                off,
                true,
                Some(StreamTransmissionEmission { id: transmission_id, retransmission: true }),
            ));
        }

        let ledger_bytes = self.stream_retransmit_bytes;
        let ledger_entries = self.stream_transmissions.len();
        let mut staged_transmission: Option<(u64, u64, Arc<[u8]>, bool)> = None;
        if let Some(stream_id) = self.writable_streams.front().copied() {
            let tag_reserve = self.tag_reserve_1rtt();
            if let Some(s) = self.streams.get_mut(&stream_id) {
                let available = {
                    #[cfg(not(feature = "stream_ring_buffer"))]
                    {
                        s.send_buf.len()
                    }
                    #[cfg(feature = "stream_ring_buffer")]
                    {
                        s.send_ring.len()
                    }
                };
                if available > 0 {
                    let header_overhead = frames::stream_frame_wire_len(stream_id, s.send_off, 0);
                    if off + header_overhead + tag_reserve <= out.len() {
                        let conn_avail =
                            self.peer_max_data.saturating_sub(self.conn_bytes_sent) as usize;
                        let stream_avail = s.max_stream_data_tx.saturating_sub(s.send_off) as usize;
                        let send_avail = conn_avail.min(stream_avail);
                        if send_avail == 0 {
                            Self::queue_control_frame(
                                &mut self.pending_control,
                                Frame::DataBlocked { limit: self.peer_max_data },
                            );
                            Self::queue_control_frame(
                                &mut self.pending_control,
                                Frame::StreamDataBlocked {
                                    stream_id,
                                    limit: s.max_stream_data_tx,
                                },
                            );
                            return Err(ConnectionError::Done);
                        }
                        let body_len = Self::maximum_stream_payload(
                            out.len(),
                            off,
                            tag_reserve,
                            stream_id,
                            s.send_off,
                            available.min(send_avail),
                        );
                        if body_len == 0 {
                            return Ok((off, false, None));
                        }
                        if ledger_entries >= MAX_STREAM_TRANSMISSIONS
                            || ledger_bytes.saturating_add(body_len) > MAX_STREAM_RETRANSMIT_BYTES
                        {
                            return Ok((off, false, None));
                        }
                        let stream_offset = s.send_off;
                        let fin_now = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_fin && body_len == available
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_fin && body_len == available
                            }
                        };
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        let data = {
                            let data = Arc::<[u8]>::from(&s.send_buf[..body_len]);
                            let written = frames::write_stream_frame(
                                s.id,
                                stream_offset,
                                data.as_ref(),
                                fin_now,
                                &mut out[off..],
                            )?;
                            off += written;
                            data
                        };
                        #[cfg(feature = "stream_ring_buffer")]
                        let data = {
                            let mut v = vec![0u8; body_len];
                            let read = s.send_ring.read(&mut v[..]);
                            if read < body_len {
                                v.truncate(read);
                            }
                            let data = Arc::<[u8]>::from(v);
                            let written = frames::write_stream_frame(
                                s.id,
                                stream_offset,
                                data.as_ref(),
                                fin_now,
                                &mut out[off..],
                            )?;
                            off += written;
                            data
                        };
                        let data_len = data.len();
                        s.send_off += data_len as u64;
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        {
                            if data_len == s.send_buf.len() {
                                s.send_buf.clear();
                            } else {
                                s.send_buf.drain(0..data_len);
                            }
                        }
                        self.conn_bytes_sent = self.conn_bytes_sent.saturating_add(data_len as u64);
                        self.stats.stream_sent_bytes += data_len as u64;
                        let emptied = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_buf.is_empty()
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_ring.is_empty()
                            }
                        };
                        if emptied && fin_now {
                            self.remove_front_writable_stream(stream_id);
                        }
                        staged_transmission = Some((stream_id, stream_offset, data, fin_now));
                    }
                } else if s.send_fin {
                    // Stream has no pending data but fin was requested: emit a
                    // fin-only STREAM frame so the peer learns the stream is
                    // half-closed. Without this, the fin flag would never reach
                    // the peer and the stream would stay open forever.
                    let header_overhead = 1
                        + crate::transport::varint::varint_len(stream_id)
                        + crate::transport::varint::varint_len(s.send_off)
                        + 2;
                    if off + header_overhead + tag_reserve < out.len() {
                        if ledger_entries >= MAX_STREAM_TRANSMISSIONS {
                            return Ok((off, false, None));
                        }
                        let stream_offset = s.send_off;
                        let written = frames::write_stream_frame(
                            s.id,
                            stream_offset,
                            &[],
                            true,
                            &mut out[off..],
                        )?;
                        off += written;
                        self.remove_front_writable_stream(stream_id);
                        staged_transmission = Some((stream_id, stream_offset, Arc::from([]), true));
                    }
                } else {
                    // Stream has no pending data and no fin: remove it from the
                    // writable queue so the next stream gets a turn. The stream
                    // is re-added to the queue when stream_send() is called again.
                    // Without this, an idle stream blocks all other streams
                    // forever because maybe_flush_one_writable_stream only looks
                    // at the front of the queue.
                    self.remove_front_writable_stream(stream_id);
                }
            }
        }
        if let Some((stream_id, stream_offset, data, fin)) = staged_transmission {
            let transmission_id =
                self.stage_stream_transmission(stream_id, stream_offset, data, fin)?;
            return Ok((
                off,
                true,
                Some(StreamTransmissionEmission { id: transmission_id, retransmission: false }),
            ));
        }
        Ok((off, false, None))
    }

    #[inline(always)]
    fn pending_datagram_frame_reserve(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        let payload_len = self.dgram_send_queue.front()?.len();
        #[cfg(feature = "zero_copy_dgram")]
        let payload_len = self.dgram_send_queue.front()?.len;
        Some(1 + 2 + payload_len)
    }

    /// Flushes one DATAGRAM frame. Returns `(new_off, wrote_ack_eliciting)`.
    /// DATAGRAM frames are ack-eliciting per RFC 9221 §2.
    #[inline(always)]
    fn maybe_flush_one_datagram_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        if let Some(need) = self.pending_datagram_frame_reserve() {
            let tag_reserve = self.tag_reserve_1rtt();
            log::trace!("maybe_flush_one_datagram_frame: off={} need={} tag_reserve={} out_len={} queue_len={}",
                off, need, tag_reserve, out.len(), self.dgram_send_queue.len());
            if off + need + tag_reserve <= out.len() {
                #[cfg(not(feature = "zero_copy_dgram"))]
                {
                    let Some(front_owned) = self.dgram_send_queue.pop_front() else {
                        return Err(crate::error::ConnectionError::Done);
                    };
                    let frame = Frame::Datagram { data: Cow::Owned(front_owned) };
                    log::trace!("maybe_flush_one_datagram_frame: attempting to write frame, frame_wire_len={:?}", frames::wire_len(&frame));
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            log::trace!("maybe_flush_one_datagram_frame: wrote {} bytes", written);
                            off += written;
                            // DATAGRAM frames are ack-eliciting (RFC 9221 §2).
                            return Ok((off, true));
                        }
                        Err(e) => {
                            log::trace!("maybe_flush_one_datagram_frame: to_bytes failed: {:?}", e);
                            if let Frame::Datagram { data } = frame {
                                self.dgram_send_queue.push_front(data.into_owned());
                            }
                            return Err(e);
                        }
                    }
                }
                #[cfg(feature = "zero_copy_dgram")]
                {
                    let Some(front) = self.dgram_send_queue.pop_front() else {
                        return Err(crate::error::ConnectionError::Done);
                    };
                    let frame =
                        Frame::Datagram { data: Cow::Owned(front.data[..front.len].to_vec()) };
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            off += written;
                            return Ok((off, true));
                        }
                        Err(error) => {
                            self.dgram_send_queue.push_front(front);
                            return Err(error);
                        }
                    }
                }
            }
        }
        Ok((off, false))
    }

    #[inline(always)]
    fn maybe_apply_stealth_padding(
        &mut self,
        out: &mut [u8],
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        // --- Traffic analysis defense modes (TODO-455) ---
        //
        // FullPadding / ConstantRate take precedence over the legacy
        // probabilistic padding path. They pad EVERY 1-RTT packet to a fixed
        // target size regardless of `stealth_padding_rate`, eliminating
        // size-based traffic analysis.
        let defense = self.config.traffic_analysis_defense;
        if matches!(defense, TrafficAnalysisDefense::FullPadding)
            || matches!(defense, TrafficAnalysisDefense::ConstantRate)
        {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);
            // Target total packet size. FullPadding uses max_udp_payload_size;
            // ConstantRate uses the chaff size (consistent across real + chaff).
            let target_total = match defense {
                TrafficAnalysisDefense::FullPadding => self.config.max_udp_payload_size as usize,
                TrafficAnalysisDefense::ConstantRate => self.config.chaff_size_bytes as usize,
                _ => 0,
            };
            if target_total > 0 && target_total > off + tag_reserve {
                let needed = target_total - off - tag_reserve;
                let pad_len = needed.min(avail);
                if pad_len > 0 {
                    off += frames::write_padding(pad_len, &mut out[off..])?;
                }
            }
            return Ok(off);
        }

        if self.config.stealth_padding_enabled {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);

            // Strategy 5 = PacketNormalize: pad all 1-RTT packets to a fixed total size.
            // target covers header + payload + tag; compute payload padding needed.
            if self.config.stealth_padding_strategy == 5 {
                let target = self.config.stealth_normalize_target_size;
                if target > 0 && target > off + tag_reserve {
                    let needed = target - off - tag_reserve;
                    let pad_len = needed.min(avail);
                    if pad_len > 0 {
                        off += frames::write_padding(pad_len, &mut out[off..])?;
                    }
                }
                return Ok(off);
            }

            let ad_len = pn_off + pn_len;
            let pt_len_now = off.saturating_sub(ad_len);
            if avail > 0 {
                let pad_len = self.compute_stealth_padding(pt_len_now, avail);
                if pad_len > 0 {
                    let written = frames::write_padding(pad_len, &mut out[off..])?;
                    off += written;
                }
            }
        }
        Ok(off)
    }

    /// Queues a cover PING frame to be emitted in the next outgoing 1-RTT packet.
    ///
    /// The PING is ack-eliciting: the peer sends an ACK, generating symmetric traffic
    /// that matches idle HTTP/3 keepalive patterns observed in real browser sessions.
    pub(crate) fn queue_cover_ping(&mut self) {
        if self.is_established() {
            Self::queue_control_frame(
                &mut self.pending_control,
                Frame::Ping { mtu_probe: None },
            );
        }
    }

    #[inline(always)]
    fn seal_short_header_packet(
        &mut self,
        out: &mut [u8],
        pn: u64,
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if !(1..=packet::MAX_PKT_NUM_LEN).contains(&pn_len) || pn_off == 0 {
            return Err(crate::error::ConnectionError::InvalidPacket);
        }
        let pn_end = pn_off
            .checked_add(pn_len)
            .ok_or(crate::error::ConnectionError::InvalidPacket)?;
        if pn_end > out.len() || off < pn_end || off > out.len() {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let sample_end = pn_off
            .checked_add(packet::MAX_PKT_NUM_LEN)
            .and_then(|offset| offset.checked_add(packet::SAMPLE_LEN))
            .ok_or(crate::error::ConnectionError::InvalidPacket)?;
        if sample_end > out.len() {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let minimum_plaintext_end = sample_end.saturating_sub(self.tag_reserve_1rtt());
        if off < minimum_plaintext_end {
            let padding_len = minimum_plaintext_end - off;
            let padding_end = off
                .checked_add(padding_len)
                .ok_or(crate::error::ConnectionError::BufferTooShort)?;
            if padding_end > out.len() {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            off += frames::write_padding(padding_len, &mut out[off..])?;
        }

        // Set PN length bits in the first byte BEFORE sealing so the AAD
        // matches what the peer sees after HP removal. Without this, the
        // first byte used for AEAD sealing is 0x40 (from format_short_header,
        // which doesn't set PN length bits), but the peer reconstructs it as
        // 0x40 | (pn_len-1) after HP removal. For 1-byte PN this happens to
        // match (0x40), but for 2+ byte PN the AAD differs and decryption fails.
        out[0] = 0x40 | (((pn_len as u8) - 1) & 0x03);
        if self.key_phase {
            out[0] |= packet::KEY_PHASE_BIT;
        }

        // Hot path: try lock-free 1-RTT ArcSwap first.
        let one_rtt = self.crypto_1rtt.load();
        if let Some(keys) = one_rtt.as_ref() {
            // 1-RTT steady state - no lock acquisition.
            let ad_len = pn_off + pn_len;
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let mut item = crate::crypto::aead::AeadSealItem {
                counter: pn,
                ad: ad_slice,
                buf: rest,
                plaintext_len: pt_len,
            };
            keys.seal.seal_batch(core::slice::from_mut(&mut item))?;
            let sealed_len = pt_len + 16;
            off = ad_len + sealed_len;
            let sample_offset = sample_end - packet::SAMPLE_LEN;
            let mask = keys
                .hp_seal
                .new_mask(&out[sample_offset..sample_end])?;
            out[0] ^= mask[0] & 0x1f;
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
            self.advance_send_packet_number(2)?;
            return Ok(off);
        }

        // Fallback: 0-RTT or handshake - use RwLock.
        let use_1rtt_seal = {
            let crypto_guard = self.crypto.read();
            crypto_guard.seal_1rtt.is_some()
        };
        let sealed_len = {
            let crypto_guard = self.crypto.read();
            let ad_len = pn_off + pn_len;
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let mut item = crate::crypto::aead::AeadSealItem {
                counter: pn,
                ad: ad_slice,
                buf: rest,
                plaintext_len: pt_len,
            };
            packet::seal_data_aead_batch(&crypto_guard, core::slice::from_mut(&mut item))?;
            pt_len + 16
        };
        let ad_len = pn_off + pn_len;
        off = ad_len + sealed_len;
        let mask = {
            let crypto_guard = self.crypto.read();
            let hp = if use_1rtt_seal {
                crypto_guard.hp_1rtt.as_deref()
            } else {
                crypto_guard.hp_0rtt.as_deref().or(crypto_guard.hp_1rtt.as_deref())
            };
            hp.map(|hp| {
                let sample_offset = sample_end - packet::SAMPLE_LEN;
                hp.new_mask(&out[sample_offset..sample_end])
            })
            .transpose()?
        };
        if let Some(mask) = mask {
            out[0] ^= mask[0] & 0x1f;
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
        }
        self.advance_send_packet_number(2)?;
        Ok(off)
    }

    #[inline(always)]
    fn send_targeted_short_header_frame(
        &mut self,
        out: &mut [u8],
        send_local: SocketAddr,
        send_peer: SocketAddr,
        frame: &Frame<'_>,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        // Build short header prefix with DCID directly - avoids two Vec
        // allocations (dcid.to_vec() + scid.to_vec()) per outbound packet.
        let pn = self.next_send_packet_number(2)?;
        let hdr_len = packet::format_short_header(self.dcid.as_ref(), false, out)?;
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        if out.len() < hdr_len + pn_len {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        let pn_off = 1 + self.dcid.as_ref().len();
        let mut tmp = [0u8; 4];
        packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
        out[pn_off..pn_off + pn_len].copy_from_slice(&tmp[..pn_len]);

        let mut off = pn_off + pn_len;
        let need = frames::wire_len(frame)?;
        let tag_reserve = self.tag_reserve_1rtt();
        if out.len().saturating_sub(off) < need.saturating_add(tag_reserve) {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let tail = out.get_mut(off..).ok_or(crate::error::ConnectionError::BufferTooShort)?;
        off += frames::to_bytes(frame, tail)?;
        off = self.seal_short_header_packet(out, pn, pn_off, pn_len, off)?;

        let now = self.clock.now();
        let info = SendInfo {
            from: send_local,
            to: send_peer,
            at: now,
            congestion_controlled: true,
            path_control: true,
        };
        self.mark_unvalidated_path_send(send_local, send_peer, off);
        self.stats.sent += 1;
        self.stats.sent_bytes += off as u64;
        self.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::Application,
            pn,
            off,
            true,
            true,
            None,
            now,
        );
        self.cwnd = self.recovery.cwnd;
        self.refresh_path_count();
        Ok((off, info))
    }
}
