use super::state::{AdmittedShortHeader, StagedApplicationAck, StagedControls, StagedStreamFrame};
use super::*;
use crate::transport::DatagramClass;

impl Connection {
    pub(super) fn enqueue_peer_stream_reset(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.reset_stream_ids.contains(&stream_id) {
            return Ok(());
        }
        if self.reset_streams.len() >= MAX_PENDING_STREAM_RESETS {
            return Err(crate::error::ConnectionError::ProtocolViolation);
        }
        self.reset_stream_ids.insert(stream_id);
        self.reset_streams.push_back((stream_id, error_code));
        Ok(())
    }

    /// Validates the complete decrypted frame payload before receive-side state is mutated.
    #[inline(always)]
    pub(super) fn preflight_frame_payload(
        payload: &[u8],
        pkt_ty: PacketType,
    ) -> Result<(), crate::error::ConnectionError> {
        if payload.is_empty() {
            return Err(crate::error::ConnectionError::InvalidFrame);
        }

        let mut off = 0usize;
        while off < payload.len() {
            prefetch_frame_parse_window(payload, off);
            let (frame, used) = frames::from_bytes(&payload[off..], pkt_ty)?;
            if pkt_ty == PacketType::ZeroRTT {
                if let Frame::Stream { stream_id, .. } = &frame {
                    if *stream_id & 0x3 != 0 {
                        return Err(crate::error::ConnectionError::InvalidFrame);
                    }
                }
            }
            if used == 0 {
                return Err(crate::error::ConnectionError::InvalidFrame);
            }
            off = off.checked_add(used).ok_or(crate::error::ConnectionError::InvalidFrame)?;
        }
        if off != payload.len() {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        Ok(())
    }

    /// Bytes of `[start, end)` this stream has not already received.
    ///
    /// The already-received set is the contiguous delivered prefix `[0, recv_next)` plus every
    /// buffered out-of-order fragment. QUIC flow-control credit represents new data, so a
    /// duplicate or partially overlapping retransmission must contribute exactly the bytes it
    /// newly covers and nothing more.
    pub(super) fn newly_covered_bytes(
        recv_next: u64,
        fragments: &std::collections::BTreeMap<u64, Vec<u8>>,
        start: u64,
        end: u64,
    ) -> u64 {
        if end <= start {
            return 0;
        }
        // Everything below `recv_next` was already delivered.
        let mut cursor = start.max(recv_next);
        if cursor >= end {
            return 0;
        }

        let mut new_bytes = 0u64;
        // Fragments are keyed by start offset, so ascending iteration walks the covered ranges in
        // order. Only fragments beginning before `end` can overlap the incoming range.
        for (&fragment_start, fragment) in fragments.range(..end) {
            let fragment_end = fragment_start.saturating_add(fragment.len() as u64);
            if fragment_end <= cursor {
                continue;
            }
            if fragment_start > cursor {
                // The gap between the cursor and this fragment is genuinely new.
                new_bytes = new_bytes.saturating_add(fragment_start - cursor);
            }
            cursor = cursor.max(fragment_end);
            if cursor >= end {
                return new_bytes;
            }
        }
        new_bytes.saturating_add(end - cursor)
    }

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
                Err(_) => {
                    // A truncated Retry cannot pass header parsing, but RFC 9000
                    // still requires discarding it without changing the connection.
                    if buf.len() >= 5 && buf[0] & packet::FORM_BIT != 0 {
                        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
                        if matches!(
                            crate::transport::version::packet_type_from_long_header(
                                version,
                                buf[0] & packet::TYPE_MASK,
                            ),
                            Ok(PacketType::Retry)
                        ) {
                            return Ok(buf.len());
                        }
                    }
                    (PacketType::Short, 0, None)
                }
            };

        if pre_ty == PacketType::VersionNegotiation {
            let Some((header, _)) = pre_parsed_hdr.as_ref() else {
                return Ok(buf.len());
            };
            return self.handle_version_negotiation_packet(header, buf.len());
        }

        // Retry verification (no payload decrypt)
        if let PacketType::Retry = pre_ty {
            let Some((retry_hdr, _)) = pre_parsed_hdr.take() else {
                return Ok(buf.len());
            };
            if self.is_server
                || self.received_non_vn_packet
                || retry_hdr.version != self.version_negotiation.chosen
                || retry_hdr.dcid != self.scid.as_ref()
                || retry_hdr.scid == self.initial_dcid.as_ref()
                || retry_hdr.token.as_ref().is_none_or(Vec::is_empty)
            {
                return Ok(buf.len());
            }
            let odcid = if !self.initial_dcid.is_empty() {
                self.initial_dcid.as_ref()
            } else {
                self.dcid.as_ref()
            };
            if packet::verify_retry_tag(buf, odcid, self.config.version).is_err() {
                return Ok(buf.len());
            }

            // Client-side Retry handling: adopt token/DCID and re-derive Initial keys.
            let (client_secret, server_secret) =
                packet::derive_initial_secrets(&retry_hdr.scid, self.config.version)?;
            let (read_secret, write_secret) = (server_secret.as_slice(), client_secret.as_slice());
            let mut crypto = self.crypto.write();
            crypto.install_aes_gcm_initial(read_secret, write_secret, self.config.version)?;
            crypto.install_hp_initial(read_secret, write_secret, self.config.version)?;
            drop(crypto);
            self.finish_zero_rtt(false);
            self.recovery.reset_for_retry(
                Duration::from_millis(self.config.initial_rtt_ms),
                self.clock.now(),
            );
            self.bytes_in_flight = self.recovery.bytes_in_flight;
            self.bytes_in_flight_started = None;
            self.cwnd = self.recovery.cwnd;
            self.rtt = self.recovery.rtt;
            self.timeout_count = 0;
            self.pending_probe_spaces.clear();
            self.pmtu_probe_pn = None;
            self.pmtu_above_floor_pns.clear();
            self.stream_transmission_by_pn.clear();
            self.lost_stream_transmission_by_pn.clear();
            self.set_destination_cid(ConnectionId::from_ref(&retry_hdr.scid));
            self.config.initial_token = retry_hdr.token;
            self.refresh_short_header_tag_reserve();
            self.requeue_all_crypto(recovery::PacketSpace::Initial);
            // For Retry we do not parse further.
            self.retry_accepted = true;
            self.retry_source_cid = Some(ConnectionId::from_ref(&retry_hdr.scid));
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
        let space_idx = match pkt_ty {
            PacketType::Initial => 0,
            PacketType::Handshake => 1,
            _ => 2,
        };
        let end = aad_len.saturating_add(pt_len).min(buf.len());
        if aad_len > end {
            return Err(ConnectionError::BufferTooShort);
        }
        if aad_len == end {
            return Err(ConnectionError::InvalidFrame);
        }

        // Preflight every frame before changing packet-number, connection, or stream state.
        // A malformed, truncated, or packet-space-invalid frame must not turn into a successful
        // receive merely because an earlier frame in the same payload was valid.
        Self::preflight_frame_payload(&buf[aad_len..end], pkt_ty)?;
        if pkt_ty == PacketType::Initial
            && self
                .peer_initial_scid
                .is_some_and(|first_scid| first_scid.as_ref() != hdr_native.scid)
        {
            return Ok(end);
        }

        if pkt_ty == PacketType::Short {
            let committed = self
                .crypto
                .write()
                .commit_private_read_epoch(hdr_native.pkt_num, hdr_native.key_phase)?;
            if committed {
                self.sync_1rtt();
            }
        }

        // Duplicate PN detection: if already observed, count and return after the frame contract
        // has been validated so malformed input cannot take the successful receive path.
        if hdr_native.pkt_num_len > 0 && self.pkt_spaces[space_idx].contains(hdr_native.pkt_num) {
            let len = aad_len.saturating_add(pt_len).min(buf.len());
            self.stats.recv += 1;
            self.stats.recv_bytes += len as u64;
            return Ok(len);
        }

        let zero_rtt_plaintext_bytes = if pkt_ty == PacketType::ZeroRTT {
            let Some(strike_register) = self.strike_register.as_ref().filter(|_| self.is_server)
            else {
                crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_POLICY_REJECT_TOTAL.inc());
                self.stats.recv += 1;
                self.stats.recv_bytes += end as u64;
                return Ok(end);
            };
            let plaintext_bytes = u64::try_from(pt_len).unwrap_or(u64::MAX);
            if self.zero_rtt_received_bytes.saturating_add(plaintext_bytes)
                > u64::from(strike_register.max_early_data_size())
            {
                crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_POLICY_REJECT_TOTAL.inc());
                self.stats.recv += 1;
                self.stats.recv_bytes += end as u64;
                return Ok(end);
            }
            let fingerprint = super::anti_replay::StrikeRegister::compute_fingerprint(
                &hdr_native.dcid,
                &hdr_native.scid,
                &buf[aad_len..end],
            );
            if !strike_register.check_and_insert(&fingerprint, self.clock.now()) {
                crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_REPLAY_REJECT_TOTAL.inc());
                log::warn!("0-RTT replay-register rejection");
                self.stats.recv += 1;
                self.stats.recv_bytes += end as u64;
                return Ok(end);
            }
            Some(plaintext_bytes)
        } else {
            None
        };

        if hdr_native.pkt_num_len > 0
            && !self.pkt_spaces[space_idx].on_packet_recv(hdr_native.pkt_num)
        {
            // Duplicate or overflow PN - silently discard per RFC 9000 Section 12.3
            self.stats.recv += 1;
            self.stats.recv_bytes += end as u64;
            return Ok(end);
        }

        if let Some(plaintext_bytes) = zero_rtt_plaintext_bytes {
            self.zero_rtt_received_bytes =
                self.zero_rtt_received_bytes.saturating_add(plaintext_bytes);
            crate::telemetry!(crate::optimize::telemetry::ZERO_RTT_ACCEPT_TOTAL.inc());
        }

        self.received_non_vn_packet = true;

        // A valid 1-RTT packet proves the peer can speak Application keys.
        // Initial keys may be dropped immediately. Handshake keys stay on the
        // client until a Handshake ACK confirms Finished; see on_peer_one_rtt_packet.
        if pkt_ty == PacketType::Short {
            self.on_peer_one_rtt_packet();
        }

        // The first authenticated Initial sets the peer CID even after Retry.
        // Subsequent Initials are bound to that first value above.
        if pkt_ty == PacketType::Initial && self.peer_initial_scid.is_none() {
            let peer_scid = ConnectionId::from_ref(&hdr_native.scid);
            self.peer_initial_scid = Some(peer_scid);
            self.set_destination_cid(peer_scid);
            if self.is_server && self.initial_dcid.is_empty() && !hdr_native.dcid.is_empty() {
                self.initial_dcid = ConnectionId::from_ref(&hdr_native.dcid);
            }
        }
        // Observer hook: notify after header processed and payload length known.
        if let Some(obs) = &self.observer {
            obs.on_packet_recv(hdr_native.pkt_num, pt_len);
        }

        // Parse frames from decrypted payload region
        let mut off = aad_len;
        self.observe_incoming_path(info.to, info.from, end);
        let mut ack_eliciting = false;
        while off < end {
            // Prefetch the next frame parse window for the recv hotpath.
            prefetch_frame_parse_window(&buf[..end], off);
            match frames::from_bytes(&buf[off..end], pkt_ty) {
                Ok((frame, used)) => {
                    if used == 0 {
                        return Err(ConnectionError::InvalidFrame);
                    }
                    off = off.checked_add(used).ok_or(ConnectionError::InvalidFrame)?;
                    match frame {
                        Frame::Stream { stream_id, offset, data, fin } => {
                            ack_eliciting = true;
                            if pkt_ty == PacketType::ZeroRTT {
                                self.record_zero_rtt_stream(stream_id);
                            }
                            if self.readable_stream_ids.insert(stream_id) {
                                self.readable_streams.push_back(stream_id);
                            }
                            // Flow-control tracking
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
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
                            // Flow-control credit represents newly received data. Counting the
                            // whole payload here let a reordered or retransmitted range consume
                            // credit again for bytes the stream already holds, which could
                            // exhaust the connection window and trip MAX_DATA without a single
                            // new byte being delivered.
                            let newly_covered =
                                Self::newly_covered_bytes(s.recv_next, &s.recv_frags, offset, end);
                            // Track highest received offset for flow control accounting.
                            s.recv_off = s.recv_off.max(end);
                            self.stats.stream_recv_bytes += newly_covered;
                            self.conn_bytes_recvd =
                                self.conn_bytes_recvd.saturating_add(newly_covered);

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
                            // (RFC 9000 sec. 19.3: ack_delay is in microseconds = value << exponent)
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
                                PacketType::Initial => {
                                    qf_transport_types::QuicEncryptionLevel::Initial
                                }
                                PacketType::Handshake => {
                                    qf_transport_types::QuicEncryptionLevel::Handshake
                                }
                                _ => qf_transport_types::QuicEncryptionLevel::Application,
                            };
                            self.process_crypto_frame(lvl, offset, data)?;
                            ack_eliciting = true;
                        }
                        Frame::Ping { .. } => {
                            ack_eliciting = true;
                        }
                        Frame::HandshakeDone => {
                            if self.is_server {
                                return Err(crate::error::ConnectionError::ProtocolViolation);
                            }
                            self.confirm_client_handshake();
                            ack_eliciting = true;
                        }
                        Frame::ResetStream { stream_id, error_code, .. } => {
                            self.enqueue_peer_stream_reset(stream_id, error_code)?;
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
                Err(error) => return Err(error),
            }
        }
        if ack_eliciting {
            let now = self.clock.now();
            self.pkt_spaces[space_idx].note_ack_eliciting_at(
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
    pub(super) fn refresh_short_header_tag_reserve(&mut self) {
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
    pub(super) fn sync_1rtt(&self) {
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
                private_seal: crypto.private_seal_1rtt.clone(),
                private_open: crypto.private_open_1rtt.clone(),
                private_next_open: crypto.private_next_open_1rtt.clone(),
                private_previous_read: crypto.private_previous_read_1rtt.iter().cloned().collect(),
                private_write_boundary: crypto.private_write_boundary_1rtt,
                private_read_boundary: crypto.private_read_boundary_1rtt,
                private_read_start: crypto.private_read_start_1rtt,
                private_read_key_phase: crypto.private_read_key_phase_1rtt,
                private_read_update_pending: crypto.private_read_update_pending_1rtt,
            })));
        } else {
            self.crypto_1rtt.store(None);
        }
    }

    #[inline(always)]
    pub(super) fn tag_reserve_1rtt(&self) -> usize {
        self.short_header_tag_reserve as usize
    }

    /// Returns true if `frame` is ack-eliciting per RFC 9000 sec. 19 / RFC 9002 sec. 7.2.
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

    /// Serialize eligible controls without consuming the queue. A terminal close is first on
    /// wire even when earlier ack-eliciting controls are blocked by congestion bypass.
    /// Queue removal occurs only after the sealed packet is accepted.
    pub(super) fn stage_pending_control_frames(
        &self,
        out: &mut [u8],
        mut off: usize,
        congestion_bypass: bool,
        already_staged: &[usize],
    ) -> Result<StagedControls, crate::error::ConnectionError> {
        // A close is serialized first without rearranging the queue. Queue mutation waits for seal.
        let close_index = self.pending_control.iter().enumerate().find_map(|(index, frame)| {
            (already_staged.binary_search(&index).is_err()
                && matches!(frame, Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. }))
            .then_some(index)
        });
        let mut indices = Vec::new();
        let mut ack_eliciting = false;
        let mut terminal_close = false;
        for index in close_index.into_iter().chain(0..self.pending_control.len()) {
            if already_staged.binary_search(&index).is_ok()
                || (close_index == Some(index) && terminal_close)
            {
                continue;
            }
            let ctrl = &self.pending_control[index];
            if congestion_bypass && Self::frame_is_ack_eliciting(ctrl) {
                break;
            }
            let need = frames::wire_len(ctrl)?;
            if out.len().saturating_sub(off) < need.saturating_add(self.tag_reserve_1rtt()) {
                break;
            }
            let tail = out.get_mut(off..).ok_or(crate::error::ConnectionError::BufferTooShort)?;
            off += frames::to_bytes(ctrl, tail)?;
            ack_eliciting |= Self::frame_is_ack_eliciting(ctrl);
            terminal_close |=
                matches!(ctrl, Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. });
            indices.push(index);
        }
        Ok(StagedControls { end: off, indices, ack_eliciting, terminal_close })
    }

    #[inline(always)]
    pub(super) fn maybe_stage_application_ack_frame(
        &self,
        out: &mut [u8],
        mut off: usize,
        already_staged: bool,
    ) -> Result<(usize, Option<StagedApplicationAck>), crate::error::ConnectionError> {
        if already_staged {
            return Ok((off, None));
        }
        let now = self.clock.now();
        if let Some((ack_delay, ack_ranges)) =
            self.pkt_spaces[2].peek_ack_at(self.config.ack_delay_exponent, now)
        {
            let ecn = if self.ecn_ect0 | self.ecn_ect1 | self.ecn_ce > 0 {
                Some(EcnCounts { ect0: self.ecn_ect0, ect1: self.ecn_ect1, ce: self.ecn_ce })
            } else {
                None
            };
            let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: ecn };
            let need = frames::wire_len(&ack)?;
            let tag_reserve = self.tag_reserve_1rtt();
            if out.len().saturating_sub(off) >= need.saturating_add(tag_reserve) {
                let tail =
                    out.get_mut(off..).ok_or(crate::error::ConnectionError::BufferTooShort)?;
                off += frames::to_bytes(&ack, tail)?;
                let Frame::Ack { ranges, .. } = ack else {
                    return Err(crate::error::ConnectionError::InvalidState);
                };
                return Ok((off, Some(StagedApplicationAck { delay: ack_delay, ranges, at: now })));
            }
        }
        Ok((off, None))
    }

    pub(super) fn commit_staged_application_ack(&mut self, staged: &StagedApplicationAck) {
        self.pkt_spaces[2].commit_ack_at(staged.at);
        if let Some(observer) = &self.observer {
            observer.on_ack(staged.delay, &staged.ranges);
        }
        let exponent = self.config.ack_delay_exponent.min(20);
        crate::telemetry::ACK_DELAY_LAST_US
            .store(staged.delay << exponent, std::sync::atomic::Ordering::Relaxed);
        if let Some(observer) = self.observer.take() {
            observer.apply_policy(self);
            self.observer = Some(observer);
        }
    }

    /// Largest STREAM body that fits the remaining packet and AEAD tag budget.
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

    /// Frame one STREAM range without moving bytes, FIN, queue entries or send credit.
    /// Earlier members of an open admitted run form the speculative cursor.
    pub(super) fn stage_next_stream_frame(
        &mut self,
        out: &mut [u8],
        off: usize,
        early_data_only: bool,
    ) -> Result<(usize, Option<StagedStreamFrame>), crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let tag_reserve =
            if early_data_only { packet::AEAD_TAG_LEN } else { self.tag_reserve_1rtt() };
        for &source_id in &self.stream_retransmit_queue {
            let Some(source) = self.stream_transmissions.get(&source_id) else {
                continue;
            };
            if !source.queued || (early_data_only && !source.early_data) {
                continue;
            }
            let start: usize = self
                .admitted_batch_frames
                .iter()
                .filter_map(|frame| match &frame.staged_stream {
                    Some(StagedStreamFrame::Retained { source_id: id, len, .. })
                        if *id == source_id =>
                    {
                        Some(*len)
                    }
                    _ => None,
                })
                .sum();
            if start >= source.data.len()
                && (start > 0 || !source.fin || self.admitted_batch_frames.iter().any(|frame| {
                    matches!(&frame.staged_stream, Some(StagedStreamFrame::Retained { source_id: id, .. }) if *id == source_id)
                }))
            {
                continue;
            }
            let data = &source.data[start..];
            let offset = source.offset.saturating_add(start as u64);
            let len = Self::maximum_stream_payload(
                out.len(),
                off,
                tag_reserve,
                source.stream_id,
                offset,
                data.len(),
            );
            if (len == 0 && !data.is_empty())
                || out.len().saturating_sub(off)
                    < frames::stream_frame_wire_len(source.stream_id, offset, len)
                        .saturating_add(tag_reserve)
            {
                return Ok((off, None));
            }
            let staged_splits = self
                .admitted_batch_frames
                .iter()
                .filter(|frame| match &frame.staged_stream {
                    Some(StagedStreamFrame::Retained { source_id, start, len, .. }) => self
                        .stream_transmissions
                        .get(source_id)
                        .is_some_and(|original| start + len < original.data.len()),
                    _ => false,
                })
                .count();
            if len < data.len()
                && self.stream_transmissions.len().saturating_add(staged_splits)
                    >= MAX_STREAM_TRANSMISSIONS
            {
                return Ok((off, None));
            }
            let fin = source.fin && start + len == source.data.len();
            let written = frames::write_stream_frame(
                source.stream_id,
                offset,
                &data[..len],
                fin,
                &mut out[off..],
            )?;
            return Ok((
                off + written,
                Some(StagedStreamFrame::Retained { source_id, start, len, offset, fin }),
            ));
        }

        let staged_fresh_bytes: usize = self
            .admitted_batch_frames
            .iter()
            .filter_map(|frame| match &frame.staged_stream {
                Some(StagedStreamFrame::Fresh { data, .. }) => Some(data.len()),
                _ => None,
            })
            .sum();
        let staged_entries = self
            .admitted_batch_frames
            .iter()
            .filter(|frame| match &frame.staged_stream {
                Some(StagedStreamFrame::Fresh { .. }) => true,
                Some(StagedStreamFrame::Retained { source_id, start, len, .. }) => self
                    .stream_transmissions
                    .get(source_id)
                    .is_some_and(|original| start + len < original.data.len()),
                None => false,
            })
            .count();
        for &stream_id in &self.writable_streams {
            if early_data_only && !self.zero_rtt_streams.contains(&stream_id) {
                continue;
            }
            let Some(stream) = self.streams.get(&stream_id) else {
                continue;
            };
            let consumed: usize = self
                .admitted_batch_frames
                .iter()
                .filter_map(|frame| match &frame.staged_stream {
                    Some(StagedStreamFrame::Fresh { stream_id: id, data, .. })
                        if *id == stream_id =>
                    {
                        Some(data.len())
                    }
                    _ => None,
                })
                .sum();
            let fin_staged = self.admitted_batch_frames.iter().any(|frame| {
                matches!(&frame.staged_stream, Some(StagedStreamFrame::Fresh { stream_id: id, fin: true, .. }) if *id == stream_id)
            });
            #[cfg(not(feature = "stream_ring_buffer"))]
            let available = stream.send_buf.len().saturating_sub(consumed);
            #[cfg(feature = "stream_ring_buffer")]
            let available = stream.send_ring.len().saturating_sub(consumed);
            if available == 0 && (!stream.send_fin || fin_staged) {
                continue;
            }
            if self.stream_transmissions.len().saturating_add(staged_entries)
                >= MAX_STREAM_ORIGINAL_TRANSMISSIONS
            {
                return Ok((off, None));
            }
            let offset = stream.send_off.saturating_add(consumed as u64);
            let early_data = self.zero_rtt_streams.contains(&stream_id);
            let body_len = if available == 0 {
                0
            } else {
                let conn_avail = self
                    .peer_max_data
                    .saturating_sub(self.conn_bytes_sent.saturating_add(staged_fresh_bytes as u64))
                    as usize;
                let stream_avail = stream.max_stream_data_tx.saturating_sub(offset) as usize;
                let send_avail = conn_avail.min(stream_avail);
                if send_avail == 0 {
                    Self::queue_control_frame(
                        &mut self.pending_control,
                        Frame::DataBlocked { limit: self.peer_max_data },
                    );
                    Self::queue_control_frame(
                        &mut self.pending_control,
                        Frame::StreamDataBlocked { stream_id, limit: stream.max_stream_data_tx },
                    );
                    return Err(ConnectionError::Done);
                }
                Self::maximum_stream_payload(
                    out.len(),
                    off,
                    tag_reserve,
                    stream_id,
                    offset,
                    available.min(send_avail),
                )
            };
            if available > 0 && body_len == 0 {
                return Ok((off, None));
            }
            if self
                .stream_retransmit_bytes
                .saturating_add(staged_fresh_bytes)
                .saturating_add(body_len)
                > MAX_STREAM_RETRANSMIT_BYTES
            {
                return Ok((off, None));
            }
            if out.len().saturating_sub(off)
                < frames::stream_frame_wire_len(stream_id, offset, body_len)
                    .saturating_add(tag_reserve)
            {
                return Ok((off, None));
            }
            let fin = stream.send_fin && body_len == available && !fin_staged;
            #[cfg(not(feature = "stream_ring_buffer"))]
            let data = Arc::<[u8]>::from(&stream.send_buf[consumed..consumed + body_len]);
            #[cfg(feature = "stream_ring_buffer")]
            let data = {
                if self.stream_tx_scratch.len() < body_len {
                    self.stream_tx_scratch.resize(body_len, 0);
                }
                let read =
                    stream.send_ring.peek_from(consumed, &mut self.stream_tx_scratch[..body_len]);
                Arc::<[u8]>::from(&self.stream_tx_scratch[..read])
            };
            let written =
                frames::write_stream_frame(stream_id, offset, data.as_ref(), fin, &mut out[off..])?;
            return Ok((
                off + written,
                Some(StagedStreamFrame::Fresh { stream_id, offset, data, fin, early_data }),
            ));
        }
        Ok((off, None))
    }

    #[inline(always)]
    pub(super) fn pending_datagram_frame_reserve(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        let payload_len = self.dgram_send_queue.get(self.admitted_batch_dgram_skip)?.data.len();
        #[cfg(feature = "zero_copy_dgram")]
        let payload_len = self.dgram_send_queue.get(self.admitted_batch_dgram_skip)?.len;
        let payload_len_u64 = u64::try_from(payload_len).ok()?;
        1usize
            .checked_add(crate::transport::varint::varint_len(payload_len_u64))?
            .checked_add(payload_len)
    }

    /// Stages one DATAGRAM frame without transferring queue ownership.
    ///
    /// The caller must commit the front item only after the complete packet has
    /// passed padding, header protection, and AEAD sealing. DATAGRAM frames are
    /// ack-eliciting per RFC 9221 sec. 2. Returns the staged entry's
    /// [`DatagramClass`] so the caller can mark bulk-only packets
    /// (`SendInfo::bulk_only`) for FEC gating (TODO-1011).
    #[inline(always)]
    pub(super) fn maybe_stage_one_datagram_frame(
        &mut self,
        out: &mut [u8],
        mut off: usize,
    ) -> Result<(usize, Option<DatagramClass>), crate::error::ConnectionError> {
        if let Some(need) = self.pending_datagram_frame_reserve() {
            let tag_reserve = self.tag_reserve_1rtt();
            log::trace!("maybe_flush_one_datagram_frame: off={} need={} tag_reserve={} out_len={} queue_len={}",
                off, need, tag_reserve, out.len(), self.dgram_send_queue.len());
            if off + need + tag_reserve <= out.len() {
                let Some(front) = self.dgram_send_queue.get(self.admitted_batch_dgram_skip) else {
                    return Ok((off, None));
                };
                #[cfg(not(feature = "zero_copy_dgram"))]
                let frame = Frame::Datagram { data: Cow::Borrowed(front.data.as_slice()) };
                #[cfg(feature = "zero_copy_dgram")]
                let frame = Frame::Datagram { data: Cow::Borrowed(&front.data[..front.len]) };
                let class = front.class;
                log::trace!("maybe_flush_one_datagram_frame: attempting to write frame, frame_wire_len={:?}", frames::wire_len(&frame));
                let written = frames::to_bytes(&frame, &mut out[off..])?;
                log::trace!("maybe_flush_one_datagram_frame: wrote {} bytes", written);
                off += written;
                return Ok((off, Some(class)));
            }
        }
        Ok((off, None))
    }

    /// Commits a previously staged DATAGRAM frame after packet sealing succeeds.
    #[inline(always)]
    pub(super) fn commit_staged_datagram_frame(
        &mut self,
    ) -> Result<(), crate::error::ConnectionError> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let Some(dgram) = self.dgram_send_queue.pop_front() else {
                return Err(crate::error::ConnectionError::InvalidState);
            };
            Self::return_dgram_freelist(&mut self.dgram_send_freelist, dgram.data);
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            if self.dgram_send_queue.pop_front().is_none() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
        }
        self.stats.dgram_sent = self.stats.dgram_sent.saturating_add(1);
        Ok(())
    }

    #[inline(always)]
    pub(super) fn maybe_apply_stealth_padding(
        &mut self,
        out: &mut [u8],
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
        reserved_wire_spend: u64,
        allow_pad_target: bool,
    ) -> Result<(usize, bool, u64), crate::error::ConnectionError> {
        // --- Traffic analysis defense modes (TODO-455) ---
        //
        // FullPadding / ConstantRate take precedence over the legacy
        // probabilistic padding path. They pad EVERY 1-RTT packet to a fixed
        // target size regardless of `stealth_padding_rate`, eliminating
        // size-based traffic analysis.
        let defense = self.config.traffic_analysis_defense;
        if let Some(target) = self.pad_short_header_to.filter(|_| allow_pad_target) {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);
            let mut staged_spend = 0;
            if target > off + tag_reserve {
                let pad_len = (target - off - tag_reserve).min(avail);
                // TODO-1052: the image-matching pad rides the shared wire
                // ledger like every other stealth byte. Under an exhausted
                // ledger the repair datagram goes out unpadded rather than
                // spending bytes the budget never granted.
                if pad_len > 0
                    && self.can_stage_wire_spend(
                        pad_len as u64,
                        reserved_wire_spend,
                        self.clock.now(),
                    )
                {
                    off += frames::write_padding(pad_len, &mut out[off..])?;
                    if self.wire_ledger.is_some() {
                        staged_spend = pad_len as u64;
                    }
                }
            }
            return Ok((off, true, staged_spend));
        }
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
            return Ok((off, false, 0));
        }

        if self.config.stealth_padding_enabled {
            let tag_reserve = self.tag_reserve_1rtt();
            let avail = out.len().saturating_sub(off + tag_reserve);

            let ad_len = pn_off + pn_len;
            let pt_len_now = off.saturating_sub(ad_len);
            if avail > 0 {
                let now = self.clock.now();
                let pad_len = if let Some(ledger) = self.wire_ledger.as_mut() {
                    ledger.preview_padding_target(pt_len_now, avail, reserved_wire_spend, now)
                } else {
                    self.compute_stealth_padding(pt_len_now, avail)
                };
                if pad_len > 0 {
                    let written = frames::write_padding(pad_len, &mut out[off..])?;
                    off += written;
                    let staged_spend = if self.wire_ledger.is_some() { written as u64 } else { 0 };
                    return Ok((off, false, staged_spend));
                }
            }
        }
        Ok((off, false, 0))
    }

    /// Queues a cover PING frame to be emitted in the next outgoing 1-RTT packet.
    ///
    /// The PING is ack-eliciting: the peer sends an ACK, generating symmetric traffic
    /// that matches idle HTTP/3 keepalive patterns observed in real browser sessions.
    pub(crate) fn queue_cover_ping(&mut self) {
        if self.is_established() {
            Self::queue_control_frame(&mut self.pending_control, Frame::Ping { mtu_probe: None });
        }
    }

    /// Queues a QUIC PADDING frame of `len` zero bytes into the next
    /// outgoing 1-RTT packet (TODO-1061). PADDING is not ack-eliciting -
    /// unlike a cover PING it adds wire bytes without soliciting an ACK,
    /// which is what a Maybenot `SendPadding` action asks for.
    pub(crate) fn queue_cover_padding(&mut self, len: usize) {
        if self.is_established() && len > 0 {
            Self::queue_control_frame(&mut self.pending_control, Frame::Padding { len });
        }
    }

    /// Pad a short header out to the header-protection sample and set the
    /// packet-number length bits that AEAD authenticates.
    #[inline(always)]
    pub(super) fn layout_short_header_plaintext(
        &mut self,
        out: &mut [u8],
        _pn: u64,
        pn_off: usize,
        pn_len: usize,
        mut off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if !(1..=packet::MAX_PKT_NUM_LEN).contains(&pn_len) || pn_off == 0 {
            return Err(crate::error::ConnectionError::InvalidPacket);
        }
        let pn_end =
            pn_off.checked_add(pn_len).ok_or(crate::error::ConnectionError::InvalidPacket)?;
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
        // matches what the peer sees after HP removal.
        out[0] = 0x40 | (((pn_len as u8) - 1) & 0x03);
        if self.key_phase {
            out[0] |= packet::KEY_PHASE_BIT;
        }
        Ok(off)
    }

    #[inline(always)]
    pub(super) fn seal_short_header_packet(
        &mut self,
        out: &mut [u8],
        pn: u64,
        pn_off: usize,
        pn_len: usize,
        off: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        let mut off = self.layout_short_header_plaintext(out, pn, pn_off, pn_len, off)?;
        let sample_end = pn_off
            .checked_add(packet::MAX_PKT_NUM_LEN)
            .and_then(|offset| offset.checked_add(packet::SAMPLE_LEN))
            .ok_or(crate::error::ConnectionError::InvalidPacket)?;

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
            let seal = packet::select_private_seal(
                Some(&keys.seal),
                keys.private_seal.as_ref(),
                pn,
                keys.private_write_boundary,
            )
            .map_err(|error| match error {
                crate::error::ConnectionError::Done => crate::error::ConnectionError::TlsError(
                    "missing AEAD sealer for 1-RTT short header".into(),
                ),
                error => error,
            })?;
            seal.seal_batch(core::slice::from_mut(&mut item))?;
            let sealed_len = pt_len + 16;
            off = ad_len + sealed_len;
            let sample_offset = sample_end - packet::SAMPLE_LEN;
            let mask = keys.hp_seal.new_mask(&out[sample_offset..sample_end])?;
            out[0] ^= mask[0] & 0x1f;
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
            self.advance_send_packet_number(2)?;
            return Ok(off);
        }

        // Fallback: 0-RTT or handshake - one read guard covers the seal choice,
        // the AEAD seal, and the header-protection mask (TODO-916). Key-update
        // writes serialize on `write()` either way; the guard is dropped before
        // `advance_send_packet_number`, which may take the write lock.
        let use_1rtt_seal;
        let sealed_len;
        let mask;
        {
            let crypto_guard = self.crypto.read();
            use_1rtt_seal = crypto_guard.seal_1rtt.is_some();
            let ad_len = pn_off + pn_len;
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let mut item = crate::crypto::aead::AeadSealItem {
                counter: pn,
                ad: ad_slice,
                buf: rest,
                plaintext_len: pt_len,
            };
            let seal = packet::select_private_seal(
                crypto_guard.seal_1rtt.as_ref(),
                crypto_guard.private_seal_1rtt.as_ref(),
                pn,
                crypto_guard.private_write_boundary_1rtt,
            )
            .map_err(|error| match error {
                crate::error::ConnectionError::Done => crate::error::ConnectionError::TlsError(
                    "missing AEAD sealer for 1-RTT short header".into(),
                ),
                error => error,
            })?;
            seal.seal_batch(core::slice::from_mut(&mut item))?;
            sealed_len = pt_len + 16;
            let hp = if use_1rtt_seal {
                crypto_guard.hp_1rtt.as_deref()
            } else {
                crypto_guard.hp_0rtt.as_deref().or(crypto_guard.hp_1rtt.as_deref())
            };
            mask = hp
                .map(|hp| {
                    let sample_offset = sample_end - packet::SAMPLE_LEN;
                    hp.new_mask(&out[sample_offset..sample_end])
                })
                .transpose()?;
        }
        off = pn_off + pn_len + sealed_len;
        if let Some(mask) = mask {
            out[0] ^= mask[0] & 0x1f;
            for i in 0..pn_len {
                out[pn_off + i] ^= mask[i + 1];
            }
        }
        self.advance_send_packet_number(2)?;
        Ok(off)
    }

    /// Seal prepared short headers with one `seal_batch` per sealer group, then
    /// apply header protection per packet. Packet numbers were already advanced
    /// when the batch was framed.
    pub(super) fn seal_prepared_short_headers(
        &mut self,
        outs: &mut [&mut [u8]],
        frames: &[AdmittedShortHeader],
    ) -> Result<Vec<usize>, crate::error::ConnectionError> {
        if outs.len() != frames.len() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        #[cfg(test)]
        let mut batch_calls = 0u64;
        #[cfg(test)]
        let mut batch_packets = 0u64;
        let one_rtt = self.crypto_1rtt.load();
        let Some(keys) = one_rtt.as_ref() else {
            return Err(crate::error::ConnectionError::TlsError(
                "admitted seal batch requires installed 1-RTT keys".into(),
            ));
        };
        let mut totals = vec![0usize; frames.len()];
        let mut group_start = 0usize;
        while group_start < frames.len() {
            let first = packet::select_private_packet_protection(
                frames[group_start].pn,
                keys.private_write_boundary,
                keys.private_seal.is_some(),
            );
            let mut group_end = group_start + 1;
            while group_end < frames.len()
                && packet::select_private_packet_protection(
                    frames[group_end].pn,
                    keys.private_write_boundary,
                    keys.private_seal.is_some(),
                ) == first
            {
                group_end += 1;
            }
            let seal = packet::select_private_seal(
                Some(&keys.seal),
                keys.private_seal.as_ref(),
                frames[group_start].pn,
                keys.private_write_boundary,
            )
            .map_err(|error| match error {
                crate::error::ConnectionError::Done => crate::error::ConnectionError::TlsError(
                    "missing AEAD sealer for admitted 1-RTT batch".into(),
                ),
                error => error,
            })?;
            let mut items = Vec::with_capacity(group_end - group_start);
            for (buf, frame) in
                outs[group_start..group_end].iter_mut().zip(frames[group_start..group_end].iter())
            {
                let ad_len = frame.pn_off + frame.pn_len;
                if frame.plaintext_end < ad_len || frame.plaintext_end > buf.len() {
                    return Err(crate::error::ConnectionError::InvalidPacket);
                }
                let (ad, rest) = buf.split_at_mut(ad_len);
                items.push(crate::crypto::aead::AeadSealItem {
                    counter: frame.pn,
                    ad,
                    buf: rest,
                    plaintext_len: frame.plaintext_end - ad_len,
                });
            }
            seal.seal_batch(&mut items)?;
            #[cfg(test)]
            {
                batch_calls = batch_calls.saturating_add(1);
                batch_packets = batch_packets.saturating_add(items.len() as u64);
            }
            for (offset, frame) in frames[group_start..group_end].iter().enumerate() {
                let buf = &mut *outs[group_start + offset];
                let sample_end = frame
                    .pn_off
                    .checked_add(packet::MAX_PKT_NUM_LEN)
                    .and_then(|value| value.checked_add(packet::SAMPLE_LEN))
                    .ok_or(crate::error::ConnectionError::InvalidPacket)?;
                let sample_offset = sample_end - packet::SAMPLE_LEN;
                let mask = keys.hp_seal.new_mask(&buf[sample_offset..sample_end])?;
                buf[0] ^= mask[0] & 0x1f;
                for byte in 0..frame.pn_len {
                    buf[frame.pn_off + byte] ^= mask[byte + 1];
                }
                totals[group_start + offset] = frame.plaintext_end + 16;
            }
            group_start = group_end;
        }
        drop(one_rtt);
        #[cfg(test)]
        {
            self.admitted_seal_batch_calls =
                self.admitted_seal_batch_calls.saturating_add(batch_calls);
            self.admitted_seal_batch_packets =
                self.admitted_seal_batch_packets.saturating_add(batch_packets);
        }
        Ok(totals)
    }

    #[inline(always)]
    pub(super) fn send_targeted_short_header_frame(
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
            bulk_only: false,
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
