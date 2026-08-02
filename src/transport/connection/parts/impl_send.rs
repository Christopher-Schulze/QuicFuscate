impl Connection {
    /// Generates outgoing packet
    #[inline(always)]
    pub fn send(
        &mut self,
        out: &mut [u8],
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send_with_datagram_overhead(out, 0)
    }

    /// Generates an outgoing packet while reserving bytes for an outer datagram
    /// envelope. Non-zero overhead is valid only after the QUIC handshake.
    #[inline(always)]
    pub fn send_with_datagram_overhead(
        &mut self,
        out: &mut [u8],
        datagram_overhead: usize,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(out.len() < MIN_CLIENT_INITIAL_LEN) {
            return Err(ConnectionError::BufferTooShort);
        }
        if unlikely(datagram_overhead != 0 && !self.post_handshake_datagram_ready()?) {
            return Err(ConnectionError::InvalidState);
        }
        // Never emit a QUIC packet larger than the negotiated max UDP payload size.
        // The caller's buffer may be larger than the path MTU (e.g. a pooled 2 KiB block),
        // but downstream send paths use fixed-size datagram buffers; an oversized packet
        // would be silently truncated, destroying the AEAD tag and making the peer unable
        // to decrypt. Clamping the working buffer to the MTU forces CRYPTO/stream framing
        // to fragment across multiple packets instead of overflowing a single one.
        //
        // DPLPMTUD (TODO-451): when enabled, clamp to the *confirmed* path MTU rather
        // than the configured max. Probe packets are sized separately below.
        let now = Instant::now();
        // Apply black-hole recovery before deriving this send's packetization
        // budget so the first recovery packet uses the safe floor immediately.
        if self.pmtu.check_black_hole(now) {
            let previous_mtu = self.pmtu.effective_mtu();
            self.pmtu.reset_to_minimum(now);
            self.pmtu_above_floor_pns.clear();
            log::warn!(
                "DPLPMTUD black hole detected: path MTU {}B -> {}B",
                previous_mtu,
                self.pmtu.effective_mtu()
            );
        }
        let pmtu = self.pmtu.effective_mtu();
        let available_probe_target = self.pmtu.probe_target().filter(|target| {
            self.is_established
                && self.pmtu.should_send_probe(now)
                && *target <= self.dgram_send_max_size
                && *target <= out.len()
        });
        let dedicated_pmtu_probe = available_probe_target.is_some();
        let packetization_mtu = available_probe_target.unwrap_or(pmtu).max(pmtu);
        let outer_mtu_cap = out
            .len()
            .min(self.dgram_send_max_size.max(MIN_CLIENT_INITIAL_LEN))
            .min(packetization_mtu.max(MIN_CLIENT_INITIAL_LEN));
        let mtu_cap = outer_mtu_cap.saturating_sub(datagram_overhead);
        log::trace!("send_with_datagram_overhead: out_len={} dgram_send_max_size={} pmtu={} packetization_mtu={} outer_mtu_cap={} datagram_overhead={} mtu_cap={} dgram_queue_len={} bytes_in_flight={} cwnd={}",
            out.len(), self.dgram_send_max_size, pmtu, packetization_mtu, outer_mtu_cap, datagram_overhead, mtu_cap, self.dgram_send_queue.len(), self.bytes_in_flight, self.cwnd);
        if unlikely(mtu_cap == 0) {
            return Err(ConnectionError::BufferTooShort);
        }
        let out = &mut out[..mtu_cap];
        // Congestion gate: only send if within cwnd budget.
        // ACK-only packets bypass the gate (RFC 9002 §7.2) to prevent
        // congestion-control deadlocks where both sides exhaust their windows
        // and neither can send ACKs to release budget.
        let congestion_blocked = !self.recovery.can_send(self.dgram_send_max_size);
        log::trace!("send_with_datagram_overhead congestion gate: recovery.bytes_in_flight={} recovery.cwnd={} dgram_send_max_size={} congestion_blocked={}",
            self.recovery.bytes_in_flight, self.recovery.cwnd, self.dgram_send_max_size, congestion_blocked);
        let mut congestion_bypass = congestion_blocked && self.has_pending_application_ack();
        let mut pmtu_probe_bypassed_congestion = false;
        if congestion_blocked && !congestion_bypass {
            // RFC 9002 §7.5/§6.2.4: PTO probes MUST NOT be blocked by the
            // congestion controller (they still count as in flight). The probe
            // PING is written below in the assembly; stream/datagram payloads
            // stay gated.
            if self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application) {
                congestion_bypass = true;
            }
        }
        if congestion_blocked
            && !congestion_bypass
            && dedicated_pmtu_probe
            && self.pmtu.can_bypass_congestion(self.recovery.rtt)
        {
            // RFC 8899 permits an isolated probe outside congestion control
            // only when the configured probe interval is at least one RTT.
            // This path emits only the PING+PADDING probe below.
            congestion_bypass = true;
            pmtu_probe_bypassed_congestion = true;
        }
        if congestion_blocked && !congestion_bypass {
            log::trace!("send_with_datagram_overhead: early Done congestion_blocked congestion_bypass={} dgram_queue_len={}", congestion_bypass, self.dgram_send_queue.len());
            return Err(ConnectionError::Done);
        }
        self.poll_path_validation_timeout(now);

        // TLS provider may derive new secrets during write-side progression. Poll here so
        // handshake completion and key installation are not dependent on receiving more CRYPTO.
        self.poll_tls_and_validate_versions()?;

        let handshake_incomplete =
            self.tls_provider.as_ref().map(|p| !p.handshake_complete()).unwrap_or(false);

        // Always flush any pending Initial/Handshake CRYPTO before falling through to the
        // 1-RTT path, even if rustls has just reported the handshake complete. The client's
        // Finished is produced at the very instant completion flips to true; if we skipped the
        // handshake send path as soon as handshake_complete became true, that Finished would
        // never reach the wire and the peer would stay stuck handshaking forever (it would
        // only ever see Initial + 1-RTT, never the Handshake-level Finished).
        {
            let (has_initial, has_handshake) = {
                let crypto = self.crypto.read();
                (crypto.seal_initial.is_some(), crypto.seal_handshake.is_some())
            };
            // Try Initial first (when applicable), then Handshake. This avoids stalling if
            // Initial keys are installed but there is no pending Initial CRYPTO, while Handshake
            // CRYPTO is ready.
            for pkt_ty in [PacketType::Initial, PacketType::Handshake] {
                if matches!(pkt_ty, PacketType::Initial) && !has_initial {
                    continue;
                }
                if matches!(pkt_ty, PacketType::Handshake) && !has_handshake {
                    continue;
                }

                let token = if matches!(pkt_ty, PacketType::Initial) {
                    self.config.initial_token.clone()
                } else {
                    None
                };
                let base_hdr = packet::Header {
                    ty: pkt_ty,
                    version: self.config.version,
                    dcid: self.dcid.to_vec(),
                    scid: self.scid.to_vec(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token,
                    versions: None,
                    key_phase: false,
                };
                let hdr_len_wo_pn = packet::format_header(&base_hdr, out)?;
                let space_idx = match pkt_ty {
                    PacketType::Initial => 0,
                    PacketType::Handshake => 1,
                    _ => 2,
                };
                let pn = self.next_send_pn_by_space[space_idx];
                let pn_len = if pn < (1 << 8) {
                    1
                } else if pn < (1 << 16) {
                    2
                } else if pn < (1 << 24) {
                    3
                } else {
                    4
                };
                if out.len() < hdr_len_wo_pn + pn_len {
                    return Err(ConnectionError::BufferTooShort);
                }
                let mut tmp = [0u8; 4];
                packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
                out[hdr_len_wo_pn..hdr_len_wo_pn + pn_len].copy_from_slice(&tmp[..pn_len]);
                let header_len = hdr_len_wo_pn + pn_len;
                let mut off = header_len;

                // The CRYPTO data budget must reserve room for everything written into
                // the same packet *after* the data: the AEAD tag (16), the CRYPTO frame
                // header (type 1 + offset varint ≤8 + length varint ≤8), and the ACK/PING
                // frames added below. Without this reserve, next_crypto_frame() returns up
                // to `out.len() - off - 16` bytes, the framed packet overflows the buffer
                // and the seal fails with BufferTooShort. (Since the CRYPTO retention
                // buffer keeps drained bytes unacked, a failed seal no longer loses the
                // data - but the oversized write would still error out every send.)
                const SEND_FRAME_OVERHEAD_RESERVE: usize = 64;
                let crypto_budget =
                    out.len().saturating_sub(off + 16 + SEND_FRAME_OVERHEAD_RESERVE);
                let (lvl, max_len) = match pkt_ty {
                    PacketType::Initial => (crate::qftls::Level::Initial, crypto_budget),
                    PacketType::Handshake => (crate::qftls::Level::Handshake, crypto_budget),
                    _ => (crate::qftls::Level::Application, crypto_budget),
                };
                if max_len < 32 {
                    continue;
                }
                let crypto_frame = self.next_crypto_frame(lvl, max_len);
                let probe_pos = self
                    .pending_probe_spaces
                    .iter()
                    .position(|s| *s == recovery::PacketSpace::from_index(space_idx));
                if crypto_frame.is_none() && probe_pos.is_none() {
                    continue;
                }
                // RFC 9002 §6.2.4: a PTO probe for this space. The packet below
                // always carries PING (ack-eliciting), plus retransmitted or
                // fresh CRYPTO when available. Client Initial probes stay
                // padded to >= 1200 bytes (§6.2.2.1) via target_total below.
                if let Some(pos) = probe_pos {
                    self.pending_probe_spaces.remove(pos);
                }
                let crypto_range = crypto_frame.as_ref().map(|(o, d)| (*o, d.len() as u64));

                if let Some((ack_delay, ack_ranges)) =
                    self.pkt_spaces[space_idx].take_ack(self.config.ack_delay_exponent)
                {
                    let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: None };
                    let need = frames::wire_len(&ack);
                    if out.len() >= off + need + 16 {
                        off += frames::to_bytes(&ack, &mut out[off..])?;
                    }
                }
                let ping = Frame::Ping { mtu_probe: None };
                off += frames::to_bytes(&ping, &mut out[off..])?;
                if let Some((crypto_off, data)) = crypto_frame {
                    let frame = Frame::Crypto { offset: crypto_off, data: Cow::Owned(data) };
                    let written = frames::to_bytes(&frame, &mut out[off..])?;
                    off += written;
                }

                let pn_off = hdr_len_wo_pn;
                let sample_min = pn_off + 4 + packet::SAMPLE_LEN;
                let mut target_total = header_len + 16;
                if sample_min > target_total {
                    target_total = sample_min;
                }
                // Ensure we can actually carry the frames we already wrote, plus the AEAD tag.
                // sample_min only guarantees enough ciphertext for header protection sampling,
                // but we may have already written more plaintext than that budget.
                let frames_min_total = off.saturating_add(16);
                if frames_min_total > target_total {
                    target_total = frames_min_total;
                }
                if matches!(pkt_ty, PacketType::Initial) && MIN_CLIENT_INITIAL_LEN > target_total {
                    target_total = MIN_CLIENT_INITIAL_LEN;
                }
                if out.len() < target_total {
                    return Err(ConnectionError::BufferTooShort);
                }
                let target_off = target_total - 16;
                if off < target_off {
                    let pad_len = target_off - off;
                    frames::write_padding(pad_len, &mut out[off..])?;
                }

                trace_send_packet(
                    self.is_server,
                    pkt_ty,
                    space_idx,
                    pn,
                    pn_len,
                    header_len,
                    target_total,
                );

                let used = {
                    let crypto = self.crypto.read();
                    packet::encrypt_and_protect(
                        &crypto,
                        &mut out[..target_total],
                        header_len,
                        pn,
                        pn_len,
                        pkt_ty,
                    )?
                };
                self.next_send_pn_by_space[space_idx] =
                    self.next_send_pn_by_space[space_idx].wrapping_add(1);
                self.stats.sent += 1;
                self.stats.sent_bytes += used as u64;
                // RFC 9002 §4.9: handshake packets are not special - they are
                // tracked for loss recovery exactly like 1-RTT packets.
                self.recovery.on_packet_sent_in_space(
                    recovery::PacketSpace::from_index(space_idx),
                    pn,
                    used,
                    true,
                    true,
                    crypto_range,
                    Instant::now(),
                );
                if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
                    self.is_established = true;
                }
                return Ok((
                    used,
                    SendInfo {
                        at: Instant::now(),
                        from: self.local_addr,
                        to: self.peer_addr,
                        congestion_controlled: true,
                        path_control: false,
                    },
                ));
            }

            // No pending Initial/Handshake CRYPTO to send. If the handshake is still in
            // progress there is nothing else to do this turn; once it is complete we fall
            // through to the 1-RTT path below.
            if handshake_incomplete {
                log::trace!("send_with_datagram_overhead: early Done handshake_incomplete dgram_queue_len={}", self.dgram_send_queue.len());
                return Err(ConnectionError::Done);
            }
        }
        if let Some(targeted_frame) = self.pop_targeted_path_frame_for_send() {
            return self.send_targeted_short_header_frame(
                out,
                targeted_frame.local_addr,
                targeted_frame.peer_addr,
                &targeted_frame.frame,
            );
        }
        // Nothing to send: return Done to avoid emitting empty 1-RTT packets
        // (header + AEAD tag only). Without this guard, the sender enters an
        // infinite loop of 38B empty packets that flood the socket buffer and
        // starve the recv path on the peer.
        //
        // The handshake-incomplete case is already handled by the early return
        // above (after the Initial/Handshake CRYPTO flush loop) - by this point
        // the handshake is always complete.
        let has_pending_data = !self.pending_control.is_empty()
            || self.has_pending_application_ack()
            || self.has_sendable_stream_frame()
            || !self.dgram_send_queue.is_empty()
            || self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application)
            || self
                .traffic_analysis
                .as_ref()
                .is_some_and(|scheduler| scheduler.has_pending_chaff());
        if !has_pending_data && !congestion_bypass && !dedicated_pmtu_probe {
            log::trace!("send_with_datagram_overhead: early Done has_pending_data=false dgram_queue_len={} pending_control={} app_ack={} sendable_stream={} probe_spaces={} congestion_bypass={} pmtu_probe={}",
                self.dgram_send_queue.len(), self.pending_control.is_empty(), self.has_pending_application_ack(), self.has_sendable_stream_frame(), self.pending_probe_spaces.iter().any(|s| *s == recovery::PacketSpace::Application), congestion_bypass, dedicated_pmtu_probe);
            return Err(ConnectionError::Done);
        }
        // Outbound stealth timing is owned by core::QuicFuscateConnection (next_packet_release).
        // Build short header prefix with DCID directly - avoids two Vec
        // allocations (dcid.to_vec() + scid.to_vec()) per outbound packet.
        let hdr_len = packet::format_short_header(self.dcid.as_ref(), false, out)?; // first byte + DCID
        let dcid_end = 1 + self.dcid.as_ref().len();
        // Decide packet number and length
        let pn = self.next_send_pn_by_space[2];
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
            return Err(ConnectionError::BufferTooShort);
        }
        // Write truncated PN (big-endian) before encryption
        {
            let mut tmp = [0u8; 4];
            packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
            out[dcid_end..dcid_end + pn_len].copy_from_slice(&tmp[..pn_len]);
        }
        let pn_off = dcid_end;
        let mut off = pn_off + pn_len;

        // Track whether any ack-eliciting frame was written in this packet.
        // Per RFC 9002 §7.2, only packets containing ack-eliciting frames are
        // congestion-controlled. Non-ack-eliciting frames: PADDING, ACK,
        // CONNECTION_CLOSE, APPLICATION_CLOSE. All others (STREAM, DATAGRAM,
        // CRYPTO, PING, MAX_DATA, NEW_CONNECTION_ID, etc.) are ack-eliciting.
        let mut wrote_ack_eliciting = false;
        let mut stream_transmission_id = None;
        let mut packet_contents = recovery::SentPacketContents::default();

        // Post-handshake Application-level CRYPTO (e.g. NewSessionTicket) is not
        // emitted here. The early return above guarantees `handshake_incomplete`
        // is false at this point, so any Application CRYPTO would be
        // post-handshake and should be flushed via a dedicated path that
        // respects flow control and the congestion window. The previous
        // `if handshake_incomplete` block was unreachable dead code.

        if !dedicated_pmtu_probe {
            let (off_after_ctrl, ctrl_ack_eliciting) =
                self.flush_pending_control_frames(out, off, congestion_bypass)?;
            off = off_after_ctrl;
            wrote_ack_eliciting |= ctrl_ack_eliciting;
            packet_contents.control |= ctrl_ack_eliciting;
            off = self.maybe_emit_application_ack_frame(out, off)?;
            // RFC 9002 §6.2.4: emit one ack-eliciting PING per pending
            // Application-space PTO probe. Written directly (not via
            // pending_control) so it also fires when the congestion gate was
            // bypassed for the probe; stream/datagram payloads stay gated.
            if let Some(pos) = self
                .pending_probe_spaces
                .iter()
                .position(|s| *s == recovery::PacketSpace::Application)
            {
                let ping = Frame::Ping { mtu_probe: None };
                let tag_reserve = self.tag_reserve_1rtt();
                if out.len() >= off + frames::wire_len(&ping) + tag_reserve {
                    self.pending_probe_spaces.remove(pos);
                    off += frames::to_bytes(&ping, &mut out[off..])?;
                    wrote_ack_eliciting = true;
                    packet_contents.control = true;
                }
            }
            // When bypassing the congestion gate for ACK-only packets, skip
            // stream and datagram data - those are congestion-controlled and
            // must not be sent when the window is exhausted.
            if !congestion_bypass {
                let datagram_reserve = self
                    .pending_datagram_frame_reserve()
                    .filter(|reserve| off + reserve + self.tag_reserve_1rtt() <= out.len())
                    .unwrap_or(0);
                let stream_limit = out.len().saturating_sub(datagram_reserve);
                let (off_after_stream, stream_ack_eliciting, emitted_transmission) =
                    self.maybe_flush_one_writable_stream(&mut out[..stream_limit], off)?;
                off = off_after_stream;
                wrote_ack_eliciting |= stream_ack_eliciting;
                packet_contents.stream |= stream_ack_eliciting;
                if let Some(emission) = emitted_transmission {
                    stream_transmission_id = Some(emission.id);
                    packet_contents.stream_retransmission |= emission.retransmission;
                }
                // FEC feed removed (handled by core)
                let (off_after_dgram, dgram_ack_eliciting) =
                    self.maybe_flush_one_datagram_frame(out, off)?;
                off = off_after_dgram;
                wrote_ack_eliciting |= dgram_ack_eliciting;
                packet_contents.datagram |= dgram_ack_eliciting;
            }
        }
        // DPLPMTUD probe (TODO-451): when the PMTU state machine requests a
        // probe and the current packet has no ack-eliciting payload (otherwise
        // the real data already serves as a probe), inject a PING frame and pad
        // the packet up to the probe target size. The probe is ack-eliciting so
        // the peer's ACK confirms the larger MTU. We only probe when the buffer
        // can hold the probe size (the caller's buffer is typically ≥ PMTU_MAX).
        let mut _pmtu_probe_sent = false;
        if dedicated_pmtu_probe
            && !wrote_ack_eliciting
            && outer_mtu_cap >= self.pmtu.probe_target().unwrap_or(0)
        {
            if let Some(probe_size) = self.pmtu.probe_size() {
                // PING frame (ack-eliciting) so the peer ACKs the probe.
                use crate::transport::Frame;
                let ping = Frame::Ping { mtu_probe: None };
                off += crate::transport::frames::to_bytes(&ping, &mut out[off..])?;
                wrote_ack_eliciting = true;
                packet_contents.control = true;
                // Pad the remainder of the probe region with PADDING frames.
                let tag_reserve = self.tag_reserve_1rtt();
                let transport_probe_size = probe_size.saturating_sub(datagram_overhead);
                let avail = out.len().saturating_sub(off + tag_reserve);
                let needed = transport_probe_size.saturating_sub(off + tag_reserve);
                let pad_len = needed.min(avail);
                if pad_len > 0 {
                    off += crate::transport::frames::write_padding(pad_len, &mut out[off..])?;
                }
                self.pmtu.on_probe_sent(probe_size, now);
                _pmtu_probe_sent = true;
                self.pmtu_probe_pn = Some(pn);
            }
        }
        // A due traffic-analysis slot emits chaff only when the packet remains
        // completely empty. ACK-only, control, stream, DATAGRAM, recovery, and
        // PMTU traffic always win and cover the slot without being converted
        // into an ack-eliciting chaff packet.
        let packet_has_real_frames = off > pn_off + pn_len;
        let mut emitted_chaff = false;
        if !packet_has_real_frames && !congestion_bypass && !dedicated_pmtu_probe {
            let tag_reserve = self.tag_reserve_1rtt();
            let chaff_size = self
                .traffic_analysis
                .as_ref()
                .filter(|scheduler| scheduler.has_pending_chaff())
                .map(|scheduler| scheduler.chaff_size_bytes())
                .unwrap_or(0);
            if chaff_size > 0 {
                use crate::transport::Frame;
                let ping = Frame::Ping { mtu_probe: None };
                off += crate::transport::frames::to_bytes(&ping, &mut out[off..])?;
                wrote_ack_eliciting = true;
                emitted_chaff = true;
                packet_contents.control = true;
                let avail = out.len().saturating_sub(off + tag_reserve);
                let needed = (chaff_size as usize).saturating_sub(off + tag_reserve);
                let pad_len = needed.min(avail);
                if pad_len > 0 {
                    off += crate::transport::frames::write_padding(pad_len, &mut out[off..])?;
                }
            }
        }
        if off == pn_off + pn_len {
            log::trace!("send_with_datagram_overhead: off==pn_off+pn_len, returning Done; dgram_queue_len={} pending_control={} application_ack={} writable_streams={} probe_spaces={}",
                self.dgram_send_queue.len(), self.pending_control.len(), self.has_pending_application_ack(), self.writable_streams.len(), self.pending_probe_spaces.len());
            return Err(ConnectionError::Done);
        }
        off = self.maybe_apply_stealth_padding(out, pn_off, pn_len, off)?;
        off = self.seal_short_header_packet(out, pn, pn_off, pn_len, off)?;
        if let Some(scheduler) = self.traffic_analysis.as_mut() {
            if emitted_chaff {
                scheduler.record_chaff_emitted();
            } else {
                scheduler.record_cover_packet(
                    now,
                    packet_contents.stream || packet_contents.datagram,
                );
            }
        }

        // Mark bytes-in-flight timing start if we actually wrote payload beyond header
        if off > (pn_off + pn_len) && self.bytes_in_flight_started.is_none() {
            self.bytes_in_flight_started = Some(Instant::now());
        }
        // Maintain minimal paths_count
        self.refresh_path_count();

        // Legacy transport-level FEC removed

        // Stealth-friendly: do not force 1200-byte minimum for short-header packets
        let total = off;
        let info = SendInfo {
            from: self.local_addr,
            to: self.peer_addr,
            at: Instant::now(),
            congestion_controlled: wrote_ack_eliciting,
            path_control: false,
        };
        self.stats.sent += 1;
        self.stats.sent_bytes += total as u64;
        // Per RFC 9002 §7.2, only packets containing ack-eliciting frames are
        // congestion-controlled. Packets carrying only ACK/PADDING/CONNECTION_CLOSE
        // are not congestion-controlled and must not inflate bytes_in_flight.
        // They are also not tracked in sent_packets_by_pn because the peer will
        // never ACK them - tracking them would leak bytes_in_flight permanently.
        //
        // `wrote_ack_eliciting` is set whenever any ack-eliciting frame (STREAM,
        // DATAGRAM, CRYPTO, PING, MAX_DATA, NEW_CONNECTION_ID, RESET_STREAM,
        // STOP_SENDING, PATH_CHALLENGE, PATH_RESPONSE, HANDSHAKE_DONE, etc.) was
        // emitted. This is the correct RFC 9002 §7.2 condition - the previous
        // heuristic ("no stream/dgram payload") misclassified PING-only keepalive
        // probes and flow-control updates as non-congestion-controlled, breaking
        // PTO-based loss detection for those packets.
        let is_ack_only = !wrote_ack_eliciting;
        if !is_ack_only {
            let now = Instant::now();
            if _pmtu_probe_sent && pmtu_probe_bypassed_congestion {
                self.recovery.on_pmtu_probe_sent_in_space(
                    recovery::PacketSpace::Application,
                    pn,
                    total,
                    now,
                );
            } else {
                self.recovery.on_packet_sent_with_contents_in_space(
                    recovery::PacketSpace::Application,
                    pn,
                    total,
                    true,
                    true,
                    None,
                    packet_contents,
                    now,
                );
            }
            if let Some(transmission_id) = stream_transmission_id {
                self.commit_stream_transmission(transmission_id, pn);
            }
            let outer_datagram_size = total.saturating_add(datagram_overhead);
            self.pmtu.on_packet_sent(outer_datagram_size, now);
            if outer_datagram_size > self.pmtu.min_mtu {
                self.pmtu_above_floor_pns.insert(pn);
            }
            self.cwnd = self.recovery.cwnd;
        }
        Ok((total, info))
    }

    /// Compute stealth padding length given current plaintext payload length and budget.
    ///
    /// Dispatches on the configured [`TrafficAnalysisDefense`] mode (TODO-455):
    /// - `Off`: existing probabilistic padding (gated by `stealth_padding_rate`).
    /// - `FullPadding`: always pad to the full available budget (no rate gating,
    ///   no random roll). The precise total-packet-size targeting to
    ///   `max_udp_payload_size` is performed in `maybe_apply_stealth_padding`,
    ///   which calls this after computing the budget; here we return `budget`
    ///   so every packet is maximally padded regardless of `stealth_padding_rate`.
    /// - `ConstantRate`: same maximal-padding behavior as `FullPadding` at this
    ///   layer; the consistent target size and chaff injection are orchestrated
    ///   by `maybe_apply_stealth_padding` and the `TrafficAnalysisScheduler`.
    #[inline(always)]
    pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
        // Traffic analysis defense modes take precedence over the legacy
        // probabilistic path. They never skip padding based on rate.
        match self.config.traffic_analysis_defense {
            TrafficAnalysisDefense::FullPadding | TrafficAnalysisDefense::ConstantRate => {
                return budget;
            }
            TrafficAnalysisDefense::Off => {}
        }

        if !self.config.stealth_padding_enabled {
            return 0;
        }
        // Gradual padding rate: only pad a fraction of packets based on the
        // configured rate (0-100%). At 100%, every packet is padded; at 50%,
        // only half of packets receive padding. This implements the gradual
        // stealth escalation from TODO-416.
        let padding_rate = self.config.stealth_padding_rate;
        if padding_rate == 0 {
            return 0;
        }
        if padding_rate < 100 {
            let roll = crate::transport::rand::fast_rand_u64_uniform(100) as u8;
            if roll >= padding_rate {
                return 0;
            }
        }
        let strategy = self.config.stealth_padding_strategy;
        if strategy == 3 && self.config.stealth_adaptive_granularity == 64 {
            let rem = cur_pt_len & 63;
            if rem == 0 {
                return 0;
            }
            let max = self.config.stealth_padding_max_size.min(budget);
            return (64 - rem).min(max);
        }
        let max = self.config.stealth_padding_max_size.min(budget);
        if max == 0 {
            return 0;
        }
        match strategy {
            // 1 = Random [0..=max]
            1 => crate::transport::rand::fast_rand_u64_uniform((max as u64).saturating_add(1))
                as usize,
            // 2 = Fixed (always pad up to max budget)
            2 => max,
            // 3 = Adaptive (pad up to next 64B boundary, capped by max)
            3 => {
                let g = self.config.stealth_adaptive_granularity.max(1) as usize;
                let rem = if g.is_power_of_two() { cur_pt_len & (g - 1) } else { cur_pt_len % g };
                if rem == 0 {
                    0
                } else {
                    let pad = g - rem;
                    if pad < max {
                        pad
                    } else {
                        max
                    }
                }
            }
            // 4 = BrowserMimic: bias profile to small values; bucket depends on bias
            4 => {
                let (bucket_div, samples) = match self.config.stealth_mimic_bias {
                    1 => (8usize, 3), // very small (Safari/iOS)
                    2 => (6usize, 2), // small (Firefox/Linux)
                    4 => (5usize, 2), // mobile (Android)
                    _ => (4usize, 2), // default (Chromium/Windows)
                };
                let bucket = (max / bucket_div).max(1) as u64;
                let mut val = crate::transport::rand::fast_rand_u64_uniform(bucket + 1);
                for _ in 1..samples {
                    let r = crate::transport::rand::fast_rand_u64_uniform(bucket + 1);
                    if r < val {
                        val = r;
                    }
                }
                std::cmp::min(val as usize, max)
            }
            _ => 0,
        }
    }

    fn try_advance_read_keys(&mut self) -> bool {
        let provider_updated = self
            .tls_provider
            .as_mut()
            .map(|provider| provider.key_update_read().is_ok())
            .unwrap_or(false);
        if provider_updated {
            // The rustls provider rotated the read key inside CryptoContext.
            // Sync the lock-free ArcSwap so the hot path picks up the new key.
            self.sync_1rtt();
            return true;
        }
        let updated = self.crypto.write().key_update_1rtt_read();
        if updated {
            self.sync_1rtt();
        }
        updated
    }

}
