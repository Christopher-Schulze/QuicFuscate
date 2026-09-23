use super::state::AdmittedShortHeader;
use super::*;

impl Connection {
    /// Generates outgoing packet
    #[inline(always)]
    pub fn send(
        &mut self,
        out: &mut [u8],
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send_with_datagram_overhead(out, 0)
    }

    /// Emit a transport close at a level the peer can decrypt before version validation.
    pub(super) fn send_pre_validation_close(
        &mut self,
        out: &mut [u8],
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let close_index = self
            .pending_control
            .iter()
            .position(|frame| matches!(frame, Frame::ConnectionClose { .. }))
            .ok_or(ConnectionError::Done)?;
        // The server learns the client's parameters in its Initial. The client
        // learns the server's parameters in EncryptedExtensions, after Handshake
        // keys become available. Use the corresponding peer-readable space.
        let packet_type = if !self.is_server && self.crypto.read().seal_handshake.is_some() {
            PacketType::Handshake
        } else {
            PacketType::Initial
        };
        let space_idx = if packet_type == PacketType::Handshake { 1 } else { 0 };
        let pn = self.next_send_packet_number(space_idx)?;
        let mut header = packet::Header {
            ty: packet_type,
            version: self.config.version,
            dcid: self.dcid.to_vec(),
            scid: self.scid.to_vec(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: if packet_type == PacketType::Initial {
                self.config.initial_token.clone()
            } else {
                None
            },
            versions: None,
            key_phase: false,
            length: None,
        };
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        // Reserve worst-case header+PN space. seal_long_header_packet resolves
        // the RFC Length, rewrites the compact header and seals once.
        let header_reserve = packet::long_header_reserve(&header)?;
        if out.len() < header_reserve {
            return Err(ConnectionError::BufferTooShort);
        }
        let close = &self.pending_control[close_index];
        let payload_len = frames::to_bytes(close, &mut out[header_reserve..])?;
        let min_total = if packet_type == PacketType::Initial { MIN_CLIENT_INITIAL_LEN } else { 0 };
        let used = {
            let crypto = self.crypto.read();
            packet::seal_long_header_packet(
                &crypto,
                &mut header,
                pn,
                pn_len,
                header_reserve,
                payload_len,
                min_total,
                out,
            )?
        };
        self.advance_send_packet_number(space_idx)?;
        self.pending_control.remove(close_index);
        self.stats.sent = self.stats.sent.saturating_add(1);
        self.stats.sent_bytes = self.stats.sent_bytes.saturating_add(used as u64);
        Ok((
            used,
            SendInfo {
                at: self.clock.now(),
                from: self.local_addr,
                to: self.peer_addr,
                congestion_controlled: false,
                path_control: false,
                bulk_only: false,
            },
        ))
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
        if self.is_closed {
            if self.tls_provider.is_some()
                && !self.version_negotiation.peer_information_validated
                && self
                    .pending_control
                    .iter()
                    .any(|frame| matches!(frame, Frame::ConnectionClose { .. }))
            {
                if datagram_overhead != 0 {
                    return Err(ConnectionError::InvalidState);
                }
                return self.send_pre_validation_close(out);
            }
            if !self.pending_control.iter().any(|frame| {
                matches!(frame, Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. })
            }) {
                return Err(ConnectionError::Done);
            }
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
        let now = self.clock.now();
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
                && !self.admitted_batch_frames.iter().any(|frame| frame.pmtu_probe_size.is_some())
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
        // ACK-only packets bypass the gate (RFC 9002 sec. 7.2) to prevent
        // congestion-control deadlocks where both sides exhaust their windows
        // and neither can send ACKs to release budget.
        let congestion_blocked = !self
            .recovery
            .can_send(self.dgram_send_max_size.saturating_add(self.admitted_batch_reserved));
        log::trace!("send_with_datagram_overhead congestion gate: recovery.bytes_in_flight={} recovery.cwnd={} dgram_send_max_size={} congestion_blocked={}",
            self.recovery.bytes_in_flight, self.recovery.cwnd, self.dgram_send_max_size, congestion_blocked);
        let mut congestion_bypass = congestion_blocked && self.has_pending_application_ack();
        let mut pmtu_probe_bypassed_congestion = false;
        if congestion_blocked && !congestion_bypass {
            // RFC 9002 sec. 7.5/sec. 6.2.4: PTO probes MUST NOT be blocked by the
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

        let handshake_incomplete = !self.tls_handshake_complete();

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
                let mut base_hdr = packet::Header {
                    ty: pkt_ty,
                    version: self.config.version,
                    dcid: self.dcid.to_vec(),
                    scid: self.scid.to_vec(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token,
                    versions: None,
                    key_phase: false,
                    length: None,
                };
                let space_idx = match pkt_ty {
                    PacketType::Initial => 0,
                    PacketType::Handshake => 1,
                    _ => 2,
                };
                let pn = self.next_send_packet_number(space_idx)?;
                let pn_len = if pn < (1 << 8) {
                    1
                } else if pn < (1 << 16) {
                    2
                } else if pn < (1 << 24) {
                    3
                } else {
                    4
                };
                // Reserve worst-case header+PN space. seal_long_header_packet
                // resolves the RFC Length, rewrites the compact header and
                // seals once with the final packet-number offset.
                let header_reserve = packet::long_header_reserve(&base_hdr)?;
                if out.len() < header_reserve {
                    return Err(ConnectionError::BufferTooShort);
                }
                let mut off = header_reserve;

                // The CRYPTO data budget must reserve room for everything written into
                // the same packet *after* the data: the AEAD tag (16), the CRYPTO frame
                // header (type 1 + offset varint <=8 + length varint <=8), and the ACK/PING
                // frames added below. Without this reserve, next_crypto_frame() returns up
                // to `out.len() - off - 16` bytes, the framed packet overflows the buffer
                // and the seal fails with BufferTooShort. (Since the CRYPTO retention
                // buffer keeps drained bytes unacked, a failed seal no longer loses the
                // data - but the oversized write would still error out every send.)
                const SEND_FRAME_OVERHEAD_RESERVE: usize = 64;
                let crypto_budget =
                    out.len().saturating_sub(off + 16 + SEND_FRAME_OVERHEAD_RESERVE);
                let (lvl, max_len) = match pkt_ty {
                    PacketType::Initial => {
                        (qf_transport_types::QuicEncryptionLevel::Initial, crypto_budget)
                    }
                    PacketType::Handshake => {
                        (qf_transport_types::QuicEncryptionLevel::Handshake, crypto_budget)
                    }
                    _ => (qf_transport_types::QuicEncryptionLevel::Application, crypto_budget),
                };
                if max_len < 32 {
                    continue;
                }
                {
                    let crypto = self.crypto.read();
                    packet::preflight_outgoing_packet_keys(&crypto, pkt_ty, pn)?;
                }
                let crypto_frame = self.next_crypto_frame(lvl, max_len)?;
                let probe_pos = self
                    .pending_probe_spaces
                    .iter()
                    .position(|s| *s == recovery::PacketSpace::from_index(space_idx));
                let pending_ack = self.pkt_spaces[space_idx].has_pending_ack_at(now);
                if crypto_frame.is_none() && probe_pos.is_none() && !pending_ack {
                    continue;
                }
                // Handshake/Initial ACK must go out even after CRYPTO is drained.
                // Otherwise Finished is never acknowledged, the client keeps
                // Handshake PTO forever, and 1-RTT throughput stalls.
                let ack_only = crypto_frame.is_none() && probe_pos.is_none();
                // RFC 9002 sec. 6.2.4: a PTO probe for this space. The packet below
                // always carries PING (ack-eliciting), plus retransmitted or
                // fresh CRYPTO when available. Client Initial probes stay
                // padded to >= 1200 bytes (sec. 6.2.2.1) via target_total below.
                if let Some(pos) = probe_pos {
                    self.pending_probe_spaces.remove(pos);
                }
                let crypto_range = crypto_frame.as_ref().map(|(o, d)| (*o, d.len() as u64));

                // Inspect without consuming. The capacity check below can reject the frame and
                // `to_bytes` can fail; either would otherwise discard a pending ACK that no
                // further inbound packet is guaranteed to re-trigger.
                let mut wrote_handshake_ack = false;
                if let Some((ack_delay, ack_ranges)) =
                    self.pkt_spaces[space_idx].peek_ack_at(self.config.ack_delay_exponent, now)
                {
                    let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: None };
                    let need = frames::wire_len(&ack)?;
                    if out.len().saturating_sub(off) >= need.saturating_add(16) {
                        off += frames::to_bytes(&ack, &mut out[off..])?;
                        // Committed only now that the bytes are in the packet.
                        self.pkt_spaces[space_idx].commit_ack_at(now);
                        wrote_handshake_ack = true;
                    }
                }
                if ack_only && !wrote_handshake_ack {
                    continue;
                }
                if !ack_only {
                    let ping = Frame::Ping { mtu_probe: None };
                    off += frames::to_bytes(&ping, &mut out[off..])?;
                    if let Some((crypto_off, data)) = crypto_frame {
                        let frame = Frame::Crypto { offset: crypto_off, data: Cow::Owned(data) };
                        let written = frames::to_bytes(&frame, &mut out[off..])?;
                        off += written;
                    }
                }

                // RFC 9000 section 14.1 keeps client Initials at the 1200-byte
                // minimum; the seal path resolves the final Length varint and
                // pads with PADDING frames accordingly.
                let payload_len = off - header_reserve;
                let min_total =
                    if matches!(pkt_ty, PacketType::Initial) { MIN_CLIENT_INITIAL_LEN } else { 0 };
                let used = {
                    let crypto = self.crypto.read();
                    packet::seal_long_header_packet(
                        &crypto,
                        &mut base_hdr,
                        pn,
                        pn_len,
                        header_reserve,
                        payload_len,
                        min_total,
                        out,
                    )?
                };

                trace_send_packet(
                    self.is_server,
                    pkt_ty,
                    space_idx,
                    pn,
                    pn_len,
                    header_reserve,
                    used,
                );
                self.advance_send_packet_number(space_idx)?;
                self.stats.sent += 1;
                self.stats.sent_bytes += used as u64;
                // RFC 9002 sec. 4.9: handshake packets are not special - they are
                // tracked for loss recovery exactly like 1-RTT packets.
                // ACK-only Handshake/Initial packets are not ack-eliciting and
                // must not occupy the congestion window.
                if !ack_only {
                    self.recovery.on_packet_sent_in_space(
                        recovery::PacketSpace::from_index(space_idx),
                        pn,
                        used,
                        true,
                        true,
                        crypto_range,
                        now,
                    );
                }
                if self.is_server
                    && matches!(pkt_ty, PacketType::Handshake)
                    && wrote_handshake_ack
                    && self.tls_handshake_complete()
                    && !self.pkt_spaces[space_idx].has_pending_ack_at(now)
                {
                    self.discard_handshake_packet_protection();
                }
                if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
                    self.is_established = true;
                }
                if let Some(ledger) = self.wire_ledger.as_mut() {
                    ledger.note_wire_send(now);
                }
                return Ok((
                    used,
                    SendInfo {
                        at: now,
                        from: self.local_addr,
                        to: self.peer_addr,
                        congestion_controlled: !ack_only,
                        path_control: false,
                        bulk_only: false,
                    },
                ));
            }

            // No pending Initial/Handshake CRYPTO to send. While the handshake
            // is still in progress a client with installed 0-RTT keys may emit
            // early STREAM data in a ZeroRTT packet; otherwise there is
            // nothing else to do this turn. Once the handshake completes we
            // fall through to the 1-RTT path below.
            if handshake_incomplete {
                if !self.is_server && !self.retry_accepted {
                    let zero_rtt_seal_ready = {
                        let crypto = self.crypto.read();
                        crypto.seal_0rtt.is_some() && crypto.hp_0rtt.is_some()
                    };
                    if zero_rtt_seal_ready && self.has_sendable_early_stream_frame() {
                        return self.send_zero_rtt_packet(out, now);
                    }
                }
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
        let pn = self.next_send_packet_number(2)?;
        let hdr_len = packet::format_short_header(self.dcid.as_ref(), false, out)?; // first byte + DCID
        let dcid_end = 1 + self.dcid.as_ref().len();
        // Decide packet number and length
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
        // Per RFC 9002 sec. 7.2, only packets containing ack-eliciting frames are
        // congestion-controlled. Non-ack-eliciting frames: PADDING, ACK,
        // CONNECTION_CLOSE, APPLICATION_CLOSE. All others (STREAM, DATAGRAM,
        // CRYPTO, PING, MAX_DATA, NEW_CONNECTION_ID, etc.) are ack-eliciting.
        let mut wrote_ack_eliciting = false;
        let mut staged_stream = None;
        let mut staged_datagram = false;
        let mut staged_bulk = false;
        let mut packet_contents = recovery::SentPacketContents::default();
        let mut staged_controls = Vec::new();
        let mut staged_terminal_close = false;
        let mut staged_ack = None;
        let mut staged_probe_index = None;
        let mut staged_wire_spend = 0u64;

        // Post-handshake Application-level CRYPTO (e.g. NewSessionTicket) is not
        // emitted here. The early return above guarantees `handshake_incomplete`
        // is false at this point, so any Application CRYPTO would be
        // post-handshake and should be flushed via a dedicated path that
        // respects flow control and the congestion window. The previous
        // `if handshake_incomplete` block was unreachable dead code.

        if !dedicated_pmtu_probe {
            let controls = self.stage_pending_control_frames(
                out,
                off,
                congestion_bypass,
                &self.admitted_batch_control_indices,
            )?;
            off = controls.end;
            wrote_ack_eliciting |= controls.ack_eliciting;
            packet_contents.control |= controls.ack_eliciting;
            staged_controls = controls.indices;
            staged_terminal_close = controls.terminal_close;
            let prior_ack =
                self.admitted_batch_frames.iter().any(|frame| frame.staged_ack.is_some());
            let (ack_end, ack) = self.maybe_stage_application_ack_frame(out, off, prior_ack)?;
            off = ack_end;
            staged_ack = ack;
            // RFC 9002 sec. 6.2.4: emit one ack-eliciting PING per pending
            // Application-space PTO probe. Written directly (not via
            // pending_control) so it also fires when the congestion gate was
            // bypassed for the probe; stream/datagram payloads stay gated.
            let prior_probes = self
                .admitted_batch_frames
                .iter()
                .filter(|frame| frame.staged_probe_index.is_some())
                .count();
            if let Some(pos) = self
                .pending_probe_spaces
                .iter()
                .enumerate()
                .filter(|(_, space)| **space == recovery::PacketSpace::Application)
                .nth(prior_probes)
                .map(|(index, _)| index)
            {
                let ping = Frame::Ping { mtu_probe: None };
                let tag_reserve = self.tag_reserve_1rtt();
                let ping_len = frames::wire_len(&ping)?;
                if out.len().saturating_sub(off) >= ping_len.saturating_add(tag_reserve) {
                    off += frames::to_bytes(&ping, &mut out[off..])?;
                    staged_probe_index = Some(pos);
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
                let (off_after_stream, stream_frame) =
                    self.stage_next_stream_frame(&mut out[..stream_limit], off, false)?;
                off = off_after_stream;
                let stream_ack_eliciting = stream_frame.is_some();
                wrote_ack_eliciting |= stream_ack_eliciting;
                packet_contents.stream |= stream_ack_eliciting;
                packet_contents.stream_retransmission |=
                    matches!(stream_frame, Some(super::state::StagedStreamFrame::Retained { .. }));
                staged_stream = stream_frame;
                // FEC feed removed (handled by core)
                let (off_after_dgram, staged_class) =
                    self.maybe_stage_one_datagram_frame(out, off)?;
                off = off_after_dgram;
                let dgram_ack_eliciting = staged_class.is_some();
                wrote_ack_eliciting |= dgram_ack_eliciting;
                staged_datagram = dgram_ack_eliciting;
                staged_bulk = staged_class == Some(crate::transport::DatagramClass::Bulk);
                packet_contents.datagram |= dgram_ack_eliciting;
            }
        }
        // DPLPMTUD probe (TODO-451): when the PMTU state machine requests a
        // probe and the current packet has no ack-eliciting payload (otherwise
        // the real data already serves as a probe), inject a PING frame and pad
        // the packet up to the probe target size. The probe is ack-eliciting so
        // the peer's ACK confirms the larger MTU. We only probe when the buffer
        // can hold the probe size (the caller's buffer is typically >= PMTU_MAX).
        let mut pmtu_probe_size = None;
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
                pmtu_probe_size = Some(probe_size);
            }
        }
        // A due traffic-analysis slot emits chaff only when the packet remains
        // completely empty. ACK-only, control, stream, DATAGRAM, recovery, and
        // PMTU traffic always win and cover the slot without being converted
        // into an ack-eliciting chaff packet.
        let packet_has_real_frames = off > pn_off + pn_len;
        let mut emitted_chaff = false;
        if !packet_has_real_frames
            && !congestion_bypass
            && !dedicated_pmtu_probe
            && self.admitted_batch_frames.is_empty()
        {
            let tag_reserve = self.tag_reserve_1rtt();
            let chaff_size = self
                .traffic_analysis
                .as_ref()
                .filter(|scheduler| scheduler.has_pending_chaff())
                .map(|scheduler| scheduler.chaff_size_bytes())
                .unwrap_or(0);
            if chaff_size > 0 {
                // The PING byte lands before the pad: `needed` must leave
                // room for it or the sealed packet outgrows chaff_size.
                let avail = out.len().saturating_sub(off + 1 + tag_reserve);
                let needed = (chaff_size as usize).saturating_sub(off + 1 + tag_reserve);
                let pad_len = needed.min(avail);
                // TODO-1052: a chaff packet is cover-class spend - the
                // ledger pays the whole wire image (header + PING + pad +
                // tag) before it is emitted. A denied chaff stays pending
                // for the next slot; it is never sent over the cap.
                let wire_len = (off + 1 + pad_len + tag_reserve) as u64;
                if self.can_stage_wire_spend(
                    wire_len,
                    self.admitted_batch_wire_reserved.saturating_add(staged_wire_spend),
                    now,
                ) {
                    use crate::transport::Frame;
                    let ping = Frame::Ping { mtu_probe: None };
                    off += crate::transport::frames::to_bytes(&ping, &mut out[off..])?;
                    wrote_ack_eliciting = true;
                    emitted_chaff = true;
                    packet_contents.control = true;
                    if self.wire_ledger.is_some() {
                        staged_wire_spend = staged_wire_spend.saturating_add(wire_len);
                    }
                    if pad_len > 0 {
                        off += crate::transport::frames::write_padding(pad_len, &mut out[off..])?;
                    }
                }
            }
        }
        if off == pn_off + pn_len {
            log::trace!("send_with_datagram_overhead: off==pn_off+pn_len, returning Done; dgram_queue_len={} pending_control={} application_ack={} writable_streams={} probe_spaces={}",
                self.dgram_send_queue.len(), self.pending_control.len(), self.has_pending_application_ack(), self.writable_streams.len(), self.pending_probe_spaces.len());
            return Err(ConnectionError::Done);
        }
        let prior_pad_target =
            self.admitted_batch_frames.iter().any(|frame| frame.staged_pad_target);
        let (padded_end, staged_pad_target, pad_spend) = self.maybe_apply_stealth_padding(
            out,
            pn_off,
            pn_len,
            off,
            self.admitted_batch_wire_reserved.saturating_add(staged_wire_spend),
            !prior_pad_target,
        )?;
        off = padded_end;
        staged_wire_spend = staged_wire_spend.saturating_add(pad_spend);
        let frame = AdmittedShortHeader {
            pn,
            pn_off,
            pn_len,
            plaintext_end: off,
            staged_datagram,
            staged_controls,
            staged_terminal_close,
            staged_ack,
            staged_probe_index,
            staged_pad_target,
            staged_wire_spend,
            emitted_chaff,
            wrote_ack_eliciting,
            staged_stream,
            packet_contents,
            pmtu_probe_size,
            pmtu_probe_bypassed_congestion,
            staged_bulk,
            datagram_overhead,
            now,
        };
        if self.admitted_batch_defer {
            off = self.layout_short_header_plaintext(out, pn, pn_off, pn_len, off)?;
            self.advance_send_packet_number(2)?;
            if staged_datagram {
                self.admitted_batch_dgram_skip = self.admitted_batch_dgram_skip.saturating_add(1);
            }
            self.admitted_batch_control_indices.extend(frame.staged_controls.iter().copied());
            self.admitted_batch_control_indices.sort_unstable();
            self.admitted_batch_wire_reserved =
                self.admitted_batch_wire_reserved.saturating_add(frame.staged_wire_spend);
            let mut deferred = frame;
            deferred.plaintext_end = off;
            self.admitted_batch_frames.push(deferred);
            return Ok((
                off,
                SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: wrote_ack_eliciting,
                    path_control: false,
                    bulk_only: staged_bulk && !packet_contents.control && !packet_contents.stream,
                },
            ));
        }
        if let Some(stream_frame) = &frame.staged_stream {
            self.preflight_staged_stream_frames(&[(pn, stream_frame)])?;
        }
        off = self.seal_short_header_packet(out, pn, pn_off, pn_len, off)?;
        self.commit_staged_short_header_effects(std::slice::from_ref(&frame))?;
        let info = self.account_admitted_short_header(off, &frame);
        if let Some(ledger) = self.wire_ledger.as_mut() {
            ledger.note_wire_send(now);
        }
        Ok((off, info))
    }

    /// Frame up to eight already-admitted 1-RTT packets and seal them with one
    /// `seal_batch`. Handshake flights stay on the single-packet path. A seal
    /// failure leaves DATAGRAM and STREAM source ownership in place; packet
    /// numbers already taken are not reused.
    pub(crate) fn send_admitted_batch(
        &mut self,
        outs: &mut [&mut [u8]],
        datagram_overhead: usize,
    ) -> Result<Vec<(usize, SendInfo)>, crate::error::ConnectionError> {
        const MAX_ADMITTED_SEAL: usize = 8;
        if self.admitted_batch_defer {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.admitted_batch_defer = true;
        self.admitted_batch_reserved = 0;
        self.admitted_batch_dgram_skip = 0;
        self.admitted_batch_frames.clear();
        self.admitted_batch_control_indices.clear();
        self.admitted_batch_wire_reserved = 0;

        let mut sealed_now: Vec<(usize, SendInfo)> = Vec::new();
        let limit = outs.len().min(MAX_ADMITTED_SEAL);
        let mut build_error = None;
        for out in outs.iter_mut().take(limit) {
            let before = self.admitted_batch_frames.len();
            match self.send_with_datagram_overhead(out, datagram_overhead) {
                Ok((len, info)) => {
                    if self.admitted_batch_frames.len() > before {
                        if self
                            .admitted_batch_frames
                            .last()
                            .is_some_and(|frame| frame.wrote_ack_eliciting)
                        {
                            self.admitted_batch_reserved = self
                                .admitted_batch_reserved
                                .saturating_add(self.dgram_send_max_size);
                        }
                        if self
                            .admitted_batch_frames
                            .last()
                            .is_some_and(|frame| frame.staged_terminal_close)
                        {
                            break;
                        }
                    } else {
                        sealed_now.push((len, info));
                        break;
                    }
                }
                Err(crate::error::ConnectionError::Done) => break,
                Err(error) => {
                    build_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = build_error {
            self.abort_admitted_batch();
            return Err(error);
        }
        if self.admitted_batch_frames.is_empty() {
            self.admitted_batch_defer = false;
            self.admitted_batch_reserved = 0;
            return Ok(sealed_now);
        }
        let frames = std::mem::take(&mut self.admitted_batch_frames);
        let framed_len = frames.len();
        let staged_streams: smallvec::SmallVec<[_; 8]> = frames
            .iter()
            .filter_map(|frame| frame.staged_stream.as_ref().map(|stream| (frame.pn, stream)))
            .collect();
        let seal_result = self
            .preflight_staged_stream_frames(&staged_streams)
            .and_then(|()| self.seal_prepared_short_headers(&mut outs[..framed_len], &frames));
        drop(staged_streams);
        self.admitted_batch_defer = false;
        self.admitted_batch_reserved = 0;
        self.admitted_batch_dgram_skip = 0;
        self.admitted_batch_control_indices.clear();
        self.admitted_batch_wire_reserved = 0;
        let sealed_lengths = seal_result?;
        self.commit_staged_short_header_effects(&frames)?;
        let mut produced = Vec::with_capacity(sealed_now.len() + sealed_lengths.len());
        produced.extend(sealed_now);
        for (total, frame) in sealed_lengths.into_iter().zip(frames) {
            let info = self.account_admitted_short_header(total, &frame);
            if let Some(ledger) = self.wire_ledger.as_mut() {
                ledger.note_wire_send(frame.now);
            }
            produced.push((total, info));
        }
        Ok(produced)
    }

    fn abort_admitted_batch(&mut self) {
        self.admitted_batch_defer = false;
        self.admitted_batch_reserved = 0;
        self.admitted_batch_dgram_skip = 0;
        self.admitted_batch_frames.clear();
        self.admitted_batch_control_indices.clear();
        self.admitted_batch_wire_reserved = 0;
    }

    /// Emit one 0-RTT packet from a complete stream message explicitly marked
    /// replay-safe by the application. This path is client-only.
    ///
    /// 0-RTT shares the Application packet-number space with 1-RTT. Rejected
    /// early-data transmissions are requeued through ordinary stream recovery.
    /// DATAGRAM frames and unmarked streams, including the VPN tunnel stream,
    /// are never offered early.
    pub(super) fn send_zero_rtt_packet(
        &mut self,
        out: &mut [u8],
        now: std::time::Instant,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let mut base_hdr = packet::Header {
            ty: PacketType::ZeroRTT,
            version: self.config.version,
            dcid: self.dcid.to_vec(),
            scid: self.scid.to_vec(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
            length: None,
        };
        let space_idx = 2; // Application space; shared with 1-RTT per RFC 9001.
        let pn = self.next_send_packet_number(space_idx)?;
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        // Reserve worst-case header+PN space. seal_long_header_packet resolves
        // the RFC Length, rewrites the compact header and seals once.
        let header_reserve = packet::long_header_reserve(&base_hdr)?;
        if out.len() < header_reserve {
            return Err(ConnectionError::BufferTooShort);
        }
        let mut off = header_reserve;

        let (off_after_stream, staged_stream) = self.stage_next_stream_frame(out, off, true)?;
        off = off_after_stream;
        if staged_stream.is_none() {
            // Nothing could be staged after all, so return Done rather than
            // emitting an empty early-data packet.
            return Err(ConnectionError::Done);
        }
        let payload_len = off - header_reserve;

        if let Some(stream_frame) = &staged_stream {
            self.preflight_staged_stream_frames(&[(pn, stream_frame)])?;
        }

        let used = {
            let crypto = self.crypto.read();
            packet::seal_long_header_packet(
                &crypto,
                &mut base_hdr,
                pn,
                pn_len,
                header_reserve,
                payload_len,
                0,
                out,
            )?
        };

        trace_send_packet(
            self.is_server,
            PacketType::ZeroRTT,
            space_idx,
            pn,
            pn_len,
            header_reserve,
            used,
        );
        self.advance_send_packet_number(space_idx)?;
        if let Some(stream_frame) = &staged_stream {
            self.commit_staged_stream_frames(&[(pn, stream_frame)])?;
        }
        self.stats.sent += 1;
        self.stats.sent_bytes += used as u64;
        self.recovery.on_packet_sent_in_space(
            recovery::PacketSpace::from_index(space_idx),
            pn,
            used,
            true,
            true,
            None,
            now,
        );
        self.bytes_in_flight = self.recovery.bytes_in_flight;
        self.cwnd = self.recovery.cwnd;
        if self.bytes_in_flight_started.is_none() {
            self.bytes_in_flight_started = Some(now);
        }
        self.pmtu.on_packet_sent(used, now);
        if used > self.pmtu.min_mtu() {
            self.pmtu_above_floor_pns.insert(pn);
        }
        self.zero_rtt_sent_pns.insert(pn);
        if let Some(ledger) = self.wire_ledger.as_mut() {
            ledger.note_wire_send(now);
        }
        Ok((
            used,
            SendInfo {
                at: now,
                from: self.local_addr,
                to: self.peer_addr,
                congestion_controlled: true,
                path_control: false,
                bulk_only: false,
            },
        ))
    }

    fn account_admitted_short_header(
        &mut self,
        total: usize,
        frame: &AdmittedShortHeader,
    ) -> SendInfo {
        if let Some(scheduler) = self.traffic_analysis.as_mut() {
            if frame.emitted_chaff {
                scheduler.record_chaff_emitted();
            } else {
                scheduler.record_cover_packet(
                    frame.now,
                    frame.packet_contents.stream || frame.packet_contents.datagram,
                );
            }
        }
        if total > frame.pn_off + frame.pn_len && self.bytes_in_flight_started.is_none() {
            self.bytes_in_flight_started = Some(frame.now);
        }
        self.refresh_path_count();
        let info = SendInfo {
            from: self.local_addr,
            to: self.peer_addr,
            at: frame.now,
            congestion_controlled: frame.wrote_ack_eliciting,
            path_control: false,
            bulk_only: frame.staged_bulk
                && !frame.packet_contents.control
                && !frame.packet_contents.stream,
        };
        self.stats.sent += 1;
        self.stats.sent_bytes += total as u64;
        if frame.wrote_ack_eliciting {
            if frame.pmtu_probe_size.is_some() && frame.pmtu_probe_bypassed_congestion {
                self.recovery.on_pmtu_probe_sent_in_space(
                    recovery::PacketSpace::Application,
                    frame.pn,
                    total,
                    frame.now,
                );
            } else {
                self.recovery.on_packet_sent_with_contents_in_space(
                    recovery::PacketSpace::Application,
                    frame.pn,
                    total,
                    true,
                    true,
                    None,
                    frame.packet_contents,
                    frame.now,
                );
            }
            let outer_datagram_size = total.saturating_add(frame.datagram_overhead);
            self.pmtu.on_packet_sent(outer_datagram_size, frame.now);
            if outer_datagram_size > self.pmtu.min_mtu() {
                self.pmtu_above_floor_pns.insert(frame.pn);
            }
            self.cwnd = self.recovery.cwnd;
        }
        info
    }

    fn commit_staged_short_header_effects(
        &mut self,
        frames: &[AdmittedShortHeader],
    ) -> Result<(), crate::error::ConnectionError> {
        use crate::error::ConnectionError;

        let staged_datagrams = frames.iter().filter(|frame| frame.staged_datagram).count();
        if staged_datagrams > self.dgram_send_queue.len()
            || frames.iter().filter(|frame| frame.staged_ack.is_some()).count() > 1
            || frames.iter().filter(|frame| frame.pmtu_probe_size.is_some()).count() > 1
        {
            return Err(ConnectionError::InvalidState);
        }
        let mut control_indices: Vec<usize> =
            frames.iter().flat_map(|frame| frame.staged_controls.iter().copied()).collect();
        control_indices.sort_unstable();
        if control_indices.last().is_some_and(|index| *index >= self.pending_control.len())
            || control_indices.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ConnectionError::InvalidState);
        }
        let mut probe_indices: Vec<usize> =
            frames.iter().filter_map(|frame| frame.staged_probe_index).collect();
        probe_indices.sort_unstable();
        if probe_indices.last().is_some_and(|index| *index >= self.pending_probe_spaces.len())
            || probe_indices.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ConnectionError::InvalidState);
        }

        if let Some(ledger) = self.wire_ledger.as_mut() {
            let spends: Vec<_> = frames
                .iter()
                .filter(|frame| frame.staged_wire_spend > 0)
                .map(|frame| (frame.staged_wire_spend, frame.now))
                .collect();
            if !ledger.commit_staged_spends(&spends) {
                return Err(ConnectionError::InvalidState);
            }
        }

        let staged_streams: smallvec::SmallVec<[_; 8]> = frames
            .iter()
            .filter_map(|frame| frame.staged_stream.as_ref().map(|stream| (frame.pn, stream)))
            .collect();
        self.commit_staged_stream_frames(&staged_streams)?;

        for _ in 0..staged_datagrams {
            self.commit_staged_datagram_frame()?;
        }

        for index in control_indices.into_iter().rev() {
            self.pending_control.remove(index);
        }
        for index in probe_indices.into_iter().rev() {
            self.pending_probe_spaces.remove(index);
        }
        for frame in frames {
            if frame.staged_pad_target {
                self.pad_short_header_to = None;
            }
            if let Some(ack) = &frame.staged_ack {
                self.commit_staged_application_ack(ack);
            }
            if let Some(size) = frame.pmtu_probe_size {
                self.pmtu.on_probe_sent(size, frame.now);
                self.pmtu_probe_pn = Some(frame.pn);
            }
        }
        Ok(())
    }

    /// Install or replace the shared wire byte ledger (TODO-1052).
    pub fn set_wire_ledger(&mut self, ledger: Option<qf_stealth::BudgetLedger>) {
        self.wire_ledger = ledger;
    }

    /// Borrow the installed wire ledger mutably (crate-internal; tests).
    #[cfg(test)]
    pub(crate) fn wire_ledger_mut(&mut self) -> Option<&mut qf_stealth::BudgetLedger> {
        self.wire_ledger.as_mut()
    }

    /// Atomically ask the ledger to pay `bytes` for a repair datagram.
    /// `true` = paid, the caller may emit; `false` = denied, the caller
    /// must drop or delay the repair - repairs are never sent over the
    /// cap. Without an installed ledger the spend always succeeds
    /// (off/performance carry no stealth budget).
    pub(crate) fn try_spend_wire_repair(&mut self, bytes: u64) -> bool {
        match self.wire_ledger.as_mut() {
            Some(ledger) => ledger.try_spend(bytes, self.clock.now()),
            None => true,
        }
    }

    /// Atomically ask the ledger to pay `bytes` for cover traffic
    /// (cover PING datagram etc.). Same contract as
    /// [`Self::try_spend_wire_repair`].
    pub(crate) fn try_spend_wire_cover(&mut self, bytes: u64) -> bool {
        match self.wire_ledger.as_mut() {
            Some(ledger) => ledger.try_spend(bytes, self.clock.now()),
            None => true,
        }
    }

    pub(crate) fn can_stage_wire_spend(&mut self, bytes: u64, reserved: u64, now: Instant) -> bool {
        self.wire_ledger.as_mut().is_none_or(|ledger| ledger.can_stage_spend(bytes, reserved, now))
    }

    /// Ask the persona trace whether a client packet is due now and the
    /// shared budget can pay for it (TODO-1054). Returns the captured wire
    /// length the PING datagram must be padded to - the caller pads via
    /// `set_short_header_pad_target` - or `None` to stay silent. Ledgerless
    /// connections (`off`/`performance`) have no trace and never answer
    /// `Some`.
    pub(crate) fn cover_ping_due(&mut self) -> Option<u64> {
        self.wire_ledger.as_mut()?.cover_ping_due(self.clock.now())
    }

    /// Whether an idle-timeout keepalive PING is due (TODO-1054 risk):
    /// when the peer has been silent past `max_idle_timeout/2`, emit one
    /// PING so the connection survives a trace that is quieter than the
    /// idle horizon. Fires once per silent stretch - the mark re-arms only
    /// when inbound activity resumes. This is a keepalive, not mimicry;
    /// the caller still has to pay it from the wire budget.
    pub(crate) fn idle_keepalive_due(&mut self) -> bool {
        let Some(window) = self.timeout() else { return false };
        if self.clock.elapsed_since(self.last_activity) < window / 2 {
            return false;
        }
        if self.idle_keepalive_mark == Some(self.last_activity) {
            return false;
        }
        self.idle_keepalive_mark = Some(self.last_activity);
        true
    }

    /// Compute stealth padding length given current plaintext payload length and budget.
    ///
    /// - With a `BudgetLedger` installed (TODO-1052): the ledger is the only
    ///   padding authority - persona-trace classes or fixed cell, capped by
    ///   the remaining shared allowance.
    /// - `TrafficAnalysisDefense::FullPadding`/`ConstantRate`: always pad to
    ///   the full available budget (no rate gating).
    /// - Otherwise: legacy probabilistic strategy dispatch gated by
    ///   `stealth_padding_rate`.
    #[inline(always)]
    pub(crate) fn compute_stealth_padding(&mut self, cur_pt_len: usize, budget: usize) -> usize {
        // Traffic analysis defense modes take precedence over the legacy
        // probabilistic path. They never skip padding based on rate.
        match self.config.traffic_analysis_defense {
            TrafficAnalysisDefense::FullPadding | TrafficAnalysisDefense::ConstantRate => {
                return budget;
            }
            TrafficAnalysisDefense::Off => {}
        }

        // TODO-1052: when a wire ledger is installed it is the only padding
        // authority. It replays the persona's captured length classes (or
        // the fixed cell), enforces the shared per-second/burst cap, and
        // returns 0 when exhausted or when no class fits - the packet
        // then goes out at its natural length. The `stealth_padding_rate`
        // RNG gate is dead under the ledger: the cap is the only throttle.
        if let Some(ledger) = self.wire_ledger.as_mut() {
            // `stealth_padding_max_size` belongs to the dead strategy
            // model - under the ledger the allowance and the physical
            // space left in the datagram are the only bounds.
            let max = budget;
            if max == 0 || !self.config.stealth_padding_enabled {
                return 0;
            }
            return ledger.padding_target(cur_pt_len, max, self.clock.now());
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

    pub(super) fn try_advance_read_keys(&mut self) -> Result<bool, crate::error::ConnectionError> {
        if let Some(provider) = self.tls_provider.as_mut() {
            provider.key_update_read(&*self.crypto)?;
            // The rustls provider rotated the transport-owned read key through the installer.
            // Sync the lock-free ArcSwap so the hot path picks up the new key.
            self.sync_1rtt();
            return Ok(true);
        }
        let updated = self.crypto.write().key_update_1rtt_read()?;
        if updated {
            self.sync_1rtt();
        }
        Ok(updated)
    }
}
