//! Outbound packet scheduling, FEC framing, and pacing for a core connection.

use super::*;

impl QuicFuscateConnection {
    /// Earliest outgoing release imposed by the pacing or stealth scheduler.
    pub fn next_outbound_release_deadline(&self) -> Option<Instant> {
        [self.outbound_pacer.next_release(), self.next_packet_release].into_iter().flatten().min()
    }

    /// Earliest instant the caller should poll `send` again.
    ///
    /// This merges outer pacing, stealth release, QUIC recovery, and the one
    /// transport-owned traffic-analysis deadline.
    pub fn next_send_deadline(&self) -> Option<Instant> {
        [
            self.next_outbound_release_deadline(),
            self.conn.recovery_deadline(),
            self.conn.traffic_analysis_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Queue one ack-eliciting transport keepalive for the next send poll.
    pub fn queue_keepalive_ping(&mut self) {
        self.conn.queue_cover_ping();
    }

    /// Atomically change the operator-owned FEC policy for this live connection.
    ///
    /// The existing connection mutex serializes this command with lifecycle,
    /// Brain feedback, loss feedback, send, and receive. Source datagrams already
    /// owned by the output queue remain byte-identical; repair-only datagrams are
    /// retired before the command is acknowledged. Both codec directions restart
    /// from empty state so Auto never inherits stale Off-era or prior-Auto evidence.
    pub fn set_fec_control_policy(
        &mut self,
        policy: crate::fec::FecControlPolicy,
    ) -> ActiveFecPolicyChange {
        let previous_policy = self.fec.control_policy();
        if previous_policy == policy {
            return ActiveFecPolicyChange {
                controller: self.fec.set_control_policy(policy),
                queued_sources_preserved: self
                    .outgoing_fec_packets
                    .iter()
                    .filter(|packet| packet.wire_meta.is_none_or(|meta| meta.systematic))
                    .count(),
                queued_repairs_discarded: 0,
            };
        }

        let queued_before = self.outgoing_fec_packets.len();
        self.outgoing_fec_packets
            .retain(|packet| packet.wire_meta.is_none_or(|meta| meta.systematic));
        let queued_sources_preserved = self.outgoing_fec_packets.len();
        let queued_repairs_discarded = queued_before.saturating_sub(queued_sources_preserved);

        self.fec_send_scratch.clear();
        self.fec_receive_scratch.clear();
        let mut wire_receiver =
            WireFecReceiver::new(self.optimization_manager.memory_pool().clone());
        if let Some(seed) = self.fec_rx_seed {
            wire_receiver.set_fountain_seed(seed);
        }
        self.fec_wire_receiver = wire_receiver;
        self.fec_tx_profile = None;
        self.fec_tx_sequence = 0;
        self.fec_tx_active = false;

        ActiveFecPolicyChange {
            controller: self.fec.set_control_policy(policy),
            queued_sources_preserved,
            queued_repairs_discarded,
        }
    }

    fn prepare_fec_wire_profile(
        &mut self,
    ) -> Result<Option<WireProfile>, crate::error::ConnectionError> {
        if self.fec_tx_seed.is_none() {
            if let Some(seed) = self.conn.fec_send_fountain_seed() {
                self.fec.set_fountain_seed(seed);
                self.fec_tx_seed = Some(seed);
            }
        }
        let candidate = match self.fec.wire_profile(self.fec_tx_epoch.max(1)) {
            Ok(profile) => profile,
            Err(wire::WireError::ZeroModeMustRemainRaw) => {
                self.fec_tx_active = false;
                return Ok(None);
            }
            Err(error) => {
                return Err(crate::error::ConnectionError::Transport(error.to_string()));
            }
        };
        let shape_changed = self.fec_tx_profile.is_some_and(|previous| {
            previous.codec != candidate.codec
                || previous.source_count != candidate.source_count
                || previous.total_count != candidate.total_count
                || previous.interleave_depth != candidate.interleave_depth
        });
        let window_space_exhausted =
            self.fec_tx_sequence / candidate.source_count as u64 > u32::MAX as u64;
        if !self.fec_tx_active || shape_changed || window_space_exhausted {
            self.fec_tx_epoch = self.fec_tx_epoch.wrapping_add(1).max(1);
            self.fec_tx_sequence = 0;
        }
        self.fec_tx_active = true;
        let profile = WireProfile { epoch: self.fec_tx_epoch, ..candidate };
        self.fec_tx_profile = Some(profile);
        Ok(Some(profile))
    }

    pub(super) fn bypass_fec_for_path_control(
        wire_profile: Option<WireProfile>,
        send_info: &crate::transport::SendInfo,
        send_buffer: &mut [u8],
        write: usize,
    ) -> Result<Option<WireProfile>, crate::error::ConnectionError> {
        if wire_profile.is_none() || !send_info.path_control {
            return Ok(wire_profile);
        }

        let quic_offset = 2 * wire::SOURCE_LENGTH_LEN;
        let quic_end = quic_offset
            .checked_add(write)
            .filter(|end| *end <= send_buffer.len())
            .ok_or(crate::error::ConnectionError::BufferTooShort)?;
        send_buffer.copy_within(quic_offset..quic_end, 0);
        Ok(None)
    }

    /// Prepares one wire datagram and discards its address metadata.
    ///
    /// Connected-socket callers can use this compatibility API. Multipath and
    /// unconnected-socket runtimes must use [`Self::send_with_info`] so targeted
    /// path-validation frames reach the address selected by the transport.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        self.send_with_info(buf).map(|(len, _)| len)
    }

    /// Prepares one wire datagram together with its exact transport-selected path.
    pub fn send_with_info(
        &mut self,
        buf: &mut [u8],
    ) -> Result<(usize, crate::transport::SendInfo), crate::error::ConnectionError> {
        let now = self.clock.now();

        // --- LOSS/PTO RECOVERY TIMER ---
        // RFC 9002 §6.1.2/§6.2.1: event loops drive the recovery timer.  When the
        // deadline has passed, run loss detection (time-threshold or PTO probe)
        // before the pacing/stealth scheduler so probes never wait on shaping.
        if self.conn.recovery_deadline().is_some_and(|recovery_deadline| now >= recovery_deadline) {
            self.conn.on_recovery_timeout(now);
            // Recovery takes precedence over pacing/stealth release; force
            // an immediate send attempt so PTO probes can emit.
            if self.next_packet_release.is_some_and(|r| r > now) {
                self.next_packet_release = None;
            }
        }

        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
        let established = self.conn.is_established();
        if established {
            self.conn.on_traffic_analysis_timeout(now);
        }
        let fec_wire_ready = self
            .conn
            .post_handshake_datagram_ready()
            .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
        let path_control_pending = self.conn.has_sendable_path_control();

        // --- REALITY FALLBACK RESPONSE POLLING ---
        // Check if there are any responses from upstream to send back (bypass stealth scheduler)
        if let Some(resp) = self.stealth_manager.poll_fallback() {
            if buf.len() < resp.data.len() {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            buf[..resp.data.len()].copy_from_slice(&resp.data);
            return Ok((
                resp.data.len(),
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        // --- ASYNC STEALTH SCHEDULER ---
        // If we are currently throttled by the StealthManager (Brain), yield immediately.
        //
        // Production invariant:
        // Never delay Initial/Handshake flights. Delaying them can stall the connection setup and
        // makes short-lived clients (like E2E) time out. Stealth timing only applies post-handshake.
        if !established {
            self.next_packet_release = None;
            self.outbound_pacer.reset();
        } else if !path_control_pending {
            if let Some(release_time) = self.next_packet_release {
                if now < release_time {
                    log::trace!(
                        "connection.send: next_packet_release blocks until {:?}",
                        release_time
                    );
                    return Ok((
                        0,
                        crate::transport::SendInfo {
                            from: self.local_addr,
                            to: self.peer_addr,
                            at: now,
                            congestion_controlled: false,
                            path_control: false,
                        },
                    )); // WouldBlock / Yield
                }
                // Timer expired, clear block and proceed
                self.next_packet_release = None;
            }
        }
        if established && !path_control_pending && self.outbound_pacer.is_blocked(now) {
            log::trace!("connection.send: outbound_pacer blocked dgram_queue={} out_fec={} bytes_in_flight={} cwnd={}",
                self.conn.dgram_send_queue_len(), self.outgoing_fec_packets.len(), self.conn.bytes_in_flight(), self.conn.cwnd());
            return Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        // If there are buffered FEC packets, send one directly. These packets
        // were already generated in a previous send() call but could not be
        // emitted because of pacing or stealth scheduling. Flushing them first
        // prevents an accumulation deadlock: if has_pending_app_data stayed true
        // (e.g. a MASQUE datagram was queued but conn.send was blocked), every
        // new send() call would generate another FEC packet and push it onto
        // outgoing_fec_packets without ever draining the buffer.
        if !path_control_pending && !self.outgoing_fec_packets.is_empty() {
            // Write from the queued item without removing it. A capacity or serialization
            // failure must leave the packet exactly where it was, in order, for the next
            // send; popping first silently discarded a locally queued packet that was never
            // emitted while backpressure counters stayed at zero.
            let (len, mut send_info, shape, congestion_controlled) = {
                let packet = self
                    .outgoing_fec_packets
                    .front()
                    .ok_or_else(|| "buffered FEC queue emptied unexpectedly".to_string())?;
                let len = packet.write_to(buf)?;
                (len, packet.send_info, packet.telemetry_shape(), packet.congestion_controlled)
            };
            // Commit: the bytes are in the caller's buffer, so ownership transfers now.
            // Dropping the popped packet recycles its pool block.
            self.outgoing_fec_packets.pop_front();
            send_info.at = now;
            if self.fec.telemetry_enabled() {
                let (systematic, source_payload_bytes) = shape;
                self.fec.observe_wire_send(systematic, source_payload_bytes, len);
            }
            self.record_paced_packet(now, len, congestion_controlled);
            return Ok((len, send_info));
        }

        // Cover PING: inject post-handshake keepalive if the interval has elapsed.
        // The PING lands in pending_control and is flushed by flush_pending_control_frames()
        // inside conn.send(), requiring no extra round-trip through this function.
        if established && !path_control_pending && self.stealth_manager.should_send_cover_ping() {
            self.conn.queue_cover_ping();
        }

        let wire_profile = if fec_wire_ready { self.prepare_fec_wire_profile()? } else { None };

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = PooledBlock::new(self.optimization_manager.memory_pool());
        let send_result = if wire_profile.is_some() {
            if send_buffer.len() <= 2 * wire::SOURCE_LENGTH_LEN {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            self.conn.send_with_datagram_overhead(
                &mut send_buffer[2 * wire::SOURCE_LENGTH_LEN..],
                wire::MAX_DATAGRAM_OVERHEAD,
            )
        } else {
            self.conn.send(&mut send_buffer)
        };
        let (write, send_info) = match send_result {
            Ok(v) => v,
            Err(crate::error::ConnectionError::Done) => {
                log::trace!("connection.send: conn.send returned Done dgram_queue={} out_fec={} bytes_in_flight={} cwnd={}",
                    self.conn.dgram_send_queue_len(), self.outgoing_fec_packets.len(), self.conn.bytes_in_flight(), self.conn.cwnd());
                // No packet currently pending is a normal state for polling loops.
                drop(send_buffer);
                return Ok((
                    0,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                    },
                ));
            }
            Err(crate::error::ConnectionError::BufferTooShort) => {
                drop(send_buffer);
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            Err(e) => {
                // The PooledBlock guard recycles the buffer on this early return.
                drop(send_buffer);
                return Err(crate::error::ConnectionError::Transport(e.to_string()));
            }
        };

        if write == 0 {
            log::trace!("connection.send: conn.send returned write=0");
            // The buffer is recycled automatically via Drop.
            drop(send_buffer);
            return Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ));
        }

        let bypass_fec_for_path_control = send_info.path_control;
        let wire_profile =
            Self::bypass_fec_for_path_control(wire_profile, &send_info, &mut send_buffer, write)?;

        // The buffer may be larger than the written data; the length is tracked separately.
        // Stealth padding may be applied by the transport configuration; do not mutate the
        // sealed datagram here to preserve AEAD integrity and FEC compatibility.

        // Obfuscate payload if enabled (includes timing/flow shaping)
        // NON-BLOCKING: If delay needed, we schedule it and yield zero bytes.
        let quic_range = if wire_profile.is_some() {
            2 * wire::SOURCE_LENGTH_LEN..2 * wire::SOURCE_LENGTH_LEN + write
        } else {
            0..write
        };
        let delay_opt = if bypass_fec_for_path_control {
            None
        } else {
            self.stealth_manager.process_outgoing_packet(&mut send_buffer[quic_range.clone()])
        };

        let (packet_id, fec_data_len) = if wire_profile.is_some() {
            let quic_len =
                u16::try_from(write).map_err(|_| crate::error::ConnectionError::BufferTooShort)?;
            let source_len = quic_len
                .checked_add(wire::SOURCE_LENGTH_LEN as u16)
                .ok_or(crate::error::ConnectionError::BufferTooShort)?;
            send_buffer[..wire::SOURCE_LENGTH_LEN].copy_from_slice(&source_len.to_be_bytes());
            send_buffer[wire::SOURCE_LENGTH_LEN..2 * wire::SOURCE_LENGTH_LEN]
                .copy_from_slice(&quic_len.to_be_bytes());
            (self.fec_tx_sequence, write + 2 * wire::SOURCE_LENGTH_LEN)
        } else {
            (self.packet_id_counter, write)
        };

        // Transfer the checked-out block only after every pre-FEC fallible operation has passed.
        let send_pool = send_buffer.pool();

        // Create a source (systematic) FEC packet, passing ownership of the buffer.
        let mut fec_packet = FecPacket::from_pooled_blocks(
            packet_id,
            Some(send_buffer),
            fec_data_len,
            true,
            None,
            0,
            // Use the same pool the buffer was allocated from to avoid cross-pool leaks
            send_pool,
        )
        .map_err(crate::error::ConnectionError::Transport)?;
        fec_packet.seq = packet_id;

        // Initial and Handshake datagrams must remain raw because the server parses
        // the first Initial before a Core connection exists. FEC starts only after
        // this endpoint has entered 1-RTT. Zero mode retains raw zero-overhead output.
        if let Some(profile) = wire_profile {
            let source_sequence = self.fec_tx_sequence;
            let window = (source_sequence / profile.source_count as u64) as u32;
            self.fec.on_send_into(fec_packet, &mut self.fec_send_scratch);
            for packet in self.fec_send_scratch.drain(..) {
                let (sequence, repair_index, block_index) = if packet.is_systematic {
                    (
                        source_sequence,
                        wire::SYSTEMATIC_REPAIR_INDEX,
                        (source_sequence % profile.interleave_depth as u64) as u8,
                    )
                } else {
                    (
                        packet.id,
                        u16::try_from(packet.seq >> 4).map_err(|_| {
                            crate::error::ConnectionError::Transport(
                                "FEC repair ordinal exceeds wire range".to_string(),
                            )
                        })?,
                        (packet.seq & 0x0F) as u8,
                    )
                };
                self.outgoing_fec_packets.push_back(OutgoingFecPacket {
                    wire_meta: Some(WirePacketMeta {
                        profile,
                        window,
                        sequence,
                        repair_index,
                        block_index,
                        systematic: packet.is_systematic,
                    }),
                    packet,
                    send_info,
                    congestion_controlled: send_info.congestion_controlled,
                });
            }
            self.fec_tx_sequence = self.fec_tx_sequence.wrapping_add(1);
        } else {
            self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
            let outgoing = OutgoingFecPacket {
                packet: fec_packet,
                wire_meta: None,
                send_info,
                congestion_controlled: send_info.congestion_controlled,
            };
            if send_info.path_control {
                self.outgoing_fec_packets.push_front(outgoing);
            } else {
                self.outgoing_fec_packets.push_back(outgoing);
            }
        }

        // Single outbound stealth timing owner: core merges StealthManager shaping delay
        // with transport jitter (when enabled) into one release deadline. Connection::send
        // no longer maintains a parallel next_send_at gate.
        if established && !bypass_fec_for_path_control {
            let transport_jitter = self.conn.transport_stealth_jitter_delay();
            if let Some(release_at) =
                Self::compute_outbound_stealth_release(now, delay_opt, transport_jitter)
            {
                self.next_packet_release = Some(release_at);
                return Ok((
                    0,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                    },
                )); // Yield immediately, do not send the just-generated packets yet.
            }
        }

        // Pop the first packet from the buffer to send it now.
        if !self.outgoing_fec_packets.is_empty() {
            // Same transactional shape as the buffered flush above: write from the front, and
            // transfer ownership only once the bytes are committed to the caller's buffer.
            let (len, mut send_info, shape, congestion_controlled) = {
                let packet = self
                    .outgoing_fec_packets
                    .front()
                    .ok_or_else(|| "FEC queue emptied unexpectedly".to_string())?;
                let len = packet.write_to(buf)?;
                (len, packet.send_info, packet.telemetry_shape(), packet.congestion_controlled)
            };
            self.outgoing_fec_packets.pop_front();
            send_info.at = now;
            log::trace!(
                "connection.send: emitting packet len={} dgram_queue_after={} remaining_fec={}",
                len,
                self.conn.dgram_send_queue_len(),
                self.outgoing_fec_packets.len()
            );
            if self.fec.telemetry_enabled() {
                let (systematic, source_payload_bytes) = shape;
                self.fec.observe_wire_send(systematic, source_payload_bytes, len);
            }
            self.record_paced_packet(now, len, congestion_controlled);
            Ok((len, send_info))
        } else {
            Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                },
            ))
        }
    }

    fn record_paced_packet(&mut self, now: Instant, bytes: usize, congestion_controlled: bool) {
        if !congestion_controlled {
            return;
        }
        let Some(rate) = self.conn.pacing_rate() else {
            return;
        };
        self.outbound_pacer.record_send(now, bytes, self.conn.send_quantum(), rate);
    }

    /// Merges StealthManager delay and transport jitter into one release instant.
    /// When both apply, the later deadline wins (no stacked duplicate yields).
    pub(crate) fn compute_outbound_stealth_release(
        now: Instant,
        stealth_manager_delay: Option<Duration>,
        transport_jitter: Option<Duration>,
    ) -> Option<Instant> {
        let mut release = stealth_manager_delay.map(|delay| now + delay);
        if let Some(jitter) = transport_jitter {
            let candidate = now + jitter;
            release = Some(match release {
                Some(current) => current.max(candidate),
                None => candidate,
            });
        }
        release
    }
}
