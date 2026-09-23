//! Outbound packet scheduling, FEC framing, and pacing for a core connection.

use super::*;

/// Outcome of one transport-datagram materialization into the outgoing
/// queue (TODO-1016 batch produce loop).
enum ProduceOutcome {
    /// The transport had nothing pending to produce.
    Done,
    /// A packet was queued and may emit immediately. Stops the produce
    /// loop so the no-drain hot path keeps one materialization per
    /// `send_with_info` call; inside `burst_draining` the loop continues.
    Ready,
}

impl QuicFuscateConnection {
    /// Earliest outgoing release imposed by the pacer or an open deferral
    /// window edge (TODO-1016).
    pub fn next_outbound_release_deadline(&self) -> Option<Instant> {
        [
            self.outbound_pacer.next_release(),
            self.bulk_window_release.get(),
            self.stealth_window_release.get(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Earliest instant the caller should poll `send` again.
    ///
    /// This merges outer pacing, the stealth/reorder gather-window edges,
    /// QUIC recovery, the TLS profile handshake-readiness deadline, the
    /// one transport-owned traffic-analysis deadline, and any pending
    /// Maybenot action/internal timer (TODO-1061).
    pub fn next_send_deadline(&self) -> Option<Instant> {
        [
            self.next_outbound_release_deadline(),
            self.conn.recovery_deadline(),
            self.conn.traffic_analysis_deadline(),
            self.conn.handshake_send_ready_at(),
            self.maybenot.as_ref().and_then(|rt| rt.next_deadline()),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Maybenot padding fills the next 1-RTT packet up to the confirmed
    /// path MTU (TODO-1061): a matured `SendPadding` becomes a PADDING
    /// frame of `effective_path_mtu - MAYBENOT_HDR_TAG_OVERHEAD`, so the
    /// emitted datagram looks like ordinary bulk output instead of a
    /// distinctively sized cell. The reserve covers a 1-RTT short header
    /// with a maximum-length DCID (1 + 20 + 4) plus the AEAD tag (16)
    /// plus slack.
    pub(crate) const MAYBENOT_HDR_TAG_OVERHEAD: usize = 48;

    /// Wire length of one matured `SendPadding` action: fill the path
    /// datagram, clamped so a degenerate MTU never produces a zero pad.
    fn maybenot_pad_len(&self) -> usize {
        self.conn.effective_path_mtu().saturating_sub(Self::MAYBENOT_HDR_TAG_OVERHEAD).max(1)
    }

    /// Expires armed action timers, internal timers and the blocking
    /// window, then turns matured `SendPadding` actions into queued QUIC
    /// PADDING frames paid from the shared wire ledger (TODO-1052). A
    /// ledger denial drops the action — no private byte channel exists.
    pub(crate) fn maybenot_tick(&mut self, now: Instant) {
        if self.maybenot.is_none() {
            return;
        }
        let len = self.maybenot_pad_len();
        let runtime = self.maybenot.as_mut().expect("checked above");
        runtime.tick(now, self.conn.current_pto_delay());
        while let Some(pad) = runtime.next_pending_pad(now) {
            if self.conn.try_spend_wire_cover(len as u64) {
                self.conn.queue_cover_padding(len);
                runtime.note_padding_sent(pad.machine, now);
            } else {
                crate::telemetry::MAYBENOT_PADDING_BUDGET_DROPPED.inc();
            }
        }
    }

    /// Whether a matured `BlockOutgoing` window currently gates outgoing
    /// traffic. Pure-ACK output is never blocked (TODO-1061): when the
    /// only pending sendable is the ACK queue, the block yields false so
    /// loss-recovery feedback keeps flowing.
    pub(crate) fn maybenot_blocks_send(&mut self, now: Instant) -> bool {
        let Some(runtime) = self.maybenot.as_ref() else {
            return false;
        };
        if !runtime.blocking_active(now) {
            return false;
        }
        let ack_only = self.conn.has_pending_application_ack()
            && self.conn.dgram_send_queue_len() == 0
            && !self.conn.has_sendable_path_control();
        !ack_only
    }

    /// TODO-1015: maximum hold applied to a bulk reorder window. The draw
    /// is shared by every bulk packet arriving while the window is open.
    /// Uniform over [0, 3 ms]: ~1.5 ms median added bulk latency, within
    /// the 2 ms acceptance bound. The standalone client's loop-tick-bound
    /// deferral drain (TODO-1016) limits the effective batch size on that
    /// path; the io_driver runtime's deadline-driven loop drains batches
    /// at higher resolution.
    pub(crate) const REORDER_HOLD_MAX_US: u64 = 3_000;
    /// Upper bound of the randomized quiet phase drawn at each reorder
    /// window edge (TODO-1017). Without a quiet phase every sustained
    /// bulk train re-arms a gather window on the first tick after a
    /// drain, so nearly all traffic pays the window-stall cadence and
    /// the emitted rate drops below the offered rate - the deficit
    /// drops in the kernel TUN queue (Omega measured 21k of 55k
    /// datagrams at `qtun0 TX dropped`, matching iperf receiver loss).
    /// Mean quiet ~10 ms bounds the reorder duty cycle to ~13%, which
    /// is the ChameleonFlow shape: occasional reordered trains inside
    /// an otherwise FIFO stream.
    pub(crate) const REORDER_QUIET_MAX_US: u64 = 20_000;
    /// Two bulk packets closer than this belong to the same burst train;
    /// train members are eligible for the hold + permuted emission.
    pub(crate) const REORDER_BURST_WINDOW: Duration = Duration::from_millis(10);

    /// Ticks the bulk reorder window for a just-produced packet
    /// (ChameleonFlow). A burst is time-based, not queue-based: any bulk
    /// packet arriving within `REORDER_BURST_WINDOW` of the previous one
    /// belongs to the same train. The window itself is a gather timer,
    /// not a packet hold - a produced-and-held packet counts in-flight
    /// from `conn.send`, so holding the window opener past ~PTO declares
    /// it lost on every epoch (measured ~26% on Omega). The opener rides
    /// out unheld as the train head; production stalls while the window
    /// is open (`deferral_window_open`) so the backlog gathers in the
    /// transport's own datagram queue as honest backpressure. At the edge
    /// the drain phase arms and the queued batch emits permuted.
    ///
    /// A lone bulk packet - the head of a train after a quiet gap - ticks
    /// without arming: delaying it would cost latency with zero
    /// redistribution gain. No-op when stealth timing is disabled, the
    /// packet is not bulk-only, or the drain phase is active.
    pub(crate) fn reorder_window_tick(&self, send_info: &crate::transport::SendInfo, now: Instant) {
        if !send_info.bulk_only {
            return;
        }
        self.reorder_window_apply(now);
    }

    /// TODO-1022 Option A: framed systematic sources under a committed
    /// wire profile may arm the gather window. `bulk_only` is the raw-path
    /// gate and also strips FEC, so the wire branch never sees it.
    /// Congestion-controlled app data is the framed equivalent. Path
    /// control never arms, and repairs never call this.
    pub(crate) fn reorder_window_tick_framed_source(
        &self,
        send_info: &crate::transport::SendInfo,
        now: Instant,
    ) {
        if send_info.path_control || !send_info.congestion_controlled {
            return;
        }
        self.reorder_window_apply(now);
    }

    fn reorder_window_apply(&self, now: Instant) {
        if !self.conn.transport_stealth_timing_active() {
            return;
        }
        if self.burst_draining.get() {
            // Post-edge drain: this packet is part of the burst the window
            // gathered. The permuted pick among the ripe batch does the
            // reordering; a fresh window would re-serialize the drain into
            // one packet per cycle.
            return;
        }
        let burst_in_progress = self.conn.dgram_send_queue_len() > 0
            || !self.outgoing_fec_packets.is_empty()
            || self
                .last_bulk_queued
                .get()
                .is_some_and(|queued| now.duration_since(queued) <= Self::REORDER_BURST_WINDOW);
        self.last_bulk_queued.set(Some(now));
        if !burst_in_progress {
            return;
        }
        if let Some(open) = self.bulk_window_release.get() {
            if now < open {
                // Mid-window production is already stalled by the caller's
                // window-open check; a packet that still slips through
                // rides out rather than reintroducing produced-and-held
                // in-flight inflation.
                return;
            }
            // The window edge just passed: consume it, open the quiet
            // phase, and switch to the drain phase instead of opening a
            // new window for this packet.
            self.bulk_window_release.set(None);
            self.open_quiet_phase(now);
            self.arm_burst_drain();
            return;
        }
        if self.skip_fresh_window(now) {
            return;
        }
        let hold_us = crate::transport::rand::fast_rand_u64_uniform(Self::REORDER_HOLD_MAX_US + 1);
        if hold_us == 0 {
            self.bulk_window_release.set(None);
            return;
        }
        let window = now + Duration::from_micros(hold_us);
        self.bulk_window_release.set(Some(window));
        log::debug!("reorder_window: bulk window +{hold_us}us");
    }

    /// TODO-1017 atomic pair emission: a freshly queued bulk datagram
    /// may swap places with the bulk entry directly ahead of it (fair
    /// coin). Both members are marked `paired` so neither can swap
    /// again - every displacement stays <= 1 position, the only reorder
    /// depth that cannot trip QUIC's packet-threshold loss detection
    /// (k = 3).
    ///
    /// Because the swap happens at join time, emission is plain FIFO:
    /// the pair always emits back-to-back inside one flush batch
    /// (sendmmsg), so a swap never costs an emit slot and no displaced
    /// datagram ever waits a pick. That is the atomicity the previous
    /// pick-time swap lacked: its displaced head emitted one loop slot
    /// later, which measured ~62% of the reorder-off ceiling plus ~1.5%
    /// residual loss on Omega. Unbounded permutation (displacement
    /// >= 3) measured ~25% spurious loss - still rejected.
    pub(crate) fn pair_swap_on_join(&mut self) {
        let len = self.outgoing_fec_packets.len();
        if len < 2 {
            return;
        }
        let (prev, last) = (len - 2, len - 1);
        let swappable = self.outgoing_fec_packets[prev].send_info.bulk_only
            && self.outgoing_fec_packets[last].send_info.bulk_only
            && !self.outgoing_fec_packets[prev].paired
            && !self.outgoing_fec_packets[last].paired;
        if swappable && crate::transport::rand::fast_rand_u64_uniform(2) == 1 {
            self.outgoing_fec_packets.swap(prev, last);
            self.outgoing_fec_packets[prev].paired = true;
            self.outgoing_fec_packets[last].paired = true;
        }
    }

    /// FIFO emission - the queue order already carries any reorder
    /// permutation (see `pair_swap_on_join`).
    pub(crate) fn next_emit_index(&self) -> Option<usize> {
        self.outgoing_fec_packets.front().map(|_| 0)
    }

    /// TODO-1006 repair-ACK producer (receiver side): drains the wire
    /// receiver's recovered-source log into one bounded report datagram
    /// and front-queues it. The datagram is already a complete wire
    /// frame, so `wire_meta: None` emits the bytes raw through
    /// `to_raw` - it consumes no `fec_tx_sequence` slot, carries no
    /// systematic position the decoder could confuse, and is marked
    /// non-bulk so the reorder permutation never displaces it (its CC
    /// signal is latency-relevant). Best-effort like an ACK: a lost
    /// report is covered by the next recovery burst.
    pub(crate) fn enqueue_repair_ack_report(
        &mut self,
    ) -> Result<(), crate::error::ConnectionError> {
        let Some(epoch) = self.fec_wire_receiver.last_rx_epoch() else {
            return Ok(());
        };
        let mut entries = [wire::RepairAckEntry::default(); wire::MAX_REPAIR_ACK_ENTRIES];
        let count = self.fec_wire_receiver.drain_recovered(&mut entries);
        if count == 0 {
            return Ok(());
        }
        let mut block = PooledBlock::new(self.optimization_manager.memory_pool());
        let len = wire::write_repair_ack(epoch, &entries[..count], &mut block)
            .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
        if self.fec_framing() == crate::engine::FecFraming::QuicFrame {
            // TODO-1052: repair-class spend gates before the datagram is
            // queued. A denied report stays unsent - it is best-effort by
            // design, and the next recovery burst covers the loss.
            if self.conn.try_spend_wire_repair(len as u64) {
                self.conn
                    .dgram_send_parts(&[wire::QUIC_REPAIR_DISCRIMINATOR], &block[..len])
                    .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
            } else {
                crate::telemetry::FEC_REPAIRS_BUDGET_DROPPED.inc();
                return Ok(());
            }
            crate::telemetry::FEC_REPAIR_ACK_ENTRIES_SENT.inc_by(count as u64);
            return Ok(());
        }
        // TODO-1052: same ledger gate on the raw-wire path — the report
        // debits `len` wire bytes (its exact `to_raw` size) at production.
        if !self.conn.try_spend_wire_repair(len as u64) {
            crate::telemetry::FEC_REPAIRS_BUDGET_DROPPED.inc();
            return Ok(());
        }
        let send_pool = block.pool();
        let packet = FecPacket::from_pooled_blocks(
            self.packet_id_counter,
            Some(block),
            len,
            false,
            None,
            0,
            send_pool,
        )
        .map_err(crate::error::ConnectionError::Transport)?;
        self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
        // TODO-1061: this datagram bypasses `conn.send`, so the queued
        // report is where the wire decides to send it (NormalSent).
        if let Some(runtime) = self.maybenot.as_mut() {
            runtime.note_wire_sent(self.clock.now());
        }
        self.outgoing_fec_packets.push_front(OutgoingFecPacket {
            packet,
            wire_meta: None,
            send_info: crate::transport::SendInfo {
                from: self.local_addr,
                to: self.peer_addr,
                at: self.clock.now(),
                congestion_controlled: false,
                path_control: false,
                bulk_only: false,
            },
            congestion_controlled: false,
            paired: false,
        });
        crate::telemetry::FEC_REPAIR_ACK_ENTRIES_SENT.inc_by(count as u64);
        Ok(())
    }

    /// Queue one ack-eliciting transport keepalive for the next send poll.
    ///
    /// On the wire a keepalive PING is indistinguishable from a cover PING,
    /// so a connection that owns a wire ledger pays for it out of the same
    /// cover budget — an unbudgeted periodic 48-byte ping would be a
    /// detectable beacon that defeats the whole point of the ledger
    /// (TODO-1052). Ledgerless connections (`off`/`performance`) send it
    /// unconditionally.
    pub fn queue_keepalive_ping(&mut self) {
        if self.conn.try_spend_wire_cover(48) {
            self.conn.queue_cover_ping();
        } else {
            crate::telemetry::COVER_PING_BUDGET_SKIPPED.inc();
        }
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

    /// Strips the FEC framing headroom for a packet that must go on the wire
    /// unframed: path-control packets (peer parses Initials before FEC exists)
    /// and `bulk_only` packets (TODO-1011: inner protocol owns reliability).
    pub(super) fn strip_framing_headroom(
        wire_profile: Option<WireProfile>,
        unframed: bool,
        send_buffer: &mut [u8],
        write: usize,
    ) -> Result<Option<WireProfile>, crate::error::ConnectionError> {
        if wire_profile.is_none() || !unframed {
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
        if self.conn.is_closed() {
            return self.conn.send(buf);
        }
        let now = self.clock.now();

        // --- LOSS/PTO RECOVERY TIMER ---
        // RFC 9002 sec. 6.1.2/sec. 6.2.1: event loops drive the recovery timer.  When the
        // deadline has passed, run loss detection (time-threshold or PTO probe)
        // before the pacing/stealth scheduler so probes never wait on shaping.
        if self.conn.recovery_deadline().is_some_and(|recovery_deadline| now >= recovery_deadline) {
            self.conn.on_recovery_timeout(now);
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

        // TODO-1061: expire Maybenot timers once per send poll and charge
        // matured padding actions onto the ledger before production.
        // Internal timers and block windows age regardless of pending
        // path-control traffic.
        if established {
            self.maybenot_tick(now);
        }

        // --- TODO-1006 REPAIR-ACK REPORT ---
        // The wire receiver logged decoder recoveries for the sender:
        // drain them into one bounded report datagram and front-queue it
        // so it emits on this call (or the next emit pass if a deferral
        // window is open - queued entries emit through emit_ripe_or_yield
        // while production stalls). Reports ride the normal emission path
        // - no extra socket writes, no FEC sequence slot consumed.
        if established && self.fec_wire_receiver.has_pending_recovered() {
            self.enqueue_repair_ack_report()?;
        }

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
                    bulk_only: false,
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
            self.bulk_window_release.set(None);
            self.stealth_window_release.set(None);
            self.reorder_quiet_until.set(None);
            self.burst_draining.set(false);
            self.outbound_pacer.reset();
        } else if !path_control_pending {
            self.maybe_abort_window_under_pressure(now);
            if self.deferral_window_open(now) {
                self.send_yield_counts[0].set(self.send_yield_counts[0].get() + 1);
                log::trace!(
                    "connection.send: deferral window open, production stalls until {:?}",
                    [self.bulk_window_release.get(), self.stealth_window_release.get()]
                        .into_iter()
                        .flatten()
                        .min()
                );
                // TODO-1016: while the window is open nothing is
                // produced - produced-but-held packets occupy QUIC's
                // in-flight window and trigger spurious PTO loss
                // (~38% measured on Omega), collapsing cwnd and the
                // pacing rate. The transport's own datagram queue
                // holds the backlog as honest backpressure; the drain
                // phase after the edge materializes it exempt from
                // new jitter draws. A queued drain leftover still emits.
                return self.emit_ripe_or_yield(
                    buf,
                    now,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                        bulk_only: false,
                    },
                );
            }
        }
        // The budgeted burst drain bypasses the delivery-rate pacer: the
        // reorder window exists to emit the gathered backlog as one
        // clustered train, which per-packet rate trickle would dissolve -
        // and a queued batch trickling out at pacing rate would sit past
        // PTO and read as loss (measured ~30% on Omega). The train size is
        // bounded by the drain budget, not the pacer; sends are still
        // recorded so the pacer debt shapes the inter-train gap.
        if established
            && !path_control_pending
            && !self.burst_draining.get()
            && self.outbound_pacer.is_blocked(now)
        {
            self.send_yield_counts[1].set(self.send_yield_counts[1].get() + 1);
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
                    bulk_only: false,
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
            let Some(emit_idx) = self.next_emit_index() else {
                self.send_yield_counts[2].set(self.send_yield_counts[2].get() + 1);
                // Every queued packet still waits inside its reorder hold
                // window (TODO-1015). The runtime re-polls at the deadline
                // merged from earliest_reorder_hold(). Nothing is produced
                // while a hold is open (TODO-1016): the transport's own
                // datagram queue is the window accumulator, so held
                // packets never inflate QUIC's in-flight clock.
                return self.emit_ripe_or_yield(
                    buf,
                    now,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                        bulk_only: false,
                    },
                );
            };
            // Write from the queued item without removing it. A capacity or serialization
            // failure must leave the packet exactly where it was, in order, for the next
            // send; popping first silently discarded a locally queued packet that was never
            // emitted while backpressure counters stayed at zero.
            let (len, mut send_info, shape, congestion_controlled) = {
                let packet = self
                    .outgoing_fec_packets
                    .get(emit_idx)
                    .ok_or_else(|| "buffered FEC queue emptied unexpectedly".to_string())?;
                let len = packet.write_to(buf)?;
                (len, packet.send_info, packet.telemetry_shape(), packet.congestion_controlled)
            };
            // Commit: the bytes are in the caller's buffer, so ownership transfers now.
            // Dropping the removed packet recycles its pool block.
            self.outgoing_fec_packets.remove(emit_idx);
            send_info.at = now;
            if self.fec.telemetry_enabled() {
                let (systematic, source_payload_bytes) = shape;
                self.fec.observe_wire_send(systematic, source_payload_bytes, len);
            }
            self.record_paced_packet(now, len, congestion_controlled);
            return Ok((len, send_info));
        }

        // Cover PING (TODO-1054): no fixed grid. The persona trace inside
        // the wire ledger decides *when* a client packet is due and how
        // long its datagram is; the same padder pads the PING packet to
        // the captured length. A denied slot is consumed — never a burst.
        if established && !path_control_pending && self.stealth_manager.cover_ping_enabled() {
            if let Some(trace_len) = self.conn.cover_ping_due() {
                self.conn.queue_cover_ping();
                self.conn.set_short_header_pad_target(trace_len as usize);
            }
        }

        // Idle keepalive (TODO-1054 risk): when the trace stays silent
        // past max_idle_timeout/2, one PING keeps the connection alive.
        // It spends the same cover budget and is recorded as a keepalive,
        // not as mimicry — there is no second grid.
        if established && !path_control_pending && self.conn.idle_keepalive_due() {
            if self.conn.try_spend_wire_cover(48) {
                self.conn.queue_cover_ping();
                crate::telemetry::COVER_PING_IDLE_KEEPALIVE.inc();
            } else {
                crate::telemetry::COVER_PING_BUDGET_SKIPPED.inc();
            }
        }

        let wire_profile = if fec_wire_ready { self.prepare_fec_wire_profile()? } else { None };

        let batch_n = self.admitted_seal_count();
        if batch_n > 1
            && self.outgoing_fec_packets.is_empty()
            && !path_control_pending
            && !self.deferral_window_open(now)
        {
            self.produce_admitted_batch(batch_n, now, established, wire_profile)?;
        } else if wire_profile.is_none()
            && self.outgoing_fec_packets.is_empty()
            && !self.burst_draining.get()
        {
            // Raw (non-FEC) emit: conn.send writes straight into the caller's
            // buffer. The burst path above is the one that seal-batches.
            return self.send_with_info_raw(buf, now, established);
        } else {
            // TODO-1016: materialize a held backlog. A non-deferred packet
            // stops the loop so the no-stealth hot path keeps one packet
            // when the admitted seal batch did not run.
            self.produce_while_held(now, established, wire_profile)?;
        }

        // Pop the first ripe packet from the buffer to send it now.
        if !self.outgoing_fec_packets.is_empty() {
            let Some(emit_idx) = self.next_emit_index() else {
                return Ok((
                    0,
                    crate::transport::SendInfo {
                        from: self.local_addr,
                        to: self.peer_addr,
                        at: now,
                        congestion_controlled: false,
                        path_control: false,
                        bulk_only: false,
                    },
                ));
            };
            self.emit_queued_packet(buf, now, emit_idx)
        } else {
            Ok((
                0,
                crate::transport::SendInfo {
                    from: self.local_addr,
                    to: self.peer_addr,
                    at: now,
                    congestion_controlled: false,
                    path_control: false,
                    bulk_only: false,
                },
            ))
        }
    }

    /// TODO-1016: maximum transport datagrams materialized into the
    /// outgoing queue per `send_with_info` call while deferral is active.
    /// Sized to one socket burst so each housekeeping wake fills a full
    /// emission train instead of a fraction of it.
    pub(crate) const PRODUCE_BATCH_MAX: usize = 64;

    /// TODO-1016: bound on packets held inside an open deferral window.
    /// Production pauses at this depth so a long window cannot grow the
    /// outgoing queue without bound (~2x the socket batch burst).
    pub(crate) const DEFER_QUEUE_CAP: usize = 128;

    /// Materialize transport datagrams into the outgoing queue in bounded
    /// batches (TODO-1016). A Deferred packet opens its stealth window
    /// and stops the loop - producing more would pile held bytes onto
    /// QUIC's in-flight window. Ready stops too: the no-stealth hot path
    /// keeps one materialization per call. Only inside `burst_draining`
    /// does the loop continue past Ready, filling the drain ahead of the
    /// one-packet-per-call emitter.
    /// True while either deferral window is open (TODO-1016). Production
    /// must stall: a packet materialized now would have to sit held in
    /// the outgoing queue, and produced-and-held packets count in-flight
    /// from `conn.send` - holds past ~PTO read as spurious loss. The
    /// transport's own datagram queue gathers the backlog as honest
    /// backpressure instead.
    pub(crate) fn deferral_window_open(&self, now: Instant) -> bool {
        self.bulk_window_release.get().is_some_and(|open| now < open)
            || self.stealth_window_release.get().is_some_and(|open| now < open)
    }

    fn produce_while_held(
        &mut self,
        now: Instant,
        established: bool,
        wire_profile: Option<WireProfile>,
    ) -> Result<(), crate::error::ConnectionError> {
        for _ in 0..Self::PRODUCE_BATCH_MAX {
            if self.outgoing_fec_packets.len() >= Self::DEFER_QUEUE_CAP {
                break;
            }
            // An open deferral window gathers the transport backlog;
            // producing into it would only refill the held queue.
            if self.deferral_window_open(now) {
                self.send_yield_counts[0].set(self.send_yield_counts[0].get() + 1);
                break;
            }
            // Drain epoch budget spent: once the queued batch has fully
            // emitted the epoch is over and the flag releases, otherwise
            // stop materializing and let the tail emit down - still
            // unpaced while the flag stays armed.
            if self.burst_draining.get() && self.drain_budget.get() == 0 {
                self.refresh_drain_budget();
                if self.drain_budget.get() == 0 {
                    if self.outgoing_fec_packets.is_empty() {
                        self.burst_draining.set(false);
                    } else {
                        break;
                    }
                }
            }
            match self.produce_one_queued(now, established, wire_profile)? {
                ProduceOutcome::Done => break,
                ProduceOutcome::Ready => {
                    if !self.burst_draining.get() {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Smallest stealth window worth arming (TODO-1016). A deferral
    /// shorter than the runtime's wake granularity cannot shape the
    /// wire - the drain cannot respond faster than the loop's ~1ms
    /// housekeeping floor - so the draw is quantized down to a direct
    /// emission instead of opening an O(1)-packet cycle.
    pub(crate) const STEALTH_MIN_WINDOW: Duration = Duration::from_millis(1);

    /// Upper bound on packets one drain epoch materializes (TODO-1016).
    /// Armed from the transport backlog at the window edge; under
    /// sustained load that backlog never reaches zero, so the cap is what
    /// ends each burst train and re-opens the window cycle. Sized to the
    /// TUN drain budget so a 5 ms gather plus 1-core drain time cannot
    /// leave more packets parked than one epoch can emit (TODO-1015
    /// tun_drops gate).
    pub(crate) const DRAIN_BUDGET_MAX: usize = 128;

    /// Transport datagrams already queued that count as a gathered train
    /// (TODO-1015). Arming another stall on top of this just overflows
    /// the TUN backlog; FIFO-drain until the queue falls back under the
    /// mark, then the next quiet gap may shape again.
    pub(crate) const WINDOW_PRESSURE_DEPTH: usize = 16;

    /// Safety valve: an open gather window whose transport queue has
    /// grown this deep is consumed immediately so production resumes
    /// before `tun_drops` start (TODO-1015). 256 is a quarter of the
    /// default dgram cap and far above a 5 ms 60 M gather (~27).
    pub(crate) const WINDOW_ABORT_DEPTH: usize = 256;

    pub(crate) fn gather_pressure(&self) -> bool {
        self.conn.dgram_send_queue_len() >= Self::WINDOW_PRESSURE_DEPTH
    }

    pub(crate) fn skip_fresh_window(&self, now: Instant) -> bool {
        self.gather_pressure() || self.reorder_quiet_until.get().is_some_and(|until| now < until)
    }

    fn open_quiet_phase(&self, now: Instant) {
        let quiet_us =
            crate::transport::rand::fast_rand_u64_uniform(Self::REORDER_QUIET_MAX_US + 1);
        self.reorder_quiet_until.set(Some(now + Duration::from_micros(quiet_us)));
    }

    pub(crate) fn maybe_abort_window_under_pressure(&self, now: Instant) {
        if !self.deferral_window_open(now) {
            return;
        }
        if self.conn.dgram_send_queue_len() < Self::WINDOW_ABORT_DEPTH {
            return;
        }
        self.bulk_window_release.set(None);
        self.stealth_window_release.set(None);
        self.open_quiet_phase(now);
        self.arm_burst_drain();
    }

    pub(crate) fn refresh_drain_budget(&self) {
        if !self.burst_draining.get() || self.drain_budget.get() > 0 {
            return;
        }
        if !self.gather_pressure() {
            return;
        }
        let refill = self.conn.dgram_send_queue_len().min(Self::DRAIN_BUDGET_MAX);
        if refill > 0 {
            self.drain_budget.set(refill);
        }
    }

    /// Arm the post-edge burst drain (TODO-1016). The budget mirrors the
    /// transport backlog gathered during the window (plus the triggering
    /// packet already consumed by `conn.send`), capped so a pathologically
    /// deep backlog cannot stretch the train past a bounded burst.
    fn arm_burst_drain(&self) {
        self.burst_draining.set(true);
        let backlog = self.conn.dgram_send_queue_len().saturating_add(1);
        self.drain_budget.set(backlog.min(Self::DRAIN_BUDGET_MAX));
        self.send_yield_counts[5].set(self.send_yield_counts[5].get() + 1);
    }

    /// Fold a stealth/jitter release into the shared deferral window
    /// (TODO-1016). The draw becomes a gather timer, not a per-packet
    /// hold - a produced-and-held packet would count in-flight from
    /// `conn.send` and declare lost past ~PTO. This packet rides out as
    /// the train head; production stalls while the window is open so the
    /// backlog gathers in the transport's own datagram queue as honest
    /// backpressure. The first produce after the edge consumes the
    /// expired window and arms `burst_draining`; every produce during
    /// the drain skips its jitter draw, which keeps QUIC's in-flight
    /// clock free of the hold duration.
    pub(crate) fn stealth_window_tick(&self, release: Option<Instant>, now: Instant) {
        if self.burst_draining.get() {
            // Drain members ride the burst without a fresh draw. The
            // drain never ends here - clearing is owned by the budget
            // check in the produce loop and by the transport-Done path
            // once the backlog is actually empty.
            return;
        }
        let Some(target) = release else { return };
        if target.saturating_duration_since(now) < Self::STEALTH_MIN_WINDOW {
            return;
        }
        if let Some(open) = self.stealth_window_release.get() {
            if now < open {
                return;
            }
            // The window edge just passed: consume it, share the reorder
            // quiet phase so a 5 ms stealth draw cannot punch through
            // the FIFO gap, and switch to the drain phase.
            self.stealth_window_release.set(None);
            self.open_quiet_phase(now);
            self.arm_burst_drain();
            return;
        }
        if self.skip_fresh_window(now) {
            return;
        }
        self.stealth_window_release.set(Some(target));
    }

    /// How many 1-RTT packets this wake may seal together.
    ///
    /// Stealth timing still produces one packet per wake so a hold can open.
    /// A drain epoch, and any connection with timing off, already emits a
    /// train; that train is one `seal_batch`.
    fn admitted_seal_count(&self) -> usize {
        if self.burst_draining.get() {
            return self.drain_budget.get().clamp(1, 8);
        }
        if self.conn.transport_stealth_timing_active() {
            return 1;
        }
        let queued = self.conn.dgram_send_queue_len();
        if queued >= 2 {
            queued.min(8)
        } else {
            1
        }
    }

    /// Frame and seal up to `count` admitted packets, then queue them.
    fn produce_admitted_batch(
        &mut self,
        count: usize,
        now: Instant,
        established: bool,
        wire_profile: Option<WireProfile>,
    ) -> Result<(), crate::error::ConnectionError> {
        if count == 0 {
            return Ok(());
        }
        let pool = self.optimization_manager.memory_pool();
        let head = if wire_profile.is_some() { 2 * wire::SOURCE_LENGTH_LEN } else { 0 };
        let overhead = if wire_profile.is_some() { wire::MAX_DATAGRAM_OVERHEAD } else { 0 };
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let block = PooledBlock::new(pool.clone());
            if block.len() <= head {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            blocks.push(block);
        }
        let produced = {
            let mut refs: Vec<&mut [u8]> =
                blocks.iter_mut().map(|block| &mut block[head..]).collect();
            self.conn.send_admitted_batch(&mut refs, overhead).map_err(|error| {
                if matches!(error, crate::error::ConnectionError::BufferTooShort) {
                    error
                } else if matches!(error, crate::error::ConnectionError::Done) {
                    crate::error::ConnectionError::Done
                } else {
                    crate::error::ConnectionError::Transport(error.to_string())
                }
            })?
        };
        let mut blocks = blocks.into_iter();
        for (write, send_info) in produced {
            let Some(block) = blocks.next() else {
                return Err(crate::error::ConnectionError::InvalidState);
            };
            self.finish_produced_packet(block, write, send_info, wire_profile, established, now)?;
        }
        Ok(())
    }

    /// Materialize one transport datagram into `outgoing_fec_packets`.
    /// Returns `Done` when the transport has nothing pending, `Ready`
    /// when the produced packet may emit immediately, and `Deferred`
    /// when a stealth/jitter hold keeps it queued - the caller then
    /// keeps producing to fill the shared window's batch.
    fn produce_one_queued(
        &mut self,
        now: Instant,
        established: bool,
        wire_profile: Option<WireProfile>,
    ) -> Result<ProduceOutcome, crate::error::ConnectionError> {
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
                drop(send_buffer);
                // Done doubles as the congestion gate (RFC 9002 sec. 7.2):
                // with transport backlog still queued the drain must stay
                // armed so it resumes the burst once ACKs release cwnd -
                // clearing here would reopen a window per packet. Queued
                // members likewise keep it armed so the tail emits
                // unpaced. Only a fully emptied state ends the drain.
                if self.conn.dgram_send_queue_len() == 0 && self.outgoing_fec_packets.is_empty() {
                    self.burst_draining.set(false);
                }
                self.send_yield_counts[3].set(self.send_yield_counts[3].get() + 1);
                return Ok(ProduceOutcome::Done);
            }
            Err(crate::error::ConnectionError::BufferTooShort) => {
                drop(send_buffer);
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            Err(e) => {
                drop(send_buffer);
                return Err(crate::error::ConnectionError::Transport(e.to_string()));
            }
        };

        if write == 0 {
            log::trace!("connection.send: conn.send returned write=0");
            drop(send_buffer);
            if self.conn.dgram_send_queue_len() == 0 && self.outgoing_fec_packets.is_empty() {
                self.burst_draining.set(false);
            }
            self.send_yield_counts[3].set(self.send_yield_counts[3].get() + 1);
            return Ok(ProduceOutcome::Done);
        }

        self.finish_produced_packet(send_buffer, write, send_info, wire_profile, established, now)
    }

    /// Queue one already-sealed transport datagram, including FEC framing.
    fn finish_produced_packet(
        &mut self,
        mut send_buffer: PooledBlock,
        write: usize,
        send_info: crate::transport::SendInfo,
        wire_profile: Option<WireProfile>,
        established: bool,
        now: Instant,
    ) -> Result<ProduceOutcome, crate::error::ConnectionError> {
        // Path-control packets must reach the peer before a Core-side FEC
        // context exists; bulk-only packets skip framing because their inner
        // protocol already retransmits (TODO-1011). Only path-control bypasses
        // stealth scheduling and front-queues - bulk traffic stays shaped.
        let unframed = send_info.path_control || send_info.bulk_only;
        let wire_profile =
            Self::strip_framing_headroom(wire_profile, unframed, &mut send_buffer, write)?;

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
        let delay_opt = if send_info.path_control {
            None
        } else {
            self.stealth_manager.process_outgoing_packet(
                &mut send_buffer[quic_range.clone()],
                !send_info.congestion_controlled,
            )
        };

        let quic_frame = self.fec_framing() == crate::engine::FecFraming::QuicFrame;
        let raw_quic =
            if quic_frame { Some(send_buffer[quic_range.clone()].to_vec()) } else { None };

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
            // Tick before materializing the FEC drain so a lone train head
            // still sees an empty outgoing queue, matching the raw path.
            // Repairs generated below inherit the source send_info but are
            // forced non-bulk and never retick this window.
            self.reorder_window_tick_framed_source(&send_info, now);
            let source_sequence = self.fec_tx_sequence;
            let window = (source_sequence / profile.source_count as u64) as u32;
            self.fec.on_send_into(fec_packet, &mut self.fec_send_scratch);
            let mut drained = std::mem::take(&mut self.fec_send_scratch);
            for packet in drained.drain(..) {
                let is_systematic = packet.is_systematic;
                let (sequence, repair_index, block_index) = if is_systematic {
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
                // Repairs carry the sliding flag under the streaming codec
                // (TODO-1018) and are tagged by their *anchor's* window -
                // a lane anchor may legitimately sit one aligned window
                // behind the newest source when lanes lag.
                let repair_window = if is_systematic {
                    window
                } else {
                    (sequence / profile.source_count as u64) as u32
                };
                let packet_send_info = if is_systematic {
                    send_info
                } else {
                    crate::transport::SendInfo { bulk_only: false, ..send_info }
                };
                if quic_frame && !is_systematic {
                    let meta = WirePacketMeta {
                        profile,
                        window: repair_window,
                        sequence,
                        repair_index,
                        block_index,
                        systematic: false,
                        sliding: profile.codec == wire::WireCodec::StreamingGf8,
                    };
                    let Some(symbol) = packet.payload_slice() else {
                        return Err(crate::error::ConnectionError::Transport(
                            "repair symbol missing".to_string(),
                        ));
                    };
                    let mut body = vec![0u8; wire::SYMBOL_HEADER_LEN + symbol.len()];
                    let written = wire::write_symbol(meta, symbol, &mut body).map_err(|error| {
                        crate::error::ConnectionError::Transport(error.to_string())
                    })?;
                    body.truncate(written);
                    // TODO-1052: the shared wire ledger pays for the repair
                    // datagram before it is queued. A denied repair is
                    // dropped here - fewer repairs inside the cap is the
                    // specified behavior; the loss is recorded, not
                    // papered over with unbudgeted bytes.
                    if !self.conn.try_spend_wire_repair(body.len() as u64) {
                        crate::telemetry::FEC_REPAIRS_BUDGET_DROPPED.inc();
                        continue;
                    }
                    self.conn.dgram_send_parts(&[wire::QUIC_REPAIR_DISCRIMINATOR], &body).map_err(
                        |error| crate::error::ConnectionError::Transport(error.to_string()),
                    )?;
                    if let Some(raw) = raw_quic.as_ref() {
                        self.conn.set_short_header_pad_target(raw.len());
                    }
                    continue;
                }
                let packet = if quic_frame && is_systematic {
                    let raw = raw_quic.as_ref().ok_or_else(|| {
                        crate::error::ConnectionError::Transport(
                            "systematic quic image missing".into(),
                        )
                    })?;
                    FecPacket::from_block(sequence, raw, self.optimization_manager.memory_pool())
                        .map_err(crate::error::ConnectionError::Transport)?
                } else {
                    packet
                };
                let wire_meta = if quic_frame && is_systematic {
                    None
                } else {
                    Some(WirePacketMeta {
                        profile,
                        window: repair_window,
                        sequence,
                        repair_index,
                        block_index,
                        systematic: is_systematic,
                        sliding: !is_systematic && profile.codec == wire::WireCodec::StreamingGf8,
                    })
                };
                // TODO-1052: raw-mode repairs are repair-class spend too.
                // The debit happens at production — before any later
                // padding or cover question sees the ledger — using the
                // exact serialized size (HEADER_LEN + payload).
                if !is_systematic {
                    let wire_len =
                        wire::HEADER_LEN + packet.payload_slice().map(|s| s.len()).unwrap_or(0);
                    if !self.conn.try_spend_wire_repair(wire_len as u64) {
                        crate::telemetry::FEC_REPAIRS_BUDGET_DROPPED.inc();
                        continue;
                    }
                    // TODO-1061: a freshly coded repair never passed
                    // `conn.send`; queueing is its send decision.
                    if let Some(runtime) = self.maybenot.as_mut() {
                        runtime.note_wire_sent(now);
                    }
                }
                self.outgoing_fec_packets.push_back(OutgoingFecPacket {
                    wire_meta,
                    packet,
                    send_info: packet_send_info,
                    congestion_controlled: packet_send_info.congestion_controlled,
                    paired: !is_systematic,
                });
                self.pair_swap_on_join();
            }
            self.fec_tx_sequence = self.fec_tx_sequence.wrapping_add(1);
        } else {
            self.packet_id_counter = self.packet_id_counter.wrapping_add(1);
            self.reorder_window_tick(&send_info, now);
            let outgoing = OutgoingFecPacket {
                packet: fec_packet,
                wire_meta: None,
                send_info,
                congestion_controlled: send_info.congestion_controlled,
                paired: false,
            };
            if send_info.path_control {
                self.outgoing_fec_packets.push_front(outgoing);
            } else {
                self.outgoing_fec_packets.push_back(outgoing);
                self.pair_swap_on_join();
            }
        }

        // Single outbound stealth timing owner: core merges StealthManager shaping delay
        // with transport jitter (when enabled) into one release deadline. Connection::send
        // no longer maintains a parallel next_send_at gate.
        if established && !send_info.path_control {
            // TODO-903: ACK-only packets are not congestion-controlled
            // (SendInfo.congestion_controlled == false, set from
            // wrote_ack_eliciting in the transport). Delaying them only delays
            // the peer's loss-recovery and RTT signals - the wire shape gains
            // nothing because the ACK cadence is already randomized by the
            // incoming packet stream. Stealth jitter stays on every
            // ack-eliciting (data/probe) packet.
            let transport_jitter = if send_info.congestion_controlled {
                self.conn.transport_stealth_jitter_delay()
            } else {
                None
            };
            self.stealth_window_tick(
                self.bounded_stealth_release(now, delay_opt, transport_jitter),
                now,
            );
        }
        // Every datagram materialized inside a drain epoch spends one unit
        // of its budget - including the packet whose window edge armed it.
        if self.burst_draining.get() {
            self.drain_budget.set(self.drain_budget.get().saturating_sub(1));
        }
        Ok(ProduceOutcome::Ready)
    }

    /// Emit the queued packet at `emit_idx`: transactional write into the
    /// caller buffer, ownership transfer only after the bytes are committed.
    fn emit_queued_packet(
        &mut self,
        buf: &mut [u8],
        now: Instant,
        emit_idx: usize,
    ) -> Result<(usize, crate::transport::SendInfo), crate::error::ConnectionError> {
        let (len, mut send_info, shape, congestion_controlled) = {
            let packet = self
                .outgoing_fec_packets
                .get(emit_idx)
                .ok_or_else(|| "FEC queue emptied unexpectedly".to_string())?;
            let len = packet.write_to(buf)?;
            (len, packet.send_info, packet.telemetry_shape(), packet.congestion_controlled)
        };
        self.outgoing_fec_packets.remove(emit_idx);
        if self.burst_draining.get() {
            self.send_yield_counts[4].set(self.send_yield_counts[4].get() + 1);
        }
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
        if let Some(runtime) = self.maybenot.as_mut() {
            runtime.note_wire_emit(now);
        }
        self.record_paced_packet(now, len, congestion_controlled);
        Ok((len, send_info))
    }

    /// A newly deferred datagram must not starve the drain: when another
    /// queued packet is already ripe, emit it instead of yielding empty so
    /// the send pipeline keeps flowing at drain rate rather than
    /// serializing into one packet per poll tick.
    fn emit_ripe_or_yield(
        &mut self,
        buf: &mut [u8],
        now: Instant,
        zero_send_info: crate::transport::SendInfo,
    ) -> Result<(usize, crate::transport::SendInfo), crate::error::ConnectionError> {
        match self.next_emit_index() {
            Some(emit_idx) => self.emit_queued_packet(buf, now, emit_idx),
            None => Ok((0, zero_send_info)),
        }
    }

    /// Raw wire emit for connections without a FEC wire profile: the transport
    /// writes the datagram straight into the caller's buffer. A stealth or jitter
    /// deferral is the only case that pays a copy - the bytes are materialized
    /// into a pooled block and queued exactly like the pooled path would.
    /// Callers must guarantee `outgoing_fec_packets` is empty so direct
    /// emission cannot reorder ahead of already queued datagrams.
    fn send_with_info_raw(
        &mut self,
        buf: &mut [u8],
        now: Instant,
        established: bool,
    ) -> Result<(usize, crate::transport::SendInfo), crate::error::ConnectionError> {
        let (local_addr, peer_addr) = (self.local_addr, self.peer_addr);
        let zero_send_info = |at: Instant| crate::transport::SendInfo {
            from: local_addr,
            to: peer_addr,
            at,
            congestion_controlled: false,
            path_control: false,
            bulk_only: false,
        };
        // An open deferral window gathers the transport backlog: producing
        // now would only queue a packet that has to sit held, inflating
        // QUIC's in-flight clock toward a spurious PTO loss (TODO-1016).
        self.maybe_abort_window_under_pressure(now);
        if self.deferral_window_open(now) {
            self.send_yield_counts[0].set(self.send_yield_counts[0].get() + 1);
            return Ok((0, zero_send_info(now)));
        }
        // TODO-1061: a matured Maybenot block stalls production like the
        // deferral window — nothing is produced, so the transport's own
        // datagram queue holds the backlog as honest backpressure. Pure
        // ACKs keep flowing.
        if established && self.maybenot_blocks_send(now) {
            self.send_yield_counts[5].set(self.send_yield_counts[5].get() + 1);
            return Ok((0, zero_send_info(now)));
        }
        let (write, mut send_info) = match self.conn.send(buf) {
            Ok(v) => v,
            Err(crate::error::ConnectionError::Done) => {
                // `Done` also covers congestion gating while datagrams are
                // still queued - the drain epoch ends only when the
                // transport backlog is actually empty.
                if self.conn.dgram_send_queue_len() == 0 {
                    self.burst_draining.set(false);
                }
                self.send_yield_counts[3].set(self.send_yield_counts[3].get() + 1);
                return Ok((0, zero_send_info(now)));
            }
            Err(crate::error::ConnectionError::BufferTooShort) => {
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            Err(e) => return Err(crate::error::ConnectionError::Transport(e.to_string())),
        };
        if write == 0 {
            if self.conn.dgram_send_queue_len() == 0 {
                self.burst_draining.set(false);
            }
            self.send_yield_counts[3].set(self.send_yield_counts[3].get() + 1);
            return Ok((0, zero_send_info(now)));
        }

        if let Some(runtime) = self.maybenot.as_mut() {
            runtime.note_wire_sent(now);
        }

        let delay_opt = if send_info.path_control {
            None
        } else {
            self.stealth_manager
                .process_outgoing_packet(&mut buf[..write], !send_info.congestion_controlled)
        };

        let packet_id = self.packet_id_counter;
        self.packet_id_counter = self.packet_id_counter.wrapping_add(1);

        if established && !send_info.path_control {
            let transport_jitter = if send_info.congestion_controlled {
                self.conn.transport_stealth_jitter_delay()
            } else {
                None
            };
            self.stealth_window_tick(
                self.bounded_stealth_release(now, delay_opt, transport_jitter),
                now,
            );
            self.reorder_window_tick(&send_info, now);
            // A window edge expiring inside the ticks arms the drain
            // mid-call: this packet belongs to the burst batch, so it
            // takes the queue + permuted-pick path instead of slipping
            // out in order ahead of the train it triggered. An armed
            // drain also queues raw-path packets so the batch emits
            // through one reorder-aware emitter.
            if self.burst_draining.get() {
                let mut send_buffer = PooledBlock::new(self.optimization_manager.memory_pool());
                if send_buffer.len() < write {
                    return Err(crate::error::ConnectionError::BufferTooShort);
                }
                send_buffer[..write].copy_from_slice(&buf[..write]);
                let send_pool = send_buffer.pool();
                let mut fec_packet = FecPacket::from_pooled_blocks(
                    packet_id,
                    Some(send_buffer),
                    write,
                    true,
                    None,
                    0,
                    send_pool,
                )
                .map_err(crate::error::ConnectionError::Transport)?;
                fec_packet.seq = packet_id;
                self.outgoing_fec_packets.push_back(OutgoingFecPacket {
                    packet: fec_packet,
                    wire_meta: None,
                    send_info,
                    congestion_controlled: send_info.congestion_controlled,
                    paired: false,
                });
                self.pair_swap_on_join();
                // A datagram materialized inside a drain epoch spends one
                // unit of its budget.
                self.drain_budget.set(self.drain_budget.get().saturating_sub(1));
                return self.emit_ripe_or_yield(buf, now, zero_send_info(now));
            }
        }

        send_info.at = now;
        log::trace!(
            "connection.send: emitting packet len={} dgram_queue_after={} remaining_fec={}",
            write,
            self.conn.dgram_send_queue_len(),
            self.outgoing_fec_packets.len()
        );
        if self.fec.telemetry_enabled() {
            self.fec.observe_wire_send(true, write, write);
        }
        if let Some(runtime) = self.maybenot.as_mut() {
            runtime.note_wire_emit(now);
        }
        self.record_paced_packet(now, write, send_info.congestion_controlled);
        Ok((write, send_info))
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

    /// Caps a requested shaping delay at `pto / 4`. An unknown or zero PTO
    /// yields zero delay so the send clock cannot invent loss.
    pub(crate) fn clamp_shaping_delay(requested: Duration, pto: Duration) -> Duration {
        if requested.is_zero() || pto < Duration::from_nanos(4) {
            return Duration::ZERO;
        }
        let bound = pto / 4;
        if requested <= bound {
            requested
        } else {
            bound
        }
    }

    fn bounded_stealth_release(
        &self,
        now: Instant,
        stealth_manager_delay: Option<Duration>,
        transport_jitter: Option<Duration>,
    ) -> Option<Instant> {
        let pto = self.conn.current_pto_delay();
        let stealth_manager_delay = stealth_manager_delay.map(|delay| {
            let clamped = Self::clamp_shaping_delay(delay, pto);
            if clamped < delay {
                crate::telemetry::CHOKE_DELAY_CLAMPED_TOTAL.inc();
            }
            clamped
        });
        let transport_jitter = transport_jitter.map(|delay| {
            let clamped = Self::clamp_shaping_delay(delay, pto);
            if clamped < delay {
                crate::telemetry::CHOKE_DELAY_CLAMPED_TOTAL.inc();
            }
            clamped
        });
        let stealth_manager_delay = stealth_manager_delay.filter(|delay| !delay.is_zero());
        let transport_jitter = transport_jitter.filter(|delay| !delay.is_zero());
        Self::compute_outbound_stealth_release(now, stealth_manager_delay, transport_jitter)
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
