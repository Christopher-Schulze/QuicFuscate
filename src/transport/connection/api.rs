use super::*;

mod stream_and_path;

impl Connection {
    #[inline]
    fn is_terminal_control_frame(frame: &Frame<'_>) -> bool {
        matches!(frame, Frame::ConnectionClose { .. } | Frame::ApplicationClose { .. })
    }

    /// Admits a control frame without allowing adversarial producers to grow the queue forever.
    /// Window updates are monotonic and replace an older queued update for the same scope; close
    /// frames can evict one non-terminal advisory frame so the peer still receives the shutdown.
    #[inline]
    pub(super) fn queue_control_frame(queue: &mut VecDeque<Frame<'static>>, frame: Frame<'static>) {
        if matches!(&frame, Frame::MaxData { .. }) {
            if let Some(existing) =
                queue.iter_mut().find(|queued| matches!(queued, Frame::MaxData { .. }))
            {
                *existing = frame;
                return;
            }
        }

        if matches!(&frame, Frame::DataBlocked { .. }) {
            if let Some(existing) =
                queue.iter_mut().find(|queued| matches!(queued, Frame::DataBlocked { .. }))
            {
                *existing = frame;
                return;
            }
        }

        let stream_update = match &frame {
            Frame::MaxStreamData { stream_id, .. } => Some(*stream_id),
            _ => None,
        };
        if let Some(stream_id) = stream_update {
            if let Some(existing) = queue.iter_mut().find(|queued| {
                matches!(
                    queued,
                    Frame::MaxStreamData { stream_id: queued_id, .. } if *queued_id == stream_id
                )
            }) {
                *existing = frame;
                return;
            }
        }

        let stream_blocked = match &frame {
            Frame::StreamDataBlocked { stream_id, .. } => Some(*stream_id),
            _ => None,
        };
        if let Some(stream_id) = stream_blocked {
            if let Some(existing) = queue.iter_mut().find(|queued| {
                matches!(
                    queued,
                    Frame::StreamDataBlocked { stream_id: queued_id, .. } if *queued_id == stream_id
                )
            }) {
                *existing = frame;
                return;
            }
        }

        if queue.len() >= MAX_PENDING_CONTROL_FRAMES {
            if !Self::is_terminal_control_frame(&frame) {
                return;
            }
            let Some(index) =
                queue.iter().position(|queued| !Self::is_terminal_control_frame(queued))
            else {
                return;
            };
            queue.remove(index);
        }
        queue.push_back(frame);
    }

    /// Performs a local 1-RTT write key update and toggles the short-header key phase bit.
    ///
    /// A configured TLS provider owns the write-key transition. Its failure is returned and
    /// never followed by a raw transport fallback, because that would desynchronize the two key
    /// stacks. Connections without a provider use the transport-owned secret path.
    pub fn key_update(&mut self) -> Result<(), crate::error::ConnectionError> {
        let result = if let Some(provider) = self.tls_provider.as_mut() {
            provider.key_update_write(&*self.crypto)
        } else if self.crypto.write().key_update_1rtt_write()? {
            Ok(())
        } else {
            Err(crate::error::ConnectionError::KeyUpdateError)
        };

        if let Err(error) = result {
            self.record_local_error(error.clone());
            return Err(error);
        }

        self.key_phase = !self.key_phase;
        self.refresh_short_header_tag_reserve();
        Ok(())
    }

    /// Receives data from a stream
    #[inline(always)]
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        // Receive stream data
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;

        let len: usize;
        #[cfg(not(feature = "stream_ring_buffer"))]
        {
            let l = std::cmp::min(buf.len(), stream.recv_buf.len());
            buf[..l].copy_from_slice(&stream.recv_buf[..l]);
            stream.recv_buf.drain(..l);
            len = l;
        }
        #[cfg(feature = "stream_ring_buffer")]
        {
            len = stream.recv_ring.read(buf);
        }

        #[cfg(not(feature = "stream_ring_buffer"))]
        let fin = stream.recv_fin && stream.recv_buf.is_empty();
        #[cfg(feature = "stream_ring_buffer")]
        let fin = stream.recv_fin && stream.recv_ring.is_empty();
        Ok((len, fin))
    }

    #[inline]
    fn insert_writable_stream_ordered(&mut self, stream_id: u64) {
        let urgency = self.streams.get(&stream_id).map(|s| s.priority_urgency).unwrap_or(3);
        let mut insert_at = None;
        for (idx, id) in self.writable_streams.iter().enumerate() {
            if let Some(s) = self.streams.get(id) {
                if urgency < s.priority_urgency {
                    insert_at = Some(idx);
                    break;
                }
            }
        }
        if let Some(idx) = insert_at {
            self.writable_streams.insert(idx, stream_id);
        } else {
            self.writable_streams.push_back(stream_id);
        }
    }

    #[inline]
    fn enqueue_writable_stream(&mut self, stream_id: u64) {
        if self.writable_stream_ids.insert(stream_id) {
            self.insert_writable_stream_ordered(stream_id);
        }
    }

    #[inline]
    pub(super) fn remove_front_writable_stream(&mut self, stream_id: u64) {
        debug_assert_eq!(self.writable_streams.front().copied(), Some(stream_id));
        if self.writable_streams.front().copied() == Some(stream_id) {
            self.writable_streams.pop_front();
        } else {
            self.writable_streams.retain(|&id| id != stream_id);
        }
        self.writable_stream_ids.remove(&stream_id);
    }

    /// Sends data on a stream
    #[inline(always)]
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, crate::error::ConnectionError> {
        // Send stream data
        // Compute connection-level pending bytes before borrowing a specific stream mutably
        let pending_conn_after = (self.conn_bytes_sent)
            .saturating_add(self.total_send_buffered_bytes() as u64)
            .saturating_add(buf.len() as u64);
        if pending_conn_after > self.peer_max_data {
            // Inform peer we are blocked by connection window
            Self::queue_control_frame(
                &mut self.pending_control,
                Frame::DataBlocked { limit: self.peer_max_data },
            );
            return Err(crate::error::ConnectionError::FlowControl);
        }

        let stream = self.streams.entry(stream_id).or_insert_with(|| Stream {
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

        // Sender-side flow control checks (per-stream)
        let pending_stream_after = {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_buf.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_ring.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
        };
        if pending_stream_after > stream.max_stream_data_tx {
            Self::queue_control_frame(
                &mut self.pending_control,
                Frame::StreamDataBlocked { stream_id, limit: stream.max_stream_data_tx },
            );
            return Err(crate::error::ConnectionError::FlowControl);
        }

        if stream.send_fin {
            return Err(crate::error::ConnectionError::FinalSize);
        }
        // Append payload and mark FIN if requested
        #[cfg(not(feature = "stream_ring_buffer"))]
        stream.send_buf.extend_from_slice(buf);
        #[cfg(feature = "stream_ring_buffer")]
        {
            let written = stream.send_ring.write(buf);
            if written < buf.len() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
        }
        stream.send_fin = fin;
        self.enqueue_writable_stream(stream_id);

        Ok(buf.len())
    }

    /// Enqueues an inbound DATAGRAM only when the queue and zero-copy block contract permit it.
    pub(super) fn enqueue_received_datagram(&mut self, data: Cow<'_, [u8]>) {
        if self.is_dgram_recv_queue_full() {
            return;
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_recv_queue.push_back(data.into_owned());
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let payload = data.as_ref();
            if payload.len() > self.dgram_pool.block_size() {
                return;
            }
            let mut buffer = crate::optimize::PooledBlock::new(Arc::clone(&self.dgram_pool));
            buffer[..payload.len()].copy_from_slice(payload);
            self.dgram_recv_queue.push_back(DatagramBuffer { data: buffer, len: payload.len() });
        }
    }

    /// Dequeues one received DATAGRAM frame into the caller's buffer.
    #[inline(always)]
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len());
            buf[..len].copy_from_slice(&dgram[..len]);
            Ok(len)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len);
            buf[..len].copy_from_slice(&dgram.data[..len]);
            Ok(len)
        }
    }

    /// Enqueues a DATAGRAM frame for transmission on the next send call.
    #[inline(always)]
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        if self.is_dgram_send_queue_full() {
            return Err(crate::error::ConnectionError::DgramQueueFull);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.push_back(buf.to_vec());
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            if buf.len() > self.dgram_pool.block_size() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
            let mut data = crate::optimize::PooledBlock::new(Arc::clone(&self.dgram_pool));
            data[..buf.len()].copy_from_slice(buf);
            self.dgram_send_queue.push_back(DatagramBuffer { data, len: buf.len() });
        }
        Ok(())
    }

    /// Dequeues one received DATAGRAM as an owned `Vec<u8>` (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_vec(&mut self) -> Result<Vec<u8>, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            if let Some(v) = self.dgram_recv_queue.pop_front() {
                Ok(v)
            } else {
                Err(crate::error::ConnectionError::Done)
            }
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let Some(dgram) = self.dgram_recv_queue.pop_front() else {
                return Err(crate::error::ConnectionError::Done);
            };
            let mut vec = vec![0u8; dgram.len];
            vec.copy_from_slice(&dgram.data[..dgram.len]);
            Ok(vec)
        }
    }

    /// Peeks at the front received DATAGRAM without consuming it.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_peek(
        &self,
        buf: &mut [u8],
        len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len()));
            buf[..n].copy_from_slice(&front[..n]);
            Ok(n)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len));
            buf[..n].copy_from_slice(&front.data[..n]);
            Ok(n)
        }
    }

    /// Returns the byte length of the front received DATAGRAM, if any.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_front_len(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.front().map(|v| v.len());
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.front().map(|v| v.len);
    }

    /// Number of DATAGRAMs currently in the receive queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_queue_len(&self) -> usize {
        self.dgram_recv_queue.len()
    }
    /// Total bytes across all DATAGRAMs in the receive queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_recv_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.iter().map(|v| v.len).sum();
    }
    /// Number of DATAGRAMs currently in the send queue.
    pub fn dgram_send_queue_len(&self) -> usize {
        self.dgram_send_queue.len()
    }
    /// Total bytes across all DATAGRAMs in the send queue.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_send_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_send_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_send_queue.iter().map(|v| v.len).sum();
    }
    fn is_dgram_send_queue_full(&self) -> bool {
        let lim = self.config.dgram_send_max_queue_len;
        lim > 0 && self.dgram_send_queue.len() >= lim
    }
    fn is_dgram_recv_queue_full(&self) -> bool {
        let lim = self.config.dgram_recv_max_queue_len;
        lim > 0 && self.dgram_recv_queue.len() >= lim
    }
    /// Enqueues an owned `Vec<u8>` as a DATAGRAM for transmission (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_send_vec(&mut self, buf: Vec<u8>) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        // Delegate to dgram_send so zero_copy path is handled uniformly
        self.dgram_send(&buf[..])
    }
    /// Removes outgoing DATAGRAMs matching the predicate.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_purge_outgoing<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.retain(|d| !f(d));
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_send_queue.retain(|d| !f(&d.data[..d.len]));
        }
    }
    /// Returns the maximum DATAGRAM payload size, or `None` if the send queue is full.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        if self.is_dgram_send_queue_full() {
            None
        } else {
            Some(self.dgram_send_max_size)
        }
    }

    /// Returns true if the connection is established
    pub fn is_established(&self) -> bool {
        self.is_established
            && !self.is_closed
            && self
                .tls_provider
                .as_ref()
                .map(|provider| provider.handshake_complete())
                .unwrap_or(true)
    }

    /// Returns true only when an outer data-plane envelope cannot capture a
    /// pending Initial or Handshake packet.
    pub fn post_handshake_datagram_ready(&mut self) -> Result<bool, crate::error::ConnectionError> {
        self.poll_tls_and_validate_versions()?;
        if !self.is_established() {
            return Ok(false);
        }
        // PTO probes for Initial/Handshake are flushed before 1-RTT data; a
        // non-zero outer datagram overhead (FEC) would leave the handshake
        // probe with too little buffer to reach MIN_CLIENT_INITIAL_LEN.
        if self
            .pending_probe_spaces
            .iter()
            .any(|s| *s == recovery::PacketSpace::Initial || *s == recovery::PacketSpace::Handshake)
        {
            return Ok(false);
        }
        let pending_handshake = self
            .tls_provider
            .as_ref()
            .map(|provider| provider.has_pending_handshake_send())
            .unwrap_or_else(|| self.crypto.read().has_pending_handshake_send());
        Ok(!pending_handshake)
    }

    /// Return the sender-side fountain seed derived from the active 1-RTT secret.
    pub(crate) fn fec_send_fountain_seed(&self) -> Option<u64> {
        let crypto = self.crypto.read();
        crypto
            .write_secret_1rtt
            .as_ref()
            .map(|secret| qf_fec::derive_fountain_seed(secret.as_slice()))
    }

    /// Return the receiver-side fountain seed derived from the active 1-RTT secret.
    pub(crate) fn fec_receive_fountain_seed(&self) -> Option<u64> {
        let crypto = self.crypto.read();
        crypto
            .read_secret_1rtt
            .as_ref()
            .map(|secret| qf_fec::derive_fountain_seed(secret.as_slice()))
    }

    /// Returns true if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }

    /// Returns the terminal error exposed to callers, preferring the local root cause.
    pub fn error(&self) -> Option<&crate::error::ConnectionError> {
        self.local_error.as_ref().or(self.remote_error.as_ref())
    }

    /// Returns the first locally decided terminal/protocol error.
    pub fn local_error(&self) -> Option<&crate::error::ConnectionError> {
        self.local_error.as_ref()
    }

    /// Returns the first close reason received from the peer.
    pub fn remote_error(&self) -> Option<&crate::error::ConnectionError> {
        self.remote_error.as_ref()
    }
    /// Returns true if the connection has any readable streams
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_readable(&self) -> bool {
        !self.readable_streams.is_empty()
    }
    /// Returns whether this is a server-side connection
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Return the negotiated QUIC version used by this connection.
    pub(crate) fn config_version(&self) -> u32 {
        self.config.version()
    }

    /// Returns a mutable reference to the BBR3 recovery/congestion controller.
    pub fn recovery_mut(&mut self) -> &mut recovery::Recovery {
        &mut self.recovery
    }

    /// Loss-rate threshold above which FEC escalation is triggered.
    pub fn fec_escalation_threshold(&self) -> f32 {
        self.fec_escalation_threshold
    }
    /// Returns true if the connection is draining
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_draining(&self) -> bool {
        self.is_draining
    }
    /// Returns true if the connection has timed out
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_timed_out(&self) -> bool {
        self.timeout_count > 0
    }
    /// Returns true when a session ticket is present in config or provider state.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_resumed(&self) -> bool {
        self.tls_provider.as_ref().is_some_and(|provider| provider.handshake_resumed())
    }
    /// Returns true while 0-RTT is allowed and handshake has not fully established.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn is_in_early_data(&self) -> bool {
        self.config.enable_early_data && !self.is_established && !self.is_closed
    }

    /// Returns connection statistics
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Return secret-free, connection-owned truth for every QUIC packet-protection level.
    pub fn packet_protection_snapshot(&self) -> crate::qftls::PacketProtectionSnapshot {
        self.crypto.read().packet_protection_snapshot()
    }

    /// Export the authenticated TLS keying material for a post-handshake protocol owner.
    pub(crate) fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<crate::qftls::SensitiveKeyingMaterial, crate::error::ConnectionError> {
        if !self.tls_handshake_complete() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.tls_provider
            .as_ref()
            .ok_or(crate::error::ConnectionError::InvalidState)?
            .export_keying_material(label, context, length)
    }

    /// Install the packet owner derived by an already-active private negotiation machine.
    pub(crate) fn activate_private_packet_protection(
        &mut self,
        machine: &crate::qftls::PrivateNegotiationMachine,
        epoch: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        if !self.tls_handshake_complete()
            || machine.state() != crate::qftls::PrivateNegotiationState::AdvancedActive
        {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        let family =
            machine.selected_family().ok_or(crate::error::ConnectionError::InvalidState)?;
        let write_boundary =
            machine.write_boundary().ok_or(crate::error::ConnectionError::InvalidState)?;
        let read_boundary =
            machine.peer_write_boundary().ok_or(crate::error::ConnectionError::InvalidState)?;
        let (write_direction, read_direction) = if self.is_server {
            (
                crate::qftls::PrivateDirection::ServerToClient,
                crate::qftls::PrivateDirection::ClientToServer,
            )
        } else {
            (
                crate::qftls::PrivateDirection::ClientToServer,
                crate::qftls::PrivateDirection::ServerToClient,
            )
        };
        let schedule = machine
            .epoch_schedule()
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        let write_material = machine
            .derive_material(write_direction, epoch)
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        let read_material = machine
            .derive_material(read_direction, epoch)
            .map_err(|error| crate::error::ConnectionError::CryptoError(error.to_string()))?;
        {
            let mut crypto = self.crypto.write();
            crypto.install_authenticated_private_1rtt_with_schedule(
                family,
                write_material.key.as_slice(),
                write_material.iv.as_slice(),
                read_material.key.as_slice(),
                read_material.iv.as_slice(),
                write_boundary,
                read_boundary,
                Some(schedule),
                Some(write_direction),
                Some(read_direction),
                self.key_phase,
            )?;
        }
        self.refresh_short_header_tag_reserve();
        Ok(())
    }

    /// Smoothed packet-loss signal owned by the active congestion controller.
    pub(crate) fn recovery_loss_rate(&self) -> f32 {
        self.recovery.get_loss_rate()
    }

    /// Lightweight telemetry: ECN counters since last ACK emission
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn ecn_counts(&self) -> (u64, u64, u64) {
        (self.ecn_ect0, self.ecn_ect1, self.ecn_ce)
    }

    /// Current send quantum (bytes) derived from recovery
    pub fn send_quantum(&self) -> usize {
        self.recovery.send_quantum()
    }

    /// Active production pacing rate in bytes per second.
    ///
    /// A configured maximum caps the congestion controller estimate. Before
    /// the controller has a delivery sample, the configured value is used as
    /// the startup rate when present.
    pub(crate) fn pacing_rate(&self) -> Option<u64> {
        if !self.config.pacing {
            return None;
        }
        match (self.recovery.get_pacing_rate(), self.config.max_pacing_rate) {
            (Some(rate), Some(cap)) => Some(rate.min(cap)).filter(|rate| *rate > 0),
            (Some(rate), None) | (None, Some(rate)) => Some(rate).filter(|rate| *rate > 0),
            (None, None) => None,
        }
    }
    /// True if we can send at least one datagram of size `sz` within cwnd
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    /// Current RTT estimate
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Return the immutable environment generation owned by this connection.
    pub(crate) fn environment_snapshot(&self) -> &crate::env_utils::EnvSnapshot {
        self.environment.as_ref()
    }

    /// Confirmed packetization-layer MTU for the active path.
    pub fn effective_path_mtu(&self) -> usize {
        self.pmtu.effective_mtu().min(self.dgram_send_max_size)
    }

    /// Configured upper bound for one outgoing UDP payload.
    pub fn max_send_udp_payload_size(&self) -> usize {
        self.dgram_send_max_size
    }

    /// Configured upper bound for one incoming UDP payload.
    pub fn max_recv_udp_payload_size(&self) -> usize {
        self.dgram_send_max_size
    }

    /// Bytes currently considered in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Current congestion window in bytes.
    pub fn cwnd(&self) -> usize {
        self.cwnd
    }

    /// Estimated delivery rate (bytes/s)
    pub fn delivery_rate(&self) -> u64 {
        self.stats.delivery_rate
    }

    /// ACK-eliciting threshold (packets) before emitting ACK
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn ack_eliciting_threshold(&self) -> u64 {
        self.config.ack_eliciting_threshold
    }

    /// Whether the transport-level stealth jitter gate is active (core-owned scheduling).
    pub(crate) fn transport_stealth_timing_active(&self) -> bool {
        self.config.stealth_timing_enabled && !self.config.external_pacing
    }

    /// Configured transport stealth jitter ceiling in microseconds.
    pub(crate) fn transport_stealth_timing_max_jitter_us(&self) -> u32 {
        self.config.stealth_timing_max_jitter_us
    }

    /// Samples a transport stealth jitter delay when the gate is active.
    pub(crate) fn transport_stealth_jitter_delay(&self) -> Option<Duration> {
        if !self.transport_stealth_timing_active() {
            return None;
        }
        let max_jitter_us = self.transport_stealth_timing_max_jitter_us();
        if max_jitter_us == 0 {
            return None;
        }
        // Gradual timing rate: scale jitter magnitude by the configured rate
        // (0-100%). At 100%, full jitter is applied; at 50%, jitter is halved.
        // This implements the gradual stealth escalation from TODO-416.
        let timing_rate = self.config.stealth_timing_rate;
        let scaled_max = if timing_rate >= 100 {
            max_jitter_us
        } else {
            ((max_jitter_us * timing_rate as u32) / 100).max(1)
        };
        let jitter_us = crate::transport::rand::fast_rand_u64_uniform(scaled_max as u64 + 1);
        Some(Duration::from_micros(jitter_us))
    }

    /// Whether external pacing is enabled (internal sleeps disabled)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn external_pacing_enabled(&self) -> bool {
        self.config.external_pacing
    }

    /// Whether stealth timing obfuscation is enabled (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_timing_enabled_for_test(&self) -> bool {
        self.config.stealth_timing_enabled
    }

    /// Configured maximum jitter in microseconds (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_timing_max_jitter_us_for_test(&self) -> u32 {
        self.config.stealth_timing_max_jitter_us
    }

    /// Whether stealth padding is enabled (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_padding_enabled_for_test(&self) -> bool {
        self.config.stealth_padding_enabled
    }

    /// Active stealth padding strategy ID (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_padding_strategy_for_test(&self) -> u8 {
        self.config.stealth_padding_strategy
    }

    /// Whether the Brain sensor-fusion engine may steer this connection (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn intelligent_stealth_runtime_enabled_for_test(&self) -> bool {
        self.intelligent_stealth_runtime
    }

    /// Whether a stealth congestion-control wrapper is currently installed.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stealth_cc_active_for_test(&self) -> bool {
        self.recovery.stealth_mode_active()
    }

    /// Current Brain runtime permission set (test accessor).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn brain_runtime_permissions_for_test(&self) -> crate::transport::BrainRuntimePermissions {
        self.brain_runtime_permissions
    }

    /// Set or clear the transport observer (integration hook)
    pub fn set_observer(&mut self, obs: Option<Arc<dyn TransportObserver>>) {
        self.observer = obs;
    }

    pub(crate) fn intelligent_stealth_runtime_enabled(&self) -> bool {
        self.intelligent_stealth_runtime
    }

    pub(crate) fn set_intelligent_stealth_runtime(&mut self, enabled: bool) {
        self.intelligent_stealth_runtime = enabled;
    }

    /// Enables or disables Brain-driven stealth runtime for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_intelligent_stealth_runtime_for_test(&mut self, enabled: bool) {
        self.set_intelligent_stealth_runtime(enabled);
    }

    pub(crate) fn brain_runtime_permissions(&self) -> crate::transport::BrainRuntimePermissions {
        self.brain_runtime_permissions
    }

    pub(crate) fn set_brain_runtime_permissions(
        &mut self,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
        self.brain_runtime_permissions = permissions;
    }

    /// Overrides Brain runtime permissions for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_brain_runtime_permissions_for_test(
        &mut self,
        permissions: crate::transport::BrainRuntimePermissions,
    ) {
        self.set_brain_runtime_permissions(permissions);
    }

    pub(super) fn install_recovery_fec_callbacks(&mut self) {
        let sent_pkts = Arc::clone(&self.fec_cb_sent_packets);
        let lost_pkts = Arc::clone(&self.fec_cb_lost_packets);
        let sent_bytes = Arc::clone(&self.fec_cb_sent_bytes);
        let lost_bytes = Arc::clone(&self.fec_cb_lost_bytes);
        self.recovery.set_fec_callbacks(
            move |_pn, bytes| {
                sent_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                sent_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
            move |_pn, bytes| {
                lost_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                lost_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
        );
    }
    /// Adjust ACK-eliciting threshold at runtime
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.config.ack_eliciting_threshold = thr.max(1);
    }
    /// Toggle external pacing controller at runtime
    pub(crate) fn set_external_pacing(&mut self, v: bool) {
        self.config.external_pacing = v;
    }
    /// Toggles external pacing for this connection (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn set_external_pacing_for_test(&mut self, v: bool) {
        self.set_external_pacing(v);
    }
    /// Adjust streaming FEC emission interval (AdaptiveFec only)
    pub fn set_fec_stream_every(&mut self, every: usize) {
        self.fec_ctrl_delta.stream_every = Some(every.clamp(1, 32));
    }
    /// Enable/disable stealth timing and set max jitter
    pub(crate) fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.config.stealth_timing_enabled = enabled;
        self.config.stealth_timing_max_jitter_us = max_jitter_us;
    }
    /// Set adaptive padding granularity (>=1)
    pub(crate) fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.config.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }
    /// Set browser mimic bias (1..=4)
    pub(crate) fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.config.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }
    /// Adjust stealth padding parameters at runtime
    pub(crate) fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.config.stealth_padding_enabled = enabled;
        self.config.stealth_padding_strategy = strategy;
        self.config.stealth_padding_max_size = max_size;
    }
    /// Set padding application rate (0-100%): fraction of packets that receive padding.
    pub(crate) fn set_stealth_padding_rate(&mut self, rate: u8) {
        self.config.stealth_padding_rate = rate.min(100);
    }
    /// Set timing obfuscation rate (0-100%): scales jitter magnitude.
    pub(crate) fn set_stealth_timing_rate(&mut self, rate: u8) {
        self.config.stealth_timing_rate = rate.min(100);
    }
    pub(crate) fn apply_brain_stealth_runtime_delta(
        &mut self,
        delta: crate::transport::StealthRuntimeDelta,
    ) -> Result<(), crate::transport::recovery::StealthShaperError> {
        if let Some(pacing) = delta.external_pacing {
            self.set_external_pacing(pacing);
        }
        if let Some((enabled, max_jitter_us)) = delta.timing {
            self.set_stealth_timing(enabled, max_jitter_us);
        }
        if let Some(bias) = delta.mimic_bias {
            self.set_stealth_mimic_bias(bias);
        }
        if let Some(granularity) = delta.adaptive_granularity {
            self.set_stealth_adaptive_granularity(granularity);
        }
        if let Some(profile) = delta.cc_profile {
            self.set_cc_stealth_profile(true, profile)?;
        }
        if let Some((enabled, strategy, max_size)) = delta.padding {
            self.set_stealth_padding(enabled, strategy, max_size);
        }
        if let Some(rate) = delta.padding_rate {
            self.set_stealth_padding_rate(rate);
        }
        if let Some(rate) = delta.timing_rate {
            self.set_stealth_timing_rate(rate);
        }
        Ok(())
    }
    /// Configure CC stealth profile to shape pacing like common browsers
    pub fn set_cc_stealth_profile(
        &mut self,
        enabled: bool,
        profile: crate::transport::recovery::BrowserProfile,
    ) -> Result<(), crate::transport::recovery::StealthShaperError> {
        self.recovery.set_stealth_mode(enabled, profile)
    }
    /// Force AdaptiveFec into streaming mode for minimal latency
    pub fn force_fec_streaming(&mut self) {
        self.fec_ctrl_delta.force_streaming = true;
    }
    /// Set redundancy hint in parts-per-million on AdaptiveFec (if present)
    pub fn set_fec_redundancy_ppm(&mut self, ppm: u32) {
        self.fec_ctrl_delta.redundancy_ppm = Some(ppm);
    }

    /// Take and clear pending FEC control delta (to be consumed by core FEC)
    pub fn take_fec_control_delta(&mut self) -> FecControlDelta {
        let d = self.fec_ctrl_delta;
        self.fec_ctrl_delta = FecControlDelta::default();
        d
    }

    /// Take and reset exact transport feedback for live FEC adaptation.
    pub(crate) fn take_fec_callback_feedback(&mut self) -> FecCallbackFeedback {
        let feedback = FecCallbackFeedback {
            sent_packets: self.fec_cb_sent_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            acked_packets: std::mem::take(&mut self.fec_acked_packets),
            lost_packets: self.fec_cb_lost_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
        };
        self.fec_cb_sent_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
        self.fec_cb_lost_bytes.swap(0, std::sync::atomic::Ordering::Relaxed);
        feedback
    }

    /// Returns the source connection ID
    pub fn source_id(&self) -> &ConnectionId {
        &self.scid
    }

    /// Returns the original destination connection ID bound to the Initial packet space.
    ///
    /// The value remains stable for the connection lifetime, including after Retry. It is
    /// exposed read-only so higher authenticated protocols can bind context without inferring
    /// endpoint-specific CID semantics from packet headers.
    pub fn initial_destination_id(&self) -> &ConnectionId {
        &self.initial_dcid
    }

    /// Returns the original client-selected Destination Connection ID, independent of Retry
    /// Initial-key derivation on the server.
    pub fn original_destination_id(&self) -> &ConnectionId {
        &self.original_dcid
    }

    /// Returns the current destination connection ID used for outgoing packets.
    pub fn destination_id(&self) -> &ConnectionId {
        &self.dcid
    }

    /// Return the local CID context only when all required transport IDs exist.
    ///
    /// The returned pair is (initial destination CID, current destination CID). A higher
    /// protocol must combine it with the peer-authenticated role and source CID; this accessor
    /// intentionally does not guess a cross-endpoint ordering.
    pub fn private_protocol_local_connection_ids(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        if self.initial_dcid.is_empty() || self.dcid.is_empty() {
            return None;
        }
        Some((self.initial_dcid.as_ref().to_vec(), self.dcid.as_ref().to_vec()))
    }

    /// Return the canonical connection-ID pair shared by both authenticated endpoints.
    /// The first value is the client original DCID; the second is the server SCID.
    pub(crate) fn private_protocol_canonical_connection_ids(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let original = if self.original_dcid.is_empty() {
            self.initial_dcid.as_ref()
        } else {
            self.original_dcid.as_ref()
        };
        let current = if self.is_server { self.scid.as_ref() } else { self.dcid.as_ref() };
        if original.is_empty() || current.is_empty() {
            return None;
        }
        Some((original.to_vec(), current.to_vec()))
    }

    /// Return the next application packet number without bypassing the QUIC overflow guard.
    pub(crate) fn next_application_send_packet_number(
        &self,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.next_send_packet_number(2)
    }

    /// Returns all source IDs (minimal: only current scid)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn source_ids(&self) -> impl Iterator<Item = &ConnectionId> {
        std::iter::once(&self.scid)
    }
    /// Peer streams left (bidi)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.config.initial_max_streams_bidi
    }
    /// Peer streams left (uni)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.config.initial_max_streams_uni
    }

    /// Closes the connection with an application or transport close frame.
    ///
    /// The first close call wins. The local error records the selected frame
    /// kind, error code, and reason unless an earlier local root cause already
    /// occupies the error slot.
    pub fn close(
        &mut self,
        app: bool,
        err: u64,
        reason: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        // A terminal connection cannot emit any later frames. Preserve the first
        // close kind, code, and reason instead of queueing a second terminal frame.
        if self.is_closed {
            return Ok(());
        }
        self.is_closed = true;
        self.is_draining = true;
        let local_error = if app {
            crate::error::ConnectionError::LocalApplicationClosed {
                error_code: err,
                reason: reason.to_vec(),
            }
        } else {
            crate::error::ConnectionError::LocalConnectionClosed {
                error_code: err,
                frame_type: 0,
                reason: reason.to_vec(),
            }
        };
        self.record_local_error(local_error);
        if let Some(scheduler) = self.traffic_analysis.as_mut() {
            scheduler.cancel();
        }
        // Emit Close frame into control queue.
        if app {
            Self::queue_control_frame(
                &mut self.pending_control,
                Frame::ApplicationClose { error_code: err, reason: Cow::Owned(reason.to_vec()) },
            );
        } else {
            // frame_type=0 (unknown) in minimal implementation
            Self::queue_control_frame(
                &mut self.pending_control,
                Frame::ConnectionClose {
                    error_code: err,
                    frame_type: 0,
                    reason: Cow::Owned(reason.to_vec()),
                },
            );
        }
        Ok(())
    }

    /// Returns the configured idle timeout, or `None` when idle timeout is disabled.
    pub fn timeout(&self) -> Option<Duration> {
        (self.config.max_idle_timeout > 0)
            .then(|| Duration::from_millis(self.config.max_idle_timeout))
    }
    /// Whether the connection has been idle (no inbound packet) for at least the
    /// idle-timeout window. Run loops invoke this each housekeeping tick to decide
    /// whether to drive `on_timeout()`; calling on_timeout() unconditionally every
    /// tick would inflate the loss counter and repeatedly collapse the congestion
    /// window for a perfectly healthy connection.
    pub fn idle_timeout_elapsed(&self) -> bool {
        self.timeout().is_some_and(|window| self.clock.elapsed_since(self.last_activity) >= window)
    }

    /// Returns the duration elapsed since the last inbound packet was received.
    /// Used by the heartbeat watchdog to detect connection loss before the
    /// transport-level idle timeout fires.
    pub fn last_activity_elapsed(&self) -> Duration {
        self.clock.elapsed_since(self.last_activity)
    }

    /// Returns the exact inbound-activity marker used by the heartbeat watchdog.
    ///
    /// This permits opt-in runtime diagnostics to distinguish a transport
    /// receive call that returned from one that completed frame processing and
    /// refreshed inbound activity, without changing transport scheduling.
    pub fn last_activity_marker(&self) -> Instant {
        self.last_activity
    }

    /// Returns true if there are pending ACK frames in the application (1-RTT)
    /// packet space that need to be sent. Used to bypass the congestion gate
    /// for ACK-only packets (RFC 9002 §7.2).
    #[inline(always)]
    pub fn has_pending_application_ack(&self) -> bool {
        self.pkt_spaces[2].has_pending_ack_at(self.clock.now())
    }

    /// Returns the armed traffic-analysis deadline after 1-RTT establishment.
    pub fn traffic_analysis_deadline(&self) -> Option<Instant> {
        if !self.is_established() {
            return None;
        }
        self.traffic_analysis.as_ref().and_then(|scheduler| scheduler.next_deadline())
    }

    /// Advances the single traffic-analysis timer at a runtime wakeup boundary.
    pub fn on_traffic_analysis_timeout(&mut self, now: Instant) {
        if !self.is_established() || self.is_closed {
            return;
        }
        if let Some(scheduler) = self.traffic_analysis.as_mut() {
            scheduler.on_timer(now);
        }
    }

    /// Atomically applies one validated traffic-analysis policy to this live connection.
    pub fn apply_traffic_analysis_policy(
        &mut self,
        policy: crate::transport::config::TrafficAnalysisPolicy,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.is_closed {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.config
            .set_traffic_analysis_policy(policy)
            .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
        self.traffic_analysis_base_policy = policy;
        self.rebuild_traffic_analysis_scheduler();
        Ok(())
    }

    /// Authorizes Intelligent traffic-analysis escalation after QKey proof succeeds.
    pub(crate) fn authorize_intelligent_traffic_analysis(
        &mut self,
        qkey_ceiling: Option<crate::transport::config::TrafficAnalysisPolicy>,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.is_closed {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        let operator_ceiling = self.config.intelligent_traffic_analysis_ceiling();
        let effective_ceiling =
            qkey_ceiling.map_or(operator_ceiling, |ceiling| operator_ceiling.bounded_by(ceiling));
        self.traffic_analysis_base_policy = self.config.traffic_analysis_policy();
        self.traffic_analysis_escalation_ceiling = (effective_ceiling.defense
            != crate::transport::config::TrafficAnalysisDefense::Off)
            .then_some(effective_ceiling);
        Ok(())
    }

    /// Applies the authorized Level-2 defense or restores the authenticated baseline.
    pub(crate) fn apply_intelligent_traffic_analysis_level(
        &mut self,
        level: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        let target = if level >= 2 {
            self.traffic_analysis_escalation_ceiling.unwrap_or(self.traffic_analysis_base_policy)
        } else {
            self.traffic_analysis_base_policy
        };
        if target == self.config.traffic_analysis_policy() {
            return Ok(());
        }
        self.config
            .set_traffic_analysis_policy(target)
            .map_err(|error| crate::error::ConnectionError::Transport(error.to_string()))?;
        self.rebuild_traffic_analysis_scheduler();
        Ok(())
    }

    /// Returns the complete active traffic-analysis policy for this connection.
    pub fn traffic_analysis_policy(&self) -> crate::transport::config::TrafficAnalysisPolicy {
        self.config.traffic_analysis_policy()
    }

    /// Handles timeout
    pub fn on_timeout(&mut self) {
        // Handle connection timeout
        self.timeout_count += 1;

        // Retransmit lost packets
        for stream in self.streams.values_mut() {
            let has_pending = {
                #[cfg(not(feature = "stream_ring_buffer"))]
                {
                    !stream.send_buf.is_empty()
                }
                #[cfg(feature = "stream_ring_buffer")]
                {
                    !stream.send_ring.is_empty()
                }
            };
            if has_pending {
                // Mark for retransmission
                self.stats.lost += 1;
            }
        }

        // RTT estimate is NOT inflated on timeout. Per RFC 9000 §5.1, the RTT
        // estimate is only updated from ACK samples (see account_sent_bytes_for_ack_ranges_with_delay).
        // The previous code added 100ms on every timeout, causing monotonic RTT inflation
        // (0→385ms observed on loopback). The PTO backoff is handled by the loss detection
        // timer, not by inflating self.rtt.
        // Terminal timeout retires recovery through its own owner. Previously this path called
        // the aggregate loss hook and zeroed the connection's `bytes_in_flight` while the three
        // recovery spaces kept their sent maps, time-threshold timers, and PTO state, so a later
        // poll could observe packets and timers belonging to a connection that already reported
        // itself closed.
        if self.bytes_in_flight > 0 {
            let lost = self.bytes_in_flight;
            let now = self.clock.now();
            self.recovery.on_loss(lost, now);
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(lost as u64);
        }
        self.recovery.discard_all_spaces();
        self.cwnd = self.recovery.cwnd;
        self.bytes_in_flight = 0;
        // Update bytes in flight duration (mock)
        if let Some(start) = self.bytes_in_flight_started.take() {
            self.stats.bytes_in_flight_duration =
                self.stats.bytes_in_flight_duration.saturating_add(self.clock.elapsed_since(start));
        }
        // QUIC idle timeout is terminal and silent: no CONNECTION_CLOSE frame
        // is sent, but runtime owners must be able to reap the connection and
        // release its session, address allocation, and policy state.
        self.record_local_error(crate::error::ConnectionError::Timeout);
        self.is_closed = true;
        self.is_draining = true;
        if let Some(scheduler) = self.traffic_analysis.as_mut() {
            scheduler.cancel();
        }
    }
}
