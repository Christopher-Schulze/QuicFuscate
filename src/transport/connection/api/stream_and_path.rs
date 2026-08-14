use super::*;

impl Connection {
    /// Server name (SNI) from TLS provider
    pub fn server_name(&self) -> Option<&str> {
        self.tls_provider.as_ref().and_then(|p| p.server_name_get())
    }

    /// Stream priority
    /// Sets urgency and incremental scheduling hints for a stream.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_priority(
        &mut self,
        stream_id: u64,
        _urgency: u8,
        _incremental: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let _stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;
        _stream.priority_urgency = _urgency;
        #[cfg(any(test, feature = "rust-tests"))]
        {
            _stream.priority_incremental = _incremental;
        }

        if self.writable_stream_ids.contains(&stream_id) {
            self.writable_streams.retain(|&id| id != stream_id);
            self.insert_writable_stream_ordered(stream_id);
        }
        Ok(())
    }

    /// Shuts down a stream in the given direction (no-op in minimal impl).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_shutdown(
        &mut self,
        _stream_id: u64,
        _direction: std::net::Shutdown,
        _err: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    /// Returns the remaining send capacity for a stream (fixed 64 KB in minimal impl).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_capacity(&self, _stream_id: u64) -> Result<usize, crate::error::ConnectionError> {
        Ok(65536)
    }

    /// Returns true if the stream has buffered receive data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_readable(&self, _stream_id: u64) -> bool {
        self.readable_stream_ids.contains(&_stream_id)
    }

    /// Returns true if the stream has queued send data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_writable(&self, _stream_id: u64, _len: usize) -> bool {
        self.writable_stream_ids.contains(&_stream_id)
    }

    /// Returns true if the stream's send buffer is empty and FIN has been set.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_finished(&self, _stream_id: u64) -> bool {
        if let Some(s) = self.streams.get(&_stream_id) {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                s.send_fin && s.send_buf.is_empty()
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                s.send_fin && s.send_ring.is_empty()
            }
        } else {
            false
        }
    }

    /// Iterates over stream IDs that have readable data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn readable(&self) -> impl Iterator<Item = u64> + '_ {
        self.readable_streams.iter().copied()
    }

    /// Iterates over stream IDs that have pending send data.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn writable(&self) -> impl Iterator<Item = u64> + '_ {
        self.writable_streams.iter().copied()
    }

    /// Pops and returns the next stream ID that has data ready to read.
    pub fn stream_readable_next(&mut self) -> Option<u64> {
        let stream_id = self.readable_streams.pop_front()?;
        self.readable_stream_ids.remove(&stream_id);
        Some(stream_id)
    }

    /// Pops one peer RESET_STREAM notification for the application protocol owner.
    pub fn stream_reset_next(&mut self) -> Option<(u64, u64)> {
        let reset = self.reset_streams.pop_front()?;
        self.reset_stream_ids.remove(&reset.0);
        Some(reset)
    }

    /// Returns the number of streams with pending writable data.
    pub fn writable_streams_count(&self) -> usize {
        self.writable_streams.len()
    }

    /// Pops the next stream ID with queued send data (test helper).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn stream_writable_next(&mut self) -> Option<u64> {
        let stream_id = self.writable_streams.pop_front()?;
        self.writable_stream_ids.remove(&stream_id);
        Some(stream_id)
    }

    /// Path migration
    pub fn migrate(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.begin_path_validation(local, peer, PathValidationOrigin::LocalMigration, 0)
    }
    /// Change only the local address (migrate source path)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn migrate_source(
        &mut self,
        local: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.begin_path_validation(local, self.peer_addr, PathValidationOrigin::LocalMigration, 0)
    }
    /// Probe a path and emit path lifecycle events for observers/control-plane.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn probe_path(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        if from == to {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        let _ = self.begin_path_validation(from, to, PathValidationOrigin::LocalMigration, 0)?;
        Ok(())
    }

    /// Returns per-path statistics for each validated path.
    pub fn path_stats(&self) -> impl Iterator<Item = PathStats> {
        std::iter::once(PathStats {
            recv: self.stats.recv_bytes,
            sent: self.stats.sent_bytes,
            lost: self.stats.lost as u64,
            rtt: self.rtt,
            cwnd: self.cwnd,
            delivery_rate: self.stats.delivery_rate,
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        })
    }
    // Pacing / Congestion / Release hooks
    /// Returns the next pacing-based release time for outbound packets.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn get_next_release_time(&self) -> Option<Instant> {
        if !self.config.pacing {
            return None;
        }

        let now = self.clock.now();
        let rate_bps = self.recovery.get_pacing_rate().or(self.config.max_pacing_rate)?;
        if rate_bps == 0 || self.bytes_in_flight == 0 {
            return Some(now);
        }

        let release_delay_us =
            ((self.bytes_in_flight as u128) * 1_000_000u128 / rate_bps as u128).max(1) as u64;
        Some(now + Duration::from_micros(release_delay_us))
    }
    /// Whether send pacing is enabled.
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn pacing_enabled(&self) -> bool {
        self.config.pacing
    }

    /// Sends a packet targeting a specific peer address (delegates to `send`).
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_on_path(
        &mut self,
        out: &mut [u8],
        _to: SocketAddr,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send(out)
    }

    /// Returns the next path event, if any
    pub fn path_event_next(&mut self) -> Option<PathEvent> {
        self.poll_path_validation_timeout(self.clock.now());
        if self.path_events.is_empty() {
            None
        } else {
            self.path_events.pop_front()
        }
    }
    /// Active SCIDs count (minimal: 1)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn active_scids(&self) -> usize {
        1
    }
    /// SCIDs left to issue (minimal: 0)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn scids_left(&self) -> usize {
        0
    }
    /// Retire a DCID by sequence (minimal: record in retired_scids)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retire_dcid(&mut self, _dcid_seq: u64) -> Result<(), crate::error::ConnectionError> {
        self.retired_scids.push_back(self.scid);
        Ok(())
    }
    /// Iterate paths (minimal: return peer addr once)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn paths_iter(&self, _from: SocketAddr) -> impl Iterator<Item = SocketAddr> {
        std::iter::once(self.peer_addr)
    }
    /// Send an ACK-eliciting frame hint (mark ACK needed)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_ack_eliciting(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.pkt_spaces[2].ack_elicited = true;
        Ok(())
    }
    /// Send ACK-eliciting on a path (ignored in minimal impl)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn send_ack_eliciting_on_path(
        &mut self,
        _from: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        self.send_ack_eliciting()
    }
    /// Retired scids count
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retired_scids(&self) -> usize {
        self.retired_scids.len()
    }
    /// Next retired scid if any
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn retired_scid_next(&mut self) -> Option<ConnectionId> {
        if self.retired_scids.is_empty() {
            None
        } else {
            self.retired_scids.pop_front()
        }
    }
    /// Available dcids (minimal: 0)
    #[cfg(any(test, feature = "rust-tests"))]
    pub fn available_dcids(&self) -> usize {
        0
    }
}
