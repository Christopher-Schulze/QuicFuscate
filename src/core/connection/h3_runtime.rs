use super::*;

impl QuicFuscateConnection {
    fn ensure_http3_ready_for_poll(&mut self, context: &str) -> bool {
        if self.h3_conn.is_none() && self.conn.is_established() {
            if let Err(e) = self.init_http3() {
                debug!("Deferred HTTP/3 init failed during {}: {:?}", context, e);
            }
        }
        self.h3_conn.is_some()
    }

    pub(super) fn ensure_http3_initialized(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3_conn.is_none() {
            self.init_http3()?;
        }
        Ok(())
    }

    fn http3_poll_bindings(&self) -> Http3PollBindings {
        Http3PollBindings {
            masque_datagram_cb: self.masque_datagram_cb.clone(),
            masque_control_cb: self.masque_control_cb.clone(),
            masque_cb: self.masque_cb.clone(),
            memory_pool: self.optimization_manager.memory_pool(),
        }
    }

    fn build_http3_request_headers(
        &self,
        method: &'static [u8],
        path: &str,
    ) -> Vec<crate::transport::h3::Header> {
        let host = self.host_header.as_str();
        let mut headers =
            self.stealth_manager.get_http3_header_list(host, path).unwrap_or_default();

        headers.retain(|h| {
            h.name() != b":method"
                && h.name() != b":scheme"
                && h.name() != b":authority"
                && h.name() != b":path"
        });
        headers.insert(0, crate::transport::h3::Header::new(b":path", path.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":authority", host.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":scheme", b"https"));
        headers.insert(0, crate::transport::h3::Header::new(b":method", method));
        Self::inject_qkey_auth_header(self.qkey_auth_token_hex.as_deref(), &mut headers);
        Self::inject_connection_generation_header(self.client_connection_generation, &mut headers);
        headers
    }

    fn send_http3_request_headers(
        &mut self,
        method: &'static [u8],
        path: &str,
        fin: bool,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        let headers = self.build_http3_request_headers(method, path);
        let h3 = self.h3_conn.as_mut().ok_or("h3 not initialized")?;
        h3.send_request(&mut self.conn, &headers, fin).map_err(Into::into)
    }

    fn poll_http3_event_loop<FH, FB>(
        &mut self,
        context: &str,
        verbose_events: bool,
        mut on_headers: FH,
        mut on_body: FB,
    ) -> Result<(), crate::error::ConnectionError>
    where
        FH: FnMut(u64, &[crate::transport::h3::Header]),
        FB: FnMut(u64, &[u8]),
    {
        if self.ensure_http3_ready_for_poll(context) {
            let start = self.clock.now();
            let bindings = self.http3_poll_bindings();
            loop {
                let (intelligent_level, stats) = self.prepare_http3_poll_iteration();
                let Some(ref mut h3) = self.h3_conn else {
                    break;
                };
                Self::emit_due_cover_headers(h3, &mut self.conn, &self.stealth_manager);
                Self::emit_server_push_cover_burst(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &stats,
                    intelligent_level,
                );
                match h3.poll(&mut self.conn) {
                    Ok(Some((sid, crate::transport::h3::Event::Headers { list, .. }))) => {
                        let webtransport_ready = if h3.webtransport_session_pending(sid)
                            && self.conn.is_server()
                        {
                            match h3.accept_webtransport_cover_session(&mut self.conn, sid) {
                                Ok(()) => true,
                                Err(error) => {
                                    warn!(
                                    "WebTransport cover session acceptance failed: sid={} error={:?}",
                                    sid, error
                                );
                                    false
                                }
                            }
                        } else {
                            h3.webtransport_session_established(sid)
                        };
                        if webtransport_ready {
                            if let Err(error) = h3.send_webtransport_unidirectional_stream(
                                &mut self.conn,
                                sid,
                                b"event: ready\ndata: {}\n\n",
                                true,
                            ) {
                                warn!(
                                "WebTransport unidirectional cover stream failed: sid={} error={:?}",
                                sid, error
                            );
                            }
                            if let Err(error) = h3.send_webtransport_bidirectional_stream(
                                &mut self.conn,
                                sid,
                                b"{\"type\":\"ping\"}",
                                true,
                            ) {
                                warn!(
                                "WebTransport bidirectional cover stream failed: sid={} error={:?}",
                                sid, error
                            );
                            }
                        }
                        // Detect peer-initiated MASQUE CONNECT-UDP requests (server side:
                        // the client opens the flow). Record the stream id and provision
                        // QUIC DATAGRAM queues so downlink sends work. Inlined here
                        // because h3 is borrowed from self.h3_conn while we also need
                        // &mut self.conn - a helper taking &mut self would conflict.
                        if Self::is_connect_udp_request(&list)
                            && self.masque_peer_stream_id.is_none()
                        {
                            self.masque_peer_stream_id = Some(sid);
                            self.masque_peer_generation = Self::peer_generation(&list);
                            self.masque_control_sent = false;
                            let _ = h3.enable_masque_datagram(&mut self.conn, sid);
                            crate::telemetry::MASQUE_ACTIVE
                                .store(1, std::sync::atomic::Ordering::Relaxed);
                            info!("MASQUE peer CONNECT-UDP flow recorded (stream={})", sid);
                        }
                        if list
                            .iter()
                            .any(|header| header.name() == b":path" && header.value() == b"/tun")
                        {
                            self.h3_tunnel_rx.entry(sid).or_default();
                            self.h3_peer_tunnel_stream_id.get_or_insert(sid);
                        }
                        on_headers(sid, &list);
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Data))) => {
                        let Some(buf) = self.h3_body_buffer.as_mut() else {
                            return Err(crate::error::ConnectionError::InvalidState);
                        };
                        let body_result: Result<(), crate::error::ConnectionError> = loop {
                            let read = match h3.recv_body(&mut self.conn, sid, buf) {
                                Ok(read) => read,
                                Err(_) => break Ok(()),
                            };
                            if read == 0 {
                                break Ok(());
                            }
                            let result = if let Some(decoder) = self.h3_tunnel_rx.get_mut(&sid) {
                                let normalizer = &self.tunnel_ingress_normalizer;
                                decoder
                                    .push(&buf[..read], |packet| {
                                        let required = normalizer.required_capacity(packet);
                                        if required > packet.len()
                                            && required <= MAX_INNER_IP_PACKET_LEN
                                        {
                                            let mut expanded = [0u8; MAX_INNER_IP_PACKET_LEN];
                                            expanded[..packet.len()].copy_from_slice(packet);
                                            let outcome = normalizer
                                                .normalize_tunnel_ingress_with_capacity(
                                                    &mut expanded,
                                                    packet.len(),
                                                );
                                            if outcome.result != NormalizeResult::Dropped {
                                                on_body(sid, &expanded[..outcome.packet_len]);
                                            }
                                        } else {
                                            let outcome = normalizer
                                                .normalize_tunnel_ingress_with_capacity(
                                                    packet,
                                                    packet.len(),
                                                );
                                            if outcome.result != NormalizeResult::Dropped {
                                                on_body(sid, &packet[..outcome.packet_len]);
                                            }
                                        }
                                    })
                                    .map_err(crate::error::ConnectionError::from)
                            } else {
                                on_body(sid, &buf[..read]);
                                Ok(())
                            };
                            if let Err(error) = result {
                                break Err(error);
                            }
                        };
                        body_result?;
                    }
                    Ok(Some((
                        _sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, mut payload },
                    ))) => {
                        Self::handle_masque_capsule_event(
                            capsule_type,
                            &mut payload,
                            &bindings.masque_datagram_cb,
                            &bindings.masque_control_cb,
                            &bindings.masque_cb,
                            &bindings.memory_pool,
                            &self.tunnel_ingress_normalizer,
                        );
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Reset(err)))) => {
                        self.h3_tunnel_rx.remove(&sid);
                        self.h3_tunnel_response_started.remove(&sid);
                        if self.masque_peer_stream_id == Some(sid) {
                            self.masque_peer_stream_id = None;
                            self.masque_peer_generation = None;
                            self.masque_control_sent = false;
                        }
                        crate::optimize::telemetry::STEALTH_SIGNAL_RST
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if verbose_events {
                            warn!("H3 stream reset: {:?}", err);
                        }
                    }
                    Ok(Some((_id, crate::transport::h3::Event::PriorityUpdate))) => {
                        if verbose_events {
                            debug!("H3 priority update received");
                        }
                    }
                    Ok(Some((_id, crate::transport::h3::Event::GoAway))) => {
                        if verbose_events {
                            info!("H3 GOAWAY received");
                        }
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Finished))) => {
                        self.h3_tunnel_rx.remove(&sid);
                        self.h3_tunnel_response_started.remove(&sid);
                        if self.masque_peer_stream_id == Some(sid) {
                            self.masque_peer_stream_id = None;
                            self.masque_peer_generation = None;
                            self.masque_control_sent = false;
                        }
                        if self.h3_peer_tunnel_stream_id == Some(sid) {
                            self.h3_peer_tunnel_stream_id = None;
                        }
                    }
                    Ok(Some((
                        _id,
                        crate::transport::h3::Event::PushPromise { push_id, headers },
                    ))) => {
                        if verbose_events {
                            info!(
                                "Received stealth push promise {} with {} headers",
                                push_id,
                                headers.len()
                            );
                        }
                    }
                    Ok(None) => break,
                    Err(crate::transport::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
                let expected_flow_id = self
                    .masque_stream_id
                    .or(self.masque_peer_stream_id)
                    .and_then(|stream_id| h3.masque_flow_id(stream_id));
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &bindings.masque_datagram_cb,
                    &bindings.masque_cb,
                    &self.tunnel_ingress_normalizer,
                    expected_flow_id,
                );
            }
            // Always drain MASQUE datagrams after the H3 event loop exits.
            // QUIC DATAGRAM frames (carrying MASQUE CONNECT-UDP payloads) are
            // NOT H3 events: they sit in the QUIC datagram recv queue and are
            // never returned by h3.poll(). Without this post-loop drain, TUN
            // uplink packets would be silently dropped whenever the H3 event
            // queue is empty (the common case after handshake).
            if let Some(ref mut h3) = self.h3_conn {
                let expected_flow_id = self
                    .masque_stream_id
                    .or(self.masque_peer_stream_id)
                    .and_then(|stream_id| h3.masque_flow_id(stream_id));
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &bindings.masque_datagram_cb,
                    &bindings.masque_cb,
                    &self.tunnel_ingress_normalizer,
                    expected_flow_id,
                );
            }
            log::trace!(
                "HTTP/3 events processed in {} ms",
                self.clock.elapsed_since(start).as_millis()
            );
        }
        Ok(())
    }

    fn emit_due_cover_headers(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &StealthManager,
    ) {
        if let Some(headers) = stealth_manager.cover_headers_due() {
            if let Err(e) = h3.send_request(conn, &headers, true) {
                crate::optimize::telemetry::STEALTH_SIGNAL_RST
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                warn!("Cover traffic send failed: {:?}", e);
            } else {
                debug!("Cover traffic request emitted");
            }
        }
    }

    fn dispatch_masque_datagram_payload(
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        payload: &[u8],
    ) {
        if let Some(cb) = masque_datagram_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(payload);
            }
        } else if let Some(cb) = masque_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(0x00, payload);
            }
        }
    }

    fn dispatch_masque_capsule_payload(
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        capsule_type: u64,
        payload: &[u8],
    ) {
        if let Some(cb) = masque_control_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(capsule_type, payload);
            }
        } else if let Some(cb) = masque_cb {
            if let Ok(mut f) = cb.lock() {
                (f)(capsule_type, payload);
            }
        }
    }

    fn dispatch_masque_compressed_datagram(
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        pool: &Arc<crate::optimize::MemoryPool>,
        payload: &[u8],
        dict: Option<&[u8]>,
        normalizer: &PacketNormalizer,
    ) {
        let decoded = match dict {
            Some(dict_bytes) => crate::compress::decompress_with_dict(pool, payload, dict_bytes),
            None => crate::compress::CompressionManager::new(Default::default())
                .decompress_to_pool(pool, payload),
        };
        if let Some((mut blk, used)) = decoded {
            let outcome = normalizer.normalize_tunnel_ingress_with_capacity(&mut blk, used);
            if outcome.result != NormalizeResult::Dropped {
                Self::dispatch_masque_datagram_payload(
                    masque_datagram_cb,
                    masque_cb,
                    &blk[..outcome.packet_len],
                );
            }
        }
    }

    fn handle_masque_capsule_event(
        capsule_type: u64,
        payload: &mut Vec<u8>,
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        memory_pool: &Arc<crate::optimize::MemoryPool>,
        normalizer: &PacketNormalizer,
    ) {
        match capsule_type {
            0x00 => {
                if normalizer.normalize_tunnel_ingress_vec(payload) != NormalizeResult::Dropped {
                    Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, payload);
                }
            }
            0x21 => {
                Self::dispatch_masque_compressed_datagram(
                    masque_datagram_cb,
                    masque_cb,
                    memory_pool,
                    payload,
                    None,
                    normalizer,
                );
            }
            0x22 => {
                if payload.len() >= 9 && payload[0] == 0x5D {
                    let mut hb = [0u8; 2];
                    hb.copy_from_slice(&payload[1..3]);
                    let hash = u16::from_be_bytes(hb);
                    let mut vb = [0u8; 2];
                    vb.copy_from_slice(&payload[3..5]);
                    let ver = u16::from_be_bytes(vb);
                    if let Some(dict) = crate::compress::get_dict_by_id(hash, ver) {
                        Self::dispatch_masque_compressed_datagram(
                            masque_datagram_cb,
                            masque_cb,
                            memory_pool,
                            payload,
                            Some(&dict),
                            normalizer,
                        );
                    }
                }
            }
            _ => {
                Self::dispatch_masque_capsule_payload(
                    masque_control_cb,
                    masque_cb,
                    capsule_type,
                    payload,
                );
            }
        }
    }

    fn drain_masque_datagrams(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &StealthManager,
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_cb: &Option<CapsuleHandler>,
        normalizer: &PacketNormalizer,
        expected_flow_id: Option<u64>,
    ) {
        // Drain whenever a sink is present (TUN bridge) or the stealth runtime
        // explicitly enabled MASQUE datagrams. Without this, MASQUE-framed
        // datagrams would be left in the QUIC datagram queue and either dropped
        // or consumed as corrupted raw bytes by a bare dgram_recv loop.
        let has_sink = masque_datagram_cb.is_some() || masque_cb.is_some();
        if stealth_manager.masque_datagram_enabled() || has_sink {
            while let Some((flow_id, mut payload)) = h3.try_recv_masque_datagram(conn) {
                if expected_flow_id != Some(flow_id) {
                    log::debug!(
                        "dropping MASQUE datagram with unbound flow-id={} expected={:?}",
                        flow_id,
                        expected_flow_id
                    );
                    continue;
                }
                if normalizer.normalize_tunnel_ingress_vec(&mut payload) != NormalizeResult::Dropped
                {
                    Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, &payload);
                }
            }
        }
    }

    /// Returns true if the H3 headers describe a MASQUE CONNECT-UDP request
    /// (`:method: CONNECT` + `:protocol: connect-udp`).
    fn is_connect_udp_request(headers: &[crate::transport::h3::Header]) -> bool {
        let mut method_connect = false;
        let mut protocol_connect_udp = false;
        for h in headers {
            if h.name().eq_ignore_ascii_case(b":method")
                && h.value().eq_ignore_ascii_case(b"CONNECT")
            {
                method_connect = true;
            }
            if h.name().eq_ignore_ascii_case(b":protocol")
                && h.value().eq_ignore_ascii_case(b"connect-udp")
            {
                protocol_connect_udp = true;
            }
        }
        method_connect && protocol_connect_udp
    }

    fn peer_generation(headers: &[crate::transport::h3::Header]) -> Option<u64> {
        let mut generation = None;
        for header in headers {
            if !header.name().eq_ignore_ascii_case(b"x-qf-generation") {
                continue;
            }
            if generation.is_some() || header.value().len() > 20 {
                return None;
            }
            let value = std::str::from_utf8(header.value()).ok()?.parse::<u64>().ok()?;
            if value == 0 {
                return None;
            }
            generation = Some(value);
        }
        generation
    }
}

impl QuicFuscateConnection {
    pub fn init_http3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3_conn.is_none() {
            // Enable a modest QPACK dynamic table to improve compression.
            let mut h3_cfg = crate::transport::h3::Config::new()
                .map_err(|_| crate::transport::h3::Error::InternalError)?;
            // Select capacities based on the active persona.
            let (qpack_capacity, qpack_blocked_streams) =
                self.stealth_manager.qpack_runtime_profile();
            h3_cfg.set_qpack_max_table_capacity(qpack_capacity);
            h3_cfg.set_qpack_blocked_streams(qpack_blocked_streams);
            h3_cfg.set_webtransport_enabled(self.stealth_manager.webtransport_cover_enabled());

            let h3 = crate::transport::h3::Connection::with_transport(&mut self.conn, &h3_cfg)?;
            let mut h3 = h3;
            // Set persona QPACK index policy
            h3.set_qpack_index_policy(self.stealth_manager.qpack_index_policy());
            self.h3_conn = Some(h3);
            // Notify the compression layer about the persona (dictionary selection).
            let persona = self.stealth_manager.current_persona_name();
            crate::compress::set_current_persona(&persona);
        }
        Ok(())
    }

    /// Sends a masqueraded HTTP/3 GET request using the stealth manager.
    pub fn send_http3_request(&mut self, path: &str) -> Result<(), crate::error::ConnectionError> {
        let intelligent_level = self.stealth_manager.intelligent_runtime_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        if let Err(e) = self.ensure_masque_tunnel_for_send() {
            warn!("MASQUE CONNECT-UDP open failed: {:?}", e);
        }
        let start = self.clock.now();
        if let Err(e) = self.send_http3_request_headers(b"GET", path, true) {
            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(e);
        }
        info!("HTTP/3 request sent in {} ms", self.clock.elapsed_since(start).as_millis());
        Ok(())
    }

    /// Initializes HTTP/3 if not yet initialized and returns a writable POST stream id.
    pub fn open_http3_stream_post(
        &mut self,
        path: &str,
    ) -> Result<u64, crate::error::ConnectionError> {
        let stream_id = self.send_http3_request_headers(b"POST", path, false)?;
        if path == "/tun" {
            self.h3_tunnel_rx.entry(stream_id).or_default();
        }
        Ok(stream_id)
    }

    /// Sends a HTTP/3 request body chunk on an existing stream.
    pub fn http3_send_body_chunk(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let intelligent_level = self.stealth_manager.intelligent_runtime_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, data, fin)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Sends one raw IP packet through the fastest safe tunnel carrier.
    ///
    /// Packets that fit the confirmed MASQUE datagram budget use the datagram
    /// fast path. IPv6-minimum packets that do not fit that budget use an
    /// explicitly length-framed HTTP/3 body so arbitrary stream segmentation
    /// cannot merge or split IP packets at the receiver.
    pub fn send_tunnel_packet(
        &mut self,
        stream_id: u64,
        packet: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if packet.is_empty()
            || packet.len() > self.effective_tunnel_mtu()
            || !matches!(packet.first().map(|byte| byte >> 4), Some(4 | 6))
        {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        if packet.len() <= self.effective_masque_mtu() {
            match self.ensure_masque_tunnel_for_send() {
                Ok(Some(sid)) => {
                    if let Some(ref mut h3) = self.h3_conn {
                        match h3.send_masque_datagram(&mut self.conn, sid, packet) {
                            Ok(()) => {
                                log::trace!("MASQUE TX: sid={} {}B", sid, packet.len());
                                return Ok(());
                            }
                            Err(crate::transport::h3::Error::DgramQueueFull) => {
                                return Err(crate::error::ConnectionError::DgramQueueFull);
                            }
                            Err(error) => {
                                warn!(
                                    "MASQUE datagram send failed, using framed H3 fallback: {:?}",
                                    error
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    warn!("MASQUE setup failed, using framed H3 fallback: {:?}", error);
                }
            }
        }

        self.prepare_h3_tunnel_frame(packet)?;
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, &self.h3_tunnel_tx_frame, false)?;
            if !self.h3_tunnel_uplink_fallback_reported {
                info!(
                    "framed H3 tunnel uplink active: sid={} packet={}B masque_limit={}B",
                    stream_id,
                    packet.len(),
                    self.effective_masque_mtu()
                );
                self.h3_tunnel_uplink_fallback_reported = true;
            }
            debug!("framed H3 tunnel uplink TX: sid={} {}B", stream_id, packet.len());
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    fn prepare_h3_tunnel_frame(
        &mut self,
        packet: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let packet_len = u16::try_from(packet.len())
            .map_err(|_| crate::error::ConnectionError::BufferTooShort)?;
        self.h3_tunnel_tx_frame.clear();
        self.h3_tunnel_tx_frame.reserve(H3_TUNNEL_FRAME_HEADER_LEN.saturating_add(packet.len()));
        self.h3_tunnel_tx_frame.extend_from_slice(H3_TUNNEL_FRAME_MAGIC);
        self.h3_tunnel_tx_frame.extend_from_slice(&packet_len.to_be_bytes());
        self.h3_tunnel_tx_frame.extend_from_slice(packet);
        Ok(())
    }

    /// Sends one UDP payload over the active MASQUE DATAGRAM tunnel.
    pub fn send_masque_udp_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.ensure_http3_initialized()?;
        let host = self.host_header.clone();
        let Some(sid) = self.ensure_masque_tunnel(&host)? else {
            return Err("masque tunnel unavailable".into());
        };
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_masque_datagram(&mut self.conn, sid, payload)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Sends an ordinary raw IP packet downlink through the fastest safe peer carrier.
    ///
    /// A bare QUIC datagram fallback was intentionally removed: the client only
    /// drains MASQUE-framed datagrams via `drain_masque_datagrams` and would
    /// never consume a bare dgram, causing silent data loss and queue growth.
    /// The fingerprint normalizer is intentionally not applied here. Only
    /// decoded client-to-server tunnel ingress is normalized.
    pub fn send_masque_downlink(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        if payload.is_empty()
            || payload.len() > self.effective_tunnel_mtu()
            || !matches!(payload.first().map(|byte| byte >> 4), Some(4 | 6))
        {
            debug!(
                "send_masque_downlink: rejected payload len={} first={:?}",
                payload.len(),
                payload.first()
            );
            return Err(crate::error::ConnectionError::BufferTooShort);
        }

        log::trace!("send_masque_downlink: payload len={} masque_mtu={} masque_peer_stream_id={:?} h3_conn={}",
        payload.len(), self.effective_masque_mtu(), self.masque_peer_stream_id, self.h3_conn.is_some());

        if payload.len() <= self.effective_masque_mtu() {
            if let Some(sid) = self.masque_peer_stream_id {
                if let Some(ref mut h3) = self.h3_conn {
                    match h3.send_masque_datagram(&mut self.conn, sid, payload) {
                        Ok(()) => {
                            log::trace!(
                                "MASQUE downlink TX: sid={} {}B dgram_queue={}",
                                sid,
                                payload.len(),
                                self.conn.dgram_send_queue_len()
                            );
                            return Ok(());
                        }
                        Err(crate::transport::h3::Error::DgramQueueFull) => {
                            return Err(crate::error::ConnectionError::DgramQueueFull);
                        }
                        Err(error) => {
                            warn!("MASQUE downlink failed, using framed H3 fallback: {:?}", error);
                        }
                    }
                } else {
                    debug!("send_masque_downlink: no h3_conn for datagram");
                }
            } else {
                debug!("send_masque_downlink: no masque_peer_stream_id");
            }
        } else {
            debug!("send_masque_downlink: payload too large for masque datagram, fallback to H3 stream");
        }

        let Some(stream_id) = self.h3_peer_tunnel_stream_id else {
            debug!("send_masque_downlink: no h3_peer_tunnel_stream_id, returning Done");
            return Err(crate::error::ConnectionError::Done);
        };
        self.prepare_h3_tunnel_frame(payload)?;
        let response_started = self.h3_tunnel_response_started.contains(&stream_id);
        let Some(ref mut h3) = self.h3_conn else {
            return Err(crate::error::ConnectionError::Done);
        };
        if !response_started {
            let headers = [
                crate::transport::h3::Header::new(b":status", b"200"),
                crate::transport::h3::Header::new(
                    b"content-type",
                    b"application/quicfuscate-tunnel",
                ),
            ];
            h3.send_response(&mut self.conn, stream_id, &headers, false)?;
            self.h3_tunnel_response_started.insert(stream_id);
        }
        h3.send_body(&mut self.conn, stream_id, &self.h3_tunnel_tx_frame, false)?;
        if !self.h3_tunnel_downlink_fallback_reported {
            info!(
                "framed H3 tunnel downlink active: sid={} packet={}B masque_limit={}B",
                stream_id,
                payload.len(),
                self.effective_masque_mtu()
            );
            self.h3_tunnel_downlink_fallback_reported = true;
        }
        debug!("framed H3 tunnel downlink TX: sid={} {}B", stream_id, payload.len());
        Ok(())
    }

    /// Maximum raw IP packet that fits the confirmed QUIC/FEC MASQUE path.
    pub fn effective_masque_mtu(&self) -> usize {
        const QUIC_AND_MASQUE_OVERHEAD: usize = 64;
        self.conn
            .effective_path_mtu()
            .min(self.conn.max_send_udp_payload_size())
            .saturating_sub(wire::MAX_DATAGRAM_OVERHEAD + QUIC_AND_MASQUE_OVERHEAD)
    }

    /// Maximum inner IP packet supported by the complete tunnel carrier set.
    /// HTTP/3 framing preserves the IPv6 minimum even when the current MASQUE
    /// datagram payload budget is smaller.
    pub fn effective_tunnel_mtu(&self) -> usize {
        self.effective_masque_mtu().max(IPV6_MINIMUM_LINK_MTU)
    }

    /// Installs a sink for decoded MASQUE datagram payloads (raw IP packets).
    /// Used by both server (uplink: MASQUE → TUN) and client (downlink: MASQUE → TUN).
    pub fn set_masque_datagram_cb(&mut self, cb: DatagramHandler) {
        self.masque_datagram_cb = Some(cb);
    }

    /// Installs a sink for authenticated MASQUE control capsules.
    pub fn set_masque_control_cb(&mut self, cb: CapsuleHandler) {
        self.masque_control_cb = Some(cb);
    }

    /// Bind subsequent client H3 requests to one reconnect generation.
    pub fn set_client_connection_generation(&mut self, generation: u64) {
        self.client_connection_generation = (generation != 0).then_some(generation);
    }

    /// Return the generation supplied by a peer CONNECT-UDP request.
    pub fn masque_peer_generation(&self) -> Option<u64> {
        self.masque_peer_generation
    }

    /// Send one server control capsule on the authenticated peer MASQUE flow.
    ///
    /// The one-shot guard prevents duplicate assignment emission when the server
    /// processes several UDP packets for the same connection. QUIC stream
    /// retransmission provides delivery without application-level replay.
    pub fn send_masque_control_once(
        &mut self,
        capsule_type: u64,
        payload: &[u8],
    ) -> Result<bool, crate::error::ConnectionError> {
        if self.masque_control_sent {
            return Ok(false);
        }
        let stream_id = self.masque_peer_stream_id.ok_or(crate::error::ConnectionError::Done)?;
        let capsule = crate::transport::h3::Connection::encode_capsule(capsule_type, payload);
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.send_capsule(&mut self.conn, stream_id, &capsule, false)?;
        self.masque_control_sent = true;
        Ok(true)
    }

    /// Returns true if a MASQUE datagram sink has been installed.
    pub fn has_masque_datagram_cb(&self) -> bool {
        self.masque_datagram_cb.is_some()
    }

    /// Installs a queue for raw IP packets that must be sent back to the peer
    /// on the peer-initiated MASQUE flow after callback dispatch returns.
    pub fn set_masque_downlink_queue(&mut self, queue: Arc<std::sync::Mutex<MasqueDownlinkQueue>>) {
        self.masque_downlink_queue = Some(queue);
    }

    /// Returns the installed MASQUE downlink queue, if present.
    pub fn masque_downlink_queue(&self) -> Option<Arc<std::sync::Mutex<MasqueDownlinkQueue>>> {
        self.masque_downlink_queue.as_ref().cloned()
    }

    /// Returns true if the MASQUE downlink response queue has been installed.
    pub fn has_masque_downlink_queue(&self) -> bool {
        self.masque_downlink_queue.is_some()
    }

    /// Returns the next queued MASQUE downlink packet, preserving a packet that
    /// previously hit QUIC DATAGRAM backpressure ahead of later responses.
    pub fn pop_masque_downlink_packet(&mut self) -> Option<Vec<u8>> {
        if let Some(packet) = self.masque_downlink_retry.take() {
            return Some(packet);
        }
        let queue = self.masque_downlink_queue.as_ref()?;
        match queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(poisoned) => poisoned.into_inner().pop_front(),
        }
    }

    /// Retains a dequeued MASQUE response for the next send attempt.
    ///
    /// This slot is intentionally separate from the shared bounded queue so a
    /// concurrent DNS producer cannot consume its released capacity and force
    /// the oldest response to be dropped or reordered.
    pub fn retry_masque_downlink_packet(&mut self, packet: Vec<u8>) {
        debug_assert!(self.masque_downlink_retry.is_none());
        self.masque_downlink_retry = Some(packet);
    }

    /// Drops all locally owned MASQUE response packets during terminal teardown.
    pub fn discard_masque_downlink_packets(&mut self) -> (usize, usize) {
        let retry = self.masque_downlink_retry.take();
        let retry_bytes = retry.as_ref().map_or(0, Vec::len);
        let retry_packets = usize::from(retry.is_some());
        let Some(queue) = self.masque_downlink_queue.as_ref() else {
            return (retry_packets, retry_bytes);
        };
        let (queued_packets, queued_bytes) = match queue.lock() {
            Ok(mut guard) => guard.discard_all(),
            Err(poisoned) => poisoned.into_inner().discard_all(),
        };
        (retry_packets.saturating_add(queued_packets), retry_bytes.saturating_add(queued_bytes))
    }

    pub fn poll_http3(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.poll_http3_event_loop(
            "poll_http3",
            true,
            |_sid, list| {
                let mut status_opt: Option<u16> = None;
                for h in list {
                    if h.name() == b":status" {
                        if let Ok(s) = std::str::from_utf8(h.value()) {
                            status_opt = s.parse::<u16>().ok();
                        }
                    }
                }
                if let Some(st) = status_opt {
                    if !(200..300).contains(&st) {
                        warn!("H3 non-2xx status: {}", st);
                    }
                }
                for h in list {
                    debug!(
                        "{}: {}",
                        String::from_utf8_lossy(h.name()),
                        String::from_utf8_lossy(h.value())
                    );
                }
            },
            |sid, data| {
                debug!("Received {} bytes on stream {}", data.len(), sid);
                debug!("{}", String::from_utf8_lossy(data));
            },
        )
    }

    /// Polls HTTP/3 events and forwards received HEADERS/DATA frames to the provided sinks.
    pub fn poll_http3_with_headers<FH, FB>(
        &mut self,
        on_headers: FH,
        on_body: FB,
    ) -> Result<(), crate::error::ConnectionError>
    where
        FH: FnMut(u64, &[crate::transport::h3::Header]),
        FB: FnMut(u64, &[u8]),
    {
        self.poll_http3_event_loop("poll_http3_with_headers", false, on_headers, on_body)
    }

    /// Polls HTTP/3 events and forwards received DATA frames to the provided sink.
    pub fn poll_http3_with<F>(
        &mut self,
        mut on_body: F,
    ) -> Result<(), crate::error::ConnectionError>
    where
        F: FnMut(&[u8]),
    {
        self.poll_http3_with_headers(|_sid, _headers| {}, |_sid, data| on_body(data))?;
        Ok(())
    }

    /// Returns true if a MASQUE CONNECT-UDP flow is currently registered.
    pub fn masque_flow_active(&self) -> bool {
        self.h3_conn.as_ref().map(|h| h.masque_flow_active()).unwrap_or(false)
    }
}
