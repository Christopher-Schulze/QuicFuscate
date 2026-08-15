use super::*;

fn masque_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("QUICFUSCATE_MASQUE_TRACE").is_some())
}

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
            masque_relay_cb: self.masque_relay_cb.clone(),
            private_packet_protection_cb: self.private_packet_protection_cb.clone(),
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
        Self::inject_circuit_headers(self.circuit_id, self.circuit_hop_budget, &mut headers);
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
                        if Self::is_masque_request(&list) {
                            let request =
                                crate::transport::h3::Connection::masque_connect_udp_request(&list)
                                    .and_then(|request| {
                                        if let Some((target, purpose)) = request {
                                            return Ok(Some((Some(target), purpose)));
                                        }
                                        crate::transport::h3::Connection::masque_connect_ip_request(
                                            &list,
                                        )
                                        .map(
                                            |is_connect_ip| {
                                                is_connect_ip
                                                    .then_some((None, MasqueFlowPurpose::TunIp))
                                            },
                                        )
                                    });
                            match request {
                                Ok(Some((target, purpose))) => {
                                    let circuit = match Self::peer_circuit(&list) {
                                        Ok(circuit) => circuit,
                                        Err(error) => {
                                            warn!(
                                                "rejecting malformed circuit headers: stream={} error={}",
                                                sid, error
                                            );
                                            continue;
                                        }
                                    };
                                    if purpose == MasqueFlowPurpose::NextHopUdp && circuit.is_none()
                                    {
                                        warn!(
                                            "rejecting next-hop MASQUE flow without circuit identity: stream={}",
                                            sid
                                        );
                                        continue;
                                    }
                                    if self.masque_peer_flows.len() >= MAX_BOUND_MASQUE_FLOWS {
                                        warn!(
                                            "rejecting MASQUE flow beyond per-connection bound: sid={}",
                                            sid
                                        );
                                        continue;
                                    }
                                    match h3.enable_masque_datagram(&mut self.conn, sid) {
                                        Ok(flow_id) => {
                                            self.masque_peer_flows.insert(
                                                flow_id,
                                                MasqueFlowBinding {
                                                    stream_id: sid,
                                                    target,
                                                    purpose,
                                                    generation: Self::peer_generation(&list),
                                                    circuit_id: circuit.map(|value| value.0),
                                                    hop_budget: circuit.map(|value| value.1),
                                                    accepted: false,
                                                    control_sent: false,
                                                },
                                            );
                                            crate::telemetry::MASQUE_ACTIVE.store(
                                                1,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                            info!(
                                                "MASQUE peer flow recorded (stream={}, flow={}, purpose={:?})",
                                                sid, flow_id, purpose
                                            );
                                        }
                                        Err(error) => warn!(
                                            "MASQUE peer flow registration failed: stream={} error={:?}",
                                            sid, error
                                        ),
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => warn!(
                                    "rejecting malformed MASQUE request: stream={} error={:?}",
                                    sid, error
                                ),
                            }
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
                        sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, mut payload },
                    ))) => {
                        let binding = self
                            .masque_local_flows
                            .get(&(sid / 4))
                            .or_else(|| self.masque_peer_flows.get(&(sid / 4)));
                        Self::handle_masque_capsule_event(
                            capsule_type,
                            &mut payload,
                            sid / 4,
                            binding,
                            &MasqueDispatchContext {
                                bindings: &bindings,
                                normalizer: &self.tunnel_ingress_normalizer,
                                local_flows: &self.masque_local_flows,
                                peer_flows: &self.masque_peer_flows,
                            },
                        );
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Reset(err)))) => {
                        self.h3_tunnel_rx.remove(&sid);
                        self.h3_tunnel_response_started.remove(&sid);
                        self.masque_peer_flows.retain(|_, flow| flow.stream_id != sid);
                        self.masque_local_flows.retain(|_, flow| flow.stream_id != sid);
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
                        self.masque_peer_flows.retain(|_, flow| flow.stream_id != sid);
                        self.masque_local_flows.retain(|_, flow| flow.stream_id != sid);
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
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &MasqueDispatchContext {
                        bindings: &bindings,
                        normalizer: &self.tunnel_ingress_normalizer,
                        local_flows: &self.masque_local_flows,
                        peer_flows: &self.masque_peer_flows,
                    },
                );
            }
            // Always drain MASQUE datagrams after the H3 event loop exits.
            // QUIC DATAGRAM frames (carrying MASQUE CONNECT-UDP payloads) are
            // NOT H3 events: they sit in the QUIC datagram recv queue and are
            // never returned by h3.poll(). Without this post-loop drain, TUN
            // uplink packets would be silently dropped whenever the H3 event
            // queue is empty (the common case after handshake).
            if let Some(ref mut h3) = self.h3_conn {
                Self::drain_masque_datagrams(
                    h3,
                    &mut self.conn,
                    &self.stealth_manager,
                    &MasqueDispatchContext {
                        bindings: &bindings,
                        normalizer: &self.tunnel_ingress_normalizer,
                        local_flows: &self.masque_local_flows,
                        peer_flows: &self.masque_peer_flows,
                    },
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

    fn dispatch_private_packet_protection_payload(
        callback: &Option<PrivatePacketProtectionHandler>,
        payload: &[u8],
    ) {
        if let Some(callback) = callback {
            if let Ok(mut callback) = callback.lock() {
                (callback)(payload);
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
        flow_id: u64,
        binding: Option<&MasqueFlowBinding>,
        context: &MasqueDispatchContext<'_>,
    ) {
        match capsule_type {
            0x00 => {
                Self::dispatch_bound_masque_payload(
                    flow_id,
                    binding,
                    payload,
                    &context.bindings.masque_datagram_cb,
                    &context.bindings.masque_control_cb,
                    &context.bindings.masque_cb,
                    &context.bindings.masque_relay_cb,
                    context.normalizer,
                );
            }
            0x21 => {
                if binding.is_some_and(|flow| flow.purpose == MasqueFlowPurpose::TunIp) {
                    Self::dispatch_masque_compressed_datagram(
                        &context.bindings.masque_datagram_cb,
                        &context.bindings.masque_cb,
                        &context.bindings.memory_pool,
                        payload,
                        None,
                        context.normalizer,
                    );
                }
            }
            0x22 => {
                if binding.is_some_and(|flow| flow.purpose == MasqueFlowPurpose::TunIp)
                    && payload.len() >= 9
                    && payload[0] == 0x5D
                {
                    let mut hb = [0u8; 2];
                    hb.copy_from_slice(&payload[1..3]);
                    let hash = u16::from_be_bytes(hb);
                    let mut vb = [0u8; 2];
                    vb.copy_from_slice(&payload[3..5]);
                    let ver = u16::from_be_bytes(vb);
                    if let Some(dict) = crate::compress::get_dict_by_id(hash, ver) {
                        Self::dispatch_masque_compressed_datagram(
                            &context.bindings.masque_datagram_cb,
                            &context.bindings.masque_cb,
                            &context.bindings.memory_pool,
                            payload,
                            Some(&dict),
                            context.normalizer,
                        );
                    }
                }
            }
            _ => {
                if capsule_type == crate::qftls::PRIVATE_PACKET_PROTECTION_CAPSULE_TYPE
                    && binding.is_some_and(|flow| {
                        flow.accepted && Self::private_packet_protection_flow(flow.purpose)
                    })
                {
                    Self::dispatch_private_packet_protection_payload(
                        &context.bindings.private_packet_protection_cb,
                        payload,
                    );
                } else {
                    Self::dispatch_masque_capsule_payload(
                        &context.bindings.masque_control_cb,
                        &context.bindings.masque_cb,
                        capsule_type,
                        payload,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_bound_masque_payload(
        flow_id: u64,
        binding: Option<&MasqueFlowBinding>,
        payload: &mut Vec<u8>,
        masque_datagram_cb: &Option<DatagramHandler>,
        masque_control_cb: &Option<CapsuleHandler>,
        masque_cb: &Option<CapsuleHandler>,
        masque_relay_cb: &Option<MasqueRelayHandler>,
        normalizer: &PacketNormalizer,
    ) {
        let Some(binding) = binding else {
            debug!("dropping MASQUE payload on unbound flow-id={flow_id}");
            return;
        };
        if !binding.accepted {
            debug!("dropping MASQUE payload on unauthenticated flow-id={flow_id}");
            return;
        }
        match binding.purpose {
            MasqueFlowPurpose::TunIp => {
                if matches!(payload.first().map(|byte| byte >> 4), Some(4 | 6))
                    && normalizer.normalize_tunnel_ingress_vec(payload) != NormalizeResult::Dropped
                {
                    Self::dispatch_masque_datagram_payload(masque_datagram_cb, masque_cb, payload);
                }
            }
            MasqueFlowPurpose::NextHopUdp => {
                if let Some(callback) = masque_relay_cb {
                    if let Ok(mut callback) = callback.lock() {
                        if let Some(target) = binding.target.as_ref() {
                            if masque_trace_enabled() {
                                info!(
                                    "dispatching MASQUE relay payload flow={} bytes={}",
                                    flow_id,
                                    payload.len()
                                );
                            }
                            (callback)(flow_id, target, payload);
                        }
                    }
                }
            }
            MasqueFlowPurpose::Control => {
                Self::dispatch_masque_capsule_payload(masque_control_cb, masque_cb, 0x00, payload);
            }
        }
    }

    fn drain_masque_datagrams(
        h3: &mut crate::transport::h3::Connection,
        conn: &mut crate::transport::Connection,
        stealth_manager: &StealthManager,
        context: &MasqueDispatchContext<'_>,
    ) {
        // Drain whenever a sink is present (TUN bridge) or the stealth runtime
        // explicitly enabled MASQUE datagrams. Without this, MASQUE-framed
        // datagrams would be left in the QUIC datagram queue and either dropped
        // or consumed as corrupted raw bytes by a bare dgram_recv loop.
        let has_sink = context.bindings.masque_datagram_cb.is_some()
            || context.bindings.masque_control_cb.is_some()
            || context.bindings.masque_cb.is_some()
            || context.bindings.masque_relay_cb.is_some();
        if stealth_manager.masque_datagram_enabled() || has_sink {
            while let Some((flow_id, mut payload)) = h3.try_recv_masque_datagram(conn) {
                let binding =
                    context.local_flows.get(&flow_id).or_else(|| context.peer_flows.get(&flow_id));
                Self::dispatch_bound_masque_payload(
                    flow_id,
                    binding,
                    &mut payload,
                    &context.bindings.masque_datagram_cb,
                    &context.bindings.masque_control_cb,
                    &context.bindings.masque_cb,
                    &context.bindings.masque_relay_cb,
                    context.normalizer,
                );
            }
        }
    }

    /// Returns true if the H3 headers describe a MASQUE CONNECT-UDP request
    /// (`:method: CONNECT` + `:protocol: connect-udp`).
    fn is_masque_request(headers: &[crate::transport::h3::Header]) -> bool {
        let mut method_connect = false;
        let mut masque_protocol = false;
        for h in headers {
            if h.name().eq_ignore_ascii_case(b":method")
                && h.value().eq_ignore_ascii_case(b"CONNECT")
            {
                method_connect = true;
            }
            if h.name().eq_ignore_ascii_case(b":protocol")
                && (h.value().eq_ignore_ascii_case(b"connect-udp")
                    || h.value().eq_ignore_ascii_case(b"connect-ip"))
            {
                masque_protocol = true;
            }
        }
        method_connect && masque_protocol
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

    pub(super) fn peer_circuit(
        headers: &[crate::transport::h3::Header],
    ) -> Result<Option<([u8; 16], u8)>, &'static str> {
        let circuit_ids = headers
            .iter()
            .filter(|header| header.name().eq_ignore_ascii_case(b"x-qf-circuit-id"))
            .collect::<Vec<_>>();
        let budgets = headers
            .iter()
            .filter(|header| header.name().eq_ignore_ascii_case(b"x-qf-hop-budget"))
            .collect::<Vec<_>>();
        if circuit_ids.is_empty() && budgets.is_empty() {
            return Ok(None);
        }
        if circuit_ids.len() != 1 || budgets.len() != 1 {
            return Err("circuit identity and hop budget must occur exactly once");
        }
        let raw_id = circuit_ids[0].value();
        if raw_id.len() != 32 || !raw_id.iter().all(u8::is_ascii_hexdigit) {
            return Err("circuit identity must contain 32 hexadecimal characters");
        }
        let mut circuit_id = [0u8; 16];
        for (index, chunk) in raw_id.chunks_exact(2).enumerate() {
            circuit_id[index] = std::str::from_utf8(chunk)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .ok_or("invalid circuit identity")?;
        }
        let hop_budget = std::str::from_utf8(budgets[0].value())
            .ok()
            .and_then(|value| value.parse::<u8>().ok())
            .filter(|value| (1..=qf_engine_types::MAX_CIRCUIT_HOPS).contains(value))
            .ok_or("circuit hop budget is outside the implementation bound")?;
        Ok(Some((circuit_id, hop_budget)))
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

    /// Opens a purpose-bound CONNECT-UDP flow to the next circuit hop.
    pub fn begin_next_hop_masque_tunnel(
        &mut self,
        proxy: &str,
        target: &str,
    ) -> Result<u64, crate::error::ConnectionError> {
        if self.masque_local_flows.len() >= MAX_BOUND_MASQUE_FLOWS {
            return Err(crate::error::ConnectionError::StreamLimit);
        }
        self.ensure_http3_initialized()?;
        let parsed_target = MasqueUdpTarget::parse_authority(target)?;
        let headers = self.build_masque_request_headers();
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::InvalidState)?;
        let stream_id = h3.connect_udp_for_purpose(
            &mut self.conn,
            proxy,
            target,
            MasqueFlowPurpose::NextHopUdp,
            &headers,
        )?;
        let flow_id = h3.enable_masque_datagram(&mut self.conn, stream_id)?;
        self.masque_local_flows.insert(
            flow_id,
            MasqueFlowBinding {
                stream_id,
                target: Some(parsed_target),
                purpose: MasqueFlowPurpose::NextHopUdp,
                generation: self.client_connection_generation,
                circuit_id: self.circuit_id,
                hop_budget: self.circuit_hop_budget,
                accepted: true,
                control_sent: false,
            },
        );
        Ok(stream_id)
    }

    /// Sends one opaque inner QUIC datagram without IP normalization.
    pub fn send_next_hop_masque_datagram(
        &mut self,
        stream_id: u64,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let flow_id = stream_id / 4;
        let valid = self.masque_local_flows.get(&flow_id).is_some_and(|flow| {
            flow.stream_id == stream_id && flow.purpose == MasqueFlowPurpose::NextHopUdp
        });
        if !valid
            || payload.is_empty()
            || payload.len()
                > self
                    .effective_masque_mtu()
                    .max(crate::transport::MIN_CLIENT_INITIAL_LEN)
        {
            return Err(crate::error::ConnectionError::BufferTooShort);
        }
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        match h3.send_masque_datagram(&mut self.conn, stream_id, payload) {
            Ok(()) => Ok(()),
            Err(crate::transport::h3::Error::DgramQueueFull) => {
                Err(crate::error::ConnectionError::DgramQueueFull)
            }
            Err(error) => Err(error.into()),
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

        let peer_stream_id = self
            .masque_peer_flows
            .values()
            .find(|flow| flow.accepted && flow.purpose == MasqueFlowPurpose::TunIp)
            .map(|flow| flow.stream_id);
        log::trace!("send_masque_downlink: payload len={} masque_mtu={} masque_peer_stream_id={:?} h3_conn={}",
        payload.len(), self.effective_masque_mtu(), peer_stream_id, self.h3_conn.is_some());

        if payload.len() <= self.effective_masque_mtu() {
            if let Some(sid) = peer_stream_id {
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
        self.conn
            .effective_path_mtu()
            .min(self.conn.max_send_udp_payload_size())
            .saturating_sub(usize::from(qf_engine_types::NESTED_MASQUE_OVERHEAD))
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

    /// Install the private packet-protection control sink without replacing assignment handling.
    pub fn set_private_packet_protection_cb(&mut self, cb: PrivatePacketProtectionHandler) {
        self.private_packet_protection_cb = Some(cb);
    }

    /// Return whether the private packet-protection control sink is installed.
    pub fn has_private_packet_protection_cb(&self) -> bool {
        self.private_packet_protection_cb.is_some()
    }

    /// Installs the authenticated opaque UDP relay sink used by intermediate hops.
    pub fn set_masque_relay_cb(&mut self, cb: MasqueRelayHandler) {
        self.masque_relay_cb = Some(cb);
    }

    pub fn set_masque_relay_response_queue(
        &mut self,
        queue: Arc<std::sync::Mutex<MasqueRelayResponseQueue>>,
    ) {
        self.masque_relay_response_queue = Some(queue);
    }

    pub fn masque_relay_response_queue(
        &self,
    ) -> Option<Arc<std::sync::Mutex<MasqueRelayResponseQueue>>> {
        self.masque_relay_response_queue.as_ref().cloned()
    }

    /// Flushes bounded UDP relay responses back onto their exact peer flow.
    pub fn flush_masque_relay_responses(&mut self) -> Result<usize, crate::error::ConnectionError> {
        let Some(queue) = self.masque_relay_response_queue.as_ref().cloned() else {
            return Ok(0);
        };
        let mut sent = 0usize;
        loop {
            let response = match queue.lock() {
                Ok(mut queue) => queue.pop_front(),
                Err(poisoned) => poisoned.into_inner().pop_front(),
            };
            let Some(response) = response else {
                break;
            };
            if masque_trace_enabled() {
                info!(
                    "dequeued MASQUE relay response flow={} bytes={}",
                    response.flow_id,
                    response.payload.len()
                );
            }
            let Some(binding) = self.masque_peer_flows.get(&response.flow_id) else {
                if masque_trace_enabled() {
                    info!(
                        "dropping MASQUE relay response with missing flow binding flow={}",
                        response.flow_id
                    );
                }
                continue;
            };
            if !binding.accepted || binding.purpose != MasqueFlowPurpose::NextHopUdp {
                if masque_trace_enabled() {
                    info!(
                        "dropping MASQUE relay response on inactive flow={} accepted={} purpose={:?}",
                        response.flow_id, binding.accepted, binding.purpose
                    );
                }
                continue;
            }
            let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
            match h3.send_masque_datagram(&mut self.conn, binding.stream_id, &response.payload) {
                Ok(()) => {
                    sent = sent.saturating_add(1);
                    if masque_trace_enabled() {
                        info!(
                            "queued MASQUE relay response for QUIC flow={} stream={} bytes={}",
                            response.flow_id,
                            binding.stream_id,
                            response.payload.len()
                        );
                    }
                }
                Err(crate::transport::h3::Error::DgramQueueFull) => {
                    let enqueue = match queue.lock() {
                        Ok(mut queue) => queue.enqueue(response.flow_id, response.payload),
                        Err(poisoned) => {
                            poisoned.into_inner().enqueue(response.flow_id, response.payload)
                        }
                    };
                    if enqueue.is_err() {
                        warn!("dropping relay response after retry queue saturation");
                    }
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(sent)
    }

    /// Snapshot of peer flows awaiting authentication and policy admission.
    pub fn pending_peer_masque_flows(&self) -> Vec<PendingMasqueFlow> {
        self.masque_peer_flows
            .values()
            .filter(|flow| !flow.accepted)
            .map(|flow| {
                (
                    flow.stream_id,
                    flow.target.clone(),
                    flow.purpose,
                    flow.circuit_id,
                    flow.hop_budget,
                )
            })
            .collect()
    }

    /// Bind subsequent client H3 requests to one reconnect generation.
    pub fn set_client_connection_generation(&mut self, generation: u64) {
        self.client_connection_generation = (generation != 0).then_some(generation);
    }

    /// Bind authenticated circuit identity and remaining hop budget to relay requests.
    pub fn set_circuit_context(&mut self, circuit_id: [u8; 16], hop_budget: u8) {
        self.circuit_id = Some(circuit_id);
        self.circuit_hop_budget = Some(hop_budget);
    }

    /// Return the generation supplied by a peer CONNECT-UDP request.
    pub fn masque_peer_generation(&self) -> Option<u64> {
        self.masque_peer_flows
            .values()
            .find(|flow| Self::private_packet_protection_flow(flow.purpose))
            .and_then(|flow| flow.generation)
    }

    fn private_packet_protection_flow(purpose: MasqueFlowPurpose) -> bool {
        matches!(
            purpose,
            MasqueFlowPurpose::TunIp | MasqueFlowPurpose::NextHopUdp | MasqueFlowPurpose::Control
        )
    }

    /// Return whether a locally initiated authenticated MASQUE flow can carry private
    /// packet-protection control capsules.
    pub fn local_private_packet_protection_control_available(&self) -> bool {
        self.masque_local_flows.values().any(|flow| {
            flow.accepted
                && Self::private_packet_protection_flow(flow.purpose)
                && self.h3_conn.as_ref().is_some_and(|h3| h3.masque_established(flow.stream_id))
        })
    }

    /// Return whether a local authenticated MASQUE flow exists, independent of whether its
    /// response has already arrived. This lets a circuit bind the QKey transcript before the
    /// private control runtime's first poll.
    pub fn has_local_private_packet_protection_flow(&self) -> bool {
        self.masque_local_flows.values().any(|flow| {
            flow.accepted
                && Self::private_packet_protection_flow(flow.purpose)
                && self.h3_conn.as_ref().is_some_and(|h3| h3.masque_established(flow.stream_id))
        })
    }

    /// Return whether an authenticated peer MASQUE flow can carry private packet-protection
    /// control capsules.
    pub fn peer_private_packet_protection_control_available(&self) -> bool {
        self.masque_peer_flows
            .values()
            .any(|flow| flow.accepted && Self::private_packet_protection_flow(flow.purpose))
    }

    /// Accepts one authenticated peer flow after authorization and policy checks.
    pub fn accept_peer_masque_flow(
        &mut self,
        stream_id: u64,
    ) -> Result<bool, crate::error::ConnectionError> {
        let flow_id = stream_id / 4;
        let Some(flow) = self.masque_peer_flows.get(&flow_id) else {
            return Ok(false);
        };
        if flow.stream_id != stream_id {
            return Ok(false);
        }
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.accept_masque_connect(&mut self.conn, stream_id)?;
        if let Some(flow) = self.masque_peer_flows.get_mut(&flow_id) {
            flow.accepted = true;
        }
        Ok(true)
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
        let Some(flow_id) = self.masque_peer_flows.iter().find_map(|(flow_id, flow)| {
            (flow.accepted && flow.purpose == MasqueFlowPurpose::TunIp).then_some(*flow_id)
        }) else {
            return Err(crate::error::ConnectionError::Done);
        };
        if self.masque_peer_flows.get(&flow_id).is_some_and(|flow| flow.control_sent) {
            return Ok(false);
        }
        let stream_id = self.masque_peer_flows[&flow_id].stream_id;
        let capsule = crate::transport::h3::Connection::encode_capsule(capsule_type, payload);
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.send_capsule(&mut self.conn, stream_id, &capsule, false)?;
        if let Some(flow) = self.masque_peer_flows.get_mut(&flow_id) {
            flow.control_sent = true;
        }
        Ok(true)
    }

    pub fn peer_connect_ip_control_sent(&self) -> bool {
        self.masque_peer_flows.values().any(|flow| {
            flow.accepted && flow.purpose == MasqueFlowPurpose::TunIp && flow.control_sent
        })
    }

    /// Returns whether an authenticated peer CONNECT-IP flow can carry the client assignment.
    pub fn peer_connect_ip_flow_active(&self) -> bool {
        self.masque_peer_flows
            .values()
            .any(|flow| flow.accepted && flow.purpose == MasqueFlowPurpose::TunIp)
    }

    /// Send one control capsule on the accepted peer CONNECT-IP flow.
    pub fn send_peer_connect_ip_capsule(
        &mut self,
        capsule_type: u64,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let stream_id = self
            .masque_peer_flows
            .values()
            .find(|flow| flow.accepted && flow.purpose == MasqueFlowPurpose::TunIp)
            .map(|flow| flow.stream_id)
            .ok_or(crate::error::ConnectionError::Done)?;
        let capsule = crate::transport::h3::Connection::encode_capsule(capsule_type, payload);
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.send_capsule(&mut self.conn, stream_id, &capsule, false)?;
        Ok(())
    }

    /// Send one private packet-protection control capsule on the local authenticated
    /// CONNECT-IP flow. This path is deliberately independent from the one-shot assignment
    /// guard and therefore supports proposal, selection, and confirmation messages.
    pub fn send_private_packet_protection_capsule(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let stream_id = self
            .masque_local_flows
            .values()
            .find(|flow| flow.accepted && Self::private_packet_protection_flow(flow.purpose))
            .map(|flow| flow.stream_id)
            .ok_or(crate::error::ConnectionError::Done)?;
        let capsule = crate::transport::h3::Connection::encode_capsule(
            crate::qftls::PRIVATE_PACKET_PROTECTION_CAPSULE_TYPE,
            payload,
        );
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.send_capsule(&mut self.conn, stream_id, &capsule, false)?;
        Ok(())
    }

    /// Send one private packet-protection control capsule on the accepted peer CONNECT-IP flow.
    /// This is the server-side counterpart of the local-flow sender and has no assignment guard.
    pub fn send_peer_private_packet_protection_capsule(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        let stream_id = self
            .masque_peer_flows
            .values()
            .find(|flow| flow.accepted && Self::private_packet_protection_flow(flow.purpose))
            .map(|flow| flow.stream_id)
            .ok_or(crate::error::ConnectionError::Done)?;
        let capsule = crate::transport::h3::Connection::encode_capsule(
            crate::qftls::PRIVATE_PACKET_PROTECTION_CAPSULE_TYPE,
            payload,
        );
        let h3 = self.h3_conn.as_mut().ok_or(crate::error::ConnectionError::Done)?;
        h3.send_capsule(&mut self.conn, stream_id, &capsule, false)?;
        Ok(())
    }

    /// Returns true if a MASQUE datagram sink has been installed.
    pub fn has_masque_datagram_cb(&self) -> bool {
        self.masque_datagram_cb.is_some()
    }

    /// Returns true if the authenticated opaque relay sink has been installed.
    pub fn has_masque_relay_cb(&self) -> bool {
        self.masque_relay_cb.is_some()
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
        )?;
        self.private_packet_protection_control_tick()
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
        self.poll_http3_event_loop("poll_http3_with_headers", false, on_headers, on_body)?;
        self.private_packet_protection_control_tick()
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
