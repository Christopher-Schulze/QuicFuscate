use super::*;

impl WebTransportSession {
    fn pending() -> Self {
        Self {
            state: WebTransportSessionState::Pending,
            local_unidirectional_streams: 0,
            local_bidirectional_streams: 0,
            peer_unidirectional_streams: 0,
            peer_bidirectional_streams: 0,
            local_data_bytes: 0,
            peer_data_bytes: 0,
        }
    }
}

impl Connection {
    pub(super) fn register_webtransport_session(&mut self, session_id: u64) -> Result<(), Error> {
        if session_id & 0x03 != 0 || self.webtransport_sessions.contains_key(&session_id) {
            return Err(Error::IdError);
        }
        if self.webtransport_sessions.len() >= MAX_WEBTRANSPORT_SESSIONS {
            return Err(Error::ExcessiveLoad);
        }
        self.webtransport_sessions.insert(session_id, WebTransportSession::pending());
        Ok(())
    }

    pub(super) fn establish_webtransport_session(&mut self, session_id: u64) -> Result<(), Error> {
        let session = self.webtransport_sessions.get_mut(&session_id).ok_or(Error::IdError)?;
        if session.state != WebTransportSessionState::Pending {
            return Err(Error::FrameUnexpected);
        }
        session.state = WebTransportSessionState::Established;
        self.publish_ready_webtransport_streams();
        Ok(())
    }

    pub(super) fn remove_webtransport_session(&mut self, session_id: u64) {
        self.webtransport_sessions.remove(&session_id);
        let associated: Vec<u64> = self
            .webtransport_session_ids
            .iter()
            .filter_map(|(stream_id, associated_session)| {
                (*associated_session == session_id).then_some(*stream_id)
            })
            .collect();
        for stream_id in associated {
            self.webtransport_session_ids.remove(&stream_id);
            self.pending_webtransport_streams.remove(&stream_id);
            self.streams.remove(&stream_id);
            self.finished_streams.remove(&stream_id);
            self.pending_events.retain(|(event_stream_id, _)| *event_stream_id != stream_id);
        }
    }

    pub(super) fn webtransport_session_is_established(&self, session_id: u64) -> bool {
        self.webtransport_sessions
            .get(&session_id)
            .is_some_and(|session| session.state == WebTransportSessionState::Established)
    }

    pub(super) fn bind_peer_webtransport_stream(
        &mut self,
        stream_id: u64,
        session_id: u64,
        unidirectional: bool,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        if !self.peer_supports_webtransport() {
            return Err(Error::SettingsError);
        }
        if session_id & 0x03 != 0 || self.webtransport_session_ids.contains_key(&stream_id) {
            return Err(Error::IdError);
        }
        let session = self.webtransport_sessions.get(&session_id).ok_or(Error::IdError)?;
        let current_streams = if unidirectional {
            session.peer_unidirectional_streams
        } else {
            session.peer_bidirectional_streams
        };
        let stream_limit = if unidirectional {
            WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI
        } else {
            WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI
        };
        let next_streams = current_streams.checked_add(1).ok_or(Error::ExcessiveLoad)?;
        if next_streams > stream_limit {
            return Err(Error::ExcessiveLoad);
        }
        let data_len = u64::try_from(data.len()).map_err(|_| Error::ExcessiveLoad)?;
        let next_data_bytes =
            session.peer_data_bytes.checked_add(data_len).ok_or(Error::ExcessiveLoad)?;
        if next_data_bytes > WEBTRANSPORT_INITIAL_MAX_DATA {
            return Err(Error::ExcessiveLoad);
        }
        let pending = session.state == WebTransportSessionState::Pending;
        let needs_pending_slot = pending && (!data.is_empty() || fin);
        if needs_pending_slot
            && self.pending_webtransport_streams.len() >= MAX_PENDING_WEBTRANSPORT_STREAMS
        {
            return Err(Error::ExcessiveLoad);
        }
        let stream = self.streams.get(&stream_id).ok_or(Error::IdError)?;
        if !stream.body_buffer.is_empty() || data.len() > MAX_BUFFERED_H3_FRAME {
            return Err(Error::ExcessiveLoad);
        }

        let session = self.webtransport_sessions.get_mut(&session_id).ok_or(Error::IdError)?;
        if unidirectional {
            session.peer_unidirectional_streams = next_streams;
        } else {
            session.peer_bidirectional_streams = next_streams;
        }
        session.peer_data_bytes = next_data_bytes;
        self.webtransport_session_ids.insert(stream_id, session_id);
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
        stream._stream_type = StreamType::WebTransportData;
        stream.body_buffer.extend_from_slice(data);
        stream.fin_received = fin;
        if pending {
            if needs_pending_slot {
                self.pending_webtransport_streams.insert(stream_id);
            }
        } else {
            if !data.is_empty() {
                self.pending_events.push_back((stream_id, Event::Data));
            }
            if fin {
                self.pending_events.push_back((stream_id, Event::Finished));
            }
        }
        Ok(())
    }

    pub(super) fn process_peer_stream_resets(
        &mut self,
        conn: &mut super::super::super::Connection,
    ) -> Result<(), Error> {
        while let Some((stream_id, error_code)) = conn.stream_reset_next() {
            if self._peer_control_stream_id == Some(stream_id)
                || self.peer_qpack_encoder_stream_id == Some(stream_id)
                || self.peer_qpack_decoder_stream_id == Some(stream_id)
            {
                return Err(Error::ClosedCriticalStream);
            }
            self.decoder.cancel_stream(stream_id)?;
            self.streams.remove(&stream_id);
            self.finished_streams.remove(&stream_id);
            self.masque_flow.remove(&stream_id);
            if self.webtransport_sessions.contains_key(&stream_id) {
                self.remove_webtransport_session(stream_id);
            } else {
                self.webtransport_session_ids.remove(&stream_id);
                self.pending_webtransport_streams.remove(&stream_id);
            }
            if self.peer_request_stream_id == Some(stream_id) {
                self.peer_request_stream_id = None;
            }
            self.pending_events.push_back((stream_id, Event::Reset(error_code)));
        }
        self.flush_qpack_decoder_instructions(conn)
    }
    /// Parse frame header
    pub(super) fn parse_frame_header(buf: &[u8]) -> Result<(u64, usize, usize), Error> {
        let (frame_type, type_offset) = Self::decode_varint(buf)?;
        let (frame_len, len_offset) = Self::decode_varint(&buf[type_offset..])?;
        let frame_len = usize::try_from(frame_len).map_err(|_| Error::ExcessiveLoad)?;
        let header_len = type_offset.checked_add(len_offset).ok_or(Error::ExcessiveLoad)?;
        Ok((frame_type, frame_len, header_len))
    }

    /// Encode a QUIC variable-length integer through the canonical transport codec.
    pub(super) fn encode_varint(val: u64, buf: &mut Vec<u8>) {
        let mut tmp = [0u8; 8];
        if let Ok(used) = qf_transport_pn::varint::write_varint(val, &mut tmp) {
            buf.extend_from_slice(&tmp[..used]);
        }
    }

    /// Decode a QUIC variable-length integer through the canonical transport codec.
    pub(super) fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
        qf_transport_pn::varint::read_varint(buf).map_err(|error| match error {
            crate::error::ConnectionError::BufferTooShort => Error::BufferTooShort,
            crate::error::ConnectionError::InvalidPacket => Error::FrameError,
            _ => Error::InternalError,
        })
    }

    /// Decode one MASQUE capsule from a buffer
    pub(super) fn decode_capsule(buf: &[u8]) -> Result<(u64, usize, Vec<u8>), Error> {
        if buf.is_empty() {
            return Err(Error::BufferTooShort);
        }
        let (ctype, off1) = Self::decode_varint(buf)?;
        let (clen, off2) = Self::decode_varint(&buf[off1..])?;
        let payload_len = usize::try_from(clen).map_err(|_| Error::ExcessiveLoad)?;
        if payload_len > MAX_BUFFERED_H3_FRAME {
            return Err(Error::ExcessiveLoad);
        }
        let need = off1
            .checked_add(off2)
            .and_then(|header_len| header_len.checked_add(payload_len))
            .ok_or(Error::ExcessiveLoad)?;
        if buf.len() < need {
            return Err(Error::BufferTooShort);
        }
        let payload_start = off1 + off2;
        let payload_bytes = &buf[payload_start..need];
        let mut payload = Vec::with_capacity(payload_bytes.len().saturating_add(4));
        payload.extend_from_slice(payload_bytes);
        // MASQUE capsule telemetry (receive).
        crate::optimize::telemetry::MASQUE_BYTES_RECEIVED.inc_by(payload.len() as u64);
        match ctype {
            0x00 => {
                crate::optimize::telemetry::MASQUE_CAPSULE_00.inc();
                crate::optimize::telemetry::MASQUE_CAPSULE_00_BYTES.inc_by(payload.len() as u64);
            }
            0x21 => {
                crate::optimize::telemetry::MASQUE_CAPSULE_21.inc();
                crate::optimize::telemetry::MASQUE_CAPSULE_21_BYTES.inc_by(payload.len() as u64);
            }
            0x22 => {
                crate::optimize::telemetry::MASQUE_CAPSULE_22.inc();
                crate::optimize::telemetry::MASQUE_CAPSULE_22_BYTES.inc_by(payload.len() as u64);
            }
            _ => {}
        }
        Ok((ctype, need, payload))
    }

    /// Decode every complete capsule in a buffered MASQUE DATA byte stream.
    ///
    /// A short tail is retained because one capsule may span multiple H3 DATA frames. Any
    /// complete framing error aborts the batch before decoded events are exposed to callers.
    pub(super) fn decode_masque_capsules(
        buffer: &mut Vec<u8>,
    ) -> Result<Vec<(u64, Vec<u8>)>, Error> {
        let mut offset = 0usize;
        let mut events = Vec::new();
        while offset < buffer.len() {
            match Self::decode_capsule(&buffer[offset..]) {
                Ok((ctype, used, payload)) => {
                    if used == 0 {
                        return Err(Error::FrameError);
                    }
                    events.push((ctype, payload));
                    offset += used;
                }
                Err(Error::BufferTooShort) => break,
                Err(error) => return Err(error),
            }
        }
        if offset > 0 {
            buffer.drain(..offset);
        }
        Ok(events)
    }

    /// Establish a MASQUE CONNECT-UDP stream and return its stream id (keeps stream open).
    pub fn connect_udp(
        &mut self,
        conn: &mut super::super::super::Connection,
        proxy: &str,
        target: &str,
    ) -> Result<u64, Error> {
        self.connect_udp_with_headers(conn, proxy, target, &[])
    }

    /// Establish a MASQUE CONNECT-UDP stream with additional request headers.
    pub fn connect_udp_with_headers(
        &mut self,
        conn: &mut super::super::super::Connection,
        proxy: &str,
        target: &str,
        extra_headers: &[Header],
    ) -> Result<u64, Error> {
        // Split target "host:port" into MASQUE path segments; fallback to old style if no ':'
        let (host, port) = match target.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => (target, "443"),
        };
        let path = format!("/.well-known/masque/udp/{}/{}/", host, port);
        let mut headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-udp"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", proxy.as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        headers.extend_from_slice(extra_headers);
        // Send request without FIN
        let sid = self.send_request(conn, &headers, false)?;
        if let Some(st) = self.streams.get_mut(&sid) {
            st._stream_type = StreamType::Masque;
        }
        Ok(sid)
    }

    pub(super) fn masque_response_status(headers: &[Header]) -> Option<u16> {
        headers.iter().find_map(|header| {
            if !header.name().eq_ignore_ascii_case(b":status") {
                return None;
            }
            std::str::from_utf8(header.value()).ok()?.parse::<u16>().ok()
        })
    }

    fn unique_header_value<'a>(
        headers: &'a [Header],
        name: &[u8],
    ) -> Result<Option<&'a [u8]>, Error> {
        let mut value = None;
        for header in headers {
            if header.name().eq_ignore_ascii_case(name) {
                if value.is_some() {
                    return Err(Error::FrameUnexpected);
                }
                value = Some(header.value());
            }
        }
        Ok(value)
    }

    pub(super) fn is_webtransport_connect(headers: &[Header]) -> Result<bool, Error> {
        let protocol = Self::unique_header_value(headers, b":protocol")?;
        if protocol != Some(&b"webtransport-h3"[..]) {
            return Ok(false);
        }
        let method = Self::unique_header_value(headers, b":method")?;
        let scheme = Self::unique_header_value(headers, b":scheme")?;
        let authority = Self::unique_header_value(headers, b":authority")?;
        let path = Self::unique_header_value(headers, b":path")?;
        if method != Some(&b"CONNECT"[..])
            || !scheme.is_some_and(|value| value.eq_ignore_ascii_case(b"https"))
            || !authority.is_some_and(|value| !value.is_empty())
            || !path.is_some_and(|value| !value.is_empty())
        {
            return Err(Error::FrameUnexpected);
        }
        Ok(true)
    }

    /// Open a bounded WebTransport-looking H3 cover session.
    ///
    /// This is cover traffic only. It does not own VPN/TUN payload routing and
    /// deliberately does not compete with the production MASQUE CONNECT-UDP
    /// carrier.
    pub(crate) fn open_webtransport_cover_session(
        &mut self,
        conn: &mut super::super::super::Connection,
        authority: &str,
        path: &str,
    ) -> Result<u64, Error> {
        if self.is_server {
            return Err(Error::StreamCreationError);
        }
        if !self.peer_supports_webtransport() {
            return Err(Error::SettingsError);
        }
        if self.webtransport_sessions.len() >= MAX_WEBTRANSPORT_SESSIONS {
            return Err(Error::ExcessiveLoad);
        }
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"webtransport-h3"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", authority.as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"origin", format!("https://{authority}").as_bytes()),
        ];
        let sid = self.send_request(conn, &headers, false)?;
        self.register_webtransport_session(sid)?;
        if let Some(st) = self.streams.get_mut(&sid) {
            st._stream_type = StreamType::WebTransportCover;
        }
        Ok(sid)
    }

    /// Accept one negotiated peer WebTransport cover session with a final 2xx response.
    pub(crate) fn accept_webtransport_cover_session(
        &mut self,
        conn: &mut super::super::super::Connection,
        session_id: u64,
    ) -> Result<(), Error> {
        if !self.is_server || !self.peer_supports_webtransport() {
            return Err(Error::SettingsError);
        }
        let session = self.webtransport_sessions.get(&session_id).ok_or(Error::IdError)?;
        if session.state != WebTransportSessionState::Pending
            || !self
                .streams
                .get(&session_id)
                .is_some_and(|stream| stream._stream_type == StreamType::WebTransportCover)
        {
            return Err(Error::FrameUnexpected);
        }
        self.send_response(conn, session_id, &[Header::new(b":status", b"200")], false)
    }

    fn send_webtransport_stream(
        &mut self,
        conn: &mut super::super::super::Connection,
        session_id: u64,
        kind: WebTransportStreamKind,
        data: &[u8],
        fin: bool,
    ) -> Result<u64, Error> {
        if !self.peer_supports_webtransport() {
            return Err(Error::SettingsError);
        }
        let settings = self.peer_settings.as_ref().ok_or(Error::SettingsError)?;
        let session = self.webtransport_sessions.get(&session_id).ok_or(Error::IdError)?;
        if session.state != WebTransportSessionState::Established {
            return Err(Error::FrameUnexpected);
        }
        let (current_streams, stream_limit) = match kind {
            WebTransportStreamKind::Unidirectional => (
                session.local_unidirectional_streams,
                settings.webtransport_initial_max_streams_uni,
            ),
            WebTransportStreamKind::Bidirectional => (
                session.local_bidirectional_streams,
                settings.webtransport_initial_max_streams_bidi,
            ),
        };
        let next_streams = current_streams.checked_add(1).ok_or(Error::ExcessiveLoad)?;
        if next_streams > stream_limit {
            return Err(Error::ExcessiveLoad);
        }
        let data_len = u64::try_from(data.len()).map_err(|_| Error::ExcessiveLoad)?;
        let next_data_bytes =
            session.local_data_bytes.checked_add(data_len).ok_or(Error::ExcessiveLoad)?;
        if data.len() > MAX_BUFFERED_H3_FRAME
            || next_data_bytes > settings.webtransport_initial_max_data
        {
            return Err(Error::ExcessiveLoad);
        }

        let (stream_id, signal) = match kind {
            WebTransportStreamKind::Unidirectional => {
                (self.next_uni_stream_id, WEBTRANSPORT_UNI_STREAM_TYPE)
            }
            WebTransportStreamKind::Bidirectional => {
                (self.next_stream_id, WEBTRANSPORT_STREAM_SIGNAL)
            }
        };
        let next_stream_id = stream_id.checked_add(4).ok_or(Error::StreamCreationError)?;
        let mut payload = Vec::with_capacity(data.len().saturating_add(16));
        Self::encode_varint(signal, &mut payload);
        Self::encode_varint(session_id, &mut payload);
        payload.extend_from_slice(data);
        let sent =
            conn.stream_send(stream_id, &payload, fin).map_err(|_| Error::StreamCreationError)?;
        if sent != payload.len() {
            return Err(Error::InternalError);
        }

        match kind {
            WebTransportStreamKind::Unidirectional => self.next_uni_stream_id = next_stream_id,
            WebTransportStreamKind::Bidirectional => self.next_stream_id = next_stream_id,
        }
        let session = self.webtransport_sessions.get_mut(&session_id).ok_or(Error::IdError)?;
        match kind {
            WebTransportStreamKind::Unidirectional => {
                session.local_unidirectional_streams = next_streams;
            }
            WebTransportStreamKind::Bidirectional => {
                session.local_bidirectional_streams = next_streams;
            }
        }
        session.local_data_bytes = next_data_bytes;
        self.webtransport_session_ids.insert(stream_id, session_id);
        self.streams.insert(
            stream_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::WebTransportData,
                sent_bytes: sent,
                fin_sent: fin,
                fin_received: false,
                masque_established: false,
                masque_capsule_buffer: Vec::new(),
                settings_received: false,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        if fin {
            self.finished_streams.insert(stream_id);
        }
        Ok(stream_id)
    }

    /// Send one bounded unidirectional WebTransport cover-data stream.
    pub(crate) fn send_webtransport_unidirectional_stream(
        &mut self,
        conn: &mut super::super::super::Connection,
        session_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<u64, Error> {
        self.send_webtransport_stream(
            conn,
            session_id,
            WebTransportStreamKind::Unidirectional,
            data,
            fin,
        )
    }

    /// Send one bounded bidirectional WebTransport cover-data stream.
    pub(crate) fn send_webtransport_bidirectional_stream(
        &mut self,
        conn: &mut super::super::super::Connection,
        session_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<u64, Error> {
        self.send_webtransport_stream(
            conn,
            session_id,
            WebTransportStreamKind::Bidirectional,
            data,
            fin,
        )
    }

    /// Return whether the WebTransport CONNECT response established this session.
    pub(crate) fn webtransport_session_established(&self, session_id: u64) -> bool {
        self.webtransport_session_is_established(session_id)
    }

    /// Return whether a negotiated peer CONNECT is waiting for a final response.
    pub(crate) fn webtransport_session_pending(&self, session_id: u64) -> bool {
        self.webtransport_sessions
            .get(&session_id)
            .is_some_and(|session| session.state == WebTransportSessionState::Pending)
    }

    /// Enable MASQUE DATAGRAM for a CONNECT-UDP stream; returns Flow-ID (default 0)
    pub fn enable_masque_datagram(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
    ) -> Result<u64, Error> {
        // Provision QUIC DATAGRAM queues (idempotent)
        conn.enable_datagrams(256, 256);
        let flow_id = 0u64;
        self.masque_flow.insert(stream_id, flow_id);
        Ok(flow_id)
    }

    /// Accepts a peer-initiated CONNECT-UDP stream exactly once.
    ///
    /// The successful response is the client-visible data-plane readiness
    /// barrier. The stream is not established merely because request headers or
    /// registration capsules arrived.
    pub fn accept_masque_connect(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
    ) -> Result<bool, Error> {
        if self.masque_established(stream_id) {
            return Ok(false);
        }
        if !self.streams.contains_key(&stream_id) {
            return Err(Error::IdError);
        }

        self.enable_masque_datagram(conn, stream_id)?;
        let headers = [Header::new(b":status", b"200"), Header::new(b"capsule-protocol", b"?1")];
        self.send_response(conn, stream_id, &headers, false)?;
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
        stream._stream_type = StreamType::Masque;
        stream.masque_established = true;
        Ok(true)
    }

    /// Send a MASQUE UDP payload via QUIC DATAGRAM using the negotiated Flow-ID
    pub fn send_masque_datagram(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
        udp_payload: &[u8],
    ) -> Result<(), Error> {
        let flow_id = *self.masque_flow.get(&stream_id).unwrap_or(&0);
        let mut buf = Vec::with_capacity(9 + udp_payload.len());
        Self::encode_varint(flow_id, &mut buf);
        buf.extend_from_slice(udp_payload);
        conn.dgram_send(&buf).map_err(|e| match e {
            crate::error::ConnectionError::DgramQueueFull => Error::DgramQueueFull,
            _ => Error::InternalError,
        })
    }

    /// Try to receive one MASQUE datagram; returns (flow_id, payload)
    pub fn try_recv_masque_datagram(
        &mut self,
        conn: &mut super::super::super::Connection,
    ) -> Option<(u64, Vec<u8>)> {
        match conn.dgram_recv(&mut self.masque_recv_buffer[..]) {
            Ok(len) if len > 0 => {
                if let Ok((flow_id, used)) = Self::decode_varint(&self.masque_recv_buffer[..len]) {
                    return Some((flow_id, self.masque_recv_buffer[used..len].to_vec()));
                }
                None
            }
            _ => None,
        }
    }

    /// Return the Flow-ID bound to one active CONNECT-UDP stream.
    pub fn masque_flow_id(&self, stream_id: u64) -> Option<u64> {
        self.masque_flow.get(&stream_id).copied()
    }

    /// Send a MASQUE capsule (raw) on the given CONNECT-UDP stream.
    pub fn send_capsule(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
        capsule: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        // Telemetry: decode capsule type and payload length.
        if !capsule.is_empty() {
            if let Ok((ctype, _need, payload)) = Self::decode_capsule(capsule) {
                crate::optimize::telemetry::MASQUE_BYTES_SENT.inc_by(payload.len() as u64);
                match ctype {
                    0x00 => {
                        crate::optimize::telemetry::MASQUE_CAPSULE_00.inc();
                        crate::optimize::telemetry::MASQUE_CAPSULE_00_BYTES
                            .inc_by(payload.len() as u64);
                    }
                    0x21 => {
                        crate::optimize::telemetry::MASQUE_CAPSULE_21.inc();
                        crate::optimize::telemetry::MASQUE_CAPSULE_21_BYTES
                            .inc_by(payload.len() as u64);
                    }
                    0x22 => {
                        crate::optimize::telemetry::MASQUE_CAPSULE_22.inc();
                        crate::optimize::telemetry::MASQUE_CAPSULE_22_BYTES
                            .inc_by(payload.len() as u64);
                    }
                    _ => {}
                }
            }
        }
        self.send_body(conn, stream_id, capsule, fin).map(|_| ())
    }

    /// Build a MASQUE capsule: varint type, varint length, payload
    pub fn encode_capsule(capsule_type: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + payload.len());
        Self::encode_varint(capsule_type, &mut out);
        Self::encode_varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    /// Register a DATAGRAM context for MASQUE with given Flow-ID and Context-ID
    pub fn register_datagram_context(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
        flow_id: u64,
        context_id: u64,
    ) -> Result<(), Error> {
        // Capsule type chosen in private range (spec types vary by draft)
        const REGISTER_CTX: u64 = 0x30;
        let mut payload = Vec::with_capacity(16);
        Self::encode_varint(flow_id, &mut payload);
        Self::encode_varint(context_id, &mut payload);
        let cap = Self::encode_capsule(REGISTER_CTX, &payload);
        self.send_capsule(conn, stream_id, &cap, false)?;
        self.masque_flow.insert(stream_id, flow_id);
        Ok(())
    }

    /// Build a compressed UDP capsule (custom type 0x21) when beneficial.
    pub fn encode_udp_compress_capsule(
        &self,
        conn: &super::super::super::Connection,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let pol = crate::compress::global_policy_with_snapshot(conn.environment_snapshot());
        if !pol.enabled || payload.len() < pol.min_len {
            return None;
        }
        if !crate::compress::CompressionManager::looks_textual(payload) {
            return None;
        }
        let rtt = conn.rtt().as_millis() as f32;
        let bw = conn.delivery_rate();
        let cm = crate::compress::CompressionManager::new(crate::compress::CompressionConfig {
            min_len: pol.min_len,
            max_level: pol.level,
        });
        if !cm.should_compress(payload.len(), rtt, 0.0, bw) {
            return None;
        }
        let pool = conn.dgram_pool_or_global();
        if let Some((blk, used)) = cm.compress_to_pool(&pool, payload) {
            let capsule = Self::encode_capsule(0x21, &blk[..used]);
            return Some(capsule);
        }
        None
    }

    pub fn masque_established(&self, stream_id: u64) -> bool {
        self.streams.get(&stream_id).map(|st| st.masque_established).unwrap_or(false)
    }

    pub fn masque_flow_active(&self) -> bool {
        !self.masque_flow.is_empty()
    }
}
