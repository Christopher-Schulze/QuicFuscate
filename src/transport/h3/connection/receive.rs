use super::*;

impl Connection {
    pub(super) fn classify_peer_unidirectional_stream(
        &mut self,
        conn: &super::super::super::Connection,
        stream_id: u64,
        stream_type: u64,
    ) -> Result<StreamType, Error> {
        let peer_initiator = stream_id & 0x01;
        let expected_initiator = if conn.is_server() { 0 } else { 1 };
        if peer_initiator != expected_initiator {
            return Err(Error::FrameUnexpected);
        }

        match stream_type {
            0x00 => {
                if self._peer_control_stream_id.is_some() {
                    return Err(Error::StreamCreationError);
                }
                self._peer_control_stream_id = Some(stream_id);
                Ok(StreamType::Control)
            }
            0x01 if !conn.is_server() => Ok(StreamType::Push),
            0x01 => Err(Error::StreamCreationError),
            0x02 => {
                if self.peer_qpack_encoder_stream_id.is_some() {
                    return Err(Error::StreamCreationError);
                }
                self.peer_qpack_encoder_stream_id = Some(stream_id);
                Ok(StreamType::QpackEncoder)
            }
            0x03 => {
                if self.peer_qpack_decoder_stream_id.is_some() {
                    return Err(Error::StreamCreationError);
                }
                self.peer_qpack_decoder_stream_id = Some(stream_id);
                Ok(StreamType::QpackDecoder)
            }
            WEBTRANSPORT_UNI_STREAM_TYPE => Ok(StreamType::WebTransportData),
            _ => Ok(StreamType::UnknownUnidirectional),
        }
    }

    pub(super) fn parse_settings_payload(payload: &[u8]) -> Result<PeerSettings, Error> {
        let mut offset = 0usize;
        let mut seen = HashSet::new();
        let mut settings = PeerSettings::default();
        while offset < payload.len() {
            let (setting, setting_len) =
                Self::decode_varint(&payload[offset..]).map_err(|error| {
                    if error == Error::BufferTooShort {
                        Error::SettingsError
                    } else {
                        error
                    }
                })?;
            offset = offset.checked_add(setting_len).ok_or(Error::FrameError)?;
            let (value, value_len) = Self::decode_varint(&payload[offset..]).map_err(|error| {
                if error == Error::BufferTooShort {
                    Error::SettingsError
                } else {
                    error
                }
            })?;
            offset = offset.checked_add(value_len).ok_or(Error::FrameError)?;
            if !seen.insert(setting) {
                return Err(Error::SettingsError);
            }
            match setting {
                0x00 | 0x02..=0x05 => return Err(Error::SettingsError),
                0x01 | 0x06 | 0x07 if value > MAX_H3_SETTING_VALUE => {
                    return Err(Error::ExcessiveLoad);
                }
                SETTINGS_ENABLE_CONNECT_PROTOCOL | SETTINGS_H3_DATAGRAM | SETTINGS_WT_ENABLED
                    if value > 1 =>
                {
                    return Err(Error::SettingsError);
                }
                SETTINGS_WT_INITIAL_MAX_STREAMS_UNI | SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI
                    if value > (1u64 << 60) =>
                {
                    return Err(Error::SettingsError);
                }
                0x01 => settings.maximum_table_capacity = value,
                0x07 => settings.blocked_streams = value,
                SETTINGS_ENABLE_CONNECT_PROTOCOL => {
                    settings.enable_connect_protocol = value == 1;
                }
                SETTINGS_H3_DATAGRAM => settings.h3_datagram = value == 1,
                SETTINGS_WT_ENABLED => settings.webtransport_enabled = value == 1,
                SETTINGS_WT_INITIAL_MAX_STREAMS_UNI => {
                    settings.webtransport_initial_max_streams_uni = value;
                }
                SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI => {
                    settings.webtransport_initial_max_streams_bidi = value;
                }
                SETTINGS_WT_INITIAL_MAX_DATA => {
                    settings.webtransport_initial_max_data = value;
                }
                _ => {}
            }
        }
        if offset != payload.len() {
            return Err(Error::FrameError);
        }
        Ok(settings)
    }

    pub(super) fn peer_supports_webtransport(&self) -> bool {
        if !self.config.webtransport_enabled() {
            return false;
        }
        self.peer_settings.as_ref().is_some_and(|settings| {
            settings.webtransport_enabled
                && settings.h3_datagram
                && (self.is_server || settings.enable_connect_protocol)
                && settings.webtransport_initial_max_streams_uni > 0
                && settings.webtransport_initial_max_streams_bidi > 0
                && settings.webtransport_initial_max_data > 0
        })
    }

    pub(super) fn decode_single_varint_payload(payload: &[u8]) -> Result<u64, Error> {
        let (value, used) = Self::decode_varint(payload).map_err(|error| {
            if error == Error::BufferTooShort {
                Error::FrameError
            } else {
                error
            }
        })?;
        if used != payload.len() {
            return Err(Error::FrameError);
        }
        Ok(value)
    }

    pub(super) fn validate_frame_placement(
        conn: &super::super::super::Connection,
        stream_type: StreamType,
        frame_type: u64,
        settings_received: bool,
        receive_message_state: ReceiveMessageState,
    ) -> Result<(), Error> {
        if matches!(frame_type, 0x02 | 0x06 | 0x08 | 0x09) {
            return Err(Error::FrameUnexpected);
        }
        if frame_type == WEBTRANSPORT_STREAM_SIGNAL {
            return Err(Error::FrameError);
        }

        let known_frame = matches!(frame_type, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x0d);
        match stream_type {
            StreamType::Control => {
                if !settings_received {
                    return if frame_type == 0x04 { Ok(()) } else { Err(Error::FrameUnexpected) };
                }
                if frame_type == 0x04 {
                    return Err(Error::FrameUnexpected);
                }
                if known_frame && !matches!(frame_type, 0x03 | 0x07 | 0x0d) {
                    return Err(Error::FrameUnexpected);
                }
                if frame_type == 0x03 && !conn.is_server() {
                    return Err(Error::FrameUnexpected);
                }
                if frame_type == 0x0d && !conn.is_server() {
                    return Err(Error::FrameUnexpected);
                }
                Ok(())
            }
            StreamType::Push => {
                if known_frame && !matches!(frame_type, 0x00 | 0x01) {
                    return Err(Error::FrameUnexpected);
                }
                if (frame_type == 0x00 && receive_message_state != ReceiveMessageState::Body)
                    || (frame_type == 0x01
                        && receive_message_state == ReceiveMessageState::Trailers)
                {
                    return Err(Error::FrameUnexpected);
                }
                Ok(())
            }
            StreamType::Request
            | StreamType::Response
            | StreamType::Masque
            | StreamType::WebTransportCover => {
                if known_frame && !matches!(frame_type, 0x00 | 0x01 | 0x05) {
                    return Err(Error::FrameUnexpected);
                }
                if frame_type == 0x05 && conn.is_server() {
                    return Err(Error::FrameUnexpected);
                }
                if (frame_type == 0x00 && receive_message_state != ReceiveMessageState::Body)
                    || (frame_type == 0x01
                        && receive_message_state == ReceiveMessageState::Trailers)
                {
                    return Err(Error::FrameUnexpected);
                }
                Ok(())
            }
            StreamType::Unidirectional
            | StreamType::Bidirectional
            | StreamType::UnknownUnidirectional
            | StreamType::QpackEncoder
            | StreamType::QpackDecoder
            | StreamType::WebTransportData => Err(Error::InternalError),
        }
    }

    pub(super) fn buffer_raw_stream_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        let session_id =
            self.webtransport_session_ids.get(&stream_id).copied().ok_or(Error::IdError)?;
        let session = self.webtransport_sessions.get(&session_id).ok_or(Error::IdError)?;
        let session_ready = session.state == WebTransportSessionState::Established;
        let data_len = u64::try_from(data.len()).map_err(|_| Error::ExcessiveLoad)?;
        let next_data_bytes =
            session.peer_data_bytes.checked_add(data_len).ok_or(Error::ExcessiveLoad)?;
        if next_data_bytes > WEBTRANSPORT_INITIAL_MAX_DATA {
            return Err(Error::ExcessiveLoad);
        }
        let needs_pending_slot = !session_ready
            && (!data.is_empty() || fin)
            && !self.pending_webtransport_streams.contains(&stream_id);
        if needs_pending_slot
            && self.pending_webtransport_streams.len() >= MAX_PENDING_WEBTRANSPORT_STREAMS
        {
            return Err(Error::ExcessiveLoad);
        }
        if !data.is_empty() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
            let buffered_len =
                stream.body_buffer.len().checked_add(data.len()).ok_or(Error::ExcessiveLoad)?;
            if buffered_len > MAX_BUFFERED_H3_FRAME {
                return Err(Error::ExcessiveLoad);
            }
            stream.body_buffer.extend_from_slice(data);
            if session_ready {
                self.pending_events.push_back((stream_id, Event::Data));
            } else {
                self.pending_webtransport_streams.insert(stream_id);
            }
        }
        let session = self.webtransport_sessions.get_mut(&session_id).ok_or(Error::IdError)?;
        session.peer_data_bytes = next_data_bytes;
        if fin {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.fin_received = true;
            }
            if session_ready {
                self.pending_events.push_back((stream_id, Event::Finished));
            } else {
                self.pending_webtransport_streams.insert(stream_id);
            }
        }
        Ok(())
    }

    pub(super) fn publish_ready_webtransport_streams(&mut self) {
        let ready: Vec<u64> = self
            .pending_webtransport_streams
            .iter()
            .copied()
            .filter(|stream_id| {
                self.webtransport_session_ids
                    .get(stream_id)
                    .is_some_and(|session_id| self.webtransport_session_is_established(*session_id))
            })
            .collect();
        for stream_id in ready {
            self.pending_webtransport_streams.remove(&stream_id);
            if self.streams.get(&stream_id).is_some_and(|stream| !stream.body_buffer.is_empty()) {
                self.pending_events.push_back((stream_id, Event::Data));
            }
            if self.streams.get(&stream_id).is_some_and(|stream| stream.fin_received) {
                self.pending_events.push_back((stream_id, Event::Finished));
            }
        }
    }

    pub(super) fn process_stream(
        &mut self,
        conn: &mut super::super::super::Connection,
        stream_id: u64,
        recv_buffer: &mut [u8],
    ) -> Result<(), Error> {
        let (len, fin) =
            conn.stream_recv(stream_id, recv_buffer).map_err(|_| Error::InternalError)?;
        let has_buffered_frames =
            self.streams.get(&stream_id).is_some_and(|stream| !stream.frame_buffer.is_empty());
        if len == 0 && !fin && !has_buffered_frames {
            return Ok(());
        }
        let received = &recv_buffer[..len];
        let existing_type = self.streams.get(&stream_id).map(|stream| stream._stream_type);
        match existing_type {
            Some(StreamType::UnknownUnidirectional) => {
                if fin {
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.fin_received = true;
                    }
                }
                return Ok(());
            }
            Some(StreamType::QpackEncoder) => {
                self.decoder.process_encoder_stream(received)?;
                self.flush_qpack_decoder_instructions(conn)?;
                return if fin { Err(Error::ClosedCriticalStream) } else { Ok(()) };
            }
            Some(StreamType::QpackDecoder) => {
                self.encoder.process_decoder_stream(received)?;
                return if fin { Err(Error::ClosedCriticalStream) } else { Ok(()) };
            }
            Some(StreamType::WebTransportData) => {
                return self.buffer_raw_stream_data(stream_id, received, fin);
            }
            _ => {}
        }
        // Track state for peer-initiated streams (e.g. incoming requests) so DATA payload
        // can be buffered and returned by recv_body(). Locally-opened streams are already
        // present; this fills in the gap for streams we first observe here.
        let is_unidirectional = stream_id & 0x02 != 0;
        if existing_type.is_none() {
            let expected_peer_initiator = if conn.is_server() { 0 } else { 1 };
            if stream_id & 0x01 != expected_peer_initiator {
                return Err(Error::StreamCreationError);
            }
        }
        self.streams.entry(stream_id).or_insert_with(|| StreamState {
            _headers: Vec::new(),
            body_buffer: Vec::new(),
            frame_buffer: Vec::new(),
            _received_bytes: 0,
            _stream_type: if is_unidirectional {
                StreamType::Unidirectional
            } else {
                StreamType::Bidirectional
            },
            sent_bytes: 0,
            fin_sent: false,
            fin_received: false,
            masque_established: false,
            masque_capsule_buffer: Vec::new(),
            settings_received: false,
            receive_message_state: ReceiveMessageState::AwaitingHeaders,
        });
        let mut buffered = {
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
            let buffered_len = stream
                .frame_buffer
                .len()
                .checked_add(received.len())
                .ok_or(Error::ExcessiveLoad)?;
            if buffered_len > MAX_BUFFERED_H3_FRAME {
                log::warn!(
                    "H3 ExcessiveLoad: stream={} buffered_len={} frame_buffer={} recv_chunk={}",
                    stream_id,
                    buffered_len,
                    stream.frame_buffer.len(),
                    received.len()
                );
                return Err(Error::ExcessiveLoad);
            }
            stream.frame_buffer.extend_from_slice(received);
            std::mem::take(&mut stream.frame_buffer)
        };

        if !is_unidirectional
            && self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream._stream_type == StreamType::Bidirectional)
        {
            let (signal, signal_len) = match Self::decode_varint(&buffered) {
                Ok(decoded) => decoded,
                Err(Error::BufferTooShort) => {
                    let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                    stream.frame_buffer.extend_from_slice(&buffered);
                    if fin {
                        return Err(Error::FrameError);
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            if signal == WEBTRANSPORT_STREAM_SIGNAL {
                let (session_id, session_id_len) =
                    match Self::decode_varint(&buffered[signal_len..]) {
                        Ok(decoded) => decoded,
                        Err(Error::BufferTooShort) => {
                            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                            stream.frame_buffer.extend_from_slice(&buffered);
                            if fin {
                                return Err(Error::FrameError);
                            }
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    };
                let prefix_len =
                    signal_len.checked_add(session_id_len).ok_or(Error::ExcessiveLoad)?;
                return self.bind_peer_webtransport_stream(
                    stream_id,
                    session_id,
                    false,
                    &buffered[prefix_len..],
                    fin,
                );
            }
            if !conn.is_server() {
                return Err(Error::StreamCreationError);
            }
            self.peer_request_stream_id = Some(stream_id);
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
            stream._stream_type = StreamType::Request;
        }

        if is_unidirectional
            && self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream._stream_type == StreamType::Unidirectional)
        {
            let (stream_type, type_len) = match Self::decode_varint(&buffered) {
                Ok(decoded) => decoded,
                Err(Error::BufferTooShort) => {
                    let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                    stream.frame_buffer.extend_from_slice(&buffered);
                    if fin {
                        return Err(Error::FrameError);
                    }
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let classified =
                self.classify_peer_unidirectional_stream(conn, stream_id, stream_type)?;
            let mut prefix_len = type_len;
            let mut webtransport_session_id = None;
            if stream_type == 0x01 {
                let (push_id, push_id_len) = match Self::decode_varint(&buffered[type_len..]) {
                    Ok(decoded) => decoded,
                    Err(Error::BufferTooShort) => {
                        let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                        stream.frame_buffer.extend_from_slice(&buffered);
                        if fin {
                            return Err(Error::FrameError);
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                if self.local_max_push_id.is_none_or(|maximum| push_id > maximum)
                    || !self.received_push_ids.insert(push_id)
                {
                    return Err(Error::IdError);
                }
                prefix_len = prefix_len.checked_add(push_id_len).ok_or(Error::ExcessiveLoad)?;
            } else if stream_type == WEBTRANSPORT_UNI_STREAM_TYPE {
                let (session_id, session_id_len) = match Self::decode_varint(&buffered[type_len..])
                {
                    Ok(decoded) => decoded,
                    Err(Error::BufferTooShort) => {
                        let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                        stream.frame_buffer.extend_from_slice(&buffered);
                        if fin {
                            return Err(Error::FrameError);
                        }
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                };
                if session_id & 0x03 != 0 {
                    return Err(Error::IdError);
                }
                webtransport_session_id = Some(session_id);
                prefix_len = prefix_len.checked_add(session_id_len).ok_or(Error::ExcessiveLoad)?;
            }
            buffered.drain(..prefix_len);
            if classified == StreamType::WebTransportData {
                let session_id = webtransport_session_id.ok_or(Error::IdError)?;
                return self
                    .bind_peer_webtransport_stream(stream_id, session_id, true, &buffered, fin);
            }
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream._stream_type = classified;
            }
            match classified {
                StreamType::UnknownUnidirectional => {
                    if fin {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.fin_received = true;
                        }
                    }
                    return Ok(());
                }
                StreamType::QpackEncoder => {
                    self.decoder.process_encoder_stream(&buffered)?;
                    self.flush_qpack_decoder_instructions(conn)?;
                    return if fin { Err(Error::ClosedCriticalStream) } else { Ok(()) };
                }
                StreamType::QpackDecoder => {
                    self.encoder.process_decoder_stream(&buffered)?;
                    return if fin { Err(Error::ClosedCriticalStream) } else { Ok(()) };
                }
                _ => {}
            }
        }

        // Parse complete frames and retain an incomplete tail for the next STREAM chunk.
        // MASQUE events are staged until the complete H3 DATA batch is valid so a malformed
        // suffix cannot leave earlier capsules from the same batch visible to callers.
        let mut pending_masque_events = Vec::new();
        let mut offset = 0;
        while offset < buffered.len() {
            let (frame_type, frame_len, frame_offset) =
                match Self::parse_frame_header(&buffered[offset..]) {
                    Ok(header) => header,
                    Err(Error::BufferTooShort) => break,
                    Err(error) => return Err(error),
                };
            if frame_len > 1024 * 1024 {
                let preview_end = (offset + 32).min(buffered.len());
                log::warn!(
                    "H3 ExcessiveLoad: stream={} frame_type=0x{:02x} frame_len={} offset={} buffered={} preview={:02x?}",
                    stream_id,
                    frame_type,
                    frame_len,
                    offset,
                    buffered.len(),
                    &buffered[offset..preview_end]
                );
                return Err(Error::ExcessiveLoad);
            }
            let body_start = offset.checked_add(frame_offset).ok_or(Error::ExcessiveLoad)?;
            let body_end = match body_start.checked_add(frame_len) {
                Some(end) if end <= buffered.len() => end,
                Some(_) => break,
                None => return Err(Error::ExcessiveLoad),
            };
            let frame_data = &buffered[body_start..body_end];
            let stream_type = self
                .streams
                .get(&stream_id)
                .map(|stream| stream._stream_type)
                .ok_or(Error::IdError)?;
            let settings_received =
                self.streams.get(&stream_id).is_some_and(|stream| stream.settings_received);
            let receive_message_state = self
                .streams
                .get(&stream_id)
                .map(|stream| stream.receive_message_state)
                .ok_or(Error::IdError)?;
            Self::validate_frame_placement(
                conn,
                stream_type,
                frame_type,
                settings_received,
                receive_message_state,
            )?;
            match frame_type {
                0x00 => {
                    // DATA frame; if this stream is MASQUE, decode capsules
                    let is_masque = self
                        .streams
                        .get(&stream_id)
                        .map(|st| matches!(st._stream_type, StreamType::Masque))
                        .unwrap_or(false);
                    if is_masque {
                        let events = {
                            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                            let buffered_len = stream
                                .masque_capsule_buffer
                                .len()
                                .checked_add(frame_data.len())
                                .ok_or(Error::ExcessiveLoad)?;
                            if buffered_len > MAX_BUFFERED_H3_FRAME {
                                return Err(Error::ExcessiveLoad);
                            }
                            stream.masque_capsule_buffer.extend_from_slice(frame_data);
                            Self::decode_masque_capsules(&mut stream.masque_capsule_buffer)?
                        };
                        pending_masque_events.extend(events.into_iter().map(|(ctype, payload)| {
                            (stream_id, Event::MasqueCapsule { capsule_type: ctype, payload })
                        }));
                    } else {
                        // Buffer the DATA payload so recv_body() returns the real body bytes
                        // (e.g. the IP packets tunneled over an H3 stream), then signal Data.
                        if let Some(st) = self.streams.get_mut(&stream_id) {
                            st.body_buffer.extend_from_slice(frame_data);
                        }
                        self.pending_events.push_back((stream_id, Event::Data));
                    }
                }
                0x01 => {
                    let headers = match self.decoder.decode(stream_id, frame_data)? {
                        qpack::DecodeOutcome::Decoded(headers) => headers,
                        qpack::DecodeOutcome::Blocked => {
                            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                            stream.frame_buffer.extend_from_slice(&buffered[offset..]);
                            self.pending_events.extend(pending_masque_events);
                            return Ok(());
                        }
                    };
                    self.flush_qpack_decoder_instructions(conn)?;
                    let current_stream_type = self
                        .streams
                        .get(&stream_id)
                        .map(|stream| stream._stream_type)
                        .ok_or(Error::IdError)?;
                    let success_response = Self::masque_response_status(&headers)
                        .is_some_and(|status| (200..300).contains(&status));
                    let masque_response_accepted =
                        current_stream_type == StreamType::Masque && success_response;
                    let webtransport_request = conn.is_server()
                        && current_stream_type == StreamType::Request
                        && Self::is_webtransport_connect(&headers)?;
                    let webtransport_response_status =
                        if current_stream_type == StreamType::WebTransportCover {
                            Self::masque_response_status(&headers)
                        } else {
                            None
                        };
                    let informational_response = !conn.is_server()
                        && Self::masque_response_status(&headers)
                            .is_some_and(|status| (100..200).contains(&status));
                    if webtransport_request {
                        if !self.peer_supports_webtransport() {
                            return Err(Error::SettingsError);
                        }
                        self.register_webtransport_session(stream_id)?;
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream._stream_type = StreamType::WebTransportCover;
                        }
                    }
                    match webtransport_response_status {
                        Some(status) if (200..300).contains(&status) => {
                            self.establish_webtransport_session(stream_id)?;
                        }
                        Some(status) if status >= 200 => {
                            self.remove_webtransport_session(stream_id);
                        }
                        _ => {}
                    }
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.receive_message_state = match stream.receive_message_state {
                            ReceiveMessageState::AwaitingHeaders if informational_response => {
                                ReceiveMessageState::AwaitingHeaders
                            }
                            ReceiveMessageState::AwaitingHeaders => ReceiveMessageState::Body,
                            ReceiveMessageState::Body => ReceiveMessageState::Trailers,
                            ReceiveMessageState::Trailers => ReceiveMessageState::Trailers,
                        };
                    }
                    let event = Event::Headers { list: headers, has_body: !fin };
                    self.pending_events.push_back((stream_id, event));
                    if masque_response_accepted {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.masque_established = true;
                        }
                    }
                }
                0x03 => {
                    let push_id = Self::decode_single_varint_payload(frame_data)?;
                    if self.peer_max_push_id.is_none_or(|maximum| push_id > maximum) {
                        return Err(Error::IdError);
                    }
                }
                0x04 => {
                    let settings = Self::parse_settings_payload(frame_data)?;
                    self.encoder.configure_peer(
                        settings.maximum_table_capacity,
                        settings.blocked_streams,
                    )?;
                    self.peer_settings = Some(settings);
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.settings_received = true;
                    }
                }
                0x05 => {
                    let (push_id, push_id_len) =
                        Self::decode_varint(frame_data).map_err(|error| {
                            if error == Error::BufferTooShort {
                                Error::FrameError
                            } else {
                                error
                            }
                        })?;
                    if self.local_max_push_id.is_none_or(|maximum| push_id > maximum) {
                        return Err(Error::IdError);
                    }
                    let headers =
                        match self.decoder.decode(stream_id, &frame_data[push_id_len..])? {
                            qpack::DecodeOutcome::Decoded(headers) => headers,
                            qpack::DecodeOutcome::Blocked => {
                                let stream =
                                    self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
                                stream.frame_buffer.extend_from_slice(&buffered[offset..]);
                                self.pending_events.extend(pending_masque_events);
                                return Ok(());
                            }
                        };
                    self.flush_qpack_decoder_instructions(conn)?;
                    self.pending_events
                        .push_back((stream_id, Event::PushPromise { push_id, headers }));
                }
                0x07 => {
                    let identifier = Self::decode_single_varint_payload(frame_data)?;
                    if !conn.is_server() && identifier & 0x03 != 0 {
                        return Err(Error::IdError);
                    }
                    if self.peer_goaway_id.is_some_and(|current| identifier > current) {
                        return Err(Error::IdError);
                    }
                    self.peer_goaway_id = Some(identifier);
                    self.goaway_received = true;
                    self.pending_events.push_back((stream_id, Event::GoAway));
                }
                0x0d => {
                    let maximum = Self::decode_single_varint_payload(frame_data)?;
                    if self.peer_max_push_id.is_some_and(|current| maximum <= current) {
                        return Err(Error::IdError);
                    }
                    self.peer_max_push_id = Some(maximum);
                }
                _ => {}
            }
            offset = offset
                .checked_add(frame_offset)
                .and_then(|value| value.checked_add(frame_len))
                .ok_or(Error::ExcessiveLoad)?;
        }
        if offset != buffered.len() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
            stream.frame_buffer.extend_from_slice(&buffered[offset..]);
        }
        if fin {
            if self.streams.get(&stream_id).is_some_and(|stream| {
                matches!(
                    stream._stream_type,
                    StreamType::Control | StreamType::QpackEncoder | StreamType::QpackDecoder
                )
            }) {
                return Err(Error::ClosedCriticalStream);
            }
            if self.streams.get(&stream_id).is_some_and(|stream| !stream.frame_buffer.is_empty()) {
                return Err(Error::FrameError);
            }
            if self.streams.get(&stream_id).is_some_and(|stream| {
                matches!(stream._stream_type, StreamType::Masque)
                    && !stream.masque_capsule_buffer.is_empty()
            }) {
                return Err(Error::FrameError);
            }
            if let Some(state) = self.streams.get_mut(&stream_id) {
                state.fin_received = true;
            }
        }
        self.pending_events.extend(pending_masque_events);
        if fin {
            self.pending_events.push_back((stream_id, Event::Finished));
        }
        Ok(())
    }
}
