use super::*;
use crate::optimize::PooledBlock;
use std::collections::{HashSet, VecDeque};

/// HTTP/3 Server Push Promise for stealth cover traffic
#[derive(Debug, Clone)]
struct PushPromise {
    /// Request headers carried by PUSH_PROMISE.
    request_headers: Vec<Header>,
    /// Response headers that start the corresponding push stream.
    response_headers: Vec<Header>,
    /// Client-initiated request stream that carries PUSH_PROMISE.
    request_stream_id: u64,
    /// Server-initiated unidirectional stream allocated after the promise is sent.
    push_stream_id: Option<u64>,
    /// Push stream state
    state: PushState,
    /// Cover traffic payload (fake resources)
    cover_payload: Vec<u8>,
    /// Timing for realistic delivery
    scheduled_at: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PushState {
    PendingPromise,
    Promised,
    DataSending,
    Complete,
}

const STREAM_RECV_BUFFER_SIZE: usize = 64 * 1024;
const MAX_QUIC_DATAGRAM_SIZE: usize = 65_535;
const MAX_BUFFERED_H3_FRAME: usize = 1024 * 1024 + 16;
const MAX_H3_SETTING_VALUE: u64 = 16 * 1024 * 1024;
const MAX_STEALTH_PUSH_ID: u64 = 63;

/// HTTP/3 connection with enhanced stream state management
pub struct Connection {
    /// Monotonic clock shared with the underlying QUIC transport.
    clock: crate::time_source::ProtocolClock,
    is_server: bool,
    config: Config,
    next_stream_id: u64,
    next_uni_stream_id: u64,
    streams: HashMap<u64, StreamState>,
    finished_streams: HashSet<u64>,
    pending_events: VecDeque<(u64, Event)>,
    encoder: qpack::Encoder,
    decoder: qpack::Decoder,
    control_stream_id: Option<u64>,
    _peer_control_stream_id: Option<u64>,
    peer_qpack_encoder_stream_id: Option<u64>,
    peer_qpack_decoder_stream_id: Option<u64>,
    peer_request_stream_id: Option<u64>,
    peer_max_push_id: Option<u64>,
    local_max_push_id: Option<u64>,
    received_push_ids: HashSet<u64>,
    webtransport_session_ids: HashMap<u64, u64>,
    established_webtransport_sessions: HashSet<u64>,
    pending_webtransport_streams: HashSet<u64>,
    goaway_sent: bool,
    goaway_received: bool,
    peer_goaway_id: Option<u64>,
    /// Server Push streams for stealth cover traffic
    push_streams: HashMap<u64, PushPromise>,
    /// MASQUE Flow-ID mapping per CONNECT-UDP stream (when datagrams enabled)
    masque_flow: HashMap<u64, u64>,
    /// Next HTTP/3 push ID, independent of the QUIC push-stream identifier.
    next_push_id: u64,
    /// Reused caller-owned buffer for one transport STREAM receive operation.
    stream_recv_buffer: Vec<u8>,
    /// Receive buffer sized to the transport's configured UDP payload ceiling.
    masque_recv_buffer: Vec<u8>,
}

/// Stream state tracking
#[derive(Debug, Clone)]
struct StreamState {
    _headers: Vec<Header>,
    body_buffer: Vec<u8>,
    frame_buffer: Vec<u8>,
    _received_bytes: usize,
    _stream_type: StreamType,
    sent_bytes: usize,
    fin_sent: bool,
    fin_received: bool,
    masque_established: bool,
    masque_capsule_buffer: Vec<u8>,
    settings_received: bool,
    receive_message_state: ReceiveMessageState,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ReceiveMessageState {
    AwaitingHeaders,
    Body,
    Trailers,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum StreamType {
    /// A peer-initiated unidirectional stream whose type prefix is incomplete.
    Unidirectional,
    /// A unidirectional stream type that this implementation does not consume.
    UnknownUnidirectional,
    /// The peer's unframed QPACK encoder instruction stream.
    QpackEncoder,
    /// The peer's unframed QPACK decoder instruction stream.
    QpackDecoder,
    /// A WebTransport unidirectional data stream after its session prefix.
    WebTransportData,
    Request,
    Response,
    Control,
    Push,
    Masque,
    WebTransportCover,
}

impl Connection {
    fn build_stealth_cover_resource_plan(
        base_path: &str,
        seed: u64,
    ) -> Vec<(String, &'static str, usize)> {
        const RESOURCES: &[(&str, &str, usize)] = &[
            ("/css/main.css", "text/css", 45_000),
            ("/css/theme.css", "text/css", 18_000),
            ("/css/fonts.css", "text/css", 8_000),
            ("/js/app.js", "application/javascript", 120_000),
            ("/js/runtime.js", "application/javascript", 22_000),
            ("/js/vendor.js", "application/javascript", 280_000),
            ("/js/analytics.js", "application/javascript", 25_000),
            ("/images/hero.jpg", "image/jpeg", 85_000),
            ("/images/card.jpg", "image/jpeg", 54_000),
            ("/images/logo.png", "image/png", 12_000),
            ("/images/icon.png", "image/png", 6_000),
            ("/media/poster.jpg", "image/jpeg", 72_000),
        ];

        let base = base_path.trim_end_matches('/');
        let count = 3 + ((seed >> 32) as usize % 5);
        let start = (seed as usize) % RESOURCES.len();
        let step = 5usize;
        let mut plan = Vec::with_capacity(count);

        for i in 0..count {
            let (path, content_type, nominal_size) =
                RESOURCES[(start + i * step) % RESOURCES.len()];
            let jitter = ((seed.rotate_left((i as u32) & 31) >> 8) % 31) as i32 - 15;
            let size =
                ((nominal_size as i64) * (100 + jitter) as i64 / 100).clamp(1024, 320_000) as usize;
            let version = seed.rotate_right((i as u32) & 31) & 0x0fff;
            let full_path = if version.is_multiple_of(3) {
                format!("{base}{path}?v={version:x}")
            } else {
                format!("{base}{path}")
            };
            plan.push((full_path, content_type, size));
        }

        plan
    }

    fn encode_headers_block(&mut self, headers: &[Header]) -> Result<Vec<u8>, Error> {
        // QPACK header blocks can exceed 4KiB when stealth adds realistic header cover.
        // Grow the buffer until the encoder succeeds (bounded to avoid pathological allocations).
        let mut cap = 4096usize;
        loop {
            let mut buf = vec![0u8; cap];
            match self.encoder.encode(headers, &mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    return Ok(buf);
                }
                Err(Error::BufferTooShort) => {
                    if cap >= 256 * 1024 {
                        return Err(Error::BufferTooShort);
                    }
                    cap = (cap * 2).min(256 * 1024);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Creates a new HTTP/3 connection with proper initialization
    pub fn with_transport(conn: &mut super::Connection, config: &Config) -> Result<Self, Error> {
        // Validate config limits for HTTP/3 compliance and safety.
        // A zero field-section limit is unusable. Every locally advertised setting is bounded
        // before it reaches QPACK state or the wire so an unchecked public setter cannot create
        // target-width truncation or an unbounded peer/runtime contract.
        if config.max_field_section_size() == 0
            || config.max_field_section_size() > MAX_H3_SETTING_VALUE
            || config.qpack_max_table_capacity() > MAX_H3_SETTING_VALUE
            || config.qpack_blocked_streams() > MAX_H3_SETTING_VALUE
        {
            return Err(Error::ExcessiveLoad);
        }
        let masque_buffer_len = conn.max_recv_udp_payload_size().clamp(1, MAX_QUIC_DATAGRAM_SIZE);
        let mut h3_conn = Self {
            clock: conn.protocol_clock(),
            is_server: conn.is_server(),
            config: config.clone(),
            next_stream_id: if conn.is_server() { 1 } else { 0 },
            next_uni_stream_id: if conn.is_server() { 3 } else { 2 },
            streams: HashMap::new(),
            finished_streams: HashSet::new(),
            pending_events: VecDeque::new(),
            encoder: qpack::Encoder::with_capacity(config.qpack_max_table_capacity()),
            decoder: qpack::Decoder::with_capacity(config.qpack_max_table_capacity()),
            control_stream_id: None,
            _peer_control_stream_id: None,
            peer_qpack_encoder_stream_id: None,
            peer_qpack_decoder_stream_id: None,
            peer_request_stream_id: None,
            peer_max_push_id: None,
            local_max_push_id: if conn.is_server() { None } else { Some(MAX_STEALTH_PUSH_ID) },
            received_push_ids: HashSet::new(),
            webtransport_session_ids: HashMap::new(),
            established_webtransport_sessions: HashSet::new(),
            pending_webtransport_streams: HashSet::new(),
            goaway_sent: false,
            goaway_received: false,
            peer_goaway_id: None,
            push_streams: HashMap::new(),
            masque_flow: HashMap::new(),
            // Server push streams are locally-created unidirectional streams, so their
            // transport IDs use the server-initiated class (3, 7, 11, ...).
            next_push_id: 0,
            stream_recv_buffer: vec![0u8; STREAM_RECV_BUFFER_SIZE],
            masque_recv_buffer: vec![0u8; masque_buffer_len],
        };

        // Try to emit the mandatory control-stream prologue immediately. A connection can be
        // constructed before peer flow-control limits are available, so a flow-control refusal
        // is deferred to the first operation that can make progress rather than failing setup.
        h3_conn.init_control_stream(conn)?;
        Ok(h3_conn)
    }

    /// Set the persona index policy (header names that should be prioritised).
    pub(crate) fn set_qpack_index_policy(&mut self, prefer: &[&[u8]]) {
        self.encoder.set_index_policy(prefer);
    }

    /// Initialize the local unidirectional control stream and emit its SETTINGS prologue.
    ///
    /// The transport's stream API is transactional: it either queues the complete byte slice or
    /// returns an error. We therefore only publish `control_stream_id` after the stream type and
    /// first SETTINGS frame have both been accepted. Flow-control refusal is intentionally
    /// retryable because H3 construction can precede transport parameter establishment.
    fn init_control_stream(&mut self, conn: &mut super::Connection) -> Result<(), Error> {
        if self.control_stream_id.is_some() {
            return Ok(());
        }

        let stream_id = self.next_uni_stream_id;
        let mut settings_payload = Vec::with_capacity(32);
        for (setting, value) in [
            (0x01u64, self.config.qpack_max_table_capacity()),
            (0x06u64, self.config.max_field_section_size()),
            (0x07u64, self.config.qpack_blocked_streams()),
        ] {
            Self::encode_varint(setting, &mut settings_payload);
            Self::encode_varint(value, &mut settings_payload);
        }

        let mut prologue = Vec::with_capacity(settings_payload.len() + 4);
        Self::encode_varint(0, &mut prologue); // H3 control stream type
        Self::encode_varint(0x04, &mut prologue); // SETTINGS frame type
        Self::encode_varint(settings_payload.len() as u64, &mut prologue);
        prologue.extend_from_slice(&settings_payload);
        if let Some(max_push_id) = self.local_max_push_id {
            let mut max_push_payload = Vec::with_capacity(8);
            Self::encode_varint(max_push_id, &mut max_push_payload);
            Self::encode_varint(0x0d, &mut prologue);
            Self::encode_varint(max_push_payload.len() as u64, &mut prologue);
            prologue.extend_from_slice(&max_push_payload);
        }

        let sent = match conn.stream_send(stream_id, &prologue, false) {
            Ok(sent) if sent == prologue.len() => sent,
            Ok(_) => return Err(Error::InternalError),
            Err(crate::error::ConnectionError::FlowControl)
            | Err(crate::error::ConnectionError::StreamLimit) => return Ok(()),
            Err(_) => return Err(Error::InternalError),
        };

        self.next_uni_stream_id = stream_id.checked_add(4).ok_or(Error::StreamCreationError)?;
        self.control_stream_id = Some(stream_id);
        self.streams.insert(
            stream_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::Control,
                sent_bytes: 0,
                fin_sent: false,
                fin_received: false,
                masque_established: false,
                masque_capsule_buffer: Vec::new(),
                settings_received: true,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.sent_bytes = sent;
        }
        Ok(())
    }

    /// Sends an HTTP/3 request with proper frame encoding
    pub fn send_request(
        &mut self,
        conn: &mut super::Connection,
        headers: &[Header],
        fin: bool,
    ) -> Result<u64, Error> {
        if self.goaway_sent || self.goaway_received {
            return Err(Error::ClosedCriticalStream);
        }
        self.init_control_stream(conn)?;
        if self.control_stream_id.is_none() {
            return Err(Error::StreamCreationError);
        }
        let stream_id = self.next_stream_id;
        self.next_stream_id += 4;
        let encoded = self.encode_headers_block(headers)?;
        let encoded_len = encoded.len();
        // Create HEADERS frame
        let mut frame = Vec::new();
        frame.push(0x01);
        Self::encode_varint(encoded_len as u64, &mut frame);
        frame.extend_from_slice(&encoded[..encoded_len]);
        conn.stream_send(stream_id, &frame, fin).map_err(|_| Error::InternalError)?;
        // Telemetry
        crate::optimize::telemetry::H3_FRAMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::optimize::telemetry::H3_HEADERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.streams.insert(
            stream_id,
            StreamState {
                _headers: headers.to_vec(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::Request,
                sent_bytes: frame.len(),
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

    /// Sends an HTTP/3 response
    pub fn send_response(
        &mut self,
        conn: &mut super::Connection,
        stream_id: u64,
        headers: &[Header],
        fin: bool,
    ) -> Result<(), Error> {
        self.init_control_stream(conn)?;
        if self.control_stream_id.is_none() {
            return Err(Error::StreamCreationError);
        }
        let encoded = self.encode_headers_block(headers)?;
        let mut frame = Vec::with_capacity(encoded.len().saturating_add(10));
        frame.push(0x01);
        Self::encode_varint(encoded.len() as u64, &mut frame);
        frame.extend_from_slice(&encoded);
        let sent = conn.stream_send(stream_id, &frame, fin).map_err(|_| Error::InternalError)?;
        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamState {
            _headers: Vec::new(),
            body_buffer: Vec::new(),
            frame_buffer: Vec::new(),
            _received_bytes: 0,
            _stream_type: StreamType::Response,
            sent_bytes: 0,
            fin_sent: false,
            fin_received: false,
            masque_established: false,
            masque_capsule_buffer: Vec::new(),
            settings_received: false,
            receive_message_state: ReceiveMessageState::AwaitingHeaders,
        });
        let webtransport_response = stream._stream_type == StreamType::WebTransportCover;
        stream._headers = headers.to_vec();
        stream._stream_type = if webtransport_response {
            StreamType::WebTransportCover
        } else {
            StreamType::Response
        };
        stream.sent_bytes = stream.sent_bytes.saturating_add(sent);
        stream.fin_sent = fin;
        if webtransport_response
            && Self::masque_response_status(headers).is_some_and(|status| (200..300).contains(&status))
        {
            self.established_webtransport_sessions.insert(stream_id);
        }
        crate::optimize::telemetry::H3_FRAMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::optimize::telemetry::H3_HEADERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if fin {
            self.finished_streams.insert(stream_id);
        }
        Ok(())
    }

    /// Sends body data with proper DATA frame encoding
    pub fn send_body(
        &mut self,
        conn: &mut super::Connection,
        stream_id: u64,
        body: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        if self.finished_streams.contains(&stream_id) {
            return Err(Error::Done);
        }
        self.init_control_stream(conn)?;
        if self.control_stream_id.is_none() {
            return Err(Error::StreamCreationError);
        }
        let stream_state = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
        if stream_state.fin_sent {
            return Err(Error::Done);
        }
        // Adaptive compression - policy + content-type aware
        let mut to_send = body;
        let mut owned_buf: Option<(PooledBlock, usize)> = None;
        // Policy & Dictionary
        let pol = crate::compress::global_policy_with_snapshot(conn.environment_snapshot());
        if pol.enabled {
            // Extract content-type header from stream state
            let ctype = stream_state._headers.iter().find_map(|h| {
                if h.name() == b"content-type" {
                    Some(String::from_utf8_lossy(h.value()).to_string())
                } else {
                    None
                }
            });
            let looks_text = crate::compress::CompressionManager::looks_textual(body);
            let should_try = pol.allows_content_type(ctype.as_deref())
                && (ctype.is_some() || looks_text);
            if should_try && body.len() >= pol.min_len {
                let rtt = conn.rtt().as_millis() as f32;
                let bw = conn.delivery_rate();
                let cm =
                    crate::compress::CompressionManager::new(crate::compress::CompressionConfig {
                        min_len: pol.min_len,
                        max_level: pol.level,
                    });
                if cm.should_compress(body.len(), rtt, 0.0, bw) {
                    // Dictionaries: try a matching dict; otherwise use the default compressor.
                    if let Some(ct) = ctype.as_ref() {
                        // Training hook.
                        crate::compress::submit_sample(ct, body);
                        crate::compress::maybe_train(ct);
                        if let Some((dict, ver)) = crate::compress::get_dict(ct) {
                            let pool = &crate::compress::body_pool();
                            if let Some((blk, used)) = crate::compress::compress_with_dict(
                                pool, body, pol.level, &dict, ver,
                            ) {
                                owned_buf = Some((blk, used));
                            }
                        } else {
                            let pool = &crate::compress::body_pool();
                            if let Some((blk, used)) = cm.compress_to_pool(pool, body) {
                                owned_buf = Some((blk, used));
                            }
                        }
                    } else {
                        let pool = &crate::compress::body_pool();
                        if let Some((blk, used)) = cm.compress_to_pool(pool, body) {
                            owned_buf = Some((blk, used));
                        }
                    }
                }
            }
        }
        if let Some((blk, used)) = &owned_buf {
            to_send = &blk[..*used];
            // The RAII owner remains live until the transport has consumed the frame bytes.
        }
        let mut frame = Vec::new();
        frame.push(0x00);
        Self::encode_varint(to_send.len() as u64, &mut frame);
        frame.extend_from_slice(to_send);
        let sent = conn.stream_send(stream_id, &frame, fin).map_err(|_| Error::InternalError)?;
        // Telemetry
        crate::optimize::telemetry::H3_FRAMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        crate::optimize::telemetry::H3_DATA_BYTES
            .fetch_add(to_send.len() as u64, std::sync::atomic::Ordering::Relaxed);
        drop(owned_buf);
        stream_state.sent_bytes += sent;
        stream_state.fin_sent = fin;
        if fin {
            // Local FIN: mark as finished for GC, but do not set fin_received here.
            self.finished_streams.insert(stream_id);
        }
        Ok(body.len())
    }

    /// Receives body data
    pub fn recv_body(
        &mut self,
        _conn: &mut super::Connection,
        stream_id: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        // Return buffered DATA-frame payload accumulated by process_stream(). Returns 0
        // when the buffer is currently drained (caller's read loop stops on 0), and
        // Error::Done when the stream is unknown.
        let st = self.streams.get_mut(&stream_id).ok_or(Error::Done)?;
        if st.body_buffer.is_empty() {
            return Ok(0);
        }
        let len = std::cmp::min(out.len(), st.body_buffer.len());
        out[..len].copy_from_slice(&st.body_buffer[..len]);
        st.body_buffer.drain(..len);
        Ok(len)
    }

    /// Process HTTP/3 frames and generate events
    pub fn poll(&mut self, conn: &mut super::Connection) -> Result<Option<(u64, Event)>, Error> {
        self.init_control_stream(conn)?;
        // Process scheduled push streams and continue sending bodies
        self.process_scheduled_push_streams(conn);
        self.process_push_data(conn);

        // Process incoming readable streams (requests, responses, MASQUE, etc).
        // The transport marks streams readable when STREAM frames deliver data.
        while let Some(stream_id) = conn.stream_readable_next() {
            let mut recv_buffer = std::mem::take(&mut self.stream_recv_buffer);
            let result = self.process_stream(conn, stream_id, &mut recv_buffer);
            self.stream_recv_buffer = recv_buffer;
            result?;
        }
        self.publish_ready_webtransport_streams();

        // Lightweight GC using fin_received. Completed push streams are locally
        // terminal after their FIN because peers do not send a reciprocal stream FIN.
        let done: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(id, st)| {
                let push_complete = st._stream_type == StreamType::Push
                    && st.fin_sent
                    && self.push_streams.values().any(|promise| {
                        promise.push_stream_id == Some(*id) && promise.state == PushState::Complete
                    });
                let pending_event = self.pending_events.iter().any(|(event_id, _)| event_id == id);
                if (st.fin_received
                    && st.body_buffer.is_empty()
                    && !pending_event
                    && !self.pending_webtransport_streams.contains(id))
                    || push_complete
                {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();
        for id in done {
            self.streams.remove(&id);
            self.finished_streams.remove(&id);
            self.masque_flow.remove(&id);
            self.webtransport_session_ids.remove(&id);
            self.pending_webtransport_streams.remove(&id);
            self.established_webtransport_sessions.remove(&id);
            if self.peer_request_stream_id == Some(id) {
                self.peer_request_stream_id = None;
            }
            self.push_streams.retain(|_, promise| {
                let abandoned_before_promise = promise.request_stream_id == id
                    && promise.state == PushState::PendingPromise;
                let completed_push_stream =
                    promise.push_stream_id == Some(id) && promise.state == PushState::Complete;
                !abandoned_before_promise && !completed_push_stream
            });
        }
        self.pending_events.pop_front().map(Some).ok_or(Error::Done)
    }

    /// **STEALTH FEATURE**: Create server push promise for cover traffic
    /// This generates realistic HTTP/3 server push traffic to mask real data flows
    fn create_stealth_push_promise(
        &mut self,
        path: &str,
        content_type: &str,
        size_bytes: usize,
    ) -> Result<u64, Error> {
        if !self.is_server {
            return Err(Error::StreamCreationError);
        }
        let request_stream_id = self.peer_request_stream_id.ok_or(Error::Done)?;
        let peer_max_push_id = self.peer_max_push_id.ok_or(Error::Done)?;
        let push_id = self.next_push_id;
        if push_id > peer_max_push_id {
            return Err(Error::IdError);
        }
        self.next_push_id = push_id.checked_add(1).ok_or(Error::IdError)?;

        let request_headers = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":path", path.as_bytes()),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", b"cdn.example.com"),
            Header::new(b"accept", b"*/*"),
        ];
        let response_headers = vec![
            Header::new(b":status", b"200"),
            Header::new(b"content-type", content_type.as_bytes()),
            Header::new(b"cache-control", b"public, max-age=31536000"),
            Header::new(b"content-length", size_bytes.to_string().as_bytes()),
            Header::new(b"x-cdn-cache", b"HIT"),
        ];

        // Generate realistic cover payload (fake CSS/JS/images)
        let cover_payload = match content_type {
            "text/css" => generate_fake_css(size_bytes),
            "application/javascript" => generate_fake_js(size_bytes),
            "image/jpeg" | "image/png" => generate_fake_image_data(size_bytes),
            _ => vec![0x20; size_bytes], // Generic padding
        };

        let push_promise = PushPromise {
            request_headers,
            response_headers,
            request_stream_id,
            push_stream_id: None,
            state: PushState::PendingPromise,
            cover_payload,
            scheduled_at: self.clock.now()
                + std::time::Duration::from_millis(
                    50 + (push_id % 200), // Realistic 50-250ms delay
                ),
        };

        self.push_streams.insert(push_id, push_promise);
        // Telemetry
        crate::telemetry::STEALTH_PUSH_PROMISES.inc();
        crate::telemetry::STEALTH_PUSH_BYTES
            .fetch_add(size_bytes as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(push_id)
    }

    /// Process scheduled push streams (called from poll)
    fn process_scheduled_push_streams(&mut self, conn: &mut super::Connection) {
        if self.init_control_stream(conn).is_err() || self.control_stream_id.is_none() {
            return;
        }
        let now = self.clock.now();
        let mut ready_push_ids = Vec::new();

        for (&push_id, promise) in &self.push_streams {
            if promise.scheduled_at <= now
                && matches!(promise.state, PushState::PendingPromise | PushState::Promised)
            {
                ready_push_ids.push(push_id);
            }
        }

        for push_id in ready_push_ids {
            let Some(snapshot) = self.push_streams.get(&push_id).cloned() else { continue };
            if snapshot.state == PushState::PendingPromise {
                let encoded = match self.encode_headers_block(&snapshot.request_headers) {
                    Ok(encoded) => encoded,
                    Err(_) => continue,
                };
                let mut payload = Vec::with_capacity(encoded.len().saturating_add(8));
                Self::encode_varint(push_id, &mut payload);
                payload.extend_from_slice(&encoded);
                let mut frame = Vec::with_capacity(payload.len().saturating_add(9));
                Self::encode_varint(0x05, &mut frame);
                Self::encode_varint(payload.len() as u64, &mut frame);
                frame.extend_from_slice(&payload);
                if conn.stream_send(snapshot.request_stream_id, &frame, false).is_err() {
                    continue;
                }
                if let Some(promise) = self.push_streams.get_mut(&push_id) {
                    promise.state = PushState::Promised;
                }
            }

            let Some(snapshot) = self.push_streams.get(&push_id).cloned() else { continue };
            if snapshot.state != PushState::Promised {
                continue;
            }
            let encoded = match self.encode_headers_block(&snapshot.response_headers) {
                Ok(encoded) => encoded,
                Err(_) => continue,
            };
            let stream_id = self.next_uni_stream_id;
            let mut prologue = Vec::with_capacity(encoded.len().saturating_add(18));
            Self::encode_varint(0x01, &mut prologue);
            Self::encode_varint(push_id, &mut prologue);
            Self::encode_varint(0x01, &mut prologue);
            Self::encode_varint(encoded.len() as u64, &mut prologue);
            prologue.extend_from_slice(&encoded);
            let Some(next_stream_id) = stream_id.checked_add(4) else {
                continue;
            };
            if conn.stream_send(stream_id, &prologue, false).is_err() {
                continue;
            }
            self.next_uni_stream_id = next_stream_id;

            // Register stream with body and switch to DataSending
            self.streams.insert(
                stream_id,
                StreamState {
                    _headers: snapshot.response_headers,
                    body_buffer: snapshot.cover_payload,
                    frame_buffer: Vec::new(),
                    _received_bytes: 0,
                    _stream_type: StreamType::Push,
                    sent_bytes: 0,
                    fin_sent: false,
                    fin_received: false,
                    masque_established: false,
                    masque_capsule_buffer: Vec::new(),
                    settings_received: false,
                    receive_message_state: ReceiveMessageState::AwaitingHeaders,
                },
            );
            if let Some(promise) = self.push_streams.get_mut(&push_id) {
                promise.push_stream_id = Some(stream_id);
                promise.state = PushState::DataSending;
            }
            crate::optimize::telemetry::H3_FRAMES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::H3_HEADERS
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn process_push_data(&mut self, conn: &mut super::Connection) {
        const CHUNK: usize = 16 * 1024;
        let mut completed = Vec::new();
        for (stream_id, st) in self.streams.iter_mut() {
            if st._stream_type != StreamType::Push || st.fin_sent {
                continue;
            }
            let total = st.body_buffer.len();
            if st.sent_bytes < total {
                let remaining = total - st.sent_bytes;
                let take = remaining.min(CHUNK);
                let start = st.sent_bytes;
                let end = start + take;
                let mut frame = Vec::new();
                frame.push(0x00); // DATA
                Self::encode_varint(take as u64, &mut frame);
                frame.extend_from_slice(&st.body_buffer[start..end]);
                let fin = end == total;
                if conn.stream_send(*stream_id, &frame, fin).is_ok() {
                    st.sent_bytes += take;
                    st.fin_sent = fin;
                    crate::optimize::telemetry::H3_FRAMES
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::optimize::telemetry::H3_DATA_BYTES
                        .fetch_add(take as u64, std::sync::atomic::Ordering::Relaxed);
                }
            }
            if st.fin_sent {
                completed.push(*stream_id);
            }
        }
        for sid in completed {
            self.finished_streams.insert(sid);
            self.pending_events.push_back((sid, Event::Finished));
            // Mark corresponding push promise as complete
            if let Some(p) = self
                .push_streams
                .values_mut()
                .find(|promise| promise.push_stream_id == Some(sid))
            {
                p.state = PushState::Complete;
            }
        }
    }

    /// **STEALTH FEATURE**: Generate burst of cover traffic push promises
    /// Simulates realistic web page loading with multiple resources
    pub(crate) fn generate_stealth_cover_burst(
        &mut self,
        base_path: &str,
    ) -> Result<Vec<u64>, Error> {
        if !self.is_server
            || self.peer_request_stream_id.is_none()
            || self.peer_max_push_id.is_none()
        {
            return Ok(Vec::new());
        }
        let mut push_ids = Vec::new();
        let plan =
            Self::build_stealth_cover_resource_plan(base_path, crate::transport::rand::rand_u64());
        let available = self
            .peer_max_push_id
            .and_then(|maximum| maximum.checked_sub(self.next_push_id))
            .and_then(|remaining| remaining.checked_add(1))
            .and_then(|remaining| usize::try_from(remaining).ok())
            .unwrap_or(0);

        for (path, content_type, size) in plan.into_iter().take(available) {
            let push_id = self.create_stealth_push_promise(&path, content_type, size)?;
            push_ids.push(push_id);
        }

        Ok(push_ids)
    }

    fn classify_peer_unidirectional_stream(
        &mut self,
        conn: &super::Connection,
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
            0x54 => Ok(StreamType::WebTransportData),
            _ => Ok(StreamType::UnknownUnidirectional),
        }
    }

    fn validate_settings_payload(&self, payload: &[u8]) -> Result<(), Error> {
        let mut offset = 0usize;
        let mut seen = HashSet::new();
        while offset < payload.len() {
            let (setting, setting_len) = Self::decode_varint(&payload[offset..]).map_err(|error| {
                if error == Error::BufferTooShort { Error::SettingsError } else { error }
            })?;
            offset = offset.checked_add(setting_len).ok_or(Error::FrameError)?;
            let (value, value_len) = Self::decode_varint(&payload[offset..]).map_err(|error| {
                if error == Error::BufferTooShort { Error::SettingsError } else { error }
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
                _ => {}
            }
        }
        if offset != payload.len() {
            return Err(Error::FrameError);
        }
        Ok(())
    }

    fn decode_single_varint_payload(payload: &[u8]) -> Result<u64, Error> {
        let (value, used) = Self::decode_varint(payload).map_err(|error| {
            if error == Error::BufferTooShort { Error::FrameError } else { error }
        })?;
        if used != payload.len() {
            return Err(Error::FrameError);
        }
        Ok(value)
    }

    fn validate_frame_placement(
        conn: &super::Connection,
        stream_type: StreamType,
        frame_type: u64,
        settings_received: bool,
        receive_message_state: ReceiveMessageState,
    ) -> Result<(), Error> {
        if matches!(frame_type, 0x02 | 0x06 | 0x08 | 0x09) {
            return Err(Error::FrameUnexpected);
        }
        if frame_type == 0x41 {
            return Err(Error::FrameError);
        }

        let known_frame = matches!(frame_type, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x0d);
        match stream_type {
            StreamType::Control => {
                if !settings_received {
                    return if frame_type == 0x04 {
                        Ok(())
                    } else {
                        Err(Error::FrameUnexpected)
                    };
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
                if (frame_type == 0x00
                    && receive_message_state != ReceiveMessageState::Body)
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
                if (frame_type == 0x00
                    && receive_message_state != ReceiveMessageState::Body)
                    || (frame_type == 0x01
                        && receive_message_state == ReceiveMessageState::Trailers)
                {
                    return Err(Error::FrameUnexpected);
                }
                Ok(())
            }
            StreamType::Unidirectional
            | StreamType::UnknownUnidirectional
            | StreamType::QpackEncoder
            | StreamType::QpackDecoder
            | StreamType::WebTransportData => Err(Error::InternalError),
        }
    }

    fn buffer_raw_stream_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        let session_ready = self.webtransport_session_ids.get(&stream_id).is_some_and(|session_id| {
            self.established_webtransport_sessions.contains(session_id)
        });
        if !data.is_empty() {
            let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
            let buffered_len = stream
                .body_buffer
                .len()
                .checked_add(data.len())
                .ok_or(Error::ExcessiveLoad)?;
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

    fn publish_ready_webtransport_streams(&mut self) {
        let ready: Vec<u64> = self
            .pending_webtransport_streams
            .iter()
            .copied()
            .filter(|stream_id| {
                self.webtransport_session_ids.get(stream_id).is_some_and(|session_id| {
                    self.established_webtransport_sessions.contains(session_id)
                })
            })
            .collect();
        for stream_id in ready {
            self.pending_webtransport_streams.remove(&stream_id);
            if self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| !stream.body_buffer.is_empty())
            {
                self.pending_events.push_back((stream_id, Event::Data));
            }
            if self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.fin_received)
            {
                self.pending_events.push_back((stream_id, Event::Finished));
            }
        }
    }

    fn process_stream(
        &mut self,
        conn: &mut super::Connection,
        stream_id: u64,
        recv_buffer: &mut [u8],
    ) -> Result<(), Error> {
        let (len, fin) =
            conn.stream_recv(stream_id, recv_buffer).map_err(|_| Error::InternalError)?;
        if len == 0 && !fin {
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
            Some(StreamType::QpackEncoder | StreamType::QpackDecoder) => {
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
        if existing_type.is_none() && !is_unidirectional {
            let expected_peer_initiator = if conn.is_server() { 0 } else { 1 };
            if stream_id & 0x01 != expected_peer_initiator || !conn.is_server() {
                return Err(Error::StreamCreationError);
            }
            self.peer_request_stream_id = Some(stream_id);
        }
        self.streams.entry(stream_id).or_insert_with(|| StreamState {
            _headers: Vec::new(),
            body_buffer: Vec::new(),
            frame_buffer: Vec::new(),
            _received_bytes: 0,
            _stream_type: if is_unidirectional {
                StreamType::Unidirectional
            } else {
                StreamType::Request
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
            let buffered_len =
                stream
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
            let classified = self.classify_peer_unidirectional_stream(conn, stream_id, stream_type)?;
            let mut prefix_len = type_len;
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
            } else if stream_type == 0x54 {
                let (session_id, session_id_len) = match Self::decode_varint(&buffered[type_len..]) {
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
                self.webtransport_session_ids.insert(stream_id, session_id);
                prefix_len = prefix_len.checked_add(session_id_len).ok_or(Error::ExcessiveLoad)?;
            }
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream._stream_type = classified;
            }
            buffered.drain(..prefix_len);
            match classified {
                StreamType::UnknownUnidirectional => {
                    if fin {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream.fin_received = true;
                        }
                    }
                    return Ok(());
                }
                StreamType::QpackEncoder | StreamType::QpackDecoder => {
                    return if fin { Err(Error::ClosedCriticalStream) } else { Ok(()) };
                }
                StreamType::WebTransportData => {
                    return self.buffer_raw_stream_data(stream_id, &buffered, fin);
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
            let settings_received = self
                .streams
                .get(&stream_id)
                .is_some_and(|stream| stream.settings_received);
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
                    let headers = self.decoder.decode(frame_data)?;
                    let current_stream_type = self
                        .streams
                        .get(&stream_id)
                        .map(|stream| stream._stream_type)
                        .ok_or(Error::IdError)?;
                    let success_response = Self::masque_response_status(&headers)
                        .is_some_and(|status| (200..300).contains(&status));
                    let masque_response_accepted = current_stream_type == StreamType::Masque
                        && success_response;
                    let webtransport_request = conn.is_server()
                        && current_stream_type == StreamType::Request
                        && Self::is_webtransport_connect(&headers);
                    let webtransport_response_accepted =
                        current_stream_type == StreamType::WebTransportCover && success_response;
                    let informational_response = !conn.is_server()
                        && Self::masque_response_status(&headers)
                            .is_some_and(|status| (100..200).contains(&status));
                    if webtransport_request {
                        if let Some(stream) = self.streams.get_mut(&stream_id) {
                            stream._stream_type = StreamType::WebTransportCover;
                        }
                    }
                    if webtransport_response_accepted {
                        self.established_webtransport_sessions.insert(stream_id);
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
                    self.validate_settings_payload(frame_data)?;
                    if let Some(stream) = self.streams.get_mut(&stream_id) {
                        stream.settings_received = true;
                    }
                }
                0x05 => {
                    let (push_id, push_id_len) =
                        Self::decode_varint(frame_data).map_err(|error| {
                            if error == Error::BufferTooShort { Error::FrameError } else { error }
                        })?;
                    if self.local_max_push_id.is_none_or(|maximum| push_id > maximum) {
                        return Err(Error::IdError);
                    }
                    let headers = self.decoder.decode(&frame_data[push_id_len..])?;
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
            })
            {
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

    /// Parse frame header
    fn parse_frame_header(buf: &[u8]) -> Result<(u64, usize, usize), Error> {
        let (frame_type, type_offset) = Self::decode_varint(buf)?;
        let (frame_len, len_offset) = Self::decode_varint(&buf[type_offset..])?;
        let frame_len = usize::try_from(frame_len).map_err(|_| Error::ExcessiveLoad)?;
        let header_len = type_offset.checked_add(len_offset).ok_or(Error::ExcessiveLoad)?;
        Ok((frame_type, frame_len, header_len))
    }

    /// Encode a QUIC variable-length integer through the canonical transport codec.
    fn encode_varint(val: u64, buf: &mut Vec<u8>) {
        let mut tmp = [0u8; 8];
        if let Ok(used) = qf_transport_pn::varint::write_varint(val, &mut tmp) {
            buf.extend_from_slice(&tmp[..used]);
        }
    }

    /// Decode a QUIC variable-length integer through the canonical transport codec.
    fn decode_varint(buf: &[u8]) -> Result<(u64, usize), Error> {
        qf_transport_pn::varint::read_varint(buf).map_err(|error| match error {
            crate::error::ConnectionError::BufferTooShort => Error::BufferTooShort,
            crate::error::ConnectionError::InvalidPacket => Error::FrameError,
            _ => Error::InternalError,
        })
    }

    /// Decode one MASQUE capsule from a buffer
    fn decode_capsule(buf: &[u8]) -> Result<(u64, usize, Vec<u8>), Error> {
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
    fn decode_masque_capsules(
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
        conn: &mut super::Connection,
        proxy: &str,
        target: &str,
    ) -> Result<u64, Error> {
        self.connect_udp_with_headers(conn, proxy, target, &[])
    }

    /// Establish a MASQUE CONNECT-UDP stream with additional request headers.
    pub fn connect_udp_with_headers(
        &mut self,
        conn: &mut super::Connection,
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

    fn masque_response_status(headers: &[Header]) -> Option<u16> {
        headers.iter().find_map(|header| {
            if !header.name().eq_ignore_ascii_case(b":status") {
                return None;
            }
            std::str::from_utf8(header.value()).ok()?.parse::<u16>().ok()
        })
    }

    fn is_webtransport_connect(headers: &[Header]) -> bool {
        let method_is_connect = headers.iter().any(|header| {
            header.name().eq_ignore_ascii_case(b":method")
                && header.value().eq_ignore_ascii_case(b"CONNECT")
        });
        let protocol_is_webtransport = headers.iter().any(|header| {
            header.name().eq_ignore_ascii_case(b":protocol")
                && header.value().eq_ignore_ascii_case(b"webtransport")
        });
        method_is_connect && protocol_is_webtransport
    }

    /// Open a bounded WebTransport-looking H3 cover session.
    ///
    /// This is cover traffic only. It does not own VPN/TUN payload routing and
    /// deliberately does not compete with the production MASQUE CONNECT-UDP
    /// carrier.
    pub(crate) fn open_webtransport_cover_session(
        &mut self,
        conn: &mut super::Connection,
        authority: &str,
        path: &str,
    ) -> Result<u64, Error> {
        let headers = vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"webtransport"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", authority.as_bytes()),
            Header::new(b":path", path.as_bytes()),
            Header::new(b"origin", format!("https://{authority}").as_bytes()),
        ];
        let sid = self.send_request(conn, &headers, false)?;
        if let Some(st) = self.streams.get_mut(&sid) {
            st._stream_type = StreamType::WebTransportCover;
        }
        Ok(sid)
    }

    /// Enable MASQUE DATAGRAM for a CONNECT-UDP stream; returns Flow-ID (default 0)
    pub fn enable_masque_datagram(
        &mut self,
        conn: &mut super::Connection,
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
        conn: &mut super::Connection,
        stream_id: u64,
    ) -> Result<bool, Error> {
        if self.masque_established(stream_id) {
            return Ok(false);
        }
        if !self.streams.contains_key(&stream_id) {
            return Err(Error::IdError);
        }

        self.enable_masque_datagram(conn, stream_id)?;
        let headers = [
            Header::new(b":status", b"200"),
            Header::new(b"capsule-protocol", b"?1"),
        ];
        self.send_response(conn, stream_id, &headers, false)?;
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::IdError)?;
        stream._stream_type = StreamType::Masque;
        stream.masque_established = true;
        Ok(true)
    }

    /// Send a MASQUE UDP payload via QUIC DATAGRAM using the negotiated Flow-ID
    pub fn send_masque_datagram(
        &mut self,
        conn: &mut super::Connection,
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
        conn: &mut super::Connection,
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
        conn: &mut super::Connection,
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
        conn: &mut super::Connection,
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
        conn: &super::Connection,
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
