use super::*;
use crate::optimize::PooledBlock;
use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(test)]
use super as h3;

mod masque_and_webtransport;
mod masque_classify;
mod receive;

#[cfg(test)]
mod tests;

const STREAM_RECV_BUFFER_SIZE: usize = 64 * 1024;
const MAX_QUIC_DATAGRAM_SIZE: usize = 65_535;
/// Spare writable bytes exposed past a received MASQUE payload so
/// tunnel-ingress normalization can expand TCP option space in place.
/// Bounded by the on-wire TCP data-offset limit (60 - 20 = 40 bytes).
pub(crate) const MASQUE_RECV_HEADROOM: usize = 40;
const MAX_BUFFERED_H3_FRAME: usize = 1024 * 1024 + 16;
const MAX_H3_SETTING_VALUE: u64 = 16 * 1024 * 1024;
const MAX_LOCAL_QPACK_BLOCKED_STREAMS: u64 = 64;
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;
const SETTINGS_WT_ENABLED: u64 = 0x2c7c_f000;
const SETTINGS_WT_INITIAL_MAX_DATA: u64 = 0x2b61;
const SETTINGS_WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
const SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;
const WEBTRANSPORT_STREAM_SIGNAL: u64 = 0x41;
const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;
const MAX_WEBTRANSPORT_SESSIONS: usize = 4;
const MAX_PENDING_WEBTRANSPORT_STREAMS: usize = 16;
const WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI: u64 = 4;
const WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI: u64 = 4;
const WEBTRANSPORT_INITIAL_MAX_DATA: u64 = 1024 * 1024;

/// HTTP/3 connection with enhanced stream state management
pub struct Connection {
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
    qpack_encoder_stream_id: Option<u64>,
    qpack_decoder_stream_id: Option<u64>,
    _peer_control_stream_id: Option<u64>,
    peer_qpack_encoder_stream_id: Option<u64>,
    peer_qpack_decoder_stream_id: Option<u64>,
    peer_request_stream_id: Option<u64>,
    peer_settings: Option<PeerSettings>,
    webtransport_session_ids: HashMap<u64, u64>,
    webtransport_sessions: HashMap<u64, WebTransportSession>,
    pending_webtransport_streams: HashSet<u64>,
    goaway_sent: bool,
    goaway_received: bool,
    peer_goaway_id: Option<u64>,
    /// MASQUE Flow-ID mapping per CONNECT-UDP stream (when datagrams enabled)
    masque_flow: HashMap<u64, u64>,
    /// Reused caller-owned buffer for one transport STREAM receive operation.
    stream_recv_buffer: Vec<u8>,
    /// Owned datagram entry taken from the transport recv queue; its backing
    /// allocation doubles as the in-place normalization region. Returned to
    /// the transport on the next take or on drop.
    masque_recv_entry: Option<crate::transport::connection::DatagramEntry>,
    /// Largest datagram payload accepted for MASQUE dispatch; bigger entries
    /// are dropped instead of truncated.
    masque_recv_capacity: usize,
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
    /// A peer-initiated bidirectional stream whose first varint is incomplete.
    Bidirectional,
    Request,
    Response,
    Control,
    Masque,
    WebTransportCover,
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerSettings {
    maximum_table_capacity: u64,
    blocked_streams: u64,
    enable_connect_protocol: bool,
    h3_datagram: bool,
    webtransport_enabled: bool,
    webtransport_initial_max_data: u64,
    webtransport_initial_max_streams_uni: u64,
    webtransport_initial_max_streams_bidi: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebTransportSessionState {
    Pending,
    Established,
}

#[derive(Debug, Clone, Copy)]
enum WebTransportStreamKind {
    Unidirectional,
    Bidirectional,
}

#[derive(Debug, Clone, Copy)]
struct WebTransportSession {
    state: WebTransportSessionState,
    local_unidirectional_streams: u64,
    local_bidirectional_streams: u64,
    peer_unidirectional_streams: u64,
    peer_bidirectional_streams: u64,
    local_data_bytes: u64,
    peer_data_bytes: u64,
}

impl Connection {
    fn prepare_headers_block(
        &self,
        stream_id: u64,
        headers: &[Header],
    ) -> Result<qpack::EncodePlan, Error> {
        self.encoder.prepare(stream_id, headers)
    }

    /// Creates a new HTTP/3 connection with proper initialization
    pub fn with_transport(
        conn: &mut super::super::Connection,
        config: &Config,
    ) -> Result<Self, Error> {
        // Validate config limits for HTTP/3 compliance and safety.
        // A zero field-section limit is unusable. Every locally advertised setting is bounded
        // before it reaches QPACK state or the wire so an unchecked public setter cannot create
        // target-width truncation or an unbounded peer/runtime contract.
        if config.max_field_section_size() == 0
            || config.max_field_section_size() > MAX_H3_SETTING_VALUE
            || config.qpack_max_table_capacity() > MAX_H3_SETTING_VALUE
            || config.qpack_blocked_streams() > MAX_LOCAL_QPACK_BLOCKED_STREAMS
        {
            return Err(Error::ExcessiveLoad);
        }
        let masque_buffer_len = conn.max_recv_udp_payload_size().clamp(1, MAX_QUIC_DATAGRAM_SIZE);
        let mut h3_conn = Self {
            is_server: conn.is_server(),
            config: config.clone(),
            next_stream_id: if conn.is_server() { 1 } else { 0 },
            next_uni_stream_id: if conn.is_server() { 3 } else { 2 },
            streams: HashMap::new(),
            finished_streams: HashSet::new(),
            pending_events: VecDeque::new(),
            encoder: qpack::Encoder::new(),
            decoder: qpack::Decoder::with_limits(
                config.qpack_max_table_capacity(),
                config.qpack_blocked_streams(),
            ),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            _peer_control_stream_id: None,
            peer_qpack_encoder_stream_id: None,
            peer_qpack_decoder_stream_id: None,
            peer_request_stream_id: None,
            peer_settings: None,
            webtransport_session_ids: HashMap::new(),
            webtransport_sessions: HashMap::new(),
            pending_webtransport_streams: HashSet::new(),
            goaway_sent: false,
            goaway_received: false,
            peer_goaway_id: None,
            masque_flow: HashMap::new(),
            stream_recv_buffer: vec![0u8; STREAM_RECV_BUFFER_SIZE],
            masque_recv_entry: None,
            masque_recv_capacity: masque_buffer_len,
        };

        // Try to emit the mandatory control-stream prologue immediately. A connection can be
        // constructed before peer flow-control limits are available, so a flow-control refusal
        // is deferred to the first operation that can make progress rather than failing setup.
        if config.webtransport_enabled() {
            conn.enable_datagrams(
                WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI as usize,
                WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI as usize,
            );
        }
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
    fn init_control_stream(&mut self, conn: &mut super::super::Connection) -> Result<(), Error> {
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
        if self.config.webtransport_enabled() {
            if self.is_server {
                Self::encode_varint(SETTINGS_ENABLE_CONNECT_PROTOCOL, &mut settings_payload);
                Self::encode_varint(1, &mut settings_payload);
            }
            for (setting, value) in [
                (SETTINGS_H3_DATAGRAM, 1),
                (SETTINGS_WT_ENABLED, 1),
                (SETTINGS_WT_INITIAL_MAX_STREAMS_UNI, WEBTRANSPORT_INITIAL_MAX_STREAMS_UNI),
                (SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, WEBTRANSPORT_INITIAL_MAX_STREAMS_BIDI),
                (SETTINGS_WT_INITIAL_MAX_DATA, WEBTRANSPORT_INITIAL_MAX_DATA),
            ] {
                Self::encode_varint(setting, &mut settings_payload);
                Self::encode_varint(value, &mut settings_payload);
            }
        }

        let mut prologue = Vec::with_capacity(settings_payload.len() + 4);
        Self::encode_varint(0, &mut prologue); // H3 control stream type
        Self::encode_varint(0x04, &mut prologue); // SETTINGS frame type
        Self::encode_varint(settings_payload.len() as u64, &mut prologue);
        prologue.extend_from_slice(&settings_payload);

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

    fn send_qpack_encoder_instructions(
        &mut self,
        conn: &mut super::super::Connection,
        instructions: &[u8],
    ) -> Result<(), Error> {
        if instructions.is_empty() {
            return Ok(());
        }
        if let Some(stream_id) = self.qpack_encoder_stream_id {
            let sent = conn
                .stream_send(stream_id, instructions, false)
                .map_err(|_| Error::StreamCreationError)?;
            if sent != instructions.len() {
                return Err(Error::InternalError);
            }
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.sent_bytes = stream.sent_bytes.saturating_add(sent);
            }
            return Ok(());
        }

        let stream_id = self.next_uni_stream_id;
        let next_stream_id = stream_id.checked_add(4).ok_or(Error::StreamCreationError)?;
        let mut prologue = Vec::with_capacity(instructions.len().saturating_add(1));
        Self::encode_varint(0x02, &mut prologue);
        prologue.extend_from_slice(instructions);
        let sent = conn
            .stream_send(stream_id, &prologue, false)
            .map_err(|_| Error::StreamCreationError)?;
        if sent != prologue.len() {
            return Err(Error::InternalError);
        }
        self.next_uni_stream_id = next_stream_id;
        self.qpack_encoder_stream_id = Some(stream_id);
        self.streams.insert(
            stream_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::QpackEncoder,
                sent_bytes: sent,
                fin_sent: false,
                fin_received: false,
                masque_established: false,
                masque_capsule_buffer: Vec::new(),
                settings_received: false,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        Ok(())
    }

    fn flush_qpack_decoder_instructions(
        &mut self,
        conn: &mut super::super::Connection,
    ) -> Result<(), Error> {
        if self.decoder.pending_decoder_instructions().is_empty() {
            return Ok(());
        }
        let pending = self.decoder.pending_decoder_instructions().to_vec();
        if let Some(stream_id) = self.qpack_decoder_stream_id {
            let sent = match conn.stream_send(stream_id, &pending, false) {
                Ok(sent) => sent,
                Err(crate::error::ConnectionError::FlowControl)
                | Err(crate::error::ConnectionError::StreamLimit) => return Ok(()),
                Err(_) => return Err(Error::InternalError),
            };
            if sent != pending.len() {
                return Err(Error::InternalError);
            }
            self.decoder.consume_decoder_instructions(sent);
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.sent_bytes = stream.sent_bytes.saturating_add(sent);
            }
            return Ok(());
        }

        let stream_id = self.next_uni_stream_id;
        let next_stream_id = stream_id.checked_add(4).ok_or(Error::StreamCreationError)?;
        let mut prologue = Vec::with_capacity(pending.len().saturating_add(1));
        Self::encode_varint(0x03, &mut prologue);
        prologue.extend_from_slice(&pending);
        let sent = match conn.stream_send(stream_id, &prologue, false) {
            Ok(sent) => sent,
            Err(crate::error::ConnectionError::FlowControl)
            | Err(crate::error::ConnectionError::StreamLimit) => return Ok(()),
            Err(_) => return Err(Error::InternalError),
        };
        if sent != prologue.len() {
            return Err(Error::InternalError);
        }
        self.next_uni_stream_id = next_stream_id;
        self.qpack_decoder_stream_id = Some(stream_id);
        self.decoder.consume_decoder_instructions(pending.len());
        self.streams.insert(
            stream_id,
            StreamState {
                _headers: Vec::new(),
                body_buffer: Vec::new(),
                frame_buffer: Vec::new(),
                _received_bytes: 0,
                _stream_type: StreamType::QpackDecoder,
                sent_bytes: sent,
                fin_sent: false,
                fin_received: false,
                masque_established: false,
                masque_capsule_buffer: Vec::new(),
                settings_received: false,
                receive_message_state: ReceiveMessageState::AwaitingHeaders,
            },
        );
        Ok(())
    }

    fn commit_qpack_plan(
        &mut self,
        conn: &mut super::super::Connection,
        plan: qpack::EncodePlan,
    ) -> Result<(Vec<u8>, bool, u64), Error> {
        self.send_qpack_encoder_instructions(conn, &plan.encoder_instructions)?;
        Ok(plan.commit(&mut self.encoder))
    }

    /// Sends an HTTP/3 request with proper frame encoding
    pub fn send_request(
        &mut self,
        conn: &mut super::super::Connection,
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
        let next_stream_id = stream_id.checked_add(4).ok_or(Error::StreamCreationError)?;
        let plan = self.prepare_headers_block(stream_id, headers)?;
        let (encoded, owns_section, section_stream_id) = self.commit_qpack_plan(conn, plan)?;
        let encoded_len = encoded.len();
        // Create HEADERS frame
        let mut frame = Vec::new();
        frame.push(0x01);
        Self::encode_varint(encoded_len as u64, &mut frame);
        frame.extend_from_slice(&encoded[..encoded_len]);
        let sent = match conn.stream_send(stream_id, &frame, fin) {
            Ok(sent) if sent == frame.len() => sent,
            Ok(_) => {
                if owns_section {
                    self.encoder.rollback_latest_section(section_stream_id);
                }
                return Err(Error::InternalError);
            }
            Err(_) => {
                if owns_section {
                    self.encoder.rollback_latest_section(section_stream_id);
                }
                return Err(Error::InternalError);
            }
        };
        self.next_stream_id = next_stream_id;
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

    /// Sends an HTTP/3 response
    pub fn send_response(
        &mut self,
        conn: &mut super::super::Connection,
        stream_id: u64,
        headers: &[Header],
        fin: bool,
    ) -> Result<(), Error> {
        self.init_control_stream(conn)?;
        if self.control_stream_id.is_none() {
            return Err(Error::StreamCreationError);
        }
        let plan = self.prepare_headers_block(stream_id, headers)?;
        let (encoded, owns_section, section_stream_id) = self.commit_qpack_plan(conn, plan)?;
        let mut frame = Vec::with_capacity(encoded.len().saturating_add(10));
        frame.push(0x01);
        Self::encode_varint(encoded.len() as u64, &mut frame);
        frame.extend_from_slice(&encoded);
        let sent = match conn.stream_send(stream_id, &frame, fin) {
            Ok(sent) if sent == frame.len() => sent,
            Ok(_) => {
                if owns_section {
                    self.encoder.rollback_latest_section(section_stream_id);
                }
                return Err(Error::InternalError);
            }
            Err(_) => {
                if owns_section {
                    self.encoder.rollback_latest_section(section_stream_id);
                }
                return Err(Error::InternalError);
            }
        };
        let webtransport_response = {
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
            webtransport_response
        };
        if webtransport_response {
            match Self::masque_response_status(headers) {
                Some(status) if (200..300).contains(&status) => {
                    self.establish_webtransport_session(stream_id)?;
                }
                Some(status) if status >= 200 => self.remove_webtransport_session(stream_id),
                _ => {}
            }
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
        conn: &mut super::super::Connection,
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
            let should_try =
                pol.allows_content_type(ctype.as_deref()) && (ctype.is_some() || looks_text);
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
        // DATA frame = type byte 0x00 + varint payload length, sent vectored so
        // the body never gets copied into a contiguous frame buffer.
        let mut frame_hdr = [0u8; 9];
        frame_hdr[0] = 0x00;
        let hdr_len =
            1 + qf_transport_pn::varint::write_varint(to_send.len() as u64, &mut frame_hdr[1..])
                .map_err(|_| Error::InternalError)?;
        let parts: [&[u8]; 2] = [&frame_hdr[..hdr_len], to_send];
        let sent =
            conn.stream_send_parts(stream_id, &parts, fin).map_err(|_| Error::InternalError)?;
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
        _conn: &mut super::super::Connection,
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
    pub fn poll(
        &mut self,
        conn: &mut super::super::Connection,
    ) -> Result<Option<(u64, Event)>, Error> {
        self.init_control_stream(conn)?;
        self.process_peer_stream_resets(conn)?;
        self.flush_qpack_decoder_instructions(conn)?;

        // Process incoming readable streams (requests, responses, MASQUE, etc).
        // The transport marks streams readable when STREAM frames deliver data.
        while let Some(stream_id) = conn.stream_readable_next() {
            let mut recv_buffer = std::mem::take(&mut self.stream_recv_buffer);
            let result = self.process_stream(conn, stream_id, &mut recv_buffer);
            self.stream_recv_buffer = recv_buffer;
            result?;
        }
        loop {
            let ready = self.decoder.take_unblocked_streams();
            if ready.is_empty() {
                break;
            }
            for stream_id in ready {
                let mut recv_buffer = std::mem::take(&mut self.stream_recv_buffer);
                let result = self.process_stream(conn, stream_id, &mut recv_buffer);
                self.stream_recv_buffer = recv_buffer;
                result?;
            }
        }
        self.flush_qpack_decoder_instructions(conn)?;
        self.publish_ready_webtransport_streams();

        // Lightweight GC using fin_received.
        let done: Vec<u64> = self
            .streams
            .iter()
            .filter_map(|(id, st)| {
                let pending_event = self.pending_events.iter().any(|(event_id, _)| event_id == id);
                if st.fin_received
                    && st.body_buffer.is_empty()
                    && !pending_event
                    && !self.pending_webtransport_streams.contains(id)
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
            if self.webtransport_sessions.contains_key(&id) {
                self.remove_webtransport_session(id);
            } else {
                self.webtransport_session_ids.remove(&id);
                self.pending_webtransport_streams.remove(&id);
            }
            if self.peer_request_stream_id == Some(id) {
                self.peer_request_stream_id = None;
            }
        }
        self.pending_events.pop_front().map(Some).ok_or(Error::Done)
    }
}
