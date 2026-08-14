//! Root-independent HTTP/3 value contracts shared by transport and stealth.

use super::TransportError;

/// Semantic owner of one authenticated HTTP Datagram flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueFlowPurpose {
    /// Raw IPv4 or IPv6 packets for the final TUN data plane.
    TunIp,
    /// Opaque UDP datagrams carrying the next hop's QUIC connection.
    NextHopUdp,
    /// Bounded circuit control messages.
    Control,
}

impl MasqueFlowPurpose {
    /// Stable request-header value used inside the authenticated H3 connection.
    pub fn as_header_value(self) -> &'static [u8] {
        match self {
            Self::TunIp => b"tun-ip",
            Self::NextHopUdp => b"next-hop-udp",
            Self::Control => b"control",
        }
    }

    /// Parse the unique authenticated request-header value.
    pub fn from_header_value(value: &[u8]) -> Option<Self> {
        if value.eq_ignore_ascii_case(b"tun-ip") {
            Some(Self::TunIp)
        } else if value.eq_ignore_ascii_case(b"next-hop-udp") {
            Some(Self::NextHopUdp)
        } else if value.eq_ignore_ascii_case(b"control") {
            Some(Self::Control)
        } else {
            None
        }
    }
}

/// Strict RFC 9298 CONNECT-UDP target authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueUdpTarget {
    host: String,
    port: u16,
}

impl MasqueUdpTarget {
    /// Parse `host:port` or `[ipv6]:port` without DNS resolution.
    pub fn parse_authority(authority: &str) -> Result<Self, Error> {
        let authority = authority.trim();
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let close = rest.find(']').ok_or(Error::FrameUnexpected)?;
            let host = &rest[..close];
            let port = rest[close + 1..].strip_prefix(':').ok_or(Error::FrameUnexpected)?;
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(Error::FrameUnexpected);
            }
            (host, port)
        } else {
            let (host, port) = authority.rsplit_once(':').ok_or(Error::FrameUnexpected)?;
            if host.contains(':') || !valid_target_host(host) {
                return Err(Error::FrameUnexpected);
            }
            (host, port)
        };
        let port =
            port.parse::<u16>().ok().filter(|port| *port != 0).ok_or(Error::FrameUnexpected)?;
        Ok(Self { host: host.to_ascii_lowercase(), port })
    }

    /// Parse the RFC 9298 URI-template path without accepting extra segments.
    pub fn parse_connect_udp_path(path: &[u8]) -> Result<Self, Error> {
        const PREFIX: &[u8] = b"/.well-known/masque/udp/";
        let suffix = path.strip_prefix(PREFIX).ok_or(Error::FrameUnexpected)?;
        let suffix = suffix.strip_suffix(b"/").ok_or(Error::FrameUnexpected)?;
        let mut segments = suffix.split(|byte| *byte == b'/');
        let host = decode_uri_segment(segments.next().ok_or(Error::FrameUnexpected)?)?;
        let port = decode_uri_segment(segments.next().ok_or(Error::FrameUnexpected)?)?;
        if segments.next().is_some() {
            return Err(Error::FrameUnexpected);
        }
        let authority =
            if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
        Self::parse_authority(&authority)
    }

    /// Encode the exact RFC 9298 URI-template path.
    pub fn connect_udp_path(&self) -> String {
        format!("/.well-known/masque/udp/{}/{}/", encode_uri_segment(&self.host), self.port)
    }

    /// Hostname or IP literal without IPv6 brackets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// UDP destination port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Canonical authority, adding brackets only for IPv6.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn valid_target_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    host.trim_end_matches('.').split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn encode_uri_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

fn decode_uri_segment(value: &[u8]) -> Result<String, Error> {
    if value.is_empty() {
        return Err(Error::FrameUnexpected);
    }
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        let pair = value.get(index + 1..index + 3).ok_or(Error::FrameUnexpected)?;
        let high = hex_nibble(pair[0]).ok_or(Error::FrameUnexpected)?;
        let low = hex_nibble(pair[1]).ok_or(Error::FrameUnexpected)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).map_err(|_| Error::FrameUnexpected)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// HTTP/3 operation and protocol errors exposed by the connection boundary.
#[derive(Debug, Clone, PartialEq)]
#[doc(hidden)]
pub enum Error {
    Done,
    BufferTooShort,
    InternalError,
    /// The underlying QUIC DATAGRAM send queue is at capacity; the caller
    /// should apply backpressure and retry rather than fall back to framed H3.
    DgramQueueFull,
    ExcessiveLoad,
    IdError,
    StreamCreationError,
    ClosedCriticalStream,
    FrameUnexpected,
    FrameError,
    SettingsError,
    QpackDecompressionFailed,
    QpackEncoderStreamError,
    QpackDecoderStreamError,
    TransportError(TransportError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for Error {}

impl From<TransportError> for Error {
    fn from(error: TransportError) -> Self {
        Self::TransportError(error)
    }
}

impl From<Error> for qf_error::ConnectionError {
    fn from(error: Error) -> Self {
        match error {
            Error::Done => Self::Done,
            other => Self::Transport(format!("H3 error: {other:?}")),
        }
    }
}

/// HTTP/3 application protocols supported by the transport boundary.
#[doc(hidden)]
pub const APPLICATION_PROTOCOL: &[&[u8]] = &[b"h3", b"h3-29", b"h3-28", b"h3-27"];

/// HTTP/3 header name/value pair.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Header {
    /// Create a header by copying borrowed name and value bytes.
    #[inline]
    #[doc(hidden)]
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        Self { name: name.to_vec(), value: value.to_vec() }
    }

    /// Build a header from owned vectors without another allocation.
    #[inline]
    #[doc(hidden)]
    pub fn from_parts(name: Vec<u8>, value: Vec<u8>) -> Self {
        Self { name, value }
    }

    /// Return the header name bytes.
    #[inline]
    #[doc(hidden)]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Return the header value bytes.
    #[inline]
    #[doc(hidden)]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Return a mutable header name for feature-gated transport regressions.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn name_mut(&mut self) -> &mut [u8] {
        &mut self.name
    }

    /// Return a mutable header value for feature-gated transport regressions.
    #[cfg(any(test, feature = "rust-tests"))]
    #[doc(hidden)]
    pub fn value_mut(&mut self) -> &mut [u8] {
        &mut self.value
    }
}

/// HTTP/3 connection settings carried by the transport-owned H3 boundary.
#[derive(Clone)]
#[doc(hidden)]
pub struct Config {
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    max_field_section_size: u64,
    webtransport_enabled: bool,
}

impl Config {
    /// Create a configuration with the safe default H3 settings.
    pub fn new() -> Result<Self, qf_error::ConnectionError> {
        Ok(Self {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            // 1MiB is a common safe default for max header section size.
            // The connection owner applies the protocol safety ceiling.
            max_field_section_size: 1024 * 1024,
            webtransport_enabled: false,
        })
    }

    /// Set the QPACK dynamic table capacity used by the H3 connection.
    #[doc(hidden)]
    pub fn set_qpack_max_table_capacity(&mut self, value: u64) {
        self.qpack_max_table_capacity = value;
    }

    /// Set the maximum number of blocked QPACK streams.
    #[doc(hidden)]
    pub fn set_qpack_blocked_streams(&mut self, value: u64) {
        self.qpack_blocked_streams = value;
    }

    /// Set the maximum H3 field-section size.
    #[doc(hidden)]
    pub fn set_max_field_section_size(&mut self, value: u64) {
        self.max_field_section_size = value;
    }

    /// Enable the bounded WebTransport cover profile on this H3 connection.
    #[doc(hidden)]
    pub fn set_webtransport_enabled(&mut self, enabled: bool) {
        self.webtransport_enabled = enabled;
    }

    /// Return the configured QPACK dynamic table capacity.
    #[inline]
    #[doc(hidden)]
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// Return the configured maximum number of blocked QPACK streams.
    #[inline]
    #[doc(hidden)]
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.qpack_blocked_streams
    }

    /// Return the configured maximum H3 field-section size.
    #[inline]
    #[doc(hidden)]
    pub fn max_field_section_size(&self) -> u64 {
        self.max_field_section_size
    }

    /// Return whether the bounded WebTransport cover profile is enabled.
    #[inline]
    #[doc(hidden)]
    pub fn webtransport_enabled(&self) -> bool {
        self.webtransport_enabled
    }
}

/// Test-only header accessor retained at the historical HTTP/3 boundary.
#[cfg(any(test, feature = "rust-tests"))]
#[doc(hidden)]
pub trait NameValue {
    fn name(&self) -> &[u8];
    fn value(&self) -> &[u8];
}

#[cfg(any(test, feature = "rust-tests"))]
impl NameValue for Header {
    fn name(&self) -> &[u8] {
        self.name()
    }

    fn value(&self) -> &[u8] {
        self.value()
    }
}

/// HTTP/3 events emitted by the connection state machine.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum Event {
    Headers {
        list: Vec<Header>,
        has_body: bool,
    },
    Data,
    /// MASQUE capsule received on a CONNECT-UDP stream.
    MasqueCapsule {
        capsule_type: u64,
        payload: Vec<u8>,
    },
    Finished,
    /// Server Push Promise event for stealth cover traffic.
    PushPromise {
        push_id: u64,
        headers: Vec<Header>,
    },
    Reset(u64),
    PriorityUpdate,
    GoAway,
}

#[cfg(test)]
mod tests {
    use super::{
        Config, Error, Event, Header, MasqueFlowPurpose, MasqueUdpTarget, APPLICATION_PROTOCOL,
    };
    use crate::TransportError;

    #[test]
    fn config_contract_preserves_defaults_and_mutations() {
        let mut config = Config::new().expect("H3 config");
        assert_eq!(config.qpack_max_table_capacity(), 0);
        assert_eq!(config.qpack_blocked_streams(), 0);
        assert_eq!(config.max_field_section_size(), 1024 * 1024);
        assert!(!config.webtransport_enabled());

        config.set_qpack_max_table_capacity(4096);
        config.set_qpack_blocked_streams(32);
        config.set_max_field_section_size(2 * 1024 * 1024);
        config.set_webtransport_enabled(true);
        assert_eq!(config.qpack_max_table_capacity(), 4096);
        assert_eq!(config.qpack_blocked_streams(), 32);
        assert_eq!(config.max_field_section_size(), 2 * 1024 * 1024);
        assert!(config.webtransport_enabled());
    }

    #[test]
    fn header_contract_preserves_owned_bytes() {
        let header = Header::new(b"x-name", b"value");
        assert_eq!(header.name(), b"x-name");
        assert_eq!(header.value(), b"value");

        let owned = Header::from_parts(b"owned".to_vec(), b"bytes".to_vec());
        assert_eq!(owned.name(), b"owned");
        assert_eq!(owned.value(), b"bytes");
    }

    #[test]
    fn masque_target_codec_roundtrips_hostname_ipv4_and_ipv6() {
        for (authority, path) in [
            ("relay.example.com:4433", "/.well-known/masque/udp/relay.example.com/4433/"),
            ("203.0.113.4:53", "/.well-known/masque/udp/203.0.113.4/53/"),
            ("[2001:db8::4]:4433", "/.well-known/masque/udp/2001%3Adb8%3A%3A4/4433/"),
        ] {
            let target = MasqueUdpTarget::parse_authority(authority).expect("target authority");
            assert_eq!(target.connect_udp_path(), path);
            assert_eq!(
                MasqueUdpTarget::parse_connect_udp_path(path.as_bytes()).expect("target path"),
                target
            );
            assert_eq!(target.authority(), authority.to_ascii_lowercase());
        }
    }

    #[test]
    fn masque_target_codec_rejects_ambiguous_or_malformed_input() {
        for authority in ["", "relay.example.com", "relay.example.com:0", "2001:db8::1:4433"] {
            assert!(MasqueUdpTarget::parse_authority(authority).is_err(), "{authority}");
        }
        for path in [
            b"/.well-known/masque/udp/host/4433".as_slice(),
            b"/.well-known/masque/udp/host/4433/extra/".as_slice(),
            b"/.well-known/masque/udp/host/%GG/".as_slice(),
        ] {
            assert!(MasqueUdpTarget::parse_connect_udp_path(path).is_err());
        }
    }

    #[test]
    fn masque_flow_purpose_header_values_are_exact() {
        for purpose in
            [MasqueFlowPurpose::TunIp, MasqueFlowPurpose::NextHopUdp, MasqueFlowPurpose::Control]
        {
            assert_eq!(
                MasqueFlowPurpose::from_header_value(purpose.as_header_value()),
                Some(purpose)
            );
        }
        assert_eq!(MasqueFlowPurpose::from_header_value(b"unknown"), None);
    }

    #[test]
    fn event_contract_keeps_header_payloads_and_variants() {
        let event = Event::Headers { list: vec![Header::new(b":status", b"200")], has_body: false };
        assert!(
            matches!(event, Event::Headers { list, has_body: false } if list[0].value() == b"200")
        );

        let capsule = Event::MasqueCapsule { capsule_type: 0x22, payload: vec![1, 2, 3] };
        assert!(
            matches!(capsule, Event::MasqueCapsule { capsule_type: 0x22, payload } if payload == [1, 2, 3])
        );
    }

    #[test]
    fn error_and_application_protocol_contracts_preserve_root_behavior() {
        let transport_error = Error::from(TransportError::BufferTooShort);
        assert!(matches!(transport_error, Error::TransportError(TransportError::BufferTooShort)));
        assert!(!transport_error.to_string().is_empty());

        let done: qf_error::ConnectionError = Error::Done.into();
        assert_eq!(done, qf_error::ConnectionError::Done);
        let other: qf_error::ConnectionError = Error::IdError.into();
        assert!(matches!(
            other,
            qf_error::ConnectionError::Transport(message) if message == "H3 error: IdError"
        ));
        assert_eq!(APPLICATION_PROTOCOL.len(), 4);
        assert_eq!(APPLICATION_PROTOCOL[0], b"h3");
        assert_eq!(APPLICATION_PROTOCOL[1], b"h3-29");
        assert_eq!(APPLICATION_PROTOCOL[2], b"h3-28");
        assert_eq!(APPLICATION_PROTOCOL[3], b"h3-27");
    }

    #[cfg(feature = "rust-tests")]
    #[test]
    fn feature_gate_keeps_mutable_header_accessors() {
        let mut header = Header::new(b"name", b"value");
        header.name_mut()[0] = b'N';
        header.value_mut()[0] = b'V';
        assert_eq!(header.name(), b"Name");
        assert_eq!(header.value(), b"Value");
    }
}
