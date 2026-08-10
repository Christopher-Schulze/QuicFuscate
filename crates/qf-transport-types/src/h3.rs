//! Root-independent HTTP/3 value contracts shared by transport and stealth.

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
    use super::{Config, Event, Header};

    #[test]
    fn config_contract_preserves_defaults_and_mutations() {
        let mut config = Config::new().expect("H3 config");
        assert_eq!(config.qpack_max_table_capacity(), 0);
        assert_eq!(config.qpack_blocked_streams(), 0);
        assert_eq!(config.max_field_section_size(), 1024 * 1024);

        config.set_qpack_max_table_capacity(4096);
        config.set_qpack_blocked_streams(32);
        config.set_max_field_section_size(2 * 1024 * 1024);
        assert_eq!(config.qpack_max_table_capacity(), 4096);
        assert_eq!(config.qpack_blocked_streams(), 32);
        assert_eq!(config.max_field_section_size(), 2 * 1024 * 1024);
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
