//! Browser transport-parameter fixtures (TODO-1047).
//!
//! `fixtures/transport_params.toml` is the single source for the QUIC
//! transport-parameter block emitted in Initial and for the flow-control
//! values applied to the internal transport configuration. Loading happens
//! once at first use; a corrupt fixture is a build-time bug and fails loudly.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

use crate::profiles::BrowserProfile;

/// Browser engine family a transport-parameter fixture describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFamily {
    /// Chromium QUIC stack (Chrome, Edge).
    Chromium,
    /// Firefox/neqo QUIC stack.
    Firefox,
    /// WebKit QUIC stack (Safari).
    WebKit,
}

impl EngineFamily {
    /// Maps a browser persona to its engine fixture.
    pub fn from_browser(browser: BrowserProfile) -> Self {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => Self::Chromium,
            BrowserProfile::Firefox => Self::Firefox,
            BrowserProfile::Safari => Self::WebKit,
        }
    }
}

/// Handshake connection IDs authenticated by the TLS transport-parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeConnectionIds {
    Client { initial_source: Vec<u8> },
    Server { initial_source: Vec<u8>, original_destination: Vec<u8>, retry_source: Option<Vec<u8>> },
}

impl HandshakeConnectionIds {
    pub fn client(initial_source: &[u8]) -> Self {
        Self::Client { initial_source: initial_source.to_vec() }
    }

    pub fn server(
        initial_source: &[u8],
        original_destination: &[u8],
        retry_source: Option<&[u8]>,
    ) -> Self {
        Self::Server {
            initial_source: initial_source.to_vec(),
            original_destination: original_destination.to_vec(),
            retry_source: retry_source.map(<[u8]>::to_vec),
        }
    }

    pub fn initial_source(&self) -> &[u8] {
        match self {
            Self::Client { initial_source } | Self::Server { initial_source, .. } => initial_source,
        }
    }
}

/// Flow-control values shared between the wire fixture and the runtime
/// transport configuration. Applying the same struct to both paths makes a
/// drift between advertised and internal parameters impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportParamValues {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct FixtureFile {
    #[allow(dead_code)]
    snapshot: String,
    chrome: FixtureEntry,
    firefox: FixtureEntry,
    safari: FixtureEntry,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FixtureEntry {
    provenance: String,
    captured_at: String,
    browser_version: String,
    source: String,
    randomize_order: bool,
    #[serde(default)]
    grease_tp: bool,
    #[serde(default)]
    grease_value_len: usize,
    #[serde(default)]
    version_information: bool,
    #[serde(default)]
    initial_source_connection_id_len: Option<u64>,
    #[serde(flatten)]
    values: BTreeMap<String, toml::Value>,
    sends: Vec<String>,
    absent: Vec<String>,
    notes: Option<String>,
    #[serde(default)]
    cipher_suites: Vec<String>,
    #[serde(default)]
    supported_groups: Vec<String>,
    #[serde(default)]
    key_share_groups: Vec<String>,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    signature_algorithms: Vec<String>,
    #[serde(default)]
    extension_order: Vec<String>,
}

/// Parsed fixture for one engine family.
#[derive(Debug)]
pub struct TransportParamFixture {
    provenance: String,
    captured_at: String,
    browser_version: String,
    source: String,
    randomize_order: bool,
    grease_tp: bool,
    grease_value_len: usize,
    version_information: bool,
    values: BTreeMap<String, u64>,
    google_connection_options: Option<Vec<u8>>,
    sends: Vec<String>,
    absent: Vec<String>,
    notes: Option<String>,
    cipher_suites: Vec<u16>,
    supported_groups: Vec<u16>,
    key_share_groups: Vec<u16>,
    alpn: Vec<String>,
    signature_algorithms: Vec<u16>,
    extension_order: Option<Vec<u16>>,
}

impl TransportParamFixture {
    /// How the fixture values were established.
    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    /// Date the fixture was captured or sourced (`YYYY-MM-DD`).
    pub fn captured_at(&self) -> &str {
        &self.captured_at
    }

    /// Browser version the fixture describes.
    pub fn browser_version(&self) -> &str {
        &self.browser_version
    }

    /// Documented source of the values.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Free-form provenance notes, if present.
    pub fn notes(&self) -> Option<&str> {
        self.notes.as_deref()
    }

    /// Captured ClientHello cipher-suite list and order.
    pub fn cipher_suites(&self) -> &[u16] {
        &self.cipher_suites
    }

    /// Captured supported-groups list and order. The provider intersects
    /// this with groups rustls can mint key shares for.
    pub fn supported_groups(&self) -> &[u16] {
        &self.supported_groups
    }

    /// Captured key-share groups (which groups carried real shares).
    pub fn key_share_groups(&self) -> &[u16] {
        &self.key_share_groups
    }

    /// Captured ALPN protocol list.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }

    /// Captured signature-algorithm list and order.
    pub fn signature_algorithms(&self) -> &[u16] {
        &self.signature_algorithms
    }

    /// Captured ClientHello extension order, when the fixture recorded one.
    /// Documentary only: rustls emits its own fixed extension order.
    pub fn extension_order(&self) -> Option<&[u16]> {
        self.extension_order.as_deref()
    }

    /// Numeric parameter values keyed by transport-parameter name.
    pub fn values(&self) -> &BTreeMap<String, u64> {
        &self.values
    }

    /// Parameter names the engine advertises, in canonical order.
    pub fn sends(&self) -> &[String] {
        &self.sends
    }

    /// Parameter names the engine does not advertise.
    pub fn absent(&self) -> &[String] {
        &self.absent
    }

    /// Whether the engine permutes parameter order per connection.
    pub fn randomizes_order(&self) -> bool {
        self.randomize_order
    }

    /// Whether the engine inserts a GREASE transport parameter.
    pub fn sends_grease_tp(&self) -> bool {
        self.grease_tp
    }

    /// Flow-control values shared by wire emission and internal config.
    pub fn flow_control(&self) -> TransportParamValues {
        let get = |name: &str| -> u64 {
            self.values
                .get(name)
                .copied()
                .unwrap_or_else(|| panic!("transport fixture missing required value '{name}'"))
        };
        TransportParamValues {
            initial_max_data: get("initial_max_data"),
            initial_max_stream_data_bidi_local: get("initial_max_stream_data_bidi_local"),
            initial_max_stream_data_bidi_remote: get("initial_max_stream_data_bidi_remote"),
            initial_max_stream_data_uni: get("initial_max_stream_data_uni"),
            initial_max_streams_bidi: get("initial_max_streams_bidi"),
            initial_max_streams_uni: get("initial_max_streams_uni"),
            max_idle_timeout_ms: get("max_idle_timeout"),
        }
    }
}

/// Wire identifier of each transport parameter we can encode.
fn tp_wire_id(name: &str) -> Option<u64> {
    Some(match name {
        "max_idle_timeout" => 0x01,
        "max_udp_payload_size" => 0x03,
        "initial_max_data" => 0x04,
        "initial_max_stream_data_bidi_local" => 0x05,
        "initial_max_stream_data_bidi_remote" => 0x06,
        "initial_max_stream_data_uni" => 0x07,
        "initial_max_streams_bidi" => 0x08,
        "initial_max_streams_uni" => 0x09,
        "ack_delay_exponent" => 0x0a,
        "max_ack_delay" => 0x0b,
        "disable_active_migration" => 0x0c,
        "active_connection_id_limit" => 0x0e,
        "initial_source_connection_id" => 0x0f,
        "version_information" => 0x11,
        "reset_stream_at" => 0x1d,
        "max_datagram_frame_size" => 0x20,
        "grease_quic_bit" => 0x2ab2,
        "google_connection_options" => 0x3128,
        "min_ack_delay" => 0xff02_de1a,
        _ => return None,
    })
}

/// RFC 9000 section 16 variable-length integer encoding.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn put_param(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    put_varint(out, id);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// Reserved GREASE transport-parameter identifier space (RFC 9000 section
/// 18.1): identifiers of the form `31 * N + 27`.
fn grease_tp_id(random: u64) -> u64 {
    31 * (random % ((1u64 << 57) - 1)) + 27
}

/// RFC 9000 section 16 variable-length integer decoding.
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &byte in &buf[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

/// Strips the parameter framing (`id` + `length`) from a fully encoded
/// transport parameter, returning its value bytes.
fn framed_param_value(encoded: &[u8]) -> Option<&[u8]> {
    let (_id, id_len) = read_varint(encoded)?;
    let (len, len_len) = read_varint(&encoded[id_len..])?;
    let start = id_len + len_len;
    if encoded.len() != start + len as usize {
        return None;
    }
    Some(&encoded[start..])
}

/// Loads the fixture table for an engine family. The fixture is embedded at
/// compile time; a parse failure indicates repository corruption.
pub fn transport_param_fixture(family: EngineFamily) -> &'static TransportParamFixture {
    static PARSED: OnceLock<BTreeMap<u8, TransportParamFixture>> = OnceLock::new();

    let parsed = PARSED.get_or_init(|| {
        let raw: FixtureFile = toml::from_str(include_str!("../fixtures/transport_params.toml"))
            .expect("embedded transport_params.toml must parse");
        let mut map = BTreeMap::new();
        map.insert(0u8, convert_entry(raw.chrome));
        map.insert(1u8, convert_entry(raw.firefox));
        map.insert(2u8, convert_entry(raw.safari));
        map
    });

    let key = match family {
        EngineFamily::Chromium => 0u8,
        EngineFamily::Firefox => 1u8,
        EngineFamily::WebKit => 2u8,
    };
    &parsed[&key]
}

fn parse_hex_list(raw: &[String]) -> Vec<u16> {
    raw.iter()
        .map(|item| {
            u16::from_str_radix(item.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("fixture hex value '{item}' must parse"))
        })
        .collect()
}

fn convert_entry(entry: FixtureEntry) -> TransportParamFixture {
    let cipher_suites = parse_hex_list(&entry.cipher_suites);
    let supported_groups = parse_hex_list(&entry.supported_groups);
    let key_share_groups = parse_hex_list(&entry.key_share_groups);
    let signature_algorithms = parse_hex_list(&entry.signature_algorithms);
    let extension_order = if entry.extension_order.is_empty() {
        None
    } else {
        Some(parse_hex_list(&entry.extension_order))
    };
    let mut values = BTreeMap::new();
    let mut google_connection_options = None;
    for (name, raw) in entry.values {
        match name.as_str() {
            "google_connection_options" => {
                if let toml::Value::String(text) = raw {
                    google_connection_options = Some(text.into_bytes());
                }
            }
            _ => {
                if let toml::Value::Integer(number) = raw {
                    values.insert(name, number as u64);
                }
            }
        }
    }
    TransportParamFixture {
        provenance: entry.provenance,
        captured_at: entry.captured_at,
        browser_version: entry.browser_version,
        source: entry.source,
        randomize_order: entry.randomize_order,
        grease_tp: entry.grease_tp,
        grease_value_len: entry.grease_value_len,
        version_information: entry.version_information,
        values,
        google_connection_options,
        sends: entry.sends,
        absent: entry.absent,
        notes: entry.notes,
        cipher_suites,
        supported_groups,
        key_share_groups,
        alpn: entry.alpn,
        signature_algorithms,
        extension_order,
    }
}

/// Encodes the fixture-driven transport-parameter block for one connection.
///
/// * `path_max_udp_payload` is the concrete MTU/path budget of this hop; when
///   the fixture advertises `max_udp_payload_size`, the emitted value is the
///   minimum of both caps.
/// * `connection_ids` supplies mandatory role-specific CIDs from the actual
///   handshake, independently of persona fixture membership.
/// * `version_information` carries the already-encoded version_information
///   parameter (parameter id + length + value) and is appended when the
///   fixture advertises it.
/// * `random` supplies per-connection entropy for GREASE and ordering.
///
/// Returns the wire-format parameter block (without the outer extension
/// framing).
pub fn encode_transport_params(
    family: EngineFamily,
    path_max_udp_payload: u64,
    connection_ids: &HandshakeConnectionIds,
    version_information: &[u8],
    random: &mut dyn rand::RngCore,
) -> Vec<u8> {
    let fixture = transport_param_fixture(family);
    let mut entries: Vec<(u64, Vec<u8>)> = Vec::with_capacity(fixture.sends.len() + 3);
    let mut initial_source_emitted = false;

    let version_information_value =
        if fixture.version_information && !version_information.is_empty() {
            Some(
                framed_param_value(version_information)
                    .expect("version_information parameter must be fully framed")
                    .to_vec(),
            )
        } else {
            None
        };

    for name in &fixture.sends {
        match name.as_str() {
            "initial_source_connection_id" => {
                entries.push((0x0f, connection_ids.initial_source().to_vec()));
                initial_source_emitted = true;
            }
            "version_information" => {
                if let Some(value) = &version_information_value {
                    entries.push((0x11, value.clone()));
                }
            }
            "grease_quic_bit" | "reset_stream_at" | "disable_active_migration" => {
                let id = tp_wire_id(name).expect("known empty parameter");
                entries.push((id, Vec::new()));
            }
            "google_connection_options" => {
                let value = fixture
                    .google_connection_options
                    .clone()
                    .expect("fixture lists google_connection_options in sends but has no value");
                entries.push((0x3128, value));
            }
            "max_udp_payload_size" => {
                let fixture_cap = fixture.values["max_udp_payload_size"];
                let advertised = fixture_cap.min(path_max_udp_payload);
                let mut encoded = Vec::new();
                put_varint(&mut encoded, advertised);
                entries.push((0x03, encoded));
            }
            other => {
                let id = tp_wire_id(other).unwrap_or_else(|| {
                    panic!("fixture sends unknown transport parameter '{other}'")
                });
                let value = fixture
                    .values
                    .get(other)
                    .copied()
                    .unwrap_or_else(|| panic!("fixture sends '{other}' but has no value"));
                let mut encoded = Vec::new();
                put_varint(&mut encoded, value);
                entries.push((id, encoded));
            }
        }
    }

    if !initial_source_emitted {
        entries.push((0x0f, connection_ids.initial_source().to_vec()));
    }
    if let HandshakeConnectionIds::Server { original_destination, retry_source, .. } =
        connection_ids
    {
        entries.push((0x00, original_destination.clone()));
        if let Some(retry_source) = retry_source {
            entries.push((0x10, retry_source.clone()));
        }
    }

    // Per-connection GREASE transport parameter at a random position, when
    // the engine emits one.
    if fixture.grease_tp {
        let mut draw = [0u8; 8];
        random.fill_bytes(&mut draw);
        let id = grease_tp_id(u64::from_be_bytes(draw));
        let mut value = vec![0u8; fixture.grease_value_len];
        random.fill_bytes(&mut value);
        let position = (draw[0] as usize) % (entries.len() + 1);
        entries.insert(position, (id, value));
    }

    // Chrome permutes the parameter order per connection (Fisher-Yates).
    if fixture.randomize_order && entries.len() > 1 {
        for i in (1..entries.len()).rev() {
            let mut draw = [0u8; 8];
            random.fill_bytes(&mut draw);
            let j = (u64::from_be_bytes(draw) as usize) % (i + 1);
            entries.swap(i, j);
        }
    }

    let mut out = Vec::with_capacity(
        entries.len() * 8 + connection_ids.initial_source().len() + version_information.len(),
    );
    for (id, value) in entries {
        put_param(&mut out, id, &value);
    }
    out
}

/// Decodes a wire-format transport-parameter block into `(id, value)` pairs
/// in wire order. Used by tests to compare emitted blocks against fixtures.
pub fn decode_transport_params(encoded: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = encoded;
    while !rest.is_empty() {
        let (id, id_len) = read_varint(rest).expect("transport parameter id must decode");
        let (len, len_len) =
            read_varint(&rest[id_len..]).expect("transport parameter length must decode");
        let value_start = id_len + len_len;
        let value_end = value_start + len as usize;
        assert!(value_end <= rest.len(), "transport parameter value exceeds block");
        out.push((id, rest[value_start..value_end].to_vec()));
        rest = &rest[value_end..];
    }
    out
}

/// Applies the fixture flow-control values to a fingerprint profile. Called
/// during profile construction so every persona carries the fixture numbers.
pub fn apply_to_fingerprint(profile: &mut crate::fingerprint_profile::FingerprintProfile) {
    let values =
        transport_param_fixture(EngineFamily::from_browser(profile.browser)).flow_control();
    profile.initial_max_data = values.initial_max_data;
    profile.initial_max_stream_data_bidi_local = values.initial_max_stream_data_bidi_local;
    profile.initial_max_stream_data_bidi_remote = values.initial_max_stream_data_bidi_remote;
    profile.initial_max_stream_data_uni = values.initial_max_stream_data_uni;
    profile.initial_max_streams_bidi = values.initial_max_streams_bidi;
    profile.initial_max_streams_uni = values.initial_max_streams_uni;
    profile.max_idle_timeout = values.max_idle_timeout_ms;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profiles::OsProfile;

    #[test]
    fn fixtures_parse_and_carry_provenance() {
        let chrome = transport_param_fixture(EngineFamily::Chromium);
        assert_eq!(chrome.provenance(), "wire-capture");
        assert_eq!(chrome.browser_version(), "Google Chrome 154.0.8037.44");
        assert!(chrome.randomizes_order());
        assert!(chrome.sends_grease_tp());

        let firefox = transport_param_fixture(EngineFamily::Firefox);
        assert_eq!(firefox.provenance(), "source-constants");
        assert!(!firefox.randomizes_order());

        let safari = transport_param_fixture(EngineFamily::WebKit);
        assert_eq!(safari.provenance(), "unverified-catalog");
        assert!(safari.notes().unwrap_or_default().contains("Unverified"));
    }

    #[test]
    fn fingerprint_carries_fixture_flow_control() {
        // The same parsed fixture values populate FingerprintProfile and the
        // wire encoder; this is the drift guard between internal transport
        // configuration and the advertised Initial parameters.
        for (browser, os, family) in [
            (BrowserProfile::Chrome, OsProfile::Windows, EngineFamily::Chromium),
            (BrowserProfile::Edge, OsProfile::Windows, EngineFamily::Chromium),
            (BrowserProfile::Firefox, OsProfile::Linux, EngineFamily::Firefox),
            (BrowserProfile::Safari, OsProfile::MacOS, EngineFamily::WebKit),
        ] {
            let profile = crate::fingerprint_profile::FingerprintProfile::new(browser, os);
            let values = transport_param_fixture(family).flow_control();
            assert_eq!(profile.initial_max_data, values.initial_max_data, "{browser:?} max_data");
            assert_eq!(
                profile.initial_max_stream_data_bidi_local,
                values.initial_max_stream_data_bidi_local
            );
            assert_eq!(
                profile.initial_max_stream_data_bidi_remote,
                values.initial_max_stream_data_bidi_remote
            );
            assert_eq!(profile.initial_max_stream_data_uni, values.initial_max_stream_data_uni);
            assert_eq!(profile.initial_max_streams_bidi, values.initial_max_streams_bidi);
            assert_eq!(profile.initial_max_streams_uni, values.initial_max_streams_uni);
            assert_eq!(profile.max_idle_timeout, values.max_idle_timeout_ms);
        }
    }

    #[test]
    fn encoded_block_decodes_to_fixture_ids() {
        // framed version_information: chosen=1, available=[1]
        let version_information = [0x11u8, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let mut rng = rand::rng();
        for family in [EngineFamily::Chromium, EngineFamily::Firefox, EngineFamily::WebKit] {
            let fixture = transport_param_fixture(family);
            let scid = [0xabu8; 16];
            let encoded = encode_transport_params(
                family,
                1350,
                &HandshakeConnectionIds::client(&scid),
                &version_information,
                &mut rng,
            );
            let decoded = decode_transport_params(&encoded);
            let decoded_ids: std::collections::BTreeSet<u64> =
                decoded.iter().map(|(id, _)| *id).collect();

            for name in fixture.sends() {
                let Some(id) = tp_wire_id(name) else { continue };
                assert!(decoded_ids.contains(&id), "{family:?} must emit '{name}' (id {id:#x})");
            }
            // SCID is the real local value.
            let scid_entry = decoded.iter().find(|(id, _)| *id == 0x0f).expect("scid present");
            assert_eq!(scid_entry.1, scid.to_vec());
            // GREASE TP count matches fixture policy. min_ack_delay
            // (0xff02de1a) and grease_quic_bit (0x2ab2) deliberately live in
            // the reserved grease space, so they are excluded.
            let grease_count = decoded
                .iter()
                .filter(|(id, _)| id % 31 == 27 && !matches!(*id, 0x2ab2 | 0xff02_de1a))
                .count();
            assert_eq!(grease_count, usize::from(fixture.grease_tp));
        }
    }

    #[test]
    fn engines_produce_distinct_parameter_sets() {
        let mut rng = rand::rng();
        let scid = [1u8; 8];
        let chrome: std::collections::BTreeSet<u64> =
            decode_transport_params(&encode_transport_params(
                EngineFamily::Chromium,
                1350,
                &HandshakeConnectionIds::client(&scid),
                &[],
                &mut rng,
            ))
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let firefox: std::collections::BTreeSet<u64> =
            decode_transport_params(&encode_transport_params(
                EngineFamily::Firefox,
                1350,
                &HandshakeConnectionIds::client(&scid),
                &[],
                &mut rng,
            ))
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_ne!(chrome, firefox);
    }

    #[test]
    fn every_persona_keeps_server_handshake_cids_exactly_once() {
        let mut rng = rand::rng();
        let ids =
            HandshakeConnectionIds::server(b"server-scid", b"original-dcid", Some(b"retry-scid"));
        for family in [EngineFamily::Chromium, EngineFamily::Firefox, EngineFamily::WebKit] {
            let encoded = encode_transport_params(family, 1350, &ids, &[], &mut rng);
            let decoded = decode_transport_params(&encoded);
            for (id, expected) in [
                (0x0f, b"server-scid".as_slice()),
                (0x00, b"original-dcid".as_slice()),
                (0x10, b"retry-scid".as_slice()),
            ] {
                let values: Vec<&[u8]> = decoded
                    .iter()
                    .filter(|(parameter_id, _)| *parameter_id == id)
                    .map(|(_, value)| value.as_slice())
                    .collect();
                assert_eq!(values, vec![expected], "{family:?} CID parameter {id:#x}");
            }
        }
    }

    #[test]
    fn version_information_parameter_is_carried() {
        // chosen=1, available=[1, 0x6b3343cf]
        let framed =
            [0x11u8, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x6b, 0x33, 0x43, 0xcf];
        let mut rng = rand::rng();
        let encoded = encode_transport_params(
            EngineFamily::Firefox,
            1350,
            &HandshakeConnectionIds::client(&[7u8; 8]),
            &framed,
            &mut rng,
        );
        let decoded = decode_transport_params(&encoded);
        let vi = decoded.iter().find(|(id, _)| *id == 0x11).expect("version_information present");
        assert_eq!(vi.1, framed[2..].to_vec());
    }
}
